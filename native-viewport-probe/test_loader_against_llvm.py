"""Optional independent ELF-reader oracle on local-only pinned evidence.

Executes llvm-readobj (host tool), NEVER the inspected firmware. No ADB.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile

import inspect_loader_bindings as binding
import inspect_loader_dependencies as dep


def observed_relocations(elf):
    """Read only dynamically authenticated runtime tables under one budget."""
    observed = {}
    total = 0
    for index, section in binding.relocation_sections(elf):
        rows = []
        for offset, info, addend in binding.relocation_rows(section):
            total += 1
            if total > binding.MAX_RELOCATIONS:
                raise dep.InventoryError("LLVM oracle aggregate relocation budget exceeded")
            rows.append((offset, info, None if addend is None else addend % (1 << 64)))
        observed[index] = rows
    return observed


def reference_relocations(document, allowed_indices):
    if (type(document) is not list or len(document) != 1 or
            type(document[0]) is not dict or type(document[0].get("Relocations")) is not list):
        raise dep.InventoryError("invalid LLVM relocation document")
    sections = document[0]["Relocations"]
    if len(sections) > binding.MAX_RELOCATION_TABLES:
        raise dep.InventoryError("LLVM relocation table budget exceeded")
    expected = {}
    total = 0
    for section in sections:
        if (type(section) is not dict or type(section.get("SectionIndex")) is not int or
                type(section.get("Relocs")) is not list):
            raise dep.InventoryError("invalid LLVM relocation section")
        index = section["SectionIndex"]
        if index not in allowed_indices or index in expected:
            raise dep.InventoryError("LLVM reported unauthenticated or duplicate relocation section")
        rows = section["Relocs"]
        total += len(rows)
        if total > binding.MAX_RELOCATIONS:
            raise dep.InventoryError("LLVM reference relocation budget exceeded")
        parsed = []
        for wrapper in rows:
            if type(wrapper) is not dict or type(wrapper.get("Relocation")) is not dict:
                raise dep.InventoryError("invalid LLVM relocation row")
            row = wrapper["Relocation"]
            symbol = row.get("Symbol")
            relocation_type = row.get("Type")
            offset = row.get("Offset")
            symbol_value = symbol.get("Value") if type(symbol) is dict else None
            type_value = relocation_type.get("Value") if type(relocation_type) is dict else None
            addend = row.get("Addend") if "Addend" in row else None
            if (type(offset) is not int or not 0 <= offset < (1 << 64) or type(symbol) is not dict or
                    type(symbol.get("Value")) is not int or type(relocation_type) is not dict or
                    type(type_value) is not int or not 0 <= symbol_value < (1 << 32) or
                    not 0 <= type_value < (1 << 32) or
                    ("Addend" in row and (type(addend) is not int or
                     not -(1 << 63) <= addend < (1 << 63)))):
                raise dep.InventoryError("invalid LLVM relocation values")
            parsed.append((offset, (symbol_value << 32) | type_value,
                           addend % (1 << 64) if addend is not None else None))
        expected[index] = parsed
    if set(expected) != set(allowed_indices):
        raise dep.InventoryError("LLVM omitted an authenticated relocation section")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--llvm-readobj", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Reuse the production authenticated source snapshot; never delegate this
    # evidence oracle to ambient sys.path or cached bytecode.
    dep.authenticate_elftools(args.python_path)
    from elftools.elf.elffile import ELFFile
    source = args.inventory.absolute()
    with dep.EvidenceDirectory(source.parent) as authority:
        inventory_bytes = authority.read(source.name,4*1024*1024)
        inventory = dep.validate_inventory_v4(dep.load_strict_json(inventory_bytes))
        binding.authenticate_inventory_raw_maps(inventory, authority)
        local_data = {}
        for path in binding.MODULES:
            metadata = inventory["libraries"][path]
            if not dep.re.fullmatch(r"[0-9a-f]{16}\.so", metadata["localFile"]):
                raise dep.InventoryError("invalid local evidence path")
            local_data[path] = authority.read(metadata["localFile"],expected_size=metadata["bytes"])
    results = []
    for path in binding.MODULES:
        metadata = inventory["libraries"][path]
        data = local_data[path]
        if hashlib.sha256(data).hexdigest() != metadata["sha256"]:
            raise dep.InventoryError("evidence digest changed")
        if path == dep.ROOT_LIBRARY and metadata["sha256"] != dep.ROOT_SHA256:
            raise dep.InventoryError("root firmware not pinned")
        dep.preflight_elf_header(data)
        elf = ELFFile(io.BytesIO(data))
        # Compare ALL records, including offsets/info/addends of APS2 records
        # ignored by the import-pointer collector (e.g. ABS64 and RELATIVE).
        observed = observed_relocations(elf)
        # LLVM reads an exclusive copy of the exact bounded bytes, not a path
        # that could grow/replace after the Python precheck.
        with tempfile.TemporaryDirectory(prefix="viewport-llvm-") as temporary:
            pinned=Path(temporary)/"pinned.so"
            with pinned.open("xb") as out: out.write(data)
            output=dep.bounded_command([str(args.llvm_readobj),"--elf-output-style=JSON",
                                       "--relocations",str(pinned)],64*1024*1024)
        expected = reference_relocations(dep.load_strict_json(output), observed)
        if observed != expected:
            raise dep.InventoryError("LLVM relocation mismatch: " + path)
        if hashlib.sha256(data).hexdigest() != metadata["sha256"]:
            raise dep.InventoryError("evidence changed during comparison")
        slots, runs = binding.import_slots(data, inventory["filteredMappings"][path])
        record = {"path": path, "sha256": metadata["sha256"],
                  "relocations": sum(len(rows) for rows in observed.values()),
                  "pointerSlots": len(slots), "boundedRuns": len(runs), "result": "PASS"}
        results.append(record)
        print("LLVM_MATCH", path, record["relocations"], flush=True)
    report = {"schema": "loader-llvm-comparison-v1", "nativeStartAllowed": False,
              "inventorySha256": hashlib.sha256(inventory_bytes).hexdigest(),
              "results": results}
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
        out.write("\n")
    print("LOADER_LLVM_COMPARISON PASS native_start_allowed=false")


if __name__ == "__main__":
    main()
