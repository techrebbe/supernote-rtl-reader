"""Optional independent ELF-reader oracle on local-only pinned evidence.

Executes llvm-readobj (host tool), NEVER the inspected firmware. No ADB.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

import inspect_loader_bindings as binding
import inspect_loader_dependencies as dep


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--llvm-readobj", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.python_path.resolve(strict=True)))
    from elftools.elf.elffile import ELFFile
    inventory_bytes = args.inventory.read_bytes()
    inventory = json.loads(inventory_bytes)
    results = []
    for path in binding.MODULES:
        metadata = inventory["libraries"][path]
        if not dep.re.fullmatch(r"[0-9a-f]{16}\.so", metadata["localFile"]):
            raise dep.InventoryError("invalid local evidence path")
        local = args.inventory.parent / metadata["localFile"]
        data = local.read_bytes()
        if hashlib.sha256(data).hexdigest() != metadata["sha256"]:
            raise dep.InventoryError("evidence digest changed")
        if path == dep.ROOT_LIBRARY and metadata["sha256"] != dep.ROOT_SHA256:
            raise dep.InventoryError("root firmware not pinned")
        elf = ELFFile(io.BytesIO(data))
        # Compare ALL records, including offsets/info/addends of APS2 records
        # ignored by the import-pointer collector (e.g. ABS64 and RELATIVE).
        observed = {}
        for index, section in enumerate(elf.iter_sections()):
            if section.name in (".rela.dyn", ".rela.plt"):
                observed[index] = [(offset, info, addend % (1 << 64))
                                   for offset, info, addend in binding.relocation_rows(section)]
        result = subprocess.run([str(args.llvm_readobj), "--elf-output-style=JSON",
                                 "--relocations", str(local)],
                                capture_output=True, timeout=30, check=True)
        reference = json.loads(result.stdout)[0]["Relocations"]
        expected = {}
        for section in reference:
            if section["SectionIndex"] in observed:
                rows = [r["Relocation"] for r in section["Relocs"]]
                expected[section["SectionIndex"]] = [
                    (r["Offset"], (r["Symbol"]["Value"] << 32) | r["Type"]["Value"],
                     r["Addend"] % (1 << 64)) for r in rows]
        if observed != expected:
            raise dep.InventoryError("LLVM relocation mismatch: " + path)
        if hashlib.sha256(local.read_bytes()).hexdigest() != metadata["sha256"]:
            raise dep.InventoryError("evidence changed during comparison")
        slots, runs = binding.import_slots(data, metadata["mappings"])
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
