"""Read existing import-pointer slots only. No attach, hooks or native calls.

Local pinned ELFs determine the exact allowed memory intervals. This is binding
evidence, NOT permission to load firmware or activate a native viewport.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys

import inspect_loader_dependencies as dep

MODULES = (
    dep.ROOT_LIBRARY,
    "/system_ext/app/drawPath/lib/arm64/libopencv_java4.so",
    "/system_ext/app/drawPath/lib/arm64/libc++_shared.so",
    "/system_ext/app/drawPath/lib/arm64/libomp.so",
    "/system/lib64/libbinder.so",
)
MAX_SPAN = 16384
MAX_MODULE_READ = 262144
MAX_RELOCATIONS = 1000000


def packed_rela(data):
    """Bounded APS2 decoder; yields (offset, info, addend), never addresses.

    Format reference: AOSP bionic linker/linker_reloc_iterators.h,
    https://android.googlesource.com/platform/bionic/+/b996d60/linker/linker_reloc_iterators.h
    This independent host parser rejects invalid groups, overflow and tails.
    """
    if not data.startswith(b"APS2"):
        raise dep.InventoryError("unsupported packed relocation signature")
    cursor = 4

    def integer():
        nonlocal cursor
        value = 0
        for shift in range(0, 70, 7):
            if cursor >= len(data):
                raise dep.InventoryError("truncated packed relocation integer")
            byte = data[cursor]
            cursor += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                if byte & 64:
                    value -= 1 << (shift+7)
                if not -(1 << 63) <= value < (1 << 63):
                    raise dep.InventoryError("packed relocation integer overflow")
                return value
        raise dep.InventoryError("overlong packed relocation integer")

    count, offset = integer(), integer()
    if not 0 <= count <= MAX_RELOCATIONS or not 0 <= offset < (1 << 64):
        raise dep.InventoryError("invalid packed relocation header")
    remaining, addend = count, 0
    while remaining:
        group, flags = integer(), integer()
        if not 0 < group <= remaining or flags < 0 or flags & ~15 or (flags & 4 and not flags & 8):
            raise dep.InventoryError("invalid packed relocation group")
        delta = integer() if flags & 2 else None
        info = integer() if flags & 1 else None
        if flags & 4:
            addend += integer()
        elif not flags & 8:
            addend = 0
        for _ in range(group):
            offset += delta if flags & 2 else integer()
            current_info = info if flags & 1 else integer()
            if flags & 8 and not flags & 4:
                addend += integer()
            if not 0 <= offset < (1 << 64) or not 0 <= current_info < (1 << 64) or not -(1 << 63) <= addend < (1 << 63):
                raise dep.InventoryError("packed relocation arithmetic overflow")
            yield offset, current_info, addend
        remaining -= group
    if cursor != len(data):
        raise dep.InventoryError("trailing packed relocation data")


def relocation_rows(section):
    if section["sh_type"] == "SHT_RELA":
        if section.num_relocations() > MAX_RELOCATIONS:
            raise dep.InventoryError("relocation count budget exceeded")
        return ((int(r["r_offset"]), int(r["r_info"]), int(r["r_addend"]))
                for r in section.iter_relocations())
    if section["sh_type"] == 0x60000002:  # SHT_ANDROID_RELA (APS2)
        return packed_rela(section.data())
    raise dep.InventoryError("unsupported import relocation format")


def checked_runs(slots, mappings):
    """Coalesce only close, same-readable-mapping slots; hard bound all reads."""
    runs = []
    last_address = None
    for slot in sorted(slots, key=lambda s: s["address"]):
        address = slot["address"]
        if type(address) is not int or not 0 < address < (1 << 56) or address % 8:
            raise dep.InventoryError("invalid import pointer address")
        if address == last_address:
            raise dep.InventoryError("duplicate import pointer slot")
        last_address = address
        owners = [m for m in mappings if m["start"] <= address and address+8 <= m["end"]
                  and m["permissions"].startswith("r")]
        if len(owners) != 1:
            raise dep.InventoryError("import pointer not in exactly one readable source mapping")
        owner = owners[0]
        if (runs and address <= runs[-1]["end"] + 64 and
                address+8-runs[-1]["start"] <= MAX_SPAN and
                runs[-1]["owner"] == owner):
            runs[-1]["end"] = address+8
        else:
            runs.append({"start": address, "end": address+8, "owner": owner})
    if sum(r["end"]-r["start"] for r in runs) > MAX_MODULE_READ:
        raise dep.InventoryError("module read budget exceeded")
    return runs


def import_slots(data, mappings):
    from elftools.elf.elffile import ELFFile
    dep.elf_metadata(data)
    elf = ELFFile(io.BytesIO(data))
    loads = [p for p in elf.iter_segments() if p["p_type"] == "PT_LOAD"]
    zeros = [m for m in mappings if m["offset"] == 0]
    if len(zeros) != 1 or not any(p["p_offset"] == 0 and p["p_vaddr"] == 0 for p in loads):
        raise dep.InventoryError("unsupported or ambiguous load bias")
    base = zeros[0]["start"]
    slots = []
    for name in (".rela.plt", ".rela.dyn"):
        section = elf.get_section_by_name(name)
        if section is None:
            continue
        symbols = elf.get_section(section["sh_link"])
        for offset, info, _ in relocation_rows(section):
            # AArch64 GLOB_DAT / JUMP_SLOT. Never read RELATIVE data/ink planes.
            if info & 0xffffffff not in (1025, 1026):
                continue
            if info >> 32 >= symbols.num_symbols():
                raise dep.InventoryError("relocation symbol index out of range")
            symbol = symbols.get_symbol(info >> 32)
            if not any(p["p_vaddr"] <= offset and offset+8 <= p["p_vaddr"]+p["p_memsz"] for p in loads):
                raise dep.InventoryError("relocation outside ELF image")
            slots.append({"symbol": symbol.name, "symbolType": symbol["st_info"]["type"],
                          "binding": symbol["st_info"]["bind"],
                          "undefined": symbol["st_shndx"] == "SHN_UNDEF",
                          "rva": offset, "address": base+offset})
    if not slots:
        raise dep.InventoryError("no supported import relocation slots")
    return slots, checked_runs(slots, mappings)


def target_owner(pointer, all_maps):
    if pointer == 0:
        return {"status": "null", "paths": []}
    owners = sorted(p for p, records in all_maps.items()
                    if any(m["start"] <= pointer < m["end"] for m in records))
    return {"status": "unique_mapped_target" if len(owners) == 1 else "unresolved_target",
            "paths": owners}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.python_path.resolve(strict=True)))
    __import__("elftools.elf.elffile")
    source = args.inventory.resolve(strict=True)
    inventory_bytes = source.read_bytes()
    inv = json.loads(inventory_bytes)
    if inv["schema"] != "native-loader-inventory-v1" or inv["serial"] != dep.SERIAL or inv["firmware"] != dep.FINGERPRINT:
        raise dep.InventoryError("wrong inventory identity")
    pid, start = inv["process"]["pid"], inv["process"]["startTime"]
    if type(pid) is not int or not 1 < pid < 4194304 or type(start) is not int or start <= 0:
        raise dep.InventoryError("invalid captured process identity")
    plans = {}
    for path in MODULES:
        meta = inv["libraries"][path]
        filename = meta["localFile"]
        if not dep.re.fullmatch(r"[0-9a-f]{16}\.so", filename):
            raise dep.InventoryError("unsupported local evidence filename")
        local = source.parent / filename
        if local.is_symlink():
            raise dep.InventoryError("symlink evidence library")
        data = local.read_bytes()
        if hashlib.sha256(data).hexdigest() != meta["sha256"]:
            raise dep.InventoryError("local library digest changed")
        if path == dep.ROOT_LIBRARY and meta["sha256"] != dep.ROOT_SHA256:
            raise dep.InventoryError("unpinned native engine")
        slots, runs = import_slots(data, meta["mappings"])
        plans[path] = {"slots": slots, "runs": runs}

    adb = str(args.adb.resolve(strict=True))
    def run(*command):
        result = subprocess.run([adb, "-s", dep.SERIAL, *command], capture_output=True, timeout=30, check=True)
        return result.stdout

    def verify_identity():
        if run("shell", "getprop", "ro.build.fingerprint").decode().strip() != dep.FINGERPRINT:
            raise dep.InventoryError("firmware changed")
        identity = dep.process_identity(run("shell", f"su -c 'cat /proc/{pid}/stat'").decode(), pid)
        if identity != (pid, start) or run("exec-out", f"su -c 'cat /proc/{pid}/cmdline'").rstrip(b"\0") != b"com.ratta.drawpath":
            raise dep.InventoryError("native process changed")
        maps = dep.mapped_libraries(run("shell", f"su -c 'cat /proc/{pid}/maps'").decode())
        # Recheck every inventory library, not only the pointer-slot owners.
        if any(maps.get(p) != m["mappings"] for p, m in inv["libraries"].items()):
            raise dep.InventoryError("library mappings changed")
        if dep.process_identity(run("shell", f"su -c 'cat /proc/{pid}/stat'").decode(), pid) != identity:
            raise dep.InventoryError("native process changed during map capture")
        return maps

    maps = verify_identity()
    if args.output.exists():
        raise dep.InventoryError("output already exists")
    results = {}
    for path, plan in plans.items():
        chunks = []
        for interval in plan["runs"]:
            address, size = interval["start"], interval["end"]-interval["start"]
            command = f"su -c 'dd if=/proc/{pid}/mem bs=1 skip={address} count={size} 2>/dev/null'"
            data = run("exec-out", command)
            if len(data) != size or run("exec-out", command) != data:
                raise dep.InventoryError("short or changing pointer capture")
            chunks.append((address, data))
        rows = []
        for slot in plan["slots"]:
            chunk_start, data = next((a, b) for a, b in chunks if a <= slot["address"] and slot["address"]+8 <= a+len(b))
            pointer = struct.unpack_from("<Q", data, slot["address"]-chunk_start)[0]
            rows.append({**slot, "pointer": pointer, **target_owner(pointer, maps)})
        results[path] = {"bytesReadPerCapture": sum(len(b) for _, b in chunks), "slots": rows}
        print("BINDING_READ", path.rsplit("/", 1)[-1], "slots="+str(len(rows)), flush=True)
    verify_identity()
    report = {"schema": "native-loader-bindings-v1", "nativeStartAllowed": False,
              "inventorySha256": hashlib.sha256(inventory_bytes).hexdigest(),
              "process": inv["process"], "modules": results,
              "notes": "Stable observed relocation targets only; no initializer/loader or full dependency-graph admission."}
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
        out.write("\n")
    print("BINDINGS_COMPLETE native_start_allowed=false")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, ImportError, KeyError, subprocess.SubprocessError) as exc:
        print("BINDINGS_FAILED", str(exc), file=sys.stderr)
        raise SystemExit(1)
