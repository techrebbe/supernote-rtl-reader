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


def relr_rows(data):
    """RELR has only relative relocations, never symbolic import pointers."""
    if not data or len(data)%8 or len(data)//8>MAX_RELOCATIONS:
        raise dep.InventoryError("invalid RELR byte count")
    base=None
    previous=-1
    count=0
    for (word,) in struct.iter_unpack("<Q",data):
        if word&1:
            if base is None: raise dep.InventoryError("RELR bitmap without base")
            offsets=[base+8*(bit-1) for bit in range(1,64) if word&(1<<bit)]
            base+=63*8
        else:
            offsets=[word]
            base=word+8
        if base>=(1<<64): raise dep.InventoryError("RELR address overflow")
        for offset in offsets:
            if offset%8 or offset<=previous or offset>=(1<<64)-7:
                raise dep.InventoryError("invalid/repeated RELR offset")
            previous=offset
            count+=1
            if count>MAX_RELOCATIONS: raise dep.InventoryError("RELR expansion budget exceeded")
            yield offset,1027,None  # No serialized addend; do not fabricate one.


def relocation_rows(section):
    if section["sh_type"] == "SHT_RELA":
        if section.num_relocations() > MAX_RELOCATIONS:
            raise dep.InventoryError("relocation count budget exceeded")
        return ((int(r["r_offset"]), int(r["r_info"]), int(r["r_addend"]))
                for r in section.iter_relocations())
    if section["sh_type"] == 0x60000002:  # SHT_ANDROID_RELA (APS2)
        return packed_rela(section.data())
    if section["sh_type"] in ("SHT_RELR",0x6fffff00):
        return relr_rows(section.data())
    raise dep.InventoryError("unsupported import relocation format")


def relocation_sections(elf):
    """Dynamic addresses/sizes are authoritative, not conventional section names.

    This bounded prototype explicitly rejects sectionless and REL layouts rather
    than reporting a partial import plan. RELR is covered but has no symbols.
    """
    dynamics=[s for s in elf.iter_segments() if s["p_type"]=="PT_DYNAMIC"]
    if len(dynamics)!=1: raise dep.InventoryError("ambiguous dynamic relocation authority")
    fields={"DT_RELA","DT_RELASZ","DT_RELAENT","DT_JMPREL","DT_PLTRELSZ","DT_PLTREL",
            "DT_ANDROID_RELA","DT_ANDROID_RELASZ","DT_SYMTAB","DT_SYMENT","DT_STRTAB","DT_STRSZ",
            "DT_REL","DT_RELSZ","DT_RELENT","DT_ANDROID_REL","DT_ANDROID_RELSZ",
            "DT_RELR","DT_RELRSZ","DT_RELRENT","DT_ANDROID_RELR","DT_ANDROID_RELRSZ","DT_ANDROID_RELRENT"}
    values={}
    for tag in dynamics[0].iter_tags():
        key=tag.entry.d_tag
        if key in fields:
            if key in values: raise dep.InventoryError("duplicate dynamic relocation metadata")
            values[key]=int(tag.entry.d_val)
    if any(values.get(k,0) for k in ("DT_REL","DT_RELSZ","DT_RELENT","DT_ANDROID_REL","DT_ANDROID_RELSZ")):
        raise dep.InventoryError("REL import layouts are not supported by this bounded probe")
    specs=[]
    for address,size,kind in (("DT_RELA","DT_RELASZ","SHT_RELA"),
                              ("DT_JMPREL","DT_PLTRELSZ","SHT_RELA"),
                              ("DT_ANDROID_RELA","DT_ANDROID_RELASZ",0x60000002),
                              ("DT_RELR","DT_RELRSZ","SHT_RELR"),
                              ("DT_ANDROID_RELR","DT_ANDROID_RELRSZ",0x6fffff00)):
        if address not in values and size not in values: continue
        if address not in values or size not in values or values[address]<=0 or values[size]<=0:
            raise dep.InventoryError("incomplete/empty dynamic relocation table")
        if kind=="SHT_RELA" and (values[size]%24 or values.get("DT_RELAENT")!=24):
            raise dep.InventoryError("invalid RELA entry metadata")
        if address=="DT_JMPREL" and values.get("DT_PLTREL")!=7:
            raise dep.InventoryError("non-RELA PLT relocation table")
        if kind in ("SHT_RELR",0x6fffff00) and (values[size]%8 or values.get(address.replace("RELR","RELRENT"))!=8):
            raise dep.InventoryError("invalid RELR entry metadata")
        specs.append((values[address],values[size],kind))
    if not specs or values.get("DT_SYMENT")!=24 or "DT_SYMTAB" not in values or values.get("DT_STRTAB",0)<=0 or values.get("DT_STRSZ",0)<=0:
        raise dep.InventoryError("missing relocation/symbol authority")
    sections=list(elf.iter_sections())
    tables=[]
    loads=[p for p in elf.iter_segments() if p["p_type"]=="PT_LOAD"]
    for address,size,kind in specs:
        found=[(i,s) for i,s in enumerate(sections) if s["sh_type"]==kind and
               s["sh_addr"]==address and s["sh_size"]==size and s["sh_flags"]&2]
        if len(found)!=1: raise dep.InventoryError("dynamic relocation table missing/ambiguous in sections")
        i,s=found[0]
        backed=[p for p in loads if p["p_vaddr"]<=address and address+size<=p["p_vaddr"]+p["p_filesz"] and
                s["sh_offset"]==p["p_offset"]+address-p["p_vaddr"]]
        if len(backed)!=1: raise dep.InventoryError("relocation table file correspondence mismatch")
        if kind in ("SHT_RELR",0x6fffff00):
            if s["sh_link"]!=0 or s["sh_entsize"]!=8:
                raise dep.InventoryError("RELR table must not name symbols")
        else:
            symbols=elf.get_section(s["sh_link"])
            if symbols["sh_type"]!="SHT_DYNSYM" or symbols["sh_addr"]!=values["DT_SYMTAB"] or symbols["sh_entsize"]!=24:
                raise dep.InventoryError("dynamic relocation symbol table mismatch")
            if symbols["sh_size"]<=0 or symbols["sh_size"]%24 or not symbols["sh_flags"]&2:
                raise dep.InventoryError("invalid dynamic symbol extent")
            validate_section_storage(symbols,loads)
            strings=elf.get_section(symbols["sh_link"])
            if strings["sh_type"]!="SHT_STRTAB" or not strings["sh_flags"]&2 or strings["sh_addr"]!=values["DT_STRTAB"] or strings["sh_size"]!=values["DT_STRSZ"]:
                raise dep.InventoryError("dynamic symbol string authority mismatch")
            validate_section_storage(strings,loads)
        tables.append((i,s))
    indices={i for i,_ in tables}
    allocated={i for i,s in enumerate(sections) if s["sh_flags"]&2 and
               s["sh_type"] in ("SHT_RELA","SHT_REL",0x60000001,0x60000002,"SHT_RELR",0x6fffff00)}
    if len(indices)!=len(specs) or indices!=allocated:
        raise dep.InventoryError("unaccounted allocated relocation table")
    ranges=sorted((a,a+s) for a,s,_ in specs)
    if any(end>next_start for (_,end),(next_start,_) in zip(ranges,ranges[1:])):
        raise dep.InventoryError("overlapping dynamic relocation tables")
    return tables


def validate_section_storage(section,loads):
    address,size=section["sh_addr"],section["sh_size"]
    if not 0<size<=dep.MAX_FILE_BYTES or address<0 or address+size>=(1<<64):
        raise dep.InventoryError("invalid dynamic section byte extent")
    owners=[p for p in loads if p["p_vaddr"]<=address and address+size<=p["p_vaddr"]+p["p_filesz"] and
            section["sh_offset"]==p["p_offset"]+address-p["p_vaddr"]]
    if len(owners)!=1: raise dep.InventoryError("dynamic section file correspondence mismatch")


def slot_file_correspondence(offset,base,loads,mappings):
    segments=[p for p in loads if p["p_vaddr"]<=offset and offset+8<=p["p_vaddr"]+p["p_filesz"]]
    owners=[m for m in mappings if m["start"]<=base+offset and base+offset+8<=m["end"] and
            m["permissions"].startswith("r")]
    if len(segments)!=1 or len(owners)!=1:
        raise dep.InventoryError("slot not in one readable file-backed segment/mapping")
    p,m=segments[0],owners[0]
    if p["p_offset"]+offset-p["p_vaddr"]!=m["offset"]+base+offset-m["start"]:
        raise dep.InventoryError("slot mapped file offset differs from ELF segment")


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
    for _,section in relocation_sections(elf):
        symbols = elf.get_section(section["sh_link"])
        strings=elf.get_section(symbols["sh_link"]).data() if section["sh_type"] not in ("SHT_RELR",0x6fffff00) else None
        for offset, info, _ in relocation_rows(section):
            # AArch64 GLOB_DAT / JUMP_SLOT. Never read RELATIVE data/ink planes.
            if info & 0xffffffff not in (1025, 1026):
                continue
            if info >> 32 >= symbols.num_symbols():
                raise dep.InventoryError("relocation symbol index out of range")
            symbol = symbols.get_symbol(info >> 32)
            name_offset=int(symbol["st_name"])
            if strings is None or not 0<=name_offset<len(strings):
                raise dep.InventoryError("symbol name outside dynamic string table")
            name_end=strings.find(b"\0",name_offset)
            if name_end<0: raise dep.InventoryError("unterminated dynamic symbol name")
            name=strings[name_offset:name_end].decode("utf-8",errors="strict")
            slot_file_correspondence(offset,base,loads,mappings)
            slots.append({"symbol": name, "symbolType": symbol["st_info"]["type"],
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
    inventory_bytes = dep.read_bounded(source,4*1024*1024)
    inv = json.loads(inventory_bytes)
    if inv["schema"] != "native-loader-inventory-v2" or inv["serial"] != dep.SERIAL or inv["firmware"] != dep.FINGERPRINT:
        raise dep.InventoryError("wrong inventory identity")
    pid, start = inv["process"]["pid"], inv["process"]["startTime"]
    if type(pid) is not int or not 1 < pid < 4194304 or type(start) is not int or start <= 0:
        raise dep.InventoryError("invalid captured process identity")
    plans = {}
    for path in MODULES:
        meta = inv["libraries"][path]
        identity=meta["mappedFileIdentity"]
        if identity.get("authority")!="proc-map-files-open-descriptor-v1" or identity["bytes"]!=meta["bytes"] or any(
                (int(m["device"].split(":")[0],16),int(m["device"].split(":")[1],16),m["inode"])!=
                (*[int(x,16) for x in identity["device"].split(":")],identity["inode"]) for m in meta["mappings"]):
            raise dep.InventoryError("inventory lacks exact mapped descriptor authority")
        filename = meta["localFile"]
        if not dep.re.fullmatch(r"[0-9a-f]{16}\.so", filename):
            raise dep.InventoryError("unsupported local evidence filename")
        local = source.parent / filename
        if local.is_symlink():
            raise dep.InventoryError("symlink evidence library")
        data = dep.read_bounded(local,expected_size=meta["bytes"])
        if hashlib.sha256(data).hexdigest() != meta["sha256"]:
            raise dep.InventoryError("local library digest changed")
        if path == dep.ROOT_LIBRARY and meta["sha256"] != dep.ROOT_SHA256:
            raise dep.InventoryError("unpinned native engine")
        slots, runs = import_slots(data, meta["mappings"])
        plans[path] = {"slots": slots, "runs": runs}

    adb = str(args.adb.resolve(strict=True))
    def run(*command):
        return dep.bounded_command([adb,"-s",dep.SERIAL,*command],4*1024*1024)

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
