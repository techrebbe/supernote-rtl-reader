"""Read existing import-pointer slots only. No attach, hooks or native calls.

Local pinned ELFs determine the exact allowed memory intervals. This is binding
evidence, NOT permission to load firmware or activate a native viewport.
"""
import argparse
import bisect
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import sys
import time

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
MAX_SYMBOLS = 262144
MAX_SYMBOL_BYTES = MAX_SYMBOLS * 24
MAX_RELOCATION_TABLES = 8
MAX_RELOCATION_BYTES = MAX_RELOCATIONS * 24
WORK_BYTES = 64
MAX_BINDING_WORK = 64_000_000  # 4 GiB-equivalent aggregate read/decode/work budget.
MAX_BINDING_SECONDS = 30
MAX_POINTER_COMMANDS = 4096
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_REPORT_NON_SLOT_BYTES = 8 * 1024 * 1024
MAX_OWNER_PATH_BYTES = 4096
MAX_ELF_ENUM_BYTES = 32


def authenticate_elftools(root):
    """Use the same authenticated parser authority as dependency collection."""
    return dep.authenticate_elftools(root)


def serialized_slot_bytes(row):
    """Validate one slot and return its worst nested report contribution.

    A standalone pretty-printed object is smaller than the same object nested
    in ``modules.*.slots`` because every row line gains indentation.  Charge
    the exact first-row delta; subsequent rows are no larger.
    """
    keys = {"symbol", "symbolType", "binding", "undefined", "rva", "address",
            "pointer", "status", "paths"}
    if type(row) is not dict or set(row) != keys:
        raise dep.InventoryError("invalid serialized import slot shape")
    symbol = row["symbol"]
    if (type(symbol) is not str or
            len(symbol.encode("utf-8", errors="strict")) > dep.MAX_DEPENDENCY_NAME_BYTES):
        raise dep.InventoryError("serialized import symbol exceeds bound")
    for key in ("symbolType", "binding"):
        value = row[key]
        if not ((type(value) is int and 0 <= value < 256) or
                (type(value) is str and len(value.encode("ascii", errors="strict")) <=
                 MAX_ELF_ENUM_BYTES)):
            raise dep.InventoryError("invalid serialized ELF enum")
    if type(row["undefined"]) is not bool or row["status"] not in (
            "null", "unresolved_target", "unique_mapped_target"):
        raise dep.InventoryError("invalid serialized import classification")
    if any(type(row[key]) is not int or not 0 <= row[key] < (1 << 64)
           for key in ("rva", "address", "pointer")):
        raise dep.InventoryError("invalid serialized import address")
    paths = row["paths"]
    if (type(paths) is not list or len(paths) > 1 or
            bool(paths) != (row["status"] == "unique_mapped_target") or
            any(type(path) is not str or len(path.encode("ascii", errors="strict")) >
                MAX_OWNER_PATH_BYTES or dep.PATH.fullmatch(path) is None for path in paths)):
        raise dep.InventoryError("invalid serialized import owner path")
    empty = {"modules": {"m": {"slots": []}}}
    nested = {"modules": {"m": {"slots": [row]}}}
    return (len(json.dumps(nested, indent=2, ensure_ascii=True).encode("ascii")) -
            len(json.dumps(empty, indent=2, ensure_ascii=True).encode("ascii")))


_WORST_APEX_SUFFIX = "/lib64/bionic/z.so"
_WORST_APEX_PATH = ("/apex/" + "a" *
    (MAX_OWNER_PATH_BYTES - len("/apex/") - len(_WORST_APEX_SUFFIX)) +
    _WORST_APEX_SUFFIX)
_WORST_SERIALIZED_SLOT = {
    "symbol": "\x01" * dep.MAX_DEPENDENCY_NAME_BYTES,
    "symbolType": "S" * MAX_ELF_ENUM_BYTES,
    "binding": "B" * MAX_ELF_ENUM_BYTES,
    "undefined": False,
    "rva": (1 << 64) - 1,
    "address": (1 << 64) - 1,
    "pointer": (1 << 64) - 1,
    "status": "unique_mapped_target",
    "paths": [_WORST_APEX_PATH],
}
MAX_SERIALIZED_SLOT_BYTES = serialized_slot_bytes(_WORST_SERIALIZED_SLOT)
MAX_TOTAL_IMPORT_SLOTS = min(
    8192, (MAX_REPORT_BYTES - MAX_REPORT_NON_SLOT_BYTES) // MAX_SERIALIZED_SLOT_BYTES)
MAX_IMPORT_SLOTS = MAX_TOTAL_IMPORT_SLOTS
if MAX_TOTAL_IMPORT_SLOTS * MAX_SERIALIZED_SLOT_BYTES + MAX_REPORT_NON_SLOT_BYTES > MAX_REPORT_BYTES:
    raise RuntimeError("binding report limits are internally inconsistent")


class WorkBudget:
    """One aggregate parser/planner budget, shared by all admitted modules."""
    def __init__(self, limit=MAX_BINDING_WORK, seconds=MAX_BINDING_SECONDS):
        if type(limit) is not int or limit <= 0 or not 0 < seconds <= 60:
            raise dep.InventoryError("invalid binding work budget")
        self.limit = limit
        self.used = 0
        self.deadline = time.monotonic() + seconds

    def step(self, count=1):
        if type(count) is not int or count < 0 or self.used > self.limit - count:
            raise dep.InventoryError("aggregate binding work budget exceeded")
        self.used += count
        self.checkpoint()

    def checkpoint(self):
        if time.monotonic() > self.deadline:
            raise dep.InventoryError("binding planning deadline exceeded")

    def remaining(self):
        self.checkpoint()
        return min(60, max(0.001, self.deadline - time.monotonic()))

    def reserve_bytes(self, count):
        if type(count) is not int or count < 0:
            raise dep.InventoryError("invalid binding byte reservation")
        self.step(max(1, (count + WORK_BYTES - 1) // WORK_BYTES))

    def remaining_bytes(self):
        self.checkpoint()
        return max(0, (self.limit - self.used) * WORK_BYTES)


class MappingIndex:
    """Validated non-overlapping interval lookup; never rescans all mappings."""
    def __init__(self, maps, budget=None):
        rows = []
        if type(maps) is dict:
            for path, records in maps.items():
                for record in records:
                    if budget is not None:
                        budget.step()
                    rows.append((record["start"], record["end"], path, record))
        elif type(maps) is list:
            if budget is not None:
                budget.step(len(maps))
            rows = [(record["start"], record["end"], None, record) for record in maps]
        else:
            raise dep.InventoryError("invalid mapping index authority")
        rows.sort(key=lambda row: (row[0], row[1], "" if row[2] is None else row[2]))
        if any(start >= end for start, end, _, _ in rows) or any(
                left[1] > right[0] for left, right in zip(rows, rows[1:])):
            raise dep.InventoryError("overlapping or invalid mapping index")
        self.rows = rows
        self.starts = [row[0] for row in rows]

    def containing(self, address, size=1):
        if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
            raise dep.InventoryError("invalid mapping lookup")
        at = bisect.bisect_right(self.starts, address) - 1
        if at < 0:
            return None
        row = self.rows[at]
        return row if address + size <= row[1] else None


class RuntimeFileIndex:
    """Effective ordered PT_LOAD page authority, built once per ELF."""
    def __init__(self, loads, budget=None):
        if type(loads) is not list or not 0 < len(loads) <= dep.MAX_PROGRAM_HEADERS:
            raise dep.InventoryError("invalid runtime load set")
        operations = []
        cuts = set()
        for ordinal, load in enumerate(loads):
            if budget is not None:
                budget.step()
            vaddr, offset, filesz, memsz = (int(load[key]) for key in
                ("p_vaddr", "p_offset", "p_filesz", "p_memsz"))
            flags = int(load["p_flags"])
            file_start = dep._page_floor(vaddr)
            file_end = dep._page_ceil(vaddr + filesz)
            current = []
            if file_end > file_start:
                current.append((file_start, file_end, "file",
                                dep._page_floor(offset), bool(flags & 4), ordinal))
            if flags & 2 and vaddr + filesz < file_end:
                current.append((vaddr + filesz, file_end, "zero", None, False, ordinal))
            if filesz < memsz:
                anonymous_end = dep._page_ceil(vaddr + memsz)
                if file_end < anonymous_end:
                    current.append((file_end, anonymous_end, "zero", None, False, ordinal))
            operations.extend(current)
            for start, end, *_ in current:
                cuts.update((start, end))
        points = sorted(cuts)
        rows = []
        for start, end in zip(points, points[1:]):
            state = None
            for op_start, op_end, kind, file_page, readable, owner in operations:
                if budget is not None:
                    budget.step()
                if op_start <= start < op_end:
                    state = (kind, file_page, readable, op_start, owner)
            if state is None:
                continue
            kind, file_page, readable, op_start, owner = state
            file_offset = None if file_page is None else file_page + start - op_start
            rows.append((start, end, kind, file_offset, readable, owner))
        self.rows = rows
        self.starts = [row[0] for row in rows]
        self.budget = budget

    def file_offset(self, address, size):
        if (type(address) is not int or type(size) is not int or address < 0 or
                size <= 0 or address + size >= (1 << 64)):
            raise dep.InventoryError("invalid runtime table extent")
        end = address + size
        at = bisect.bisect_right(self.starts, address) - 1
        first = None
        expected = None
        cursor = address
        while cursor < end:
            if self.budget is not None:
                self.budget.step()
            if at < 0 or at >= len(self.rows):
                raise dep.InventoryError("runtime table lacks effective readable file backing")
            start, stop, kind, offset, readable, _ = self.rows[at]
            if not start <= cursor < stop or kind != "file" or not readable:
                raise dep.InventoryError("runtime table lacks effective readable file backing")
            current = offset + cursor - start
            if expected is not None and current != expected:
                raise dep.InventoryError("runtime table has discontinuous effective file backing")
            if first is None:
                first = current
            cursor = min(end, stop)
            expected = current + (cursor - max(address, start))
            at += 1
        return first

    def effective_owner(self, address, size=1):
        self.file_offset(address, size)
        at = bisect.bisect_right(self.starts, address) - 1
        owner = self.rows[at][5]
        cursor, end = address, address + size
        while cursor < end:
            row = self.rows[at]
            if row[5] != owner:
                raise dep.InventoryError("runtime extent has multiple effective PT_LOAD owners")
            cursor = min(end, row[1])
            at += 1
        return owner


def packed_rela(data, budget=None):
    """Bounded APS2 decoder; yields (offset, info, addend), never addresses.

    Format reference: AOSP bionic linker/linker_reloc_iterators.h,
    https://android.googlesource.com/platform/bionic/+/b996d60/linker/linker_reloc_iterators.h
    This independent host parser rejects invalid groups, overflow and tails.
    """
    if budget is not None:
        budget.reserve_bytes(len(data))
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
        if budget is not None:
            budget.step()
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
            if budget is not None:
                budget.step()
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


def relr_rows(data, budget=None):
    """RELR has only relative relocations, never symbolic import pointers."""
    if budget is not None:
        budget.reserve_bytes(len(data))
    if not data or len(data)%8 or len(data)//8>MAX_RELOCATIONS:
        raise dep.InventoryError("invalid RELR byte count")
    base=None
    previous=-1
    count=0
    for (word,) in struct.iter_unpack("<Q",data):
        if budget is not None:
            budget.step()
        if word&1:
            if base is None: raise dep.InventoryError("RELR bitmap without base")
            offsets=[base+8*(bit-1) for bit in range(1,64) if word&(1<<bit)]
            base+=63*8
        else:
            offsets=[word]
            base=word+8
        if base>=(1<<64): raise dep.InventoryError("RELR address overflow")
        for offset in offsets:
            if budget is not None:
                budget.step()
            if offset%8 or offset<=previous or offset>=(1<<64)-7:
                raise dep.InventoryError("invalid/repeated RELR offset")
            previous=offset
            count+=1
            if count>MAX_RELOCATIONS: raise dep.InventoryError("RELR expansion budget exceeded")
            yield offset,1027,None  # No serialized addend; do not fabricate one.


def relocation_rows(section, budget=None):
    if section["sh_type"] not in ("SHT_RELA",0x60000002,"SHT_RELR",0x6fffff00):
        raise dep.InventoryError("unsupported import relocation format")
    if section["sh_flags"]&0x800:
        raise dep.InventoryError("compressed relocation section is not runtime loader storage")
    if section["sh_type"] == "SHT_RELA":
        if section["sh_entsize"] != 24 or section["sh_size"] % 24:
            raise dep.InventoryError("invalid RELA section entry size")
        if section["sh_size"] // 24 > MAX_RELOCATIONS:
            raise dep.InventoryError("relocation count budget exceeded")
        count = int(section["sh_size"]) // 24
        if budget is not None:
            budget.reserve_bytes(int(section["sh_size"]))
        def rows():
            for r in section.iter_relocations():
                if budget is not None:
                    budget.step()
                yield int(r["r_offset"]), int(r["r_info"]), int(r["r_addend"])
        return rows()
    if section["sh_type"] == 0x60000002:  # SHT_ANDROID_RELA (APS2)
        size = int(section["sh_size"])
        if budget is not None:
            budget.reserve_bytes(size)
        data = section.data()
        if len(data) != size:
            raise dep.InventoryError("truncated packed relocation section")
        return packed_rela(data, budget)
    if section["sh_type"] in ("SHT_RELR",0x6fffff00):
        size = int(section["sh_size"])
        if budget is not None:
            budget.reserve_bytes(size)
        data = section.data()
        if len(data) != size:
            raise dep.InventoryError("truncated RELR section")
        return relr_rows(data, budget)
    raise dep.InventoryError("unsupported import relocation format")


def relocation_sections(elf, budget=None):
    """Dynamic addresses/sizes are authoritative, not conventional section names.

    This bounded prototype explicitly rejects sectionless and REL layouts rather
    than reporting a partial import plan. RELR is covered but has no symbols.
    """
    entries,loads=dep.dynamic_entries(elf, budget)
    fields={"DT_RELA","DT_RELASZ","DT_RELAENT","DT_JMPREL","DT_PLTRELSZ","DT_PLTREL",
            "DT_ANDROID_RELA","DT_ANDROID_RELASZ","DT_SYMTAB","DT_SYMENT","DT_STRTAB","DT_STRSZ",
            "DT_REL","DT_RELSZ","DT_RELENT","DT_ANDROID_REL","DT_ANDROID_RELSZ",
            "DT_RELR","DT_RELRSZ","DT_RELRENT","DT_ANDROID_RELR","DT_ANDROID_RELRSZ","DT_ANDROID_RELRENT"}
    values={}
    for tag in entries:
        key=tag.d_tag
        if key in fields:
            if key in values: raise dep.InventoryError("duplicate dynamic relocation metadata")
            values[key]=int(tag.d_val)
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
        if values[size] > MAX_RELOCATION_BYTES:
            raise dep.InventoryError("relocation byte budget exceeded")
        if kind=="SHT_RELA" and (values[size]%24 or values.get("DT_RELAENT")!=24):
            raise dep.InventoryError("invalid RELA entry metadata")
        if address=="DT_JMPREL" and values.get("DT_PLTREL")!=7:
            raise dep.InventoryError("non-RELA PLT relocation table")
        if kind in ("SHT_RELR",0x6fffff00) and (values[size]%8 or values.get(address.replace("RELR","RELRENT"))!=8):
            raise dep.InventoryError("invalid RELR entry metadata")
        specs.append((values[address],values[size],kind))
    if not specs or values.get("DT_SYMENT")!=24 or "DT_SYMTAB" not in values or values.get("DT_STRTAB",0)<=0 or values.get("DT_STRSZ",0)<=0:
        raise dep.InventoryError("missing relocation/symbol authority")
    if len(specs) > MAX_RELOCATION_TABLES:
        raise dep.InventoryError("relocation table count budget exceeded")
    if not 0 < elf.num_sections() <= dep.MAX_SECTION_HEADERS:
        raise dep.InventoryError("section header budget exceeded")
    section_count = elf.num_sections()
    if budget is not None:
        budget.step(section_count)
    sections=list(elf.iter_sections())
    tables=[]
    for address,size,kind in specs:
        found=[(i,s) for i,s in enumerate(sections) if s["sh_type"]==kind and
               s["sh_addr"]==address and s["sh_size"]==size and s["sh_flags"]&2]
        if len(found)!=1: raise dep.InventoryError("dynamic relocation table missing/ambiguous in sections")
        i,s=found[0]
        if dep.runtime_file_offset(address,size,loads) != s["sh_offset"]:
            raise dep.InventoryError("relocation table effective file correspondence mismatch")
        if kind == "SHT_RELA" and s["sh_entsize"] != 24:
            raise dep.InventoryError("RELA section entry size differs from dynamic authority")
        if kind in ("SHT_RELR",0x6fffff00):
            if s["sh_link"]!=0 or s["sh_entsize"]!=8:
                raise dep.InventoryError("RELR table must not name symbols")
        else:
            symbols=elf.get_section(s["sh_link"])
            if symbols["sh_type"]!="SHT_DYNSYM" or symbols["sh_addr"]!=values["DT_SYMTAB"] or symbols["sh_entsize"]!=24:
                raise dep.InventoryError("dynamic relocation symbol table mismatch")
            if symbols["sh_size"]<=0 or symbols["sh_size"]>MAX_SYMBOL_BYTES or symbols["sh_size"]%24 or not symbols["sh_flags"]&2:
                raise dep.InventoryError("invalid dynamic symbol extent")
            validate_section_storage(symbols,loads)
            strings=elf.get_section(symbols["sh_link"])
            if strings["sh_type"]!="SHT_STRTAB" or not strings["sh_flags"]&2 or strings["sh_addr"]!=values["DT_STRTAB"] or strings["sh_size"]!=values["DT_STRSZ"]:
                raise dep.InventoryError("dynamic symbol string authority mismatch")
            if not 0 < strings["sh_size"] <= dep.MAX_DYNAMIC_STRING_BYTES:
                raise dep.InventoryError("dynamic symbol string budget exceeded")
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
    if section["sh_flags"]&0x800 or not 0<size<=dep.MAX_FILE_BYTES or address<0 or address+size>=(1<<64):
        raise dep.InventoryError("invalid dynamic section byte extent")
    if dep.runtime_file_offset(address,size,loads) != section["sh_offset"]:
        raise dep.InventoryError("dynamic section effective file correspondence mismatch")


def slot_file_correspondence(offset, base, loads, mappings, budget=None):
    index = mappings if isinstance(mappings, MappingIndex) else MappingIndex(mappings)
    runtime = loads if isinstance(loads, RuntimeFileIndex) else RuntimeFileIndex(loads, budget)
    if budget is not None:
        budget.step()
    owner_row = index.containing(base + offset, 8)
    if owner_row is None or not owner_row[3]["permissions"].startswith("r"):
        raise dep.InventoryError("slot not in one readable file-backed segment/mapping")
    m=owner_row[3]
    if runtime.file_offset(offset, 8) != m["offset"]+base+offset-m["start"]:
        raise dep.InventoryError("slot mapped file offset differs from ELF segment")


def checked_runs(slots, mappings, budget=None):
    """Coalesce only close, same-readable-mapping slots; hard bound all reads."""
    budget = budget or WorkBudget()
    index = MappingIndex(mappings, budget)
    runs = []
    last_address = None
    for slot in sorted(slots, key=lambda s: s["address"]):
        budget.step()
        address = slot["address"]
        if type(address) is not int or not 0 < address < (1 << 56) or address % 8:
            raise dep.InventoryError("invalid import pointer address")
        if address == last_address:
            raise dep.InventoryError("duplicate import pointer slot")
        last_address = address
        owner_row = index.containing(address, 8)
        if owner_row is None or not owner_row[3]["permissions"].startswith("r"):
            raise dep.InventoryError("import pointer not in exactly one readable source mapping")
        owner = owner_row[3]
        if (runs and address <= runs[-1]["end"] + 64 and
                address+8-runs[-1]["start"] <= MAX_SPAN and
                runs[-1]["owner"] == owner):
            runs[-1]["end"] = address+8
        else:
            runs.append({"start": address, "end": address+8, "owner": owner})
            if len(runs) > MAX_POINTER_COMMANDS:
                raise dep.InventoryError("pointer command count budget exceeded")
        slot["runIndex"] = len(runs) - 1
    if sum(r["end"]-r["start"] for r in runs) > MAX_MODULE_READ:
        raise dep.InventoryError("module read budget exceeded")
    return runs


def canonical_load_bias(loads, mappings, budget=None):
    runtime = RuntimeFileIndex(loads, budget)
    zeros = [mapping for mapping in mappings if mapping["offset"] == 0]
    anchors = [index for index, load in enumerate(loads)
               if int(load["p_offset"]) == 0 and int(load["p_vaddr"]) == 0]
    if (len(zeros) != 1 or len(anchors) != 1 or runtime.file_offset(0, 1) != 0 or
            runtime.effective_owner(0, 1) != anchors[0]):
        raise dep.InventoryError("unsupported or ambiguous load bias")
    return zeros[0]["start"], runtime


def import_slots(data, mappings, budget=None):
    budget = budget or WorkBudget()
    from elftools.elf.elffile import ELFFile
    budget.reserve_bytes(len(data))
    dep.elf_metadata(data)
    elf = ELFFile(io.BytesIO(data))
    budget.step(elf.num_segments() + elf.num_sections())
    loads = [p for p in elf.iter_segments() if p["p_type"] == "PT_LOAD"]
    base, runtime = canonical_load_bias(loads, mappings, budget)
    mapping_index = MappingIndex(mappings, budget)
    slots = []
    relocation_count = 0
    for _,section in relocation_sections(elf, budget):
        symbols = elf.get_section(section["sh_link"])
        strings = None
        symbol_data = None
        if section["sh_type"] not in ("SHT_RELR",0x6fffff00):
            strings_section = elf.get_section(symbols["sh_link"])
            strings_size = int(strings_section["sh_size"])
            symbol_size = int(symbols["sh_size"])
            budget.reserve_bytes(strings_size)
            strings = strings_section.data()
            budget.reserve_bytes(symbol_size)
            symbol_data = symbols.data()
            if len(strings) != strings_size or len(symbol_data) != symbol_size:
                raise dep.InventoryError("truncated dynamic symbol authority")
        symbol_count = int(symbols["sh_size"]) // 24 if strings is not None else 0
        budget.step(symbol_count)
        if strings is not None and (symbol_count <= 0 or symbol_count > MAX_SYMBOLS or len(symbol_data) != symbol_count * 24):
            raise dep.InventoryError("dynamic symbol budget/mismatch")
        names = {}
        for offset, info, _ in relocation_rows(section, budget):
            relocation_count += 1
            if relocation_count > MAX_RELOCATIONS:
                raise dep.InventoryError("aggregate relocation budget exceeded")
            # AArch64 GLOB_DAT / JUMP_SLOT. Never read RELATIVE data/ink planes.
            if info & 0xffffffff not in (1025, 1026):
                continue
            if info >> 32 >= symbol_count:
                raise dep.InventoryError("relocation symbol index out of range")
            # Parse only the validated record, without get_symbol() resolving a
            # string through its own fallback before our bound check.
            start=(info>>32)*24
            symbol=elf.structs.Elf_Sym.parse(symbol_data[start:start+24])
            name_offset=int(symbol["st_name"])
            if name_offset not in names:
                names[name_offset] = dep.bounded_string(strings, name_offset)
            name=names[name_offset]
            slot_file_correspondence(offset, base, runtime, mapping_index, budget)
            if len(slots) >= MAX_IMPORT_SLOTS:
                raise dep.InventoryError("import slot result budget exceeded")
            slots.append({"symbol": name, "symbolType": symbol["st_info"]["type"],
                          "binding": symbol["st_info"]["bind"],
                          "undefined": symbol["st_shndx"] == "SHN_UNDEF",
                          "rva": offset, "address": base+offset})
    if not slots:
        raise dep.InventoryError("no supported import relocation slots")
    return slots, checked_runs(slots, mappings, budget)


def target_owner(pointer, all_maps, budget=None):
    if budget is not None:
        budget.step()
    if pointer == 0:
        return {"status": "null", "paths": []}
    index = all_maps if isinstance(all_maps, MappingIndex) else MappingIndex(all_maps)
    row = index.containing(pointer)
    return ({"status": "unresolved_target", "paths": []} if row is None else
            {"status": "unique_mapped_target", "paths": [row[2]]})


def inventory_mapping_authority(inv, budget=None):
    maps = dep.validate_mapping_set(inv.get("filteredMappings"))
    if budget is not None:
        budget.step(sum(len(records) for records in maps.values()) + len(maps))
    digest = dep.mapping_set_digest(maps)
    if inv.get("filteredMapSetSha256") != digest:
        raise dep.InventoryError("filtered mapping authority digest mismatch")
    return maps, digest


def authenticate_inventory_raw_maps(inv, authority, budget=None):
    """Consume both exact raw-map witnesses bound by inventory-v4.

    The dependency inventory's filtered JSON is not independent authority for
    what `/proc/<pid>/maps` contained.  Re-read both terminal artifacts through
    the retained evidence directory, require byte identity, authenticate their
    exact LF wire, and independently derive the serialized filtered set.
    """
    if not isinstance(authority, dep.EvidenceDirectory):
        raise dep.InventoryError("invalid raw-map evidence authority")
    size = inv.get("completeRawMapsBytes")
    expected_digest = inv.get("completeRawMapsSha256")
    if (type(size) is not int or not 0 < size <= dep.MAX_RAW_MAP_BYTES or
            type(expected_digest) is not str or
            dep.re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None):
        raise dep.InventoryError("invalid inventory raw-map authority")
    before = authority.read("maps-before.txt", dep.MAX_RAW_MAP_BYTES,
                            expected_size=size, budget=budget)
    after = authority.read("maps-after.txt", dep.MAX_RAW_MAP_BYTES,
                           expected_size=size, budget=budget)
    if before != after:
        raise dep.InventoryError("inventory raw-map witnesses differ")
    if (dep.complete_map_digest(before) != expected_digest or
            dep.complete_map_digest(after) != expected_digest):
        raise dep.InventoryError("inventory raw-map witness digest mismatch")
    parsed = dep.validate_mapping_set(dep.mapped_libraries(
        before.decode("utf-8", errors="strict")))
    serialized, serialized_digest = inventory_mapping_authority(inv, budget)
    if parsed != serialized:
        raise dep.InventoryError("raw maps differ from filtered mapping authority")
    return before, serialized, serialized_digest


def require_stable_mapping_set(live_maps, inventory_maps, expected_digest):
    live = dep.validate_mapping_set(live_maps)
    if live != inventory_maps or dep.mapping_set_digest(live) != expected_digest:
        raise dep.InventoryError("complete filtered library mapping set changed")
    return live


def require_inventory_raw_map_digest(inv, live_digest):
    expected = inv.get("completeRawMapsSha256")
    if (type(live_digest) is not str or
            dep.re.fullmatch(r"[0-9a-f]{64}", live_digest) is None or
            live_digest != expected):
        raise dep.InventoryError("live process maps differ from inventory raw authority")
    return live_digest


def authenticate_local_inventory(inv, complete_maps, source, budget=None, authority=None):
    """Authenticate every owner-eligible ELF and rebuild closure from its bytes."""
    budget = budget or WorkBudget()
    libraries = inv.get("libraries")
    if type(libraries) is not dict or not libraries or not set(libraries) <= set(complete_maps):
        raise dep.InventoryError("invalid authenticated binding-owner inventory")
    parsed = {}
    data_by_path = {}
    derived_fields = ("sha256", "bytes", "soname", "needed",
                      "initArrayEntries", "initFunctions")
    for path in sorted(libraries):
        budget.step()
        meta = libraries[path]
        filename = meta["localFile"]
        if not dep.re.fullmatch(r"[0-9a-f]{16}\.so", filename):
            raise dep.InventoryError("unsupported local evidence filename")
        data = (authority.read(filename, expected_size=meta["bytes"], budget=budget)
                if authority is not None else dep.read_bounded(
                    source.parent / filename, expected_size=meta["bytes"], budget=budget))
        budget.reserve_bytes(len(data))
        actual = dep.elf_metadata(data)
        budget.checkpoint()
        if any(not dep.exact_equal(actual[field], meta[field]) for field in derived_fields):
            raise dep.InventoryError("serialized library metadata differs from reparsed ELF")
        if path == dep.ROOT_LIBRARY and actual["sha256"] != dep.ROOT_SHA256:
            raise dep.InventoryError("unpinned native engine")
        parsed[path] = actual
        data_by_path[path] = data

    # Serialized `needed` and edge records are never closure authority here.
    # Start at the pinned root and follow only reparsed DT_NEEDED names through
    # the complete authenticated mapping set.
    reachable = {dep.ROOT_LIBRARY}
    pending = [dep.ROOT_LIBRARY]
    candidate_index = dep.dependency_candidate_index(complete_maps, budget)
    while pending:
        requester = pending.pop()
        for needed in parsed[requester]["needed"]:
            budget.step()
            for candidate in dep.dependency_candidates(
                    needed, complete_maps, candidate_index, budget):
                if candidate not in parsed:
                    raise dep.InventoryError("reparsed root closure lacks authenticated local ELF")
                if candidate not in reachable:
                    reachable.add(candidate)
                    pending.append(candidate)
    if reachable != set(parsed):
        raise dep.InventoryError("authenticated ELFs differ from reparsed root closure")
    return ({path: complete_maps[path] for path in sorted(reachable)}, data_by_path, parsed)


def authenticate_live_inventory(capture, pid, inv, owner_maps, data_by_path,
                                budget=None):
    """Recapture every owner ELF through its live mapped descriptor."""
    for path in sorted(owner_maps):
        if budget is not None:
            budget.step()
        allowance = inv["libraries"][path]["bytes"]
        command = dep.mapped_capture_command(pid, owner_maps[path], allowance)
        if budget is not None:
            budget.reserve_bytes(allowance + 512)
        payload = (capture(command, allowance + 512) if budget is None else
                   capture(command, allowance + 512, budget.remaining()))
        live, identity = dep.parse_mapped_capture(payload, owner_maps[path], allowance)
        if live != data_by_path[path] or identity != inv["libraries"][path]["mappedFileIdentity"]:
            raise dep.InventoryError("live mapped ELF differs from authenticated local evidence")


def authenticate_final_window(verify, authenticate):
    """Require one identical complete process/map authority around recapture."""
    before = verify()
    authenticate()
    after = verify()
    if not dep.exact_equal(before, after):
        raise dep.InventoryError("mapping authority changed during final recapture")
    return after


def require_drawpath_cmdline(value):
    return dep.require_drawpath_cmdline(value)


class PublicationReviewRequired(dep.InventoryError):
    """A terminal name may exist; an unattended retry is never safe."""


class StagedReport:
    """One retained, read-only stage awaiting its terminal no-replace commit."""
    def __init__(self, output, descriptor=None, authority=None, authorities=None,
                 temporary_name=None, windows_handle=None):
        self.output = Path(output)
        self.descriptor = descriptor
        self.authority = authority
        self.authorities = ([authority] if authorities is None and authority is not None
                            else list(authorities or []))
        self.temporary_name = temporary_name
        self.windows_handle = windows_handle
        self._publication_state = "private"
        self.size = 0
        self.sha256 = None

    @property
    def retained(self):
        return self.descriptor is not None or self.windows_handle is not None

    @property
    def committed(self):
        """Compatibility view of the explicit publication state."""
        return self._publication_state == "published"

    @property
    def publication_state(self):
        return self._publication_state

    def begin_commit(self):
        if self._publication_state != "private":
            raise dep.InventoryError("invalid publication-state transition")
        # Set before the syscall.  If control does not return normally, the
        # retained Windows handle must not be marked delete-on-close: the
        # syscall may already have made the terminal name visible.
        self._publication_state = "outcome-unknown"

    def mark_published(self):
        if self._publication_state != "outcome-unknown":
            raise dep.InventoryError("invalid publication-state transition")
        self._publication_state = "published"

    def mark_collision(self):
        if self._publication_state != "outcome-unknown":
            raise dep.InventoryError("invalid publication-state transition")
        # A no-replace collision proves this retained private inode/handle was
        # not installed.  Its private stage may be retired, but the existing
        # terminal name still makes an automatic retry unsafe.
        self._publication_state = "collision"

    def _windows_dispose(self):
        if self.windows_handle is None:
            return
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                       ctypes.c_void_p, wintypes.DWORD]
        kernel.SetFileInformationByHandle.restype = wintypes.BOOL
        class Disposition(ctypes.Structure):
            _fields_ = [("DeleteFile", wintypes.BOOL)]
        disposition = Disposition(True)
        if not kernel.SetFileInformationByHandle(
                self.windows_handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise dep.InventoryError("could not retire private Windows binding stage")

    def close(self):
        errors = []
        try:
            if self.windows_handle is not None:
                try:
                    if self._publication_state in ("private", "collision"):
                        self._windows_dispose()
                except Exception as error:
                    errors.append(error)
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                from ctypes import wintypes
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel.CloseHandle.restype = wintypes.BOOL
                if not kernel.CloseHandle(self.windows_handle):
                    errors.append(dep.InventoryError("could not close Windows binding stage"))
                self.windows_handle = None
            if self.descriptor is not None:
                try:
                    os.close(self.descriptor)
                except OSError as error:
                    errors.append(error)
                self.descriptor = None
        finally:
            for authority in reversed(self.authorities):
                try:
                    authority.__exit__(None, None, None)
                except Exception as error:
                    errors.append(error)
            self.authorities = []
            self.authority = None
        # Once commit is logically published, cleanup cannot turn success into an
        # ambiguous failure that invites an unsafe retry.
        # Cleanup after a published, outcome-unknown, or collision result is
        # diagnostic only.  It must neither delete a possible authority nor
        # replace a success/nonretryable result with ordinary exit status 1.
        if errors and self._publication_state == "private":
            raise errors[0]


class _WindowsDirectoryAuthority:
    """One absolute, non-reparse directory handle which denies delete sharing."""
    def __init__(self, path):
        self.path = Path(path).absolute()
        self.directory = None

    def __enter__(self):
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
        kernel.GetFileAttributesW.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        invalid = wintypes.HANDLE(-1).value
        attributes = kernel.GetFileAttributesW(str(self.path))
        if (attributes == 0xffffffff or not attributes & 0x10 or
                attributes & 0x400):
            raise dep.InventoryError("unsafe Windows output directory component")
        # Share read/write, deliberately not delete: the component cannot be
        # renamed or removed while the publication authority is retained.
        handle = kernel.CreateFileW(str(self.path), 0x00100081, 3, None, 3,
                                    0x02000000 | 0x00200000, None)
        if handle == invalid or not handle:
            raise OSError(ctypes.get_last_error(),
                          f"could not retain Windows output directory component {self.path}")
        self._kernel = kernel
        self.directory = handle
        try:
            if _windows_final_path(handle) != self.path:
                raise dep.InventoryError("Windows output directory resolved through another path")
        except Exception:
            self.directory = None
            kernel.CloseHandle(handle)
            raise
        return self

    def __exit__(self, *_):
        if self.directory is not None:
            handle, self.directory = self.directory, None
            if not self._kernel.CloseHandle(handle):
                raise dep.InventoryError("could not close Windows output authority")


def _windows_authority_chain(path):
    """Retain the checked output directory and reauthenticate its final path.

    A user-profile ancestor can already be open elsewhere with DELETE access,
    making a new deny-delete handle to that ancestor impossible.  The leaf is
    therefore retained with delete sharing denied, and its handle-resolved path
    is checked immediately before and after the handle-relative commit.
    """
    path = Path(path).absolute()
    if not path.is_absolute() or not path.parts:
        raise dep.InventoryError("invalid Windows output parent")
    authority = _WindowsDirectoryAuthority(path)
    try:
        authority.__enter__()
        return [authority]
    except Exception:
        try:
            authority.__exit__(None, None, None)
        except Exception:
            pass
        raise


def _windows_create_stage(output, authorities):
    """Create an exclusive stage after retaining every output-path component."""
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    invalid = wintypes.HANDLE(-1).value
    for _ in range(64):
        name = ".bindings-" + secrets.token_hex(16) + ".tmp"
        # READ/WRITE/DELETE/SYNCHRONIZE, share none, FILE_CREATE.  The stage
        # cannot be opened, renamed, deleted, or modified through its name.
        handle = kernel.CreateFileW(str(output.parent / name), 0xC0110000, 0,
                                    None, 1, 0x80000100, None)
        if handle != invalid and handle:
            return handle, name
        error = ctypes.get_last_error()
        if error not in (80, 183):
            raise OSError(error, "could not create private Windows binding stage")
    raise dep.InventoryError("could not allocate private Windows binding stage")


def _windows_write(handle, payload):
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.WriteFile.restype = wintypes.BOOL
    at = 0
    while at < len(payload):
        chunk = payload[at:at + 65536]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not kernel.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
            raise OSError(ctypes.get_last_error(), "could not write Windows binding stage")
        if written.value != len(chunk):
            raise dep.InventoryError("short Windows binding stage write")
        at += written.value


def _windows_flush(handle):
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel.FlushFileBuffers.restype = wintypes.BOOL
    if not kernel.FlushFileBuffers(handle):
        raise OSError(ctypes.get_last_error(), "could not flush Windows binding stage")


def _windows_hash_handle(handle, expected_size):
    """Hash exactly one retained Windows stage without reopening its name."""
    from ctypes import wintypes
    if type(expected_size) is not int or expected_size < 0 or expected_size > MAX_REPORT_BYTES:
        raise dep.InventoryError("invalid retained Windows stage size")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    kernel.GetFileSizeEx.restype = wintypes.BOOL
    kernel.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                        ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    kernel.SetFilePointerEx.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.ReadFile.restype = wintypes.BOOL
    size = ctypes.c_longlong()
    if not kernel.GetFileSizeEx(handle, ctypes.byref(size)) or size.value != expected_size:
        raise dep.InventoryError("retained Windows stage size changed")
    position = ctypes.c_longlong()
    if not kernel.SetFilePointerEx(handle, 0, ctypes.byref(position), 0):
        raise OSError(ctypes.get_last_error(), "could not rewind retained Windows stage")
    digest = hashlib.sha256()
    total = 0
    remaining = expected_size + 1
    while remaining:
        amount = min(65536, remaining)
        buffer = ctypes.create_string_buffer(amount)
        count = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, amount, ctypes.byref(count), None):
            raise OSError(ctypes.get_last_error(), "could not read retained Windows stage")
        if not count.value:
            break
        digest.update(buffer.raw[:count.value])
        total += count.value
        remaining -= count.value
    if total != expected_size:
        raise dep.InventoryError("retained Windows stage content length changed")
    return digest.hexdigest()


def _windows_rename_no_replace(handle, parent_handle, destination):
    """Rename the retained handle to one checked absolute path, no replace."""
    from ctypes import wintypes
    destination = Path(destination).absolute()
    name = destination.name
    if (not destination.is_absolute() or name in ("", ".", "..") or
            "\\" in name or "/" in name or "\0" in name or ":" in name):
        raise dep.InventoryError("invalid absolute binding output")

    class RenameInfo(ctypes.Structure):
        _fields_ = [("ReplaceIfExists", ctypes.c_ubyte),
                    ("RootDirectory", wintypes.HANDLE),
                    ("FileNameLength", wintypes.DWORD),
                    ("FileName", wintypes.WCHAR * 1)]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p),
                    ("Information", ctypes.c_size_t)]

    encoded = name.encode("utf-16-le")
    offset = RenameInfo.FileName.offset
    storage = ctypes.create_string_buffer(max(
        ctypes.sizeof(RenameInfo), RenameInfo.FileName.offset + len(encoded)))
    info = ctypes.cast(storage, ctypes.POINTER(RenameInfo)).contents
    info.ReplaceIfExists = 0
    # The leaf parent is retained; the NT rename uses it as the actual root
    # authority rather than merely checking it around an absolute-path rename.
    info.RootDirectory = parent_handle
    info.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(storage) + offset, encoded, len(encoded))
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtSetInformationFile.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(IoStatusBlock), ctypes.c_void_p,
        wintypes.ULONG, ctypes.c_int]
    ntdll.NtSetInformationFile.restype = wintypes.LONG
    status = IoStatusBlock()
    result = ntdll.NtSetInformationFile(
        handle, ctypes.byref(status), storage, len(storage), 10)  # FileRenameInformation
    code = result & 0xffffffff
    if code:
        if code == 0xc0000035:  # STATUS_OBJECT_NAME_COLLISION
            raise FileExistsError(183, "output already exists", name)
        raise OSError(code, "handle-relative report rename failed")


def _windows_final_path(handle):
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    needed = kernel.GetFinalPathNameByHandleW(handle, None, 0, 0)
    if not needed:
        raise OSError(ctypes.get_last_error(), "could not resolve committed report handle")
    buffer = ctypes.create_unicode_buffer(needed + 1)
    written = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise OSError(ctypes.get_last_error(), "could not resolve committed report path")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value).absolute()


def _hash_posix_descriptor(descriptor, size):
    digest = hashlib.sha256()
    at = 0
    while at < size:
        chunk = os.pread(descriptor, min(65536, size - at), at)
        if not chunk:
            raise dep.InventoryError("truncated anonymous binding stage")
        digest.update(chunk)
        at += len(chunk)
    return digest.hexdigest()


def _posix_link_anonymous(descriptor, directory, output_name):
    """Publish the anonymous inode; the proc-fd fallback is still fd-authority."""
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_int]
    linkat.restype = ctypes.c_int
    if linkat(descriptor, b"", directory, os.fsencode(output_name), 0x1000) == 0:
        return
    error = ctypes.get_errno()
    if error not in (errno.EPERM, errno.ENOENT, errno.EINVAL,
                     getattr(errno, "EOPNOTSUPP", errno.EINVAL)):
        raise OSError(error, "anonymous report publication failed")
    # Unprivileged Linux may reject AT_EMPTY_PATH.  Following the proc-fd
    # magic link still names the retained descriptor, never a writable stage.
    if linkat(-100, os.fsencode(f"/proc/self/fd/{descriptor}"), directory,
              os.fsencode(output_name), 0x400) != 0:  # AT_SYMLINK_FOLLOW
        raise OSError(ctypes.get_errno(), "anonymous report publication failed")


def _same_parent_path(authority, path):
    try:
        held = os.fstat(authority.directory)
        with dep.EvidenceDirectory(path) as current:
            named = os.fstat(current.directory)
        return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
    except (OSError, dep.InventoryError):
        return False


def stage_report(report, output, budget):
    """Encode and fsync the complete bounded report before the final window."""
    output = Path(output).absolute()
    output_name = output.name
    if (output_name in ("", ".", "..") or "/" in output_name or
            "\\" in output_name or "\0" in output_name or
            (os.name == "nt" and ":" in output_name)):
        raise dep.InventoryError("invalid direct-child binding output name")
    if not output.parent.is_dir():
        raise dep.InventoryError("output parent is not a directory")
    authority = None
    authorities = []
    descriptor = None
    windows_handle = None
    temporary_name = None
    if os.name == "posix":
        authority = dep.EvidenceDirectory(output.parent)
        authority.__enter__()
        authorities = [authority]
        try:
            anonymous = getattr(os, "O_TMPFILE", 0)
            if not anonymous:
                raise dep.InventoryError("anonymous report staging is unavailable")
            descriptor = os.open(".", os.O_RDWR | os.O_CLOEXEC | anonymous,
                                 0o600, dir_fd=authority.directory)
        except Exception:
            authority.__exit__(None, None, None)
            raise
    elif os.name == "nt":
        authorities = _windows_authority_chain(output.parent)
        authority = authorities[-1]
        try:
            windows_handle, temporary_name = _windows_create_stage(output, authorities)
        except Exception:
            for item in reversed(authorities):
                item.__exit__(None, None, None)
            raise
    else:
        raise dep.InventoryError("unsupported report publication platform")
    total = 0
    digest = hashlib.sha256()
    staged = StagedReport(output, descriptor, authority, authorities,
                          temporary_name, windows_handle)
    try:
        def write(chunk):
            nonlocal total
            if total > MAX_REPORT_BYTES - len(chunk):
                raise dep.InventoryError("binding report exceeds publication cap")
            budget.reserve_bytes(len(chunk))
            if os.name == "posix":
                stream.write(chunk)
            else:
                _windows_write(windows_handle, chunk)
            digest.update(chunk)
            total += len(chunk)

        if os.name == "posix":
            stream = os.fdopen(os.dup(descriptor), "wb", closefd=True)
        else:
            stream = None
        try:
            for text in json.JSONEncoder(indent=2, ensure_ascii=True).iterencode(report):
                write(text.encode("ascii"))
            if total == MAX_REPORT_BYTES:
                raise dep.InventoryError("binding report exceeds publication cap")
            write(b"\n")
            if stream is not None:
                stream.flush()
                os.fsync(stream.fileno())
            else:
                _windows_flush(windows_handle)
        finally:
            if stream is not None:
                stream.close()
        if os.name == "posix":
            opened = os.fstat(descriptor)
            if opened.st_size != total or not stat.S_ISREG(opened.st_mode):
                raise dep.InventoryError("anonymous binding stage identity mismatch")
            # Remove ordinary write access and drop our writable descriptor
            # before entering the final-live window.  The commit rehash below
            # remains the authority against privileged/same-UID tampering.
            os.fchmod(descriptor, stat.S_IRUSR)
            readonly = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC)
            reopened = os.fstat(readonly)
            if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                    (reopened.st_dev, reopened.st_ino, reopened.st_size)):
                os.close(readonly)
                raise dep.InventoryError("anonymous binding stage reopen mismatch")
            os.close(descriptor)
            descriptor = readonly
            staged.descriptor = readonly
            if _hash_posix_descriptor(readonly, total) != digest.hexdigest():
                raise dep.InventoryError("anonymous binding stage content mismatch")
        budget.checkpoint()
        staged.size = total
        staged.sha256 = digest.hexdigest()
        return staged
    except Exception:
        staged.close()
        raise


def stage_bytes(payload, output, budget, authority):
    """Stage arbitrary bounded bytes under one caller-retained parent authority."""
    if type(payload) is not bytes or not payload or len(payload) > MAX_REPORT_BYTES:
        raise dep.InventoryError("invalid bounded publication payload")
    if budget is not None:
        budget.reserve_bytes(len(payload))
        budget.checkpoint()
    output = Path(output).absolute()
    name = output.name
    if (name in ("", ".", "..") or "/" in name or "\\" in name or "\0" in name or
            (os.name == "nt" and ":" in name)):
        raise dep.InventoryError("invalid direct-child publication name")
    if authority is None or authority.directory is None:
        raise dep.InventoryError("missing retained publication-directory authority")
    if os.name == "posix":
        if not _same_parent_path(authority, output.parent):
            raise dep.InventoryError("publication parent authority changed before staging")
        anonymous = getattr(os, "O_TMPFILE", 0)
        if not anonymous:
            raise dep.InventoryError("anonymous byte staging is unavailable")
        descriptor = os.open(".", os.O_RDWR | os.O_CLOEXEC | anonymous,
                             0o600, dir_fd=authority.directory)
        staged = StagedReport(output, descriptor=descriptor, authority=authority,
                              authorities=[])
        try:
            at = 0
            while at < len(payload):
                written = os.write(descriptor, payload[at:at + 65536])
                if written <= 0:
                    raise dep.InventoryError("short staged byte write")
                at += written
            os.fsync(descriptor)
            os.fchmod(descriptor, stat.S_IRUSR)
            readonly = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC)
            before, after = os.fstat(descriptor), os.fstat(readonly)
            if ((before.st_dev, before.st_ino, before.st_size) !=
                    (after.st_dev, after.st_ino, after.st_size)):
                os.close(readonly)
                raise dep.InventoryError("staged byte authority changed during reopen")
            os.close(descriptor)
            staged.descriptor = readonly
        except Exception:
            staged.close()
            raise
    elif os.name == "nt":
        if _windows_final_path(authority.directory) != output.parent:
            raise dep.InventoryError("publication parent authority changed before staging")
        handle, temporary_name = _windows_create_stage(output, [authority])
        staged = StagedReport(output, authority=authority, authorities=[],
                              temporary_name=temporary_name, windows_handle=handle)
        try:
            _windows_write(handle, payload)
            _windows_flush(handle)
        except Exception:
            staged.close()
            raise
    else:
        raise dep.InventoryError("unsupported byte-publication platform")
    staged.size = len(payload)
    staged.sha256 = hashlib.sha256(payload).hexdigest()
    if os.name == "posix":
        if _hash_posix_descriptor(staged.descriptor, staged.size) != staged.sha256:
            staged.close()
            raise dep.InventoryError("staged publication bytes changed")
    elif _windows_hash_handle(staged.windows_handle, staged.size) != staged.sha256:
        staged.close()
        raise dep.InventoryError("staged publication bytes changed")
    return staged


def verify_committed_stage(staged):
    """Rebind one named output to its still-retained exact byte authority."""
    if not isinstance(staged, StagedReport) or not staged.committed or staged.authority is None:
        raise dep.InventoryError("invalid committed publication stage")
    try:
        if os.name == "posix":
            opened = os.fstat(staged.descriptor)
            if (_hash_posix_descriptor(staged.descriptor, staged.size) != staged.sha256 or
                    not _same_parent_path(staged.authority, staged.output.parent)):
                raise dep.InventoryError("retained committed publication changed")
            checked = os.open(staged.output.name, os.O_RDONLY | os.O_CLOEXEC |
                              os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
                              dir_fd=staged.authority.directory)
            try:
                named = os.fstat(checked)
                if ((named.st_dev, named.st_ino, named.st_size) !=
                        (opened.st_dev, opened.st_ino, opened.st_size) or
                        _hash_posix_descriptor(checked, staged.size) != staged.sha256):
                    raise dep.InventoryError("committed publication name or bytes changed")
            finally:
                os.close(checked)
        elif os.name == "nt":
            if (_windows_final_path(staged.authority.directory) != staged.output.parent or
                    _windows_final_path(staged.windows_handle) != staged.output or
                    _windows_hash_handle(staged.windows_handle, staged.size) != staged.sha256):
                raise dep.InventoryError("retained committed publication changed")
            # The retained stage was created with share mode zero.  Its final
            # path cannot be changed while this verification runs.
        else:
            raise dep.InventoryError("unsupported committed-publication platform")
    except BaseException as error:
        if isinstance(error, PublicationReviewRequired):
            raise
        raise PublicationReviewRequired(
            "published output authority is uncertain; review required") from error


def commit_report(staged):
    """Install one terminal name; never make a possible commit retryable."""
    if (not isinstance(staged, StagedReport) or
            staged.publication_state != "private"):
        raise dep.InventoryError("invalid staged binding report")
    output = staged.output
    if os.name == "nt":
        # Every fallible file-data operation and every validation that can be
        # performed before publication belongs before the rename syscall.
        try:
            resolved_parent = _windows_final_path(staged.authority.directory)
            expected_private = (output.parent / staged.temporary_name).absolute()
            resolved_private = _windows_final_path(staged.windows_handle)
        except BaseException as error:
            raise PublicationReviewRequired(
                "Windows publication parent or private name is uncertain; review required") \
                from error
        if resolved_parent != output.parent.absolute():
            raise PublicationReviewRequired(
                "output parent authority relocated; review required")
        if resolved_private != expected_private:
            raise PublicationReviewRequired(
                "private Windows stage name is uncertain; review required")
        _windows_flush(staged.windows_handle)
        if _windows_hash_handle(staged.windows_handle, staged.size) != staged.sha256:
            raise dep.InventoryError("retained Windows stage changed before commit")
        staged.begin_commit()
        try:
            _windows_rename_no_replace(
                staged.windows_handle, staged.authority.directory, output)
            # Keep the state transition inside the same BaseException bracket
            # as the syscall so an asynchronously delivered exception cannot
            # expose a terminal name as an ordinary failure.
            staged.mark_published()
        except FileExistsError as error:
            if staged.publication_state == "outcome-unknown":
                staged.mark_collision()
            raise PublicationReviewRequired(
                "output already exists; review required") from error
        except BaseException as error:
            raise PublicationReviewRequired(
                "Windows publication outcome is uncertain; review required") from error
        # NtSetInformationFile success is the logical commit, now recorded
        # before any post-commit name/parent diagnostics can fail.
        try:
            resolved_output = _windows_final_path(staged.windows_handle)
            if resolved_output != output.absolute():
                raise dep.InventoryError("committed Windows report path changed")
            if _windows_final_path(staged.authority.directory) != output.parent.absolute():
                raise dep.InventoryError("committed Windows output parent changed")
        except BaseException as error:
            if isinstance(error, PublicationReviewRequired):
                raise
            raise PublicationReviewRequired(
                "published Windows output authority is uncertain; review required") from error
        return

    if os.name == "posix":
        directory = staged.authority.directory
        output_name = output.name
        if output_name in ("", ".", "..") or "/" in output_name or "\\" in output_name:
            raise dep.InventoryError("binding output must be a direct child name")
        if not _same_parent_path(staged.authority, output.parent):
            raise PublicationReviewRequired(
                "output parent authority relocated; review required")
        opened = os.fstat(staged.descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_size != staged.size or
                _hash_posix_descriptor(staged.descriptor, staged.size) != staged.sha256):
            raise dep.InventoryError("anonymous report stage changed before commit")
        # Prove the parent is synchronizable before the terminal syscall.  A
        # second fsync after linkat is necessarily post-commit and therefore
        # has a distinct nonretryable error class.
        os.fsync(directory)
        staged.begin_commit()
        try:
            _posix_link_anonymous(staged.descriptor, directory, output_name)
            # Keep the state transition inside the same BaseException bracket
            # as the syscall so an asynchronously delivered exception cannot
            # expose a terminal name as an ordinary failure.
            staged.mark_published()
        except FileExistsError as error:
            if staged.publication_state == "outcome-unknown":
                staged.mark_collision()
            raise PublicationReviewRequired(
                "output already exists; review required") from error
        except BaseException as error:
            raise PublicationReviewRequired(
                "POSIX publication outcome is uncertain; review required") from error
        # linkat success is the logical commit.  Record it immediately.  From
        # here onward nothing may unlink the name or invite an automatic retry.
        try:
            linked = os.stat(output_name, dir_fd=directory, follow_symlinks=False)
            if (linked.st_dev, linked.st_ino, linked.st_size) != (
                    opened.st_dev, opened.st_ino, opened.st_size):
                raise dep.InventoryError("published report differs from retained stage")
            os.fsync(directory)
            if not _same_parent_path(staged.authority, output.parent):
                raise dep.InventoryError("output parent changed during report commit")
            rebound = os.stat(
                output_name, dir_fd=directory, follow_symlinks=False)
            if (rebound.st_dev, rebound.st_ino, rebound.st_size) != (
                    opened.st_dev, opened.st_ino, opened.st_size):
                raise dep.InventoryError("published report name changed")
        except BaseException as error:
            if isinstance(error, PublicationReviewRequired):
                raise
            raise PublicationReviewRequired(
                "published POSIX output durability or name is uncertain; review required") from error
        return

    raise dep.InventoryError("unsupported report publication platform")


def publish_after_final_window(report, output, budget, final_window):
    """Stage first, then run the final bracket and immediately terminal-commit."""
    staged = stage_report(report, output, budget)
    primary_error = None
    try:
        result = final_window()
        commit_report(staged)
        return result
    except BaseException as error:
        if (not isinstance(error, PublicationReviewRequired) and
                staged.publication_state != "private"):
            primary_error = PublicationReviewRequired(
                "publication crossed the terminal boundary; review required")
            raise primary_error from error
        primary_error = error
        raise
    finally:
        try:
            staged.close()
        except BaseException as cleanup_error:
            if primary_error is None:
                if staged.committed:
                    # A completed logical commit is success.  Cleanup-only
                    # diagnostics cannot invite a duplicate publication.
                    pass
                elif staged.publication_state != "private":
                    raise PublicationReviewRequired(
                        "publication cleanup outcome is uncertain; review required") \
                        from cleanup_error
                else:
                    raise
            try:
                primary_error.add_note(
                    "suppressed publication cleanup failure: " + str(cleanup_error))
            except (AttributeError, OSError, ValueError):
                pass


def publish_report(report, output, budget):
    """Compatibility wrapper used by focused publication tests."""
    return publish_after_final_window(report, output, budget, lambda: None)


def main():
    work = WorkBudget()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    work.checkpoint()
    # The dependency collector owns the shared authenticated source loader.
    # Establish it before admitting any local evidence or reading the device.
    authenticate_elftools(args.python_path)
    work.checkpoint()
    source = args.inventory.absolute()
    with dep.EvidenceDirectory(source.parent) as local_authority:
        inventory_bytes = local_authority.read(source.name,4*1024*1024,budget=work)
        work.reserve_bytes(len(inventory_bytes))
        inv = dep.validate_inventory_v4(dep.load_strict_json(inventory_bytes), work)
        _, inventory_maps, inventory_maps_digest = authenticate_inventory_raw_maps(
            inv, local_authority, work)
        work.checkpoint()
        owner_maps, local_data, _ = authenticate_local_inventory(
            inv, inventory_maps, source, work, local_authority)
    owner_index = MappingIndex(owner_maps, work)
    pid, start = inv["process"]["pid"], inv["process"]["startTime"]
    if type(pid) is not int or not 1 < pid < 4194304 or type(start) is not int or start <= 0:
        raise dep.InventoryError("invalid captured process identity")
    plans = {}
    total_slots = 0
    for path in MODULES:
        meta = inv["libraries"][path]
        authoritative_mappings = inventory_maps[path]
        identity=meta["mappedFileIdentity"]
        if identity.get("authority")!="proc-map-files-open-descriptor-v1" or identity["bytes"]!=meta["bytes"] or any(
                (int(m["device"].split(":")[0],16),int(m["device"].split(":")[1],16),m["inode"])!=
                (*[int(x,16) for x in identity["device"].split(":")],identity["inode"]) for m in authoritative_mappings):
            raise dep.InventoryError("inventory lacks exact mapped descriptor authority")
        slots, runs = import_slots(local_data[path], authoritative_mappings, work)
        total_slots += len(slots)
        if total_slots > MAX_TOTAL_IMPORT_SLOTS:
            raise dep.InventoryError("aggregate import slot result budget exceeded")
        plans[path] = {"slots": slots, "runs": runs}

    adb = str(args.adb.resolve(strict=True))
    def run(*command, output_limit=4*1024*1024):
        work.reserve_bytes(output_limit)
        result = dep.bounded_command([adb,"-s",dep.SERIAL,*command],
                                     output_limit, work.remaining())
        return result
    def capture(command, limit, timeout=None):
        # authenticate_live_inventory reserves this declared producer maximum.
        result = dep.bounded_command([adb,"-s",dep.SERIAL,"exec-out",command],
                                     limit, work.remaining() if timeout is None else
                                     min(timeout, work.remaining()))
        return result

    def verify_identity():
        if run("shell", "getprop", "ro.build.fingerprint", output_limit=4096).decode().strip() != dep.FINGERPRINT:
            raise dep.InventoryError("firmware changed")
        identity = dep.process_identity(run("exec-out", f"su -c 'cat /proc/{pid}/stat'", output_limit=4096).decode(), pid)
        cmdline = run("exec-out", f"su -c 'cat /proc/{pid}/cmdline'", output_limit=4096)
        require_drawpath_cmdline(cmdline)
        if identity != (pid, start):
            raise dep.InventoryError("native process changed")
        raw_maps = run("exec-out", f"su -c 'cat /proc/{pid}/maps'", output_limit=dep.MAX_RAW_MAP_BYTES)
        raw_maps_digest = dep.complete_map_digest(raw_maps)
        require_inventory_raw_map_digest(inv, raw_maps_digest)
        maps = require_stable_mapping_set(
            dep.mapped_libraries(raw_maps.decode("utf-8", errors="strict")),
            inventory_maps, inventory_maps_digest)
        if dep.process_identity(run("exec-out", f"su -c 'cat /proc/{pid}/stat'", output_limit=4096).decode(), pid) != identity:
            raise dep.InventoryError("native process changed during map capture")
        return {"process": [pid, start],
                "cmdlineSha256": hashlib.sha256(cmdline).hexdigest(),
                "rawMapsSha256": raw_maps_digest,
                "filteredMapSetSha256": inventory_maps_digest}

    initial_authority = verify_identity()
    authenticate_live_inventory(capture, pid, inv, owner_maps, local_data, work)
    results = {}
    for path, plan in plans.items():
        chunks = []
        for interval in plan["runs"]:
            work.step()
            address, size = interval["start"], interval["end"]-interval["start"]
            command = f"su -c 'dd if=/proc/{pid}/mem bs=1 skip={address} count={size} 2>/dev/null'"
            data = run("exec-out", command, output_limit=size)
            if len(data) != size or run("exec-out", command, output_limit=size) != data:
                raise dep.InventoryError("short or changing pointer capture")
            chunks.append((address, data))
        rows = []
        for slot in plan["slots"]:
            chunk_start, data = chunks[slot["runIndex"]]
            pointer = struct.unpack_from("<Q", data, slot["address"]-chunk_start)[0]
            public_slot = {key: value for key, value in slot.items() if key != "runIndex"}
            row = {**public_slot, "pointer": pointer,
                   **target_owner(pointer, owner_index, work)}
            if serialized_slot_bytes(row) > MAX_SERIALIZED_SLOT_BYTES:
                raise dep.InventoryError("serialized import slot exceeds derived bound")
            rows.append(row)
        results[path] = {"bytesReadPerCapture": sum(len(b) for _, b in chunks), "slots": rows}
        print("BINDING_READ", path.rsplit("/", 1)[-1], "slots="+str(len(rows)), flush=True)
    work.checkpoint()
    report_authority = verify_identity()
    report = {"schema": "native-loader-bindings-v1", "nativeStartAllowed": False,
              "inventorySha256": hashlib.sha256(inventory_bytes).hexdigest(),
              "process": inv["process"], "finalAuthority": report_authority,
              "modules": results,
              "notes": "Stable observed relocation targets only; no initializer/loader or full dependency-graph admission."}
    def final_window():
        final_authority = authenticate_final_window(
            verify_identity, lambda: authenticate_live_inventory(
                capture, pid, inv, owner_maps, local_data, work))
        if not dep.exact_equal(initial_authority, report_authority) or not dep.exact_equal(
                report_authority, final_authority):
            raise dep.InventoryError("complete native authority changed during binding collection")
        return final_authority

    publish_after_final_window(report, args.output, work, final_window)
    # The visible no-replace publication is terminal. This is not a power-loss
    # durability claim. A broken diagnostic stdout cannot turn success into a
    # retryable reported failure.
    _report_terminal_success("BINDINGS_COMPLETE native_start_allowed=false")


def _report_terminal_success(message):
    """Use the inventory collector's descriptor-safe terminal reporter."""
    dep._report_terminal_success(message)


def _run_cli(operation=main):
    """Map publication uncertainty/collision to a nonretryable process result."""
    try:
        operation()
        return 0
    except PublicationReviewRequired as exc:
        try:
            print("BINDINGS_PUBLICATION_NONRETRYABLE", str(exc), file=sys.stderr)
        except (OSError, ValueError):
            pass
        return 2
    except (ValueError, OSError, ImportError, KeyError, subprocess.SubprocessError) as exc:
        try:
            print("BINDINGS_FAILED", str(exc), file=sys.stderr)
        except (OSError, ValueError):
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(_run_cli())
