"""Read-only Nomad dependency inventory. NEVER authorizes native loading.

Only existing proc metadata and mapped system-library files are read. Collected
ELFs stay in an exclusive local build directory; do not publish/upload them.
Multiple mapped candidates for a SONAME are recorded as unresolved, not guessed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import threading
from pathlib import Path, PurePosixPath

SERIAL = "SN078C10015092"
FINGERPRINT = "Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys"
ROOT_LIBRARY = "/system_ext/app/drawPath/lib/arm64/librecgnition.so"
ROOT_SHA256 = "3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2"
MAX_FILES = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9_+@.\-]+\.so\Z")
PATH = re.compile(r"/(?:system/lib64|system_ext/app/drawPath/lib/arm64|apex/[A-Za-z0-9_.@\-]+/lib64(?:/bionic)?)/[A-Za-z0-9_+@.\-]+\.so\Z")
MAP = re.compile(r"([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) ([0-9a-f]+:[0-9a-f]+) ([0-9]+)(?:\s+(.*))?\Z")


class InventoryError(ValueError):
    pass


def read_bounded(path: Path, limit=MAX_FILE_BYTES, expected_size=None) -> bytes:
    """Check the opened descriptor, and cap the read even if the file grows."""
    if type(limit) is not int or limit<=0:
        raise InventoryError("invalid read budget")
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before,"st_file_attributes",0)&0x400:
        raise InventoryError("nonregular or reparse evidence file")
    with path.open("rb") as stream:
        opened=os.fstat(stream.fileno())
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
            raise InventoryError("evidence replaced during open")
        if not 0<opened.st_size<=limit or (expected_size is not None and
                (type(expected_size) is not int or opened.st_size!=expected_size)):
            raise InventoryError("evidence size budget/mismatch")
        data=stream.read(opened.st_size+1)
        after=os.fstat(stream.fileno())
        fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(data)!=opened.st_size or fields(opened)!=fields(after):
            raise InventoryError("evidence changed during bounded read")
        return data


def bounded_command(command, limit, timeout=30):
    """Cap stdout in memory while reading, not after subprocess.run allocates it."""
    if type(limit) is not int or limit<=0 or not 0<timeout<=60:
        raise InventoryError("invalid command budget")
    with subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as process:
        expired=threading.Event()
        def stop():
            expired.set()
            try: process.kill()
            except ProcessLookupError: pass
        timer=threading.Timer(timeout,stop)
        timer.start()
        try:
            data=process.stdout.read(limit+1)
            if len(data)>limit:
                process.kill()
                raise InventoryError("command output budget exceeded")
            code=process.wait(timeout=2)
            if expired.is_set() or code:
                raise InventoryError("bounded command timed out or failed")
            return data
        finally:
            timer.cancel()
            if process.poll() is None: process.kill()
            process.wait(timeout=2)


def mapped_file_identity(header, mappings):
    """stat decimal Linux dev_t must match maps' hexadecimal major:minor."""
    if not re.fullmatch(rb"[0-9]+:[0-9]+:[0-9]+:[0-9a-fA-F]+:[0-9]+:[0-9]+",header):
        raise InventoryError("invalid mapped descriptor stat")
    dev,inode,size,mode,mtime,ctime=header.decode().split(":")
    dev,inode,size=int(dev),int(inode),int(size)
    major=((dev>>8)&0xfff)|((dev>>32)&~0xfff)
    minor=(dev&0xff)|((dev>>12)&~0xff)
    identities={(tuple(int(x,16) for x in m["device"].split(":")),m["inode"]) for m in mappings}
    if identities!={((major,minor),inode)} or inode<=0 or not stat.S_ISREG(int(mode,16)) or not 0<size<=MAX_FILE_BYTES:
        raise InventoryError("descriptor differs from mapped file identity/size")
    return {"device":f"{major:x}:{minor:x}","inode":inode,"bytes":size,
            "mtime":int(mtime),"ctime":int(ctime),"authority":"proc-map-files-open-descriptor-v1"}


def mapped_capture_command(pid, mappings):
    if type(pid) is not int or not 1<pid<4194304 or not mappings:
        raise InventoryError("invalid mapped capture process")
    mapping=mappings[0]
    start,end=mapping["start"],mapping["end"]
    if type(start) is not int or type(end) is not int or not 0<start<end<(1<<56):
        raise InventoryError("invalid mapped capture range")
    # Open the exact mapped inode through the process, not an adb namespace
    # pathname. Keep that descriptor across both stat records and the data read.
    return (f"su -c 'exec 9</proc/{pid}/map_files/{start:x}-{end:x} || exit 61; "
            "stat -L -c %d:%i:%s:%f:%Y:%Z /proc/self/fd/9 || exit 62; "
            f"dd if=/proc/self/fd/9 bs=65536 count={MAX_FILE_BYTES//65536+1} 2>/dev/null || exit 63; "
            "stat -L -c %d:%i:%s:%f:%Y:%Z /proc/self/fd/9 || exit 64'")


def parse_mapped_capture(payload, mappings):
    header,separator,rest=payload.partition(b"\n")
    if not separator or len(header)>256: raise InventoryError("missing descriptor header")
    identity=mapped_file_identity(header,mappings)
    size=identity["bytes"]
    if len(rest)!=size+len(header)+1 or rest[size:]!=header+b"\n":
        raise InventoryError("mapped descriptor changed or transfer size mismatch")
    return rest[:size],identity


def process_identity(stat: str, expected_pid: int) -> tuple[int, int]:
    # comm can contain spaces or parentheses. Fields after final ')' start at 3.
    head, sep, tail = stat.strip().rpartition(")")
    if not sep or not head.startswith(str(expected_pid) + " ("):
        raise InventoryError("process stat identity mismatch")
    fields = tail.split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise InventoryError("malformed process start time")
    return expected_pid, int(fields[19])


def mapped_libraries(text: str) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for line in text.splitlines():
        match = MAP.fullmatch(line)
        if not match:
            raise InventoryError("malformed maps record")
        start, end, perms, offset, dev, inode, path = match.groups()
        if int(start, 16) >= int(end, 16):
            raise InventoryError("invalid mapping extent")
        if not path or not path.endswith(".so") or not PATH.fullmatch(path):
            continue
        parts = path.split("/")
        if any(part in (".", "..") for part in parts):
            raise InventoryError("noncanonical library path")
        result.setdefault(path, []).append({
            "start": int(start, 16), "end": int(end, 16), "permissions": perms,
            "offset": int(offset, 16), "device": dev, "inode": int(inode),
        })
    for path, records in result.items():
        if len({(r["device"], r["inode"]) for r in records}) != 1:
            raise InventoryError("inconsistent mapped file identity: " + path)
    return result


def dynamic_entries(elf):
    """Validate the runtime-address authority before parsing any dynamic tag.

    Do not use DynamicSegment.iter_tags: that resolves strings through optional
    section links and can scan past PT_DYNAMIC searching for a terminator.
    """
    stream=elf.stream
    saved=stream.tell()
    length=stream.seek(0,2)
    stream.seek(saved)
    if not 0<length<=MAX_FILE_BYTES or elf.elfclass!=64 or not elf.little_endian or elf["e_machine"]!="EM_AARCH64":
        raise InventoryError("unsupported dynamic image")
    segments=list(elf.iter_segments())
    if not 0<len(segments)<=1024: raise InventoryError("program segment budget exceeded")
    loads=[s for s in segments if s["p_type"]=="PT_LOAD"]
    for load in loads:
        offset,address,size,memory,align=(load[k] for k in ("p_offset","p_vaddr","p_filesz","p_memsz","p_align"))
        if min(offset,address,size,memory,align)<0 or size>memory or offset+size>length or address+memory>=(1<<64) or (
                align>1 and (align&(align-1) or address%align!=offset%align)):
            raise InventoryError("invalid file-backed program segment")
    dynamics=[s for s in segments if s["p_type"]=="PT_DYNAMIC"]
    if len(dynamics)!=1: raise InventoryError("expected one dynamic segment")
    dynamic=dynamics[0]
    address,offset,size=dynamic["p_vaddr"],dynamic["p_offset"],dynamic["p_filesz"]
    if size<=0 or size>1024*1024 or size%16 or offset%8 or address%8 or dynamic["p_memsz"]!=size:
        raise InventoryError("invalid dynamic extent")
    if runtime_file_offset(address,size,loads)!=offset:
        raise InventoryError("dynamic segment file correspondence mismatch")
    stream.seek(offset)
    data=stream.read(size)
    if len(data)!=size: raise InventoryError("truncated dynamic segment")
    entries=[]
    for i in range(0,size,16):
        entry=elf.structs.Elf_Dyn.parse(data[i:i+16])
        entries.append(entry)
        if entry.d_tag=="DT_NULL": return entries,loads
    raise InventoryError("dynamic terminator outside declared extent")


def runtime_file_offset(address,size,loads):
    if min(address,size)<0 or size==0 or address+size>=(1<<64):
        raise InventoryError("invalid runtime table extent")
    owners=[p for p in loads if p["p_vaddr"]<=address and address+size<=p["p_vaddr"]+p["p_filesz"] and p["p_flags"]&4]
    if len(owners)!=1: raise InventoryError("runtime table lacks unique readable file backing")
    return owners[0]["p_offset"]+address-owners[0]["p_vaddr"]


def dynamic_strings(elf,entries,loads):
    tables=[int(e.d_val) for e in entries if e.d_tag=="DT_STRTAB"]
    sizes=[int(e.d_val) for e in entries if e.d_tag=="DT_STRSZ"]
    if len(tables)!=1 or len(sizes)!=1 or not 0<sizes[0]<=MAX_FILE_BYTES:
        raise InventoryError("ambiguous dynamic string table")
    offset=runtime_file_offset(tables[0],sizes[0],loads)
    elf.stream.seek(offset)
    data=elf.stream.read(sizes[0])
    if len(data)!=sizes[0]: raise InventoryError("truncated dynamic strings")
    return data


def bounded_string(data,offset):
    if not 0<=offset<len(data): raise InventoryError("dynamic name offset outside string table")
    end=data.find(b"\0",offset)
    if end<0: raise InventoryError("unterminated dynamic name")
    return data[offset:end].decode("utf-8",errors="strict")


def elf_metadata(data: bytes) -> dict:
    from elftools.elf.elffile import ELFFile
    if not data or len(data) > MAX_FILE_BYTES:
        raise InventoryError("invalid ELF file size")
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_DYN":
        raise InventoryError("expected AArch64 little-endian shared library")
    entries,loads=dynamic_entries(elf)
    strings=dynamic_strings(elf,entries,loads)
    needed, sonames, sizes, init_functions = [], [], [], []
    for tag in entries:
        kind = tag.d_tag
        if kind == "DT_NEEDED":
            name=bounded_string(strings,int(tag.d_val))
            if not NAME.fullmatch(name):
                raise InventoryError("unsupported dependency name")
            needed.append(name)
        elif kind == "DT_SONAME":
            sonames.append(bounded_string(strings,int(tag.d_val)))
        elif kind == "DT_INIT_ARRAYSZ":
            sizes.append(int(tag.d_val))
        elif kind == "DT_INIT":
            init_functions.append(int(tag.d_ptr))
    if len(sonames) > 1 or any(not NAME.fullmatch(x) for x in sonames):
        raise InventoryError("invalid SONAME")
    if len(sizes) > 1 or (sizes and (sizes[0] % 8 or sizes[0] > len(data))):
        raise InventoryError("invalid initializer array size")
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "soname": sonames[0] if sonames else None, "needed": needed,
            "initArrayEntries": sizes[0] // 8 if sizes else 0,
            "initFunctions": init_functions}


def dependency_candidates(name: str, maps: dict[str, list[dict]]) -> list[str]:
    if not NAME.fullmatch(name):
        raise InventoryError("unsupported dependency name")
    return sorted(p for p in maps if PurePosixPath(p).name == name)


def collect_graph(maps: dict, read_library) -> tuple[dict, list[dict]]:
    if ROOT_LIBRARY not in maps:
        raise InventoryError("pinned DrawPath library is not mapped")
    pending, libraries, edges, total = [ROOT_LIBRARY], {}, [], 0
    while pending:
        path = pending.pop(0)
        if path in libraries:
            continue
        if len(libraries) >= MAX_FILES:
            raise InventoryError("dependency file budget exceeded")
        metadata = read_library(path)
        if type(metadata["bytes"]) is not int or not 0 < metadata["bytes"] <= MAX_FILE_BYTES:
            raise InventoryError("invalid library byte count")
        total += metadata["bytes"]
        if total > MAX_TOTAL_BYTES:
            raise InventoryError("dependency byte budget exceeded")
        if path == ROOT_LIBRARY and metadata["sha256"] != ROOT_SHA256:
            raise InventoryError("root library digest differs from pinned firmware")
        libraries[path] = {**metadata, "mappings": maps[path]}
        for name in metadata["needed"]:
            candidates = dependency_candidates(name, maps)
            edges.append({"requester": path, "needed": name, "candidates": candidates,
                          "resolution": "unresolved_multiple" if len(candidates) > 1 else
                          "missing" if not candidates else "unique_mapped_candidate"})
            pending.extend(c for c in candidates if c not in libraries and c not in pending)
    # Even a unique mapped candidate does not prove the actual relocation target.
    return libraries, edges


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.python_path.resolve(strict=True)))
    # Check local parser access before reading the device or creating artifacts.
    __import__("elftools.elf.elffile")
    adb = str(args.adb.resolve(strict=True))

    def run(*command: str, timeout=30) -> bytes:
        return bounded_command([adb,"-s",SERIAL,*command],4*1024*1024,timeout)

    fingerprint = run("shell", "getprop", "ro.build.fingerprint").decode().strip()
    if fingerprint != FINGERPRINT:
        raise InventoryError("wrong firmware or device")
    pid_text = run("shell", "pidof", "com.ratta.drawpath").decode().strip()
    if not pid_text.isdecimal() or not 1 < int(pid_text) < 4194304:
        raise InventoryError("expected exactly one native pen process")
    pid = int(pid_text)

    def snapshot() -> tuple[tuple, dict, str]:
        first = process_identity(run("shell", f"su -c 'cat /proc/{pid}/stat'").decode(), pid)
        cmdline = run("exec-out", f"su -c 'cat /proc/{pid}/cmdline'").rstrip(b"\x00")
        if cmdline != b"com.ratta.drawpath":
            raise InventoryError("native process command mismatch")
        raw = run("shell", f"su -c 'cat /proc/{pid}/maps'").decode()
        last = process_identity(run("shell", f"su -c 'cat /proc/{pid}/stat'").decode(), pid)
        if first != last:
            raise InventoryError("native process changed during capture")
        return first, mapped_libraries(raw), raw

    before, maps, raw = snapshot()
    # Exclusive local artifact directory only; existing evidence is never overwritten.
    args.output.mkdir()
    (args.output / "maps-before.txt").write_text(raw, encoding="utf-8")

    def read_library(path: str) -> dict:
        if not PATH.fullmatch(path):
            raise InventoryError("path outside allowed system-library roots")
        basename = PurePosixPath(path).name
        # Short artifact basename: adb on Windows cannot reliably create long
        # paths. The complete remote path/digest remain in the JSON inventory.
        filename = hashlib.sha256(path.encode()).hexdigest()[:16] + ".so"
        local = args.output / filename
        if local.exists():
            raise InventoryError("local evidence filename collision")
        command=[adb,"-s",SERIAL,"exec-out",mapped_capture_command(pid,maps[path])]
        data,identity=parse_mapped_capture(bounded_command(command,MAX_FILE_BYTES+512,60),maps[path])
        again,identity_again=parse_mapped_capture(bounded_command(command,MAX_FILE_BYTES+512,60),maps[path])
        if data!=again or identity!=identity_again:
            raise InventoryError("mapped library changed across bounded captures")
        metadata = elf_metadata(data)
        with local.open("xb") as out: out.write(data)
        print("READ", basename, metadata["bytes"], flush=True)
        return {**metadata, "localFile": filename,"mappedFileIdentity":identity}

    libraries, edges = collect_graph(maps, read_library)
    after, after_maps, after_raw = snapshot()
    if after != before or any(after_maps.get(p) != maps[p] for p in libraries):
        raise InventoryError("process or selected library mapping changed")
    (args.output / "maps-after.txt").write_text(after_raw, encoding="utf-8")
    report = {"schema": "native-loader-inventory-v2", "firmware": fingerprint,
              "serial": SERIAL, "process": {"pid": pid, "startTime": before[1]},
              "nativeStartAllowed": False, "bindingAuthority": False,
              "libraries": libraries, "edges": edges,
              "notes": "Candidate closure only, not ELF binding/namespace or safe-initializer proof."}
    (args.output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    unresolved = [e for e in edges if e["resolution"] != "unique_mapped_candidate"]
    print(f"INVENTORY_COMPLETE libraries={len(libraries)} edges={len(edges)} unresolved={len(unresolved)} native_start_allowed=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, subprocess.SubprocessError, UnicodeError, ImportError) as exc:
        print("INVENTORY_FAILED", str(exc), file=sys.stderr)
        raise SystemExit(1)
