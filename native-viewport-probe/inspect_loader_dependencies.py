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
import re
import subprocess
import sys
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


def elf_metadata(data: bytes) -> dict:
    from elftools.elf.elffile import ELFFile
    if not data or len(data) > MAX_FILE_BYTES:
        raise InventoryError("invalid ELF file size")
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_DYN":
        raise InventoryError("expected AArch64 little-endian shared library")
    dynamics = [s for s in elf.iter_segments() if s["p_type"] == "PT_DYNAMIC"]
    if len(dynamics) != 1:
        raise InventoryError("expected one dynamic segment")
    needed, sonames, sizes, init_functions = [], [], [], []
    for tag in dynamics[0].iter_tags():
        kind = tag.entry.d_tag
        if kind == "DT_NEEDED":
            if not NAME.fullmatch(tag.needed):
                raise InventoryError("unsupported dependency name")
            needed.append(tag.needed)
        elif kind == "DT_SONAME":
            sonames.append(tag.soname)
        elif kind == "DT_INIT_ARRAYSZ":
            sizes.append(int(tag.entry.d_val))
        elif kind == "DT_INIT":
            init_functions.append(int(tag.entry.d_ptr))
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
        p = subprocess.run([adb, "-s", SERIAL, *command], capture_output=True, timeout=timeout)
        if p.returncode:
            raise InventoryError("ADB read failed: " + p.stderr.decode("utf-8", "replace")[:300])
        return p.stdout

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
        size_text = run("shell", "stat", "-L", "-c", "%s", path).decode().strip()
        if not size_text.isdecimal() or not 0 < int(size_text) <= MAX_FILE_BYTES:
            raise InventoryError("unsupported remote library size")
        run("pull", path, str(local), timeout=60)
        data = local.read_bytes()
        if len(data) != int(size_text):
            raise InventoryError("library changed during pull")
        metadata = elf_metadata(data)
        remote_digest = run("shell", "sha256sum", path).decode().split()[0]
        if remote_digest != metadata["sha256"]:
            raise InventoryError("remote/local library digest mismatch")
        print("READ", basename, metadata["bytes"], flush=True)
        return {**metadata, "localFile": filename}

    libraries, edges = collect_graph(maps, read_library)
    after, after_maps, after_raw = snapshot()
    if after != before or any(after_maps.get(p) != maps[p] for p in libraries):
        raise InventoryError("process or selected library mapping changed")
    (args.output / "maps-after.txt").write_text(after_raw, encoding="utf-8")
    report = {"schema": "native-loader-inventory-v1", "firmware": fingerprint,
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
