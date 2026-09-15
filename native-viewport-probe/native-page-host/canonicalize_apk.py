#!/usr/bin/env python3
"""Create a byte-reproducible unsigned APK from aapt output and one DEX."""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import zipfile


MAX_ENTRY = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
ALLOWED_BASE_ENTRIES = {"AndroidManifest.xml", "resources.arsc"}


class CanonicalApkError(ValueError):
    pass


def _read_regular_once(path: Path, limit: int) -> bytes:
    """Read through one no-follow descriptor and never reopen the authority path."""
    path = Path(path).absolute()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise CanonicalApkError(f"not a bounded single-link regular file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > limit
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise CanonicalApkError(f"descriptor authority changed: {path.name}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CanonicalApkError(f"short descriptor read: {path.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise CanonicalApkError(f"descriptor changed while read: {path.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _safe_name(name: str) -> bool:
    value = PurePosixPath(name)
    return bool(name and not name.startswith("/") and "\\" not in name
                and not value.is_absolute() and ".." not in value.parts
                and all(part not in ("", ".") for part in value.parts))


def _read_base(path: Path) -> dict[str, bytes]:
    base_bytes = _read_regular_once(path, MAX_TOTAL)
    payloads: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(base_bytes), "r") as archive:
        for entry in archive.infolist():
            if entry.is_dir() or not _safe_name(entry.filename):
                raise CanonicalApkError("invalid base APK entry")
            if entry.filename in payloads:
                raise CanonicalApkError("duplicate base APK entry")
            if entry.filename not in ALLOWED_BASE_ENTRIES:
                raise CanonicalApkError("unexpected base APK entry")
            if entry.flag_bits & 1 or entry.file_size > MAX_ENTRY:
                raise CanonicalApkError("encrypted or oversized base APK entry")
            value = archive.read(entry)
            if len(value) != entry.file_size:
                raise CanonicalApkError("short base APK entry")
            total += len(value)
            if total > MAX_TOTAL:
                raise CanonicalApkError("base APK expansion limit exceeded")
            payloads[entry.filename] = value
    if "AndroidManifest.xml" not in payloads:
        raise CanonicalApkError("base APK lacks AndroidManifest.xml")
    return payloads


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits = 0
    return info


def canonicalize(base_apk: Path, dex: Path, output: Path) -> None:
    base_apk = Path(base_apk).absolute()
    dex = Path(dex).absolute()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise CanonicalApkError("output must be a new path")
    dex_bytes = _read_regular_once(dex, MAX_ENTRY)
    if not dex_bytes.startswith(b"dex\n") or len(dex_bytes) > MAX_ENTRY:
        raise CanonicalApkError("invalid or oversized classes.dex")
    entries = _read_base(base_apk)
    entries["classes.dex"] = dex_bytes
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", allowZip64=False,
                             compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as archive:
            for name in sorted(entries):
                archive.writestr(_zip_info(name), entries[name], compresslevel=9)
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-apk", required=True, type=Path)
    parser.add_argument("--dex", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    canonicalize(args.base_apk, args.dex, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
