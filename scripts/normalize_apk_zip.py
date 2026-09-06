#!/usr/bin/env python3
"""Rewrite an unsigned APK with canonical entry order and timestamps."""

from __future__ import annotations

import os
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


CANONICAL_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def fail(message: str) -> None:
    raise SystemExit(f"normalize_apk_zip.py: {message}")


def normalize(source: Path, destination: Path) -> None:
    if source.resolve() == destination.resolve():
        fail("source and destination must differ")
    try:
        with zipfile.ZipFile(source, "r") as archive:
            entries: dict[str, bytes] = {}
            seen: set[str] = set()
            for info in archive.infolist():
                if info.filename in seen:
                    fail(f"duplicate input entry: {info.filename}")
                seen.add(info.filename)
                archive_path = PurePosixPath(info.filename)
                if (
                    not info.filename
                    or info.filename.startswith("/")
                    or "\\" in info.filename
                    or "\0" in info.filename
                    or any(part in ("", ".", "..") for part in archive_path.parts)
                ):
                    fail(f"unsafe input entry: {info.filename!r}")
                if info.is_dir():
                    continue
                entries[info.filename] = archive.read(info)
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"cannot read source APK: {error}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".tmp", dir=destination.parent
    )
    os.close(temporary_fd)
    try:
        with zipfile.ZipFile(
            temporary_name,
            "w",
            compression=zipfile.ZIP_STORED,
            allowZip64=False,
        ) as output:
            for name in sorted(entries):
                info = zipfile.ZipInfo(name, CANONICAL_TIMESTAMP)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 0
                info.external_attr = 0
                info.flag_bits = 0
                output.writestr(info, entries[name])
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: normalize_apk_zip.py <source.apk> <destination.apk>")
    normalize(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
