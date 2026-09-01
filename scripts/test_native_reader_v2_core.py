#!/usr/bin/env python3
"""Compile and execute the pure Native Reader v2 authority core tests."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


def fail(message: str) -> None:
    raise SystemExit(f"test_native_reader_v2_core.py: {message}")


def main() -> None:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    source_root = root / "native-spread-module" / "src" / "com" / "techrebbe" / "supernote" / "spreadprobe" / "v2"
    test_root = root / "native-spread-module" / "tests"
    sources = sorted(source_root.glob("*.java"))
    tests = sorted(test_root.rglob("*.java"))
    if not sources or not tests:
        fail("Native Reader v2 source or test files are missing")
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        fail("JDK javac/java are required")
    with tempfile.TemporaryDirectory(prefix="native-reader-v2-") as temp:
        output = pathlib.Path(temp) / "classes"
        output.mkdir()
        compile_command = [
            javac,
            "-source",
            "8",
            "-target",
            "8",
            "-encoding",
            "UTF-8",
            "-d",
            os.fspath(output),
            *[os.fspath(path) for path in sources],
            *[os.fspath(path) for path in tests],
        ]
        subprocess.run(compile_command, cwd=root, check=True)
        subprocess.run(
            [
                java,
                "-ea",
                "-cp",
                os.fspath(output),
                "com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2CoreTests",
            ],
            cwd=root,
            check=True,
        )


if __name__ == "__main__":
    main()
