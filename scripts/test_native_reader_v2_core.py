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


def java_block(text: str, marker: str, offset: int) -> tuple[str, int]:
    start = text.find(marker, offset)
    if start < 0:
        return "", -1
    brace = text.find("{", start)
    if brace < 0:
        fail(f"missing block after {marker!r}")
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : index + 1], index + 1
    fail(f"unterminated block after {marker!r}")


def check_architecture(source_root: pathlib.Path) -> None:
    controller = (source_root / "NativeReaderController.java").read_text(
        encoding="utf-8"
    )
    offset = 0
    monitor_count = 0
    while True:
        block, offset = java_block(controller, "synchronized (lock)", offset)
        if offset < 0:
            break
        monitor_count += 1
        if "port." in block:
            fail("firmware port call occurs while controller monitor is held")
    if monitor_count < 10:
        fail("controller monitor scan did not cover the expected critical sections")

    entry_lines = []
    controller_lines = controller.splitlines()
    for index, line in enumerate(controller_lines):
        if line.startswith("    public ") and not any(
            marker in line
            for marker in (" class ", " interface ", " enum ")
        ) and "NativeReaderController(" not in line:
            entry_lines.append(index)
            window = "\n".join(controller_lines[index : index + 25])
            if "assertOwnerThread();" not in window:
                fail(
                    "public controller entry lacks owner-thread guard: "
                    + line.strip()
                )
    if len(entry_lines) != 11:
        fail(
            "controller owner-thread scan expected 11 public entries, found "
            f"{len(entry_lines)}"
        )

    firmware_port = (source_root / "NativeReaderFirmwarePort.java").read_text(
        encoding="utf-8"
    )
    firmware_requirements = (
        "requested == null || token != requested",
        "after.markRevision >= sourceMarkRevision",
        "disabled == null || disabled.writerEnabled",
        "targetAuthority.equals(after.authority)",
        "observation.snapshot.layoutGeneration\n"
        "            <= requested.layoutGeneration",
        "phase == Phase.REPLAYING",
        "Thread.currentThread().getId() != ownerThreadId",
    )
    for marker in firmware_requirements:
        if marker not in firmware_port:
            fail(f"firmware authority gate missing: {marker!r}")

    all_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(source_root.glob("*.java"))
    )
    forbidden = (
        "Thread.sleep",
        "postDelayed",
        "java.util.Timer",
        "Runtime.getRuntime",
        "ProcessBuilder",
        "ObjectInputStream",
        "ObjectOutputStream",
        "RandomAccessFile",
        "FileInputStream",
        "FileOutputStream",
        "SpreadProbe",
    )
    for marker in forbidden:
        if marker in all_source:
            fail(f"forbidden v2 dependency or timing fallback: {marker}")
    required_states = (
        "SOURCE_SAVING",
        "TARGET_LOADING",
        "TARGET_VERIFYING",
        "TARGET_PUBLISHING",
        "REPLAYING",
        "ROLLING_BACK",
        "ROLLBACK_PUBLISHING",
        "DISABLED",
    )
    machine = (source_root / "ActivationMachine.java").read_text(
        encoding="utf-8"
    )
    for state in required_states:
        if state not in machine:
            fail(f"activation state missing: {state}")


def main() -> None:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    source_root = root / "native-spread-module" / "src" / "com" / "techrebbe" / "supernote" / "spreadprobe" / "v2"
    test_root = root / "native-spread-module" / "tests"
    sources = sorted(source_root.glob("*.java"))
    tests = sorted(test_root.rglob("*.java"))
    if not sources or not tests:
        fail("Native Reader v2 source or test files are missing")
    check_architecture(source_root)
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
