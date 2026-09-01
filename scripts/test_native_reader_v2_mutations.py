#!/usr/bin/env python3
"""Prove that critical Native Reader v2 authority mutations are detected."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


MAIN_CLASS = (
    "com.techrebbe.supernote.spreadprobe.v2.NativeReaderV2CoreTests"
)


MUTATIONS = (
    (
        "Affine2D.java",
        "<= MIN_RELATIVE_DETERMINANT * linearNorm * linearNorm",
        "< -MIN_RELATIVE_DETERMINANT * linearNorm * linearNorm",
        "singular-affine guard",
    ),
    (
        "PageSlot.java",
        "return sourcePageIndex < 0;",
        "return false;",
        "blank-slot identity",
    ),
    (
        "NativeReaderV2Config.java",
        "if (!ENGINE_VALUE.equals(properties.getProperty(ENGINE_KEY))) {",
        "if (false) {",
        "explicit v2 marker admission",
    ),
    (
        "NativeReaderV2Config.java",
        "if (\"true\".equals(value)) return true;",
        "if (\"true\".equalsIgnoreCase(value)) return true;",
        "canonical config boolean",
    ),
    (
        "SpreadSnapshot.java",
        "if (writerAuthority == null || !writerAuthority.matches(",
        "if (writerAuthority == null || false && !writerAuthority.matches(",
        "writer-authority match",
    ),
    (
        "GestureRouter.java",
        "else if (page >= 0 && snapshot.writerReady\n"
        "                    && page != snapshot.activePageIndex\n"
        "                    && (tool == Tool.STYLUS || tool == Tool.ERASER))",
        "else if (page >= 0\n"
        "                    && page != snapshot.activePageIndex\n"
        "                    && (tool == Tool.STYLUS || tool == Tool.ERASER))",
        "inactive-writer authority",
    ),
    (
        "GestureBuffer.java",
        "sample.eventTimeMs - firstEventTimeMs > maxDurationMs",
        "sample.eventTimeMs - firstEventTimeMs < maxDurationMs",
        "gesture-duration bound",
    ),
    (
        "ActivationMachine.java",
        "authority.layoutGeneration <= token.layoutGeneration\n"
        "            || authority.pageIndex != token.targetPage",
        "authority.layoutGeneration < token.layoutGeneration\n"
        "            || authority.pageIndex != token.targetPage",
        "activation-generation advance",
    ),
    (
        "PageSlot.java",
        "return sourceBox.contains(source.x, source.y);",
        "return true;",
        "exact rotated-page content hit",
    ),
    (
        "PageProjectionFactory.java",
        "double scale = sizing == Sizing.FILL\n"
        "            ? Math.max(widthScale, heightScale)\n"
        "            : Math.min(widthScale, heightScale);",
        "double scale = sizing == Sizing.FILL\n"
        "            ? Math.min(widthScale, heightScale)\n"
        "            : Math.min(widthScale, heightScale);",
        "fill projection covers physical slot",
    ),
    (
        "SpreadSnapshot.java",
        "|| leftOrFull.screenBounds.right\n"
        "                    > right.screenBounds.left",
        "|| leftOrFull.screenBounds.right\n"
        "                    < right.screenBounds.left",
        "physical slot order",
    ),
    (
        "SpreadSession.java",
        "|| next.layoutGeneration <= current.layoutGeneration\n"
        "                || gestureRouter.hasActiveGesture())",
        "|| next.layoutGeneration <= current.layoutGeneration)",
        "contact-safe layout publication",
    ),
    (
        "SpreadSession.java",
        "        published.set(next);\n"
        "        return true;\n"
        "    }\n\n"
        "    public synchronized boolean publishRollback",
        "        gestureRouter.retire();\n"
        "        published.set(next);\n"
        "        return true;\n"
        "    }\n\n"
        "    public synchronized boolean publishRollback",
        "pen route survives target publication",
    ),
    (
        "NativeReaderController.java",
        "if (current == null || current.sourceSaveHandled) {",
        "if (current == null) {",
        "duplicate source callback idempotency",
    ),
    (
        "NativeReaderController.java",
        "if (retired || context != expected || !expected.inputComplete\n"
        "                || !expected.targetPublished\n"
        "                || expected.replayKind != ReplayKind.DROP_PEN) {",
        "if (retired || context != expected\n"
        "                || !expected.targetPublished\n"
        "                || expected.replayKind != ReplayKind.DROP_PEN) {",
        "direct pen drain waits for input terminal",
    ),
    (
        "NativeReaderController.java",
        "ActivationMachine.CompletionMode.DRAIN_CONTACT\n"
        "        );",
        "ActivationMachine.CompletionMode.REPLAY_INPUT\n"
        "        );",
        "direct pen uses drain completion",
    ),
    (
        "NativeReaderController.java",
        "    public boolean onInactiveHover(\n"
        "        double screenX,\n"
        "        double screenY,\n"
        "        List<RectD> visibleNativeChrome\n"
        "    ) {\n"
        "        assertOwnerThread();",
        "    public boolean onInactiveHover(\n"
        "        double screenX,\n"
        "        double screenY,\n"
        "        List<RectD> visibleNativeChrome\n"
        "    ) {",
        "controller thread confinement",
    ),
    (
        "NativeReaderController.java",
        "if (replayMayHaveMutated) {\n"
        "            hardDisable(token, "
        "\"native_replay_timeout_uncertain\");",
        "if (replayMayHaveMutated) {\n"
        "            requestRollback(current, "
        "\"native_replay_timeout_uncertain\");",
        "uncertain replay timeout containment",
    ),
    (
        "NativeReaderFirmwarePort.java",
        "after.markRevision >= sourceMarkRevision",
        "after.markRevision < sourceMarkRevision",
        "firmware source-save revision",
    ),
    (
        "NativeReaderFirmwarePort.java",
        "disabled == null || disabled.writerEnabled",
        "disabled == null || false && disabled.writerEnabled",
        "firmware writer-disable proof",
    ),
    (
        "NativeReaderFirmwarePort.java",
        "&& targetAuthority.equals(after.authority);",
        ";",
        "firmware replay component authority",
    ),
    (
        "NativeReaderFirmwarePort.java",
        "    public Phase phase() {\n"
        "        assertOwnerThread();",
        "    public Phase phase() {",
        "firmware port thread confinement",
    ),
    (
        "NativeReaderFirmwarePort.java",
        "if (!bridge.isStableObservationCurrent(source)) {",
        "if (false) {",
        "firmware cached-authority freshness",
    ),
    (
        "NativeReaderFirmwarePort.java",
        "bridge.postToOwnerThread(completion);",
        "completion.run();",
        "firmware save callback owner marshalling",
    ),
)


def fail(message: str) -> None:
    raise SystemExit(f"test_native_reader_v2_mutations.py: {message}")


def compile_and_run(
    javac: str,
    java: str,
    source_dir: pathlib.Path,
    test_dir: pathlib.Path,
    output_dir: pathlib.Path,
) -> subprocess.CompletedProcess[str]:
    sources = sorted(source_dir.rglob("*.java")) + sorted(
        test_dir.rglob("*.java")
    )
    compile_result = subprocess.run(
        [
            javac,
            "-source",
            "8",
            "-target",
            "8",
            "-encoding",
            "UTF-8",
            "-d",
            os.fspath(output_dir),
            *[os.fspath(path) for path in sources],
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if compile_result.returncode != 0:
        return compile_result
    return subprocess.run(
        [java, "-ea", "-cp", os.fspath(output_dir), MAIN_CLASS],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> None:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    original_source = (
        root
        / "native-spread-module"
        / "src"
        / "com"
        / "techrebbe"
        / "supernote"
        / "spreadprobe"
        / "v2"
    )
    original_tests = root / "native-spread-module" / "tests"
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        fail("JDK javac/java are required")

    with tempfile.TemporaryDirectory(prefix="native-reader-v2-mut-") as temp:
        temp_root = pathlib.Path(temp)
        for filename, old, new, label in MUTATIONS:
            source_dir = temp_root / label / "src"
            test_dir = temp_root / label / "tests"
            output_dir = temp_root / label / "classes"
            shutil.copytree(original_source, source_dir)
            shutil.copytree(original_tests, test_dir)
            output_dir.mkdir()
            target = source_dir / filename
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                fail(
                    f"{label} mutation marker count is {text.count(old)}, not 1"
                )
            target.write_text(text.replace(old, new), encoding="utf-8")
            result = compile_and_run(
                javac, java, source_dir, test_dir, output_dir
            )
            if result.returncode == 0:
                fail(f"critical mutation survived: {label}")
            print(f"Mutation rejected: {label}")
    print(f"Native Reader v2 mutation tests: PASS ({len(MUTATIONS)} mutations)")


if __name__ == "__main__":
    main()
