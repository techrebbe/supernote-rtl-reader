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
        "NativeReaderV2StrictProperties.java",
        "if (!keys.add(key)) {",
        "if (false) {",
        "duplicate marker key rejection",
    ),
    (
        "NativeReaderV2MarkerClaim.java",
        "if (!COMMITTED_FIELDS.equals(properties.stringPropertyNames())) {",
        "if (false) {",
        "committed marker exact schema",
    ),
    (
        "NativeReaderV2MarkerClaim.java",
        "if (claimedLength != observedDocumentLength\n"
        "            || !isCanonicalSha256(claimedSha256)",
        "if (claimedLength == observedDocumentLength\n"
        "            || !isCanonicalSha256(claimedSha256)",
        "marker document length authority",
    ),
    (
        "NativeReaderV2MarkerClaim.java",
        "|| !claimedSha256.equals(observedDocumentSha256)) {",
        "|| false && !claimedSha256.equals(observedDocumentSha256)) {",
        "marker document digest authority",
    ),
    (
        "NativeSaveWitness.java",
        "return attempt.observed && attempt.nativeResult;",
        "return true;",
        "native dirty-save acknowledgement",
    ),
    (
        "NativeWriterGeometry.java",
        "viewWidth - right,",
        "0,",
        "writer slot origin authority",
    ),
    (
        "NativeReaderController.java",
        "startNavigation(current, target);",
        "clearContext(current);",
        "swipe navigation must transfer writer authority",
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
        "GestureRouter.java",
        "route = Route.ACTIVATE_AND_DRAIN_PEN;",
        "route = Route.ACTIVATE_AND_REPLAY_HIT;",
        "inactive pen cannot enter replay path",
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
        "NativePageTransform.java",
        "activeSlot.sourceToScreen.then(\n"
            "            displayToOrigin\n"
            "        )",
        "displayToOrigin.then(\n"
        "            activeSlot.sourceToScreen\n"
        "        )",
        "native crop transform order",
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


# Android/framework code cannot run in the host JVM suite. Mutate each
# security/lifecycle invariant in an isolated repository copy and prove the
# fail-closed static gate rejects it. This converts recurring review findings
# into deterministic regression coverage instead of relying on prose review.
STATIC_MUTATIONS = (
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Compositor.java",
        "                Affine2D.identity(),",
        "                slot.sourceToScreen,",
        "live presenter display transform",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        (
            "                    if (!prepared) {\n"
            "                        // The old document remains the writer authority until"
        ),
        (
            "                    if (false) {\n"
            "                        // The old document remains the writer authority until"
        ),
        "document replacement abort",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "        if (runtime != null && !runtime.retire(reason)) {",
        "        if (runtime != null && false) {",
        "retirement restoration proof",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                entry.stylusRoutePass = !entry.fingerPhysicalContact\n"
        "                    && runtime.mayPassNativePenImmediately(x, y, chrome);",
        "                entry.stylusRoutePass =\n"
        "                    runtime.mayPassNativePenImmediately(x, y, chrome);",
        "cross-tool physical fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        (
            "                            requireBackupDocumentIdentity(\n"
            "                                pdfFile,\n"
            "                                revalidatedBackup,\n"
            '                                "before-mark-publish",'
        ),
        (
            "                            requireBackupDocumentIdentity(\n"
            "                                pdfFile,\n"
            "                                revalidatedBackup,\n"
            '                                "before-mark-publish-disabled",'
        ),
        "restore PDF publication revalidation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            .candidateMarkerPresent(path);",
        "            .candidateMarkerPresent(path) && false;",
        "pre-admission configured document fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2EntryPoint.java",
        "NativeReaderV2PackageAdmission.verifyLoaded(",
        "NativeReaderV2PackageAdmission.verify(",
        "loaded APK classloader authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        (
            "            firmware.refreshWriterDisabledAreas(\n"
            "                current,\n"
            "                geometry,\n"
            "                writerChrome"
        ),
        (
            "            firmware.refreshWriterDisabledAreas(\n"
            "                current,\n"
            "                geometry,\n"
            "                Collections.<RectD>emptyList()"
        ),
        "native chrome writer mask",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            scheduleNativeTerminalGuard(entry, runtime);",
        "            releaseStylusRouteIfComplete(entry);",
        "missing native pen terminal guard",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        return new RectD(0, 0, bitmap.getWidth(), bitmap.getHeight());",
        "        return new RectD(1, 1, bitmap.getWidth(), bitmap.getHeight());",
        "full origin sizing authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        ownerHandler.post(guarded(label, action));",
        "        ownerHandler.post(action);",
        "guarded queued continuation",
    ),
    (
        ".github/workflows/build.yml",
        "       github.actor == github.repository_owner)",
        "       true)",
        "trusted manual stable signing actor scope",
    ),
    (
        ".github/workflows/build.yml",
        "       github.ref == 'refs/heads/main' &&\n"
        "       github.actor == github.repository_owner)",
        "       github.actor == github.repository_owner)",
        "trusted manual stable signing main scope",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                        if (!NativeReaderV2DocumentGate\n"
        "                            .evidenceStillCurrent(evidence)) {",
        "                        if (false) {",
        "admission worker publication freshness",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "                    final boolean current = NativeReaderV2DocumentGate\n"
        "                        .evidenceStillCurrent(evidence);",
        "                    final boolean current = true;",
        "activation publication freshness",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            module.third == NATIVE_READER_V2_SIGNER_SHA256",
        "            true",
        "runtime companion signer pin",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "    private NativeReaderV2FirmwareAccess.Components inspectNativeCurrent() {",
        "    private NativeReaderV2FirmwareAccess.Components inspectCurrent() {",
        "no UI-thread filesystem authority check",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "            || snapshot.layoutGeneration < request.layoutGeneration) {",
        "            || false) {",
        "deferred navigation generation fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "            cancelFingerGesture(event.getEventTime());\n"
        "            fingerConcurrentBlocked = true;",
        "            fingerConcurrentBlocked = true;",
        "multi-pointer cancellation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        if (retired || containedFailClosed || detachmentPrepared\n"
        "            || generation != refreshGeneration) return;",
        "        if (retired || detachmentPrepared\n"
        "            || generation != refreshGeneration) return;",
        "contained runtime publication fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        if (hasPhysicalInputContact()) {\n"
        "            pendingContainmentReason = reason == null",
        "        if (false) {\n"
        "            pendingContainmentReason = reason == null",
        "deferred containment during physical contact",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "            || physicalContactFence.stylusContactActive();",
        "            || false;",
        "android stylus lifecycle fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        if (stockPresentationReadyMask != STOCK_PRESENTATION_READY) return;",
        "        if (stockPresentationReadyMask == 0) return;",
        "three-layer stock restoration acknowledgement",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        projectionExecutor.shutdownNow();",
        "        projectionExecutor.shutdown();",
        "projection cancellation before identity release",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "                            if (projectionExecutor.awaitTermination(",
        "                            if (true || projectionExecutor.awaitTermination(",
        "asynchronous projection drain",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        '                "candidate marker lookup is forbidden on the main thread"',
        '                "candidate marker lookup unexpectedly ran on the main thread"',
        "worker-only candidate marker lookup",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2FirmwareAccess.java",
        "            if (rect.left == 0 && rect.top == 0\n"
        "                && rect.right == 0 && rect.bottom == 0) {",
        "            if (false) {",
        "zero-area native mask sentinel",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                pathBefore.st_nlink == 1L &&",
        "                pathBefore.st_nlink >= 1L &&",
        "companion single-link marker authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,",
        "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC,",
        "companion no-follow marker authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        val previousMarkerBytes = readPersistedBytesIfFile(marker)",
        "                        val previousMarkerBytes = if (marker.isFile) marker.readBytes() else null",
        "companion rollback marker descriptor authority",
    ),
    (
        "overlay/App.js",
        "          ? 'rtl'\n          : restored.direction;",
        "          ? restored.direction\n          : restored.direction;",
        "trusted marker direction authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "            return failure.errno != OsConstants.ENOENT;",
        "            return false;",
        "malformed marker early fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        Bitmap activeInk = writerGeometryLease == null\n"
        "            ? null : firmware.liveHandwritingBitmap(current);",
        "        Bitmap activeInk = firmware.liveHandwritingBitmap(current);",
        "first spread live ink authority",
    ),
    (
        "native-spread-module/build.ps1",
        "if (-not ($verificationOutput -contains 'Number of signers: 1') -or",
        "if ($false -or",
        "packaged signer verification",
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


def prepare_static_tree(root: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir()
    for name in ("AGENTS.md", "build.sh", "PluginConfig.json"):
        shutil.copy2(root / name, destination / name)
    for name in (".github", "overlay", "native", "native-spread-module"):
        shutil.copytree(
            root / name,
            destination / name,
            ignore=shutil.ignore_patterns(
                "build",
                "out",
                "node_modules",
                "__pycache__",
                "*.pyc",
            ),
        )
    scripts = destination / "scripts"
    scripts.mkdir()
    shutil.copy2(
        root / "scripts" / "check_native_reader_v2_invariants.py",
        scripts / "check_native_reader_v2_invariants.py",
    )


def run_static_mutations(root: pathlib.Path, temp_root: pathlib.Path) -> None:
    static_root = temp_root / "android-static"
    prepare_static_tree(root, static_root)
    checker = static_root / "scripts" / "check_native_reader_v2_invariants.py"
    for relative, old, new, label in STATIC_MUTATIONS:
        target = static_root / pathlib.PurePosixPath(relative)
        original = target.read_text(encoding="utf-8")
        if original.count(old) != 1:
            fail(
                f"{label} static mutation marker count is "
                f"{original.count(old)}, not 1"
            )
        target.write_text(original.replace(old, new), encoding="utf-8")
        try:
            result = subprocess.run(
                [sys.executable, os.fspath(checker), os.fspath(static_root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode == 0:
                fail(f"critical static mutation survived: {label}")
            print(f"Static mutation rejected: {label}")
        finally:
            target.write_text(original, encoding="utf-8")


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
        run_static_mutations(root, temp_root)
    total = len(MUTATIONS) + len(STATIC_MUTATIONS)
    print(f"Native Reader v2 mutation tests: PASS ({total} mutations)")


if __name__ == "__main__":
    main()
