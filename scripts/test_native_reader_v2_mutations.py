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
        "status.state != ActivationMachine.State.SOURCE_SAVING",
        "false",
        "late source callback transaction-state fence",
    ),
    (
        "NativeReaderController.java",
        "preserveUnsavedSource(\n"
        "                current,\n"
        '                "source_save_failed_or_stale"\n'
        "            );",
        "requestRollback(\n"
        "                current,\n"
        '                "source_save_failed_or_stale"\n'
        "            );",
        "uncertain source save preserves live ink",
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
        "v2android/NativeReaderV2Runtime.java",
        "            fingerIngressAdmitted = inputAdmission.begin(\n"
        "                AtomicInputAdmission.Contact.FINGER\n"
        "            );",
        "            fingerIngressAdmitted = true;",
        "atomic finger down admission",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        if (pressure > 0 && !penContact) {\n"
        "            if (inputFrozen) {",
        "        if (pressure > 0 && !penContact) {\n"
        "            if (false) {",
        "frozen pen down admission",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "entry.runtime.onNativeWriterDisableCompleted(",
        "entry.runtime.disableNativeReaderV2(",
        "writer-disable firmware completion witness",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                    entry.pendingNativeOpen = pending;\n"
        "                    boolean prepared =",
        "                    entry.pendingNativeOpen = null;\n"
        "                    boolean prepared =",
        "cross-document open retention",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "if (pendingOpen != null && entry.runtime == null)",
        "if (false)",
        "cross-document open retained during admission",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "immediateMarkerBytes?.contentEquals(previousMarkerBytes)",
        "true",
        "pending-marker compare-and-publish",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "immediateMarker?.bytes?.contentEquals(pendingMarkerBytes)",
        "true",
        "committed-marker compare-and-publish",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                    if (propertiesResult.isFailure) {",
        "                    if (false) {",
        "malformed marker recovery state",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        '            startNativeBackupWorker("RTLReaderNativeModeLoad") {',
        "            run {",
        "native-mode validation background worker",
    ),
    (
        ".github/workflows/build.yml",
        "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4",
        "uses: actions/setup-node@v4 # v4",
        "immutable CI action pin",
    ),
    (
        ".github/workflows/build.yml",
        "needs:\n      - native-spread-build\n      - build",
        "needs:\n      - native-spread-build",
        "stable artifact plugin dependency",
    ),
    (
        "scripts/verify_plugin_package.py",
        "        verify_apk_tools(Path(temporary_name))",
        "        pass",
        "embedded APK platform verification",
    ),
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
        "                    && runtime.beginNativePenContactImmediately(x, y, chrome);",
        "                entry.stylusRoutePass =\n"
        "                    runtime.beginNativePenContactImmediately(x, y, chrome);",
        "cross-tool physical fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        (
            "                                requireBackupDocumentIdentity(\n"
            "                                    pdfFile,\n"
            "                                    revalidatedBackup,\n"
            "                                    if (revalidatedBackup.originalMarkPresent) {\n"
            '                                        "before-mark-publish"'
        ),
        (
            "                                requireBackupDocumentIdentity(\n"
            "                                    pdfFile,\n"
            "                                    revalidatedBackup,\n"
            "                                    if (revalidatedBackup.originalMarkPresent) {\n"
            '                                        "before-mark-publish-disabled"'
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
        "            || lifecycleSuspended\n"
        "            || generation != refreshGeneration) return;",
        "        if (retired || detachmentPrepared\n"
        "            || lifecycleSuspended\n"
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
        "        if (!stockRestoreWitness.ready(token)) return;",
        "        if (false) return;",
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
        "v2/AtomicInputAdmission.java",
        "        if (freezeToken != null || fingerActive || stylusActive) return null;",
        "        if (freezeToken != null) return null;",
        "atomic freeze rejects live contact",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/AtomicInputAdmission.java",
        "        if (token == null || token != freezeToken) return false;",
        "        if (token == null) return false;",
        "freeze release token identity",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "            || lifecycleEpoch != compositionLifecycleEpoch\n"
        "            || !inputAdmission.current(compositionFreeze)) {",
        "            || !inputAdmission.current(compositionFreeze)) {",
        "composition lifecycle epoch",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                            expectedRuntime.onLifecycleResumeRevalidated();",
        "                            expectedRuntime.scheduleRefresh(\n"
        "                                \"resume_authority_revalidated\"\n"
        "                            );",
        "resume requires runtime lifecycle revalidation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/NativePresentationRestoreWitness.java",
        "            || observed == null || reloadGeneration != token.reloadGeneration",
        "            || observed == null",
        "stock restoration reload generation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/NativePresentationRestoreWitness.java",
        "            && !token.invalid && token.mask == 7 && token.pageReady;",
        "            && !token.invalid && token.mask == 7;",
        "stock restoration native page-ready receipt",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "                || !firmware.stockPresentationLayersMatch(\n",
        "                || false && !firmware.stockPresentationLayersMatch(\n",
        "stock restoration installed layer identities",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        sourceSaveFence.cancel();",
        "        sourceSaveFence.active();",
        "queued source save cancellation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "                    | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,",
        "                    | OsConstants.O_CLOEXEC,",
        "live mark lease no-follow authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                    entry.runtime.onNativeWriterGeometryCompleted(",
        "                    entry.runtime.onNativeWriterEnableCompleted(",
        "final writer geometry firmware receipt",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/NativePresentationRestoreWitness.java",
        "        if (receiver != expectedReceiver || replacement == null",
        "        if (replacement == null",
        "stock restoration receiver identity",
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
        (
            "        val descriptor = Os.open(\n"
            "            path,\n"
            "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,"
        ),
        (
            "        val descriptor = Os.open(\n"
            "            path,\n"
            "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC,"
        ),
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
    (
        "build.sh",
        'TEMPLATE_VERSION="1.0.12"',
        'TEMPLATE_VERSION="latest"',
        "immutable Supernote template version",
    ),
    (
        "scripts/materialize_plugin_template.py",
        "34dceadedd77d2c77c83521fee838dc60f3893b948a9070bf38271184268636f",
        "04dceadedd77d2c77c83521fee838dc60f3893b948a9070bf38271184268636f",
        "Supernote template content digest",
    ),
    (
        "scripts/patch_plugin_packager.py",
        "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
        "0ac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
        "embedded plugin APK signer pin",
    ),
    (
        "scripts/verify_plugin_package.py",
        "defined_classes.update(verify_dex(native.read(name), name))",
        "defined_classes.update(set())",
        "structural DEX class authority",
    ),
    (
        "native-spread-module/build.ps1",
        "Two clean Native Reader builds are byte-for-byte reproducible",
        "Native Reader build completed",
        "two-clean-build reproducibility gate",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "NATIVE_READER_V2_APK_LENGTH = 250395L",
        "NATIVE_READER_V2_APK_LENGTH = 250394L",
        "installed companion APK length pin",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "59474ec2ac115bf5bba7b936c1d1a63a4195056af3e048821dd36f28cba31817",
        "09474ec2ac115bf5bba7b936c1d1a63a4195056af3e048821dd36f28cba31817",
        "installed companion APK digest pin",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "applicationInfo.splitSourceDirs.isNullOrEmpty()",
        "true",
        "installed companion split rejection",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "Os.rename(file.absolutePath, displaced.absolutePath)",
        "Os.rename(displaced.absolutePath, file.absolutePath)",
        "mark displaced-inode preservation",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "OsConstants.O_EXCL or OsConstants.O_CLOEXEC or\n"
        "                OsConstants.O_NOFOLLOW,",
        "OsConstants.O_CLOEXEC or\n"
        "                OsConstants.O_NOFOLLOW,",
        "mark no-clobber final creation",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "val committed = persistenceError == null",
        "val committed = true",
        "post-commit relaunch boundary",
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


class _InterleavingRejected(RuntimeError):
    def __init__(self, message: str, preserved: pathlib.Path | None = None):
        super().__init__(message)
        self.preserved = preserved


def _read_if_file(path: pathlib.Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _model_no_clobber_publish(
    destination: pathlib.Path,
    expected: bytes | None,
    replacement: bytes,
    hook,
) -> pathlib.Path | None:
    """Executable model of the Kotlin preserve + O_EXCL protocol."""
    hook("before_check", destination, None)
    if _read_if_file(destination) != expected:
        raise _InterleavingRejected("destination changed before preservation")
    hook("after_check", destination, None)
    displaced = None
    if expected is not None:
        displaced = destination.with_name(destination.name + ".displaced")
        if displaced.exists():
            raise AssertionError("test displacement path unexpectedly exists")
        os.replace(destination, displaced)
        if displaced.read_bytes() != expected:
            raise _InterleavingRejected(
                "race moved a foreign inode; it was preserved", displaced
            )
        if destination.exists():
            raise _InterleavingRejected("destination reappeared", displaced)
    hook("after_preserve", destination, displaced)
    try:
        with destination.open("xb") as output:
            output.write(replacement)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise _InterleavingRejected(
            "O_EXCL preserved a racing destination", displaced
        ) from error
    return displaced


def _model_no_clobber_rollback(
    destination: pathlib.Path,
    published: bytes | None,
    previous: bytes | None,
    hook,
) -> pathlib.Path | None:
    hook("before_check", destination, None)
    if _read_if_file(destination) != published:
        raise _InterleavingRejected("published destination changed")
    hook("after_check", destination, None)
    rejected = None
    if published is not None:
        rejected = destination.with_name(destination.name + ".rejected")
        os.replace(destination, rejected)
        if rejected.read_bytes() != published:
            raise _InterleavingRejected(
                "rollback preserved a racing inode", rejected
            )
    hook("after_preserve", destination, rejected)
    if previous is not None:
        try:
            with destination.open("xb") as output:
                output.write(previous)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError as error:
            raise _InterleavingRejected(
                "rollback O_EXCL preserved a racing destination", rejected
            ) from error
    return rejected


def run_no_clobber_interleaving_tests(temp_root: pathlib.Path) -> None:
    def scenario(name: str) -> pathlib.Path:
        root = temp_root / "no-clobber" / name
        root.mkdir(parents=True)
        return root

    no_hook = lambda *_: None

    root = scenario("normal-and-rollback")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    displaced = _model_no_clobber_publish(mark, b"old", b"new", no_hook)
    assert mark.read_bytes() == b"new"
    assert displaced is not None and displaced.read_bytes() == b"old"
    rejected = _model_no_clobber_rollback(mark, b"new", b"old", no_hook)
    assert mark.read_bytes() == b"old"
    assert rejected is not None and rejected.read_bytes() == b"new"

    root = scenario("replacement-before-check")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    def before_check(phase, destination, _preserved):
        if phase == "before_check":
            destination.write_bytes(b"racer")
    try:
        _model_no_clobber_publish(mark, b"old", b"new", before_check)
        raise AssertionError("pre-check replacement was accepted")
    except _InterleavingRejected:
        assert mark.read_bytes() == b"racer"

    root = scenario("replacement-between-check-and-preserve")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    saved_old = root / "attacker-preserved-old"
    def after_check(phase, destination, _preserved):
        if phase == "after_check":
            os.replace(destination, saved_old)
            destination.write_bytes(b"racer")
    try:
        _model_no_clobber_publish(mark, b"old", b"new", after_check)
        raise AssertionError("mid-preservation replacement was accepted")
    except _InterleavingRejected as error:
        assert saved_old.read_bytes() == b"old"
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"racer"

    root = scenario("replacement-after-preserve")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    def after_preserve(phase, destination, _preserved):
        if phase == "after_preserve":
            destination.write_bytes(b"racer")
    try:
        _model_no_clobber_publish(mark, b"old", b"new", after_preserve)
        raise AssertionError("O_EXCL did not reject a late publication racer")
    except _InterleavingRejected as error:
        assert mark.read_bytes() == b"racer"
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"old"

    root = scenario("rollback-replacement-after-preserve")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"new")
    def rollback_after_preserve(phase, destination, _preserved):
        if phase == "after_preserve":
            destination.write_bytes(b"racer")
    try:
        _model_no_clobber_rollback(
            mark, b"new", b"old", rollback_after_preserve
        )
        raise AssertionError("rollback O_EXCL did not reject a late racer")
    except _InterleavingRejected as error:
        assert mark.read_bytes() == b"racer"
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"new"

    print("Native Reader v2 no-clobber interleavings: PASS")


def prepare_static_tree(root: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir()
    for name in ("AGENTS.md", "build.sh", "PluginConfig.json"):
        shutil.copy2(root / name, destination / name)
    for name in (
        ".github",
        "overlay",
        "native",
        "native-spread-module",
        "provenance",
    ):
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
    for name in (
        "materialize_plugin_template.py",
        "normalize_apk_zip.py",
        "patch_plugin_packager.py",
        "test_build_provenance.py",
        "verify_plugin_package.py",
    ):
        shutil.copy2(root / "scripts" / name, scripts / name)


def run_static_mutations(root: pathlib.Path, temp_root: pathlib.Path) -> None:
    static_root = temp_root / "android-static"
    prepare_static_tree(root, static_root)
    checker = static_root / "scripts" / "check_native_reader_v2_invariants.py"
    baseline = subprocess.run(
        [sys.executable, os.fspath(checker), os.fspath(static_root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if baseline.returncode != 0:
        fail(
            "static mutation baseline is not clean; mutation rejection would "
            "be ambiguous:\n" + baseline.stdout + baseline.stderr
        )
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
        run_no_clobber_interleaving_tests(temp_root)
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
