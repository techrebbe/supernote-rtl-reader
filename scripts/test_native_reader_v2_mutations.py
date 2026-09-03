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
        "NativeComponentIdentityRegistry.java",
        "                entry.leaseCount++;",
        "                entry.leaseCount += 0;",
        "replacement-runtime component identity reference count",
    ),
    (
        "NativeComponentIdentityRegistry.java",
        "            if (entry.leaseCount == 0) entries.remove(entry);",
        "            if (false) entries.remove(entry);",
        "fully released component identity retirement",
    ),
    (
        "NativeComponentIdentityRegistry.java",
        "            return owner.id(this, role, component);",
        "            return ids[role];",
        "leased component role identity",
    ),
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
    (
        "NativeHandshakeSingleFlight.java",
        "return pending.compareAndSet(false, true);",
        "return true;",
        "handshake flood single-flight admission",
    ),
    (
        "NativeHandshakeSingleFlight.java",
        "pending.set(false);",
        "pending.set(true);",
        "handshake terminal-path admission release",
    ),
)


# Android/framework code cannot run in the host JVM suite. Mutate each
# security/lifecycle invariant in an isolated repository copy and prove the
# fail-closed static gate rejects it. This converts recurring review findings
# into deterministic regression coverage instead of relying on prose review.
STATIC_MUTATIONS = (
    (
        "scripts/patch_plugin_packager.py",
        'build-tools/35.0.0',
        'build-tools/36.0.0',
        "plugin packager build-tools pin",
    ),
    (
        "scripts/patch_plugin_packager.py",
        "[[:space:]]*$/\\\\1/p'",
        "[[:space:]]*$/\\1/p'",
        "plugin packager signer-parser backreference",
    ),
    (
        "scripts/verify_plugin_package.py",
        'ANDROID_BUILD_TOOLS_VERSION = "35.0.0"',
        'ANDROID_BUILD_TOOLS_VERSION = "36.0.0"',
        "plugin verifier build-tools pin",
    ),
    (
        "scripts/patch_plugin_packager.py",
        'for required_scheme in 2 3; do',
        'for required_scheme in 2; do',
        "plugin packager v2/v3 requirement",
    ),
    (
        "scripts/verify_plugin_package.py",
        'required_schemes != {"2", "3"}',
        'not required_schemes',
        "plugin verifier v2/v3 requirement",
    ),
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
        "                if (Looper.myLooper() != Looper.getMainLooper()) {\n"
        "                    Log.e(TAG, \"v2 handshake rejected outside main snapshot looper\");",
        "                if (false) {\n"
        "                    Log.e(TAG, \"v2 handshake rejected outside main snapshot looper\");",
        "handshake receiver main snapshot affinity",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                boolean queued = handler.post(() -> {",
        "                boolean queued = mainHandler.post(() -> {",
        "handshake canonicalization worker dispatch",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            Process.THREAD_PRIORITY_BACKGROUND",
        "            Process.THREAD_PRIORITY_DEFAULT",
        "handshake worker background priority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                            publicationAccepted = mainHandler.post(() -> {",
        "                            publicationAccepted = handler.post(() -> {",
        "handshake main-thread publication dispatch",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "        String expected = canonicalPath(requestedPath);",
        "        String expected = requestedPath;",
        "handshake requested-path canonical authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            String actual = canonicalPath(candidate.rawPath);",
        "            String actual = candidate.rawPath;",
        "handshake candidate-path canonical authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            if (match != null && match.entry != candidate.entry) return null;",
        "            if (false) return null;",
        "handshake unique matching activity authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            || !handshakeSnapshotStillCurrent(snapshot)",
        "            || false",
        "handshake final snapshot freshness",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                || expectedCandidate.entryGeneration !=\n"
        "                    actualCandidate.entryGeneration",
        "                || false",
        "handshake entry generation fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                || expectedCandidate.lifecycleGeneration !=\n"
        "                    actualCandidate.lifecycleGeneration",
        "                || false",
        "handshake lifecycle generation fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                || expectedCandidate.resumed != actualCandidate.resumed",
        "                || false",
        "handshake resumed-state fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                || !sameHandshakePath(\n"
        "                    expectedCandidate.rawPath,\n"
        "                    actualCandidate.rawPath\n"
        "                )",
        "                || false",
        "handshake exact raw-path fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                || !sameHandshakeComponents(\n"
        "                    expectedCandidate.components,\n"
        "                    actualCandidate.components\n"
        "                )",
        "                || false",
        "handshake exact component authority fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            && expected.binder == actual.binder",
        "            && true",
        "handshake binder component identity",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "        if (Looper.myLooper() == Looper.getMainLooper()) {\n"
        "            Log.e(TAG, \"v2 handshake canonicalization rejected on main looper\");",
        "        if (false) {\n"
        "            Log.e(TAG, \"v2 handshake canonicalization rejected on main looper\");",
        "handshake canonicalization main-thread rejection",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                    synchronized(nativeSpreadConfigurationIntentLock) {\n"
        "                        if (!nativeSpreadModuleInvalidated.get()) {\n"
        "                            val terminalResult =\n"
        "                                if (nativeSpreadConfigurationGeneration.get() ==\n"
        "                                    configurationGeneration\n"
        "                                ) {\n"
        "                                    result\n"
        "                                } else {\n"
        "                                    NativeSpreadHandshake(false, \"stale_operation\")\n"
        "                                }\n"
        "                            callback(terminalResult)\n"
        "                        }\n"
        "                    }",
        "                    if (!nativeSpreadModuleInvalidated.get()) {\n"
        "                        callback(NativeSpreadHandshake(false, \"stale_operation\"))\n"
        "                    }",
        "plugin handshake callback terminal generation linearization",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        val newlyInvalidated = synchronized(nativeSpreadConfigurationIntentLock) {\n"
        "            if (nativeSpreadModuleInvalidated.compareAndSet(false, true)) {\n"
        "                nativeSpreadConfigurationGeneration.incrementAndGet()",
        "        val newlyInvalidated = if (nativeSpreadModuleInvalidated.compareAndSet(false, true)) {\n"
        "            nativeSpreadConfigurationGeneration.incrementAndGet()",
        "plugin invalidation generation linearization",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        if (!mainHandler.postDelayed(\n"
        "                timeout,\n"
        "                NATIVE_SPREAD_HANDSHAKE_TIMEOUT_MS,",
        "        if (!mainHandler.postDelayed(\n"
        "                timeout,\n"
        "                60_000L,",
        "plugin handshake end-to-end timeout",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        if (nativeSpreadConfigurationGeneration.get() != configurationGeneration) {\n"
        "            finish(NativeSpreadHandshake(false, \"stale_operation\"))\n"
        "            return\n"
        "        }\n\n"
        "        try {",
        "        if (false) {\n"
        "            finish(NativeSpreadHandshake(false, \"stale_operation\"))\n"
        "            return\n"
        "        }\n\n"
        "        try {",
        "plugin handshake pre-worker generation fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            NATIVE_SPREAD_HANDSHAKE_EXECUTOR.execute(task)",
        "            task.run()",
        "plugin bounded handshake path executor",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        check(Looper.myLooper() == Looper.getMainLooper()) {\n"
        '            "Native Reader v2 handshake registration must run on the main thread"',
        "        check(true) {\n"
        '            "Native Reader v2 handshake registration must run on the main thread"',
        "plugin handshake registration thread affinity",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                    reportedPath == expectedPath",
        "                    reportedPath?.let { File(it).canonicalPath } == expectedPath",
        "plugin handshake response avoids main-thread canonicalization",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                !nativeSpreadModuleInvalidated.get() &&\n"
        "                    nativeSpreadConfigurationGeneration.get() == expected",
        "                nativeSpreadConfigurationGeneration.get() == expected",
        "plugin persisted-state generation authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            ArrayBlockingQueue<Runnable>(1),",
        "            java.util.concurrent.LinkedBlockingQueue<Runnable>(),",
        "plugin bounded handshake executor queue",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            if (nativeSpreadModuleInvalidated.compareAndSet(false, true)) {",
        "            if (false) {",
        "plugin module invalidation fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        withNativeSpreadConfigurationAuthority(configurationGeneration) {\n"
        "            writePropertiesAtomicallyCas(\n"
        "                marker,\n"
        "                properties,",
        "        run {\n"
        "            writePropertiesAtomicallyCas(\n"
        "                marker,\n"
        "                properties,",
        "plugin persisted-state publication linearization",
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
        ".github/workflows/build.yml",
        "$expectedSignedLength = 258587L",
        "$expectedSignedLength = 250394L",
        "published companion exact signed length",
    ),
    (
        ".github/workflows/build.yml",
        "31e83f5ea104d41ed1fe9bddb140a6e19572fb766893e2754810496b5ca4bf80",
        "09474ec2ac115bf5bba7b936c1d1a63a4195056af3e048821dd36f28cba31817",
        "published companion exact signed digest",
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
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "                    postGuarded(\"activation_evidence_failure\", () -> {\n"
        "                        if (lifecycleSuspended\n"
        "                            || lifecycleEpoch != activationLifecycleEpoch) {\n"
        "                            return;\n"
        "                        }",
        "                    postGuarded(\"activation_evidence_failure\", () -> {",
        "activation failure lifecycle epoch fence",
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
        "            || lifecycleSuspended || nativeLifecycleHandoffPending\n"
        "            || generation != refreshGeneration) return;",
        "        if (retired || detachmentPrepared\n"
        "            || lifecycleSuspended || nativeLifecycleHandoffPending\n"
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
        "        advanceLifecycleEpoch();\n"
        "        if (hasLiveInputContact()) {",
        "        if (hasLiveInputContact()) {",
        "configuration handoff epoch invalidation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        if (retired || containedFailClosed || detachmentPrepared\n"
        "            || lifecycleSuspended || nativeLifecycleHandoffPending) return;\n"
        "        long generation = ++refreshGeneration;",
        "        if (retired || containedFailClosed || detachmentPrepared\n"
        "            || lifecycleSuspended) return;\n"
        "        long generation = ++refreshGeneration;",
        "configuration handoff refresh-scheduling fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "        if (retired || containedFailClosed || detachmentPrepared\n"
        "            || lifecycleSuspended || nativeLifecycleHandoffPending\n"
        "            || generation != refreshGeneration) return;",
        "        if (retired || containedFailClosed || detachmentPrepared\n"
        "            || lifecycleSuspended\n"
        "            || generation != refreshGeneration) return;",
        "configuration handoff refresh-publication fence",
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
        "v2android/NativeReaderV2Runtime.java",
        "                    firmware.releaseComponentIdentityLease(\n"
        "                        releasedIdentityLease\n"
        "                    );",
        "                    firmware.releaseComponentIdentityLease(null);",
        "retiring runtime releases its exact component identity lease",
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
        "    if (-not $ExpectedSignerSha256) {",
        "    if ($false) {",
        "missing signed-build identity rejection",
    ),
    (
        "native-spread-module/build.ps1",
        "    if ($ExpectedSignerSha256) {",
        "    if ($false) {",
        "aligned-only signer rejection",
    ),
    (
        "native-spread-module/build.ps1",
        "-ExpectedSignerSha256 is required for signed builds",
        "-ExpectedSignerSha256 is optional for signed builds",
        "required explicit signer pin",
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
        "NATIVE_READER_V2_APK_LENGTH = 258587L",
        "NATIVE_READER_V2_APK_LENGTH = 250394L",
        "installed companion APK length pin",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "31e83f5ea104d41ed1fe9bddb140a6e19572fb766893e2754810496b5ca4bf80",
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
        "if (!renameCompleted) throw failure",
        "if (renameCompleted) throw failure",
        "post-rename recovery entry",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "retained == null || live != null",
        "retained == null && live != null",
        "post-rename no-clobber live-occupant fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "if (recoveryRequired) {",
        "if (false && recoveryRequired) {",
        "recovery-required native-reader relaunch fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "if (!desiredStateRestored || !displacedEvidenceIntact) {",
        "if (!desiredStateRestored && !displacedEvidenceIntact) {",
        "failed-publication exact-state recovery fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "if (nativeMarkRecoveryRequiredPending() || durableRecovery ||\n"
        "            annotationRecoveryPending.get() ||",
        "if (annotationRecoveryPending.get() ||",
        "handoff persistent recovery-required gate",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "private val NATIVE_MARK_RECOVERY_REQUIRED_PATHS = HashSet<String>()",
        "private val NATIVE_MARK_RECOVERY_REQUIRED_PATHS = emptySet<String>()",
        "process-global native mark recovery containment",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        publishNativeMarkRecoveryJournal(\n"
        "                            pdfFile,\n"
        "                            marker,\n"
        "                            revalidatedBackup,\n"
        "                        )\n"
        "                    }\n\n"
        "                    var publication: NativeMarkPublication? = null",
        "                        error(\"recovery journal skipped\")\n"
        "                    }\n\n"
        "                    var publication: NativeMarkPublication? = null",
        "durable recovery journal precedes mark publication",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "require(liveNativeAnnotationMatchesRecoveryJournal(expected))",
        "require(true || liveNativeAnnotationMatchesRecoveryJournal(expected))",
        "exact live mark verification precedes recovery fence retirement",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        onCommitProven()\n"
        "        val displaced = try {",
        "        val displaced = try {",
        "fresh journal and live-mark proof publish recovery commit",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        if (!recoveryCommitProven) {",
        "                        if (true) {",
        "post-commit journal retirement failure cannot roll mark backward",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                SystemClock.sleep(900)\n\n"
        "                synchronized(nativeSpreadConfigurationLock) {\n"
        "                    if (nativeMarkRecoveryRequiredPending() ||\n"
        "                        inspectNativeMarkRecoveryFence(pdfFile).blocking\n"
        "                    ) {",
        "                SystemClock.sleep(900)\n\n"
        "                synchronized(nativeSpreadConfigurationLock) {\n"
        "                    if (nativeMarkRecoveryRequiredPending()) {",
        "queued native reopen durable recovery rescan",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        var rejected: DisplacedRegularFile? = null\n"
        "        try {\n"
        "            // The initial authority check/preservation is part of rollback",
        "        val rejected = preserveRegularDestinationNoClobber(\n"
        "            publication.mark,\n"
        "            publishedAuthority,\n"
        "            \"rejected annotation publication rollback\",\n"
        "        ) {}\n"
        "        try {\n"
        "            // The initial authority check/preservation is part of rollback",
        "initial rollback preservation is recovery-required contained",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "Pre-publication annotation state is not proven restored;",
        "Pre-publication annotation state might not be restored;",
        "rollback recovery-required classification",
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
    def __init__(
        self,
        message: str,
        preserved: pathlib.Path | None = None,
        *,
        recovery_required: bool = False,
        live_restored: bool = False,
    ):
        super().__init__(message)
        self.preserved = preserved
        self.recovery_required = recovery_required
        self.live_restored = live_restored

    @property
    def reopen_allowed(self) -> bool:
        return not self.recovery_required


class _ConfigurationGenerationGate:
    """Executable model of the process-shared Kotlin publication gate."""

    def __init__(self) -> None:
        self.generation = 0
        self.invalidated = False

    def begin(self) -> int:
        self.generation += 1
        return self.generation

    def require(self, expected: int) -> None:
        if self.invalidated or self.generation != expected:
            raise _InterleavingRejected("configuration was superseded")

    def publish(self, expected: int, action) -> None:
        # Kotlin holds one process-shared intent monitor across this check and
        # the exact CAS publication/retirement boundary.
        self.require(expected)
        action()

    def invalidate(self) -> None:
        # The real module advances the shared generation in the same monitor
        # transaction that publishes its invalidated state.
        if not self.invalidated:
            self.invalidated = True
            self.generation += 1

    def complete(self, expected: int, result: str, callback) -> None:
        # A live superseded request receives one fail-closed terminal result so
        # its Promise settles. A destroyed module receives no callback at all.
        if self.invalidated:
            return
        callback(result if self.generation == expected else "stale_operation")


def run_configuration_generation_interleaving_tests() -> None:
    gate = _ConfigurationGenerationGate()
    state = {"marker": "off", "pending": None}

    # Supersession after preliminary work but before pending publication.
    first = gate.begin()
    gate.require(first)
    second = gate.begin()
    try:
        gate.publish(first, lambda: state.update(pending="first"))
        raise AssertionError("superseded operation published a pending marker")
    except _InterleavingRejected:
        assert state == {"marker": "off", "pending": None}

    gate.publish(second, lambda: state.update(pending="second"))
    assert state["pending"] == "second"

    # A handshake response that was valid when received cannot invoke its old
    # callback after a newer configure request linearizes.
    callback_state = {"results": [], "publications": 0}
    response_generation = second
    third = gate.begin()
    gate.complete(
        response_generation,
        "ok",
        lambda result: callback_state["results"].append(result),
    )
    assert callback_state == {
        "results": ["stale_operation"],
        "publications": 0,
    }

    # Supersession between pending and commit rejects the old authorization;
    # the pending transaction evidence permits an exact rollback.
    try:
        gate.publish(second, lambda: state.update(marker="enabled"))
        raise AssertionError("superseded pending marker committed")
    except _InterleavingRejected:
        state.update(marker="off", pending=None)
    assert state == {"marker": "off", "pending": None}

    # Likewise, a response accepted before teardown cannot invoke its callback
    # after invalidation advances the same process-wide generation.
    invalidation_callback = {"results": []}
    gate.invalidate()
    gate.complete(
        third,
        "ok",
        lambda result: invalidation_callback["results"].append(result),
    )
    assert invalidation_callback == {"results": []}

    try:
        gate.publish(third, lambda: state.update(marker="enabled"))
        raise AssertionError("invalidated module published persisted state")
    except _InterleavingRejected:
        assert state == {"marker": "off", "pending": None}

    print("Native Reader v2 configuration-generation interleavings: PASS")


def _read_if_file(path: pathlib.Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _restore_displaced_after_rejected_rename(
    destination: pathlib.Path,
    displaced: pathlib.Path,
    message: str,
) -> None:
    """Model the Kotlin post-rename O_EXCL recovery boundary.

    The displaced pathname is intentionally retained after successful recovery.
    If an independently created live pathname exists, it is never overwritten
    and the caller must keep DocumentActivity stopped for explicit recovery.
    """
    try:
        retained = displaced.read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError) as error:
        raise _InterleavingRejected(
            message,
            displaced,
            recovery_required=True,
        ) from error
    if os.path.lexists(destination):
        raise _InterleavingRejected(
            message,
            displaced,
            recovery_required=True,
        )
    try:
        with destination.open("xb") as output:
            output.write(retained)
            output.flush()
            os.fsync(output.fileno())
        if destination.read_bytes() != retained or displaced.read_bytes() != retained:
            raise OSError("recovered live bytes or displaced evidence changed")
    except (FileExistsError, FileNotFoundError, IsADirectoryError, OSError) as error:
        raise _InterleavingRejected(
            message,
            displaced,
            recovery_required=True,
        ) from error
    raise _InterleavingRejected(
        message,
        displaced,
        live_restored=True,
    )


def _model_preserve_regular_destination_no_clobber(
    destination: pathlib.Path,
    expected: bytes | None,
    displaced_suffix: str,
    hook,
) -> pathlib.Path | None:
    hook("before_check", destination, None)
    if _read_if_file(destination) != expected:
        raise _InterleavingRejected("destination changed before preservation")
    hook("after_capture", destination, None)
    if expected is None:
        return None

    displaced = destination.with_name(destination.name + displaced_suffix)
    if displaced.exists():
        raise AssertionError("test displacement path unexpectedly exists")
    hook("before_rename", destination, displaced)
    os.replace(destination, displaced)
    hook("after_rename_before_validation", destination, displaced)
    if displaced.read_bytes() != expected:
        _restore_displaced_after_rejected_rename(
            destination,
            displaced,
            "race moved a foreign or mutated inode; it was retained",
        )
    if os.path.lexists(destination):
        _restore_displaced_after_rejected_rename(
            destination,
            displaced,
            "destination reappeared after preservation",
        )
    return displaced


def _model_recover_desired_live_state(
    destination: pathlib.Path,
    desired: bytes | None,
    original_evidence: pathlib.Path | None,
    failed_suffix: str,
    message: str,
) -> None:
    failed = _read_if_file(destination)
    if failed is None and os.path.lexists(destination):
        raise _InterleavingRejected(
            message, original_evidence, recovery_required=True
        )
    if failed is not None:
        try:
            _model_preserve_regular_destination_no_clobber(
                destination,
                failed,
                failed_suffix,
                lambda *_: None,
            )
        except _InterleavingRejected as error:
            raise _InterleavingRejected(
                message,
                original_evidence,
                recovery_required=True,
            ) from error
    try:
        if desired is not None:
            with destination.open("xb") as output:
                output.write(desired)
                output.flush()
                os.fsync(output.fileno())
        if _read_if_file(destination) != desired:
            raise OSError("desired live bytes were not restored")
        if original_evidence is not None and not original_evidence.is_file():
            raise OSError("original displaced evidence was not retained")
    except (FileExistsError, FileNotFoundError, IsADirectoryError, OSError) as error:
        raise _InterleavingRejected(
            message,
            original_evidence,
            recovery_required=True,
        ) from error
    raise _InterleavingRejected(
        message,
        original_evidence,
        live_restored=True,
    )


def _model_no_clobber_publish(
    destination: pathlib.Path,
    expected: bytes | None,
    replacement: bytes,
    hook,
) -> pathlib.Path | None:
    """Executable model of the Kotlin preserve + O_EXCL protocol."""
    displaced = _model_preserve_regular_destination_no_clobber(
        destination,
        expected,
        ".displaced",
        hook,
    )
    hook("after_preserve", destination, displaced)
    try:
        with destination.open("xb") as output:
            output.write(replacement)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        try:
            _model_recover_desired_live_state(
                destination,
                expected,
                displaced,
                ".failed",
                "O_EXCL preserved a racing destination",
            )
        except _InterleavingRejected as rejected:
            raise rejected from error
    return displaced


def _model_no_clobber_rollback(
    destination: pathlib.Path,
    published: bytes | None,
    previous: bytes | None,
    hook,
) -> pathlib.Path | None:
    try:
        rejected = _model_preserve_regular_destination_no_clobber(
            destination,
            published,
            ".rejected",
            hook,
        )
    except _InterleavingRejected as error:
        raise _InterleavingRejected(
            "pre-publication state is not proven restored",
            error.preserved,
            recovery_required=True,
            live_restored=error.live_restored,
        ) from error
    hook("after_preserve", destination, rejected)
    if previous is not None:
        try:
            with destination.open("xb") as output:
                output.write(previous)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError as error:
            try:
                _model_recover_desired_live_state(
                    destination,
                    previous,
                    rejected,
                    ".rollback-failed",
                    "rollback O_EXCL preserved a racing destination",
                )
            except _InterleavingRejected as rejected_error:
                raise rejected_error from error
    return rejected


_RECOVERY_FENCE_BYTES = b"native-mark-recovery-fence-v1"


def _model_scan_recovery_fence(
    marker: pathlib.Path,
    process_latch: set[pathlib.Path],
) -> bool:
    """Model process recreation and fail-closed durable fence admission."""
    marker_key = marker.resolve(strict=False)
    observed = _read_if_file(marker)
    if observed is None:
        return marker_key in process_latch or os.path.lexists(marker)
    process_latch.add(marker_key)
    # Both an exact journal and malformed/replaced evidence are blocking. Only
    # exact journal bytes are eligible for repair; callers check that separately.
    return True


def _model_publish_recovery_fence(
    marker: pathlib.Path,
    process_latch: set[pathlib.Path],
) -> None:
    process_latch.add(marker.resolve(strict=False))
    with marker.open("xb") as output:
        output.write(_RECOVERY_FENCE_BYTES)
        output.flush()
        os.fsync(output.fileno())
    assert marker.read_bytes() == _RECOVERY_FENCE_BYTES


def _model_resume_recovery_from_fence(
    mark: pathlib.Path,
    marker: pathlib.Path,
    desired: bytes | None,
    process_latch: set[pathlib.Path],
) -> pathlib.Path | None:
    """Model crash-safe exact repair and journal retirement.

    Any extant live bytes are first moved to retained evidence. The desired
    bytes are then created with O_EXCL, so an interleaving occupant is never
    overwritten. The durable fence remains until the exact live state verifies.
    """
    marker_key = marker.resolve(strict=False)
    if _read_if_file(marker) != _RECOVERY_FENCE_BYTES:
        process_latch.add(marker_key)
        raise _InterleavingRejected(
            "recovery fence is not exact",
            recovery_required=True,
        )
    process_latch.add(marker_key)
    current = _read_if_file(mark)
    displaced = None
    if current != desired and current is not None:
        displaced = _model_preserve_regular_destination_no_clobber(
            mark,
            current,
            ".recovery-displaced",
            lambda *_: None,
        )
    try:
        if desired is not None and _read_if_file(mark) is None:
            with mark.open("xb") as output:
                output.write(desired)
                output.flush()
                os.fsync(output.fileno())
        if _read_if_file(mark) != desired:
            raise OSError("desired recovery state did not verify")
        if displaced is not None and displaced.read_bytes() != current:
            raise OSError("displaced recovery evidence changed")
        retired = marker.with_name(marker.name + ".recovery-retired")
        os.replace(marker, retired)
        if marker.exists() or retired.read_bytes() != _RECOVERY_FENCE_BYTES:
            raise OSError("recovery fence retirement did not verify")
        process_latch.remove(marker_key)
        return displaced
    except (FileExistsError, FileNotFoundError, IsADirectoryError, OSError) as error:
        process_latch.add(marker_key)
        raise _InterleavingRejected(
            "recovery remains fenced",
            displaced,
            recovery_required=True,
        ) from error


def run_durable_recovery_fence_tests(temp_root: pathlib.Path) -> None:
    def scenario(name: str) -> pathlib.Path:
        root = temp_root / "recovery-fence" / name
        root.mkdir(parents=True)
        return root

    # Crash immediately after the durable fence: a fresh module instance finds
    # it from disk, suppresses reopen, and can complete exact recovery.
    root = scenario("crash-after-fence-publication")
    mark = root / "book.pdf.mark"
    marker = root / ".book.pdf.snspread"
    mark.write_bytes(b"working")
    process_latch: set[pathlib.Path] = set()
    _model_publish_recovery_fence(marker, process_latch)
    process_latch = set()  # process/context recreation
    assert _model_scan_recovery_fence(marker, process_latch)
    displaced = _model_resume_recovery_from_fence(
        mark, marker, b"canonical", process_latch
    )
    assert mark.read_bytes() == b"canonical"
    assert displaced is not None and displaced.read_bytes() == b"working"
    assert not marker.exists() and not process_latch

    # Crash after the live pathname was displaced but before O_EXCL
    # publication. The fresh process sees the fence, repairs the absent live
    # path, and leaves the exact moved inode as evidence.
    root = scenario("crash-after-displacement")
    mark = root / "book.pdf.mark"
    marker = root / ".book.pdf.snspread"
    mark.write_bytes(b"working")
    process_latch = set()
    _model_publish_recovery_fence(marker, process_latch)
    prior = _model_preserve_regular_destination_no_clobber(
        mark, b"working", ".pre-crash-displaced", lambda *_: None
    )
    assert not mark.exists() and prior is not None
    process_latch = set()
    assert _model_scan_recovery_fence(marker, process_latch)
    _model_resume_recovery_from_fence(mark, marker, b"canonical", process_latch)
    assert mark.read_bytes() == b"canonical"
    assert prior.read_bytes() == b"working"
    assert not marker.exists() and not process_latch

    # Crash after desired publication but before journal retirement: recovery
    # merely verifies the exact bytes and retires the durable fence.
    root = scenario("crash-after-desired-publication")
    mark = root / "book.pdf.mark"
    marker = root / ".book.pdf.snspread"
    mark.write_bytes(b"canonical")
    process_latch = set()
    _model_publish_recovery_fence(marker, process_latch)
    process_latch = set()
    assert _model_scan_recovery_fence(marker, process_latch)
    assert _model_resume_recovery_from_fence(
        mark, marker, b"canonical", process_latch
    ) is None
    assert mark.read_bytes() == b"canonical"
    assert not marker.exists() and not process_latch

    # A pathname replacement present at recovery is preserved byte-for-byte;
    # desired publication remains O_EXCL and no evidence is destroyed.
    root = scenario("racer-present-at-recovery")
    mark = root / "book.pdf.mark"
    marker = root / ".book.pdf.snspread"
    mark.write_bytes(b"racer")
    process_latch = set()
    _model_publish_recovery_fence(marker, process_latch)
    process_latch = set()
    assert _model_scan_recovery_fence(marker, process_latch)
    displaced = _model_resume_recovery_from_fence(
        mark, marker, b"canonical", process_latch
    )
    assert mark.read_bytes() == b"canonical"
    assert displaced is not None and displaced.read_bytes() == b"racer"
    assert not marker.exists() and not process_latch

    # Same-process deletion/replacement of an observed journal can never clear
    # containment. A fresh process also treats malformed persisted evidence as
    # blocking and ineligible for repair.
    root = scenario("journal-deletion-and-replacement")
    marker = root / ".book.pdf.snspread"
    process_latch = set()
    _model_publish_recovery_fence(marker, process_latch)
    marker.unlink()
    assert _model_scan_recovery_fence(marker, process_latch)
    marker.write_bytes(b"replacement")
    assert _model_scan_recovery_fence(marker, process_latch)
    process_latch = set()
    assert _model_scan_recovery_fence(marker, process_latch)
    try:
        _model_resume_recovery_from_fence(
            root / "book.pdf.mark", marker, b"canonical", process_latch
        )
        raise AssertionError("malformed replacement journal was repaired")
    except _InterleavingRejected as error:
        assert error.recovery_required and not error.reopen_allowed
        assert marker.read_bytes() == b"replacement"

    # Once exact desired bytes and the still-live fence have both verified,
    # journal retirement is the cleanup side of an irreversible commit. A
    # replacement marker racing with retirement must not trigger rollback of
    # the already repaired live mark; the displaced journal remains evidence.
    root = scenario("marker-replacement-during-retirement")
    mark = root / "book.pdf.mark"
    marker = root / ".book.pdf.snspread"
    mark.write_bytes(b"canonical")
    process_latch = set()
    _model_publish_recovery_fence(marker, process_latch)
    recovery_commit_proven = (
        mark.read_bytes() == b"canonical"
        and marker.read_bytes() == _RECOVERY_FENCE_BYTES
    )
    retained_journal = marker.with_name(marker.name + ".retirement-displaced")
    os.replace(marker, retained_journal)
    marker.write_bytes(b"valid-ordinary-marker-racer")
    retirement_failed = True
    if retirement_failed and not recovery_commit_proven:
        mark.write_bytes(b"discarded-working-copy")
    assert mark.read_bytes() == b"canonical"
    assert retained_journal.read_bytes() == _RECOVERY_FENCE_BYTES
    assert marker.read_bytes() == b"valid-ordinary-marker-racer"

    print("Native Reader v2 durable recovery fence tests: PASS")


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
    def before_rename(phase, destination, _preserved):
        if phase == "before_rename":
            os.replace(destination, saved_old)
            destination.write_bytes(b"racer")
    try:
        _model_no_clobber_publish(mark, b"old", b"new", before_rename)
        raise AssertionError("mid-preservation replacement was accepted")
    except _InterleavingRejected as error:
        assert saved_old.read_bytes() == b"old"
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"racer"
        assert mark.read_bytes() == b"racer"
        assert error.live_restored and error.reopen_allowed

    root = scenario("same-inode-mutation-after-capture")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    captured_inode = mark.stat().st_ino
    def mutate_after_capture(phase, destination, _preserved):
        if phase == "after_capture":
            destination.write_bytes(b"same-inode-mutated")
            assert destination.stat().st_ino == captured_inode
    try:
        _model_no_clobber_publish(
            mark, b"old", b"new", mutate_after_capture
        )
        raise AssertionError("same-inode mutation after capture was accepted")
    except _InterleavingRejected as error:
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"same-inode-mutated"
        assert mark.read_bytes() == b"same-inode-mutated"
        assert error.live_restored and error.reopen_allowed

    root = scenario("displaced-mutation-after-rename-before-validation")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    def mutate_displaced_after_rename(phase, _destination, preserved):
        if phase == "after_rename_before_validation":
            assert preserved is not None
            preserved.write_bytes(b"moved-then-mutated")
    try:
        _model_no_clobber_publish(
            mark, b"old", b"new", mutate_displaced_after_rename
        )
        raise AssertionError("post-rename displaced mutation was accepted")
    except _InterleavingRejected as error:
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"moved-then-mutated"
        assert mark.read_bytes() == b"moved-then-mutated"
        assert error.live_restored and error.reopen_allowed

    root = scenario("new-occupant-after-rename-before-validation")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"old")
    def occupy_after_rename(phase, destination, _preserved):
        if phase == "after_rename_before_validation":
            destination.write_bytes(b"new-occupant")
    try:
        _model_no_clobber_publish(mark, b"old", b"new", occupy_after_rename)
        raise AssertionError("post-rename live occupant was accepted")
    except _InterleavingRejected as error:
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"old"
        assert mark.read_bytes() == b"new-occupant"
        assert error.recovery_required and not error.reopen_allowed

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
        assert mark.read_bytes() == b"old"
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"old"
        assert (root / "book.pdf.mark.failed").read_bytes() == b"racer"
        assert error.live_restored and error.reopen_allowed

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
        assert mark.read_bytes() == b"old"
        assert error.preserved is not None
        assert error.preserved.read_bytes() == b"new"
        assert (root / "book.pdf.mark.rollback-failed").read_bytes() == b"racer"
        assert error.live_restored and error.reopen_allowed

    root = scenario("rollback-replacement-before-preserve")
    mark = root / "book.pdf.mark"
    mark.write_bytes(b"new")
    def rollback_before_preserve(phase, destination, _preserved):
        if phase == "before_check":
            destination.write_bytes(b"racer")
    try:
        _model_no_clobber_rollback(
            mark, b"new", b"old", rollback_before_preserve
        )
        raise AssertionError("rollback accepted a pre-preservation racer")
    except _InterleavingRejected as error:
        assert mark.read_bytes() == b"racer"
        assert error.recovery_required and not error.reopen_allowed

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
        run_configuration_generation_interleaving_tests()
        run_no_clobber_interleaving_tests(temp_root)
        run_durable_recovery_fence_tests(temp_root)
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
