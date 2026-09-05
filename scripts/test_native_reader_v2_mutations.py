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
        "MINIMUM_COMPANION_MODULE_VERSION = 140L",
        "MINIMUM_COMPANION_MODULE_VERSION = 139L",
        "companion marker and handshake version authority",
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
        "return owner.compareAndSet(0L, token) ? token : 0L;",
        "return token;",
        "handshake flood single-flight admission",
    ),
    (
        "NativeHandshakeSingleFlight.java",
        "return token != 0L && owner.compareAndSet(token, 0L);",
        "owner.set(0L);\n        return token != 0L;",
        "handshake generation-owned admission release",
    ),
    (
        "NativeHandshakeSingleFlight.java",
        "        return nowUptimeMs < deadlineUptimeMs && current(token);",
        "        return current(token);",
        "handshake absolute publication deadline",
    ),
)


# Android/framework code cannot run in the host JVM suite. Mutate each
# security/lifecycle invariant in an isolated repository copy and prove the
# fail-closed static gate rejects it. This converts recurring review findings
# into deterministic regression coverage instead of relying on prose review.
STATIC_MUTATIONS = (
    (
        "native-spread-module/README.md",
        "requires Supernote RTL Reader v0.4.22 and refuses every other companion",
        "requires Supernote RTL Reader v0.4.19 and refuses every other companion",
        "documented companion plugin pairing",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            require(payloadState == current.state) {",
        "            require(true) {",
        "journal header/payload state binding",
    ),
    (
        "native/NativeReaderV2AuthorityJournal.kt.template",
        "        if (strictFailure.errno != OsConstants.EINVAL) throw strictFailure",
        "        if (false) throw strictFailure",
        "journal directory FUSE fallback scope",
    ),
    (
        "native/NativeReaderV2AuthorityJournal.kt.template",
        "        if (valid.size != 1 || malformed.size != 1) return null",
        "        if (valid.isEmpty() && malformed.isEmpty()) return null",
        "interrupted-journal repair requires exactly one valid and one malformed slot",
    ),
    (
        "native/NativeReaderV2AuthorityJournal.kt.template",
        "                sameVersion(expected.identity, before) &&",
        "                sameStableFileMetadata(expected.identity, before) &&",
        "interrupted-journal repair exact-version authority",
    ),
    (
        "native/NativeReaderV2AuthorityJournal.kt.template",
        "            val encoded = encodeSlot(slotIndex, State.RECOVERY, generation, payload)",
        "            val encoded = encodeSlot(slotIndex, State.COMMITTED, generation, payload)",
        "interrupted-journal repair can publish only recovery authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        if (journalInspection.blocking &&\n"
        "                            !repairableInterruptedPublication\n"
        "                        ) {",
        "                        if (false) {",
        "ambiguous journal remains blocked outside exact repair classification",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            currentAuthority.journalGeneration == expectation.generation &&",
        "            true &&",
        "post-ACK live journal generation revalidation",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        require(samePersistedAuthority(\n"
        "                            legacyMigration.authority,\n"
        "                            exactLegacy,\n"
        "                        )) {\n"
        "                            \"Legacy Native Spread authority changed at migration publication\"",
        "                        require(true) {\n"
        "                            \"Legacy Native Spread authority changed at migration publication\"",
        "legacy authority migration publication fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                                        }.getOrElse { Properties() }",
        "                                        }.getOrThrow()",
        "legacy migration failure completes its React promise",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/android/NativeReaderFirmwareAdmission.java",
        'field(VIEW_MODEL, "documentAnnotationMap", "java.util.Map")',
        'field(VIEW_MODEL, "documentAnnotationMap", "java.util.HashMap")',
        "firmware annotation-map declared type",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/android/NativeReaderFirmwareAdmission.java",
        '            "android.graphics.Point"),',
        '            "com.artifex.mupdf.fitz.Point"),',
        "firmware link hit-test point type",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/android/NativeReaderFirmwareAdmission.java",
        'field(NATIVE_CALLBACK, "this$0", ACTIVITY)',
        'field(NATIVE_CALLBACK, "mPressure", "int")',
        "firmware native listener owner field",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/android/NativeReaderFirmwareAdmission.java",
        'field(NATIVE_EVENT_CALLBACK, "mPressure", "int")',
        'field(NATIVE_CALLBACK, "mPressure", "int")',
        "firmware native event pressure owner",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "Entry entry = BY_ACTIVITY.get(signal.activity);",
        "Entry entry = BY_COMPONENT.get(param.thisObject);",
        "native pen listener activity ownership",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "BY_COMPONENT.get(signal.eventCallback) != entry",
        "BY_COMPONENT.get(signal.eventCallback) == entry",
        "native event callback component authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "entry.fenceAndroidPass = pointInsideChrome(\n"
        "                    event.getX(index), event.getY(index), chrome\n"
        "                );",
        "entry.fenceAndroidPass = true;",
        "admission fence Android document exclusion",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "entry.fenceNativePenPass = pointInsideChrome(x, y, chrome);",
        "entry.fenceNativePenPass = true;",
        "admission fence native-pen document exclusion",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "Entry entry = entry(param.thisObject);\n"
        "                    if (entry == null) return;\n"
        "                    if (entry.runtime == null\n"
        "                        || admissionFenceContactActive(entry)",
        "Entry entry = entry(param.thisObject);\n"
        "                    if (entry == null) return;\n"
        "                    if (entry.runtime == null",
        "admission fence contact terminal continuity",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "        ensureChromeTracker(entry);\n"
        "        entry.attemptedPath = path;",
        "        entry.attemptedPath = path;",
        "pre-admission native chrome recovery authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        'committedMarker.getProperty("activationState", "") !=\n'
        "                NATIVE_SPREAD_ACTIVATION_COMMITTED",
        "false",
        "durable committed-marker success state",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "int pressure = signal.pressure;",
        "int pressure = 0;",
        "native event callback pressure signal",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/android/NativeReaderFirmwareAdmission.java",
        '            } catch (IllegalStateException failure) {',
        '            } catch (IllegalArgumentException failure) {',
        "batch firmware symbol mismatch reporting",
    ),
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
        "    private static final int HANDSHAKE_PROTOCOL = 4;",
        "    private static final int HANDSHAKE_PROTOCOL = 3;",
        "native handshake protocol v4",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        private const val NATIVE_SPREAD_HANDSHAKE_PROTOCOL = 4",
        "        private const val NATIVE_SPREAD_HANDSHAKE_PROTOCOL = 3",
        "plugin handshake protocol v4",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "    private static final long HANDSHAKE_PROVIDER_EXPIRY_MS = 2_500L;",
        "    private static final long HANDSHAKE_PROVIDER_EXPIRY_MS = Long.MAX_VALUE;",
        "handshake provider bounded expiry",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                    || requestedPath.indexOf('\\0') >= 0",
        "                    || false",
        "handshake required raw-path request authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            if (!requestedPath.equals(candidate.rawPath)) continue;",
        "            if (false) continue;",
        "handshake exact request raw-path binding",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "            : new HandshakeResolution(match, match.rawPath);",
        "            : new HandshakeResolution(match, requestedPath);",
        "handshake provider-source raw-path echo binding",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "        if (!HANDSHAKE_SINGLE_FLIGHT.currentBefore(\n"
        "                handshakeToken,\n"
        "                SystemClock.uptimeMillis(),\n"
        "                handshakeDeadlineUptimeMs\n"
        "            )) {\n"
        "            Log.w(TAG, \"v2 handshake publication expired\");\n"
        "            return;\n"
        "        }",
        "        if (false) {\n"
        "            Log.w(TAG, \"v2 handshake publication expired\");\n"
        "            return;\n"
        "        }",
        "handshake expired main publication fence",
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
        "        val start = Runnable {",
        "        if (false) {\n"
        "            finish(NativeSpreadHandshake(false, \"stale_operation\"))\n"
        "            return\n"
        "        }\n\n"
        "        val start = Runnable {",
        "plugin handshake pre-dispatch generation fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        val expectedPath = pdfFile.absolutePath",
        "        val expectedPath = pdfFile.canonicalPath",
        "plugin handshake filesystem-free path capture",
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
        "                    putExtra(HANDSHAKE_EXTRA_RAW_DOCUMENT_PATH, expectedPath)",
        "                    putExtra(HANDSHAKE_EXTRA_RAW_DOCUMENT_PATH, pdfFile.path)",
        "plugin handshake raw-path request binding",
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
        "            if (SystemClock.uptimeMillis() >= handshakeDeadlineUptimeMs) {\n"
        "                finish(NativeSpreadHandshake(false, \"timeout\"))\n"
        "                return\n"
        "            }\n"
        "            reactApplicationContext.sendBroadcast(",
        "            if (false) {\n"
        "                finish(NativeSpreadHandshake(false, \"timeout\"))\n"
        "                return\n"
        "            }\n"
        "            reactApplicationContext.sendBroadcast(",
        "plugin handshake pre-send absolute deadline",
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
        "                properties,\n"
        "                \"Supernote RTL protected editable pending activation\",",
        "        run {\n"
        "            writePropertiesAtomicallyCas(\n"
        "                marker,\n"
        "                properties,\n"
        "                \"Supernote RTL protected editable pending activation\",",
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
        "sameFileObject(stagedIdentity, renamedStagedIdentity)",
        "sameFileObject(stagedIdentity, stagedIdentity)",
        "post-rename staged inode identity",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            } finally {\n"
        "                // Rename is the irreversible publication boundary. Record it\n",
        "            }\n"
        "                // Rename is the irreversible publication boundary. Record it\n",
        "post-rename failure still publishes commit boundary",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        renamedStagedIdentity,\n"
        "                        published.identity,",
        "                        stagedIdentity,\n"
        "                        published.identity,",
        "post-rename descriptor version authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        published.identity,\n"
        "                        Os.lstat(file.absolutePath),",
        "                        published.identity,\n"
        "                        published.identity,",
        "post-publication destination path recheck",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "sameFileObject(admittedIdentity, renamedAdmittedIdentity)",
        "sameFileObject(admittedIdentity, admittedIdentity)",
        "displaced-file post-rename descriptor identity",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                                    renamedAdmittedIdentity,\n"
        "                                    moved.identity,",
        "                                    admittedIdentity,\n"
        "                                    moved.identity,",
        "FUSE-safe displaced-file post-rename version authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "immediate.bytes.contentEquals(moved.bytes)",
        "true || immediate.bytes.contentEquals(moved.bytes)",
        "displaced-file byte continuity",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                                    admittedIdentity,\n"
        "                                    Os.fstat(admittedDescriptor),",
        "                                    admittedIdentity,\n"
        "                                    admittedIdentity,",
        "pre-rename displaced-file descriptor revalidation",
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
        "                    samePersistedAuthority(\n"
        "                        expectedMarkerAuthority,\n"
        "                        currentMarkerAuthority,\n"
        "                    ),",
        "                    samePersistedAuthority(\n"
        "                        currentMarkerAuthority,\n"
        "                        currentMarkerAuthority,\n"
        "                    ),",
        "post-handshake marker snapshot revalidation",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            if (committedMarkerPublishedByActivation) {\n"
        "                // The committed journal header is final authorization, so rollback is\n",
        "            if (false) {\n"
        "                // The committed journal header is final authorization, so rollback is\n",
        "committed-marker verification failure propagation",
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
        "$expectedSignedLength = 295451L",
        "$expectedSignedLength = 250394L",
        "published companion exact signed length",
    ),
    (
        ".github/workflows/build.yml",
        "a576ba581a77f0438814ec13c1b1db211ebdd558d1042227db0ae62a0e085798",
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
            "                                    requireBackupDocumentIdentity(\n"
            "                                        pdfFile,\n"
            "                                        revalidatedBackup,\n"
            "                                        if (revalidatedBackup.originalMarkPresent) {\n"
            '                                            "before-mark-publish"'
        ),
        (
            "                                    requireBackupDocumentIdentity(\n"
            "                                        pdfFile,\n"
            "                                        revalidatedBackup,\n"
            "                                        if (revalidatedBackup.originalMarkPresent) {\n"
            '                                            "before-mark-publish-disabled"'
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
        "            || !inputAdmission.current(compositionFreeze)\n"
        "            || physicalContactFence.stylusContactActive()) {",
        "            || !inputAdmission.current(compositionFreeze)\n"
        "            || physicalContactFence.stylusContactActive()) {",
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
        "    private fun readRegularFileAuthorityIfFile(\n"
        "        file: File,\n"
        "        maximumBytes: Long,\n"
        "        requireNonEmpty: Boolean,\n"
        "        authorityLabel: String,\n"
        "    ): PersistedFileAuthority? {\n"
        "        val path = file.absolutePath\n"
        "        val pathBefore = try {\n"
        "            Os.lstat(path)\n"
        "        } catch (missing: ErrnoException) {\n"
        "            if (missing.errno == OsConstants.ENOENT) return null\n"
        "            throw missing\n"
        "        }\n"
        "        require(\n"
        "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
        "                pathBefore.st_nlink == 1L &&",
        "    private fun readRegularFileAuthorityIfFile(\n"
        "        file: File,\n"
        "        maximumBytes: Long,\n"
        "        requireNonEmpty: Boolean,\n"
        "        authorityLabel: String,\n"
        "    ): PersistedFileAuthority? {\n"
        "        val path = file.absolutePath\n"
        "        val pathBefore = try {\n"
        "            Os.lstat(path)\n"
        "        } catch (missing: ErrnoException) {\n"
        "            if (missing.errno == OsConstants.ENOENT) return null\n"
        "            throw missing\n"
        "        }\n"
        "        require(\n"
        "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
        "                pathBefore.st_nlink >= 1L &&",
        "companion single-link marker authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        (
            "    private fun readRegularFileAuthorityIfFile(\n"
            "        file: File,\n"
            "        maximumBytes: Long,\n"
            "        requireNonEmpty: Boolean,\n"
            "        authorityLabel: String,\n"
            "    ): PersistedFileAuthority? {\n"
            "        val path = file.absolutePath\n"
            "        val pathBefore = try {\n"
            "            Os.lstat(path)\n"
            "        } catch (missing: ErrnoException) {\n"
            "            if (missing.errno == OsConstants.ENOENT) return null\n"
            "            throw missing\n"
            "        }\n"
            "        require(\n"
            "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
            "                pathBefore.st_nlink == 1L &&\n"
            "                pathBefore.st_size >= (if (requireNonEmpty) 1L else 0L) &&\n"
            "                pathBefore.st_size <= maximumBytes &&\n"
            "                pathBefore.st_size <= Int.MAX_VALUE.toLong(),\n"
            "        ) {\n"
            "            \"$authorityLabel authority is not one bounded single-link file\"\n"
            "        }\n"
            "        val descriptor = Os.open(\n"
            "            path,\n"
            "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,"
        ),
        (
            "    private fun readRegularFileAuthorityIfFile(\n"
            "        file: File,\n"
            "        maximumBytes: Long,\n"
            "        requireNonEmpty: Boolean,\n"
            "        authorityLabel: String,\n"
            "    ): PersistedFileAuthority? {\n"
            "        val path = file.absolutePath\n"
            "        val pathBefore = try {\n"
            "            Os.lstat(path)\n"
            "        } catch (missing: ErrnoException) {\n"
            "            if (missing.errno == OsConstants.ENOENT) return null\n"
            "            throw missing\n"
            "        }\n"
            "        require(\n"
            "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
            "                pathBefore.st_nlink == 1L &&\n"
            "                pathBefore.st_size >= (if (requireNonEmpty) 1L else 0L) &&\n"
            "                pathBefore.st_size <= maximumBytes &&\n"
            "                pathBefore.st_size <= Int.MAX_VALUE.toLong(),\n"
            "        ) {\n"
            "            \"$authorityLabel authority is not one bounded single-link file\"\n"
            "        }\n"
            "        val descriptor = Os.open(\n"
            "            path,\n"
            "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC,"
        ),
        "companion no-follow marker authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "    private fun readRegularFileFingerprintIfFile(\n"
        "        file: File,\n"
        "        maximumBytes: Long,\n"
        "        requireNonEmpty: Boolean,\n"
        "        authorityLabel: String,\n"
        "    ): PersistedFileFingerprint? {\n"
        "        val path = file.absolutePath\n"
        "        val pathBefore = try {\n"
        "            Os.lstat(path)\n"
        "        } catch (missing: ErrnoException) {\n"
        "            if (missing.errno == OsConstants.ENOENT) return null\n"
        "            throw missing\n"
        "        }\n"
        "        require(\n"
        "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
        "                pathBefore.st_nlink == 1L &&",
        "    private fun readRegularFileFingerprintIfFile(\n"
        "        file: File,\n"
        "        maximumBytes: Long,\n"
        "        requireNonEmpty: Boolean,\n"
        "        authorityLabel: String,\n"
        "    ): PersistedFileFingerprint? {\n"
        "        val path = file.absolutePath\n"
        "        val pathBefore = try {\n"
        "            Os.lstat(path)\n"
        "        } catch (missing: ErrnoException) {\n"
        "            if (missing.errno == OsConstants.ENOENT) return null\n"
        "            throw missing\n"
        "        }\n"
        "        require(\n"
        "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
        "                pathBefore.st_nlink >= 1L &&",
        "backup fingerprint single-link authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "    private fun readRegularFileFingerprintIfFile(\n"
        "        file: File,\n"
        "        maximumBytes: Long,\n"
        "        requireNonEmpty: Boolean,\n"
        "        authorityLabel: String,\n"
        "    ): PersistedFileFingerprint? {\n"
        "        val path = file.absolutePath\n"
        "        val pathBefore = try {\n"
        "            Os.lstat(path)\n"
        "        } catch (missing: ErrnoException) {\n"
        "            if (missing.errno == OsConstants.ENOENT) return null\n"
        "            throw missing\n"
        "        }\n"
        "        require(\n"
        "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
        "                pathBefore.st_nlink == 1L &&\n"
        "                pathBefore.st_size >= (if (requireNonEmpty) 1L else 0L) &&\n"
        "                pathBefore.st_size <= maximumBytes,\n"
        "        ) {\n"
        "            \"$authorityLabel authority is not one bounded single-link file\"\n"
        "        }\n"
        "        val descriptor = Os.open(\n"
        "            path,\n"
        "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,",
        "    private fun readRegularFileFingerprintIfFile(\n"
        "        file: File,\n"
        "        maximumBytes: Long,\n"
        "        requireNonEmpty: Boolean,\n"
        "        authorityLabel: String,\n"
        "    ): PersistedFileFingerprint? {\n"
        "        val path = file.absolutePath\n"
        "        val pathBefore = try {\n"
        "            Os.lstat(path)\n"
        "        } catch (missing: ErrnoException) {\n"
        "            if (missing.errno == OsConstants.ENOENT) return null\n"
        "            throw missing\n"
        "        }\n"
        "        require(\n"
        "            OsConstants.S_ISREG(pathBefore.st_mode) &&\n"
        "                pathBefore.st_nlink == 1L &&\n"
        "                pathBefore.st_size >= (if (requireNonEmpty) 1L else 0L) &&\n"
        "                pathBefore.st_size <= maximumBytes,\n"
        "        ) {\n"
        "            \"$authorityLabel authority is not one bounded single-link file\"\n"
        "        }\n"
        "        val descriptor = Os.open(\n"
        "            path,\n"
        "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC,",
        "backup fingerprint no-follow authority",
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
        "NATIVE_READER_V2_APK_LENGTH = 295451L",
        "NATIVE_READER_V2_APK_LENGTH = 250394L",
        "installed companion APK length pin",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "a576ba581a77f0438814ec13c1b1db211ebdd558d1042227db0ae62a0e085798",
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
        "                        withNativeSpreadConfigurationAuthority(\n"
        "                            configurationGeneration,\n"
        "                        ) {\n"
        "                            publishNativeMarkRecoveryJournal(\n"
        "                                pdfFile,\n"
        "                                marker,\n"
        "                                revalidatedBackup,\n"
        "                                configurationGeneration,\n"
        "                            )\n"
        "                        }\n"
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
        "            current.authority,\n"
        "            onCommitProven,",
        "            current.authority,\n"
        "            {},",
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
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "            boolean publicationAdmitted = physicalContactFence.runWhenStylusIdle(\n",
        "            boolean publicationAdmitted = true;\n"
        "            physicalContactFence.runWhenStylusIdle(\n",
        "physical stylus publication admission",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Runtime.java",
        "            || !inputAdmission.current(compositionFreeze)\n"
        "            || physicalContactFence.stylusContactActive()) {",
        "            || !inputAdmission.current(compositionFreeze)) {",
        "prepared publication physical-contact assertion",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                                            publication.run();\n"
        "                                            return true;",
        "                                            return true;",
        "hook-level atomic publication execution",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                val currentBackupResult = readNativeAnnotationBackup(pdfFile)",
        "                val currentBackupResult = backupResult",
        "post-handshake backup evidence reread",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                require(currentAuthority == authority) {",
        "                require(true) {",
        "post-handshake recovery authority equality",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            samePersistedAuthority(backup.manifestAuthority, currentManifest) &&",
        "            currentManifest != null &&",
        "backup manifest descriptor identity",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                    samePersistedFingerprint(\n"
        "                        backup.snapshotAuthority,\n"
        "                        currentSnapshot,\n"
        "                    )",
        "                    currentSnapshot != null",
        "backup snapshot fingerprint identity",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            val snapshotAuthority = readRegularFileFingerprintIfFile(\n"
        "                snapshot,",
        "            val snapshotAuthority = readRegularFileAuthorityIfFile(\n"
        "                snapshot,",
        "backup snapshot streaming admission authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        val currentSnapshot = readRegularFileFingerprintIfFile(\n"
        "            backup.snapshot,",
        "        val currentSnapshot = readRegularFileAuthorityIfFile(\n"
        "            backup.snapshot,",
        "backup snapshot streaming revalidation authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "                    if (contactStart) {\n"
        "                        synchronized (entry.stylusRouteLock) {",
        "                    if (contactStart) {\n"
        "                        if (true) {",
        "native callback DOWN publication lock",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "        if (action == MotionEvent.ACTION_DOWN) {\n"
        "            int index = event.getActionIndex();\n"
        "            synchronized (entry.stylusRouteLock) {",
        "        if (action == MotionEvent.ACTION_DOWN) {\n"
        "            int index = event.getActionIndex();\n"
        "            if (true) {",
        "Android DOWN publication lock",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            val loadGeneration = captureNativeSpreadConfigurationGeneration()",
        "            val loadGeneration = nativeSpreadConfigurationGeneration.get()",
        "native-mode load generation capture",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                Handler(Looper.getMainLooper()).post {\n"
        "                    try {\n"
        "                        withNativeSpreadConfigurationAuthority(\n"
        "                            configurationGeneration,\n"
        "                        ) {",
        "                Handler(Looper.getMainLooper()).post {\n"
        "                    try {\n"
        "                        run {",
        "native-mode main publication generation fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        digest.update(buffer, 0, count)",
        "                        digest.update(buffer, 0, count - 1)",
        "backup fingerprint complete-byte digest",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            expected.length == actual.length &&\n"
        "            expected.sha256 == actual.sha256",
        "            expected.length == actual.length",
        "backup fingerprint content equality",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            val marker = nativeSpreadMarker(pdfFile)\n"
        "            val configurationGeneration = beginNativeSpreadRecovery()",
        "            val marker = nativeSpreadMarker(pdfFile)\n"
        "            val configurationGeneration = captureNativeSpreadConfigurationGeneration()",
        "reconciliation recovery-generation admission",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            val pdfFile = requirePdf(filePath)\n"
        "            val configurationGeneration = beginNativeSpreadRecovery()\n"
        "            recoveryGeneration = configurationGeneration\n"
        "            recoveryClaimed = true",
        "            val pdfFile = requirePdf(filePath)\n"
        "            val configurationGeneration = captureNativeSpreadConfigurationGeneration()\n"
        "            recoveryGeneration = configurationGeneration\n"
        "            recoveryClaimed = true",
        "restore recovery-generation admission",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                    if (!completeNativeSpreadRecovery(configurationGeneration)) {\n"
        "                        throw IllegalStateException(\n"
        "                            \"Native Spread recovery was superseded before completion\",",
        "                    if (false) {\n"
        "                        throw IllegalStateException(\n"
        "                            \"Native Spread recovery was superseded before completion\",",
        "reconciliation terminal recovery-generation fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        if (!completeNativeSpreadRecovery(configurationGeneration)) {\n"
        "                            annotationRecoveryHandoffPending.set(false)",
        "                        if (false) {\n"
        "                            annotationRecoveryHandoffPending.set(false)",
        "restore terminal recovery-generation fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "    private fun beginNativeSpreadRecovery(): Long =\n"
        "        synchronized(nativeSpreadConfigurationIntentLock) {\n"
        "            check(!nativeSpreadModuleInvalidated.get())",
        "    private fun beginNativeSpreadRecovery(): Long =\n"
        "        synchronized(nativeSpreadConfigurationIntentLock) {\n"
        "            check(true)",
        "recovery admission module-validity fence",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            if (!annotationRecoveryPending.compareAndSet(false, true)) {",
        "            if (false) {",
        "recovery single-owner admission",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            val exactOwner = nativeSpreadRecoveryOwnerGeneration.compareAndSet(\n"
        "                expected,\n"
        "                NATIVE_SPREAD_NO_RECOVERY_OWNER,\n"
        "            )",
        "            val exactOwner = true",
        "recovery exact-owner release",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            nativeSpreadRecoveryOwnerGeneration.set(generation)\n"
        "            generation",
        "            nativeSpreadRecoveryOwnerGeneration.get()\n"
        "            generation",
        "recovery owner recorded at admission",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            if (!exactOwner) return@synchronized false\n"
        "            val owned = annotationRecoveryPending.compareAndSet(true, false)",
        "            if (false) return@synchronized false\n"
        "            val owned = annotationRecoveryPending.compareAndSet(true, false)",
        "stale recovery retry cannot release replacement owner",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                    try {\n"
        "                        withNativeSpreadConfigurationAuthority(\n"
        "                            configurationGeneration,\n"
        "                        ) {\n"
        "                            publication = publishNativeAnnotationRestore(",
        "                    try {\n"
        "                        run {\n"
        "                            publication = publishNativeAnnotationRestore(",
        "restore publication generation authority",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "    ) {\n"
        "        try {\n"
        "            val configurationGeneration = beginNativeSpreadConfiguration()\n"
        "            if (enabled) {",
        "    ) {\n"
        "        val configurationGeneration = beginNativeSpreadConfiguration()\n"
        "        try {\n"
        "            if (enabled) {",
        "read-only configuration recovery rejection settlement",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "    ) {\n"
        "        try {\n"
        "            val configurationGeneration = beginNativeSpreadConfiguration()\n"
        "            val pdfFile = requirePdf(filePath)",
        "    ) {\n"
        "        val configurationGeneration = beginNativeSpreadConfiguration()\n"
        "        try {\n"
        "            val pdfFile = requirePdf(filePath)",
        "editable configuration recovery rejection settlement",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        val currentMarkerAuthority = readPersistedAuthorityIfFile(marker)\n"
        "        if (!samePersistedAuthority(expectedMarkerAuthority, currentMarkerAuthority)) {",
        "        val currentMarkerAuthority = readPersistedAuthorityIfFile(marker)\n"
        "        if (currentMarkerAuthority == null) {",
        "pending-marker restoration exact authority comparison",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                \"Interrupted Native Reader activation OFF authority\",\n"
        "                expectedMarkerAuthority,\n"
        "            )",
        "                \"Interrupted Native Reader activation OFF authority\",\n"
        "                null,\n"
        "            )",
        "pending-marker null restoration compare-and-publish",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "            writeBytesAtomicallyCas(\n"
        "                marker,\n"
        "                previousBytes,\n"
        "                expectedMarkerAuthority,\n"
        "            )",
        "            writeBytesAtomically(marker, previousBytes)",
        "pending-marker bytes restoration compare-and-swap",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "        val markerAuthority = readPersistedAuthorityIfFile(marker)\n"
        "        val markerProperties = markerAuthority?.let { authority ->\n"
        "            strictNativeSpreadMarkerProperties(authority.bytes)\n"
        "        } ?: Properties()",
        "        val markerProperties = readPropertiesIfFile(marker)\n"
        "        val markerAuthority = readPersistedAuthorityIfFile(marker)",
        "reconciliation exact pending-marker descriptor snapshot",
    ),
    (
        "native/ReaderPreferencesModule.kt.template",
        "                        // This routine never guesses: every destructive branch is\n"
        "                        // gated by the pending token, document/marker identity, and\n"
        "                        // exact backup/archive hashes. Ambiguous evidence is kept.\n"
        "                        withNativeSpreadPublicationLock(marker) {",
        "                        // This routine never guesses: every destructive branch is\n"
        "                        // gated by the pending token, document/marker identity, and\n"
        "                        // exact backup/archive hashes. Ambiguous evidence is kept.\n"
        "                        run {",
        "reconciliation cross-process publication lock",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "Thread worker = authorityObservationWorker\n"
        "                                .getAndSet(null);\n"
        "                            if (worker != null) worker.interrupt();",
        "Thread worker = authorityObservationWorker.get();",
        "expired authority observation worker replacement",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "Thread worker = new Thread(new Runnable() {",
        "ADMISSION.execute(new Runnable() {",
        "authority ACK isolation from admission worker",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "|| !documentIdentity.sha256.equals(\n"
        "                        payload.getProperty(\"documentSha256\"))",
        "|| false && !documentIdentity.sha256.equals(\n"
        "                        payload.getProperty(\"documentSha256\"))",
        "authority ACK live PDF digest binding",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "|| !Arrays.equals(bytes.bytes, bytesAfter.bytes))",
        "|| false)",
        "authority ACK journal reread binding",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "openedDocument.verifyUnchangedAndCurrent(canonical);\n"
        "                if (!NativeReaderV2Config.ENGINE_VALUE.equals(",
        "if (!NativeReaderV2Config.ENGINE_VALUE.equals(",
        "authority ACK post-journal PDF revalidation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2Hooks.java",
        "entry.retryAdmissionAfterAuthorityOff = true;",
        "entry.retryAdmissionAfterAuthorityOff = false;",
        "recovery OFF re-admission trigger",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2/NativeReaderV2MarkerClaim.java",
        "originalMarkPresent && (markLength < 0L",
        "originalMarkPresent && (markLength <= 0L",
        "empty regular mark acceptance",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "LIVE_MARK_CHECKPOINT_FIELDS.equals(\n"
        "                properties.stringPropertyNames())",
        "properties.stringPropertyNames().containsAll(\n"
        "                LIVE_MARK_CHECKPOINT_FIELDS)",
        "witness checkpoint exact schema",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "|| !claim.backupManifestSha256.equals(\n"
        "                properties.getProperty(\"backupManifestSha256\"))",
        "|| false && !claim.backupManifestSha256.equals(\n"
        "                properties.getProperty(\"backupManifestSha256\"))",
        "witness checkpoint recovery binding",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "if (!liveMarkMatchesRecovery(claim, liveMark)) {",
        "if (false) {",
        "cold admission requires witnessed changed mark authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "checkpointExecutor.execute(new Runnable() {",
        "return; // checkpoint publication removed\n"
        "                checkpointExecutor.execute(new Runnable() {",
        "witnessed save checkpoint scheduling",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "FileDescriptor parentDescriptor = openPinnedDirectory(\n"
        "            parent.getAbsolutePath()\n"
        "        );\n"
        "        File temporary = new File(",
        "FileDescriptor parentDescriptor = Os.open(\n"
        "            parent.getAbsolutePath(),\n"
        "            OsConstants.O_RDONLY | OsConstants.O_CLOEXEC,\n"
        "            0\n"
        "        );\n"
        "        File temporary = new File(",
        "witness checkpoint FUSE-safe pinned parent",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "String checkpointPath = claim.markPath + LIVE_MARK_CHECKPOINT_SUFFIX;\n"
        "        requireNoPendingLiveMarkCheckpoint(checkpointPath);",
        "String checkpointPath = claim.markPath + LIVE_MARK_CHECKPOINT_SUFFIX;",
        "cold checkpoint admission pending-publication fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "requireNoPendingLiveMarkCheckpoint(\n"
        "                    claim.markPath + LIVE_MARK_CHECKPOINT_SUFFIX\n"
        "                );\n"
        "                requireLiveMarkWriterLeaseCurrent(\n"
        "                    leasePath,\n"
        "                    stream.getFD(),\n"
        "                    descriptorIdentity\n"
        "                );\n"
        "                LiveMarkState liveMark",
        "LiveMarkState liveMark",
        "recovery-baseline admission pending-publication fence",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "StableBytes verified = readRegularFile(\n"
        "                checkpoint.getAbsolutePath(),",
        "Os.remove(pending.getAbsolutePath());\n"
        "            StableBytes verified = readRegularFile(\n"
        "                checkpoint.getAbsolutePath(),",
        "verified checkpoint precedes pending-fence retirement",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "Os.dup(pendingDescriptor))) {\n"
        "                output.write(bytes);",
        "Os.dup(pendingDescriptor))) {\n"
        "                output.write(new byte[0]);",
        "pending checkpoint fence carries authenticated intent",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "            commitValidator.validate();",
        "            // final checkpoint validation removed",
        "pending fence spans final checkpoint validation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "                reconcilePendingLiveMarkCheckpoint(\n"
        "                    claim,\n"
        "                    leasePath,\n"
        "                    stream.getFD(),\n"
        "                    descriptorIdentity\n"
        "                );\n"
        "                requireNoPendingLiveMarkCheckpoint(",
        "                requireNoPendingLiveMarkCheckpoint(",
        "exclusive writer reconciles stopped checkpoint publication",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "                requireLiveMarkWriterLeaseCurrent(\n"
        "                    leasePath,\n"
        "                    leaseDescriptor,\n"
        "                    leaseIdentity\n"
        "                );\n"
        "                Os.remove(checkpointPath);",
        "                Os.remove(checkpointPath);",
        "baseline checkpoint retirement retains writer lease authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "            requireLiveMarkWriterLeaseCurrent(\n"
        "                leasePath,\n"
        "                leaseDescriptor,\n"
        "                leaseIdentity\n"
        "            );\n"
        "            Os.remove(pendingPath);",
        "            Os.remove(pendingPath);",
        "pending checkpoint retirement retains writer lease authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "                requireNoPendingLiveMarkCheckpoint(\n"
        "                    claim.markPath + LIVE_MARK_CHECKPOINT_SUFFIX\n"
        "                );\n"
        "                requireLiveMarkWriterLeaseCurrent(\n"
        "                    leasePath,\n"
        "                    stream.getFD(),\n"
        "                    descriptorIdentity\n"
        "                );",
        "                requireNoPendingLiveMarkCheckpoint(\n"
        "                    claim.markPath + LIVE_MARK_CHECKPOINT_SUFFIX\n"
        "                );",
        "cold admission revalidates writer lease after reconciliation",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "if (!Arrays.equals(pending.bytes, published.bytes)\n"
        "                    || intended.generation",
        "if (false\n"
        "                    || intended.generation",
        "pending recovery exact checkpoint-byte authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "boolean restoredBaseline = liveMarkMatchesRecovery(claim, live);",
        "boolean restoredBaseline = false;",
        "pending recovery exact rollback-baseline authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "if (restoredBaseline && pathExistsNoFollow(checkpointPath)) {",
        "if (false) {",
        "baseline recovery retires obsolete checkpoint authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "                Os.remove(checkpointPath);",
        "                // obsolete checkpoint retirement removed",
        "baseline recovery removes obsolete checkpoint",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "StableBytes pendingAfterRetirement = readRegularFile(",
        "StableBytes pendingAfterRetirement = pending; // final read removed\n"
        "                if (false) readRegularFile(",
        "baseline recovery revalidates pending fence after retirement",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "!pending.identity.sameVersion(pendingAfter.identity)\n"
        "                || !Arrays.equals(pending.bytes, pendingAfter.bytes)",
        "!Arrays.equals(pending.bytes, pendingAfter.bytes)",
        "pending recovery final fence inode authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "!published.identity.sameVersion(\n"
        "                            checkpointAfter.identity)\n"
        "                        || !Arrays.equals(",
        "false\n"
        "                        || !Arrays.equals(",
        "pending recovery final checkpoint-inode authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "|| !Arrays.equals(\n"
        "                            pending.bytes,\n"
        "                            checkpointAfter.bytes",
        "|| false",
        "pending recovery final checkpoint-byte authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "if (!revalidateForCheckpoint()) {\n"
        "                    throw new IllegalStateException(\n"
        "                        \"live mark writer lease changed before checkpoint\"",
        "if (true) {\n"
        "                    throw new IllegalStateException(\n"
        "                        \"live mark writer lease changed before checkpoint\"",
        "witness checkpoint live writer lease binding",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "if (drained) {\n"
        "                releaseLeaseAfterCheckpointDrain();\n"
        "                return;\n"
        "            }",
        "if (drained) {\n"
        "                return;\n"
        "            }",
        "checkpoint drain retains writer lease",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "if (closed || (closing && !allowClosing) || unsafe\n"
        "                || lease == null || !lease.isValid()) {",
        "if (closed || unsafe\n"
        "                || lease == null || !lease.isValid()) {",
        "closing mark authority rejects new runtime work",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "commitValidator.validate();\n"
        "            StableBytes checkpointAtCommit = readRegularFile(\n"
        "                checkpoint.getAbsolutePath(),",
        "commitValidator.validate();\n"
        "            StableBytes checkpointAtCommit = checkpointAfterValidation;\n"
        "            if (false) readRegularFile(\n"
        "                checkpoint.getAbsolutePath(),",
        "checkpoint publication revalidates exact file after final callback",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "|| !pendingIdentity.sameVersion(pendingAtCommit.identity)\n"
        "                || !Arrays.equals(bytes, pendingAtCommit.bytes)",
        "|| !Arrays.equals(bytes, pendingAtCommit.bytes)",
        "checkpoint publication final pending inode authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "RecoveryIdentity recoveryAtCommit = verifyRecoveryEvidence(\n"
        "                claim,\n"
        "                new File(claim.canonicalDocumentPath)\n"
        "            );",
        "RecoveryIdentity recoveryAtCommit = recoveryAfter;",
        "stopped-process recovery revalidates authority at unlink boundary",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "throw new CheckpointSupersededException(\n"
        "                                        generation,\n"
        "                                        witnessGeneration\n"
        "                                    );",
        "throw new IllegalStateException(\n"
        "                                        \"checkpoint generation changed\"\n"
        "                                    );",
        "newer save receives recoverable checkpoint supersession",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "                    retireSupersededCheckpoint(\n"
        "                        generation,\n"
        "                        attemptedCheckpointBytes\n"
        "                    );",
        "                    throw superseded;",
        "superseded checkpoint fence is retired before queued save",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "|| !Arrays.equals(\n"
        "                        attemptedCheckpointBytes,\n"
        "                        pendingBytes.bytes)\n"
        "                    || !Arrays.equals(\n"
        "                        attemptedCheckpointBytes,\n"
        "                        checkpointBytes.bytes)",
        "|| !Arrays.equals(\n"
        "                        pendingBytes.bytes,\n"
        "                        checkpointBytes.bytes)",
        "superseded retirement binds exact attempted checkpoint bytes",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "RecoveryIdentity recoveryAtCommit = verifyRecoveryEvidence(\n"
        "                    claim,\n"
        "                    new File(claim.canonicalDocumentPath)\n"
        "                );",
        "RecoveryIdentity recoveryAtCommit = recovery;",
        "superseded fence retirement final recovery authority",
    ),
    (
        "native-spread-module/src/com/techrebbe/supernote/spreadprobe/"
        "v2android/NativeReaderV2DocumentGate.java",
        "// Final lease identity is checked after both exact file rereads.\n"
        "                requireLiveMarkWriterLeaseCurrent(",
        "// Final lease identity check removed.\n"
        "                if (false) requireLiveMarkWriterLeaseCurrent(",
        "superseded fence retirement final lease identity",
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
        self.recovery_pending = False
        self.recovery_owner = None

    def begin(self) -> int:
        if self.invalidated:
            raise _InterleavingRejected("module was invalidated")
        if self.recovery_pending:
            raise _InterleavingRejected("recovery is in progress")
        self.generation += 1
        return self.generation

    def capture(self) -> int:
        if self.invalidated:
            raise _InterleavingRejected("module was invalidated")
        if self.recovery_pending:
            raise _InterleavingRejected("recovery is in progress")
        return self.generation

    def begin_recovery(self) -> int:
        if self.invalidated:
            raise _InterleavingRejected("module was invalidated")
        if self.recovery_pending:
            raise _InterleavingRejected("recovery is in progress")
        if self.recovery_owner is not None:
            raise _InterleavingRejected("recovery owner is inconsistent")
        self.recovery_pending = True
        self.generation += 1
        self.recovery_owner = self.generation
        return self.generation

    def complete_recovery(self, expected: int) -> bool:
        if self.recovery_owner != expected:
            return False
        self.recovery_owner = None
        if not self.recovery_pending:
            return False
        self.recovery_pending = False
        current = not self.invalidated and self.generation == expected
        if current:
            self.generation += 1
        return current

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


class _PendingMarkerAuthorityStore:
    """Executable model of descriptor identity plus pathname CAS restoration."""

    def __init__(self, value: bytes):
        self._serial = 1
        self.current = (self._serial, value)

    def replace(self, value: bytes) -> tuple[int, bytes]:
        self._serial += 1
        self.current = (self._serial, value)
        return self.current

    def restore(self, expected, previous: bytes | None, before_cas=lambda: None) -> None:
        # The Kotlin helper performs both checks: descriptor-backed equality
        # rejects an already-stale caller, while the path CAS closes a
        # replacement that races between that check and publication.
        if self.current != expected:
            raise _InterleavingRejected("pending marker changed before restoration")
        before_cas()
        if self.current != expected:
            raise _InterleavingRejected("pending marker changed at restoration CAS")
        if previous is None:
            self.current = None
        else:
            self.replace(previous)


def run_pending_marker_restore_interleaving_tests() -> None:
    store = _PendingMarkerAuthorityStore(b"pending-a")
    stale_authority = store.current
    replacement = store.replace(b"pending-b")
    try:
        store.restore(stale_authority, b"previous-a")
        raise AssertionError("stale reconciler overwrote a newer pending marker")
    except _InterleavingRejected:
        assert store.current == replacement

    exact_authority = store.current
    store.restore(exact_authority, b"previous-b")
    assert store.current[1] == b"previous-b"

    exact_delete_authority = store.current
    store.restore(exact_delete_authority, None)
    assert store.current is None

    store = _PendingMarkerAuthorityStore(b"pending-c")
    raced_authority = store.current
    try:
        store.restore(
            raced_authority,
            b"previous-c",
            before_cas=lambda: store.replace(b"pending-d"),
        )
        raise AssertionError("pathname replacement raced through restoration CAS")
    except _InterleavingRejected:
        assert store.current[1] == b"pending-d"
    print("Native Reader v2 pending-marker restoration interleavings: PASS")


def _model_post_rename_identity_capture(identity_reader, on_published):
    """Model Kotlin's try/finally around the irreversible rename boundary."""
    try:
        return identity_reader()
    finally:
        on_published()


def run_post_rename_publication_boundary_tests() -> None:
    state = {"publications": 0}

    def published() -> None:
        state["publications"] += 1

    try:
        _model_post_rename_identity_capture(
            lambda: (_ for _ in ()).throw(OSError("post-rename fstat failed")),
            published,
        )
        raise AssertionError("post-rename descriptor fault was not propagated")
    except OSError as error:
        assert str(error) == "post-rename fstat failed"
    assert state == {"publications": 1}

    observed = _model_post_rename_identity_capture(lambda: "identity", published)
    assert observed == "identity"
    assert state == {"publications": 2}
    print("Native Reader v2 post-rename publication boundary: PASS")


def run_marker_snapshot_revalidation_tests() -> None:
    """Model the one-snapshot load fence across an asynchronous handshake."""
    persisted = {"identity": 1, "bytes": b"coverSeparate=false"}
    snapshot = dict(persisted)

    def publish_loaded_settings() -> str:
        if persisted != snapshot:
            raise _InterleavingRejected("marker changed while settings loaded")
        return "published"

    assert publish_loaded_settings() == "published"
    persisted["identity"] = 2
    persisted["bytes"] = b"coverSeparate=true"
    try:
        publish_loaded_settings()
        raise AssertionError("stale marker settings were published")
    except _InterleavingRejected as error:
        assert str(error) == "marker changed while settings loaded"
    print("Native Reader v2 marker snapshot revalidation: PASS")


def run_backup_snapshot_revalidation_tests() -> None:
    """Model recovery-evidence revalidation across an asynchronous handshake."""
    persisted = {
        "status": "verified",
        "manifest_identity": 11,
        "manifest_sha256": "manifest-a",
        "snapshot_identity": 12,
        "snapshot_sha256": "snapshot-a",
    }
    snapshot = dict(persisted)

    def publish_loaded_recovery() -> str:
        if persisted != snapshot:
            raise _InterleavingRejected(
                "recovery evidence changed while settings loaded"
            )
        return "published"

    assert publish_loaded_recovery() == "published"
    persisted["manifest_identity"] = 21
    persisted["manifest_sha256"] = "manifest-b"
    try:
        publish_loaded_recovery()
        raise AssertionError("stale backup capability was published")
    except _InterleavingRejected as error:
        assert str(error) == "recovery evidence changed while settings loaded"

    persisted.clear()
    persisted.update(snapshot)
    persisted["status"] = "invalid:snapshot_missing"
    persisted.pop("snapshot_identity")
    persisted.pop("snapshot_sha256")
    try:
        publish_loaded_recovery()
        raise AssertionError("removed recovery snapshot was published as available")
    except _InterleavingRejected as error:
        assert str(error) == "recovery evidence changed while settings loaded"
    print("Native Reader v2 backup snapshot revalidation: PASS")


def run_physical_contact_publication_fence_tests() -> None:
    """Model an atomic choice between stylus DOWN and native publication."""
    state = {"stylus": False, "deferred": False, "publications": 0}

    def publish_if_idle() -> bool:
        if state["stylus"]:
            state["deferred"] = True
            return False
        state["publications"] += 1
        return True

    # DOWN wins the shared hook lock: publication waits for the terminal edge.
    state["stylus"] = True
    assert not publish_if_idle()
    assert state == {"stylus": True, "deferred": True, "publications": 0}
    state["stylus"] = False
    if state["deferred"]:
        state["deferred"] = False
        assert publish_if_idle()
    assert state == {"stylus": False, "deferred": False, "publications": 1}

    # Publication wins the same lock: a later DOWN begins only after commit.
    assert publish_if_idle()
    state["stylus"] = True
    assert state == {"stylus": True, "deferred": False, "publications": 2}
    print("Native Reader v2 physical-contact publication fence: PASS")


def run_committed_marker_verification_failure_tests() -> None:
    """Publication suppresses rollback but never turns failed verification into success."""
    state = {"published": False, "verified": False, "rollbacks": 0}

    def activate(commit) -> str:
        try:
            result = commit(lambda: state.update(published=True))
            state["verified"] = True
            return result
        except OSError:
            if state["published"]:
                raise
            state["rollbacks"] += 1
            raise

    def fail_after_publish(on_published):
        on_published()
        raise OSError("post-publication verification failed")

    try:
        activate(fail_after_publish)
        raise AssertionError("post-publication verification failure became success")
    except OSError as error:
        assert str(error) == "post-publication verification failed"
    assert state == {"published": True, "verified": False, "rollbacks": 0}

    state.update(published=False, verified=False, rollbacks=0)

    def fail_before_publish(_on_published):
        raise OSError("pre-publication failure")

    try:
        activate(fail_before_publish)
        raise AssertionError("pre-publication failure became success")
    except OSError as error:
        assert str(error) == "pre-publication failure"
    assert state == {"published": False, "verified": False, "rollbacks": 1}

    state.update(published=False, verified=False, rollbacks=0)

    def succeed(on_published):
        on_published()
        return "verified"

    assert activate(succeed) == "verified"
    assert state == {"published": True, "verified": True, "rollbacks": 0}
    print("Native Reader v2 committed marker verification failures: PASS")


def run_configuration_generation_interleaving_tests() -> None:
    gate = _ConfigurationGenerationGate()
    state = {"marker": "off", "pending": None}

    # Recovery entry advances the same generation that guards a mode-load
    # publication. While the mutation is active, neither a new load nor a
    # competing configuration can join its generation. Completion advances it
    # again so no load sampled during recovery can publish afterward.
    load_generation = gate.capture()
    recovery_generation = gate.begin_recovery()
    stale_load = {"results": []}
    gate.complete(
        load_generation,
        "ready",
        lambda result: stale_load["results"].append(result),
    )
    assert stale_load == {"results": ["stale_operation"]}
    for blocked in (gate.capture, gate.begin):
        try:
            blocked()
            raise AssertionError("recovery allowed overlapping configuration")
        except _InterleavingRejected as error:
            assert str(error) == "recovery is in progress"
    assert gate.complete_recovery(recovery_generation)
    assert gate.generation == recovery_generation + 1
    assert not gate.recovery_pending
    assert gate.recovery_owner is None

    # A superseded owner may retry its completion after a replacement recovery
    # has entered. The retry must compare the exact owner token before clearing
    # the replacement's public pending fence.
    superseded_recovery = gate.begin_recovery()
    gate.generation += 1
    assert not gate.complete_recovery(superseded_recovery)
    replacement_recovery = gate.begin_recovery()
    assert not gate.complete_recovery(superseded_recovery)
    assert gate.recovery_pending
    assert gate.recovery_owner == replacement_recovery
    assert gate.complete_recovery(replacement_recovery)

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


def run_live_mark_checkpoint_recovery_tests(temp_root: pathlib.Path) -> None:
    """Model the two safe stopped-publisher recovery outcomes."""

    def reconcile(
        root: pathlib.Path,
        baseline: bytes,
        live: bytes,
        intended: bytes,
    ) -> None:
        pending = root / "book.pdf.mark.snspread-live-mark-v1.pending"
        checkpoint = root / "book.pdf.mark.snspread-live-mark-v1"
        pending_bytes = pending.read_bytes()
        if live != baseline:
            if pending_bytes != intended:
                raise _InterleavingRejected("pending intent changed")
            if not checkpoint.exists() or checkpoint.read_bytes() != intended:
                raise _InterleavingRejected("checkpoint publication incomplete")
            if live != b"live:" + intended:
                raise _InterleavingRejected("live mark disagrees with checkpoint")
        elif checkpoint.exists():
            checkpoint.unlink()
        if pending.read_bytes() != pending_bytes:
            raise _InterleavingRejected("pending intent changed before commit")
        pending.unlink()

    def scenario(name: str) -> pathlib.Path:
        root = temp_root / "live-mark-checkpoint" / name
        root.mkdir(parents=True)
        return root

    intended = b"authenticated-checkpoint-v1"
    baseline = b"rollback-baseline"

    # Crash after canonical checkpoint publication: the exact checkpoint and
    # exact live mark complete the interrupted publication under a new lease.
    root = scenario("published-before-final-validation")
    (root / "book.pdf.mark.snspread-live-mark-v1.pending").write_bytes(intended)
    (root / "book.pdf.mark.snspread-live-mark-v1").write_bytes(intended)
    reconcile(root, baseline, b"live:" + intended, intended)
    assert not (root / "book.pdf.mark.snspread-live-mark-v1.pending").exists()

    # Exact rollback restore independently makes the interrupted newer
    # checkpoint obsolete, even if rename never published it.
    root = scenario("rollback-baseline-restored")
    pending = root / "book.pdf.mark.snspread-live-mark-v1.pending"
    pending.write_bytes(b"torn-pending-record")
    stale = root / "book.pdf.mark.snspread-live-mark-v1"
    stale.write_bytes(b"obsolete-checkpoint")
    reconcile(root, baseline, baseline, intended)
    assert not pending.exists()
    assert not stale.exists()

    for name, checkpoint, live, pending_bytes in (
        ("crash-before-rename", None, b"live:" + intended, intended),
        ("wrong-published-checkpoint", b"other", b"live:" + intended, intended),
        ("unwitnessed-live-mark", intended, b"unwitnessed", intended),
        ("corrupt-pending-intent", intended, b"live:" + intended, b"corrupt"),
    ):
        root = scenario(name)
        pending = root / "book.pdf.mark.snspread-live-mark-v1.pending"
        pending.write_bytes(pending_bytes)
        if checkpoint is not None:
            (root / "book.pdf.mark.snspread-live-mark-v1").write_bytes(
                checkpoint
            )
        try:
            reconcile(root, baseline, live, intended)
            raise AssertionError(f"unsafe checkpoint recovery accepted: {name}")
        except _InterleavingRejected:
            assert pending.exists()

    # A later witnessed save may supersede an older publication while its
    # fence is still present.  The single checkpoint worker retires only that
    # exact older fence, leaves the now-stale checkpoint fail closed, and then
    # publishes the queued newest generation.
    root = scenario("newer-save-supersedes-published-checkpoint")
    pending = root / "book.pdf.mark.snspread-live-mark-v1.pending"
    checkpoint = root / "book.pdf.mark.snspread-live-mark-v1"
    older = b"authenticated-checkpoint-generation-7"
    newest = b"authenticated-checkpoint-generation-8"
    pending.write_bytes(older)
    checkpoint.write_bytes(older)
    observed_pending = pending.read_bytes()
    observed_checkpoint = checkpoint.read_bytes()
    if observed_pending != older or observed_checkpoint != older:
        raise AssertionError("superseded checkpoint setup changed")
    pending.unlink()
    assert checkpoint.read_bytes() == older
    assert b"live:" + newest != b"live:" + checkpoint.read_bytes()
    pending.write_bytes(newest)
    checkpoint.write_bytes(newest)
    assert pending.read_bytes() == checkpoint.read_bytes() == newest
    pending.unlink()
    assert checkpoint.read_bytes() == newest

    root = scenario("superseded-fence-replaced-before-retirement")
    pending = root / "book.pdf.mark.snspread-live-mark-v1.pending"
    checkpoint = root / "book.pdf.mark.snspread-live-mark-v1"
    pending.write_bytes(older)
    checkpoint.write_bytes(older)
    observed_pending = pending.read_bytes()
    pending.write_bytes(b"replacement")
    try:
        if pending.read_bytes() != observed_pending:
            raise _InterleavingRejected("superseded fence changed")
        pending.unlink()
        raise AssertionError("replaced superseded fence was retired")
    except _InterleavingRejected:
        assert pending.exists()

    root = scenario("superseded-pair-replaced-with-same-generation")
    pending = root / "book.pdf.mark.snspread-live-mark-v1.pending"
    checkpoint = root / "book.pdf.mark.snspread-live-mark-v1"
    replacement = b"different-checkpoint-generation-7"
    pending.write_bytes(replacement)
    checkpoint.write_bytes(replacement)
    try:
        if pending.read_bytes() != older or checkpoint.read_bytes() != older:
            raise _InterleavingRejected(
                "replacement pair does not match attempted publication"
            )
        pending.unlink()
        raise AssertionError("replacement checkpoint pair was retired")
    except _InterleavingRejected:
        assert pending.exists()

    print("Native Reader v2 live-mark checkpoint recovery tests: PASS")


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
        "install_native.py",
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
        run_pending_marker_restore_interleaving_tests()
        run_post_rename_publication_boundary_tests()
        run_marker_snapshot_revalidation_tests()
        run_backup_snapshot_revalidation_tests()
        run_physical_contact_publication_fence_tests()
        run_committed_marker_verification_failure_tests()
        run_no_clobber_interleaving_tests(temp_root)
        run_durable_recovery_fence_tests(temp_root)
        run_live_mark_checkpoint_recovery_tests(temp_root)
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
