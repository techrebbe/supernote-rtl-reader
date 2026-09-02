#!/usr/bin/env python3
"""Fail-closed source/package-boundary checks for exclusive Native Reader v2."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"check_native_reader_v2_invariants.py: {message}")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"could not read {path}: {error}")


def require(text: str, markers: list[str], label: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        fail(f"{label} is missing {missing!r}")


def ordered(text: str, markers: list[str], label: str) -> None:
    positions = [text.find(marker) for marker in markers]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail(f"{label} is missing or reordered: {markers!r}")


def normalized_sha256(path: Path) -> str:
    value = read(path).replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    module = root / "native-spread-module"
    source = module / "src/com/techrebbe/supernote/spreadprobe"
    entry = read(source / "v2android/NativeReaderV2EntryPoint.java")
    hooks = read(source / "v2android/NativeReaderV2Hooks.java")
    runtime = read(source / "v2android/NativeReaderV2Runtime.java")
    gate = read(source / "v2android/NativeReaderV2DocumentGate.java")
    package_gate = read(
        source / "v2android/NativeReaderV2PackageAdmission.java"
    )
    firmware_gate = read(
        source / "v2/android/NativeReaderFirmwareAdmission.java"
    )
    marker = read(source / "v2/NativeReaderV2MarkerClaim.java")
    transform = read(source / "v2/NativePageTransform.java")
    compositor = read(source / "v2android/NativeReaderV2Compositor.java")
    chrome_tracker = read(
        source / "v2android/NativeReaderV2ChromeTracker.java"
    )
    firmware = read(
        source / "v2android/NativeReaderV2FirmwareAccess.java"
    )
    status_overlay = read(
        source / "v2android/NativeReaderV2StatusOverlay.java"
    )
    build = read(module / "build.ps1")
    manifest = read(module / "AndroidManifest.xml")
    xposed = read(module / "assets/xposed_init").strip()
    workflow = read(root / ".github/workflows/build.yml")
    guidance = read(root / "AGENTS.md")
    plugin = read(root / "native/ReaderPreferencesModule.kt.template")
    app = read(root / "overlay/App.js")
    index = read(root / "overlay/index.js")
    plugin_config = read(root / "PluginConfig.json")

    expected_entry = (
        "com.techrebbe.supernote.spreadprobe.v2android."
        "NativeReaderV2EntryPoint"
    )
    if xposed != expected_entry:
        fail(f"xposed_init must contain only {expected_entry!r}")
    if (module / "assets/native_init").exists():
        fail("v2 assets must not auto-load the legacy native hook library")
    if read(module / "legacy-assets/native_init").strip() != "libspreadprobe.so":
        fail("preserved legacy native-init evidence changed")
    if normalized_sha256(source / "SpreadProbe.java") != (
        "7883f6bc72e9dced6066ff8873a993faa0b65ed970bd9911523819952d55f77f"
    ):
        fail("preserved v0.0.135 SpreadProbe source changed")
    if normalized_sha256(module / "native/spread_probe_native.cpp") != (
        "9584855fdefac7e7795d8ad34dde6b0d17ecfd8c93518d309f170af2bb882221"
    ):
        fail("preserved legacy native hook source changed")

    require(
        manifest,
        [
            'android:versionCode="136"',
            'android:versionName="0.0.136"',
            'android:label="Supernote Native Reader v2"',
        ],
        "v2 manifest",
    )
    require(
        plugin_config,
        ['"versionCode": "34"', '"versionName": "0.4.15"'],
        "plugin version",
    )
    if (
        '"${PYTHON_CMD[@]}" '
        '"$ROOT/scripts/check_native_reader_v2_invariants.py" "$ROOT"'
        not in read(root / "build.sh")
    ):
        fail("plugin build does not execute the exclusive v2 invariant gate")
    if "RTL_READER_OPEN v0.4.15-native-reader-v2" not in index:
        fail("runtime marker does not identify the v2 plugin build")
    require(
        guidance,
        [
            "python scripts/check_native_invariants.py .",
            "python scripts/check_native_reader_v2_invariants.py .",
            "python scripts/test_native_reader_v2_core.py .",
            "python scripts/test_native_reader_v2_mutations.py .",
            "python scripts/test_plugin_packaging_fail_closed.py",
            "legacy gate is expected to reject the v2 workflow",
        ],
        "Native Reader v2 repository validation guidance",
    )

    ordered(
        entry,
        [
            "NativeReaderV2PackageAdmission.verify(",
            "NativeReaderFirmwareAdmission.verify(",
            "NativeReaderV2Hooks.install(",
        ],
        "entry-point admission order",
    )
    require(
        entry,
        [
            '!TARGET_PACKAGE.equals(loadPackageParam.packageName)',
            '!TARGET_PACKAGE.equals(loadPackageParam.processName)',
            'log("rejected; no hooks installed: " + failure)',
        ],
        "entry-point containment",
    )
    if "com.techrebbe.supernote.spreadprobe.SpreadProbe" in entry:
        fail("v2 entry point references the experimental SpreadProbe")

    require(
        package_gate,
        [
            "EXPECTED_FINGERPRINT",
            "EXPECTED_APK_PATH",
            "EXPECTED_APK_LENGTH = 138486560L",
            "EXPECTED_APK_SHA256",
            "OsConstants.O_NOFOLLOW",
            "StructStat pathBefore = Os.lstat(EXPECTED_APK_PATH)",
            "StructStat pathAfter = Os.lstat(EXPECTED_APK_PATH)",
            "first.st_mtim.tv_nsec == second.st_mtim.tv_nsec",
            "first.st_ctim.tv_nsec == second.st_ctim.tv_nsec",
        ],
        "exact firmware package admission",
    )
    require(
        firmware_gate,
        [
            '"supernote-document-1.02.446-native-reader-v2-symbols-v5"',
            'method(IMAGE_VIEW, "setImageBitmap", "void",',
            'method(NOTE, "createSuperNoteNote", NOTE)',
            'method(NOTE, "markInitProcess", "boolean", "int")',
            'method(NOTE, "changeDirtyFlag", "void", "boolean")',
            'method(NOTE, "freeCommon", "void")',
            'method(DOCUMENT_CONSTANTS, "getDeviceType", "int")',
            'constructor(MATRIX,',
            'if ("C".equals(parts[0])) {',
            'owner.getDeclaredConstructor(parameterTypes);',
            'if (!"M".equals(parts[0])) {',
        ],
        "complete reflected firmware symbol admission",
    )
    require(
        hooks,
        [
            "installLifecycle(loader, hooks);",
            "installPresentation(loader, hooks);",
            "installNavigation(loader, hooks);",
            "installNativeChromeMasks(loader, hooks);",
            "installInput(loader, hooks);",
            "installSaveWitness(loader, hooks);",
            "hooks.get(index).unhook();",
            "if (entry.runtime != null && !entry.admitting)",
            "revalidateExistingRuntime(entry, path);",
            "expectedRuntime.admissionEvidenceStillCurrent()",
            "resetRuntime(entry, \"resume_authority_changed\")",
            "BY_COMPONENT.remove(previous, entry);",
            "containsIdentity(current, previous)",
            "BY_COMPONENT.putIfAbsent(component, entry)",
            "native component is claimed by another live activity",
            "firmware.releaseProjectionReader();",
            "native_chrome_discovery_failed",
            "refreshChromeAtContactStart(entry, runtime)",
            "chromeSnapshot(entry)",
            "if (chrome == null || entry.runtime != runtime)",
            "tracker.refresh();",
            "Passing the sample to\n                        // Supernote must not make the contact invisible to",
            "entry.penPass = beginStylusRoute(",
            "entry.androidPenPass = beginStylusRoute(",
            "private static boolean beginStylusRoute(",
            "Whichever stream observes DOWN first owns\n"
            "     * this single immutable decision",
            "synchronized (entry.stylusRouteLock)",
            "releaseStylusRouteIfComplete(entry);",
            "Stock onPause is the terminal boundary for both pen",
            "clearStylusContact(entry);",
            "volatile boolean androidPenContact;",
            "volatile boolean androidPenPass;",
            "volatile boolean resumed;",
            "volatile long lifecycleGeneration;",
            "entry.resumed = true;",
            "entry.resumed = false;",
            "final long admissionLifecycleGeneration = entry.lifecycleGeneration;",
            "if (!entry.resumed || entry.lifecycleGeneration !=",
        ],
        "hook installation and resume authority",
    )
    if "chrome(entry)" in hooks:
        fail("input hooks still rescan native chrome after contact classification")
    if hooks.count("tracker.refresh();") != 1:
        fail("native chrome must refresh exactly at immutable contact start")
    require(
        chrome_tracker,
        [
            "collectAdditionalWindows(decorArea, captured);",
            'throw new IllegalStateException(\n'
            '                    "native window inventory is not iterable"',
            "published = Collections.emptyList();",
            "retired = true;",
            "failureHandler.run();",
        ],
        "fail-closed native chrome inventory",
    )
    pen_contact_start = hooks.find("if (entry.penContact) {")
    pen_contact_end = hooks.find("} else {", pen_contact_start)
    if pen_contact_start < 0 or pen_contact_end < 0:
        fail("could not isolate native pen-contact routing branch")
    pen_contact = hooks[pen_contact_start:pen_contact_end]
    if "postOrRoutePen(entry, runtime, x, y, pressure, chrome);" not in pen_contact:
        fail(
            "native pass-through contacts must remain visible to the v2 "
            "gesture authority"
        )
    if "runtime.noteNativePenCallbackContact();" not in hooks:
        fail("native pen DOWN lacks callback-thread refresh exclusion")
    require(
        runtime,
        [
            "nativePenCallbackContact = !retired;",
            "scheduleRefresh(\"native_pen_contact_before_session\")",
        ],
        "portrait-safe native pen callback latch",
    )
    if "nativePenCallbackContact || currentSession != null" not in runtime:
        fail("presentation refresh can race callback-thread pen DOWN")
    if runtime.count("nativePenCallbackContact = false;") < 2:
        fail("native pen callback latch lacks terminal and retirement release")
    require(
        runtime,
        [
            "!claim.markPath.equals(current.markPath)",
            "claim.markPath.equals(components.markPath)",
            "if (hasLiveInputContact()) {",
            "beginNativeLifecycleHandoff(",
            "configuration_change_during_contact",
            "pause_during_contact",
            "private void completeNativeLifecycleHandoffIfReady()",
            "restoreWriterGeometry();",
            "restorePageGeometry();",
            "restorePresentationScale();",
        ],
        "live native mark-path and lifecycle authority",
    )
    same_page_start = runtime.find("public boolean prepareSamePageReload()")
    same_page_end = runtime.find(
        "public boolean prepareNativeDocumentOpen()",
        same_page_start,
    )
    if same_page_start < 0 or same_page_end < 0:
        fail("could not isolate same-page native reload preparation")
    ordered(
        runtime[same_page_start:same_page_end],
        [
            "saveCurrentSourceNow()",
            "firmware.disableWriter(",
            "restoreWriterGeometry();",
            "restorePageGeometry();",
            "restorePresentationScale();",
            "samePageReloadPrepared = true;",
            "retireTransactionalCore();",
        ],
        "same-page native presentation restoration",
    )
    lifecycle_start = runtime.find(
        "private void completeNativeLifecycleHandoffIfReady()"
    )
    lifecycle_end = runtime.find(
        "private boolean hasPhysicalInputContact()",
        lifecycle_start,
    )
    if lifecycle_start < 0 or lifecycle_end < 0:
        fail("could not isolate deferred native lifecycle restoration")
    ordered(
        runtime[lifecycle_start:lifecycle_end],
        [
            "saveCurrentSourceNow()",
            "firmware.disableWriter(",
            "restoreWriterGeometry();",
            "restorePageGeometry();",
            "restorePresentationScale();",
            "retireTransactionalCore();",
        ],
        "deferred native lifecycle restoration",
    )
    lifecycle_begin = runtime.find(
        "private void beginNativeLifecycleHandoff("
    )
    if lifecycle_begin < 0 or lifecycle_start < lifecycle_begin:
        fail("could not isolate native lifecycle handoff initiation")
    if (
        "pageGeometryLease = null;" in runtime[lifecycle_begin:lifecycle_start]
        or "presentationScaleLease = null;"
        in runtime[lifecycle_begin:lifecycle_start]
    ):
        fail("live-contact lifecycle handoff abandons restoration leases")
    require(
        hooks,
        [
            "entry.runtime.beforeLifecyclePause();",
            "entry.runtime.afterLifecyclePause();",
            "releaseDestroyedEntry(entry, \"activity_destroyed\");",
        ],
        "stock pause before/after settlement hooks",
    )
    lifecycle_admission = hooks[
        hooks.find("private static void maybeAdmit("):
        hooks.find("private static synchronized void registerHandshakeReceiver(")
    ]
    ordered(
        lifecycle_admission,
        [
            "final long admissionLifecycleGeneration = entry.lifecycleGeneration;",
            "if (!entry.resumed || entry.lifecycleGeneration !=",
            "entry.runtime = new NativeReaderV2Runtime(",
        ],
        "resumed-lifecycle admission fence",
    )
    destroy_hook = hooks.find('ACTIVITY, loader, "onDestroy"')
    destroy_release = hooks.find(
        'releaseDestroyedEntry(entry, "activity_destroyed");',
        destroy_hook,
    )
    if destroy_hook < 0 or destroy_release < 0:
        fail("native destroy after-hook cleanup is missing")
    destroy_segment = hooks[destroy_hook:destroy_release]
    if "beforeHookedMethod" in destroy_segment:
        fail("v2 restores or retires before Supernote's final destroy save")
    require(
        runtime,
        [
            "public void retireAfterNativeDestroy(String reason)",
            'removeStatusOverlayQuietly("native_activity_destroyed")',
        ],
        "post-native-destroy lease retirement",
    )
    revalidation_start = hooks.find(
        "private static void revalidateExistingRuntime("
    )
    revalidation_end = hooks.find(
        "private static synchronized void registerHandshakeReceiver(",
        revalidation_start,
    )
    if revalidation_start < 0 or revalidation_end < 0:
        fail("could not isolate resume revalidation method")
    revalidation = hooks[revalidation_start:revalidation_end]
    ordered(
        revalidation,
        [
            "entry.admitting = true;",
            "expectedRuntime.admissionEvidenceStillCurrent();",
            "resetRuntime(entry, \"resume_authority_changed\")",
        ],
        "resume revalidation publication",
    )
    reset_position = revalidation.find(
        'resetRuntime(entry, "resume_authority_changed")'
    )
    if reset_position < 0 or revalidation.find(
        "maybeAdmit(entry, true);", reset_position
    ) < 0:
        fail("resume authority reset does not retry admission")

    require(
        runtime,
        [
            "private volatile SpreadSession session;",
            "private volatile boolean inputFrozen;",
            "private volatile boolean retired;",
            "admissionEvidenceStillCurrent()",
            "NativeReaderV2DocumentGate.evidenceStillCurrent(evidence)",
            "NativeReaderV2DocumentGate.fastEvidenceStillCurrent(evidence)",
            "admitted document or recovery evidence changed",
            "private NativeReaderV2FirmwareAccess.Components inspectNativeCurrent()",
            "Revoking the external marker must stop all new authorized work",
            "disableNativeReaderV2(\"admission_evidence_changed\")",
            "return true;\n        if (inputFrozen) return false;",
            "scheduleActivationTimeout",
            "saveWitness.abort(token);",
            "presentationPublicationAttempted = true;",
            "restorePageGeometryQuietly(\"compose_failed\")",
            "restoreWriterGeometryQuietly(\"compose_failed\")",
            "SN_NATIVE_READER_V2 compose failed",
            "retire(reason, true);",
            "SN_NATIVE_READER_V2 fail-closed retirement",
            "current.handWriteView == components.handWriteView",
            "current.digestImage == components.digestImage",
            "current.documentLayout == components.documentLayout",
            "updateStatusOverlay(snapshot);",
            "removeStatusOverlayQuietly(\"portrait\")",
            "removeStatusOverlayQuietly(\"runtime_retire\")",
            'scheduleRefresh("native_pen_contact_complete");',
            'scheduleRefresh("native_finger_contact_complete");',
            "currentSession.gestures().hasActiveGesture()",
            "refresh deferred until native gesture completes",
            "refresh ignored during transaction phase=",
            "if (stable.markRevision == markRevision) return stable;",
            "stable.snapshot,\n                true,\n                markRevision",
        ],
        "runtime concurrency and input containment",
    )
    compose_start = runtime.find("private boolean composeAndPublish(")
    compose_end = runtime.find(
        "private void leaveSpreadForPortrait(",
        compose_start,
    )
    if compose_start < 0 or compose_end < 0:
        fail("could not isolate spread composition transaction")
    ordered(
        runtime[compose_start:compose_end],
        [
            "inputFrozen = true;",
            "next = compositor.compose(current, snapshot, activeInk);",
            'firmware.disableWriter(current, "SN_NATIVE_READER_V2 compose")',
            "presentationPublicationAttempted = true;",
            "firmware.setBackground(current, next.background);",
            "pageGeometryLease = firmware.programPageGeometry(",
            "firmware.programWriterGeometry(",
            "committed = true;",
        ],
        "read-only composition before native mutation",
    )
    require(
        runtime[compose_start:compose_end],
        [
            "boolean inputWasFrozen = inputFrozen;",
            "inputFrozen = inputWasFrozen;",
            "next.recycle();",
        ],
        "composition preflight rollback",
    )
    disable_start = runtime.find(
        "public void disableNativeReaderV2(String reason)"
    )
    disable_end = runtime.find(
        "private void refreshWhenReady(",
        disable_start,
    )
    if disable_start < 0 or disable_end < 0:
        fail("could not isolate fail-closed writer disable")
    disable_segment = runtime[disable_start:disable_end]
    if "inspectNativeCurrent()" not in disable_segment:
        fail("authority revocation can prevent native writer disable")
    if "inspectCurrent()" in disable_segment:
        fail("fail-closed writer disable still depends on revoked evidence")
    require(
        hooks,
        [
            'VIEW_MODEL, loader, "openDocument",',
            "entry.runtime.prepareNativeDocumentOpen();",
            'resetRuntime(',
            "entry.attemptedPath = null;",
        ],
        "pre-URI document replacement hook",
    )
    document_open = runtime.find("public boolean prepareNativeDocumentOpen()")
    document_open_end = runtime.find(
        "/** Restores stock page geometry before DocumentViewModel changes crop.",
        document_open,
    )
    if document_open < 0 or document_open_end < 0:
        fail("could not isolate native document-open relinquishment")
    ordered(
        runtime[document_open:document_open_end],
        [
            "inputFrozen = true;",
            "saveCurrentSourceNow()",
            "firmware.disableWriter(",
            "restoreWriterGeometry();",
            "restorePageGeometry();",
            "restorePresentationScale();",
            "retireTransactionalCore();",
            "firmware.releaseProjectionReader();",
        ],
        "pre-URI document replacement ordering",
    )
    routed_pen = runtime.find("if (penContact) {")
    pen_finish = runtime.find("if (pressure <= 0) {", routed_pen)
    refresh_gate = runtime.find(
        "private void refreshWhenReady(long generation, int attempt, String reason)"
    )
    if pen_finish < 0 or refresh_gate < 0:
        fail("could not isolate native-contact refresh containment")
    ordered(
        runtime[pen_finish:pen_finish + 900],
        [
            "clearPenRoute();",
            'scheduleRefresh("native_pen_contact_complete");',
        ],
        "post-contact authoritative refresh",
    )
    ordered(
        runtime[refresh_gate:refresh_gate + 900],
        [
            "generation != refreshGeneration",
            "nativePenCallbackContact",
            "currentSession.gestures().hasActiveGesture()",
            '"refresh deferred until native gesture completes reason="',
            "+ reason);\n            return;",
        ],
        "mid-gesture publication suppression",
    )
    refresh_segment = runtime[refresh_gate:refresh_gate + 1800]
    for phase in ["FROZEN", "SOURCE_SAVED", "TARGET_READY", "REPLAYING"]:
        if f"NativeReaderFirmwarePort.Phase.{phase}" not in refresh_segment:
            fail(f"refresh publication is not blocked during {phase}")
    phase_start = refresh_segment.find(
        "NativeReaderFirmwarePort currentPort = port;"
    )
    phase_log = refresh_segment.find(
        "refresh ignored during transaction phase=",
        phase_start,
    )
    phase_return = refresh_segment.find("return;", phase_log)
    phase_try = refresh_segment.find("try {", phase_return)
    if min(phase_start, phase_log, phase_return, phase_try) < 0:
        fail("transaction-phase refresh suppression is incomplete")
    forbidden_runtime = [
        "FileOutputStream",
        "ObjectOutputStream",
        "Instrumentation",
        "injectInputEvent",
        "PointMess",
    ]
    for forbidden in forbidden_runtime:
        if forbidden in runtime:
            fail(f"runtime contains prohibited authority shortcut {forbidden!r}")

    require(
        gate,
        [
            "document admission is forbidden on the main thread",
            "document revalidation is forbidden on the main thread",
            "StableBytes markerBefore",
            "StableDigest document = hashRegularFile(canonical)",
            "StableBytes markerAfter",
            "RecoveryIdentity recovery = verifyRecoveryEvidence(",
            "public static boolean fastEvidenceStillCurrent(Evidence evidence)",
            "evidence.recoveryManifestIdentity.sameVersion(",
            "evidence.recoverySnapshotIdentity.sameVersion(",
            "!pathExistsNoFollow(evidence.claim.backupSnapshotPath)",
            "recovery manifest bytes disagree with marker authority",
            "recovery snapshot bytes disagree with marker authority",
            "RECOVERY_MANIFEST_FIELDS.equals(",
            "strictNonNegativeDecimal(recovery, \"documentModified\")",
            "modifiedNanos",
            "changedNanos",
            "OsConstants.O_NOFOLLOW",
        ],
        "document and recovery admission",
    )
    ordered(
        gate,
        [
            "StableBytes markerBefore",
            "StableDigest document = hashRegularFile(canonical)",
            "StableBytes markerAfter",
            "NativeReaderV2MarkerClaim.admit(",
            "RecoveryIdentity recovery = verifyRecoveryEvidence(",
        ],
        "descriptor-backed document admission",
    )

    require(
        marker,
        [
            "MINIMUM_COMPANION_MODULE_VERSION = 136L",
            "COMMITTED_FIELDS.equals(properties.stringPropertyNames())",
            "minimumVersion != MINIMUM_COMPANION_MODULE_VERSION",
            'requireExact(properties, "activationState", "committed")',
            'rejectPresent(properties, "pendingIntent")',
            'String activationToken = properties.getProperty("activationToken")',
            '"backupManifestPath"',
            '"backupSnapshotPath"',
            '"originalMarkPresent"',
            '"backupCreatedAt"',
        ],
        "committed marker authority",
    )
    require(
        plugin,
        [
            "NATIVE_READER_V2_COMMITTED_FIELDS",
            "NATIVE_READER_V2_PENDING_FIELDS",
            "NATIVE_ANNOTATION_BACKUP_FIELDS",
            "strictNativeSpreadMarkerProperties(file.readBytes())",
            "duplicate persisted-property key $key",
            "Native Reader v2 marker schema is not exact",
            "strictProperties(\n                manifestBytes,\n"
            "                NATIVE_ANNOTATION_BACKUP_FIELDS,",
        ],
        "cross-layer strict persisted authority",
    )
    if "minimumVersion <" in marker or "minimumVersion >" in marker:
        fail("v2 marker admission permits a version range instead of exact contract")

    require(
        transform,
        [
            "Affine2D projection = activeSlot.sourceToScreen.then(",
            "displayToOrigin",
        ],
        "crop/PageInfo affine order",
    )
    if "displayToOrigin.then(\n            activeSlot.sourceToScreen" in transform:
        fail("PageInfo crop transform uses the pre-projection trim order")

    projection_start = firmware.find(
        "public CanonicalInk committedCanonicalHandwriting("
    )
    projection_end = firmware.find(
        "public void releaseProjectionReader()",
        projection_start,
    )
    if projection_start < 0 or projection_end < 0:
        fail("could not isolate the inactive-page projection reader")
    projection = firmware[projection_start:projection_end]
    require(
        firmware,
        [
            "private final Object projectionNoteLock = new Object();",
            'noteCreate = method(noteClass, "createSuperNoteNote");',
            'noteMarkInitProcess = method(',
            'noteFreeCommon = method(noteClass, "freeCommon");',
            "private Object createProjectionNoteLocked()",
            "projection readers are snapshot-scoped",
        ],
        "isolated native projection reader lifecycle",
    )
    require(
        firmware,
        [
            "&& canvasUsesPhysicalScreenOrigin();",
            "documentLayout.getLocationOnScreen(location);",
            "return location[0] == 0 && location[1] == 0;",
        ],
        "shared physical input/canvas coordinate origin",
    )
    forbidden_projection_cache = [
        "private Object projectionNote;",
        "private String projectionMarkPath;",
        "private Object projectionNoteLocked(String markPath)",
    ]
    for forbidden in forbidden_projection_cache:
        if forbidden in firmware:
            fail(
                "firmware contains persistent projection reader cache "
                f"{forbidden!r}"
            )
    require(
        firmware,
        [
            'presenterRefresh = method(presenter, "refreshBitmap");',
            "public void prepareSourceForTransfer(Components components)",
            "invoke(handWriteViewCancelSelection, components.handWriteView);",
            "invoke(presenterRefresh, components.presenter);",
            "clearAreaSelectionView() is a view",
        ],
        "stock lasso transfer boundary",
    )
    require(
        firmware,
        [
            "components.readerPage != lease.pageIndex",
            "pageInfo(components, lease.pageIndex) != lease.pageInfo",
            "native PageInfo identity changed while v2 held its lease",
        ],
        "PageInfo lease restoration authority",
    )
    require(
        runtime,
        [
            "statusOverlay.protectedAreas(",
            "concatenateMasks(",
            "firmware.programWriterGeometry(",
            "overlayMasks",
        ],
        "custom status chrome writer exclusion",
    )
    require(
        read(source / "v2android/NativeReaderV2StatusOverlay.java"),
        [
            "ViewGroup.LayoutParams.MATCH_PARENT",
            "List<RectD> protectedAreas(",
            "Math.min(viewHeight, TOP_MARGIN_PX + HEIGHT_PX)",
        ],
        "status overlay physical bounds",
    )
    transfer_start = runtime.find("private boolean saveSourceWithWitness(")
    transfer_end = runtime.find("private void retireTransactionalCore()", transfer_start)
    if transfer_start < 0 or transfer_end < 0:
        fail("could not isolate the witnessed source-transfer helper")
    ordered(
        runtime[transfer_start:transfer_end],
        [
            "firmware.prepareSourceForTransfer(source);",
            "boolean dirty = firmware.sourceHasTrails(source);",
            "token = saveWitness.begin(",
            "firmware.saveSource(source);",
            "saveWitness.finish(token)",
        ],
        "native selection commit/save ordering",
    )
    if "handWriteViewClearSelection" in firmware:
        fail("ordinary source transfer still destroys the native lasso view")
    require(
        projection,
        [
            "synchronized (projectionNoteLock)",
            "Object reader = createProjectionNoteLocked();",
            "RuntimeException projectionFailure = null;",
            "noteFetchPagesOfMark,",
            "noteScreenRotation,",
            "noteLoadMarkPageBitmap,",
            "invoke(noteFreeCommon, reader);",
            "projectionFailure.addSuppressed(cleanupFailure);",
        ],
        "snapshot-scoped inactive-page projection isolation",
    )
    if "components.note" in projection:
        fail("inactive-page projection still mutates the live writer note")
    require(
        compositor,
        [
            "NativeDisplayTransform.displayToOrigin(",
            ").then(slot.sourceToScreen)",
            "committedCanonicalHandwriting(",
            "drawDivider(pageCanvas, snapshot);",
            "DIVIDER_PAINT.setColor(Color.BLACK)",
            "snapshot.leftOrFull.screenBounds.right",
            "snapshot.right.screenBounds.left",
        ],
        "shared presentation geometry",
    )
    require(
        status_overlay,
        [
            '"RTL".equals(readingDirection)',
            '"LTR".equals(readingDirection)',
            'readingDirection + " SPREAD: ACTIVE "',
            "active.side.name()",
            "label.setClickable(false)",
            "label.setFocusable(false)",
            "View.IMPORTANT_FOR_ACCESSIBILITY_NO",
            "status overlay used off its owner thread",
        ],
        "v2 active-page status overlay",
    )

    forbidden_build = [
        "aarch64-linux-android27-clang++",
        "jar native-library update",
    ]
    for forbidden in forbidden_build:
        if forbidden in build:
            fail(f"v2 build still packages legacy native behavior: {forbidden!r}")
    require(
        build,
        [
            "$legacySource",
            "exclude it from compilation entirely",
            "'SpreadProbe*.class'",
            "Legacy SpreadProbe executable classes entered the v2 build.",
            "'assets/native_init'",
            "'lib/arm64-v8a/libspreadprobe.so'",
            "v2 APK contains forbidden legacy payload",
        ],
        "exclusive v2 packaging",
    )

    if "RTL read-only" in app:
        fail("retired read-only mode remains exposed by the v2 UI")
    require(
        app,
        [
            'label="RTL native"',
            "Back up & enable",
            "legacy read-only marker remains",
        ],
        "v2 settings UI",
    )
    require(
        plugin,
        [
            "NATIVE_READER_V2_MIN_VERSION_CODE = 136L",
            "moduleVersionCode == NATIVE_READER_V2_MIN_VERSION_CODE",
            "module.first == NATIVE_READER_V2_MIN_VERSION_CODE",
            "Native Reader v2 supports only Off or protected native editing.",
            '"enabled",\n                configuredEditable && runtimeCompatible',
        ],
        "companion v2 authority",
    )
    require(
        plugin,
        [
            "Os.rename(temporary.absolutePath, file.absolutePath)",
            "onPublished()\n            syncParentDirectory(file)",
            "Os.rename(temporary.absolutePath, destination.absolutePath)",
            "onPublished()\n            syncParentDirectory(destination)",
            "OsConstants.O_RDONLY",
            "Os.fsync(directory)",
            "Os.close(directory)",
            "Os.rename(source.absolutePath, destination.absolutePath)",
            "syncParentDirectory(destination)",
            "Files.deleteIfExists(file.toPath())",
            "if (!deleted) return true",
        ],
        "crash-durable atomic publication",
    )

    require(
        workflow,
        [
            "python3 scripts/check_native_reader_v2_invariants.py .",
            "supernote-rtl-reader-v0.4.15-native-reader-v2",
            "native-spread-upgrade-artifact:",
            "if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'",
            "secrets.NATIVE_SPREAD_KEYSTORE_B64",
            "supernote-native-reader-v2-v0.0.136",
        ],
        "CI v2 gates",
    )
    if "check_native_spread_invariants.py ." in workflow:
        fail("release CI still treats the retired legacy engine as runtime authority")
    if "ndk;" in workflow or "-AndroidNdk" in workflow:
        fail("release CI still provisions the retired legacy native hook toolchain")

    print("Native Reader v2 invariants: PASS")


if __name__ == "__main__":
    main()
