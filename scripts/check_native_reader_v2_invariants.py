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
    controller = read(source / "v2/NativeReaderController.java")
    firmware_port = read(source / "v2/NativeReaderFirmwarePort.java")
    gate = read(source / "v2android/NativeReaderV2DocumentGate.java")
    package_gate = read(
        source / "v2android/NativeReaderV2PackageAdmission.java"
    )
    firmware_gate = read(
        source / "v2/android/NativeReaderFirmwareAdmission.java"
    )
    marker = read(source / "v2/NativeReaderV2MarkerClaim.java")
    config = read(source / "v2/NativeReaderV2Config.java")
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
    plugin_verifier = read(root / "scripts/verify_plugin_package.py")

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
            'android:versionCode="137"',
            'android:versionName="0.0.137"',
            'android:label="Supernote Native Reader v2"',
        ],
        "v2 manifest",
    )
    require(
        plugin_config,
        ['"versionCode": "35"', '"versionName": "0.4.16"'],
        "plugin version",
    )
    if (
        '"${PYTHON_CMD[@]}" '
        '"$ROOT/scripts/check_native_reader_v2_invariants.py" "$ROOT"'
        not in read(root / "build.sh")
    ):
        fail("plugin build does not execute the exclusive v2 invariant gate")
    if "RTL_READER_OPEN v0.4.16-native-reader-v2" not in index:
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
            "NativeReaderV2PackageAdmission.verifyLoaded(",
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
            "loadPackageParam.appInfo == null",
            "loadPackageParam.appInfo.sourceDir",
            "loadPackageParam.appInfo.splitSourceDirs",
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
            "public static Report verifyLoaded(",
            "active document class loader is not backed by the admitted APK",
            "active document class loader has unadmitted split APKs",
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
            '"resume_authority_changed",',
            "BY_COMPONENT.remove(previous, entry);",
            "containsIdentity(current, previous)",
            "BY_COMPONENT.putIfAbsent(component, entry)",
            "native component is claimed by another live activity",
            "firmware.releaseProjectionReader();",
            "native_chrome_discovery_failed",
            "chromeSnapshot(entry)",
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
            "volatile boolean admissionFence;",
            ".candidateMarkerPresent(path);",
            "entry.admissionFence = true;",
            "indexAdmissionComponents(entry, components);",
            "onRuntimeInputAuthorityReady(",
            "entry.admissionFence = false;",
            "fingerPhysicalContact = true;",
            "runtime.mayPassNativePenImmediately(x, y, chrome)",
            "scheduleNativeTerminalGuard(entry, runtime);",
            "entry.suppressNativeUntilTerminal = true;",
            "runtime.cancelMissingNativePenTerminal();",
            "guardedHookContinuation(",
        ],
        "hook installation and resume authority",
    )
    if "chrome(entry)" in hooks:
        fail("input hooks still rescan native chrome after contact classification")
    if "refreshChromeAtContactStart" in hooks or "tracker.refresh();" in hooks:
        fail("input hooks still traverse native chrome at contact start")
    if hooks.count("if (entry.admissionFence)") < 5:
        fail("configured-document admission fence does not cover all write/navigation hooks")
    require(
        chrome_tracker,
        [
            "ViewTreeObserver.OnPreDrawListener",
            "observer.addOnPreDrawListener(preDrawListener);",
            "observer.removeOnPreDrawListener(preDrawListener);",
            "collectAdditionalWindows(decorArea, captured);",
            'throw new IllegalStateException(\n'
            '                    "native window inventory is not iterable"',
            "published = Collections.emptyList();",
            "retired = true;",
            "failureHandler.run();",
            "changeHandler.run();",
            "failClosed();",
        ],
        "fail-closed native chrome inventory",
    )
    activation = read(source / "v2/ActivationMachine.java")
    require(
        activation,
        ["targetPage < 0 || targetPage >= snapshot.pageCount"],
        "document-bounded cross-spread activation",
    )
    if "snapshot.slotForPage(targetPage) == null" in activation:
        fail("activation still rejects targets outside the source spread")
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
    begin_route = hooks.find("private static boolean beginStylusRoute(")
    end_route = hooks.find("private static void scheduleNativeTerminalGuard(", begin_route)
    if begin_route < 0 or end_route < 0:
        fail("could not isolate stylus/finger physical contact fence")
    require(
        hooks[begin_route:end_route],
        [
            "synchronized (entry.stylusRouteLock)",
            "!entry.fingerPhysicalContact",
            "runtime.mayPassNativePenImmediately(x, y, chrome)",
            "entry.stylusRouteActive = true;",
        ],
        "single-decision cross-tool contact fence",
    )
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
            "disableWriterWithWitness(",
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
            "disableWriterWithWitness(",
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
            '"resume_authority_changed",',
        ],
        "resume revalidation publication",
    )
    reset_position = revalidation.find(
        '"resume_authority_changed",'
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
            "private boolean containedFailClosed;",
            "private final ExecutorService projectionExecutor",
            "admissionEvidenceStillCurrent()",
            "NativeReaderV2DocumentGate.evidenceStillCurrent(evidence)",
            "fastEvidenceStillCurrent(evidence)",
            "private NativeReaderV2FirmwareAccess.Components inspectNativeCurrent()",
            "Revoking the external marker must stop all new authorized work",
            "disableNativeReaderV2(\"admission_evidence_changed\")",
            "if (nativeLifecycleHandoffPending) return false;",
            "if (inputFrozen) return false;",
            "scheduleActivationTimeout",
            "saveWitness.abort(token);",
            "presentationPublicationAttempted = true;",
            "restorePageGeometryQuietly(\"compose_failed\")",
            "restoreWriterGeometryQuietly(\"compose_failed\")",
            "SN_NATIVE_READER_V2 compose failed",
            'beginStockPresentationRestoration(reason, "safe_retirement")',
            "containFailClosed(reason);",
            "runtime retained fail-closed reason=",
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
            "PhysicalContactFence physicalContactFence",
            "physicalContactFence.stylusContactActive()",
            "MotionEvent.ACTION_POINTER_DOWN",
            "cancelFingerGesture(event.getEventTime());",
            "cancelMissingNativePenTerminal()",
            "private final ArrayDeque<DeferredNavigation>",
            "snapshot.layoutGeneration < request.layoutGeneration",
            "snapshot.activePageIndex != request.sourcePage",
            "stale deferred navigation discarded",
            "projection completion failed closed",
            "queued continuation failed label=",
            "if (action == MotionEvent.ACTION_DOWN && inputFrozen)",
            "if (pressure > 0 && !penContact)",
            "if (inputFrozen) {",
            "preservingUnsavedSource",
            "transactionAllowsStockRestoration()",
        ],
        "runtime concurrency and input containment",
    )
    require(
        controller,
        [
            "source_save_timeout_uncertain",
            "source_save_failed_or_stale",
            "port.preserveUnsavedSource(token, reason);",
            "status.state != ActivationMachine.State.SOURCE_SAVING",
        ],
        "uncertain source-save preservation",
    )
    require(
        firmware_port,
        [
            "void preserveUnsavedNativeSource(String reason);",
            "phase = Phase.DISABLED;",
            "bridge.preserveUnsavedNativeSource(",
            "public void retireDisabledForStock()",
        ],
        "firmware unsaved-source containment",
    )
    require(
        runtime,
        [
            "port.retireDisabledForStock();",
            "preservingUnsavedSource = false;",
            "preserved source lost its disabled transaction authority",
        ],
        "witnessed preserved-source stock restoration",
    )
    if runtime.count("firmware.disableWriter(") != 1:
        fail("writer disable bypasses the witnessed firmware after-hook")
    require(
        hooks,
        [
            'PRESENTER, loader, "disableHandWrite", String.class,',
            "runtime.onNativeWriterDisableCompleted(",
            "PendingNativeOpen pending = new PendingNativeOpen(",
            "entry.pendingNativeOpen = pending;\n"
            "                    boolean prepared =",
            "replayNativeDocumentOpen(",
            "DOCUMENT_OPEN_BYPASS.set(Boolean.TRUE);",
            "pending.method.invoke(pending.receiver, pending.arguments);",
            "if (pendingOpen != null && entry.runtime == null)",
            "replayNativeDocumentOpen(entry, pendingOpen);",
        ],
        "observed writer disable and queued document-open replay",
    )
    admission_worker_start = hooks.find("ADMISSION.execute(new Runnable()")
    admission_publish = hooks.find(
        'entry.activity.runOnUiThread(guardedHookContinuation(',
        admission_worker_start,
    )
    if admission_worker_start < 0 or admission_publish < 0:
        fail("could not isolate document admission worker publication")
    ordered(
        hooks[admission_worker_start:admission_publish],
        [
            ".candidateMarkerPresent(path);",
            "NativeReaderV2DocumentGate.admit(path);",
            ".evidenceStillCurrent(evidence)",
            '"admission evidence changed before publication"',
        ],
        "worker admission evidence revalidated before UI publication",
    )
    start_method = runtime.find("public void start()")
    start_end = runtime.find("public boolean ownsViewModel(", start_method)
    if start_method < 0 or start_end < 0:
        fail("could not isolate runtime activation start")
    require(
        runtime[start_method:start_end],
        [
            'executeProjection("activation_evidence"',
            ".evidenceStillCurrent(evidence);",
            '"activation_publication_evidence_changed"',
            'scheduleRefresh("document_admitted_revalidated")',
        ],
        "runtime activation evidence revalidation",
    )
    if "inspectCurrent(" in runtime:
        fail("runtime still performs filesystem authority checks on the UI thread")
    if len(re.findall(r"fastEvidenceStillCurrent\(\s*evidence", runtime)) != 4:
        fail("async authority bracketing changed without invariant review")
    if runtime.count("compositor.compose(") != 1:
        fail("spread compositor has more than one presentation path")
    if runtime.count("ownerHandler.post(new Runnable()") != 1:
        fail("only the resource-owning projection completion may post directly")
    require(
        runtime,
        [
            "if (result != null && result != visible)",
            "projection completion failed closed",
            "if (!posted && result != null) result.recycle();",
        ],
        "resource-owning projection completion containment",
    )
    require(
        runtime,
        ["ownerHandler.post(guarded(label, action));"],
        "guarded runtime continuation publication",
    )
    pointer_start = runtime.find(
        "if ((action == MotionEvent.ACTION_POINTER_DOWN"
    )
    pointer_end = runtime.find("boolean terminal =", pointer_start)
    if pointer_start < 0 or pointer_end < 0:
        fail("could not isolate multi-pointer cancellation")
    require(
        runtime[pointer_start:pointer_end],
        [
            "|| action == MotionEvent.ACTION_POINTER_UP",
            "cancelFingerGesture(event.getEventTime());",
            "fingerConcurrentBlocked = true;",
            "return true;",
            "PASS_NATIVE is immutable for the complete physical contact",
            "return false;",
        ],
        "multi-pointer gesture cancellation",
    )
    compose_start = runtime.find("private boolean beginComposition(")
    compose_end = runtime.find("private void completeComposition(", compose_start)
    if compose_start < 0 or compose_end < 0:
        fail("could not isolate asynchronous spread composition")
    ordered(
        runtime[compose_start:compose_end],
        [
            "inputFrozen = true;",
            'executeProjection("spread_composition", new Runnable()',
            "fastEvidenceStillCurrent(evidence)",
            "prepared = compositor.compose(",
            "authority changed during projection",
            "boolean posted = ownerHandler.post(new Runnable()",
        ],
        "off-thread composition and evidence bracketing",
    )
    publish_start = runtime.find("private boolean publishPreparedComposition(")
    publish_end = runtime.find("private void leaveSpreadForPortrait(", publish_start)
    if publish_start < 0 or publish_end < 0:
        fail("could not isolate spread publication transaction")
    ordered(
        runtime[publish_start:publish_end],
        [
            'disableWriterWithWitness(current, "SN_NATIVE_READER_V2 compose")',
            "restoreWriterGeometry();",
            "restorePageGeometry();",
            "capturePresentationScale(",
            "presentationPublicationAttempted = true;",
            "firmware.setBackground(current, next.background);",
            "pageGeometryLease = firmware.programPageGeometry(",
            "firmware.programWriterGeometry(",
            "committed = true;",
        ],
        "prepared spread publication transaction",
    )
    require(
        runtime[compose_start:publish_end],
        [
            "boolean inputWasFrozen = inputFrozen;",
            "inputFrozen = inputWasFrozen;",
            "next.recycle();",
        ],
        "composition preflight rollback",
    )
    if "refreshActiveLayersIfPossible" in runtime:
        fail("dead UI-thread active-layer compositor remains reachable")
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
    if "containFailClosed(reason);" not in disable_segment:
        fail("runtime disable does not retain fail-closed hook ownership")
    contain_start = runtime.find("private void containFailClosed(String reason)")
    contain_end = runtime.find("private void beginNativeLifecycleHandoff(", contain_start)
    if contain_start < 0 or contain_end < 0:
        fail("could not isolate retained fail-closed containment")
    require(
        runtime[contain_start:contain_end],
        [
            "inputFrozen = true;",
            "containedFailClosed = true;",
            "if (hasPhysicalInputContact()) {",
            "pendingContainmentReason",
            "inspectNativeCurrent();",
            "disableWriterWithWitness(",
        ],
        "authority-independent writer containment",
    )
    require(
        hooks,
        [
            'VIEW_MODEL, loader, "openDocument",',
            "boolean prepared = entry.runtime.prepareNativeDocumentOpen();",
            (
                "if (!prepared) {\n"
                "                        // The old document remains the writer authority until"
            ),
            "param.setResult(null);",
            'if (!resetRuntime(entry, "native_document_open"))',
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
    require(
        runtime[document_open:document_open_end],
        [
            "ownsModifiedNativePresentation()",
            "stockPresentationRestorePending",
            "hasLiveInputContact()",
            'beginStockPresentationRestoration(\n                "native_document_open",\n                "native_document_open"',
            "return false;",
        ],
        "acknowledged pre-URI document replacement boundary",
    )
    retirement_start = runtime.find("public boolean retire(String reason)")
    retirement_end = runtime.find(
        "public void retireAfterNativeDestroy(String reason)",
        retirement_start,
    )
    if retirement_start < 0 or retirement_end < 0:
        fail("could not isolate safe runtime retirement")
    require(
        runtime[retirement_start:retirement_end],
        [
            'beginStockPresentationRestoration(reason, "safe_retirement")',
            "containFailClosed(reason);",
            "return false;",
            "retirePrepared(reason, false);",
        ],
        "acknowledged stock restore before hook detachment",
    )
    require(
        runtime,
        [
            "STOCK_PRESENTATION_READY =",
            "STOCK_BACKGROUND_READY | STOCK_INK_READY | STOCK_DIGEST_READY",
            "onNativeStockBackgroundPresented()",
            "onNativeStockInkPresented()",
            "onNativeStockDigestPresented()",
            "if (stockPresentationReadyMask != STOCK_PRESENTATION_READY) return;",
            "stock presentation restoration acknowledged",
            "detachmentListener.onRuntimeDetachmentReady(this, reason)",
        ],
        "three-layer stock presentation acknowledgement",
    )
    reset_start = hooks.find("private static boolean resetRuntime(")
    reset_end = hooks.find("private static void releaseDestroyedEntry(", reset_start)
    if reset_start < 0 or reset_end < 0:
        fail("could not isolate hook/runtime detachment")
    ordered(
        hooks[reset_start:reset_end],
        [
            "if (runtime != null && !runtime.retire(reason))",
            "return false;",
            "entry.runtime = null;",
            "BY_COMPONENT.remove(component, entry);",
        ],
        "hook detachment after runtime retirement proof",
    )
    routed_pen = runtime.find("if (penContact) {")
    pen_finish = runtime.find("if (pressure <= 0) {", routed_pen)
    refresh_gate = runtime.find(
        "private void refreshWhenReady(long generation, int attempt, String reason)"
    )
    if pen_finish < 0 or refresh_gate < 0:
        fail("could not isolate native-contact refresh containment")
    ordered(
        runtime[pen_finish:pen_finish + 1800],
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
    require(
        refresh_segment,
        [
            "retired || containedFailClosed || detachmentPrepared",
            "generation != refreshGeneration",
        ],
        "permanent fail-closed refresh fence",
    )
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
            "document identity revalidation is forbidden on the main thread",
            "public static boolean candidateMarkerPresent(String documentPath)",
            "Os.lstat(markerPath);",
            "return failure.errno != OsConstants.ENOENT;",
            "catch (Throwable ambiguous)",
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
    if "getCanonicalFile()" in gate[gate.find("candidateMarkerPresent"):gate.find("public static Evidence admit")]:
        fail("early marker fence performs canonical filesystem resolution")
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
            "MINIMUM_COMPANION_MODULE_VERSION = 137L",
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
            "strictNativeSpreadMarkerProperties(bytes)",
            "duplicate persisted-property key $key",
            "Native Reader v2 marker schema is not exact",
            "strictProperties(\n                manifestBytes,\n"
            "                NATIVE_ANNOTATION_BACKUP_FIELDS,",
        ],
        "cross-layer strict persisted authority",
    )
    load_start = plugin.find("fun loadNativeSpreadMode(")
    load_end = plugin.find("fun reconcileNativeSpreadRecovery(", load_start)
    if load_start < 0 or load_end < 0:
        fail("could not isolate native-mode loading")
    load_segment = plugin[load_start:load_end]
    ordered(
        load_segment,
        [
            'startNativeBackupWorker("RTLReaderNativeModeLoad")',
            "readNativeAnnotationBackup(pdfFile)",
            "readPropertiesIfFile(marker)",
            "assessNativeSpreadAuthority(",
            "Handler(Looper.getMainLooper()).post",
            "resolveNativeSpreadMode(",
        ],
        "off-main-thread marker and recovery validation",
    )
    require(
        load_segment,
        [
            "if (propertiesResult.isFailure)",
            'NativeSpreadHandshake(false, "marker_unreadable")',
            "backupResult,\n                                authority,",
        ],
        "malformed-marker recovery-only state",
    )
    if "minimumVersion <" in marker or "minimumVersion >" in marker:
        fail("v2 marker admission permits a version range instead of exact contract")
    require(
        config,
        [
            'if (!"rtl".equals(directionValue))',
            "Native Reader v2 supports only RTL markers",
            "SpreadPairing.Direction direction = SpreadPairing.Direction.RTL;",
        ],
        "cross-layer RTL-only v2 admission",
    )
    if '"ltr".equals(directionValue)' in config:
        fail("v2 module still admits LTR markers rejected by the companion")

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
            "postGuarded(\"native_pen_position\"",
            "postGuarded(\"refresh:\" + refreshReason",
            "guarded(\n                \"refresh_retry:\" + reason",
            "queued source-save inspection failed",
            "sourceSaveAuthorityMatches(source)",
            "Always cross a queue boundary",
            "source-save prevalidation failed",
            "source-save postvalidation failed",
            "statusOverlay.protectedAreas(",
            "concatenateMasks(",
            "firmware.programWriterGeometry(",
            "overlayMasks",
        ],
        "custom status chrome writer exclusion",
    )
    require(
        runtime,
        [
            "public void onTrackedNativeChromeChanged(List<RectD> visibleChrome)",
            "new ArrayList<>(safeChrome(visibleChrome))",
            "List<RectD> writerChrome = concatenateMasks(",
            "trackedChromeMasks,",
            "firmware.nativeChromeDisabledAreas(current), writerChrome",
            "firmware.refreshWriterDisabledAreas(",
            (
                "firmware.refreshWriterDisabledAreas(\n"
                "                current,\n"
                "                geometry,\n"
                "                writerChrome"
            ),
        ],
        "all visible pass-through chrome excluded from native writer",
    )
    require(
        compositor,
        [
            "drawActiveInk(",
            "activeNativeInk.getWidth() == inkCanvas.getWidth()",
            "Affine2D.identity()",
            "requireOriginInkGeometry(activeNativeInk, page);",
        ],
        "native-display versus origin-space live ink",
    )
    require(
        runtime,
        [
            "Bitmap activeInk = writerGeometryLease == null",
            "? null : firmware.liveHandwritingBitmap(current);",
            "return new RectD(0, 0, bitmap.getWidth(), bitmap.getHeight());",
        ],
        "first-spread live ink and full-origin sizing authority",
    )
    require(
        firmware,
        [
            "WeakReference<Object>",
            "public synchronized void releaseComponentIds(Components components)",
            "Firmware access is process-scoped",
        ],
        "bounded native component identity lifetime",
    )
    if "IdentityHashMap<Object, Long> componentIds" in firmware:
        fail("firmware still strongly retains retired component graphs")
    require(
        runtime,
        ["firmware.releaseComponentIds(releasedComponents);"],
        "retired component identity release",
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
            "[string]$ExpectedSignerSha256",
            "Expected signer SHA-256 is not canonical lowercase hexadecimal.",
            "Number of signers: 1",
            "APK signer does not match the exact established upgrade identity",
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
            "Legacy read-only settings cannot be edited.",
            "Legacy read-only appearance cannot be edited.",
            "(!nativeSpreadCompatible || !nativeSpreadConfiguredEditable)",
            "const restoredDirection = nativeSpreadHasPersistedAppearance",
            "? 'rtl'",
            "directionRef.current = restoredDirection;",
            "setDirection(restoredDirection);",
        ],
        "v2 settings UI",
    )
    require(
        plugin,
        [
            "NATIVE_READER_V2_MIN_VERSION_CODE = 137L",
            "NATIVE_READER_V2_SIGNER_SHA256 =",
            "PackageManager.GET_SIGNING_CERTIFICATES",
            "signing.hasMultipleSigners()",
            "Native Reader signer set is not exact",
            "moduleVersionCode == NATIVE_READER_V2_MIN_VERSION_CODE",
            "module.first == NATIVE_READER_V2_MIN_VERSION_CODE",
            "module.third == NATIVE_READER_V2_SIGNER_SHA256",
            'putString("moduleSignerSha256", capability.moduleSignerSha256)',
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
            "requireBackupDocumentIdentity(",
            (
                "requireBackupDocumentIdentity(\n"
                "                                pdfFile,\n"
                "                                revalidatedBackup,\n"
                '                                "before-mark-publish",'
            ),
            '"before-mark-publish"',
            '"after-mark-publish"',
            '"after-mark-verification"',
            '"before-mark-delete"',
            '"after-mark-delete"',
            '"before-backup-retirement"',
            "restorePrePublicationMark(",
            "immediateMarkerBytes?.contentEquals(previousMarkerBytes)",
            "sameNativeAnnotationBackup(backup, immediateBackup)",
            "immediateMarkerBytes?.contentEquals(pendingMarkerBytes)",
            "liveNativeAnnotationMatchesBackup(backup)",
        ],
        "crash-durable compare-and-publish authority",
    )
    require(
        gate,
        [
            "candidate marker lookup is forbidden on the main thread",
            "Os.lstat(markerPath);",
        ],
        "worker-only candidate marker lookup",
    )
    require(
        firmware,
        [
            "rect.left == 0 && rect.top == 0",
            "rect.right == 0 && rect.bottom == 0",
            "continue;",
            "native writer mask is invalid or outside the canvas",
            "must never wait on projectionNoteLock from the UI thread",
        ],
        "native mask sentinel and nonblocking projection lifecycle",
    )
    require(
        runtime,
        [
            "projectionExecutor.shutdownNow();",
            "if (projectionExecutor.awaitTermination(",
            "firmware.releaseComponentIds(releasedComponents);",
            "if (retired || projectionShutdown",
            "if (prepared != null) prepared.recycle();",
        ],
        "asynchronous projection cancellation and resource drain",
    )
    shutdown_start = runtime.find("private void shutdownProjectionWorker(")
    shutdown_end = runtime.find("private Runnable guarded(", shutdown_start)
    if shutdown_start < 0 or shutdown_end < 0:
        fail("could not isolate asynchronous projection shutdown")
    ordered(
        runtime[shutdown_start:shutdown_end],
        [
            "projectionExecutor.shutdownNow();",
            "if (projectionExecutor.awaitTermination(",
            "firmware.releaseProjectionReader();",
            "firmware.releaseComponentIds(releasedComponents);",
        ],
        "projection identities released only after worker drain",
    )
    physical_start = runtime.find("private boolean hasPhysicalInputContact()")
    physical_end = runtime.find("private void clearNativeLifecycleHandoff()", physical_start)
    if physical_start < 0 or physical_end < 0:
        fail("could not isolate physical input lifecycle fence")
    require(
        runtime[physical_start:physical_end],
        ["|| physicalContactFence.stylusContactActive();"],
        "Android stylus contact included in lifecycle gates",
    )
    require(
        plugin,
        [
            "OsConstants.O_NOFOLLOW",
            "pathBefore.st_nlink == 1L",
            "samePersistedFileVersion(opened, pathAfter)",
            "private fun readPersistedBytesIfFile(file: File): ByteArray?",
        ],
        "single-link descriptor-backed companion marker reads",
    )
    if "marker.readBytes()" in plugin:
        fail("companion marker recovery bypasses descriptor-backed authority")

    require(
        workflow,
        [
            "python3 scripts/check_native_reader_v2_invariants.py .",
            "supernote-rtl-reader-v0.4.16-native-reader-v2",
            "native-spread-upgrade-artifact:",
            "github.event_name == 'workflow_dispatch'",
            "github.actor == github.repository_owner",
            "secrets.NATIVE_SPREAD_KEYSTORE_B64",
            "-ExpectedSignerSha256 $runnerSigner",
            "-ExpectedSignerSha256 a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67",
            "supernote-native-reader-v2-v0.0.137",
        ],
        "CI v2 gates",
    )
    mutable_actions = re.findall(
        r"^\s*uses:\s*actions/[^@\s]+@(?![0-9a-f]{40}(?:\s|$))([^\s#]+)",
        workflow,
        re.MULTILINE,
    )
    if mutable_actions:
        fail(f"workflow uses mutable GitHub Action refs: {mutable_actions!r}")
    require(
        plugin_verifier,
        [
            "EXPECTED_ANDROID_PACKAGE = \"com.supernotertlreader\"",
            "def verify_binary_manifest(",
            "def verify_dex(",
            'find_android_tool("aapt")',
            'find_android_tool("apksigner")',
            '"Number of signers: 1"',
            "verify_apk_tools(Path(temporary_name))",
        ],
        "embedded APK structural and signature verification",
    )
    if "check_native_spread_invariants.py ." in workflow:
        fail("release CI still treats the retired legacy engine as runtime authority")
    if "ndk;" in workflow or "-AndroidNdk" in workflow:
        fail("release CI still provisions the retired legacy native hook toolchain")
    stable_job = workflow[workflow.find("native-spread-upgrade-artifact:"):]
    stable_job = stable_job.split("\n  build:", 1)[0]
    stable_condition = stable_job.split("    needs:", 1)[0]
    require(
        stable_condition,
        [
            "(github.event_name == 'workflow_dispatch' &&\n"
            "       github.ref == 'refs/heads/main' &&\n"
            "       github.actor == github.repository_owner)",
        ],
        "trusted manual stable signing scope",
    )
    require(
        stable_job,
        [
            "needs:\n      - native-spread-build\n      - build",
        ],
        "stable APK waits for both companion and plugin gates",
    )

    print("Native Reader v2 invariants: PASS")


if __name__ == "__main__":
    main()
