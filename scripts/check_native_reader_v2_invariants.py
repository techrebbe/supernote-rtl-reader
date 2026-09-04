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
    module_readme = read(module / "README.md")
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
    authority_journal = read(source / "v2/NativeReaderV2AuthorityJournal.java")
    config = read(source / "v2/NativeReaderV2Config.java")
    transform = read(source / "v2/NativePageTransform.java")
    input_admission = read(source / "v2/AtomicInputAdmission.java")
    handshake_single_flight = read(
        source / "v2/NativeHandshakeSingleFlight.java"
    )
    async_save_fence = read(source / "v2/NativeAsyncSaveFence.java")
    restore_witness = read(
        source / "v2/NativePresentationRestoreWitness.java"
    )
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
    root_build = read(root / "build.sh")
    build = read(module / "build.ps1")
    manifest = read(module / "AndroidManifest.xml")
    xposed = read(module / "assets/xposed_init").strip()
    workflow = read(root / ".github/workflows/build.yml")
    guidance = read(root / "AGENTS.md")
    plugin = read(root / "native/ReaderPreferencesModule.kt.template")
    plugin_authority_journal = read(
        root / "native/NativeReaderV2AuthorityJournal.kt.template"
    )
    native_installer = read(root / "scripts/install_native.py")
    app = read(root / "overlay/App.js")
    index = read(root / "overlay/index.js")
    plugin_config = read(root / "PluginConfig.json")
    core_tests = read(
        module
        / "tests/com/techrebbe/supernote/spreadprobe/v2/NativeReaderV2CoreTests.java"
    )
    template_materializer = read(
        root / "scripts/materialize_plugin_template.py"
    )
    apk_normalizer = read(root / "scripts/normalize_apk_zip.py")
    packager_patch = read(root / "scripts/patch_plugin_packager.py")
    plugin_verifier = read(root / "scripts/verify_plugin_package.py")
    provenance_test = read(root / "scripts/test_build_provenance.py")
    lock_input = read(
        root / "provenance/plugin-template-package-lock.json.gz.b64"
    )

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
            'android:versionCode="140"',
            'android:versionName="0.0.140"',
            'android:label="Supernote Native Reader v2"',
        ],
        "v2 manifest",
    )
    require(
        plugin_config,
        ['"versionCode": "41"', '"versionName": "0.4.22"'],
        "plugin version",
    )
    require(
        core_tests,
        [
            'olderContract.setProperty("minimumModuleVersionCode", "139")',
            'futureContract.setProperty("minimumModuleVersionCode", "141")',
        ],
        "adjacent companion contract rejection tests",
    )
    require(
        module_readme,
        [
            "The v0.0.140 APK\n"
            "requires Supernote RTL Reader v0.4.22 and refuses every other companion\n"
            "contract version."
        ],
        "documented Native Reader v2 pairing",
    )
    if (
        '"${PYTHON_CMD[@]}" '
        '"$ROOT/scripts/check_native_reader_v2_invariants.py" "$ROOT"'
        not in root_build
    ):
        fail("plugin build does not execute the exclusive v2 invariant gate")
    if "RTL_READER_OPEN v0.4.22-native-reader-v2" not in index:
        fail("runtime marker does not identify the v2 plugin build")
    require(
        guidance,
        [
            "python scripts/check_native_invariants.py .",
            "python scripts/check_native_reader_v2_invariants.py .",
            "python scripts/test_native_reader_v2_core.py .",
            "python scripts/test_native_reader_v2_mutations.py .",
            "python scripts/test_plugin_packaging_fail_closed.py",
            "It is required for a v2",
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
            '"supernote-document-1.02.446-native-reader-v2-symbols-v6"',
            'field(VIEW_MODEL, "documentAnnotationMap", "java.util.Map")',
            '"android.graphics.Point")',
            'field(NATIVE_CALLBACK, "this$0", ACTIVITY)',
            'field(NATIVE_EVENT_CALLBACK, "mPressure", "int")',
            'for (String encoded : SYMBOLS) {',
            '} catch (IllegalStateException failure) {',
            '"required firmware symbols are missing or changed ("',
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
            "ensureChromeTracker(entry);",
            "routeAdmissionFenceAndroidContact(",
            "routeAdmissionFenceNativePen(",
            "admissionFenceContactActive(entry)",
            "Entry entry = entry(param.thisObject);\n"
            "                    if (entry == null) return;\n"
            "                    if (entry.runtime == null\n"
            "                        || admissionFenceContactActive(entry)",
            "entry.fenceAndroidPass = pointInsideChrome(",
            "entry.fenceNativePenPass = pointInsideChrome(x, y, chrome);",
            "if (!entry.fenceAndroidContact) return true;",
            "boolean consume = !entry.fenceAndroidPass;",
            "boolean consume = !entry.fenceNativePenContact\n"
            "                || !entry.fenceNativePenPass;",
            "retireChromeTrackerWhenUnfenced(entry);",
            "onRuntimeInputAuthorityReady(",
            "entry.admissionFence = false;",
            "fingerPhysicalContact = true;",
            "runtime.beginNativePenContactImmediately(x, y, chrome)",
            "scheduleNativeTerminalGuard(entry, runtime);",
            "entry.suppressNativeUntilTerminal = true;",
            "runtime.cancelMissingNativePenTerminal();",
            "guardedHookContinuation(",
            "firmware.inspectNativePenCallback(",
            "Entry entry = BY_ACTIVITY.get(signal.activity);",
            "BY_COMPONENT.get(signal.eventCallback) != entry",
            "int pressure = signal.pressure;",
        ],
        "hook installation and resume authority",
    )
    if "chrome(entry)" in hooks:
        fail("input hooks still rescan native chrome after contact classification")
    if 'getIntField(\n                        param.thisObject,\n                        "mPressure"' in hooks:
        fail("native pen hook reads pressure from the anonymous listener")
    require(
        firmware,
        [
            "public NativePenSignal inspectNativePenCallback(Object callback)",
            "Object activity = nativeCallbackActivity.get(callback);",
            "Object eventCallback = activityEventCallback.get(activity);",
            "nativeEventCallbackPressure.getInt(eventCallback)",
        ],
        "exact native pen callback owner and pressure source",
    )
    if "refreshChromeAtContactStart" in hooks or "tracker.refresh();" in hooks:
        fail("input hooks still traverse native chrome at contact start")
    if hooks.count("if (entry.admissionFence)") < 3:
        fail("configured-document admission fence does not cover all write/navigation hooks")
    admission_start = hooks.find("private static void maybeAdmit(")
    admission_end = hooks.find(
        "private static void revalidateExistingRuntime(", admission_start
    )
    if admission_start < 0 or admission_end < 0:
        fail("could not isolate document admission")
    ordered(
        hooks[admission_start:admission_end],
        [
            "entry.admissionFence = true;",
            "indexAdmissionComponents(entry, components);",
            "ensureChromeTracker(entry);",
            "candidate = NativeReaderV2DocumentGate",
        ],
        "pre-admission native chrome recovery authority",
    )
    require(
        hooks[admission_start:admission_end],
        [
            "if (entry.retryAdmissionAfterAuthorityOff)",
            "entry.retryAdmissionAfterAuthorityOff = false;",
            "if (entry.retryAdmissionAfterAuthorityOff\n"
            "                            && entry.resumed)",
            "releaseEvidence(accepted);",
            "maybeAdmit(entry, true);",
        ],
        "post-recovery OFF admission retry",
    )
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
    if "runtime.beginNativePenContactImmediately(x, y, chrome)" not in hooks:
        fail("native pen DOWN lacks atomic callback-thread admission")
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
            "runtime.beginNativePenContactImmediately(x, y, chrome)",
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
    configuration_start = runtime.find("public void beforeConfigurationChange()")
    configuration_end = runtime.find(
        "public void afterConfigurationChange()",
        configuration_start,
    )
    if configuration_start < 0 or configuration_end < 0:
        fail("could not isolate configuration-change lifecycle handoff")
    ordered(
        runtime[configuration_start:configuration_end],
        [
            "if (retired) return;",
            "advanceLifecycleEpoch();",
            "if (hasLiveInputContact()) {",
            "beginNativeLifecycleHandoff(",
        ],
        "configuration handoff epoch invalidation",
    )
    schedule_start = runtime.find("public void scheduleRefresh(String reason)")
    schedule_end = runtime.find(
        "public void beforeConfigurationChange()",
        schedule_start,
    )
    refresh_start = runtime.find("private void refreshWhenReady(")
    refresh_end = runtime.find("private void retryRefresh(", refresh_start)
    if min(schedule_start, schedule_end, refresh_start, refresh_end) < 0:
        fail("could not isolate lifecycle-gated presentation refresh")
    for segment, label in (
        (runtime[schedule_start:schedule_end], "refresh scheduling"),
        (runtime[refresh_start:refresh_end], "refresh publication"),
    ):
        if "nativeLifecycleHandoffPending" not in segment:
            fail(f"{label} can run during a native lifecycle handoff")
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

    handshake_start = hooks.find(
        "private static synchronized void registerHandshakeReceiver("
    )
    handshake_end = hooks.find(
        "private static HandshakeSnapshot captureHandshakeSnapshot(",
        handshake_start,
    )
    if handshake_start < 0 or handshake_end < 0:
        fail("could not isolate v2 handshake receiver")
    handshake = hooks[handshake_start:handshake_end]
    require(
        hooks,
        [
            "private static final int HANDSHAKE_PROTOCOL = 4;",
            "private static final NativeHandshakeSingleFlight HANDSHAKE_SINGLE_FLIGHT",
            "private static final long HANDSHAKE_PROVIDER_EXPIRY_MS = 2_500L",
            "final long handshakeToken = HANDSHAKE_SINGLE_FLIGHT.tryBegin()",
            "if (handshakeToken == 0L)",
        ],
        "bounded in-memory handshake authority",
    )
    require(
        handshake_single_flight,
        [
            "private final AtomicLong nextToken",
            "private final AtomicLong owner",
            "return owner.compareAndSet(0L, token) ? token : 0L;",
            "return token != 0L && owner.compareAndSet(token, 0L);",
            "return token != 0L && owner.get() == token;",
            "return nowUptimeMs < deadlineUptimeMs && current(token);",
        ],
        "generation-owned bounded handshake single-flight gate",
    )
    ordered(
        handshake,
        [
            "Looper.myLooper() != Looper.getMainLooper()",
            'request.getStringExtra("rawDocumentPath")',
            "requestedPath.indexOf('\\0') >= 0",
            "final long handshakeToken = HANDSHAKE_SINGLE_FLIGHT.tryBegin();",
            "final long handshakeDeadlineUptimeMs =",
            "SystemClock.uptimeMillis() + HANDSHAKE_PROVIDER_EXPIRY_MS;",
            "final AtomicReference<Thread> authorityObservationWorker =",
            "final Runnable handshakeExpiry = new Runnable()",
            "if (!MAIN_HANDLER.postAtTime(",
            "HandshakeSnapshot snapshot = captureHandshakeSnapshot();",
            "HandshakeResolution resolution = resolveHandshake(",
            "if (authorityAckRequested)",
            "Thread worker = new Thread(new Runnable()",
            ".observeAuthority(requestedPath);",
            "boolean posted = MAIN_HANDLER.post(new Runnable()",
            "publishHandshakeResponse(",
            "finishHandshake(",
            "worker.setDaemon(true);",
            "worker.start();",
            "new IntentFilter(HANDSHAKE_REQUEST)",
        ],
        "main-thread snapshot, raw-path binding, and final publication",
    )
    if (
        "getCanonicalPath(" in handshake
        or "HandlerThread" in handshake
        or "ADMISSION.execute(new Runnable()" in handshake
    ):
        fail("handshake provider can enter blocking filesystem worker state")
    require(
        handshake,
        [
            "HANDSHAKE_SINGLE_FLIGHT.finish(handshakeToken)",
            "authorityObservationWorker\n                                .getAndSet(null)",
            "if (worker != null) worker.interrupt();",
            "if (!posted)",
            "finishHandshake(handshakeToken, handshakeExpiry)",
            "MAIN_HANDLER.removeCallbacks(expiry)",
            "HANDSHAKE_SINGLE_FLIGHT.finish(token)",
        ],
        "bounded sync/async handshake admission release",
    )

    snapshot_start = hooks.find(
        "private static HandshakeSnapshot captureHandshakeSnapshot("
    )
    resolve_start = hooks.find(
        "private static HandshakeResolution resolveHandshake(", snapshot_start
    )
    publish_start = hooks.find(
        "private static void publishHandshakeResponse(", resolve_start
    )
    freshness_start = hooks.find(
        "private static boolean handshakeSnapshotStillCurrent(", publish_start
    )
    path_match_start = hooks.find(
        "private static boolean sameHandshakePath(", freshness_start
    )
    component_match_start = hooks.find(
        "private static boolean sameHandshakeComponents(", path_match_start
    )
    component_match_end = hooks.find(
        "private static final class HandshakeCandidate", component_match_start
    )
    if min(
        snapshot_start,
        resolve_start,
        publish_start,
        freshness_start,
        path_match_start,
        component_match_start,
        component_match_end,
    ) < 0:
        fail("could not isolate handshake authority pipeline")
    snapshot_capture = hooks[snapshot_start:resolve_start]
    resolution = hooks[resolve_start:publish_start]
    publication = hooks[publish_start:freshness_start]
    freshness = hooks[freshness_start:path_match_start]
    if "getCanonicalPath(" in resolution or "getCanonicalPath(" in publication:
        fail("handshake path binding or publication touches filesystem authority")
    ordered(
        snapshot_capture,
        [
            "Looper.myLooper() != Looper.getMainLooper()",
            "firmware.inspect(candidate.activity)",
            "candidate.generation",
            "candidate.lifecycleGeneration",
            "candidate.resumed",
            "components.documentPath",
        ],
        "main-thread immutable handshake snapshot",
    )
    ordered(
        resolution,
        [
            "requestedPath == null",
            "if (!requestedPath.equals(candidate.rawPath)) continue;",
            "if (match != null && match.entry != candidate.entry) return null;",
            "new HandshakeResolution(match, match.rawPath)",
        ],
        "in-memory raw-path binding and unique Activity authority",
    )
    ordered(
        publication,
        [
            "Looper.myLooper() != Looper.getMainLooper()",
            "!handshakeSnapshotStillCurrent(snapshot)",
            "snapshot.candidates.contains(resolution.candidate)",
            "response.setPackage(PLUGIN_HOST_PACKAGE);",
            'response.putExtra("nonce", nonce);',
            'response.putExtra("rawDocumentPath", resolution.rawPath);',
            "HANDSHAKE_SINGLE_FLIGHT.currentBefore(\n"
            "                handshakeToken,\n"
            "                SystemClock.uptimeMillis(),\n"
            "                handshakeDeadlineUptimeMs",
            "receiverContext.sendBroadcast(response);",
            'if (observation != null && "off".equals(observation.state))',
            "entry.retryAdmissionAfterAuthorityOff = true;",
            "maybeAdmit(entry, true);",
        ],
        "main-thread handshake response publication",
    )
    provider_expiry = re.search(
        r"HANDSHAKE_PROVIDER_EXPIRY_MS\s*=\s*([0-9_]+)L", hooks
    )
    plugin_timeout = re.search(
        r"NATIVE_SPREAD_HANDSHAKE_TIMEOUT_MS\s*=\s*([0-9_]+)L", plugin
    )
    if provider_expiry is None or plugin_timeout is None:
        fail("could not compare provider expiry with plug-in timeout")
    if int(provider_expiry.group(1).replace("_", "")) >= int(
        plugin_timeout.group(1).replace("_", "")
    ):
        fail("provider expiry must precede the plug-in terminal timeout")
    ordered(
        freshness,
        [
            "HandshakeSnapshot actual = captureHandshakeSnapshot();",
            "expected.candidates.size() != actual.candidates.size()",
            "candidate.entry == expectedCandidate.entry",
            "expectedCandidate.entryGeneration !=",
            "expectedCandidate.lifecycleGeneration !=",
            "expectedCandidate.resumed != actualCandidate.resumed",
            "!sameHandshakePath(",
            "!sameHandshakeComponents(",
        ],
        "handshake final Activity/lifecycle/document/component freshness",
    )
    component_match = hooks[component_match_start:component_match_end]
    require(
        component_match,
        [
            "expected.activity == actual.activity",
            "expected.viewModel == actual.viewModel",
            "expected.presenter == actual.presenter",
            "expected.handWriteView == actual.handWriteView",
            "expected.eventCallback == actual.eventCallback",
            "expected.image == actual.image",
            "expected.digestImage == actual.digestImage",
            "expected.documentLayout == actual.documentLayout",
            "expected.note == actual.note",
            "expected.client == actual.client",
            "expected.binder == actual.binder",
            "expected.documentPath.equals(actual.documentPath)",
        ],
        "handshake exact component authority",
    )

    plugin_handshake_start = plugin.find(
        "private fun requestNativeSpreadHandshake("
    )
    plugin_handshake_end = plugin.find(
        "private fun nativeSpreadCapability()", plugin_handshake_start
    )
    plugin_bound_start = plugin.find(
        "private fun requestNativeSpreadHandshakeBound(",
        plugin_handshake_start,
    )
    plugin_generation_start = plugin.find(
        "private fun requireNativeSpreadConfigurationGeneration(",
        plugin_bound_start,
    )
    if min(
        plugin_handshake_start,
        plugin_bound_start,
        plugin_generation_start,
        plugin_handshake_end,
    ) < 0:
        fail("could not isolate plug-in v2 handshake")
    plugin_handshake = plugin[plugin_handshake_start:plugin_handshake_end]
    plugin_wrapper = plugin[plugin_handshake_start:plugin_bound_start]
    plugin_response = plugin[plugin_bound_start:plugin_generation_start]
    ordered(
        plugin_wrapper,
        [
            "val completed = AtomicBoolean(false)",
            "val receiver = AtomicReference<BroadcastReceiver?>(null)",
            "val expectedPath = pdfFile.absolutePath",
            "val handshakeDeadlineUptimeMs =",
            "if (!mainHandler.postDelayed(\n"
            "                timeout,\n"
            "                NATIVE_SPREAD_HANDSHAKE_TIMEOUT_MS,",
            "nativeSpreadConfigurationGeneration.get() != configurationGeneration",
            "val start = Runnable {",
            "SystemClock.uptimeMillis() >= handshakeDeadlineUptimeMs",
            "requestNativeSpreadHandshakeBound(",
            "            start.run()",
            "} else if (!mainHandler.post(start))",
        ],
        "filesystem-free plug-in handshake dispatch and absolute deadline",
    )
    require(
        plugin_wrapper,
        [
            "completed.compareAndSet(false, true)",
            "mainHandler.removeCallbacks(timeout)",
            "receiver.getAndSet(null)",
            "synchronized(nativeSpreadConfigurationIntentLock)",
            "if (!nativeSpreadModuleInvalidated.get())",
            "val terminalResult =",
            "nativeSpreadConfigurationGeneration.get() ==",
            "configurationGeneration",
            'NativeSpreadHandshake(false, "stale_operation")',
            "callback(terminalResult)",
            'NativeSpreadHandshake(false, "stale_operation")',
        ],
        "plug-in single-completion and stale-operation fence",
    )
    ordered(
        plugin_response,
        [
            "check(Looper.myLooper() == Looper.getMainLooper())",
            "if (completed.get()) return",
            "nativeSpreadConfigurationGeneration.get() != configurationGeneration",
            "receiver.set(registered)",
            "IntentFilter(NATIVE_SPREAD_HANDSHAKE_RESPONSE),\n"
            "            )\n"
            "            if (SystemClock.uptimeMillis() >= handshakeDeadlineUptimeMs)",
            "reactApplicationContext.sendBroadcast(",
            "putExtra(HANDSHAKE_EXTRA_RAW_DOCUMENT_PATH, expectedPath)",
        ],
        "plug-in main-thread registration with raw-path authority",
    )
    ordered(
        plugin_response,
        [
            "val reportedPath = intent.getStringExtra(",
            "val valid = hooksReady",
            "reportedPath == expectedPath",
            "if (valid) \"ok\" else \"invalid_response\"",
        ],
        "plug-in handshake exact native raw-path response",
    )
    for forbidden in (
        ".canonicalPath",
        "getCanonicalPath(",
        "FutureTask",
        "ThreadPoolExecutor",
        "NATIVE_SPREAD_HANDSHAKE_EXECUTOR",
        "nativeSpreadHandshakeTasks",
    ):
        if forbidden in plugin_handshake:
            fail(f"plug-in handshake retains blocking worker authority: {forbidden}")
    if plugin_handshake.count(
        "SystemClock.uptimeMillis() >= handshakeDeadlineUptimeMs"
    ) < 3:
        fail("plug-in handshake lacks entry, pre-send, and response deadlines")
    if "postDelayed(" in plugin_response:
        fail("plug-in handshake helper starts a second timeout window")
    require(
        plugin[plugin_generation_start:plugin_handshake_end],
        [
            "nativeSpreadConfigurationGeneration.get() == expected",
            "!nativeSpreadModuleInvalidated.get()",
            '"Native Spread configuration was superseded"',
        ],
        "plug-in persisted-state generation authority",
    )
    if plugin.count(
        "val configurationGeneration = beginNativeSpreadConfiguration()"
    ) != 2:
        fail("Native Spread configuration entrypoints do not both supersede older work")
    require(
        plugin,
        [
            "private const val NATIVE_SPREAD_HANDSHAKE_PROTOCOL = 4",
            "private val nativeSpreadConfigurationGeneration = AtomicLong(0L)",
            "private val nativeSpreadConfigurationIntentLock = Any()",
            "private val nativeSpreadConfigurationLock = Any()",
            "override fun invalidate()",
            "val newlyInvalidated = synchronized(nativeSpreadConfigurationIntentLock)",
            "nativeSpreadModuleInvalidated.compareAndSet(false, true)",
            "nativeSpreadConfigurationGeneration.incrementAndGet()",
            "nativeSpreadHandshakeReceivers.toList()",
            "super.invalidate()",
        ],
        "filesystem-free handshake and module invalidation containment",
    )
    if plugin.count(
        "withNativeSpreadConfigurationAuthority(configurationGeneration)"
    ) < 3:
        fail("persisted Native Spread publications are not generation-linearized")

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
            "if (lifecycleSuspended || nativeLifecycleHandoffPending) return false;",
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
            "boolean runWhenStylusIdle(Runnable publication);",
            "private boolean compositionDeferredForPhysicalContact;",
            'scheduleRefresh("physical_contact_publication_released");',
            "MotionEvent.ACTION_POINTER_DOWN",
            "cancelFingerGesture(event.getEventTime());",
            "cancelMissingNativePenTerminal()",
            "private final ArrayDeque<DeferredNavigation>",
            "snapshot.layoutGeneration < request.layoutGeneration",
            "snapshot.activePageIndex != request.sourcePage",
            "stale deferred navigation discarded",
            "projection completion failed closed",
            "queued continuation failed label=",
            "private final AtomicInputAdmission inputAdmission",
            "fingerIngressAdmitted = inputAdmission.begin(",
            "inputAdmission.begin(AtomicInputAdmission.Contact.STYLUS)",
            "inputAdmission.freezeIfIdle()",
            "inputAdmission.current(compositionFreeze)",
            "releaseInputIngress(compositionFreeze)",
            "supersedeInputIngressIfIdle()",
            "inputAdmission.end(AtomicInputAdmission.Contact.FINGER)",
            "inputAdmission.end(AtomicInputAdmission.Contact.STYLUS)",
            "if (pressure > 0 && !penContact)",
            "preservingUnsavedSource",
            "transactionAllowsStockRestoration()",
        ],
        "runtime concurrency and input containment",
    )
    native_pen_route_start = runtime.find(
        "public boolean routeNativePenPosition("
    )
    native_pen_route_end = runtime.find(
        "public void cancelMissingNativePenTerminal()",
        native_pen_route_start,
    )
    if native_pen_route_start < 0 or native_pen_route_end < 0:
        fail("could not isolate native pen route")
    require(
        runtime[native_pen_route_start:native_pen_route_end],
        ["if (inputFrozen) {"],
        "frozen native pen-down admission",
    )
    require(
        input_admission,
        [
            "public synchronized boolean begin(Contact contact)",
            "public synchronized FreezeToken freezeIfIdle()",
            "public synchronized FreezeToken supersedeIfIdle()",
            "public synchronized boolean release(FreezeToken token)",
            "token != freezeToken",
            "public synchronized boolean current(FreezeToken token)",
        ],
        "token-owned atomic contact/freeze admission",
    )
    freeze_idle_start = input_admission.find(
        "public synchronized FreezeToken freezeIfIdle()"
    )
    supersede_freeze_start = input_admission.find(
        "public synchronized FreezeToken supersedeIfIdle()",
        freeze_idle_start,
    )
    if freeze_idle_start < 0 or supersede_freeze_start < 0:
        fail("could not isolate contact-free freeze admission")
    require(
        input_admission[freeze_idle_start:supersede_freeze_start],
        ["if (freezeToken != null || fingerActive || stylusActive) return null;"],
        "contact-free freeze admission",
    )
    require(
        async_save_fence,
        [
            "public synchronized Token begin(SpreadSnapshot snapshot",
            "token.layoutGeneration == snapshot.layoutGeneration",
            "token.sourcePage == snapshot.activePageIndex",
            "public synchronized void cancel()",
        ],
        "generation-bound asynchronous save fence",
    )
    require(
        runtime,
        [
            "sourceSaveFence.begin(snapshot, markRevision)",
            "if (!sourceSaveAttemptCurrent(attempt)) return;",
            "sourceSaveFence.complete(attempt.token)",
            "sourceSaveFence.cancel();",
        ],
        "queued source-save token containment",
    )
    restore_observe_start = restore_witness.find("public boolean observe(")
    restore_page_ready_start = restore_witness.find(
        "public boolean observePageReady(", restore_observe_start
    )
    restore_installed_start = restore_witness.find(
        "public boolean installedLayersMatch(", restore_page_ready_start
    )
    restore_ready_start = restore_witness.find(
        "public boolean ready(", restore_installed_start
    )
    restore_finish_start = restore_witness.find(
        "public boolean finish(", restore_ready_start
    )
    if min(
        restore_observe_start,
        restore_page_ready_start,
        restore_installed_start,
        restore_ready_start,
        restore_finish_start,
    ) < 0:
        fail("could not isolate stock presentation witness methods")
    require(
        restore_witness[restore_observe_start:restore_page_ready_start],
        [
            "token.activityGeneration != observed.activityGeneration",
            "token.layoutGeneration != observed.layoutGeneration",
            "receiver != expectedReceiver",
            "replacement == oldBitmap",
            "reloadGeneration != token.reloadGeneration",
        ],
        "reload-bound stock layer receipts",
    )
    require(
        restore_witness[restore_page_ready_start:restore_installed_start],
        [
            "reloadGeneration != token.reloadGeneration",
            "presenterMarkPage != token.page + 1",
        ],
        "reload-bound native page-ready receipt",
    )
    require(
        restore_witness[restore_installed_start:restore_ready_start],
        [
            "background == token.backgroundReplacement",
            "ink == token.inkReplacement",
            "digest == token.digestReplacement",
        ],
        "exact installed stock layer identities",
    )
    require(
        restore_witness[restore_ready_start:restore_finish_start],
        ["token.mask == 7 && token.pageReady"],
        "three-layer and page-ready stock restoration witness",
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
            'PRESENTER, loader, "sendWriteInfo",',
            "runtime.onNativeWriterEnableCompleted(",
            'NOTE, loader, "screenRotation",',
            "runtime.onNativeWriterGeometryCompleted(",
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
    activation_start_segment = runtime[start_method:start_end]
    if activation_start_segment.count("lifecycleSuspended") != 2:
        fail("activation success and failure callbacks are not lifecycle-suspended fenced")
    if activation_start_segment.count(
        "lifecycleEpoch != activationLifecycleEpoch"
    ) != 2:
        fail("activation success and failure callbacks are not lifecycle-epoch fenced")
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
            "reserveInputIngressIfIdle()",
            'executeProjection("spread_composition", new Runnable()',
            "fastEvidenceStillCurrent(evidence)",
            "prepared = compositor.compose(",
            "authority changed during projection",
            "boolean posted = ownerHandler.post(new Runnable()",
        ],
        "off-thread composition and evidence bracketing",
    )
    completion_start = runtime.find("private void completeComposition(")
    completion_end = runtime.find(
        "private boolean publishPreparedComposition(", completion_start
    )
    if completion_start < 0 or completion_end < 0:
        fail("could not isolate guarded composition publication")
    ordered(
        runtime[completion_start:completion_end],
        [
            "boolean publicationAdmitted = physicalContactFence.runWhenStylusIdle(",
            "publishPreparedComposition(",
            "if (!publicationAdmitted) {",
            "if (next != visible) next.recycle();",
            "compositionDeferredForPhysicalContact = true;",
        ],
        "physical-contact-atomic composition publication",
    )
    require(
        runtime[completion_start:completion_end],
        [
            "if (!publicationAdmitted) {\n"
            "                if (next != visible) next.recycle();\n"
            "                if (!inputWasFrozen) releaseInputIngress(compositionFreeze);\n"
            "                compositionDeferredForPhysicalContact = true;",
        ],
        "deferred composition cleanup and terminal retry",
    )
    require(
        hooks,
        [
            "@Override public boolean runWhenStylusIdle(",
            "synchronized (entry.stylusRouteLock) {",
            "if (entry.penContact",
            "|| entry.androidPenContact",
            "|| entry.stylusRouteActive",
            "publication.run();",
        ],
        "hook-owned physical stylus publication lock",
    )
    native_pen_down_start = hooks.find("if (contactStart) {")
    native_pen_down_end = hooks.find("if (entry.penContact) {", native_pen_down_start)
    if native_pen_down_start < 0 or native_pen_down_end < 0:
        fail("could not isolate native callback stylus DOWN admission")
    ordered(
        hooks[native_pen_down_start:native_pen_down_end],
        [
            "synchronized (entry.stylusRouteLock) {",
            "if (!entry.penContact) {",
            "entry.penContact = true;",
            "entry.penPass = beginStylusRoute(",
        ],
        "native callback DOWN shares the presentation-publication lock",
    )
    android_pen_down_start = hooks.find(
        "private static boolean routeAndroidPen("
    )
    android_pen_down_end = hooks.find(
        "if (!entry.androidPenContact) return false;",
        android_pen_down_start,
    )
    if android_pen_down_start < 0 or android_pen_down_end < 0:
        fail("could not isolate Android stylus DOWN admission")
    ordered(
        hooks[android_pen_down_start:android_pen_down_end],
        [
            "if (action == MotionEvent.ACTION_DOWN) {",
            "synchronized (entry.stylusRouteLock) {",
            "entry.androidPenContact = true;",
            "entry.androidPenPass = beginStylusRoute(",
        ],
        "Android DOWN shares the presentation-publication lock",
    )
    publish_start = runtime.find("private boolean publishPreparedComposition(")
    publish_end = runtime.find("private void leaveSpreadForPortrait(", publish_start)
    if publish_start < 0 or publish_end < 0:
        fail("could not isolate spread publication transaction")
    ordered(
        runtime[publish_start:publish_end],
        [
            "|| physicalContactFence.stylusContactActive()) {",
            'disableWriterWithWitness(current, "SN_NATIVE_READER_V2 compose")',
            "restoreWriterGeometry();",
            "restorePageGeometry();",
            "capturePresentationScale(",
            "presentationPublicationAttempted = true;",
            "firmware.setBackground(current, next.background);",
            "pageGeometryLease = firmware.programPageGeometry(",
            "programWriterGeometryWithWitness(",
            "committed = true;",
        ],
        "prepared spread publication transaction",
    )
    require(
        runtime[compose_start:publish_end],
        [
            "boolean inputWasFrozen = inputFrozen;",
            "if (!inputWasFrozen) releaseInputIngress(compositionFreeze);",
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
            "cancelActiveSourceSave();",
            "freezeInputIngress();",
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
            "private final NativePresentationRestoreWitness stockRestoreWitness",
            "stockRestoreWitness.begin(",
            "onNativeStockBackgroundPresented(",
            "onNativeStockInkPresented(",
            "onNativeStockDigestPresented(",
            "onNativeStockPageReady(",
            "stockRestoreWitness.observe(",
            "stockRestoreWitness.observePageReady(",
            "stockRestoreWitness.ready(token)",
            "stockRestoreWitness.finish(token)",
            "stock presentation restoration acknowledged",
            "detachmentListener.onRuntimeDetachmentReady(this, reason)",
        ],
        "reload-bound three-layer stock presentation acknowledgement",
    )
    stock_finish_start = runtime.find(
        "private void finishStockPresentationRestorationIfReady("
    )
    stock_finish_end = runtime.find(
        "private long nextStockPresentationReloadGeneration()",
        stock_finish_start,
    )
    if stock_finish_start < 0 or stock_finish_end < 0:
        fail("could not isolate stock restoration authorization")
    require(
        runtime[stock_finish_start:stock_finish_end],
        [
            "|| !firmware.stockPresentationLayersMatch(\n",
            "current.presenterMarkPage != token.page + 1",
            "|| !stockRestoreWitness.finish(token)",
        ],
        "stock restoration exact native authorization",
    )

    require(
        runtime,
        [
            "private long lifecycleEpoch = 1L;",
            "private volatile boolean lifecycleSuspended;",
            "lifecycleSuspended = true;",
            "advanceLifecycleEpoch();",
            "public void onLifecycleResumeRevalidated()",
            "lifecycleSuspended = false;",
        ],
        "lifecycle-suspended publication epoch",
    )
    composition_publish_start = runtime.find(
        "private boolean publishPreparedComposition("
    )
    composition_publish_end = runtime.find(
        "private void leaveSpreadForPortrait(",
        composition_publish_start,
    )
    if composition_publish_start < 0 or composition_publish_end < 0:
        fail("could not isolate prepared-composition publication")
    require(
        runtime[composition_publish_start:composition_publish_end],
        [
            "lifecycleSuspended",
            "lifecycleEpoch != compositionLifecycleEpoch",
            "!inputAdmission.current(compositionFreeze)",
        ],
        "prepared composition lifecycle/freeze publication fence",
    )
    require(
        hooks,
        [
            "expectedRuntime.onLifecycleResumeRevalidated();",
            "entry.runtime.onNativeStockPageReady(",
        ],
        "revalidated lifecycle and native page-ready hook delivery",
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
            "NativeReaderV2AuthorityJournal.inspect(journal.bytes);",
            "return failure.errno != OsConstants.ENOENT;",
            "catch (Throwable ambiguous)",
            "StableBytes markerBefore",
            "StableDigest document = hashRegularFile(canonical)",
            "StableBytes markerAfter",
            "RecoveryIdentity recovery = verifyRecoveryEvidence(",
            "MarkAuthority.acquire(claim)",
            "StableDigest documentIdentity = hashRegularFile(canonical);",
            "StableBytes bytesAfter = readRegularFile(",
            "Long.toString(documentIdentity.identity.size).equals(",
            (
                "|| !documentIdentity.sha256.equals(\n"
                "                    payload.getProperty(\"documentSha256\"))"
            ),
            "!bytes.identity.sameVersion(bytesAfter.identity)",
            "!Arrays.equals(bytes.bytes, bytesAfter.bytes)",
            "public static boolean fastEvidenceStillCurrent(Evidence evidence)",
            "if (!evidence.markAuthorityCurrent()) return false;",
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
            (
                "OsConstants.O_RDWR | OsConstants.O_CREAT\n"
                "                    | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,"
            ),
            "tryLock()",
            "native-reader-v2-live-mark-checkpoint",
            "LIVE_MARK_CHECKPOINT_FIELDS.equals(",
            (
                "|| !claim.backupManifestSha256.equals(\n"
                "                properties.getProperty(\"backupManifestSha256\"))"
            ),
            "live mark checkpoint does not bind recovery authority",
            "if (!liveMarkMatchesRecovery(claim, liveMark)) {",
            "live mark lacks witnessed persisted authority",
            (
                "try {\n"
                "                checkpointExecutor.execute(new Runnable()"
            ),
            "persistWitnessedCheckpoint(generation)",
            "writeLiveMarkCheckpointAtomically(checkpoint, bytes)",
            "FileDescriptor parentDescriptor = openPinnedDirectory(",
            "commonFlags | LINUX_O_DIRECTORY",
            "failure.errno != OsConstants.EINVAL",
            "checkpoint parent changed during FUSE fallback",
            (
                "if (!revalidateForCheckpoint()) {\n"
                "                    throw new IllegalStateException(\n"
                "                        \"live mark writer lease changed before checkpoint\""
            ),
            "live mark writer lease changed across checkpoint",
            "return revalidateLocked(false);",
            "return revalidateLocked(true);",
            "if (closed || (closing && !allowClosing) || unsafe",
            "drained = checkpointExecutor.awaitTermination(",
            (
                "if (drained) {\n"
                "                releaseLeaseAfterCheckpointDrain();\n"
                "                return;\n"
                "            }"
            ),
            "checkpointExecutor.shutdownNow();",
            '}, "sn-v2-mark-lease-cleanup");',
            "if (leaseReleased) return;",
            "another process owns the live mark writer lease",
            "expectedTransition",
        ],
        "document and recovery admission",
    )
    require(
        marker,
        [
            "originalMarkPresent && (markLength < 0L",
        ],
        "empty regular mark authority",
    )
    require(
        authority_journal,
        [
            "public static final int FORMAT_VERSION = 3;",
            "public static final int SLOT_COUNT = 2;",
            "public static final int SLOT_SIZE = 16 * 1024;",
            "public static final int HEADER_SIZE = 128;",
            '"supernote-native-reader-v2-authority-slot-v3\\0"',
            "Any non-zero invalid slot rejects the whole file",
            "journal slots reuse one generation",
            "journal slot has unauthenticated tail",
            "MessageDigest.isEqual(",
        ],
        "fixed authority journal wire contract",
    )
    require(
        plugin_authority_journal,
        [
            "const val FORMAT_VERSION = 3",
            "const val SLOT_COUNT = 2",
            "const val SLOT_SIZE = 16 * 1024",
            "const val HEADER_SIZE = 128",
            '"supernote-native-reader-v2-authority-slot-v3\\u0000"',
            "OsConstants.O_NOFOLLOW",
            "Os.pread(",
            "Os.pwrite(",
            "writeExactly(descriptor, ByteArray(HEADER_SIZE), slotOffset)",
            "encoded.copyOfRange(HEADER_SIZE, SLOT_SIZE)",
            "encoded.copyOfRange(0, HEADER_SIZE)",
            "requireRegularSingleLink(after)",
            "sameStableFileMetadata(before, after)",
            "first.st_uid == second.st_uid",
            "first.st_gid == second.st_gid",
            "strictFailure.errno != OsConstants.EINVAL",
            "sameVersion(before, opened) && sameVersion(opened, path)",
            "New journal path does not name its created inode",
            "New journal was replaced before admission",
            "fun readRepairCandidate(file: File): RepairCandidate?",
            "fun repairWithRecovery(",
            "if (valid.size != 1 || malformed.size != 1) return null",
            "sameVersion(expected.identity, before)",
            "sha256(currentBytes) == expected.fileSha256",
            "val encoded = encodeSlot(slotIndex, State.RECOVERY, generation, payload)",
            "sameRecord(current.first, expected.trusted)",
            "first.st_mtim.tv_nsec == second.st_mtim.tv_nsec",
            "first.st_ctim.tv_nsec == second.st_ctim.tv_nsec",
        ],
        "Android fixed-inode journal implementation",
    )
    publication_segment = plugin_authority_journal[
        plugin_authority_journal.find("fun publish("):
        plugin_authority_journal.find("fun repairWithRecovery(")
    ]
    if publication_segment.count("Os.fsync(descriptor)") != 3:
        fail("authority journal does not sync all three publication stages")
    for forbidden in ("Os.rename", "Files.delete", "ftruncate", "FileOutputStream"):
        if forbidden in publication_segment:
            fail(f"authority journal publication uses forbidden mutation: {forbidden}")
    repair_segment = plugin_authority_journal[
        plugin_authority_journal.find("fun repairWithRecovery("):
        plugin_authority_journal.find("private fun encodeSlot(")
    ]
    if repair_segment.count("Os.fsync(descriptor)") != 3:
        fail("authority journal recovery repair does not sync all three stages")
    for forbidden in ("Os.rename", "Files.delete", "ftruncate", "FileOutputStream"):
        if forbidden in repair_segment:
            fail(f"authority journal recovery repair uses forbidden mutation: {forbidden}")
    require(
        plugin,
        [
            "NativeReaderV2AuthorityJournal.readRepairCandidate(marker) != null",
            "if (unreadableJournal != null) {",
            "NativeReaderV2AuthorityJournal.repairWithRecovery(",
            "if (journalInspection.blocking &&\n                            !repairableInterruptedPublication",
            "Native mark recovery authority changed before repair",
        ],
        "explicit interrupted-journal recovery containment",
    )
    require(
        plugin,
        [
            '"Acknowledged Native Reader journal disappeared"',
            "currentAuthority.journalGeneration == expectation.generation",
            "currentAuthority.journalAuthoritySha256 ==",
            "expectation.authoritySha256",
            "currentAuthority.journalState?.name?.lowercase(Locale.ROOT) ==",
            '"Native Reader journal changed after Document acknowledgement"',
        ],
        "post-ACK live journal revalidation",
    )
    require(
        plugin,
        [
            "val payloadState = journalState(strictProperties(current.payload))",
            "require(payloadState == current.state)",
            "Native Reader journal header and payload states disagree",
            "private fun nativeSpreadLegacyMarker(pdfFile: File): File",
            "LegacyNativeSpreadAuthority(",
            "legacy_protected_authority_requires_migration",
            "legacy_authority_requires_supersession",
            "must not\n                                        // strand the React promise",
            "                                        }.getOrElse { Properties() }",
            "require(samePersistedAuthority(\n"
            "                            legacyMigration.authority,\n"
            "                            exactLegacy,\n"
            "                        )) {\n"
            "                            \"Legacy Native Spread authority changed at migration publication\"",
            "Legacy Native Spread authority changed at migration publication",
            "legacyMigration = legacy",
            "preserved backup evidence remains an",
            "independent recovery blocker",
        ],
        "journal semantic state and legacy-authority migration",
    )
    require(
        native_installer,
        [
            '"NativeReaderV2AuthorityJournal.kt.template"',
            '"NativeReaderV2AuthorityJournal.kt"',
        ],
        "authority journal template installation",
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
            "MINIMUM_COMPANION_MODULE_VERSION = 140L",
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
            "val markerAuthority = readPersistedAuthorityIfFile(marker)",
            "strictNativeSpreadMarkerProperties(authority.bytes)",
            "assessNativeSpreadAuthority(",
            "publishNativeSpreadModeAfterRevalidation(",
        ],
        "single-snapshot off-main-thread marker and recovery validation",
    )
    require(
        load_segment,
        [
            "if (propertiesResult.isFailure)",
            'NativeSpreadHandshake(false, "marker_unreadable")',
            "markerAuthority,\n                            capability,",
            "backupResult,\n                            authority,",
        ],
        "malformed-marker recovery-only state",
    )
    publish_start = plugin.find("private fun publishNativeSpreadModeAfterRevalidation(")
    publish_end = plugin.find("private fun resolveNativeSpreadMode(", publish_start)
    if publish_start < 0 or publish_end < 0:
        fail("could not isolate native-mode snapshot publication")
    publish_segment = plugin[publish_start:publish_end]
    ordered(
        publish_segment,
        [
            "requireNativeSpreadConfigurationGeneration(\n"
            "                    configurationGeneration,",
            "val currentMarkerAuthority = readPersistedAuthorityIfFile(marker)",
            "samePersistedAuthority(\n                        expectedMarkerAuthority,",
            '"Native Spread marker changed while its settings were loading"',
            "val currentBackupResult = readNativeAnnotationBackup(pdfFile)",
            "sameNativeAnnotationBackupResult(\n                        backupResult,",
            '"Native Spread recovery evidence changed while its settings were loading"',
            "val currentAuthority = assessNativeSpreadAuthority(",
            "require(currentAuthority == authority)",
            "Handler(Looper.getMainLooper()).post",
            "withNativeSpreadConfigurationAuthority(\n"
            "                            configurationGeneration,",
            "resolveNativeSpreadMode(",
        ],
        "post-handshake exact marker and recovery-snapshot revalidation",
    )
    require(
        plugin,
        [
            "val loadGeneration = captureNativeSpreadConfigurationGeneration()",
            "val handshakeGeneration = loadGeneration",
            "private fun captureNativeSpreadConfigurationGeneration(): Long =",
            "check(!nativeSpreadModuleInvalidated.get())",
        ],
        "native-mode load generation authority",
    )
    reconcile_start = plugin.find("fun reconcileNativeSpreadRecovery(")
    reconcile_end = plugin.find("fun configureNativeSpreadReadOnly(", reconcile_start)
    restore_start = plugin.find("fun restoreNativeAnnotationBackup(")
    restore_end = plugin.find("private fun writeNativeSpreadReadOnlyMarker(", restore_start)
    if min(reconcile_start, reconcile_end, restore_start, restore_end) < 0:
        fail("could not isolate native recovery configuration entrypoints")
    ordered(
        plugin[reconcile_start:reconcile_end],
        [
            "val configurationGeneration = beginNativeSpreadRecovery()",
            "requireNativeSpreadConfigurationGeneration(\n"
            "                        configurationGeneration,",
            "withNativeSpreadPublicationLock(marker)",
            "withNativeSpreadConfigurationAuthority(",
            "reconcileFailedActivationBackupForExplicitActivation(",
            "completeNativeSpreadRecovery(configurationGeneration)",
            "promise.resolve(true)",
        ],
        "recovery reconciliation generation ownership",
    )
    ordered(
        plugin[restore_start:restore_end],
        [
            "val configurationGeneration = beginNativeSpreadRecovery()",
            "requireNativeSpreadConfigurationGeneration(\n"
            "                    configurationGeneration,",
            "val recoveryInspection = inspectNativeMarkRecoveryFence(pdfFile, marker)",
            "scheduleAnnotationRestore(\n"
            "                    pdfFile,\n"
            "                    backup,\n"
            "                    configurationGeneration,",
            "completeNativeSpreadRecovery(configurationGeneration)",
            "promise.resolve(nativeAnnotationBackupMap(backup, \"restored\"))",
        ],
        "annotation restore generation ownership",
    )
    recovery_helpers_start = plugin.find("private fun beginNativeSpreadConfiguration(): Long =")
    recovery_helpers_end = plugin.find("private fun nativeSpreadCapability(", recovery_helpers_start)
    if recovery_helpers_start < 0 or recovery_helpers_end < 0:
        fail("could not isolate native recovery generation helpers")
    recovery_helpers = plugin[recovery_helpers_start:recovery_helpers_end]
    begin_recovery_start = recovery_helpers.find(
        "private fun beginNativeSpreadRecovery(): Long ="
    )
    complete_recovery_start = recovery_helpers.find(
        "private fun completeNativeSpreadRecovery(expected: Long): Boolean ="
    )
    capture_generation_start = recovery_helpers.find(
        "private fun captureNativeSpreadConfigurationGeneration(): Long ="
    )
    if min(
        begin_recovery_start,
        complete_recovery_start,
        capture_generation_start,
    ) < 0:
        fail("could not isolate native recovery generation phases")
    ordered(
        recovery_helpers[:begin_recovery_start],
        [
            "check(!nativeSpreadModuleInvalidated.get())",
            "check(!annotationRecoveryPending.get())",
            "nativeSpreadConfigurationGeneration.incrementAndGet()",
        ],
        "configuration admission excludes active recovery",
    )
    ordered(
        recovery_helpers[begin_recovery_start:complete_recovery_start],
        [
            "check(!nativeSpreadModuleInvalidated.get())",
            "nativeSpreadRecoveryOwnerGeneration.get() ==\n"
            "                    NATIVE_SPREAD_NO_RECOVERY_OWNER",
            "annotationRecoveryPending.compareAndSet(false, true)",
            "nativeSpreadConfigurationGeneration.incrementAndGet()",
            "nativeSpreadRecoveryOwnerGeneration.set(generation)",
        ],
        "recovery admission exact-owner generation advance",
    )
    ordered(
        recovery_helpers[complete_recovery_start:capture_generation_start],
        [
            "nativeSpreadRecoveryOwnerGeneration.compareAndSet(\n"
            "                expected,\n"
            "                NATIVE_SPREAD_NO_RECOVERY_OWNER,",
            "if (!exactOwner) return@synchronized false",
            "annotationRecoveryPending.compareAndSet(true, false)",
            "nativeSpreadConfigurationGeneration.get() == expected",
            "Invalidate any load that began while recovery was active",
            "nativeSpreadConfigurationGeneration.incrementAndGet()",
        ],
        "recovery completion generation advance",
    )
    ordered(
        recovery_helpers[capture_generation_start:],
        [
            "check(!nativeSpreadModuleInvalidated.get())",
            "check(!annotationRecoveryPending.get())",
            "nativeSpreadConfigurationGeneration.get()",
        ],
        "mode-load admission excludes active recovery",
    )
    if plugin.count("val configurationGeneration = beginNativeSpreadRecovery()") != 2:
        fail("both recovery mutation entrypoints must acquire a fresh generation")
    readonly_start = plugin.find("fun configureNativeSpreadReadOnly(")
    readonly_end = plugin.find("fun configureNativeSpreadEditable(", readonly_start)
    editable_start = readonly_end
    editable_end = plugin.find("fun restoreNativeAnnotationBackup(", editable_start)
    if min(readonly_start, readonly_end, editable_start, editable_end) < 0:
        fail("could not isolate Native Spread configuration entrypoints")
    for segment, label in (
        (plugin[readonly_start:readonly_end], "read-only/off configuration"),
        (plugin[editable_start:editable_end], "editable configuration"),
    ):
        ordered(
            segment,
            [
                "try {",
                "val configurationGeneration = beginNativeSpreadConfiguration()",
            ],
            f"{label} promise-safe recovery exclusion",
        )
        ordered(
            segment,
            [
                "withNativeSpreadPublicationLock(marker)",
                "withNativeSpreadConfigurationAuthority(",
                "reconcileFailedActivationBackupForExplicitActivation(",
            ],
            f"{label} cross-process reconciliation authority",
        )
    restore_pending_start = plugin.find(
        "private fun restorePendingActivationPreviousMarker("
    )
    reconcile_pending_start = plugin.find(
        "private fun reconcileFailedActivationBackupForExplicitActivation("
    )
    reconcile_pending_end = plugin.find(
        "private fun nativeAnnotationBackupMap(", reconcile_pending_start
    )
    if min(
        restore_pending_start,
        reconcile_pending_start,
        reconcile_pending_end,
    ) < 0 or restore_pending_start >= reconcile_pending_start:
        fail("could not isolate pending-marker reconciliation authority")
    restore_pending_segment = plugin[
        restore_pending_start:reconcile_pending_start
    ]
    ordered(
        restore_pending_segment,
        [
            "pdfFile: File,",
            "expectedMarkerAuthority: PersistedFileAuthority,",
            "val currentMarkerAuthority = readPersistedAuthorityIfFile(marker)",
            "samePersistedAuthority(expectedMarkerAuthority, currentMarkerAuthority)",
            "val previousBytes = pending.previousMarkerBytes",
            "val off = nativeSpreadOffMarkerProperties(",
            "writePropertiesAtomicallyCas(",
            '"Interrupted Native Reader activation OFF authority",\n'
            "                expectedMarkerAuthority,",
            "writeBytesAtomicallyCas(",
            "previousBytes,\n                expectedMarkerAuthority,",
        ],
        "pending-marker exact-authority restore",
    )
    if "deleteRegularFileCas(" in restore_pending_segment:
        fail("fixed Native Reader journal must not be deleted during rollback")
    if restore_pending_segment.count("writePropertiesAtomicallyCas(") != 1:
        fail("absent prior authority must restore as one durable OFF record")
    if restore_pending_segment.count("writeBytesAtomicallyCas(") != 1:
        fail("pending-marker restoration must use exactly one exact-authority CAS")
    reconcile_pending_segment = plugin[
        reconcile_pending_start:reconcile_pending_end
    ]
    ordered(
        reconcile_pending_segment,
        [
            "val markerAuthority = readPersistedAuthorityIfFile(marker)",
            "strictNativeSpreadMarkerProperties(authority.bytes)",
            "val pendingMarkerPresent =",
            "val pendingMarkerAuthority = markerAuthority",
        ],
        "pending-marker descriptor authority capture",
    )
    if reconcile_pending_segment.count(
        "restorePendingActivationPreviousMarker("
    ) != 4:
        fail("all four pending-marker restoration branches must retain exact authority")
    if reconcile_pending_segment.count("pendingMarkerAuthority,") != 5:
        fail("a pending-marker restoration branch dropped its exact authority")
    require(
        reconcile_pending_segment,
        [
            "val off = nativeSpreadOffMarkerProperties(",
            '"Interrupted protected-session retirement OFF authority",',
            "NativeReaderV2AuthorityJournal.State.OFF",
        ],
        "pending-retirement durable OFF authority",
    )
    restore_worker_start = plugin.find("private fun scheduleAnnotationRestore(")
    restore_worker_end = plugin.find(
        "private fun nativeMarkRecoveryRequired(", restore_worker_start
    )
    if restore_worker_start < 0 or restore_worker_end < 0:
        fail("could not isolate annotation restore worker")
    ordered(
        plugin[restore_worker_start:restore_worker_end],
        [
            "withNativeSpreadPublicationLock(marker) {",
            "withNativeSpreadConfigurationAuthority(",
            "publishNativeMarkRecoveryJournal(",
            "publication = publishNativeAnnotationRestore(",
            "retireNativeMarkRecoveryJournal(",
            "removeNativeAnnotationBackupFiles(",
        ],
        "restore publication retains generation authority through commit",
    )
    require(
        plugin,
        [
            "private fun sameNativeAnnotationBackupResult(",
            "expected.status == actual.status",
            "else -> sameNativeAnnotationBackup(expected.backup, actual.backup)",
            "val manifestAuthority: PersistedFileAuthority,",
            "val snapshotAuthority: PersistedFileFingerprint?,",
            "private data class PersistedFileFingerprint(",
            'authorityLabel = "annotation-backup manifest"',
            'authorityLabel = "annotation-backup snapshot"',
            "samePersistedAuthority(\n                expected.manifestAuthority,",
            "samePersistedFingerprint(\n                expected.snapshotAuthority,",
            "private fun readRegularFileFingerprintIfFile(",
            'MessageDigest.getInstance("SHA-256")',
            "FileInputStream(Os.dup(descriptor)).use",
            "length == opened.st_size",
            'authorityLabel = "annotation-backup manifest revalidation"',
            'authorityLabel = "annotation-backup snapshot revalidation"',
        ],
        "descriptor-backed complete native backup result identity",
    )
    backup_match_start = plugin.find(
        "private fun nativeAnnotationBackupSourceFilesMatch("
    )
    backup_match_end = plugin.find(
        "private fun protectedEditableSessionMarkerValid(", backup_match_start
    )
    if backup_match_start < 0 or backup_match_end < 0:
        fail("could not isolate native backup source-file revalidation")
    require(
        plugin[backup_match_start:backup_match_end],
        [
            "val currentSnapshot = readRegularFileFingerprintIfFile(\n"
            "            backup.snapshot,",
            "samePersistedAuthority(backup.manifestAuthority, currentManifest)",
            "samePersistedFingerprint(\n"
            "                        backup.snapshotAuthority,\n"
            "                        currentSnapshot,\n"
            "                    )",
        ],
        "native backup manifest and snapshot descriptor revalidation",
    )
    if "snapshotAuthority.bytes" in plugin:
        fail("large annotation backup snapshot is retained in the plug-in heap")
    require(
        plugin,
        [
            "private fun inspectNativeMarkRecoveryFenceFromAuthority(",
            "markerAuthority: PersistedFileAuthority?,",
            "inspectNativeMarkRecoveryFenceFromAuthority(\n            pdfFile,",
        ],
        "recovery assessment consumes the loaded marker authority",
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
    component_identity_registry = read(
        source / "v2/NativeComponentIdentityRegistry.java"
    )
    require(
        component_identity_registry,
        [
            "public synchronized Lease acquire(Object... requestedComponents)",
            "entry.leaseCount++;",
            "public synchronized void release(Lease lease)",
            "entry.leaseCount--;",
            "if (entry.leaseCount == 0) entries.remove(entry);",
            "if (lease.components[role] != component)",
            "native component identity lease authority was lost",
        ],
        "runtime-leased native component identities",
    )
    require(
        firmware,
        [
            "NativeComponentIdentityRegistry componentIdentities",
            "acquireComponentIdentityLease(",
            "releaseComponentIdentityLease(",
            "identityLease.id(0, components.viewModel)",
            "identityLease.id(3, components.binder)",
        ],
        "firmware component identity lease boundary",
    )
    require(
        runtime,
        [
            "componentIdentityLease =",
            "firmware.acquireComponentIdentityLease(current);",
            (
                "firmware.releaseComponentIdentityLease(\n"
                "                        releasedIdentityLease\n"
                "                    );"
            ),
        ],
        "retired runtime identity lease release",
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
            "dirty = firmware.sourceHasTrails(source);",
            "token = saveWitness.begin(",
            "firmware.saveSource(source);",
            "saveWitness.finish(token)",
            "evidence.noteWitnessedMarkSave(dirty, saved);",
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
            "[string]$ExpectedSignerSha256 = ''",
            "-ExpectedSignerSha256 is required for signed builds",
            "-ExpectedSignerSha256 is incompatible with -AlignedOnly.",
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
            "spread-probe-unsigned-normalized.apk",
            "[switch]$AlignedOnly",
            "$outputApk = $alignedApk",
            "if (-not $AlignedOnly)",
            "APK entry timestamp is not canonical",
            "APK entry order is not canonical",
            "Two clean Native Reader builds are byte-for-byte reproducible",
        ],
        "exclusive v2 packaging",
    )
    ordered(
        build,
        [
            "$normalizedExpectedSigner = ''",
            "if ($AlignedOnly) {",
            "if ($ExpectedSignerSha256) {",
            "-ExpectedSignerSha256 is incompatible with -AlignedOnly.",
            "if (-not $ExpectedSignerSha256) {",
            "-ExpectedSignerSha256 is required for signed builds",
            "$ExpectedSignerSha256.Trim().ToLowerInvariant()",
            "Expected signer SHA-256 is not canonical lowercase hexadecimal.",
        ],
        "explicit signed-build identity selection",
    )
    require(
        root_build,
        [
            'TEMPLATE_VERSION="1.0.12"',
            "plugin-template-package-lock.json.gz.b64",
            "npm pack --ignore-scripts --silent",
            "scripts/materialize_plugin_template.py",
            "npm ci --ignore-scripts --no-audit --no-fund",
            'EXPECTED_BUNDLE="$PROJECT/build/generated/SupernoteRtlReader.bundle"',
            'EXPECTED_NATIVE_APK="$PROJECT/build/generated/app.npk"',
            'PROVENANCE_OUTPUT="$ROOT/out/build-provenance"',
            'cp "$EXPECTED_BUNDLE" "$PROVENANCE_OUTPUT/SupernoteRtlReader.bundle"',
            'cp "$EXPECTED_NATIVE_APK" "$PROVENANCE_OUTPUT/app.npk"',
        ],
        "authenticated plugin-template build",
    )
    if "@supernote-plugin/sn-plugin-template \\" in root_build:
        fail("plugin build still initializes from a mutable template tag")
    require(
        template_materializer,
        [
            'EXPECTED_TEMPLATE_VERSION = "1.0.12"',
            "34dceadedd77d2c77c83521fee838dc60f3893b948a9070bf38271184268636f",
            "sha512-n7wY9y43DYJUNGdFEjFu+i8bU9C3TX9UG1yWjYbkcn3zWBUNSFuEC5LQ5FmK",
            "33ea436d56b68d332949db0689f4b0c2bfd6f227e78e904b7706360ebc161022",
            "member.issym() or member.islnk() or member.isdev()",
            "lacks SHA-512 integrity",
        ],
        "template and locked dependency authority",
    )
    if len("".join(lock_input.split())) < 100_000:
        fail("committed compressed package lock is unexpectedly small")
    require(
        apk_normalizer,
        [
            "CANONICAL_TIMESTAMP = (1980, 1, 1, 0, 0, 0)",
            "for name in sorted(entries)",
            "compression=zipfile.ZIP_STORED",
            "duplicate input entry",
        ],
        "deterministic unsigned APK normalization",
    )
    require(
        packager_patch,
        [
            "EXPECTED_PLUGIN_APK_SIGNER_SHA256",
            "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
            "Final compacted APK signer is not the reviewed identity",
            "build-tools/35.0.0",
            "normalized_verification_output",
            "signer_digests",
            "Final compacted APK must contain exactly one signer digest",
            "for required_scheme in 2 3; do",
            r"[[:space:]]*$/\\1/p'",
        ],
        "embedded plugin APK signer authority",
    )
    if "sort -V" in packager_patch or "tail -n 1" in packager_patch:
        fail("plugin packager may select an unreviewed Android build-tools version")
    require(
        provenance_test,
        [
            "canonical ZIP output depends on input order or timestamps",
            "mutated package lock",
            "unreviewed template tarball",
        ],
        "build provenance failure tests",
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
            "NATIVE_READER_V2_MIN_VERSION_CODE = 140L",
            "NATIVE_READER_V2_SIGNER_SHA256 =",
            "NATIVE_READER_V2_APK_LENGTH = 287259L",
            "NATIVE_READER_V2_APK_SHA256 =",
            "af6b0b88f0622504471660d5db877ba9472860b67e845b5560caac3e9374e017",
            "PackageManager.GET_SIGNING_CERTIFICATES",
            "signing.hasMultipleSigners()",
            "Native Reader signer set is not exact",
            "applicationInfo.sourceDir",
            "applicationInfo.splitSourceDirs.isNullOrEmpty()",
            'openPinnedRegularFile(',
            '"Native Reader base APK"',
            "sourceBytes.size.toLong() != NATIVE_READER_V2_APK_LENGTH",
            "sha256(sourceBytes) != NATIVE_READER_V2_APK_SHA256",
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
            "                                    requireBackupDocumentIdentity(\n"
            "                                        pdfFile,\n"
            "                                        revalidatedBackup,\n"
            "                                        if (revalidatedBackup.originalMarkPresent) {\n"
            "                                            \"before-mark-publish\"",
            '"before-mark-publish"',
            '"after-mark-publish"',
            '"after-mark-verification"',
            '"before-mark-delete"',
            '"after-mark-delete"',
            '"before-backup-retirement"',
            "restorePrePublicationMark(",
            "immediateMarkerBytes?.contentEquals(previousMarkerBytes)",
            "sameNativeAnnotationBackup(backup, immediateBackup)",
            "immediateMarker?.bytes?.contentEquals(pendingMarkerBytes)",
            "liveNativeAnnotationMatchesBackup(backup)",
            "val committedMarkerAuthority = readPersistedAuthorityIfFile(marker)",
            "strictNativeSpreadMarkerProperties(\n"
            "            committedMarkerAuthority.bytes,",
            'committedMarker.getProperty("activationState", "") !=\n'
            "                NATIVE_SPREAD_ACTIVATION_COMMITTED",
            "sameNativeAnnotationBackup(backup, committedBackup)",
            "protectedEditableMarkerValid(\n"
            "                pdfFile,\n"
            "                committedMarker,\n"
            "                committedBackup,",
            "RTL_READER_NATIVE_EDITABLE_COMMIT_VERIFIED",
        ],
        "crash-durable compare-and-publish authority",
    )
    require(
        plugin,
        [
            'NATIVE_SPREAD_PUBLICATION_LOCK_SUFFIX =',
            "NATIVE_SPREAD_PUBLICATION_PROCESS_LOCK",
            "private fun <T> withNativeSpreadPublicationLock(",
            "channel.lock().use",
            "LINUX_O_DIRECTORY = 0x10000",
            "LINUX_O_DIRECTORY or OsConstants.O_NOFOLLOW",
            "private fun openPinnedDirectory(",
            "if (strictFailure.errno != OsConstants.EINVAL)",
            "val before = Os.lstat(directory.absolutePath)",
            "OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or\n"
            "                OsConstants.O_NOFOLLOW,",
            "sameFileObject(before, opened)",
            "sameFileObject(opened, after)",
            "RTL_READER_PINNED_DIRECTORY_FUSE_FALLBACK",
            "OsConstants.O_NOFOLLOW",
            "OsConstants.O_EXCL",
            "private data class PersistedFileAuthority(",
            (
                "val descriptor = Os.open(\n"
                "            path,\n"
                "            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,"
            ),
            "private fun samePersistedAuthority(",
            "private fun writePropertiesAtomicallyCas(",
            "expected = currentMarkerAuthority",
            "expected = pendingMarkerAuthority",
            "Published destination changed before compare-and-publish",
            "val renamedStagedIdentity = try {",
            "Os.fstat(openedTemporary)",
            "} finally {\n                // Rename is the irreversible publication boundary.",
            "sameFileObject(stagedIdentity, renamedStagedIdentity)",
            (
                "samePersistedFileVersion(\n"
                "                        renamedStagedIdentity,\n"
                "                        published.identity,"
            ),
            (
                "samePersistedFileVersion(\n"
                "                        published.identity,\n"
                "                        Os.lstat(file.absolutePath),"
            ),
        ],
        "cross-process marker compare-and-publish",
    )
    publication_start = plugin.find("private fun writeBytesAtomicallyCas(")
    publication_end = plugin.find(
        "private fun pathIdentityNoFollow(",
        publication_start,
    )
    if publication_start < 0 or publication_end < 0:
        fail("could not isolate atomic CAS publication method")
    publication = plugin[publication_start:publication_end]
    if "samePersistedFileVersion(stagedIdentity, published.identity)" in publication:
        fail("atomic publication compares pre-rename ctime to published ctime")
    rename_publication = publication[publication.find("val parent ="):]
    ordered(
        rename_publication,
        [
            "Os.rename(temporary.absolutePath, file.absolutePath)",
            (
                "val renamedStagedIdentity = try {\n"
                "                Os.fstat(openedTemporary)"
            ),
            "onPublished()",
            "val published = readPersistedAuthorityIfFile(file)",
        ],
        "post-rename descriptor capture precedes adversarial publication callback",
    )
    activation_start = plugin.find(
        "private fun activateNativeSpreadEditableWithStableBackup("
    )
    activation_end = plugin.find(
        "private fun rollbackNativeSpreadEditableActivation(", activation_start
    )
    if activation_start < 0 or activation_end < 0:
        fail("could not isolate protected editable activation")
    activation = plugin[activation_start:activation_end]
    ordered(
        activation,
        [
            "var committedMarkerPublishedByActivation = false",
            "var committedMarkerVerifiedByActivation = false",
            "val committedBackup = commitNativeSpreadEditableMarker(",
            "committedMarkerPublishedByActivation = true",
            "committedMarkerVerifiedByActivation = true",
            "return committedBackup",
            "if (committedMarkerPublishedByActivation) {",
            "RTL_READER_NATIVE_EDITABLE_COMMIT_VERIFICATION_FAILED",
            "throw activationError",
        ],
        "committed publication is distinct from verified activation success",
    )
    commit_start = plugin.find("private fun commitNativeSpreadEditableMarker(")
    commit_end = plugin.find(
        "private fun resolveNativeSpreadMode(", commit_start
    )
    if commit_start < 0 or commit_end < 0:
        fail("could not isolate committed marker publication")
    ordered(
        plugin[commit_start:commit_end],
        [
            "writePropertiesAtomicallyCas(",
            "val committedMarkerAuthority = readPersistedAuthorityIfFile(marker)",
            "val committedBackup = readNativeAnnotationBackup(pdfFile).backup",
            "!protectedEditableMarkerValid(\n"
            "                pdfFile,\n"
            "                committedMarker,",
            "RTL_READER_NATIVE_EDITABLE_COMMIT_VERIFIED",
            "        committedBackup\n    }",
        ],
        "durable committed-marker success postcondition",
    )
    if "if (markerCommittedByActivation" in activation or (
        "if (committedMarkerPublishedByActivation" in activation
        and "return backup" in activation[
            activation.find("if (committedMarkerPublishedByActivation") :
        ]
    ):
        fail("post-publication verification failure is converted into success")
    if plugin.count("LINUX_O_DIRECTORY or OsConstants.O_NOFOLLOW") != 1:
        fail("directory descriptors bypass the pinned FUSE-compatible opener")
    pending_publish_start = plugin.find("private fun writeNativeSpreadPendingMarker(")
    pending_publish_end = plugin.find(
        "private fun commitNativeSpreadEditableMarker(",
        pending_publish_start,
    )
    commit_publish_end = plugin.find(
        "private fun resolveNativeSpreadMode(",
        pending_publish_end,
    )
    if pending_publish_start < 0 or pending_publish_end < 0 or commit_publish_end < 0:
        fail("could not isolate companion marker publication methods")
    for label, section in (
        ("pending", plugin[pending_publish_start:pending_publish_end]),
        ("committed", plugin[pending_publish_end:commit_publish_end]),
    ):
        require(
            section,
            [
                "withNativeSpreadPublicationLock(marker)",
                "withNativeSpreadConfigurationAuthority(configurationGeneration)",
                "readPersistedAuthorityIfFile(marker)",
                "writePropertiesAtomicallyCas(",
            ],
            f"{label} marker locked CAS publication",
        )

    require(
        plugin,
        [
            "private data class NativeMarkPublication(",
            "private data class DisplacedRegularFile(",
            "private data class NativeMarkRecoveryJournal(",
            "private class NativeMarkRecoveryRequiredException(",
            "private val NATIVE_MARK_RECOVERY_REQUIRED_PATHS = HashSet<String>()",
            "private fun inspectNativeMarkRecoveryFence(",
            "private fun publishNativeMarkRecoveryJournal(",
            "private fun retireNativeMarkRecoveryJournal(",
            "private fun readPinnedRegularBytes(",
            "private fun openPinnedRegularFile(",
            "private fun publishNativeAnnotationRestore(",
            'Os.fstat(snapshotDescriptor)',
            'Os.lstat(backup.snapshot.absolutePath)',
            'Os.fstat(previousDescriptor)',
            "private fun preserveRegularDestinationNoClobber(",
            "private fun createRegularFileNoClobber(",
            "private fun publishRegularFileNoClobber(",
            "private fun publishRegularFileAbsenceNoClobber(",
            "Files.createDirectory(transactionDirectory.toPath())",
            'File(transactionDirectory, "displaced")',
            "Os.rename(file.absolutePath, displaced.absolutePath)",
            "OsConstants.O_EXCL",
            "raced with destination preservation; displaced inode retained",
            "withNativeSpreadPublicationLock(marker)",
            "publishNativeMarkRecoveryJournal(",
            "retireNativeMarkRecoveryJournal(",
            "RTL_READER_NATIVE_BACKUP_RESTORE_POST_PUBLICATION_ROLLED_BACK",
            "restorePrePublicationMark(value)",
            "publishedIdentity",
            "RTL_READER_NATIVE_BACKUP_RESTORE_RECOVERY_REQUIRED_NOT_REOPENED",
            "RTL_READER_HANDOFF_RESTART_BLOCKED reason=native_mark_recovery_required",
        ],
        "descriptor-pinned annotation restore and rollback",
    )
    if "currentMark.readBytes()" in plugin:
        fail("annotation restore reads the live .mark without no-follow descriptor authority")
    if "copyFileAtomically(\n                        revalidatedBackup.snapshot" in plugin:
        fail("annotation restore reopens its snapshot by path during publication")
    no_clobber_create_start = plugin.find("private fun createRegularFileNoClobber(")
    no_clobber_create_end = plugin.find(
        "private fun publishRegularFileNoClobber(",
        no_clobber_create_start,
    )
    if no_clobber_create_start < 0 or no_clobber_create_end < 0:
        fail("could not isolate native annotation no-clobber creation")
    require(
        plugin[no_clobber_create_start:no_clobber_create_end],
        [
            "OsConstants.O_CREAT",
            "OsConstants.O_EXCL",
            "OsConstants.O_NOFOLLOW",
            "samePersistedFileVersion(",
            "syncParentDirectory(file)",
        ],
        "native annotation no-clobber final creation",
    )
    preserve_start = plugin.find(
        "private fun preserveRegularDestinationNoClobber("
    )
    preserve_end = plugin.find(
        "private fun createRegularFileNoClobber(", preserve_start
    )
    if preserve_start < 0 or preserve_end < 0:
        fail("could not isolate native annotation displaced-file preservation")
    preserve = plugin[preserve_start:preserve_end]
    require(
        preserve,
        [
            "val parentDescriptor = openPinnedDirectory(",
            '"$authorityLabel preservation parent"',
            "beforePublish()",
            "val immediate = readRegularFileAuthorityIfFile(",
            "val admittedDescriptor = Os.open(",
            "val admittedIdentity = Os.fstat(admittedDescriptor)",
            "samePersistedFileVersion(immediate.identity, admittedIdentity)",
            "var renameCompleted = false",
            "samePersistedFileVersion(\n"
            "                                    admittedIdentity,\n"
            "                                    Os.fstat(admittedDescriptor),",
            "Os.rename(file.absolutePath, displaced.absolutePath)",
            "renameCompleted = true",
            "val renamedAdmittedIdentity = Os.fstat(admittedDescriptor)",
            "sameFileObject(admittedIdentity, renamedAdmittedIdentity)",
            "samePersistedFileVersion(\n"
            "                                    renamedAdmittedIdentity,\n"
            "                                    moved.identity,",
            "immediate.bytes.contentEquals(moved.bytes)",
            "Os.fsync(transactionDirectoryDescriptor)",
            "Os.fsync(parentDescriptor)",
            "if (!renameCompleted) throw failure",
            "val pathAuthoritiesStillOwned = runCatching",
            "retained == null || live != null",
            "NativeMarkRecoveryRequiredException(",
            '"$authorityLabel rejected-preservation recovery"',
            "val retainedAfterRestore = readRegularFileAuthorityIfFile(",
            "retained.bytes.contentEquals(restored.bytes)",
            "sameRegularFileAuthority(retained, retainedAfterRestore)",
            "closeDescriptorWithoutMaskingRecovery(",
            '"$authorityLabel admitted destination"',
            "throw failure",
        ],
        "FUSE-safe post-rename annotation recovery and retained evidence",
    )
    if "sameRegularFileAuthority(expected, moved)" in preserve:
        fail("displaced-file preservation compares pre-rename ctime after FUSE rename")
    if "true || immediate.bytes.contentEquals(moved.bytes)" in preserve:
        fail("displaced-file preservation bypasses byte continuity")
    ordered(
        preserve,
        [
            "beforePublish()",
            "val immediate = readRegularFileAuthorityIfFile(",
            "val admittedDescriptor = Os.open(",
            "val admittedIdentity = Os.fstat(admittedDescriptor)",
            "Os.rename(file.absolutePath, displaced.absolutePath)",
            "renameCompleted = true",
            "val renamedAdmittedIdentity = Os.fstat(admittedDescriptor)",
            "val moved = readRegularFileAuthorityIfFile(",
            "sameFileObject(admittedIdentity, renamedAdmittedIdentity)",
            "catch (failure: Throwable)",
            "val live = runCatching",
            "retained == null || live != null",
            "val restoredIdentity = createRegularFileNoClobber(",
            "val retainedAfterRestore = readRegularFileAuthorityIfFile(",
            "The live path again contains the exact bytes moved aside",
        ],
        "capture, FUSE rename authority, no-clobber recovery, and rejection order",
    )
    failed_publish_start = plugin.find("private fun publishRegularFileNoClobber(")
    failed_publish_end = plugin.find(
        "private fun publishRegularFileAbsenceNoClobber(", failed_publish_start
    )
    if failed_publish_start < 0 or failed_publish_end < 0:
        fail("could not isolate failed native annotation publication recovery")
    failed_publish = plugin[failed_publish_start:failed_publish_end]
    require(
        failed_publish,
        [
            "val recoveryErrors = mutableListOf<Throwable>()",
            "var recoveredIdentity: StructStat? = null",
            "livePathAbsentBeforeRecovery",
            "recoveredIdentity = createRegularFileNoClobber(",
            "val desiredStateRestored = if (expected == null)",
            "requireDisplacedRegularFileIntact(",
            "if (!desiredStateRestored || !displacedEvidenceIntact)",
            "throw NativeMarkRecoveryRequiredException(",
        ],
        "failed publication exact-state recovery fence",
    )
    journal_retire_start = plugin.find("private fun retireNativeMarkRecoveryJournal(")
    journal_retire_end = plugin.find(
        "private fun nativeAnnotationBackupSourceFilesMatch(",
        journal_retire_start,
    )
    if journal_retire_start < 0 or journal_retire_end < 0:
        fail("could not isolate native mark recovery journal retirement")
    ordered(
        plugin[journal_retire_start:journal_retire_end],
        [
            "val inspection = inspectNativeMarkRecoveryFence(pdfFile, expected.marker)",
            "samePersistedAuthority(expected.authority, current.authority)",
            "require(liveNativeAnnotationMatchesRecoveryJournal(expected))",
            "startDocumentAuthorityProviderForRecovery(configurationGeneration)",
            "requireDocumentAuthorityAck(",
            '"recovery",',
            "publishNativeSpreadOffMarkerLocked(",
            "current.authority,\n            onCommitProven,",
        ],
        "fresh journal and live-mark proof precede irreversible recovery commit",
    )
    require(
        plugin[journal_retire_start:journal_retire_end],
        [
            "private fun startDocumentAuthorityProviderForRecovery(",
            "Intent.FLAG_ACTIVITY_NEW_TASK",
            "DOCUMENT_PROVIDER_START_TIMEOUT_MS",
            '"recovery-authority-provider"',
            "DOCUMENT_PROVIDER_SETTLE_MS",
            "document_provider_start_timeout",
        ],
        "recovery-fenced Document authority-provider bootstrap",
    )
    restore_worker_start = plugin.find("private fun scheduleAnnotationRestore(")
    restore_helpers_start = plugin.find(
        "private fun requireBackupDocumentIdentity(",
        restore_worker_start,
    )
    if restore_worker_start < 0 or restore_helpers_start < 0:
        fail("could not isolate companion annotation restore worker")
    restore_worker = plugin[restore_worker_start:restore_helpers_start]
    ordered(
        restore_worker,
        [
            "publishNativeMarkRecoveryJournal(",
            "publication = publishNativeAnnotationRestore(",
            '"after-mark-verification"',
            '"before-recovery-journal-retirement"',
            "retireNativeMarkRecoveryJournal(",
            "recoveryCommitProven = true",
            "if (!recoveryCommitProven)",
            "restorePrePublicationMark(value)",
            "throw restoreError",
            "removeNativeAnnotationBackupFiles(",
            "val committed = persistenceError == null",
            "val recoveryRequired = nativeMarkRecoveryRequiredPending() ||\n"
            "                nativeMarkRecoveryRequired(persistenceError)",
            "if (recoveryRequired)",
            "RTL_READER_NATIVE_BACKUP_RESTORE_RECOVERY_REQUIRED_NOT_REOPENED",
            "} else {\n                try {\n                    if (committed)",
            "reactApplicationContext.startActivity(Intent().apply",
        ],
        "persistence rollback and recovery-required fence precede relaunch",
    )
    require(
        restore_worker,
        [
            "registerNativeMarkRecoveryRequired(nativeSpreadMarker(pdfFile))",
            "nativeMarkRecoveryRequiredPending()",
            "val journalInspection = inspectNativeMarkRecoveryFence(pdfFile, marker)",
            "                    try {\n"
            "                        withNativeSpreadConfigurationAuthority(\n"
            "                            configurationGeneration,\n"
            "                        ) {\n"
            "                            publication = publishNativeAnnotationRestore(",
        ],
        "durable and process-global recovery-required restart fencing",
    )
    handoff_start = plugin.find("fun handoffLastSavedPage(promise: Promise)")
    handoff_end = plugin.find("private fun findMatchingConfig(", handoff_start)
    restart_start = plugin.find("private fun scheduleDocumentRestart(pdfFile: File)")
    restart_end = plugin.find("private fun scheduleAnnotationRestore(", restart_start)
    if min(handoff_start, handoff_end, restart_start, restart_end) < 0:
        fail("could not isolate native-reader handoff and restart gates")
    require(
        plugin[handoff_start:handoff_end],
        [
            "if (nativeMarkRecoveryRequiredPending() || durableRecovery ||\n"
            "            annotationRecoveryPending.get() ||",
            "inspectNativeMarkRecoveryFence(pdfFile).blocking",
            '"native_mark_recovery_required"',
        ],
        "handoff recovery-required gate",
    )
    require(
        plugin[restart_start:restart_end],
        [
            "synchronized(nativeSpreadConfigurationLock)",
            "nativeMarkRecoveryRequiredPending()",
            "inspectNativeMarkRecoveryFence(pdfFile).blocking",
            "RTL_READER_HANDOFF_RESTART_BLOCKED reason=native_mark_recovery_required",
            "reactApplicationContext.startActivity(intent)",
        ],
        "queued restart recovery-required gate",
    )
    if plugin[restart_start:restart_end].count(
        "inspectNativeMarkRecoveryFence(pdfFile).blocking"
    ) != 2:
        fail("queued restart does not rescan durable recovery before both process actions")
    rollback_start = plugin.find("private fun restorePrePublicationMark(")
    rollback_end = plugin.find("private fun requireDisplacedRegularFileIntact(", rollback_start)
    if rollback_start < 0 or rollback_end < 0:
        fail("could not isolate native annotation rollback recovery fence")
    require(
        plugin[rollback_start:rollback_end],
        [
            "var rejected: DisplacedRegularFile? = null",
            "try {",
            "rejected = preserveRegularDestinationNoClobber(",
            "val restoredIdentity = createRegularFileNoClobber(",
            "samePersistedFileVersion(restoredIdentity, restored.identity)",
            "requireDisplacedRegularFileIntact(",
            "throw NativeMarkRecoveryRequiredException(",
            "Pre-publication annotation state is not proven restored;",
        ],
        "rollback exact-state and retained-evidence fence",
    )
    committed_scope = restore_worker[
        restore_worker.find("withNativeSpreadPublicationLock("):
        restore_worker.find("val committed = persistenceError == null")
    ]
    if "startActivity(" in committed_scope:
        fail("fallible native-reader relaunch remains inside persistence rollback scope")
    require(
        gate,
        [
            "candidate marker lookup is forbidden on the main thread",
            "NativeReaderV2AuthorityJournal.inspect(journal.bytes);",
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
            (
                "firmware.releaseComponentIdentityLease(\n"
                "                        releasedIdentityLease\n"
                "                    );"
            ),
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
            (
                "firmware.releaseComponentIdentityLease(\n"
                "                        releasedIdentityLease\n"
                "                    );"
            ),
            "evidence.close();",
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
    marker_authority_start = plugin.find(
        "private fun readRegularFileAuthorityIfFile("
    )
    fingerprint_authority_start = plugin.find(
        "private fun readRegularFileFingerprintIfFile("
    )
    fingerprint_authority_end = plugin.find(
        "private fun sameFileObject(", fingerprint_authority_start
    )
    if min(
        marker_authority_start,
        fingerprint_authority_start,
        fingerprint_authority_end,
    ) < 0:
        fail("could not isolate persisted-file descriptor authorities")
    require(
        plugin[marker_authority_start:fingerprint_authority_start],
        [
            "OsConstants.O_NOFOLLOW",
            "pathBefore.st_nlink == 1L",
            "samePersistedFileVersion(opened, pathAfter)",
        ],
        "single-link descriptor-backed companion marker reads",
    )
    require(
        plugin[fingerprint_authority_start:fingerprint_authority_end],
        [
            "OsConstants.O_NOFOLLOW",
            "pathBefore.st_nlink == 1L",
            "samePersistedFileVersion(opened, pathAfter)",
            "digest.update(buffer, 0, count)",
            "length == opened.st_size",
        ],
        "single-link descriptor-backed backup fingerprint reads",
    )
    fingerprint_match_start = plugin.find("private fun samePersistedFingerprint(")
    fingerprint_match_end = plugin.find(
        "private fun writePropertiesAtomicallyCas(", fingerprint_match_start
    )
    if fingerprint_match_start < 0 or fingerprint_match_end < 0:
        fail("could not isolate persisted-file fingerprint equality")
    require(
        plugin[fingerprint_match_start:fingerprint_match_end],
        [
            "samePersistedFileVersion(expected.identity, actual.identity)",
            "expected.length == actual.length",
            "expected.sha256 == actual.sha256",
        ],
        "backup fingerprint exact identity/content equality",
    )
    backup_read_start = plugin.find("private fun readNativeAnnotationBackup(")
    backup_read_end = plugin.find(
        "private fun sameNativeAnnotationBackup(", backup_read_start
    )
    if backup_read_start < 0 or backup_read_end < 0:
        fail("could not isolate native annotation backup admission")
    require(
        plugin[backup_read_start:backup_read_end],
        [
            "val snapshotAuthority = readRegularFileFingerprintIfFile(\n"
            "                snapshot,",
            "snapshotAuthority.length != markLength",
            "snapshotAuthority.sha256 != markHash",
        ],
        "streaming backup snapshot admission",
    )
    require(
        plugin,
        ["private fun readPersistedBytesIfFile(file: File): ByteArray?"],
        "descriptor-backed companion marker byte routing",
    )
    if "marker.readBytes()" in plugin:
        fail("companion marker recovery bypasses descriptor-backed authority")

    require(
        workflow,
        [
            "python3 scripts/check_native_reader_v2_invariants.py .",
            "python3 scripts/test_build_provenance.py .",
            "out/build-provenance/SupernoteRtlReader.bundle",
            "out/build-provenance/app.npk",
            "supernote-rtl-reader-v0.4.22-native-reader-v2",
            "native-spread-upgrade-artifact:",
            "github.event_name == 'workflow_dispatch'",
            "github.actor == github.repository_owner",
            "secrets.NATIVE_SPREAD_KEYSTORE_B64",
            "-AlignedOnly",
            "supernote-native-reader-v2-release-input-v1",
            "native-reader-v2-release-input-${{ github.sha }}",
            "environment: virtual-spread-release",
            "NATIVE_SPREAD_KEYSTORE_B64 must exist only as an environment",
            "never as a repository-scoped secret",
            "Verify aligned APK provenance without signing credentials",
            "Sign, verify, and remove protected Native Reader signing key",
            "supernote-native-reader-v2-v0.0.140",
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
            "def verify_application_xmltree(",
            "def verify_signer_output(",
            'ANDROID_BUILD_TOOLS_VERSION = "35.0.0"',
            'required_schemes != {"2", "3"}',
            'find_android_tool("aapt")',
            'find_android_tool("apksigner")',
            "EXPECTED_NATIVE_APK_SIGNER_SHA256",
            "EXPECTED_NATIVE_CLASS_DESCRIPTORS",
            "defined_classes.update(verify_dex(",
            "JavaScript bundle does not match the independently named build output",
            "embedded app.npk does not match the independently named build output",
            "verify_apk_tools(Path(temporary_name))",
        ],
        "embedded APK structural and signature verification",
    )
    v2_invariant_job = workflow.split("  invariant-suites:", 1)[1].split(
        "  native-spread-build:", 1
    )[0]
    if "check_native_spread_invariants.py ." not in v2_invariant_job:
        fail(
            "Native Reader v2 CI does not run the cross-layer handshake, "
            "lifecycle, packaging, and trace safety invariants"
        )
    if "ndk;" in workflow or "-AndroidNdk" in workflow:
        fail("release CI still provisions the retired legacy native hook toolchain")
    stable_job = workflow[workflow.find("native-spread-upgrade-artifact:"):]
    stable_job = stable_job.split("\n  virtual-spread-tests:", 1)[0]
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
    unsigned_job = workflow[workflow.find("  native-spread-build:") :]
    unsigned_job = unsigned_job.split("\n  native-spread-upgrade-artifact:", 1)[0]
    if "secrets." in unsigned_job or "NATIVE_SPREAD_KEYSTORE_B64" in unsigned_job:
        fail("checked-out Native Reader build receives the stable signing credential")
    if "NATIVE_SPREAD_KEYSTORE_B64" in workflow.replace(stable_job, ""):
        fail("Native Reader signing credential is referenced outside its protected job")
    if "actions/checkout@" in stable_job:
        fail("secret-bearing Native Reader signing job checks out repository code")
    for forbidden in (
        "native-spread-module",
        "scripts/",
        "scripts\\",
        ".ps1",
        ".py",
        "GITHUB_ENV",
    ):
        if forbidden in stable_job:
            fail(
                "secret-bearing Native Reader signing job may execute repository "
                f"content: {forbidden!r}"
            )
    require(
        stable_job,
        [
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            "$env:NATIVE_SPREAD_KEYSTORE_B64 = $null",
            "Remove-Item -LiteralPath $keystore -Force",
            "release-output/SupernoteNativeSpreadProbe-v0.0.140.apk",
            "$expectedSignedLength = 287259L",
            "af6b0b88f0622504471660d5db877ba9472860b67e845b5560caac3e9374e017",
            "Signed APK length differs from the reviewed upgrade identity",
            "Signed APK SHA-256 differs from the reviewed upgrade identity.",
        ],
        "checkout-free protected Native Reader signing boundary",
    )
    ordered(
        stable_job,
        [
            "apksigner verification failed",
            "$expectedSignedLength = 287259L",
            "Signed APK SHA-256 differs from the reviewed upgrade identity.",
            "} finally {",
            "Upload upgrade-compatible Native Reader APK",
        ],
        "signature then exact signed identity then cleanup then publication",
    )

    print("Native Reader v2 invariants: PASS")


if __name__ == "__main__":
    main()
