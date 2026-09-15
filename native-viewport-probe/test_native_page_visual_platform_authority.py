"""Offline-only tests for the complete visual platform authority.

All evidence is literal in-memory text.  No device, network, process, ambient
ADB, filesystem discovery, or user-document operation is available here.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import unittest
import uuid

import native_page_host_authority as host
import native_page_visual_platform_authority as platform
import native_page_visual_session_harness as harness


SESSION = "12345678-1234-4234-8234-123456789abc"
BOOT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
DISPLAY = 5
HOST_TASK = 90
HOST_TOKEN = "abc1234"
FOREIGN_TASK = 77
FOREIGN_TOKEN = "11846f4"
HOST_PROCESS = host.ProcessIdentity(900, 12345, 10123, host.HOST_PACKAGE)
STOCK_PROCESS = host.ProcessIdentity(700, 54321, 1000, host.FOREIGN_PACKAGE)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def replace_last(raw: bytes, old: bytes, new: bytes) -> bytes:
    position = raw.rfind(old)
    if position < 0:
        raise AssertionError("literal mutation target is absent")
    return raw[:position] + new + raw[position + len(old):]


def task_block(*, task_id: int, task_token: str, activity_token: str,
               raw_component: str, package: str, pid: int, uid: int,
               base_dir: str, configuration: str) -> str:
    return f"""  Stack #{task_id}: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{{activity_token} u0 {raw_component} t{task_id}}}
    * Task{{{task_token} #{task_id} visible=true type=standard mode=fullscreen translucent=false A={uid}:{package} U=0 StackId={task_id} sz=1}}
      taskId={task_id} stackId={task_id}
      * Hist #0: ActivityRecord{{{activity_token} u0 {raw_component} t{task_id}}}
          packageName={package} processName={package}
          app=ProcessRecord{{2083011 {pid}:{package}/{uid}}}
          mActivityComponent={raw_component}
          baseDir={base_dir}
          CurrentConfiguration={configuration}
          state=RESUMED stopped=false delayedResume=false finishing=false
          mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
          nowVisible=true lastVisibleTime=-1s
"""


def activity_wire(*, display: int | None, foreign: bool,
                  host_present: bool = True, preamble: bool = True,
                  empty_stack: bool = False,
                  physical: tuple[int, int] = (1404, 1872)) -> bytes:
    host_component = host.HOST_COMPONENT
    host_config = (
        "{1.0 en_US 300dpi port winConfig={ mBounds=Rect(0, 0 - "
        + str(physical[0]) + ", " + str(physical[1]) +
        ") mRotation=ROTATION_0}}"
    )
    stock_config = (
        "{1.0 en_US 300dpi port winConfig={ mBounds=Rect(0, 0 - 1404, 1872) "
        "mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0} s.186}"
    )
    lines = ["ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)"]
    if preamble:
        lines.append("Display areas in focus order:")
    lines.append("Display #0 (activities from top to bottom):")
    if host_present:
        lines.extend(task_block(
            task_id=HOST_TASK, task_token="def1234",
            activity_token=HOST_TOKEN, raw_component=host_component,
            package=host.HOST_PACKAGE, pid=HOST_PROCESS.pid,
            uid=HOST_PROCESS.uid, base_dir="/data/app/native-page-host/base.apk",
            configuration=host_config,
        ).rstrip("\n").split("\n"))
    if display is not None:
        lines.append(f"Display #{display} (activities from top to bottom):")
        if foreign:
            lines.extend(task_block(
                task_id=FOREIGN_TASK, task_token="66d8263",
                activity_token=FOREIGN_TOKEN,
                raw_component="com.supernote.document/.document.DocumentActivity",
                package=host.FOREIGN_PACKAGE, pid=STOCK_PROCESS.pid,
                uid=STOCK_PROCESS.uid,
                base_dir="/system_ext/app/SupernoteDocument/SupernoteDocument.apk",
                configuration=stock_config,
            ).rstrip("\n").split("\n"))
        elif empty_stack:
            lines.extend((
                f"  Stack #{display}: type=standard mode=fullscreen",
                "    mResumedActivity: null",
            ))
    return ("\n".join(lines) + "\n").encode("utf-8")


def window_wire(*, display: int | None, foreign: bool,
                host_present: bool = True,
                physical: tuple[int, int] = (1404, 1872)) -> bytes:
    focus: list[str] = []
    windows: list[tuple[str, str, str, str, str]] = []
    if host_present:
        focus.append(f"FocusedWindow displayId=0 activityToken={HOST_TOKEN}")
        windows.append((
            host.HOST_COMPONENT,
            f"  owner pid={HOST_PROCESS.pid} uid={HOST_PROCESS.uid} package={host.HOST_PACKAGE}",
            f"  taskId={HOST_TASK} activityToken={HOST_TOKEN} displayId=0",
            f"  frame=[0,0][{physical[0]},{physical[1]}] surfaceFrame=[0,0][{physical[0]},{physical[1]}] buffer=1404x1872",
            "  visible=true focused=true",
        ))
    if foreign:
        assert display is not None
        focus.append(f"FocusedWindow displayId={display} activityToken={FOREIGN_TOKEN}")
        windows.append((
            "com.supernote.document/.document.DocumentActivity",
            f"  owner pid={STOCK_PROCESS.pid} uid={STOCK_PROCESS.uid} package={host.FOREIGN_PACKAGE}",
            f"  taskId={FOREIGN_TASK} activityToken={FOREIGN_TOKEN} displayId={display}",
            "  frame=[0,0][1404,1872] surfaceFrame=[0,0][1404,1872] buffer=1404x1872",
            "  visible=true focused=true",
        ))
    lines = ["WINDOW MANAGER WINDOWS (dumpsys window windows)", *focus]
    for index, (component, owner, identity, geometry, state) in enumerate(windows):
        lines.extend((f"Window #{index} Window{{aa{index:05x} u0 {component}}}:",
                      owner, identity, geometry, state))
    lines.append(f"END windowCount={len(windows)} focusedCount={len(focus)}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def display_wire(*, display: int | None,
                 physical: tuple[int, int] = (1404, 1872)) -> bytes:
    lines = [
        "DISPLAY MANAGER DISPLAYS (dumpsys display)",
        "Display #0:",
        "  uniqueId=local:0",
        f"  name={platform.PHYSICAL_DISPLAY_NAME}",
        "  owner=none",
        f"  metrics={physical[0]}x{physical[1]} density=300",
        "  flags=none",
        "  state=ON",
    ]
    if display is not None:
        lines.extend((
            f"Display #{display}:",
            f"  uniqueId=virtual:{display}",
            f"  name=NativePageVisualOnly-{SESSION}-1",
            f"  ownerPid={HOST_PROCESS.pid} ownerUid={HOST_PROCESS.uid} ownerPackage={host.HOST_PACKAGE}",
            "  metrics=1404x1872 density=300",
            "  flags=DESTROY_CONTENT_ON_REMOVAL,OWN_CONTENT_ONLY,PUBLIC",
            "  state=ON",
        ))
    lines.append(f"END displayCount={1 + int(display is not None)}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def foreign_for(activity: bytes, process: host.ProcessIdentity = STOCK_PROCESS) -> host.ForeignIdentity:
    task = platform.android.parse_document_task_authority(
        activity, expected_pid=process.pid, require_live=True)
    return host.ForeignIdentity(
        process, FOREIGN_TASK, FOREIGN_TOKEN,
        platform.android.stable_authority_sha256(task), host.FOREIGN_COMPONENT)


def process_wire(*, activity: bytes, window: bytes, display_raw: bytes,
                 label: str, captured_ns: int, capture_id: str,
                 display: int | None, foreign: host.ForeignIdentity | None,
                 started_ns: int | None = None,
                 finished_ns: int | None = None,
                 processes: tuple[host.ProcessIdentity, ...] =
                 (STOCK_PROCESS, HOST_PROCESS), serial: str = harness.AUTHORIZED_SERIAL,
                 boot: str = BOOT) -> bytes:
    foreign_sha = "none" if foreign is None else sha(canonical(foreign.wire()))
    display_text = "none" if display is None else str(display)
    started_ns = captured_ns - 4 if started_ns is None else started_ns
    finished_ns = captured_ns + 4 if finished_ns is None else finished_ns
    lines = [
        "NATIVE PAGE PROCESS INVENTORY (visual-platform-v1)",
        f"capture authority={platform.BACKEND_CAPTURE_AUTHORITY} captureId={capture_id} label={label} serial={serial} bootId={boot} startedNs={started_ns} capturedNs={captured_ns} finishedNs={finished_ns}",
        f"scope displayId={display_text} foreignSha256={foreign_sha}",
        f"bind activityBytes={len(activity)} activitySha256={sha(activity)} windowBytes={len(window)} windowSha256={sha(window)} displayBytes={len(display_raw)} displaySha256={sha(display_raw)}",
        "policy complete=true readOnly=true mutationCount=0 userDocumentSelectionCount=0 "
        "scopePackages=com.supernote.document,com.techrebbe.supernote.nativepagehost",
        f"package name={host.PINNED_PACKAGE.package} "
        f"installedApkSha256={host.PINNED_PACKAGE.apk_sha256} "
        f"reviewedUnsignedApkSha256={host.PINNED_PACKAGE.reviewed_unsigned_apk_sha256} "
        f"dexSha256={host.PINNED_PACKAGE.dex_sha256} "
        f"signerCertSha256={host.PINNED_PACKAGE.signer_cert_sha256} "
        f"versionCode={host.PINNED_PACKAGE.version_code} "
        f"versionName={host.PINNED_PACKAGE.version_name}",
    ]
    for item in processes:
        lines.append(
            f"process pid={item.pid} startTicks={item.start_ticks} uid={item.uid} package={item.package}")
    lines.append(f"END processCount={len(processes)} packageCount=1")
    return ("\n".join(lines) + "\n").encode("ascii")


def make_bundle(*, label: str = "postlaunch-preack", captured_ns: int = 1005,
                capture_id: str = "00000000-0000-4000-8000-000000000001",
                display: int | None = DISPLAY, foreign_live: bool = True,
                host_present: bool = True, preamble: bool = True,
                empty_stack: bool = False,
                physical: tuple[int, int] = (1404, 1872),
                activity_mutation=None, window_mutation=None,
                display_mutation=None,
                processes: tuple[host.ProcessIdentity, ...] =
                (STOCK_PROCESS, HOST_PROCESS), serial: str = harness.AUTHORIZED_SERIAL,
                boot: str = BOOT):
    activity = activity_wire(display=display, foreign=foreign_live,
                             host_present=host_present, preamble=preamble,
                             empty_stack=empty_stack,
                             physical=physical)
    # Bind the expected launch identity to the valid pre-mutation authority.
    # Adversarial mutations below deliberately make the fresh ActivityManager
    # wire malformed or semantically different; deriving the expected identity
    # from that wire would either fail fixture construction or bless the
    # mutation that the verifier is meant to reject.
    foreign = foreign_for(activity) if foreign_live else None
    window = window_wire(display=display, foreign=foreign_live,
                         host_present=host_present, physical=physical)
    display_raw = display_wire(display=display, physical=physical)
    if activity_mutation is not None:
        activity = activity_mutation(activity)
    if window_mutation is not None:
        window = window_mutation(window)
    if display_mutation is not None:
        display_raw = display_mutation(display_raw)
    process = process_wire(
        activity=activity, window=window, display_raw=display_raw,
        label=label, captured_ns=captured_ns, capture_id=capture_id,
        display=display, foreign=foreign, processes=processes,
        serial=serial, boot=boot,
    )
    return platform.RawPlatformBundle(activity, window, process, display_raw), foreign


class Backend:
    def __init__(self, bundles, *, clock: int = 1000, after=None):
        self.bundles = list(bundles)
        self.clock = clock
        self.after = list(after or [])
        self.requests = []
        self.bad = False
        self.drift_after_capture = False
        self.touched = 0
        self.raw = canonical({
            "authority": "test-retained-complete-private-adb-v1",
            "serial": harness.AUTHORIZED_SERIAL,
            "bootId": BOOT,
            "readOnly": True,
        })
        self.current_identity = platform.BackendIdentity(
            "test-retained-complete-private-adb-v1", sha(self.raw),
            harness.AUTHORIZED_SERIAL, BOOT, 1, True, True, False,
        )

    def verify(self):
        self.touched += 1
        if self.bad:
            raise RuntimeError("backend drift")

    def canonical_bytes(self):
        self.touched += 1
        return self.raw

    def identity(self):
        self.touched += 1
        return self.current_identity

    def now_ns(self):
        self.touched += 1
        return self.clock

    def capture_complete(self, request, deadline_ns):
        self.touched += 1
        self.requests.append((request, deadline_ns))
        if not self.bundles:
            raise RuntimeError("no fixture")
        bundle = self.bundles.pop(0)
        self.clock = self.after.pop(0) if self.after else self.clock + 10
        if self.drift_after_capture:
            self.current_identity = replace(self.current_identity, generation=2)
        return bundle


def make_authority(backend: Backend) -> platform.VisualPlatformAuthority:
    return platform.VisualPlatformAuthority(
        backend, host_process=HOST_PROCESS, host_task_id=HOST_TASK,
        host_activity_token=HOST_TOKEN, session_id=SESSION,
    )


def capture_once(bundle, foreign, display, *, clock=1000, after=1010,
                 label="postlaunch-preack"):
    backend = Backend([bundle], clock=clock, after=[after])
    authority = make_authority(backend)
    return authority.capture(label, foreign, display, clock + 1000)


class VisualPlatformAuthorityTests(unittest.TestCase):
    def test_live_multi_display_preamble_returns_exact_harness_capture(self):
        bundle, foreign = make_bundle()
        value = capture_once(bundle, foreign, DISPLAY)
        self.assertIs(type(value), harness.PlatformCapture)
        self.assertIs(type(value.snapshot), host.Snapshot)
        self.assertEqual(value.captured_ns, 1005)
        self.assertTrue(value.snapshot.complete)
        self.assertEqual(value.snapshot.package, host.PINNED_PACKAGE)
        self.assertEqual(value.snapshot.processes, (STOCK_PROCESS, HOST_PROCESS))
        self.assertEqual([item.display_id for item in value.snapshot.displays], [0, DISPLAY])
        self.assertEqual(
            (value.snapshot.am_sha256, value.snapshot.window_sha256,
             value.snapshot.process_sha256, value.snapshot.display_sha256),
            (sha(bundle.activity_manager_raw), sha(bundle.window_manager_raw),
             sha(bundle.process_inventory_raw), sha(bundle.display_inventory_raw)),
        )

    def test_current_direct_multi_display_header_form_is_also_admitted(self):
        bundle, foreign = make_bundle(preamble=False)
        value = capture_once(bundle, foreign, DISPLAY)
        self.assertEqual(len(value.snapshot.activities), 2)
        stock = next(item for item in value.snapshot.activities
                     if item.process == STOCK_PROCESS)
        self.assertEqual(stock.component, host.FOREIGN_COMPONENT)

    def test_fresh_activity_bytes_may_change_only_with_stable_task_authority(self):
        launch_activity = activity_wire(display=DISPLAY, foreign=True)
        fresh_activity = launch_activity.replace(b" s.186}", b" s.187}", 1)
        self.assertNotEqual(sha(launch_activity), sha(fresh_activity))
        foreign = foreign_for(launch_activity)
        window = window_wire(display=DISPLAY, foreign=True)
        display_raw = display_wire(display=DISPLAY)
        process = process_wire(
            activity=fresh_activity, window=window, display_raw=display_raw,
            label="postlaunch-preack", captured_ns=1005,
            capture_id="00000000-0000-4000-8000-000000000019",
            display=DISPLAY, foreign=foreign,
        )
        bundle = platform.RawPlatformBundle(
            fresh_activity, window, process, display_raw)
        value = capture_once(bundle, foreign, DISPLAY)
        self.assertEqual(value.snapshot.am_sha256, sha(fresh_activity))
        self.assertNotEqual(value.snapshot.am_sha256,
                            foreign.evidence_sha256)

    def test_prelaunch_foreign_none_keeps_exact_empty_owned_display(self):
        bundle, _ = make_bundle(
            label="prelaunch", foreign_live=False, empty_stack=True,
            captured_ns=1005)
        value = capture_once(bundle, None, DISPLAY, label="prelaunch")
        self.assertEqual(len(value.snapshot.activities), 1)
        self.assertEqual(value.snapshot.activities[0].process, HOST_PROCESS)
        self.assertFalse(any(item.process.package == host.FOREIGN_PACKAGE
                             for item in value.snapshot.windows))
        self.assertEqual(backend_request := value.snapshot.displays[1].owner,
                         HOST_PROCESS)
        self.assertEqual(backend_request.package, host.HOST_PACKAGE)

    def test_final_foreign_none_has_only_physical_display_and_process_liveness(self):
        bundle, _ = make_bundle(
            label="final-clean-inventory", captured_ns=1005,
            display=None, foreign_live=False, host_present=False,
            preamble=False)
        value = capture_once(bundle, None, None,
                             label="final-clean-inventory")
        self.assertEqual(value.snapshot.activities, ())
        self.assertEqual(value.snapshot.windows, ())
        self.assertEqual([item.display_id for item in value.snapshot.displays], [0])
        self.assertIn(STOCK_PROCESS, value.snapshot.processes)

    def test_sequence_pins_process_identity_capture_ids_and_increasing_time(self):
        pre, _ = make_bundle(label="prelaunch", foreign_live=False,
                             captured_ns=1005,
                             capture_id="00000000-0000-4000-8000-000000000001")
        live, foreign = make_bundle(captured_ns=1025,
                                    capture_id="00000000-0000-4000-8000-000000000002")
        final, _ = make_bundle(label="final-clean-inventory", captured_ns=1045,
                               capture_id="00000000-0000-4000-8000-000000000003",
                               display=None, foreign_live=False,
                               host_present=False, preamble=False)
        backend = Backend([pre, live, final], clock=1000,
                          after=[1010, 1030, 1050])
        authority = make_authority(backend)
        authority.capture("prelaunch", None, DISPLAY, 2000)
        authority.capture("postlaunch-preack", foreign, DISPLAY, 2000)
        authority.capture("final-clean-inventory", None, None, 2000)
        self.assertEqual(len(backend.requests), 3)
        self.assertEqual(backend.requests[1][0].foreign_sha256,
                         sha(canonical(foreign.wire())))
        authority.verify()

    def test_adapter_authority_is_stable_and_binds_retained_backend(self):
        bundle, _ = make_bundle(label="prelaunch", foreign_live=False)
        backend = Backend([bundle])
        authority = make_authority(backend)
        first = authority.canonical_bytes()
        second = authority.canonical_bytes()
        self.assertEqual(first, second)
        parsed = json.loads(first)
        self.assertEqual(parsed["authority"], platform.AUTHORITY)
        self.assertEqual(parsed["backendAuthoritySha256"], sha(backend.raw))
        self.assertFalse(parsed["ambientAdbDiscovery"])
        self.assertFalse(parsed["deviceMutation"])
        self.assertFalse(parsed["userDocumentSelection"])

    def test_existing_private_adb_bridge_is_explicitly_blocked_without_touching_object(self):
        class Untouchable:
            def __getattribute__(self, name):
                raise AssertionError("existing backend was touched")
        with self.assertRaisesRegex(platform.PlatformAdmissionBlocked,
                                    platform.PRODUCTION_BACKEND_BLOCKER):
            platform.admit_existing_private_adb(Untouchable())
        status = platform.production_backend_status()
        self.assertFalse(status["admitted"])
        self.assertFalse(status["ambientAdbFallback"])
        self.assertIn("process PID/start-ticks", " ".join(status["missing"]))

    def test_backend_admission_rejects_serial_boot_capability_and_digest_drift(self):
        bundle, _ = make_bundle(label="prelaunch", foreign_live=False)
        changes = (
            {"serial": "OTHER"},
            {"boot_id": "not-a-uuid"},
            {"read_only": False},
            {"complete_capture": False},
            {"ambient_discovery": True},
            {"authority_sha256": "0" * 64},
        )
        for change in changes:
            with self.subTest(change=change):
                backend = Backend([bundle])
                backend.current_identity = replace(backend.current_identity, **change)
                with self.assertRaises(platform.VisualPlatformError):
                    make_authority(backend)

    def test_backend_identity_drift_during_capture_is_rejected_and_seals_adapter(self):
        bundle, foreign = make_bundle()
        backend = Backend([bundle], after=[1010])
        backend.drift_after_capture = True
        authority = make_authority(backend)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "identity/bytes drifted"):
            authority.capture("postlaunch-preack", foreign, DISPLAY, 2000)
        backend.current_identity = replace(backend.current_identity, generation=1)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected, "sealed"):
            authority.verify()

    def test_reentrant_capture_is_rejected_before_a_second_backend_dispatch(self):
        bundle, foreign = make_bundle()

        class ReentrantClockBackend(Backend):
            authority = None
            attempted = False
            reentrant_error = None

            def now_ns(self):
                if self.authority is not None and not self.attempted:
                    self.attempted = True
                    try:
                        self.authority.capture(
                            "postlaunch-preack", foreign, DISPLAY, 2000)
                    except BaseException as error:
                        self.reentrant_error = error
                return super().now_ns()

        backend = ReentrantClockBackend([bundle], after=[1010])
        authority = make_authority(backend)
        backend.authority = authority
        value = authority.capture(
            "postlaunch-preack", foreign, DISPLAY, 2000)
        self.assertIs(type(value), harness.PlatformCapture)
        self.assertEqual(len(backend.requests), 1)
        self.assertIsInstance(backend.reentrant_error,
                              platform.PlatformEvidenceRejected)
        self.assertIn("concurrent or reentrant", str(backend.reentrant_error))

    def test_scope_metadata_rejects_serial_boot_label_display_and_foreign_borrowing(self):
        base, foreign = make_bundle()
        mutations = (
            (b"serial=SN078C10015092", b"serial=OTHER"),
            (BOOT.encode(), b"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            (b"label=postlaunch-preack", b"label=phase-99"),
            (b"displayId=5", b"displayId=6"),
            (sha(canonical(foreign.wire())).encode(), b"0" * 64),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                changed = replace(
                    base,
                    process_inventory_raw=base.process_inventory_raw.replace(old, new, 1),
                )
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(changed, foreign, DISPLAY)

    def test_timestamp_must_be_fresh_inside_backend_bracket(self):
        for captured, clock, after in ((999, 1000, 1010),
                                       (1011, 1000, 1010)):
            with self.subTest(captured=captured):
                bundle, foreign = make_bundle(captured_ns=captured)
                with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                            "stale or future"):
                    capture_once(bundle, foreign, DISPLAY,
                                 clock=clock, after=after)

    def test_replayed_capture_id_and_nonincreasing_timestamp_are_rejected(self):
        capture_id = "00000000-0000-4000-8000-000000000099"
        first, foreign = make_bundle(captured_ns=1005, capture_id=capture_id)
        replay, foreign_replay = make_bundle(captured_ns=1025,
                                              capture_id=capture_id)
        backend = Backend([first, replay], clock=1000, after=[1010, 1030])
        authority = make_authority(backend)
        authority.capture("postlaunch-preack", foreign, DISPLAY, 2000)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "capture ID was replayed"):
            authority.capture("postlaunch-preack", foreign_replay, DISPLAY, 2000)

        first, foreign = make_bundle(captured_ns=1005)
        stale, stale_foreign = make_bundle(
            captured_ns=1005,
            capture_id="00000000-0000-4000-8000-000000000002")
        backend = Backend([first, stale], clock=1000, after=[1010, 1020])
        authority = make_authority(backend)
        authority.capture("postlaunch-preack", foreign, DISPLAY, 2000)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "stale or future"):
            authority.capture("postlaunch-preack", stale_foreign, DISPLAY, 2000)

    def test_relevant_process_start_identity_cannot_drift_between_captures(self):
        first, _ = make_bundle(label="prelaunch", foreign_live=False,
                               captured_ns=1005)
        changed_stock = replace(STOCK_PROCESS, start_ticks=STOCK_PROCESS.start_ticks + 1)
        second, _ = make_bundle(
            label="prelaunch", foreign_live=False, captured_ns=1025,
            capture_id="00000000-0000-4000-8000-000000000002",
            processes=(changed_stock, HOST_PROCESS))
        backend = Backend([first, second], clock=1000, after=[1010, 1030])
        authority = make_authority(backend)
        authority.capture("prelaunch", None, DISPLAY, 2000)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "identity drifted"):
            authority.capture("prelaunch", None, DISPLAY, 2000)

    def test_process_policy_package_counts_order_and_unknown_format_fail_closed(self):
        base, foreign = make_bundle()
        mutations = (
            (b"complete=true", b"complete=false"),
            (host.APK_SHA256.encode(), b"0" * 64),
            (host.REVIEWED_UNSIGNED_APK_SHA256.encode(), b"1" * 64),
            (host.DEX_SHA256.encode(), b"2" * 64),
            (host.SIGNER_CERT_SHA256.encode(), b"3" * 64),
            (b"versionCode=2", b"versionCode=3"),
            (b"versionName=0.0.2-native-page-visual-only",
             b"versionName=0.0.3-native-page-visual-only"),
            (b"END processCount=2", b"END processCount=1"),
            (b"packageCount=1", b"packageCount=2"),
            (b"process pid=700", b"unknown pid=700"),
            (b"process pid=700", b"process pid=9999"),
            (b"scopePackages=com.supernote.document", b"scopePackages=com.attacker"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                changed = replace(
                    base,
                    process_inventory_raw=base.process_inventory_raw.replace(old, new, 1),
                )
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(changed, foreign, DISPLAY)

        reversed_processes, foreign = make_bundle(
            processes=(HOST_PROCESS, STOCK_PROCESS))
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "canonical PID order"):
            capture_once(reversed_processes, foreign, DISPLAY)

    def test_activity_structural_mutations_are_re_signed_then_rejected_by_parser(self):
        mutations = (
            lambda raw: raw[:-1],
            lambda raw: raw.replace(b"Display #5 (activities from top to bottom):",
                                    b"Display #5 (activities from top to bottom): extra", 1),
            lambda raw: raw.replace(b"  Stack #77:", b"  Stack #77 extra:", 1),
            lambda raw: raw.replace(b"    * Task{66d8263", b"     * Task{66d8263", 1),
            lambda raw: raw.replace(b"    * Task{66d8263", b"    * Task{def1234", 1),
            lambda raw: raw.replace(b"          app=ProcessRecord{2083011 700:",
                                    b"          app=ProcessRecord{2083011 701:", 1),
            lambda raw: raw.replace(b"          state=RESUMED", b"          state=PAUSED", 1),
            lambda raw: raw.replace(b"Display areas in focus order:\n",
                                    b"Display areas in focus order:\nDisplay areas in focus order:\n", 1),
            lambda raw: raw + b"Recent tasks:\n",
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                bundle, foreign = make_bundle(activity_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

    def test_window_structural_mutations_are_re_signed_then_rejected_by_parser(self):
        mutations = (
            lambda raw: raw[:-1],
            lambda raw: raw.replace(b"END windowCount=2", b"END windowCount=1", 1),
            lambda raw: raw.replace(b"Window #1 Window{", b" Window #1 Window{", 1),
            lambda raw: raw.replace(b"Window #1 Window{aa00001", b"Window #1 Window{aa00000", 1),
            lambda raw: raw.replace(b"activityToken=11846f4", b"activityToken=deadbee", 1),
            lambda raw: raw.replace(b"owner pid=700", b"owner pid=701", 1),
            lambda raw: raw.replace(b"displayId=5 activityToken=11846f4\n",
                                    b"displayId=5 activityToken=11846f4\n"
                                    b"FocusedWindow displayId=5 activityToken=deadbee\n", 1),
            lambda raw: raw.replace(b"  visible=true focused=true\nEND",
                                    b"  visible=true focused=true\n  unknown=true\nEND", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                bundle, foreign = make_bundle(window_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

    def test_display_structural_mutations_are_re_signed_then_rejected_by_parser(self):
        mutations = (
            lambda raw: raw[:-1],
            lambda raw: raw.replace(b"END displayCount=2", b"END displayCount=1", 1),
            lambda raw: raw.replace(b"Display #5:", b"Display #0:", 1),
            lambda raw: raw.replace(b"flags=DESTROY_CONTENT_ON_REMOVAL,OWN_CONTENT_ONLY,PUBLIC",
                                    b"flags=PUBLIC", 1),
            lambda raw: raw.replace(b"ownerPid=900", b"ownerPid=901", 1),
            lambda raw: raw.replace(b"name=NativePageVisualOnly-", b"name=Borrowed-", 1),
            lambda raw: raw.replace(b"  state=ON\nEND", b"  state=OFF\nEND", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                bundle, foreign = make_bundle(display_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

    def test_display_unique_identity_is_pinned_across_captures(self):
        first, _ = make_bundle(
            label="prelaunch", foreign_live=False, captured_ns=1005,
            capture_id="00000000-0000-4000-8000-000000000021")
        second, _ = make_bundle(
            label="prelaunch", foreign_live=False, captured_ns=1025,
            capture_id="00000000-0000-4000-8000-000000000022",
            display_mutation=lambda raw: raw.replace(
                b"uniqueId=virtual:5", b"uniqueId=virtual:replacement", 1))
        backend = Backend([first, second], clock=1000, after=[1010, 1030])
        authority = make_authority(backend)
        authority.capture("prelaunch", None, DISPLAY, 2000)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "display unique identity drifted"):
            authority.capture("prelaunch", None, DISPLAY, 2000)

    def test_foreign_native_configuration_surface_and_buffer_must_match_display(self):
        activity_mutations = (
            lambda raw: replace_last(raw, b"300dpi", b"600dpi"),
            lambda raw: replace_last(
                raw, b"mBounds=Rect(0, 0 - 1404, 1872)",
                b"mBounds=Rect(0, 0 - 1000, 1000)"),
            lambda raw: replace_last(
                raw, b"mRotation=ROTATION_0", b"mRotation=ROTATION_3"),
            lambda raw: replace_last(
                raw, b"mAppBounds=Rect(0, 0 - 1404, 1872)",
                b"mAppBounds=Rect(200, 300 - 1200, 1500)"),
            lambda raw: replace_last(
                raw, b"300dpi port winConfig=", b"300dpi land winConfig="),
            lambda raw: replace_last(
                raw, b" mAppBounds=Rect(0, 0 - 1404, 1872)", b""),
            lambda raw: replace_last(
                raw, b" mRotation=ROTATION_0}",
                b" mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}"),
            lambda raw: replace_last(
                raw, b"mAppBounds=Rect(0, 0 - 1404, 1872)",
                b"mAppBounds=[0,0][1404,1872]"),
            lambda raw: replace_last(
                raw, b"{1.0 en_US 300dpi port winConfig=",
                b"{1.0 port 300dpi undefined winConfig="),
            lambda raw: replace_last(
                raw,
                b"mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0} s.186}",
                b"mAppBounds=undefined mRotation=ROTATION_0} "
                b"mAppBounds=Rect(0, 0 - 1404, 1872) s.186}"),
            lambda raw: replace_last(
                raw, b"winConfig={ mBounds=",
                b"winConfig={ mBounds=undefined mBounds="),
            lambda raw: replace_last(
                raw, b"mRotation=ROTATION_0} s.186}",
                b"mRotation=undefined} mRotation=ROTATION_0 s.186}"),
            lambda raw: replace_last(
                raw, b"{1.0 en_US 300dpi port winConfig=",
                b"{1.0 300dpi port en_US winConfig="),
            lambda raw: replace_last(
                raw,
                b"mBounds=Rect(0, 0 - 1404, 1872) "
                b"mAppBounds=Rect(0, 0 - 1404, 1872)",
                b"mAppBounds=Rect(0, 0 - 1404, 1872) "
                b"mBounds=Rect(0, 0 - 1404, 1872)"),
            lambda raw: replace_last(
                raw,
                b"mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0",
                b"mRotation=ROTATION_0 "
                b"mAppBounds=Rect(0, 0 - 1404, 1872)"),
            lambda raw: replace_last(
                raw, b"mRotation=ROTATION_0}",
                b"mWindowingMode=freeform mRotation=ROTATION_0}"),
            lambda raw: replace_last(
                raw, b"mRotation=ROTATION_0} s.186}",
                b"mRotation=ROTATION_0} mWindowingMode=freeform s.186}"),
        )
        for index, mutation in enumerate(activity_mutations):
            with self.subTest(kind="activity", index=index):
                bundle, foreign = make_bundle(activity_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

        window_mutations = (
            lambda raw: replace_last(
                raw, b"surfaceFrame=[0,0][1404,1872]",
                b"surfaceFrame=[100,100][1100,1600]"),
            lambda raw: replace_last(
                raw, b"buffer=1404x1872", b"buffer=1000x1500"),
        )
        for index, mutation in enumerate(window_mutations):
            with self.subTest(kind="window", index=index):
                bundle, foreign = make_bundle(window_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

    def test_activity_task_and_stack_presentation_modes_are_exact(self):
        mutations = (
            lambda raw: replace_last(
                raw, b"type=standard mode=fullscreen translucent=false",
                b"type=home mode=freeform translucent=true"),
            lambda raw: replace_last(
                raw, b"Stack #77: type=standard mode=fullscreen",
                b"Stack #77: type=home mode=freeform"),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                bundle, foreign = make_bundle(activity_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

    def test_cross_inventory_task_token_display_and_component_mismatches_fail(self):
        mutations = (
            lambda raw: raw.replace(b"activityToken=11846f4 displayId=5",
                                    b"activityToken=11846f4 displayId=0", 1),
            lambda raw: raw.replace(b"taskId=77 activityToken=11846f4",
                                    b"taskId=78 activityToken=11846f4", 1),
            lambda raw: raw.replace(b"com.supernote.document/.document.DocumentActivity}:",
                                    b"com.supernote.document/.document.OtherActivity}:", 1),
            lambda raw: raw.replace(b"frame=[0,0][1404,1872] surfaceFrame",
                                    b"frame=[0,0][1403,1872] surfaceFrame", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                bundle, foreign = make_bundle(window_mutation=mutation)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(bundle, foreign, DISPLAY)

    def test_foreign_none_cannot_borrow_live_document_task_or_window(self):
        live, foreign = make_bundle()
        process = process_wire(
            activity=live.activity_manager_raw,
            window=live.window_manager_raw,
            display_raw=live.display_inventory_raw,
            label="prelaunch", captured_ns=1005,
            capture_id="00000000-0000-4000-8000-000000000010",
            display=DISPLAY, foreign=None)
        borrowed = replace(live, process_inventory_raw=process)
        self.assertIsNotNone(foreign)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "unexpected DocumentActivity"):
            capture_once(borrowed, None, DISPLAY, label="prelaunch")

    def test_foreign_identity_must_match_stable_task_process_and_display(self):
        bundle, foreign = make_bundle()
        variants = (
            replace(foreign, evidence_sha256="0" * 64),
            replace(foreign, task_id=FOREIGN_TASK + 1),
            replace(foreign, activity_token="deadbee"),
            replace(foreign, process=replace(STOCK_PROCESS, start_ticks=99999)),
        )
        for value in variants:
            with self.subTest(value=value):
                # Rebind only the scope header to the supplied identity so the
                # typed/raw cross-check, not an earlier scope digest, decides.
                rebound = replace(
                    bundle,
                    process_inventory_raw=process_wire(
                        activity=bundle.activity_manager_raw,
                        window=bundle.window_manager_raw,
                        display_raw=bundle.display_inventory_raw,
                        label="postlaunch-preack", captured_ns=1005,
                        capture_id=str(uuid.uuid4()), display=DISPLAY,
                        foreign=value),
                )
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(rebound, value, DISPLAY)

    def test_literal_line_mutation_property_rejects_every_process_structure_line(self):
        bundle, foreign = make_bundle()
        lines = bundle.process_inventory_raw.splitlines(keepends=True)
        for index in range(len(lines)):
            with self.subTest(line=index):
                mutated = list(lines)
                original = mutated[index]
                mutated[index] = b"?" + original[1:]
                changed = replace(bundle,
                                  process_inventory_raw=b"".join(mutated))
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    capture_once(changed, foreign, DISPLAY)

    def test_raw_digest_binding_rejects_unresigned_single_byte_mutation(self):
        bundle, foreign = make_bundle()
        for field in ("activity_manager_raw", "window_manager_raw",
                      "display_inventory_raw"):
            with self.subTest(field=field):
                raw = getattr(bundle, field)
                changed_raw = raw[:-2] + bytes([raw[-2] ^ 1]) + raw[-1:]
                changed = replace(bundle, **{field: changed_raw})
                with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                            "not bound"):
                    capture_once(changed, foreign, DISPLAY)

    def test_crlf_is_accepted_only_when_uniform_and_digest_remains_exact(self):
        bundle, _ = make_bundle(label="prelaunch", foreign_live=False,
                                preamble=False)
        activity = bundle.activity_manager_raw.replace(b"\n", b"\r\n")
        window = bundle.window_manager_raw.replace(b"\n", b"\r\n")
        display_raw = bundle.display_inventory_raw.replace(b"\n", b"\r\n")
        process = process_wire(
            activity=activity, window=window, display_raw=display_raw,
            label="prelaunch", captured_ns=1005,
            capture_id="00000000-0000-4000-8000-000000000011",
            display=DISPLAY, foreign=None).replace(b"\n", b"\r\n")
        crlf = platform.RawPlatformBundle(activity, window, process, display_raw)
        value = capture_once(crlf, None, DISPLAY, label="prelaunch")
        self.assertEqual(value.snapshot.am_sha256, sha(activity))

        mixed = replace(crlf, window_manager_raw=window.replace(b"\r\n", b"\n", 1))
        process_mixed = process_wire(
            activity=mixed.activity_manager_raw, window=mixed.window_manager_raw,
            display_raw=mixed.display_inventory_raw, label="prelaunch",
            captured_ns=1005,
            capture_id="00000000-0000-4000-8000-000000000012",
            display=DISPLAY, foreign=None)
        mixed = replace(mixed, process_inventory_raw=process_mixed)
        with self.assertRaisesRegex(platform.PlatformEvidenceRejected,
                                    "mixed line endings"):
            capture_once(mixed, None, DISPLAY, label="prelaunch")

    def test_bounds_wrong_types_and_invalid_scope_fail_before_backend_dispatch(self):
        bundle, foreign = make_bundle()
        cases = (
            ("bad label!", foreign, DISPLAY, 2000),
            ("postlaunch-preack", foreign, None, 2000),
            ("postlaunch-preack", foreign, 0, 2000),
            ("postlaunch-preack", foreign, DISPLAY, 1000),
            ("postlaunch-preack", foreign, DISPLAY, True),
        )
        for label, selected_foreign, display, deadline in cases:
            with self.subTest(label=label, display=display, deadline=deadline):
                backend = Backend([bundle], clock=1000)
                authority = make_authority(backend)
                before = len(backend.requests)
                with self.assertRaises(platform.PlatformEvidenceRejected):
                    authority.capture(label, selected_foreign, display, deadline)
                self.assertEqual(len(backend.requests), before)


if __name__ == "__main__":
    unittest.main()
