from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import native_page_alpha_runner as alpha
import native_page_android_authority as android
import native_page_host_authority as host
import recover_post_restart_orphan_alpha_run as recovery


class FakeDevice:
    DOCUMENT_PID = 2055
    DOCUMENT_START = 3726
    TASK_ID = 4668
    TASK_TOKEN = "fca4b5d"
    ACTIVITY_TOKEN = "752a246"
    PROCESS_TOKEN = "92d1dc"
    WINDOW_TOKEN = "91f6dfd"
    WINDOW_SESSION = "aabbccd"
    OTHER_PDF = "/storage/emulated/0/Document/Unrelated.pdf"

    def __init__(self) -> None:
        self.history: list[dict[str, object]] = []
        self.files = {
            **recovery.ORIGINALS,
            recovery.PARKING_PDF: recovery.PARKING,
            **recovery.TARGETS,
        }
        self.host_pids: tuple[int, ...] = ()
        self.document_pids: tuple[int, ...] = (self.DOCUMENT_PID,)
        self.document_start = self.DOCUMENT_START
        self.fd_targets = {self.OTHER_PDF}
        self.stale_host_task = False
        self.stale_host_window = False
        self.stale_host_display = False
        self.extra_document_task = False
        self.extra_document_window = False
        self.malformed_activities = False
        self.rotation = ("1", "2")
        self.lose_after: set[str] = set()
        self.physical_name = "Built-in Screen"
        self.physical_unique_id = "local:0"
        self.physical_size = (1404, 1872)
        self.physical_rotation = 0
        self.physical_state = "ON"
        self.physical_type = "INTERNAL"
        self.base_name = "Built-in Screen"
        self.base_display_id = 0
        self.base_size = (1404, 1872)
        self.base_rotation = 0
        self.base_state = "ON"
        self.base_type = "INTERNAL"
        self.base_unique_id = "local:0"
        self.override_name = "Built-in Screen"
        self.override_display_id = 0
        self.override_frames = ((1404, 1872, 0),)
        self.override_states = ("ON",)
        self.override_type = "INTERNAL"
        self.override_unique_id = "local:0"
        self.display_reads = 0
        self.display_mutator = None
        self.power_wakefulness = ("Awake",)
        self.power_display_ready = ("true",)
        self.power_suspend_blocker = ("true",)
        self.power_user_activity = ("0x1",)
        self.power_wake_lock = ("0x0",)
        self.power_reads = 0
        self.power_mutator = None

    def adb_authority(self):
        return {"path": "C:/exact/adb.exe", "size": 123,
                "sha256": "a" * 64, "device": 1, "inode": 2,
                "mtimeNs": 3}

    def environment(self):
        return {
            "hostUid": recovery.launch.HOST_UID,
            "hostApk": "/data/app/exact/base.apk",
            "documentApk": alpha.DOCUMENT_APK,
        }

    def pidof(self, package: str) -> tuple[int, ...]:
        if package == alpha.HOST_PACKAGE:
            return self.host_pids
        if package == alpha.DOCUMENT_PACKAGE:
            return self.document_pids
        raise AssertionError("unexpected package")

    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity:
        if pid != self.DOCUMENT_PID or package != alpha.DOCUMENT_PACKAGE:
            raise AssertionError("unexpected process identity request")
        return host.ProcessIdentity(
            pid, self.document_start, recovery.launch.DOCUMENT_UID, package)

    def process_fd_links(self, pid: int) -> str:
        if pid != self.DOCUMENT_PID:
            raise AssertionError("unexpected descriptor request")
        return "".join(
            "lr-x------ 1 root root 64 2026-09-22 09:00 " +
            str(number) + " -> " + path + "\n"
            for number, path in enumerate(sorted(self.fd_targets), 40))

    def stat_file(self, path: str, *, absent_ok: bool = False):
        value = self.files.get(path)
        if value is None and not absent_ok:
            raise AssertionError("missing fake file: " + path)
        return value

    def rotation_settings(self) -> tuple[str, str]:
        return self.rotation

    def activities(self) -> bytes:
        if self.malformed_activities:
            return b"ACTIVITY MANAGER ACTIVITIES malformed\n"
        if not self.document_pids:
            stale = ("  stale=" + alpha.HOST_PACKAGE + "\n"
                     if self.stale_host_task else "")
            return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
{stale}ActivityStackSupervisor state:
  topDisplayFocusedStack=null
  mLastOrientationSource=DefaultTaskDisplayArea@1234
  deepestLastOrientationSource=DefaultTaskDisplayArea@1234
  Display: mDisplayId=0 stacks=0
""".encode("utf-8")
        package = alpha.DOCUMENT_PACKAGE
        component = android.SHORT_COMPONENT
        task = self.TASK_ID
        extra = ""
        if self.extra_document_task:
            extra = f"""  Stack #4777: type=standard mode=fullscreen
    * Task{{deadbee #4777 visible=false type=standard mode=fullscreen translucent=false A=1000:{package} U=0 StackId=4777 sz=1}}
      taskId=4777 stackId=4777
      * Hist #0: ActivityRecord{{deadbad u0 {component} t4777}}
"""
        stale = ("  stale=" + alpha.HOST_PACKAGE + "\n"
                 if self.stale_host_task else "")
        return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #{task}: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{{self.ACTIVITY_TOKEN} u0 {component} t{task}}}
    * Task{{{self.TASK_TOKEN} #{task} visible=true type=standard mode=fullscreen translucent=false A=1000:{package} U=0 StackId={task} sz=1}}
      taskId={task} stackId={task}
      intent={{act=android.intent.action.VIEW
        dat=file://{self.OTHER_PDF} typ=application/pdf
        cmp={component}}}
      * Hist #0: ActivityRecord{{{self.ACTIVITY_TOKEN} u0 {component} t{task}}}
          packageName={package} processName={package}
          app=ProcessRecord{{{self.PROCESS_TOKEN} {self.DOCUMENT_PID}:{package}/1000}}
          mActivityComponent={component}
          baseDir={alpha.DOCUMENT_APK}
          CurrentConfiguration={{1.0 en_US 300dpi port winConfig={{ mBounds=Rect(0, 0 - 1404, 1872) mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}} s.186}}
          state=RESUMED stopped=false delayedResume=false finishing=false
          mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
          nowVisible=true lastVisibleTime=-1s
{extra}{stale}ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{{self.TASK_TOKEN} #{task} visible=true A=1000:{package} sz=1}}
  mLastOrientationSource=ActivityRecord{{{self.ACTIVITY_TOKEN} u0 {component} t{task}}}
  deepestLastOrientationSource=ActivityRecord{{{self.ACTIVITY_TOKEN} u0 {component} t{task}}}
  Display: mDisplayId=0 stacks={2 if self.extra_document_task else 1}
""".encode("utf-8")

    def windows(self) -> bytes:
        if not self.document_pids:
            stale = ("  stale=" + alpha.HOST_PACKAGE + "\n"
                     if self.stale_host_window else "")
            return ("WINDOW MANAGER WINDOWS (dumpsys window windows)\n" +
                    stale).encode("utf-8")
        package = alpha.DOCUMENT_PACKAGE
        record = (f"ActivityRecord{{{self.ACTIVITY_TOKEN} u0 "
                  f"{android.SHORT_COMPONENT} t{self.TASK_ID}}}")
        extra = ""
        if self.extra_document_window:
            extra = (f"  Window #2 Window{{deadbeef u0 "
                     f"{package}/.OtherActivity}}:\n"
                     "    mDisplayId=0 rootTaskId=4777\n")
        stale = ("  stale=" + alpha.HOST_PACKAGE + "\n"
                 if self.stale_host_window else "")
        return f"""WINDOW MANAGER WINDOWS (dumpsys window windows)
  Window #1 Window{{{self.WINDOW_TOKEN} u0 {android.FULL_COMPONENT}}}:
    mDisplayId=0 rootTaskId={self.TASK_ID} mSession=Session{{{self.WINDOW_SESSION} {self.DOCUMENT_PID}:1000}} mClient=android.os.BinderProxy@1
    mOwnerUid=1000 showForAllUsers=false package={package} appop=NONE
    mActivityRecord={record}
{extra}{stale}""".encode("utf-8")

    def displays(self) -> bytes:
        index = self.display_reads
        self.display_reads += 1
        frame = self.override_frames[min(index, len(self.override_frames) - 1)]
        override_state = self.override_states[
            min(index, len(self.override_states) - 1)]
        stale = ""
        size = 1
        if self.stale_host_display:
            size = 2
            stale = f"""  Display 2:
    mDisplayId=2
    name={recovery.DISPLAY_NAME}
"""
        wire = f"""DISPLAY MANAGER (dumpsys display)
Display Devices: size=1
  DisplayDeviceInfo{{"{self.physical_name}": uniqueId="{self.physical_unique_id}", {self.physical_size[0]} x {self.physical_size[1]}, rotation {self.physical_rotation}, type {self.physical_type}, state {self.physical_state}, FLAG_DEFAULT_DISPLAY}}
Logical Displays: size={size}
  Display 0:
    mDisplayId=0
    mBaseDisplayInfo=DisplayInfo{{"{self.base_name}", displayId {self.base_display_id}, real {self.base_size[0]} x {self.base_size[1]}, rotation {self.base_rotation}, state {self.base_state}, type {self.base_type}, uniqueId "{self.base_unique_id}"}}
    mOverrideDisplayInfo=DisplayInfo{{"{self.override_name}", displayId {self.override_display_id}, real {frame[0]} x {frame[1]}, rotation {frame[2]}, state {override_state}, type {self.override_type}, uniqueId "{self.override_unique_id}"}}
{stale}""".encode("ascii")
        if self.display_mutator is not None:
            wire = self.display_mutator(wire, index)
        return wire

    def power(self) -> bytes:
        index = self.power_reads
        self.power_reads += 1
        wakefulness = self.power_wakefulness[
            min(index, len(self.power_wakefulness) - 1)]
        ready = self.power_display_ready[
            min(index, len(self.power_display_ready) - 1)]
        blocker = self.power_suspend_blocker[
            min(index, len(self.power_suspend_blocker) - 1)]
        user_activity = self.power_user_activity[
            min(index, len(self.power_user_activity) - 1)]
        wake_lock = self.power_wake_lock[
            min(index, len(self.power_wake_lock) - 1)]
        wire = f"""POWER MANAGER (dumpsys power)
  mWakefulness={wakefulness}
  mDisplayReady={ready}
  mHoldingDisplaySuspendBlocker={blocker}
  mUserActivitySummary={user_activity}
  mWakeLockSummary={wake_lock}
""".encode("ascii")
        if self.power_mutator is not None:
            wire = self.power_mutator(wire, index)
        return wire

    def _maybe_lost(self, operation: str) -> None:
        if operation in self.lose_after:
            self.lose_after.remove(operation)
            raise recovery.MutationTransportUncertain("lost reply: " + operation)

    def move_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult:
        expected = self.files.pop(source)
        self.files[quarantine] = alpha.DeviceFile(
            quarantine, expected.kind, expected.size, expected.uid,
            expected.gid, expected.inode, expected.device, expected.sha256)
        operation = "recovery_quarantine_" + Path(source).name
        self.history.append({"operation": operation})
        self._maybe_lost(operation)
        return alpha.CommandResult(operation, (), 0, b"", b"")

    def delete_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult:
        self.files.pop(quarantine)
        operation = "recovery_remove_" + Path(quarantine).name
        self.history.append({"operation": operation})
        self._maybe_lost(operation)
        return alpha.CommandResult(operation, (), 0, b"", b"")


class DriftingFileDevice(FakeDevice):
    def __init__(self) -> None:
        super().__init__()
        self.target_pdf_reads = 0

    def stat_file(self, path: str, *, absent_ok: bool = False):
        value = super().stat_file(path, absent_ok=absent_ok)
        if path == recovery.TARGET_PDF:
            self.target_pdf_reads += 1
            if self.target_pdf_reads > 1 and value is not None:
                return replace(value, inode=value.inode + 1)
        return value


class PostRestartOrphanRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).parent.resolve()

    @staticmethod
    def _replace_wire_line(
            raw: bytes, marker: bytes,
            replacement) -> bytes:
        lines = raw.splitlines(keepends=True)
        matches = [index for index, line in enumerate(lines)
                   if marker in line]
        if len(matches) != 1:
            raise AssertionError("test wire marker is absent or ambiguous")
        index = matches[0]
        lines[index] = replacement(lines[index])
        return b"".join(lines)

    def test_fixed_authority_loads_and_pins_separate_helper_dependencies(self) -> None:
        authority = recovery.load_authority(self.root)
        self.assertEqual(recovery.launch.REPORT_SHA256,
                         authority.report_identity["sha256"])
        self.assertEqual(recovery.launch.ACTIVE_SHA256,
                         authority.active_identity["sha256"])
        self.assertEqual(
            recovery.LAUNCH_HELPER_SHA256,
            authority.dependency_identities[
                "recover_launch_identity_alpha_run.py"]["sha256"])
        self.assertIn(Path(recovery.__file__).name,
                      authority.dependency_identities)
        self.assertFalse(authority.ledger_path.exists())
        self.assertFalse(authority.evidence_path.exists())

    def test_unrelated_live_document_produces_stable_read_only_plan(self) -> None:
        authority = recovery.load_authority(self.root)
        device = FakeDevice()
        plan = recovery.build_plan(authority, device)
        self.assertEqual(recovery.PLAN_AUTHORITY, plan["authority"])
        self.assertEqual(2, plan["schemaVersion"])
        self.assertEqual(
            ["quarantine-delete-mark", "quarantine-delete-pdf",
             "archive-active-journal", "publish-evidence"],
            plan["mutationOrder"])
        self.assertEqual(["remove-task", "force-stop-package"],
                         plan["forbiddenMutations"])
        self.assertEqual(
            "live-unrelated", plan["first"]["document"]["mode"])
        self.assertEqual(
            [FakeDevice.OTHER_PDF],
            plan["first"]["document"]["stable"]["fdTargets"])
        self.assertEqual([], device.history)

    def test_override_off_is_admitted_only_under_positive_authority(self) -> None:
        device = FakeDevice()
        device.override_states = ("OFF",)
        observation = recovery.observe(device).wire()
        physical = observation["host"]["physicalDisplay"]
        self.assertEqual("ON", physical["device"]["state"])
        self.assertEqual("ON", physical["base"]["state"])
        self.assertEqual("OFF", physical["override"]["state"])
        self.assertEqual(
            {"wakefulness": "Awake", "displayReady": True,
             "holdingDisplaySuspendBlocker": True,
             "userActivitySummary": "0x1", "wakeLockSummary": "0x0"},
            observation["power"])

    def test_override_off_never_bypasses_other_required_authority(self) -> None:
        cases = (
            ("physical", "physical_state", "OFF"),
            ("base", "base_state", "OFF"),
            ("wakefulness", "power_wakefulness", ("Dreaming",)),
            ("ready", "power_display_ready", ("false",)),
            ("blocker", "power_suspend_blocker", ("false",)),
            ("user-activity", "power_user_activity", ("0x0",)),
            ("wake-lock", "power_wake_lock", ("0x1",)),
        )
        for label, field, value in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                device.override_states = ("OFF",)
                setattr(device, field, value)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.observe(device)

    def test_override_state_flicker_is_advisory_between_observations(self) -> None:
        authority = recovery.load_authority(self.root)
        device = FakeDevice()
        device.override_states = ("ON", "OFF")
        plan = recovery.build_plan(authority, device)
        self.assertEqual(
            "ON", plan["first"]["host"]["physicalDisplay"]["override"]["state"])
        self.assertEqual(
            "OFF", plan["second"]["host"]["physicalDisplay"]["override"]["state"])
        self.assertEqual(
            recovery._stable_observation(plan["first"]),
            recovery._stable_observation(plan["second"]))

    def test_physical_and_base_state_are_independent_required_authorities(self) -> None:
        cases = (
            ("physical", "physical_state"),
            ("base", "base_state"),
        )
        for label, field in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                setattr(device, field, "OFF")
                with self.assertRaises(recovery.RecoveryError):
                    recovery.observe(device)

    def test_power_authority_rejects_non_awake_or_unready_state(self) -> None:
        cases = (
            ("Dreaming", "power_wakefulness", "Dreaming"),
            ("Dozing", "power_wakefulness", "Dozing"),
            ("Asleep", "power_wakefulness", "Asleep"),
            ("not-ready", "power_display_ready", "false"),
            ("no-blocker", "power_suspend_blocker", "false"),
        )
        for label, field, value in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                setattr(device, field, (value,))
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "PowerManager"):
                    recovery.observe(device)

    def test_power_authority_rejects_missing_duplicate_or_unknown_tokens(
            self) -> None:
        fields = (
            b"  mWakefulness=",
            b"  mDisplayReady=",
            b"  mHoldingDisplaySuspendBlocker=",
            b"  mUserActivitySummary=",
            b"  mWakeLockSummary=",
        )
        for field in fields:
            for mode in ("missing", "duplicate", "shadow-duplicate"):
                with self.subTest(field=field, mode=mode):
                    device = FakeDevice()
                    if mode == "missing":
                        change = lambda line: b""
                    elif mode == "duplicate":
                        change = lambda line: line + line
                    else:
                        change = lambda line: line + b"  " + line
                    device.power_mutator = (
                        lambda raw, _index, marker=field, mutate=change:
                        self._replace_wire_line(raw, marker, mutate))
                    with self.assertRaisesRegex(
                            recovery.RecoveryError, "PowerManager"):
                        recovery.observe(device)
        device = FakeDevice()
        device.power_display_ready = ("unknown",)
        with self.assertRaisesRegex(recovery.RecoveryError, "PowerManager"):
            recovery.observe(device)

    def test_power_authority_change_between_observations_fails_closed(
            self) -> None:
        authority = recovery.load_authority(self.root)
        device = FakeDevice()
        device.power_wakefulness = ("Awake", "Dreaming")
        with self.assertRaisesRegex(recovery.RecoveryError, "PowerManager"):
            recovery.build_plan(authority, device)

    def test_display_authority_rejects_identity_and_geometry_mismatches(
            self) -> None:
        cases = (
            ("physical-name", "physical_name", "Other Screen"),
            ("physical-id", "physical_unique_id", "local:9"),
            ("physical-type", "physical_type", "EXTERNAL"),
            ("physical-size", "physical_size", (1400, 1872)),
            ("physical-rotation", "physical_rotation", 1),
            ("base-name", "base_name", "Other Screen"),
            ("base-id", "base_display_id", 1),
            ("base-unique", "base_unique_id", "local:9"),
            ("base-type", "base_type", "EXTERNAL"),
            ("base-size", "base_size", (1872, 1404)),
            ("base-rotation", "base_rotation", 3),
            ("override-name", "override_name", "Other Screen"),
            ("override-id", "override_display_id", 1),
            ("override-unique", "override_unique_id", "local:9"),
            ("override-type", "override_type", "EXTERNAL"),
            ("override-state", "override_states", ("UNKNOWN",)),
            ("override-frame", "override_frames", ((1404, 1872, 3),)),
        )
        for label, field, value in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                setattr(device, field, value)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.observe(device)

    def test_display_authority_rejects_missing_or_duplicate_records(self) -> None:
        markers = (
            b"DisplayDeviceInfo{",
            b"mBaseDisplayInfo=",
            b"mOverrideDisplayInfo=",
        )
        for marker in markers:
            for mode in ("missing", "duplicate"):
                with self.subTest(marker=marker, mode=mode):
                    device = FakeDevice()
                    if mode == "missing":
                        change = lambda line: b""
                    else:
                        change = lambda line: line + line
                    device.display_mutator = (
                        lambda raw, _index, selected=marker, mutate=change:
                        self._replace_wire_line(raw, selected, mutate))
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.observe(device)

    def test_secondary_or_incomplete_display_inventory_fails_closed(
            self) -> None:
        unrelated = (
            b"  Display 2:\n"
            b"    mDisplayId=2\n"
            b"    name=UnrelatedExternal\n")
        unrelated_device = (
            b"  DisplayDeviceInfo{\"External\": uniqueId=\"local:7\", "
            b"1024 x 768, rotation 0, type EXTERNAL, state ON}\n")
        cases = (
            ("logical-truncated",
             lambda raw, _index:
             raw.replace(b"Logical Displays: size=1",
                         b"Logical Displays: size=2", 1)),
            ("logical-extra-block",
             lambda raw, _index: raw + unrelated),
            ("logical-duplicate-header",
             lambda raw, _index:
             raw.replace(b"Logical Displays: size=1\n",
                         b"Logical Displays: size=1\n"
                         b"Logical Displays: size=1\n", 1)),
            ("logical-complete-secondary",
             lambda raw, _index:
             raw.replace(b"Logical Displays: size=1",
                         b"Logical Displays: size=2", 1) +
             unrelated),
            ("device-truncated",
             lambda raw, _index:
             raw.replace(b"Display Devices: size=1",
                         b"Display Devices: size=2", 1)),
            ("device-extra-record",
             lambda raw, _index: raw + unrelated_device),
            ("device-duplicate-header",
             lambda raw, _index:
             raw.replace(b"Display Devices: size=1\n",
                         b"Display Devices: size=1\n"
                         b"Display Devices: size=1\n", 1)),
            ("device-complete-secondary",
             lambda raw, _index:
             raw.replace(b"Display Devices: size=1",
                         b"Display Devices: size=2", 1) +
             unrelated_device),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                device.display_mutator = mutate
                with self.assertRaises(recovery.RecoveryError):
                    recovery.observe(device)

    def test_literal_known_nomad_override_off_wire_is_accepted(self) -> None:
        display = b"""DISPLAY MANAGER (dumpsys display)
Display Devices: size=1
    mSupportedColorModes=[0]  DisplayDeviceInfo{"Built-in Screen": uniqueId="local:0", 1404 x 1872, modeId 1, rotation 0, type INTERNAL, state ON, FLAG_DEFAULT_DISPLAY}
Logical Displays: size=1
  Display 0:
    mDisplayId=0
    mBaseDisplayInfo=DisplayInfo{"Built-in Screen", displayId 0, real 1404 x 1872, rotation 0, state ON, type INTERNAL, uniqueId "local:0"}
    mOverrideDisplayInfo=DisplayInfo{"Built-in Screen", displayId 0, real 1872 x 1404, rotation 3, state OFF, type INTERNAL, uniqueId "local:0"}
"""
        power = b"""POWER MANAGER (dumpsys power)
  mWakefulness=Awake
  mDisplayReady=true
  mHoldingDisplaySuspendBlocker=true
  mUserActivitySummary=0x1
  mWakeLockSummary=0x0
"""
        parsed_display = recovery._physical_display0_authority(display)
        parsed_power = recovery._power_authority(power)
        self.assertEqual("OFF", parsed_display["override"]["state"])
        self.assertEqual(3, parsed_display["override"]["rotation"])
        self.assertEqual("Awake", parsed_power["wakefulness"])

    def test_semantic_authority_drift_fails_but_raw_evidence_drift_does_not(
            self) -> None:
        authority = recovery.load_authority(self.root)
        geometry = FakeDevice()
        geometry.override_frames = (
            (1404, 1872, 0), (1872, 1404, 3))
        with self.assertRaisesRegex(
                recovery.RecoveryError, "authority drifted"):
            recovery.build_plan(authority, geometry)

        raw_only = FakeDevice()
        raw_only.power_mutator = (
            lambda raw, index:
            raw + ("  diagnostic=" + str(index) + "\n").encode("ascii"))
        plan = recovery.build_plan(authority, raw_only)
        self.assertNotEqual(
            plan["first"]["powerSha256"], plan["second"]["powerSha256"])
        self.assertEqual(
            recovery._stable_observation(plan["first"]),
            recovery._stable_observation(plan["second"]))

    def test_stale_or_reappearing_host_authority_fails_closed(self) -> None:
        cases = (
            ("process", lambda item: setattr(item, "host_pids", (28990,))),
            ("task", lambda item: setattr(item, "stale_host_task", True)),
            ("window", lambda item: setattr(item, "stale_host_window", True)),
            ("display", lambda item: setattr(item, "stale_host_display", True)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                mutate(device)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.observe(device)

    def test_owned_virtual_display_reappearing_on_second_observation_fails(
            self) -> None:
        authority = recovery.load_authority(self.root)
        device = FakeDevice()

        def reappear(raw: bytes, index: int) -> bytes:
            if index == 0:
                return raw
            return (
                raw.replace(b"Logical Displays: size=1",
                            b"Logical Displays: size=2", 1) +
                b"  Display 2:\n"
                b"    mDisplayId=2\n"
                b"    name=" + recovery.DISPLAY_NAME.encode("ascii") + b"\n")

        device.display_mutator = reappear
        with self.assertRaises(recovery.RecoveryError):
            recovery.build_plan(authority, device)

    def test_target_or_deleted_target_fd_use_fails_closed(self) -> None:
        for target in (recovery.TARGET_PDF,
                       recovery.TARGET_MARK + " (deleted)"):
            with self.subTest(target=target):
                device = FakeDevice()
                device.fd_targets = {target}
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "disposable alpha descriptor"):
                    recovery.observe(device)

    def test_task_target_use_fails_even_when_descriptors_are_unrelated(self) -> None:
        device = FakeDevice()
        device.OTHER_PDF = recovery.TARGET_PDF
        self.assertEqual({FakeDevice.OTHER_PDF}, device.fd_targets)
        with self.assertRaisesRegex(
                recovery.RecoveryError, "task still names"):
            recovery.observe(device)

    def test_fully_absent_document_authority_is_admitted(self) -> None:
        device = FakeDevice()
        device.document_pids = ()
        observation = recovery.observe(device).wire()
        self.assertEqual("absent", observation["document"]["mode"])
        self.assertEqual([], observation["document"]["stable"]["fdTargets"])
        self.assertEqual([], device.history)

    def test_file_replacement_and_staging_or_quarantine_occupancy_fail(self) -> None:
        cases = []
        replaced = FakeDevice()
        replaced.files[recovery.TARGET_PDF] = replace(
            replaced.files[recovery.TARGET_PDF], inode=999999)
        cases.append(("replacement", replaced))
        staged = FakeDevice()
        staged_path = recovery.STAGING[recovery.TARGET_PDF]
        staged.files[staged_path] = replace(
            recovery.TARGETS[recovery.TARGET_PDF], path=staged_path)
        cases.append(("staging", staged))
        occupied = FakeDevice()
        quarantine = recovery.QUARANTINES[recovery.TARGET_MARK]
        occupied.files[quarantine] = replace(
            recovery.TARGETS[recovery.TARGET_MARK], path=quarantine)
        cases.append(("quarantine", occupied))
        for label, device in cases:
            with self.subTest(label=label), self.assertRaises(
                    recovery.RecoveryError):
                recovery.observe(device)

    def test_file_identity_drift_between_plan_observations_fails_closed(self) -> None:
        authority = recovery.load_authority(self.root)
        with self.assertRaisesRegex(
                recovery.RecoveryError, "disposable target identity changed"):
            recovery.build_plan(authority, DriftingFileDevice())

    def test_ambiguous_or_malformed_task_window_evidence_fails_closed(self) -> None:
        cases = (
            ("task", "extra_document_task"),
            ("window", "extra_document_window"),
            ("wire", "malformed_activities"),
        )
        for label, field in cases:
            with self.subTest(label=label):
                device = FakeDevice()
                setattr(device, field, True)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.observe(device)

    def _execution_authority(self, directory: Path) -> recovery.Authority:
        retained = recovery.load_authority(self.root)
        report_path = directory / "report.json"
        active_path = directory / "active.jsonl"
        shutil.copyfile(retained.report_path, report_path)
        shutil.copyfile(retained.active_path, active_path)
        _, report_identity = recovery._read_regular(
            report_path, 128 * 1024, "test report")
        _, active_identity = recovery._read_regular(
            active_path, 256 * 1024, "test active")
        return recovery.Authority(
            self.root, report_path, active_path,
            directory / "retired.jsonl", directory / "recovery.jsonl",
            directory / "evidence.json", directory / "plan.json",
            report_identity, {**active_identity, "path": str(active_path)},
            retained.dependency_identities)

    @staticmethod
    def _operation_names(device: FakeDevice) -> list[str]:
        return [str(item["operation"]) for item in device.history]

    def test_loaded_plan_rejects_missing_or_invalid_advisory_state(self) -> None:
        for mode in ("missing", "invalid"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as directory_name:
                    authority = self._execution_authority(Path(directory_name))
                    plan = recovery.build_plan(authority, FakeDevice())
                    for side in ("first", "second"):
                        override = plan[side]["host"]["physicalDisplay"][
                            "override"]
                        if mode == "missing":
                            del override["state"]
                        else:
                            override["state"] = "UNKNOWN"
                    unsigned = dict(plan)
                    unsigned.pop("bindingSha256")
                    plan["bindingSha256"] = recovery._canonical_sha(unsigned)
                    recovery._write_exclusive(authority.plan_path, plan)
                    with self.assertRaisesRegex(
                            recovery.RecoveryError,
                            "override state is malformed"):
                        recovery.load_plan(authority.plan_path, authority)

    def test_v2_plan_loads_and_rebound_v1_plan_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = self._execution_authority(Path(directory_name))
            plan = recovery.build_plan(authority, FakeDevice())
            identity = recovery._write_exclusive(authority.plan_path, plan)
            loaded, observed_identity = recovery.load_plan(
                authority.plan_path, authority)
            self.assertEqual(plan, loaded)
            self.assertEqual(identity, observed_identity)

        with tempfile.TemporaryDirectory() as directory_name:
            authority = self._execution_authority(Path(directory_name))
            plan = recovery.build_plan(authority, FakeDevice())
            plan["authority"] = (
                "native-page-alpha-post-restart-orphan-recovery-plan-v1")
            plan["schemaVersion"] = 1
            unsigned = dict(plan)
            unsigned.pop("bindingSha256")
            plan["bindingSha256"] = recovery._canonical_sha(unsigned)
            recovery._write_exclusive(authority.plan_path, plan)
            with self.assertRaisesRegex(
                    recovery.RecoveryError,
                    "plan binding or exact-run authority differs"):
                recovery.load_plan(authority.plan_path, authority)

    def test_execute_is_mark_before_pdf_and_publishes_verified_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = self._execution_authority(Path(directory_name))
            device = FakeDevice()
            plan = recovery.build_plan(authority, device)
            result = recovery.execute(
                authority, device, copy.deepcopy(plan),
                {"path": "test-plan", "sha256": "b" * 64})
            self.assertEqual(
                "POST_RESTART_ORPHAN_RECOVERED_CLEANLY", result["result"])
            self.assertEqual(recovery.AUTHORITY, result["authority"])
            self.assertEqual(2, result["schemaVersion"])
            self.assertEqual(
                [
                    "recovery_quarantine_" + Path(recovery.TARGET_MARK).name,
                    "recovery_remove_" +
                    Path(recovery.QUARANTINES[recovery.TARGET_MARK]).name,
                    "recovery_quarantine_" + Path(recovery.TARGET_PDF).name,
                    "recovery_remove_" +
                    Path(recovery.QUARANTINES[recovery.TARGET_PDF]).name,
                ],
                self._operation_names(device))
            self.assertFalse(authority.active_path.exists())
            self.assertTrue(authority.retired_path.exists())
            self.assertTrue(authority.ledger_path.exists())
            self.assertTrue(authority.evidence_path.exists())
            self.assertNotIn(recovery.TARGET_MARK, device.files)
            self.assertNotIn(recovery.TARGET_PDF, device.files)

    def test_lost_mutation_reply_settles_only_from_exact_postcondition(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = self._execution_authority(Path(directory_name))
            device = FakeDevice()
            operation = "recovery_quarantine_" + Path(recovery.TARGET_MARK).name
            device.lose_after.add(operation)
            plan = recovery.build_plan(authority, device)
            result = recovery.execute(
                authority, device, plan,
                {"path": "test-plan", "sha256": "c" * 64})
            self.assertEqual(
                "POST_RESTART_ORPHAN_RECOVERED_CLEANLY", result["result"])
            ledger = authority.ledger_path.read_text(encoding="ascii")
            self.assertIn("lost reply: " + operation, ledger)

    def test_pre_mutation_plan_drift_leaves_no_ledger_or_device_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = self._execution_authority(Path(directory_name))
            device = FakeDevice()
            plan = recovery.build_plan(authority, device)
            drifted = copy.deepcopy(plan)
            drifted["first"]["document"]["stable"]["fdTargets"] = [
                "/storage/emulated/0/Document/Changed.pdf"]
            drifted["second"]["document"]["stable"]["fdTargets"] = [
                "/storage/emulated/0/Document/Changed.pdf"]
            with mock.patch.object(
                    recovery, "build_plan", return_value=copy.deepcopy(plan)):
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "live authority no longer matches"):
                    recovery.execute(
                        authority, device, drifted,
                        {"path": "test-plan", "sha256": "d" * 64})
            self.assertEqual([], device.history)
            self.assertFalse(authority.ledger_path.exists())
            self.assertTrue(authority.active_path.exists())
            self.assertFalse(authority.retired_path.exists())

    def test_nomad_power_transport_is_bounded_to_dumpsys_power(self) -> None:
        device = object.__new__(recovery.Nomad)
        token = object()
        with mock.patch.object(
                recovery.Nomad, "_invoke", return_value=token) as invoke:
            with mock.patch.object(
                    recovery.Nomad, "_require_zero",
                    return_value=b"POWER MANAGER (dumpsys power)\n") as require:
                self.assertEqual(
                    b"POWER MANAGER (dumpsys power)\n", device.power())
        invoke.assert_called_once_with(
            "power", ("shell", "dumpsys", "power"))
        require.assert_called_once_with(token)

    def test_nomad_rejects_task_and_package_mutation_capabilities(self) -> None:
        device = object.__new__(recovery.Nomad)
        with self.assertRaisesRegex(
                recovery.RecoveryError, "no task-removal"):
            device.remove_task(1)
        with self.assertRaisesRegex(
                recovery.RecoveryError, "no package-force-stop"):
            device.force_stop_document()


if __name__ == "__main__":
    unittest.main()
