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
        stale = ""
        size = 1
        if self.stale_host_display:
            size = 2
            stale = f"""  Display 2:
    mDisplayId=2
    name={recovery.DISPLAY_NAME}
"""
        return f"""DISPLAY MANAGER (dumpsys display)
Logical Displays: size={size}
  Display 0:
    mDisplayId=0
    mOverrideDisplayInfo=DisplayInfo{{"Built-in Screen", displayId 0, real 1404 x 1872, largest app 1404 x 1872, smallest app 1404 x 1872, rotation 0, state ON, type INTERNAL, uniqueId "local:0"}}
{stale}""".encode("ascii")

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
