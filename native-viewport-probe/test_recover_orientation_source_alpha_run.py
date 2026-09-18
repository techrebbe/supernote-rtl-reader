from __future__ import annotations

from dataclasses import replace
import os
import shutil
import stat
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_page_alpha_runner as alpha
import native_page_host_authority as host
import recover_orientation_source_alpha_run as recovery


class FakeDevice:
    def __init__(self) -> None:
        self.history: list[dict[str, object]] = []
        self.files = {
            alpha.SOURCE_PDF: recovery.PINNED_SOURCE_PDF,
            alpha.SOURCE_MARK: recovery.PINNED_SOURCE_MARK,
            alpha.PARKING_PDF: recovery.PINNED_PARKING,
            alpha.TARGET_PDF: recovery.PINNED_TARGET_PDF,
            alpha.TARGET_MARK: recovery.PINNED_TARGET_MARK,
        }
        self.host_live = True
        self.host_scope_live = True
        self.host_supervisor_ghost = False
        self.alter_host_supervisor_ghost = False
        self.host_remove_sent = False
        self.post_remove_host_scope_reads = 0
        self.rogue_host_display = False
        self.rogue_display_after_host_remove = False
        self.host_apk = ("/data/app/~~P-zBGtsmYw_zm5K3dk4bUA==/"
                         "com.techrebbe.supernote.nativepagehost-"
                         "EuyxNt_S29aDH5ZARLJotQ==/base.apk")
        self.host_task_token = "93d94cf"
        self.host_activity_token = "45537a9"
        self.host_process_token = "9a99e5c"
        self.host_window_token = "d295460"
        self.host_window_session_token = "7171c1d"
        self.physical_rotation = 0
        self.host_frame_override = None
        self.extra_host_task = False
        self.extra_same_stack_other_task = False
        self.task_live = False
        self.parking_was_launched = False
        self.parking_remove_sent = False
        self.parking_supervisor_ghost = False
        self.parking_task_id = 7001
        self.parking_task_token = "66d8263"
        self.parking_activity_token = "11846f4"
        self.parking_authority_sha256 = None
        self.extra_document_task = False
        self.extra_document_window = False
        self.post_remove_parking_scope_reads = 0
        self.post_remove_parking_malformed_reads = 0
        self.vary_parking_raw_hash = False
        self.parking_capture_count = 0
        self.parking_ui_bounds = [0, 0, 400, 100]
        self.mark_replacement_on_launch = None
        self.mark_replacement_on_remove = None
        self.recreate_mark_during_pdf_delete = False
        self.rotation = ("1", "2")
        self.fd_targets = {alpha.TARGET_PDF, alpha.PARKING_PDF}
        self.logs = self._base_logs()
        self.ui_dump_count = 0
        self.ui_dump_override = None
        self.fail_after: set[str] = set()
        self.semantic_after: set[str] = set()
        self.fail_before: set[str] = set()

    @staticmethod
    def _base_logs() -> str:
        session0 = f"session={recovery.SESSION} generation=0"
        generation1 = f"session={recovery.SESSION} generation={recovery.GENERATION}"
        return "\n".join([
            "SESSION " + session0 + " readiness=WAITING_FOR_SURFACE visualOnly=true",
            "HOST_AUTHORITY " + session0 + " display=0 resumed=true visible=true focused=true",
            "DISPLAY_ALLOCATED " + generation1 + " display=1 readiness=METRICS_PENDING",
            "DISPLAY_READY " + generation1 + " display=1 density=300 readiness=WAITING_FOR_FOREIGN_ACK",
            "DISPLAY_RESUMED " + generation1 + " callbackGeneration=1",
            "HOST_AUTHORITY_SUSPENDED " + generation1 + " reason=configuration_change",
            "WAIT_CONFIGURATION_FRAME " + generation1 + " host=1872x1404",
            "FRAME_READY " + generation1 + " host=1872x1404 requested=1872x1404",
            "HOST_AUTHORITY_REACQUIRED " + generation1 + " density=300",
            "HOST_AUTHORITY_READY " + generation1 + " deadlinePreserved=true",
            "TIMEOUT " + generation1 + " phase=foreign_attach displayRetained=true",
            "FAILED " + generation1 + " reason=host_surface_lost_unexpectedly display=1 emergencyDestroyContent=true",
        ]) + "\n"

    def adb_authority(self):
        return {"path": str(recovery.PINNED_ADB), "size": recovery.PINNED_ADB_SIZE,
                "sha256": recovery.PINNED_ADB_SHA256, "device": 1,
                "inode": 2, "mtimeNs": 3}

    def environment(self):
        return {"hostUid": recovery.HOST_UID, "hostApk": self.host_apk,
                "documentApk": alpha.DOCUMENT_APK}

    def stat_file(self, path, *, absent_ok=False):
        value = self.files.get(path)
        if value is None and not absent_ok:
            raise recovery.RecoveryError("missing fake path " + path)
        return value

    def pidof(self, package):
        if package == alpha.HOST_PACKAGE:
            return (recovery.HOST_PID,) if self.host_live else ()
        return (recovery.DOCUMENT_PID,)

    def process_identity(self, pid, package):
        if package == alpha.HOST_PACKAGE:
            return host.ProcessIdentity(
                recovery.HOST_PID, recovery.HOST_START_TICKS,
                recovery.HOST_UID, alpha.HOST_PACKAGE)
        return host.ProcessIdentity(recovery.DOCUMENT_PID, 3382, 1000,
                                    alpha.DOCUMENT_PACKAGE)

    def process_fd_links(self, pid):
        return "".join(
            f"lr-x------ 1 root root 64 2026-09-16 20:00 {number} -> {path}\n"
            for number, path in enumerate(sorted(self.fd_targets), 40))

    def host_logs(self, pid): return self.logs

    def _host_activities(self):
        package = alpha.HOST_PACKAGE
        component = package + "/.NativePageHostActivity"
        task = (f"Task{{{self.host_task_token} #4646 visible=true type=standard "
                f"mode=fullscreen translucent=false A=10142:{package} U=0 "
                "StackId=4646 sz=1}")
        activity = (f"ActivityRecord{{{self.host_activity_token} u0 "
                    f"{component} t4646}}")
        process = (f"ProcessRecord{{{self.host_process_token} 18691:"
                   f"{package}/u0a142}}")
        extra = (f"  Stack #9999: type=standard mode=fullscreen\n"
                 f"    * Task{{deadbee #9999 visible=false type=standard "
                 f"mode=fullscreen translucent=false A=10142:{package} U=0 "
                 "StackId=9999 sz=0}\n") if self.extra_host_task else ""
        same_stack = (
            "    * Task{7777777 #7777 visible=true type=standard "
            "mode=fullscreen translucent=false A=10001:com.example.other "
            "U=0 StackId=4646 sz=1}\n"
            "      taskId=7777 stackId=4646\n"
            "      * Hist #0: ActivityRecord{7654321 u0 "
            "com.example.other/.OtherActivity t7777}\n"
            if self.extra_same_stack_other_task else "")
        return ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
                "Display #0 (activities from top to bottom):\n"
                "  Stack #4646: type=standard mode=fullscreen\n"
                f"    mResumedActivity: {activity}\n"
                f"    * {task}\n"
                f"    intent={{act=android.intent.action.MAIN "
                "cat=[android.intent.category.LAUNCHER] flg=0x10000000 "
                f"cmp={component}}}\n"
                f"    Activities=[{activity}]\n"
                f"    mRootProcess={process}\n"
                "    taskId=4646 stackId=4646\n"
                f"      * Hist #0: {activity}\n"
                f"      app={process}\n"
                "      state=RESUMED stopped=false finishing=false\n"
                f"      baseDir={self.host_apk}\n"
                f"      * {task}\n" + same_stack + extra)

    def _host_windows(self):
        package = alpha.HOST_PACKAGE
        short = package + "/.NativePageHostActivity"
        full = alpha.HOST_COMPONENT
        activity = (f"ActivityRecord{{{self.host_activity_token} u0 "
                    f"{short} t4646}}")
        width, height = ((1872, 1404)
                         if self.physical_rotation in (1, 3)
                         else (1404, 1872))
        if self.host_frame_override is not None:
            width, height = self.host_frame_override
        return ("WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
                f"  Window #5 Window{{{self.host_window_token} u0 {full}}}:\n"
                "    mDisplayId=0 rootTaskId=4646 "
                f"mSession=Session{{{self.host_window_session_token} "
                "18691:u0a10142} mClient=android.os.BinderProxy@79a1063\n"
                f"    mOwnerUid=10142 showForAllUsers=false package={package} "
                "appop=NONE\n"
                f"    mBaseLayer=21000 mSubLayer=0    mToken={activity}\n"
                f"    mActivityRecord={activity}\n"
                "    mHasSurface=true isReadyForDisplay()=true "
                "mWindowRemovalAllowed=false\n"
                f"    mFrame=[0,0][{width},{height}] "
                f"last=[0,0][{width},{height}]\n"
                "    isOnScreen=true\n"
                "    isVisible=true\n")

    def _displays(self):
        width, height = ((1872, 1404)
                         if self.physical_rotation in (1, 3)
                         else (1404, 1872))
        rogue = (
            "  Display 2:\n"
            "    mDisplayId=2\n"
            "    name=NativePageVisualOnly-"
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee-7\n"
            if self.rogue_host_display else "")
        return (
            "DISPLAY MANAGER (dumpsys display)\n"
            "Logical Displays: size=1\n"
            "  Display 0:\n"
            "    mDisplayId=0\n"
            "    mOverrideDisplayInfo=DisplayInfo{\"Built-in Screen\", "
            f"displayId 0, real {width} x {height}, "
            f"largest app {width} x {height}, smallest app {width} x {height}, "
            f"rotation {self.physical_rotation}, state ON, type INTERNAL, "
            "uniqueId \"local:0\"}\n" + rogue).encode("ascii")

    def absence_raw(self):
        if self.task_live:
            return (b"com.supernote.document/.DocumentActivity\n", b"windows\n",
                    self._displays())
        if self.host_remove_sent and self.post_remove_host_scope_reads > 0:
            self.post_remove_host_scope_reads -= 1
            if self.post_remove_host_scope_reads == 0:
                self.host_scope_live = False
        if self.host_scope_live:
            return (self._host_activities().encode("utf-8"),
                    self._host_windows().encode("utf-8"), self._displays())
        if (self.parking_remove_sent and
                self.post_remove_parking_malformed_reads > 0):
            self.post_remove_parking_malformed_reads -= 1
            return (b"\x00malformed\n", b"no windows\n", self._displays())
        if (self.parking_remove_sent and
                self.post_remove_parking_scope_reads > 0):
            self.post_remove_parking_scope_reads -= 1
            return (b"com.supernote.document/.DocumentActivity\n",
                    b"windows\n", self._displays())
        if self.parking_was_launched and self.parking_supervisor_ghost:
            return (self._parking_supervisor_activity(), b"no windows\n",
                    self._displays())
        if self.host_supervisor_ghost:
            return (self._host_supervisor_activity(), b"no windows\n",
                    self._displays())
        return b"no activity tasks\n", b"no windows\n", self._displays()

    def _host_supervisor_activity(self):
        activity_token = ("deadbee" if self.alter_host_supervisor_ghost else
                          self.host_activity_token)
        package = alpha.HOST_PACKAGE
        component = package + "/.NativePageHostActivity"
        return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{{self.host_task_token} #4646 visible=false A=10142:{package} sz=0}}
  mLastOrientationSource=ActivityRecord{{{activity_token} u0 {component} t4646}}
  deepestLastOrientationSource=ActivityRecord{{{activity_token} u0 {component} t4646}}
  mLastFocusedStack=Task{{{self.host_task_token} #4646 visible=false A=10142:{package} sz=0}}
  Display: mDisplayId=0 stacks=0
""".encode("utf-8")

    def _parking_authority(self, raw_hash):
        return recovery.android.DocumentTaskAuthority(
            recovery.android.AUTHORITY, raw_hash, 0, self.parking_task_id,
            self.parking_task_id, self.parking_task_token,
            self.parking_activity_token, recovery.DOCUMENT_PID, 1000,
            alpha.DOCUMENT_PACKAGE, alpha.DOCUMENT_PACKAGE,
            recovery.android.SHORT_COMPONENT, alpha.DOCUMENT_APK, "RESUMED",
            True, False, False, False, True, True, True, True, True, True,
            True, 1404, 1872, 300, 0)

    def _parking_activity_wire(self, *, extra_task=False, same_stack=False):
        task = self.parking_task_id
        token = self.parking_activity_token
        task_token = self.parking_task_token
        package = alpha.DOCUMENT_PACKAGE
        component = recovery.android.SHORT_COMPONENT
        if extra_task:
            extra_record = f"""    * Task{{7777777 #7002 visible=true type=standard mode=fullscreen translucent=false A=1000:{package} U=0 StackId={task if same_stack else 7002} sz=1}}
      taskId=7002 stackId={task if same_stack else 7002}
      * Hist #0: ActivityRecord{{7654321 u0 {package}/.OtherActivity t7002}}
"""
            extra = (extra_record if same_stack else
                     "Display #7 (activities from top to bottom):\n"
                     "  Stack #7002: type=standard mode=fullscreen\n" +
                     extra_record)
        else:
            extra = ""
        return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #{task}: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{{token} u0 {component} t{task}}}
    * Task{{{task_token} #{task} visible=true type=standard mode=fullscreen translucent=false A=1000:{package} U=0 StackId={task} sz=1}}
      taskId={task} stackId={task}
      intent={{act=android.intent.action.VIEW
        dat={alpha.PARKING_URI} typ=application/pdf
        cmp={component}}}
      * Hist #0: ActivityRecord{{{token} u0 {component} t{task}}}
          packageName={package} processName={package}
          app=ProcessRecord{{2083011 {recovery.DOCUMENT_PID}:{package}/1000}}
          mActivityComponent={component}
          baseDir={alpha.DOCUMENT_APK}
          state=RESUMED stopped=false delayedResume=false finishing=false
          mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
          nowVisible=true lastVisibleTime=-1s
{extra}""".encode("utf-8")

    def _parking_window_wire(self, *, extra_window=False):
        package = alpha.DOCUMENT_PACKAGE
        component = recovery.android.FULL_COMPONENT
        record = (f"ActivityRecord{{{self.parking_activity_token} u0 "
                  f"{recovery.android.SHORT_COMPONENT} "
                  f"t{self.parking_task_id}}}")
        extra = (f"  Window #2 Window{{deadbeef u0 "
                 f"{package}/.OtherActivity}}:\n"
                 f"    mDisplayId=0 rootTaskId=7002\n") if extra_window else ""
        return f"""WINDOW MANAGER WINDOWS (dumpsys window windows)
  Window #1 Window{{cafebabe u0 {component}}}:
    mDisplayId=0 rootTaskId={self.parking_task_id} mSession=Session{{7171c1d {recovery.DOCUMENT_PID}:1000}} mClient=android.os.BinderProxy@1
    mOwnerUid=1000 showForAllUsers=false package={package} appop=NONE
    mActivityRecord={record}
{extra}""".encode("utf-8")

    def _parking_supervisor_activity(self):
        return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{{self.parking_task_token} #{self.parking_task_id} visible=false A=1000:com.supernote.document sz=0}}
  mLastOrientationSource=ActivityRecord{{{self.parking_activity_token} u0 com.supernote.document/.document.DocumentActivity t{self.parking_task_id}}}
  deepestLastOrientationSource=ActivityRecord{{{self.parking_activity_token} u0 com.supernote.document/.document.DocumentActivity t{self.parking_task_id}}}
  mLastFocusedStack=Task{{{self.parking_task_token} #{self.parking_task_id} visible=false A=1000:com.supernote.document sz=0}}
  Display: mDisplayId=0 stacks=0
""".encode("utf-8")

    def ui_dump(self):
        self.ui_dump_count += 1
        if isinstance(self.ui_dump_override, BaseException):
            raise self.ui_dump_override
        if self.ui_dump_override is not None:
            return self.ui_dump_override
        value = "&#10;".join((
            "NATIVE PAGE HOST — VISUAL ONLY",
            "session=" + recovery.SESSION,
            "generation=1 display=-1",
            "state=RELEASED",
            "FAILED (sticky): foreign attach acknowledgment timed out",
            "Stylus is swallowed; no reader launch, pen, file, or root authority.",
        ))
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<hierarchy rotation="0"><node text="{value}" '
                f'class="android.widget.TextView" package="{alpha.HOST_PACKAGE}" '
                'bounds="[709,0][1404,194]" /></hierarchy>\n').encode("utf-8")
    def rotation_settings(self): return self.rotation

    def _maybe_before(self, name):
        if name in self.fail_before:
            raise recovery.MutationTransportUncertain(
                "simulated uncertain transport before " + name)

    def _maybe_after(self, name):
        if name in self.semantic_after:
            self.semantic_after.remove(name)
            raise recovery.RecoveryError(
                "authoritative semantic failure after " + name)
        if name in self.fail_after:
            self.fail_after.remove(name)
            raise recovery.MutationTransportUncertain(
                "simulated uncertain transport after " + name)

    def launch_parking(self):
        self._maybe_before("launch")
        self.history.append({"operation": "launch_parking"})
        self.task_live = True
        self.parking_was_launched = True
        self.fd_targets = {alpha.PARKING_PDF}
        if self.mark_replacement_on_launch is not None:
            self.files[alpha.TARGET_MARK] = replace(
                self.files[alpha.TARGET_MARK],
                **self.mark_replacement_on_launch)
        self._maybe_after("launch")
        stdout = (
            "Starting: Intent { act=" + alpha.DOCUMENT_LAUNCH_ACTION +
            " dat=" + alpha.PARKING_URI + " typ=" +
            alpha.DOCUMENT_LAUNCH_MIME + " cmp=" +
            recovery.android.SHORT_COMPONENT + " }\r\n").encode("ascii")
        return alpha.CommandResult(
            "launch_parking_document", (), 0, stdout, b"")

    def parking_identity(self):
        if not self.task_live or self.fd_targets != {alpha.PARKING_PDF}:
            raise recovery.RecoveryError("parking task is not ready")
        if self.extra_document_task:
            raise recovery.RecoveryError(
                "additional or malformed stock Document task scope exists")
        if self.extra_document_window:
            raise recovery.RecoveryError(
                "parking package does not own exactly one window")
        process = self.process_identity(recovery.DOCUMENT_PID, alpha.DOCUMENT_PACKAGE)
        self.parking_capture_count += 1
        raw_hash = ((format(self.parking_capture_count, "064x"))
                    if self.vary_parking_raw_hash else "b" * 64)
        authority = self._parking_authority(raw_hash)
        authority_sha = (recovery.android.stable_authority_sha256(authority)
                         if self.parking_authority_sha256 is None else
                         self.parking_authority_sha256)
        return {
            "process": recovery.asdict(process),
            "taskId": self.parking_task_id,
            "displayId": 0,
            "authoritySha256": authority_sha,
            "activityToken": self.parking_activity_token,
            "documentAuthority": recovery.asdict(authority),
            "documentScope": {
                "taskId": self.parking_task_id, "displayId": 0,
                "taskToken": self.parking_task_token,
                "activityToken": self.parking_activity_token,
                "processToken": "2083011", "windowToken": "cafebabe",
                "windowSessionToken": "7171c1d",
                "windowComponent": recovery.android.FULL_COMPONENT,
                "pid": recovery.DOCUMENT_PID, "uid": 1000,
                "oneChildRootTask": True, "solePackageWindow": True,
            },
            "uiWitness": {
                "filename": Path(alpha.PARKING_PDF).name,
                "pageCount": "1/1", "bounds": list(self.parking_ui_bounds),
                "package": alpha.DOCUMENT_PACKAGE, "rotation": 0,
                "sha256": raw_hash,
            },
            "fdTargets": [alpha.PARKING_PDF], "activitiesSha256": raw_hash,
            "windowsSha256": raw_hash,
        }

    def remove_task(self, task_id):
        if task_id == recovery.HOST_TASK_ID:
            self._maybe_before("remove_host_task")
            self.history.append({"operation": "remove_host_task",
                                 "taskId": task_id})
            self.host_remove_sent = True
            if self.rogue_display_after_host_remove:
                self.rogue_host_display = True
            if self.post_remove_host_scope_reads == 0:
                self.host_scope_live = False
            self._maybe_after("remove_host_task")
            return alpha.CommandResult(
                "remove_exact_task", (), 0, b"", b"")
        if task_id == self.parking_task_id:
            self._maybe_before("remove_task")
            self.history.append({"operation": "remove_task", "taskId": task_id})
            self.task_live = False
            self.parking_remove_sent = True
            if self.mark_replacement_on_remove is not None:
                self.files[alpha.TARGET_MARK] = replace(
                    self.files[alpha.TARGET_MARK],
                    **self.mark_replacement_on_remove)
            self._maybe_after("remove_task")
            return alpha.CommandResult(
                "remove_exact_task", (), 0, b"", b"")
        raise AssertionError("wrong task")

    def move_quarantine(self, source, target):
        self._maybe_before("move_" + Path(source).suffix)
        self.history.append({"operation": "move", "source": source, "target": target})
        original = self.files.pop(source)
        self.files[target] = replace(original, path=target)
        self._maybe_after("move_" + Path(source).suffix)
        return alpha.CommandResult(
            "recovery_quarantine_" + Path(source).name, (), 0, b"", b"")

    def remove_quarantine(self, path):
        name = "delete_mark" if path == recovery.QUARANTINE_MARK else "delete_pdf"
        self._maybe_before(name)
        self.history.append({"operation": "delete", "path": path})
        self.files.pop(path)
        if (path == recovery.QUARANTINE_PDF and
                self.recreate_mark_during_pdf_delete):
            self.files[alpha.TARGET_MARK] = replace(
                recovery.PINNED_TARGET_MARK, inode=999998)
        self._maybe_after(name)
        return alpha.CommandResult(
            "recovery_remove_" + Path(path).name, (), 0, b"", b"")


class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run_dir = self.root / recovery.RUN_ID
        self.run_dir.mkdir()
        self.report = self.run_dir / "report.json"
        self.report.write_bytes(b"report placeholder\n")
        source_active = (Path(__file__).parent / "build" /
                         "native-page-alpha-runs" /
                         alpha.ACTIVE_MUTATION_JOURNAL_FILENAME)
        self.active = self.root / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        shutil.copyfile(source_active, self.active)
        _, report_identity = recovery._read_regular(self.report, 1024, "test report")
        _, active_identity = recovery._read_regular(
            self.active, 256 * 1024, "test active")
        self.authority = recovery.Authority(
            self.root, self.run_dir, self.report, self.active,
            self.run_dir / recovery.RECOVERY_BASENAME,
            self.run_dir / recovery.EVIDENCE_BASENAME,
            self.run_dir / recovery.RETIRED_BASENAME,
            report_identity, active_identity, True)
        self.device = FakeDevice()
        self.open_journals = []

    def tearDown(self) -> None:
        for journal in self.open_journals:
            journal.close()
        self.temp.cleanup()

    def make_recovery(self, execute=False):
        if not execute:
            return recovery.Recovery(self.device, self.authority, sleep=lambda _: None)
        probe = recovery.Recovery(self.device, self.authority, sleep=lambda _: None)
        header = probe._header()
        header["admissionSha256"] = "f" * 64
        journal = recovery.Journal(self.authority.recovery_path, header)
        self.open_journals.append(journal)
        return recovery.Recovery(
            self.device, self.authority, sleep=lambda _: None, journal=journal)

    def test_plan_is_device_and_local_read_only(self):
        result = self.make_recovery().plan()
        self.assertEqual("PLAN_READY", result["result"])
        self.assertFalse(result["deviceMutationAttempted"])
        self.assertEqual([], self.device.history)
        self.assertTrue(self.active.exists())
        self.assertFalse(self.authority.recovery_path.exists())
        self.assertIn(alpha.TARGET_PDF, self.device.files)
        self.assertEqual(1, self.device.ui_dump_count)

    def test_any_visual_host_virtual_display_fails_plan(self):
        self.device.rogue_host_display = True
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "visual-host virtual display"):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)
        self.assertFalse(self.authority.recovery_path.exists())

    def test_unrelated_secondary_display_is_not_rejected(self):
        recovery._assert_no_virtual_display(
            b"Display 0\nDisplay 2 name=ExternalPresentation\n")

    def test_recreated_visual_host_display_after_remove_blocks_settlement(self):
        self.device.rogue_display_after_host_remove = True
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "task/window absence was not proved twice"):
            self.make_recovery(True).execute()
        self.assertEqual(
            ["remove_host_task"],
            [item["operation"] for item in self.device.history])

    def test_plan_does_not_require_uiautomator_status_witness(self):
        for value in (b"Killed\n", recovery.RecoveryError("uiautomator died")):
            with self.subTest(value=repr(value)):
                self.device.ui_dump_override = value
                before = self.device.ui_dump_count
                result = self.make_recovery().plan()
                self.assertEqual("PLAN_READY", result["result"])
                self.assertFalse(result["hostTaskObservations"] is None)
                self.assertEqual(before + 1, self.device.ui_dump_count)
                proof = [item for item in result["proofs"]
                         if item["kind"] == "released_host_task_authority"][-1]
                self.assertFalse(proof["optionalUi"]["available"])
                self.assertFalse(proof["optionalUi"]["required"])
                lifecycle = result["hostTaskStable"]["terminalLifecycle"]
                self.assertEqual("FAILED", lifecycle["terminalEvent"])
                self.assertEqual("RELEASED", lifecycle["derivedState"])
                self.assertEqual(64, len(lifecycle["selectedEventsSha256"]))

    def test_execution_preflight_rejects_occupied_evidence_before_journal(self):
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                evidence = self.authority.evidence_path
                target = self.root / "symlink-target"
                if kind == "file":
                    evidence.write_bytes(b"collision\n")
                elif kind == "directory":
                    evidence.mkdir()
                else:
                    target.write_bytes(b"collision\n")
                    try:
                        evidence.symlink_to(target)
                    except OSError:
                        target.unlink()
                        continue
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "evidence path is already occupied"):
                    recovery._assert_publication_paths_clear(
                        self.authority, before_journal=True)
                self.assertEqual([], self.device.history)
                self.assertTrue(self.active.exists())
                self.assertFalse(self.authority.recovery_path.exists())
                self.assertFalse(self.authority.retired_path.exists())
                if evidence.is_dir() and not evidence.is_symlink():
                    evidence.rmdir()
                else:
                    evidence.unlink()
                if target.exists():
                    target.unlink()

    def test_plan_rejects_occupied_evidence_before_device_reads(self):
        self.authority.evidence_path.write_bytes(b"collision\n")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "evidence path is already occupied"):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)

    def test_window_session_uses_full_uid_dialect(self):
        process = self.device.process_identity(
            recovery.HOST_PID, alpha.HOST_PACKAGE)
        raw = self.device.absence_raw()
        capture = recovery._host_task_capture(raw, process, self.device.host_apk)
        self.assertEqual("7171c1d",
                         capture["stable"]["windowSessionToken"])
        wrong = (raw[0], raw[1].replace(b"u0a10142", b"u0a142"), raw[2])
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "window session identity differs"):
            recovery._host_task_capture(wrong, process, self.device.host_apk)

    def test_landscape_host_frame_is_bound_to_physical_display_override(self):
        self.device.physical_rotation = 1
        result = self.make_recovery().plan()
        self.assertEqual("PLAN_READY", result["result"])
        stable = result["hostTaskStable"]
        self.assertEqual([0, 0, 1872, 1404], stable["frame"])
        self.assertEqual(
            {"width": 1872, "height": 1404, "rotation": 1},
            stable["physicalDisplay"])
        self.assertEqual([], self.device.history)

    def test_host_frame_must_match_same_physical_display_sample(self):
        self.device.host_frame_override = (1872, 1404)
        with self.assertRaisesRegex(
                recovery.RecoveryError,
                "window frame differs from physical display"):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)

    def test_orientation_change_before_host_remove_blocks_dispatch(self):
        self._assert_host_mutation_blocks_remove(
            lambda: setattr(self.device, "physical_rotation", 1),
            "changed before removal")

    def test_execute_exact_order_and_archives_original_journal(self):
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(
            ["remove_host_task", "launch_parking", "remove_task", "move", "delete",
             "move", "delete"],
            [item["operation"] for item in self.device.history])
        self.assertEqual(alpha.TARGET_MARK, self.device.history[3]["source"])
        self.assertEqual(alpha.TARGET_PDF, self.device.history[5]["source"])
        self.assertNotIn(alpha.TARGET_MARK, self.device.files)
        self.assertNotIn(alpha.TARGET_PDF, self.device.files)
        self.assertFalse(self.active.exists())
        self.assertTrue(self.authority.retired_path.exists())
        self.assertEqual(
            recovery.ACTIVE_JOURNAL_SHA256,
            recovery._sha(self.authority.retired_path.read_bytes()))

    def test_archive_revalidates_active_path_after_durable_intent(self):
        probe = self.make_recovery(True)
        original_intent = probe._intent
        displaced = self.root / "displaced-authentic-journal.jsonl"

        def intent(name, payload):
            fresh = original_intent(name, payload)
            if name == "active_journal_archive":
                self.authority.active_path.rename(displaced)
                self.authority.active_path.write_bytes(b"impostor\n")
            return fresh

        probe._intent = intent
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "changed before archive dispatch"):
            probe.execute()
        self.assertEqual(b"impostor\n", self.authority.active_path.read_bytes())
        self.assertTrue(displaced.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertEqual(("1", "2"), self.device.rotation)

    def test_target_drift_rejected_before_any_mutation(self):
        self.device.files[alpha.TARGET_PDF] = replace(
            recovery.PINNED_TARGET_PDF, inode=999999)
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "absent or changed"):
            self.make_recovery(True).execute()
        self.assertEqual([], self.device.history)

    def test_missing_initial_target_rejected_before_journal_or_mutation(self):
        self.device.files.pop(alpha.TARGET_MARK)
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "absent or changed"):
            self.make_recovery(False).plan()
        self.assertEqual([], self.device.history)
        self.assertTrue(self.active.exists())
        self.assertFalse(self.authority.recovery_path.exists())

    def test_initial_quarantine_rejected_before_journal_or_mutation(self):
        retained = self.device.files[alpha.TARGET_MARK]
        self.device.files[recovery.QUARANTINE_MARK] = replace(
            retained, path=recovery.QUARANTINE_MARK)
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "quarantine leaf is already occupied"):
            self.make_recovery(False).plan()
        self.assertEqual([], self.device.history)
        self.assertTrue(self.active.exists())
        self.assertFalse(self.authority.recovery_path.exists())

    def test_source_drift_rejected_before_any_mutation(self):
        self.device.files[alpha.SOURCE_MARK] = replace(
            recovery.PINNED_SOURCE_MARK, size=999)
        with self.assertRaisesRegex(recovery.RecoveryError, "static"):
            self.make_recovery(True).execute()
        self.assertEqual([], self.device.history)

    def test_rotation_drift_rejected_before_any_mutation(self):
        self.device.rotation = ("0", "0")
        with self.assertRaisesRegex(recovery.RecoveryError, "rotation"):
            self.make_recovery(True).execute()
        self.assertEqual([], self.device.history)

    def test_host_task_remove_transport_loss_is_settled_not_retried(self):
        self.device.fail_after.add("remove_host_task")
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item["operation"] == "remove_host_task"
                                for item in self.device.history))
        outcome = [item for item in result["dispatchOutcomes"]
                   if item["name"] == "released_host_task_remove"]
        self.assertEqual("TRANSPORT_UNCERTAIN", outcome[0]["mode"])
        self.assertFalse(outcome[0]["retryAllowed"])
        self.assertIn(
            "released_host_task_remove_dispatch_outcome",
            self.authority.recovery_path.read_text(encoding="ascii"))

    def test_authoritative_mutation_failures_never_settle_as_success(self):
        scenarios = (
            ("remove_host_task", ["remove_host_task"]),
            ("launch", ["remove_host_task", "launch_parking"]),
            ("remove_task",
             ["remove_host_task", "launch_parking", "remove_task"]),
            ("move_.mark",
             ["remove_host_task", "launch_parking", "remove_task", "move"]),
            ("delete_mark",
             ["remove_host_task", "launch_parking", "remove_task", "move",
              "delete"]),
        )
        for name, expected in scenarios:
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                self.device.semantic_after.add(name)
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "authoritative semantic failure"):
                    self.make_recovery(True).execute()
                self.assertEqual(
                    expected,
                    [item["operation"] for item in self.device.history])
                raw = self.authority.recovery_path.read_text(encoding="ascii")
                self.assertIn("semantic_failure", raw)

    def test_completed_bad_receipts_are_fatal_after_observed_side_effect(self):
        scenarios = ("host", "launch", "parking")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.tearDown()
                self.setUp()
                if scenario == "launch":
                    original = self.device.launch_parking

                    def launch_bad():
                        result = original()
                        return replace(result, returncode=1,
                                       stderr=b"Error: launch failed\n")

                    self.device.launch_parking = launch_bad
                else:
                    original = self.device.remove_task

                    def remove_bad(task_id, which=scenario):
                        result = original(task_id)
                        if ((which == "host" and
                             task_id == recovery.HOST_TASK_ID) or
                                (which == "parking" and
                                 task_id == self.device.parking_task_id)):
                            return replace(result, returncode=1,
                                           stderr=b"Error: remove failed\n")
                        return result

                    self.device.remove_task = remove_bad
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "nonzero status"):
                    self.make_recovery(True).execute()
                operations = [item["operation"] for item in self.device.history]
                if scenario == "host":
                    self.assertEqual(["remove_host_task"], operations)
                elif scenario == "launch":
                    self.assertEqual(
                        ["remove_host_task", "launch_parking"], operations)
                else:
                    self.assertEqual(
                        ["remove_host_task", "launch_parking", "remove_task"],
                        operations)

    def test_mutation_receipts_use_closed_operation_specific_grammar(self):
        valid_launch = self.device.launch_parking()
        recovery._validate_mutation_result(
            valid_launch, "launch_parking_document")
        bad = (
            replace(valid_launch, stdout=b"Killed\r\n"),
            replace(valid_launch, stdout=b"garbage\r\n"),
            replace(valid_launch, stderr=b"warning\n"),
            replace(valid_launch, returncode=1),
        )
        for result in bad:
            with self.subTest(result=result), self.assertRaises(
                    recovery.RecoveryError):
                recovery._validate_mutation_result(
                    result, "launch_parking_document")
        valid_remove = alpha.CommandResult(
            "remove_exact_task", (), 0, b"", b"")
        recovery._validate_mutation_result(valid_remove, "remove_exact_task")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "unexpected protocol receipt"):
            recovery._validate_mutation_result(
                replace(valid_remove, stdout=b"removed\n"),
                "remove_exact_task")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "invalid receipt object"):
            recovery._validate_mutation_result(None, "remove_exact_task")

    def test_only_exact_timeout_maps_to_uncertain_mutation_channel(self):
        device = object.__new__(recovery.RecoveryNomad)
        operation = "remove_exact_task"

        def timed_out():
            raise alpha.AlphaError(
                operation + " timed out; side effect is uncertain")

        with self.assertRaises(recovery.MutationTransportUncertain):
            device._authoritative_mutation_reply(operation, timed_out)

        def semantic():
            raise alpha.AlphaError(operation + " failed (1): denied")

        with self.assertRaises(alpha.AlphaError) as context:
            device._authoritative_mutation_reply(operation, semantic)
        self.assertNotIsInstance(
            context.exception, recovery.MutationTransportUncertain)

    def _assert_host_mutation_blocks_remove(self, mutation, message):
        probe = self.make_recovery(True)
        original_intent = probe._intent
        mutated = False

        def intent(name, payload):
            nonlocal mutated
            fresh = original_intent(name, payload)
            if name == "released_host_task_remove":
                mutation()
                mutated = True
            return fresh

        probe._intent = intent
        with self.assertRaisesRegex(recovery.RecoveryError, message):
            probe.execute()
        self.assertTrue(mutated)
        self.assertEqual(
            0, sum(item["operation"] == "remove_host_task"
                   for item in self.device.history))

    def test_disappeared_released_host_task_is_not_removed(self):
        self._assert_host_mutation_blocks_remove(
            lambda: setattr(self.device, "host_scope_live", False),
            "root task|stack|absent")

    def test_same_id_reused_host_task_is_not_removed(self):
        self._assert_host_mutation_blocks_remove(
            lambda: setattr(self.device, "host_activity_token", "abc1234"),
            "changed before removal")

    def test_additional_host_task_fails_plan_before_mutation(self):
        self.device.extra_host_task = True
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "additional.*host task scope"):
            self.make_recovery(False).plan()
        self.assertEqual([], self.device.history)
        self.assertFalse(self.authority.recovery_path.exists())

    def test_second_unrelated_task_in_host_stack_fails_plan(self):
        self.device.extra_same_stack_other_task = True
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "one exact child task"):
            self.make_recovery(False).plan()
        self.assertEqual([], self.device.history)
        self.assertFalse(self.authority.recovery_path.exists())

    def test_additional_host_task_before_dispatch_is_not_removed(self):
        self._assert_host_mutation_blocks_remove(
            lambda: setattr(self.device, "extra_host_task", True),
            "additional.*host task scope")

    def test_changed_terminal_lifecycle_before_dispatch_is_not_removed(self):
        self._assert_host_mutation_blocks_remove(
            lambda: setattr(
                self.device, "logs",
                self.device.logs.replace(
                    "emergencyDestroyContent=true",
                    "emergencyDestroyContent=false")),
            "failure semantics differ")

    def test_host_raw_hash_drift_is_evidence_not_stable_identity(self):
        original = self.device.absence_raw
        counter = 0

        def absence_raw():
            nonlocal counter
            raw = original()
            if self.device.host_scope_live:
                counter += 1
                raw = (raw[0] +
                       (f"    mDiagnosticSequence={counter}\n").encode("ascii"),
                       raw[1], raw[2])
            return raw

        self.device.absence_raw = absence_raw
        result = self.make_recovery().plan()
        self.assertEqual("PLAN_READY", result["result"])
        hashes = [item["activitiesSha256"]
                  for item in result["hostTaskObservations"]]
        self.assertEqual(2, len(set(hashes)))

    def test_cached_host_process_after_task_release_is_safe(self):
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        cached = [proof for proof in result["proofs"]
                  if proof["kind"] == "host_runtime_after_task_release"]
        self.assertTrue(cached)
        self.assertTrue(all(
            observation["mode"] == "CACHED_PROCESS_ONLY"
            for proof in cached
            for observation in proof["processObservations"]))
        self.assertTrue(all(not proof["processCleanupRequired"]
                            for proof in cached))

    def test_cached_host_process_may_disappear_monotonically(self):
        self.device.host_scope_live = False
        samples = iter(((recovery.HOST_PID,), ()))
        original = self.device.pidof

        def pidof(package):
            if package == alpha.HOST_PACKAGE:
                return next(samples)
            return original(package)

        self.device.pidof = pidof
        result = self.make_recovery(False)._host_absent_twice()
        self.assertEqual(
            ["CACHED_PROCESS_ONLY", "PROCESS_ABSENT"],
            [sample["mode"] for sample in result["processObservations"]])

    def test_cached_process_exit_between_pid_and_identity_is_reconciled(self):
        self.device.host_scope_live = False
        pid_samples = iter(((recovery.HOST_PID,), (), ()))
        original_pidof = self.device.pidof

        def pidof(package):
            if package == alpha.HOST_PACKAGE:
                return next(pid_samples)
            return original_pidof(package)

        self.device.pidof = pidof
        original_identity = self.device.process_identity

        def process_identity(pid, package):
            if package == alpha.HOST_PACKAGE:
                raise recovery.RecoveryError("process exited")
            return original_identity(pid, package)

        self.device.process_identity = process_identity
        result = self.make_recovery(False)._host_absent_twice()
        self.assertEqual(
            ["PROCESS_ABSENT", "PROCESS_ABSENT"],
            [sample["mode"] for sample in result["processObservations"]])

    def test_absent_host_process_must_not_reappear(self):
        self.device.host_scope_live = False
        samples = iter(((), (recovery.HOST_PID,)))
        original = self.device.pidof

        def pidof(package):
            if package == alpha.HOST_PACKAGE:
                return next(samples)
            return original(package)

        self.device.pidof = pidof
        with self.assertRaisesRegex(recovery.RecoveryError, "reappeared"):
            self.make_recovery(False)._host_absent_twice()

    def test_post_remove_process_proof_rejects_wrong_pid_or_identity(self):
        for wrong_pid, wrong_start in ((recovery.HOST_PID + 1, None),
                                       (recovery.HOST_PID,
                                        recovery.HOST_START_TICKS + 1)):
            with self.subTest(wrong_pid=wrong_pid, wrong_start=wrong_start):
                device = FakeDevice()
                device.host_scope_live = False
                device.pidof = lambda package, pid=wrong_pid: (
                    (pid,) if package == alpha.HOST_PACKAGE
                    else (recovery.DOCUMENT_PID,))
                if wrong_start is not None:
                    original = device.process_identity

                    def process_identity(pid, package, start=wrong_start):
                        if package == alpha.HOST_PACKAGE:
                            return host.ProcessIdentity(
                                recovery.HOST_PID, start, recovery.HOST_UID,
                                alpha.HOST_PACKAGE)
                        return original(pid, package)

                    device.process_identity = process_identity
                probe = recovery.Recovery(device, self.authority,
                                          sleep=lambda _: None)
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "process set changed|process identity changed"):
                    probe._host_absent_twice()

    def test_host_removal_waits_for_two_real_scope_absences(self):
        self.device.post_remove_host_scope_reads = 3
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        proofs = [proof for proof in result["proofs"]
                  if proof["kind"] == "host_and_foreign_absence"]
        self.assertTrue(proofs)
        self.assertEqual(2, len(proofs[0]["observations"]))

    def test_exact_stale_host_supervisor_ghost_is_accepted(self):
        self.device.host_supervisor_ghost = True
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item["operation"] == "remove_host_task"
                                for item in self.device.history))

    def test_altered_stale_host_supervisor_ghost_is_rejected(self):
        self.device.host_supervisor_ghost = True
        self.device.alter_host_supervisor_ghost = True
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "task/window absence was not proved twice"):
            self.make_recovery(True).execute()
        self.assertEqual(["remove_host_task"],
                         [item["operation"] for item in self.device.history])

    def test_host_then_document_supervisor_ghosts_complete_full_execute(self):
        self.device.host_supervisor_ghost = True
        self.device.parking_supervisor_ghost = True
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertFalse(self.active.exists())

    def test_host_remove_receipt_does_not_authorize_persistent_scope(self):
        self.device.post_remove_host_scope_reads = recovery.POLL_LIMIT + 10
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "task/window absence was not proved twice"):
            self.make_recovery(True).execute()
        self.assertEqual(["remove_host_task"],
                         [item["operation"] for item in self.device.history])

    def test_launch_transport_loss_is_settled_not_retried(self):
        self.device.fail_after.add("launch")
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item["operation"] == "launch_parking"
                                for item in self.device.history))
        outcome = [item for item in result["dispatchOutcomes"]
                   if item["name"] == "parking_launch"]
        self.assertEqual("TRANSPORT_UNCERTAIN", outcome[0]["mode"])

    def test_changed_document_process_is_rejected_before_task_remove(self):
        original = self.device.process_identity

        def process_identity(pid, package):
            value = original(pid, package)
            if package == alpha.DOCUMENT_PACKAGE and self.device.task_live:
                return replace(value, start_ticks=value.start_ticks + 1)
            return value

        self.device.process_identity = process_identity
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "stock Document process"):
            self.make_recovery(True).execute()
        self.assertTrue(self.device.task_live)
        self.assertEqual(0, sum(item["operation"] == "remove_task"
                                for item in self.device.history))

    def test_task_remove_transport_loss_is_settled_not_retried(self):
        self.device.fail_after.add("remove_task")
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item["operation"] == "remove_task"
                                for item in self.device.history))
        outcome = [item for item in result["dispatchOutcomes"]
                   if item["name"] == "parking_task_remove"]
        self.assertEqual("TRANSPORT_UNCERTAIN", outcome[0]["mode"])

    def test_parking_raw_hash_drift_does_not_fake_identity_reuse(self):
        self.device.vary_parking_raw_hash = True
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertGreaterEqual(self.device.parking_capture_count, 2)
        self.assertEqual(1, sum(item["operation"] == "remove_task"
                                for item in self.device.history))

    def test_exact_stale_parking_supervisor_ghost_is_accepted(self):
        self.device.parking_supervisor_ghost = True
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        proofs = [item for item in result["proofs"]
                  if item["kind"] == "post_parking_task_absence"]
        self.assertEqual(1, len(proofs))
        self.assertEqual(self.device.parking_task_id,
                         proofs[0]["retainedTaskId"])

    def test_parking_removal_waits_for_two_consecutive_absences(self):
        self.device.post_remove_parking_scope_reads = 3
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item["operation"] == "remove_task"
                                for item in self.device.history))
        proof = [item for item in result["proofs"]
                 if item["kind"] == "post_parking_task_absence"][-1]
        self.assertEqual(2, len(proof["observations"]))

    def test_parking_removal_tolerates_one_malformed_teardown_sample(self):
        self.device.post_remove_parking_malformed_reads = 1
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item["operation"] == "remove_task"
                                for item in self.device.history))

    def test_parking_removal_never_retries_when_scope_persists(self):
        self.device.post_remove_parking_scope_reads = recovery.POLL_LIMIT + 5
        with self.assertRaisesRegex(
                recovery.RecoveryError,
                "post-parking task/window absence was not proved twice"):
            self.make_recovery(True).execute()
        self.assertEqual(1, sum(item["operation"] == "remove_task"
                                for item in self.device.history))
        self.assertFalse(any(item["operation"] in {"move", "delete"}
                             for item in self.device.history))

    def test_altered_stale_parking_supervisor_ghost_is_rejected(self):
        self.device.parking_supervisor_ghost = True
        original = self.device._parking_supervisor_activity

        def altered():
            return original().replace(
                self.device.parking_activity_token.encode("ascii"),
                b"deadbee", 1)

        self.device._parking_supervisor_activity = altered
        with self.assertRaisesRegex(
                recovery.RecoveryError,
                "exact or recreated Document task/window"):
            self.make_recovery(True).execute()
        self.assertEqual(1, sum(item["operation"] == "remove_task"
                                for item in self.device.history))
        self.assertFalse(any(item["operation"] in {"move", "delete"}
                             for item in self.device.history))

    def test_same_content_mark_inode_replacement_is_adopted_once(self):
        self.device.mark_replacement_on_launch = {"inode": 999999}
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        adoption = [item for item in result["proofs"]
                    if item["kind"] ==
                    "target_mark_recreated_or_replaced_at_parking"]
        self.assertEqual(1, len(adoption))
        self.assertEqual(recovery.PINNED_TARGET_MARK.inode,
                         adoption[0]["previousInode"])
        self.assertEqual(999999, adoption[0]["currentInode"])

    def test_ineligible_mark_replacement_cleans_task_then_fails_before_delete(self):
        mutations = (
            {"inode": 999999, "sha256": "0" * 64},
            {"inode": 999999, "uid": 10089},
            {"inode": 999999, "device": 55},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.tearDown()
                self.setUp()
                self.device.mark_replacement_on_launch = mutation
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "safely removed.*mark authority was rejected"):
                    self.make_recovery(True).execute()
                operations = [item["operation"] for item in self.device.history]
                self.assertIn("remove_task", operations)
                self.assertNotIn("move", operations)
                self.assertNotIn("delete", operations)
                self.assertFalse(self.device.task_live)
                self.assertTrue(self.active.exists())

    def test_second_mark_replacement_at_task_removal_is_rejected(self):
        self.device.mark_replacement_on_launch = {"inode": 999999}
        self.device.mark_replacement_on_remove = {"inode": 999998}
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "changed more than once"):
            self.make_recovery(True).execute()
        self.assertFalse(self.device.task_live)
        self.assertFalse(any(item["operation"] in {"move", "delete"}
                             for item in self.device.history))

    def _assert_parking_mutation_blocks_remove(self, mutation, message):
        original = self.device.rotation_settings
        mutated = False

        def rotation_settings():
            nonlocal mutated
            if self.device.task_live and not mutated:
                mutation()
                mutated = True
            return original()

        self.device.rotation_settings = rotation_settings
        with self.assertRaisesRegex(recovery.RecoveryError, message):
            self.make_recovery(True).execute()
        self.assertTrue(mutated)
        self.assertEqual(
            0, sum(item["operation"] == "remove_task"
                   for item in self.device.history))

    def test_disappeared_parking_task_is_not_removed_by_stale_id(self):
        self._assert_parking_mutation_blocks_remove(
            lambda: setattr(self.device, "task_live", False),
            "disappeared before removal")

    def test_swapped_parking_task_is_not_removed_by_stale_id(self):
        self._assert_parking_mutation_blocks_remove(
            lambda: setattr(self.device, "parking_task_id", 7002),
            "changed before removal")

    def test_reused_parking_task_id_is_not_removed(self):
        self._assert_parking_mutation_blocks_remove(
            lambda: setattr(self.device, "parking_authority_sha256", "c" * 64),
            "aliases disagree|changed before removal")

    def test_parking_semantic_ui_drift_blocks_numeric_remove(self):
        self._assert_parking_mutation_blocks_remove(
            lambda: setattr(self.device, "parking_ui_bounds", [1, 0, 401, 100]),
            "changed before removal")

    def test_package_wide_document_scope_parser_rejects_extras(self):
        process = self.device.process_identity(
            recovery.DOCUMENT_PID, alpha.DOCUMENT_PACKAGE)
        authority = self.device._parking_authority("b" * 64)
        accepted = recovery._assert_sole_document_scope(
            self.device._parking_activity_wire(),
            self.device._parking_window_wire(), authority, process)
        self.assertTrue(accepted["stable"]["oneChildRootTask"])
        for activity, windows, message in (
                (self.device._parking_activity_wire(extra_task=True),
                 self.device._parking_window_wire(), "Document task scope"),
                (self.device._parking_activity_wire(
                    extra_task=True, same_stack=True),
                 self.device._parking_window_wire(), "Document task scope|child task"),
                (self.device._parking_activity_wire(),
                 self.device._parking_window_wire(extra_window=True),
                 "exactly one window")):
            with self.subTest(message=message):
                with self.assertRaisesRegex(recovery.RecoveryError, message):
                    recovery._assert_sole_document_scope(
                        activity, windows, authority, process)

    def test_extra_document_scope_never_dispatches_parking_remove(self):
        for field in ("extra_document_task", "extra_document_window"):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                setattr(self.device, field, True)
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "did not settle exactly"):
                    self.make_recovery(True).execute()
                self.assertEqual(0, sum(
                    item["operation"] == "remove_task"
                    for item in self.device.history))

    def test_extra_document_scope_on_immediate_reauth_blocks_remove(self):
        for field in ("extra_document_task", "extra_document_window"):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                self._assert_parking_mutation_blocks_remove(
                    lambda name=field: setattr(self.device, name, True),
                    "disappeared before removal")

    def test_delete_transport_loss_is_settled_not_retried(self):
        self.device.fail_after.add("delete_mark")
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item.get("path") == recovery.QUARANTINE_MARK
                                for item in self.device.history))
        outcome = [item for item in result["dispatchOutcomes"]
                   if item["name"] == "mark_quarantine_delete"]
        self.assertEqual("TRANSPORT_UNCERTAIN", outcome[0]["mode"])

    def test_move_transport_loss_is_settled_not_retried(self):
        self.device.fail_after.add("move_.mark")
        result = self.make_recovery(True).execute()
        self.assertEqual("RECOVERED_CLEANLY", result["result"])
        self.assertEqual(1, sum(item.get("source") == alpha.TARGET_MARK
                                for item in self.device.history))
        outcome = [item for item in result["dispatchOutcomes"]
                   if item["name"] == "mark_quarantine_move"]
        self.assertEqual("TRANSPORT_UNCERTAIN", outcome[0]["mode"])

    def test_final_joint_absence_rejects_recreated_mark(self):
        self.device.recreate_mark_during_pdf_delete = True
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "joint disposable-file absence"):
            self.make_recovery(True).execute()
        self.assertIn(alpha.TARGET_MARK, self.device.files)
        self.assertTrue(self.active.exists())
        self.assertFalse(self.authority.retired_path.exists())

    def test_uncertain_move_without_postcondition_never_retries(self):
        self.device.fail_before.add("move_.mark")
        session = self.make_recovery(True)
        with self.assertRaisesRegex(recovery.RecoveryError, "remains present"):
            session.execute()
        first_count = len(self.device.history)
        with self.assertRaisesRegex(recovery.RecoveryError, "remains present"):
            session._quarantine_delete(alpha.TARGET_MARK)
        self.assertEqual(first_count, len(self.device.history))

    def test_wrong_initial_descriptor_domain_fails_plan(self):
        self.device.fd_targets.add("/storage/emulated/0/Document/user.pdf")
        with self.assertRaisesRegex(recovery.RecoveryError, "descriptors differ"):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)

    def test_document_task_presence_fails_plan(self):
        self.device.task_live = True
        with self.assertRaisesRegex(recovery.RecoveryError, "still present"):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)

    def test_wrong_host_process_fails_plan(self):
        original = self.device.process_identity

        def wrong(pid, package):
            value = original(pid, package)
            return replace(value, start_ticks=value.start_ticks + 1)

        self.device.process_identity = wrong
        with self.assertRaisesRegex(recovery.RecoveryError, "host process"):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)

    def test_quarantine_without_durable_intent_is_rejected(self):
        retained = self.device.files.pop(alpha.TARGET_MARK)
        self.device.files[recovery.QUARANTINE_MARK] = replace(
            retained, path=recovery.QUARANTINE_MARK)
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "absent or changed"):
            self.make_recovery(True).execute()

    def test_unjournalled_target_disappearance_is_not_adopted(self):
        session = self.make_recovery(True)
        self.device.files.pop(alpha.TARGET_MARK)
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "without its durable delete intent"):
            session._quarantine_delete(alpha.TARGET_MARK)
        self.assertEqual([], self.device.history)

    def test_journal_rejects_duplicate_one_shot_record(self):
        session = self.make_recovery(True)
        assert session.journal is not None
        session.journal.append("released_host_task_remove_intent", {"x": 1})
        session.journal.append("released_host_task_remove_intent", {"x": 1})
        with self.assertRaisesRegex(recovery.RecoveryError, "repeats"):
            session.journal.one("released_host_task_remove_intent")

    def test_recovery_journal_is_an_exclusive_execute_barrier(self):
        path = self.run_dir / "exclusive.jsonl"
        header = {"authority": recovery.AUTHORITY, "nonce": "one-shot"}
        first = recovery.Journal(path, header)
        self.open_journals.append(first)
        self.assertEqual(1, len(first.records))
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "concurrent or resumed"):
            recovery.Journal(path, header)

    def test_recovery_journal_byte_tamper_blocks_first_device_mutation(self):
        probe = self.make_recovery(True)
        self.authority.recovery_path.write_bytes(b"REPLACEMENT\n")
        with self.assertRaisesRegex(
                recovery.RecoveryError,
                "descriptor identity changed|bytes or hash chain changed"):
            probe.execute()
        self.assertEqual([], self.device.history)

    def test_journal_tamper_after_intent_blocks_immediate_dispatch(self):
        probe = self.make_recovery(True)
        original = probe._capture_host_task
        captures = 0

        def capture():
            nonlocal captures
            result = original()
            captures += 1
            if captures == 3:
                self.authority.recovery_path.write_bytes(b"AFTER-INTENT\n")
            return result

        probe._capture_host_task = capture
        with self.assertRaisesRegex(
                recovery.RecoveryError,
                "descriptor identity changed|bytes or hash chain changed"):
            probe.execute()
        self.assertEqual(3, captures)
        self.assertEqual([], self.device.history)

    def test_recovery_journal_hardlink_blocks_first_device_mutation(self):
        probe = self.make_recovery(True)
        alias = self.run_dir / "journal-hardlink"
        try:
            os.link(self.authority.recovery_path, alias)
        except OSError as error:
            self.skipTest("hard links unavailable: " + str(error))
        with self.assertRaisesRegex(
                recovery.RecoveryError, "descriptor identity changed"):
            probe.execute()
        self.assertEqual([], self.device.history)

    def test_recovery_journal_path_swap_blocks_first_device_mutation(self):
        probe = self.make_recovery(True)
        displaced = self.run_dir / "journal-displaced"
        try:
            self.authority.recovery_path.rename(displaced)
        except OSError as error:
            # A retained descriptor that makes replacement impossible is an
            # equally strong platform-level outcome for this threat model.
            self.assertTrue(self.authority.recovery_path.exists())
            self.assertEqual([], self.device.history)
            self.assertIsInstance(error, OSError)
            return
        self.authority.recovery_path.write_bytes(b"IMPOSTOR\n")
        with self.assertRaisesRegex(
                recovery.RecoveryError, "path was replaced"):
            probe.execute()
        self.assertEqual([], self.device.history)

    def test_recovery_journal_symlink_path_is_rejected(self):
        probe = self.make_recovery(True)
        assert probe.journal is not None
        actual = os.lstat(self.authority.recovery_path)
        synthetic = os.stat_result((stat.S_IFLNK | 0o777, *actual[1:]))
        real_lstat = recovery.os.lstat

        def lstat(path):
            if Path(path) == self.authority.recovery_path:
                return synthetic
            return real_lstat(path)

        with mock.patch.object(recovery.os, "lstat", side_effect=lstat):
            with self.assertRaisesRegex(
                    recovery.RecoveryError, "path was replaced"):
                probe.execute()
        self.assertEqual([], self.device.history)

    def test_rotation_reads_only_two_literal_system_keys(self):
        observed = []

        def executor(argv, *, capture_output, timeout, check):
            observed.append(tuple(argv))
            value = b"1\n" if argv[-1] == "accelerometer_rotation" else b"2\n"
            return subprocess.CompletedProcess(argv, 0, value, b"")

        device = object.__new__(recovery.RecoveryNomad)
        device.adb = str(recovery.PINNED_ADB)
        device._executor = executor
        device.history = []
        self.assertEqual(("1", "2"), device.rotation_settings())
        self.assertEqual(
            [
                (device.adb, "-s", alpha.AUTHORIZED_SERIAL, "exec-out", "settings",
                 "get", "system", "accelerometer_rotation"),
                (device.adb, "-s", alpha.AUTHORIZED_SERIAL, "exec-out", "settings",
                 "get", "system", "user_rotation"),
            ], observed)
        self.assertEqual(
            ["read_rotation_accelerometer_rotation", "read_rotation_user_rotation"],
            [item["operation"] for item in device.history])

    def test_recovery_uses_separate_closed_physical_parking_launch(self):
        with self.assertRaises(alpha.AlphaError):
            alpha.parking_document_launch_argv("adb", 0)
        adb = str(recovery.PINNED_ADB)
        expected = recovery._physical_parking_launch_argv(adb)
        calls = []
        stdout = (
            "Starting: Intent { act=" + alpha.DOCUMENT_LAUNCH_ACTION +
            " dat=" + alpha.PARKING_URI + " typ=" +
            alpha.DOCUMENT_LAUNCH_MIME + " cmp=" +
            recovery.android.SHORT_COMPONENT + " }\r\n").encode("ascii")

        def executor(argv, *, capture_output, timeout, check):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        device = object.__new__(recovery.RecoveryNomad)
        device.adb = adb
        device._executor = executor
        device.history = []
        result = device.launch_parking()
        self.assertEqual([expected], calls)
        self.assertEqual(expected, result.argv)
        self.assertIn("--display 0", expected[-1])
        self.assertEqual("launch_parking_document",
                         device.history[-1]["operation"])

    def test_rotation_rejects_noncanonical_or_failed_reply(self):
        for result in (
                subprocess.CompletedProcess([], 0, b"9\n", b""),
                subprocess.CompletedProcess([], 0, b"1\r\n", b""),
                subprocess.CompletedProcess([], 0, b"1\x00\n", b""),
                subprocess.CompletedProcess([], 0, b"1\n", b"warning\n"),
                subprocess.CompletedProcess([], 1, b"", b"denied\n")):
            device = object.__new__(recovery.RecoveryNomad)
            device.adb = str(recovery.PINNED_ADB)
            device._executor = lambda *args, value=result, **kwargs: value
            device.history = []
            with self.assertRaises((recovery.RecoveryError, alpha.AlphaError)):
                device.rotation_settings()

    def test_quarantine_move_requires_exact_empty_transport_reply(self):
        source, target = alpha.TARGET_MARK, recovery.QUARANTINE_MARK

        def run(stdout, stderr=b"", returncode=0):
            observed = []
            device = object.__new__(recovery.RecoveryNomad)
            device.history = []

            def invoke(operation, tail, **kwargs):
                observed.append((operation, tuple(tail)))
                return alpha.CommandResult(operation, tuple(tail), returncode,
                                           stdout, stderr)

            device._invoke = invoke
            return device, observed

        device, observed = run(b"")
        device.move_quarantine(source, target)
        self.assertEqual("exec-out", observed[0][1][0])
        for mutated in (("mv '" + source + "'\n").encode("ascii"),
                        ("mv '" + source + "'\r\n").encode("ascii"),
                        ("mv '" + target + "'\n").encode("ascii"), b"\x00"):
            device, _ = run(mutated)
            with self.assertRaisesRegex(recovery.RecoveryError,
                                        "unexpected output"):
                device.move_quarantine(source, target)
        device, _ = run(b"", b"warning\n")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "unexpected output"):
            device.move_quarantine(source, target)

    def test_fd_inventory_rejects_empty_and_duplicate_records(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "empty"):
            recovery._validated_fd_targets("")
        line = ("lr-x------ 1 root root 64 2026-09-16 20:00 40 -> " +
                alpha.PARKING_PDF)
        with self.assertRaisesRegex(recovery.RecoveryError, "framing"):
            recovery._validated_fd_targets(line + "\n" + line + "\n")

    def test_real_multiphase_log_accepts_display_free_authority_events(self):
        selected = recovery._validate_failed_host_log(self.device.logs)
        self.assertTrue(any("HOST_AUTHORITY_SUSPENDED" in line
                            and "display=1" not in line for line in selected))
        self.assertTrue(any("TIMEOUT" in line and "display=1" not in line
                            for line in selected))

    def test_prior_foreign_ready_or_cleanup_log_is_rejected(self):
        identity = (f"session={recovery.SESSION} "
                    f"generation={recovery.GENERATION}")
        with self.assertRaisesRegex(recovery.RecoveryError, "cleanup residue"):
            recovery._validate_failed_host_log(
                self.device.logs + "READY " + identity + "\n")
        with self.assertRaisesRegex(recovery.RecoveryError, "cleanup residue"):
            recovery._validate_failed_host_log(
                self.device.logs + "EMPTY_ATTACH_ABORT " + identity + "\n")

    def test_historical_failure_cannot_authorize_a_new_host_session(self):
        self.device.logs += (
            "SESSION session=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee "
            "generation=0 readiness=WAITING_FOR_SURFACE visualOnly=true\n")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "another session identity"):
            self.make_recovery(False).plan()
        self.assertEqual([], self.device.history)


if __name__ == "__main__":
    unittest.main()
