from __future__ import annotations

from dataclasses import asdict, replace
import ast
from pathlib import Path
import shutil
import tempfile
import unittest

import continue_orientation_source_after_parking_alpha_run as second
import continue_orientation_source_alpha_run as first
import native_page_alpha_runner as alpha
import native_page_android_authority as android
import recover_orientation_source_alpha_run as prior
import test_continue_orientation_source_alpha_run as first_test
import test_native_page_android_authority as android_test
import test_recover_orientation_source_alpha_run as prior_test


class FakeDevice(first_test.FakeDevice):
    def __init__(self) -> None:
        super().__init__()
        self.host_live = False
        self.host_scope_live = False
        self.task_live = True
        self.parking_was_launched = True
        self.parking_task_id = second.PINNED_TASK_ID
        self.parking_task_token = second.PINNED_TASK_TOKEN
        self.parking_activity_token = second.PINNED_ACTIVITY_TOKEN
        self.release_on_remove = False
        self.fds_closed = False
        self.document_live = True
        self.document_token = second.PINNED_PROCESS_TOKEN
        self.extra_document_process_line = ""
        self.parking_drift = False
        self.remove_ids: list[int] = []

    def pidof(self, package):
        if package == alpha.DOCUMENT_PACKAGE:
            return ((second.PINNED_DOCUMENT_PROCESS.pid,)
                    if self.document_live else ())
        return super().pidof(package)

    def process_identity(self, pid, package):
        if package == alpha.DOCUMENT_PACKAGE:
            if not self.document_live:
                raise prior.RecoveryError("fake Document process is absent")
            return second.PINNED_DOCUMENT_PROCESS
        return super().process_identity(pid, package)

    def host_processes(self):
        raw = super().host_processes().decode("utf-8")
        raw = raw.replace("12ec554 2053:com.supernote.document/1000",
                          self.document_token +
                          " 2053:com.supernote.document/1000")
        raw = raw.replace(
            "  *APP* UID 1000 ProcessRecord{" + self.document_token +
            " 2053:com.supernote.document/1000}\n",
            "  *APP* UID 1000 ProcessRecord{" + self.document_token +
            " 2053:com.supernote.document/1000}\n"
            "    packageList={com.supernote.document}\n", 1)
        if not self.document_live:
            raw = "\n".join(
                line for line in raw.splitlines()
                if "com.supernote.document" not in line) + "\n"
        if self.extra_document_process_line:
            marker = "  Process OOM control (31 total, non-act at 4, non-svc at 4):\n"
            raw = raw.replace(marker, self.extra_document_process_line + "\n" + marker)
        return raw.encode("utf-8")

    def process_fd_links(self, pid):
        if pid == prior.HOST_PID:
            return super().process_fd_links(pid)
        system = ("lr-x------ 1 root root 64 2026-09-16 20:00 "
                  "40 -> /system/framework/framework.jar\n")
        if self.fds_closed:
            return system
        return system + "".join((
            "lr-x------ 1 root root 64 2026-09-17 01:40 44 -> " +
            alpha.TARGET_PDF + "\n",
            "lr-x------ 1 root root 64 2026-09-17 01:40 65 -> " +
            alpha.PARKING_PDF + "\n",
            "lr-x------ 1 root root 64 2026-09-16 20:40 93 -> " +
            alpha.PARKING_PDF + "\n",
        ))

    def parking_identity(self):
        task_token = ("deadbeef" if self.parking_drift else
                      second.PINNED_TASK_TOKEN)
        authority = android.DocumentTaskAuthority(
            authority=android.AUTHORITY, raw_sha256="a" * 64,
            display_id=0, stack_id=second.PINNED_TASK_ID,
            task_id=second.PINNED_TASK_ID, task_token=task_token,
            activity_token=second.PINNED_ACTIVITY_TOKEN,
            pid=second.PINNED_DOCUMENT_PROCESS.pid,
            uid=android.SYSTEM_UID, package_name=alpha.DOCUMENT_PACKAGE,
            process_name=alpha.DOCUMENT_PACKAGE,
            component=android.SHORT_COMPONENT,
            base_apk_path=alpha.DOCUMENT_APK, state="RESUMED",
            resumed=True, stopped=False, delayed_resume=False,
            finishing=False, task_visible=True, visible_requested=True,
            visible=True, client_visible=True, reported_drawn=True,
            reported_visible=True, now_visible=True,
            width=1872, height=1404, density_dpi=300, rotation=1)
        scope = {
            "taskId": second.PINNED_TASK_ID, "displayId": 0,
            "taskToken": task_token,
            "activityToken": second.PINNED_ACTIVITY_TOKEN,
            "processToken": second.PINNED_PROCESS_TOKEN,
            "windowToken": second.PINNED_WINDOW_TOKEN,
            "windowSessionToken": second.PINNED_WINDOW_SESSION_TOKEN,
            "windowComponent": android.FULL_COMPONENT,
            "pid": second.PINNED_DOCUMENT_PROCESS.pid,
            "uid": android.SYSTEM_UID, "oneChildRootTask": True,
            "solePackageWindow": True,
        }
        return {
            "process": asdict(second.PINNED_DOCUMENT_PROCESS),
            "taskId": second.PINNED_TASK_ID, "taskToken": task_token,
            "activityToken": second.PINNED_ACTIVITY_TOKEN,
            "windowToken": second.PINNED_WINDOW_TOKEN,
            "documentAuthority": asdict(authority),
            "documentScope": scope,
            "configuration": {
                "rotationLiteral": "ROTATION_90", "rotation": 1,
                "width": 1872, "height": 1404,
                "configurationSha256": "b" * 64,
            },
            "display": {"width": 1872, "height": 1404, "rotation": 1,
                        "rawSha256": "c" * 64},
            "window": {"windowToken": second.PINNED_WINDOW_TOKEN,
                       "width": 1872, "height": 1404,
                       "rawSha256": "d" * 64},
            "fdAuthority": {
                "shared": {str(key): value for key, value in
                           sorted(second.PRE_REMOVE_SHARED_FDS.items())},
                "rawSha256": "e" * 64,
            },
            "activitiesSha256": "f" * 64,
            "windowsSha256": "1" * 64,
        }

    def remove_parking_task(self, task_id):
        if task_id != second.PINNED_TASK_ID:
            raise AssertionError("wrong fake task")
        self.remove_ids.append(task_id)
        result = prior_test.FakeDevice.remove_task(self, task_id)
        if self.release_on_remove:
            self.fds_closed = True
        return result


class AfterParkingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run_dir = self.root / prior.RUN_ID
        self.run_dir.mkdir()
        self.report = self.run_dir / "report.json"
        self.report.write_bytes(b"after parking test report\n")
        source = Path(__file__).parent
        source_active = (source / "build" / "native-page-alpha-runs" /
                         alpha.ACTIVE_MUTATION_JOURNAL_FILENAME)
        self.active = self.root / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        shutil.copyfile(source_active, self.active)
        self.prior_ledger = self.run_dir / prior.RECOVERY_BASENAME
        shutil.copyfile(source / "build" / "native-page-alpha-runs" /
                        prior.RUN_ID / prior.RECOVERY_BASENAME,
                        self.prior_ledger)
        self.first_ledger = self.run_dir / first.CONTINUATION_BASENAME
        shutil.copyfile(source / "build" / "native-page-alpha-runs" /
                        prior.RUN_ID / first.CONTINUATION_BASENAME,
                        self.first_ledger)
        _, report_identity = prior._read_regular(
            self.report, 1024, "test report")
        _, active_identity = prior._read_regular(
            self.active, 256 * 1024, "test active")
        prior_raw, prior_identity = first._read_prior_ledger(self.prior_ledger)
        first_raw, first_identity = second._read_sole_regular(
            self.first_ledger, 32 * 1024, "test first ledger")
        self.dependency_paths = {}
        for name, spec in second.DEPENDENCY_SPECS.items():
            target = self.root / spec["filename"]
            shutil.copyfile(source / spec["filename"], target)
            self.dependency_paths[name] = target
        self.authority = second.Authority(
            self.root, self.run_dir, self.report, self.active,
            self.run_dir / second.JOURNAL_BASENAME,
            self.run_dir / second.EVIDENCE_BASENAME,
            self.run_dir / prior.RETIRED_BASENAME,
            report_identity, active_identity,
            self.prior_ledger, prior_identity,
            first._validate_prior_ledger(prior_raw),
            self.first_ledger, first_identity,
            second._validate_first_ledger(first_raw),
            source / "recover_orientation_source_alpha_run.py",
            source / "continue_orientation_source_alpha_run.py",
            self.dependency_paths)
        self.device = FakeDevice()
        self.journals: list[second.Journal] = []

    def tearDown(self) -> None:
        for journal in self.journals:
            journal.close()
        self.temp.cleanup()

    def make_recovery(self, execute: bool = False):
        if not execute:
            return second.Recovery(
                self.device, self.authority, sleep=lambda _: None)
        probe = second.Recovery(
            self.device, self.authority, sleep=lambda _: None)
        admission = probe.plan()
        header = probe._header()
        header["admissionSha256"] = prior._canonical_sha(admission)
        journal = second.Journal(self.authority.journal_path, header)
        self.journals.append(journal)
        recovery = second.Recovery(
            self.device, self.authority, sleep=lambda _: None,
            journal=journal, durable_header=journal.records[0]["payload"],
            prior_admission=admission)
        journal.external_guard = recovery._assert_dispatch_authority
        return recovery

    @staticmethod
    def rotation_wire(literal: str, width: int, height: int,
                      *, app_width: int | None = None,
                      duplicate: bool = False) -> bytes:
        raw = android_test.wire(
            pid=second.PINNED_DOCUMENT_PROCESS.pid,
            task_id=second.PINNED_TASK_ID)
        text = raw.decode("utf-8")
        text = (text.replace("Stack #4538", "Stack #4648")
                .replace("StackId=4538", "StackId=4648")
                .replace("stackId=4538", "stackId=4648")
                .replace(" t4538", " t4648")
                .replace("66d8263", second.PINNED_TASK_TOKEN)
                .replace("11846f4", second.PINNED_ACTIVITY_TOKEN)
                .replace("2083011", second.PINNED_PROCESS_TOKEN)
                .replace("1404, 1872", f"{width}, {height}")
                .replace("ROTATION_0", "ROTATION_" + literal))
        if app_width is not None:
            text = text.replace(
                f"mAppBounds=Rect(0, 0 - {width}, {height})",
                f"mAppBounds=Rect(0, 0 - {app_width}, {height})")
        if duplicate:
            text = text.replace(
                "} s.186}", " mRotation=ROTATION_" + literal + "} s.186}")
        tail = first_test.FakeDevice()._settled_activity().decode("utf-8")
        tail = tail[tail.index("ActivityStackSupervisor state:\n"):]
        return (text + tail).encode("utf-8")

    @classmethod
    def parking_activity_wire(
            cls, *, extra_same_root_child: bool = False,
            extra_document_task: bool = False) -> bytes:
        text = cls.rotation_wire("90", 1872, 1404).decode("utf-8")
        siblings = (
            "  Stack #1: type=home mode=fullscreen\n"
            "  Stack #3: type=standard mode=split-screen-primary\n"
            "  Stack #4: type=standard mode=split-screen-secondary\n")
        text = text.replace(
            "  Stack #4648: type=standard mode=fullscreen\n",
            siblings + "  Stack #4648: type=standard mode=fullscreen\n",
            1)
        text = text.replace(
            "      taskId=4648 stackId=4648\n",
            "      taskId=4648 stackId=4648\n"
            "      intent={act=android.intent.action.VIEW "
            f"dat={alpha.PARKING_URI} typ=application/pdf "
            "flg=0x10000000 "
            "cmp=com.supernote.document/.document.DocumentActivity}\n",
            1)
        text = text.replace(
            "          baseDir=/system_ext/app/SupernoteDocument/"
            "SupernoteDocument.apk\n",
            "          baseDir=/system_ext/app/SupernoteDocument/"
            "SupernoteDocument.apk\n"
            "          Intent { act=android.intent.action.VIEW "
            f"dat={alpha.PARKING_URI} typ=application/pdf "
            "flg=0x10000000 "
            "cmp=com.supernote.document/.document.DocumentActivity }\n",
            1)
        insert = "ActivityStackSupervisor state:\n"
        if extra_same_root_child:
            child = (
                "    * Task{7777777 #7777 visible=true type=standard "
                "mode=fullscreen translucent=false A=1000:com.example.other "
                "U=0 StackId=4648 sz=1}\n"
                "      taskId=7777 stackId=4648\n"
                "      * Hist #0: ActivityRecord{7654321 u0 "
                "com.example.other/.OtherActivity t7777}\n")
            text = text.replace(insert, child + insert, 1)
        if extra_document_task:
            child = (
                "  Stack #7002: type=standard mode=fullscreen\n"
                "    * Task{7777777 #7002 visible=true type=standard "
                "mode=fullscreen translucent=false "
                "A=1000:com.supernote.document U=0 StackId=7002 sz=1}\n"
                "      taskId=7002 stackId=7002\n"
                "      * Hist #0: ActivityRecord{7654321 u0 "
                "com.supernote.document/.OtherActivity t7002}\n")
            text = text.replace(insert, child + insert, 1)
        text = text.replace(
            "  Display: mDisplayId=0 stacks=1\n",
            "  Display: mDisplayId=0 stacks=" +
            ("5" if extra_document_task else "4") + "\n",
            1)
        return text.encode("utf-8")

    @staticmethod
    def parking_window_wire(*, extra_document_window: bool = False) -> bytes:
        extra = ""
        if extra_document_window:
            extra = (
                "  Window #2 Window{deadbeef u0 "
                "com.supernote.document/com.supernote.document.OtherActivity}:\n"
                "    mDisplayId=0 rootTaskId=7002\n")
        tail = first_test.FakeDevice()._settled_windows().decode("utf-8")
        tail = tail[tail.index("  mGlobalConfiguration="):]
        return (
            "WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
            "  Window #1 Window{a330753 u0 "
            "com.supernote.document/"
            "com.supernote.document.document.DocumentActivity}:\n"
            "    mDisplayId=0 rootTaskId=4648 "
            "mSession=Session{2bac998 2053:1000} "
            "mClient=android.os.BinderProxy@1\n"
            "    mOwnerUid=1000 showForAllUsers=false "
            "package=com.supernote.document appop=NONE\n"
            "    mActivityRecord=ActivityRecord{6f539a6 u0 "
            "com.supernote.document/.document.DocumentActivity t4648}\n"
            "    mHasSurface=true isReadyForDisplay()=true\n"
            "    display=[0,0][1872,1404]\n"
            "    mFrame=[0,0][1872,1404] last=[0,0][1872,1404]\n"
            "    isOnScreen=true\n"
            "    isVisible=true\n" + extra + tail).encode("utf-8")

    @staticmethod
    def parking_nomad(activity: bytes, windows: bytes):
        class Transport:
            def pidof(self, package):
                return ((second.PINNED_DOCUMENT_PROCESS.pid,)
                        if package == alpha.DOCUMENT_PACKAGE else ())

            def process_identity(self, pid, package):
                if (pid, package) != (
                        second.PINNED_DOCUMENT_PROCESS.pid,
                        alpha.DOCUMENT_PACKAGE):
                    raise AssertionError("unexpected process request")
                return second.PINNED_DOCUMENT_PROCESS

            def activities(self):
                return activity

            def windows(self):
                return windows

            def displays(self):
                device = first_test.FakeDevice()
                device.physical_rotation = 1
                return device._displays()

            def process_fd_links(self, pid):
                return FakeDevice().process_fd_links(pid)

        nomad = object.__new__(second.SecondNomad)
        nomad._transport = Transport()
        return nomad

    def test_plan_is_read_only_and_adopts_exact_four_record_ledger(self):
        result = self.make_recovery().plan()
        self.assertEqual("AFTER_PARKING_PLAN_READY", result["result"])
        self.assertEqual([], self.device.history)
        self.assertFalse(self.authority.journal_path.exists())
        self.assertEqual(
            second.FIRST_HEAD,
            result["parkingLaunchAdoption"]["priorDispatchRecordSha256"])
        self.assertFalse(
            result["firstContinuation"]["parkingLaunchMayRepeat"])
        self.assertTrue(all(
            observation["documentScopePresent"]
            for observation in result["hostAbsence"]["observations"]))

    def test_open_descriptors_stop_pending_without_file_mutation_or_archive(self):
        result = self.make_recovery(True).execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING", result["result"])
        self.assertEqual(["remove_task"],
                         [item["operation"] for item in self.device.history])
        self.assertEqual([second.PINNED_TASK_ID], self.device.remove_ids)
        self.assertTrue(self.active.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())
        self.assertEqual(prior.PINNED_TARGET_PDF,
                         self.device.files[alpha.TARGET_PDF])
        self.assertEqual(prior.PINNED_TARGET_MARK,
                         self.device.files[alpha.TARGET_MARK])
        kinds = [item["kind"] for item in self.journals[0].records]
        self.assertIn("descriptor_release_pending_settled", kinds)
        self.assertNotIn("mark_quarantine_move_intent", kinds)

    def test_closed_descriptors_complete_existing_cleanup_path(self):
        self.device.release_on_remove = True
        result = self.make_recovery(True).execute()
        self.assertEqual("AFTER_PARKING_RECOVERED_CLEANLY", result["result"])
        self.assertEqual(
            ["remove_task", "move", "delete", "move", "delete"],
            [item["operation"] for item in self.device.history])
        self.assertFalse(self.active.exists())
        self.assertTrue(self.authority.retired_path.exists())
        self.assertTrue(self.authority.evidence_path.exists())
        self.assertNotIn(alpha.TARGET_PDF, self.device.files)
        self.assertNotIn(alpha.TARGET_MARK, self.device.files)

    def _assert_cached_host_exit_after_header(self, boundary):
        self.device.host_live = True
        self.device.release_on_remove = True
        recovery = self.make_recovery(True)
        self.assertEqual(1, len(self.journals[0].records))

        if boundary == "identity":
            original = self.device.process_identity

            def exit_during_identity(pid, package):
                if package == alpha.HOST_PACKAGE:
                    self.device.host_live = False
                    raise prior.RecoveryError("simulated cached-host exit")
                return original(pid, package)

            self.device.process_identity = exit_during_identity
        elif boundary == "process inventory":
            original = self.device.host_processes
            injected = False

            def exit_during_process_inventory():
                nonlocal injected
                if self.device.host_live and not injected:
                    injected = True
                    self.device.host_live = False
                    raise prior.RecoveryError("simulated cached-host exit")
                return original()

            self.device.host_processes = exit_during_process_inventory
        elif boundary == "descriptor inventory":
            original = self.device.process_fd_links

            def exit_during_descriptor_inventory(pid):
                if pid == prior.HOST_PID:
                    self.device.host_live = False
                    raise prior.RecoveryError("simulated cached-host exit")
                return original(pid)

            self.device.process_fd_links = exit_during_descriptor_inventory
        elif boundary == "lifecycle log":
            original = self.device.host_logs

            def exit_during_lifecycle_log(pid):
                if pid == prior.HOST_PID:
                    self.device.host_live = False
                    raise prior.RecoveryError("simulated cached-host exit")
                return original(pid)

            self.device.host_logs = exit_during_lifecycle_log
        else:
            self.fail("unknown cached-host exit boundary")

        result = recovery.execute()
        self.assertEqual("AFTER_PARKING_RECOVERED_CLEANLY", result["result"])
        self.assertEqual(
            ["remove_task", "move", "delete", "move", "delete"],
            [item["operation"] for item in self.device.history])
        self.assertFalse(self.device.host_live)
        self.assertTrue(any(
            observation["hostProcess"]["mode"] == "PROCESS_ABSENT"
            for proof in result["proofs"]
            for observation in proof.get("observations", [])
            if isinstance(observation, dict) and "hostProcess" in observation))

    def test_cached_host_exit_during_identity_after_header_reconciles(self):
        self._assert_cached_host_exit_after_header("identity")

    def test_cached_host_exit_during_process_list_after_header_reconciles(self):
        self._assert_cached_host_exit_after_header("process inventory")

    def test_cached_host_exit_during_fd_read_after_header_reconciles(self):
        self._assert_cached_host_exit_after_header("descriptor inventory")

    def test_cached_host_exit_during_log_read_after_header_reconciles(self):
        self._assert_cached_host_exit_after_header("lifecycle log")

    def test_exact_pre_remove_fd_numbers_and_paths_are_required(self):
        valid = self.device.process_fd_links(second.PINNED_DOCUMENT_PROCESS.pid)
        self.assertEqual(
            {"44": alpha.TARGET_PDF, "65": alpha.PARKING_PDF,
             "93": alpha.PARKING_PDF},
            second._pre_remove_fd_authority(valid)["shared"])
        for changed in (
                valid.replace(" 44 ->", " 45 ->", 1),
                valid + ("lr-x------ 1 root root 64 2026-09-17 01:40 99 -> " +
                         alpha.TARGET_MARK + "\n"),
                valid + ("lr-x------ 1 root root 64 2026-09-17 01:40 99 -> "
                         "/data/local/tmp/other.pdf\n")):
            with self.assertRaises(second.ContinuationError):
                second._pre_remove_fd_authority(changed)

    def test_closed_rotation_literals_normalize_to_surface_rotation(self):
        cases = (("0", 1404, 1872, 0), ("90", 1872, 1404, 1),
                 ("180", 1404, 1872, 2), ("270", 1872, 1404, 3))
        for literal, width, height, expected in cases:
            with self.subTest(literal=literal):
                raw = self.rotation_wire(literal, width, height)
                _, config = second._selected_configuration(raw)
                self.assertEqual(expected, config["rotation"])
                authority, config2 = second._closed_document_authority(
                    raw, second.PINNED_DOCUMENT_PROCESS.pid)
                self.assertEqual(expected, authority.rotation)
                self.assertEqual((width, height),
                                 (config2["width"], config2["height"]))

    def test_live_neighbor_configuration_records_are_not_authority(self):
        raw = self.rotation_wire("90", 1872, 1404)
        current = next(
            line for line in raw.splitlines(keepends=True)
            if b"CurrentConfiguration=" in line)
        siblings = (
            "            mGlobalConfig={1.0 300dpi winConfig={ "
            "mBounds=Rect(0, 0 - 1872, 1404) "
            "mAppBounds=Rect(0, 0 - 1872, 1404) "
            "mRotation=ROTATION_90}}\n"
            "            mOverrideConfig={1.0 300dpi winConfig={ "
            "mBounds=Rect(0, 0 - 1872, 1404) "
            "mAppBounds=Rect(0, 0 - 1872, 1404) "
            "mRotation=ROTATION_90}}\n"
            "          RequestedOverrideConfiguration={0.0 ?density "
            "winConfig={ mBounds=Rect(0, 0 - 0, 0) "
            "mAppBounds=null mRotation=undefined}}\n").encode("utf-8")
        _, configuration = second._selected_configuration(
            raw.replace(current, siblings + current, 1))
        self.assertEqual(("ROTATION_90", 1, 1872, 1404), (
            configuration["rotationLiteral"], configuration["rotation"],
            configuration["width"], configuration["height"]))

    def test_rotation_alias_duplicates_and_app_bounds_mismatch_fail_closed(self):
        for literal in ("1", "2", "3", "45", "360", "undefined"):
            with self.subTest(literal=literal):
                with self.assertRaises(second.ContinuationError):
                    second._selected_configuration(
                        self.rotation_wire(literal, 1872, 1404))
        with self.assertRaises(second.ContinuationError):
            second._selected_configuration(
                self.rotation_wire("90", 1872, 1404, duplicate=True))
        with self.assertRaises(second.ContinuationError):
            second._selected_configuration(
                self.rotation_wire("90", 1872, 1404, app_width=1800))
        with self.assertRaises(second.ContinuationError):
            second._selected_configuration(
                self.rotation_wire("90", 1404, 1872))
        valid = self.rotation_wire("90", 1872, 1404)
        shifted = (
            "         CurrentConfiguration={1.0 en_US 300dpi port "
            "winConfig={ mBounds=Rect(0, 0 - 1404, 1872) "
            "mAppBounds=Rect(0, 0 - 1404, 1872) "
            "mRotation=ROTATION_0} s.186}\n").encode("utf-8")
        valid_line = next(
            line for line in valid.splitlines(keepends=True)
            if b"CurrentConfiguration=" in line)
        with self.assertRaises(second.ContinuationError):
            second._selected_configuration(
                valid.replace(valid_line, valid_line + shifted, 1))

    def test_full_parking_wire_accepts_closed_rotation_and_sibling_roots(self):
        nomad = self.parking_nomad(
            self.parking_activity_wire(), self.parking_window_wire())
        identity = nomad.parking_identity()
        self.assertEqual("ROTATION_90",
                         identity["configuration"]["rotationLiteral"])
        self.assertEqual((1872, 1404, 1), (
            identity["display"]["width"],
            identity["display"]["height"],
            identity["display"]["rotation"]))
        self.assertEqual(second.PINNED_TASK_ID, identity["taskId"])

    def test_full_parking_wire_rejects_extra_child_task_or_package_scope(self):
        cases = (
            (self.parking_activity_wire(extra_same_root_child=True),
             self.parking_window_wire()),
            (self.parking_activity_wire(extra_document_task=True),
             self.parking_window_wire()),
            (self.parking_activity_wire(),
             self.parking_window_wire(extra_document_window=True)),
        )
        for activity, windows in cases:
            with self.subTest(case=second.prior._sha(activity + windows)):
                with self.assertRaises((second.ContinuationError,
                                        prior.RecoveryError)):
                    self.parking_nomad(activity, windows).parking_identity()

    def test_full_parking_wire_rejects_shifted_contradictory_intents(self):
        activity = self.parking_activity_wire()
        root_line = next(
            line for line in activity.splitlines(keepends=True)
            if line.startswith(b"      intent={"))
        shifted_root = (
            "       intent={act=android.intent.action.VIEW "
            "dat=file:///storage/emulated/0/Download/Other.pdf "
            "typ=application/pdf flg=0x10000000 "
            "cmp=com.supernote.document/.document.DocumentActivity}\n"
        ).encode("utf-8")
        activity_line = next(
            line for line in activity.splitlines(keepends=True)
            if line.startswith(b"          Intent {"))
        shifted_activity = (
            "         Intent { act=android.intent.action.VIEW "
            "dat=file:///storage/emulated/0/Download/Other.pdf "
            "typ=application/pdf flg=0x10000000 "
            "cmp=com.supernote.document/.document.DocumentActivity }\n"
        ).encode("utf-8")
        for changed in (
                activity.replace(root_line, root_line + shifted_root, 1),
                activity.replace(
                    activity_line, activity_line + shifted_activity, 1)):
            with self.subTest(sha256=prior._sha(changed)):
                with self.assertRaises(second.ContinuationError):
                    self.parking_nomad(
                        changed, self.parking_window_wire()).parking_identity()

    def test_parking_drift_after_intent_blocks_numeric_remove(self):
        recovery = self.make_recovery(True)
        original = recovery._runtime_remove_boundary

        def drift(stable):
            self.device.parking_drift = True
            return original(stable)

        recovery._runtime_remove_boundary = drift
        with self.assertRaises(second.ContinuationError):
            recovery.execute()
        self.assertEqual([], self.device.history)

    def test_changed_or_multiple_document_process_never_authorizes_files(self):
        self.device.extra_document_process_line = (
            "  *APP* UID 1000 ProcessRecord{deadbee 2053:"
            "com.supernote.document:remote/1000}")
        result = self.make_recovery(True).execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING", result["result"])
        self.assertEqual(["remove_task"],
                         [item["operation"] for item in self.device.history])

    def test_descriptor_read_rejects_same_pid_identity_or_token_drift(self):
        recovery = self.make_recovery()
        original_identity = self.device.process_identity
        calls = 0

        def changed_identity(pid, package):
            nonlocal calls
            value = original_identity(pid, package)
            if package == alpha.DOCUMENT_PACKAGE:
                calls += 1
                if calls == 2:
                    return replace(value, start_ticks=value.start_ticks + 1)
            return value

        self.device.process_identity = changed_identity
        self.device.fds_closed = True
        observation = recovery._descriptor_observation()
        self.assertEqual(
            "PENDING_PROCESS_CHANGED_DURING_FD_READ",
            observation["state"])

        self.device.process_identity = original_identity
        self.device.document_token = second.PINNED_PROCESS_TOKEN
        original_fds = self.device.process_fd_links

        def changed_token_after_read(pid):
            value = original_fds(pid)
            self.device.document_token = "deadbee"
            return value

        self.device.process_fd_links = changed_token_after_read
        observation = recovery._descriptor_observation()
        self.assertEqual(
            "PENDING_PROCESS_CHANGED_DURING_FD_READ",
            observation["state"])

    def test_descriptor_read_error_with_remote_record_is_not_closed(self):
        recovery = self.make_recovery()

        def exit_with_malformed_record(pid):
            self.device.document_live = False
            self.device.extra_document_process_line = (
                "  *APP* UID 1000 ProcessRecord{deadbee 2053:"
                "com.supernote.document:remote/1000}")
            raise prior.RecoveryError("simulated descriptor race")

        self.device.process_fd_links = exit_with_malformed_record
        observation = recovery._descriptor_observation()
        self.assertEqual("PENDING_UNCERTAIN_PROCESS_READ",
                         observation["state"])
        self.assertTrue(
            observation["inventory"]["malformedPackageRecords"])

    def test_colocated_expected_and_remote_process_records_are_malformed(self):
        for suffix in (
                "peer=ProcessRecord{deadbee 2999:"
                "com.supernote.document:remote/1000}",
                "peer=ProcessRecord{deadbee 2999:"
                "com.supernote.document:remote/1000"):
            with self.subTest(suffix=suffix):
                self.device.fds_closed = True
                self.device.extra_document_process_line = (
                    "  *APP* UID 1000 "
                    "ProcessRecord{8081090 2053:"
                    "com.supernote.document/1000} " + suffix)
                observation = self.make_recovery()._descriptor_observation()
                self.assertNotEqual("CLOSED", observation["state"])
                self.assertEqual("PENDING_CHANGED_PROCESS_SET",
                                 observation["state"])
                self.assertTrue(
                    observation["inventory"]["malformedPackageRecords"])

    def test_alias_only_document_process_residue_is_never_closed(self):
        recovery = self.make_recovery()
        for alias in (
                "    Proc # 0: cch C/CEM --- t: 0 2999:"
                "com.supernote.document:remote/1000 (cch-empty)",
                "    #31: cch CEM 2053:com.supernote.document/1000"):
            with self.subTest(alias=alias):
                self.device.document_live = False
                self.device.extra_document_process_line = alias
                observation = recovery._descriptor_observation()
                self.assertNotEqual("CLOSED", observation["state"])
                self.assertTrue(
                    observation["inventoryBefore"]["processAliases"] or
                    observation["inventoryBefore"][
                        "malformedProcessAliases"])

    def test_noncanonical_alias_uid_or_pid_is_never_absent(self):
        recovery = self.make_recovery()
        aliases = (
            "    Proc # 0: cch C/CEM --- t: 0 2999:"
            "com.supernote.document/9999 (cch-empty)",
            "    Proc # 0: cch C/CEM --- t: 0 2999:"
            "com.supernote.document/u0a1000 (cch-empty)",
            "    Proc # 0: cch C/CEM --- t: 0 2053:"
            "com.supernote.document/1000/u0 (cch-empty)",
            "    ReceiverList{deadbeef 2053 "
            "com.supernote.document/u0a1000 remote:feedface}",
            "    Proc # 0: cch C/CEM --- t: 0 02053:"
            "com.supernote.document/1000 (cch-empty)",
            "    Proc # 0: cch C/CEM --- t: 0 0:"
            "com.supernote.document/1000 (cch-empty)",
            "    Proc # 0: cch C/CEM --- t: 0 2053:"
            "com.supernote.document:remote/1000 (cch-empty)",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                self.device.document_live = False
                self.device.extra_document_process_line = alias
                observation = recovery._descriptor_observation()
                self.assertEqual(
                    "PENDING_UNCERTAIN_PROCESS", observation["state"])
                self.assertTrue(
                    observation["inventoryBefore"][
                        "malformedProcessAliases"])
                self.assertEqual([], self.device.history)

    def test_live_receiver_alias_dialect_is_canonical(self):
        self.device.fds_closed = True
        self.device.extra_document_process_line = "\n".join(
            "    ReceiverList{" + str(index) + " 2053 "
            "com.supernote.document/1000/u0 remote:feedface}"
            for index in range(6))
        observation = self.make_recovery()._descriptor_observation()
        self.assertEqual("CLOSED", observation["state"])
        self.assertEqual(
            [{"pid": second.PINNED_DOCUMENT_PROCESS.pid,
              "processName": alpha.DOCUMENT_PACKAGE, "uid": "1000"}],
            observation["inventory"]["processAliases"])
        self.assertEqual(
            [], observation["inventory"]["malformedProcessAliases"])

    def test_activity_user_id_is_not_misread_as_process_pid(self):
        self.device.document_live = False
        self.device.extra_document_process_line = (
            "    ActivityRecord{6f539a6 u0 "
            "com.supernote.document/.document.DocumentActivity t4648}")
        observation = self.make_recovery()._descriptor_observation()
        self.assertEqual("CLOSED", observation["state"])
        self.assertEqual(
            [], observation["inventory"]["malformedProcessAliases"])
        self.assertEqual([], self.device.history)

    def test_alias_only_process_after_remove_never_authorizes_files(self):
        self.device.release_on_remove = True
        original_remove = self.device.remove_parking_task

        def remove_then_leave_noncanonical_alias(task_id):
            result = original_remove(task_id)
            self.device.document_live = False
            self.device.extra_document_process_line = (
                "    Proc # 0: cch C/CEM --- t: 0 2999:"
                "com.supernote.document/9999 (cch-empty)")
            return result

        self.device.remove_parking_task = remove_then_leave_noncanonical_alias
        result = self.make_recovery(True).execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING", result["result"])
        self.assertEqual(
            ["remove_task"],
            [item["operation"] for item in self.device.history])
        self.assertTrue(self.active.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())
        self.assertIn(alpha.TARGET_PDF, self.device.files)
        self.assertIn(alpha.TARGET_MARK, self.device.files)

    def test_global_process_owning_document_package_is_never_closed(self):
        for kind in ("APP", "PERS"):
            with self.subTest(kind=kind):
                self.device.document_live = False
                self.device.extra_document_process_line = (
                    "  *" + kind + "* UID 1000 "
                    "ProcessRecord{deadbee 2999:"
                    "com.ratta.sharedreader/1000}\n"
                    "    pid=2999 starting=false\n"
                    "    packageList={com.supernote.document}")
                observation = self.make_recovery()._descriptor_observation()
                self.assertNotEqual("CLOSED", observation["state"])
                self.assertEqual(
                    [{"token": "deadbee", "pid": 2999,
                      "processName": "com.ratta.sharedreader",
                      "uid": "1000"}],
                    observation["inventoryBefore"]["packageOwners"])

    def test_noncanonical_document_package_list_is_never_ignored(self):
        self.device.fds_closed = True
        for package_list in (
                "com.other,com.supernote.document",
                "com.other,  com.supernote.document",
                "com.other , com.supernote.document"):
            with self.subTest(package_list=package_list):
                self.device.extra_document_process_line = (
                    "  *PERS* UID 1000 ProcessRecord{deadbee 2999:"
                    "com.ratta.sharedreader/1000}\n"
                    "    pid=2999 starting=false\n"
                    "    packageList={" + package_list + "}")
                observation = self.make_recovery()._descriptor_observation()
                self.assertNotEqual("CLOSED", observation["state"])
                self.assertTrue(
                    observation["inventory"]["malformedPackageOwners"])

    def test_document_package_owner_header_uid_is_cross_bound(self):
        self.device.fds_closed = True
        original = self.device.host_processes

        def conflicting_uid():
            return original().replace(
                b"*APP* UID 1000 ProcessRecord{8081090 2053:",
                b"*APP* UID 9999 ProcessRecord{8081090 2053:", 1)

        self.device.host_processes = conflicting_uid
        observation = self.make_recovery()._descriptor_observation()
        self.assertNotEqual("CLOSED", observation["state"])
        self.assertTrue(
            observation["inventory"]["malformedPackageOwners"])

    def test_malformed_process_header_still_delimits_package_owner(self):
        for header in (
                "  *PERS* BROKEN ProcessRecord{deadbee 2999:"
                "com.ratta.sharedreader/1000}",
                "   *PERS* UID 1000 ProcessRecord{deadbee 2999:"
                "com.ratta.sharedreader/1000}",
                "  mOtherProcess=ProcessRecord{deadbee 2999:"
                "com.ratta.sharedreader/1000}"):
            with self.subTest(header=header):
                self.device.fds_closed = True
                self.device.extra_document_process_line = (
                    header + "\n"
                    "    pid=2999 starting=false\n"
                    "    packageList={com.supernote.document}")
                observation = self.make_recovery()._descriptor_observation()
                self.assertNotEqual("CLOSED", observation["state"])
                self.assertTrue(
                    observation["inventory"]["malformedPackageOwners"])

    def test_document_process_uid_alias_is_not_normalized(self):
        self.device.fds_closed = True
        original = self.device.host_processes

        def alternate_uid_spelling():
            return original().replace(
                b"2053:com.supernote.document/1000",
                b"2053:com.supernote.document/u0a1000")

        self.device.host_processes = alternate_uid_spelling
        observation = self.make_recovery()._descriptor_observation()
        self.assertNotEqual("CLOSED", observation["state"])

    def test_immutable_first_ledger_tamper_blocks_plan(self):
        with self.first_ledger.open("ab") as stream:
            stream.write(b"{}\n")
        with self.assertRaises(second.ContinuationError):
            self.make_recovery().plan()
        self.assertEqual([], self.device.history)

    def test_dependency_replacement_after_admission_blocks_mutation(self):
        recovery = self.make_recovery(True)
        with self.dependency_paths["android"].open("ab") as stream:
            stream.write(b"# replaced after admission\n")
        with self.assertRaises(second.ContinuationError):
            recovery.execute()
        self.assertEqual([], self.device.history)

    def test_second_ledger_is_exclusive(self):
        recovery = self.make_recovery(True)
        with self.assertRaises(prior.RecoveryError):
            second.Journal(self.authority.journal_path, recovery._header())

    def test_source_structurally_has_no_launch_or_host_remove_api(self):
        tree = ast.parse(Path(second.__file__).read_text(encoding="utf-8"))
        names = {node.name for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertNotIn("launch_parking", names)
        self.assertNotIn("remove_host_task", names)
        calls = [node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Attribute)]
        self.assertNotIn("launch_parking", calls)
        remove_calls = []
        for function in (node for node in ast.walk(tree)
                         if isinstance(node, ast.FunctionDef)):
            if any(isinstance(node, ast.Call) and
                   isinstance(node.func, ast.Attribute) and
                   node.func.attr == "remove_task"
                   for node in ast.walk(function)):
                remove_calls.append(function.name)
        self.assertEqual(["remove_parking_task"], remove_calls)


if __name__ == "__main__":
    unittest.main()
