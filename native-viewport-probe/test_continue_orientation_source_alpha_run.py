from __future__ import annotations

from dataclasses import replace
import ast
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import native_page_alpha_runner as alpha
import recover_orientation_source_alpha_run as prior
import continue_orientation_source_alpha_run as continuation
import test_recover_orientation_source_alpha_run as prior_test


class FakeDevice(prior_test.FakeDevice):
    def __init__(self) -> None:
        super().__init__()
        self.physical_rotation = 1
        self.host_scope_live = False
        self.host_live = True
        self.host_pid_sequence: list[bool] = []
        self.host_process_token_override = None
        self.host_cached = True
        self.host_empty = True
        self.host_proc_state = 19
        self.host_process_inventory_truncated = False
        self.host_fd_target = None
        self.window_residue = continuation.PINNED_FREEZE_RESIDUE
        self.window_extra = ""
        self.window_frozen = False
        self.activity_extra = ""
        self.parking_ui_mode = "PARSED"
        self.generic_remove_called = False
        self.parking_remove_ids: list[int] = []

    def _settled_activity(self) -> bytes:
        return ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
                "Display #0 (activities from top to bottom):\n"
                "  Stack #1: type=home mode=fullscreen\n"
                "ActivityStackSupervisor state:\n"
                "  topDisplayFocusedStack=Task{dee5147 #1 visible=false "
                "type=home mode=fullscreen translucent=true ?? U=0 "
                "StackId=1 sz=1}\n"
                "  mLastOrientationSource=DefaultTaskDisplayArea@241755270\n"
                "  deepestLastOrientationSource="
                "DefaultTaskDisplayArea@241755270\n"
                "  mLastFocusedStack=Task{dee5147 #1 visible=false "
                "type=home mode=fullscreen translucent=true ?? U=0 "
                "StackId=1 sz=1}\n"
                "  Display: mDisplayId=0 stacks=1\n" +
                self.activity_extra +
                "  KeyguardController:\n"
                "    mKeyguardShowing=false\n"
                "  LockTaskController:\n"
                "    mLockTaskModeState=NONE\n"
                "  TaskOrganizerController:\n"
                "    Per windowing mode:\n"
                "      split-screen-primary:\n"
                "        ITaskOrganizer=android.os.BinderProxy@1111111\n"
                "          Task{1111111 #1 visible=true}\n"
                "      split-screen-secondary:\n"
                "        ITaskOrganizer=android.os.BinderProxy@1111111\n"
                "          Task{2222222 #2 visible=true}\n\n").encode("utf-8")

    def _displays(self):
        raw = super()._displays()
        return raw + (
            "Display Power State:\n"
            "Photonic Modulator State:\n"
            "Color Fade State:\n"
            "Automatic Brightness Controller Configuration:\n"
            "Automatic Brightness Controller State:\n"
            "SimpleMappingStrategy\n"
            "BrightnessTracker state:\n"
            "PersistentDataStore\n"
            "  mLoaded=true\n"
            "  mDirty=false\n"
            "  RememberedWifiDisplays:\n"
            "  DisplayStates:\n"
            "  StableDeviceValues:\n"
            "      StableDisplayWidth=1404\n"
            "      StableDisplayHeight=1872\n"
            "  BrightnessConfigurations:\n").encode("ascii")

    def _settled_windows(self) -> bytes:
        residue = "" if self.window_residue is None else self.window_residue + "\n"
        frozen = "true" if self.window_frozen else "false"
        return ("WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
                "  Window #0 Window{82b4189 u0 "
                "com.ratta.supernote.background/"
                "com.ratta.supernote.background.MainActivity}:\n"
                "    mDisplayId=0 rootTaskId=1\n"
                "  mGlobalConfiguration={landscape exact fake}\n" +
                residue + self.window_extra +
                "  mDisplayFrozen=" + frozen +
                " windows=0 client=false apps=0  mRotation=1  "
                "mLastOrientation=-1\n"
                " waitingForConfig=false\n"
                "  Animation settings: disabled=false window=1.0 "
                "transition=1.0 animator=1.0\n"
                "  PolicyControl.sImmersiveStatusFilter=null\n"
                "  PolicyControl.sImmersiveNavigationFilter=null\n"
                "  PolicyControl.sImmersivePreconfirmationsFilter=null\n").encode(
                    "utf-8")

    def absence_raw(self):
        if self.task_live:
            boundary = b"ActivityStackSupervisor state:\n"
            activity_tail = self._settled_activity().split(boundary, 1)[1]
            activity = self._parking_activity_wire() + boundary + activity_tail
            window_tail = self._settled_windows()
            window_tail = window_tail[window_tail.index(
                b"  mGlobalConfiguration="):]
            windows = self._parking_window_wire().replace(
                b"7171c1d", b"8181818") + window_tail
            return activity, windows, self._displays()
        raw = super().absence_raw()
        activity = raw[0]
        if activity in {b"no activity tasks\n", b"no activity tasks\r\n"}:
            activity = self._settled_activity()
        elif (activity.startswith(
                b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n")
              and b"  KeyguardController:\n" not in activity):
            complete = self._settled_activity()
            activity += complete[complete.index(b"  KeyguardController:\n"):]
        windows = self._settled_windows()
        return activity, windows, raw[2]

    def pidof(self, package):
        if package == alpha.HOST_PACKAGE and self.host_pid_sequence:
            live = self.host_pid_sequence.pop(0)
            self.host_live = live
        return super().pidof(package)

    def process_identity(self, pid, package):
        value = super().process_identity(pid, package)
        if (package == alpha.HOST_PACKAGE and
                self.host_process_token_override == "start"):
            return replace(value, start_ticks=value.start_ticks + 1)
        return value

    def host_processes(self):
        if self.host_process_inventory_truncated:
            return b"cached=true empty=true\n"
        token = (self.host_process_token_override
                 if self.host_process_token_override not in (None, "start")
                 else self.host_process_token)
        cached = "true" if self.host_cached else "false"
        empty = "true" if self.host_empty else "false"
        state = self.host_proc_state
        host_record = ""
        host_oom = ""
        host_lru = ""
        host_pid = ""
        if self.host_live:
            host_record = (
                f"  *APP* UID 10142 ProcessRecord{{{token} 18691:"
                f"{alpha.HOST_PACKAGE}/u0a142}}\n"
                "    user #0 uid=10142 gids={50142, 20142, 9997}\n"
                f"    packageList={{{alpha.HOST_PACKAGE}}}\n"
                "    pid=18691 starting=false\n"
                f"    curProcState={state} mRepProcState={state} "
                f"pssProcState={state} setProcState={state} "
                "lastStateTime=-1s\n"
                f"    cached={cached} empty={empty}\n")
            alias = (f"    Proc #13: cch+85 b/ /CEM --- t: 0 18691:"
                     f"{alpha.HOST_PACKAGE}/u0a142 (cch-empty)\n")
            host_oom = alias + "        cached=true empty=true\n"
            host_lru = alias
            host_pid = (
                f"    PID #18691: ProcessRecord{{{token} 18691:"
                f"{alpha.HOST_PACKAGE}/u0a142}}\n")
        return ("ACTIVITY MANAGER RUNNING PROCESSES "
                "(dumpsys activity processes)\n"
                "  All known processes:\n" + host_record +
                "  *APP* UID 1000 ProcessRecord{12ec554 2053:"
                "com.supernote.document/1000}\n"
                "  mHomeProcess: ProcessRecord{e6d8b2b 1184:"
                "com.ratta.supernote.background/1000}\n"
                "  Process OOM control (31 total, non-act at 4, "
                "non-svc at 4):\n" + host_oom +
                "  UID states:\n"
                "    UID u0a142: UidRecord{194214c u0a142 CEM procs:1}\n"
                "  Process LRU list (sorted by oom_adj, 31 total, "
                "non-act at 4, non-svc at 4):\n" + host_lru +
                "\n  PID mappings:\n" + host_pid +
                "\n  ServiceManager statistics:\n"
                "    Stats:\n"
                "      getService(): 1 calls, 0.1ms total\n"
                "\n  mForceBackgroundCheck=false\n").encode(
                    "utf-8")

    def process_fd_links(self, pid):
        if pid == prior.HOST_PID:
            target = self.host_fd_target or "/system/framework/framework.jar"
            return ("lr-x------ 1 root root 64 2026-09-16 20:00 "
                    "3 -> " + target + "\n")
        return super().process_fd_links(pid)

    def parking_identity(self):
        value = super().parking_identity()
        ui = value.pop("uiWitness")
        if self.parking_ui_mode == "PARSED":
            evidence = {
                "mode": "PARSED", "semantic": ui,
                "rawSha256": ui["sha256"], "size": 100,
            }
        else:
            evidence = {
                "mode": "UNAVAILABLE", "errorType": "AlphaError",
                "error": "parking UI hierarchy unavailable",
                "rawSha256": prior._sha(b"Killed\n"), "size": 7,
            }
        value["uiEvidence"] = evidence
        return value

    def remove_task(self, task_id):
        self.generic_remove_called = True
        raise AssertionError("generic task removal must never be called")

    def remove_parking_task(self, task_id):
        if task_id == prior.HOST_TASK_ID:
            raise continuation.ContinuationError(
                "parking removal task ID is outside the continuation domain")
        self.parking_remove_ids.append(task_id)
        return prior_test.FakeDevice.remove_task(self, task_id)


class ContinuationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run_dir = self.root / prior.RUN_ID
        self.run_dir.mkdir()
        self.report = self.run_dir / "report.json"
        self.report.write_bytes(b"continuation test report\n")
        source_dir = Path(__file__).parent
        source_active = (source_dir / "build" / "native-page-alpha-runs" /
                         alpha.ACTIVE_MUTATION_JOURNAL_FILENAME)
        self.active = self.root / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        shutil.copyfile(source_active, self.active)
        source_prior = (source_dir / "build" / "native-page-alpha-runs" /
                        prior.RUN_ID / prior.RECOVERY_BASENAME)
        self.prior_ledger = self.run_dir / prior.RECOVERY_BASENAME
        shutil.copyfile(source_prior, self.prior_ledger)
        _, report_identity = prior._read_regular(
            self.report, 1024, "test report")
        _, active_identity = prior._read_regular(
            self.active, 256 * 1024, "test active")
        prior_raw, prior_identity = continuation._read_prior_ledger(
            self.prior_ledger)
        prior_summary = continuation._validate_prior_ledger(prior_raw)
        self.authority = continuation.Authority(
            self.root, self.run_dir, self.report, self.active,
            self.run_dir / continuation.CONTINUATION_BASENAME,
            self.run_dir / continuation.EVIDENCE_BASENAME,
            self.run_dir / prior.RETIRED_BASENAME,
            report_identity, active_identity, True,
            self.prior_ledger, prior_identity, prior_summary,
            source_dir / "recover_orientation_source_alpha_run.py")
        self.device = FakeDevice()
        self.open_journals = []

    def tearDown(self) -> None:
        for journal in self.open_journals:
            journal.close()
        self.temp.cleanup()

    def make_recovery(self, execute=False):
        if not execute:
            return continuation.Recovery(
                self.device, self.authority, sleep=lambda _: None)
        probe = continuation.Recovery(
            self.device, self.authority, sleep=lambda _: None)
        admission = probe.plan()
        header = probe._header()
        header["admissionSha256"] = prior._canonical_sha(admission)
        journal = continuation.Journal(
            self.authority.recovery_path, header)
        self.open_journals.append(journal)
        recovery = continuation.Recovery(
            self.device, self.authority, sleep=lambda _: None,
            journal=journal, durable_header=journal.records[0]["payload"],
            prior_admission=admission)
        journal.external_guard = recovery._assert_dispatch_authority
        return recovery

    def test_plan_is_read_only_and_adopts_exact_prior_receipt(self):
        result = self.make_recovery().plan()
        self.assertEqual("CONTINUATION_PLAN_READY", result["result"])
        self.assertFalse(result["deviceMutationAttempted"])
        self.assertEqual([], self.device.history)
        self.assertFalse(self.authority.recovery_path.exists())
        self.assertTrue(result["priorRecovery"]["immutable"])
        self.assertEqual(
            continuation.PRIOR_RECOVERY_HEAD,
            result["adoptedHostRemovalAbsence"]
            ["priorReceiptRecordSha256"])

    def test_execute_never_redispatches_host_removal(self):
        result = self.make_recovery(True).execute()
        self.assertEqual("CONTINUATION_RECOVERED_CLEANLY", result["result"])
        operations = [item["operation"] for item in self.device.history]
        self.assertEqual(
            ["launch_parking", "remove_task", "move", "delete", "move",
             "delete"], operations)
        self.assertFalse(self.device.generic_remove_called)
        self.assertNotIn(prior.HOST_TASK_ID, self.device.parking_remove_ids)
        self.assertFalse(self.active.exists())
        self.assertTrue(self.authority.retired_path.exists())
        self.assertEqual(
            continuation.PRIOR_RECOVERY_SHA256,
            prior._sha(self.prior_ledger.read_bytes()))

    def test_source_has_no_host_remove_dispatch_call(self):
        tree = ast.parse(Path(continuation.__file__).read_text(encoding="utf-8"))
        dispatch_sites = []
        for function in (node for node in ast.walk(tree)
                         if isinstance(node, (ast.FunctionDef,
                                              ast.AsyncFunctionDef))):
            calls = [node for node in ast.walk(function)
                     if isinstance(node, ast.Call) and
                     isinstance(node.func, ast.Attribute) and
                     node.func.attr == "remove_task"]
            dispatch_sites.extend((function.name, call) for call in calls)
        self.assertEqual(1, len(dispatch_sites))
        self.assertEqual("remove_parking_task", dispatch_sites[0][0])
        nomad = next(node for node in tree.body
                     if isinstance(node, ast.ClassDef) and
                     node.name == "ContinuationNomad")
        wrapper = next(node for node in nomad.body
                       if isinstance(node, ast.FunctionDef) and
                       node.name == "remove_parking_task")
        wrapper_source = ast.unparse(wrapper)
        self.assertIn("task_id == prior.HOST_TASK_ID", wrapper_source)
        self.assertIn("prior.RecoveryNomad.remove_task(self, task_id)",
                      wrapper_source)
        self.assertNotIn(
            "remove_task(prior.HOST_TASK_ID)",
            Path(continuation.__file__).read_text(encoding="utf-8"))

    def test_exact_residue_or_monotonic_disappearance_is_allowed(self):
        self.device.window_residue = None
        result = self.make_recovery().plan()
        self.assertEqual("CONTINUATION_PLAN_READY", result["result"])
        self.assertTrue(all(
            not item["windows"]["residuePresent"]
            for item in result["adoptedHostRemovalAbsence"]["observations"]))

    def test_altered_or_live_window_residue_is_rejected(self):
        variants = (
            continuation.PINNED_FREEZE_RESIDUE.replace("+259ms", "+260ms"),
            continuation.PINNED_FREEZE_RESIDUE.replace("d295460", "deadbee"),
            continuation.PINNED_FREEZE_RESIDUE.replace(
                "NativePageHostActivity", "OtherActivity"),
            " " + continuation.PINNED_FREEZE_RESIDUE,
            continuation.PINNED_FREEZE_RESIDUE + "\n" +
            continuation.PINNED_FREEZE_RESIDUE,
        )
        for value in variants:
            with self.subTest(value=value[-40:]):
                self.device.window_residue = value
                with self.assertRaises(continuation.ContinuationError):
                    self.make_recovery().plan()
                self.assertEqual([], self.device.history)
                self.device.window_residue = continuation.PINNED_FREEZE_RESIDUE
        self.device.window_extra = (
            "  Window #9 Window{d295460 u0 " + alpha.HOST_COMPONENT + "}:\n")
        with self.assertRaises(continuation.ContinuationError):
            self.make_recovery().plan()

    def test_frozen_or_truncated_window_dump_is_rejected(self):
        self.device.window_frozen = True
        with self.assertRaisesRegex(
                continuation.ContinuationError, "non-frozen"):
            self.make_recovery().plan()
        self.device.window_frozen = False
        with self.assertRaises(continuation.ContinuationError):
            continuation._window_residue_state(
                b"  mDisplayFrozen=false windows=0 client=false apps=0  "
                b"mRotation=1  mLastOrientation=-1\n",
                self.authority.prior_recovery_summary["stableAuthority"])
        complete = self.device._settled_windows()
        with self.assertRaisesRegex(
                continuation.ContinuationError, "framing"):
            continuation._window_residue_state(
                complete.rstrip(b"\n"),
                self.authority.prior_recovery_summary["stableAuthority"])
        terminal = b"  PolicyControl.sImmersivePreconfirmationsFilter=null\n"
        with self.assertRaisesRegex(
                continuation.ContinuationError, "framing"):
            continuation._window_residue_state(
                complete.replace(terminal, b""),
                self.authority.prior_recovery_summary["stableAuthority"])

    def test_display_inventory_is_complete_rotation_bound_and_host_free(self):
        complete = self.device._displays()
        state = continuation._strict_display0_state(complete)
        self.assertEqual(1, state["rotation"])
        for raw in (b"", b"DISPLAY MANAGER (dumpsys display)\n",
                    complete.rstrip(b"\n")):
            with self.subTest(size=len(raw)):
                with self.assertRaises(prior.RecoveryError):
                    continuation._strict_display0_state(raw)
        self.device.rogue_host_display = True
        with self.assertRaisesRegex(prior.RecoveryError, "virtual display"):
            self.make_recovery().plan()
        self.device.rogue_host_display = False
        self.device.physical_rotation = 0
        with self.assertRaisesRegex(
                continuation.ContinuationError, "rotations differ"):
            self.make_recovery().plan()

    def test_every_display_prefix_before_persistent_tail_is_rejected(self):
        complete = self.device._displays()
        lines = complete.splitlines(keepends=True)
        self.assertGreater(len(lines), 10)
        for count in range(1, len(lines)):
            with self.subTest(count=count):
                with self.assertRaises(prior.RecoveryError):
                    continuation._strict_display0_state(
                        b"".join(lines[:count]))

    def test_activity_ghost_and_truncated_activity_dump_are_rejected(self):
        self.device.activity_extra = (
            "  topDisplayFocusedStack=Task{93d94cf #4646 visible=false "
            f"A=10142:{alpha.HOST_PACKAGE} sz=0}}\n")
        with self.assertRaisesRegex(
                continuation.ContinuationError, "ActivityManager"):
            self.make_recovery().plan()
        with self.assertRaises(continuation.ContinuationError):
            continuation._strict_activity_absence(
                b"garbage\n",
                self.authority.prior_recovery_summary["stableAuthority"])

    def test_every_activity_prefix_before_organizer_tail_is_rejected(self):
        complete = self.device._settled_activity()
        stable = self.authority.prior_recovery_summary["stableAuthority"]
        continuation._strict_activity_absence(complete, stable)
        lines = complete.splitlines(keepends=True)
        self.assertGreater(len(lines), 10)
        for count in range(1, len(lines)):
            with self.subTest(count=count):
                with self.assertRaises(continuation.ContinuationError):
                    continuation._strict_activity_absence(
                        b"".join(lines[:count]), stable)

    def test_parking_capture_requires_complete_envelopes_before_scope(self):
        boundary = b"ActivityStackSupervisor state:\n"
        activity_tail = self.device._settled_activity().split(boundary, 1)[1]
        activity_base = self.device._parking_activity_wire()
        activity = activity_base + boundary + activity_tail
        continuation._complete_activity_envelope(activity)
        with self.assertRaises(continuation.ContinuationError):
            continuation._complete_activity_envelope(activity_base)

        window_base = self.device._parking_window_wire()
        window_tail = self.device._settled_windows()
        window_tail = window_tail[window_tail.index(
            b"  mGlobalConfiguration="):]
        windows = window_base + window_tail
        continuation._complete_window_envelope(windows)
        with self.assertRaises(continuation.ContinuationError):
            continuation._complete_window_envelope(window_base)

        process = self.device.process_identity(
            prior.DOCUMENT_PID, alpha.DOCUMENT_PACKAGE)
        authority = self.device._parking_authority(prior._sha(activity))
        prior._assert_sole_document_scope(
            activity, windows, authority, process)

        hidden_activity = self.device._parking_activity_wire(
            extra_task=True, same_stack=True) + boundary + activity_tail
        continuation._complete_activity_envelope(hidden_activity)
        with self.assertRaises(prior.RecoveryError):
            prior._assert_sole_document_scope(
                hidden_activity, windows, authority, process)
        hidden_windows = self.device._parking_window_wire(
            extra_window=True) + window_tail
        continuation._complete_window_envelope(hidden_windows)
        with self.assertRaises(prior.RecoveryError):
            prior._assert_sole_document_scope(
                activity, hidden_windows, authority, process)

    def test_nomad_routes_all_inventories_through_complete_envelopes(self):
        source = Path(continuation.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        nomad = next(node for node in tree.body
                     if isinstance(node, ast.ClassDef) and
                     node.name == "ContinuationNomad")
        methods = {node.name: ast.unparse(node) for node in nomad.body
                   if isinstance(node, ast.FunctionDef)}
        self.assertIn("_complete_activity_envelope(raw)",
                      methods["activities"])
        self.assertIn("_complete_window_envelope(raw)", methods["windows"])
        self.assertIn("_strict_display0_state(raw)", methods["displays"])

    def test_exact_cached_process_may_disappear_but_not_reappear(self):
        self.device.host_pid_sequence = [True, False]
        result = self.make_recovery().plan()
        modes = [item["hostProcess"]["mode"] for item in
                 result["adoptedHostRemovalAbsence"]["observations"]]
        self.assertEqual(["CACHED_EMPTY_PROCESS", "PROCESS_ABSENT"], modes)
        self.tearDown()
        self.setUp()
        self.device.host_pid_sequence = [False, True]
        with self.assertRaisesRegex(
                continuation.ContinuationError, "appeared|reappeared"):
            self.make_recovery().plan()

    def test_bad_cached_process_semantics_are_rejected(self):
        mutations = (
            ("host_cached", False), ("host_empty", False),
            ("host_proc_state", 18),
            ("host_process_token_override", "deadbee"),
            ("host_process_token_override", "start"),
            ("host_process_inventory_truncated", True),
            ("host_fd_target", alpha.TARGET_PDF),
        )
        for name, value in mutations:
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                setattr(self.device, name, value)
                with self.assertRaises(continuation.ContinuationError):
                    self.make_recovery().plan()

    def test_cached_process_exit_during_fd_or_log_read_is_reconciled(self):
        for boundary in ("fd", "log"):
            with self.subTest(boundary=boundary):
                self.tearDown()
                self.setUp()
                executor = self.make_recovery(True)
                if boundary == "fd":
                    original = self.device.process_fd_links

                    def process_fd_links(pid):
                        if pid == prior.HOST_PID and self.device.host_live:
                            self.device.host_live = False
                            raise prior.RecoveryError(
                                "host exited during descriptor read")
                        return original(pid)

                    self.device.process_fd_links = process_fd_links
                else:
                    original = self.device.host_logs

                    def host_logs(pid):
                        if pid == prior.HOST_PID and self.device.host_live:
                            self.device.host_live = False
                            raise prior.RecoveryError(
                                "host exited during lifecycle read")
                        return original(pid)

                    self.device.host_logs = host_logs
                result = executor.execute()
                self.assertEqual(
                    "CONTINUATION_RECOVERED_CLEANLY", result["result"])
                self.assertEqual(
                    ["launch_parking", "remove_task", "move", "delete",
                     "move", "delete"],
                    [item["operation"] for item in self.device.history])

    def test_cached_process_read_failure_while_live_is_fatal(self):
        for boundary in ("fd", "log"):
            with self.subTest(boundary=boundary):
                self.tearDown()
                self.setUp()
                executor = self.make_recovery(True)
                if boundary == "fd":
                    original = self.device.process_fd_links

                    def process_fd_links(pid):
                        if pid == prior.HOST_PID:
                            raise prior.RecoveryError("descriptor read failed")
                        return original(pid)

                    self.device.process_fd_links = process_fd_links
                else:
                    self.device.host_logs = lambda _: (_ for _ in ()).throw(
                        prior.RecoveryError("lifecycle read failed"))
                with self.assertRaisesRegex(
                        continuation.ContinuationError, "lost its"):
                    executor.execute()
                self.assertEqual([], self.device.history)

    def test_host_reappearance_after_launch_blocks_parking_remove(self):
        self.device.host_live = False
        executor = self.make_recovery(True)
        original = self.device.launch_parking

        def launch_parking():
            result = original()
            self.device.host_live = True
            return result

        self.device.launch_parking = launch_parking
        with self.assertRaisesRegex(
                continuation.ContinuationError, "reappeared"):
            executor.execute()
        self.assertEqual(
            ["launch_parking"],
            [item["operation"] for item in self.device.history])

    def test_failed_parking_poll_cannot_hide_host_reappearance(self):
        self.device.host_live = False
        executor = self.make_recovery(True)
        original = self.device.parking_identity
        first = True

        def parking_identity():
            nonlocal first
            if first:
                first = False
                self.device.host_live = True
                raise prior.RecoveryError(
                    "transient parking identity failure")
            self.device.host_live = False
            return original()

        self.device.parking_identity = parking_identity
        with self.assertRaisesRegex(
                continuation.ContinuationError, "reappeared"):
            executor.execute()
        self.assertEqual(
            ["launch_parking"],
            [item["operation"] for item in self.device.history])

    def test_parking_change_during_host_check_blocks_numeric_remove(self):
        executor = self.make_recovery(True)
        original = executor._assert_host_scope_before_dispatch

        def host_scope(**kwargs):
            result = original(**kwargs)
            if not kwargs.get("require_document_absent", False):
                self.device.task_live = False
            return result

        executor._assert_host_scope_before_dispatch = host_scope
        with self.assertRaisesRegex(
                continuation.ContinuationError, "parking identity"):
            executor.execute()
        self.assertEqual(
            ["launch_parking"],
            [item["operation"] for item in self.device.history])

    def test_tool_swap_during_runtime_scope_blocks_next_dispatch(self):
        for phase in ("parking", "file"):
            with self.subTest(phase=phase):
                self.tearDown()
                self.setUp()
                executor = self.make_recovery(True)
                original = executor._assert_host_scope_before_dispatch
                original_adb = self.device.adb_authority()
                changed = False

                def host_scope(**kwargs):
                    nonlocal changed
                    result = original(**kwargs)
                    is_file = kwargs.get("require_document_absent", False)
                    if not changed and ((phase == "file" and is_file) or
                                        (phase == "parking" and not is_file)):
                        changed = True
                        self.device.adb_authority = lambda: {
                            **original_adb, "sha256": "f" * 64}
                    return result

                executor._assert_host_scope_before_dispatch = host_scope
                with self.assertRaisesRegex(
                        continuation.ContinuationError, "tool identity"):
                    executor.execute()
                expected = (["launch_parking"] if phase == "parking" else
                            ["launch_parking", "remove_task"])
                self.assertEqual(
                    expected,
                    [item["operation"] for item in self.device.history])

    def test_exact_parking_supervisor_ghost_allows_file_cleanup(self):
        self.device.parking_supervisor_ghost = True
        result = self.make_recovery(True).execute()
        self.assertEqual("CONTINUATION_RECOVERED_CLEANLY", result["result"])
        self.assertEqual(
            ["launch_parking", "remove_task", "move", "delete",
             "move", "delete"],
            [item["operation"] for item in self.device.history])

    def test_altered_parking_supervisor_ghost_blocks_file_cleanup(self):
        self.device.parking_supervisor_ghost = True
        original = self.device._parking_supervisor_activity

        def altered():
            return original().replace(
                self.device.parking_activity_token.encode("ascii"),
                b"deadbee", 1)

        self.device._parking_supervisor_activity = altered
        with self.assertRaisesRegex(
                continuation.ContinuationError, "absence|Document"):
            self.make_recovery(True).execute()
        self.assertEqual(
            ["launch_parking", "remove_task"],
            [item["operation"] for item in self.device.history])

    def test_host_reappearance_after_move_blocks_following_delete(self):
        self.device.host_live = False
        executor = self.make_recovery(True)
        original = self.device.move_quarantine
        first = True

        def move_quarantine(source, target):
            nonlocal first
            result = original(source, target)
            if first:
                first = False
                self.device.host_live = True
            return result

        self.device.move_quarantine = move_quarantine
        with self.assertRaisesRegex(
                continuation.ContinuationError, "reappeared"):
            executor.execute()
        self.assertEqual(
            ["launch_parking", "remove_task", "move"],
            [item["operation"] for item in self.device.history])

    def test_runtime_reappearance_blocks_first_file_mutation(self):
        scenarios = (
            (lambda: setattr(self.device, "host_live", True),
             "reappeared"),
            (lambda: setattr(
                self.device, "activity_extra",
                "  com.supernote.document/.DocumentActivity\n"),
             "Document"),
            (lambda: self.device.fd_targets.add(alpha.TARGET_PDF),
             "parking-only"),
        )
        for mutation, message in scenarios:
            with self.subTest(message=message):
                self.tearDown()
                self.setUp()
                if message == "reappeared":
                    self.device.host_live = False
                executor = self.make_recovery(True)
                original = executor._quarantine_delete
                first = True

                def quarantine_delete(path):
                    nonlocal first
                    if first:
                        first = False
                        mutation()
                    return original(path)

                executor._quarantine_delete = quarantine_delete
                with self.assertRaisesRegex(
                        continuation.ContinuationError, message):
                    executor.execute()
                self.assertEqual(
                    ["launch_parking", "remove_task"],
                    [item["operation"] for item in self.device.history])

    def test_process_inventory_requires_complete_contextual_aliases(self):
        raw = self.device.host_processes()
        state = continuation._cached_process_semantics(
            raw, self.authority.prior_recovery_summary["stableAuthority"])
        self.assertTrue(state["cached"])
        aliases = [match.start() for match in __import__("re").finditer(
            rb"^    Proc #13:.*18691:", raw, __import__("re").MULTILINE)]
        self.assertEqual(2, len(aliases))
        for candidate in (
                raw[:aliases[1]] + raw[raw.find(b"\n", aliases[1]) + 1:],
                raw.replace(b"\n  mForceBackgroundCheck=false\n", b""),
                raw.rstrip(b"\n")):
            with self.subTest(size=len(candidate)):
                with self.assertRaises(continuation.ContinuationError):
                    continuation._cached_process_semantics(
                        candidate,
                        self.authority.prior_recovery_summary[
                            "stableAuthority"])

    def test_absent_process_requires_complete_host_free_inventory(self):
        self.device.host_live = False
        result = self.make_recovery().plan()
        self.assertTrue(all(
            item["hostProcess"]["mode"] == "PROCESS_ABSENT"
            for item in result["adoptedHostRemovalAbsence"]["observations"]))
        self.tearDown()
        self.setUp()
        self.device.host_live = False
        self.device.host_process_inventory_truncated = True
        with self.assertRaises(continuation.ContinuationError):
            self.make_recovery().plan()
        self.tearDown()
        self.setUp()
        self.device.host_live = False
        original = self.device.host_processes

        def contaminated():
            return original().replace(
                b"  UID states:\n",
                ("  mPreviousProcess=" + alpha.HOST_PACKAGE + "\n"
                 "  UID states:\n").encode("ascii"))

        self.device.host_processes = contaminated
        with self.assertRaisesRegex(
                continuation.ContinuationError, "still contains"):
            self.make_recovery().plan()

    def test_prior_ledger_tamper_fails_without_device_mutation(self):
        original = self.prior_ledger.read_bytes()
        mutations = (
            original + b"{}\n",
            original.replace(b'"sequence":2', b'"sequence":9'),
            original[:-1],
        )
        for raw in mutations:
            with self.subTest(size=len(raw)):
                self.prior_ledger.write_bytes(raw)
                with self.assertRaises(continuation.ContinuationError):
                    self.make_recovery().plan()
                self.assertEqual([], self.device.history)
                self.prior_ledger.write_bytes(original)
                _, identity = continuation._read_prior_ledger(self.prior_ledger)
                self.authority = replace(
                    self.authority, prior_recovery_identity=identity)

    def test_prior_ledger_hardlink_or_symlink_is_rejected(self):
        hardlink = self.run_dir / "hardlink-ledger"
        os.link(self.prior_ledger, hardlink)
        with self.assertRaisesRegex(
                continuation.ContinuationError, "sole regular"):
            self.make_recovery().plan()
        hardlink.unlink()
        displaced = self.run_dir / "displaced-ledger"
        self.prior_ledger.rename(displaced)
        try:
            self.prior_ledger.symlink_to(displaced)
        except OSError:
            displaced.rename(self.prior_ledger)
            return
        with self.assertRaises(continuation.ContinuationError):
            self.make_recovery().plan()

    def test_report_and_active_must_remain_sole_regular_paths(self):
        for path, label in ((self.report, "report"),
                            (self.active, "active")):
            with self.subTest(label=label):
                link = self.root / (label + "-hardlink")
                os.link(path, link)
                try:
                    with self.assertRaisesRegex(
                            continuation.ContinuationError, "sole regular"):
                        self.make_recovery().plan()
                    self.assertEqual([], self.device.history)
                finally:
                    link.unlink()

    def _mutate_after_parking_intent(self, mutation, message):
        probe = self.make_recovery(True)
        original_intent = probe._intent

        def intent(name, payload):
            result = original_intent(name, payload)
            if name == "parking_launch":
                mutation()
            return result

        probe._intent = intent
        with self.assertRaisesRegex(prior.RecoveryError, message):
            probe.execute()
        self.assertEqual([], self.device.history)

    def test_old_ledger_swap_after_intent_blocks_first_dispatch(self):
        def mutate():
            self.prior_ledger.write_bytes(
                self.prior_ledger.read_bytes() + b"{}\n")
        self._mutate_after_parking_intent(mutate, "ledger")

    def test_continuation_path_swap_after_intent_blocks_first_dispatch(self):
        displaced = self.run_dir / "displaced-continuation"

        def mutate():
            # Windows denies renaming an open journal.  Closing the retained
            # descriptor makes the attack possible in the test harness; the
            # next authority check must still fail before device dispatch.
            for journal in self.open_journals:
                if journal.path == self.authority.recovery_path:
                    journal.close()
            self.authority.recovery_path.rename(displaced)
            self.authority.recovery_path.write_bytes(b"replacement\n")

        self._mutate_after_parking_intent(mutate, "journal")

    def test_host_scope_drift_after_intent_blocks_first_dispatch(self):
        self._mutate_after_parking_intent(
            lambda: setattr(
                self.device, "window_extra",
                "  Window #9 Window{d295460 u0 " +
                alpha.HOST_COMPONENT + "}:\n"),
            "WindowManager")

    def test_rotation_target_and_document_drift_block_first_dispatch(self):
        scenarios = (
            (lambda: setattr(self.device, "rotation", ("0", "0")),
             "rotation"),
            (lambda: self.device.files.__setitem__(
                alpha.TARGET_PDF,
                replace(prior.PINNED_TARGET_PDF, inode=999999)),
             "target"),
            (lambda: self.device.fd_targets.discard(alpha.TARGET_PDF),
             "descriptor"),
            (lambda: self.report.write_bytes(b"changed report\n"),
             "report"),
            (lambda: self.active.write_bytes(b"changed active\n"),
             "active mutation journal"),
        )
        for mutation, message in scenarios:
            with self.subTest(message=message):
                self.tearDown()
                self.setUp()
                self._mutate_after_parking_intent(mutation, message)

    def test_publication_path_race_blocks_first_dispatch(self):
        paths = (
            (lambda: self.authority.evidence_path,
             "continuation evidence"),
            (lambda: self.authority.retired_path,
             "retired active-journal"),
            (lambda: self.run_dir / prior.EVIDENCE_BASENAME,
             "prior recovery evidence"),
        )
        for get_path, message in paths:
            with self.subTest(message=message):
                self.tearDown()
                self.setUp()
                self._mutate_after_parking_intent(
                    lambda get_path=get_path: get_path().write_bytes(b"race\n"),
                    message)

    def test_tool_swap_during_boundary_blocks_first_dispatch(self):
        probe = self.make_recovery(True)
        original_rotation = self.device.rotation_settings
        original_adb = self.device.adb_authority()

        def rotation_settings():
            self.device.adb_authority = lambda: {
                **original_adb, "sha256": "0" * 64}
            return original_rotation()

        self.device.rotation_settings = rotation_settings
        with self.assertRaisesRegex(
                continuation.ContinuationError, "tool identity"):
            probe.execute()
        self.assertEqual([], self.device.history)

    def test_unjournalled_active_to_retired_rename_blocks_dispatch(self):
        probe = self.make_recovery(True)
        original_intent = probe._intent
        original_rotation = self.device.rotation_settings

        def intent(name, payload):
            result = original_intent(name, payload)
            if name == "parking_launch":
                def rotation_settings():
                    if self.active.exists():
                        self.active.rename(self.authority.retired_path)
                    return original_rotation()

                self.device.rotation_settings = rotation_settings
            return result

        probe._intent = intent
        with self.assertRaisesRegex(
                continuation.ContinuationError, "durable authority"):
            probe.execute()
        self.assertEqual([], self.device.history)

    def test_durable_archive_intent_authorizes_exact_retired_state(self):
        probe = self.make_recovery(True)
        retired = probe._archive_active()
        self.assertEqual(
            self.authority.active_identity["sha256"], retired["sha256"])
        probe._assert_dispatch_authority()
        self.assertFalse(self.active.exists())
        self.assertTrue(self.authority.retired_path.exists())

    def test_continuation_journal_is_exclusive_and_tamper_guarded(self):
        first = self.make_recovery(True)
        with self.assertRaisesRegex(
                prior.RecoveryError, "occupied|already exists"):
            self.make_recovery(True)
        original_intent = first._intent

        def intent(name, payload):
            result = original_intent(name, payload)
            if name == "parking_launch":
                with open(self.authority.recovery_path, "ab") as stream:
                    stream.write(b"tamper\n")
            return result

        first._intent = intent
        with self.assertRaises(prior.RecoveryError):
            first.execute()
        self.assertEqual([], self.device.history)

    def test_durable_header_tool_identity_is_executor_authority(self):
        probe = continuation.Recovery(
            self.device, self.authority, sleep=lambda _: None)
        admission = probe.plan()
        header = probe._header()
        header["admissionSha256"] = prior._canonical_sha(admission)
        changed = dict(header["continuationHelper"])
        changed["sha256"] = "0" * 64
        header["continuationHelper"] = changed
        journal = continuation.Journal(self.authority.recovery_path, header)
        self.open_journals.append(journal)
        executor = continuation.Recovery(
            self.device, self.authority, sleep=lambda _: None,
            journal=journal, durable_header=journal.records[0]["payload"],
            prior_admission=admission)
        journal.external_guard = executor._assert_dispatch_authority
        with self.assertRaisesRegex(
                continuation.ContinuationError, "tool identity"):
            executor.execute()
        self.assertEqual([], self.device.history)

    def test_admission_absence_cannot_reappear_in_executor(self):
        self.device.host_live = False
        self.device.window_residue = None
        executor = self.make_recovery(True)
        self.device.host_live = True
        self.device.window_residue = continuation.PINNED_FREEZE_RESIDUE
        with self.assertRaisesRegex(
                continuation.ContinuationError, "reappeared"):
            executor.execute()
        self.assertEqual([], self.device.history)

    def test_transient_poll_never_retries_host_reappearance(self):
        probe = self.make_recovery()
        probe.host_process_gone = True
        with self.assertRaisesRegex(
                continuation.ContinuationError, "process reappeared"):
            probe._prove_host_absence_twice(poll_transient=True)
        probe = self.make_recovery()
        probe.host_residue_gone = True
        with self.assertRaisesRegex(
                continuation.ContinuationError, "residue reappeared"):
            probe._prove_host_absence_twice(poll_transient=True)
        probe = self.make_recovery()
        self.device.activity_extra = (
            "  mLastOrientationSource=ActivityRecord{45537a9 u0 " +
            alpha.HOST_PACKAGE + "/.NativePageHostActivity t4646}\n")
        with self.assertRaises(continuation.ContinuationError):
            probe._prove_host_absence_twice(poll_transient=True)

    def test_document_teardown_retries_only_before_first_absence(self):
        probe = self.make_recovery()
        clean = probe._scope_observation()
        lingering = dict(clean, documentScopePresent=True)
        sequence = [lingering, clean, clean]

        def collect(*, parking=None):
            del parking
            return sequence.pop(0)

        probe._scope_observation = collect
        proof = probe._prove_host_absence_twice(
            parking={"test": True}, poll_transient=True)
        self.assertEqual(2, len(proof["observations"]))

        probe = self.make_recovery()
        clean = probe._scope_observation()
        lingering = dict(clean, documentScopePresent=True)
        sequence = [clean, lingering, clean, clean]

        def reappears(*, parking=None):
            del parking
            return sequence.pop(0)

        probe._scope_observation = reappears
        with self.assertRaisesRegex(
                continuation.ContinuationError, "reappeared"):
            probe._prove_host_absence_twice(
                parking={"test": True}, poll_transient=True)

    def test_document_present_before_parking_is_a_closed_failure(self):
        probe = self.make_recovery()
        present = dict(
            probe._scope_observation(), documentScopePresent=True)
        probe._scope_observation = lambda **_: present
        with self.assertRaisesRegex(
                continuation.DocumentScopePresent, "still present"):
            probe._prove_host_absence_twice()

    def test_lingering_document_cannot_mask_host_reappearance(self):
        probe = self.make_recovery()
        clean = probe._scope_observation()
        probe.host_process_gone = True
        reappeared = dict(clean, documentScopePresent=True)
        reappeared["hostProcess"] = dict(
            clean["hostProcess"], mode="CACHED_EMPTY_PROCESS")
        sequence = [reappeared, clean, clean]

        def collect(*, parking=None):
            del parking
            return sequence.pop(0)

        probe._scope_observation = collect
        with self.assertRaisesRegex(
                continuation.ContinuationError, "process reappeared"):
            probe._prove_host_absence_twice(
                parking={"test": True}, poll_transient=True)

    def test_parking_task_cannot_alias_removed_host_task(self):
        self.device.parking_task_id = prior.HOST_TASK_ID
        with self.assertRaisesRegex(
                continuation.ContinuationError, "aliases the removed host"):
            self.make_recovery(True).execute()
        self.assertEqual(
            ["launch_parking"],
            [item["operation"] for item in self.device.history])
        self.assertFalse(self.device.generic_remove_called)

    def test_parking_ui_is_optional_evidence_not_stable_authority(self):
        self.device.parking_ui_mode = "UNAVAILABLE"
        result = self.make_recovery(True).execute()
        self.assertEqual("CONTINUATION_RECOVERED_CLEANLY", result["result"])

        self.tearDown()
        self.setUp()
        original = self.device.parking_identity
        calls = 0

        def changes():
            nonlocal calls
            calls += 1
            self.device.parking_ui_mode = (
                "PARSED" if calls == 1 else "UNAVAILABLE")
            return original()

        self.device.parking_identity = changes
        result = self.make_recovery(True).execute()
        self.assertEqual("CONTINUATION_RECOVERED_CLEANLY", result["result"])
        self.assertGreaterEqual(calls, 2)
        tree = ast.parse(Path(
            continuation.__file__).read_text(encoding="utf-8"))
        ui_method = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and
            node.name == "_parking_ui_evidence_once")
        self.assertEqual(1, ast.unparse(ui_method).count("self.ui_dump()"))
        nomad = next(node for node in tree.body
                     if isinstance(node, ast.ClassDef) and
                     node.name == "ContinuationNomad")
        identity_method = next(
            node for node in nomad.body
            if isinstance(node, ast.FunctionDef) and
            node.name == "parking_identity")
        source = ast.unparse(identity_method)
        self.assertLess(source.index("_parking_ui_evidence_once"),
                        source.index("self.pidof"))

    def test_ui_callback_cannot_make_parking_capture_return_stale_task(self):
        nomad = object.__new__(continuation.ContinuationNomad)
        state = {"live": True, "uiCalls": 0}

        def ui_dump():
            state["uiCalls"] += 1
            state["live"] = False
            return b"Killed\n"

        nomad.ui_dump = ui_dump
        nomad.pidof = lambda package: (
            (prior.DOCUMENT_PID,) if state["live"] else ())
        with self.assertRaisesRegex(
                continuation.ContinuationError, "lacks one stock"):
            nomad.parking_identity()
        self.assertEqual(1, state["uiCalls"])


if __name__ == "__main__":
    unittest.main()
