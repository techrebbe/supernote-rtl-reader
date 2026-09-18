from __future__ import annotations

import copy
from dataclasses import asdict
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import native_page_alpha_runner as alpha
import native_page_host_authority as host
import recover_launch_identity_alpha_run as recovery
import test_native_page_android_authority as android_test


class FakeExecutionDevice:
    def __init__(self) -> None:
        self.history: list[dict[str, object]] = []
        self.document_task_live = True
        self.host_task_live = True
        self.document_process_live = True
        self.files = {
            **recovery.ORIGINALS,
            recovery.PARKING_PDF: recovery.PARKING,
            **recovery.TARGETS,
        }

    def pidof(self, package: str) -> tuple[int, ...]:
        if package == alpha.DOCUMENT_PACKAGE:
            return ((recovery.DOCUMENT_PID,)
                    if self.document_process_live else ())
        return ()

    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity:
        if (pid != recovery.DOCUMENT_PID or
                package != alpha.DOCUMENT_PACKAGE or
                not self.document_process_live):
            raise AssertionError("unexpected process identity request")
        return host.ProcessIdentity(
            recovery.DOCUMENT_PID, 44_444, recovery.DOCUMENT_UID,
            alpha.DOCUMENT_PACKAGE)

    def process_fd_links(self, pid: int) -> str:
        if pid != recovery.DOCUMENT_PID:
            raise AssertionError("unexpected descriptor request")
        return (
            "lr-x------ 1 root root 64 2026-09-17 01:40 40 -> " +
            recovery.TARGET_PDF + "\n")

    def stat_file(self, path: str, *, absent_ok: bool = False):
        value = self.files.get(path)
        if value is None and not absent_ok:
            raise AssertionError("required fake file is absent: " + path)
        return value

    def rotation_settings(self) -> tuple[str, str]:
        return ("1", "2")

    def remove_task(self, task_id: int) -> alpha.CommandResult:
        if task_id == 4_634 and self.document_task_live:
            self.document_task_live = False
        elif task_id == 4_633 and self.host_task_live:
            self.host_task_live = False
        else:
            raise AssertionError("unexpected task removal")
        self.history.append({"operation": "remove_exact_task", "taskId": task_id})
        return alpha.CommandResult("remove_exact_task", (), 0, b"", b"")

    def force_stop_document(self) -> alpha.CommandResult:
        self.document_process_live = False
        self.history.append({"operation": "force_stop_document"})
        return alpha.CommandResult("force_stop_document", (), 0, b"", b"")

    def move_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult:
        expected = self.files.pop(source)
        self.files[quarantine] = alpha.DeviceFile(
            quarantine, expected.kind, expected.size, expected.uid,
            expected.gid, expected.inode, expected.device, expected.sha256)
        operation = "recovery_quarantine_" + Path(source).name
        self.history.append({"operation": operation})
        return alpha.CommandResult(operation, (), 0, b"", b"")

    def delete_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult:
        self.files.pop(quarantine)
        operation = "recovery_remove_" + Path(quarantine).name
        self.history.append({"operation": operation})
        return alpha.CommandResult(operation, (), 0, b"", b"")

    def activities(self) -> bytes:
        return b"ACTIVITY MANAGER ACTIVITIES clean\n"

    def windows(self) -> bytes:
        return b"WINDOW MANAGER WINDOWS clean\n"

    def displays(self) -> bytes:
        return b"DISPLAY MANAGER clean\n"


class LaunchIdentityRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).parent.resolve()

    def test_exact_retained_run_and_current_dependencies_load_read_only(self) -> None:
        authority = recovery.load_authority(self.root)
        self.assertEqual(recovery.REPORT_SHA256,
                         authority.report_identity["sha256"])
        self.assertEqual(recovery.ACTIVE_SHA256,
                         authority.active_identity["sha256"])
        self.assertEqual(
            recovery.RUNNER_SHA256,
            authority.dependency_identities[
                "native_page_alpha_runner.py"]["sha256"])
        self.assertFalse(authority.ledger_path.exists())
        self.assertFalse(authority.evidence_path.exists())
        self.assertTrue(authority.active_path.exists())
        self.assertFalse(authority.retired_path.exists())

    def test_runner_dependency_pin_rejects_any_byte_or_size_mismatch(self) -> None:
        original_size = recovery.RUNNER_BYTES
        original_digest = recovery.RUNNER_SHA256
        try:
            recovery.RUNNER_BYTES = original_size + 1
            with self.assertRaisesRegex(
                    recovery.RecoveryError,
                    "native_page_alpha_runner.py differs"):
                recovery.load_authority(self.root)
            recovery.RUNNER_BYTES = original_size
            recovery.RUNNER_SHA256 = "0" * 64
            with self.assertRaisesRegex(
                    recovery.RecoveryError,
                    "native_page_alpha_runner.py differs"):
                recovery.load_authority(self.root)
        finally:
            recovery.RUNNER_BYTES = original_size
            recovery.RUNNER_SHA256 = original_digest

    def test_stable_plan_projection_ignores_only_raw_capture_digests(self) -> None:
        base = {
            "authority": recovery.PLAN_AUTHORITY,
            "bindingSha256": "a" * 64,
            "first": {
                "activitySha256": "1" * 64,
                "windowSha256": "2" * 64,
                "displaySha256": "3" * 64,
                "environment": {"serial": "fixed"},
            },
            "second": {
                "activitySha256": "4" * 64,
                "windowSha256": "5" * 64,
                "displaySha256": "6" * 64,
                "environment": {"serial": "fixed"},
            },
            "mutationOrder": ["fixed"],
        }
        volatile = copy.deepcopy(base)
        volatile["bindingSha256"] = "b" * 64
        volatile["first"]["activitySha256"] = "7" * 64
        volatile["first"]["windowSha256"] = "8" * 64
        volatile["second"]["displaySha256"] = "9" * 64
        self.assertEqual(
            recovery._stable_plan_projection(base),
            recovery._stable_plan_projection(volatile))
        self.assertEqual("a" * 64, base["bindingSha256"])
        self.assertEqual("1" * 64, base["first"]["activitySha256"])

        drifted = copy.deepcopy(volatile)
        drifted["first"]["environment"]["serial"] = "changed"
        self.assertNotEqual(
            recovery._stable_plan_projection(base),
            recovery._stable_plan_projection(drifted))

    def test_stable_plan_projection_rejects_missing_observation(self) -> None:
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "plan observation is malformed"):
            recovery._stable_plan_projection({"first": {}, "second": None})

    def test_real_nomad_supervisor_summaries_are_metadata_only(self) -> None:
        raw = android_test.real_display_summary_wire()
        prefix, digest, summaries = recovery._display_summary_split(raw)
        self.assertEqual(((0, 5), (4, 0)), summaries)
        self.assertNotIn(b"ActivityStackSupervisor state:", prefix)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_supervisor_summary_mismatch_and_malformed_boundary_fail_closed(self) -> None:
        raw = android_test.real_display_summary_wire()
        cases = (
            raw.replace(b"mDisplayId=4 stacks=0",
                        b"mDisplayId=4 stacks=1", 1),
            raw.replace(b"ActivityStackSupervisor state:",
                        b"ActivityStackSupervisor state :", 1),
            raw + b"ActivityStackSupervisor state:\n",
        )
        for value in cases:
            with self.subTest(value=value[-80:]), self.assertRaises(
                    recovery.RecoveryError):
                recovery._display_summary_split(value)

    def test_completed_bad_mutation_reply_cannot_settle_by_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = recovery.Journal(
                Path(directory) / "recovery.jsonl", {"test": True})
            try:
                bad = alpha.CommandResult(
                    "remove_exact_task", (), 1, b"", b"failure\n")
                with self.assertRaises(recovery.RecoveryError):
                    recovery._dispatch_one(
                        journal, "remove-document-task", "remove_exact_task",
                        {"taskId": 1}, lambda: bad, lambda: True)
                self.assertEqual(
                    ["header", "remove-document-task-intent"],
                    [record["kind"] for record in journal.records])
            finally:
                journal.close()

    def _execution_authority(self, directory: Path) -> recovery.Authority:
        retained = recovery.load_authority(self.root)
        report_path = directory / "report.json"
        active_path = directory / "active.jsonl"
        shutil.copyfile(retained.report_path, report_path)
        shutil.copyfile(retained.active_path, active_path)
        _, report_identity = recovery._read_regular(
            report_path, 128 * 1024, "test report")
        _, active_identity = recovery._read_regular(
            active_path, 256 * 1024, "test active journal")
        return recovery.Authority(
            self.root, report_path, active_path,
            directory / "retired.jsonl", directory / "recovery.jsonl",
            directory / "evidence.json", report_identity,
            {**active_identity, "path": str(active_path)},
            retained.dependency_identities)

    @staticmethod
    def _plan(stable: str = "fixed") -> dict[str, object]:
        observation = {
            "activitySha256": "1" * 64,
            "windowSha256": "2" * 64,
            "displaySha256": "3" * 64,
            "stable": stable,
        }
        return {
            "authority": recovery.PLAN_AUTHORITY,
            "bindingSha256": "a" * 64,
            "first": copy.deepcopy(observation),
            "second": copy.deepcopy(observation),
        }

    @staticmethod
    def _observation() -> recovery.Observation:
        process = host.ProcessIdentity(
            recovery.DOCUMENT_PID, 44_444, recovery.DOCUMENT_UID,
            alpha.DOCUMENT_PACKAGE)
        document = {
            "taskId": 4_634, "activityToken": "doc-token",
            "component": alpha.DOCUMENT_COMPONENT,
            "process": asdict(process),
        }
        visual_host = {
            "taskId": 4_633, "activityToken": "host-token",
            "component": alpha.HOST_COMPONENT,
        }
        return recovery.Observation(
            {}, visual_host, document, (), "1" * 64, "2" * 64,
            "3" * 64, {}, ("1", "2"))

    def test_execute_uses_exact_order_and_publishes_archive_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            authority = self._execution_authority(directory)
            device = FakeExecutionDevice()
            plan = self._plan()
            observation = self._observation()
            with (mock.patch.object(
                        recovery, "build_plan",
                        return_value=copy.deepcopy(plan)),
                  mock.patch.object(
                        recovery, "observe", return_value=observation),
                  mock.patch.object(
                        recovery, "_document_task_absent",
                        side_effect=lambda target, pinned:
                        not target.document_task_live),
                  mock.patch.object(
                        recovery, "_host_task_absent_and_display_gone",
                        side_effect=lambda target, pinned:
                        not target.host_task_live)):
                result = recovery.execute(
                    authority, device, copy.deepcopy(plan),
                    {"path": "test-plan", "sha256": "b" * 64})

            self.assertEqual("LAUNCH_IDENTITY_RECOVERED_CLEANLY",
                             result["result"])
            self.assertEqual(
                ["remove_exact_task", "remove_exact_task",
                 "force_stop_document",
                 "recovery_quarantine_" + Path(recovery.TARGET_MARK).name,
                 "recovery_remove_" +
                 Path(recovery.QUARANTINE_MARK).name,
                 "recovery_quarantine_" + Path(recovery.TARGET_PDF).name,
                 "recovery_remove_" +
                 Path(recovery.QUARANTINE_PDF).name],
                [item["operation"] for item in device.history])
            self.assertFalse(authority.active_path.exists())
            self.assertTrue(authority.retired_path.exists())
            self.assertTrue(authority.ledger_path.exists())
            self.assertTrue(authority.evidence_path.exists())
            self.assertNotIn(recovery.TARGET_MARK, device.files)
            self.assertNotIn(recovery.TARGET_PDF, device.files)
            self.assertEqual(recovery.ORIGINALS[recovery.ORIGINAL_PDF],
                             device.files[recovery.ORIGINAL_PDF])
            self.assertEqual(recovery.PARKING,
                             device.files[recovery.PARKING_PDF])

    def test_stable_plan_drift_fails_before_ledger_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = self._execution_authority(Path(directory_name))
            device = FakeExecutionDevice()
            with mock.patch.object(
                    recovery, "build_plan", return_value=self._plan("drift")):
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "live authority no longer matches"):
                    recovery.execute(
                        authority, device, self._plan(),
                        {"path": "test-plan", "sha256": "b" * 64})
            self.assertEqual([], device.history)
            self.assertFalse(authority.ledger_path.exists())
            self.assertTrue(authority.active_path.exists())
            self.assertFalse(authority.retired_path.exists())

    def test_lost_reply_may_settle_once_by_exact_postcondition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = recovery.Journal(
                Path(directory) / "recovery.jsonl", {"test": True})
            try:
                def uncertain():
                    raise recovery.MutationTransportUncertain("lost reply")

                recovery._dispatch_one(
                    journal, "remove-document-task", "remove_exact_task",
                    {"taskId": 1}, uncertain, lambda: True)
                self.assertEqual(
                    ["header", "remove-document-task-intent",
                     "remove-document-task-settled"],
                    [record["kind"] for record in journal.records])
                self.assertEqual(
                    "lost reply",
                    journal.records[-1]["payload"]["transportError"])
            finally:
                journal.close()


if __name__ == "__main__":
    unittest.main()
