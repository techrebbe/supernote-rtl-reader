from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

import native_page_alpha_runner as alpha
import recover_launch_identity_alpha_run as recovery
import test_native_page_android_authority as android_test


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


if __name__ == "__main__":
    unittest.main()
