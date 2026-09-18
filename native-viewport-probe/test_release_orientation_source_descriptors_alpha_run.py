from __future__ import annotations

from dataclasses import replace
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import native_page_alpha_runner as alpha
import native_page_host_authority as host
import recover_orientation_source_alpha_run as prior
import release_orientation_source_descriptors_alpha_run as release
import test_continue_orientation_source_after_parking_alpha_run as after_test


EXPECTED_THREAT_BOUNDARY = (
    "no deliberate concurrent human or independent local/device actor changes "
    "the report, adb, helper/dependency source, predecessor ledger, active or "
    "retired journal after its last full local authority guard, changes a "
    "protected device pathname after the second exact file pass, or relaunches "
    "a task/process during the final runtime closure and literal dispatch, "
    "archive, or evidence publication; every drift observable inside the "
    "recorded file-runtime-file-runtime sandwich fails closed, the current "
    "release-ledger handle is still revalidated, and no kernel atomicity is "
    "claimed")


class FakeDevice(after_test.FakeDevice):
    def __init__(self) -> None:
        super().__init__()
        self.task_live = False
        self.force_stop_mode = "release"
        self.fd_override: str | None = None
        self.after_fd_read = None
        self.restarted_pid: int | None = None
        self.restarted_token = "deadbee"
        self.restarted_start = 9_999
        self.restarted_fd_raw = (
            "lr-x------ 1 root root 64 2026-09-17 01:40 40 -> "
            "/system/framework/framework.jar\n")
        self.conditional_attempts = []

    def pidof(self, package):
        if package == alpha.DOCUMENT_PACKAGE:
            result = ([release.PINNED_PROCESS.pid]
                      if self.document_live else [])
            if self.restarted_pid is not None:
                result.append(self.restarted_pid)
            return tuple(sorted(result))
        return super().pidof(package)

    def process_identity(self, pid, package):
        if (package == alpha.DOCUMENT_PACKAGE and
                pid == self.restarted_pid):
            return host.ProcessIdentity(
                pid, self.restarted_start, 1000, alpha.DOCUMENT_PACKAGE)
        return super().process_identity(pid, package)

    def host_processes(self):
        raw = super().host_processes().decode("utf-8")
        if self.restarted_pid is not None:
            block = (
                "  *APP* UID 1000 ProcessRecord{" + self.restarted_token +
                " " + str(self.restarted_pid) + ":" +
                alpha.DOCUMENT_PACKAGE + "/1000}\n"
                "    pid=" + str(self.restarted_pid) + " starting=false\n"
                "    packageList={" + alpha.DOCUMENT_PACKAGE + "}\n")
            marker = "  Process OOM control (31 total, non-act at 4, non-svc at 4):\n"
            raw = raw.replace(marker, block + marker, 1)
        return raw.encode("utf-8")

    def process_fd_links(self, pid):
        if pid == self.restarted_pid:
            value = self.restarted_fd_raw
        else:
            value = (self.fd_override if self.fd_override is not None else
                     super().process_fd_links(pid))
        callback = self.after_fd_read
        if callback is not None and pid == release.PINNED_PROCESS.pid:
            self.after_fd_read = None
            callback()
        return value

    def force_stop_document(self):
        self.history.append({"operation": "force_stop_document"})
        if self.force_stop_mode in {"release", "uncertain", "bad", "garbage"}:
            self.document_live = False
            self.fds_closed = True
        if self.force_stop_mode == "uncertain":
            raise prior.MutationTransportUncertain(
                "simulated lost force-stop reply")
        if self.force_stop_mode == "bad":
            return alpha.CommandResult(
                "force_stop_document", (), 1, b"", b"Error\n")
        if self.force_stop_mode == "garbage":
            return alpha.CommandResult(
                "force_stop_document", (), 0, b"Killed\n", b"")
        return alpha.CommandResult(
            "force_stop_document", (), 0, b"", b"")

    def _conditional_phase_matches(self, mode, source, target):
        regular, absent = release._conditional_file_phase(
            mode, source, target)
        return (all(self.files.get(item.path) == item for item in regular) and
                all(path not in self.files for path in absent))

    def move_quarantine_if_exact(self, source, target):
        self.conditional_attempts.append(("move", source, target))
        if not self._conditional_phase_matches("move", source, target):
            return alpha.CommandResult(
                "recovery_quarantine_" + Path(source).name,
                (), 73, b"", b"")
        return super().move_quarantine(source, target)

    def remove_quarantine_if_exact(self, source, target):
        self.conditional_attempts.append(("delete", source, target))
        if not self._conditional_phase_matches("delete", source, target):
            return alpha.CommandResult(
                "recovery_remove_" + Path(target).name,
                (), 73, b"", b"")
        return super().remove_quarantine(target)


class TestRelease(release.Release):
    """Use the immutable pending record for admission; runtime stays real."""

    def _descriptor_observation(self):
        value = self.authority.after_summary["pending"]["observations"][0]
        return json.loads(json.dumps(value))


class DescriptorReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = after_test.AfterParkingTests(
            "test_plan_is_read_only_and_adopts_exact_four_record_ledger")
        self.base.setUp()
        self.source = Path(__file__).parent.resolve()
        self.after_ledger = self.base.authority.journal_path
        shutil.copyfile(
            self.source / "build" / "native-page-alpha-runs" /
            prior.RUN_ID / release.after.JOURNAL_BASENAME,
            self.after_ledger)
        after_raw, after_identity = release._read_sole_regular(
            self.after_ledger, 256 * 1024, "test after-parking ledger")
        after_summary = release._validate_after_ledger(after_raw)
        base = self.base.authority
        self.authority = release.Authority(
            self.source, base.run_dir, base.report_path, base.active_path,
            base.run_dir / release.JOURNAL_BASENAME,
            base.run_dir / release.EVIDENCE_BASENAME,
            base.run_dir / release.PENDING_EVIDENCE_BASENAME,
            base.retired_path, base.report_identity, base.active_identity,
            base.prior_path, base.prior_identity, base.prior_summary,
            base.first_path, base.first_identity, base.first_summary,
            self.after_ledger, after_identity, after_summary,
            base.prior_helper_path, base.first_helper_path,
            self.source /
            "continue_orientation_source_after_parking_alpha_run.py",
            base.dependency_paths)
        self.device = FakeDevice()
        self.journals: list[release.Journal] = []

    def tearDown(self) -> None:
        for journal in self.journals:
            journal.close()
        self.base.tearDown()

    def make_release(self, execute: bool = False) -> release.Release:
        probe = TestRelease(
            self.device, self.authority, sleep=lambda _: None)
        if not execute:
            return probe
        admission = probe.plan()
        header = probe._header()
        header["admissionSha256"] = prior._canonical_sha(admission)
        journal = release.Journal(self.authority.journal_path, header)
        self.journals.append(journal)
        recovery = TestRelease(
            self.device, self.authority, sleep=lambda _: None,
            journal=journal, durable_header=journal.records[0]["payload"],
            prior_admission=admission)
        journal.external_guard = recovery._assert_dispatch_authority
        return recovery

    def operations(self) -> list[str]:
        return [str(item["operation"]) for item in self.device.history]

    def test_exact_after_ledger_binding_and_plan_are_read_only(self):
        result = self.make_release().plan()
        self.assertEqual("DESCRIPTOR_RELEASE_PLAN_READY", result["result"])
        self.assertEqual(release.AFTER_HEAD,
                         result["afterParking"]["summary"]["head"])
        self.assertEqual([], self.device.history)
        self.assertFalse(self.authority.journal_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())
        self.assertFalse(self.authority.pending_evidence_path.exists())

    def test_validated_force_stop_releases_then_cleans_in_exact_order(self):
        recovery = self.make_release(True)
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_RECOVERED_CLEANLY",
                         result["result"])
        self.assertEqual(
            ["force_stop_document", "move", "delete", "move", "delete"],
            self.operations())
        self.assertNotIn(alpha.TARGET_MARK, self.device.files)
        self.assertNotIn(alpha.TARGET_PDF, self.device.files)
        self.assertEqual(prior.PINNED_PARKING,
                         self.device.files[alpha.PARKING_PDF])
        self.assertFalse(self.authority.active_path.exists())
        self.assertTrue(self.authority.retired_path.exists())
        self.assertTrue(self.authority.evidence_path.exists())
        self.assertFalse(self.authority.pending_evidence_path.exists())
        self.assertEqual(
            release.DEVICE_CONDITIONAL_MUTATION_ASSUMPTION,
            result["conditionalDeviceMutationAssumption"])
        self.assertEqual(
            EXPECTED_THREAT_BOUNDARY,
            release.AUTHORIZED_RECOVERY_THREAT_BOUNDARY)
        self.assertEqual(
            EXPECTED_THREAT_BOUNDARY,
            result["authorizedRecoveryThreatBoundary"])
        self.assertEqual(
            EXPECTED_THREAT_BOUNDARY,
            result["postArchiveBoundary"]["residualThreatBoundary"])
        assert recovery.journal is not None
        self.assertEqual(
            EXPECTED_THREAT_BOUNDARY,
            recovery.journal.records[0]["payload"][
                "authorizedRecoveryThreatBoundary"])

    def test_persistent_descriptors_publish_pending2_without_file_mutation(self):
        self.device.force_stop_mode = "persistent"
        result = self.make_release(True).execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertEqual(prior.PINNED_TARGET_MARK,
                         self.device.files[alpha.TARGET_MARK])
        self.assertEqual(prior.PINNED_TARGET_PDF,
                         self.device.files[alpha.TARGET_PDF])
        self.assertTrue(self.authority.active_path.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertTrue(self.authority.pending_evidence_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())
        self.assertEqual(
            EXPECTED_THREAT_BOUNDARY,
            result["authorizedRecoveryThreatBoundary"])

    def test_pending_execute_cannot_repeat_force_stop(self):
        self.device.force_stop_mode = "persistent"
        recovery = self.make_release(True)
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2",
                         recovery.execute()["result"])
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual(["force_stop_document"], self.operations())

    def test_transport_uncertainty_is_always_pending_and_never_cleans(self):
        self.device.force_stop_mode = "uncertain"
        recovery = self.make_release(True)

        def forbidden_poll():
            self.fail("transport-uncertain force-stop must not poll device")

        recovery._prove_release_after_stop = forbidden_poll
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertTrue(self.authority.active_path.exists())
        self.assertIn(alpha.TARGET_MARK, self.device.files)
        self.assertIn(alpha.TARGET_PDF, self.device.files)
        self.assertEqual(
            "TRANSPORT_UNCERTAIN", result["forceStopDispatch"]["mode"])

    def _assert_authoritative_bad_force_stop_receipt(self, mode: str) -> None:
        self.device.force_stop_mode = mode
        recovery = self.make_release(True)
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            recovery.execute()
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertIn(alpha.TARGET_MARK, self.device.files)
        self.assertIn(alpha.TARGET_PDF, self.device.files)
        self.assertTrue(self.authority.active_path.exists())

    def test_authoritative_nonzero_force_stop_receipt_is_fatal(self):
        self._assert_authoritative_bad_force_stop_receipt("bad")

    def test_authoritative_garbage_force_stop_receipt_is_fatal(self):
        self._assert_authoritative_bad_force_stop_receipt("garbage")

    def test_natural_release_before_dispatch_skips_force_stop(self):
        recovery = self.make_release(True)
        self.device.document_live = False
        self.device.fds_closed = True
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_RECOVERED_CLEANLY",
                         result["result"])
        self.assertEqual(["move", "delete", "move", "delete"],
                         self.operations())

    def test_late_document_task_during_fd_read_blocks_force_stop(self):
        recovery = self.make_release(True)
        self.device.after_fd_read = lambda: setattr(
            self.device, "task_live", True)
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual([], self.operations())
        self.assertIn(alpha.TARGET_MARK, self.device.files)
        self.assertIn(alpha.TARGET_PDF, self.device.files)

    def test_pre_dispatch_pidof_error_publishes_pending_without_force_stop(self):
        recovery = self.make_release(True)
        original = self.device.pidof

        def fail_document_pidof(package):
            if package == alpha.DOCUMENT_PACKAGE:
                raise release.ReleaseError("simulated pidof read failure")
            return original(package)

        self.device.pidof = fail_document_pidof
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual([], self.operations())
        self.assertTrue(self.authority.active_path.exists())
        self.assertTrue(self.authority.pending_evidence_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())
        self.assertIn(alpha.TARGET_MARK, self.device.files)
        self.assertIn(alpha.TARGET_PDF, self.device.files)

    def test_post_receipt_observation_error_publishes_pending_once(self):
        recovery = self.make_release(True)
        original_force_stop = self.device.force_stop_document
        original_pidof = self.device.pidof

        def force_stop_then_break_observation():
            result = original_force_stop()

            def fail_document_pidof(package):
                if package == alpha.DOCUMENT_PACKAGE:
                    raise release.ReleaseError(
                        "simulated post-receipt pidof failure")
                return original_pidof(package)

            self.device.pidof = fail_document_pidof
            return result

        self.device.force_stop_document = force_stop_then_break_observation
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertTrue(self.authority.active_path.exists())
        self.assertTrue(self.authority.pending_evidence_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())
        self.assertIn(alpha.TARGET_MARK, self.device.files)
        self.assertIn(alpha.TARGET_PDF, self.device.files)

    def test_task_reappearance_during_heavy_guard_blocks_force_stop(self):
        recovery = self.make_release(True)
        assert recovery.journal is not None
        original = recovery.journal.assert_authority
        armed = True

        def guard_then_reappear():
            nonlocal armed
            original()
            if armed:
                armed = False
                self.device.task_live = True

        recovery.journal.assert_authority = guard_then_reappear
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual([], self.operations())

    def test_remote_process_after_force_stop_stays_pending(self):
        original = self.device.force_stop_document

        def release_with_remote():
            result = original()
            self.device.extra_document_process_line = (
                "    Proc # 0: cch C/CEM --- t: 0 2999:"
                "com.supernote.document:remote/1000 (cch-empty)")
            return result

        self.device.force_stop_document = release_with_remote
        result = self.make_release(True).execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertIn(alpha.TARGET_PDF, self.device.files)

    def test_restarted_main_process_without_relevant_fds_is_exhaustively_safe(self):
        recovery = self.make_release()
        self.device.document_live = False
        self.device.fds_closed = True
        self.device.restarted_pid = 2999
        sample = recovery._runtime_descriptor_sample()
        self.assertEqual("RELEASED", sample["state"])
        self.assertEqual([2999], sample["view"]["pids"])
        self.assertEqual([], sample["relevantFdTargets"])

    def test_restarted_main_process_target_or_quarantine_fd_is_not_released(self):
        recovery = self.make_release()
        self.device.document_live = False
        self.device.fds_closed = True
        self.device.restarted_pid = 2999
        for target in (alpha.TARGET_PDF, prior.QUARANTINE_PDF,
                       prior.QUARANTINE_MARK + " (deleted)"):
            with self.subTest(target=target):
                self.device.restarted_fd_raw = (
                    "lr-x------ 1 root root 64 2026-09-17 01:40 77 -> " +
                    target + "\n")
                sample = recovery._runtime_descriptor_sample()
                self.assertNotEqual("RELEASED", sample["state"])
                self.assertIn(target, sample["relevantFdTargets"])

    def test_document_reappearance_before_first_file_move_blocks_move(self):
        recovery = self.make_release(True)
        original = recovery._runtime_file_boundary

        def reopen(path, quarantine, expected, *, source_present):
            self.device.document_live = True
            self.device.fds_closed = False
            return original(path, quarantine, expected,
                            source_present=source_present)

        recovery._runtime_file_boundary = reopen
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertIn(alpha.TARGET_MARK, self.device.files)

    def test_reappearance_from_closing_file_stat_blocks_move(self):
        recovery = self.make_release(True)
        original_boundary = recovery._runtime_file_boundary

        def install_stat_hook(path, quarantine, expected, *, source_present):
            original_stat = self.device.stat_file
            current_reads = 0

            def stat_with_reappearance(candidate, *, absent_ok=False):
                nonlocal current_reads
                value = original_stat(candidate, absent_ok=absent_ok)
                if candidate == path:
                    current_reads += 1
                    if current_reads == 2:
                        self.device.document_live = True
                        self.device.fds_closed = False
                return value

            self.device.stat_file = stat_with_reappearance
            return original_boundary(
                path, quarantine, expected, source_present=source_present)

        recovery._runtime_file_boundary = install_stat_hook
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual(["force_stop_document"], self.operations())

    def test_parking_identity_drift_during_runtime_blocks_move(self):
        recovery = self.make_release(True)
        original_boundary = recovery._runtime_file_boundary

        def drift_during_runtime(path, quarantine, expected, *, source_present):
            original_runtime = recovery._runtime_descriptor_sample

            def runtime_then_drift():
                value = original_runtime()
                recovery._runtime_descriptor_sample = original_runtime
                self.device.files[alpha.PARKING_PDF] = replace(
                    prior.PINNED_PARKING, inode=999_992)
                return value

            recovery._runtime_descriptor_sample = runtime_then_drift
            return original_boundary(
                path, quarantine, expected, source_present=source_present)

        recovery._runtime_file_boundary = drift_during_runtime
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual(["force_stop_document"], self.operations())

    def test_source_drift_after_final_runtime_is_rejected_by_same_dispatch(self):
        recovery = self.make_release(True)
        original_boundary = recovery._runtime_file_boundary
        injected = False

        def inject_after_final_runtime(
                path, quarantine, expected, *, source_present):
            nonlocal injected
            original_runtime = recovery._runtime_descriptor_sample
            calls = 0

            def runtime_then_drift():
                nonlocal calls, injected
                value = original_runtime()
                calls += 1
                if (not injected and source_present and
                        path == alpha.TARGET_MARK and calls == 2):
                    injected = True
                    self.device.files[path] = replace(
                        expected, inode=999_995)
                return value

            recovery._runtime_descriptor_sample = runtime_then_drift
            try:
                return original_boundary(
                    path, quarantine, expected,
                    source_present=source_present)
            finally:
                recovery._runtime_descriptor_sample = original_runtime

        recovery._runtime_file_boundary = inject_after_final_runtime
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            recovery.execute()
        self.assertTrue(injected)
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertNotIn(prior.QUARANTINE_MARK, self.device.files)
        self.assertEqual(999_995, self.device.files[alpha.TARGET_MARK].inode)

    def test_quarantine_drift_after_final_runtime_blocks_unlink(self):
        recovery = self.make_release(True)
        original_boundary = recovery._runtime_file_boundary
        injected = False

        def inject_after_final_runtime(
                path, quarantine, expected, *, source_present):
            nonlocal injected
            original_runtime = recovery._runtime_descriptor_sample
            calls = 0

            def runtime_then_drift():
                nonlocal calls, injected
                value = original_runtime()
                calls += 1
                if (not injected and not source_present and
                        path == alpha.TARGET_MARK and calls == 2):
                    injected = True
                    current = self.device.files[quarantine]
                    self.device.files[quarantine] = replace(
                        current, inode=999_996)
                return value

            recovery._runtime_descriptor_sample = runtime_then_drift
            try:
                return original_boundary(
                    path, quarantine, expected,
                    source_present=source_present)
            finally:
                recovery._runtime_descriptor_sample = original_runtime

        recovery._runtime_file_boundary = inject_after_final_runtime
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            recovery.execute()
        self.assertTrue(injected)
        self.assertEqual(
            ["force_stop_document", "move"], self.operations())
        self.assertIn(prior.QUARANTINE_MARK, self.device.files)
        self.assertEqual(
            999_996, self.device.files[prior.QUARANTINE_MARK].inode)

    def test_parking_drift_after_final_runtime_blocks_composite_move(self):
        recovery = self.make_release(True)
        original_boundary = recovery._runtime_file_boundary
        injected = False

        def inject_after_final_runtime(
                path, quarantine, expected, *, source_present):
            nonlocal injected
            original_runtime = recovery._runtime_descriptor_sample
            calls = 0

            def runtime_then_drift():
                nonlocal calls, injected
                value = original_runtime()
                calls += 1
                if (not injected and source_present and
                        path == alpha.TARGET_MARK and calls == 2):
                    injected = True
                    self.device.files[alpha.PARKING_PDF] = replace(
                        prior.PINNED_PARKING, inode=999_997)
                return value

            recovery._runtime_descriptor_sample = runtime_then_drift
            try:
                return original_boundary(
                    path, quarantine, expected,
                    source_present=source_present)
            finally:
                recovery._runtime_descriptor_sample = original_runtime

        recovery._runtime_file_boundary = inject_after_final_runtime
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            recovery.execute()
        self.assertTrue(injected)
        self.assertEqual(["force_stop_document"], self.operations())
        self.assertIn(alpha.TARGET_MARK, self.device.files)

    def test_quarantine_or_deleted_fd_never_authorizes_unlink(self):
        recovery = self.make_release(True)
        original = recovery._runtime_file_boundary
        injected = False

        def reopen_on_mark_unlink(path, quarantine, expected, *, source_present):
            nonlocal injected
            if path == alpha.TARGET_MARK and not source_present and not injected:
                injected = True
                self.device.document_live = True
                self.device.fds_closed = False
                self.device.fd_override = (
                    "lr-x------ 1 root root 64 2026-09-17 01:40 77 -> " +
                    quarantine + " (deleted)\n")
            return original(path, quarantine, expected,
                            source_present=source_present)

        recovery._runtime_file_boundary = reopen_on_mark_unlink
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual(["force_stop_document", "move"], self.operations())
        self.assertIn(prior.QUARANTINE_MARK, self.device.files)
        self.assertNotIn(alpha.TARGET_MARK, self.device.files)
        self.assertTrue(self.authority.active_path.exists())

    def test_restart_during_heavy_delete_guard_blocks_unlink(self):
        recovery = self.make_release(True)
        assert recovery.journal is not None
        original_move = self.device.move_quarantine_if_exact
        original_guard = recovery.journal.assert_authority
        armed = False

        def move_then_arm(source, target):
            nonlocal armed
            result = original_move(source, target)
            if source == alpha.TARGET_MARK:
                armed = True
            return result

        def guard_then_restart():
            nonlocal armed
            original_guard()
            if armed:
                armed = False
                self.device.restarted_pid = 2999
                self.device.restarted_fd_raw = (
                    "lr-x------ 1 root root 64 2026-09-17 01:40 77 -> " +
                    prior.QUARANTINE_MARK + "\n")

        self.device.move_quarantine_if_exact = move_then_arm
        recovery.journal.assert_authority = guard_then_restart
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual(["force_stop_document", "move"], self.operations())
        self.assertIn(prior.QUARANTINE_MARK, self.device.files)

    def test_target_reappearance_before_archive_prevents_archive_and_clean(self):
        recovery = self.make_release(True)
        original = recovery._released_file_settlement_boundary

        def reappear(kind, **kwargs):
            if kind == "immediate_pre_active_journal_archive":
                self.device.files[alpha.TARGET_MARK] = replace(
                    prior.PINNED_TARGET_MARK, inode=999_991)
            return original(kind, **kwargs)

        recovery._released_file_settlement_boundary = reappear
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertFalse(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_target_reappearance_after_archive_intent_prevents_rename(self):
        recovery = self.make_release(True)
        original_intent = recovery._intent

        def reappear_after_intent(name, payload):
            original_intent(name, payload)
            if name == "active_journal_archive":
                self.device.files[alpha.TARGET_PDF] = replace(
                    prior.PINNED_TARGET_PDF, inode=999_993)

        recovery._intent = reappear_after_intent
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(self.authority.active_path.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_target_drift_after_final_runtime_prevents_archive_rename(self):
        recovery = self.make_release(True)
        original_boundary = recovery._released_file_settlement_boundary
        injected = False

        def inject_inside_boundary(kind, **kwargs):
            nonlocal injected
            if kind != "post_intent_pre_active_journal_rename":
                return original_boundary(kind, **kwargs)
            original_runtime = recovery._runtime_descriptor_sample
            calls = 0

            def runtime_then_reappear():
                nonlocal calls, injected
                value = original_runtime()
                calls += 1
                if calls == 2:
                    injected = True
                    self.device.files[alpha.TARGET_MARK] = replace(
                        prior.PINNED_TARGET_MARK, inode=999_981)
                return value

            recovery._runtime_descriptor_sample = runtime_then_reappear
            try:
                return original_boundary(kind, **kwargs)
            finally:
                recovery._runtime_descriptor_sample = original_runtime

        recovery._released_file_settlement_boundary = inject_inside_boundary
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(injected)
        self.assertTrue(self.authority.active_path.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_task_appearance_during_second_archive_file_pass_blocks_rename(self):
        recovery = self.make_release(True)
        original_boundary = recovery._released_file_settlement_boundary
        injected = False

        def inject_inside_boundary(kind, **kwargs):
            nonlocal injected
            if kind != "post_intent_pre_active_journal_rename":
                return original_boundary(kind, **kwargs)
            original_snapshot = recovery._file_authority_snapshot
            calls = 0

            def files_then_reopen(*args, **snapshot_kwargs):
                nonlocal calls, injected
                value = original_snapshot(*args, **snapshot_kwargs)
                calls += 1
                if calls == 4:
                    injected = True
                    self.device.task_live = True
                return value

            recovery._file_authority_snapshot = files_then_reopen
            try:
                return original_boundary(kind, **kwargs)
            finally:
                recovery._file_authority_snapshot = original_snapshot

        recovery._released_file_settlement_boundary = inject_inside_boundary
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(injected)
        self.assertTrue(self.authority.active_path.exists())
        self.assertFalse(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_target_drift_after_final_runtime_blocks_clean_evidence(self):
        recovery = self.make_release(True)
        original_boundary = recovery._released_file_settlement_boundary
        injected = False

        def inject_inside_boundary(kind, **kwargs):
            nonlocal injected
            if kind != "immediate_pre_clean_evidence_publication":
                return original_boundary(kind, **kwargs)
            original_runtime = recovery._runtime_descriptor_sample
            calls = 0

            def runtime_then_reappear():
                nonlocal calls, injected
                value = original_runtime()
                calls += 1
                if calls == 2:
                    injected = True
                    self.device.files[alpha.TARGET_PDF] = replace(
                        prior.PINNED_TARGET_PDF, inode=999_982)
                return value

            recovery._runtime_descriptor_sample = runtime_then_reappear
            try:
                return original_boundary(kind, **kwargs)
            finally:
                recovery._runtime_descriptor_sample = original_runtime

        recovery._released_file_settlement_boundary = inject_inside_boundary
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(injected)
        self.assertTrue(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_task_appearance_during_final_publication_files_blocks_evidence(self):
        recovery = self.make_release(True)
        original_publish = recovery._publish_result
        injected = False

        def publish_with_task_reappearance(path, result, *, archived):
            nonlocal injected
            if not archived:
                return original_publish(path, result, archived=archived)
            original_snapshot = recovery._file_authority_snapshot
            calls = 0

            def files_then_reopen(*args, **kwargs):
                nonlocal calls, injected
                value = original_snapshot(*args, **kwargs)
                calls += 1
                if calls == 2:
                    injected = True
                    self.device.task_live = True
                return value

            recovery._file_authority_snapshot = files_then_reopen
            try:
                return original_publish(path, result, archived=archived)
            finally:
                recovery._file_authority_snapshot = original_snapshot

        recovery._publish_result = publish_with_task_reappearance
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(injected)
        self.assertTrue(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_report_change_after_archive_blocks_clean_publication(self):
        recovery = self.make_release(True)
        original_boundary = recovery._released_file_settlement_boundary

        def change_report(kind, **kwargs):
            if kind == "immediate_pre_clean_evidence_publication":
                self.authority.report_path.write_bytes(b"changed report\n")
            return original_boundary(kind, **kwargs)

        recovery._released_file_settlement_boundary = change_report
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_report_change_during_final_device_sample_blocks_publication(self):
        recovery = self.make_release(True)
        original_runtime = recovery._runtime_descriptor_sample
        archived_runtime_calls = 0

        def runtime_then_change_report():
            nonlocal archived_runtime_calls
            value = original_runtime()
            if self.authority.retired_path.exists():
                archived_runtime_calls += 1
                if archived_runtime_calls == 2:
                    self.authority.report_path.write_bytes(
                        b"changed during final device sample\n")
            return value

        recovery._runtime_descriptor_sample = runtime_then_change_report
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertTrue(self.authority.retired_path.exists())
        self.assertFalse(self.authority.evidence_path.exists())

    def test_after_ledger_tamper_fails_plan_without_mutation(self):
        self.after_ledger.write_bytes(self.after_ledger.read_bytes() + b"{}\n")
        with self.assertRaises(release.ReleaseError):
            self.make_release().plan()
        self.assertEqual([], self.operations())

    def test_after_ledger_tamper_after_header_blocks_force_stop(self):
        recovery = self.make_release(True)
        self.after_ledger.write_bytes(self.after_ledger.read_bytes() + b"{}\n")
        with self.assertRaises(release.ReleaseError):
            recovery.execute()
        self.assertEqual([], self.operations())

    def test_target_drift_after_header_settles_pending_without_force_stop(self):
        recovery = self.make_release(True)
        self.device.files[alpha.TARGET_PDF] = replace(
            prior.PINNED_TARGET_PDF, inode=999_994)
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual([], self.operations())
        self.assertTrue(self.authority.pending_evidence_path.exists())

    def test_process_token_drift_after_header_never_authorizes_force_stop(self):
        recovery = self.make_release(True)
        self.device.document_token = "deadbee"
        result = recovery.execute()
        self.assertEqual("DESCRIPTOR_RELEASE_PENDING_2", result["result"])
        self.assertEqual([], self.operations())

    def test_dependency_drift_after_header_blocks_force_stop(self):
        recovery = self.make_release(True)
        dependency = self.authority.dependency_paths["host"]
        dependency.write_bytes(dependency.read_bytes() + b"\n")
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            recovery.execute()
        self.assertEqual([], self.operations())

    def test_live_document_scope_fails_plan_before_journal(self):
        self.device.task_live = True
        with self.assertRaises(release.ReleaseError):
            self.make_release().plan()
        self.assertFalse(self.authority.journal_path.exists())
        self.assertEqual([], self.operations())

    def test_loaded_predecessor_module_must_be_official_path(self):
        original = release.after.__file__
        release.after.__file__ = str(self.base.root / "shadow_after.py")
        try:
            with self.assertRaises(release.ReleaseError):
                self.make_release().plan()
        finally:
            release.after.__file__ = original
        self.assertEqual([], self.operations())
        self.assertFalse(self.authority.journal_path.exists())

    def test_new_ledger_is_exclusive(self):
        recovery = self.make_release(True)
        self.assertIsNotNone(recovery.journal)
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            release.Journal(self.authority.journal_path, recovery._header())
        self.assertEqual([], self.operations())

    def test_journal_revalidates_after_external_guard(self):
        recovery = self.make_release(True)
        assert recovery.journal is not None
        journal = recovery.journal
        original_guard = journal.external_guard

        def truncate_during_guard():
            assert original_guard is not None
            original_guard()
            os.truncate(journal.path, 0)

        journal.external_guard = truncate_during_guard
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            journal.assert_authority()
        self.assertEqual([], self.operations())

    def test_publication_rechecks_journal_after_local_phase_scan(self):
        recovery = self.make_release(True)
        assert recovery.journal is not None
        original = recovery._assert_local_before_archive

        def truncate_after_local_scan():
            original()
            os.truncate(recovery.journal.path, 0)

        recovery._assert_local_before_archive = truncate_after_local_scan
        with self.assertRaises((release.ReleaseError, prior.RecoveryError)):
            recovery._publish_result(
                self.authority.pending_evidence_path,
                {"result": "TEST_ONLY"}, archived=False)
        self.assertFalse(self.authority.pending_evidence_path.exists())

    def test_force_stop_transport_is_exact_and_closed(self):
        calls = []

        def executor(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        nomad = object.__new__(release.DescriptorNomad)
        transport = object.__new__(prior.RecoveryNomad)
        transport.adb = "C:/exact/adb.exe"
        transport.serial = alpha.AUTHORIZED_SERIAL
        transport._executor = executor
        transport.history = []
        nomad._transport = transport
        result = nomad.force_stop_document()
        self.assertEqual(0, result.returncode)
        self.assertEqual((
            "C:/exact/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
            "exec-out", "am", "force-stop", "--user", "0",
            alpha.DOCUMENT_PACKAGE), calls[0][0])
        self.assertEqual(1, len(calls))

    def test_conditional_file_transport_is_one_closed_complete_dispatch(self):
        calls = []

        def executor(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        nomad = object.__new__(release.DescriptorNomad)
        transport = object.__new__(prior.RecoveryNomad)
        transport.adb = "C:/exact/adb.exe"
        transport.serial = alpha.AUTHORIZED_SERIAL
        transport._executor = executor
        transport.history = []
        nomad._transport = transport

        move = nomad.move_quarantine_if_exact(
            alpha.TARGET_MARK, prior.QUARANTINE_MARK)
        delete = nomad.remove_quarantine_if_exact(
            alpha.TARGET_MARK, prior.QUARANTINE_MARK)
        self.assertEqual(0, move.returncode)
        self.assertEqual(0, delete.returncode)
        self.assertEqual(2, len(calls))
        for index, (argv, kwargs) in enumerate(calls):
            self.assertEqual((
                "C:/exact/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                "exec-out", "sh", "-c"), tuple(argv[:6]))
            self.assertEqual("fixed-descriptor-release", argv[7])
            self.assertEqual(alpha.TARGET_MARK, argv[8])
            self.assertEqual(prior.QUARANTINE_MARK, argv[9])
            self.assertNotIn(alpha.TARGET_MARK, argv[6])
            self.assertNotIn(prior.QUARANTINE_MARK, argv[6])
            self.assertIn("%F,%s,%u,%g,%i,%d,%h", argv[6])
            self.assertIn("[ ! -L", argv[6])
            self.assertNotIn("eval", argv[6])
            self.assertTrue(kwargs["capture_output"])
            self.assertFalse(kwargs["check"])
            regular, absent = release._conditional_file_phase(
                "move" if index == 0 else "delete",
                alpha.TARGET_MARK, prior.QUARANTINE_MARK)
            for item in regular:
                self.assertIn(item.path, argv)
                self.assertIn(item.sha256, argv)
            for path in absent:
                self.assertIn(path, argv)

    def test_conditional_file_transport_rejects_path_and_bad_predicate(self):
        calls = []

        def predicate_failure(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 73, b"", b"")

        nomad = object.__new__(release.DescriptorNomad)
        transport = object.__new__(prior.RecoveryNomad)
        transport.adb = "C:/exact/adb.exe"
        transport.serial = alpha.AUTHORIZED_SERIAL
        transport._executor = predicate_failure
        transport.history = []
        nomad._transport = transport
        with self.assertRaises(release.ReleaseError):
            nomad.move_quarantine_if_exact(
                "/storage/emulated/0/Download/not-authorized",
                prior.QUARANTINE_MARK)
        self.assertEqual([], calls)
        result = nomad.move_quarantine_if_exact(
            alpha.TARGET_MARK, prior.QUARANTINE_MARK)
        with self.assertRaises(prior.RecoveryError):
            prior._validate_mutation_result(
                result,
                "recovery_quarantine_" + Path(alpha.TARGET_MARK).name,
                empty_stdout=True)
        self.assertEqual(1, len(calls))

        def garbage_receipt(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b"garbage\n", b"")

        transport._executor = garbage_receipt
        result = nomad.remove_quarantine_if_exact(
            alpha.TARGET_MARK, prior.QUARANTINE_MARK)
        with self.assertRaises(prior.RecoveryError):
            prior._validate_mutation_result(
                result,
                "recovery_remove_" + Path(prior.QUARANTINE_MARK).name,
                empty_stdout=True)
        self.assertEqual(2, len(calls))

    def test_conditional_file_timeout_is_transport_uncertain_once(self):
        calls = []

        def timeout(argv, **kwargs):
            calls.append(argv)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        nomad = object.__new__(release.DescriptorNomad)
        transport = object.__new__(prior.RecoveryNomad)
        transport.adb = "C:/exact/adb.exe"
        transport.serial = alpha.AUTHORIZED_SERIAL
        transport._executor = timeout
        transport.history = []
        nomad._transport = transport
        with self.assertRaises(prior.MutationTransportUncertain):
            nomad.remove_quarantine_if_exact(
                alpha.TARGET_MARK, prior.QUARANTINE_MARK)
        self.assertEqual(1, len(calls))
        self.assertEqual(1, len(transport.history))
        self.assertTrue(transport.history[0]["timeout"])

    def test_conditional_move_timeout_after_effect_settles_without_retry(self):
        self.device.fail_after.add("move_.mark")
        result = self.make_release(True).execute()
        self.assertEqual("DESCRIPTOR_RELEASE_RECOVERED_CLEANLY",
                         result["result"])
        self.assertEqual(
            ["force_stop_document", "move", "delete", "move", "delete"],
            self.operations())
        move_outcomes = [
            item for item in result["dispatchOutcomes"]
            if item["kind"] == "mark_quarantine_move"]
        self.assertEqual(1, len(move_outcomes))
        self.assertEqual("TRANSPORT_UNCERTAIN", move_outcomes[0]["mode"])
        self.assertEqual(
            [("move", alpha.TARGET_MARK, prior.QUARANTINE_MARK)],
            [item for item in self.device.conditional_attempts
             if item[0] == "move" and item[1] == alpha.TARGET_MARK])

    def test_source_has_no_prior_launch_or_task_removal_route(self):
        tree = ast.parse(Path(release.__file__).read_text(encoding="utf-8"))
        forbidden_attributes = {
            "launch_parking", "launch_parking_document", "remove_task",
            "remove_parking_task", "remove_exact_task", "remove_host_task",
            "move_quarantine", "remove_quarantine",
        }
        calls = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and
            isinstance(node.func, ast.Attribute)}
        methods = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertTrue(forbidden_attributes.isdisjoint(calls))
        self.assertTrue(forbidden_attributes.isdisjoint(methods))
        source = Path(release.__file__).read_text(encoding="utf-8")
        self.assertNotIn("am stack remove", source)
        self.assertNotIn("android.intent.action.VIEW", source)


if __name__ == "__main__":
    unittest.main()
