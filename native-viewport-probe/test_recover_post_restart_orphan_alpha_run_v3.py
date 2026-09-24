from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import recover_post_restart_orphan_alpha_run as v2
import recover_post_restart_orphan_alpha_run_v3 as v3
from test_recover_post_restart_orphan_alpha_run import FakeDevice


class FakeExecuteDevice(FakeDevice):
    def arm_file_mutations(self, preflight, expected_adb):
        self.preflight = preflight
        self.expected_adb = expected_adb

    def move_if_exact(self, source, quarantine):
        self.preflight("recovery_quarantine_" + Path(source).name)
        return super().move_if_exact(source, quarantine)

    def delete_if_exact(self, source, quarantine):
        raise AssertionError("v3 must never call device deletion")


class VersionedContinuationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.run_dir = Path(temporary.name)
        self.device = FakeExecuteDevice()
        authority = v2.Authority(
            self.run_dir, self.run_dir / "report.json",
            self.run_dir / "active.jsonl", self.run_dir / "retired.jsonl",
            self.run_dir / v2.LEDGER_BASENAME,
            self.run_dir / v2.EVIDENCE_BASENAME,
            self.run_dir / v2.PLAN_BASENAME,
            {"sha256": "a" * 64}, {"sha256": "b" * 64},
            {"dependency.py": {"sha256": "c" * 64}},
        )
        self.context = SimpleNamespace(
            authority=authority,
            plan={"bindingSha256": "d" * 64,
                  "first": v2.observe(self.device).wire()},
            plan_identity={"sha256": "e" * 64},
            ledger_identity={"sha256": "f" * 64},
            producer_identity={"sha256": "0" * 64},
            attestation_path=self.run_dir / "post-restart-orphan-noop-attestation.json",
        )
        self.session = v3.Session(
            self.context,
            {"bindingSha256": "1" * 64,
             "adb": self.device.adb_authority(),
             "first": copy.deepcopy(self.context.plan["first"]),
             "second": copy.deepcopy(self.context.plan["first"])},
            {"sha256": "2" * 64},
            self.run_dir / v3.PLAN_BASENAME,
            self.run_dir / v3.LEDGER_BASENAME,
            self.run_dir / v3.EVIDENCE_BASENAME,
        )

    def _current_v2(self) -> dict:
        first = v2.observe(self.device)
        second = v2.observe(self.device)
        v2._assert_stable(first, second)
        return {"adb": self.device.adb_authority(),
                "first": first.wire(), "second": second.wire()}

    def _plan(self) -> dict:
        with (mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "build_read_only_plan_with_wake_lock_retries",
                                return_value=self._current_v2())):
            return v3.build_plan(self.session, self.device)

    def _publish_test_plan(self, plan: dict) -> None:
        self.session.plan_path.write_bytes(v2._canonical(plan))

    def test_plan_binds_old_attempt_attestation_and_exact_transport(self) -> None:
        plan = self._plan()
        self.assertEqual(v3.PLAN_AUTHORITY, plan["authority"])
        self.assertEqual(3, plan["schemaVersion"])
        self.assertEqual(self.context.plan_identity, plan["oldV2Plan"])
        self.assertEqual(self.context.ledger_identity, plan["oldV2Ledger"])
        self.assertEqual(self.session.attestation_identity,
                         plan["noOpAttestation"])
        self.assertEqual(v3.TRANSPORT, plan["transport"])
        self.assertEqual(v3.FORBIDDEN, plan["forbiddenMutations"])
        self.assertEqual([], self.device.history)

    def test_load_plan_accepts_one_canonical_complete_plan(self) -> None:
        plan = self._plan()
        self._publish_test_plan(plan)
        with mock.patch.object(v3, "_guard_local"):
            observed, identity = v3.load_plan(self.session.plan_path,
                                               self.session)
        self.assertEqual(plan, observed)
        self.assertEqual(v2._sha(v2._canonical(plan)), identity["sha256"])

    def test_authenticated_field_changes_fail_even_after_rebinding(self) -> None:
        plan = self._plan()
        mutations = {
            "producer": {"sha256": "9" * 64},
            "oldV2Plan": {"sha256": "9" * 64},
            "oldV2Ledger": {"sha256": "9" * 64},
            "noOpAttestation": {"sha256": "9" * 64},
            "noOpAttestationBindingSha256": "9" * 64,
            "transport": "adb-exec-out-shell-sh-v1",
            "forbiddenMutations": [],
            "mutationOrder": list(reversed(v3.MUTATION_ORDER)),
            "schemaVersion": True,
        }
        for field, changed in mutations.items():
            with self.subTest(field=field):
                candidate = copy.deepcopy(plan)
                candidate[field] = changed
                candidate["bindingSha256"] = v2._canonical_sha({
                    key: value for key, value in candidate.items()
                    if key != "bindingSha256"})
                self._publish_test_plan(candidate)
                with mock.patch.object(v3, "_guard_local"):
                    with self.assertRaises(v3.RecoveryError):
                        v3.load_plan(self.session.plan_path, self.session)

    def test_missing_extra_and_duplicate_fields_fail_closed(self) -> None:
        plan = self._plan()
        for change in ("missing", "extra", "duplicate"):
            with self.subTest(change=change):
                if change == "duplicate":
                    raw = v2._canonical(plan).replace(
                        b'"schemaVersion":3',
                        b'"schemaVersion":3,"schemaVersion":3', 1)
                else:
                    candidate = copy.deepcopy(plan)
                    if change == "missing":
                        del candidate["oldV2Ledger"]
                    else:
                        candidate["unexpected"] = True
                    candidate["bindingSha256"] = v2._canonical_sha({
                        key: value for key, value in candidate.items()
                        if key != "bindingSha256"})
                    raw = v2._canonical(candidate)
                self.session.plan_path.write_bytes(raw)
                with mock.patch.object(v3, "_guard_local"):
                    with self.assertRaises((v3.RecoveryError,
                                            v2.RecoveryError,
                                            v2.launch.RecoveryError)):
                        v3.load_plan(self.session.plan_path, self.session)

    def test_attestation_drift_fails_before_build_or_mutation(self) -> None:
        with (mock.patch.object(v3.noop, "_guard"),
              mock.patch.object(v3.noop, "load_attestation",
                                return_value=(self.session.attestation,
                                              {"sha256": "9" * 64}))):
            with self.assertRaises(v3.RecoveryError):
                v3._guard_local(self.session)
        with mock.patch.object(v3.noop, "_guard", side_effect=RuntimeError("drift")):
            with self.assertRaisesRegex(RuntimeError, "drift"):
                v3._guard_local(self.session)

    def test_changed_file_observation_rejects_plan(self) -> None:
        current = self._current_v2()
        current["second"]["files"][v2.TARGET_MARK] = None
        with (mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "build_read_only_plan_with_wake_lock_retries",
                                return_value=current)):
            with self.assertRaises(v3.noop.AdjudicationError):
                v3.build_plan(self.session, self.device)

    def test_self_rehashed_attestation_scalar_drift_rejects_fresh_scope(self) -> None:
        tampered = copy.deepcopy(self.session.attestation)
        tampered["first"]["document"]["stable"]["process"]["start_ticks"] += 1
        tampered["second"]["document"]["stable"]["process"]["start_ticks"] += 1
        body = {key: value for key, value in tampered.items()
                if key != "bindingSha256"}
        tampered["bindingSha256"] = v2._canonical_sha(body)
        session = replace(self.session, attestation=tampered)
        with (mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "build_read_only_plan_with_wake_lock_retries",
                                return_value=self._current_v2())):
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "differs from no-op attestation"):
                v3.build_plan(session, self.device)

    def test_two_transport_tails_match_inherited_exact_move_script(self) -> None:
        class Capture(v3.Nomad):
            def _mutation(self, operation, tail):
                return operation, tail

        capture = Capture.__new__(Capture)
        for source in (v2.TARGET_MARK, v2.TARGET_PDF):
            quarantine = v2.QUARANTINES[source]
            with self.subTest(source=source):
                operation, tail = v2.launch.Nomad._file_mutation(
                    capture, "move", source, quarantine)
                self.assertIn(operation, v3._fixed_mutations())
                self.assertEqual(v3._fixed_script(), tail[3])
                self.assertEqual(("shell", "sh", "-c"), tail[:3])

    def test_transport_strips_only_shell_after_full_tail_validation(self) -> None:
        class Capture(v3.Nomad):
            def _mutation(self, operation, tail):
                return operation, tail

        source = v2.TARGET_MARK
        operation, tail = v2.launch.Nomad._file_mutation(
            Capture.__new__(Capture), "move", source,
            v2.QUARANTINES[source])
        device = v3.Nomad.__new__(v3.Nomad)
        preflight = mock.Mock()
        device._pre_mutation = preflight
        device._expected_adb = self.device.adb_authority()
        with (mock.patch.object(device, "adb_authority",
                                return_value=self.device.adb_authority()),
              mock.patch.object(v2.Nomad, "_mutation", return_value="sent") as send):
            self.assertEqual("sent", v3.Nomad._mutation(device, operation, tail))
        send.assert_called_once_with(operation, tail[1:])
        preflight.assert_called_once_with(operation)
        for replacement in (
                tail[:3] + (tail[3] + "; echo unsafe",) + tail[4:],
                tail[:7] + ("0" * 64,) + tail[8:],
                tail[:5] + (v2.TARGET_PDF,) + tail[6:],
                ("sh",) + tail[1:],
                tail + ("extra",)):
            with self.subTest(replacement=replacement):
                with self.assertRaises(v3.RecoveryError):
                    v3.Nomad._mutation(device, operation, replacement)
        with self.assertRaises(v3.RecoveryError):
            v3.Nomad._mutation(device, "remove_exact_task", tail)
        with self.assertRaises(v3.RecoveryError):
            v3.Nomad.delete_if_exact(device, source, v2.QUARANTINES[source])
        device._pre_mutation = mock.Mock(
            side_effect=v3.RecoveryError("local attestation drift"))
        with (mock.patch.object(device, "adb_authority",
                                return_value=self.device.adb_authority()),
              mock.patch.object(v2.Nomad, "_mutation") as send):
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "local attestation drift"):
                v3.Nomad._mutation(device, operation, tail)
            send.assert_not_called()

    def test_unarmed_transport_and_occupied_output_fail_closed(self) -> None:
        class Capture(v3.Nomad):
            def _mutation(self, operation, tail):
                return operation, tail

        source = v2.TARGET_MARK
        operation, tail = v2.launch.Nomad._file_mutation(
            Capture.__new__(Capture), "move", source,
            v2.QUARANTINES[source])
        device = v3.Nomad.__new__(v3.Nomad)
        device._pre_mutation = None
        with self.assertRaises(v3.RecoveryError):
            v3.Nomad._mutation(device, operation, tail)
        for path in (self.session.plan_path, self.session.ledger_path,
                     self.session.evidence_path):
            with self.subTest(path=path):
                path.write_bytes(b"occupied")
                with self.assertRaises(v3.RecoveryError):
                    v3._require_new_paths_vacant(self.session, plan=True)
                path.unlink()

    def test_adb_replacement_after_preflight_blocks_exec_out_dispatch(self) -> None:
        class Capture(v3.Nomad):
            def _mutation(self, operation, tail):
                return operation, tail

        source = v2.TARGET_MARK
        operation, tail = v2.launch.Nomad._file_mutation(
            Capture.__new__(Capture), "move", source,
            v2.QUARANTINES[source])
        device = v3.Nomad.__new__(v3.Nomad)
        expected = self.device.adb_authority()
        current = expected.copy()

        def drift_after_preflight(_operation):
            current["sha256"] = "9" * 64

        device._pre_mutation = drift_after_preflight
        device._expected_adb = expected.copy()
        with (mock.patch.object(device, "adb_authority", side_effect=lambda: current),
              mock.patch.object(v2.Nomad, "_mutation") as dispatch):
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "ADB executable changed immediately before file dispatch"):
                v3.Nomad._mutation(device, operation, tail)
            dispatch.assert_not_called()

    def test_checkpoint_rejects_local_drift_before_device_observation(self) -> None:
        plan = self._plan()
        with (mock.patch.object(v3, "_guard_local",
                                side_effect=v3.RecoveryError("drift")),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries")
              as observe):
            with self.assertRaisesRegex(v3.RecoveryError, "drift"):
                v3._checkpoint(self.session, self.device, plan,
                               v3.STAGE_INITIAL)
            observe.assert_not_called()

    def test_producer_drift_rejects_before_device_observation(self) -> None:
        plan = self._plan()
        with (mock.patch.object(v3, "_producer_identity",
                                return_value={"sha256": "9" * 64}),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries")
              as observe):
            with self.assertRaisesRegex(v3.RecoveryError, "producer changed"):
                v3._checkpoint(self.session, self.device, plan,
                               v3.STAGE_INITIAL)
            observe.assert_not_called()

    def test_checkpoint_rejects_file_drift_without_mutation(self) -> None:
        plan = self._plan()
        with (mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                return_value={}),
              mock.patch.object(v3, "_assert_stage_files",
                                side_effect=v3.RecoveryError("file drift"))):
            with self.assertRaisesRegex(v3.RecoveryError, "file drift"):
                v3._checkpoint(self.session, self.device, plan,
                               v3.STAGE_INITIAL)
        self.assertEqual([], self.device.history)

    def test_occupied_quarantine_rejects_before_move(self) -> None:
        source = v2.TARGET_MARK
        quarantine = v2.QUARANTINES[source]
        self.device.files[quarantine] = v2._renamed(
            v2.TARGETS[source], quarantine)
        with self.assertRaisesRegex(v3.RecoveryError,
                                    "file identity differs"):
            v3._assert_stage_files(self.device, v3.STAGE_INITIAL)
        self.assertEqual([], self.device.history)

    def test_raced_source_move_keeps_replacement_in_quarantine(self) -> None:
        class RacedSource(FakeExecuteDevice):
            def move_if_exact(self, source, quarantine):
                self.preflight("recovery_quarantine_" + Path(source).name)
                self.files[source] = replace(
                    self.files[source], inode=self.files[source].inode + 1)
                return FakeDevice.move_if_exact(self, source, quarantine)

        device = RacedSource()
        device.arm_file_mutations(lambda _operation: None,
                                  device.adb_authority())
        journal = v3.Journal(self.run_dir / "race-ledger.jsonl", {})
        try:
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "did not reach exact postcondition"):
                v3._quarantine_one(journal, device, v2.TARGET_MARK,
                                   v3.STAGE_MARK)
        finally:
            journal.close()
        moved = device.files[v2.QUARANTINES[v2.TARGET_MARK]]
        self.assertEqual(v2.TARGETS[v2.TARGET_MARK].inode + 1, moved.inode)
        self.assertEqual(["header", "quarantine-intent", "quarantine-unsettled"],
                         [v2._strict_json(line, "record")["kind"] for line in
                          (self.run_dir / "race-ledger.jsonl").read_bytes().splitlines()])

    def _active_fixture(self) -> bytes:
        content = b"A" * v2.launch.ACTIVE_BYTES
        self.context.authority.active_path.write_bytes(content)
        _, identity = v2._read_regular(
            self.context.authority.active_path, 256 * 1024, "test active")
        self.context.authority = replace(
            self.context.authority, active_identity=identity)
        return content

    def test_active_retirement_is_no_clobber_and_identity_checked(self) -> None:
        content = self._active_fixture()
        journal = v3.Journal(self.run_dir / "retire-ledger.jsonl", {})
        try:
            with mock.patch.object(v3, "_guard_local"):
                retired = v3._retire_active_no_clobber(self.session, journal)
        finally:
            journal.close()
        self.assertFalse(self.context.authority.active_path.exists())
        self.assertEqual(content,
                         self.context.authority.retired_path.read_bytes())
        self.assertEqual(str(self.context.authority.retired_path),
                         retired["path"])
        self.assertEqual(["header", "archive-active-intent",
                          "archive-active-settled"],
                         [v2._strict_json(line, "record")["kind"] for line in
                          (self.run_dir / "retire-ledger.jsonl").read_bytes().splitlines()])

    def test_occupied_active_retirement_destination_is_untouched(self) -> None:
        content = self._active_fixture()
        self.context.authority.retired_path.write_bytes(b"not our journal\n")
        journal = v3.Journal(self.run_dir / "occupied-retire-ledger.jsonl", {})
        try:
            with mock.patch.object(v3, "_guard_local"):
                with self.assertRaisesRegex(v3.RecoveryError,
                                            "destination is already occupied"):
                    v3._retire_active_no_clobber(self.session, journal)
        finally:
            journal.close()
        self.assertEqual(content, self.context.authority.active_path.read_bytes())
        self.assertEqual(b"not our journal\n",
                         self.context.authority.retired_path.read_bytes())

    def test_destination_appearing_during_rename_cannot_be_clobbered(self) -> None:
        content = self._active_fixture()
        journal = v3.Journal(self.run_dir / "race-retire-ledger.jsonl", {})
        original_rename = v3.os.rename

        def race(source, destination):
            Path(destination).write_bytes(b"raced-in destination\n")
            return original_rename(source, destination)

        try:
            with (mock.patch.object(v3, "_guard_local"),
                  mock.patch.object(v3.os, "rename", side_effect=race)):
                with self.assertRaises(FileExistsError):
                    v3._retire_active_no_clobber(self.session, journal)
        finally:
            journal.close()
        self.assertEqual(content, self.context.authority.active_path.read_bytes())
        self.assertEqual(b"raced-in destination\n",
                         self.context.authority.retired_path.read_bytes())

    def test_source_change_during_retirement_fails_postcheck_recoverably(self) -> None:
        self._active_fixture()
        journal = v3.Journal(self.run_dir / "changed-retire-ledger.jsonl", {})
        original_rename = v3.os.rename

        def race(source, destination):
            Path(source).write_bytes(b"raced replacement\n")
            return original_rename(source, destination)

        try:
            with (mock.patch.object(v3, "_guard_local"),
                  mock.patch.object(v3.os, "rename", side_effect=race)):
                with self.assertRaisesRegex(v3.RecoveryError,
                                            "did not reach exact postcondition"):
                    v3._retire_active_no_clobber(self.session, journal)
        finally:
            journal.close()
        self.assertFalse(self.context.authority.active_path.exists())
        self.assertEqual(b"raced replacement\n",
                         self.context.authority.retired_path.read_bytes())

    def test_successful_fake_execution_uses_new_ledger_not_old_files(self) -> None:
        plan = self._plan()
        old_plan = b"old plan evidence\n"
        old_ledger = b"old ledger evidence\n"
        self.context.authority.plan_path.write_bytes(old_plan)
        self.context.authority.ledger_path.write_bytes(old_ledger)
        def fake_retire(_session, journal):
            journal.append("archive-active-intent", {"noClobber": True})
            journal.append("archive-active-settled", {})
            return {"sha256": "a" * 64}

        with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
              mock.patch.object(v3, "build_plan", return_value=plan),
              mock.patch.object(v3, "_checkpoint", return_value={}),
              mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                return_value=v2._capture_scope(self.device)),
              mock.patch.object(v3, "_assert_retired_local"),
              mock.patch.object(v3, "_retire_active_no_clobber",
                                side_effect=fake_retire),
              mock.patch.object(v2.launch.prior, "_fsync_directory")):
            evidence = v3.execute(self.session, self.device, plan,
                                  {"sha256": "p"})
        self.assertEqual("DISPOSABLES_QUARANTINED_RETAINED_V3",
                         evidence["result"])
        self.assertTrue(self.session.ledger_path.exists())
        self.assertTrue(self.session.evidence_path.exists())
        self.assertEqual(old_plan, self.context.authority.plan_path.read_bytes())
        self.assertEqual(old_ledger, self.context.authority.ledger_path.read_bytes())
        self.assertEqual(2, len(self.device.history))
        self.assertIsNone(self.device.files.get(v2.TARGET_MARK))
        self.assertIsNone(self.device.files.get(v2.TARGET_PDF))
        self.assertEqual(v2._renamed(v2.TARGETS[v2.TARGET_MARK],
                                     v2.QUARANTINES[v2.TARGET_MARK]),
                         self.device.files[v2.QUARANTINES[v2.TARGET_MARK]])
        self.assertEqual(v2._renamed(v2.TARGETS[v2.TARGET_PDF],
                                     v2.QUARANTINES[v2.TARGET_PDF]),
                         self.device.files[v2.QUARANTINES[v2.TARGET_PDF]])
        records = [v2._strict_json(line, "v3 record") for line in
                   self.session.ledger_path.read_bytes().splitlines()]
        self.assertEqual(["header", "quarantine-intent", "quarantine-settled",
                          "quarantine-intent", "quarantine-settled",
                          "archive-active-intent", "archive-active-settled",
                          "evidence-intent"], [r["kind"] for r in records])
        self.assertTrue(all(r["authority"] == v3.AUTHORITY for r in records))

    def test_quarantine_drift_after_retirement_blocks_success_evidence(self) -> None:
        plan = self._plan()
        old_plan = b"immutable old plan\n"
        old_ledger = b"immutable old ledger\n"
        self.context.authority.plan_path.write_bytes(old_plan)
        self.context.authority.ledger_path.write_bytes(old_ledger)

        def retire_then_change_quarantine(_session, journal):
            journal.append("archive-active-intent", {"noClobber": True})
            journal.append("archive-active-settled", {})
            path = v2.QUARANTINES[v2.TARGET_MARK]
            self.device.files[path] = replace(
                self.device.files[path], inode=self.device.files[path].inode + 1)
            return {"sha256": "a" * 64}

        with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
              mock.patch.object(v3, "build_plan", return_value=plan),
              mock.patch.object(v3, "_checkpoint", return_value={}),
              mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                return_value={}),
              mock.patch.object(v3, "_assert_retired_local"),
              mock.patch.object(v3, "_retire_active_no_clobber",
                                side_effect=retire_then_change_quarantine),
              mock.patch.object(v2.launch.prior, "_fsync_directory")):
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "file identity differs"):
                v3.execute(self.session, self.device, plan, {"sha256": "p"})
        self.assertTrue(self.session.ledger_path.exists())
        self.assertFalse(self.session.evidence_path.exists())
        self.assertEqual(old_plan, self.context.authority.plan_path.read_bytes())
        self.assertEqual(old_ledger, self.context.authority.ledger_path.read_bytes())
        self.assertEqual(2, len(self.device.history))

    def test_adb_replacement_after_move_intent_blocks_first_dispatch(self) -> None:
        class DriftBeforeMove(FakeExecuteDevice):
            def __init__(self):
                super().__init__()
                self.current_adb = super().adb_authority()

            def adb_authority(self):
                return self.current_adb.copy()

            def move_if_exact(self, source, quarantine):
                self.current_adb["sha256"] = "9" * 64
                return super().move_if_exact(source, quarantine)

        self.device = DriftBeforeMove()
        plan = self._plan()
        with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
              mock.patch.object(v3, "build_plan", return_value=plan),
              mock.patch.object(v3, "_checkpoint", return_value={}),
              mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                return_value=v2._capture_scope(self.device)),
              mock.patch.object(v2.launch.prior, "_fsync_directory")):
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "ADB executable changed before file preflight"):
                v3.execute(self.session, self.device, plan, {"sha256": "p"})
        self.assertEqual([], self.device.history)
        self.assertFalse(self.session.evidence_path.exists())
        records = [v2._strict_json(line, "v3 record") for line in
                   self.session.ledger_path.read_bytes().splitlines()]
        self.assertEqual(["header", "quarantine-intent"],
                         [record["kind"] for record in records])

    def test_noop_producer_replacement_after_retirement_blocks_evidence(self) -> None:
        plan = self._plan()
        read_regular = v2._read_regular

        def altered_producer(path, limit, label):
            if Path(path).resolve() == Path(v3.noop.__file__).resolve():
                return b"changed producer", {"sha256": "9" * 64}
            return read_regular(path, limit, label)

        def fake_retire(_session, journal):
            journal.append("archive-active-intent", {"noClobber": True})
            journal.append("archive-active-settled", {})
            return {"sha256": "a" * 64}

        with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
              mock.patch.object(v3, "build_plan", return_value=plan),
              mock.patch.object(v3, "_checkpoint", return_value={}),
              mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                return_value=v2._capture_scope(self.device)),
              mock.patch.object(v3, "_retire_active_no_clobber",
                                side_effect=fake_retire),
              mock.patch.object(v2, "_read_regular",
                                side_effect=altered_producer),
              mock.patch.object(v2.launch.prior, "_fsync_directory")):
            with self.assertRaisesRegex(v3.RecoveryError,
                                        "no-op adjudication producer changed after retirement"):
                v3.execute(self.session, self.device, plan, {"sha256": "p"})
        self.assertEqual(2, len(self.device.history))
        self.assertTrue(self.session.ledger_path.exists())
        self.assertFalse(self.session.evidence_path.exists())

    def _execute_with_final_scope(self, first_scope: dict,
                                  final_scope: dict) -> dict:
        plan = self._plan()
        observations = 0

        def observed_scope(_plan, _device):
            nonlocal observations
            observations += 1
            return copy.deepcopy(first_scope if observations <= 3 else final_scope)

        def fake_retire(_session, journal):
            journal.append("archive-active-intent", {"noClobber": True})
            journal.append("archive-active-settled", {})
            return {"sha256": "a" * 64}

        try:
            with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
                  mock.patch.object(v3, "build_plan", return_value=plan),
                  mock.patch.object(v3, "_checkpoint", return_value={}),
                  mock.patch.object(v3, "_guard_local"),
                  mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                    side_effect=observed_scope),
                  mock.patch.object(v3, "_assert_retired_local"),
                  mock.patch.object(v3, "_retire_active_no_clobber",
                                    side_effect=fake_retire),
                  mock.patch.object(v2.launch.prior, "_fsync_directory")):
                return v3.execute(self.session, self.device, plan,
                                  {"sha256": "p"})
        finally:
            self.assertEqual(4, observations)

    def test_volatile_post_retirement_scope_changes_allow_success(self) -> None:
        first_scope = v2._capture_scope(self.device)
        final_scope = copy.deepcopy(first_scope)
        final_scope["activitySha256"] = "9" * 64
        final_scope["document"]["evidence"] = {"newCapture": "volatile"}
        final_scope["host"]["physicalDisplay"]["override"]["state"] = "OFF"
        self.assertNotEqual(first_scope, final_scope)
        self.assertEqual(v2._stable_scope(first_scope),
                         v2._stable_scope(final_scope))

        evidence = self._execute_with_final_scope(first_scope, final_scope)
        self.assertEqual("DISPOSABLES_QUARANTINED_RETAINED_V3",
                         evidence["result"])
        self.assertEqual(first_scope, evidence["finalScope"])
        self.assertTrue(self.session.evidence_path.exists())
        self.assertEqual(2, len(self.device.history))

    def test_stable_post_retirement_scope_drift_blocks_success(self) -> None:
        first_scope = v2._capture_scope(self.device)
        final_scope = copy.deepcopy(first_scope)
        final_scope["document"]["stable"]["process"]["start_ticks"] += 1
        self.assertNotEqual(v2._stable_scope(first_scope),
                            v2._stable_scope(final_scope))

        with self.assertRaisesRegex(v3.RecoveryError,
                                    "post-retirement scope or files changed before evidence"):
            self._execute_with_final_scope(first_scope, final_scope)
        self.assertTrue(self.session.ledger_path.exists())
        self.assertFalse(self.session.evidence_path.exists())
        self.assertEqual(2, len(self.device.history))

    def test_interruption_after_new_header_preserves_one_shot_barrier(self) -> None:
        plan = self._plan()
        old_plan = b"old plan evidence\n"
        old_ledger = b"old ledger evidence\n"
        self.context.authority.plan_path.write_bytes(old_plan)
        self.context.authority.ledger_path.write_bytes(old_ledger)
        with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
              mock.patch.object(v3, "build_plan", return_value=plan),
              mock.patch.object(v3, "_checkpoint",
                                side_effect=[{}, v3.RecoveryError("after header")]),
              mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v2.launch.prior, "_fsync_directory")):
            with self.assertRaisesRegex(v3.RecoveryError, "after header"):
                v3.execute(self.session, self.device, plan, {"sha256": "p"})
        self.assertTrue(self.session.ledger_path.exists())
        self.assertFalse(self.session.evidence_path.exists())
        self.assertEqual([], self.device.history)
        self.assertEqual(old_plan, self.context.authority.plan_path.read_bytes())
        self.assertEqual(old_ledger, self.context.authority.ledger_path.read_bytes())
        with self.assertRaises(v3.RecoveryError):
            v3.execute(self.session, self.device, plan, {"sha256": "p"})

    def test_interruption_after_first_intent_cannot_replay(self) -> None:
        plan = self._plan()
        def abort_after_intent(journal, _device, source, _after_stage):
            journal.append("quarantine-intent", {"source": source})
            raise v3.RecoveryError("interrupted after intent")

        with (mock.patch.object(v3, "load_plan", return_value=(plan, {"sha256": "p"})),
              mock.patch.object(v3, "build_plan", return_value=plan),
              mock.patch.object(v3, "_checkpoint", return_value={}),
              mock.patch.object(v3, "_guard_local"),
              mock.patch.object(v3, "_quarantine_one",
                                side_effect=abort_after_intent),
              mock.patch.object(v2.launch.prior, "_fsync_directory")):
            with self.assertRaisesRegex(v3.RecoveryError, "after intent"):
                v3.execute(self.session, self.device, plan, {"sha256": "p"})
        self.assertTrue(self.session.ledger_path.exists())
        self.assertFalse(self.session.evidence_path.exists())
        self.assertEqual([], self.device.history)
        self.assertEqual(2, len(self.session.ledger_path.read_bytes().splitlines()))
        with self.assertRaises(v3.RecoveryError):
            v3.execute(self.session, self.device, plan, {"sha256": "p"})

    def test_every_durable_record_boundary_remains_occupied(self) -> None:
        plan = self._plan()
        old_plan = b"immutable old plan\n"
        old_ledger = b"immutable old ledger\n"
        self.context.authority.plan_path.write_bytes(old_plan)
        self.context.authority.ledger_path.write_bytes(old_ledger)
        original_append = v3.Journal.append

        class SimulatedCrash(RuntimeError):
            pass

        def fake_archive(_authority, journal):
            journal.append("archive-active-intent", {})
            journal.append("archive-active-settled", {})

        # Header, two move intents/settlements, archive intent/settled,
        # and evidence intent are durable before the following action.
        for stop_after in range(1, 9):
            with self.subTest(stop_after=stop_after):
                run_dir = self.run_dir / f"crash-{stop_after}"
                run_dir.mkdir()
                session = replace(
                    self.session,
                    plan_path=run_dir / v3.PLAN_BASENAME,
                    ledger_path=run_dir / v3.LEDGER_BASENAME,
                    evidence_path=run_dir / v3.EVIDENCE_BASENAME)
                device = FakeExecuteDevice()

                def append_then_crash(journal, kind, payload):
                    record = original_append(journal, kind, payload)
                    if len(journal.records) == stop_after:
                        raise SimulatedCrash(f"after record {stop_after}")
                    return record

                with (mock.patch.object(v3, "load_plan",
                                        return_value=(plan, {"sha256": "p"})),
                      mock.patch.object(v3, "build_plan", return_value=plan),
                      mock.patch.object(v3, "_checkpoint", return_value={}),
                      mock.patch.object(v3, "_guard_local"),
                      mock.patch.object(v2, "require_planned_scope_with_wake_lock_retries",
                                        return_value={}),
                      mock.patch.object(v3, "_assert_retired_local"),
                      mock.patch.object(v3, "_retire_active_no_clobber",
                                        side_effect=fake_archive),
                      mock.patch.object(v3.Journal, "append",
                                        new=append_then_crash),
                      mock.patch.object(v2.launch.prior,
                                        "_fsync_directory")):
                    with self.assertRaisesRegex(SimulatedCrash,
                                                f"after record {stop_after}"):
                        v3.execute(session, device, plan, {"sha256": "p"})
                self.assertTrue(session.ledger_path.exists())
                self.assertEqual(
                    stop_after,
                    len(session.ledger_path.read_bytes().splitlines()))
                self.assertFalse(session.evidence_path.exists())
                self.assertEqual(old_plan,
                                 self.context.authority.plan_path.read_bytes())
                self.assertEqual(old_ledger,
                                 self.context.authority.ledger_path.read_bytes())
                with self.assertRaises(v3.RecoveryError):
                    v3.execute(session, device, plan, {"sha256": "p"})


if __name__ == "__main__":
    unittest.main()
