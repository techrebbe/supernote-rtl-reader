from __future__ import annotations

from dataclasses import asdict
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import adjudicate_noop_post_restart as adjudicate
import recover_post_restart_orphan_alpha_run as recovery
from test_recover_post_restart_orphan_alpha_run import FakeDevice


def synthetic_ledger(plan_identity: dict) -> tuple[bytes, str]:
    records = []
    for kind, payload in (
            ("header", {
                "plan": plan_identity,
                "planBindingSha256": adjudicate.PLAN_BINDING,
                "reportSha256": adjudicate.launch.REPORT_SHA256,
                "activeJournalSha256": adjudicate.launch.ACTIVE_SHA256}),
            ("quarantine-intent", {
                "source": recovery.TARGET_MARK,
                "quarantine": recovery.QUARANTINES[recovery.TARGET_MARK],
                "identity": asdict(recovery.TARGETS[recovery.TARGET_MARK])})):
        unsigned = {
            "authority": recovery.AUTHORITY, "kind": kind,
            "payload": payload,
            "previousSha256": None if not records else records[-1]["recordSha256"],
            "sequence": len(records),
        }
        records.append({**unsigned, "recordSha256": recovery._canonical_sha(unsigned)})
    raw = b"".join(recovery._canonical(record) + b"\n" for record in records)
    return raw, records[-1]["recordSha256"]


def fake_context(root: Path, device: FakeDevice) -> adjudicate.Context:
    run = root / "run"
    run.mkdir(parents=True)
    authority = SimpleNamespace(
        report_path=run / "report.json", active_path=run / "active.jsonl",
        plan_path=run / recovery.PLAN_BASENAME,
        ledger_path=run / recovery.LEDGER_BASENAME,
        retired_path=run / "retired.jsonl",
        evidence_path=run / recovery.EVIDENCE_BASENAME,
        report_identity={"sha256": "r" * 64},
        active_identity={"sha256": "a" * 64},
        dependency_identities={"native_page_alpha_runner.py": {"sha256": "d" * 64}},
    )
    _, producer_identity = adjudicate._read(
        Path(adjudicate.__file__), recovery.MAX_LOCAL_BYTES,
        "synthetic adjudicator producer")
    return adjudicate.Context(
        authority, {"adb": device.adb_authority(),
                    "first": recovery.observe(device).wire()},
        {"sha256": "p" * 64}, {"sha256": "l" * 64}, producer_identity,
        run / adjudicate.ATTESTATION_BASENAME)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.plan = {"path": "fixed-plan", "sha256": "p" * 64}
        self.raw, self.head = synthetic_ledger(self.plan)
        self.sha = recovery._sha(self.raw)

    def verify(self, raw: bytes, *, head: str | None = None) -> None:
        adjudicate._verify_ledger(
            raw, self.plan, pinned_sha256=recovery._sha(raw),
            pinned_head=self.head if head is None else head)

    def test_exact_two_record_chain(self):
        self.verify(self.raw)

    def test_truncated_or_extra_record_fails(self):
        for raw in (self.raw[:-1], self.raw + self.raw.split(b"\n")[1] + b"\n"):
            with self.subTest(raw=raw[-15:]), self.assertRaises(adjudicate.AdjudicationError):
                self.verify(raw)

    def test_wrong_intent_payload_fails_even_if_rehashed(self):
        records = [json.loads(line) for line in self.raw[:-1].split(b"\n")]
        records[1]["payload"]["source"] = recovery.TARGET_PDF
        unsigned = dict(records[1]); unsigned.pop("recordSha256")
        records[1]["recordSha256"] = recovery._canonical_sha(unsigned)
        raw = b"".join(recovery._canonical(record) + b"\n" for record in records)
        with self.assertRaisesRegex(adjudicate.AdjudicationError, "semantics"):
            self.verify(raw, head=records[1]["recordSha256"])

    def test_duplicate_key_and_chain_mismatch_fail(self):
        lines = self.raw[:-1].split(b"\n")
        duplicate = lines[0].replace(b'"kind":"header"',
                                     b'"kind":"header","kind":"header"')
        with self.assertRaises(adjudicate.AdjudicationError):
            self.verify(duplicate + b"\n" + lines[1] + b"\n")
        records = [json.loads(line) for line in lines]
        records[1]["previousSha256"] = "0" * 64
        unsigned = dict(records[1]); unsigned.pop("recordSha256")
        records[1]["recordSha256"] = recovery._canonical_sha(unsigned)
        raw = b"".join(recovery._canonical(record) + b"\n" for record in records)
        with self.assertRaisesRegex(adjudicate.AdjudicationError, "chain"):
            self.verify(raw, head=records[1]["recordSha256"])


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.device = FakeDevice()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context = fake_context(Path(self.temp.name), self.device)

    def plan(self):
        with mock.patch.object(adjudicate, "_guard"), mock.patch.object(
                recovery, "_await_quiet_power"):
            return adjudicate.build_read_only_plan(
                self.context, self.device, pause=lambda _: None)

    def test_two_full_observations_and_no_device_mutation(self):
        plan = self.plan()
        adjudicate._validate_attestation(self.context, plan)
        self.assertEqual(plan["result"], "MARK_QUARANTINE_INTENT_NOT_APPLIED")
        self.assertEqual(plan["deviceMutationCount"], 0)
        self.assertEqual(plan["first"]["files"], adjudicate._expected_files())
        self.assertEqual(plan["second"]["files"], adjudicate._expected_files())
        self.assertTrue(all(item["operation"] not in {"move", "delete"}
                            for item in self.device.history))

    def test_missing_disposable_source_fails_without_publication(self):
        self.device.files[recovery.TARGET_MARK] = None
        with self.assertRaises(adjudicate.AdjudicationError):
            self.plan()
        self.assertFalse(self.context.attestation_path.exists())

    def test_original_parking_and_target_identity_change_fail(self):
        protected = (
            next(iter(recovery.ORIGINALS)),
            recovery.PARKING_PDF,
            recovery.TARGET_PDF,
            recovery.TARGET_MARK,
        )
        for path in protected:
            old = self.device.files[path]
            self.device.files[path] = None
            with self.subTest(path=path), self.assertRaises(
                    adjudicate.AdjudicationError):
                self.plan()
            self.device.files[path] = old

    def test_staging_or_quarantine_file_fails(self):
        for path in (recovery.STAGING[recovery.TARGET_MARK],
                     recovery.QUARANTINES[recovery.TARGET_MARK]):
            self.device.files[path] = recovery.TARGETS[recovery.TARGET_MARK]
            with self.subTest(path=path), self.assertRaises(adjudicate.AdjudicationError):
                self.plan()
            del self.device.files[path]

    def test_document_fd_to_disposable_fails(self):
        self.device.fd_targets = {recovery.TARGET_MARK}
        with self.assertRaises(adjudicate.AdjudicationError):
            self.plan()

    def test_document_absent_is_not_positive_unrelated_authority(self):
        self.device.document_pids = ()
        with self.assertRaisesRegex(adjudicate.AdjudicationError,
                                    "schema differs|unrelated stock Document"):
            self.plan()

    def test_drift_between_observations_fails(self):
        reads = 0
        def after_quiet(*_args, **_kwargs):
            nonlocal reads
            reads += 1
            if reads == 2:
                self.device.document_start += 1
        with mock.patch.object(adjudicate, "_guard"), mock.patch.object(
                recovery, "_await_quiet_power", side_effect=after_quiet):
            with self.assertRaisesRegex(adjudicate.AdjudicationError, "drifted"):
                adjudicate.build_read_only_plan(self.context, self.device)

    def test_adb_change_fails_before_or_after_observations(self):
        self.context.plan["adb"] = {"sha256": "wrong"}
        with self.assertRaisesRegex(adjudicate.AdjudicationError, "ADB executable"):
            self.plan()

    def test_read_only_cli_never_publishes(self):
        output = io.StringIO()
        with mock.patch.object(adjudicate, "load_context", return_value=self.context), \
                mock.patch.object(adjudicate, "ReadOnlyNomad", return_value=self.device), \
                mock.patch.object(adjudicate, "_guard"), \
                mock.patch.object(recovery, "_await_quiet_power"), \
                mock.patch("sys.stdout", output):
            self.assertEqual(adjudicate.main(["--adb", "C:/fake/adb.exe"]), 0)
        self.assertFalse(self.context.attestation_path.exists())
        self.assertEqual(json.loads(output.getvalue())["deviceMutationCount"], 0)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.device = FakeDevice()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context = fake_context(Path(self.temp.name), self.device)
        with mock.patch.object(adjudicate, "_guard"), mock.patch.object(
                recovery, "_await_quiet_power"):
            self.plan = adjudicate.build_read_only_plan(self.context, self.device)

    def test_exclusive_publication_and_strict_reread(self):
        with mock.patch.object(adjudicate, "_guard"):
            identity = adjudicate.publish_attestation(self.context, self.plan)
            loaded, observed_identity = adjudicate.load_attestation(self.context)
            self.assertEqual(loaded, self.plan)
            self.assertEqual(identity, observed_identity)
            with self.assertRaisesRegex(adjudicate.AdjudicationError, "occupied"):
                adjudicate.publish_attestation(self.context, self.plan)

    def test_changed_anchor_rejected_before_publication(self):
        for field in ("oldPlan", "occupiedLedger", "report", "activeJournal",
                      "dependencies", "producer", "adb"):
            mutated = copy.deepcopy(self.plan)
            mutated[field] = {"sha256": "wrong"}
            unsigned = dict(mutated); unsigned.pop("bindingSha256")
            mutated["bindingSha256"] = recovery._canonical_sha(unsigned)
            with self.subTest(field=field), mock.patch.object(adjudicate, "_guard"):
                with self.assertRaises(adjudicate.AdjudicationError):
                    adjudicate.publish_attestation(self.context, mutated)
            self.assertFalse(self.context.attestation_path.exists())

    def test_rehashed_extra_field_rejected_before_publication(self):
        mutated = copy.deepcopy(self.plan)
        mutated["unreviewedAuthority"] = True
        unsigned = dict(mutated); unsigned.pop("bindingSha256")
        mutated["bindingSha256"] = recovery._canonical_sha(unsigned)
        with mock.patch.object(adjudicate, "_guard"):
            with self.assertRaisesRegex(adjudicate.AdjudicationError, "fields differ"):
                adjudicate.publish_attestation(self.context, mutated)
        self.assertFalse(self.context.attestation_path.exists())

    def test_short_write_leaves_occupied_incomplete_file(self):
        with mock.patch.object(adjudicate, "_guard"), mock.patch.object(
                adjudicate.os, "write", return_value=0):
            with self.assertRaisesRegex(adjudicate.AdjudicationError, "publication failed"):
                adjudicate.publish_attestation(self.context, self.plan)
        self.assertTrue(self.context.attestation_path.exists())
        with mock.patch.object(adjudicate, "_guard"):
            with self.assertRaises(adjudicate.AdjudicationError):
                adjudicate.load_attestation(self.context)
            with self.assertRaisesRegex(adjudicate.AdjudicationError, "occupied"):
                adjudicate.publish_attestation(self.context, self.plan)

    def test_attestation_duplicate_key_and_drift_rejected(self):
        with mock.patch.object(adjudicate, "_guard"):
            adjudicate.publish_attestation(self.context, self.plan)
            raw = self.context.attestation_path.read_bytes()
            self.context.attestation_path.write_bytes(raw.replace(
                b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'))
            with self.assertRaises(adjudicate.AdjudicationError):
                adjudicate.load_attestation(self.context)

    def test_rehashed_stored_observation_omissions_fail(self):
        with mock.patch.object(adjudicate, "_guard"):
            adjudicate.publish_attestation(self.context, self.plan)
            for path in (
                    ("environment",),
                    ("rotation",),
                    ("document", "stable", "taskAuthority"),
                    ("document", "evidence", "taskSha256"),
            ):
                tampered = copy.deepcopy(self.plan)
                target = tampered["first"]
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]
                unsigned = dict(tampered); unsigned.pop("bindingSha256")
                tampered["bindingSha256"] = recovery._canonical_sha(unsigned)
                self.context.attestation_path.write_bytes(recovery._canonical(tampered))
                with self.subTest(path=path), self.assertRaisesRegex(
                        adjudicate.AdjudicationError, "schema differs"):
                    adjudicate.load_attestation(self.context)

    def test_rehashed_stored_hash_mutation_fails(self):
        with mock.patch.object(adjudicate, "_guard"):
            adjudicate.publish_attestation(self.context, self.plan)
            tampered = copy.deepcopy(self.plan)
            tampered["first"]["activitySha256"] = "not-a-sha"
            unsigned = dict(tampered); unsigned.pop("bindingSha256")
            tampered["bindingSha256"] = recovery._canonical_sha(unsigned)
            self.context.attestation_path.write_bytes(recovery._canonical(tampered))
            with self.assertRaisesRegex(adjudicate.AdjudicationError,
                                        "hash is malformed"):
                adjudicate.load_attestation(self.context)

    def test_parent_reparse_drift_after_open_leaves_occupied_file(self):
        with mock.patch.object(adjudicate, "_guard"), mock.patch.object(
                adjudicate, "_publication_parent",
                side_effect=[(1, 1), (2, 2)]):
            with self.assertRaisesRegex(adjudicate.AdjudicationError,
                                        "directory changed"):
                adjudicate.publish_attestation(self.context, self.plan)
        self.assertTrue(self.context.attestation_path.exists())
        with mock.patch.object(adjudicate, "_guard"):
            with self.assertRaises(adjudicate.AdjudicationError):
                adjudicate.load_attestation(self.context)


class LocalGuardTests(unittest.TestCase):
    def setUp(self):
        device = FakeDevice()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context = fake_context(Path(self.temp.name), device)
        self.context.authority.plan_path.write_bytes(b"plan")
        self.context.authority.ledger_path.write_bytes(b"ledger")
        _, plan_identity = adjudicate._read(
            self.context.authority.plan_path, 100, "synthetic plan")
        _, ledger_identity = adjudicate._read(
            self.context.authority.ledger_path, 100, "synthetic ledger")
        self.context = adjudicate.Context(
            self.context.authority, self.context.plan, plan_identity,
            ledger_identity, self.context.producer_identity,
            self.context.attestation_path)

    def test_changed_plan_or_ledger_file_rejected(self):
        with mock.patch.object(recovery, "_authority_guard"), mock.patch.object(
                adjudicate, "_verify_ledger"):
            adjudicate._guard(self.context)
            self.context.authority.plan_path.write_bytes(b"changed")
            with self.assertRaisesRegex(adjudicate.AdjudicationError,
                                        "identity changed"):
                adjudicate._guard(self.context)
            self.context.authority.plan_path.write_bytes(b"plan")
            self.context.authority.ledger_path.write_bytes(b"changed")
            with self.assertRaisesRegex(adjudicate.AdjudicationError,
                                        "identity changed"):
                adjudicate._guard(self.context)

    def test_report_active_or_dependency_guard_failure_propagates(self):
        with mock.patch.object(recovery, "_authority_guard",
                               side_effect=recovery.RecoveryError("report changed")):
            with self.assertRaisesRegex(adjudicate.AdjudicationError, "report changed"):
                adjudicate._guard(self.context)

    def test_producer_source_drift_rejected(self):
        original_read = adjudicate._read
        def changed_producer(path, maximum, label):
            raw, identity = original_read(path, maximum, label)
            if label == "no-op adjudication producer":
                return raw, {**identity, "sha256": "0" * 64}
            return raw, identity
        with mock.patch.object(recovery, "_authority_guard"), mock.patch.object(
                adjudicate, "_verify_ledger"), mock.patch.object(
                adjudicate, "_read", side_effect=changed_producer):
            with self.assertRaisesRegex(adjudicate.AdjudicationError,
                                        "producer changed"):
                adjudicate._guard(self.context)


if __name__ == "__main__":
    unittest.main()
