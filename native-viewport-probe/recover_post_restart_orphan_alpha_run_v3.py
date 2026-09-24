"""One-shot, attestation-bound continuation of one failed orphan cleanup.

The v2 recovery's two-record ledger is immutable evidence, not a resumable
command queue.  This adapter admits it only after a separately published
read-only no-op adjudication.  It never edits or moves the v2 plan or ledger.

Plan mode only observes and publishes a new O_EXCL plan.  Execute creates a
different O_EXCL ledger, writes an intent before each exact file operation,
and never retries an unsettled operation.  A crash or uncertainty after ledger
creation needs a separately reviewed recovery, not another invocation here.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, NoReturn, Sequence

import adjudicate_noop_post_restart as noop
import native_page_alpha_runner as alpha
import recover_post_restart_orphan_alpha_run as v2


AUTHORITY = "native-page-alpha-post-restart-orphan-recovery-v3"
PLAN_AUTHORITY = "native-page-alpha-post-restart-orphan-recovery-plan-v3"
PLAN_BASENAME = "post-restart-orphan-recovery-v3-plan.json"
LEDGER_BASENAME = "post-restart-orphan-recovery-v3.jsonl"
EVIDENCE_BASENAME = "post-restart-orphan-recovery-v3-evidence.json"
TRANSPORT = "adb-exec-out-direct-sh-for-two-quarantine-moves-v1"
MUTATION_ORDER = [
    "quarantine-mark", "quarantine-pdf", "retire-active-journal",
    "publish-evidence-with-quarantines-retained",
]
FORBIDDEN = ["remove-task", "force-stop-package"]


class RecoveryError(RuntimeError):
    """The narrowly authorized v3 continuation cannot safely proceed."""


def _fail(message: str) -> NoReturn:
    raise RecoveryError(message)


@dataclass(frozen=True)
class Session:
    context: noop.Context
    attestation: dict[str, Any]
    attestation_identity: dict[str, Any]
    plan_path: Path
    ledger_path: Path
    evidence_path: Path


def load_session(root: Path) -> Session:
    context = noop.load_context(root)
    attestation, identity = noop.load_attestation(context)
    run_dir = context.authority.report_path.parent
    if (context.attestation_path != run_dir / noop.ATTESTATION_BASENAME or
            context.authority.plan_path != run_dir / v2.PLAN_BASENAME or
            context.authority.ledger_path != run_dir / v2.LEDGER_BASENAME):
        _fail("old recovery paths differ from the fixed run")
    return Session(context, attestation, identity,
                   run_dir / PLAN_BASENAME, run_dir / LEDGER_BASENAME,
                   run_dir / EVIDENCE_BASENAME)


def _guard_local(session: Session) -> None:
    """Keep old evidence and the no-op attestation descriptor-authoritative."""
    noop._guard(session.context)
    attestation, identity = noop.load_attestation(session.context)
    if (attestation != session.attestation or
            identity != session.attestation_identity):
        _fail("no-op attestation changed after admission")


def _producer_identity() -> dict[str, Any]:
    _, identity = v2._read_regular(
        Path(__file__).resolve(), v2.MAX_LOCAL_BYTES, "v3 recovery producer")
    return identity


def _assert_producer(plan: dict[str, Any]) -> None:
    if (type(plan.get("producer")) is not dict or
            plan["producer"] != _producer_identity()):
        _fail("v3 recovery producer changed after plan publication")


def _require_new_paths_vacant(session: Session, *, plan: bool) -> None:
    paths = [session.ledger_path, session.evidence_path]
    if plan:
        paths.append(session.plan_path)
    if any(os.path.lexists(path) for path in paths):
        _fail("v3 one-shot plan, ledger, or evidence path is already occupied")


def _publication_parent(target: Path, session: Session) -> tuple[int, int]:
    expected = session.context.authority.report_path.parent.resolve(strict=True)
    if target.parent.resolve(strict=True) != expected:
        _fail("v3 publication directory differs from the fixed run")
    parent = os.stat(target.parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        _fail("v3 publication parent is not an ordinary directory")
    return parent.st_dev, parent.st_ino


def _write_exclusive(session: Session, target: Path,
                     value: dict[str, Any]) -> dict[str, Any]:
    """Publish on one verified fixed directory/leaf, never replacing evidence."""
    if target not in {session.plan_path, session.evidence_path}:
        _fail("v3 publication target escaped fixed paths")
    parent_identity = _publication_parent(target, session)
    if os.path.lexists(target):
        _fail("v3 publication path is already occupied")
    raw = v2._canonical(value)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(target, flags, 0o600)
    try:
        for phase in ("before-write", "after-write"):
            if _publication_parent(target, session) != parent_identity:
                _fail("v3 publication directory changed " + phase)
            if target.resolve(strict=True) != (
                    session.context.authority.report_path.parent.resolve(
                        strict=True) / target.name):
                _fail("v3 publication leaf resolves outside fixed run")
            opened = os.fstat(descriptor)
            linked = os.stat(target, follow_symlinks=False)
            if (not stat.S_ISREG(opened.st_mode) or
                    not stat.S_ISREG(linked.st_mode) or
                    opened.st_nlink != 1 or linked.st_nlink != 1 or
                    (opened.st_dev, opened.st_ino) !=
                    (linked.st_dev, linked.st_ino)):
                _fail("v3 publication leaf changed after exclusive open")
            if phase == "before-write":
                if os.write(descriptor, raw) != len(raw):
                    _fail("short v3 exclusive publication write")
                os.fsync(descriptor)
    finally:
        os.close(descriptor)
    v2.launch.prior._fsync_directory(target.parent)
    observed, identity = v2._read_regular(
        target, len(raw), "v3 exclusive publication")
    if (observed != raw or
            (identity["device"], identity["inode"]) !=
            (opened.st_dev, opened.st_ino)):
        _fail("v3 published bytes or identity differ")
    return identity


def _assert_observations(plan: dict[str, Any],
                         exemplar: dict[str, Any]) -> None:
    for side in ("first", "second"):
        noop._verify_observation(plan[side], exemplar)
    if (v2._stable_observation(plan["first"]) !=
            v2._stable_observation(plan["second"])):
        _fail("v3 plan observations are not stable")


def _assert_attested_scope(session: Session, observation: dict[str, Any]) -> None:
    if (v2._stable_observation(observation) !=
            v2._stable_observation(session.attestation["first"])):
        _fail("v3 stable native scope differs from no-op attestation")


def build_plan(session: Session, device: v2.Device) -> dict[str, Any]:
    """Build a fresh, complete read-only observation bound to the old attempt."""
    producer = _producer_identity()
    _guard_local(session)
    current = v2.build_read_only_plan_with_wake_lock_retries(
        session.context.authority, device)
    _assert_observations(current, session.context.plan["first"])
    _assert_attested_scope(session, current["first"])
    _assert_attested_scope(session, current["second"])
    if current["adb"] != session.attestation["adb"]:
        _fail("ADB executable differs from the no-op attestation")
    _guard_local(session)
    if producer != _producer_identity():
        _fail("v3 producer changed during read-only plan construction")
    body = {
        "authority": PLAN_AUTHORITY,
        "schemaVersion": 3,
        "producer": producer,
        "report": session.context.authority.report_identity,
        "activeJournal": session.context.authority.active_identity,
        "dependencies": session.context.authority.dependency_identities,
        "oldV2Plan": session.context.plan_identity,
        "oldV2PlanBindingSha256": session.context.plan["bindingSha256"],
        "oldV2Ledger": session.context.ledger_identity,
        "noOpAttestation": session.attestation_identity,
        "noOpAttestationBindingSha256": session.attestation["bindingSha256"],
        "adb": current["adb"],
        "first": current["first"],
        "second": current["second"],
        "transport": TRANSPORT,
        "mutationOrder": MUTATION_ORDER,
        "forbiddenMutations": FORBIDDEN,
    }
    return {**body, "bindingSha256": v2._canonical_sha(body)}


def load_plan(path: Path, session: Session) -> tuple[dict[str, Any], dict[str, Any]]:
    if path.resolve() != session.plan_path.resolve():
        _fail("v3 plan path differs from the fixed run")
    _guard_local(session)
    raw, identity = v2._read_regular(path, v2.MAX_LOCAL_BYTES, "v3 plan")
    plan = v2._strict_json(raw, "v3 plan")
    expected = {
        "authority", "schemaVersion", "producer", "report", "activeJournal",
        "dependencies", "oldV2Plan", "oldV2PlanBindingSha256",
        "oldV2Ledger", "noOpAttestation",
        "noOpAttestationBindingSha256", "adb", "first", "second",
        "transport", "mutationOrder", "forbiddenMutations", "bindingSha256",
    }
    if set(plan) != expected:
        _fail("v3 plan fields differ")
    unsigned = dict(plan)
    binding = unsigned.pop("bindingSha256")
    if (plan["authority"] != PLAN_AUTHORITY or
            type(plan["schemaVersion"]) is not int or
            plan["schemaVersion"] != 3 or
            type(binding) is not str or
            binding != v2._canonical_sha(unsigned) or
            plan["producer"] != _producer_identity() or
            plan["report"] != session.context.authority.report_identity or
            plan["activeJournal"] != session.context.authority.active_identity or
            plan["dependencies"] != session.context.authority.dependency_identities or
            plan["oldV2Plan"] != session.context.plan_identity or
            plan["oldV2PlanBindingSha256"] !=
            session.context.plan["bindingSha256"] or
            plan["oldV2Ledger"] != session.context.ledger_identity or
            plan["noOpAttestation"] != session.attestation_identity or
            plan["noOpAttestationBindingSha256"] !=
            session.attestation["bindingSha256"] or
            plan["adb"] != session.attestation["adb"] or
            plan["transport"] != TRANSPORT or
            plan["mutationOrder"] != MUTATION_ORDER or
            plan["forbiddenMutations"] != FORBIDDEN):
        _fail("v3 plan binding or exact-run authority differs")
    _assert_observations(plan, session.context.plan["first"])
    _assert_attested_scope(session, plan["first"])
    _assert_attested_scope(session, plan["second"])
    _guard_local(session)
    return plan, identity


class Journal(v2.Journal):
    """The inherited O_EXCL ledger mechanics with an explicit v3 wire label."""

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("v3 recovery ledger record is malformed")
        unsigned = {
            "authority": AUTHORITY,
            "kind": kind,
            "payload": payload,
            "previousSha256": (None if not self.records else
                               self.records[-1]["recordSha256"]),
            "sequence": len(self.records),
        }
        record = {**unsigned, "recordSha256": v2._canonical_sha(unsigned)}
        encoded = v2._canonical(record) + b"\n"
        self._assert_open_authority()
        if os.write(self._descriptor, encoded) != len(encoded):
            _fail("short v3 recovery ledger write")
        os.fsync(self._descriptor)
        self._encoded += encoded
        self._assert_open_authority()
        v2.launch.prior._fsync_directory(self.path.parent)
        self.records.append(record)
        return record


def _fixed_mutations() -> dict[str, tuple[str, str, str]]:
    values: dict[str, tuple[str, str, str]] = {}
    for source in (v2.TARGET_MARK, v2.TARGET_PDF):
        quarantine = v2.QUARANTINES[source]
        values["recovery_quarantine_" + Path(source).name] = (
            source, quarantine, source)
    if len(values) != 2:
        _fail("fixed file operation names are not unique")
    return values


def _fixed_script() -> str:
    return (
        "set -f; current=$1; opposite=$2; digest=$3; stat_wire=$4; "
        "[ ! -L \"$current\" ] || exit 71; "
        "actual=$(stat -c '%F,%s,%u,%g,%i,%d,%h' \"$current\" 2>/dev/null) || exit 72; "
        "[ \"$actual\" = \"$stat_wire\" ] || exit 73; "
        "sum=$(sha256sum \"$current\" 2>/dev/null) || exit 74; "
        "set -- $sum; [ \"$#\" -eq 2 ] && [ \"$1\" = \"$digest\" ] "
        "&& [ \"$2\" = \"$current\" ] || exit 75; "
        "[ ! -e \"$opposite\" ] && [ ! -L \"$opposite\" ] || exit 76; "
        "exec toybox mv -n -T \"$current\" \"$opposite\"")


class Nomad(v2.Nomad):
    """Correct only two inherited moves; deletion is not a capability."""

    def __init__(self, adb: Path, serial: str):
        super().__init__(adb, serial)
        self._pre_mutation: Callable[[str], None] | None = None
        self._expected_adb: dict[str, Any] | None = None

    def arm_file_mutations(self, preflight: Callable[[str], None],
                           expected_adb: dict[str, Any]) -> None:
        if (self._pre_mutation is not None or not callable(preflight) or
                type(expected_adb) is not dict):
            _fail("v3 file-mutation preflight is missing or already armed")
        self._pre_mutation = preflight
        self._expected_adb = expected_adb.copy()

    def _mutation(self, operation: str,
                  tail: tuple[str, ...]) -> alpha.CommandResult:
        expected = _fixed_mutations().get(operation)
        if (expected is None or type(tail) is not tuple or len(tail) != 9 or
                tail[:3] != ("shell", "sh", "-c") or
                tail[4] != "fixed-launch-recovery" or
                (tail[5], tail[6]) != expected[:2] or
                tail[7] != v2.TARGETS[expected[2]].sha256):
            _fail("file mutation escaped the two fixed transport tails")
        source = v2.TARGETS[expected[2]]
        stat_wire = ",".join((source.kind, str(source.size), str(source.uid),
                              str(source.gid), str(source.inode),
                              str(source.device), "1"))
        if (tail[3] != _fixed_script() or tail[8] != stat_wire or
                self._pre_mutation is None or self._expected_adb is None):
            _fail("file mutation script, stat, or preflight differs")
        self._pre_mutation(operation)
        if self.adb_authority() != self._expected_adb:
            _fail("ADB executable changed immediately before file dispatch")
        # exec-out executes its tail directly; `exec-out shell sh -c` tried to
        # execute a nonexistent command named `shell` and created the v2 no-op.
        return super()._mutation(operation, tail[1:])

    def delete_if_exact(self, source: str,
                        quarantine: str) -> alpha.CommandResult:
        _fail("v3 recovery has no device deletion capability")


STAGE_INITIAL = "both-sources"
STAGE_MARK = "mark-quarantined"
STAGE_BOTH = "both-quarantined"


def _assert_stage_files(device: v2.Device, stage: str) -> dict[str, Any]:
    """Require exact source/quarantine identities for one durable checkpoint."""
    if stage not in {STAGE_INITIAL, STAGE_MARK, STAGE_BOTH}:
        _fail("v3 file stage is outside the closed state machine")
    expected: dict[str, alpha.DeviceFile | None] = {
        path: None for path in v2.PROTECTED_PATHS}
    expected.update(v2.ORIGINALS)
    expected[v2.PARKING_PDF] = v2.PARKING
    for source in (v2.TARGET_MARK, v2.TARGET_PDF):
        quarantine = v2.QUARANTINES[source]
        moved = (stage == STAGE_BOTH or
                 (stage == STAGE_MARK and source == v2.TARGET_MARK))
        expected[source] = None if moved else v2.TARGETS[source]
        expected[quarantine] = (
            v2._renamed(v2.TARGETS[source], quarantine) if moved else None)
    observed: dict[str, Any] = {}
    for path in sorted(v2.PROTECTED_PATHS):
        current = device.stat_file(path, absent_ok=True)
        observed[path] = v2._file_wire(current)
        if current != expected[path]:
            _fail("v3 " + stage + " file identity differs: " + path)
    return observed


def _quarantine_one(journal: Journal, device: v2.Device,
                    source: str, after_stage: str) -> None:
    if (source, after_stage) not in {
            (v2.TARGET_MARK, STAGE_MARK),
            (v2.TARGET_PDF, STAGE_BOTH)}:
        _fail("v3 quarantine transition escaped the two fixed sources")
    quarantine = v2.QUARANTINES[source]
    expected = v2.TARGETS[source]
    journal.append("quarantine-intent", {
        "source": source, "quarantine": quarantine,
        "identity": v2.asdict(expected)})
    reply: alpha.CommandResult | None = None
    transport_error: BaseException | None = None
    try:
        reply = device.move_if_exact(source, quarantine)
        v2._validate_mutation_result(
            reply, "recovery_quarantine_" + Path(source).name)
    except v2.MutationTransportUncertain as error:
        transport_error = error
    moved = device.stat_file(quarantine, absent_ok=True)
    original = device.stat_file(source, absent_ok=True)
    if moved != v2._renamed(expected, quarantine) or original is not None:
        journal.append("quarantine-unsettled", {"source": source})
        _fail("v3 quarantine move did not reach exact postcondition; no retry")
    _assert_stage_files(device, after_stage)
    journal.append("quarantine-settled", {
        "source": source,
        "reply": None if reply is None else reply.returncode,
        "transportError": None if transport_error is None else str(transport_error),
        "bytesRetained": True,
    })


def _retire_active_no_clobber(session: Session, journal: Journal) -> dict[str, Any]:
    if os.name != "nt":
        _fail("v3 active-journal retirement requires Windows no-clobber rename")
    _guard_local(session)
    authority = session.context.authority
    if os.path.lexists(authority.retired_path):
        _fail("retired active-journal destination is already occupied")
    raw, current = v2._read_regular(
        authority.active_path, 256 * 1024, "active journal before retirement")
    if (len(raw) != v2.launch.ACTIVE_BYTES or
            current != authority.active_identity):
        _fail("active journal identity changed before retirement")
    journal.append("archive-active-intent", {
        "source": str(authority.active_path),
        "target": str(authority.retired_path),
        "identity": current,
        "noClobber": True,
    })
    # Python's os.rename never replaces an existing destination on Windows.
    # A raced replacement of the source would remain recoverable in the
    # retired leaf and fail the exact postcheck; it is never deleted here.
    os.rename(authority.active_path, authority.retired_path)
    v2.launch.prior._fsync_directory(authority.active_path.parent)
    retired_raw, retired = v2._read_regular(
        authority.retired_path, 256 * 1024, "retired active journal")
    expected = {**current, "path": str(authority.retired_path)}
    if (retired_raw != raw or retired != expected or
            os.path.lexists(authority.active_path)):
        _fail("no-clobber active retirement did not reach exact postcondition")
    journal.append("archive-active-settled", retired)
    return retired


def _assert_retired_local(session: Session, plan: dict[str, Any],
                          plan_identity: dict[str, Any],
                          retired_active: dict[str, Any]) -> None:
    """Verify all immutable authority after active-journal retirement.

    The pre-retirement no-op guard intentionally requires the active path, so
    it cannot be used after the one authorized no-clobber rename.
    """
    _, noop_producer = v2._read_regular(
        Path(noop.__file__).resolve(), v2.MAX_LOCAL_BYTES,
        "v3 retained no-op adjudication producer")
    if noop_producer != session.context.producer_identity:
        _fail("no-op adjudication producer changed after retirement")
    authority = session.context.authority
    if os.path.lexists(authority.active_path):
        _fail("active journal reappeared after v3 retirement")
    raw, identity = v2._read_regular(
        authority.retired_path, 256 * 1024, "v3 retired active journal")
    if (identity != retired_active or
            identity != {**authority.active_identity,
                         "path": str(authority.retired_path)} or
            len(raw) != v2.launch.ACTIVE_BYTES or
            identity["sha256"] != v2.launch.ACTIVE_SHA256):
        _fail("retired active journal changed after v3 retirement")
    _, report_identity = v2._read_regular(
        authority.report_path, 128 * 1024, "v3 fixed report")
    if report_identity != authority.report_identity:
        _fail("fixed report changed after v3 retirement")
    for name, expected in authority.dependency_identities.items():
        _, observed = v2._read_regular(
            authority.root / name, expected["size"],
            "v3 retained dependency " + name)
        if observed != expected:
            _fail("retained dependency changed after v3 retirement")
    _, old_plan_identity = v2._read_regular(
        authority.plan_path, v2.MAX_LOCAL_BYTES, "v3 old plan")
    old_ledger_raw, old_ledger_identity = v2._read_regular(
        authority.ledger_path, v2.MAX_LOCAL_BYTES, "v3 old ledger")
    if (old_plan_identity != session.context.plan_identity or
            old_ledger_identity != session.context.ledger_identity):
        _fail("old v2 plan or ledger changed after retirement")
    noop._verify_ledger(old_ledger_raw, old_plan_identity)
    attestation_raw, attestation_identity = v2._read_regular(
        session.context.attestation_path, v2.MAX_LOCAL_BYTES,
        "v3 no-op attestation")
    if attestation_identity != session.attestation_identity:
        _fail("no-op attestation changed after retirement")
    attestation = noop._strict(attestation_raw, "v3 no-op attestation")
    noop._validate_attestation(session.context, attestation)
    if attestation != session.attestation:
        _fail("no-op attestation semantics changed after retirement")
    _, current_plan_identity = v2._read_regular(
        session.plan_path, v2.MAX_LOCAL_BYTES, "v3 exact plan")
    if current_plan_identity != plan_identity:
        _fail("v3 plan changed after retirement")
    _assert_producer(plan)


def _post_retirement_guard(session: Session, device: v2.Device,
                           plan: dict[str, Any],
                           plan_identity: dict[str, Any],
                           retired_active: dict[str, Any]
                           ) -> tuple[dict[str, Any], dict[str, Any]]:
    _assert_retired_local(session, plan, plan_identity, retired_active)
    scope = v2.require_planned_scope_with_wake_lock_retries(plan, device)
    files = _assert_stage_files(device, STAGE_BOTH)
    _assert_retired_local(session, plan, plan_identity, retired_active)
    return scope, files


def _checkpoint(session: Session, device: v2.Device,
                plan: dict[str, Any], stage: str) -> dict[str, Any]:
    _assert_producer(plan)
    _guard_local(session)
    scope = v2.require_planned_scope_with_wake_lock_retries(plan, device)
    _assert_stage_files(device, stage)
    _guard_local(session)
    _assert_producer(plan)
    return scope


def execute(session: Session, device: Nomad, plan: dict[str, Any],
            plan_identity: dict[str, Any]) -> dict[str, Any]:
    _require_new_paths_vacant(session, plan=False)
    _assert_producer(plan)
    reread_plan, reread_identity = load_plan(session.plan_path, session)
    if reread_plan != plan or reread_identity != plan_identity:
        _fail("v3 plan changed before execution")
    fresh = build_plan(session, device)
    if (v2._stable_plan_projection(fresh) !=
            v2._stable_plan_projection(plan)):
        _fail("live v3 scope no longer matches the exact plan")
    _checkpoint(session, device, plan, STAGE_INITIAL)

    journal = Journal(session.ledger_path, {
        "plan": plan_identity,
        "planBindingSha256": plan["bindingSha256"],
        "oldV2Plan": session.context.plan_identity,
        "oldV2Ledger": session.context.ledger_identity,
        "noOpAttestation": session.attestation_identity,
        "reportSha256": v2.launch.REPORT_SHA256,
        "activeJournalSha256": v2.launch.ACTIVE_SHA256,
    })
    evidence: dict[str, Any] = {
        "authority": AUTHORITY,
        "schemaVersion": 3,
        "plan": plan_identity,
        "oldV2Plan": session.context.plan_identity,
        "oldV2Ledger": session.context.ledger_identity,
        "noOpAttestation": session.attestation_identity,
        "result": "RECOVERY_PENDING",
    }
    try:
        def pre_mutation(operation: str) -> None:
            _assert_producer(plan)
            _guard_local(session)
            if device.adb_authority() != plan["adb"]:
                _fail("ADB executable changed before file preflight")
            v2.require_planned_scope_with_wake_lock_retries(plan, device)
            stage = (STAGE_INITIAL if operation ==
                     "recovery_quarantine_" + Path(v2.TARGET_MARK).name
                     else STAGE_MARK if operation ==
                     "recovery_quarantine_" + Path(v2.TARGET_PDF).name
                     else None)
            if stage is None:
                _fail("v3 operation has no authorized source stage")
            _assert_stage_files(device, stage)
            _assert_producer(plan)
            if device.adb_authority() != plan["adb"]:
                _fail("ADB executable changed during file preflight")

        device.arm_file_mutations(pre_mutation, plan["adb"])
        _checkpoint(session, device, plan, STAGE_INITIAL)
        _quarantine_one(journal, device, v2.TARGET_MARK, STAGE_MARK)
        _checkpoint(session, device, plan, STAGE_MARK)
        _quarantine_one(journal, device, v2.TARGET_PDF, STAGE_BOTH)
        _checkpoint(session, device, plan, STAGE_BOTH)
        retired_active = _retire_active_no_clobber(session, journal)
        final_scope, final_files = _post_retirement_guard(
            session, device, plan, plan_identity, retired_active)
        evidence.update({
            "result": "DISPOSABLES_QUARANTINED_RETAINED_V3",
            "finalScope": final_scope,
            "finalFiles": final_files,
            "retiredActiveJournal": retired_active,
            "quarantinesRetained": [
                v2.QUARANTINES[v2.TARGET_MARK],
                v2.QUARANTINES[v2.TARGET_PDF],
            ],
            "commands": list(device.history),
            "ledgerHeadSha256": journal.records[-1]["recordSha256"],
            "ledgerRecordCount": len(journal.records),
        })
        journal.append("evidence-intent", {
            "path": str(session.evidence_path),
            "payloadSha256": v2._canonical_sha(evidence),
        })
        journal._assert_open_authority()
        _assert_producer(plan)
        check_scope, check_files = _post_retirement_guard(
            session, device, plan, plan_identity, retired_active)
        if (v2._stable_scope(check_scope) != v2._stable_scope(final_scope) or
                check_files != final_files):
            _fail("post-retirement scope or files changed before evidence")
        _write_exclusive(session, session.evidence_path, evidence)
        return evidence
    finally:
        journal.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    session = load_session(Path(__file__).resolve().parent)
    device = Nomad(args.adb, alpha.AUTHORIZED_SERIAL)
    if args.execute:
        if args.plan is None or args.output is not None:
            _fail("execute requires --plan and forbids --output")
        plan, identity = load_plan(args.plan, session)
        evidence = execute(session, device, plan, identity)
        print(json.dumps({"result": evidence["result"],
                          "evidence": str(session.evidence_path)}, sort_keys=True))
        return 0
    if args.output is None or args.plan is not None:
        _fail("read-only plan mode requires --output and forbids --plan")
    if args.output.resolve() != session.plan_path.resolve():
        _fail("--output differs from the fixed v3 plan path")
    _require_new_paths_vacant(session, plan=True)
    plan = build_plan(session, device)
    _guard_local(session)
    identity = _write_exclusive(session, session.plan_path, plan)
    print(json.dumps({"result": "V3_PLAN_READY",
                      "plan": str(session.plan_path),
                      "sha256": identity["sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
