"""Exact final descriptor-release continuation for the failed alpha run.

The immutable predecessor ledgers prove that the visual host and stock-reader
task were each removed once and that the stock reader retained the disposable
target and persistent parking PDFs only through its cached process.  This
helper exposes none of those earlier launch/removal operations.  Its sole
process mutation is one report-bound force-stop of the task-free stock reader.

Plan mode is read-only.  Execute mode creates a new O_EXCL ledger.  If process
or descriptor release cannot be proved, it publishes DESCRIPTOR_RELEASE_PENDING_2
without moving/deleting files or archiving the active mutation journal.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable, NoReturn, Protocol, Sequence

import continue_orientation_source_after_parking_alpha_run as after
import continue_orientation_source_alpha_run as first
import native_page_alpha_runner as alpha
import native_page_android_authority as android
import native_page_host_authority as host
import recover_orientation_source_alpha_run as prior


AUTHORITY = "native-page-alpha-orientation-source-descriptor-release-v1"
JOURNAL_ID = "8b09d6c7-2e95-44f5-b2e9-4e714eaf073d"
JOURNAL_BASENAME = "orientation-source-descriptor-release.jsonl"
EVIDENCE_BASENAME = "orientation-source-descriptor-release-evidence.json"
PENDING_EVIDENCE_BASENAME = (
    "orientation-source-descriptor-release-pending-evidence.json")
AFTER_BYTES = 135_557
AFTER_SHA256 = "b19870ba3aeead1d8e8e74a8808fd931a4a3c370efafdfc741a0e74ee9a6f8f1"
AFTER_HEAD = "a5cfbc8cf9e3361d7bac03ce9bf46694d146a0cba01cd7fd10baadb069f5ecf8"
AFTER_HELPER_SHA256 = (
    "c4bffdbb04fb5ea482472e9fca6205b1bb45da1dd2e57c38bae824f1e216ba79")
AFTER_HELPER_BYTES = 93_772
AFTER_RECORD_HASHES = (
    "04011093121def8a30d9a8e8590049bab454a936fde50d9c251e53263f8db3fa",
    "3affb596a205ff4d633047d4ec027a989620c0b1636a24701aee048901626a14",
    "7b940bf1c00c382acc648e01e05d5a64fc4e42fdf436334320df12a6a18b9454",
    "775b52be12e7b6dbc7724e9e47dd48936410e26dc2d7a7ff4f1f10811bb7d8ec",
    "bf6800349b203521bb8fad3a9efe8a383776f71c29bd523119cd871e64ab0adc",
    AFTER_HEAD,
)
AFTER_PENDING_PROOF_SHA256 = (
    "5c9b72f968809e88bb6613056ea988397d8eaf065d8369b34752b5189d455c09")
AFTER_PARKING_STABLE_SHA256 = (
    "be4259d088d672655c20c8192da905ac7bfedc8233ec4efa17c5e893460006d2")
AFTER_REMOVE_BOUNDARY_SHA256 = (
    "5aed9c85ce92fb9bbf415ab9e94d85253c706a49a1b01324992bb788d0108c32")
AFTER_REMOVE_ABSENCE_SHA256 = (
    "b0b53e4b417bd8843298dc0dafa5e50164107c8b52992aa110d29d73eae483f7")
PINNED_PROCESS = after.PINNED_DOCUMENT_PROCESS
PINNED_PROCESS_TOKEN = after.PINNED_PROCESS_TOKEN
PINNED_SHARED_FDS = dict(after.PRE_REMOVE_SHARED_FDS)
RELEVANT_PATHS = frozenset((
    alpha.TARGET_PDF, alpha.TARGET_MARK,
    alpha.PARKING_PDF, alpha.PARKING_MARK,
    prior.QUARANTINE_PDF, prior.QUARANTINE_MARK,
))
DEVICE_CONDITIONAL_MUTATION_ASSUMPTION = (
    "the pinned device has no concurrent writer during the single closed "
    "shell invocation that reauthenticates every protected pathname and "
    "immediately renames or unlinks one disposable leaf")
AUTHORIZED_RECOVERY_THREAT_BOUNDARY = (
    "no deliberate concurrent human or independent local/device actor changes "
    "the report, adb, helper/dependency source, predecessor ledger, active or "
    "retired journal after its last full local authority guard, changes a "
    "protected device pathname after the second exact file pass, or relaunches "
    "a task/process during the final runtime closure and literal dispatch, "
    "archive, or evidence publication; every drift observable inside the "
    "recorded file-runtime-file-runtime sandwich fails closed, the current "
    "release-ledger handle is still revalidated, and no kernel atomicity is "
    "claimed")
POLL_SECONDS = prior.POLL_SECONDS
POLL_LIMIT = prior.POLL_LIMIT
MAX_LOCAL_BYTES = prior.MAX_LOCAL_BYTES


class ReleaseError(prior.RecoveryError):
    """The exact descriptor-release continuation cannot proceed safely."""


def _fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def _renamed_file(value: alpha.DeviceFile, path: str) -> alpha.DeviceFile:
    """Project one pinned inode/content identity onto its quarantine path."""
    if (type(value) is not alpha.DeviceFile or
            value.kind != "regular file" or
            re.fullmatch(r"[0-9a-f]{64}", value.sha256) is None):
        _fail("conditional mutation received a malformed file identity")
    return alpha.DeviceFile(
        path, value.kind, value.size, value.uid, value.gid,
        value.inode, value.device, value.sha256)


def _conditional_file_phase(
        mode: str, source: str, quarantine: str,
        ) -> tuple[tuple[alpha.DeviceFile, ...], tuple[str, ...]]:
    """Return the one closed protected-path phase for an exact mutation.

    The current regular object and its opposite absent pathname are ordered
    last.  The device-side predicate therefore finishes on the exact pair
    consumed by the immediately following mv/rm, after authenticating every
    other retained or already-deleted protected pathname.
    """
    if mode not in {"move", "delete"} or prior.QUARANTINES.get(source) != quarantine:
        _fail("conditional mutation escaped the fixed quarantine mapping")
    if source not in {alpha.TARGET_MARK, alpha.TARGET_PDF}:
        _fail("conditional mutation escaped the disposable target set")
    regular: dict[str, alpha.DeviceFile] = {
        item.path: item for item in prior.STATIC_FILES}
    absent = {alpha.PARKING_MARK, prior.STAGING_MARK, prior.STAGING_PDF}

    if source == alpha.TARGET_MARK:
        regular[alpha.TARGET_PDF] = prior.PINNED_TARGET_PDF
        absent.add(prior.QUARANTINE_PDF)
        if mode == "move":
            current = prior.PINNED_TARGET_MARK
            opposite = prior.QUARANTINE_MARK
        else:
            current = _renamed_file(
                prior.PINNED_TARGET_MARK, prior.QUARANTINE_MARK)
            opposite = alpha.TARGET_MARK
    else:
        absent.update((alpha.TARGET_MARK, prior.QUARANTINE_MARK))
        if mode == "move":
            current = prior.PINNED_TARGET_PDF
            opposite = prior.QUARANTINE_PDF
        else:
            current = _renamed_file(
                prior.PINNED_TARGET_PDF, prior.QUARANTINE_PDF)
            opposite = alpha.TARGET_PDF

    regular[current.path] = current
    absent.add(opposite)
    protected = {
        *(item.path for item in prior.STATIC_FILES),
        alpha.PARKING_MARK, prior.STAGING_MARK, prior.STAGING_PDF,
        alpha.TARGET_MARK, alpha.TARGET_PDF,
        prior.QUARANTINE_MARK, prior.QUARANTINE_PDF,
    }
    if (set(regular).intersection(absent) or
            set(regular).union(absent) != protected):
        _fail("conditional mutation phase does not cover every protected path")
    ordered_regular = tuple(
        [regular[path] for path in sorted(regular) if path != current.path] +
        [current])
    ordered_absent = tuple(
        [path for path in sorted(absent) if path != opposite] + [opposite])
    return ordered_regular, ordered_absent


_CONDITIONAL_FILE_PREDICATE = (
    "set -f; source_path=$1; quarantine_path=$2; regular_count=$3; shift 3; "
    "while [ \"$regular_count\" -gt 0 ]; do "
    "path=$1; expected=$2; digest=$3; shift 3; "
    "[ ! -L \"$path\" ] || exit 71; "
    "actual=$(stat -c '%F,%s,%u,%g,%i,%d,%h' \"$path\" 2>/dev/null) "
    "|| exit 72; [ \"$actual\" = \"$expected\" ] || exit 73; "
    "sum=$(sha256sum \"$path\" 2>/dev/null) || exit 74; "
    "(set -- $sum; [ \"$#\" -eq 2 ] && [ \"$1\" = \"$digest\" ] "
    "&& [ \"$2\" = \"$path\" ]) || exit 75; "
    "[ ! -L \"$path\" ] || exit 77; "
    "actual_after=$(stat -c '%F,%s,%u,%g,%i,%d,%h' \"$path\" "
    "2>/dev/null) || exit 78; "
    "[ \"$actual_after\" = \"$expected\" ] || exit 79; "
    "regular_count=$((regular_count - 1)); done; "
    "for path in \"$@\"; do "
    "[ ! -e \"$path\" ] && [ ! -L \"$path\" ] || exit 76; done; ")
_CONDITIONAL_MOVE_SCRIPT = (
    _CONDITIONAL_FILE_PREDICATE +
    "exec toybox mv -n -T \"$source_path\" \"$quarantine_path\"")
_CONDITIONAL_DELETE_SCRIPT = (
    _CONDITIONAL_FILE_PREDICATE +
    "exec toybox rm -f \"$quarantine_path\"")


def _conditional_file_argv(
        adb: str, mode: str, source: str, quarantine: str,
        ) -> tuple[str, ...]:
    if type(adb) is not str or not adb:
        _fail("conditional mutation adb path is invalid")
    regular, absent = _conditional_file_phase(mode, source, quarantine)
    fields: list[str] = [source, quarantine, str(len(regular))]
    for value in regular:
        if (value.kind != "regular file" or
                any(type(item) is not int or item < 0 for item in (
                    value.size, value.uid, value.gid, value.inode,
                    value.device)) or
                re.fullmatch(r"[0-9a-f]{64}", value.sha256) is None):
            _fail("conditional mutation file identity is malformed")
        fields.extend((
            value.path,
            ",".join((
                value.kind, str(value.size), str(value.uid), str(value.gid),
                str(value.inode), str(value.device), "1")),
            value.sha256,
        ))
    fields.extend(absent)
    script = (_CONDITIONAL_MOVE_SCRIPT if mode == "move" else
              _CONDITIONAL_DELETE_SCRIPT)
    return (
        adb, "-s", alpha.AUTHORIZED_SERIAL, "exec-out", "sh", "-c",
        script, "fixed-descriptor-release", *fields)


@dataclass(frozen=True)
class Authority:
    root: Path
    run_dir: Path
    report_path: Path
    active_path: Path
    journal_path: Path
    evidence_path: Path
    pending_evidence_path: Path
    retired_path: Path
    report_identity: dict[str, Any]
    active_identity: dict[str, Any]
    prior_path: Path
    prior_identity: dict[str, Any]
    prior_summary: dict[str, Any]
    first_path: Path
    first_identity: dict[str, Any]
    first_summary: dict[str, Any]
    after_path: Path
    after_identity: dict[str, Any]
    after_summary: dict[str, Any]
    prior_helper_path: Path
    first_helper_path: Path
    after_helper_path: Path
    dependency_paths: dict[str, Path]


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("ascii"), object_pairs_hook=prior._unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(label + " is not canonical JSON") from error
    if type(value) is not dict:
        _fail(label + " is not a JSON object")
    return value


def _read_sole_regular(
        path: Path, maximum: int, label: str,
        ) -> tuple[bytes, dict[str, Any]]:
    return after._read_sole_regular(path, maximum, label)


def _validate_pending_inventory(value: Any, label: str) -> None:
    if type(value) is not dict:
        _fail(label + " is not an object")
    expected_records = [{"pid": PINNED_PROCESS.pid,
                         "token": PINNED_PROCESS_TOKEN}]
    expected_aliases = [{"pid": PINNED_PROCESS.pid,
                         "processName": alpha.DOCUMENT_PACKAGE,
                         "uid": "1000"}]
    expected_owners = [{"token": PINNED_PROCESS_TOKEN,
                        "pid": PINNED_PROCESS.pid,
                        "processName": alpha.DOCUMENT_PACKAGE,
                        "uid": "1000"}]
    if (value.get("records") != expected_records or
            value.get("processAliases") != expected_aliases or
            value.get("packageOwners") != expected_owners or
            value.get("malformedPackageRecords") != [] or
            value.get("malformedProcessAliases") != [] or
            value.get("malformedPackageOwners") != [] or
            re.fullmatch(r"[0-9a-f]{64}",
                         str(value.get("rawSha256"))) is None):
        _fail(label + " semantic process authority differs")


def _validate_pending_observation(value: Any, label: str) -> None:
    if type(value) is not dict:
        _fail(label + " is not an object")
    expected_relevant = sorted((alpha.TARGET_PDF, alpha.PARKING_PDF))
    expected_shared = {
        str(key): target for key, target in sorted(PINNED_SHARED_FDS.items())}
    if (value.get("state") != "PENDING_OPEN_FDS" or
            value.get("mode") != "RETAINED_PROCESS" or
            value.get("process") != asdict(PINNED_PROCESS) or
            value.get("relevantFdTargets") != expected_relevant or
            value.get("allPdfMarkTargets") != expected_relevant or
            value.get("sharedFds") != expected_shared or
            value.get("fdRawSha256") !=
            "5bf4bb0ce1b70176bc21ea17379d6a4c661fab563c40b88ae95bf537f351db0e"):
        _fail(label + " descriptor authority differs")
    _validate_pending_inventory(value.get("inventory"), label + " inventory")
    _validate_pending_inventory(
        value.get("inventoryAfter"), label + " ending inventory")


def _validate_after_ledger(raw: bytes) -> dict[str, Any]:
    if (len(raw) != AFTER_BYTES or prior._sha(raw) != AFTER_SHA256 or
            not raw.endswith(b"\n") or b"\r" in raw):
        _fail("after-parking ledger bytes differ")
    encoded = raw.splitlines(keepends=True)
    if len(encoded) != 6 or any(not line.endswith(b"\n") for line in encoded):
        _fail("after-parking ledger must contain exactly six records")
    records = [_strict_json(line[:-1], "after-parking record")
               for line in encoded]
    kinds = (
        "header", "parking_launch_adopted_settled",
        "parking_task_remove_intent", "parking_task_remove_dispatch_outcome",
        "parking_task_remove_settled", "descriptor_release_pending_settled",
    )
    previous: str | None = None
    for index, record in enumerate(records):
        if set(record) != {
                "authority", "kind", "payload", "previousSha256",
                "recordSha256", "sequence"}:
            _fail("after-parking record fields differ")
        if (record["authority"] != after.AUTHORITY or
                record["kind"] != kinds[index] or
                record["sequence"] != index or
                record["previousSha256"] != previous or
                record["recordSha256"] != AFTER_RECORD_HASHES[index]):
            _fail("after-parking record topology differs")
        unsigned = dict(record)
        digest = unsigned.pop("recordSha256")
        if prior._canonical_sha(unsigned) != digest:
            _fail("after-parking hash chain differs")
        previous = digest
    if previous != AFTER_HEAD:
        _fail("after-parking ledger head differs")
    header = records[0]["payload"]
    if (header.get("authority") != after.AUTHORITY or
            header.get("runId") != prior.RUN_ID or
            header.get("journalId") != after.JOURNAL_ID or
            header.get("helper", {}).get("sha256") != AFTER_HELPER_SHA256 or
            header.get("helper", {}).get("size") != AFTER_HELPER_BYTES or
            header.get("firstContinuation", {}).get("sha256") !=
            after.FIRST_SHA256 or
            header.get("firstContinuation", {}).get("head") !=
            after.FIRST_HEAD or
            header.get("priorRecovery", {}).get("sha256") !=
            first.PRIOR_RECOVERY_SHA256 or
            header.get("priorRecovery", {}).get("head") !=
            first.PRIOR_RECOVERY_HEAD):
        _fail("after-parking header authority differs")
    adopted = records[1]["payload"]
    if (adopted.get("dispatchRepeated") is not False or
            adopted.get("firstContinuationSha256") != after.FIRST_SHA256 or
            adopted.get("firstContinuationHead") != after.FIRST_HEAD or
            adopted.get("taskId") != after.PINNED_TASK_ID):
        _fail("parking-launch adoption differs")
    remove_intent = records[2]["payload"]
    if (remove_intent.get("taskId") != after.PINNED_TASK_ID or
            remove_intent.get("dispatchMayRepeat") is not False or
            remove_intent.get("stableAuthoritySha256") !=
            AFTER_PARKING_STABLE_SHA256):
        _fail("parking-task removal intent differs")
    stable = remove_intent.get("stableAuthority")
    if (type(stable) is not dict or
            prior._canonical_sha(stable) != AFTER_PARKING_STABLE_SHA256):
        _fail("parking-task stable authority differs")
    receipt = records[3]["payload"]
    empty_sha = prior._sha(b"")
    if receipt != {
            "mode": "VALIDATED_RECEIPT", "operation": "remove_exact_task",
            "receiptGrammar": "EXACT_EMPTY_STREAMS", "returncode": 0,
            "stderrSha256": empty_sha, "stderrSize": 0,
            "stdoutSha256": empty_sha, "stdoutSize": 0}:
        _fail("parking-task removal receipt differs")
    settled = records[4]["payload"]
    if (settled.get("taskId") != after.PINNED_TASK_ID or
            settled.get("boundarySha256") != AFTER_REMOVE_BOUNDARY_SHA256 or
            settled.get("absenceSha256") != AFTER_REMOVE_ABSENCE_SHA256 or
            settled.get("dispatch", {}).get("mode") != "VALIDATED_RECEIPT"):
        _fail("parking-task removal settlement differs")
    pending = records[5]["payload"]
    if (pending.get("kind") != "descriptor_release_pending" or
            pending.get("terminal") != "DESCRIPTOR_RELEASE_PENDING" or
            pending.get("fileMutationAuthorized") is not False or
            pending.get("activeJournalArchiveAuthorized") is not False or
            pending.get("sha256") != AFTER_PENDING_PROOF_SHA256 or
            len(pending.get("observations", [])) != 75):
        _fail("after-parking pending settlement differs")
    unsigned_pending = dict(pending)
    proof_sha = unsigned_pending.pop("sha256")
    if prior._canonical_sha(unsigned_pending) != proof_sha:
        _fail("after-parking pending proof hash differs")
    for index, observation in enumerate(pending["observations"]):
        _validate_pending_observation(
            observation, "after-parking pending observation " + str(index))
    retained = json.loads(json.dumps(stable))
    retained["documentAuthority"]["raw_sha256"] = "0" * 64
    return {
        "recordCount": 6, "sha256": AFTER_SHA256, "head": AFTER_HEAD,
        "recordHashes": list(AFTER_RECORD_HASHES), "header": header,
        "parkingStable": retained, "pending": pending,
        "pendingRecordSha256": AFTER_HEAD,
    }


def load_authority(root: Path, report_path: Path,
                   active_path: Path) -> Authority:
    base = after.load_authority(root, report_path, active_path)
    after_path = base.journal_path
    after_raw, after_identity = _read_sole_regular(
        after_path, 256 * 1024, "after-parking pending ledger")
    after_summary = _validate_after_ledger(after_raw)
    after_helper_path = (
        root.absolute() / "continue_orientation_source_after_parking_alpha_run.py")
    after_helper_raw, after_helper_identity = _read_sole_regular(
        after_helper_path, MAX_LOCAL_BYTES, "after-parking helper")
    if ((len(after_helper_raw), prior._sha(after_helper_raw)) !=
            (AFTER_HELPER_BYTES, AFTER_HELPER_SHA256) or
            after_helper_identity != after_summary["header"]["helper"]):
        _fail("after-parking helper differs from its ledger")
    return Authority(
        base.root, base.run_dir, base.report_path, base.active_path,
        base.run_dir / JOURNAL_BASENAME,
        base.run_dir / EVIDENCE_BASENAME,
        base.run_dir / PENDING_EVIDENCE_BASENAME,
        base.retired_path, base.report_identity, base.active_identity,
        base.prior_path, base.prior_identity, base.prior_summary,
        base.first_path, base.first_identity, base.first_summary,
        after_path, after_identity, after_summary,
        base.prior_helper_path, base.first_helper_path, after_helper_path,
        base.dependency_paths)


def _assert_publication_paths_clear(authority: Authority, *,
                                    before_journal: bool) -> None:
    forbidden = (
        authority.evidence_path, authority.pending_evidence_path,
        authority.run_dir / after.EVIDENCE_BASENAME,
        authority.run_dir / first.EVIDENCE_BASENAME,
        authority.run_dir / prior.EVIDENCE_BASENAME,
        authority.retired_path,
    )
    if any(os.path.lexists(path) for path in forbidden):
        _fail("an expected-absent publication path is occupied")
    if not os.path.lexists(authority.active_path):
        _fail("active mutation journal is absent")
    if before_journal and os.path.lexists(authority.journal_path):
        _fail("descriptor-release ledger is already occupied")


class Journal(prior.Journal):
    """Exclusive final-continuation ledger with retained-handle authority."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.external_guard: Callable[[], None] | None = None
        super().__init__(path, header)

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.external_guard is not None:
            self.external_guard()
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("descriptor-release ledger record is malformed")
        unsigned = {
            "authority": AUTHORITY, "kind": kind, "payload": payload,
            "previousSha256": (
                None if not self.records else self.records[-1]["recordSha256"]),
            "sequence": len(self.records),
        }
        record = {**unsigned, "recordSha256": prior._canonical_sha(unsigned)}
        encoded = prior._canonical(record) + b"\n"
        self._assert_open_authority()
        if os.write(self._descriptor, encoded) != len(encoded):
            _fail("short descriptor-release ledger write")
        os.fsync(self._descriptor)
        self._encoded += encoded
        self._assert_open_authority()
        prior._fsync_directory(self.path.parent)
        self.records.append(record)
        return record

    def assert_authority(self) -> None:
        if self.external_guard is not None:
            self.external_guard()
        # The external guard hashes several local authorities.  Finish, rather
        # than begin, with the retained descriptor/path/chain check so a path
        # replacement during those reads cannot survive to dispatch.
        super().assert_authority()

    def assert_retained_authority(self) -> None:
        """Constant-scope final ledger check with no external/device work."""
        super().assert_authority()


class Device(Protocol):
    history: list[dict[str, Any]]
    def adb_authority(self) -> dict[str, Any]: ...
    def environment(self) -> dict[str, Any]: ...
    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def host_logs(self, pid: int) -> str: ...
    def host_processes(self) -> bytes: ...
    def absence_raw(self) -> tuple[bytes, bytes, bytes]: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def force_stop_document(self) -> alpha.CommandResult: ...
    def move_quarantine_if_exact(
            self, source: str, target: str) -> alpha.CommandResult: ...
    def remove_quarantine_if_exact(
            self, source: str, target: str) -> alpha.CommandResult: ...


def _force_stop_argv(adb: str) -> tuple[str, ...]:
    if type(adb) is not str or not adb:
        _fail("force-stop adb path is invalid")
    return (
        adb, "-s", alpha.AUTHORIZED_SERIAL, "exec-out", "am", "force-stop",
        "--user", "0", alpha.DOCUMENT_PACKAGE,
    )


class DescriptorNomad:
    """Closed transport exposing only force-stop and exact quarantine I/O."""

    def __init__(self, adb: Path, serial: str, *,
                 executor: Callable[..., Any] = subprocess.run):
        self._transport = prior.RecoveryNomad(
            adb, serial, executor=executor)

    @property
    def history(self) -> list[dict[str, Any]]:
        return self._transport.history

    def adb_authority(self) -> dict[str, Any]:
        return self._transport.adb_authority()

    def environment(self) -> dict[str, Any]:
        return self._transport.environment()

    def stat_file(self, path: str, *,
                  absent_ok: bool = False) -> alpha.DeviceFile | None:
        return self._transport.stat_file(path, absent_ok=absent_ok)

    def pidof(self, package: str) -> tuple[int, ...]:
        return self._transport.pidof(package)

    def process_identity(self, pid: int,
                         package: str) -> host.ProcessIdentity:
        return self._transport.process_identity(pid, package)

    def process_fd_links(self, pid: int) -> str:
        return self._transport.process_fd_links(pid)

    def host_logs(self, pid: int) -> str:
        return self._transport.host_logs(pid)

    def host_processes(self) -> bytes:
        result = self._transport._invoke(
            "host_processes", ("shell", "dumpsys", "activity", "processes"))
        return self._transport._require_zero(result)

    def activities(self) -> bytes:
        raw = self._transport.activities()
        first._complete_activity_envelope(raw)
        return raw

    def windows(self) -> bytes:
        raw = self._transport.windows()
        first._complete_window_envelope(raw)
        return raw

    def displays(self) -> bytes:
        raw = self._transport.displays()
        first._strict_display0_state(raw)
        return raw

    def absence_raw(self) -> tuple[bytes, bytes, bytes]:
        return self.activities(), self.windows(), self.displays()

    def rotation_settings(self) -> tuple[str, str]:
        return self._transport.rotation_settings()

    def force_stop_document(self) -> alpha.CommandResult:
        operation = "force_stop_document"
        argv = _force_stop_argv(self._transport.adb)
        started = time.monotonic_ns()
        try:
            completed = self._transport._executor(
                argv, capture_output=True,
                timeout=alpha.STEP_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired as error:
            self.history.append({
                "operation": operation, "argv": list(argv),
                "startedNs": str(started),
                "finishedNs": str(time.monotonic_ns()),
                "returncode": None, "timeout": True})
            raise prior.MutationTransportUncertain(
                operation + " timed out; side effect is uncertain") from error
        stdout = bytes(completed.stdout or b"")
        stderr = bytes(completed.stderr or b"")
        if (len(stdout) > alpha.MAX_TEXT_BYTES or
                len(stderr) > alpha.MAX_TEXT_BYTES):
            _fail("force-stop returned oversized output")
        result = alpha.CommandResult(
            operation, argv, int(completed.returncode), stdout, stderr)
        self.history.append({
            "operation": operation, "argv": list(argv),
            "startedNs": str(started),
            "finishedNs": str(time.monotonic_ns()),
            "returncode": result.returncode,
            "stdoutSha256": prior._sha(stdout),
            "stderrSha256": prior._sha(stderr)})
        return result

    def _conditional_file_mutation(
            self, mode: str, source: str,
            target: str) -> alpha.CommandResult:
        operation = (
            "recovery_quarantine_" + Path(source).name if mode == "move"
            else "recovery_remove_" + Path(target).name)
        argv = _conditional_file_argv(
            self._transport.adb, mode, source, target)
        started = time.monotonic_ns()
        try:
            completed = self._transport._executor(
                argv, capture_output=True,
                timeout=alpha.STEP_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired as error:
            self.history.append({
                "operation": operation, "argv": list(argv),
                "startedNs": str(started),
                "finishedNs": str(time.monotonic_ns()),
                "returncode": None, "timeout": True})
            raise prior.MutationTransportUncertain(
                operation + " timed out; side effect is uncertain") from error
        stdout = bytes(completed.stdout or b"")
        stderr = bytes(completed.stderr or b"")
        if (len(stdout) > alpha.MAX_TEXT_BYTES or
                len(stderr) > alpha.MAX_TEXT_BYTES):
            _fail(operation + " returned oversized output")
        result = alpha.CommandResult(
            operation, argv, int(completed.returncode), stdout, stderr)
        self.history.append({
            "operation": operation, "argv": list(argv),
            "startedNs": str(started),
            "finishedNs": str(time.monotonic_ns()),
            "returncode": result.returncode,
            "stdoutSha256": prior._sha(stdout),
            "stderrSha256": prior._sha(stderr)})
        return result

    def move_quarantine_if_exact(
            self, source: str, target: str) -> alpha.CommandResult:
        return self._conditional_file_mutation("move", source, target)

    def remove_quarantine_if_exact(
            self, source: str, target: str) -> alpha.CommandResult:
        return self._conditional_file_mutation("delete", source, target)


class Release:
    def __init__(self, device: Device, authority: Authority, *,
                 sleep: Callable[[float], None] = time.sleep,
                 journal: Journal | None = None,
                 durable_header: dict[str, Any] | None = None,
                 prior_admission: dict[str, Any] | None = None):
        self.device = device
        self.authority = authority
        self.sleep = sleep
        self.journal = journal
        self.proofs: list[dict[str, Any]] = []
        self.mutations: list[dict[str, Any]] = []
        self.dispatch_outcomes: list[dict[str, Any]] = []
        self.retained_targets = dict(prior.PINNED_TARGETS)
        self.deleted_targets: set[str] = set()
        self.environment: dict[str, Any] | None = None
        self.adb_identity: dict[str, Any] | None = None
        self.helper_identity: dict[str, Any] | None = None
        self.after_helper_identity: dict[str, Any] | None = None
        self.first_helper_identity: dict[str, Any] | None = None
        self.prior_helper_identity: dict[str, Any] | None = None
        self.dependency_identities: dict[str, Any] | None = None
        self.host_process_gone = False
        self.host_residue_gone = False
        self.document_scope_gone = True
        self.retained_parking = authority.after_summary["parkingStable"]
        self.prior_admission = prior_admission
        if (durable_header is None) != (prior_admission is None):
            _fail("durable descriptor-release seed is incomplete")
        if durable_header is not None and prior_admission is not None:
            self._seed_durable_admission(durable_header, prior_admission)

    def _proof(self, kind: str, **fields: Any) -> dict[str, Any]:
        payload = {"kind": kind, **fields}
        proof = {**payload, "sha256": prior._canonical_sha(payload)}
        self.proofs.append(proof)
        return proof

    def _assert_ledgers(self) -> None:
        prior_raw, prior_identity = first._read_prior_ledger(
            self.authority.prior_path)
        if (prior_identity != self.authority.prior_identity or
                first._validate_prior_ledger(prior_raw) !=
                self.authority.prior_summary):
            _fail("immutable partial-recovery ledger changed")
        first_raw, first_identity = _read_sole_regular(
            self.authority.first_path, 32 * 1024,
            "immutable first-continuation ledger")
        if (first_identity != self.authority.first_identity or
                after._validate_first_ledger(first_raw) !=
                self.authority.first_summary):
            _fail("immutable first-continuation ledger changed")
        after_raw, after_identity = _read_sole_regular(
            self.authority.after_path, 256 * 1024,
            "immutable after-parking ledger")
        if (after_identity != self.authority.after_identity or
                _validate_after_ledger(after_raw) !=
                self.authority.after_summary):
            _fail("immutable after-parking ledger changed")

    def _assert_unpublished(self) -> None:
        for path in (
                self.authority.evidence_path,
                self.authority.pending_evidence_path,
                self.authority.run_dir / after.EVIDENCE_BASENAME,
                self.authority.run_dir / first.EVIDENCE_BASENAME,
                self.authority.run_dir / prior.EVIDENCE_BASENAME):
            if os.path.lexists(path):
                _fail("an immutable predecessor/final evidence path appeared")

    def _assert_local_before_archive(self) -> None:
        self._assert_unpublished()
        if os.path.lexists(self.authority.retired_path):
            _fail("retired active-journal path became occupied")
        _, report = _read_sole_regular(
            self.authority.report_path, 128 * 1024, "failed-run report")
        if report != self.authority.report_identity:
            _fail("failed-run report identity changed")
        _, active = _read_sole_regular(
            self.authority.active_path, 256 * 1024,
            "active mutation journal")
        active = {**active, "path": str(self.authority.active_path)}
        if active != self.authority.active_identity:
            _fail("active mutation journal identity changed")

    def _assert_local_after_archive(self) -> None:
        self._assert_unpublished()
        if os.path.lexists(self.authority.active_path):
            _fail("active mutation journal reappeared")
        _, report = _read_sole_regular(
            self.authority.report_path, 128 * 1024, "failed-run report")
        if report != self.authority.report_identity:
            _fail("failed-run report identity changed")
        _, retired = _read_sole_regular(
            self.authority.retired_path, 256 * 1024,
            "retired active mutation journal")
        retired = {**retired, "path": str(self.authority.active_path)}
        if retired != self.authority.active_identity:
            _fail("retired active mutation journal identity changed")

    def _tool_values(self) -> tuple[Any, ...]:
        adb = self.device.adb_authority()
        expected_self = (
            self.authority.root /
            "release_orientation_source_descriptors_alpha_run.py").resolve()
        if Path(__file__).resolve() != expected_self:
            _fail("descriptor-release helper was imported from an untrusted path")
        _, helper = _read_sole_regular(
            expected_self, MAX_LOCAL_BYTES, "descriptor-release helper")
        after_raw, after_helper = _read_sole_regular(
            self.authority.after_helper_path, MAX_LOCAL_BYTES,
            "after-parking helper")
        first_raw, first_helper = _read_sole_regular(
            self.authority.first_helper_path, MAX_LOCAL_BYTES,
            "first-continuation helper")
        prior_raw, prior_helper = _read_sole_regular(
            self.authority.prior_helper_path, MAX_LOCAL_BYTES,
            "prior recovery helper")
        loaded_helpers = (
            (after, self.authority.after_helper_path,
             after_raw, after_helper, "loaded after-parking helper"),
            (first, self.authority.first_helper_path,
             first_raw, first_helper, "loaded first-continuation helper"),
            (prior, self.authority.prior_helper_path,
             prior_raw, prior_helper, "loaded prior recovery helper"),
        )
        for module, official_path, official_raw, official_identity, label in loaded_helpers:
            loaded_name = getattr(module, "__file__", None)
            if type(loaded_name) is not str:
                _fail(label + " lacks a source path")
            loaded_path = Path(loaded_name).resolve()
            if loaded_path != official_path.resolve():
                _fail(label + " was imported from an untrusted path")
            loaded_raw, loaded_identity = _read_sole_regular(
                loaded_path, MAX_LOCAL_BYTES, label)
            if (loaded_raw != official_raw or
                    loaded_identity != official_identity):
                _fail(label + " differs from the pinned official helper")
        dependencies = after._dependency_authority(
            self.authority.dependency_paths)
        return (adb, helper, after_helper, first_helper, prior_helper,
                dependencies)

    def _assert_tools(self) -> None:
        self._assert_local_before_archive()
        self._assert_ledgers()
        values = self._tool_values()
        retained = (
            self.adb_identity, self.helper_identity,
            self.after_helper_identity, self.first_helper_identity,
            self.prior_helper_identity, self.dependency_identities)
        if self.adb_identity is None:
            (self.adb_identity, self.helper_identity,
             self.after_helper_identity, self.first_helper_identity,
             self.prior_helper_identity,
             self.dependency_identities) = values
        elif values != retained:
            _fail("descriptor-release tool identity changed")
        if (self.after_helper_identity !=
                self.authority.after_summary["header"]["helper"] or
                self.first_helper_identity !=
                self.authority.first_summary["header"]["continuationHelper"] or
                self.prior_helper_identity !=
                self.authority.prior_summary["priorHelper"]):
            _fail("predecessor helper identity changed")

    def _assert_dispatch_authority(self) -> None:
        archive_intent = (
            self.journal is not None and
            self.journal.one("active_journal_archive_intent") is not None)
        active = os.path.lexists(self.authority.active_path)
        retired = os.path.lexists(self.authority.retired_path)
        if not archive_intent:
            if not active or retired:
                _fail("active-journal phase lacks durable archive authority")
            self._assert_local_before_archive()
        elif active and not retired:
            self._assert_local_before_archive()
        elif retired and not active:
            self._assert_local_after_archive()
        else:
            _fail("active-journal archive state is ambiguous")
        self._assert_ledgers()
        if any(value is None for value in (
                self.adb_identity, self.helper_identity,
                self.after_helper_identity, self.first_helper_identity,
                self.prior_helper_identity, self.dependency_identities)):
            _fail("descriptor-release tool authority is uninitialized")
        if self._tool_values() != (
                self.adb_identity, self.helper_identity,
                self.after_helper_identity, self.first_helper_identity,
                self.prior_helper_identity, self.dependency_identities):
            _fail("descriptor-release dispatch tool identity changed")

    def _assert_rotation(self) -> None:
        if self.device.rotation_settings() != ("1", "2"):
            _fail("rotation settings changed from the admitted 1/2 state")

    def _assert_static(self) -> None:
        after.Recovery._assert_static(self)

    def _assert_target_phase(self) -> None:
        for path, expected in self.retained_targets.items():
            quarantine = prior.QUARANTINES[path]
            target_value = self.device.stat_file(path, absent_ok=True)
            quarantine_value = self.device.stat_file(
                quarantine, absent_ok=True)
            if path in self.deleted_targets:
                if target_value is not None or quarantine_value is not None:
                    _fail("deleted target/quarantine reappeared: " + path)
            elif target_value != expected or quarantine_value is not None:
                _fail("retained target/quarantine identity changed: " + path)

    def _file_authority_snapshot(
            self, *, current_path: str | None = None,
            source_present: bool | None = None) -> dict[str, Any]:
        """Capture the complete physical/file authority for one phase."""
        if (current_path is None) != (source_present is None):
            _fail("file phase selector is incomplete")
        environment = self.device.environment()
        if self.environment is None or environment != self.environment:
            _fail("package environment changed from durable admission")
        rotation = self.device.rotation_settings()
        if rotation != ("1", "2"):
            _fail("rotation settings changed from the admitted 1/2 state")
        static: dict[str, Any] = {}
        for expected in prior.STATIC_FILES:
            observed = self.device.stat_file(expected.path, absent_ok=True)
            if observed != expected:
                _fail("source/parking identity changed: " + expected.path)
            static[expected.path] = asdict(observed)
        absent_static: dict[str, None] = {}
        for absent_path in (
                alpha.PARKING_MARK, prior.STAGING_MARK, prior.STAGING_PDF):
            if self.device.stat_file(absent_path, absent_ok=True) is not None:
                _fail("expected-absent protected path appeared: " + absent_path)
            absent_static[absent_path] = None
        disposable: dict[str, Any] = {}
        for path, expected in self.retained_targets.items():
            quarantine = prior.QUARANTINES[path]
            source = self.device.stat_file(path, absent_ok=True)
            moved = self.device.stat_file(quarantine, absent_ok=True)
            if path == current_path:
                if source_present:
                    if source != expected or moved is not None:
                        _fail("quarantine-move file authority changed")
                elif (source is not None or moved is None or
                      not prior._same_renamed(expected, moved, quarantine)):
                    _fail("quarantine-delete file authority changed")
            elif path in self.deleted_targets:
                if source is not None or moved is not None:
                    _fail("deleted target/quarantine reappeared: " + path)
            elif source != expected or moved is not None:
                _fail("retained target/quarantine identity changed: " + path)
            disposable[path] = {
                "source": None if source is None else asdict(source),
                "quarantine": None if moved is None else asdict(moved),
            }
        payload = {
            "environment": environment, "rotation": list(rotation),
            "static": static,
            "absentStatic": absent_static, "disposable": disposable,
            "currentPath": current_path, "sourcePresent": source_present,
        }
        return {**payload, "sha256": prior._canonical_sha(payload)}

    def _header(self) -> dict[str, Any]:
        self._assert_tools()
        assert all(value is not None for value in (
            self.adb_identity, self.helper_identity,
            self.after_helper_identity, self.first_helper_identity,
            self.prior_helper_identity, self.dependency_identities))
        return {
            "authority": AUTHORITY, "runId": prior.RUN_ID,
            "journalId": JOURNAL_ID,
            "report": self.authority.report_identity,
            "activeJournal": self.authority.active_identity,
            "helper": self.helper_identity, "adb": self.adb_identity,
            "afterHelper": self.after_helper_identity,
            "firstHelper": self.first_helper_identity,
            "priorHelper": self.prior_helper_identity,
            "dependencies": self.dependency_identities,
            "priorRecovery": {
                "identity": self.authority.prior_identity,
                "sha256": first.PRIOR_RECOVERY_SHA256,
                "head": first.PRIOR_RECOVERY_HEAD, "recordCount": 3},
            "firstContinuation": {
                "identity": self.authority.first_identity,
                "sha256": after.FIRST_SHA256, "head": after.FIRST_HEAD,
                "recordCount": 4},
            "afterParking": {
                "identity": self.authority.after_identity,
                "sha256": AFTER_SHA256, "head": AFTER_HEAD,
                "recordCount": 6,
                "pendingProofSha256": AFTER_PENDING_PROOF_SHA256,
                "forceStopMayRepeat": False,
                "priorTaskOrLaunchMayRepeat": False},
            "retainedProcess": asdict(PINNED_PROCESS),
            "retainedProcessToken": PINNED_PROCESS_TOKEN,
            "retainedSharedFds": {
                str(key): value for key, value in sorted(PINNED_SHARED_FDS.items())},
            "targets": {path: asdict(value)
                        for path, value in prior.PINNED_TARGETS.items()},
            "quarantines": prior.QUARANTINES,
            "residualAssumption": prior.RESIDUAL_ASSUMPTION,
            "conditionalDeviceMutationAssumption":
                DEVICE_CONDITIONAL_MUTATION_ASSUMPTION,
            "authorizedRecoveryThreatBoundary":
                AUTHORIZED_RECOVERY_THREAT_BOUNDARY,
        }

    def _seed_durable_admission(
            self, header: dict[str, Any], admission: dict[str, Any]) -> None:
        if (header.get("authority") != AUTHORITY or
                header.get("runId") != prior.RUN_ID or
                header.get("journalId") != JOURNAL_ID or
                header.get("admissionSha256") !=
                prior._canonical_sha(admission) or
                header.get("afterParking", {}).get("sha256") != AFTER_SHA256 or
                header.get("afterParking", {}).get("head") != AFTER_HEAD):
            _fail("durable descriptor-release header differs from admission")
        tools = (
            header.get("adb"), header.get("helper"),
            header.get("afterHelper"), header.get("firstHelper"),
            header.get("priorHelper"), header.get("dependencies"))
        if any(type(value) is not dict for value in tools):
            _fail("durable descriptor-release tool authority is malformed")
        (self.adb_identity, self.helper_identity,
         self.after_helper_identity, self.first_helper_identity,
         self.prior_helper_identity, self.dependency_identities) = tools
        environment = admission.get("environment")
        if type(environment) is not dict:
            _fail("durable descriptor-release environment is malformed")
        self.environment = environment
        observations = admission.get("scopeAbsence", {}).get("observations")
        if type(observations) is not list or len(observations) != 2:
            _fail("durable task/window absence proof is malformed")
        self.host_process_gone = any(
            item.get("hostProcess", {}).get("mode") == "PROCESS_ABSENT"
            for item in observations if type(item) is dict)
        self.host_residue_gone = any(
            item.get("windows", {}).get("residuePresent") is False
            for item in observations if type(item) is dict)

    def _host_process_observation(self) -> dict[str, Any]:
        return after.Recovery._host_process_observation(self)

    def _scope_observation(self) -> dict[str, Any]:
        return after.Recovery._scope_observation(
            self, self.retained_parking)

    def _accept_host_observation(
            self, observation: dict[str, Any],
            previous: dict[str, Any] | None = None) -> None:
        after.Recovery._accept_host_observation(self, observation, previous)

    def _prove_scope_absence_twice(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        for index in range(2):
            observation = self._scope_observation()
            self._accept_host_observation(
                observation, observations[-1] if observations else None)
            if observation["documentScopePresent"]:
                _fail("stock Document task/window remains present")
            observations.append(observation)
            if index == 0:
                self.sleep(POLL_SECONDS)
        return self._proof("task_window_host_absence", observations=observations)

    def _document_inventory(self) -> dict[str, Any]:
        return after.Recovery._document_inventory(self)

    def _descriptor_observation(self) -> dict[str, Any]:
        return after.Recovery._descriptor_observation(self)

    @staticmethod
    def _pending_descriptor_semantic(value: dict[str, Any]) -> dict[str, Any]:
        _validate_pending_observation(value, "live pending descriptor")
        return {
            "state": value["state"], "mode": value["mode"],
            "process": value["process"],
            "relevantFdTargets": value["relevantFdTargets"],
            "allPdfMarkTargets": value["allPdfMarkTargets"],
            "sharedFds": value["sharedFds"],
            "inventory": {
                key: value["inventory"][key]
                for key in (
                    "records", "processAliases", "malformedProcessAliases",
                    "packageOwners", "malformedPackageRecords",
                    "malformedPackageOwners")},
        }

    def _prove_pending_descriptor_twice(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        semantic: dict[str, Any] | None = None
        for index in range(2):
            value = self._descriptor_observation()
            current = self._pending_descriptor_semantic(value)
            if semantic is None:
                semantic = current
            elif current != semantic:
                _fail("retained descriptor authority changed across admission")
            observations.append(value)
            if index == 0:
                self.sleep(POLL_SECONDS)
        assert semantic is not None
        return self._proof(
            "retained_descriptor_pending", semanticAuthority=semantic,
            semanticAuthoritySha256=prior._canonical_sha(semantic),
            observations=observations,
            adoptedPendingRecordSha256=AFTER_HEAD)

    def plan(self) -> dict[str, Any]:
        _assert_publication_paths_clear(
            self.authority, before_journal=self.journal is None)
        self._assert_tools()
        environment = self.device.environment()
        if self.environment is None:
            self.environment = environment
        elif environment != self.environment:
            _fail("package environment changed during admission")
        self._assert_rotation()
        self._assert_static()
        self._assert_target_phase()
        scope = self._prove_scope_absence_twice()
        descriptor = self._prove_pending_descriptor_twice()
        return {
            "authority": AUTHORITY, "mode": "plan",
            "result": "DESCRIPTOR_RELEASE_PLAN_READY",
            "deviceMutationAttempted": False,
            "environment": environment,
            "priorRecovery": {
                "identity": self.authority.prior_identity,
                "summary": self.authority.prior_summary, "immutable": True},
            "firstContinuation": {
                "identity": self.authority.first_identity,
                "summary": self.authority.first_summary, "immutable": True},
            "afterParking": {
                "identity": self.authority.after_identity,
                "summary": self.authority.after_summary, "immutable": True,
                "hostRemovalMayRepeat": False,
                "parkingLaunchMayRepeat": False,
                "parkingTaskRemovalMayRepeat": False},
            "scopeAbsence": scope,
            "retainedDescriptor": descriptor,
            "plannedSequence": [
                "ADOPT_EXACT_DESCRIPTOR_RELEASE_PENDING",
                "FORCE_STOP_TASK_FREE_STOCK_DOCUMENT_AT_MOST_ONCE",
                "PROVE_ORIGINAL_PROCESS_AND_RELEVANT_FDS_GONE",
                "STOP_PENDING_2_IF_UNCERTAIN",
                "DELETE_TARGET_MARK_THEN_TARGET_PDF_IF_RELEASED",
                "ARCHIVE_ACTIVE_JOURNAL_IF_CLEAN"],
            "proofs": self.proofs,
        }

    def _intent(self, name: str, payload: dict[str, Any]) -> None:
        if self.journal is None:
            _fail("execute mode lacks a descriptor-release ledger")
        if self.journal.one(name + "_intent") is not None:
            _fail("descriptor-release ledger cannot be resumed in place")
        self._assert_dispatch_authority()
        self._assert_rotation()
        self._assert_static()
        record = self.journal.append(name + "_intent", payload)
        self.mutations.append({
            "kind": name, "sequence": record["sequence"], **payload})

    def _settle(self, name: str, payload: dict[str, Any]) -> None:
        if self.journal is None:
            _fail("execute mode lacks a descriptor-release ledger")
        existing = self.journal.one(name + "_settled")
        if existing is not None:
            if existing["payload"] != payload:
                _fail("descriptor-release settlement differs: " + name)
            return
        self.journal.append(name + "_settled", payload)

    def _record_dispatch_outcome(
            self, name: str, *, result: alpha.CommandResult | None = None,
            uncertain: prior.MutationTransportUncertain | None = None,
            ) -> dict[str, Any]:
        if self.journal is None or (result is None) == (uncertain is None):
            _fail("descriptor-release mutation outcome is ambiguous")
        if result is not None:
            payload = {
                "mode": "VALIDATED_RECEIPT", "operation": result.operation,
                "returncode": result.returncode,
                "stdoutSize": len(result.stdout),
                "stdoutSha256": prior._sha(result.stdout),
                "stderrSize": len(result.stderr),
                "stderrSha256": prior._sha(result.stderr),
                "receiptGrammar": "EXACT_EMPTY_STREAMS"}
        else:
            assert uncertain is not None
            payload = {
                "mode": "TRANSPORT_UNCERTAIN",
                "errorType": type(uncertain).__name__, "error": str(uncertain)}
        record = self.journal.append(name + "_dispatch_outcome", payload)
        retained = {"kind": name, "sequence": record["sequence"], **payload}
        self.dispatch_outcomes.append(retained)
        return retained

    def _record_mutation_failure(self, name: str,
                                 error: BaseException) -> None:
        assert self.journal is not None
        self.journal.append(name + "_semantic_failure", {
            "errorType": type(error).__name__, "error": str(error)})

    def _adopt_pending(self) -> dict[str, Any]:
        payload = {
            "afterParkingSha256": AFTER_SHA256,
            "afterParkingHead": AFTER_HEAD,
            "pendingProofSha256": AFTER_PENDING_PROOF_SHA256,
            "taskRemovalAlreadySettled": True,
            "priorTaskOrLaunchDispatchRepeated": False,
            "fileMutationPreviouslyAuthorized": False}
        self._settle("descriptor_pending_adopted", payload)
        return payload

    @staticmethod
    def _generic_alias(value: str) -> tuple[int, str] | None:
        match = re.fullmatch(
            r"([0-9]+)(:|[ \t]+)(" +
            re.escape(alpha.DOCUMENT_PACKAGE) +
            r"[^/\s{}\[\](),]*)/([^\s{}\[\](),]*)", value)
        if match is None:
            return None
        pid, separator, name, uid = match.groups()
        canonical_uid = (
            uid == "1000" if separator == ":" else
            uid in ("1000", "1000/u0"))
        if (pid == "0" or pid.startswith("0") or
                name != alpha.DOCUMENT_PACKAGE or not canonical_uid):
            return None
        return int(pid), name

    @staticmethod
    def _relevant_shared_links(shared: dict[int, str]) -> list[str]:
        """Retain protected live and kernel-deleted descriptor spellings."""
        relevant: set[str] = set()
        for target in shared.values():
            base = (target[:-10] if target.endswith(" (deleted)") else target)
            if base in RELEVANT_PATHS:
                relevant.add(target)
        return sorted(relevant)

    def _generic_inventory_view(
            self, inventory: dict[str, Any],
            pidof: tuple[int, ...]) -> dict[str, Any]:
        malformed = (
            list(inventory.get("malformedPackageRecords", [])) +
            list(inventory.get("malformedPackageOwners", [])))
        alias_pids = {
            int(item["pid"]) for item in inventory.get("processAliases", [])
            if (item.get("processName") == alpha.DOCUMENT_PACKAGE and
                item.get("uid") == "1000")}
        for value in inventory.get("malformedProcessAliases", []):
            parsed = self._generic_alias(value)
            if parsed is None:
                malformed.append(value)
            else:
                alias_pids.add(parsed[0])
        record_tokens: dict[int, set[str]] = {}
        for item in inventory.get("records", []):
            record_tokens.setdefault(int(item["pid"]), set()).add(item["token"])
        owner_tokens: dict[int, set[str]] = {}
        for item in inventory.get("packageOwners", []):
            if (item.get("processName") != alpha.DOCUMENT_PACKAGE or
                    item.get("uid") != "1000"):
                malformed.append(json.dumps(item, sort_keys=True))
                continue
            owner_tokens.setdefault(int(item["pid"]), set()).add(item["token"])
        pid_set = set(pidof)
        sets = (pid_set, set(record_tokens), alias_pids, set(owner_tokens))
        valid = (
            not malformed and all(candidate == pid_set for candidate in sets) and
            all(len(record_tokens[pid]) == 1 and
                record_tokens[pid] == owner_tokens[pid]
                for pid in pid_set))
        return {
            "valid": valid, "pids": sorted(pid_set),
            "tokens": {str(pid): sorted(record_tokens.get(pid, set()))
                       for pid in sorted(pid_set)},
            "malformed": sorted(set(malformed)),
            "semanticSha256": prior._canonical_sha({
                "pids": sorted(pid_set),
                "recordTokens": {str(key): sorted(value)
                                 for key, value in sorted(record_tokens.items())},
                "aliasPids": sorted(alias_pids),
                "ownerTokens": {str(key): sorted(value)
                                for key, value in sorted(owner_tokens.items())},
                "malformed": sorted(set(malformed))}),
            "rawSha256": inventory.get("rawSha256"),
        }

    @staticmethod
    def _scope_stable_projection(scope: dict[str, Any]) -> dict[str, Any]:
        """Return only semantic physical/absence fields from a scope sample."""
        display = scope["display"]
        windows = scope["windows"]
        return {
            "documentScopePresent": scope["documentScopePresent"],
            "display": {
                "width": display["width"],
                "height": display["height"],
                "rotation": display["rotation"],
            },
            "windowRotation": windows["rotation"],
            "hostResiduePresent": windows["residuePresent"],
        }

    @staticmethod
    def _device_observation_failure(
            stage: str, error: BaseException, **evidence: Any,
            ) -> dict[str, Any]:
        """Represent a device read/parser failure as tainted non-authority.

        This is deliberately used only inside device-observation regions.
        Local report, helper, predecessor-ledger, and retained-journal failures
        remain fatal and are never converted into a pending device result.
        """
        return {
            "state": "UNCERTAIN_DEVICE_OBSERVATION",
            "tainted": True,
            "observationStage": stage,
            "observationErrorType": type(error).__name__,
            "observationError": str(error),
            **evidence,
        }

    def _close_observation_failure(
            self, scope: dict[str, Any], stage: str,
            error: BaseException, **evidence: Any,
            ) -> dict[str, Any]:
        return self._close_runtime_sample(
            scope, self._device_observation_failure(
                stage, error, scope=scope, **evidence))

    def _close_runtime_sample(
            self, opening: dict[str, Any],
            sample: dict[str, Any]) -> dict[str, Any]:
        """Close a descriptor observation with a fresh task/window sample.

        Process and descriptor reads are intentionally bracketed by complete
        AM/WM/DM captures.  A task/window appearing during the comparatively
        slow /proc reads therefore cannot authorize force-stop or file I/O.
        """
        try:
            closing = self._scope_observation()
            self._accept_host_observation(closing, opening)
        except Exception as error:
            return {
                **sample,
                "state": "UNCERTAIN_CLOSING_SCOPE",
                "tainted": True,
                "scopeOpening": opening,
                "closingScopeError": type(error).__name__ + ": " + str(error),
            }
        opening_projection = self._scope_stable_projection(opening)
        closing_projection = self._scope_stable_projection(closing)
        if (opening["documentScopePresent"] or
                closing["documentScopePresent"] or
                opening_projection != closing_projection):
            return {
                **sample,
                "state": "UNCERTAIN_SCOPE_CHANGED",
                "tainted": True,
                "scopeOpening": opening,
                "scopeClosing": closing,
                "scopeOpeningSemantic": opening_projection,
                "scopeClosingSemantic": closing_projection,
            }
        result = dict(sample)
        result.pop("scope", None)
        return {
            **result,
            "scopeOpening": opening,
            "scopeClosing": closing,
            "scopeSemantic": closing_projection,
        }

    def _runtime_descriptor_sample(self) -> dict[str, Any]:
        try:
            scope = self._scope_observation()
            self._accept_host_observation(scope)
        except Exception as error:
            return self._device_observation_failure(
                "opening_scope", error)
        if scope["documentScopePresent"]:
            return self._close_runtime_sample(scope, {
                "state": "UNCERTAIN_DOCUMENT_SCOPE", "tainted": True,
                "scope": scope})
        try:
            pids_before = self.device.pidof(alpha.DOCUMENT_PACKAGE)
            inventory_before = self._document_inventory()
            view_before = self._generic_inventory_view(
                inventory_before, pids_before)
        except Exception as error:
            return self._close_observation_failure(
                scope, "opening_process_inventory", error)
        if not view_before["valid"]:
            return self._close_runtime_sample(scope, {
                "state": "UNCERTAIN_PROCESS_INVENTORY", "tainted": True,
                "scope": scope, "inventory": inventory_before,
                "view": view_before})
        identities: dict[int, host.ProcessIdentity] = {}
        fd_evidence: dict[str, Any] = {}
        try:
            for pid in pids_before:
                identity = self.device.process_identity(
                    pid, alpha.DOCUMENT_PACKAGE)
                if (identity.pid != pid or identity.uid != android.SYSTEM_UID or
                        identity.package != alpha.DOCUMENT_PACKAGE):
                    return self._close_runtime_sample(scope, {
                        "state": "UNCERTAIN_PROCESS_IDENTITY", "tainted": True,
                        "scope": scope, "process": asdict(identity),
                        "view": view_before})
                raw = self.device.process_fd_links(pid)
                targets, shared = after._fd_inventory(raw)
                relevant_links = self._relevant_shared_links(shared)
                identities[pid] = identity
                fd_evidence[str(pid)] = {
                    "identity": asdict(identity),
                    "allPdfMarkTargets": sorted(targets),
                    "relevantFdTargets": sorted(set(
                        targets.intersection(RELEVANT_PATHS)).union(
                            relevant_links)),
                    "relevantSharedLinks": relevant_links,
                    "sharedFds": {str(key): value
                                  for key, value in sorted(shared.items())},
                    "rawSha256": prior._sha(raw.encode("utf-8"))}
        except Exception as error:
            try:
                pids_after_error = self.device.pidof(alpha.DOCUMENT_PACKAGE)
                inventory_after_error = self._document_inventory()
                view_after_error = self._generic_inventory_view(
                    inventory_after_error, pids_after_error)
            except Exception as reconciliation_error:
                return self._close_observation_failure(
                    scope, "process_read_reconciliation",
                    reconciliation_error,
                    originalReadError=(
                        type(error).__name__ + ": " + str(error)))
            retryable = (
                view_after_error["valid"] and
                set(pids_after_error).issubset(set(pids_before)))
            return self._close_runtime_sample(scope, {
                "state": ("TRANSIENT_PROCESS_EXIT" if retryable else
                          "UNCERTAIN_PROCESS_READ"),
                "tainted": not retryable, "scope": scope,
                "viewBefore": view_before, "viewAfter": view_after_error,
                "readError": type(error).__name__ + ": " + str(error)})
        try:
            pids_after = self.device.pidof(alpha.DOCUMENT_PACKAGE)
            inventory_after = self._document_inventory()
            view_after = self._generic_inventory_view(
                inventory_after, pids_after)
        except Exception as error:
            return self._close_observation_failure(
                scope, "closing_process_inventory", error,
                viewBefore=view_before)
        identities_after: dict[int, host.ProcessIdentity] = {}
        try:
            for pid in pids_after:
                identities_after[pid] = self.device.process_identity(
                    pid, alpha.DOCUMENT_PACKAGE)
        except Exception as error:
            return self._close_runtime_sample(scope, {
                "state": "TRANSIENT_PROCESS_CHANGE", "tainted": False,
                "scope": scope, "viewBefore": view_before,
                "viewAfter": view_after,
                "readError": type(error).__name__ + ": " + str(error)})
        if (not view_after["valid"] or view_after["semanticSha256"] !=
                view_before["semanticSha256"] or
                identities_after != identities):
            return self._close_runtime_sample(scope, {
                "state": ("TRANSIENT_PROCESS_CHANGE" if view_after["valid"]
                          else "UNCERTAIN_PROCESS_CHANGE"),
                "tainted": not view_after["valid"], "scope": scope,
                "viewBefore": view_before, "viewAfter": view_after,
                "identitiesBefore": {str(key): asdict(value)
                                     for key, value in identities.items()},
                "identitiesAfter": {str(key): asdict(value)
                                    for key, value in identities_after.items()}})
        relevant_by_pid = {
            int(pid): set(value["relevantFdTargets"])
            for pid, value in fd_evidence.items()}
        original_present = any(value == PINNED_PROCESS
                               for value in identities.values())
        restarted_relevant = any(
            relevant_by_pid.get(pid) and identity != PINNED_PROCESS
            for pid, identity in identities.items())
        all_relevant = sorted(set().union(*relevant_by_pid.values())
                              if relevant_by_pid else set())
        if restarted_relevant:
            state, tainted = "UNCERTAIN_RESTARTED_RELEVANT_FDS", True
        elif all_relevant:
            exact_original = (
                set(identities.values()) == {PINNED_PROCESS} and
                view_before["pids"] == [PINNED_PROCESS.pid] and
                view_before["tokens"] == {
                    str(PINNED_PROCESS.pid): [PINNED_PROCESS_TOKEN]} and
                fd_evidence.get(str(PINNED_PROCESS.pid), {}).get(
                    "allPdfMarkTargets") ==
                sorted((alpha.TARGET_PDF, alpha.PARKING_PDF)) and
                fd_evidence.get(str(PINNED_PROCESS.pid), {}).get(
                    "sharedFds") == {
                        str(key): value
                        for key, value in sorted(PINNED_SHARED_FDS.items())})
            state = ("ORIGINAL_OPEN_EXACT" if exact_original else
                     "UNCERTAIN_DESCRIPTOR_DRIFT")
            tainted = not exact_original
        elif original_present:
            state, tainted = "WAIT_ORIGINAL_PROCESS_EXIT", False
        else:
            state, tainted = "RELEASED", False
        return self._close_runtime_sample(scope, {
            "state": state, "tainted": tainted, "scope": scope,
            "view": view_before, "processes": fd_evidence,
            "originalIdentityGone": not original_present,
            "relevantFdTargets": all_relevant})

    def _pending_force_stop_boundary(
            self, stage: str, error: BaseException | None = None,
            **evidence: Any,
            ) -> dict[str, Any]:
        sample = self._device_observation_failure(
            stage, error or ReleaseError(stage), **evidence)
        return self._proof(
            "immediate_pre_force_stop_boundary", terminal="PENDING",
            forceStopAuthorized=False, sample=sample,
            deviceObservationFailed=True)

    def _force_stop_boundary(self) -> dict[str, Any]:
        self._assert_dispatch_authority()
        try:
            if (self.environment is None or
                    self.device.environment() != self.environment):
                _fail("package environment changed before force-stop")
            files_opening = self._file_authority_snapshot()
            sample_opening = self._runtime_descriptor_sample()
            files_closing = self._file_authority_snapshot()
            if files_closing != files_opening:
                _fail("protected file authority changed during force-stop proof")
        except Exception as error:
            return self._pending_force_stop_boundary(
                "opening_force_stop_device_boundary", error)
        assert self.journal is not None
        self.journal.assert_authority()
        try:
            files_final = self._file_authority_snapshot()
            if files_final != files_opening:
                _fail("protected file authority changed before force-stop")
            # End with a second closed task/process/FD observation.  The file
            # and heavy local captures before it cannot conceal a late task.
            sample = self._runtime_descriptor_sample()
        except Exception as error:
            return self._pending_force_stop_boundary(
                "closing_force_stop_device_boundary", error,
                filesOpening=files_opening,
                filesClosing=files_closing,
                sampleOpening=sample_opening)
        self.journal.assert_retained_authority()
        force_stop_authorized = (
            sample_opening["state"] == "ORIGINAL_OPEN_EXACT" and
            sample["state"] == "ORIGINAL_OPEN_EXACT")
        natural_release = (
            sample_opening["state"] in {"ORIGINAL_OPEN_EXACT", "RELEASED"} and
            sample["state"] == "RELEASED")
        if not force_stop_authorized and not natural_release:
            return self._proof(
                "immediate_pre_force_stop_boundary", terminal="PENDING",
                forceStopAuthorized=False, filesOpening=files_opening,
                filesClosing=files_closing, filesFinal=files_final,
                sampleOpening=sample_opening,
                sample=sample)
        return self._proof(
            "immediate_pre_force_stop_boundary",
            terminal=("FORCE_STOP_AUTHORIZED" if force_stop_authorized else
                      "NATURAL_RELEASE"),
            forceStopAuthorized=force_stop_authorized,
            filesOpening=files_opening, filesClosing=files_closing,
            filesFinal=files_final,
            sampleOpening=sample_opening, sample=sample)

    def _prove_release_after_stop(self) -> tuple[bool, dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        released: list[dict[str, Any]] = []
        tainted = False
        for _ in range(POLL_LIMIT):
            try:
                sample = self._runtime_descriptor_sample()
            except Exception as error:
                sample = self._device_observation_failure(
                    "post_force_stop_poll", error)
            observations.append(sample)
            tainted = tainted or bool(sample.get("tainted"))
            if sample["state"] == "UNCERTAIN_DEVICE_OBSERVATION":
                break
            if sample["state"] == "RELEASED" and not tainted:
                released.append(sample)
                if len(released) == 2:
                    proof = self._proof(
                        "descriptor_release_after_force_stop",
                        terminal="RELEASED_TWICE", observations=observations)
                    return True, proof
            else:
                released.clear()
            self.sleep(POLL_SECONDS)
        proof = self._proof(
            "descriptor_release_pending_2",
            terminal="DESCRIPTOR_RELEASE_PENDING_2",
            observations=observations, uncertaintyObserved=tainted,
            fileMutationAuthorized=False,
            activeJournalArchiveAuthorized=False)
        return False, proof

    def _runtime_file_boundary(
            self, path: str, quarantine: str,
            expected: alpha.DeviceFile, *, source_present: bool,
            ) -> dict[str, Any]:
        self._assert_dispatch_authority()
        if self.retained_targets.get(path) != expected or quarantine != prior.QUARANTINES[path]:
            _fail("file mutation boundary aliases differ")
        files_opening = self._file_authority_snapshot(
            current_path=path, source_present=source_present)
        sample_opening = self._runtime_descriptor_sample()
        if sample_opening["state"] != "RELEASED":
            _fail("descriptor/task authority reopened before file mutation")
        files_closing = self._file_authority_snapshot(
            current_path=path, source_present=source_present)
        if files_closing != files_opening:
            _fail("protected file authority changed during runtime proof")
        assert self.journal is not None
        self.journal.assert_authority()
        files_final = self._file_authority_snapshot(
            current_path=path, source_present=source_present)
        if files_final != files_opening:
            _fail("protected file authority changed before file dispatch")
        # This final closed runtime sample follows every device file read.
        # A process/task appearing from a stat callback cannot be retried away.
        sample = self._runtime_descriptor_sample()
        if sample["state"] != "RELEASED":
            _fail("descriptor/task authority reopened at file dispatch")
        self.journal.assert_retained_authority()
        phase_regular, phase_absent = _conditional_file_phase(
            "move" if source_present else "delete", path, quarantine)
        phase_payload = {
            "regular": [asdict(item) for item in phase_regular],
            "absent": list(phase_absent),
            "assumption": DEVICE_CONDITIONAL_MUTATION_ASSUMPTION,
        }
        return self._proof(
            "immediate_pre_file_mutation", path=path,
            quarantine=quarantine, sourcePresent=source_present,
            filesOpening=files_opening, filesClosing=files_closing,
            filesFinal=files_final,
            runtimeOpening=sample_opening, runtime=sample,
            conditionalDevicePhase=phase_payload,
            conditionalDevicePhaseSha256=prior._canonical_sha(phase_payload))

    def _released_file_settlement_boundary(
            self, kind: str, *, defer_proof: bool = False,
            ) -> dict[str, Any]:
        """Cross-bind deleted leaves and runtime before archive/publication."""
        self._assert_dispatch_authority()
        opening = self._file_authority_snapshot()
        runtime_opening = self._runtime_descriptor_sample()
        if runtime_opening["state"] != "RELEASED":
            _fail("descriptor/task authority reopened at " + kind)
        closing = self._file_authority_snapshot()
        if closing != opening:
            _fail("protected file authority changed at " + kind)
        assert self.journal is not None
        self.journal.assert_authority()
        final_files = self._file_authority_snapshot()
        if final_files != opening:
            _fail("protected file authority changed at " + kind)
        runtime = self._runtime_descriptor_sample()
        if runtime["state"] != "RELEASED":
            _fail("descriptor/task authority reopened at " + kind)
        # Archive/evidence has no remote compare-and-mutate primitive.  Close
        # the mirror-image race by re-reading the complete file phase after
        # the final closed runtime sample, then perform only the retained
        # journal check before the literal local rename/publication path.
        files_after_runtime = self._file_authority_snapshot()
        if files_after_runtime != opening:
            _fail("protected file authority changed after runtime at " + kind)
        # Finish the bounded sandwich with task/process/FD authority.  This
        # catches a task relaunch caused by any callback during the second file
        # pass.  An independent writer after that pass is explicitly outside
        # AUTHORIZED_RECOVERY_THREAT_BOUNDARY; this is not kernel atomicity.
        runtime_after_files = self._runtime_descriptor_sample()
        if runtime_after_files["state"] != "RELEASED":
            _fail("descriptor/task authority reopened after files at " + kind)
        self.journal.assert_retained_authority()
        fields = {
            "filesOpening": opening, "filesClosing": closing,
            "filesFinal": final_files,
            "runtimeOpening": runtime_opening,
            "runtime": runtime,
            "filesAfterRuntime": files_after_runtime,
            "runtimeAfterFiles": runtime_after_files,
            "residualThreatBoundary": AUTHORIZED_RECOVERY_THREAT_BOUNDARY,
        }
        if defer_proof:
            return fields
        return self._proof(kind, **fields)

    def _prove_path_absent_twice(self, path: str) -> None:
        after.Recovery._prove_path_absent_twice(self, path)

    def _quarantine_delete(self, path: str) -> None:
        expected = self.retained_targets[path]
        quarantine = prior.QUARANTINES[path]
        stem = "mark" if path == alpha.TARGET_MARK else "pdf"
        if (self.device.stat_file(path, absent_ok=True) != expected or
                self.device.stat_file(quarantine, absent_ok=True) is not None):
            _fail("initial quarantine authority differs for " + path)
        self._intent(stem + "_quarantine_move", {
            "source": path, "quarantine": quarantine,
            "retained": asdict(expected),
            "conditionalDeviceMutation": True,
            "threatBoundary": DEVICE_CONDITIONAL_MUTATION_ASSUMPTION})
        self._runtime_file_boundary(
            path, quarantine, expected, source_present=True)
        try:
            result = self.device.move_quarantine_if_exact(path, quarantine)
            prior._validate_mutation_result(
                result, "recovery_quarantine_" + Path(path).name,
                empty_stdout=True)
            self._record_dispatch_outcome(
                stem + "_quarantine_move", result=result)
        except prior.MutationTransportUncertain as error:
            self._record_dispatch_outcome(
                stem + "_quarantine_move", uncertain=error)
        except Exception as error:
            self._record_mutation_failure(stem + "_quarantine_move", error)
            raise
        self._prove_path_absent_twice(path)
        quarantined = self.device.stat_file(quarantine, absent_ok=True)
        if (quarantined is None or
                not prior._same_renamed(expected, quarantined, quarantine)):
            _fail("one-shot quarantine move did not settle exactly")
        self._settle(stem + "_quarantine_move", {
            "source": path, "quarantine": quarantine,
            "retained": asdict(quarantined)})
        self._intent(stem + "_quarantine_delete", {
            "source": path, "quarantine": quarantine,
            "retained": asdict(quarantined),
            "conditionalDeviceMutation": True,
            "threatBoundary": DEVICE_CONDITIONAL_MUTATION_ASSUMPTION})
        self._runtime_file_boundary(
            path, quarantine, expected, source_present=False)
        try:
            result = self.device.remove_quarantine_if_exact(path, quarantine)
            prior._validate_mutation_result(
                result, "recovery_remove_" + Path(quarantine).name,
                empty_stdout=True)
            self._record_dispatch_outcome(
                stem + "_quarantine_delete", result=result)
        except prior.MutationTransportUncertain as error:
            self._record_dispatch_outcome(
                stem + "_quarantine_delete", uncertain=error)
        except Exception as error:
            self._record_mutation_failure(stem + "_quarantine_delete", error)
            raise
        self._prove_path_absent_twice(quarantine)
        self._prove_path_absent_twice(path)
        self.deleted_targets.add(path)
        self._settle(stem + "_quarantine_delete", {
            "source": path, "quarantine": quarantine, "observations": 2})

    def _joint_absence(self) -> dict[str, Any]:
        return after.Recovery._joint_absence(self)

    def _archive_active(self) -> dict[str, Any]:
        payload = {
            "activePath": str(self.authority.active_path),
            "retiredPath": str(self.authority.retired_path),
            "sha256": self.authority.active_identity["sha256"],
            "device": self.authority.active_identity["device"],
            "inode": self.authority.active_identity["inode"],
        }
        self._intent("active_journal_archive", payload)
        raw, identity = _read_sole_regular(
            self.authority.active_path, 256 * 1024,
            "active journal immediately before archive")
        identity = {**identity, "path": str(self.authority.active_path)}
        if identity != self.authority.active_identity:
            _fail("active journal changed before archive")
        prior._verify_mutation_journal(raw)
        assert self.journal is not None
        self.journal.assert_authority()
        move_windows: Any = None
        get_windows_error: Callable[[], int] | None = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            move_windows = ctypes.WinDLL(
                "kernel32", use_last_error=True).MoveFileExW
            move_windows.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR,
                                     wintypes.DWORD)
            move_windows.restype = wintypes.BOOL
            get_windows_error = ctypes.get_last_error
        # All long local reads precede this final device/file boundary.  Once
        # it returns, only a retained journal-handle check has occurred and
        # the next operation is the literal local rename.
        boundary_fields = self._released_file_settlement_boundary(
            "post_intent_pre_active_journal_rename", defer_proof=True)
        if os.name == "nt":
            assert move_windows is not None and get_windows_error is not None
            if not move_windows(str(self.authority.active_path),
                                str(self.authority.retired_path), 0x00000008):
                raise ReleaseError(
                    "active-journal archive failed with Windows error " +
                    str(get_windows_error()))
        else:
            os.rename(self.authority.active_path, self.authority.retired_path)
        boundary = self._proof(
            "post_intent_pre_active_journal_rename", **boundary_fields)
        prior._fsync_directory(self.authority.active_path.parent)
        _, retired = _read_sole_regular(
            self.authority.retired_path, 256 * 1024,
            "retired active mutation journal")
        if ((retired["device"], retired["inode"], retired["size"],
             retired["sha256"]) !=
                (self.authority.active_identity["device"],
                 self.authority.active_identity["inode"],
                 self.authority.active_identity["size"],
                 self.authority.active_identity["sha256"])):
            _fail("archived active journal identity differs")
        self._settle("active_journal_archive", {
            "retired": retired, "boundarySha256": boundary["sha256"]})
        return retired

    def _publish_result(self, path: Path, result: dict[str, Any], *,
                        archived: bool) -> None:
        # Encode before the final archived device sandwich.  Once its second
        # runtime closure succeeds, only the retained ledger handle and the
        # literal O_EXCL publication remain; no result encoding or device read
        # can hide a task appearing during the second file pass.
        encoded = json.dumps(
            result, indent=2, sort_keys=True, ensure_ascii=True,
            allow_nan=False).encode("ascii") + b"\n"
        assert self.journal is not None
        self.journal.assert_authority()
        if archived:
            self._assert_local_after_archive()
            boundary = result.get("postArchiveBoundary")
            if (type(boundary) is not dict or
                    type(boundary.get("filesAfterRuntime")) is not dict):
                _fail("clean publication lacks its final file boundary")
            publication_opening = self._file_authority_snapshot()
            if publication_opening != boundary["filesAfterRuntime"]:
                _fail("protected file authority changed before clean evidence")
            publication_runtime = self._runtime_descriptor_sample()
            if publication_runtime["state"] != "RELEASED":
                _fail("descriptor/task authority reopened before clean evidence")
            publication_closing = self._file_authority_snapshot()
            if publication_closing != publication_opening:
                _fail("protected file authority changed during clean publication")
            publication_runtime_closing = self._runtime_descriptor_sample()
            if publication_runtime_closing["state"] != "RELEASED":
                _fail("descriptor/task authority reopened after publication files")
        else:
            self._assert_local_before_archive()
        self.journal.assert_retained_authority()
        try:
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError as error:
            raise ReleaseError("result evidence path became occupied") from error
        try:
            if os.write(descriptor, encoded) != len(encoded):
                _fail("short result evidence write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        prior._fsync_directory(path.parent)

    def _pending_result(
            self, adopted: dict[str, Any], boundary: dict[str, Any],
            dispatch: dict[str, Any] | None,
            proof: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "terminal": "DESCRIPTOR_RELEASE_PENDING_2",
            "forceStopDispatch": dispatch,
            "boundarySha256": boundary["sha256"],
            "releaseProofSha256": proof["sha256"],
            "fileMutationAuthorized": False,
            "activeJournalArchiveAuthorized": False}
        self._settle("descriptor_release_pending_2", payload)
        result = {
            "authority": AUTHORITY, "mode": "execute",
            "result": "DESCRIPTOR_RELEASE_PENDING_2",
            "runId": prior.RUN_ID, "pendingAdoption": adopted,
            "forceStopBoundary": boundary,
            "forceStopDispatch": dispatch,
            "descriptorRelease": proof,
            "fileMutationAttempted": False,
            "activeJournalArchived": False,
            "priorLedgersPreserved": True,
            "conditionalDeviceMutationAssumption":
                DEVICE_CONDITIONAL_MUTATION_ASSUMPTION,
            "authorizedRecoveryThreatBoundary":
                AUTHORIZED_RECOVERY_THREAT_BOUNDARY,
            "mutations": self.mutations,
            "dispatchOutcomes": self.dispatch_outcomes,
            "proofs": self.proofs}
        self._publish_result(
            self.authority.pending_evidence_path, result, archived=False)
        return result

    def execute(self) -> dict[str, Any]:
        if self.journal is None or self.prior_admission is None:
            _fail("execute mode requires the descriptor-release ledger")
        adopted = self._adopt_pending()
        intent = {
            "package": alpha.DOCUMENT_PACKAGE, "user": 0,
            "retainedProcess": asdict(PINNED_PROCESS),
            "retainedProcessToken": PINNED_PROCESS_TOKEN,
            "adoptedPendingRecordSha256": AFTER_HEAD,
            "dispatchMayRepeat": False,
            "taskWindowAuthorityRequiredAbsent": True}
        self._intent("document_force_stop", intent)
        boundary = self._force_stop_boundary()
        dispatch: dict[str, Any] | None = None
        if boundary["terminal"] == "PENDING":
            proof = self._proof(
                "descriptor_release_pending_2",
                terminal="DESCRIPTOR_RELEASE_PENDING_2",
                observations=[boundary["sample"]],
                uncertaintyObserved=True,
                fileMutationAuthorized=False,
                activeJournalArchiveAuthorized=False)
            return self._pending_result(adopted, boundary, dispatch, proof)
        if boundary["forceStopAuthorized"]:
            try:
                result = self.device.force_stop_document()
                prior._validate_mutation_result(
                    result, "force_stop_document", empty_stdout=True)
                dispatch = self._record_dispatch_outcome(
                    "document_force_stop", result=result)
            except prior.MutationTransportUncertain as error:
                dispatch = self._record_dispatch_outcome(
                    "document_force_stop", uncertain=error)
            except Exception as error:
                self._record_mutation_failure("document_force_stop", error)
                raise
        else:
            self._settle("document_force_stop_skipped", {
                "reason": "NATURAL_RELEASE_BEFORE_DISPATCH",
                "boundarySha256": boundary["sha256"],
                "dispatchAttempted": False})
        transport_uncertain = (
            dispatch is not None and
            dispatch.get("mode") == "TRANSPORT_UNCERTAIN")
        if transport_uncertain:
            proof = self._proof(
                "descriptor_release_pending_2",
                terminal="DESCRIPTOR_RELEASE_PENDING_2",
                observations=[], uncertaintyObserved=True,
                forceStopTransportUncertain=True,
                fileMutationAuthorized=False,
                activeJournalArchiveAuthorized=False)
            return self._pending_result(adopted, boundary, dispatch, proof)
        released, proof = self._prove_release_after_stop()
        if not released:
            return self._pending_result(adopted, boundary, dispatch, proof)
        self._settle("document_force_stop", {
            "boundarySha256": boundary["sha256"],
            "dispatch": dispatch, "releaseProofSha256": proof["sha256"],
            "originalProcessGone": True,
            "relevantDescriptorsGone": True})
        self._assert_target_phase()
        self._quarantine_delete(alpha.TARGET_MARK)
        self._quarantine_delete(alpha.TARGET_PDF)
        joint = self._joint_absence()
        pre_archive = self._released_file_settlement_boundary(
            "immediate_pre_active_journal_archive")
        retired = self._archive_active()
        self._assert_ledgers()
        post_archive = self._released_file_settlement_boundary(
            "immediate_pre_clean_evidence_publication")
        result = {
            "authority": AUTHORITY, "mode": "execute",
            "result": "DESCRIPTOR_RELEASE_RECOVERED_CLEANLY",
            "runId": prior.RUN_ID, "pendingAdoption": adopted,
            "forceStopBoundary": boundary,
            "forceStopDispatch": dispatch,
            "descriptorRelease": proof,
            "jointTargetAbsence": joint,
            "preArchiveBoundary": pre_archive,
            "postArchiveBoundary": post_archive,
            "activeJournalArchived": retired,
            "priorLedgersPreserved": True,
            "parkingPdfRetained": alpha.PARKING_PDF,
            "mutations": self.mutations,
            "dispatchOutcomes": self.dispatch_outcomes,
            "proofs": self.proofs,
            "deletedDisposablePaths": [alpha.TARGET_MARK, alpha.TARGET_PDF],
            "residualAssumption": prior.RESIDUAL_ASSUMPTION,
            "conditionalDeviceMutationAssumption":
                DEVICE_CONDITIONAL_MUTATION_ASSUMPTION,
            "authorizedRecoveryThreatBoundary":
                AUTHORIZED_RECOVERY_THREAT_BOUNDARY}
        self._publish_result(
            self.authority.evidence_path, result, archived=True)
        return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="perform the exact descriptor-release continuation")
    parser.add_argument("--adb", type=Path, default=prior.PINNED_ADB)
    parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--active-journal", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    root = arguments.root.absolute()
    report = (arguments.report or
              (root / prior.REPORT_RELATIVE)).absolute()
    active = (arguments.active_journal or
              (root / prior.ACTIVE_RELATIVE)).absolute()
    try:
        authority = load_authority(root, report, active)
        device = DescriptorNomad(arguments.adb, alpha.AUTHORIZED_SERIAL)
        probe = Release(device, authority)
        admission = probe.plan()
        if not arguments.execute:
            print(json.dumps(admission, indent=2, sort_keys=True,
                             ensure_ascii=True, allow_nan=False))
            return 0
        _assert_publication_paths_clear(authority, before_journal=True)
        header = probe._header()
        header["admissionSha256"] = prior._canonical_sha(admission)
        journal = Journal(authority.journal_path, header)
        try:
            recovery = Release(
                device, authority, journal=journal,
                durable_header=journal.records[0]["payload"],
                prior_admission=admission)
            journal.external_guard = recovery._assert_dispatch_authority
            result = recovery.execute()
            print(json.dumps(result, indent=2, sort_keys=True,
                             ensure_ascii=True, allow_nan=False))
        finally:
            journal.close()
        return 0
    except (ReleaseError, prior.RecoveryError, alpha.AlphaError,
            android.AndroidAuthorityError, OSError) as error:
        print("DESCRIPTOR_RELEASE_ERROR: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
