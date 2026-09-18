"""One-shot cleanup for alpha-20260916-175637Z-0e7d2cb2.

The failed alpha copied one hash-pinned PDF to one random staging capability,
then rejected the firmware's CRLF copy receipt before publication.  This
helper is deliberately bound to that report, active journal, run ID, journal
ID, staging inode, and every neighboring path.  Plan mode is device-read-only.
Execute mode can unlink only the exact staging capability and retires the
active mutation journal only after two independent post-delete proofs.

Residual assumption: Android shared storage has no compare-and-unlink system
call.  Immediately before unlink, the helper therefore revalidates the full
device/inode/owner/size/hash identity twice and assumes no concurrent writer
can replace the cryptographically random leaf between the second stat and the
literal unlink command.  Any observed drift fails closed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable, NoReturn, Protocol, Sequence

import native_page_alpha_runner as alpha
import native_page_host_authority as host
import recover_native_page_alpha_run as shared


AUTHORITY = "native-page-alpha-fresh-staging-recovery-v1"
RUN_ID = "alpha-20260916-175637Z-0e7d2cb2"
JOURNAL_ID = "f847b6f2-575e-493a-a0d2-f30cb21b2d2c"
REPORT_SHA256 = "8622bde3234051c2b5213c16b6bc5a9fca2aafa61596c4f8017d4b6d00b236f4"
ACTIVE_JOURNAL_SHA256 = "74c3eec93c77678e7b864ade3b83ee9e7a6194c539ad6d258e3f8441036b24d7"
ACTIVE_JOURNAL_HEAD = "b4ec1bd557d8f92886dc567b0507527c51f1efaf6a3e15109dd12aa5c089ebbb"
REPORT_BYTES = 47_262
ACTIVE_JOURNAL_BYTES = 23_199
COPY_STDOUT_SHA256 = "c9b7430b0f62a060bdc433a21c39b6bd24590793953dd9edd06a4da499f60c45"
STAGING_PDF = (
    "/storage/emulated/0/Download/"
    ".NativeViewportVisualOnly-Alpha-2eeadd7-staging-"
    "9e006175dc6fdb244a3395bf7e0a2d88-pdf"
)
STAGING_MARK = (
    "/storage/emulated/0/Download/"
    ".NativeViewportVisualOnly-Alpha-2eeadd7-staging-"
    "994d07c12ce0bfa8ed7795621fadb7f4-mark"
)
QUARANTINE_PDF = (
    "/storage/emulated/0/Download/"
    ".NativeViewportVisualOnly-Alpha-2eeadd7-quarantine-"
    "1badad73a482dce75e58977cc43959a2-pdf"
)
QUARANTINE_MARK = (
    "/storage/emulated/0/Download/"
    ".NativeViewportVisualOnly-Alpha-2eeadd7-quarantine-"
    "d51c01b6cb441970d35545695a12e04f-mark"
)
PINNED_STAGING = alpha.DeviceFile(
    STAGING_PDF, "regular file", 4678, 10088, 10088, 185075, 54,
    alpha.SOURCE_PDF_SHA256,
)
PINNED_SOURCE_PDF = alpha.DeviceFile(
    alpha.SOURCE_PDF, "regular file", 4678, 10088, 10088, 183984, 54,
    alpha.SOURCE_PDF_SHA256,
)
PINNED_SOURCE_MARK = alpha.DeviceFile(
    alpha.SOURCE_MARK, "regular file", 5756, 10088, 10088, 185219, 54,
    alpha.SOURCE_MARK_SHA256,
)
PINNED_PARKING = alpha.DeviceFile(
    alpha.PARKING_PDF, "regular file", 4678, 10088, 10088, 182600, 54,
    alpha.SOURCE_PDF_SHA256,
)
EXPECTED_ABSENT = (
    alpha.TARGET_PDF, alpha.TARGET_MARK, STAGING_MARK,
    QUARANTINE_PDF, QUARANTINE_MARK,
)
REPORT_RELATIVE = Path("build/native-page-alpha-runs") / RUN_ID / "report.json"
ACTIVE_RELATIVE = Path("build/native-page-alpha-runs") / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
RECOVERY_BASENAME = "fresh-staging-recovery.jsonl"
RETIRED_BASENAME = "mutation-authority.retired-" + JOURNAL_ID + ".jsonl"
EVIDENCE_BASENAME = "fresh-staging-recovery-evidence.json"
MAX_RECOVERY_BYTES = 512 * 1024
RESIDUAL_ASSUMPTION = (
    "the cryptographically random staging leaf is not concurrently replaced "
    "between its second exact identity proof and literal unlink"
)


class RecoveryError(RuntimeError):
    """The fixed failed-run state is not authoritative enough to mutate."""


def _fail(message: str) -> NoReturn:
    raise RecoveryError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key in pinned authority")
        result[key] = value
    return result


def _exact_local_path(actual: Path, expected: Path, label: str) -> Path:
    candidate = actual.absolute()
    wanted = expected.absolute()
    if os.path.normcase(str(candidate)) != os.path.normcase(str(wanted)):
        _fail(label + " path differs from the fixed run")
    return candidate


@dataclass(frozen=True)
class LocalFile:
    path: str
    size: int
    sha256: str
    device: int
    inode: int
    mtimeNs: int | None


def _read_local(path: Path, maximum: int, label: str) -> tuple[bytes, LocalFile]:
    raw, wire = shared._read_pinned_regular(path, maximum, label)
    return raw, LocalFile(
        wire["path"], wire["size"], wire["sha256"], wire["device"],
        wire["inode"], wire["mtimeNs"],
    )


@dataclass(frozen=True)
class RunAuthority:
    script_root: Path
    run_dir: Path
    report: LocalFile
    active_journal: LocalFile
    recovery_path: Path
    retired_path: Path
    evidence_path: Path


def _read_bound_journal(
        active_path: Path, retired_path: Path, recovery_path: Path,
        ) -> tuple[bytes, LocalFile, bool]:
    active_exists = os.path.lexists(active_path)
    retired_exists = os.path.lexists(retired_path)
    if active_exists == retired_exists:
        _fail("exactly one active/retired mutation journal must exist")
    journal_location = active_path if active_exists else retired_path
    journal_raw, located = _read_local(
        journal_location, alpha.MUTATION_JOURNAL_MAX_BYTES,
        "active mutation journal" if active_exists else "retired mutation journal")
    if not active_exists:
        if not os.path.lexists(recovery_path):
            _fail("retired journal lacks its recovery transaction")
        recovery_records, _, _ = RecoveryJournal.inspect(recovery_path)
        kinds = tuple(record["kind"] for record in recovery_records)
        if len(kinds) < 4 or kinds[:4] != RecoveryJournal.KINDS[:4]:
            _fail("retired journal is not authorized by a durable retire intent")
        header = recovery_records[0]["payload"]
        expected_header = {
            "authority": AUTHORITY, "runId": RUN_ID,
            "journalId": JOURNAL_ID, "reportSha256": REPORT_SHA256,
            "activeJournalSha256": ACTIVE_JOURNAL_SHA256,
            "activeJournalDevice": located.device,
            "activeJournalInode": located.inode,
            "staging": asdict(PINNED_STAGING),
            "expectedAbsent": list(EXPECTED_ABSENT),
            "residualAssumption": RESIDUAL_ASSUMPTION,
        }
        if header != expected_header:
            _fail("retired journal recovery header does not bind its exact object")
        retire = recovery_records[3]["payload"]
        if (type(retire) is not dict or
                retire.get("activePath") != str(active_path) or
                retire.get("retiredPath") != str(retired_path) or
                retire.get("sha256") != ACTIVE_JOURNAL_SHA256 or
                type(retire.get("proofs")) is not list or
                len(retire["proofs"]) != 2):
            _fail("retired journal lacks the exact durable retirement intent")
    return journal_raw, LocalFile(
        str(active_path), located.size, located.sha256, located.device,
        located.inode, located.mtimeNs), active_exists


def load_authority(
        script_root: Path, report_path: Path, active_path: Path,
        *, expected_report_sha256: str = REPORT_SHA256,
        expected_journal_sha256: str = ACTIVE_JOURNAL_SHA256,
        ) -> RunAuthority:
    root = script_root.absolute()
    report_expected = root / REPORT_RELATIVE
    active_expected = root / ACTIVE_RELATIVE
    report_path = _exact_local_path(report_path, report_expected, "report")
    active_path = _exact_local_path(active_path, active_expected, "active journal")
    report_raw, report_file = _read_local(report_path, 128 * 1024, "failed report")
    run_dir = report_path.parent
    recovery_path = run_dir / RECOVERY_BASENAME
    retired_path = run_dir / RETIRED_BASENAME
    journal_raw, journal_file, active_exists = _read_bound_journal(
        active_path, retired_path, recovery_path)
    if (len(report_raw) != REPORT_BYTES or report_file.sha256 != expected_report_sha256 or
            len(journal_raw) != ACTIVE_JOURNAL_BYTES or
            journal_file.sha256 != expected_journal_sha256):
        _fail("report or active journal bytes differ from the fixed failed run")
    try:
        report = json.loads(
            report_raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError("failed report is not strict UTF-8 JSON") from error
    if (report.get("authority") != alpha.AUTHORITY or
            report.get("authorizedSerial") != alpha.AUTHORIZED_SERIAL or
            report.get("checkpoint") != alpha.CHECKPOINT or
            report.get("result") != "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN" or
            report.get("primaryError") !=
            "AlphaError: fixture copy lacks the exact created-copy receipt" or
            report.get("documentLaunchAttempted") is not False or
            report.get("launchOwned") is not False or
            report.get("host") is not None or report.get("screenshots") != [] or
            report.get("rotationAuthority") != alpha.ROTATION_ADB_SYSTEM_SETTINGS):
        _fail("failed report semantic state differs from the fresh staging failure")
    fixture = report.get("fixture")
    if type(fixture) is not dict:
        _fail("failed report lacks fixture authority")
    journal_wire = fixture.get("mutationJournal")
    if (type(journal_wire) is not dict or
            journal_wire.get("journalId") != JOURNAL_ID or
            journal_wire.get("fileSha256") != expected_journal_sha256 or
            journal_wire.get("headSha256") != ACTIVE_JOURNAL_HEAD or
            journal_wire.get("recordCount") != 4 or
            journal_wire.get("path") != str(active_path) or
            journal_wire.get("retired") is not False):
        _fail("report does not bind the exact active mutation journal")
    obligations = fixture.get("cleanupObligations")
    if type(obligations) is not dict or set(obligations) != {
            alpha.TARGET_PDF, alpha.TARGET_MARK}:
        _fail("failed report cleanup topology differs")
    pdf_obligation = obligations[alpha.TARGET_PDF]
    mark_obligation = obligations[alpha.TARGET_MARK]
    expected_staging_wire = asdict(PINNED_STAGING)
    if (type(pdf_obligation) is not dict or
            pdf_obligation.get("staging_path") != STAGING_PDF or
            pdf_obligation.get("staging_cleanup_pre_observed") !=
            expected_staging_wire or
            pdf_obligation.get("staging_ownership_ambiguous") is not True or
            pdf_obligation.get("copy_attempted") is not True or
            pdf_obligation.get("copy_reply_proved") is not False or
            pdf_obligation.get("publish_move_attempted") is not False or
            pdf_obligation.get("target") != alpha.TARGET_PDF or
            pdf_obligation.get("quarantine_path") != QUARANTINE_PDF or
            type(mark_obligation) is not dict or
            mark_obligation.get("staging_path") != STAGING_MARK or
            mark_obligation.get("staging_resolved_absent") is not True or
            mark_obligation.get("copy_attempted") is not False or
            mark_obligation.get("target") != alpha.TARGET_MARK or
            mark_obligation.get("quarantine_path") != QUARANTINE_MARK):
        _fail("failed report does not bind the single retained staging PDF")
    copy_commands = [
        item for item in report.get("commands", [])
        if type(item) is dict and item.get("operation") ==
        "copy_staging_" + Path(STAGING_PDF).name
    ]
    expected_copy_argv = [
        str(shared.PINNED_ADB_PATH), "-s", alpha.AUTHORIZED_SERIAL,
        "shell", "toybox", "cp", "-n", "-T", "-v",
        alpha.SOURCE_PDF, STAGING_PDF,
    ]
    if (len(copy_commands) != 1 or copy_commands[0].get("argv") != expected_copy_argv or
            copy_commands[0].get("returncode") != 0 or
            copy_commands[0].get("stdoutSha256") != COPY_STDOUT_SHA256 or
            copy_commands[0].get("stderrSha256") != alpha._sha(b"")):
        _fail("copy receipt evidence differs from the exact CRLF failure")
    if active_exists:
        recovered = alpha.recover_mutation_journal(active_path)
        if (recovered["journalId"] != JOURNAL_ID or
                recovered["headSha256"] != ACTIVE_JOURNAL_HEAD or
                recovered["recordCount"] != 4 or recovered["tornTail"] is not False or
                recovered["lastRecord"]["event"] != "FIXTURE_COPY_ATTEMPTED" or
                recovered["lastRecord"]["details"] != {
                    "retryAllowed": False, "source": alpha.SOURCE_PDF,
                    "staging": STAGING_PDF, "target": alpha.TARGET_PDF}):
            _fail("active journal chain differs from the exact copy attempt")
    if run_dir.name != RUN_ID or run_dir.parent != active_path.parent:
        _fail("failed report and active journal directory binding differs")
    return RunAuthority(
        root, run_dir, report_file, journal_file,
        recovery_path,
        retired_path,
        run_dir / EVIDENCE_BASENAME,
    )


class Device(Protocol):
    history: list[dict[str, Any]]
    def adb_authority(self) -> dict[str, Any]: ...
    def get_state(self) -> str: ...
    def get_serial(self) -> str: ...
    def getprop(self, name: str) -> str: ...
    def current_user(self) -> str: ...
    def package_dump(self, package: str) -> str: ...
    def package_path(self, package: str) -> str: ...
    def sha256_file(self, path: str) -> str: ...
    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def activities(self) -> bytes: ...
    def windows(self) -> bytes: ...
    def displays(self) -> bytes: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def remove_staging_member(self, staging: str) -> alpha.CommandResult: ...


class FixedNomad(shared.RecoveryNomad):
    """Reuse the reviewed exact ADB-byte and read-only rotation authority."""

    def remove_staging_member(self, staging: str) -> alpha.CommandResult:
        if staging != STAGING_PDF:
            _fail("fresh recovery deletion escaped its sole staging capability")
        return super().remove_staging_member(staging)


def _same_file(actual: alpha.DeviceFile | None,
               expected: alpha.DeviceFile, label: str) -> None:
    if actual != expected:
        _fail(label + " identity differs")


@dataclass(frozen=True)
class LiveProof:
    adbSha256: str
    documentPid: int | None
    documentStartTicks: int | None
    documentFdTargets: tuple[str, ...]
    documentTaskWindowAbsent: bool
    hostScopeAbsent: bool
    cleanupPathScopeAbsent: bool
    rotation: tuple[str, str]
    stagingPresent: bool


def _observe(device: Device, *, staging_must_exist: bool) -> LiveProof:
    adb_wire = device.adb_authority()
    if (adb_wire.get("sha256") != shared.PINNED_ADB_SHA256 or
            device.get_state() != "device" or
            device.get_serial() != alpha.AUTHORIZED_SERIAL or
            device.getprop("ro.product.model") != alpha.MODEL or
            device.getprop("ro.build.version.sdk") != alpha.SDK or
            device.getprop("ro.build.fingerprint") != alpha.FINGERPRINT or
            device.current_user() != "0"):
        _fail("device identity differs from the pinned Nomad")
    document_dump = device.package_dump(alpha.DOCUMENT_PACKAGE)
    host_dump = device.package_dump(alpha.HOST_PACKAGE)
    alpha._package_version(
        document_dump, alpha.DOCUMENT_VERSION_CODE,
        alpha.DOCUMENT_VERSION_NAME, "Document")
    alpha._package_version(
        host_dump, alpha.HOST_VERSION_CODE, alpha.HOST_VERSION_NAME, "host")
    document_apk = device.package_path(alpha.DOCUMENT_PACKAGE)
    host_apk = device.package_path(alpha.HOST_PACKAGE)
    if (document_apk != alpha.DOCUMENT_APK or
            device.sha256_file(document_apk) != alpha.DOCUMENT_APK_SHA256 or
            device.sha256_file(host_apk) != alpha.ALPHA_SIGNED_APK_SHA256):
        _fail("installed package identity differs")
    _same_file(device.stat_file(alpha.SOURCE_PDF), PINNED_SOURCE_PDF, "source PDF")
    _same_file(device.stat_file(alpha.SOURCE_MARK), PINNED_SOURCE_MARK, "source mark")
    _same_file(device.stat_file(alpha.PARKING_PDF), PINNED_PARKING, "parking PDF")
    if device.stat_file(alpha.PARKING_MARK, absent_ok=True) is not None:
        _fail("parking mark unexpectedly exists")
    staging = device.stat_file(STAGING_PDF, absent_ok=True)
    if staging_must_exist:
        _same_file(staging, PINNED_STAGING, "retained staging PDF")
    elif staging is not None:
        _fail("retained staging PDF still exists after cleanup")
    for path in EXPECTED_ABSENT:
        if device.stat_file(path, absent_ok=True) is not None:
            _fail("neighbor path unexpectedly exists: " + path)
    if device.pidof(alpha.HOST_PACKAGE):
        _fail("visual host process is live")
    pids = device.pidof(alpha.DOCUMENT_PACKAGE)
    if len(pids) > 1:
        _fail("multiple stock Document processes are live")
    pid: int | None = None
    start_ticks: int | None = None
    fd_targets: tuple[str, ...] = ()
    if pids:
        pid = pids[0]
        identity = device.process_identity(pid, alpha.DOCUMENT_PACKAGE)
        if identity.pid != pid or identity.uid != 1000 or identity.package != alpha.DOCUMENT_PACKAGE:
            _fail("stock Document process identity differs")
        start_ticks = identity.start_ticks
        links = device.process_fd_links(pid)
        targets = shared._validated_document_fd_targets(links)
        forbidden_fd_paths = (
            alpha.SOURCE_PDF, alpha.SOURCE_MARK, alpha.TARGET_PDF,
            alpha.TARGET_MARK, STAGING_PDF, STAGING_MARK,
            QUARANTINE_PDF, QUARANTINE_MARK,
        )
        if any(re.search(
                r" -> " + re.escape(path) + r"(?: \(deleted\))?$",
                links, re.MULTILINE) is not None
                for path in forbidden_fd_paths):
            _fail("stock Document descriptor inventory references cleanup scope")
        if targets != frozenset((alpha.PARKING_PDF,)):
            _fail("stock Document descriptor authority is not parking-only")
        fd_targets = tuple(sorted(targets))
    activities = device.activities()
    windows = device.windows()
    displays = device.displays()
    if (alpha._contains_document_task_or_window(activities) or
            alpha._contains_document_task_or_window(windows)):
        _fail("a stock Document task or window remains live")
    forbidden = (
        alpha.HOST_PACKAGE, alpha.HOST_COMPONENT, STAGING_PDF,
        alpha.TARGET_PDF, alpha.TARGET_URI,
    )
    for label, raw in (("activities", activities), ("windows", windows),
                       ("displays", displays)):
        text = alpha._decode_text(raw, label)
        if any(token in text for token in forbidden):
            _fail(label + " retains failed alpha scope")
    rotation = device.rotation_settings()
    if rotation != ("1", "2"):
        _fail("persisted rotation differs from the pre-run authority")
    return LiveProof(
        str(adb_wire["sha256"]), pid, start_ticks, fd_targets,
        True, True, True,
        rotation, staging is not None,
    )


def _prove_twice(device: Device, *, staging_must_exist: bool,
                 sleep: Callable[[float], None]) -> tuple[LiveProof, LiveProof]:
    first = _observe(device, staging_must_exist=staging_must_exist)
    sleep(0.25)
    second = _observe(device, staging_must_exist=staging_must_exist)
    if first != second:
        _fail("live authority changed between the two independent observations")
    return first, second


def _sync_file(stream: Any) -> None:
    stream.flush()
    os.fsync(stream.fileno())


class RecoveryJournal:
    EVENTS = (
        "RECOVERY_CREATED", "DELETE_INTENT", "DELETE_SETTLED",
        "RETIRE_INTENT", "ACTIVE_JOURNAL_RETIRED", "RECOVERY_COMPLETE",
    )
    KINDS = (
        "header", "delete_intent", "delete_settled", "retire_intent",
        "active_journal_retired", "recovery_complete",
    )

    def __init__(self, path: Path, authority: RunAuthority):
        self.path = path
        self.authority = authority
        self.records: list[dict[str, Any]] = []
        if path.exists() or path.is_symlink():
            self._load()
        else:
            header = self._header()
            self._durable = shared.DurableJournal(path, header)
            self.records.append({
                "event": self.EVENTS[0], "details": header,
                "recordSha256": self._durable.head_hash,
            })

    @property
    def events(self) -> tuple[str, ...]:
        return tuple(record["event"] for record in self.records)

    def _header(self) -> dict[str, Any]:
        return {
            "authority": AUTHORITY, "runId": RUN_ID,
            "journalId": JOURNAL_ID, "reportSha256": REPORT_SHA256,
            "activeJournalSha256": ACTIVE_JOURNAL_SHA256,
            "activeJournalDevice": self.authority.active_journal.device,
            "activeJournalInode": self.authority.active_journal.inode,
            "staging": asdict(PINNED_STAGING),
            "expectedAbsent": list(EXPECTED_ABSENT),
            "residualAssumption": RESIDUAL_ASSUMPTION,
        }

    def _header_record_bytes(self) -> bytes:
        base = {
            "seq": 0, "prevHash": "0" * 64, "kind": "header",
            "payload": self._header(),
        }
        record = {**base, "recordHash": alpha._canonical_sha(base)}
        return _canonical(record) + b"\n"

    @classmethod
    def inspect(cls, path: Path) -> tuple[list[dict[str, Any]], int, bytes]:
        raw, _ = _read_local(path, MAX_RECOVERY_BYTES, "recovery journal")
        boundary = len(raw) if raw.endswith(b"\n") else raw.rfind(b"\n") + 1
        if boundary <= 0:
            _fail("recovery journal has no complete durable record")
        complete, torn = raw[:boundary], raw[boundary:]
        previous = "0" * 64
        parsed: list[dict[str, Any]] = []
        for sequence, line in enumerate(complete.splitlines()):
            if sequence >= len(cls.KINDS):
                _fail("recovery journal has records beyond the one-shot grammar")
            try:
                record = json.loads(
                    line.decode("ascii", "strict"), object_pairs_hook=_pairs)
            except (UnicodeError, json.JSONDecodeError) as error:
                raise RecoveryError("recovery journal is not canonical JSON") from error
            if _canonical(record) != line:
                _fail("recovery journal record is not canonical")
            if set(record) != {"kind", "payload", "prevHash", "recordHash", "seq"}:
                _fail("recovery journal record topology differs")
            payload = {
                "seq": record["seq"], "prevHash": record["prevHash"],
                "kind": record["kind"], "payload": record["payload"],
            }
            if (record["seq"] != sequence or record["prevHash"] != previous or
                    record["kind"] != cls.KINDS[sequence] or
                    type(record["payload"]) is not dict or
                    record["recordHash"] != alpha._canonical_sha(payload)):
                _fail("recovery journal chain or grammar differs")
            parsed.append(record)
            previous = record["recordHash"]
        if not parsed or parsed[0]["kind"] != "header":
            _fail("recovery journal header is absent")
        if torn:
            if (len(torn) > 64 * 1024 or b"\r" in torn or b"\x00" in torn or
                    len(parsed) >= len(cls.KINDS)):
                _fail("recovery journal torn tail is outside the closed bound")
            try:
                torn.decode("ascii", "strict")
            except UnicodeError as error:
                raise RecoveryError("recovery journal torn tail is not ASCII") from error
            expected_prefix = (
                '{"kind":' + json.dumps(cls.KINDS[len(parsed)]) + ',"payload":'
            ).encode("ascii")
            if not (expected_prefix.startswith(torn) or torn.startswith(expected_prefix)):
                _fail("recovery journal torn tail is not the next canonical record")
        return parsed, boundary, torn

    def _load(self) -> None:
        raw, wire = _read_local(
            self.path, MAX_RECOVERY_BYTES, "recovery journal")
        if b"\n" not in raw:
            expected = self._header_record_bytes()
            if not expected.startswith(raw):
                _fail("partial recovery header is not an exact canonical prefix")
            self._durable = shared.DurableJournal.resume(
                self.path, count=0, head_hash="0" * 64, valid_size=0,
                expected_prefix_sha256=_sha(b""),
                expected_identity={
                    "device": wire.device, "inode": wire.inode,
                    "size": wire.size,
                })
            record = self._durable.record("header", self._header())
            self.records = [{
                "event": self.EVENTS[0], "details": self._header(),
                "recordSha256": record["recordHash"],
            }]
            return
        parsed, valid_size, torn = self.inspect(self.path)
        expected_header = self._header()
        if parsed[0]["payload"] != expected_header:
            _fail("recovery journal header differs from the fixed authority")
        raw, wire = _read_local(self.path, MAX_RECOVERY_BYTES, "recovery journal")
        prefix_sha = _sha(raw[:valid_size])
        self._durable = shared.DurableJournal.resume(
            self.path, count=len(parsed), head_hash=parsed[-1]["recordHash"],
            valid_size=valid_size, expected_prefix_sha256=prefix_sha,
            expected_identity={
                "device": wire.device, "inode": wire.inode, "size": wire.size,
            })
        self.records = [
            {"event": self.EVENTS[index], "details": record["payload"],
             "recordSha256": record["recordHash"]}
            for index, record in enumerate(parsed)
        ]

    def append(self, event: str, details: dict[str, Any]) -> None:
        sequence = len(self.records)
        if sequence >= len(self.EVENTS) or event != self.EVENTS[sequence]:
            _fail("recovery event is outside the one-shot grammar")
        record = self._durable.record(self.KINDS[sequence], details)
        self.records.append({
            "event": event, "details": details,
            "recordSha256": record["recordHash"],
        })

    def close(self) -> None:
        self._durable.close()


def _host_file_matches(path: Path, expected: LocalFile) -> bool:
    try:
        raw, wire = _read_local(path, expected.size, "active journal archive")
    except RecoveryError:
        return False
    return (len(raw) == expected.size and wire.sha256 == expected.sha256 and
            wire.size == expected.size)


def _assert_local_authority_current(authority: RunAuthority) -> None:
    _, report = _read_local(
        Path(authority.report.path), REPORT_BYTES, "current failed report")
    _, active = _read_local(
        Path(authority.active_journal.path), ACTIVE_JOURNAL_BYTES,
        "current active mutation journal")
    for current, expected, label in (
            (report, authority.report, "failed report"),
            (active, authority.active_journal, "active mutation journal")):
        if (current.size, current.sha256, current.device, current.inode,
                current.mtimeNs) != (
                expected.size, expected.sha256, expected.device,
                expected.inode, expected.mtimeNs):
            _fail(label + " changed after authority loading")


def _retire_active(authority: RunAuthority) -> LocalFile:
    active = Path(authority.active_journal.path)
    retired = authority.retired_path
    if retired.exists() or retired.is_symlink():
        if active.exists() or active.is_symlink() or not _host_file_matches(
                retired, authority.active_journal):
            _fail("active journal retirement state is ambiguous")
        _, wire = _read_local(
            retired, ACTIVE_JOURNAL_BYTES, "retired active journal")
        if (wire.device, wire.inode) != (
                authority.active_journal.device,
                authority.active_journal.inode):
            _fail("retired active journal object identity differs")
        return wire
    raw, current = _read_local(active, ACTIVE_JOURNAL_BYTES, "active journal before retire")
    if (current.sha256 != authority.active_journal.sha256 or
            current.size != authority.active_journal.size or
            current.device != authority.active_journal.device or
            current.inode != authority.active_journal.inode or
            _sha(raw) != ACTIVE_JOURNAL_SHA256):
        _fail("active journal changed before retirement")
    try:
        active_parent = os.lstat(active.parent)
        retired_parent = os.lstat(retired.parent)
    except OSError as error:
        raise RecoveryError("journal retirement parent is unavailable") from error
    if (stat.S_ISLNK(active_parent.st_mode) or
            stat.S_ISLNK(retired_parent.st_mode) or
            not stat.S_ISDIR(active_parent.st_mode) or
            not stat.S_ISDIR(retired_parent.st_mode) or
            active_parent.st_dev != retired_parent.st_dev or
            active_parent.st_dev != current.device or
            os.path.lexists(retired)):
        _fail("journal retirement is not one same-device no-clobber publication")
    try:
        alpha._publish_local_file_exclusive(active, retired)
    except OSError as error:
        raise RecoveryError("active journal retirement publication failed") from error
    _, wire = _read_local(retired, ACTIVE_JOURNAL_BYTES, "retired active journal")
    if (wire.sha256 != ACTIVE_JOURNAL_SHA256 or
            wire.size != ACTIVE_JOURNAL_BYTES or
            (wire.device, wire.inode) !=
            (authority.active_journal.device, authority.active_journal.inode) or
            os.path.lexists(active)):
        _fail("retired active journal bytes differ")
    return wire


class Recovery:
    def __init__(self, device: Device, authority: RunAuthority, *,
                 sleep: Callable[[float], None] = time.sleep):
        self.device = device
        self.authority = authority
        self.sleep = sleep

    def plan(self) -> dict[str, Any]:
        _assert_local_authority_current(self.authority)
        proofs = _prove_twice(self.device, staging_must_exist=True, sleep=self.sleep)
        _assert_local_authority_current(self.authority)
        return {
            "authority": AUTHORITY, "result": "PLAN_READY", "mode": "plan",
            "deviceMutationAttempted": False, "runId": RUN_ID,
            "journalId": JOURNAL_ID, "reportSha256": REPORT_SHA256,
            "activeJournalSha256": ACTIVE_JOURNAL_SHA256,
            "staging": asdict(PINNED_STAGING),
            "proofs": [asdict(value) for value in proofs],
            "expectedAbsent": list(EXPECTED_ABSENT),
            "residualAssumption": RESIDUAL_ASSUMPTION,
        }

    def execute(self) -> dict[str, Any]:
        journal = RecoveryJournal(self.authority.recovery_path, self.authority)
        try:
            return self._execute_with_journal(journal)
        finally:
            journal.close()

    def _execute_with_journal(self, journal: RecoveryJournal) -> dict[str, Any]:
        events = journal.events
        if events == RecoveryJournal.EVENTS:
            if not _host_file_matches(self.authority.retired_path,
                                      self.authority.active_journal):
                _fail("completed recovery lacks its exact retired journal")
            _prove_twice(self.device, staging_must_exist=False, sleep=self.sleep)
            evidence = self._evidence(journal, "RECOVERED_CLEANLY")
            self._write_evidence(evidence)
            return evidence
        if "DELETE_INTENT" not in events:
            _assert_local_authority_current(self.authority)
            before = _prove_twice(
                self.device, staging_must_exist=True, sleep=self.sleep)
            _assert_local_authority_current(self.authority)
            journal.append("DELETE_INTENT", {
                "proofs": [asdict(value) for value in before],
                "path": STAGING_PDF, "identity": asdict(PINNED_STAGING),
            })
            events = journal.events
        if "DELETE_SETTLED" not in events:
            current = self.device.stat_file(STAGING_PDF, absent_ok=True)
            if current is not None:
                _assert_local_authority_current(self.authority)
                _prove_twice(self.device, staging_must_exist=True, sleep=self.sleep)
                _assert_local_authority_current(self.authority)
                self.device.remove_staging_member(STAGING_PDF)
            after = _prove_twice(
                self.device, staging_must_exist=False, sleep=self.sleep)
            journal.append("DELETE_SETTLED", {
                "proofs": [asdict(value) for value in after],
                "path": STAGING_PDF, "absenceObservations": 2,
            })
            events = journal.events
        if "RETIRE_INTENT" not in events:
            _assert_local_authority_current(self.authority)
            after = _prove_twice(
                self.device, staging_must_exist=False, sleep=self.sleep)
            _assert_local_authority_current(self.authority)
            journal.append("RETIRE_INTENT", {
                "proofs": [asdict(value) for value in after],
                "activePath": self.authority.active_journal.path,
                "retiredPath": str(self.authority.retired_path),
                "sha256": ACTIVE_JOURNAL_SHA256,
            })
            events = journal.events
        # A restart after RETIRE_INTENT must not use the old proof as current
        # deletion authority.  Re-prove the complete device/FD/task/path state
        # before either publishing the retirement or accepting it as settled.
        active_still_present = os.path.lexists(
            Path(self.authority.active_journal.path))
        if active_still_present:
            _assert_local_authority_current(self.authority)
        _prove_twice(
            self.device, staging_must_exist=False, sleep=self.sleep)
        if active_still_present:
            _assert_local_authority_current(self.authority)
        retired = _retire_active(self.authority)
        if "ACTIVE_JOURNAL_RETIRED" not in events:
            journal.append("ACTIVE_JOURNAL_RETIRED", asdict(retired))
            events = journal.events
        final = _prove_twice(
            self.device, staging_must_exist=False, sleep=self.sleep)
        if "RECOVERY_COMPLETE" not in events:
            journal.append("RECOVERY_COMPLETE", {
                "proofs": [asdict(value) for value in final],
                "deviceMutations": [{"operation": "unlink", "path": STAGING_PDF}],
                "retiredJournalSha256": retired.sha256,
            })
        evidence = self._evidence(journal, "RECOVERED_CLEANLY")
        self._write_evidence(evidence)
        return evidence

    def _evidence(self, journal: RecoveryJournal, result: str) -> dict[str, Any]:
        return {
            "authority": AUTHORITY, "result": result, "mode": "execute",
            "runId": RUN_ID, "journalId": JOURNAL_ID,
            "reportSha256": REPORT_SHA256,
            "activeJournalSha256": ACTIVE_JOURNAL_SHA256,
            "retiredJournalPath": str(self.authority.retired_path),
            "recoveryJournalPath": str(self.authority.recovery_path),
            "recoveryJournalHead": journal.records[-1]["recordSha256"],
            "recoveryEvents": list(journal.events),
            "onlyDeviceMutation": {"operation": "unlink", "path": STAGING_PDF},
            "sourcesPreserved": [asdict(PINNED_SOURCE_PDF), asdict(PINNED_SOURCE_MARK)],
            "residualAssumption": RESIDUAL_ASSUMPTION,
        }

    def _write_evidence(self, evidence: dict[str, Any]) -> None:
        # Keep evidence deterministic across process restarts.  The durable
        # journal contains the authoritative live proofs; per-process command
        # history is intentionally excluded because it changes on a resume.
        raw = (json.dumps(
            evidence, ensure_ascii=True, allow_nan=False, sort_keys=True,
            indent=2) + "\n").encode("ascii")
        path = self.authority.evidence_path
        if path.exists() or path.is_symlink():
            existing, identity = _read_local(
                path, len(raw), "recovery evidence")
            if existing == raw:
                return
            if not raw.startswith(existing):
                _fail("existing recovery evidence differs")
            flags = (os.O_RDWR | getattr(os, "O_BINARY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                        (identity.device, identity.inode, identity.size) or
                        not stat.S_ISREG(opened.st_mode)):
                    _fail("partial recovery evidence changed before resume")
                os.lseek(descriptor, 0, os.SEEK_SET)
                observed = b""
                while len(observed) < len(existing):
                    chunk = os.read(descriptor, len(existing) - len(observed))
                    if not chunk:
                        break
                    observed += chunk
                if observed != existing:
                    _fail("partial recovery evidence descriptor differs")
                os.lseek(descriptor, len(existing), os.SEEK_SET)
                offset = len(existing)
                while offset < len(raw):
                    written = os.write(descriptor, raw[offset:])
                    if type(written) is not int or written <= 0:
                        _fail("recovery evidence resume made no write progress")
                    offset += written
                os.ftruncate(descriptor, len(raw))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            final, _ = _read_local(path, len(raw), "completed recovery evidence")
            if final != raw:
                _fail("completed recovery evidence reread differs")
            return
        reservation = shared.EvidenceReservation(path)
        try:
            reservation.write(evidence)
        finally:
            reservation.close()


def _default_root() -> Path:
    return Path(__file__).resolve(strict=True).parent


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="perform the one exact staging cleanup")
    parser.add_argument("--adb", type=Path, default=shared.PINNED_ADB_PATH)
    args = parser.parse_args(argv)
    root = _default_root()
    try:
        authority = load_authority(
            root, root / REPORT_RELATIVE, root / ACTIVE_RELATIVE)
        device = FixedNomad(args.adb, alpha.AUTHORIZED_SERIAL)
        recovery = Recovery(device, authority)
        evidence = recovery.execute() if args.execute else recovery.plan()
        sys.stdout.buffer.write(_canonical(evidence) + b"\n")
        return 0
    except (RecoveryError, alpha.AlphaError, OSError) as error:
        sys.stderr.write(type(error).__name__ + ": " + str(error) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
