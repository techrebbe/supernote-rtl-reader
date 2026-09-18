"""Report-bound recovery for ``alpha-20260916-190148Z-b28865bb``.

This is deliberately a one-run program, not a general cleanup utility.  The
failed alpha published two disposable files and left the visual host in a
sticky failure after Android's two displays legitimately reported different
orientation-source activities.  The program binds every operation to the
immutable failed report, its active mutation journal, the retained host
session/process, and the exact file objects named below.

The default ``plan`` mode is device-read-only.  ``--execute`` performs a
durably journalled, one-shot sequence:

* prove twice that the exact released visual-host task remains the sole
  relevant task/window and that Document/display 1 are absent;
* journal and remove only that exact one-child host task once, after an
  immediate stable-identity revalidation;
* open the exact persistent parking PDF on display 0 exactly once;
* authenticate its sole stock-Document task, UI, process, and parking-only
  descriptors, then remove only that exact one-child/root task once;
* prove global task absence and parking-only descriptors twice;
* quarantine and unlink the exact retained mark, then PDF, without retrying
  an uncertain transport; and
* archive (never overwrite or delete) the original active mutation journal.

Android shared storage has no compare-and-rename or compare-and-unlink
primitive.  Immediately before each path mutation the full device/inode/
owner/size/hash identity is revalidated.  The cryptographically random,
report-pinned quarantine leaves are assumed not to be concurrently replaced
between that proof and the literal operation; any observable drift fails
closed.
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
import xml.etree.ElementTree as ET

import native_page_alpha_runner as alpha
import native_page_android_authority as android
import native_page_host_authority as host


AUTHORITY = "native-page-alpha-orientation-source-recovery-v1"
RUN_ID = "alpha-20260916-190148Z-b28865bb"
JOURNAL_ID = "d8efa86f-cc41-407f-8700-aad69bc5a719"
REPORT_SHA256 = "bdb9bd8c89e811c85ee568afa2872cf2fc36f68e9f3aefa4a7c5470fd5d9892c"
ACTIVE_JOURNAL_SHA256 = "1ae820986f546f92f5ad733e88784baa531bc2d1bcaea2e329f9472c51f6a29b"
ACTIVE_JOURNAL_HEAD = "06240a733436e9881956aef4d7470ba68cd897b068d5acb8cb92acb927fd9651"
REPORT_BYTES = 107_836
ACTIVE_JOURNAL_BYTES = 82_094
ACTIVE_RECORDS = 12
HOST_PID = 18_691
HOST_START_TICKS = 508_075
HOST_UID = 10_142
HOST_TASK_ID = 4_646
DOCUMENT_PID = 2_053
SESSION = "6239c239-41d3-4b32-bb1e-d4b98405fbaa"
GENERATION = 1
DISPLAY_ID = 1
POLL_SECONDS = 0.20
POLL_LIMIT = 75
PINNED_ADB = Path(
    r"C:\Users\mmkap\AppData\Local\Android\Sdk\platform-tools\adb.exe")
PINNED_ADB_SIZE = 8_273_560
PINNED_ADB_SHA256 = "b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f"

STAGING_PDF = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "staging-dff9fdb983754ac08ac3ee010dd97e35-pdf")
STAGING_MARK = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "staging-1f0c3da37db79954f56e745cd2704855-mark")
QUARANTINE_PDF = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "quarantine-33aa1e9e5e547693edbf29ada469fdd6-pdf")
QUARANTINE_MARK = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "quarantine-5477a2317e98cbab85db725ca68f27c2-mark")
QUARANTINES = {
    alpha.TARGET_MARK: QUARANTINE_MARK,
    alpha.TARGET_PDF: QUARANTINE_PDF,
}

PINNED_SOURCE_PDF = alpha.DeviceFile(
    alpha.SOURCE_PDF, "regular file", 4678, 10088, 10088, 183984, 54,
    alpha.SOURCE_PDF_SHA256)
PINNED_SOURCE_MARK = alpha.DeviceFile(
    alpha.SOURCE_MARK, "regular file", 5756, 10088, 10088, 185219, 54,
    alpha.SOURCE_MARK_SHA256)
PINNED_PARKING = alpha.DeviceFile(
    alpha.PARKING_PDF, "regular file", 4678, 10088, 10088, 182600, 54,
    alpha.SOURCE_PDF_SHA256)
PINNED_TARGET_PDF = alpha.DeviceFile(
    alpha.TARGET_PDF, "regular file", 4678, 10088, 10088, 185256, 54,
    alpha.SOURCE_PDF_SHA256)
PINNED_TARGET_MARK = alpha.DeviceFile(
    alpha.TARGET_MARK, "regular file", 5756, 10088, 10088, 185257, 54,
    alpha.SOURCE_MARK_SHA256)
PINNED_TARGETS = {
    alpha.TARGET_MARK: PINNED_TARGET_MARK,
    alpha.TARGET_PDF: PINNED_TARGET_PDF,
}
STATIC_FILES = (PINNED_SOURCE_PDF, PINNED_SOURCE_MARK, PINNED_PARKING)

REPORT_RELATIVE = Path("build/native-page-alpha-runs") / RUN_ID / "report.json"
ACTIVE_RELATIVE = (Path("build/native-page-alpha-runs") /
                   alpha.ACTIVE_MUTATION_JOURNAL_FILENAME)
RECOVERY_BASENAME = "orientation-source-recovery.jsonl"
EVIDENCE_BASENAME = "orientation-source-recovery-evidence.json"
RETIRED_BASENAME = "mutation-authority.retired-" + JOURNAL_ID + ".jsonl"
MAX_LOCAL_BYTES = 2 * 1024 * 1024
RESIDUAL_ASSUMPTION = (
    "no concurrent writer replaces a report-pinned random quarantine leaf "
    "between its second exact identity proof and literal rename/unlink")


class RecoveryError(RuntimeError):
    """The exact failed-run state is not authoritative enough to mutate."""


class MutationTransportUncertain(RecoveryError):
    """A one-shot mutation may have reached the device before transport loss.

    Only this closed exception channel permits settlement by authenticated
    postcondition.  A returned nonzero status, malformed receipt, unexpected
    output, or other semantic/protocol failure is authoritative failure and
    must never be converted into success merely because a side effect is
    observable.
    """


def _validate_mutation_result(
        result: Any, operation: str, *, empty_stdout: bool = False,
        ) -> alpha.CommandResult:
    """Validate the completed reply independently of device postconditions."""
    if not isinstance(result, alpha.CommandResult) or \
            result.operation != operation:
        _fail(operation + " returned an invalid receipt object")
    if result.returncode != 0:
        _fail(operation + " returned nonzero status " + str(result.returncode))
    if result.stderr != b"":
        _fail(operation + " returned unexpected stderr")
    if operation == "launch_parking_document":
        expected = (
            "Starting: Intent { act=" + alpha.DOCUMENT_LAUNCH_ACTION +
            " dat=" + alpha.PARKING_URI + " typ=" +
            alpha.DOCUMENT_LAUNCH_MIME + " cmp=" + android.SHORT_COMPONENT +
            " }\r\n").encode("ascii")
    elif (operation == "remove_exact_task" or empty_stdout or
          operation.startswith("recovery_quarantine_") or
          operation.startswith("recovery_remove_")):
        expected = b""
    else:
        _fail("mutation receipt operation is outside the closed grammar")
    if result.stdout != expected:
        _fail(operation + " returned an unexpected protocol receipt")
    return result


def _fail(message: str) -> NoReturn:
    raise RecoveryError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def _canonical_sha(value: Any) -> str:
    return _sha(_canonical(value))


def _physical_parking_launch_argv(adb: str) -> tuple[str, ...]:
    """Render the one recovery-only privileged launch on physical display 0.

    The alpha runner intentionally permits only positive virtual display IDs.
    Recovery must not broaden that grammar, so this separate builder has no
    display parameter and pins every root-shell token, including literal 0.
    """
    if (type(adb) is not str or not adb or
            alpha.AUTHORIZED_SERIAL != "SN078C10015092" or
            alpha.DOCUMENT_LAUNCH_USER != "0" or
            alpha.DOCUMENT_LAUNCH_ACTION != "android.intent.action.VIEW" or
            alpha.PARKING_URI != (
                "file:///storage/emulated/0/Download/"
                ".NativeViewportParking-Alpha-2eeadd7.pdf") or
            alpha.DOCUMENT_LAUNCH_MIME != "application/pdf" or
            alpha.DOCUMENT_COMPONENT !=
            ("com.supernote.document/"
             "com.supernote.document.document.DocumentActivity")):
        _fail("physical parking launch authority differs from its pins")
    command = (
        "am start --user 0 --display 0 -a android.intent.action.VIEW "
        "-d " + alpha.PARKING_URI + " -t application/pdf -n " +
        alpha.DOCUMENT_COMPONENT)
    return (adb, "-s", alpha.AUTHORIZED_SERIAL, "shell", "su", "-c",
            command)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _read_regular(path: Path, maximum: int, label: str) -> tuple[bytes, dict[str, Any]]:
    candidate = path.absolute()
    try:
        before = os.lstat(candidate)
    except OSError as error:
        raise RecoveryError(label + " is unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        _fail(label + " is not a non-symlink regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        key = (opened.st_dev, opened.st_ino, opened.st_size,
               getattr(opened, "st_mtime_ns", None))
        if key != (before.st_dev, before.st_ino, before.st_size,
                   getattr(before, "st_mtime_ns", None)):
            _fail(label + " changed during open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                _fail(label + " is oversized")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if key != (after.st_dev, after.st_ino, after.st_size,
                   getattr(after, "st_mtime_ns", None)):
            _fail(label + " changed while reading")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    final = os.lstat(candidate)
    if stat.S_ISLNK(final.st_mode) or key != (
            final.st_dev, final.st_ino, final.st_size,
            getattr(final, "st_mtime_ns", None)):
        _fail(label + " path was replaced while reading")
    return raw, {
        "path": str(candidate), "size": len(raw), "sha256": _sha(raw),
        "device": key[0], "inode": key[1], "mtimeNs": key[3],
    }


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # Python cannot open Windows directory handles for fsync.  File data
        # is flushed independently; directory-entry renames below use the
        # platform's MOVEFILE_WRITE_THROUGH primitive.
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Authority:
    root: Path
    run_dir: Path
    report_path: Path
    active_path: Path
    recovery_path: Path
    evidence_path: Path
    retired_path: Path
    report_identity: dict[str, Any]
    active_identity: dict[str, Any]
    active_present: bool


def _device_file(value: Any, expected: alpha.DeviceFile, label: str) -> None:
    if type(value) is not dict or set(value) != set(asdict(expected)):
        _fail(label + " topology differs")
    if value != asdict(expected):
        _fail(label + " identity differs")


def _verify_mutation_journal(raw: bytes) -> None:
    lines = raw.splitlines()
    if len(lines) != ACTIVE_RECORDS or raw[-1:] != b"\n":
        _fail("active mutation journal framing differs")
    previous: str | None = None
    for index, line in enumerate(lines):
        try:
            record = json.loads(line.decode("ascii"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RecoveryError("active mutation journal is not canonical JSONL") from error
        if (type(record) is not dict or record.get("sequence") != index or
                record.get("journalId") != JOURNAL_ID or
                record.get("authority") != "native-page-alpha-mutation-journal-v1" or
                record.get("previousRecordSha256") != previous):
            _fail("active mutation journal chain metadata differs")
        digest = record.get("recordSha256")
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            _fail("active mutation journal record digest is malformed")
        unsigned = dict(record)
        del unsigned["recordSha256"]
        if _canonical_sha(unsigned) != digest:
            _fail("active mutation journal record digest differs")
        previous = digest
    if previous != ACTIVE_JOURNAL_HEAD:
        _fail("active mutation journal head differs")


def load_authority(root: Path, report_path: Path, active_path: Path) -> Authority:
    fixed_root = root.absolute()
    expected_report = (fixed_root / REPORT_RELATIVE).absolute()
    expected_active = (fixed_root / ACTIVE_RELATIVE).absolute()
    if os.path.normcase(str(report_path.absolute())) != os.path.normcase(str(expected_report)):
        _fail("report path differs from the fixed failed run")
    if os.path.normcase(str(active_path.absolute())) != os.path.normcase(str(expected_active)):
        _fail("active journal path differs from the fixed failed run")
    report_raw, report_identity = _read_regular(expected_report, 128 * 1024, "report")
    retired = expected_report.parent / RETIRED_BASENAME
    active_present = os.path.lexists(expected_active)
    retired_present = os.path.lexists(retired)
    if active_present == retired_present:
        _fail("exactly one active or report-bound retired journal must exist")
    journal_location = expected_active if active_present else retired
    active_raw, observed_identity = _read_regular(
        journal_location, 256 * 1024,
        "active journal" if active_present else "retired active journal")
    # The durable recovery header is invariant across retirement.  Preserve
    # the original authority pathname while retaining the observed inode.
    active_identity = {**observed_identity, "path": str(expected_active)}
    if (len(report_raw) != REPORT_BYTES or report_identity["sha256"] != REPORT_SHA256 or
            len(active_raw) != ACTIVE_JOURNAL_BYTES or
            active_identity["sha256"] != ACTIVE_JOURNAL_SHA256):
        _fail("report or active journal bytes differ from the fixed failed run")
    _verify_mutation_journal(active_raw)
    try:
        report = json.loads(report_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError("report is not strict UTF-8 JSON") from error
    if (report.get("authority") != alpha.AUTHORITY or
            report.get("authorizedSerial") != alpha.AUTHORIZED_SERIAL or
            report.get("checkpoint") != alpha.CHECKPOINT or
            report.get("result") != "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN" or
            report.get("primaryError") !=
            "AndroidAuthorityError: ActivityManager per-display orientation sources differ" or
            report.get("rotationAuthority") != alpha.ROTATION_ADB_SYSTEM_SETTINGS or
            report.get("documentLaunchAttempted") is not True or
            report.get("launchOwned") is not False or report.get("foreign") is not None):
        _fail("failed report semantic state differs")
    if report.get("host") != {
            "displayId": DISPLAY_ID, "generation": GENERATION,
            "hostPid": HOST_PID, "session": SESSION}:
        _fail("failed report host identity differs")
    fixture = report.get("fixture")
    if type(fixture) is not dict:
        _fail("failed report lacks fixture authority")
    journal = fixture.get("mutationJournal")
    if (type(journal) is not dict or journal.get("journalId") != JOURNAL_ID or
            journal.get("fileSha256") != ACTIVE_JOURNAL_SHA256 or
            journal.get("headSha256") != ACTIVE_JOURNAL_HEAD or
            journal.get("recordCount") != ACTIVE_RECORDS or
            journal.get("size") != ACTIVE_JOURNAL_BYTES or
            journal.get("retired") is not False or
            os.path.normcase(str(Path(journal.get("path", "")).absolute())) !=
            os.path.normcase(str(expected_active))):
        _fail("report mutation-journal authority differs")
    obligations = fixture.get("cleanupObligations")
    if type(obligations) is not dict or set(obligations) != set(PINNED_TARGETS):
        _fail("report cleanup topology differs")
    expected_staging = {alpha.TARGET_PDF: STAGING_PDF, alpha.TARGET_MARK: STAGING_MARK}
    for target, expected in PINNED_TARGETS.items():
        obligation = obligations[target]
        if type(obligation) is not dict:
            _fail("report cleanup obligation is malformed")
        _device_file(obligation.get("retained"), expected, "retained target")
        _device_file(obligation.get("publish_move_target_observed"), expected,
                     "published target")
        staged = asdict(expected)
        staged["path"] = expected_staging[target]
        _device_file(obligation.get("staging_post_copy_observed"),
                     alpha.DeviceFile(**{
                         "path": staged["path"], "kind": staged["kind"],
                         "size": staged["size"], "uid": staged["uid"],
                         "gid": staged["gid"], "inode": staged["inode"],
                         "device": staged["device"], "sha256": staged["sha256"]}),
                     "staged target")
        if (obligation.get("staging_path") != expected_staging[target] or
                obligation.get("quarantine_path") != QUARANTINES[target] or
                obligation.get("copy_attempted") is not True or
                obligation.get("copy_reply_proved") is not True or
                obligation.get("publish_move_attempted") is not True or
                obligation.get("publish_move_reply_proved") is not True or
                obligation.get("publish_move_postcondition") !=
                "stage-absent/target-exact" or
                obligation.get("quarantine_move_attempted") is not False or
                obligation.get("quarantine_remove_attempted") is not False):
            _fail("report cleanup obligation state differs")
    run_dir = expected_report.parent
    return Authority(
        fixed_root, run_dir, expected_report, expected_active,
        run_dir / RECOVERY_BASENAME, run_dir / EVIDENCE_BASENAME,
        retired, report_identity, active_identity, active_present)


def _assert_publication_paths_clear(authority: Authority, *,
                                    before_journal: bool) -> None:
    if not authority.active_present:
        _fail("active journal is already retired")
    if os.path.lexists(authority.evidence_path):
        _fail("recovery evidence path is already occupied")
    if os.path.lexists(authority.retired_path):
        _fail("retired active-journal path is already occupied")
    if before_journal and os.path.lexists(authority.recovery_path):
        _fail("recovery journal path is already occupied")


class Journal:
    """Durable, canonical, append-only one-shot operation ledger."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.path = path
        self.records: list[dict[str, Any]] = []
        self._encoded = b""
        self._descriptor = -1
        # This run is intentionally one-shot.  O_EXCL is the cross-process
        # execution barrier: a second process, or any restart after a crash,
        # must fail closed rather than reconstructing intent from a journal
        # that another process may still own.  The retained journal is then
        # evidence for a separately reviewed follow-up recovery.
        if os.path.lexists(path):
            _fail("recovery journal already exists; refusing concurrent or resumed execute")
        flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        self._descriptor = os.open(path, flags, 0o600)
        created = os.fstat(self._descriptor)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            os.close(self._descriptor)
            self._descriptor = -1
            _fail("recovery journal descriptor is not a regular file")
        self._device = created.st_dev
        self._inode = created.st_ino
        self.append("header", header)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._descriptor = -1

    def _assert_open_authority(self) -> None:
        """Bind the retained descriptor and pathname to exact ledger bytes."""
        if self._descriptor < 0:
            _fail("recovery journal descriptor is closed")
        descriptor_stat = os.fstat(self._descriptor)
        if (not stat.S_ISREG(descriptor_stat.st_mode) or
                descriptor_stat.st_dev != self._device or
                descriptor_stat.st_ino != self._inode or
                descriptor_stat.st_nlink != 1 or
                descriptor_stat.st_size != len(self._encoded)):
            _fail("recovery journal descriptor identity changed")
        try:
            path_stat = os.lstat(self.path)
        except OSError as error:
            raise RecoveryError("recovery journal path disappeared") from error
        if (stat.S_ISLNK(path_stat.st_mode) or
                not stat.S_ISREG(path_stat.st_mode) or
                path_stat.st_dev != self._device or
                path_stat.st_ino != self._inode or
                path_stat.st_nlink != 1 or
                path_stat.st_size != len(self._encoded)):
            _fail("recovery journal path was replaced")
        read_flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        reader = os.open(self.path, read_flags)
        try:
            reader_stat = os.fstat(reader)
            if (not stat.S_ISREG(reader_stat.st_mode) or
                    reader_stat.st_dev != self._device or
                    reader_stat.st_ino != self._inode or
                    reader_stat.st_nlink != 1):
                _fail("recovery journal read authority changed")
            chunks: list[bytes] = []
            remaining = len(self._encoded) + 1
            while remaining > 0:
                chunk = os.read(reader, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if b"".join(chunks) != self._encoded:
                _fail("recovery journal bytes or hash chain changed")
        finally:
            os.close(reader)

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("recovery journal record is malformed")
        unsigned = {
            "authority": AUTHORITY, "kind": kind, "payload": payload,
            "previousSha256": (None if not self.records else
                               self.records[-1]["recordSha256"]),
            "sequence": len(self.records),
        }
        record = {**unsigned, "recordSha256": _canonical_sha(unsigned)}
        encoded = _canonical(record) + b"\n"
        self._assert_open_authority()
        written = os.write(self._descriptor, encoded)
        if written != len(encoded):
            _fail("short recovery journal write")
        os.fsync(self._descriptor)
        self._encoded += encoded
        self._assert_open_authority()
        _fsync_directory(self.path.parent)
        self.records.append(record)
        return record

    def assert_authority(self) -> None:
        self._assert_open_authority()

    def entries(self, kind: str) -> list[dict[str, Any]]:
        return [record for record in self.records if record["kind"] == kind]

    def one(self, kind: str) -> dict[str, Any] | None:
        entries = self.entries(kind)
        if len(entries) > 1:
            _fail("recovery journal repeats one-shot record " + kind)
        return None if not entries else entries[0]


class Device(Protocol):
    history: list[dict[str, Any]]
    def adb_authority(self) -> dict[str, Any]: ...
    def environment(self) -> dict[str, Any]: ...
    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def host_logs(self, pid: int) -> str: ...
    def absence_raw(self) -> tuple[bytes, bytes, bytes]: ...
    def ui_dump(self) -> bytes: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def launch_parking(self) -> Any: ...
    def parking_identity(self) -> dict[str, Any]: ...
    def remove_task(self, task_id: int) -> Any: ...
    def move_quarantine(self, source: str, target: str) -> Any: ...
    def remove_quarantine(self, path: str) -> Any: ...


class RecoveryNomad(alpha.AdbNomad):
    """Closed transport for only this report's recovery operations."""

    def adb_authority(self) -> dict[str, Any]:
        path = Path(self.adb).absolute()
        raw, identity = _read_regular(path, PINNED_ADB_SIZE, "adb executable")
        if (path != PINNED_ADB or len(raw) != PINNED_ADB_SIZE or
                identity["sha256"] != PINNED_ADB_SHA256):
            _fail("adb executable identity differs")
        return identity

    def environment(self) -> dict[str, Any]:
        if (self.get_state() != "device" or self.get_serial() != alpha.AUTHORIZED_SERIAL or
                self.getprop("ro.product.model") != alpha.MODEL or
                self.getprop("ro.build.version.sdk") != alpha.SDK or
                self.getprop("ro.build.fingerprint") != alpha.FINGERPRINT or
                self.current_user() != "0"):
            _fail("connected device differs from the pinned Nomad")
        host_dump = self.package_dump(alpha.HOST_PACKAGE)
        alpha._package_version(host_dump, alpha.HOST_VERSION_CODE,
                               alpha.HOST_VERSION_NAME, "visual host")
        uid = re.findall(r"^\s*userId=([1-9][0-9]*)\s*$", host_dump, re.MULTILINE)
        if uid != [str(HOST_UID)]:
            _fail("visual host UID differs")
        host_apk = self.package_path(alpha.HOST_PACKAGE)
        if self.sha256_file(host_apk) != alpha.ALPHA_SIGNED_APK_SHA256:
            _fail("visual host APK differs")
        document_dump = self.package_dump(alpha.DOCUMENT_PACKAGE)
        alpha._package_version(document_dump, alpha.DOCUMENT_VERSION_CODE,
                               alpha.DOCUMENT_VERSION_NAME, "stock Document")
        if self.package_path(alpha.DOCUMENT_PACKAGE) != alpha.DOCUMENT_APK:
            _fail("stock Document APK path differs")
        document_apk = self.stat_file(alpha.DOCUMENT_APK)
        if (document_apk is None or document_apk.size != alpha.DOCUMENT_APK_SIZE or
                document_apk.sha256 != alpha.DOCUMENT_APK_SHA256):
            _fail("stock Document APK differs")
        return {"hostUid": HOST_UID, "hostApk": host_apk,
                "documentApk": alpha.DOCUMENT_APK}

    def rotation_settings(self) -> tuple[str, str]:
        """Read only the two report-pinned system settings.

        The alpha transport correctly rejects the broad ``settings`` command
        family.  Recovery receives no caller-controlled key, namespace, or
        value and records the two literal read-only invocations itself.
        """
        values: list[str] = []
        for key in ("accelerometer_rotation", "user_rotation"):
            argv = (self.adb, "-s", alpha.AUTHORIZED_SERIAL, "exec-out",
                    "settings", "get", "system", key)
            started = time.monotonic_ns()
            try:
                completed = self._executor(
                    argv, capture_output=True,
                    timeout=alpha.STEP_TIMEOUT_SECONDS, check=False)
            except subprocess.TimeoutExpired as error:
                self.history.append({
                    "operation": "read_rotation_" + key, "argv": list(argv),
                    "startedNs": str(started),
                    "finishedNs": str(time.monotonic_ns()),
                    "returncode": None, "timeout": True})
                raise RecoveryError("persisted rotation read timed out") from error
            stdout = bytes(completed.stdout or b"")
            stderr = bytes(completed.stderr or b"")
            if (len(stdout) > alpha.MAX_TEXT_BYTES or
                    len(stderr) > alpha.MAX_TEXT_BYTES):
                _fail("persisted rotation read returned oversized output")
            result = alpha.CommandResult(
                "read_rotation_" + key, argv, int(completed.returncode),
                stdout, stderr)
            self.history.append({
                "operation": result.operation, "argv": list(argv),
                "startedNs": str(started),
                "finishedNs": str(time.monotonic_ns()),
                "returncode": result.returncode,
                "stdoutSha256": _sha(stdout), "stderrSha256": _sha(stderr)})
            self._require_zero(result)
            if (stdout not in {b"0\n", b"1\n", b"2\n", b"3\n"} or
                    stderr != b""):
                _fail("persisted rotation read has a noncanonical reply")
            values.append(stdout[:1].decode("ascii"))
        return values[0], values[1]

    def absence_raw(self) -> tuple[bytes, bytes, bytes]:
        return self.activities(), self.windows(), self.displays()

    def _authoritative_mutation_reply(
            self, operation: str,
            invoke: Callable[[], alpha.CommandResult]) -> alpha.CommandResult:
        """Distinguish a lost transport from an authoritative bad reply."""
        try:
            result = invoke()
        except alpha.AlphaError as error:
            if str(error) == operation + " timed out; side effect is uncertain":
                raise MutationTransportUncertain(str(error)) from error
            raise
        return _validate_mutation_result(result, operation)

    def launch_parking(self) -> alpha.CommandResult:
        operation = "launch_parking_document"

        def invoke() -> alpha.CommandResult:
            argv = _physical_parking_launch_argv(self.adb)
            started = time.monotonic_ns()
            try:
                completed = self._executor(
                    argv, capture_output=True, timeout=15.0, check=False)
            except subprocess.TimeoutExpired as error:
                self.history.append({
                    "operation": operation, "argv": list(argv),
                    "startedNs": str(started),
                    "finishedNs": str(time.monotonic_ns()),
                    "returncode": None, "timeout": True})
                raise alpha.AlphaError(
                    operation +
                    " timed out; side effect is uncertain") from error
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
                "stdoutSha256": _sha(stdout),
                "stderrSha256": _sha(stderr),
            })
            return result

        return self._authoritative_mutation_reply(
            operation, invoke)

    def parking_identity(self) -> dict[str, Any]:
        pids = self.pidof(alpha.DOCUMENT_PACKAGE)
        if len(pids) != 1:
            _fail("parking launch lacks one stock Document process")
        process_before = self.process_identity(pids[0], alpha.DOCUMENT_PACKAGE)
        raw = self.activities()
        windows = self.windows()
        authority = android.parse_document_task_authority(
            raw, expected_pid=process_before.pid, require_live=True)
        if (authority.display_id != 0 or authority.stack_id != authority.task_id or
                authority.base_apk_path != alpha.DOCUMENT_APK or
                authority.density_dpi != 300 or authority.rotation not in range(4) or
                (authority.width, authority.height) not in {(1404, 1872), (1872, 1404)}):
            _fail("parking task differs from the stock physical-display authority")
        task_block = alpha.AlphaSession._assert_exact_stack_scope(raw, authority)
        expected_uri = alpha.PARKING_URI
        if (task_block.count("intent={") != 1 or
                "act=" + alpha.DOCUMENT_LAUNCH_ACTION not in task_block or
                "dat=" + expected_uri not in task_block or
                "typ=" + alpha.DOCUMENT_LAUNCH_MIME not in task_block or
                not any("cmp=" + component in task_block
                        for component in alpha._document_components())):
            _fail("parking task lacks the exact ACTION_VIEW intent")
        scope = _assert_sole_document_scope(
            raw, windows, authority, process_before)
        ui = alpha.parse_parking_ui_witness(self.ui_dump())
        targets = _validated_fd_targets(self.process_fd_links(process_before.pid))
        if targets != frozenset((alpha.PARKING_PDF,)):
            _fail("parking process descriptors are not parking-only")
        process_after = self.process_identity(pids[0], alpha.DOCUMENT_PACKAGE)
        if process_after != process_before:
            _fail("stock Document process changed during parking capture")
        return {
            "process": asdict(process_before), "taskId": authority.task_id,
            "displayId": authority.display_id,
            "authoritySha256": android.stable_authority_sha256(authority),
            "activityToken": authority.activity_token,
            "documentAuthority": asdict(authority),
            "documentScope": scope["stable"],
            "uiWitness": ui, "fdTargets": sorted(targets),
            "activitiesSha256": _sha(raw),
            "windowsSha256": scope["evidence"]["windowsSha256"],
        }

    def remove_task(self, task_id: int) -> alpha.CommandResult:
        return self._authoritative_mutation_reply(
            "remove_exact_task", lambda: self.remove_exact_task(task_id))

    def move_quarantine(self, source: str, target: str) -> alpha.CommandResult:
        if QUARANTINES.get(source) != target:
            _fail("quarantine move escaped the report")
        operation = "recovery_quarantine_" + Path(source).name
        try:
            result = self._invoke(
                operation,
                ("exec-out", "toybox", "mv", "-n", "-T", "-v", source,
                 target))
        except alpha.AlphaError as error:
            if str(error) == operation + " timed out; side effect is uncertain":
                raise MutationTransportUncertain(str(error)) from error
            raise
        self._require_zero(result)
        # This pinned Nomad's toybox accepts ``-v`` but emits no rename
        # receipt.  The durable intent and exact source/destination
        # postconditions settle ownership; any bytes on either stream are an
        # unexpected transport result and fail closed.
        if result.stdout != b"" or result.stderr != b"":
            _fail("quarantine move returned unexpected output")
        return result

    def remove_quarantine(self, path: str) -> alpha.CommandResult:
        if path not in set(QUARANTINES.values()):
            _fail("quarantine removal escaped the report")
        operation = "recovery_remove_" + Path(path).name
        try:
            result = self._invoke(
                operation, ("shell", "toybox", "rm", "-f", path))
        except alpha.AlphaError as error:
            if str(error) == operation + " timed out; side effect is uncertain":
                raise MutationTransportUncertain(str(error)) from error
            raise
        self._require_zero(result)
        if result.stdout or result.stderr:
            _fail("quarantine removal output differs")
        return result


def _validated_fd_targets(raw: str) -> frozenset[str]:
    if type(raw) is not str or not raw or len(raw.encode("utf-8")) > alpha.MAX_TEXT_BYTES:
        _fail("descriptor inventory is empty or oversized")
    lines = raw.splitlines()
    if lines and re.fullmatch(r"total [0-9]+", lines[0]):
        lines = lines[1:]
    pattern = re.compile(
        r"^l[rwxstST-]{9} [1-9][0-9]* \S+ \S+ [0-9]+ \S+ \S+ "
        r"([0-9]+) -> (.+)$")
    seen: set[str] = set()
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None or match.group(1) in seen:
            _fail("descriptor inventory framing differs")
        seen.add(match.group(1))
    if not seen:
        _fail("descriptor inventory has no records")
    return alpha._document_file_targets(raw)


def _assert_sole_document_scope(
        activity_raw: bytes, window_raw: bytes,
        authority: android.DocumentTaskAuthority,
        process: host.ProcessIdentity) -> dict[str, Any]:
    """Bind parking removal to the sole package task and package window."""
    try:
        activity_text, _ = android._wire(  # type: ignore[attr-defined]
            activity_raw)
        canonical = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            activity_text)
    except android.AndroidAuthorityError as error:
        raise RecoveryError("parking package scope is malformed") from error
    package = alpha.DOCUMENT_PACKAGE
    components = (android.SHORT_COMPONENT, android.FULL_COMPONENT)
    activity_lines = activity_text.splitlines()
    task_lines = [line for line in activity_lines
                  if "Task{" in line and package in line]
    if not task_lines:
        _fail("parking package lacks task scope")
    for line in task_lines:
        matches = re.findall(
            r"Task\{([0-9a-f]+) #([1-9][0-9]*)[^\n}]*"
            r"A=([1-9][0-9]*):" + re.escape(package) +
            r"(?=\s|\})[^\n}]*\}", line)
        if (not matches or any(
                token != authority.task_token or
                task_id != str(authority.task_id) or
                uid != str(android.SYSTEM_UID)
                for token, task_id, uid in matches)):
            _fail("additional or malformed stock Document task scope exists")
    package_activity_lines = [
        line for line in activity_lines
        if "ActivityRecord{" in line and package + "/" in line]
    if not package_activity_lines:
        _fail("parking package lacks activity scope")
    generic_activity = re.compile(
        r"ActivityRecord\{([0-9a-f]+) u0 (" +
        re.escape(package) + r"/[^\s{}]+) t([1-9][0-9]*)\}")
    for line in package_activity_lines:
        matches = generic_activity.findall(line)
        if (not matches or any(
                token != authority.activity_token or
                component not in components or task_id != str(authority.task_id)
                for token, component, task_id in matches)):
            _fail("additional or malformed stock Document activity scope exists")
    package_process_lines = [
        line for line in activity_lines
        if "ProcessRecord{" in line and package in line]
    if not package_process_lines:
        _fail("parking package lacks process scope")
    process_tokens: set[str] = set()
    generic_process = re.compile(
        r"ProcessRecord\{([0-9a-f]+) ([1-9][0-9]*):" +
        re.escape(package) + r"/(1000|u0a1000)\}")
    for line in package_process_lines:
        matches = generic_process.findall(line)
        if (not matches or any(pid != str(process.pid)
                               for _, pid, _ in matches)):
            _fail("additional or malformed stock Document process scope exists")
        process_tokens.update(token for token, _, _ in matches)
    if len(process_tokens) != 1:
        _fail("stock Document process token is absent or ambiguous")

    # Recheck the selected root task has one child independently of package-
    # wide uniqueness.  An unrelated task under the same root would otherwise
    # also be removed by this firmware's numeric stack-removal primitive.
    stacks = [
        (display_id, stack_id, block)
        for display_id, stack_id, block
        in android._display_stack_blocks(canonical)  # type: ignore[attr-defined]
        if stack_id == authority.stack_id]
    tasks = ([] if len(stacks) != 1 else
             android._task_blocks(stacks[0][2]))  # type: ignore[attr-defined]
    if (len(stacks) != 1 or stacks[0][0] != authority.display_id or
            len(tasks) != 1 or authority.component not in tasks[0]):
        _fail("parking root task does not have one exact child task")

    window_text = alpha._decode_text(window_raw, "parking window inventory")
    window_lines = window_text.splitlines()
    headers = [
        index for index, line in enumerate(window_lines)
        if re.match(r"^\s*Window #[0-9]+ Window\{", line) is not None and
        package in line]
    if len(headers) != 1:
        _fail("parking package does not own exactly one window")
    start = headers[0]
    end = next((index for index in range(start + 1, len(window_lines))
                if re.match(r"^\s*Window #[0-9]+ Window\{",
                            window_lines[index]) is not None), len(window_lines))
    block = window_lines[start:end]
    header = block[0].strip()
    component_pattern = "(?:" + "|".join(
        re.escape(component) for component in components) + ")"
    header_match = re.fullmatch(
        r"Window #[0-9]+ Window\{([0-9a-f]+) u0 (" +
        component_pattern + r")\}:", header)
    if header_match is None:
        _fail("parking package window component differs")
    window_token, window_component = header_match.groups()
    session_line = _one_line(
        block,
        lambda line: ("mDisplayId=" + str(authority.display_id)) in line and
        ("rootTaskId=" + str(authority.task_id)) in line and
        "mSession=Session{" in line,
        "parking package window session")
    session_match = re.search(
        r"Session\{([0-9a-f]+) " + str(process.pid) +
        r":(?:1000|u0a1000)\}", session_line)
    if session_match is None:
        _fail("parking package window session differs")
    owner_line = _one_line(
        block,
        lambda line: "mOwnerUid=1000" in line and
        ("package=" + package) in line,
        "parking package window owner")
    expected_records = {
        "ActivityRecord{" + authority.activity_token + " u0 " + component +
        " t" + str(authority.task_id) + "}" for component in components}
    record_lines = [line.strip() for line in block
                    if "mActivityRecord=ActivityRecord{" in line]
    if (len(record_lines) != 1 or
            record_lines[0].removeprefix("mActivityRecord=") not in
            expected_records):
        _fail("parking package window activity binding differs")
    # A second package window hidden elsewhere in the inventory was already
    # rejected by the package-wide header count above.
    if not all((owner_line, canonical, tasks[0])):
        _fail("parking package semantic scope is incomplete")
    return {
        "stable": {
            "taskId": authority.task_id, "displayId": authority.display_id,
            "taskToken": authority.task_token,
            "activityToken": authority.activity_token,
            "processToken": next(iter(process_tokens)),
            "windowToken": window_token,
            "windowSessionToken": session_match.group(1),
            "windowComponent": window_component,
            "pid": process.pid, "uid": process.uid,
            "oneChildRootTask": True, "solePackageWindow": True,
        },
        "evidence": {
            "activitiesSha256": _sha(activity_raw),
            "windowsSha256": _sha(window_raw),
        },
    }


def _exact_token(line: str, key: str) -> list[str]:
    return re.findall(
        r"(?:^|\s)" + re.escape(key) + r"=([^\s]+)(?=\s|$)", line)


def _event_lines(lines: list[str], event: str) -> list[tuple[int, str]]:
    pattern = re.compile(r"(?:^|\s)" + re.escape(event) + r"(?=\s|$)")
    return [(index, line) for index, line in enumerate(lines)
            if pattern.search(line) is not None]


def _validate_failed_host_log(logs: str) -> list[str]:
    """Validate the observed generation-0/1 host lifecycle event by event.

    Display-free authority-transition events are intentionally valid.  Only
    lifecycle events that semantically own display 1 are required to carry
    ``display=1``; this avoids the original cleanup parser's false global
    equality assumption while retaining exact protocol ordering.
    """
    if (type(logs) is not str or not logs or
            len(logs.encode("utf-8")) > alpha.MAX_TEXT_BYTES or "\x00" in logs):
        _fail("retained host log is absent, oversized, or binary")
    selected: list[str] = []
    for raw_line in logs.splitlines():
        sessions = _exact_token(raw_line, "session")
        if sessions and sessions != [SESSION]:
            _fail("retained host log contains another session identity")
        if not sessions:
            continue
        generations = _exact_token(raw_line, "generation")
        if len(generations) != 1 or \
                generations[0] not in {"0", str(GENERATION)}:
            _fail("identity-bound host log has conflicting identity tokens")
        selected.append(raw_line.strip())
    if not selected:
        _fail("retained host log has no identity-bound records")

    required = {
        "SESSION": ("0", None),
        "DISPLAY_ALLOCATED": (str(GENERATION), str(DISPLAY_ID)),
        "DISPLAY_READY": (str(GENERATION), str(DISPLAY_ID)),
        "DISPLAY_RESUMED": (str(GENERATION), None),
        "TIMEOUT": (str(GENERATION), None),
        "FAILED": (str(GENERATION), str(DISPLAY_ID)),
    }
    positions: dict[str, int] = {}
    for event, (generation, display) in required.items():
        matches = _event_lines(selected, event)
        if len(matches) != 1:
            _fail("retained host log does not contain one exact " + event)
        position, line = matches[0]
        if _exact_token(line, "generation") != [generation]:
            _fail(event + " generation differs")
        if display is not None and _exact_token(line, "display") != [display]:
            _fail(event + " display differs")
        positions[event] = position
    if not (positions["SESSION"] < positions["DISPLAY_ALLOCATED"] <
            positions["DISPLAY_READY"] <= positions["DISPLAY_RESUMED"] <
            positions["TIMEOUT"] < positions["FAILED"]):
        _fail("retained host lifecycle event order differs")
    timeout = selected[positions["TIMEOUT"]]
    failed = selected[positions["FAILED"]]
    if (_exact_token(timeout, "phase") != ["foreign_attach"] or
            _exact_token(timeout, "displayRetained") != ["true"] or
            _exact_token(failed, "reason") !=
            ["host_surface_lost_unexpectedly"] or
            _exact_token(failed, "emergencyDestroyContent") != ["true"]):
        _fail("retained timeout/failure semantics differ")
    forbidden = (
        "READY", "ATTACHED", "FOREIGN_DESTROYED", "EMPTY_ATTACH_ABORT",
        "EMPTY_ATTACH_ABORT_REPLAY", "DISPLAY_RELEASED", "RELEASE_FAILED",
        "PROCESS_CLEANUP_ESCALATED", "COMMAND_IGNORED", "COMMAND_REJECTED",
    )
    if any(_event_lines(selected, event) for event in forbidden):
        _fail("retained host log contains foreign-ready or cleanup residue")
    return selected


def _assert_no_virtual_display(displays: bytes) -> None:
    display_text = alpha._decode_text(displays, "display inventory")
    if (re.search(r"(?m)^\s*Display\s+" + str(DISPLAY_ID) + r"\b",
                  display_text) or
            "NativePageVisualOnly-" in display_text):
        # Display IDs are allocated dynamically and a recreated host session
        # would use a fresh UUID/generation.  The signed host owns the closed
        # NativePageVisualOnly-* namespace, so *any* such display is forbidden
        # after the failed generation released its surface.  Unrelated
        # secondary displays remain permissible.
        _fail("visual-host virtual display is still present")


def _physical_display0_override(displays: bytes) -> dict[str, int]:
    """Bind the current physical display-0 geometry to its WM override.

    The failed host can remain visible in either portrait or landscape while
    the persisted auto-rotation settings remain unchanged.  DisplayManager's
    logical display-0 override is the authority for the frame presented to
    WindowManager; the device's natural dimensions alone are not.  Accept
    only the two exact Nomad axis orderings, with a matching Android rotation,
    and retain that tuple in the task-removal authority.
    """
    text = alpha._decode_text(displays, "display inventory")
    logical_pattern = re.compile(
        r"(?ms)^  Display (0|[1-9][0-9]*):\s*\n"
        r"(.*?)(?=^  Display (?:0|[1-9][0-9]*):|\Z)")
    blocks = list(logical_pattern.finditer(text))
    selected = [item for item in blocks if item.group(1) == "0"]
    if len(selected) != 1:
        _fail("physical display-0 logical record is absent or ambiguous")
    block = selected[0].group(2)
    display_ids = [line.strip() for line in block.splitlines()
                   if line.lstrip().startswith("mDisplayId=")]
    if display_ids != ["mDisplayId=0"]:
        _fail("physical display-0 logical ID differs")
    override_lines = [line.strip() for line in block.splitlines()
                      if line.lstrip().startswith("mOverrideDisplayInfo=")]
    if len(override_lines) != 1:
        _fail("physical display-0 override is absent or ambiguous")
    override = override_lines[0]
    if not override.startswith('mOverrideDisplayInfo=DisplayInfo{"'):
        _fail("physical display-0 override is malformed")

    def one(pattern: str, label: str) -> str:
        values = re.findall(pattern, override)
        if len(values) != 1:
            _fail("physical display-0 override " + label + " is ambiguous")
        return values[0]

    display_id = one(r"(?<![A-Za-z0-9_])displayId (0|[1-9][0-9]*)",
                     "display ID")
    dimensions = re.findall(
        r"(?<![A-Za-z0-9_])real ([0-9]{1,5}) x ([0-9]{1,5})",
        override)
    if len(dimensions) != 1:
        _fail("physical display-0 override geometry is ambiguous")
    rotation = one(r"(?<![A-Za-z0-9_])rotation ([0-3])", "rotation")
    states = re.findall(r"(?<![A-Za-z0-9_])state ([A-Z]+)", override)
    types = re.findall(r"(?<![A-Za-z0-9_])type ([A-Z]+)", override)
    if (display_id != "0" or states != ["ON"] or types != ["INTERNAL"]):
        _fail("physical display-0 override identity differs")
    width, height = (int(dimensions[0][0]), int(dimensions[0][1]))
    rotation_value = int(rotation)
    expected = ((1404, 1872) if rotation_value in (0, 2)
                else (1872, 1404))
    if (width, height) != expected:
        _fail("physical display-0 override geometry/rotation differs")
    return {"width": width, "height": height, "rotation": rotation_value}


def _assert_no_document_or_virtual_display(
    raw: tuple[bytes, bytes, bytes]) -> None:
    activities, windows, displays = raw
    activity_text = alpha._decode_text(activities, "activity inventory")
    window_text = alpha._decode_text(windows, "window inventory")
    # This helper is bound to one known quiescent run.  A broad package-wide
    # rejection is intentionally conservative: even a stale/supervisor echo
    # of Document makes the state non-authoritative rather than being guessed
    # away during recovery.
    if (alpha.DOCUMENT_PACKAGE in activity_text or
            alpha.DOCUMENT_PACKAGE in window_text):
        _fail("stock Document task/window is still present")
    _assert_no_virtual_display(displays)


def _is_exact_stale_host_supervisor_ghost(
        raw: bytes, stable: dict[str, Any]) -> bool:
    """Recognize only this run's empty post-removal host history."""
    try:
        full_text, _ = android._wire(raw)  # type: ignore[attr-defined]
        canonical = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            full_text)
    except android.AndroidAuthorityError:
        return False
    boundary = "ActivityStackSupervisor state:\n"
    if full_text.count(boundary) != 1:
        return False
    canonical_prefix, suffix = full_text.split(boundary, 1)
    package = alpha.HOST_PACKAGE
    task = str(HOST_TASK_ID)
    task_token = stable.get("taskToken")
    activity_token = stable.get("activityToken")
    component = stable.get("component")
    if (type(task_token) is not str or type(activity_token) is not str or
            component != package + "/.NativePageHostActivity" or
            stable.get("taskId") != HOST_TASK_ID or
            stable.get("process") != asdict(host.ProcessIdentity(
                HOST_PID, HOST_START_TICKS, HOST_UID, package))):
        return False
    package_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])" + re.escape(package) +
        r"(?=/|[\s}:,\]]|$)")
    retained_patterns = (
        package_pattern, re.compile(re.escape(task_token)),
        re.compile(re.escape(activity_token)),
    )
    if any(pattern.search(canonical_prefix) is not None
           for pattern in retained_patterns):
        return False
    lines = suffix.splitlines()
    expected = [
        ("  topDisplayFocusedStack=Task{" + task_token + " #" + task +
         " visible=false A=" + str(HOST_UID) + ":" + package + " sz=0}"),
        ("  mLastOrientationSource=ActivityRecord{" + activity_token +
         " u0 " + component + " t" + task + "}"),
        ("  deepestLastOrientationSource=ActivityRecord{" + activity_token +
         " u0 " + component + " t" + task + "}"),
        ("  mLastFocusedStack=Task{" + task_token + " #" + task +
         " visible=false A=" + str(HOST_UID) + ":" + package + " sz=0}"),
    ]
    if lines[:4] != expected:
        return False
    target_indexes = [index for index, line in enumerate(lines)
                      if any(pattern.search(line) is not None
                             for pattern in retained_patterns)]
    if target_indexes != [0, 1, 2, 3]:
        return False

    decimal = r"0|[1-9][0-9]{0,9}"

    def bounded(value: str, maximum: int) -> int | None:
        if re.fullmatch(decimal, value) is None:
            return None
        number = int(value, 10)
        return number if number <= maximum else None

    header_pattern = re.compile(
        r"^Display #(" + decimal +
        r") \(activities from top to bottom\):$")
    header_ids: list[int] = []
    for line in canonical.splitlines():
        match = header_pattern.fullmatch(line)
        if match is not None:
            display_id = bounded(match.group(1), 1024)
            if display_id is None or display_id in header_ids:
                return False
            header_ids.append(display_id)
    if not header_ids:
        return False
    summary = re.compile(
        r"^  Display: mDisplayId=(" + decimal + r") stacks=0$")
    area = re.compile(
        r"^  (?P<label>mLastOrientationSource|"
        r"deepestLastOrientationSource)=DefaultTaskDisplayArea@(" +
        decimal + r")$")
    summary_ids: list[int] = []
    pair_displays: set[int] = set()
    pair_identities: set[int] = set()
    index = 4
    while index < len(lines):
        match = summary.fullmatch(lines[index])
        if match is not None:
            display_id = bounded(match.group(1), 1024)
            if display_id is None or display_id in summary_ids:
                return False
            summary_ids.append(display_id)
            index += 1
            continue
        if index + 2 >= len(lines):
            return False
        last = area.fullmatch(lines[index])
        deepest = area.fullmatch(lines[index + 1])
        match = summary.fullmatch(lines[index + 2])
        if (last is None or deepest is None or match is None or
                last.group("label") != "mLastOrientationSource" or
                deepest.group("label") != "deepestLastOrientationSource"):
            return False
        left = bounded(last.group(2), 2_147_483_647)
        right = bounded(deepest.group(2), 2_147_483_647)
        display_id = bounded(match.group(1), 1024)
        if (left is None or right is None or left != right or
                display_id is None or display_id == 0 or
                display_id in summary_ids or display_id in pair_displays or
                left in pair_identities):
            return False
        pair_displays.add(display_id)
        pair_identities.add(left)
        summary_ids.append(display_id)
        index += 3
    return bool(summary_ids) and summary_ids == header_ids


def _contains_host_scope_for_global_absence(
        raw: bytes, stable: dict[str, Any] | None) -> bool:
    text = alpha._decode_text(raw, "global visual-host task/window inventory")
    package_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])" + re.escape(alpha.HOST_PACKAGE) +
        r"(?=/|[\s}:,\]]|$)")
    if not text.startswith("ACTIVITY MANAGER"):
        return package_pattern.search(text) is not None
    full_text, _ = android._wire(raw)  # type: ignore[attr-defined]
    canonical = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
        full_text)
    if package_pattern.search(canonical) is not None:
        return True
    if stable is None:
        return package_pattern.search(full_text) is not None
    retained = (
        package_pattern,
        re.compile(re.escape(str(stable.get("taskToken", "")))),
        re.compile(re.escape(str(stable.get("activityToken", "")))),
    )
    present = any(pattern.search(full_text) is not None for pattern in retained)
    if not present:
        return False
    return not _is_exact_stale_host_supervisor_ghost(raw, stable)


def _one_line(lines: list[str], predicate: Callable[[str], bool],
              label: str) -> str:
    matches = [line.strip() for line in lines if predicate(line)]
    if len(matches) != 1:
        _fail(label + " is absent or ambiguous")
    return matches[0]


def _host_task_capture(raw: tuple[bytes, bytes, bytes],
                       process: host.ProcessIdentity,
                       host_apk: str) -> dict[str, Any]:
    """Parse the exact released-host task/window dialect retained by this run."""
    _assert_no_document_or_virtual_display(raw)
    expected_process = host.ProcessIdentity(
        HOST_PID, HOST_START_TICKS, HOST_UID, alpha.HOST_PACKAGE)
    if process != expected_process:
        _fail("host task capture process identity differs")
    if (type(host_apk) is not str or not host_apk.startswith("/data/app/") or
            not host_apk.endswith("/base.apk")):
        _fail("host APK path is malformed")

    activity_text = alpha._decode_text(raw[0], "host activity inventory")
    window_text = alpha._decode_text(raw[1], "host window inventory")
    physical_display = _physical_display0_override(raw[2])
    activity_lines = activity_text.splitlines()
    window_lines = window_text.splitlines()
    short_component = alpha.HOST_PACKAGE + "/.NativePageHostActivity"
    full_component = alpha.HOST_COMPONENT

    stack_indexes = [
        index for index, line in enumerate(activity_lines)
        if re.fullmatch(
            r"  Stack #" + str(HOST_TASK_ID) +
            r": type=standard mode=fullscreen", line) is not None]
    if len(stack_indexes) != 1:
        _fail("released host root task does not have one exact child task")
    stack_start = stack_indexes[0]
    stack_end = next((
        index for index in range(stack_start + 1, len(activity_lines))
        if re.match(r"^  Stack #[1-9][0-9]*:", activity_lines[index])
        is not None or
        activity_lines[index].startswith("ActivityStackSupervisor state:")),
        len(activity_lines))
    stack_block = activity_lines[stack_start:stack_end]
    # Only four-space Task headers are direct children of the selected Stack.
    # This firmware also prints a six-space textual echo of the same task in
    # its Activity detail; it is evidence, not a second child.
    child_tasks = [line for line in stack_block
                   if re.match(r"^    \* Task\{", line) is not None]
    if (len(child_tasks) != 1 or
            (" #" + str(HOST_TASK_ID) + " ") not in child_tasks[0] or
            short_component not in "\n".join(stack_block)):
        _fail("released host root task does not have one exact child task")

    stack_line = _one_line(
        activity_lines,
        lambda line: re.fullmatch(
            r"\s*Stack #" + str(HOST_TASK_ID) +
            r": type=standard mode=fullscreen\s*", line) is not None,
        "released host stack")
    task_line = _one_line(
        activity_lines,
        lambda line: line.startswith("    * Task{") and
        (" #" + str(HOST_TASK_ID) + " ") in line and
        ("A=" + str(HOST_UID) + ":" + alpha.HOST_PACKAGE) in line,
        "released host root task")
    task_match = re.search(
        r"Task\{([0-9a-f]+) #" + str(HOST_TASK_ID) + r"\b", task_line)
    if (task_match is None or " visible=true " not in task_line or
            " type=standard " not in task_line or
            " mode=fullscreen " not in task_line or
            " U=0 " not in task_line or
            " StackId=" + str(HOST_TASK_ID) not in task_line or
            not task_line.endswith(" sz=1}")):
        _fail("released host root-task topology differs")
    task_token = task_match.group(1)

    resumed_line = _one_line(
        activity_lines,
        lambda line: "mResumedActivity:" in line and
        short_component in line and
        (" t" + str(HOST_TASK_ID) + "}") in line,
        "released host resumed activity")
    activity_match = re.search(
        r"ActivityRecord\{([0-9a-f]+) u0 " +
        re.escape(short_component) + r" t" + str(HOST_TASK_ID) + r"\}",
        resumed_line)
    if activity_match is None:
        _fail("released host activity token differs")
    activity_token = activity_match.group(1)
    for prefix in ("Activities=[", "* Hist #0:"):
        line = _one_line(
            activity_lines,
            lambda value, expected=prefix: expected in value and
            short_component in value,
            "released host " + prefix.rstrip(":=["))
        if ("ActivityRecord{" + activity_token + " u0 " + short_component +
                " t" + str(HOST_TASK_ID) + "}") not in line:
            _fail("released host activity aliases differ")

    root_process_line = _one_line(
        activity_lines,
        lambda line: "mRootProcess=ProcessRecord{" in line and
        alpha.HOST_PACKAGE in line,
        "released host root process")
    process_match = re.search(
        r"ProcessRecord\{([0-9a-f]+) " + str(HOST_PID) + r":" +
        re.escape(alpha.HOST_PACKAGE) + r"/u0a" +
        str(HOST_UID - 10_000) + r"\}", root_process_line)
    if process_match is None:
        _fail("released host root-process identity differs")
    process_token = process_match.group(1)
    app_line = _one_line(
        activity_lines,
        lambda line: line.strip().startswith("app=ProcessRecord{") and
        alpha.HOST_PACKAGE in line,
        "released host activity process")
    if ("ProcessRecord{" + process_token + " " + str(HOST_PID) + ":" +
            alpha.HOST_PACKAGE + "/u0a" + str(HOST_UID - 10_000) + "}") not in app_line:
        _fail("released host activity process alias differs")

    ids_line = _one_line(
        activity_lines,
        lambda line: ("taskId=" + str(HOST_TASK_ID)) in line and
        ("stackId=" + str(HOST_TASK_ID)) in line,
        "released host task identifiers")
    intent_line = _one_line(
        activity_lines,
        lambda line: line.strip().startswith("intent={") and
        short_component in line,
        "released host root intent")
    if ("act=android.intent.action.MAIN" not in intent_line or
            "cat=[android.intent.category.LAUNCHER]" not in intent_line or
            "flg=0x10000000" not in intent_line or
            "cmp=" + short_component not in intent_line or
            any(field in intent_line for field in (" dat=", " typ=", " pkg="))):
        _fail("released host launch intent differs")
    base_line = _one_line(
        activity_lines,
        lambda line: line.strip().startswith("baseDir=") and
        alpha.HOST_PACKAGE in line,
        "released host APK binding")
    if base_line != "baseDir=" + host_apk:
        _fail("released host APK binding differs")
    state_line = _one_line(
        activity_lines,
        lambda line: "state=RESUMED" in line and
        "stopped=false" in line and "finishing=false" in line,
        "released host activity state")

    header_indexes = [
        index for index, line in enumerate(window_lines)
        if re.match(r"^\s*Window #[0-9]+ Window\{", line) is not None and
        full_component in line]
    if len(header_indexes) != 1:
        _fail("released host window header is absent or ambiguous")
    window_start = header_indexes[0]
    window_end = next((
        index for index in range(window_start + 1, len(window_lines))
        if re.match(r"^\s*Window #[0-9]+ Window\{", window_lines[index])
        is not None), len(window_lines))
    window_block = window_lines[window_start:window_end]
    header_line = window_block[0].strip()
    window_match = re.fullmatch(
        r"Window #[0-9]+ Window\{([0-9a-f]+) u0 " +
        re.escape(full_component) + r"\}:", header_line)
    if window_match is None:
        _fail("released host window token differs")
    window_token = window_match.group(1)
    session_line = _one_line(
        window_block,
        lambda line: "mDisplayId=0" in line and
        ("rootTaskId=" + str(HOST_TASK_ID)) in line and
        "mSession=Session{" in line,
        "released host window session")
    session_match = re.search(
        r"Session\{([0-9a-f]+) " + str(HOST_PID) + r":u0a" +
        str(HOST_UID) + r"\}", session_line)
    if session_match is None:
        _fail("released host window session identity differs")
    window_session_token = session_match.group(1)
    owner_line = _one_line(
        window_block,
        lambda line: ("mOwnerUid=" + str(HOST_UID)) in line and
        ("package=" + alpha.HOST_PACKAGE) in line,
        "released host window owner")
    expected_record = ("ActivityRecord{" + activity_token + " u0 " +
                       short_component + " t" + str(HOST_TASK_ID) + "}")
    token_line = _one_line(
        window_block,
        lambda value: re.fullmatch(
            r"\s*mBaseLayer=[0-9]+ mSubLayer=-?[0-9]+\s+mToken=" +
            re.escape(expected_record) + r"\s*", value) is not None,
        "released host window token")
    activity_record_line = _one_line(
        window_block,
        lambda value: value.strip() == "mActivityRecord=" + expected_record,
        "released host window activity record")
    frame_matches = [
        re.fullmatch(
            r"\s*mFrame=\[0,0\]\[([0-9]{1,5}),([0-9]{1,5})\] "
            r"last=\[0,0\]\[([0-9]{1,5}),([0-9]{1,5})\]\s*",
            line)
        for line in window_block]
    frame_matches = [item for item in frame_matches if item is not None]
    if len(frame_matches) != 1:
        _fail("released host window frame is absent or ambiguous")
    frame_match = frame_matches[0]
    frame_width, frame_height = (
        int(frame_match.group(1)), int(frame_match.group(2)))
    if ((frame_width, frame_height) !=
            (int(frame_match.group(3)), int(frame_match.group(4))) or
            (frame_width, frame_height) !=
            (physical_display["width"], physical_display["height"])):
        _fail("released host window frame differs from physical display")
    frame_line = frame_match.group(0).strip()
    surface_line = _one_line(
        window_block,
        lambda line: "mHasSurface=true" in line and
        "isReadyForDisplay()=true" in line,
        "released host window surface")
    _one_line(window_block, lambda line: line.strip() == "isOnScreen=true",
              "released host on-screen state")
    _one_line(window_block, lambda line: line.strip() == "isVisible=true",
              "released host visible state")

    # Every package-bearing task/activity/process/window record must alias the
    # one admitted scope.  The pinned dumpsys dialect legitimately repeats the
    # same #4646 Task textual record in root/history/token sections, so count
    # semantic identities rather than demanding one textual occurrence.
    host_task_lines = [line for line in activity_lines
                       if "Task{" in line and alpha.HOST_PACKAGE in line]
    if not host_task_lines:
        _fail("released host package lacks task scope")
    for line in host_task_lines:
        matches = re.findall(
            r"Task\{([0-9a-f]+) #([1-9][0-9]*)[^\n}]*"
            r"A=([1-9][0-9]*):" + re.escape(alpha.HOST_PACKAGE) +
            r"(?=\s|\})[^\n}]*\}", line)
        if (not matches or any(
                token != task_token or task_id != str(HOST_TASK_ID) or
                uid != str(HOST_UID)
                for token, task_id, uid in matches)):
            _fail("additional or malformed visual-host task scope exists")
    host_activity_lines = [
        line for line in activity_lines
        if "ActivityRecord{" in line and short_component in line]
    if not host_activity_lines:
        _fail("released host package lacks activity scope")
    expected_activity_pattern = re.compile(
        r"ActivityRecord\{" + re.escape(activity_token) + r" u0 " +
        re.escape(short_component) + r" t" + str(HOST_TASK_ID) + r"\}")
    generic_host_activity = re.compile(
        r"ActivityRecord\{[0-9a-f]+ u0 " + re.escape(short_component) +
        r" t[1-9][0-9]*\}")
    for line in host_activity_lines:
        generic = generic_host_activity.findall(line)
        expected = expected_activity_pattern.findall(line)
        if not generic or generic != expected:
            _fail("additional or malformed visual-host activity scope exists")
    host_process_lines = [line for line in activity_lines
                          if "ProcessRecord{" in line and
                          alpha.HOST_PACKAGE in line]
    if not host_process_lines:
        _fail("released host package lacks process scope")
    expected_process_record = (
        "ProcessRecord{" + process_token + " " + str(HOST_PID) + ":" +
        alpha.HOST_PACKAGE + "/u0a" + str(HOST_UID - 10_000) + "}")
    for line in host_process_lines:
        records = re.findall(
            r"ProcessRecord\{[0-9a-f]+ [1-9][0-9]*:" +
            re.escape(alpha.HOST_PACKAGE) + r"/u0a[1-9][0-9]*\}", line)
        if not records or any(record != expected_process_record
                              for record in records):
            _fail("additional or malformed visual-host process scope exists")
    package_window_headers = [
        line.strip() for line in window_lines
        if re.match(r"^\s*Window #[0-9]+ Window\{", line) is not None and
        alpha.HOST_PACKAGE in line]
    if package_window_headers != [header_line]:
        _fail("additional or malformed visual-host window scope exists")

    stable = {
        "process": asdict(process), "taskId": HOST_TASK_ID,
        "stackId": HOST_TASK_ID, "taskToken": task_token,
        "activityToken": activity_token, "processToken": process_token,
        "component": short_component, "windowComponent": full_component,
        "windowToken": window_token,
        "windowSessionToken": window_session_token,
        "displayId": 0,
        "frame": [0, 0, frame_width, frame_height],
        "physicalDisplay": physical_display,
        "hostApk": host_apk, "oneChildRootTask": True,
    }
    # Variables are intentionally referenced so future edits cannot silently
    # remove one of the observed semantic witnesses while retaining the same
    # stable projection.
    if not all((stack_line, ids_line, intent_line, state_line, owner_line,
                token_line, activity_record_line, frame_line, surface_line)):
        _fail("released host semantic witnesses are incomplete")
    return {
        "stable": stable,
        "evidence": {
            "activitiesSha256": _sha(raw[0]),
            "windowsSha256": _sha(raw[1]),
            "displaysSha256": _sha(raw[2]),
        },
    }


def _parking_stable(identity: dict[str, Any]) -> dict[str, Any]:
    required = {
        "process", "taskId", "displayId", "authoritySha256",
        "activityToken", "documentAuthority", "documentScope", "uiWitness",
        "fdTargets", "activitiesSha256", "windowsSha256",
    }
    if type(identity) is not dict or set(identity) != required:
        _fail("parking identity fields differ")
    ui = identity["uiWitness"]
    ui_fields = {"filename", "pageCount", "bounds", "package", "rotation", "sha256"}
    if (type(ui) is not dict or set(ui) != ui_fields or
            re.fullmatch(r"[0-9a-f]{64}", str(ui["sha256"])) is None or
            re.fullmatch(r"[0-9a-f]{64}",
                         str(identity["activitiesSha256"])) is None or
            re.fullmatch(r"[0-9a-f]{64}",
                         str(identity["windowsSha256"])) is None):
        _fail("parking raw evidence fields differ")
    authority_wire = identity["documentAuthority"]
    process_wire = identity["process"]
    if (type(authority_wire) is not dict or type(process_wire) is not dict or
            set(process_wire) != {"pid", "start_ticks", "uid", "package"}):
        _fail("parking Document authority is malformed")
    try:
        authority = android.DocumentTaskAuthority(**authority_wire)
        authority_sha = android.stable_authority_sha256(authority)
        process = host.ProcessIdentity(**process_wire)
    except (TypeError, android.AndroidAuthorityError) as error:
        raise RecoveryError("parking Document authority is malformed") from error
    if (authority_sha != identity["authoritySha256"] or
            authority.task_id != identity["taskId"] or
            authority.display_id != identity["displayId"] or
            authority.activity_token != identity["activityToken"] or
            process.pid != authority.pid or process.uid != authority.uid or
            process.package != authority.process_name):
        _fail("parking Document authority aliases disagree")
    scope = identity["documentScope"]
    scope_fields = {
        "taskId", "displayId", "taskToken", "activityToken",
        "processToken", "windowToken", "windowSessionToken",
        "windowComponent", "pid", "uid", "oneChildRootTask",
        "solePackageWindow",
    }
    if (type(scope) is not dict or set(scope) != scope_fields or
            scope["taskId"] != authority.task_id or
            scope["displayId"] != authority.display_id or
            scope["taskToken"] != authority.task_token or
            scope["activityToken"] != authority.activity_token or
            scope["pid"] != process.pid or scope["uid"] != process.uid or
            scope["windowComponent"] not in {
                android.SHORT_COMPONENT, android.FULL_COMPONENT} or
            scope["oneChildRootTask"] is not True or
            scope["solePackageWindow"] is not True or
            any(type(scope[key]) is not str or not scope[key]
                for key in ("processToken", "windowToken",
                            "windowSessionToken"))):
        _fail("parking package-wide scope aliases disagree")
    stable_authority = asdict(authority)
    stable_authority.pop("raw_sha256")
    ui_stable = {key: ui[key] for key in (
        "filename", "pageCount", "bounds", "package", "rotation")}
    # Raw ActivityManager/UI digests identify observations, not stable task
    # authority.  Their semantic parser outputs remain in this projection.
    return {
        "process": identity["process"], "taskId": identity["taskId"],
        "displayId": identity["displayId"],
        "authoritySha256": identity["authoritySha256"],
        "activityToken": identity["activityToken"],
        "documentAuthority": stable_authority,
        "documentScope": scope,
        "uiWitness": ui_stable, "fdTargets": identity["fdTargets"],
    }


def _parking_absence_authorities(
        identity: dict[str, Any],
        ) -> tuple[host.ForeignIdentity, android.DocumentTaskAuthority]:
    """Rebuild the exact retained task authority for the ghost exception."""
    _parking_stable(identity)
    try:
        authority = android.DocumentTaskAuthority(
            **identity["documentAuthority"])
        process = host.ProcessIdentity(**identity["process"])
    except (KeyError, TypeError) as error:
        raise RecoveryError("parking absence authority is malformed") from error
    foreign = host.ForeignIdentity(
        process, authority.task_id, authority.activity_token,
        identity["authoritySha256"], alpha.DOCUMENT_COMPONENT)
    return foreign, authority


def _released_host_ui(raw: bytes) -> dict[str, Any]:
    text = alpha._decode_text(raw, "released host UI")
    begin, end = text.find("<hierarchy"), text.rfind("</hierarchy>")
    if begin < 0 or end < begin:
        _fail("released host UI hierarchy is absent")
    try:
        root = ET.fromstring(text[begin:end + len("</hierarchy>")])
    except ET.ParseError as error:
        raise RecoveryError("released host UI hierarchy is malformed") from error
    if root.attrib.get("rotation") != "0":
        _fail("released host UI rotation differs")
    expected = "\n".join((
        "NATIVE PAGE HOST — VISUAL ONLY",
        "session=" + SESSION,
        "generation=" + str(GENERATION) + " display=-1",
        "state=RELEASED",
        "FAILED (sticky): foreign attach acknowledgment timed out",
        "Stylus is swallowed; no reader launch, pen, file, or root authority.",
    ))
    nodes = [node for node in root.iter("node")
             if node.attrib.get("text") == expected]
    if len(nodes) != 1:
        _fail("released host terminal status is absent or ambiguous")
    node = nodes[0]
    if (node.attrib.get("package") != alpha.HOST_PACKAGE or
            node.attrib.get("class") != "android.widget.TextView" or
            node.attrib.get("bounds") != "[709,0][1404,194]"):
        _fail("released host terminal status geometry differs")
    return {
        "session": SESSION, "generation": GENERATION, "displayId": -1,
        "state": "RELEASED", "stickyFailure":
        "foreign attach acknowledgment timed out",
        "bounds": [709, 0, 1404, 194], "hierarchyRotation": 0,
        "rawSha256": _sha(raw),
    }


def _same_file(first: alpha.DeviceFile | None, second: alpha.DeviceFile) -> bool:
    return first == second


def _same_renamed(first: alpha.DeviceFile, second: alpha.DeviceFile,
                  path: str) -> bool:
    return (second.path == path and first.kind == second.kind == "regular file" and
            (first.size, first.uid, first.gid, first.inode, first.device, first.sha256) ==
            (second.size, second.uid, second.gid, second.inode, second.device,
             second.sha256))


class Recovery:
    def __init__(self, device: Device, authority: Authority, *,
                 sleep: Callable[[float], None] = time.sleep,
                 journal: Journal | None = None):
        self.device = device
        self.authority = authority
        self.sleep = sleep
        self.journal = journal
        self.proofs: list[dict[str, Any]] = []
        self.mutations: list[dict[str, Any]] = []
        self.dispatch_outcomes: list[dict[str, Any]] = []
        self.adb_identity: dict[str, Any] | None = None
        self.helper_identity: dict[str, Any] | None = None
        self.document_process: host.ProcessIdentity | None = None
        self.host_apk: str | None = None
        self.released_host_task: dict[str, Any] | None = None
        self.retained_parking_identity: dict[str, Any] | None = None
        # The initial authority is immutable and report-pinned.  The stock
        # reader may, however, replace the target .mark inode once while
        # switching to the persistent parking PDF.  Only that narrowly
        # authenticated same-content replacement can advance this retained
        # delete authority.
        self.retained_targets = dict(PINNED_TARGETS)
        self.target_mark_adoption: dict[str, Any] | None = None

    def _proof(self, kind: str, **fields: Any) -> dict[str, Any]:
        record = {"kind": kind, **fields}
        record["sha256"] = _canonical_sha(record)
        self.proofs.append(record)
        return record

    def _assert_tools(self) -> None:
        adb = self.device.adb_authority()
        _, helper = _read_regular(Path(__file__), MAX_LOCAL_BYTES, "recovery helper")
        if self.adb_identity is None:
            self.adb_identity = adb
            self.helper_identity = helper
        elif adb != self.adb_identity or helper != self.helper_identity:
            _fail("recovery tool identity changed")

    def _assert_rotation(self) -> None:
        if self.device.rotation_settings() != ("1", "2"):
            _fail("persisted rotation differs from the original 1/2 state")

    def _assert_static(self) -> None:
        for expected in STATIC_FILES:
            if not _same_file(self.device.stat_file(expected.path), expected):
                _fail("static source/parking file changed: " + expected.path)
        if self.device.stat_file(alpha.PARKING_MARK, absent_ok=True) is not None:
            _fail("parking mark unexpectedly exists")
        for path in (STAGING_MARK, STAGING_PDF):
            if self.device.stat_file(path, absent_ok=True) is not None:
                _fail("published staging path unexpectedly exists")

    def _assert_targets(self) -> None:
        for path, expected in self.retained_targets.items():
            target = self.device.stat_file(path, absent_ok=True)
            quarantine = self.device.stat_file(QUARANTINES[path], absent_ok=True)
            if target is not None and target != expected:
                _fail("disposable target identity changed: " + path)
            if quarantine is not None and not _same_renamed(expected, quarantine,
                                                             QUARANTINES[path]):
                _fail("quarantine identity changed: " + QUARANTINES[path])
            if target is not None and quarantine is not None:
                _fail("target and quarantine are both occupied")

    def _assert_initial_targets(self) -> None:
        """Require the exact untouched report leaves before any recovery."""
        for path, expected in PINNED_TARGETS.items():
            if self.device.stat_file(path, absent_ok=True) != expected:
                _fail("initial disposable target is absent or changed: " + path)
            if self.device.stat_file(
                    QUARANTINES[path], absent_ok=True) is not None:
                _fail("initial quarantine leaf is already occupied: " +
                      QUARANTINES[path])

    def _assert_host(self) -> tuple[host.ProcessIdentity, dict[str, Any]]:
        if self.device.pidof(alpha.HOST_PACKAGE) != (HOST_PID,):
            _fail("retained host PID differs")
        process = self.device.process_identity(HOST_PID, alpha.HOST_PACKAGE)
        if process != host.ProcessIdentity(HOST_PID, HOST_START_TICKS, HOST_UID,
                                           alpha.HOST_PACKAGE):
            _fail("retained host process identity differs")
        selected = _validate_failed_host_log(self.device.host_logs(HOST_PID))
        lifecycle = {
            "session": SESSION, "generation": GENERATION,
            "terminalEvent": "FAILED",
            "reason": "host_surface_lost_unexpectedly",
            "emergencyDestroyContent": True,
            "derivedState": "RELEASED",
            "derivation": (
                "pinned host emits this FAILED event only after "
                "releaseForUnexpectedLoss marks lifecycle released, clears "
                "virtualDisplay, and sets displayId=-1"),
            "selectedEvents": selected,
            "selectedEventsSha256": _canonical_sha(selected),
        }
        return process, lifecycle

    def _capture_host_task(self) -> dict[str, Any]:
        if self.host_apk is None:
            _fail("host APK authority was not admitted")
        process, lifecycle = self._assert_host()
        capture = _host_task_capture(
            self.device.absence_raw(), process, self.host_apk)
        capture["stable"]["terminalLifecycle"] = {
            key: value for key, value in lifecycle.items()
            if key != "selectedEvents"}
        capture["evidence"]["terminalLifecycle"] = lifecycle
        return capture

    def _capture_optional_released_host_ui(self) -> dict[str, Any]:
        """Collect one corroborative UI sample without making it authority.

        The pinned host intentionally toggles its status TextView between
        VISIBLE and GONE, and this firmware's uiautomator can return literal
        ``Killed`` despite an intact Activity/window.  The signed host APK,
        exact process/task/window topology, and exact terminal lifecycle log
        are the removal authority.  UI is therefore sampled once, never
        retried, and retained only as optional evidence.
        """
        try:
            raw = self.device.ui_dump()
        except Exception as error:
            return {"available": False, "required": False,
                    "reason": type(error).__name__ + ": " + str(error)}
        raw_sha = _sha(raw) if type(raw) is bytes else None
        try:
            witness = _released_host_ui(raw)
        except (RecoveryError, alpha.AlphaError, UnicodeError,
                ET.ParseError) as error:
            return {"available": False, "required": False,
                    "rawSha256": raw_sha,
                    "reason": type(error).__name__ + ": " + str(error)}
        return {"available": True, "required": False, "witness": witness}

    def _prove_host_task_twice(self) -> dict[str, Any]:
        captures: list[dict[str, Any]] = []
        for index in range(2):
            captures.append(self._capture_host_task())
            if index == 0:
                self.sleep(POLL_SECONDS)
        stable = captures[0]["stable"]
        if captures[1]["stable"] != stable:
            _fail("released host stable task authority changed across proofs")
        result = {"stable": stable,
                  "observations": [capture["evidence"] for capture in captures],
                  "optionalUi": self._capture_optional_released_host_ui()}
        self._proof("released_host_task_authority", **result)
        return result

    @staticmethod
    def _raw_absent(raw: tuple[bytes, bytes, bytes]) -> None:
        _assert_no_document_or_virtual_display(raw)

    def _prove_absence_twice(self, label: str) -> list[dict[str, str]]:
        observations: list[dict[str, str]] = []
        for index in range(2):
            raw = self.device.absence_raw()
            self._raw_absent(raw)
            observations.append({
                "activitiesSha256": _sha(raw[0]), "windowsSha256": _sha(raw[1]),
                "displaysSha256": _sha(raw[2])})
            if index == 0:
                self.sleep(POLL_SECONDS)
        self._proof(label, observations=observations)
        return observations

    def _prove_parking_absence_twice(
            self, parking: dict[str, Any]) -> list[dict[str, str]]:
        """Prove task/window absence, admitting only the exact stale ghost.

        This firmware can retain the just-removed DocumentActivity identity in
        ActivityStackSupervisor's empty history.  It is not task-selection
        authority.  The shared alpha parser accepts only the exact invisible,
        zero-child ghost bound to the retained task/activity/process; any live,
        altered, or recreated Document scope still fails closed.
        """
        foreign, authority = _parking_absence_authorities(parking)
        observations: list[dict[str, str]] = []
        last_error: Exception | None = None
        for _ in range(POLL_LIMIT):
            try:
                raw = self.device.absence_raw()
                _assert_no_virtual_display(raw[2])
                alpha._decode_text(
                    raw[0], "post-parking activity inventory")
                alpha._decode_text(
                    raw[1], "post-parking window inventory")
                if (_contains_host_scope_for_global_absence(
                        raw[0], self.released_host_task) or
                        _contains_host_scope_for_global_absence(
                            raw[1], self.released_host_task)):
                    _fail("visual-host scope reappeared after parking removal")
                document_present = (
                    alpha._contains_document_scope_for_global_absence(
                        raw[0], foreign, authority) or
                    alpha._contains_document_scope_for_global_absence(
                        raw[1], foreign, authority))
                if document_present:
                    _fail("exact or recreated Document task/window is still present")
                observations.append({
                    "activitiesSha256": _sha(raw[0]),
                    "windowsSha256": _sha(raw[1]),
                    "displaysSha256": _sha(raw[2]),
                })
                if len(observations) == 2:
                    break
            except (RecoveryError, alpha.AlphaError,
                    android.AndroidAuthorityError, UnicodeError) as error:
                # Task/window teardown can lag the one-shot numeric removal.
                # Reset the consecutive-proof count and poll; never resend.
                observations = []
                last_error = error
            self.sleep(POLL_SECONDS)
        if len(observations) != 2:
            suffix = "" if last_error is None else ": " + str(last_error)
            _fail("post-parking task/window absence was not proved twice" +
                  suffix)
        self._proof("post_parking_task_absence", observations=observations,
                    retainedTaskId=foreign.task_id,
                    retainedActivityToken=foreign.activity_token)
        return observations

    def _document_process(self) -> host.ProcessIdentity:
        pids = self.device.pidof(alpha.DOCUMENT_PACKAGE)
        if pids != (DOCUMENT_PID,):
            _fail("stock Document process PID differs from the retained consumer")
        process = self.device.process_identity(DOCUMENT_PID, alpha.DOCUMENT_PACKAGE)
        if (process.pid != DOCUMENT_PID or process.uid != 1000 or
                process.package != alpha.DOCUMENT_PACKAGE or
                type(process.start_ticks) is not int or process.start_ticks <= 0):
            _fail("stock Document process identity is malformed")
        if self.document_process is None:
            self.document_process = process
        elif process != self.document_process:
            _fail("stock Document process changed during recovery")
        return process

    def _parking_fd_proof(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        first_process: host.ProcessIdentity | None = None
        for index in range(2):
            process = self._document_process()
            if first_process is not None and process != first_process:
                _fail("stock Document process changed across descriptor proofs")
            first_process = process
            targets = _validated_fd_targets(self.device.process_fd_links(process.pid))
            if targets != frozenset((alpha.PARKING_PDF,)):
                _fail("stock Document descriptors are not parking-only")
            observations.append({"process": asdict(process),
                                 "targets": sorted(targets)})
            if index == 0:
                self.sleep(POLL_SECONDS)
        return self._proof("parking_only_descriptors", observations=observations)

    def _header(self) -> dict[str, Any]:
        self._assert_tools()
        assert self.adb_identity is not None and self.helper_identity is not None
        return {
            "authority": AUTHORITY, "runId": RUN_ID, "journalId": JOURNAL_ID,
            "report": self.authority.report_identity,
            "activeJournal": self.authority.active_identity,
            "helper": self.helper_identity, "adb": self.adb_identity,
            "host": {"pid": HOST_PID, "startTicks": HOST_START_TICKS,
                     "uid": HOST_UID, "session": SESSION,
                     "generation": GENERATION, "displayId": DISPLAY_ID},
            "targets": {path: asdict(value) for path, value in PINNED_TARGETS.items()},
            "quarantines": QUARANTINES, "residualAssumption": RESIDUAL_ASSUMPTION,
        }

    def _intent(self, name: str, payload: dict[str, Any]) -> bool:
        if self.journal is None:
            _fail("execute mode lacks a recovery journal")
        existing = self.journal.one(name + "_intent")
        if existing is not None:
            if existing["payload"] != payload:
                _fail("resumed mutation intent differs: " + name)
            return False
        self._assert_tools()
        self._assert_rotation()
        self._assert_static()
        self._assert_targets()
        record = self.journal.append(name + "_intent", payload)
        self.mutations.append({"kind": name, "sequence": record["sequence"],
                               **payload})
        return True

    def _parking_task_remove_intent(
            self, payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Journal exact task removal even if parking exposed bad mark state.

        Numeric removal of the independently authenticated parking task is a
        safe cleanup action and must not be blocked by an ineligible stock
        save at the target mark path.  This deliberately narrow intent still
        authenticates every tool/static input, the target PDF, and both random
        quarantine leaves.  It records (but does not adopt) the current mark
        observation.  No file mutation is authorized by this method.
        """
        if self.journal is None:
            _fail("execute mode lacks a recovery journal")
        self._assert_tools()
        self._assert_rotation()
        self._assert_static()
        target_pdf = self.device.stat_file(alpha.TARGET_PDF, absent_ok=True)
        if target_pdf != self.retained_targets[alpha.TARGET_PDF]:
            _fail("target PDF changed before parking task removal")
        for quarantine in (QUARANTINE_MARK, QUARANTINE_PDF):
            if self.device.stat_file(quarantine, absent_ok=True) is not None:
                _fail("quarantine occupied before parking task removal: " +
                      quarantine)
        mark = self.device.stat_file(alpha.TARGET_MARK, absent_ok=True)
        complete = dict(payload)
        complete["targetMarkObservation"] = (
            None if mark is None else asdict(mark))
        existing = self.journal.one("parking_task_remove_intent")
        if existing is not None:
            if existing["payload"] != complete:
                _fail("resumed mutation intent differs: parking_task_remove")
            return False, complete
        record = self.journal.append("parking_task_remove_intent", complete)
        self.mutations.append({
            "kind": "parking_task_remove", "sequence": record["sequence"],
            **complete,
        })
        return True, complete

    def _authorize_target_mark_after_parking(self) -> dict[str, Any]:
        """Admit at most one same-content stock-save inode replacement."""
        if (self.device.stat_file(alpha.TARGET_PDF, absent_ok=True) !=
                self.retained_targets[alpha.TARGET_PDF]):
            _fail("target PDF changed at the parking boundary")
        if (self.device.stat_file(QUARANTINE_MARK, absent_ok=True) is not None or
                self.device.stat_file(QUARANTINE_PDF, absent_ok=True) is not None):
            _fail("quarantine occupied at the parking boundary")
        current = self.device.stat_file(alpha.TARGET_MARK, absent_ok=True)
        retained = self.retained_targets[alpha.TARGET_MARK]
        if current == retained:
            return {
                "mode": ("ADOPTED_REPLACEMENT" if self.target_mark_adoption
                         is not None else "ORIGINAL_RETAINED"),
                "retained": asdict(retained),
                "adoption": self.target_mark_adoption,
            }
        original = PINNED_TARGET_MARK
        eligible = (
            current is not None and current.path == alpha.TARGET_MARK and
            current.kind == original.kind == "regular file" and
            current.inode != original.inode and
            (current.size, current.uid, current.gid, current.device,
             current.sha256) ==
            (original.size, original.uid, original.gid, original.device,
             original.sha256))
        if not eligible:
            _fail("stock parking save produced an ineligible target mark")
        if self.target_mark_adoption is not None or retained != original:
            _fail("target mark changed more than once at the parking boundary")
        assert current is not None
        adoption = {
            "path": alpha.TARGET_MARK,
            "previous": asdict(original), "current": asdict(current),
            "previousInode": original.inode, "currentInode": current.inode,
            "sameContentOwnerDevice": True,
        }
        self.retained_targets[alpha.TARGET_MARK] = current
        self.target_mark_adoption = adoption
        self._proof("target_mark_recreated_or_replaced_at_parking", **adoption)
        self._settle("target_mark_authority_adopted", adoption)
        return {"mode": "ADOPTED_REPLACEMENT",
                "retained": asdict(current), "adoption": adoption}

    def _settle(self, name: str, payload: dict[str, Any]) -> None:
        if self.journal is None:
            _fail("execute mode lacks a recovery journal")
        existing = self.journal.one(name + "_settled")
        if existing is not None:
            if existing["payload"] != payload:
                _fail("resumed mutation settlement differs: " + name)
            return
        self.journal.append(name + "_settled", payload)

    def _record_mutation_failure(self, name: str, error: BaseException) -> None:
        """Durably retain an authoritative bad reply before propagating it."""
        if self.journal is None:
            _fail("execute mode lacks a recovery journal")
        payload = {"errorType": type(error).__name__, "error": str(error)}
        existing = self.journal.one(name + "_semantic_failure")
        if existing is None:
            self.journal.append(name + "_semantic_failure", payload)
        elif existing["payload"] != payload:
            _fail("mutation semantic-failure evidence changed: " + name)

    def _record_dispatch_outcome(
            self, name: str, *, result: alpha.CommandResult | None = None,
            uncertain: MutationTransportUncertain | None = None,
            ) -> dict[str, Any]:
        if self.journal is None:
            _fail("execute mode lacks a recovery journal")
        if (result is None) == (uncertain is None):
            _fail("mutation dispatch outcome is ambiguous")
        if result is not None:
            payload = {
                "mode": "VALIDATED_RECEIPT",
                "operation": result.operation,
                "returncode": result.returncode,
                "stdoutSize": len(result.stdout),
                "stdoutSha256": _sha(result.stdout),
                "stderrSize": len(result.stderr),
                "stderrSha256": _sha(result.stderr),
                "receiptGrammar": (
                    "EXACT_PARKING_START_CRLF" if
                    result.operation == "launch_parking_document" else
                    "EXACT_EMPTY_STREAMS"),
            }
        else:
            assert uncertain is not None
            payload = {
                "mode": "TRANSPORT_UNCERTAIN",
                "errorType": type(uncertain).__name__,
                "error": str(uncertain),
                "retryAllowed": False,
                "settlementAuthority": "AUTHENTICATED_POSTCONDITION_ONLY",
            }
        record = self.journal.append(name + "_dispatch_outcome", payload)
        evidence = {"name": name, "sequence": record["sequence"], **payload}
        evidence["sha256"] = _canonical_sha(evidence)
        self.dispatch_outcomes.append(evidence)
        return evidence

    def _host_absent_twice(self) -> dict[str, Any]:
        observations: list[dict[str, str]] = []
        last_error: Exception | None = None
        for _ in range(POLL_LIMIT):
            try:
                raw = self.device.absence_raw()
                _assert_no_virtual_display(raw[2])
                if (_contains_host_scope_for_global_absence(
                        raw[0], self.released_host_task) or
                        _contains_host_scope_for_global_absence(
                            raw[1], self.released_host_task)):
                    _fail("visual-host task/window is still present")
                if self.retained_parking_identity is None:
                    if (alpha._contains_document_task_or_window(raw[0]) or
                            alpha._contains_document_task_or_window(raw[1])):
                        _fail("stock Document task/window is still present")
                else:
                    foreign, authority = _parking_absence_authorities(
                        self.retained_parking_identity)
                    if (alpha._contains_document_scope_for_global_absence(
                            raw[0], foreign, authority) or
                            alpha._contains_document_scope_for_global_absence(
                                raw[1], foreign, authority)):
                        _fail("stock Document task/window is still present")
                observations.append({
                    "activitiesSha256": _sha(raw[0]),
                    "windowsSha256": _sha(raw[1]),
                    "displaysSha256": _sha(raw[2])})
                if len(observations) == 2:
                    break
            except (RecoveryError, alpha.AlphaError,
                    android.AndroidAuthorityError, UnicodeError) as error:
                observations = []
                last_error = error
            self.sleep(POLL_SECONDS)
        if len(observations) != 2:
            suffix = "" if last_error is None else ": " + str(last_error)
            _fail("visual-host task/window absence was not proved twice" + suffix)
        self._proof("host_and_foreign_absence", observations=observations)
        process_observations: list[dict[str, Any]] = []
        for index in range(2):
            pids = self.device.pidof(alpha.HOST_PACKAGE)
            if not pids:
                current = {"mode": "PROCESS_ABSENT", "process": None}
            elif pids == (HOST_PID,):
                try:
                    process = self.device.process_identity(
                        HOST_PID, alpha.HOST_PACKAGE)
                except Exception as error:
                    # A cached process may exit between pidof and /proc reads.
                    # Reconcile only the safe monotonic transition to absence;
                    # any retained/reused PID keeps the original failure.
                    if self.device.pidof(alpha.HOST_PACKAGE):
                        raise RecoveryError(
                            "cached visual-host process identity could not be "
                            "authenticated") from error
                    process = None
                if process is None:
                    current = {"mode": "PROCESS_ABSENT", "process": None}
                    process_observations.append(current)
                    if index == 0:
                        self.sleep(POLL_SECONDS)
                    continue
                expected = host.ProcessIdentity(
                    HOST_PID, HOST_START_TICKS, HOST_UID, alpha.HOST_PACKAGE)
                if process != expected:
                    _fail("cached visual-host process identity changed")
                current = {"mode": "CACHED_PROCESS_ONLY",
                           "process": asdict(process)}
            else:
                _fail("visual-host process set changed after task release")
            if process_observations:
                previous_mode = process_observations[0]["mode"]
                current_mode = current["mode"]
                if (previous_mode == "PROCESS_ABSENT" and
                        current_mode != "PROCESS_ABSENT"):
                    _fail("visual-host process reappeared across proofs")
                if (previous_mode == "CACHED_PROCESS_ONLY" and
                        current_mode not in {
                            "CACHED_PROCESS_ONLY", "PROCESS_ABSENT"}):
                    _fail("visual-host cached-process state changed unsafely")
            process_observations.append(current)
            if index == 0:
                self.sleep(POLL_SECONDS)
        result = {"scopeAbsence": observations,
                  "processObservations": process_observations,
                  "processCleanupRequired": False,
                  "rationale": (
                      "a cached process with the original identity owns no "
                      "task, window, virtual display, or disposable file")}
        self._proof("host_runtime_after_task_release", **result)
        return result

    def _remove_released_host(self, admitted: dict[str, Any]) -> dict[str, Any]:
        self.released_host_task = admitted
        payload = {
            "taskId": HOST_TASK_ID,
            "stableAuthority": admitted,
            "stableAuthoritySha256": _canonical_sha(admitted),
        }
        fresh = self._intent("released_host_task_remove", payload)
        if fresh:
            immediate = self._capture_host_task()
            if immediate["stable"] != admitted:
                _fail("released host task changed before removal")
            assert self.journal is not None
            self.journal.assert_authority()
            try:
                result = self.device.remove_task(HOST_TASK_ID)
                _validate_mutation_result(result, "remove_exact_task")
                self._record_dispatch_outcome(
                    "released_host_task_remove", result=result)
            except MutationTransportUncertain as error:
                # Never resend an uncertain numeric task-removal mutation.
                self._record_dispatch_outcome(
                    "released_host_task_remove", uncertain=error)
            except Exception as error:
                self._record_mutation_failure(
                    "released_host_task_remove", error)
                raise
        absence = self._host_absent_twice()
        settled = {
            "taskId": HOST_TASK_ID,
            "stableAuthoritySha256": payload["stableAuthoritySha256"],
            "postRemoval": absence,
        }
        self._settle("released_host_task_remove", settled)
        return settled

    def _launch_and_remove_parking(self) -> dict[str, Any]:
        launch_payload = {"displayId": 0, "uri": alpha.PARKING_URI}
        fresh = self._intent("parking_launch", launch_payload)
        if fresh:
            assert self.journal is not None
            self.journal.assert_authority()
            try:
                result = self.device.launch_parking()
                _validate_mutation_result(result, "launch_parking_document")
                self._record_dispatch_outcome("parking_launch", result=result)
            except MutationTransportUncertain as error:
                self._record_dispatch_outcome(
                    "parking_launch", uncertain=error)
            except Exception as error:
                self._record_mutation_failure("parking_launch", error)
                raise
        parking: dict[str, Any] | None = None
        for _ in range(POLL_LIMIT):
            try:
                parking = self.device.parking_identity()
                break
            except Exception:
                self.sleep(POLL_SECONDS)
        if parking is None:
            _fail("parking launch was attempted once but did not settle exactly")
        retained_document = self._document_process()
        if parking.get("process") != asdict(retained_document):
            _fail("parking task belongs to a changed stock Document process")
        self.retained_parking_identity = parking
        self._settle("parking_launch", parking)
        parking_stable = _parking_stable(parking)
        mark_authority: dict[str, Any] | None = None
        mark_error: RecoveryError | None = None
        try:
            mark_authority = self._authorize_target_mark_after_parking()
        except RecoveryError as error:
            # An ineligible stock-save result must not strand the independently
            # authenticated parking task.  Remove only that exact task below,
            # prove its absence, record the rejection, and then stop before
            # every file mutation.
            mark_error = error
        task_id = parking.get("taskId")
        if type(task_id) is not int or task_id <= 0:
            _fail("parking task ID is malformed")
        remove_payload = {
            "taskId": task_id, "stableAuthority": parking_stable,
            "stableAuthoritySha256": _canonical_sha(parking_stable)}
        fresh, remove_payload = self._parking_task_remove_intent(remove_payload)
        if fresh:
            # Task removal is numeric-ID based.  Reauthenticate the complete
            # stock task/process/UI/FD authority after the durable intent and
            # immediately before dispatch, so a disappeared, replaced, or
            # ID-reused task is never removed through stale authority.
            try:
                removal_identity = self.device.parking_identity()
            except Exception as error:
                raise RecoveryError(
                    "parking identity disappeared before removal") from error
            if _parking_stable(removal_identity) != parking_stable:
                _fail("parking identity changed before removal")
            assert self.journal is not None
            self.journal.assert_authority()
            try:
                result = self.device.remove_task(task_id)
                _validate_mutation_result(result, "remove_exact_task")
                self._record_dispatch_outcome(
                    "parking_task_remove", result=result)
            except MutationTransportUncertain as error:
                self._record_dispatch_outcome(
                    "parking_task_remove", uncertain=error)
            except Exception as error:
                self._record_mutation_failure("parking_task_remove", error)
                raise
        absence = self._prove_parking_absence_twice(parking)
        descriptors = self._parking_fd_proof()
        if mark_error is None:
            try:
                mark_authority = self._authorize_target_mark_after_parking()
            except RecoveryError as error:
                mark_error = error
        settled = {"taskId": task_id, "absence": absence,
                   "descriptorProofSha256": descriptors["sha256"],
                   "targetMarkAuthority": mark_authority,
                   "targetMarkRejected": (None if mark_error is None else
                                           str(mark_error))}
        self._settle("parking_task_remove", settled)
        if mark_error is not None:
            raise RecoveryError(
                "parking task was safely removed but target mark authority "
                "was rejected: " + str(mark_error))
        return settled

    def _prove_path_absent_twice(self, path: str) -> None:
        for index in range(2):
            if self.device.stat_file(path, absent_ok=True) is not None:
                _fail("path remains present: " + path)
            if index == 0:
                self.sleep(POLL_SECONDS)

    def _quarantine_delete(self, path: str) -> None:
        expected = self.retained_targets[path]
        quarantine = QUARANTINES[path]
        stem = "mark" if path == alpha.TARGET_MARK else "pdf"
        target_now = self.device.stat_file(path, absent_ok=True)
        quarantine_now = self.device.stat_file(quarantine, absent_ok=True)
        if target_now is None and quarantine_now is None:
            if (self.journal is None or
                    self.journal.one(stem + "_quarantine_delete_intent") is None):
                _fail("target disappeared without its durable delete intent")
            self._prove_path_absent_twice(path)
            self._prove_path_absent_twice(quarantine)
            self._settle(stem + "_quarantine_delete", {
                "source": path, "quarantine": quarantine,
                "observations": 2})
            return
        if target_now is not None and target_now != expected:
            _fail("target changed before quarantine: " + path)
        if quarantine_now is not None and not _same_renamed(expected, quarantine_now,
                                                             quarantine):
            _fail("quarantine changed before cleanup: " + quarantine)
        if target_now is not None and quarantine_now is not None:
            _fail("target and quarantine are both occupied")
        move_payload = {"source": path, "quarantine": quarantine,
                        "retained": asdict(expected)}
        if quarantine_now is None:
            fresh = self._intent(stem + "_quarantine_move", move_payload)
            if fresh:
                assert self.journal is not None
                self.journal.assert_authority()
                try:
                    result = self.device.move_quarantine(path, quarantine)
                    _validate_mutation_result(
                        result, "recovery_quarantine_" + Path(path).name,
                        empty_stdout=True)
                    self._record_dispatch_outcome(
                        stem + "_quarantine_move", result=result)
                except MutationTransportUncertain as error:
                    self._record_dispatch_outcome(
                        stem + "_quarantine_move", uncertain=error)
                except Exception as error:
                    self._record_mutation_failure(
                        stem + "_quarantine_move", error)
                    raise
            self._prove_path_absent_twice(path)
            quarantine_now = self.device.stat_file(quarantine)
            if not _same_renamed(expected, quarantine_now, quarantine):
                _fail("one-shot quarantine move did not settle exactly")
            self._settle(stem + "_quarantine_move", {
                "source": path, "quarantine": quarantine,
                "retained": asdict(quarantine_now)})
        else:
            # Resume only a previously journalled move.  A pre-existing random
            # capability without its exact intent is never adopted.
            if self.journal is None or self.journal.one(stem + "_quarantine_move_intent") is None:
                _fail("quarantine exists without its durable move intent")
            self._prove_path_absent_twice(path)
        delete_payload = {"source": path, "quarantine": quarantine,
                          "retained": asdict(quarantine_now)}
        fresh = self._intent(stem + "_quarantine_delete", delete_payload)
        if fresh:
            assert self.journal is not None
            self.journal.assert_authority()
            try:
                result = self.device.remove_quarantine(quarantine)
                _validate_mutation_result(
                    result, "recovery_remove_" + Path(quarantine).name,
                    empty_stdout=True)
                self._record_dispatch_outcome(
                    stem + "_quarantine_delete", result=result)
            except MutationTransportUncertain as error:
                self._record_dispatch_outcome(
                    stem + "_quarantine_delete", uncertain=error)
            except Exception as error:
                self._record_mutation_failure(
                    stem + "_quarantine_delete", error)
                raise
        self._prove_path_absent_twice(quarantine)
        self._prove_path_absent_twice(path)
        self._settle(stem + "_quarantine_delete", {
            "source": path, "quarantine": quarantine, "observations": 2})

    def _joint_target_absence(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        paths = (alpha.TARGET_MARK, alpha.TARGET_PDF,
                 QUARANTINE_MARK, QUARANTINE_PDF)
        for index in range(2):
            present = [path for path in paths
                       if self.device.stat_file(path, absent_ok=True) is not None]
            if present:
                _fail("joint disposable-file absence is not stable: " +
                      ", ".join(present))
            observations.append({"observation": index + 1,
                                 "absent": list(paths)})
            if index == 0:
                self.sleep(POLL_SECONDS)
        self._assert_static()
        return self._proof("joint_target_absence", observations=observations)

    def _archive_active(self) -> dict[str, Any]:
        payload = {
            "activePath": str(self.authority.active_path),
            "retiredPath": str(self.authority.retired_path),
            "sha256": ACTIVE_JOURNAL_SHA256,
            "device": self.authority.active_identity["device"],
            "inode": self.authority.active_identity["inode"],
        }
        fresh = self._intent("active_journal_archive", payload)
        if fresh and self.authority.active_present:
            if os.path.lexists(self.authority.retired_path):
                _fail("retired active-journal path already exists")
            # Re-open and authenticate the path after the durable archive
            # intent, immediately before the single rename primitive.  This
            # proves the path still names the exact loaded inode and bytes;
            # a replacement is never archived.  Windows exposes no
            # rename-by-open-handle primitive here, so the only remaining
            # assumption is that the local workspace is not maliciously
            # replaced in the minimal interval between this check and
            # MoveFileExW.  Post-rename inode/content checks remain mandatory.
            active_raw, active_identity = _read_regular(
                self.authority.active_path, 256 * 1024,
                "active journal immediately before archive")
            if (active_identity != self.authority.active_identity or
                    len(active_raw) != ACTIVE_JOURNAL_BYTES or
                    _sha(active_raw) != ACTIVE_JOURNAL_SHA256):
                _fail("active journal changed before archive dispatch")
            _verify_mutation_journal(active_raw)
            assert self.journal is not None
            self.journal.assert_authority()
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes
                move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
                move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
                move.restype = wintypes.BOOL
                if not move(str(self.authority.active_path),
                            str(self.authority.retired_path), 0x00000008):
                    raise RecoveryError(
                        "active-journal archive failed with Windows error " +
                        str(ctypes.get_last_error()))
            else:
                os.rename(self.authority.active_path, self.authority.retired_path)
            _fsync_directory(self.authority.active_path.parent)
            _fsync_directory(self.authority.retired_path.parent)
        elif fresh:
            _fail("retired journal exists without its durable archive intent")
        if os.path.lexists(self.authority.active_path):
            _fail("active journal still exists after archive")
        raw, identity = _read_regular(
            self.authority.retired_path, 256 * 1024, "retired active journal")
        if (len(raw) != ACTIVE_JOURNAL_BYTES or _sha(raw) != ACTIVE_JOURNAL_SHA256 or
                identity["device"] != payload["device"] or
                identity["inode"] != payload["inode"]):
            _fail("archived active journal identity differs")
        self._settle("active_journal_archive", identity)
        return identity

    def plan(self) -> dict[str, Any]:
        _assert_publication_paths_clear(
            self.authority, before_journal=self.journal is None)
        self._assert_tools()
        environment = self.device.environment()
        self.host_apk = environment["hostApk"]
        self._assert_rotation()
        self._assert_static()
        self._assert_initial_targets()
        host_task = self._prove_host_task_twice()
        document = self._document_process()
        targets = _validated_fd_targets(self.device.process_fd_links(document.pid))
        if (alpha.TARGET_PDF not in targets or alpha.PARKING_PDF not in targets or
                not targets.issubset({alpha.TARGET_PDF, alpha.TARGET_MARK,
                                      alpha.PARKING_PDF})):
            _fail("pre-recovery Document descriptors differ from target+parking authority")
        return {
            "authority": AUTHORITY, "mode": "plan", "result": "PLAN_READY",
            "deviceMutationAttempted": False, "environment": environment,
            "hostProcess": host_task["stable"]["process"],
            "hostTaskStable": host_task["stable"],
            "hostTaskObservations": host_task["observations"],
            "documentProcess": asdict(document),
            "documentFileTargets": sorted(targets),
            "plannedSequence": [
                "REMOVE_EXACT_RELEASED_HOST_TASK", "LAUNCH_PARKING_DISPLAY_0",
                "REMOVE_EXACT_PARKING_TASK", "DELETE_MARK", "DELETE_PDF",
                "ARCHIVE_ACTIVE_JOURNAL"],
            "residualAssumption": RESIDUAL_ASSUMPTION,
            "proofs": self.proofs,
        }

    def execute(self) -> dict[str, Any]:
        if self.journal is None:
            _fail("execute mode requires the durable recovery journal")
        # Re-run the entire admission before the first mutation.  Plan itself
        # is guaranteed not to create or append the recovery journal.
        admission = self.plan()
        host_removal = self._remove_released_host(admission["hostTaskStable"])
        parking = self._launch_and_remove_parking()
        self._quarantine_delete(alpha.TARGET_MARK)
        self._quarantine_delete(alpha.TARGET_PDF)
        joint_absence = self._joint_target_absence()
        self._assert_static()
        self._assert_rotation()
        self._parking_fd_proof()
        self._host_absent_twice()
        retired = self._archive_active()
        result = {
            "authority": AUTHORITY, "mode": "execute",
            "result": "RECOVERED_CLEANLY", "runId": RUN_ID,
            "reportSha256": REPORT_SHA256,
            "activeJournalArchived": retired,
            "hostTaskSettlement": host_removal,
            "parkingSettlement": parking,
            "jointTargetAbsence": joint_absence,
            "mutations": self.mutations,
            "dispatchOutcomes": self.dispatch_outcomes,
            "proofs": self.proofs,
            "rotation": {"accelerometerRotation": "1", "userRotation": "2"},
            "originalsUnchanged": [asdict(value) for value in STATIC_FILES],
            "deletedDisposablePaths": [alpha.TARGET_MARK, alpha.TARGET_PDF],
            "recoveryJournal": str(self.authority.recovery_path),
            "residualAssumption": RESIDUAL_ASSUMPTION,
        }
        encoded = json.dumps(result, indent=2, sort_keys=True,
                             ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
        self.journal.assert_authority()
        try:
            descriptor = os.open(
                self.authority.evidence_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600)
        except FileExistsError as error:
            raise RecoveryError(
                "recovery evidence path became occupied before publication") from error
        try:
            if os.write(descriptor, encoded) != len(encoded):
                _fail("short recovery evidence write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.authority.evidence_path.parent)
        return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="perform the exact journalled recovery")
    parser.add_argument("--adb", type=Path, default=PINNED_ADB)
    parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--active-journal", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    root = arguments.root.absolute()
    report = arguments.report or root / REPORT_RELATIVE
    active = arguments.active_journal or root / ACTIVE_RELATIVE
    try:
        authority = load_authority(root, report, active)
        if arguments.execute:
            _assert_publication_paths_clear(authority, before_journal=True)
        device = RecoveryNomad(arguments.adb, alpha.AUTHORIZED_SERIAL)
        recovery = Recovery(device, authority)
        if not arguments.execute:
            result = recovery.plan()
        else:
            # The header is derived only after a complete read-only admission.
            admission = recovery.plan()
            header = recovery._header()
            header["admissionSha256"] = _canonical_sha(admission)
            journal = Journal(authority.recovery_path, header)
            recovery = Recovery(device, authority, journal=journal)
            result = recovery.execute()
        print(json.dumps(result, indent=2, sort_keys=True,
                         ensure_ascii=True, allow_nan=False))
        return 0
    except (RecoveryError, alpha.AlphaError, android.AndroidAuthorityError,
            host.HostAuthorityError, OSError, UnicodeError,
            json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
