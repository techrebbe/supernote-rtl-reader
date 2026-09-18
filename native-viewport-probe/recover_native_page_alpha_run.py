"""One-shot, report-bound cleanup for the interrupted native-page alpha run.

This is intentionally not a general recovery utility.  It accepts exactly the
failed report named below, the fixed Nomad, fixed packages, fixed APKs, and the
two disposable files created by that run.  Plan mode is read-only.  Execute
mode may refocus the already-live singleTask host once, send at most one empty
display acknowledgement, and then quarantine/delete the retained mark followed
by the retained PDF.  A canonical report-bound journal makes every execute
attempt one-shot across process restarts.

The host's status TextView is not used: on the pinned firmware its active
requestLayout loop prevents UIAutomator from reaching idle and its SurfaceView
obscures the text.  A guarded MAIN refocus produces a fresh, identity-bound
REFOCUS log without changing lifecycle state.  Every identity is rechecked
immediately after that refocus before any cleanup command is admitted.

Threat-model boundary: this one report-bound cleanup runs on an isolated
device with no adversarial or concurrent writer to either fixed hidden
quarantine directory entry.  Observed replacements fail closed, but Android's
path-based removal is not a compare-and-unlink primitive.  The helper records
this residual assumption in both plan and execute evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable, NoReturn, Protocol

import native_page_alpha_runner as alpha
import native_page_host_authority as host


RECOVERY_AUTHORITY = "native-page-alpha-report-recovery-v1"
ROTATION_LEASE_AUTHORITY = "native-page-alpha-rotation-lease-v1"
ROTATION_COMMAND_DIALECTS = {
    "acquire": ["shell", "wm", "set-user-rotation", "lock", "0"],
    "restoreUserRotation": ["shell", "wm", "set-user-rotation", "lock", "2"],
    "restoreSensor": ["shell", "wm", "set-user-rotation", "free"],
}
CANONICAL_JOURNAL_BASENAME = (
    "alpha-20260916-010621Z-12d71446-"
    "e7828a6e61291d284bf7ceb5481068c.recovery.journal.jsonl"
)
REPORT_RELATIVE = Path(
    "build/native-page-alpha-runs/"
    "alpha-20260916-010621Z-12d71446/report.json"
)
REPORT_SHA256 = "e7828a6e61291d284bf7ceb5481068ced90c4042ab322bc08ad1f552c13cd60e"
REPORT_MAX_BYTES = 128 * 1024
HELPER_MAX_BYTES = 512 * 1024
JOURNAL_MAX_BYTES = 2 * 1024 * 1024
ACTION_FAILED = alpha.HOST_PACKAGE + ".ACK_NO_FOREIGN_AFTER_FAILURE"
EVENT_FAILED = "EMPTY_ATTACH_ABORT"
EVENT_RELEASED = "DISPLAY_RELEASED"
POLL_SECONDS = 0.20
ABSENCE_POLLS = 60
PINNED_HOST_UID = 10142
PINNED_ADB_PATH = Path(
    r"C:\Users\mmkap\AppData\Local\Android\Sdk\platform-tools\adb.exe")
PINNED_ADB_SIZE = 8273560
PINNED_ADB_SHA256 = "b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f"
PINNED_TARGET_IDENTITY = {
    alpha.TARGET_PDF: (4678, 10088, 10088, 182764, 54),
    alpha.TARGET_MARK: (5756, 10088, 10088, 182765, 54),
}
QUARANTINE_PDF = (
    "/storage/emulated/0/Download/"
    ".NativeViewportRecovery-Alpha-2eeadd7.pdf"
)
QUARANTINE_MARK = QUARANTINE_PDF + ".mark"
QUARANTINES = {
    alpha.TARGET_PDF: QUARANTINE_PDF,
    alpha.TARGET_MARK: QUARANTINE_MARK,
}
DESCRIPTOR_AUTHORITY_PARKING_ONLY = "PARKING_ONLY"
DESCRIPTOR_AUTHORITY_IDLE_ZERO = "IDLE_ZERO"


def _validated_document_fd_targets(links: str) -> frozenset[str]:
    """Accept one complete, bounded toybox ``ls -l /proc/PID/fd`` wire.

    Empty or malformed command output must never become idle-zero deletion
    authority.  The retained Nomad's rooted inventory consists of an optional
    ``total`` prologue followed by one or more canonical symlink records.
    """
    if type(links) is not str:
        _fail("Document descriptor inventory is not text")
    raw = links.encode("utf-8")
    if not raw or len(raw) > alpha.MAX_TEXT_BYTES or "\x00" in links:
        _fail("Document descriptor inventory is empty, oversized, or binary")
    if any(ord(character) < 32 and character not in "\n" for character in links):
        _fail("Document descriptor inventory contains control bytes")
    lines = links.splitlines()
    if lines and re.fullmatch(r"total [0-9]+", lines[0]):
        lines = lines[1:]
    record = re.compile(
        r"^l[rwxstST-]{9} [1-9][0-9]* \S+ \S+ [0-9]+ "
        r"\S+ \S+ ([0-9]+) -> (.+)$")
    descriptor_numbers: set[str] = set()
    for line in lines:
        match = record.fullmatch(line)
        if match is None or match.group(1) in descriptor_numbers:
            _fail("Document descriptor inventory framing differs")
        descriptor_numbers.add(match.group(1))
    if not descriptor_numbers:
        _fail("Document descriptor inventory contains no symlink records")
    return alpha._document_file_targets(links)


class RecoveryError(RuntimeError):
    """The retained state is not sufficiently authoritative to mutate."""


class RotationRestoreError(RecoveryError):
    """The cleanup transaction could not prove original rotation restored."""


def _fail(message: str) -> NoReturn:
    raise RecoveryError(message)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("recovery report contains a duplicate JSON key")
        result[key] = value
    return result


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _fail(label + " topology differs from the pinned report")
    return value


def _read_pinned_regular(path: Path, maximum: int,
                         label: str) -> tuple[bytes, dict[str, Any]]:
    supplied = path.absolute()
    try:
        before = os.lstat(supplied)
    except OSError as error:
        raise RecoveryError(label + " cannot be lstat'd") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        _fail(label + " must be a non-symlink regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(supplied, flags)
    except OSError as error:
        raise RecoveryError(label + " cannot be opened without following") from error
    try:
        opened = os.fstat(descriptor)
        before_key = (before.st_dev, before.st_ino, before.st_size,
                      getattr(before, "st_mtime_ns", None))
        opened_key = (opened.st_dev, opened.st_ino, opened.st_size,
                      getattr(opened, "st_mtime_ns", None))
        if not stat.S_ISREG(opened.st_mode) or before_key != opened_key:
            _fail(label + " changed during descriptor open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                _fail(label + " is oversized")
        after = os.fstat(descriptor)
        after_key = (after.st_dev, after.st_ino, after.st_size,
                     getattr(after, "st_mtime_ns", None))
        if opened_key != after_key:
            _fail(label + " changed while reading")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        final = os.lstat(supplied)
    except OSError as error:
        raise RecoveryError(label + " path disappeared after reading") from error
    final_key = (final.st_dev, final.st_ino, final.st_size,
                 getattr(final, "st_mtime_ns", None))
    if stat.S_ISLNK(final.st_mode) or final_key != opened_key:
        _fail(label + " path was replaced while reading")
    return raw, {
        "path": str(supplied), "size": len(raw), "sha256": alpha._sha(raw),
        "device": opened.st_dev, "inode": opened.st_ino,
        "mtimeNs": getattr(opened, "st_mtime_ns", None),
    }


def _device_file(value: Any, path: str, expected_sha256: str) -> alpha.DeviceFile:
    wire = _exact_keys(value, {
        "device", "gid", "inode", "kind", "path", "sha256", "size", "uid",
    }, "retained file")
    if (wire["path"] != path or wire["kind"] != "regular file" or
            wire["sha256"] != expected_sha256 or
            any(type(wire[name]) is not int or wire[name] < 0
                for name in ("device", "gid", "inode", "size", "uid")) or
            wire["inode"] == 0 or wire["device"] == 0 or wire["size"] == 0 or
            (wire["size"], wire["uid"], wire["gid"], wire["inode"],
             wire["device"]) != PINNED_TARGET_IDENTITY[path]):
        _fail("retained file identity differs from the pinned cleanup obligation")
    return alpha.DeviceFile(
        wire["path"], wire["kind"], wire["size"], wire["uid"], wire["gid"],
        wire["inode"], wire["device"], wire["sha256"],
    )


@dataclass(frozen=True)
class ReportAuthority:
    report_path: Path
    report_sha256: str
    status: alpha.HostStatus
    host_pid: int
    host_start_ticks: int
    retained_pdf: alpha.DeviceFile
    retained_mark: alpha.DeviceFile


def load_report(path: Path, *, expected_sha256: str = REPORT_SHA256) -> ReportAuthority:
    # Do not resolve before testing the caller-supplied directory entry.  A
    # resolved-path `is_symlink()` check only examines the target and therefore
    # silently accepts a symlink.  Open once, no-follow where the platform
    # supports it, and bind all bytes to the descriptor identity.
    supplied = path.absolute()
    if supplied.name != "report.json":
        _fail("recovery authority must be the exact regular report.json")
    raw, _ = _read_pinned_regular(
        supplied, REPORT_MAX_BYTES, "recovery report")
    if not 0 < len(raw) <= REPORT_MAX_BYTES or alpha._sha(raw) != expected_sha256:
        _fail("recovery report bytes differ from the pinned failed run")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError("recovery report is not strict UTF-8 JSON") from error
    top = _exact_keys(value, {
        "authority", "authorizedSerial", "checkpoint", "cleanup",
        "cleanupErrors", "commands", "diagnosticOnly", "documentLaunchAttempted",
        "events", "fixture", "foreign", "formalAdmission", "host",
        "hostArtifact", "initialOrientation", "launchOwned",
        "manualPhysicalRotation", "packageRollbackSafe", "parking",
        "pendingHostCommand", "portraitOrientation", "prelaunchAbsenceSha256",
        "primaryError", "result", "returnedOrientation", "rotationAuthority",
        "schemaVersion", "screenshots", "startingOrientation",
        "unownedForeignCandidate",
    }, "recovery report")
    if (top["authority"] != alpha.AUTHORITY or
            top["authorizedSerial"] != alpha.AUTHORIZED_SERIAL or
            top["checkpoint"] != alpha.CHECKPOINT or
            top["schemaVersion"] != 1 or top["diagnosticOnly"] is not True or
            top["formalAdmission"] is not False or
            top["result"] != "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN" or
            top["documentLaunchAttempted"] is not False or
            top["launchOwned"] is not False or top["foreign"] is not None or
            top["unownedForeignCandidate"] is not None or
            top["pendingHostCommand"] is not None or
            top["manualPhysicalRotation"] is not False or
            top["screenshots"] != [] or top["initialOrientation"] != 0 or
            top["primaryError"] !=
            "AndroidAuthorityError: ActivityManager supervisor prologue is ambiguous"):
        _fail("failed-run state is not the exact pre-Document-launch interruption")

    cleanup = _exact_keys(top["cleanup"], {
        "displayAbsent", "disposableDescriptorsClosed", "documentGloballyAbsent",
        "documentParked", "fixtureRemoved", "hostTaskAbsent", "stockProcessAlive",
        "taskAbsent",
    }, "cleanup state")
    if any(value is not False for value in cleanup.values()):
        _fail("pinned report unexpectedly claims completed cleanup")
    if top["cleanupErrors"] != [
            "ActivityManager supervisor prologue is ambiguous",
            "disposable fixture retained because task/display cleanup is unresolved"]:
        _fail("pinned cleanup failure evidence differs")

    host_wire = _exact_keys(
        top["host"], {"displayId", "generation", "hostPid", "session"},
        "retained host")
    if (host_wire["displayId"], host_wire["generation"], host_wire["hostPid"],
            host_wire["session"]) != (
                1, 1, 8758, "b4284fd3-b5f5-4644-916a-053746e87abd"):
        _fail("retained host identity differs from the pinned failed run")
    status = alpha.HostStatus(
        host_wire["session"], host_wire["generation"], host_wire["displayId"],
        "FAILED", "report-bound status; live state must be reconciled")
    status.validate()

    artifact = _exact_keys(top["hostArtifact"], {
        "dex_sha256", "signed_apk_sha256", "signer_certificate_sha256",
        "source", "unsigned_apk_sha256", "unsigned_authority_sha256",
    }, "host artifact")
    expected_artifact = asdict(alpha._fixed_host_artifact())
    if artifact != expected_artifact:
        _fail("host artifact differs from the independent alpha pins")

    fixture = _exact_keys(top["fixture"], {
        "cleanupObligations", "foreignFixtureBound", "markSha256", "pdfSha256",
        "sourceWasModified", "uri",
    }, "fixture")
    if (fixture["foreignFixtureBound"] is not False or
            fixture["sourceWasModified"] is not False or
            fixture["pdfSha256"] != alpha.SOURCE_PDF_SHA256 or
            fixture["markSha256"] != alpha.SOURCE_MARK_SHA256 or
            fixture["uri"] != alpha.TARGET_URI):
        _fail("fixture state differs from the exact staged copy")
    obligations = fixture["cleanupObligations"]
    if type(obligations) is not dict or set(obligations) != {
            alpha.TARGET_PDF, alpha.TARGET_MARK}:
        _fail("cleanup obligation names differ")

    retained: dict[str, alpha.DeviceFile] = {}
    for source, target, expected in (
            (alpha.SOURCE_PDF, alpha.TARGET_PDF, alpha.SOURCE_PDF_SHA256),
            (alpha.SOURCE_MARK, alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256)):
        obligation = _exact_keys(obligations[target], {
            "copy_attempted", "copy_reply_proved", "expected_sha256",
            "ownership_ambiguous", "parking_absent_before_switch",
            "parking_recreated_or_replaced", "pre_copy_absence_sha256",
            "pre_parking_retained", "remove_attempted", "remove_reply_proved",
            "resolved_absent", "retained", "source", "target",
        }, "cleanup obligation")
        if (obligation["source"] != source or obligation["target"] != target or
                obligation["expected_sha256"] != expected or
                obligation["copy_attempted"] is not True or
                obligation["copy_reply_proved"] is not True or
                obligation["ownership_ambiguous"] is not False or
                obligation["remove_attempted"] is not False or
                obligation["remove_reply_proved"] is not False or
                obligation["resolved_absent"] is not False or
                type(obligation["pre_copy_absence_sha256"]) is not str or
                re.fullmatch(r"[0-9a-f]{64}",
                             obligation["pre_copy_absence_sha256"]) is None):
            _fail("cleanup obligation is not an exact unremoved staged copy")
        retained[target] = _device_file(obligation["retained"], target, expected)

    parking = _exact_keys(top["parking"], {
        "bound", "path", "persistentNeverRemoved", "retainedIntent", "sha256",
        "switchAttempted", "uiWitness", "uri",
    }, "parking")
    if (parking["bound"] is not False or parking["switchAttempted"] is not False or
            parking["retainedIntent"] is not None or parking["uiWitness"] is not None or
            parking["path"] != alpha.PARKING_PDF or
            parking["uri"] != alpha.PARKING_URI or
            parking["sha256"] != alpha.SOURCE_PDF_SHA256 or
            parking["persistentNeverRemoved"] is not True):
        _fail("parking authority differs")

    events = top["events"]
    if type(events) is not list or [event.get("name") for event in events] != [
            "parking_pdf_verified", "preflight_complete", "fixture_staged",
            "host_ready"]:
        _fail("failed-run event sequence differs")
    ready = events[-1]
    if (ready.get("session"), ready.get("generation"), ready.get("displayId"),
            ready.get("hostPid"), ready.get("hostStartTicks")) != (
                status.session, status.generation, status.display_id, 8758, "589785"):
        _fail("host_ready evidence differs")

    commands = top["commands"]
    if type(commands) is not list or not commands:
        _fail("failed-run command ledger is absent")
    start_count = 0
    forbidden_actions = (ACTION_FAILED,)
    for command in commands:
        if type(command) is not dict or type(command.get("argv")) is not list:
            _fail("failed-run command ledger is malformed")
        argv = command["argv"]
        if any(type(token) is not str for token in argv):
            _fail("failed-run command argv is malformed")
        if command.get("operation") == "start_host":
            start_count += 1
        joined = "\0".join(argv)
        if (any(action in joined for action in forbidden_actions) or
                (command.get("operation", "").startswith("host_") and
                 command.get("operation") != "host_logs") or
                command.get("operation", "").startswith("remove_") or
                alpha.DOCUMENT_COMPONENT in joined):
            _fail("report contains a cleanup or Document command attempt")
    if start_count != 1:
        _fail("report must contain one exact host start")

    return ReportAuthority(
        supplied, expected_sha256, status, 8758, 589785,
        retained[alpha.TARGET_PDF], retained[alpha.TARGET_MARK])


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
    def window_displays(self) -> bytes: ...
    def displays(self) -> bytes: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def lock_rotation_zero(self) -> Any: ...
    def lock_rotation_two(self) -> Any: ...
    def free_rotation(self) -> Any: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def recovery_stat_file(self, path: str, *,
                           absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def start_host(self) -> Any: ...
    def host_logs(self, pid: int) -> str: ...
    def send_recovery(self, status: alpha.HostStatus, action: str,
                      evidence_sha256: str) -> Any: ...
    def move_to_quarantine(self, source: str, target: str) -> Any: ...
    def remove_quarantine(self, path: str) -> Any: ...


class Journal(Protocol):
    def record(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]: ...
    @property
    def count(self) -> int: ...
    @property
    def head_hash(self) -> str: ...


class RecoveryNomad(alpha.AdbNomad):
    """Adds only the one fixed failed-session cleanup action."""

    def adb_authority(self) -> dict[str, Any]:
        path = Path(self.adb).absolute()
        if path != PINNED_ADB_PATH:
            _fail("adb executable path differs from the exact host pin")
        raw, authority = _read_pinned_regular(
            path, PINNED_ADB_SIZE, "adb executable")
        if len(raw) != PINNED_ADB_SIZE or alpha._sha(raw) != PINNED_ADB_SHA256:
            _fail("adb executable bytes differ from the exact host pin")
        return authority

    def rotation_settings(self) -> tuple[str, str]:
        """Read the two fixed persisted settings despite alpha's write ban.

        The generic alpha transport deliberately rejects the ``settings``
        token because that runner owns rotation writes.  Recovery needs no
        write authority, so these two literal read-only commands are rendered
        here without any caller-controlled namespace/key/value.
        """
        values: list[str] = []
        for key in ("accelerometer_rotation", "user_rotation"):
            argv = (self.adb, "-s", alpha.AUTHORIZED_SERIAL, "shell",
                    "settings", "get", "system", key)
            started = time.monotonic_ns()
            try:
                completed = self._executor(
                    argv, capture_output=True, timeout=alpha.STEP_TIMEOUT_SECONDS,
                    check=False)
            except subprocess.TimeoutExpired as error:
                self.history.append({
                    "operation": "read_rotation_" + key,
                    "argv": list(argv), "startedNs": str(started),
                    "finishedNs": str(time.monotonic_ns()),
                    "returncode": None, "timeout": True,
                })
                raise RecoveryError(
                    "persisted rotation read timed out") from error
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
                "stdoutSha256": alpha._sha(stdout),
                "stderrSha256": alpha._sha(stderr),
            })
            self._require_zero(result)
            values.append(alpha._decode_text(stdout, result.operation).strip())
        return values[0], values[1]

    def lock_rotation_zero(self) -> alpha.CommandResult:
        """Acquire the one literal portrait rotation lease.

        No argument is accepted deliberately: callers cannot turn this into a
        general WindowManager command capability.
        """
        result = self._invoke(
            "rotation_lock_zero",
            ("shell", "wm", "set-user-rotation", "lock", "0"))
        self._require_zero(result)
        return result

    def lock_rotation_two(self) -> alpha.CommandResult:
        """Restore the report's exact persisted user rotation, literally 2."""
        result = self._invoke(
            "rotation_restore_lock_two",
            ("shell", "wm", "set-user-rotation", "lock", "2"))
        self._require_zero(result)
        return result

    def free_rotation(self) -> alpha.CommandResult:
        """Restore sensor control; this exact command has no value operand."""
        result = self._invoke(
            "rotation_restore_free",
            ("shell", "wm", "set-user-rotation", "free"))
        self._require_zero(result)
        return result

    def send_recovery(self, status: alpha.HostStatus, action: str,
                      evidence_sha256: str) -> alpha.CommandResult:
        status.validate()
        if action != ACTION_FAILED:
            _fail("recovery action escaped the one closed failed-host action")
        if re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None:
            _fail("absence evidence is not one canonical SHA-256")
        result = self._invoke(
            "recovery_" + action.rsplit(".", 1)[-1].lower(), (
                "shell", "am", "start", "--user", "0", "--display", "0",
                "-a", action, "-n", alpha.HOST_COMPONENT,
                "--es", "session", status.session,
                "--el", "generation", str(status.generation),
                "--ei", "display", str(status.display_id),
                "--el", "sequence", "1",
                "--es", "absenceEvidenceSha256", evidence_sha256,
            ))
        self._require_zero(result)
        return result

    def recovery_stat_file(self, path: str, *,
                           absent_ok: bool = False) -> alpha.DeviceFile | None:
        if path not in {QUARANTINE_PDF, QUARANTINE_MARK}:
            _fail("recovery stat escaped the two fixed quarantine paths")
        result = self._invoke(
            "recovery_stat_" + Path(path).name,
            ("shell", "stat", "-c", "%F,%s,%u,%g,%i,%d", path))
        if result.returncode != 0:
            combined = alpha._decode_text(
                result.stdout + b"\n" + result.stderr, result.operation)
            if absent_ok and "No such file or directory" in combined:
                return None
            self._require_zero(result)
        output = alpha._decode_text(result.stdout, result.operation).strip()
        fields = output.split(",")
        if (len(fields) != 6 or fields[0] != "regular file" or
                any(re.fullmatch(r"0|[1-9][0-9]{0,19}", item) is None
                    for item in fields[1:])):
            _fail("quarantine stat identity differs")
        size, uid, gid, inode, device = map(int, fields[1:])
        digest = self.text(
            "recovery_sha256_" + Path(path).name,
            ("shell", "sha256sum", path)).strip()
        match = re.fullmatch(r"([0-9a-f]{64})\s+" + re.escape(path), digest)
        if match is None:
            _fail("quarantine sha256 output differs")
        return alpha.DeviceFile(
            path, fields[0], size, uid, gid, inode, device, match.group(1))

    def move_to_quarantine(self, source: str, target: str) -> alpha.CommandResult:
        if QUARANTINES.get(source) != target:
            _fail("quarantine move escaped the fixed target mapping")
        result = self._invoke(
            "quarantine_" + Path(source).name,
            ("shell", "mv", "-n", "-T", "-v", source, target))
        self._require_zero(result)
        # The pinned Nomad toybox was probed read-only with disposable names:
        # even `-v` emits no output on success.  Thus bytes cannot distinguish
        # success from `-n` refusing a raced-in destination; only the post-move
        # source absence plus exact destination inode/device/hash can do so.
        if result.stdout or result.stderr:
            _fail("quarantine move returned an unpinned output dialect")
        return result

    def remove_quarantine(self, path: str) -> alpha.CommandResult:
        if path not in {QUARANTINE_PDF, QUARANTINE_MARK}:
            _fail("quarantine removal escaped the fixed path set")
        result = self._invoke(
            "remove_quarantine_" + Path(path).name,
            ("shell", "rm", "-f", path))
        self._require_zero(result)
        return result


def _package_uid(raw: str, package: str) -> int:
    if type(raw) is not str or package not in raw:
        _fail("host package dump does not identify the pinned package")
    matches = re.findall(r"^\s*userId=([1-9][0-9]{0,8})\s*$", raw, re.MULTILINE)
    if len(matches) != 1:
        _fail("host package UID is absent or ambiguous")
    return int(matches[0])


def _identity_lines(logs: str, status: alpha.HostStatus) -> list[str]:
    if type(logs) is not str or len(logs.encode("utf-8")) > alpha.MAX_TEXT_BYTES:
        _fail("host log evidence is malformed or oversized")
    status.validate()
    selected: list[str] = []
    for line in logs.splitlines():
        sessions = re.findall(
            r"(?:^|\s)session=([^\s]+)(?=\s|$)", line)
        generations = re.findall(
            r"(?:^|\s)generation=([^\s]+)(?=\s|$)", line)
        if status.session not in sessions:
            continue
        if (sessions != [status.session] or
                generations != [str(status.generation)]):
            _fail("identity-bound host log has duplicate or conflicting identity tokens")
        selected.append(line.strip())
    return selected


def _attempted_abort(lines: list[str]) -> bool:
    return bool(_cleanup_event_records(lines))


def _cleanup_event_records(
        lines: list[str]) -> list[tuple[str, tuple[str, ...]]]:
    pattern = re.compile(
        r"\b(?:EMPTY_[A-Z0-9_]*ABORT[A-Z0-9_]*|"
        r"DISPLAY_RELEASE[A-Z0-9_]*|RELEASE_FAILED|FAILED_RELEASE|"
        r"EMERGENCY_RELEASE|EMERGENCY_DESTROY)\b")
    records: list[tuple[str, tuple[str, ...]]] = []
    for line in lines:
        tokens = tuple(pattern.findall(line))
        if tokens:
            records.append((line, tokens))
    return records


def _exact_log_token(line: str, key: str, expected: str) -> bool:
    if (type(line) is not str or re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key) is None or
            type(expected) is not str or not expected or any(ch.isspace() for ch in expected)):
        _fail("internal exact log-token request is malformed")
    values = re.findall(
        r"(?:^|\s)" + re.escape(key) + r"=([^\s]+)(?=\s|$)", line)
    return values == [expected]


def _validate_prior_failed_cleanup(lines: list[str]) -> tuple[str, str, str]:
    records = _cleanup_event_records(lines)
    if ([tokens for _, tokens in records] !=
            [(EVENT_FAILED,), (EVENT_RELEASED,)]):
        _fail("prior cleanup is missing, duplicated, or mixed")
    abort, release = records[0][0], records[1][0]
    digests = re.findall(
        r"(?:^|\s)absenceEvidenceSha256=([^\s]+)(?=\s|$)", abort)
    if (len(digests) != 1 or
            re.fullmatch(r"[0-9a-f]{64}", digests[0]) is None):
        _fail("prior failed-host abort lacks exact absence evidence")
    if (not _exact_log_token(release, "display", "1") or
            not _exact_log_token(
                release, "mode", "acknowledged_cleanup")):
        _fail("prior display release fields differ")
    return abort, release, digests[0]


def _reject_protocol_drift(lines: list[str]) -> None:
    forbidden = (
        "COMMAND_IGNORED", "COMMAND_REJECTED", "COMMAND_DEFERRED",
        "COMMAND_RESUMED", "READY", "PLACEMENT_REQUESTED",
        "WAIT_FOREIGN_DESTROY", "FOREIGN_DESTROYED", "ATTACH_REPLAY",
        "PLACEMENT_REPLAY", "CLOSE_REPLAY", "DESTROY_REPLAY",
    )
    for line in lines:
        if any(re.search(r"\b" + event + r"\b", line) for event in forbidden):
            _fail("host log contains an intervening command/foreign-state event")
        match = re.search(r"\bREFOCUS\b.*\breadiness=([A-Z_]+)(?:\s|$)", line)
        if match is not None and match.group(1) != "FAILED":
            _fail("host log contains a non-FAILED refocus state")
    for _, tokens in _cleanup_event_records(lines):
        if any(token not in {EVENT_FAILED, EVENT_RELEASED}
               for token in tokens):
            _fail("host log contains a non-closed cleanup event")


@dataclass(frozen=True)
class HostScopeIdentity:
    task_id: int
    task_token: str
    activity_token: str
    window_token: str
    window_session_token: str
    activity_display_id: int
    window_display_id: int
    component: str
    resumed: bool
    visible: bool
    focused: bool
    activity_authority_lines: tuple[str, ...]
    window_authority_lines: tuple[str, ...]


@dataclass(frozen=True)
class VirtualDisplayIdentity:
    display_id: int
    layer_stack: int
    name: str
    unique_id: str
    owner_package: str
    owner_uid: int
    display_token: str
    surface_token: str
    device_authority_lines: tuple[str, ...]
    logical_authority_lines: tuple[str, ...]


def _decode_bounded(raw: bytes, label: str, maximum: int) -> str:
    if type(raw) is not bytes or not raw or len(raw) > maximum or b"\x00" in raw:
        _fail(label + " bytes are absent, oversized, or contain NUL")
    try:
        return raw.decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeError as error:
        raise RecoveryError(label + " is not strict UTF-8") from error


def _reject_host_package_structural_residue(
        text: str, allowed: tuple[re.Pattern[str], ...], label: str) -> None:
    """Require every host-package task/activity/window record to be consumed.

    The strict authority parsers below select the expected component dialect.
    This deliberately broader pass prevents an alternate user/component or a
    malformed record with omitted trailing fields from simply falling outside
    those selectors and becoming invisible residue.
    """
    package = re.compile(
        r"(?<![A-Za-z0-9_.])" + re.escape(alpha.HOST_PACKAGE) +
        r"(?![A-Za-z0-9_.])")
    structural_start = re.compile(
        r"(?<![A-Za-z0-9_])(?:Task|ActivityRecord|Window)\{")
    structural = re.compile(
        r"(?<![A-Za-z0-9_])(?:Task|ActivityRecord|Window)\{[^{}\n]*\}")
    for line in text.splitlines():
        if package.search(line) is None:
            continue
        starts = list(structural_start.finditer(line))
        if not starts:
            # Detailed ActivityRecord blocks contain ordinary package-bearing
            # metadata (packageName/processName, affinity, intent/component,
            # baseDir/dataDir, ProcessRecord and taskAffinity).  Those are not
            # independent task/activity/window identities and are deliberately
            # outside this structural identity scanner.
            continue
        matches = list(structural.finditer(line))
        if ([item.start() for item in starts] !=
                [item.start() for item in matches]):
            _fail(label + " contains malformed host-package structural residue")
        remainder = line
        for match in reversed(matches):
            record = match.group(0)
            if package.search(record) is None:
                continue
            if (len(package.findall(record)) != 1 or
                    not any(pattern.fullmatch(record) is not None
                            for pattern in allowed)):
                _fail(label + " contains an alternate host-package record")
            remainder = remainder[:match.start()] + remainder[match.end():]
        if package.search(remainder) is not None:
            _fail(label + " contains malformed host-package structural residue")


def _host_scope_identity(activities: bytes, windows: bytes,
                         host_uid: int, host_pid: int) -> HostScopeIdentity:
    """Extract one exact, live host task/activity/window on physical display 0.

    The retained report did not capture framework tokens.  They therefore are
    not constants: two pre-refocus observations establish the live semantic
    identity and every post-refocus observation must retain it exactly.
    """
    activity_text = _decode_bounded(
        activities, "ActivityManager", alpha.MAX_TEXT_BYTES)
    if activity_text.count("ActivityStackSupervisor state:") != 1:
        _fail("ActivityManager supervisor boundary is absent or ambiguous")
    canonical, supervisor = activity_text.split(
        "ActivityStackSupervisor state:", 1)
    component = (r"(?:" + re.escape(alpha.HOST_COMPONENT) + r"|" +
                 re.escape(alpha.HOST_PACKAGE + "/.NativePageHostActivity") + r")")
    task_pattern = re.compile(
        r"^\s*\* Task\{([0-9a-f]{1,64}) #([1-9][0-9]{0,9}) "
        r"visible=true\b[^\n]*\bA=" + re.escape(str(host_uid)) + r":" +
        re.escape(alpha.HOST_PACKAGE) +
        r"\b[^\n]*\bStackId=([1-9][0-9]{0,9})\b[^\n]*\bsz=1\}\s*$",
        re.MULTILINE)
    tasks = list(task_pattern.finditer(canonical))
    if len(tasks) != 1 or tasks[0].group(2) != tasks[0].group(3):
        _fail("host task identity is absent, duplicate, invisible, or inconsistent")
    # The firmware repeats the same Task object in canonical detail lines such
    # as ``rootOfTask=true task=Task{...}``.  Only the leading ``* Task`` line
    # is authoritative for display containment, but identical structural
    # references are legitimate.  The all-host-task identity check and the
    # structural-residue pass below consume every repeated record and still
    # reject a different token/id, alternate component/user, or malformed
    # package-bearing Task record.
    task_token, task_text = tasks[0].group(1), tasks[0].group(2)
    task_id = int(task_text)

    display_headers = list(re.finditer(
        r"^Display #([0-9]+) \(activities from top to bottom\):\s*$",
        canonical, re.MULTILINE))
    if not display_headers:
        _fail("ActivityManager display headers are absent")
    containing = [
        int(item.group(1)) for index, item in enumerate(display_headers)
        if item.end() <= tasks[0].start() <
        (display_headers[index + 1].start()
         if index + 1 < len(display_headers) else len(canonical))
    ]
    if containing != [0]:
        _fail("host task is not uniquely scoped to physical display 0")

    resumed_pattern = re.compile(
        r"^\s*mResumedActivity: ActivityRecord\{([0-9a-f]{1,64}) u0 " +
        component + r" t" + re.escape(task_text) + r"\}\s*$", re.MULTILINE)
    resumed = list(resumed_pattern.finditer(canonical))
    if len(resumed) != 1:
        _fail("host resumed activity identity is absent or ambiguous")
    activity_token = resumed[0].group(1)
    hist_pattern = re.compile(
        r"^\s*\* Hist #[0-9]+: ActivityRecord\{" +
        re.escape(activity_token) + r" u0 " + component + r" t" +
        re.escape(task_text) + r"\}\s*$", re.MULTILINE)
    histories = list(hist_pattern.finditer(canonical))
    if len(histories) != 1:
        _fail("host history activity does not uniquely match the resumed activity")
    # The authoritative activity remains exactly one mResumedActivity plus
    # exactly one matching Hist record.  Firmware detail fields legitimately
    # repeat that same ActivityRecord (for example in ``Activities=[...]``),
    # so raw package-bearing line counts are not activity cardinality.  The
    # all-record identity check and structural-residue pass below consume each
    # repeated record and reject a different user/token/task/component or any
    # malformed package-bearing ActivityRecord.

    all_host_tasks = re.findall(
        r"Task\{([0-9a-f]{1,64}) #([1-9][0-9]{0,9})[^\n}]*" +
        re.escape(alpha.HOST_PACKAGE) + r"[^\n}]*\}", activity_text)
    if (not all_host_tasks or any(
            token != task_token or int(identifier) != task_id
            for token, identifier in all_host_tasks)):
        _fail("ActivityManager contains another host-package task identity")
    all_host_activities = re.findall(
        r"ActivityRecord\{([0-9a-f]{1,64}) u0 (" +
        re.escape(alpha.HOST_PACKAGE) +
        r"/(?:[^\s}]+)) t([1-9][0-9]{0,9})\}", activity_text)
    allowed_components = {
        alpha.HOST_COMPONENT,
        alpha.HOST_PACKAGE + "/.NativePageHostActivity",
    }
    for line in activity_text.splitlines():
        if "Task{" not in line or alpha.HOST_PACKAGE not in line:
            continue
        task_components = re.findall(
            re.escape(alpha.HOST_PACKAGE) + r"/[^\s}]+", line)
        if any(value not in allowed_components for value in task_components):
            _fail("ActivityManager host task names an alternate component")
    if (not all_host_activities or any(
            token != activity_token or activity_component not in allowed_components or
            int(identifier) != task_id
            for token, activity_component, identifier in all_host_activities)):
        _fail("ActivityManager contains another host-package activity identity")

    window_text = _decode_bounded(windows, "WindowManager", alpha.MAX_TEXT_BYTES)
    header_pattern = re.compile(
        r"^\s*Window #[0-9]+ Window\{([0-9a-f]{1,64}) u0 " +
        component + r"\}:?\s*$", re.MULTILINE)
    headers = list(header_pattern.finditer(window_text))
    if len(headers) != 1:
        _fail("host window identity is absent or ambiguous")
    window_token = headers[0].group(1)
    package_windows = re.findall(
        r"^\s*Window #[0-9]+ Window\{([0-9a-f]{1,64}) u0 (" +
        re.escape(alpha.HOST_PACKAGE) + r"/[^\s}]+)\}:?\s*$",
        window_text, re.MULTILINE)
    if (package_windows != [(window_token, alpha.HOST_COMPONENT)] and
            package_windows != [(
                window_token,
                alpha.HOST_PACKAGE + "/.NativePageHostActivity")]):
        _fail("additional or alternate host-package window exists")
    next_header = re.search(r"^\s*Window #[0-9]+ Window\{", window_text[headers[0].end():],
                            re.MULTILINE)
    block_end = (headers[0].end() + next_header.start()
                 if next_header is not None else len(window_text))
    block = window_text[headers[0].end():block_end]
    session_pattern = re.compile(
        r"^\s*mDisplayId=(0) rootTaskId=(" + re.escape(task_text) +
        r") mSession=Session\{([0-9a-f]{1,64}) " +
        re.escape(str(host_pid)) + r":u0a" +
        re.escape(str(host_uid)) +
        r"\} mClient=android\.os\.BinderProxy@[0-9a-f]{1,64}\s*$",
        re.MULTILINE)
    sessions = list(session_pattern.finditer(block))
    if len(sessions) != 1:
        _fail("host window display/task/session owner identity differs")
    window_session_token = sessions[0].group(3)
    token_pattern = re.compile(
        r"^\s*mBaseLayer=[0-9]+ mSubLayer=-?[0-9]+\s+"
        r"mToken=ActivityRecord\{" + re.escape(activity_token) +
        r" u0 " + component + r" t" + re.escape(task_text) + r"\}\s*$",
        re.MULTILINE)
    activity_record_pattern = re.compile(
        r"^\s*mActivityRecord=ActivityRecord\{" +
        re.escape(activity_token) + r" u0 " + component + r" t" +
        re.escape(task_text) + r"\}\s*$", re.MULTILINE)
    token_lines = list(token_pattern.finditer(block))
    activity_record_lines = list(activity_record_pattern.finditer(block))
    if len(token_lines) != 1 or len(activity_record_lines) != 1:
        _fail("host window is not doubly bound to the resumed activity token")
    window_activities = re.findall(
        r"ActivityRecord\{([0-9a-f]{1,64}) u0 (" +
        re.escape(alpha.HOST_PACKAGE) +
        r"/[^\s}]+) t([1-9][0-9]{0,9})\}", window_text)
    if (not window_activities or any(
            token != activity_token or activity_component not in allowed_components or
            int(identifier) != task_id
            for token, activity_component, identifier in window_activities)):
        _fail("WindowManager contains another host-package activity identity")
    surface = list(re.finditer(
        r"^\s*mHasSurface=true isReadyForDisplay\(\)=true "
        r"mWindowRemovalAllowed=false\s*$", block, re.MULTILINE))
    on_screen = list(re.finditer(r"^\s*isOnScreen=true\s*$", block, re.MULTILINE))
    visible = list(re.finditer(r"^\s*isVisible=true\s*$", block, re.MULTILINE))
    if len(surface) != 1 or len(on_screen) != 1 or len(visible) != 1:
        _fail("host window surface/visibility authority differs")

    summary_pattern = re.compile(
        r"^\s*Display: mDisplayId=([0-9]+) stacks=([0-9]+)\s*$",
        re.MULTILINE)
    summaries = list(summary_pattern.finditer(supervisor))
    if [int(item.group(1)) for item in summaries] != [0, 1]:
        _fail("supervisor focus display summaries differ from exact 0/1 scope")
    segments: dict[int, str] = {}
    for index, item in enumerate(summaries):
        end = summaries[index + 1].start() if index + 1 < len(summaries) else len(supervisor)
        segments[int(item.group(1))] = supervisor[item.end():end]
    focus_pattern = re.compile(
        r"^\s*mCurrentFocus=Window\{" + re.escape(window_token) +
        r" u0 " + component + r"\}\s*$", re.MULTILINE)
    focused_app_pattern = re.compile(
        r"^\s*mFocusedApp=ActivityRecord\{" + re.escape(activity_token) +
        r" u0 " + component + r" t" + re.escape(task_text) + r"\}\s*$",
        re.MULTILINE)
    host_focus = list(focus_pattern.finditer(segments[0]))
    host_app = list(focused_app_pattern.finditer(segments[0]))
    null_focus = re.findall(r"^\s*mCurrentFocus=null\s*$", segments[1], re.MULTILINE)
    null_app = re.findall(r"^\s*mFocusedApp=null\s*$", segments[1], re.MULTILINE)
    all_focus_lines = re.findall(
        r"^\s*m(?:CurrentFocus|FocusedApp)=.*$", supervisor, re.MULTILINE)
    if (len(host_focus) != 1 or len(host_app) != 1 or
            len(null_focus) != 1 or len(null_app) != 1 or
            len(all_focus_lines) != 4):
        _fail("display-scoped supervisor focus/app pairs differ")

    allowed_task_record = re.compile(
        r"Task\{" + re.escape(task_token) + r" #" + re.escape(task_text) +
        r" (?=[^}]*\bA=" + re.escape(str(host_uid)) + r":" +
        re.escape(alpha.HOST_PACKAGE) + r"(?=\s|}))[^}]*\}")
    allowed_activity_record = re.compile(
        r"ActivityRecord\{" + re.escape(activity_token) + r" u0 " +
        component + r" t" + re.escape(task_text) + r"\}")
    allowed_window_record = re.compile(
        r"Window\{" + re.escape(window_token) + r" u0 " + component + r"\}")
    _reject_host_package_structural_residue(
        activity_text,
        (allowed_task_record, allowed_activity_record, allowed_window_record),
        "ActivityManager")
    _reject_host_package_structural_residue(
        window_text, (allowed_activity_record, allowed_window_record),
        "WindowManager")

    activity_lines = (
        tasks[0].group(0).strip(), resumed[0].group(0).strip(),
        histories[0].group(0).strip(), host_focus[0].group(0).strip(),
        host_app[0].group(0).strip(),
        "mCurrentFocus=null", "mFocusedApp=null")
    window_lines = (
        headers[0].group(0).strip(),
        sessions[0].group(0).strip(), token_lines[0].group(0).strip(),
        activity_record_lines[0].group(0).strip(),
        surface[0].group(0).strip(), on_screen[0].group(0).strip(),
        visible[0].group(0).strip(),
    )
    return HostScopeIdentity(
        task_id, task_token, activity_token, window_token,
        window_session_token, 0, 0,
        alpha.HOST_COMPONENT, True, True, True,
        activity_lines, window_lines)


def _retained_virtual_display_identity(
        raw: bytes, status: alpha.HostStatus,
        host_uid: int) -> VirtualDisplayIdentity:
    """Bind the one retained VirtualDisplay device to logical display 1.

    DisplayManager repeats a legitimate display name in its device record,
    primary-device reference, BaseDisplayInfo and OverrideDisplayInfo.  Raw
    occurrence counts therefore are not topology.  This parser instead proves
    one exact virtual-device record and one exact logical-display record, then
    requires every repeated reference to carry the same name, unique ID,
    owner, display ID and layer stack.
    """
    status.validate()
    if status.display_id != 1 or host_uid != PINNED_HOST_UID:
        _fail("retained virtual-display request differs from the report pin")
    text = _decode_bounded(raw, "DisplayManager", alpha.MAX_TEXT_BYTES)
    name = status.display_name
    unique_id = (
        "virtual:" + alpha.HOST_PACKAGE + "," + str(host_uid) + "," +
        name + ",0")

    device_pattern = re.compile(
        r'^([^\n]*DisplayDeviceInfo\{"([^"\n]+)": '
        r'uniqueId="([^"\n]+)", ([^\n]*)\})\s*$', re.MULTILINE)
    device_headers = list(device_pattern.finditer(text))
    matching_name = [item for item in device_headers if item.group(2) == name]
    matching_unique = [item for item in device_headers
                       if item.group(3) == unique_id]
    if (len(matching_name) != 1 or len(matching_unique) != 1 or
            matching_name[0] is not matching_unique[0]):
        _fail("retained virtual display device identity is absent or ambiguous")
    device = matching_name[0]
    raw_device_lines = [line for line in text.splitlines()
                        if "DisplayDeviceInfo{" in line]
    host_owned_device_lines = [
        line for line in raw_device_lines
        if (name in line or
            ("virtual:" + alpha.HOST_PACKAGE + ",") in line or
            ("owner " + alpha.HOST_PACKAGE) in line)]
    if host_owned_device_lines != [device.group(1)]:
        _fail("additional or malformed host-owned virtual display device exists")
    expected_device_line = (
        '    mSupportedColorModes=[0]  DisplayDeviceInfo{"' + name +
        '": uniqueId="' + unique_id +
        '", 1404 x 1872, modeId 2, defaultModeId 2, supportedModes '
        '[{id=2, width=1404, height=1872, fps=60.0}], colorMode 0, '
        'supportedColorModes [0], HdrCapabilities null, allmSupported false, '
        'gameContentTypeSupported false, density 300, 300.0 x 300.0 dpi, '
        'appVsyncOff 0, presDeadline 16666666, touch NONE, rotation 0, '
        'type VIRTUAL, deviceProductInfo null, state ON, owner ' +
        alpha.HOST_PACKAGE + ' (uid ' + str(host_uid) +
        '), FLAG_OWN_CONTENT_ONLY}')
    if device.group(1) != expected_device_line:
        _fail("retained virtual display device facts differ")

    logical_pattern = re.compile(
        r'(?ms)^  Display ([0-9]+):\s*\n(.*?)(?=^  Display [0-9]+:|\Z)')
    logical_blocks = list(logical_pattern.finditer(text))
    matching_logical = [item for item in logical_blocks
                        if int(item.group(1)) == status.display_id]
    if len(matching_logical) != 1:
        _fail("retained logical display header is absent or ambiguous")
    logical = matching_logical[0]
    host_owned_logical = [
        item for item in logical_blocks
        if (name in item.group(0) or unique_id in item.group(0) or
            alpha.HOST_PACKAGE in item.group(0))]
    if host_owned_logical != [logical]:
        _fail("additional or malformed host-owned logical display exists")
    for item in logical_blocks:
        if item is not logical and (name in item.group(0) or
                                    unique_id in item.group(0)):
            _fail("retained virtual display identity is borrowed by another display")

    # The device record ends at the next device header or the retained logical
    # display header.  This prevents fields from a neighboring device from
    # satisfying the retained device's proof.
    block_candidates = [item.start() for item in device_headers
                        if item.start() > device.start()]
    block_candidates.extend(item.start() for item in logical_blocks
                            if item.start() > device.start())
    device_end = min(block_candidates) if block_candidates else len(text)
    device_block = text[device.end():device_end]

    def exact_field(block: str, key: str, expected: str, label: str) -> str:
        matches = [line for line in block.splitlines()
                   if line.lstrip().startswith(key + "=")]
        if matches != [expected]:
            _fail(label + " is absent, duplicated, or differs")
        return expected.strip()

    device_lines = [device.group(1).strip()]
    for key, expected, label in (
            ("mAdapter", "mAdapter=VirtualDisplayAdapter",
             "virtual-display adapter"),
            ("mUniqueId", "    mUniqueId=" + unique_id,
             "virtual-display unique ID"),
            ("mCurrentLayerStack", "    mCurrentLayerStack=1",
             "virtual-display layer stack"),
            ("mCurrentOrientation", "    mCurrentOrientation=0",
             "virtual-display orientation"),
            ("mCurrentLayerStackRect",
             "    mCurrentLayerStackRect=Rect(0, 0 - 1404, 1872)",
             "virtual-display layer rectangle"),
            ("mCurrentDisplayRect",
             "    mCurrentDisplayRect=Rect(0, 0 - 1404, 1872)",
             "virtual-display destination rectangle"),
            ("mFlags", "    mFlags=265", "virtual-display flags"),
            ("mDisplayState", "    mDisplayState=ON",
             "virtual-display state"),
            ("mStopped", "    mStopped=false",
             "virtual-display stopped state"),
            ("mDisplayIdToMirror", "    mDisplayIdToMirror=0",
             "virtual-display mirror binding")):
        device_lines.append(exact_field(
            device_block, key, expected, label))

    token_lines = re.findall(
        r'^\s*mDisplayToken=android\.os\.BinderProxy@([0-9a-f]{1,64})\s*$',
        device_block, re.MULTILINE)
    all_token_lines = re.findall(
        r'^\s*mDisplayToken=.*$', device_block, re.MULTILINE)
    if len(token_lines) != 1 or len(all_token_lines) != 1:
        _fail("virtual-display token is absent, duplicated, or malformed")
    surface_lines = re.findall(
        r'^\s*mCurrentSurface=Surface\(name=null\)/@(0x[0-9a-f]{1,64})\s*$',
        device_block, re.MULTILINE)
    all_surface_lines = re.findall(
        r'^\s*mCurrentSurface=.*$', device_block, re.MULTILINE)
    if len(surface_lines) != 1 or len(all_surface_lines) != 1:
        _fail("virtual-display surface is absent, duplicated, or malformed")
    device_lines.extend((
        "mDisplayToken=android.os.BinderProxy@" + token_lines[0],
        "mCurrentSurface=Surface(name=null)/@" + surface_lines[0]))

    logical_block = logical.group(2)
    base_line = (
        '    mBaseDisplayInfo=DisplayInfo{"' + name +
        '", displayId 1, real 1404 x 1872, largest app 1404 x 1872, '
        'smallest app 1404 x 1872, appVsyncOff 0, presDeadline 16666666, '
        'mode 2, defaultMode 2, modes [{id=2, width=1404, height=1872, '
        'fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported '
        'false, rotation 0, state ON, type VIRTUAL, uniqueId "' + unique_id +
        '", app 1404 x 1872, density 300 (300.0 x 300.0) dpi, layerStack 1, '
        'colorMode 0, supportedColorModes [0], deviceProductInfo null, owner ' +
        alpha.HOST_PACKAGE + ' (uid ' + str(host_uid) + '), removeMode 1}')
    override_line = (
        '    mOverrideDisplayInfo=DisplayInfo{"' + name +
        '", displayId 1, real 1404 x 1872, largest app 1872 x 1872, '
        'smallest app 1404 x 1404, appVsyncOff 0, presDeadline 16666666, '
        'mode 2, defaultMode 2, modes [{id=2, width=1404, height=1872, '
        'fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported '
        'false, rotation 0, state ON, type VIRTUAL, uniqueId "' + unique_id +
        '", app 1404 x 1872, density 300 (300.0 x 300.0) dpi, layerStack 1, '
        'colorMode 0, supportedColorModes [0], deviceProductInfo null, owner ' +
        alpha.HOST_PACKAGE + ' (uid ' + str(host_uid) + '), removeMode 1}')
    logical_lines = ["Display 1:"]
    for key, expected, label in (
            ("mDisplayId", "    mDisplayId=1", "logical display ID"),
            ("mLayerStack", "    mLayerStack=1",
             "logical display layer stack"),
            ("mHasContent", "    mHasContent=false",
             "logical display content state"),
            ("mDesiredDisplayModeSpecs",
             "    mDesiredDisplayModeSpecs={baseModeId=2 "
             "primaryRefreshRateRange=[0 60] appRequestRefreshRateRange=[0 Infinity]}",
             "logical display mode"),
            ("mRequestedColorMode", "    mRequestedColorMode=0",
             "logical display color mode"),
            ("mDisplayOffset", "    mDisplayOffset=(0, 0)",
             "logical display offset"),
            ("mDisplayScalingDisabled", "    mDisplayScalingDisabled=false",
             "logical display scaling"),
            ("mPrimaryDisplayDevice", "    mPrimaryDisplayDevice=" + name,
             "logical display primary device"),
            ("mBaseDisplayInfo", base_line, "logical base display info"),
            ("mOverrideDisplayInfo", override_line,
             "logical override display info"),
            ("mRequestedMinimalPostProcessing",
             "    mRequestedMinimalPostProcessing=false",
             "logical minimal-post-processing state")):
        logical_lines.append(exact_field(
            logical_block, key, expected, label))

    return VirtualDisplayIdentity(
        status.display_id, 1, name, unique_id, alpha.HOST_PACKAGE, host_uid,
        token_lines[0], surface_lines[0], tuple(device_lines),
        tuple(logical_lines))


@dataclass(frozen=True)
class LiveProof:
    process: host.ProcessIdentity
    scope: HostScopeIdentity
    display: VirtualDisplayIdentity
    activities_sha256: str
    windows_sha256: str
    displays_sha256: str
    target_pdf: alpha.DeviceFile
    target_mark: alpha.DeviceFile


@dataclass(frozen=True)
class StableLiveProof:
    first: LiveProof
    second: LiveProof


class Recovery:
    def __init__(self, device: Device, authority: ReportAuthority, *,
                 sleep: Callable[[float], None] = time.sleep,
                 journal: Journal | None = None,
                 evidence_guard: Callable[[], None] | None = None,
                 header_helper_identity: dict[str, Any] | None = None,
                 header_adb_identity: dict[str, Any] | None = None,
                 expected_descriptor_authority: dict[str, Any] | None = None):
        self.device = device
        self.authority = authority
        self.sleep = sleep
        self.journal = journal
        self.evidence_guard = evidence_guard
        _, self.helper_identity = _read_pinned_regular(
            Path(__file__), HELPER_MAX_BYTES, "recovery helper")
        self.header_helper_identity = (None if header_helper_identity is None
                                       else dict(header_helper_identity))
        self.header_adb_identity = (None if header_adb_identity is None
                                    else dict(header_adb_identity))
        self.expected_descriptor_authority = (
            None if expected_descriptor_authority is None
            else dict(expected_descriptor_authority))
        self.source_pdf: alpha.DeviceFile | None = None
        self.source_mark: alpha.DeviceFile | None = None
        self.parking_pdf: alpha.DeviceFile | None = None
        self.document_process: host.ProcessIdentity | None = None
        self.adb_identity: dict[str, Any] | None = None
        self.rotation_lease_intent = False
        self.rotation_lease_owned = False
        self.rotation_restored = False
        self.execute_admission_rotation: dict[str, Any] | None = None
        self.descriptor_authority_mode: str | None = None
        self.cleanup_complete = False
        self.evidence: dict[str, Any] = {
            "authority": RECOVERY_AUTHORITY,
            "schemaVersion": 1,
            "pinnedReport": {
                "path": str(authority.report_path),
                "sha256": authority.report_sha256,
            },
            "mutations": [],
            "proofs": [],
            "result": "NOT_RUN",
            "caveats": [
                "UIAutomator status is unavailable because the pinned host never idles.",
                "FD closure is proven for the only file consumer in this run, stock Document; the visual host never opens fixture files.",
                "SurfaceView/status z-order and the requestLayout loop require a future host fix and are outside retained cleanup.",
                "This report-bound cleanup assumes no adversarial or concurrent writer can replace either fixed hidden quarantine directory entry between exact verification and path-based rm; observed races fail closed, but compare-and-unlink is not atomic.",
            ],
        }

    def _proof(self, kind: str, **fields: Any) -> None:
        record = {"kind": kind, **fields}
        record["sha256"] = alpha._canonical_sha(record)
        self.evidence["proofs"].append(record)

    def _mutation(self, kind: str, **fields: Any) -> None:
        if self.journal is None:
            _fail("execute mode lacks a durable pre-mutation journal")
        if self.evidence_guard is not None:
            self.evidence_guard()
        self._assert_execution_identity("recovery mutation")
        self._assert_owned_rotation()
        self._assert_static_files()
        document_authority = self._prove_no_target_fd_holders()
        for path in (alpha.TARGET_MARK, alpha.TARGET_PDF):
            if self.device.stat_file(path, absent_ok=True) is not None:
                self._assert_retained_target(path)
        intent = {
            "authority": RECOVERY_AUTHORITY,
            "descriptorAuthority": document_authority["descriptorAuthority"],
            "ordinal": len(self.evidence["mutations"]) + 1,
            "intent": {"kind": kind, **fields},
            "reportSha256": self.authority.report_sha256,
        }
        journal_record = self.journal.record("mutation_intent", intent)
        self.evidence["mutations"].append({
            **intent["intent"], "journalSeq": journal_record["seq"],
            "journalHash": journal_record["recordHash"],
        })
        # Close the fsync-to-dispatch gap as far as the observable interface
        # permits.  The durable intent is authority to attempt only the exact
        # mutation it names; it is not authority to continue after Document,
        # descriptor, static-file, or retained-target state drifts.  Re-prove
        # the complete gate after fsync and immediately before dispatch.
        self._assert_owned_rotation()
        self._assert_execution_identity("cleanup command dispatch")
        self._assert_static_files()
        self._prove_no_target_fd_holders()
        for path in (alpha.TARGET_MARK, alpha.TARGET_PDF):
            if self.device.stat_file(path, absent_ok=True) is not None:
                self._assert_retained_target(path)

    def _settle(self, kind: str, **fields: Any) -> None:
        if self.journal is None:
            _fail("execute mode lacks a durable settlement journal")
        payload = {
            "authority": RECOVERY_AUTHORITY,
            "kind": kind,
            "reportSha256": self.authority.report_sha256,
            **fields,
        }
        record = self.journal.record("settlement", payload)
        self._proof("journal_settlement", settlementKind=kind,
                    journalSeq=record["seq"],
                    journalHash=record["recordHash"])

    def _rotation_sandwich(
            self, expected_settings: tuple[str, str] | None) -> dict[str, Any]:
        """Bind persisted settings on both sides of one WM observation."""
        before = self.device.rotation_settings()
        window_displays = self.device.window_displays()
        physical = alpha._physical_orientation(window_displays)
        after = self.device.rotation_settings()
        if before != after:
            _fail("persisted rotation settings changed across WindowManager capture")
        if expected_settings is not None and before != expected_settings:
            _fail("persisted rotation settings differ from exact " +
                  "/".join(expected_settings))
        if type(physical) is not int or physical not in range(4):
            _fail("physical WindowManager rotation is outside 0..3")
        return {
            "settingsBefore": {
                "accelerometerRotation": before[0],
                "userRotation": before[1],
            },
            "physicalRotation": physical,
            "windowDisplaysSha256": alpha._sha(window_displays),
            "settingsAfter": {
                "accelerometerRotation": after[0],
                "userRotation": after[1],
            },
        }

    def _rotation_admission_sandwich(self) -> dict[str, Any]:
        return self._rotation_sandwich(("1", "2"))

    def _owned_rotation_observation(self) -> dict[str, Any]:
        observation = self._rotation_sandwich(("0", "0"))
        if observation["physicalRotation"] != 0:
            _fail("owned rotation lease is not physical rotation 0")
        return observation

    def _restored_rotation_observation(self) -> dict[str, Any]:
        # Sensor control is authoritative after `free`; its current physical
        # orientation is evidence only and may legitimately be any 0..3.
        return self._rotation_sandwich(("1", "2"))

    def _assert_owned_rotation(self) -> dict[str, Any]:
        if not self.rotation_lease_owned or self.rotation_restored:
            _fail("cleanup mutation lacks the owned rotation lease")
        return self._owned_rotation_observation()

    def _record_rotation(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.journal is None:
            _fail("rotation mutation lacks a durable journal")
        if self.evidence_guard is not None:
            self.evidence_guard()
        self._assert_execution_identity("rotation mutation")
        return self.journal.record(kind, payload)

    def _assert_execution_identity(self, label: str) -> None:
        """Bind every write boundary to the identities in record zero."""
        if (self.header_helper_identity is None or
                self.header_adb_identity is None):
            _fail("execute mode lacks canonical journal tool identities")
        current_adb = self.device.adb_authority()
        if (self.adb_identity is None or current_adb != self.adb_identity or
                current_adb != self.header_adb_identity):
            _fail("adb executable identity changed before " + label)
        _, current_helper = _read_pinned_regular(
            Path(__file__), HELPER_MAX_BYTES, "recovery helper")
        if (current_helper != self.helper_identity or
                current_helper != self.header_helper_identity):
            _fail("recovery helper source changed before " + label)

    def _acquire_rotation_lease(self) -> None:
        if self.rotation_lease_intent or self.rotation_lease_owned:
            _fail("rotation lease acquisition was attempted more than once")
        if self.execute_admission_rotation is None:
            _fail("execute admission rotation evidence is absent")
        payload = {
            "authority": ROTATION_LEASE_AUTHORITY,
            "reportSha256": self.authority.report_sha256,
            "admissionSandwich": self.execute_admission_rotation,
            "commandDialect": ROTATION_COMMAND_DIALECTS["acquire"],
            "rollbackCommandDialects": {
                "lockTwo": ROTATION_COMMAND_DIALECTS["restoreUserRotation"],
                "free": ROTATION_COMMAND_DIALECTS["restoreSensor"],
            },
            "target": {
                "accelerometerRotation": "0",
                "userRotation": "0",
                "physicalRotation": 0,
            },
        }
        intent = self._record_rotation("rotation_lock_intent", payload)
        self.rotation_lease_intent = True
        self._proof("rotation_lock_intent", journalSeq=intent["seq"],
                    journalHash=intent["recordHash"], **payload)
        uncertain: str | None = None
        try:
            self._assert_execution_identity("rotation lock-zero dispatch")
            self.device.lock_rotation_zero()
        except Exception as error:
            uncertain = type(error).__name__ + ": " + str(error)
        observations: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for _ in range(ABSENCE_POLLS):
            try:
                self._assert_execution_identity(
                    "rotation lock-zero observation")
                current = self._owned_rotation_observation()
                observations.append(current)
                if len(observations) == 2:
                    break
            except Exception as error:
                observations = []
                last_error = error
            self.sleep(POLL_SECONDS)
        if len(observations) != 2:
            suffix = "" if last_error is None else ": " + str(last_error)
            raise RecoveryError("rotation lock 0 was not proved twice" + suffix)
        self.rotation_lease_owned = True
        settlement = {
            "authority": ROTATION_LEASE_AUTHORITY,
            "reportSha256": self.authority.report_sha256,
            "commandDialect": ROTATION_COMMAND_DIALECTS["acquire"],
            "transportUncertain": uncertain,
            "observations": observations,
        }
        record = self._record_rotation("rotation_lock_settlement", settlement)
        self._proof("rotation_lease_owned", journalSeq=record["seq"],
                    journalHash=record["recordHash"], **settlement)

    def _restore_rotation_lease(self, *, record_intent: bool = True) -> dict[str, Any]:
        if not self.rotation_lease_intent:
            _fail("rotation restore requested without a durable lock intent")
        payload = {
            "authority": ROTATION_LEASE_AUTHORITY,
            "reportSha256": self.authority.report_sha256,
            "commandDialects": {
                "lockTwo": ROTATION_COMMAND_DIALECTS["restoreUserRotation"],
                "free": ROTATION_COMMAND_DIALECTS["restoreSensor"],
            },
            "targetPersisted": {
                "accelerometerRotation": "1",
                "userRotation": "2",
            },
        }
        intent_error: BaseException | None = None
        if record_intent:
            try:
                record = self._record_rotation("rotation_restore_intent", payload)
                self._proof("rotation_restore_intent", journalSeq=record["seq"],
                            journalHash=record["recordHash"], **payload)
            except BaseException as error:
                # The durable lock intent already pre-authorizes these exact
                # idempotent rollback commands.  A later journal failure must
                # not strand the tablet in locked portrait; it does prevent a
                # clean transactional result.
                intent_error = error
        else:
            self._proof("rotation_restore_intent_resumed", **payload)
        lock_error: str | None = None
        free_error: str | None = None
        try:
            try:
                self._assert_execution_identity(
                    "rotation lock-two dispatch")
                self.device.lock_rotation_two()
            except Exception as error:
                lock_error = type(error).__name__ + ": " + str(error)
        finally:
            # `free` is mandatory even if lock 2 timed out or failed.  Both
            # operations are idempotent restoration commands authorized by the
            # durable lock/restore records, never cleanup replay.
            try:
                self._assert_execution_identity("rotation free dispatch")
                self.device.free_rotation()
            except Exception as error:
                free_error = type(error).__name__ + ": " + str(error)
        observations: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for _ in range(ABSENCE_POLLS):
            try:
                self._assert_execution_identity(
                    "rotation restoration observation")
                current = self._restored_rotation_observation()
                observations.append(current)
                if len(observations) == 2:
                    break
            except Exception as error:
                observations = []
                last_error = error
            self.sleep(POLL_SECONDS)
        if len(observations) != 2:
            suffix = "" if last_error is None else ": " + str(last_error)
            raise RotationRestoreError(
                "original persisted rotation 1/2 was not proved twice" + suffix)
        settlement = {
            "authority": ROTATION_LEASE_AUTHORITY,
            "reportSha256": self.authority.report_sha256,
            "commandDialects": payload["commandDialects"],
            "lockTwoTransportUncertain": lock_error,
            "freeTransportUncertain": free_error,
            "observations": observations,
        }
        self.rotation_restored = True
        self.rotation_lease_owned = False
        if intent_error is not None:
            raise RotationRestoreError(
                "rotation restored but restore intent was not durably appended") from intent_error
        try:
            settled = self._record_rotation(
                "rotation_restore_settlement", settlement)
        except BaseException as error:
            raise RotationRestoreError(
                "rotation restored but settlement was not durably appended") from error
        self._proof("rotation_restored", journalSeq=settled["seq"],
                    journalHash=settled["recordHash"], **settlement)
        return settlement

    def _check_environment(self) -> int:
        self.adb_identity = self.device.adb_authority()
        if (self.adb_identity.get("path") != str(PINNED_ADB_PATH) or
                self.adb_identity.get("size") != PINNED_ADB_SIZE or
                self.adb_identity.get("sha256") != PINNED_ADB_SHA256):
            _fail("adb executable identity differs from the exact host pin")
        if (self.header_helper_identity is not None or
                self.header_adb_identity is not None):
            self._assert_execution_identity("execute admission")
        if (self.device.get_state() != "device" or
                self.device.get_serial() != alpha.AUTHORIZED_SERIAL or
                self.device.getprop("ro.product.model") != alpha.MODEL or
                self.device.getprop("ro.build.version.sdk") != alpha.SDK or
                self.device.getprop("ro.build.fingerprint") != alpha.FINGERPRINT or
                self.device.current_user() != "0"):
            _fail("connected device identity differs from the pinned Nomad")
        host_dump = self.device.package_dump(alpha.HOST_PACKAGE)
        alpha._package_version(
            host_dump, alpha.HOST_VERSION_CODE, alpha.HOST_VERSION_NAME,
            "visual host")
        host_uid = _package_uid(host_dump, alpha.HOST_PACKAGE)
        if host_uid != PINNED_HOST_UID:
            _fail("installed host UID differs from the retained run")
        host_apk = self.device.package_path(alpha.HOST_PACKAGE)
        if self.device.sha256_file(host_apk) != alpha.ALPHA_SIGNED_APK_SHA256:
            _fail("installed host APK bytes differ from the signed alpha pin")
        document_dump = self.device.package_dump(alpha.DOCUMENT_PACKAGE)
        alpha._package_version(
            document_dump, alpha.DOCUMENT_VERSION_CODE,
            alpha.DOCUMENT_VERSION_NAME, "stock Document")
        if self.device.package_path(alpha.DOCUMENT_PACKAGE) != alpha.DOCUMENT_APK:
            _fail("stock Document APK path differs")
        apk = self.device.stat_file(alpha.DOCUMENT_APK)
        if (apk is None or apk.size != alpha.DOCUMENT_APK_SIZE or
                apk.sha256 != alpha.DOCUMENT_APK_SHA256):
            _fail("stock Document APK identity differs")
        self.source_pdf = self.device.stat_file(alpha.SOURCE_PDF)
        self.source_mark = self.device.stat_file(alpha.SOURCE_MARK)
        self.parking_pdf = self.device.stat_file(alpha.PARKING_PDF)
        if (self.source_pdf is None or
                self.source_pdf.sha256 != alpha.SOURCE_PDF_SHA256 or
                self.source_mark is None or
                self.source_mark.sha256 != alpha.SOURCE_MARK_SHA256 or
                self.parking_pdf is None or
                self.parking_pdf.sha256 != alpha.SOURCE_PDF_SHA256 or
                self.device.stat_file(alpha.PARKING_MARK, absent_ok=True) is not None):
            _fail("source or persistent parking fixture differs")
        self._assert_static_files()
        admission_rotation = self._rotation_admission_sandwich()
        self._proof("rotation_admission_sandwich", **admission_rotation)
        self.execute_admission_rotation = admission_rotation
        document_pids = self.device.pidof(alpha.DOCUMENT_PACKAGE)
        if len(document_pids) != 1:
            _fail("one retained stock Document process is required")
        self.document_process = self.device.process_identity(
            document_pids[0], alpha.DOCUMENT_PACKAGE)
        if (self.document_process.uid != 1000 or
                self.document_process.package != alpha.DOCUMENT_PACKAGE):
            _fail("retained stock Document process identity differs")
        self._prove_no_target_fd_holders()
        self._proof("environment", hostUid=host_uid,
                    adb=self.adb_identity,
                    helper=self.helper_identity,
                    hostApkSha256=alpha.ALPHA_SIGNED_APK_SHA256,
                    documentApkSha256=alpha.DOCUMENT_APK_SHA256)
        return host_uid

    def _assert_static_files(self) -> None:
        assert self.source_pdf is not None
        assert self.source_mark is not None
        assert self.parking_pdf is not None
        for path, retained, expected in (
                (alpha.SOURCE_PDF, self.source_pdf, alpha.SOURCE_PDF_SHA256),
                (alpha.SOURCE_MARK, self.source_mark, alpha.SOURCE_MARK_SHA256),
                (alpha.PARKING_PDF, self.parking_pdf, alpha.SOURCE_PDF_SHA256)):
            current = self.device.stat_file(path)
            if (current is None or not retained.same_object(current) or
                    current.sha256 != expected):
                _fail("source/parking object changed during recovery: " + path)
        if self.device.stat_file(alpha.PARKING_MARK, absent_ok=True) is not None:
            _fail("parking mark appeared during recovery")

    def _static_authority(self) -> dict[str, Any]:
        self._assert_static_files()
        assert self.source_pdf is not None
        assert self.source_mark is not None
        assert self.parking_pdf is not None
        return {
            "sourcePdf": asdict(self.source_pdf),
            "sourceMark": asdict(self.source_mark),
            "parkingPdf": asdict(self.parking_pdf),
            "parkingMarkAbsent": True,
        }

    def _assert_retained_target(self, path: str) -> alpha.DeviceFile:
        retained = (self.authority.retained_pdf if path == alpha.TARGET_PDF
                    else self.authority.retained_mark)
        current = self.device.stat_file(path)
        if (current is None or not retained.same_object(current) or
                current.sha256 != retained.sha256):
            _fail("staged file object/hash changed: " + path)
        return current

    @staticmethod
    def _same_payload_object(retained: alpha.DeviceFile,
                             current: alpha.DeviceFile,
                             quarantine: str) -> bool:
        return (
            current.path == quarantine and current.kind == retained.kind == "regular file" and
            current.size == retained.size and current.uid == retained.uid and
            current.gid == retained.gid and current.inode == retained.inode and
            current.device == retained.device and current.sha256 == retained.sha256
        )

    def _assert_quarantine_exact(self, source: str) -> alpha.DeviceFile:
        quarantine = QUARANTINES[source]
        retained = (self.authority.retained_pdf if source == alpha.TARGET_PDF
                    else self.authority.retained_mark)
        current = self.device.recovery_stat_file(quarantine)
        if (current is None or
                not self._same_payload_object(retained, current, quarantine)):
            _fail("quarantine does not contain the exact retained staged object")
        return current

    def _prove_path_absent_twice(self, path: str, *, quarantine: bool) -> None:
        for observation in range(2):
            current = (self.device.recovery_stat_file(path, absent_ok=True)
                       if quarantine else
                       self.device.stat_file(path, absent_ok=True))
            if current is not None:
                _fail("path is not stably absent: " + path)
            if observation == 0:
                self.sleep(POLL_SECONDS)

    def _capture_live(self, host_uid: int) -> LiveProof:
        status = self.authority.status
        pids = self.device.pidof(alpha.HOST_PACKAGE)
        if pids != (self.authority.host_pid,):
            _fail("retained host PID is absent, duplicated, or replaced")
        process = self.device.process_identity(pids[0], alpha.HOST_PACKAGE)
        if (process.pid != self.authority.host_pid or
                process.start_ticks != self.authority.host_start_ticks or
                process.uid != host_uid or process.package != alpha.HOST_PACKAGE):
            _fail("retained host process identity changed")
        activities = self.device.activities()
        windows = self.device.windows()
        displays = self.device.displays()
        if (not alpha._contains_component(activities, alpha._host_components()) or
                not alpha._contains_component(windows, alpha._host_components())):
            _fail("retained host task/window is absent")
        scope = _host_scope_identity(
            activities, windows, host_uid, process.pid)
        if (alpha._contains_document_task_or_window(activities) or
                alpha._contains_document_task_or_window(windows)):
            _fail("stock Document scope appeared in the pre-attach recovery")
        alpha._assert_owned_display_empty(activities, status)
        alpha._assert_owned_display_windows_empty(windows, status)
        display = _retained_virtual_display_identity(
            displays, status, host_uid)
        pdf = self._assert_retained_target(alpha.TARGET_PDF)
        mark = self._assert_retained_target(alpha.TARGET_MARK)
        self._assert_static_files()
        return LiveProof(
            process, scope, display, alpha._sha(activities),
            alpha._sha(windows), alpha._sha(displays), pdf, mark)

    def _capture_live_stable(self, host_uid: int) -> StableLiveProof:
        first = self._capture_live(host_uid)
        self.sleep(POLL_SECONDS)
        second = self._capture_live(host_uid)
        if (first.process != second.process or first.scope != second.scope or
                first.display != second.display or
                first.target_pdf != second.target_pdf or
                first.target_mark != second.target_mark):
            _fail("live host/file semantics changed across two observations")
        self._proof(
            "stable_live_scope", observations=2,
            firstRawHashes=[first.activities_sha256, first.windows_sha256,
                            first.displays_sha256],
            secondRawHashes=[second.activities_sha256, second.windows_sha256,
                             second.displays_sha256],
            process=asdict(second.process),
            hostScope=asdict(second.scope),
            virtualDisplay=asdict(second.display),
            targetPdf=asdict(second.target_pdf),
            targetMark=asdict(second.target_mark))
        return StableLiveProof(first, second)

    def _host_absent_once(self) -> dict[str, Any] | None:
        activities = self.device.activities()
        windows = self.device.windows()
        displays = self.device.displays()
        if (alpha._contains_document_task_or_window(activities) or
                alpha._contains_document_task_or_window(windows)):
            _fail("Document task/window exists during empty pre-attach recovery")
        absent = not (
            alpha._contains_component(activities, alpha._host_components()) or
            alpha._contains_component(windows, alpha._host_components()) or
            alpha._virtual_display_present(displays, self.authority.status) or
            self.device.pidof(alpha.HOST_PACKAGE))
        if not absent:
            return None
        return {
            "activitiesSha256": alpha._sha(activities),
            "windowsSha256": alpha._sha(windows),
            "displaysSha256": alpha._sha(displays),
            "hostPids": [],
            "documentGloballyAbsent": True,
        }

    def _prove_host_absent_twice(self, *, settle: bool = False) -> list[dict[str, Any]]:
        first: dict[str, Any] | None = None
        for _ in range(ABSENCE_POLLS):
            first = self._host_absent_once()
            if first is not None:
                break
            self.sleep(POLL_SECONDS)
        if first is None:
            _fail("exact host task/display/process did not settle absent")
        self.sleep(POLL_SECONDS)
        second = self._host_absent_once()
        if second is None:
            _fail("host scope reappeared during the second absence observation")
        observations = [first, second]
        self._proof("host_absent", observations=observations)
        if settle:
            self._settle("host_absent_twice", observations=observations)
        return observations

    @staticmethod
    def _stable_live_wire(stable: StableLiveProof) -> dict[str, Any]:
        def one(item: LiveProof) -> dict[str, Any]:
            return {
                "process": asdict(item.process),
                "hostScope": asdict(item.scope),
                "virtualDisplay": asdict(item.display),
                "activitiesSha256": item.activities_sha256,
                "windowsSha256": item.windows_sha256,
                "displaysSha256": item.displays_sha256,
                "targetPdf": asdict(item.target_pdf),
                "targetMark": asdict(item.target_mark),
            }
        return {"first": one(stable.first), "second": one(stable.second)}

    def _complete_absence_authority(self, stable: StableLiveProof) -> dict[str, Any]:
        rotation = (self._assert_owned_rotation() if self.rotation_lease_owned
                    else self._rotation_admission_sandwich())
        return {
            "authority": RECOVERY_AUTHORITY,
            "reportSha256": self.authority.report_sha256,
            "session": self.authority.status.session,
            "generation": self.authority.status.generation,
            "displayId": self.authority.status.display_id,
            "liveObservations": self._stable_live_wire(stable),
            "document": self._prove_no_target_fd_holders(),
            "staticFiles": self._static_authority(),
            "rotation": rotation,
            "documentLaunchAttempted": False,
            "state": "FAILED",
        }

    def _document_process_observation(self) -> host.ProcessIdentity:
        pids = self.device.pidof(alpha.DOCUMENT_PACKAGE)
        if self.document_process is None or pids != (self.document_process.pid,):
            _fail("retained stock Document PID changed")
        process = self.device.process_identity(pids[0], alpha.DOCUMENT_PACKAGE)
        if process != self.document_process:
            _fail("retained stock Document PID/start/UID changed")
        return process

    def _prove_no_target_fd_holders(self) -> dict[str, Any]:
        self._assert_static_files()
        observations: list[dict[str, Any]] = []
        mode: str | None = None
        final_process: host.ProcessIdentity | None = None
        for _ in range(2):
            before = self._document_process_observation()
            links = self.device.process_fd_links(before.pid)
            targets = _validated_document_fd_targets(links)
            activities = self.device.activities()
            windows = self.device.windows()
            try:
                document_scope_present = (
                    alpha._contains_document_task_or_window(activities) or
                    alpha._contains_document_task_or_window(windows))
            except Exception as error:
                raise RecoveryError(
                    "Document task/window authority is malformed") from error
            if document_scope_present:
                _fail("stock Document retains a task or window")
            if targets == frozenset({alpha.PARKING_PDF}):
                observed_mode = DESCRIPTOR_AUTHORITY_PARKING_ONLY
                relevant_targets = [alpha.PARKING_PDF]
            elif not targets:
                observed_mode = DESCRIPTOR_AUTHORITY_IDLE_ZERO
                relevant_targets = []
            else:
                _fail("stock Document descriptor authority is neither exact "
                      "parking-only nor exact idle-zero")
            observation = {
                "activitiesSha256": alpha._sha(activities),
                "documentTaskWindowAbsent": True,
                "fdInventorySha256": alpha._sha(links.encode("utf-8")),
                "relevantTargets": relevant_targets,
                "windowsSha256": alpha._sha(windows),
            }
            after = self._document_process_observation()
            if before != after:
                _fail("retained stock Document identity changed across descriptor proof")
            if mode is None:
                mode = observed_mode
            elif mode != observed_mode:
                _fail("stock Document descriptor authority changed across observations")
            observations.append(observation)
            final_process = after
            if len(observations) == 1:
                self.sleep(POLL_SECONDS)
        assert mode is not None and final_process is not None
        if self.descriptor_authority_mode is None:
            self.descriptor_authority_mode = mode
        elif self.descriptor_authority_mode != mode:
            _fail("stock Document descriptor authority mode changed during recovery")
        descriptor_authority = {
            "documentProcess": asdict(final_process),
            "mode": mode,
            "observations": observations,
        }
        if self.expected_descriptor_authority is not None:
            expected = self.expected_descriptor_authority
            if (expected.get("mode") != mode or
                    expected.get("documentProcess") !=
                    descriptor_authority["documentProcess"]):
                _fail("execute descriptor authority differs from read-only admission")
        self._assert_static_files()
        self._proof(
            "target_fds_absent", descriptorAuthority=descriptor_authority,
            documentPids=[final_process.pid],
            retainedPdfMarkTargets=observations[-1]["relevantTargets"])
        return {"descriptorAuthority": descriptor_authority}

    def _reconcile_state(self, host_uid: int, execute: bool) -> tuple[str | None, StableLiveProof, list[str]]:
        proof = self._capture_live_stable(host_uid)
        before_logs = self.device.host_logs(self.authority.host_pid)
        before_lines = _identity_lines(before_logs, self.authority.status)
        _reject_protocol_drift(before_lines)
        if _attempted_abort(before_lines):
            abort, release, digest = _validate_prior_failed_cleanup(before_lines)
            self._proof("prior_cleanup_pair", abortLogLine=abort,
                        releaseLogLine=release,
                        absenceEvidenceSha256=digest)
            return "ALREADY_ATTEMPTED", proof, before_lines
        if not execute:
            return None, proof, before_lines
        self._mutation("host_main_refocus", sequence=None)
        uncertain: str | None = None
        try:
            self.device.start_host()
        except Exception as error:  # MAIN is never replayed
            uncertain = type(error).__name__ + ": " + str(error)
        before_counts = Counter(before_lines)
        after_lines: list[str] = []
        fresh: list[str] = []
        for _ in range(ABSENCE_POLLS):
            after_lines = _identity_lines(
                self.device.host_logs(self.authority.host_pid), self.authority.status)
            counts = Counter(after_lines)
            fresh = []
            for line, count in counts.items():
                fresh.extend([line] * max(0, count - before_counts[line]))
            if any(re.search(r"\bREFOCUS\b.*\breadiness=FAILED(?:\s|$)", line)
                   for line in fresh):
                break
            self.sleep(POLL_SECONDS)
        _reject_protocol_drift(after_lines)
        exact_refocus = [line for line in fresh if re.search(
            r"\bREFOCUS\b.*\breadiness=FAILED(?:\s|$)", line)]
        if len(exact_refocus) != 1 or any(
                "REFOCUS " in line and "readiness=FAILED" not in line
                for line in fresh):
            _fail("guarded MAIN did not yield one fresh exact FAILED refocus")
        if _attempted_abort(fresh):
            _fail("cleanup action appeared during the guarded MAIN refocus")
        after_proof = self._capture_live_stable(host_uid)
        if (after_proof.second.process != proof.second.process or
                after_proof.second.scope != proof.second.scope or
                after_proof.second.display != proof.second.display):
            _fail("host task/activity/window/display identity changed across refocus")
        self._settle(
            "host_main_refocus", state="FAILED", transportUncertain=uncertain,
            logLine=exact_refocus[0], process=asdict(after_proof.second.process),
            hostScope=asdict(after_proof.second.scope),
            virtualDisplay=asdict(after_proof.second.display))
        return "FAILED", after_proof, after_lines

    def _await_failed_abort_release(
            self, baseline: list[str], absence_sha: str) -> tuple[str, str]:
        baseline_counts = Counter(baseline)
        latest: list[str] = []
        fresh: list[str] = []
        for _ in range(ABSENCE_POLLS):
            latest = _identity_lines(
                self.device.host_logs(self.authority.host_pid),
                self.authority.status)
            counts = Counter(latest)
            fresh = []
            for line, count in counts.items():
                fresh.extend([line] * max(0, count - baseline_counts[line]))
            event_tokens = [tokens for _, tokens in
                            _cleanup_event_records(fresh)]
            if ((EVENT_FAILED,) in event_tokens and
                    (EVENT_RELEASED,) in event_tokens):
                break
            self.sleep(POLL_SECONDS)
        _reject_protocol_drift(latest)
        records = _cleanup_event_records(fresh)
        if ([tokens for _, tokens in records] !=
                [(EVENT_FAILED,), (EVENT_RELEASED,)]):
            _fail("failed ACK lacks one exact accepted-abort/released pair")
        abort, release = records[0][0], records[1][0]
        if not _exact_log_token(
                abort, "absenceEvidenceSha256", absence_sha):
            _fail("failed ACK abort evidence differs")
        if (not _exact_log_token(
                release, "display", str(self.authority.status.display_id)) or
                not _exact_log_token(
                    release, "mode", "acknowledged_cleanup")):
            _fail("failed ACK display release fields differ")
        return abort, release

    def _validate_terminal_cleanup_logs(
            self, expected_digest: str | None) -> str:
        lines = _identity_lines(
            self.device.host_logs(self.authority.host_pid),
            self.authority.status)
        _reject_protocol_drift(lines)
        abort, release, observed_digest = _validate_prior_failed_cleanup(lines)
        if (expected_digest is not None and
                observed_digest != expected_digest):
            _fail("terminal cleanup evidence digest changed")
        self._proof(
            "terminal_cleanup_event_stream", abortLogLine=abort,
            releaseLogLine=release,
            absenceEvidenceSha256=observed_digest,
            identityLogSha256=alpha._canonical_sha(lines))
        return observed_digest

    def _validate_final_mutations(self) -> None:
        kinds = [item["kind"] for item in self.evidence["mutations"]]
        allowed = {
            "host_main_refocus": 1,
            "empty_display_abort": 1,
            "quarantine_move_attempt": 2,
            "quarantine_delete_attempt": 2,
        }
        for kind in kinds:
            if kind not in allowed:
                _fail("unexpected recovery mutation kind: " + kind)
        if any(kinds.count(kind) > maximum for kind, maximum in allowed.items()):
            _fail("a one-shot recovery mutation was attempted more than once")
        if "empty_display_abort" in kinds:
            if ("host_main_refocus" not in kinds or
                    kinds.index("host_main_refocus") >
                    kinds.index("empty_display_abort")):
                _fail("failed-host ACK was not preceded by its one refocus")
        elif "host_main_refocus" in kinds:
            _fail("refocus completed without the one failed-host ACK")
        quarantine_items = [item for item in self.evidence["mutations"]
                            if item["kind"].startswith("quarantine_")]
        seen_pdf = False
        for source in (alpha.TARGET_MARK, alpha.TARGET_PDF):
            member = [item for item in quarantine_items
                      if item.get("source") == source]
            member_kinds = [item["kind"] for item in member]
            if member_kinds not in (
                    [], ["quarantine_delete_attempt"],
                    ["quarantine_move_attempt", "quarantine_delete_attempt"]):
                _fail("quarantine member mutation sequence differs")
        for item in quarantine_items:
            if item.get("source") == alpha.TARGET_PDF:
                seen_pdf = True
            elif item.get("source") == alpha.TARGET_MARK:
                if seen_pdf:
                    _fail("mark recovery occurred after PDF recovery")
            else:
                _fail("quarantine mutation escaped the two retained targets")

    def _quarantine_and_delete_once(self, path: str) -> None:
        quarantine = QUARANTINES[path]
        self._assert_static_files()
        self._prove_no_target_fd_holders()
        original = self.device.stat_file(path, absent_ok=True)
        isolated = self.device.recovery_stat_file(quarantine, absent_ok=True)
        if original is not None and isolated is not None:
            _fail("original and quarantine are both occupied")
        if isolated is not None:
            exact = self._assert_quarantine_exact(path)
            self._prove_path_absent_twice(path, quarantine=False)
            self._settle("preexisting_quarantine_verified", source=path,
                         quarantine=quarantine, retainedObject=asdict(exact))
        elif original is not None:
            self._assert_retained_target(path)
            self._prove_path_absent_twice(quarantine, quarantine=True)
            self._mutation("quarantine_move_attempt", source=path,
                           quarantine=quarantine)
            uncertain_move: str | None = None
            try:
                self.device.move_to_quarantine(path, quarantine)
            except Exception as error:  # move is never retried
                uncertain_move = type(error).__name__ + ": " + str(error)
            self._prove_path_absent_twice(path, quarantine=False)
            isolated = self._assert_quarantine_exact(path)
            self._proof(
                "target_quarantined", source=path, quarantine=quarantine,
                retainedObject=asdict(isolated),
                transportUncertain=uncertain_move)
            self._settle(
                "target_quarantined", source=path, quarantine=quarantine,
                retainedObject=asdict(isolated),
                transportUncertain=uncertain_move)
        else:
            # A previous recovery may already have completed this member.  Two
            # absences settle it without recreating or repeating any mutation.
            self._prove_path_absent_twice(path, quarantine=False)
            self._prove_path_absent_twice(quarantine, quarantine=True)
            self._proof("target_already_absent", source=path,
                        quarantine=quarantine, observations=2)
            self._settle("target_already_absent", source=path,
                         quarantine=quarantine, observations=2)
            return

        self._mutation("quarantine_delete_attempt", source=path,
                       quarantine=quarantine)
        uncertain: str | None = None
        try:
            self.device.remove_quarantine(quarantine)
        except Exception as error:  # never resend after uncertain transport
            uncertain = type(error).__name__ + ": " + str(error)
        try:
            self._prove_path_absent_twice(quarantine, quarantine=True)
        except RecoveryError:
            if uncertain is not None:
                _fail("uncertain quarantine deletion remains present; refusing to retry")
            raise
        self._prove_path_absent_twice(path, quarantine=False)
        self._assert_static_files()
        self._proof("quarantine_absent_after_delete", source=path,
                    quarantine=quarantine,
                    observations=2, transportUncertain=uncertain)
        self._settle(
            "quarantine_absent_after_delete", source=path,
            quarantine=quarantine, observations=2,
            transportUncertain=uncertain)

    def _joint_absence(self) -> None:
        for observation in range(2):
            if (self.device.stat_file(alpha.TARGET_MARK, absent_ok=True) is not None or
                    self.device.stat_file(alpha.TARGET_PDF, absent_ok=True) is not None or
                    self.device.recovery_stat_file(
                        QUARANTINE_MARK, absent_ok=True) is not None or
                    self.device.recovery_stat_file(
                        QUARANTINE_PDF, absent_ok=True) is not None):
                _fail("joint staged-file absence is not stable")
            if observation == 0:
                self.sleep(POLL_SECONDS)
        self._assert_static_files()
        self._proof("joint_target_absence", observations=2)

    def _run_cleanup(self, *, execute: bool, host_uid: int) -> dict[str, Any]:
        host_pids = self.device.pidof(alpha.HOST_PACKAGE)
        terminal_cleanup_digest: str | None = None
        if not host_pids:
            self._prove_host_absent_twice(settle=execute)
            state = "ALREADY_RELEASED"
        else:
            state, stable, lines = self._reconcile_state(host_uid, execute)
            live = stable.second
            self._proof(
                "live_host", state=state, process=asdict(live.process),
                hostScope=asdict(live.scope),
                virtualDisplay=asdict(live.display),
                stableRawAuthority=self._stable_live_wire(stable),
                activitiesSha256=live.activities_sha256,
                windowsSha256=live.windows_sha256,
                displaysSha256=live.displays_sha256,
                targetPdf=asdict(live.target_pdf), targetMark=asdict(live.target_mark),
                identityLogSha256=alpha._canonical_sha(lines))
            if state is None:
                self.evidence["result"] = "PLAN_REFOCUS_REQUIRED"
                return self.evidence
            if state == "ALREADY_ATTEMPTED":
                if not execute:
                    self.evidence["result"] = "PLAN_SETTLE_ONLY"
                    return self.evidence
                self._prove_host_absent_twice(settle=True)
                terminal_cleanup_digest = self._validate_terminal_cleanup_logs(
                    None)
            elif state == "FAILED":
                # This is deliberately recomputed after the guarded refocus and
                # immediately before ACK.  It binds both stable host semantic
                # observations, Document's parking-only descriptor authority,
                # immutable source/parking objects, and persisted/WM rotation.
                proof_wire = self._complete_absence_authority(stable)
                absence_sha = alpha._canonical_sha(proof_wire)
                self.evidence["absenceEvidence"] = proof_wire
                self.evidence["absenceEvidenceSha256"] = absence_sha
                if not execute:
                    self.evidence["plannedAction"] = ACTION_FAILED
                    self.evidence["result"] = "PLAN_READY"
                    return self.evidence
                baseline = list(lines)
                self._mutation("empty_display_abort", action=ACTION_FAILED,
                               sequence=1, absenceEvidenceSha256=absence_sha)
                uncertain: str | None = None
                try:
                    self.device.send_recovery(
                        self.authority.status, ACTION_FAILED, absence_sha)
                except Exception as error:  # action must never be resent
                    uncertain = type(error).__name__ + ": " + str(error)
                abort_line, release_line = self._await_failed_abort_release(
                    baseline, absence_sha)
                self._proof(
                    "empty_display_abort_accepted", event=EVENT_FAILED,
                    releaseEvent=EVENT_RELEASED, sequence=1,
                    transportUncertain=uncertain,
                    absenceEvidenceSha256=absence_sha,
                    abortLogLine=abort_line, releaseLogLine=release_line)
                self._settle(
                    "empty_display_abort_and_release", sequence=1,
                    absenceEvidenceSha256=absence_sha,
                    transportUncertain=uncertain,
                    abortLogLine=abort_line, releaseLogLine=release_line)
                self._prove_host_absent_twice(settle=True)
                terminal_cleanup_digest = self._validate_terminal_cleanup_logs(
                    absence_sha)
            else:
                _fail("host state is outside the closed recovery model")

        self._prove_no_target_fd_holders()
        if not execute:
            self.evidence["result"] = "PLAN_READY_ALREADY_RELEASED"
            return self.evidence
        if terminal_cleanup_digest is not None:
            self._validate_terminal_cleanup_logs(terminal_cleanup_digest)
        self._quarantine_and_delete_once(alpha.TARGET_MARK)
        self._quarantine_and_delete_once(alpha.TARGET_PDF)
        self._joint_absence()
        self._prove_no_target_fd_holders()
        final_rotation = self._assert_owned_rotation()
        final_static = self._static_authority()
        final_host_absence = self._prove_host_absent_twice()
        if terminal_cleanup_digest is not None:
            self._validate_terminal_cleanup_logs(terminal_cleanup_digest)
        final_adb = self.device.adb_authority()
        if final_adb != self.adb_identity:
            _fail("adb executable identity changed before final settlement")
        self._validate_final_mutations()
        self._settle(
            "cleanup_complete", hostAbsence=final_host_absence,
            document=self._prove_no_target_fd_holders(),
            staticFiles=final_static, rotation=final_rotation, adb=final_adb,
            mutationKinds=[item["kind"] for item in self.evidence["mutations"]])
        self.cleanup_complete = True
        self.evidence["result"] = "CLEANUP_COMPLETE_ROTATION_RESTORE_PENDING"
        return self.evidence

    def run(self, *, execute: bool = False) -> dict[str, Any]:
        self.evidence["mode"] = "execute" if execute else "plan"
        if execute and (self.header_helper_identity is None or
                        self.header_adb_identity is None):
            _fail("execute mode lacks canonical journal tool identities")
        host_uid = self._check_environment()
        if not execute:
            return self._run_cleanup(execute=False, host_uid=host_uid)

        # `main` already performs this admission before creating the canonical
        # journal.  Repeat it here so the Recovery object itself cannot mutate
        # rotation before all non-mutating host/file/protocol checks reach one
        # of the three closed plans (including in direct tests or future use).
        admission_plan = self._run_cleanup(execute=False, host_uid=host_uid)
        if admission_plan.get("result") not in {
                "PLAN_REFOCUS_REQUIRED", "PLAN_SETTLE_ONLY",
                "PLAN_READY_ALREADY_RELEASED"}:
            _fail("execute admission did not reach a closed read-only plan")
        self.evidence["executeAdmissionSha256"] = alpha._canonical_sha(
            admission_plan)
        self.evidence["result"] = "EXECUTE_ADMITTED"

        cleanup_error: BaseException | None = None
        restore_error: BaseException | None = None
        restore_settlement: dict[str, Any] | None = None
        try:
            self._acquire_rotation_lease()
            self._run_cleanup(execute=True, host_uid=host_uid)
        except BaseException as error:
            cleanup_error = error
        finally:
            if self.rotation_lease_intent:
                try:
                    restore_settlement = self._restore_rotation_lease()
                except BaseException as error:
                    restore_error = error

        if cleanup_error is not None:
            self.evidence["result"] = (
                "CLEANUP_NOT_STARTED_ROTATION_UNCHANGED"
                if not self.rotation_lease_intent else
                "CLEANUP_FAILED_ROTATION_RESTORED"
                if self.rotation_restored else
                "CLEANUP_FAILED_ROTATION_RESTORE_FAILED")
            self.evidence["cleanupError"] = (
                type(cleanup_error).__name__ + ": " + str(cleanup_error))
            if restore_error is not None:
                self.evidence[("rotationJournalError" if self.rotation_restored
                               else "rotationRestoreError")] = (
                    type(restore_error).__name__ + ": " + str(restore_error))
            raise cleanup_error
        if restore_error is not None or not self.rotation_restored:
            self.evidence["result"] = "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED"
            if restore_error is not None:
                self.evidence["rotationRestoreError"] = (
                    type(restore_error).__name__ + ": " + str(restore_error))
                raise RotationRestoreError(str(restore_error)) from restore_error
            raise RotationRestoreError("rotation restoration lacks a settled proof")
        if not self.cleanup_complete or restore_settlement is None:
            _fail("clean recovery lacks cleanup/restoration completion")
        self._settle(
            "final_state", cleanupComplete=True,
            rotationRestoration=restore_settlement,
            mutationKinds=[item["kind"] for item in self.evidence["mutations"]])
        self.evidence["result"] = "RECOVERED_CLEANLY"
        return self.evidence


class DurableJournal:
    """Exclusive, fsync'd, hash-chained recovery journal."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._count = 0
        self._head_hash = "0" * 64
        self._poisoned = False
        try:
            # Unbuffered writes make the exact-progress loop and torn-tail
            # boundary describe the bytes the kernel actually accepted.
            self._stream = self.path.open("xb", buffering=0)
        except FileExistsError as error:
            raise RecoveryError("refusing to reuse a recovery journal") from error
        self._lock_stream()
        opened = os.fstat(self._stream.fileno())
        self._file_identity = (opened.st_dev, opened.st_ino)
        try:
            self.record("header", header)
        except BaseException:
            self.close()
            raise

    def _lock_stream(self) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self._stream.fileno(), 0, os.SEEK_SET)
                msvcrt.locking(self._stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._stream.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError) as error:
            self._stream.close()
            raise RecoveryError(
                "recovery journal is concurrently owned") from error

    @classmethod
    def resume(cls, path: Path, *, count: int, head_hash: str,
               valid_size: int, expected_prefix_sha256: str,
               expected_identity: dict[str, Any] | None = None) -> "DurableJournal":
        """Resume only a previously validated prefix, trimming one torn tail."""
        supplied = path.absolute()
        before = os.lstat(supplied)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            _fail("recovery journal must be one non-symlink regular file")
        flags = (os.O_RDWR | getattr(os, "O_BINARY", 0) |
                 getattr(os, "O_NOFOLLOW", 0))
        try:
            descriptor = os.open(supplied, flags)
        except OSError as error:
            raise RecoveryError(
                "recovery journal is concurrently owned") from error
        value: DurableJournal | None = None
        try:
            stream = os.fdopen(descriptor, "r+b", buffering=0)
            descriptor = -1
            value = cls.__new__(cls)
            value.path = supplied
            value._stream = stream
            value._count = count
            value._head_hash = head_hash
            value._poisoned = False
            value._lock_stream()
            opened = os.fstat(value._stream.fileno())
            value._file_identity = (opened.st_dev, opened.st_ino)
            if ((opened.st_dev, opened.st_ino) !=
                    (before.st_dev, before.st_ino) or
                    opened.st_size < valid_size):
                _fail("recovery journal changed before restore-only resume")
            if (expected_identity is not None and (
                    opened.st_dev != expected_identity.get("device") or
                    opened.st_ino != expected_identity.get("inode") or
                    opened.st_size != expected_identity.get("size"))):
                _fail("recovery journal identity changed before restore-only resume")
            os.lseek(value._stream.fileno(), 0, os.SEEK_SET)
            prefix = b""
            while len(prefix) < valid_size:
                chunk = os.read(value._stream.fileno(), valid_size - len(prefix))
                if not chunk:
                    break
                prefix += chunk
            if (len(prefix) != valid_size or
                    alpha._sha(prefix) != expected_prefix_sha256):
                _fail("recovery journal prefix changed before restore-only resume")
            if opened.st_size != valid_size:
                os.ftruncate(value._stream.fileno(), valid_size)
                os.fsync(value._stream.fileno())
            os.lseek(value._stream.fileno(), 0, os.SEEK_END)
            return value
        except Exception:
            if value is not None:
                value.close()
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @property
    def count(self) -> int:
        return self._count

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def file_identity(self) -> tuple[int, int]:
        return self._file_identity

    def record(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("journal record kind/payload is malformed")
        if self._poisoned:
            _fail("journal append stream is poisoned after an uncertain write")
        base = {
            "seq": self._count,
            "prevHash": self._head_hash,
            "kind": kind,
            "payload": payload,
        }
        record = {**base, "recordHash": alpha._canonical_sha(base)}
        raw = (json.dumps(record, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        written = 0
        try:
            while written < len(raw):
                count = self._stream.write(raw[written:])
                if type(count) is not int or count <= 0 or count > len(raw) - written:
                    _fail("journal append made invalid write progress")
                written += count
            self._stream.flush()
            os.fsync(self._stream.fileno())
        except BaseException:
            # The local bytes may now contain a non-newline partial record.
            # Never append another record in this process: restore-only first
            # validates/truncates the single torn suffix under an exclusive
            # lock, preventing concatenated fragments from becoming authority.
            self._poisoned = True
            raise
        self._count += 1
        self._head_hash = record["recordHash"]
        return record

    def close(self) -> None:
        if not self._stream.closed:
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(self._stream.fileno(), 0, os.SEEK_SET)
                    msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
            finally:
                self._stream.close()


def _parse_journal_prefix(
        raw: bytes, *, allow_torn_final: bool = False
        ) -> tuple[list[dict[str, Any]], int, bytes]:
    if type(raw) is not bytes or not raw:
        _fail("journal bytes are absent")
    torn = b""
    complete = raw
    if not raw.endswith(b"\n"):
        if not allow_torn_final:
            _fail("journal bytes are absent or truncated")
        boundary = raw.rfind(b"\n")
        if boundary < 0:
            _fail("journal has no complete durable record")
        complete = raw[:boundary + 1]
        torn = raw[boundary + 1:]
        if not torn:
            _fail("journal torn-tail classification is inconsistent")
    previous = "0" * 64
    records: list[dict[str, Any]] = []
    for count, line in enumerate(complete.splitlines()):
        try:
            value = json.loads(line.decode("ascii"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RecoveryError("journal is not canonical JSONL") from error
        wire = _exact_keys(value, {
            "kind", "payload", "prevHash", "recordHash", "seq",
        }, "journal record")
        if (wire["seq"] != count or type(wire["seq"]) is not int or
                wire["prevHash"] != previous or type(wire["kind"]) is not str or
                not wire["kind"] or type(wire["payload"]) is not dict):
            _fail("journal sequence or previous hash differs")
        base = {key: wire[key] for key in
                ("seq", "prevHash", "kind", "payload")}
        if wire["recordHash"] != alpha._canonical_sha(base):
            _fail("journal record hash differs")
        canonical = json.dumps(
            wire, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":")).encode("ascii")
        if line != canonical:
            _fail("journal record is not byte-canonical")
        if count == 0 and wire["kind"] != "header":
            _fail("journal header is absent")
        previous = wire["recordHash"]
        records.append(wire)
    if not records:
        _fail("journal is empty")
    if torn:
        _validate_torn_journal_fragment(
            torn, next_seq=len(records), previous_hash=previous,
            allowed_kinds=_possible_next_journal_kinds(records))
    return records, len(complete), torn


class _IncompleteJsonPrefix(Exception):
    pass


class _JsonPrefixParser:
    """Strict JSON prefix parser used only for a possible torn payload."""

    def __init__(self, text: str):
        self.text = text
        self.index = 0

    def _take(self) -> str:
        if self.index == len(self.text):
            raise _IncompleteJsonPrefix()
        value = self.text[self.index]
        self.index += 1
        return value

    def _literal(self, expected: str) -> None:
        for token in expected:
            if self._take() != token:
                _fail("journal torn tail is not a plausible JSON prefix")

    def _string(self) -> None:
        if self._take() != '"':
            _fail("journal torn tail JSON string is malformed")
        while True:
            value = self._take()
            if value == '"':
                return
            if ord(value) < 0x20:
                _fail("journal torn tail contains a JSON control character")
            if value != "\\":
                continue
            escape = self._take()
            if escape == "u":
                for _ in range(4):
                    if self._take() not in "0123456789abcdefABCDEF":
                        _fail("journal torn tail unicode escape is malformed")
            elif escape not in '\\"/bfnrt':
                _fail("journal torn tail JSON escape is malformed")

    def _number(self) -> None:
        start = self.index
        if self.text[self.index] == "-":
            self.index += 1
            if self.index == len(self.text):
                raise _IncompleteJsonPrefix()
        if self.text[self.index] == "0":
            self.index += 1
            if (self.index < len(self.text) and
                    self.text[self.index].isdigit()):
                _fail("journal torn tail number has a leading zero")
        elif self.text[self.index] in "123456789":
            self.index += 1
            while (self.index < len(self.text) and
                   self.text[self.index].isdigit()):
                self.index += 1
        else:
            _fail("journal torn tail number is malformed")
        if self.index < len(self.text) and self.text[self.index] == ".":
            self.index += 1
            if self.index == len(self.text):
                raise _IncompleteJsonPrefix()
            if not self.text[self.index].isdigit():
                _fail("journal torn tail number fraction is malformed")
            while (self.index < len(self.text) and
                   self.text[self.index].isdigit()):
                self.index += 1
        if (self.index < len(self.text) and
                self.text[self.index] in "eE"):
            self.index += 1
            if self.index == len(self.text):
                raise _IncompleteJsonPrefix()
            if self.text[self.index] in "+-":
                self.index += 1
                if self.index == len(self.text):
                    raise _IncompleteJsonPrefix()
            if not self.text[self.index].isdigit():
                _fail("journal torn tail number exponent is malformed")
            while (self.index < len(self.text) and
                   self.text[self.index].isdigit()):
                self.index += 1
        if self.index == start:
            _fail("journal torn tail number made no progress")

    def _value(self) -> None:
        if self.index == len(self.text):
            raise _IncompleteJsonPrefix()
        value = self.text[self.index]
        if value == "{":
            self.index += 1
            if self.index == len(self.text):
                raise _IncompleteJsonPrefix()
            if self.text[self.index] == "}":
                self.index += 1
                return
            while True:
                self._string()
                if self._take() != ":":
                    _fail("journal torn tail object colon is malformed")
                self._value()
                separator = self._take()
                if separator == "}":
                    return
                if separator != ",":
                    _fail("journal torn tail object separator is malformed")
        elif value == "[":
            self.index += 1
            if self.index == len(self.text):
                raise _IncompleteJsonPrefix()
            if self.text[self.index] == "]":
                self.index += 1
                return
            while True:
                self._value()
                separator = self._take()
                if separator == "]":
                    return
                if separator != ",":
                    _fail("journal torn tail array separator is malformed")
        elif value == '"':
            self._string()
        elif value == "t":
            self._literal("true")
        elif value == "f":
            self._literal("false")
        elif value == "n":
            self._literal("null")
        elif value == "-" or value.isdigit():
            self._number()
        else:
            _fail("journal torn tail JSON value is malformed")


def _validate_torn_journal_fragment(
        raw: bytes, *, next_seq: int, previous_hash: str,
        allowed_kinds: set[str]) -> None:
    """Accept only a prefix of the next fixed canonical JSONL envelope."""
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise RecoveryError("journal torn tail is not ASCII") from error
    if (not text or any(ord(value) < 0x20 or ord(value) > 0x7e
                        for value in text)):
        _fail("journal torn tail contains non-canonical bytes")
    opening = '{"kind":"'
    if len(text) <= len(opening):
        if not opening.startswith(text):
            _fail("journal torn tail is not the next canonical envelope")
        return
    if not text.startswith(opening):
        _fail("journal torn tail is not the next canonical envelope")
    remainder = text[len(opening):]
    quote = remainder.find('"')
    if not allowed_kinds:
        _fail("journal torn tail follows a terminal record")
    if quote < 0:
        if not any(kind.startswith(remainder) for kind in allowed_kinds):
            _fail("journal torn tail record kind is impossible")
        return
    kind = remainder[:quote]
    if kind not in allowed_kinds:
        _fail("journal torn tail record kind is impossible")
    after_kind = remainder[quote + 1:]
    payload_marker = ',"payload":'
    if len(after_kind) <= len(payload_marker):
        if not payload_marker.startswith(after_kind):
            _fail("journal torn tail payload marker is malformed")
        return
    if not after_kind.startswith(payload_marker):
        _fail("journal torn tail payload marker is malformed")
    payload_text = after_kind[len(payload_marker):]
    if not payload_text:
        return
    payload_opening = ('{"admissionSandwich":'
                       if kind == "rotation_lock_intent" else
                       '{"authority":')
    if len(payload_text) <= len(payload_opening):
        if not payload_opening.startswith(payload_text):
            _fail("journal torn tail payload cannot be canonical for its kind")
        return
    if not payload_text.startswith(payload_opening):
        _fail("journal torn tail payload cannot be canonical for its kind")
    if payload_text[0] != "{":
        _fail("journal torn tail payload must be an object")
    parser = _JsonPrefixParser(payload_text)
    try:
        parser._value()
    except _IncompleteJsonPrefix:
        return
    complete_payload = payload_text[:parser.index]
    try:
        payload = json.loads(complete_payload, object_pairs_hook=_unique_pairs)
    except json.JSONDecodeError as error:
        raise RecoveryError("journal torn payload is malformed") from error
    if type(payload) is not dict:
        _fail("journal torn tail payload must be an object")
    canonical_payload = json.dumps(
        payload, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"))
    if complete_payload != canonical_payload:
        _fail("journal torn tail payload is not canonical")
    base = {
        "seq": next_seq, "prevHash": previous_hash,
        "kind": kind, "payload": payload,
    }
    suffix = (',"prevHash":"' + previous_hash + '","recordHash":"' +
              alpha._canonical_sha(base) + '","seq":' + str(next_seq) + '}')
    observed_suffix = payload_text[parser.index:]
    if not suffix.startswith(observed_suffix):
        _fail("journal torn tail authority suffix is malformed")


def _possible_next_journal_kinds(
        records: list[dict[str, Any]]) -> set[str]:
    if len(records) == 1:
        return {"rotation_lock_intent"}
    if any(item["kind"] == "settlement" and
           item["payload"].get("kind") == "final_state"
           for item in records[1:]):
        return set()
    if any(item["kind"] == "rotation_restore_settlement"
           for item in records[1:]):
        return {"settlement"}
    if any(item["kind"] == "rotation_restore_intent"
           for item in records[1:]):
        return {"rotation_restore_settlement"}
    if any(item["kind"] == "settlement" and
           item["payload"].get("kind") == "cleanup_complete"
           for item in records[1:]):
        return {"rotation_restore_intent"}
    if not any(item["kind"] == "rotation_lock_settlement"
               for item in records[1:]):
        return {"rotation_lock_settlement", "rotation_restore_intent"}
    return {"mutation_intent", "settlement", "rotation_restore_intent"}


def validate_journal_bytes(raw: bytes) -> tuple[int, str]:
    records, _, torn = _parse_journal_prefix(raw)
    if torn:
        _fail("strict journal validation accepted a torn tail")
    return len(records), records[-1]["recordHash"]


def _validate_rotation_wire(value: Any, expected: tuple[str, str], *,
                            require_physical_zero: bool) -> dict[str, Any]:
    wire = _exact_keys(value, {
        "physicalRotation", "settingsAfter", "settingsBefore",
        "windowDisplaysSha256",
    }, "rotation sandwich")
    expected_wire = {
        "accelerometerRotation": expected[0],
        "userRotation": expected[1],
    }
    if (wire["settingsBefore"] != expected_wire or
            wire["settingsAfter"] != expected_wire or
            type(wire["physicalRotation"]) is not int or
            wire["physicalRotation"] not in range(4) or
            (require_physical_zero and wire["physicalRotation"] != 0) or
            type(wire["windowDisplaysSha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", wire["windowDisplaysSha256"]) is None):
        _fail("rotation sandwich differs from its closed authority")
    return wire


def _validate_file_identity_wire(value: Any, label: str) -> dict[str, Any]:
    wire = _exact_keys(value, {
        "device", "inode", "mtimeNs", "path", "sha256", "size",
    }, label)
    if (type(wire["path"]) is not str or not wire["path"] or
            not Path(wire["path"]).is_absolute() or
            type(wire["sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", wire["sha256"]) is None or
            any(type(wire[name]) is not int or wire[name] < 0
                for name in ("device", "inode", "mtimeNs", "size"))):
        _fail(label + " fields differ from exact file identity")
    if wire["device"] == 0 or wire["inode"] == 0 or wire["size"] == 0:
        _fail(label + " cannot identify an empty or anonymous file")
    return wire


def _validate_evidence_reservation_wire(value: Any) -> dict[str, Any]:
    wire = _exact_keys(value, {
        "device", "exclusive", "initialSize", "inode", "noFollow",
        "parent", "parentDevice", "parentInode", "path",
    }, "restore-only evidence reservation")
    if (type(wire["path"]) is not str or not wire["path"] or
            type(wire["parent"]) is not str or not wire["parent"] or
            not Path(wire["path"]).is_absolute() or
            not Path(wire["parent"]).is_absolute() or
            any(type(wire[name]) is not int or wire[name] < 0 for name in (
                "device", "inode", "parentDevice", "parentInode")) or
            any(wire[name] == 0 for name in (
                "device", "inode", "parentDevice", "parentInode")) or
            type(wire["initialSize"]) is not int or
            wire["initialSize"] != 0 or
            wire["exclusive"] is not True or wire["noFollow"] is not True or
            os.path.normcase(str(Path(wire["path"]).parent)) !=
            os.path.normcase(wire["parent"])):
        _fail("restore-only evidence reservation authority differs")
    return wire


def _validate_uncertainty(value: Any, label: str) -> None:
    if value is not None and type(value) is not str:
        _fail(label + " transport uncertainty is malformed")


def _validate_host_absence(value: Any) -> None:
    if type(value) is not list or len(value) != 2:
        _fail("host absence settlement must contain two observations")
    for item in value:
        wire = _exact_keys(item, {
            "activitiesSha256", "displaysSha256", "documentGloballyAbsent",
            "hostPids", "windowsSha256",
        }, "host absence observation")
        if (wire["documentGloballyAbsent"] is not True or
                wire["hostPids"] != [] or
                any(type(wire[name]) is not str or
                    re.fullmatch(r"[0-9a-f]{64}", wire[name]) is None
                    for name in ("activitiesSha256", "displaysSha256",
                                 "windowsSha256"))):
            _fail("host absence observation authority differs")


def _validate_quarantine_object(
        value: Any, source: str, quarantine: str,
        authority: ReportAuthority) -> None:
    wire = _exact_keys(value, {
        "device", "gid", "inode", "kind", "path", "sha256", "size", "uid",
    }, "quarantine retained object")
    retained = (authority.retained_mark if source == alpha.TARGET_MARK
                else authority.retained_pdf)
    expected = asdict(retained)
    expected["path"] = quarantine
    if wire != expected:
        _fail("quarantine retained object differs from report authority")


def _validate_process_wire(
        value: Any, *, package: str, uid: int, label: str) -> None:
    wire = _exact_keys(value, {
        "package", "pid", "start_ticks", "uid"}, label)
    if (wire["package"] != package or wire["uid"] != uid or
            any(type(wire[name]) is not int or wire[name] <= 0
                for name in ("pid", "start_ticks")) or
            type(wire["uid"]) is not int):
        _fail(label + " identity differs")


def _validate_host_scope_wire(value: Any) -> None:
    wire = _exact_keys(value, {
        "activity_authority_lines", "activity_display_id", "activity_token",
        "component", "focused", "resumed", "task_id", "task_token",
        "visible", "window_authority_lines", "window_display_id",
        "window_session_token", "window_token",
    }, "host scope settlement")
    if (wire["component"] != alpha.HOST_COMPONENT or
            wire["activity_display_id"] != 0 or
            wire["window_display_id"] != 0 or
            any(type(wire[name]) is not int or wire[name] < 0
                for name in ("task_id", "activity_display_id",
                             "window_display_id")) or
            any(wire[name] is not True for name in (
                "focused", "resumed", "visible")) or
            any(type(wire[name]) is not str or not wire[name] for name in (
                "activity_token", "task_token", "window_session_token",
                "window_token")) or
            any(type(wire[name]) is not list or not wire[name] or
                any(type(line) is not str or not line for line in wire[name])
                for name in ("activity_authority_lines",
                             "window_authority_lines"))):
        _fail("host scope settlement identity differs")


def _validate_virtual_display_wire(value: Any) -> None:
    wire = _exact_keys(value, {
        "device_authority_lines", "display_id", "display_token",
        "layer_stack", "logical_authority_lines", "name", "owner_package",
        "owner_uid", "surface_token", "unique_id",
    }, "virtual display settlement")
    if (type(wire["display_id"]) is not int or wire["display_id"] <= 0 or
            type(wire["layer_stack"]) is not int or wire["layer_stack"] <= 0 or
            wire["owner_package"] != alpha.HOST_PACKAGE or
            wire["owner_uid"] != PINNED_HOST_UID or
            type(wire["owner_uid"]) is not int or
            any(type(wire[name]) is not str or not wire[name] for name in (
                "display_token", "name", "surface_token", "unique_id")) or
            any(type(wire[name]) is not list or not wire[name] or
                any(type(line) is not str or not line for line in wire[name])
                for name in ("device_authority_lines",
                             "logical_authority_lines"))):
        _fail("virtual display settlement identity differs")


def _validate_generic_device_file(
        value: Any, path: str, sha256: str, label: str) -> None:
    wire = _exact_keys(value, {
        "device", "gid", "inode", "kind", "path", "sha256", "size", "uid",
    }, label)
    if (wire["path"] != path or wire["sha256"] != sha256 or
            wire["kind"] != "regular file" or
            any(type(wire[name]) is not int or wire[name] < 0 for name in (
                "device", "gid", "inode", "size", "uid")) or
            wire["device"] == 0 or wire["inode"] == 0 or wire["size"] == 0):
        _fail(label + " differs")


def _validate_descriptor_authority(value: Any) -> tuple[str, str]:
    wire = _exact_keys(value, {
        "documentProcess", "mode", "observations",
    }, "cleanup descriptor authority")
    _validate_process_wire(
        wire["documentProcess"], package=alpha.DOCUMENT_PACKAGE, uid=1000,
        label="cleanup Document process")
    mode = wire["mode"]
    observations = wire["observations"]
    if (mode not in {DESCRIPTOR_AUTHORITY_PARKING_ONLY,
                     DESCRIPTOR_AUTHORITY_IDLE_ZERO} or
            type(observations) is not list or len(observations) != 2):
        _fail("cleanup descriptor mode/observation count differs")
    for observation in observations:
        item = _exact_keys(observation, {
            "activitiesSha256", "documentTaskWindowAbsent",
            "fdInventorySha256", "relevantTargets", "windowsSha256",
        }, "descriptor observation")
        expected_targets = ([alpha.PARKING_PDF]
                            if mode == DESCRIPTOR_AUTHORITY_PARKING_ONLY
                            else [])
        if (item["relevantTargets"] != expected_targets or
                item["documentTaskWindowAbsent"] is not True or
                any(type(item[name]) is not str or
                    re.fullmatch(r"[0-9a-f]{64}", item[name]) is None
                    for name in ("activitiesSha256", "fdInventorySha256",
                                 "windowsSha256"))):
            _fail("descriptor observation authority differs")
    return mode, alpha._canonical_sha(wire["documentProcess"])


def _validate_document_authority(value: Any) -> tuple[str, str]:
    wire = _exact_keys(value, {
        "descriptorAuthority"}, "cleanup document authority")
    return _validate_descriptor_authority(wire["descriptorAuthority"])


def _validate_static_authority(value: Any) -> None:
    wire = _exact_keys(value, {
        "parkingMarkAbsent", "parkingPdf", "sourceMark", "sourcePdf",
    }, "cleanup static-file authority")
    if wire["parkingMarkAbsent"] is not True:
        _fail("cleanup parking mark absence differs")
    _validate_generic_device_file(
        wire["sourcePdf"], alpha.SOURCE_PDF, alpha.SOURCE_PDF_SHA256,
        "source PDF authority")
    _validate_generic_device_file(
        wire["sourceMark"], alpha.SOURCE_MARK, alpha.SOURCE_MARK_SHA256,
        "source mark authority")
    _validate_generic_device_file(
        wire["parkingPdf"], alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256,
        "parking PDF authority")


def _cleanup_sequences() -> list[list[str]]:
    host_paths = [
        ["I:host_main_refocus", "S:host_main_refocus",
         "I:empty_display_abort", "S:empty_display_abort_and_release",
         "S:host_absent_twice"],
        ["S:host_absent_twice"],
    ]

    def members(source: str) -> list[list[str]]:
        return [
            ["S:target_already_absent:" + source],
            ["S:preexisting_quarantine_verified:" + source,
             "I:quarantine_delete_attempt:" + source,
             "S:quarantine_absent_after_delete:" + source],
            ["I:quarantine_move_attempt:" + source,
             "S:target_quarantined:" + source,
             "I:quarantine_delete_attempt:" + source,
             "S:quarantine_absent_after_delete:" + source],
        ]
    return [host_path + mark_path + pdf_path
            for host_path in host_paths
            for mark_path in members(alpha.TARGET_MARK)
            for pdf_path in members(alpha.TARGET_PDF)]


def _validate_restore_journal(
        records: list[dict[str, Any]], authority: ReportAuthority,
        helper_identity: dict[str, Any]) -> dict[str, Any]:
    """Validate the finite execution grammar; authorize rollback only."""
    if not records or records[0]["kind"] != "header" or any(
            item["kind"] == "header" for item in records[1:]):
        _fail("restore-only journal header topology differs")
    header = _exact_keys(records[0]["payload"], {
        "authority", "descriptorAuthority", "device", "evidenceReservation", "helper",
        "readOnlyAdmissionSha256", "reportSha256", "rotationLease",
        "schemaVersion",
    }, "restore-only journal header")
    if (header["authority"] != RECOVERY_AUTHORITY or
            type(header["schemaVersion"]) is not int or
            header["schemaVersion"] != 1 or
            header["reportSha256"] != authority.report_sha256 or
            header["helper"] != helper_identity or
            type(header["readOnlyAdmissionSha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}",
                         header["readOnlyAdmissionSha256"]) is None):
        _fail("restore-only journal header authority differs")
    _validate_file_identity_wire(header["helper"], "restore-only helper")
    _validate_evidence_reservation_wire(header["evidenceReservation"])
    header_descriptor_semantics = _validate_descriptor_authority(
        header["descriptorAuthority"])
    device = _exact_keys(header["device"], {
        "adb", "documentApkSha256", "documentPackage", "fingerprint",
        "hostApkSha256", "hostPackage", "model", "sdk", "serial",
    }, "restore-only journal device")
    adb = _validate_file_identity_wire(
        device["adb"], "restore-only adb identity")
    if (device["serial"] != alpha.AUTHORIZED_SERIAL or
            device["model"] != alpha.MODEL or device["sdk"] != alpha.SDK or
            device["fingerprint"] != alpha.FINGERPRINT or
            device["hostPackage"] != alpha.HOST_PACKAGE or
            device["hostApkSha256"] != alpha.ALPHA_SIGNED_APK_SHA256 or
            device["documentPackage"] != alpha.DOCUMENT_PACKAGE or
            device["documentApkSha256"] != alpha.DOCUMENT_APK_SHA256 or
            adb["path"] != str(PINNED_ADB_PATH) or
            adb["size"] != PINNED_ADB_SIZE or
            adb["sha256"] != PINNED_ADB_SHA256):
        _fail("restore-only journal is bound to another device/toolchain")
    lease = _exact_keys(header["rotationLease"], {
        "authority", "commandDialects", "originalPersisted",
        "readOnlyAdmissionSandwich",
    }, "restore-only rotation lease")
    if (lease["authority"] != ROTATION_LEASE_AUTHORITY or
            lease["commandDialects"] != ROTATION_COMMAND_DIALECTS or
            lease["originalPersisted"] != {
                "accelerometerRotation": "1", "userRotation": "2"}):
        _fail("restore-only command dialect or original rotation differs")
    _validate_rotation_wire(
        lease["readOnlyAdmissionSandwich"], ("1", "2"),
        require_physical_zero=False)

    allowed_cleanup = _cleanup_sequences()
    cleanup_events: list[str] = []
    intent_kinds: list[str] = []
    next_ordinal = 1
    lock_intent = False
    lock_settlement = False
    restore_intent = False
    restore_settlement: dict[str, Any] | None = None
    cleanup_complete = False
    final_seen = False
    abort_digest: str | None = None
    descriptor_semantics: tuple[str, str] | None = header_descriptor_semantics

    def bind_descriptor(value: Any) -> None:
        nonlocal descriptor_semantics
        current = _validate_descriptor_authority(value)
        if descriptor_semantics is None:
            descriptor_semantics = current
        elif descriptor_semantics != current:
            _fail("cleanup descriptor mode/process changed across journal")

    def require_cleanup_prefix() -> None:
        if not any(sequence[:len(cleanup_events)] == cleanup_events
                   for sequence in allowed_cleanup):
            _fail("cleanup records are not a legal finite execution prefix")

    def add_cleanup_event(token: str) -> None:
        if restore_intent or cleanup_complete or final_seen:
            _fail("cleanup record follows its terminal boundary")
        cleanup_events.append(token)
        require_cleanup_prefix()

    for record in records[1:]:
        kind = record["kind"]
        payload = record["payload"]
        if final_seen:
            _fail("journal record follows terminal final state")
        if kind == "rotation_lock_intent":
            if lock_intent or len(records) < 2 or record is not records[1]:
                _fail("rotation lock intent is duplicated or out of order")
            wire = _exact_keys(payload, {
                "admissionSandwich", "authority", "commandDialect",
                "reportSha256", "rollbackCommandDialects", "target",
            }, "rotation lock intent")
            if (wire["authority"] != ROTATION_LEASE_AUTHORITY or
                    wire["reportSha256"] != authority.report_sha256 or
                    wire["commandDialect"] != ROTATION_COMMAND_DIALECTS["acquire"] or
                    wire["rollbackCommandDialects"] != {
                        "lockTwo": ROTATION_COMMAND_DIALECTS["restoreUserRotation"],
                        "free": ROTATION_COMMAND_DIALECTS["restoreSensor"]} or
                    wire["target"] != {
                        "accelerometerRotation": "0", "userRotation": "0",
                        "physicalRotation": 0}):
                _fail("rotation lock intent authority differs")
            _validate_rotation_wire(
                wire["admissionSandwich"], ("1", "2"),
                require_physical_zero=False)
            lock_intent = True
        elif kind == "rotation_lock_settlement":
            if (not lock_intent or lock_settlement or restore_intent or
                    cleanup_events):
                _fail("rotation lock settlement is out of order")
            wire = _exact_keys(payload, {
                "authority", "commandDialect", "observations",
                "reportSha256", "transportUncertain",
            }, "rotation lock settlement")
            _validate_uncertainty(
                wire["transportUncertain"], "rotation lock")
            if (wire["authority"] != ROTATION_LEASE_AUTHORITY or
                    wire["reportSha256"] != authority.report_sha256 or
                    wire["commandDialect"] != ROTATION_COMMAND_DIALECTS["acquire"] or
                    type(wire["observations"]) is not list or
                    len(wire["observations"]) != 2):
                _fail("rotation lock settlement authority differs")
            for observation in wire["observations"]:
                _validate_rotation_wire(
                    observation, ("0", "0"), require_physical_zero=True)
            lock_settlement = True
        elif kind == "mutation_intent":
            if not lock_settlement or restore_intent:
                _fail("cleanup mutation exists outside the owned lease")
            wire = _exact_keys(payload, {
                "authority", "descriptorAuthority", "intent", "ordinal",
                "reportSha256",
            }, "cleanup mutation intent")
            if (wire["authority"] != RECOVERY_AUTHORITY or
                    wire["reportSha256"] != authority.report_sha256 or
                    type(wire["ordinal"]) is not int or
                    wire["ordinal"] != next_ordinal):
                _fail("cleanup mutation ordinal/authority differs")
            bind_descriptor(wire["descriptorAuthority"])
            next_ordinal += 1
            intent = wire["intent"]
            if type(intent) is not dict or type(intent.get("kind")) is not str:
                _fail("cleanup mutation intent shape differs")
            mutation_kind = intent["kind"]
            if mutation_kind == "host_main_refocus":
                _exact_keys(intent, {"kind", "sequence"}, mutation_kind)
                if intent["sequence"] is not None:
                    _fail("host refocus sequence differs")
                token = "I:host_main_refocus"
            elif mutation_kind == "empty_display_abort":
                _exact_keys(intent, {
                    "absenceEvidenceSha256", "action", "kind", "sequence",
                }, mutation_kind)
                if (intent["action"] != ACTION_FAILED or
                        type(intent["sequence"]) is not int or
                        intent["sequence"] != 1 or
                        type(intent["absenceEvidenceSha256"]) is not str or
                        re.fullmatch(r"[0-9a-f]{64}",
                                     intent["absenceEvidenceSha256"]) is None):
                    _fail("empty-display abort intent differs")
                abort_digest = intent["absenceEvidenceSha256"]
                token = "I:empty_display_abort"
            elif mutation_kind in {
                    "quarantine_move_attempt", "quarantine_delete_attempt"}:
                _exact_keys(intent, {
                    "kind", "quarantine", "source"}, mutation_kind)
                source = intent["source"]
                if (source not in QUARANTINES or
                        intent["quarantine"] != QUARANTINES[source]):
                    _fail("quarantine intent escaped the retained targets")
                token = "I:" + mutation_kind + ":" + source
            else:
                _fail("cleanup mutation kind is unknown")
            intent_kinds.append(mutation_kind)
            add_cleanup_event(token)
        elif kind == "rotation_restore_intent":
            if not lock_intent or restore_intent or restore_settlement is not None:
                _fail("rotation restore intent is duplicated or out of order")
            require_cleanup_prefix()
            wire = _exact_keys(payload, {
                "authority", "commandDialects", "reportSha256",
                "targetPersisted",
            }, "rotation restore intent")
            if (wire["authority"] != ROTATION_LEASE_AUTHORITY or
                    wire["reportSha256"] != authority.report_sha256 or
                    wire["commandDialects"] != {
                        "lockTwo": ROTATION_COMMAND_DIALECTS["restoreUserRotation"],
                        "free": ROTATION_COMMAND_DIALECTS["restoreSensor"]} or
                    wire["targetPersisted"] != {
                        "accelerometerRotation": "1", "userRotation": "2"}):
                _fail("rotation restore intent authority differs")
            restore_intent = True
        elif kind == "rotation_restore_settlement":
            if not restore_intent or restore_settlement is not None:
                _fail("rotation restore settlement is out of order")
            wire = _exact_keys(payload, {
                "authority", "commandDialects", "freeTransportUncertain",
                "lockTwoTransportUncertain", "observations", "reportSha256",
            }, "rotation restore settlement")
            _validate_uncertainty(
                wire["freeTransportUncertain"], "rotation free")
            _validate_uncertainty(
                wire["lockTwoTransportUncertain"], "rotation lock-two")
            if (wire["authority"] != ROTATION_LEASE_AUTHORITY or
                    wire["reportSha256"] != authority.report_sha256 or
                    wire["commandDialects"] != {
                        "lockTwo": ROTATION_COMMAND_DIALECTS["restoreUserRotation"],
                        "free": ROTATION_COMMAND_DIALECTS["restoreSensor"]} or
                    type(wire["observations"]) is not list or
                    len(wire["observations"]) != 2):
                _fail("rotation restore settlement authority differs")
            for observation in wire["observations"]:
                _validate_rotation_wire(
                    observation, ("1", "2"), require_physical_zero=False)
            restore_settlement = wire
        elif kind == "settlement":
            if not lock_settlement:
                _fail("cleanup settlement exists outside the owned lease")
            if (type(payload) is not dict or
                    payload.get("authority") != RECOVERY_AUTHORITY or
                    payload.get("reportSha256") != authority.report_sha256 or
                    type(payload.get("kind")) is not str):
                _fail("cleanup settlement authority differs")
            settlement_kind = payload["kind"]
            if settlement_kind == "final_state":
                wire = _exact_keys(payload, {
                    "authority", "cleanupComplete", "kind", "mutationKinds",
                    "reportSha256", "rotationRestoration",
                }, "final state settlement")
                if (restore_settlement is None or not cleanup_complete or
                        wire["cleanupComplete"] is not True or
                        wire["mutationKinds"] != intent_kinds or
                        wire["rotationRestoration"] != restore_settlement):
                    _fail("final state precedes exact cleanup/restoration")
                final_seen = True
                continue
            if restore_intent:
                _fail("cleanup settlement follows rotation restore intent")
            if settlement_kind == "host_main_refocus":
                wire = _exact_keys(payload, {
                    "authority", "hostScope", "kind", "logLine", "process",
                    "reportSha256", "state", "transportUncertain",
                    "virtualDisplay",
                }, "host refocus settlement")
                _validate_uncertainty(wire["transportUncertain"], "host refocus")
                if (wire["state"] != "FAILED" or
                        type(wire["logLine"]) is not str or
                        any(type(wire[name]) is not dict for name in (
                            "hostScope", "process", "virtualDisplay"))):
                    _fail("host refocus settlement shape differs")
                _validate_process_wire(
                    wire["process"], package=alpha.HOST_PACKAGE,
                    uid=PINNED_HOST_UID, label="host refocus process")
                _validate_host_scope_wire(wire["hostScope"])
                _validate_virtual_display_wire(wire["virtualDisplay"])
                token = "S:host_main_refocus"
            elif settlement_kind == "empty_display_abort_and_release":
                wire = _exact_keys(payload, {
                    "abortLogLine", "absenceEvidenceSha256", "authority",
                    "kind", "releaseLogLine", "reportSha256", "sequence",
                    "transportUncertain",
                }, "empty-display abort settlement")
                _validate_uncertainty(wire["transportUncertain"], "empty abort")
                if (type(wire["sequence"]) is not int or wire["sequence"] != 1 or
                        type(wire["absenceEvidenceSha256"]) is not str or
                        re.fullmatch(r"[0-9a-f]{64}",
                                     wire["absenceEvidenceSha256"]) is None or
                        any(type(wire[name]) is not str for name in (
                            "abortLogLine", "releaseLogLine"))):
                    _fail("empty-display abort settlement shape differs")
                if (abort_digest is None or
                        wire["absenceEvidenceSha256"] != abort_digest):
                    _fail("empty-display abort digest differs from its intent")
                token = "S:empty_display_abort_and_release"
            elif settlement_kind == "host_absent_twice":
                wire = _exact_keys(payload, {
                    "authority", "kind", "observations", "reportSha256",
                }, "host absence settlement")
                _validate_host_absence(wire["observations"])
                token = "S:host_absent_twice"
            elif settlement_kind in {
                    "target_quarantined", "preexisting_quarantine_verified"}:
                expected_keys = {
                    "authority", "kind", "quarantine", "reportSha256",
                    "retainedObject", "source",
                }
                if settlement_kind == "target_quarantined":
                    expected_keys.add("transportUncertain")
                wire = _exact_keys(payload, expected_keys,
                                   settlement_kind + " settlement")
                source = wire["source"]
                if source not in QUARANTINES or wire["quarantine"] != QUARANTINES[source]:
                    _fail("quarantine settlement escaped the retained targets")
                _validate_quarantine_object(
                    wire["retainedObject"], source, QUARANTINES[source],
                    authority)
                if settlement_kind == "target_quarantined":
                    _validate_uncertainty(
                        wire["transportUncertain"], "quarantine move")
                token = "S:" + settlement_kind + ":" + source
            elif settlement_kind in {
                    "target_already_absent", "quarantine_absent_after_delete"}:
                expected_keys = {
                    "authority", "kind", "observations", "quarantine",
                    "reportSha256", "source",
                }
                if settlement_kind == "quarantine_absent_after_delete":
                    expected_keys.add("transportUncertain")
                wire = _exact_keys(payload, expected_keys,
                                   settlement_kind + " settlement")
                source = wire["source"]
                if (source not in QUARANTINES or
                        wire["quarantine"] != QUARANTINES[source] or
                        type(wire["observations"]) is not int or
                        wire["observations"] != 2):
                    _fail("quarantine absence settlement differs")
                if settlement_kind == "quarantine_absent_after_delete":
                    _validate_uncertainty(
                        wire["transportUncertain"], "quarantine delete")
                token = "S:" + settlement_kind + ":" + source
            elif settlement_kind == "cleanup_complete":
                if cleanup_complete:
                    _fail("cleanup completion is duplicated")
                wire = _exact_keys(payload, {
                    "adb", "authority", "document", "hostAbsence", "kind",
                    "mutationKinds", "reportSha256", "rotation", "staticFiles",
                }, "cleanup complete settlement")
                _validate_host_absence(wire["hostAbsence"])
                _validate_rotation_wire(
                    wire["rotation"], ("0", "0"), require_physical_zero=True)
                completed_descriptor = _validate_document_authority(
                    wire["document"])
                if (descriptor_semantics is not None and
                        completed_descriptor != descriptor_semantics):
                    _fail("cleanup completion descriptor mode/process differs")
                descriptor_semantics = completed_descriptor
                _validate_static_authority(wire["staticFiles"])
                if (wire["adb"] != adb or wire["mutationKinds"] != intent_kinds or
                        not any(sequence == cleanup_events
                                for sequence in allowed_cleanup)):
                    _fail("cleanup completion lacks an exact complete execution")
                cleanup_complete = True
                continue
            else:
                _fail("cleanup settlement kind is unknown")
            add_cleanup_event(token)
        else:
            _fail("restore-only journal contains an unknown record kind")
    if not lock_intent:
        if len(records) != 1:
            _fail("no-attempt journal contains a record after its header")
        return {
            "cleanupComplete": False,
            "restoreIntent": False,
            "restoreSettlement": False,
            "noAttempt": True,
            "phase": "NO_ATTEMPT",
            "journalDevice": device,
        }
    require_cleanup_prefix()
    return {
        "cleanupComplete": cleanup_complete,
        "restoreIntent": restore_intent,
        "restoreSettlement": restore_settlement is not None,
        "noAttempt": False,
        "phase": ("FINAL" if final_seen else "RESTORED"
                  if restore_settlement is not None else "RESTORE_INTENDED"
                  if restore_intent else "LEASED" if lock_settlement
                  else "LOCK_INTENDED"),
        "journalDevice": device,
    }


class EvidenceReservation:
    """Exclusive evidence descriptor acquired before any device mutation.

    An execute crash may leave this reserved file empty or partial.  That is
    deliberate: its identity is bound into the canonical journal, the journal
    independently prevents replay, and a later process must never reuse or
    overwrite the reservation.
    """

    def __init__(self, path: Path):
        target = path.absolute()
        if (not target.name or target.name in {".", ".."} or
                ":" in target.name):
            _fail("evidence output leaf is malformed or aliases a stream")
        parent = target.parent
        try:
            parent_before = os.lstat(parent)
        except OSError as error:
            raise RecoveryError("evidence parent is absent or unreadable") from error
        if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(
                parent_before.st_mode):
            _fail("evidence parent must be a non-symlink directory")
        try:
            resolved_parent = parent.resolve(strict=True)
        except OSError as error:
            raise RecoveryError("evidence parent cannot be resolved") from error
        if os.path.normcase(str(resolved_parent)) != os.path.normcase(str(parent)):
            _fail("evidence parent aliases another directory")
        if os.path.lexists(target):
            _fail("refusing to overwrite or follow recovery evidence")
        flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            descriptor = os.open(target, flags, 0o600)
        except OSError as error:
            raise RecoveryError(
                "evidence output cannot be exclusively reserved") from error
        self.path = target
        self._descriptor = descriptor
        self._written = False
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size != 0 or
                    opened.st_nlink != 1):
                _fail("exclusive evidence reservation is not one empty regular file")
            after_path = os.lstat(target)
            parent_after = os.lstat(parent)
            if (stat.S_ISLNK(after_path.st_mode) or
                    (after_path.st_dev, after_path.st_ino) !=
                    (opened.st_dev, opened.st_ino) or
                    (parent_after.st_dev, parent_after.st_ino) !=
                    (parent_before.st_dev, parent_before.st_ino)):
                _fail("evidence path or parent changed during reservation")
            self._parent_identity = (
                parent_before.st_dev, parent_before.st_ino)
            self._file_identity = (opened.st_dev, opened.st_ino)
            self.authority = {
                "path": str(target),
                "parent": str(parent),
                "parentDevice": parent_before.st_dev,
                "parentInode": parent_before.st_ino,
                "device": opened.st_dev,
                "inode": opened.st_ino,
                "initialSize": 0,
                "exclusive": True,
                "noFollow": True,
            }
        except Exception:
            os.close(descriptor)
            self._descriptor = -1
            raise

    def _revalidate(self, expected_size: int) -> None:
        if self._descriptor < 0:
            _fail("evidence reservation is closed")
        current = os.fstat(self._descriptor)
        try:
            path_state = os.lstat(self.path)
            parent_state = os.lstat(self.path.parent)
        except OSError as error:
            raise RecoveryError(
                "evidence reservation path disappeared") from error
        if (not stat.S_ISREG(current.st_mode) or
                current.st_size != expected_size or current.st_nlink != 1 or
                stat.S_ISLNK(path_state.st_mode) or
                (current.st_dev, current.st_ino) != self._file_identity or
                (path_state.st_dev, path_state.st_ino) != self._file_identity or
                (parent_state.st_dev, parent_state.st_ino) !=
                self._parent_identity):
            _fail("evidence reservation identity changed")

    def write(self, value: dict[str, Any]) -> None:
        if self._written:
            _fail("evidence reservation was already consumed")
        raw = (json.dumps(value, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, indent=2) + "\n").encode("ascii")
        self._revalidate(0)
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        written = 0
        while written < len(raw):
            count = os.write(self._descriptor, raw[written:])
            if count <= 0:
                _fail("evidence descriptor write made no progress")
            written += count
        os.ftruncate(self._descriptor, len(raw))
        os.fsync(self._descriptor)
        self._revalidate(len(raw))
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        observed = b""
        while len(observed) < len(raw):
            chunk = os.read(self._descriptor, len(raw) - len(observed))
            if not chunk:
                break
            observed += chunk
        if observed != raw:
            _fail("durable evidence descriptor reread differs")
        self._revalidate(len(raw))
        self._written = True

    def assert_reserved(self) -> None:
        if self._written:
            _fail("evidence reservation was already consumed")
        self._revalidate(0)

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


def write_evidence(path: Path, value: dict[str, Any]) -> None:
    reservation = EvidenceReservation(path)
    try:
        reservation.write(value)
    finally:
        reservation.close()


def _assert_restore_only_device(device: RecoveryNomad,
                                journal_device: dict[str, Any]) -> dict[str, Any]:
    adb_identity = device.adb_authority()
    if adb_identity != journal_device["adb"]:
        _fail("restore-only adb identity differs from journal authority")
    if (device.get_state() != "device" or
            device.get_serial() != alpha.AUTHORIZED_SERIAL or
            device.getprop("ro.product.model") != alpha.MODEL or
            device.getprop("ro.build.version.sdk") != alpha.SDK or
            device.getprop("ro.build.fingerprint") != alpha.FINGERPRINT or
            device.current_user() != "0"):
        _fail("restore-only connected device differs from journal authority")
    return adb_identity


def _retire_no_attempt_journal(
        journal_path: Path, raw: bytes, journal_identity: dict[str, Any],
        records: list[dict[str, Any]]) -> dict[str, Any]:
    """Archive an exact pre-lock crash ledger without device mutation."""
    if len(records) != 1 or records[0]["kind"] != "header":
        _fail("no-attempt retirement requires exactly one durable header")
    digest = alpha._sha(raw)
    archive = journal_path.with_name(
        journal_path.name + ".no-attempt-" + digest[:16] + ".retired")
    if os.path.lexists(archive):
        _fail("no-attempt journal archive already exists")
    # Lock and re-prove the complete byte stream, including any one validated
    # torn first-intent suffix.  No append is attempted against that suffix.
    locked = DurableJournal.resume(
        journal_path, count=1, head_hash=records[0]["recordHash"],
        valid_size=len(raw), expected_prefix_sha256=digest,
        expected_identity=journal_identity)
    locked.close()
    current_raw, current_identity = _read_pinned_regular(
        journal_path, JOURNAL_MAX_BYTES, "no-attempt recovery journal")
    if (current_raw != raw or
            (current_identity["device"], current_identity["inode"]) !=
            (journal_identity["device"], journal_identity["inode"])):
        _fail("no-attempt recovery journal changed before retirement")
    if os.path.lexists(archive):
        _fail("no-attempt journal archive appeared before retirement")
    try:
        os.rename(journal_path, archive)
    except OSError as error:
        raise RecoveryError("no-attempt journal could not be retired") from error
    archived_raw, archived_identity = _read_pinned_regular(
        archive, JOURNAL_MAX_BYTES, "retired no-attempt journal")
    if (archived_raw != raw or
            (archived_identity["device"], archived_identity["inode"]) !=
            (journal_identity["device"], journal_identity["inode"]) or
            os.path.lexists(journal_path)):
        _fail("retired no-attempt journal identity differs")
    if os.name != "nt":
        descriptor = os.open(archive.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {**archived_identity, "originalPath": str(journal_path)}


def _run_reserved_restore_only(
        args: argparse.Namespace, authority: ReportAuthority,
        journal_path: Path, reservation: EvidenceReservation) -> int:
    raw, journal_identity = _read_pinned_regular(
        journal_path, JOURNAL_MAX_BYTES, "canonical recovery journal")
    records, valid_size, torn = _parse_journal_prefix(
        raw, allow_torn_final=True)
    _, helper_identity = _read_pinned_regular(
        Path(__file__), HELPER_MAX_BYTES, "recovery helper")
    state = _validate_restore_journal(records, authority, helper_identity)
    device = RecoveryNomad(args.adb, alpha.AUTHORIZED_SERIAL)
    adb_identity = _assert_restore_only_device(device, state["journalDevice"])
    reservation.assert_reserved()
    evidence: dict[str, Any] = {
        "authority": RECOVERY_AUTHORITY,
        "schemaVersion": 1,
        "mode": "restore-only",
        "pinnedReport": {
            "path": str(authority.report_path),
            "sha256": authority.report_sha256,
        },
        "journalBefore": {
            **journal_identity,
            "validSize": valid_size,
            "recordCount": len(records),
            "headHash": records[-1]["recordHash"],
            "tornFinalFragment": None if not torn else {
                "size": len(torn), "sha256": alpha._sha(torn)},
        },
        "cleanupCompleteBeforeRestore": state["cleanupComplete"],
        "proofs": [],
        "mutations": [],
        "result": "NOT_RUN",
        "evidenceReservation": reservation.authority,
    }
    journal: DurableJournal | None = None
    exit_code = 0
    recovery = Recovery(
        device, authority, sleep=lambda seconds: time.sleep(seconds),
        journal=None, evidence_guard=reservation.assert_reserved,
        header_helper_identity=helper_identity,
        header_adb_identity=state["journalDevice"]["adb"])
    recovery.evidence = evidence
    recovery.adb_identity = adb_identity
    try:
        if state["noAttempt"]:
            recovery._assert_execution_identity("no-attempt observation")
            observations = [recovery._rotation_admission_sandwich()]
            recovery.sleep(POLL_SECONDS)
            recovery._assert_execution_identity("no-attempt observation")
            observations.append(recovery._rotation_admission_sandwich())
            evidence["noAttemptRotation"] = observations
            evidence["journalArchive"] = _retire_no_attempt_journal(
                journal_path, raw, journal_identity, records)
            evidence["result"] = "NO_ATTEMPT_JOURNAL_RETIRED"
        elif state["restoreSettlement"]:
            recovery._assert_execution_identity(
                "already-restored observation")
            observations = [recovery._restored_rotation_observation()]
            recovery.sleep(POLL_SECONDS)
            recovery._assert_execution_identity(
                "already-restored observation")
            observations.append(recovery._restored_rotation_observation())
            recovery.rotation_restored = True
            recovery._proof(
                "rotation_already_restored", observations=observations)
            evidence["result"] = "ROTATION_ALREADY_RESTORED"
        else:
            recovery.rotation_lease_intent = True
            journal = DurableJournal.resume(
                journal_path, count=len(records),
                head_hash=records[-1]["recordHash"], valid_size=valid_size,
                expected_prefix_sha256=alpha._sha(raw[:valid_size]),
                expected_identity=journal_identity)
            recovery.journal = journal
            settlement = recovery._restore_rotation_lease(
                record_intent=not state["restoreIntent"])
            evidence["rotationRestoration"] = settlement
            evidence["result"] = (
                "CLEANUP_COMPLETE_ROTATION_RESTORED_ONLY"
                if state["cleanupComplete"] else
                "CLEANUP_FAILED_ROTATION_RESTORED")
    except Exception as error:
        evidence["result"] = (
            "NO_ATTEMPT_RETIREMENT_FAILED" if state["noAttempt"] else
            "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED"
            if state["cleanupComplete"] else
            "CLEANUP_FAILED_ROTATION_RESTORE_FAILED")
        evidence["error"] = type(error).__name__ + ": " + str(error)
        exit_code = 1
    finally:
        if journal is not None:
            try:
                journal.close()
            except Exception as error:
                evidence["result"] = (
                    "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED"
                    if state["cleanupComplete"] else
                    "CLEANUP_FAILED_ROTATION_RESTORE_FAILED")
                evidence["journalCloseError"] = (
                    type(error).__name__ + ": " + str(error))
                exit_code = 1
        if not (state["noAttempt"] and
                evidence["result"] == "NO_ATTEMPT_JOURNAL_RETIRED"):
            try:
                final_raw, final_identity = _read_pinned_regular(
                    journal_path, JOURNAL_MAX_BYTES,
                    "canonical recovery journal")
                if ((final_identity["device"], final_identity["inode"]) !=
                        (journal_identity["device"], journal_identity["inode"])):
                    _fail("canonical recovery journal was replaced after resume")
                count, head = validate_journal_bytes(final_raw)
                evidence["journalAfter"] = {
                    **final_identity, "recordCount": count, "headHash": head}
            except Exception as error:
                evidence["result"] = (
                    "NO_ATTEMPT_RETIREMENT_FAILED" if state["noAttempt"] else
                    "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED"
                    if state["cleanupComplete"] else
                    "CLEANUP_FAILED_ROTATION_RESTORE_FAILED")
                evidence["journalValidationError"] = (
                    type(error).__name__ + ": " + str(error))
                exit_code = 1
    evidence["commands"] = list(device.history)
    reservation.write(evidence)
    print(json.dumps({"result": evidence["result"],
                      "evidence": str(reservation.path)}, sort_keys=True))
    return exit_code


def _run_reserved_main(
        args: argparse.Namespace, base: Path, authority: ReportAuthority,
        journal_path: Path, reservation: EvidenceReservation) -> int:
    device = RecoveryNomad(args.adb, alpha.AUTHORIZED_SERIAL)
    journal = None
    preflight: dict[str, Any] | None = None
    preflight_descriptor_authority: dict[str, Any] | None = None
    helper_identity: dict[str, Any] | None = None
    adb_identity: dict[str, Any] | None = None
    if args.execute:
        # Complete the read-only admission before consuming the one execution
        # ledger.  Any concurrent executor can observe too, but only one can
        # exclusively create the canonical ledger and mutate afterward.
        preflight = Recovery(device, authority).run(execute=False)
        if preflight.get("result") not in {
                "PLAN_REFOCUS_REQUIRED", "PLAN_SETTLE_ONLY",
                "PLAN_READY_ALREADY_RELEASED"}:
            _fail("read-only recovery admission did not reach a closed plan")
        rotation_proofs = [
            item for item in preflight.get("proofs", [])
            if type(item) is dict and
            item.get("kind") == "rotation_admission_sandwich"]
        if len(rotation_proofs) != 1:
            _fail("read-only admission lacks one rotation sandwich")
        admission_rotation = {
            key: value for key, value in rotation_proofs[0].items()
            if key not in {"kind", "sha256"}
        }
        descriptor_proofs = [
            item for item in preflight.get("proofs", [])
            if type(item) is dict and item.get("kind") == "target_fds_absent"]
        if not descriptor_proofs:
            _fail("read-only admission lacks descriptor authority")
        descriptor_semantics: tuple[str, str] | None = None
        for proof in descriptor_proofs:
            current = _validate_descriptor_authority(
                proof.get("descriptorAuthority"))
            if descriptor_semantics is None:
                descriptor_semantics = current
            elif descriptor_semantics != current:
                _fail("read-only descriptor authority changed within admission")
        preflight_descriptor_authority = dict(
            descriptor_proofs[-1]["descriptorAuthority"])
        adb_identity = device.adb_authority()
        # This path is deliberately independent of timestamped evidence output.
        # Its exclusive creation is the cross-process one-shot barrier: after
        # any execute attempt, a later process cannot create a fresh ledger and
        # replay an uncertain MAIN, ACK, move, or removal.
        _, helper_identity = _read_pinned_regular(
            Path(__file__), HELPER_MAX_BYTES, "recovery helper")
        reservation.assert_reserved()
        journal = DurableJournal(journal_path, {
            "authority": RECOVERY_AUTHORITY,
            "schemaVersion": 1,
            "reportSha256": authority.report_sha256,
            "readOnlyAdmissionSha256": alpha._canonical_sha(preflight),
            "descriptorAuthority": preflight_descriptor_authority,
            "evidenceReservation": reservation.authority,
            "helper": helper_identity,
            "rotationLease": {
                "authority": ROTATION_LEASE_AUTHORITY,
                "originalPersisted": {
                    "accelerometerRotation": "1",
                    "userRotation": "2",
                },
                "readOnlyAdmissionSandwich": admission_rotation,
                "commandDialects": ROTATION_COMMAND_DIALECTS,
            },
            "device": {
                "serial": alpha.AUTHORIZED_SERIAL,
                "model": alpha.MODEL,
                "sdk": alpha.SDK,
                "fingerprint": alpha.FINGERPRINT,
                "hostPackage": alpha.HOST_PACKAGE,
                "hostApkSha256": alpha.ALPHA_SIGNED_APK_SHA256,
                "documentPackage": alpha.DOCUMENT_PACKAGE,
                "documentApkSha256": alpha.DOCUMENT_APK_SHA256,
                "adb": adb_identity,
            },
        })
    recovery = Recovery(
        device, authority, journal=None if journal is None else journal,
        evidence_guard=(reservation.assert_reserved if args.execute else None),
        header_helper_identity=helper_identity,
        header_adb_identity=adb_identity,
        expected_descriptor_authority=preflight_descriptor_authority)
    recovery.evidence["evidenceReservation"] = reservation.authority
    if preflight is not None:
        recovery.evidence["readOnlyAdmissionSha256"] = alpha._canonical_sha(preflight)
    exit_code = 0
    try:
        recovery.run(execute=args.execute)
    except Exception as error:
        if recovery.evidence.get("result") not in {
                "CLEANUP_NOT_STARTED_ROTATION_UNCHANGED",
                "CLEANUP_FAILED_ROTATION_RESTORED",
                "CLEANUP_FAILED_ROTATION_RESTORE_FAILED",
                "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED"}:
            recovery.evidence["result"] = "FAILED_RETAINED"
        recovery.evidence["error"] = type(error).__name__ + ": " + str(error)
        exit_code = 1
    finally:
        if journal is not None:
            try:
                journal_identity = journal.file_identity
                journal.close()
                journal_raw, journal_authority = _read_pinned_regular(
                    journal.path, JOURNAL_MAX_BYTES,
                    "canonical recovery journal")
                if ((journal_authority["device"],
                     journal_authority["inode"]) != journal_identity):
                    _fail("canonical recovery journal was replaced after close")
                journal_count, journal_head = validate_journal_bytes(journal_raw)
                if (journal_count != journal.count or
                        journal_head != journal.head_hash):
                    _fail("durable journal reread differs from in-memory chain")
                recovery.evidence["journal"] = {
                    **journal_authority,
                    "recordCount": journal_count,
                    "headHash": journal_head,
                }
            except Exception as error:
                if recovery.evidence.get("result") not in {
                        "CLEANUP_NOT_STARTED_ROTATION_UNCHANGED",
                        "CLEANUP_FAILED_ROTATION_RESTORED",
                        "CLEANUP_FAILED_ROTATION_RESTORE_FAILED",
                        "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED"}:
                    recovery.evidence["result"] = "FAILED_RETAINED"
                recovery.evidence["journalValidationError"] = (
                    type(error).__name__ + ": " + str(error))
                exit_code = 1
    recovery.evidence["commands"] = list(device.history)
    reservation.write(recovery.evidence)
    print(json.dumps({"result": recovery.evidence["result"],
                      "evidence": str(reservation.path)}, sort_keys=True))
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true",
                      help="perform the one-shot cleanup; default is read-only plan")
    mode.add_argument(
        "--restore-only", action="store_true",
        help="validate an interrupted journal and restore only rotation 1/2")
    parser.add_argument("--output", type=Path,
                        help="new evidence JSON path (never overwritten)")
    args = parser.parse_args(argv)
    base = Path(__file__).resolve().parent
    output = args.output
    if output is None:
        stamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime())
        suffix = ("-restore-only.json" if args.restore_only else
                  "-execute.json" if args.execute else "-plan.json")
        output = base / "build/native-page-alpha-recovery" / (stamp + suffix)
    authority = load_report(base / REPORT_RELATIVE)
    journal_path = (base / "build/native-page-alpha-recovery" /
                    CANONICAL_JOURNAL_BASENAME)
    if args.restore_only and not os.path.lexists(journal_path):
        raise RecoveryError(
            "restore-only requires the exact canonical recovery journal")
    if args.execute and os.path.lexists(journal_path):
        # This check is intentionally before construction of the ADB adapter or
        # any device observation.  Exclusive creation below remains the final
        # race-safe authority after the first process completes read-only plan.
        raise RecoveryError(
            "canonical recovery journal already exists; cleanup replay is forbidden; "
            "use --restore-only")
    reservation = EvidenceReservation(output)
    try:
        if args.restore_only:
            return _run_reserved_restore_only(
                args, authority, journal_path, reservation)
        return _run_reserved_main(args, base, authority, journal_path, reservation)
    finally:
        reservation.close()


if __name__ == "__main__":
    sys.exit(main())
