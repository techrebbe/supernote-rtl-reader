"""Crash-safe external rotation supervisor for the visual-only Nomad alpha.

The alpha runner deliberately does not own Android rotation settings.  This
small supervisor is the only process allowed to mutate them.  It starts one
exact runner, consumes three controller-bound phase records from that child's
stdout, and journals every rotation intent before dispatch.  The original
Nomad settings are restored in ``finally`` and can also be restored by a
separate, idempotent ``--restore-only`` invocation after a controller crash.

This module is intentionally narrow.  It supports one device, one original
settings tuple, three phases, and four literal WindowManager commands.  It is
not a general screen-rotation utility.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Iterable, Iterator, NoReturn, Protocol, Sequence
import uuid

import native_page_alpha_runner as alpha


AUTHORITY = "native-page-alpha-external-rotation-controller-v1"
JOURNAL_AUTHORITY = "native-page-alpha-rotation-controller-journal-v1"
PHASE_AUTHORITY = "native-page-alpha-rotation-phase-v1"
EVIDENCE_AUTHORITY = "native-page-alpha-rotation-controller-evidence-v1"
AUTHORIZED_SERIAL = "SN078C10015092"
EXPECTED_DEVICE_IDENTITY = {
    "currentUser": "0",
    "fingerprint": alpha.FINGERPRINT,
    "model": alpha.MODEL,
    "ro.serialno": AUTHORIZED_SERIAL,
    "sdk": alpha.SDK,
    "serial": AUTHORIZED_SERIAL,
    "state": "device",
}
ORIGINAL_SETTINGS = ("1", "2")
PHASE_PREFIX = b"NATIVE_PAGE_ALPHA_ROTATION_PHASE "
PHASES = ("START_LANDSCAPE", "PORTRAIT", "RETURN_LANDSCAPE")
PHASE_TARGETS = {
    "START_LANDSCAPE": ("0", "1", 1),
    "PORTRAIT": ("0", "0", 0),
    "RETURN_LANDSCAPE": ("0", "1", 1),
}
COMMANDS = {
    "BOOTSTRAP_LOCK_ZERO": ("shell", "wm", "set-user-rotation", "lock", "0"),
    "START_LANDSCAPE": ("shell", "wm", "set-user-rotation", "lock", "1"),
    "PORTRAIT": ("shell", "wm", "set-user-rotation", "lock", "0"),
    "RETURN_LANDSCAPE": ("shell", "wm", "set-user-rotation", "lock", "1"),
    "RESTORE_LOCK_TWO": ("shell", "wm", "set-user-rotation", "lock", "2"),
    "RESTORE_FREE": ("shell", "wm", "set-user-rotation", "free"),
}
PINNED_ADB_PATH = Path(
    r"C:\Users\mmkap\AppData\Local\Android\Sdk\platform-tools\adb.exe")
PINNED_ADB_SIZE = 8273560
PINNED_ADB_SHA256 = "b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f"
MAX_TOOL_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024
STEP_TIMEOUT_SECONDS = 15.0
CHILD_TIMEOUT_SECONDS = 20 * 60.0
CHILD_FAILURE_SETTLE_SECONDS = 180.0
POLL_SECONDS = 0.20
PROOF_ATTEMPTS = 60


class ControllerError(RuntimeError):
    """The controller cannot prove that a requested operation is safe."""


class RestoreError(ControllerError):
    """The original persisted rotation settings were not restored."""


def _fail(message: str) -> NoReturn:
    raise ControllerError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def _canonical_sha(value: Any) -> str:
    return _sha(_canonical(value))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON contains a duplicate key")
        result[key] = value
    return result


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _fail(label + " topology differs")
    return value


@dataclass(frozen=True)
class FileIdentity:
    path: str
    size: int
    sha256: str
    device: int
    inode: int
    mtimeNs: int


def _read_regular(path: Path, maximum: int,
                  label: str) -> tuple[bytes, FileIdentity]:
    """Read one file without following its final directory entry."""
    supplied = path.absolute()
    try:
        before = os.lstat(supplied)
    except OSError as error:
        raise ControllerError(label + " cannot be inspected") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        _fail(label + " must be a non-symlink regular file")
    if before.st_size <= 0 or before.st_size > maximum:
        _fail(label + " has an invalid size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(supplied, flags)
    except OSError as error:
        raise ControllerError(label + " cannot be opened without following") from error
    try:
        opened = os.fstat(descriptor)
        opened_key = (opened.st_dev, opened.st_ino, opened.st_size,
                      getattr(opened, "st_mtime_ns", 0))
        before_key = (before.st_dev, before.st_ino, before.st_size,
                      getattr(before, "st_mtime_ns", 0))
        if not stat.S_ISREG(opened.st_mode) or opened_key != before_key:
            _fail(label + " changed during descriptor open")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total <= 0 or total > maximum:
            _fail(label + " is empty or oversized")
        after = os.fstat(descriptor)
        after_key = (after.st_dev, after.st_ino, after.st_size,
                     getattr(after, "st_mtime_ns", 0))
        if after_key != opened_key:
            _fail(label + " changed while reading")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        final = os.lstat(supplied)
    except OSError as error:
        raise ControllerError(label + " disappeared after reading") from error
    final_key = (final.st_dev, final.st_ino, final.st_size,
                 getattr(final, "st_mtime_ns", 0))
    if stat.S_ISLNK(final.st_mode) or final_key != opened_key:
        _fail(label + " path was replaced while reading")
    return raw, FileIdentity(
        str(supplied), len(raw), _sha(raw), opened.st_dev, opened.st_ino,
        getattr(opened, "st_mtime_ns", 0))


def read_regular_identity(path: Path, maximum: int, label: str) -> FileIdentity:
    return _read_regular(path, maximum, label)[1]


def _directory_fsync(path: Path) -> None:
    if os.name == "nt":
        # Python cannot portably open a Windows directory for fsync.  The
        # journal file itself is still opened exclusively and fsync'd.
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class DurableJournal:
    """Exclusive, unbuffered, hash-chained JSONL journal."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.path = path.absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._count = 0
        self._head_hash = "0" * 64
        self._poisoned = False
        try:
            self._stream = self.path.open("xb", buffering=0)
        except FileExistsError as error:
            raise ControllerError("refusing to reuse a rotation journal") from error
        self._lock()
        opened = os.fstat(self._stream.fileno())
        self._identity = (opened.st_dev, opened.st_ino)
        try:
            self.record("header", header)
            _directory_fsync(self.path.parent)
        except BaseException:
            self.close()
            raise

    def _lock(self) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self._stream.fileno(), 0, os.SEEK_SET)
                msvcrt.locking(self._stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError) as error:
            self._stream.close()
            raise ControllerError("rotation journal is concurrently owned") from error

    @classmethod
    def resume(cls, path: Path, *, count: int, head_hash: str,
               valid_size: int, prefix_sha256: str,
               identity: FileIdentity) -> "DurableJournal":
        supplied = path.absolute()
        before = os.lstat(supplied)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            _fail("rotation journal must be a non-symlink regular file")
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(supplied, flags)
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
            value._lock()
            opened = os.fstat(stream.fileno())
            value._identity = (opened.st_dev, opened.st_ino)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or
                    opened.st_dev != identity.device or opened.st_ino != identity.inode or
                    opened.st_size != identity.size or opened.st_size < valid_size):
                _fail("rotation journal identity changed before resume")
            os.lseek(stream.fileno(), 0, os.SEEK_SET)
            prefix = b""
            while len(prefix) < valid_size:
                chunk = os.read(stream.fileno(), valid_size - len(prefix))
                if not chunk:
                    break
                prefix += chunk
            if len(prefix) != valid_size or _sha(prefix) != prefix_sha256:
                _fail("rotation journal prefix changed before resume")
            if opened.st_size != valid_size:
                os.ftruncate(stream.fileno(), valid_size)
                os.fsync(stream.fileno())
            os.lseek(stream.fileno(), 0, os.SEEK_END)
            return value
        except BaseException:
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

    def assert_current_path(self) -> None:
        """Prove the retained journal FD is still named by its exact path."""
        try:
            named = os.lstat(self.path)
            opened = os.fstat(self._stream.fileno())
        except OSError as error:
            raise ControllerError("rotation journal path cannot be revalidated") from error
        if (stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or
                not stat.S_ISREG(opened.st_mode) or
                (named.st_dev, named.st_ino) != self._identity or
                (opened.st_dev, opened.st_ino) != self._identity or
                named.st_size != opened.st_size):
            _fail("rotation journal path or descriptor identity changed")

    def record(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("journal kind or payload is malformed")
        if self._poisoned:
            _fail("journal stream is poisoned after an uncertain write")
        base = {
            "kind": kind, "payload": payload, "prevHash": self._head_hash,
            "seq": self._count,
        }
        record = {**base, "recordHash": _canonical_sha(base)}
        raw = _canonical(record) + b"\n"
        written = 0
        try:
            self.assert_current_path()
            while written < len(raw):
                count = self._stream.write(raw[written:])
                if type(count) is not int or count <= 0 or count > len(raw) - written:
                    _fail("journal append made invalid progress")
                written += count
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self.assert_current_path()
        except BaseException:
            self._poisoned = True
            raise
        self._count += 1
        self._head_hash = record["recordHash"]
        return record

    def close(self) -> None:
        if self._stream.closed:
            return
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


@dataclass(frozen=True)
class JournalPrefix:
    records: tuple[dict[str, Any], ...]
    valid_size: int
    prefix_sha256: str
    identity: FileIdentity
    torn: bytes


def _possible_next_kinds(records: Sequence[dict[str, Any]]) -> set[str]:
    if not records:
        return {"header"}
    if records[-1]["kind"] in {"complete", "restore_failed"}:
        return set()
    return {
        "rotation_intent", "rotation_settlement", "child_start_intent",
        "child_started", "phase_received", "child_exit", "restore_intent",
        "restore_settlement", "complete", "restore_failed",
    }


def _validate_torn(torn: bytes, allowed: set[str]) -> None:
    if not torn or len(torn) > MAX_LINE_BYTES or not allowed:
        _fail("rotation journal has an invalid torn suffix")
    try:
        text = torn.decode("ascii", "strict")
    except UnicodeError as error:
        raise ControllerError("rotation journal torn suffix is not ASCII") from error
    if any(ord(character) < 32 or ord(character) > 126 for character in text):
        _fail("rotation journal torn suffix contains control bytes")
    prefixes = [f'{{"kind":"{kind}"' for kind in sorted(allowed)]
    if not any(prefix.startswith(text) or text.startswith(prefix + ',"payload":{')
               for prefix in prefixes):
        _fail("rotation journal torn suffix is not a plausible next record")


def read_journal(path: Path, *, allow_torn: bool) -> JournalPrefix:
    raw, identity = _read_regular(path, MAX_JOURNAL_BYTES, "rotation journal")
    complete = raw
    torn = b""
    if not raw.endswith(b"\n"):
        if not allow_torn:
            _fail("rotation journal is truncated")
        boundary = raw.rfind(b"\n")
        if boundary < 0:
            _fail("rotation journal has no complete record")
        complete = raw[:boundary + 1]
        torn = raw[boundary + 1:]
    previous = "0" * 64
    records: list[dict[str, Any]] = []
    for expected_seq, line in enumerate(complete.splitlines()):
        try:
            value = json.loads(line.decode("ascii", "strict"),
                               object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ControllerError("rotation journal is not canonical JSONL") from error
        wire = _exact_keys(value, {"kind", "payload", "prevHash", "recordHash", "seq"},
                           "rotation journal record")
        if (wire["seq"] != expected_seq or type(wire["seq"]) is not int or
                wire["prevHash"] != previous or type(wire["kind"]) is not str or
                not wire["kind"] or type(wire["payload"]) is not dict):
            _fail("rotation journal chain differs")
        base = {key: wire[key] for key in ("kind", "payload", "prevHash", "seq")}
        if wire["recordHash"] != _canonical_sha(base) or line != _canonical(wire):
            _fail("rotation journal record hash or encoding differs")
        previous = wire["recordHash"]
        records.append(wire)
    if not records or records[0]["kind"] != "header":
        _fail("rotation journal header is absent")
    validate_journal_grammar(records)
    if torn:
        _validate_torn(torn, _possible_next_kinds(records))
    return JournalPrefix(
        tuple(records), len(complete), _sha(complete), identity, torn)


def _command_wire(operation: str) -> list[str]:
    if type(operation) is not str or operation not in COMMANDS:
        _fail("journal names an unknown rotation operation")
    return list(COMMANDS[operation])


def _target_wire(target: tuple[str, str, int]) -> dict[str, Any]:
    return {
        "accelerometerRotation": target[0],
        "physicalRotation": target[2],
        "userRotation": target[1],
    }


def _operation_target(operation: str) -> tuple[str, str, int]:
    if operation == "BOOTSTRAP_LOCK_ZERO":
        return "0", "0", 0
    if operation in PHASE_TARGETS:
        return PHASE_TARGETS[operation]
    _fail("journal rotation operation has no closed target")


def _validate_observations(value: Any, expected_settings: tuple[str, str],
                           expected_physical: int | None,
                           label: str) -> None:
    if type(value) is not list or len(value) != 2:
        _fail(label + " must contain exactly two observations")
    expected_settings_wire = {
        "accelerometerRotation": expected_settings[0],
        "userRotation": expected_settings[1],
    }
    for item in value:
        wire = _exact_keys(item, {
            "physicalRotation", "settingsAfter", "settingsBefore",
            "windowDisplaysSha256",
        }, label + " observation")
        before = _exact_keys(
            wire["settingsBefore"], {"accelerometerRotation", "userRotation"},
            label + " settingsBefore")
        after = _exact_keys(
            wire["settingsAfter"], {"accelerometerRotation", "userRotation"},
            label + " settingsAfter")
        physical = wire["physicalRotation"]
        digest = wire["windowDisplaysSha256"]
        if (before != expected_settings_wire or after != expected_settings_wire or
                type(physical) is not int or physical not in range(4) or
                (expected_physical is not None and physical != expected_physical) or
                type(digest) is not str or
                re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            _fail(label + " observation differs from its exact target")


def _validate_child_argv(value: Any, header: dict[str, Any]) -> None:
    if (type(value) is not list or len(value) != 15 or
            any(type(item) is not str or not item or "\x00" in item
                for item in value)):
        _fail("child argv topology differs")
    tools = header["tools"]
    expected_fixed = {
        0: tools["python"]["path"],
        1: "-u",
        2: tools["runner"]["path"],
        3: "--adb",
        4: tools["adb"]["path"],
        5: "--serial",
        6: AUTHORIZED_SERIAL,
        7: "--output-root",
        9: "--host-metadata",
        11: "--rotation-authority",
        12: alpha.ROTATION_ADB_SYSTEM_SETTINGS,
        13: "--rotation-controller-run-id",
        14: header["controllerId"],
    }
    if any(value[index] != expected for index, expected in expected_fixed.items()):
        _fail("child argv differs from the closed controller command")
    for index, label in ((8, "output root"), (10, "host metadata")):
        supplied = Path(value[index])
        if not supplied.is_absolute() or str(supplied.absolute()) != value[index]:
            _fail("child " + label + " path is not canonical and absolute")
    if value[8] == value[10]:
        _fail("child output root and host metadata paths overlap")


def validate_journal_grammar(records: Sequence[dict[str, Any]]) -> None:
    """Reject any complete record outside the controller's closed language."""
    header = _exact_keys(records[0]["payload"], {
        "authority", "commands", "controllerId", "device", "originalSettings",
        "phaseProtocol", "schemaVersion", "tools",
    }, "rotation journal header")
    if (header["authority"] != JOURNAL_AUTHORITY or header["schemaVersion"] != 1 or
            type(header["controllerId"]) is not str or
            re.fullmatch(r"[0-9a-f]{32}", header["controllerId"]) is None or
            header["device"] != EXPECTED_DEVICE_IDENTITY or
            header["originalSettings"] != {
                "accelerometerRotation": "1", "userRotation": "2"} or
            header["phaseProtocol"] != {
                "authority": PHASE_AUTHORITY, "phases": list(PHASES),
                "prefix": PHASE_PREFIX.decode("ascii")} or
            header["commands"] != {key: list(value) for key, value in COMMANDS.items()}):
        _fail("rotation journal header authority differs")
    tools = _exact_keys(header["tools"], {"adb", "controller", "python", "runner"},
                        "rotation journal tools")
    for name, value in tools.items():
        wire = _exact_keys(value, {"device", "inode", "mtimeNs", "path", "sha256", "size"},
                           "rotation journal " + name)
        if (type(wire["path"]) is not str or type(wire["sha256"]) is not str or
                re.fullmatch(r"[0-9a-f]{64}", wire["sha256"]) is None or
                any(type(wire[key]) is not int or wire[key] < 0
                    for key in ("device", "inode", "mtimeNs", "size")) or
                wire["inode"] == 0 or wire["size"] == 0):
            _fail("rotation journal tool identity is malformed")

    expected_phase = 0
    bootstrap_done = False
    child_start_intent = False
    child_started = False
    child_exited = False
    phase_pending: str | None = None
    restore_seen = False
    restore_settled = False
    terminal = False
    intent_operation: str | None = None
    rotation_ever_intended = False
    for record in records[1:]:
        if terminal:
            _fail("rotation journal contains records after a terminal record")
        kind = record["kind"]
        payload = record["payload"]
        if kind == "rotation_intent":
            wire = _exact_keys(payload, {"command", "operation", "target"},
                               "rotation intent")
            operation = wire["operation"]
            if (intent_operation is not None or
                    wire["command"] != _command_wire(operation) or
                    wire["target"] != _target_wire(_operation_target(operation))):
                _fail("rotation intent order or command differs")
            allowed = (["BOOTSTRAP_LOCK_ZERO"] if not bootstrap_done else
                       ([phase_pending] if phase_pending is not None else []))
            if operation not in allowed:
                _fail("rotation intent is out of phase")
            intent_operation = operation
            rotation_ever_intended = True
        elif kind == "rotation_settlement":
            wire = _exact_keys(payload, {"observations", "operation", "transportUncertain"},
                               "rotation settlement")
            if (wire["operation"] != intent_operation or
                    (wire["transportUncertain"] is not None and
                     (type(wire["transportUncertain"]) is not str or
                      not wire["transportUncertain"] or
                      len(wire["transportUncertain"]) > 4096))):
                _fail("rotation settlement does not settle its exact intent")
            settled_target = _operation_target(intent_operation)
            _validate_observations(
                wire["observations"], (settled_target[0], settled_target[1]),
                settled_target[2], "rotation settlement")
            if intent_operation == "BOOTSTRAP_LOCK_ZERO":
                bootstrap_done = True
            elif intent_operation in PHASES:
                expected_phase += 1
                phase_pending = None
            intent_operation = None
        elif kind == "child_start_intent":
            wire = _exact_keys(payload, {"argv", "controllerId"}, "child start intent")
            if (child_start_intent or child_started or not bootstrap_done or
                    intent_operation is not None or expected_phase != 0 or
                    wire["controllerId"] != header["controllerId"]):
                _fail("child start intent is out of phase")
            _validate_child_argv(wire["argv"], header)
            child_start_intent = True
        elif kind == "child_started":
            wire = _exact_keys(payload, {"controllerId", "pid"}, "child started")
            if (not child_start_intent or child_started or
                    wire["controllerId"] != header["controllerId"] or
                    type(wire["pid"]) is not int or wire["pid"] <= 0):
                _fail("child start settlement differs")
            child_started = True
        elif kind == "phase_received":
            wire = _exact_keys(payload, {"authority", "controllerId", "phase", "sequence"},
                               "phase receipt")
            if (not child_started or intent_operation is not None or restore_seen or
                    child_exited or phase_pending is not None or
                    expected_phase >= len(PHASES) or
                    wire != {"authority": PHASE_AUTHORITY,
                             "controllerId": header["controllerId"],
                             "phase": PHASES[expected_phase],
                             "sequence": expected_phase + 1}):
                _fail("phase receipt is out of order or unbound")
            phase_pending = wire["phase"]
        elif kind == "child_exit":
            wire = _exact_keys(payload, {"returncode", "stderrSha256", "stdoutSha256"},
                               "child exit")
            if (child_exited or
                    phase_pending is not None or intent_operation is not None or
                    type(wire["returncode"]) is not int or
                    wire["returncode"] not in (0, 3) or
                    (wire["returncode"] == 0 and
                     expected_phase != len(PHASES)) or
                    any(type(wire[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", wire[key]) is None
                        for key in ("stderrSha256", "stdoutSha256"))):
                _fail("child exit is premature or malformed")
            child_exited = True
        elif kind == "restore_intent":
            wire = _exact_keys(payload, {"commands", "target"}, "restore intent")
            if (restore_seen or not rotation_ever_intended or
                    wire["commands"] != [
                    _command_wire("RESTORE_LOCK_TWO"), _command_wire("RESTORE_FREE")] or
                    wire["target"] != {"accelerometerRotation": "1", "userRotation": "2"}):
                _fail("restore intent differs")
            restore_seen = True
            # A durable restoration supersedes an unsettled rotation command.
            # Restore-only must be able to recover a crash immediately after
            # any intent, when no command settlement can exist yet.
            intent_operation = None
            phase_pending = None
        elif kind == "restore_settlement":
            wire = _exact_keys(payload, {"freeError", "lockError", "observations"},
                               "restore settlement")
            if (not restore_seen or restore_settled or
                    any(value is not None and
                        (type(value) is not str or not value or len(value) > 4096)
                        for value in (wire["freeError"], wire["lockError"]))):
                _fail("restore settlement differs")
            _validate_observations(
                wire["observations"], ORIGINAL_SETTINGS, None,
                "restore settlement")
            restore_settled = True
        elif kind in {"complete", "restore_failed"}:
            wire = _exact_keys(payload, {"result"}, "terminal record")
            if (not restore_settled or type(wire["result"]) is not str or
                    (kind == "complete" and wire["result"] != "ROTATION_CONTROLLER_CLEAN") or
                    (kind == "restore_failed" and wire["result"] != "ROTATION_RESTORE_UNPROVED")):
                _fail("terminal result differs")
            terminal = True
        else:
            _fail("rotation journal contains an unknown record kind")


@dataclass(frozen=True)
class RotationObservation:
    settingsBefore: dict[str, str]
    physicalRotation: int
    windowDisplaysSha256: str
    settingsAfter: dict[str, str]


class RotationDevice(Protocol):
    def identity(self) -> dict[str, str]: ...
    def settings(self) -> tuple[str, str]: ...
    def window_displays(self) -> bytes: ...
    def command(self, operation: str) -> None: ...


class AdbRotationDevice:
    def __init__(self, adb: Path, serial: str, *, executor: Callable[..., Any] = subprocess.run):
        if adb.absolute() != PINNED_ADB_PATH or serial != AUTHORIZED_SERIAL:
            _fail("ADB path or device serial differs from the exact Nomad pin")
        self.adb = str(adb.absolute())
        self.serial = serial
        self._executor = executor

    def adb_identity(self) -> FileIdentity:
        value = read_regular_identity(Path(self.adb), PINNED_ADB_SIZE, "adb executable")
        if value.size != PINNED_ADB_SIZE or value.sha256 != PINNED_ADB_SHA256:
            _fail("adb executable bytes differ from the exact pin")
        return value

    def _run(self, operation: str, tail: tuple[str, ...]) -> bytes:
        argv = (self.adb, "-s", self.serial, *tail)
        try:
            completed = self._executor(
                argv, capture_output=True, timeout=STEP_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired as error:
            raise ControllerError(operation + " timed out") from error
        stdout = bytes(completed.stdout or b"")
        stderr = bytes(completed.stderr or b"")
        if len(stdout) > alpha.MAX_TEXT_BYTES or len(stderr) > alpha.MAX_TEXT_BYTES:
            _fail(operation + " returned oversized output")
        if int(completed.returncode) != 0:
            _fail(operation + " failed")
        return stdout

    def identity(self) -> dict[str, str]:
        state = self._run("adb get-state", ("get-state",)).decode("ascii", "strict").strip()
        serial = self._run("adb get-serialno", ("get-serialno",)).decode("ascii", "strict").strip()
        prop = self._run("device serial property", ("shell", "getprop", "ro.serialno")).decode("ascii", "strict").strip()
        model = self._run("device model", ("shell", "getprop", "ro.product.model")).decode("ascii", "strict").strip()
        sdk = self._run("device SDK", ("shell", "getprop", "ro.build.version.sdk")).decode("ascii", "strict").strip()
        fingerprint = self._run(
            "firmware fingerprint",
            ("shell", "getprop", "ro.build.fingerprint")).decode("ascii", "strict").strip()
        current_user = self._run(
            "current Android user", ("shell", "am", "get-current-user")).decode(
                "ascii", "strict").strip()
        identity = {
            "currentUser": current_user,
            "fingerprint": fingerprint,
            "model": model,
            "ro.serialno": prop,
            "sdk": sdk,
            "serial": serial,
            "state": state,
        }
        if identity != EXPECTED_DEVICE_IDENTITY:
            _fail("connected device identity differs from the exact Nomad")
        return identity

    def settings(self) -> tuple[str, str]:
        values: list[str] = []
        for key in ("accelerometer_rotation", "user_rotation"):
            value = self._run(
                "read rotation " + key,
                ("shell", "settings", "get", "system", key)).decode("ascii", "strict").strip()
            if re.fullmatch(r"[0-3]", value) is None:
                _fail("persisted rotation setting is malformed")
            values.append(value)
        return values[0], values[1]

    def window_displays(self) -> bytes:
        return self._run("read WindowManager displays",
                         ("shell", "dumpsys", "window", "displays"))

    def command(self, operation: str) -> None:
        if operation not in COMMANDS:
            _fail("rotation command escaped the closed command set")
        self._run("rotation " + operation.lower(), COMMANDS[operation])


def observe(device: RotationDevice, expected: tuple[str, str],
            physical: int | None) -> RotationObservation:
    before = device.settings()
    displays = device.window_displays()
    actual_physical = alpha._physical_orientation(displays)
    after = device.settings()
    if before != after or before != expected:
        _fail("rotation settings changed across or differ from the observation")
    if actual_physical not in range(4) or (physical is not None and actual_physical != physical):
        _fail("physical rotation differs from the expected target")
    return RotationObservation(
        {"accelerometerRotation": before[0], "userRotation": before[1]},
        actual_physical, _sha(displays),
        {"accelerometerRotation": after[0], "userRotation": after[1]})


def prove_twice(device: RotationDevice, expected: tuple[str, str],
                physical: int | None, *, sleep: Callable[[float], None] = time.sleep,
                attempts: int = PROOF_ATTEMPTS) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    last_error: BaseException | None = None
    for _ in range(attempts):
        try:
            current = observe(device, expected, physical)
            observations.append(asdict(current))
            if len(observations) == 2:
                return observations
        except BaseException as error:
            observations = []
            last_error = error
        sleep(POLL_SECONDS)
    suffix = "" if last_error is None else ": " + str(last_error)
    _fail("rotation target was not proved twice" + suffix)


@dataclass(frozen=True)
class PhaseRecord:
    authority: str
    controllerId: str
    phase: str
    sequence: int


def encode_phase(controller_id: str, phase: str, sequence: int) -> bytes:
    record = PhaseRecord(PHASE_AUTHORITY, controller_id, phase, sequence)
    return PHASE_PREFIX + _canonical(asdict(record)) + b"\n"


def parse_phase_line(line: bytes, controller_id: str,
                     expected_sequence: int) -> PhaseRecord | None:
    if type(line) is not bytes or len(line) > MAX_LINE_BYTES or b"\x00" in line:
        _fail("child output line is malformed or oversized")
    if not line.startswith(PHASE_PREFIX):
        return None
    if not line.endswith(b"\n"):
        _fail("phase record is not newline framed")
    raw = line[len(PHASE_PREFIX):-1]
    try:
        value = json.loads(raw.decode("ascii", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ControllerError("phase record is not strict ASCII JSON") from error
    wire = _exact_keys(value, {"authority", "controllerId", "phase", "sequence"},
                       "phase record")
    if raw != _canonical(wire):
        _fail("phase record is not byte-canonical")
    expected_phase = PHASES[expected_sequence - 1] if 1 <= expected_sequence <= len(PHASES) else None
    if (wire != {"authority": PHASE_AUTHORITY, "controllerId": controller_id,
                 "phase": expected_phase, "sequence": expected_sequence}):
        _fail("phase record is stale, replayed, or out of order")
    return PhaseRecord(**wire)


@dataclass(frozen=True)
class ChildLine:
    stream: str
    raw: bytes


class Child(Protocol):
    pid: int
    argv: tuple[str, ...]
    def lines(self, timeout: float) -> Iterator[ChildLine]: ...
    def wait(self, timeout: float) -> int: ...
    def poll(self) -> int | None: ...
    @property
    def stdout_bytes(self) -> bytes: ...
    @property
    def stderr_bytes(self) -> bytes: ...


class SubprocessChild:
    """Bounded concurrent drain of one exact unbuffered Python child."""

    def __init__(self, argv: Sequence[str]):
        self.argv = tuple(argv)
        self._process = subprocess.Popen(
            self.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0)
        self.pid = self._process.pid
        self._queue: queue.Queue[ChildLine | tuple[str, None]] = queue.Queue()
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._threads: list[threading.Thread] = []
        assert self._process.stdout is not None and self._process.stderr is not None
        for name, stream in (("stdout", self._process.stdout),
                             ("stderr", self._process.stderr)):
            thread = threading.Thread(
                target=self._drain, args=(name, stream), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _drain(self, name: str, stream: Any) -> None:
        try:
            while True:
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES or not line.endswith(b"\n"):
                    self._queue.put(ChildLine(name, line))
                    break
                destination = self._stdout if name == "stdout" else self._stderr
                destination.extend(line)
                if len(destination) > MAX_TRANSCRIPT_BYTES:
                    self._queue.put(ChildLine(name, b"X" * (MAX_LINE_BYTES + 1)))
                    break
                self._queue.put(ChildLine(name, bytes(line)))
        finally:
            self._queue.put((name, None))

    def lines(self, timeout: float) -> Iterator[ChildLine]:
        deadline = time.monotonic() + timeout
        closed: set[str] = set()
        while len(closed) != 2:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("alpha child output timed out")
            try:
                item = self._queue.get(timeout=remaining)
            except queue.Empty as error:
                raise ControllerError("alpha child output timed out") from error
            if isinstance(item, tuple):
                closed.add(item[0])
            else:
                yield item

    def wait(self, timeout: float) -> int:
        try:
            return self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ControllerError("alpha child did not exit") from error

    def poll(self) -> int | None:
        return self._process.poll()

    @property
    def stdout_bytes(self) -> bytes:
        return bytes(self._stdout)

    @property
    def stderr_bytes(self) -> bytes:
        return bytes(self._stderr)


class RotationController:
    def __init__(self, device: RotationDevice, journal: DurableJournal,
                 controller_id: str, tools: dict[str, FileIdentity],
                 *, sleep: Callable[[float], None] = time.sleep,
                 child_factory: Callable[[Sequence[str]], Child] = SubprocessChild):
        if re.fullmatch(r"[0-9a-f]{32}", controller_id) is None:
            _fail("controller ID is malformed")
        self.device = device
        self.journal = journal
        self.controller_id = controller_id
        self.tools = dict(tools)
        self.sleep = sleep
        self.child_factory = child_factory
        self.rotation_intent_durable = False
        self.rotation_restored = False
        self.child: Child | None = None
        self.phases: list[str] = []

    def _guard(self, expected_settings: tuple[str, str] | None = None,
               physical: int | None = None) -> None:
        self.journal.assert_current_path()
        if self.device.identity() != EXPECTED_DEVICE_IDENTITY:
            _fail("device identity changed")
        for name, expected in self.tools.items():
            current = read_regular_identity(Path(expected.path), MAX_TOOL_BYTES,
                                            name + " tool")
            if current != expected:
                _fail(name + " tool identity changed")
        if expected_settings is not None:
            observe(self.device, expected_settings, physical)

    def _intent(self, operation: str, target: tuple[str, str, int]) -> None:
        payload = {
            "command": _command_wire(operation), "operation": operation,
            "target": {"accelerometerRotation": target[0],
                       "userRotation": target[1], "physicalRotation": target[2]},
        }
        self.journal.record("rotation_intent", payload)
        self.rotation_intent_durable = True

    def _rotate(self, operation: str, target: tuple[str, str, int],
                current: tuple[str, str], current_physical: int | None) -> None:
        self._guard(current, current_physical)
        self._intent(operation, target)
        self._guard(current, current_physical)
        uncertain: str | None = None
        try:
            self.device.command(operation)
        except BaseException as error:
            uncertain = type(error).__name__ + ": " + str(error)
        observations = prove_twice(
            self.device, (target[0], target[1]), target[2], sleep=self.sleep)
        self._guard((target[0], target[1]), target[2])
        self.journal.record("rotation_settlement", {
            "observations": observations, "operation": operation,
            "transportUncertain": uncertain,
        })

    def _restore(self) -> None:
        if not self.rotation_intent_durable:
            return
        payload = {
            "commands": [_command_wire("RESTORE_LOCK_TWO"),
                         _command_wire("RESTORE_FREE")],
            "target": {"accelerometerRotation": "1", "userRotation": "2"},
        }
        intent_error: BaseException | None = None
        try:
            self.journal.record("restore_intent", payload)
        except BaseException as error:
            intent_error = error
        lock_error: str | None = None
        free_error: str | None = None
        try:
            try:
                self._guard()
                self.device.command("RESTORE_LOCK_TWO")
            except BaseException as error:
                lock_error = type(error).__name__ + ": " + str(error)
        finally:
            try:
                self._guard()
                self.device.command("RESTORE_FREE")
            except BaseException as error:
                free_error = type(error).__name__ + ": " + str(error)
        observations = prove_twice(
            self.device, ORIGINAL_SETTINGS, None, sleep=self.sleep)
        self.rotation_restored = True
        if intent_error is not None:
            raise RestoreError("restore intent journal failed after durable rotation intent") from intent_error
        self.journal.record("restore_settlement", {
            "freeError": free_error, "lockError": lock_error,
            "observations": observations,
        })
        if lock_error is not None or free_error is not None:
            raise RestoreError("rotation commands were transport-uncertain despite restored settings")

    def _settle_child_before_restore(self) -> None:
        """Never race restoration against a child that can still act.

        The alpha's own bounded orientation waits cause its normal failure
        path to enter cleanup within two minutes.  If it does not exit within
        this larger bound, leave the durable rotation intent for restore-only
        rather than changing settings underneath a live device actor.
        """
        if self.child is None or self.child.poll() is not None:
            return
        self.child.wait(CHILD_FAILURE_SETTLE_SECONDS)

    def run(self, child_argv: Sequence[str]) -> dict[str, Any]:
        primary: BaseException | None = None
        returncode: int | None = None
        try:
            self._guard(ORIGINAL_SETTINGS, None)
            self._rotate("BOOTSTRAP_LOCK_ZERO", ("0", "0", 0), ORIGINAL_SETTINGS, None)
            self.journal.record("child_start_intent", {
                "argv": list(child_argv), "controllerId": self.controller_id})
            self._guard(("0", "0"), 0)
            self.child = self.child_factory(child_argv)
            self.journal.record("child_started", {
                "controllerId": self.controller_id, "pid": self.child.pid})
            expected_sequence = 1
            current = ("0", "0")
            current_physical = 0
            for item in self.child.lines(CHILD_TIMEOUT_SECONDS):
                if len(item.raw) > MAX_LINE_BYTES:
                    _fail("alpha child output line is oversized")
                if item.stream != "stdout":
                    continue
                phase = parse_phase_line(item.raw, self.controller_id, expected_sequence)
                if phase is None:
                    continue
                self.journal.record("phase_received", asdict(phase))
                target = PHASE_TARGETS[phase.phase]
                self._rotate(phase.phase, target, current, current_physical)
                current = (target[0], target[1])
                current_physical = target[2]
                self.phases.append(phase.phase)
                expected_sequence += 1
            returncode = self.child.wait(STEP_TIMEOUT_SECONDS)
            self.journal.record("child_exit", {
                "returncode": returncode,
                "stderrSha256": _sha(self.child.stderr_bytes),
                "stdoutSha256": _sha(self.child.stdout_bytes),
            })
            if returncode == 0 and self.phases != list(PHASES):
                _fail("successful alpha child omitted a rotation phase")
            if returncode not in (0, 3):
                _fail("alpha child exit is outside clean/diagnostic-clean results")
        except BaseException as error:
            primary = error
        finally:
            restore_error: BaseException | None = None
            try:
                self._settle_child_before_restore()
                self._restore()
            except BaseException as error:
                restore_error = error
            if restore_error is not None:
                if primary is not None:
                    raise RestoreError(
                        str(primary) + "; rotation restore also failed: " +
                        str(restore_error)) from restore_error
                raise restore_error
        if primary is not None:
            raise primary
        if not self.rotation_restored:
            _fail("clean controller result lacks rotation restoration")
        self.journal.record("complete", {"result": "ROTATION_CONTROLLER_CLEAN"})
        return {
            "authority": EVIDENCE_AUTHORITY,
            "controllerId": self.controller_id,
            "phases": list(self.phases),
            "returncode": returncode,
            "result": (
                "ROTATION_CONTROLLER_CLEAN" if returncode == 0 else
                "ROTATION_CONTROLLER_CHILD_DIAGNOSTIC_CLEAN"),
            "rotationRestored": True,
        }


def _header(controller_id: str, tools: dict[str, FileIdentity]) -> dict[str, Any]:
    return {
        "authority": JOURNAL_AUTHORITY,
        "commands": {key: list(value) for key, value in COMMANDS.items()},
        "controllerId": controller_id,
        "device": dict(EXPECTED_DEVICE_IDENTITY),
        "originalSettings": {
            "accelerometerRotation": "1", "userRotation": "2"},
        "phaseProtocol": {
            "authority": PHASE_AUTHORITY, "phases": list(PHASES),
            "prefix": PHASE_PREFIX.decode("ascii")},
        "schemaVersion": 1,
        "tools": {name: asdict(value) for name, value in tools.items()},
    }


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(evidence, ensure_ascii=True, allow_nan=False,
                     sort_keys=True, indent=2).encode("ascii") + b"\n"
    try:
        with path.open("xb", buffering=0) as stream:
            written = 0
            while written < len(raw):
                count = stream.write(raw[written:])
                if type(count) is not int or count <= 0:
                    _fail("evidence append made invalid progress")
                written += count
            stream.flush()
            os.fsync(stream.fileno())
        _directory_fsync(path.parent)
    except FileExistsError as error:
        raise ControllerError("refusing to reuse rotation evidence") from error


def _tool_identities(runner: Path, adb: Path) -> dict[str, FileIdentity]:
    tools = {
        "controller": read_regular_identity(Path(__file__), MAX_TOOL_BYTES,
                                             "rotation controller"),
        "python": read_regular_identity(Path(sys.executable), MAX_TOOL_BYTES,
                                         "Python executable"),
        "runner": read_regular_identity(runner, MAX_TOOL_BYTES, "alpha runner"),
        "adb": read_regular_identity(adb, MAX_TOOL_BYTES, "adb executable"),
    }
    if (Path(tools["adb"].path) != PINNED_ADB_PATH or
            tools["adb"].size != PINNED_ADB_SIZE or
            tools["adb"].sha256 != PINNED_ADB_SHA256):
        _fail("adb executable identity differs from the exact pin")
    return tools


def _child_argv(arguments: argparse.Namespace, controller_id: str) -> tuple[str, ...]:
    return (
        str(Path(sys.executable).absolute()), "-u", str(arguments.runner.absolute()),
        "--adb", str(arguments.adb.absolute()), "--serial", AUTHORIZED_SERIAL,
        "--output-root", str(arguments.output_root.absolute()),
        "--host-metadata", str(arguments.host_metadata.absolute()),
        "--rotation-authority", alpha.ROTATION_ADB_SYSTEM_SETTINGS,
        "--rotation-controller-run-id", controller_id,
    )


def _restore_only(arguments: argparse.Namespace) -> dict[str, Any]:
    prefix = read_journal(arguments.journal, allow_torn=True)
    header = prefix.records[0]["payload"]
    tools = {name: FileIdentity(**value) for name, value in header["tools"].items()}
    current_tools = _tool_identities(Path(tools["runner"].path), Path(tools["adb"].path))
    if current_tools != tools:
        _fail("tool identities differ from the rotation journal")
    device = AdbRotationDevice(Path(tools["adb"].path), AUTHORIZED_SERIAL)
    if device.identity() != EXPECTED_DEVICE_IDENTITY:
        _fail("restore-only device differs")
    def guard_restore() -> None:
        journal.assert_current_path()
        if device.identity() != EXPECTED_DEVICE_IDENTITY:
            _fail("restore-only device identity changed")
        for name, value in current_tools.items():
            if read_regular_identity(Path(value.path), MAX_TOOL_BYTES,
                                     name + " restore tool") != value:
                _fail(name + " restore tool identity changed")
    kinds = [record["kind"] for record in prefix.records]
    if "rotation_intent" not in kinds:
        prove_twice(device, ORIGINAL_SETTINGS, None)
        return {
            "authority": EVIDENCE_AUTHORITY,
            "controllerId": header["controllerId"], "phases": [],
            "returncode": None, "result": "ROTATION_UNCHANGED_NO_INTENT",
            "rotationRestored": True,
        }
    if kinds[-1] == "complete":
        prove_twice(device, ORIGINAL_SETTINGS, None)
        return {
            "authority": EVIDENCE_AUTHORITY,
            "controllerId": header["controllerId"], "phases": [],
            "returncode": None, "result": "ROTATION_ALREADY_RESTORED",
            "rotationRestored": True,
        }
    journal = DurableJournal.resume(
        arguments.journal, count=len(prefix.records),
        head_hash=prefix.records[-1]["recordHash"],
        valid_size=prefix.valid_size, prefix_sha256=prefix.prefix_sha256,
        identity=prefix.identity)
    try:
        if "restore_settlement" in kinds:
            prove_twice(device, ORIGINAL_SETTINGS, None)
            journal.record("complete", {"result": "ROTATION_CONTROLLER_CLEAN"})
            return {
                "authority": EVIDENCE_AUTHORITY,
                "controllerId": header["controllerId"], "phases": [],
                "returncode": None, "result": "ROTATION_RESTORED_ONLY",
                "rotationRestored": True,
            }
        if "restore_intent" not in kinds:
            journal.record("restore_intent", {
                "commands": [_command_wire("RESTORE_LOCK_TWO"),
                             _command_wire("RESTORE_FREE")],
                "target": {"accelerometerRotation": "1", "userRotation": "2"},
            })
        lock_error: str | None = None
        free_error: str | None = None
        try:
            try:
                guard_restore()
                device.command("RESTORE_LOCK_TWO")
            except BaseException as error:
                lock_error = type(error).__name__ + ": " + str(error)
        finally:
            try:
                guard_restore()
                device.command("RESTORE_FREE")
            except BaseException as error:
                free_error = type(error).__name__ + ": " + str(error)
        observations = prove_twice(device, ORIGINAL_SETTINGS, None)
        guard_restore()
        journal.record("restore_settlement", {
            "freeError": free_error, "lockError": lock_error,
            "observations": observations})
        if lock_error is not None or free_error is not None:
            raise RestoreError("restore-only commands were transport-uncertain")
        journal.record("complete", {"result": "ROTATION_CONTROLLER_CLEAN"})
        return {
            "authority": EVIDENCE_AUTHORITY,
            "controllerId": header["controllerId"], "phases": [],
            "returncode": None, "result": "ROTATION_RESTORED_ONLY",
            "rotationRestored": True,
        }
    finally:
        journal.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the fixed Nomad alpha under crash-safe ADB rotation control")
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--serial", required=True, choices=(AUTHORIZED_SERIAL,))
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--host-metadata", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--restore-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.restore_only:
            evidence = _restore_only(arguments)
        else:
            controller_id = uuid.uuid4().hex
            tools = _tool_identities(arguments.runner, arguments.adb)
            device = AdbRotationDevice(arguments.adb, arguments.serial)
            if device.adb_identity() != tools["adb"]:
                _fail("ADB identity changed between admission reads")
            journal = DurableJournal(arguments.journal, _header(controller_id, tools))
            try:
                controller = RotationController(device, journal, controller_id, tools)
                evidence = controller.run(_child_argv(arguments, controller_id))
            finally:
                journal.close()
        _write_evidence(arguments.evidence, evidence)
    except (ControllerError, OSError) as error:
        print("ROTATION CONTROLLER STOPPED: " + str(error), file=sys.stderr)
        return 2
    print("Rotation-controlled visual alpha finished: " + str(arguments.evidence.absolute()))
    return 3 if evidence.get("returncode") == 3 else 0


if __name__ == "__main__":
    raise SystemExit(main())
