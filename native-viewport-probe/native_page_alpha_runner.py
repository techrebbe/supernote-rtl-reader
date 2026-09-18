"""Disposable Nomad visual alpha for one native Document page.

This is deliberately *not* the formal visual-session admission harness.  It is
an operator-facing diagnostic that exercises the already-reviewed host command
protocol with a much smaller evidence boundary.  It has no input-injection,
writer, process-kill, force-stop, package-clear, settings, or arbitrary shell
surface.

The only device mutations are:

* durably journal every exact mutation capability and intent locally first;
* provision one fixed, persistent, hash-pinned parking PDF if it is absent;
* no-clobber-copy two pinned files to random staging capabilities, then
  no-clobber-publish their exact identities to fixed disposable paths;
* start the pinned visual-only host;
* launch the exact disposable PDF in the exact stock component/display;
* send the host's authenticated placement/cleanup actions;
* deliver one exact parking ACTION_VIEW to the same retained task/display;
* remove the one retained task ID with Android's ``am stack remove`` route;
* remove any exact staging leftover, then rename each owned target to a per-run
  random quarantine leaf and remove only those revalidated random capabilities
  under the documented residual model.

Every device command carries the one authorized serial.  A caller may choose an
ADB executable and a local output directory, but cannot choose device command
text, a serial, a package, a task, a fixture, or an Android path.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat as stat_module
import struct
import subprocess
import sys
import time
from typing import Any, Callable, NoReturn, Protocol, Sequence
import uuid
import xml.etree.ElementTree as ET
import zipfile
import zlib

import native_page_android_authority as android
import native_page_host_authority as host


AUTHORITY = "native-page-nomad-visual-alpha-v1"
CHECKPOINT = "2eeadd701d25dfeaf978108c358326e8edfaf87d"
AUTHORIZED_SERIAL = "SN078C10015092"
MODEL = "Supernote Nomad"
SDK = "30"
FINGERPRINT = (
    "Supernote/Supernote/Supernote:11/RQ2A.210505.003/"
    "eng.supern.20260616.100032:user/release-keys"
)

DOCUMENT_VERSION_CODE = "102446"
DOCUMENT_VERSION_NAME = "1.02.446"
DOCUMENT_APK = "/system_ext/app/SupernoteDocument/SupernoteDocument.apk"
DOCUMENT_APK_SIZE = 138_486_560
DOCUMENT_APK_SHA256 = (
    "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482"
)

SOURCE_PDF = "/storage/emulated/0/Document/NativeViewport-Stock-20260906.pdf"
SOURCE_MARK = SOURCE_PDF + ".mark"
SOURCE_PDF_SHA256 = (
    "e470c33c6525e02acf88e51352d73b7ed8b6c1591be8d40629a42c708484e720"
)
SOURCE_MARK_SHA256 = (
    "b95c02b05abd9a4f5a3106ffbe442f1f893256a66f8cac3628f04d300992ffd6"
)
TARGET_PDF = (
    "/storage/emulated/0/Download/"
    "NativeViewportVisualOnly-Alpha-2eeadd7.pdf"
)
TARGET_MARK = TARGET_PDF + ".mark"
TARGET_URI = "file://" + TARGET_PDF
STAGING_PREFIX = (
    "/storage/emulated/0/Download/"
    ".NativeViewportVisualOnly-Alpha-2eeadd7-staging-"
)
STAGING_PATTERN = re.compile(
    re.escape(STAGING_PREFIX) +
    r"(?P<nonce>[0-9a-f]{32})-(?P<member>pdf|mark)\Z")
QUARANTINE_PREFIX = (
    "/storage/emulated/0/Download/"
    ".NativeViewportVisualOnly-Alpha-2eeadd7-quarantine-"
)
QUARANTINE_PATTERN = re.compile(
    re.escape(QUARANTINE_PREFIX) +
    r"(?P<nonce>[0-9a-f]{32})-(?P<member>pdf|mark)\Z")
PARKING_PDF = (
    "/storage/emulated/0/Download/"
    ".NativeViewportParking-Alpha-2eeadd7.pdf"
)
PARKING_MARK = PARKING_PDF + ".mark"
PARKING_URI = "file://" + PARKING_PDF

MUTATION_JOURNAL_AUTHORITY = "native-page-alpha-mutation-journal-v1"
ACTIVE_MUTATION_JOURNAL_FILENAME = ".native-page-alpha-active.jsonl"
MUTATION_JOURNAL_FILENAME = "mutation-authority.jsonl"
MUTATION_JOURNAL_MAX_BYTES = 16 * 1024 * 1024
MUTATION_JOURNAL_MAX_RECORDS = 4096

HOST_PACKAGE = host.HOST_PACKAGE
HOST_COMPONENT = host.HOST_COMPONENT
DOCUMENT_PACKAGE = host.FOREIGN_PACKAGE
DOCUMENT_COMPONENT = host.FOREIGN_COMPONENT
DOCUMENT_LAUNCH_USER = "0"
DOCUMENT_LAUNCH_ACTION = "android.intent.action.VIEW"
DOCUMENT_LAUNCH_MIME = "application/pdf"
BOOX_PACKAGE = "com.example.booxplanner"
ALPHA_HOST_VERSION_CODE = 2
ALPHA_HOST_VERSION_NAME = "0.0.2-native-page-visual-only"
ALPHA_SIGNED_APK_SHA256 = (
    "3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03"
)
ALPHA_SIGNER_CERT_SHA256 = (
    "d3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4"
)
REVIEWED_UNSIGNED_APK_SHA256 = (
    "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178"
)
ALPHA_DEX_SHA256 = (
    "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6"
)
REVIEWED_UNSIGNED_AUTHORITY_SHA256 = (
    "94783276471ad4797b9a4ebf2200ae7adfd1ce1fe6ad888e2b5df09b403cb647"
)
HOST_VERSION_CODE = str(ALPHA_HOST_VERSION_CODE)
HOST_VERSION_NAME = ALPHA_HOST_VERSION_NAME

ROTATION_MANUAL_PHYSICAL = "manual-physical-v1"
ROTATION_ADB_SYSTEM_SETTINGS = "adb-system-settings-v1"
ROTATION_AUTHORITIES = (
    ROTATION_MANUAL_PHYSICAL,
    ROTATION_ADB_SYSTEM_SETTINGS,
)
ROTATION_CONTROLLER_PHASE_AUTHORITY = "native-page-alpha-rotation-phase-v1"
ROTATION_CONTROLLER_PHASE_PREFIX = b"NATIVE_PAGE_ALPHA_ROTATION_PHASE "
ROTATION_CONTROLLER_PHASES = (
    "START_LANDSCAPE", "PORTRAIT", "RETURN_LANDSCAPE",
)
ROTATION_CONTROLLER_ID = re.compile(r"[0-9a-f]{32}\Z")

HOST_ACTION_PREFIX = HOST_PACKAGE + "."
ACTION_ATTACH = HOST_ACTION_PREFIX + "ACK_FOREIGN_ATTACHED"
ACTION_FULL = HOST_ACTION_PREFIX + "PLACE_FULL"
ACTION_LEFT = HOST_ACTION_PREFIX + "PLACE_LEFT"
ACTION_RIGHT = HOST_ACTION_PREFIX + "PLACE_RIGHT"
ACTION_CLOSE = HOST_ACTION_PREFIX + "BEGIN_CLOSE"
ACTION_DESTROYED = HOST_ACTION_PREFIX + "ACK_FOREIGN_DESTROYED"
ACTION_EMPTY_PRE_ATTACH = (
    HOST_ACTION_PREFIX + "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"
)
HOST_ACTIONS = frozenset((
    ACTION_ATTACH, ACTION_FULL, ACTION_LEFT, ACTION_RIGHT, ACTION_CLOSE,
    ACTION_DESTROYED, ACTION_EMPTY_PRE_ATTACH,
))

MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_SCREENSHOT_BYTES = 32 * 1024 * 1024
MAX_OBSERVATION_ERROR_BYTES = 1024
MAX_ID = 10_000_000
POLL_SECONDS = 0.20
STEP_TIMEOUT_SECONDS = 12.0
HOST_START_TIMEOUT_SECONDS = 20.0
MANUAL_ROTATION_TIMEOUT_SECONDS = 120.0
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
HEX = re.compile(r"[0-9a-f]{64}\Z")
SAFE_APK = re.compile(r"/(?:data|system|system_ext)/[A-Za-z0-9_./=+~-]+\.apk\Z")

# Defense-in-depth audit for every final argv.  The coordinator has no public
# generic command method, and these primitives are rejected even if a future
# edit accidentally tries to route them through the retained executor.
FORBIDDEN_TOKENS = frozenset({
    "input", "keyevent", "tap", "swipe", "motionevent", "text",
    "force-stop", "kill", "kill-all", "killall", "pkill", "stop-app",
    "settings", "pm-clear", "reboot", "sh", "bash",
})

# These independent literals make the one privileged launch fail closed if a
# future refactor changes any URI/component/action/MIME/user authority without
# deliberately updating this alpha's reviewed command boundary.  No caller can
# supply any of these values; the sole variable is one bounded integer display.
_PINNED_ROOT_LAUNCH_USER = "0"
_PINNED_ROOT_LAUNCH_ACTION = "android.intent.action.VIEW"
_PINNED_ROOT_LAUNCH_URI = (
    "file:///storage/emulated/0/Download/"
    "NativeViewportVisualOnly-Alpha-2eeadd7.pdf"
)
_PINNED_ROOT_LAUNCH_MIME = "application/pdf"
_PINNED_ROOT_LAUNCH_COMPONENT = (
    "com.supernote.document/"
    "com.supernote.document.document.DocumentActivity"
)
_PINNED_ROOT_PARKING_USER = "0"
_PINNED_ROOT_PARKING_ACTION = "android.intent.action.VIEW"
_PINNED_ROOT_PARKING_URI = (
    "file:///storage/emulated/0/Download/"
    ".NativeViewportParking-Alpha-2eeadd7.pdf"
)
_PINNED_ROOT_PARKING_MIME = "application/pdf"
_PINNED_ROOT_PARKING_COMPONENT = (
    "com.supernote.document/"
    "com.supernote.document.document.DocumentActivity"
)


class AlphaError(RuntimeError):
    """The diagnostic cannot safely continue or make a clean claim."""


class CleanupUncertain(AlphaError):
    """At least one exact task/display/file postcondition is unresolved."""


class DiagnosticFailedClean(AlphaError):
    """The probe failed, but its narrow device mutations were all reversed."""

    def __init__(self, report_path: Path):
        self.report_path = report_path
        super().__init__("diagnostic failed cleanly; inspect " + str(report_path))


def _fail(message: str) -> NoReturn:
    raise AlphaError(message)


def _positive(value: int, label: str, maximum: int = MAX_ID) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        _fail(label + " is outside the exact positive range")
    return value


def _canonical_uuid(value: str, label: str) -> str:
    if type(value) is not str:
        _fail(label + " is not text")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as error:
        raise AlphaError(label + " is not a UUID") from error
    if canonical != value:
        _fail(label + " is not a canonical lowercase UUID")
    return value


def _hex(value: str, label: str) -> str:
    if type(value) is not str or HEX.fullmatch(value) is None:
        _fail(label + " is not a lowercase SHA-256")
    return value


def _decode_text(raw: bytes, label: str) -> str:
    if type(raw) is not bytes or len(raw) > MAX_TEXT_BYTES or b"\x00" in raw:
        _fail(label + " output is oversized or contains NUL")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise AlphaError(label + " output is not UTF-8") from error
    if "\r" in text:
        if text.count("\r") != text.count("\r\n"):
            _fail(label + " output has mixed line endings")
        text = text.replace("\r\n", "\n")
    return text


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return _sha(raw)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _unique_journal_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlphaError("mutation journal contains duplicate keys")
        result[key] = value
    return result


def _sync_directory(path: Path) -> None:
    """Durably commit a directory entry on hosts with directory fsync."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_local_file_exclusive(temp: Path, target: Path) -> None:
    """Publish one fsynced local file without replacing an existing journal.

    Windows cannot fsync a directory handle through Python.  Its
    ``MOVEFILE_WRITE_THROUGH`` flag is therefore the pinned host equivalent of
    the POSIX link-plus-directory-fsync publication below.
    """
    if target.exists() or target.is_symlink():
        _fail("mutation journal path already exists and will not be reused")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        move_file_ex = ctypes.WinDLL(
            "kernel32", use_last_error=True).MoveFileExW
        move_file_ex.argtypes = (
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
        move_file_ex.restype = wintypes.BOOL
        movefile_write_through = 0x00000008
        if not move_file_ex(
                str(temp), str(target), movefile_write_through):
            error = ctypes.get_last_error()
            raise AlphaError(
                "exclusive mutation journal publication failed with Windows "
                f"error {error}")
        return
    try:
        source_parent = temp.parent
        os.link(temp, target)
        _sync_directory(target.parent)
        temp.unlink()
        _sync_directory(source_parent)
    except OSError as error:
        raise AlphaError(
            "exclusive mutation journal publication failed") from error


def _journal_record_bytes(payload: dict[str, Any]) -> tuple[bytes, str]:
    digest = _sha(_canonical_json_bytes(payload))
    record = {**payload, "recordSha256": digest}
    return _canonical_json_bytes(record) + b"\n", digest


def recover_mutation_journal(path: Path) -> dict[str, Any]:
    """Strictly recover the exact capabilities from a known journal path.

    Recovery deliberately accepts an exact path only.  It never scans a run
    directory or the device Download directory for guessed capabilities.
    """
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
        parent_before = os.lstat(candidate.parent)
        file_before = os.lstat(candidate)
    except OSError as error:
        raise AlphaError("mutation journal path cannot be retained") from error
    if (os.path.normcase(str(resolved_parent)) !=
            os.path.normcase(str(candidate.parent)) or
            candidate.name not in {
                ACTIVE_MUTATION_JOURNAL_FILENAME,
                MUTATION_JOURNAL_FILENAME} or
            stat_module.S_ISLNK(parent_before.st_mode) or
            not stat_module.S_ISDIR(parent_before.st_mode) or
            stat_module.S_ISLNK(file_before.st_mode) or
            not stat_module.S_ISREG(file_before.st_mode)):
        _fail("mutation journal is absent, linked, or misnamed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if ((opened.st_dev, opened.st_ino) !=
                    (file_before.st_dev, file_before.st_ino)):
                _fail("mutation journal changed at recovery open boundary")
            raw = stream.read(MUTATION_JOURNAL_MAX_BYTES + 1)
        file_after = os.lstat(candidate)
        parent_after = os.lstat(candidate.parent)
    except OSError as error:
        raise AlphaError("mutation journal recovery read failed") from error
    if ((file_after.st_dev, file_after.st_ino) !=
            (file_before.st_dev, file_before.st_ino) or
            (parent_after.st_dev, parent_after.st_ino) !=
            (parent_before.st_dev, parent_before.st_ino)):
        _fail("mutation journal or parent changed during recovery")
    if not 0 < len(raw) <= MUTATION_JOURNAL_MAX_BYTES:
        _fail("mutation journal framing is absent or oversized")
    fragments = raw.split(b"\n")
    torn_tail: bytes | None
    if fragments[-1] == b"":
        lines = [value + b"\n" for value in fragments[:-1]]
        torn_tail = None
    else:
        lines = [value + b"\n" for value in fragments[:-1]]
        torn_tail = fragments[-1]
        canonical_start = b'{"authority":'
        if (not (canonical_start.startswith(torn_tail) or
                 torn_tail.startswith(canonical_start)) or
                b"\r" in torn_tail or b"\x00" in torn_tail):
            _fail("mutation journal torn tail is outside the canonical prefix")
        try:
            torn_tail.decode("ascii", "strict")
        except UnicodeError as error:
            raise AlphaError(
                "mutation journal torn tail is not ASCII") from error
    if (not 0 < len(lines) <= MUTATION_JOURNAL_MAX_RECORDS or
            len(lines) + int(torn_tail is not None) >
            MUTATION_JOURNAL_MAX_RECORDS):
        _fail("mutation journal record count is outside the closed bound")
    previous: str | None = None
    journal_id: str | None = None
    initial_obligations: dict[str, Any] | None = None
    parsed: list[dict[str, Any]] = []
    seen: dict[str, set[str]] = {
        "manifest": set(), "parking": set(), "target_events": set(),
        "publish_settled": set(), "publish_terminal": set(),
        "quarantine_terminal": set(), "fixture_staged": set(),
        "final": set(),
    }
    for expected_sequence, line in enumerate(lines):
        if not line.endswith(b"\n") or b"\r" in line or b"\x00" in line:
            _fail("mutation journal line framing is not canonical LF JSON")
        try:
            value = json.loads(
                line[:-1].decode("ascii", "strict"),
                object_pairs_hook=_unique_journal_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AlphaError("mutation journal is not strict JSON") from error
        required = {
            "authority", "schemaVersion", "journalId", "sequence",
            "previousRecordSha256", "event", "details", "obligations",
            "sourceAuthorities", "parkingProvisioning", "recordSha256",
        }
        if type(value) is not dict or set(value) != required:
            _fail("mutation journal record topology differs")
        try:
            canonical_line = _canonical_json_bytes(value) + b"\n"
        except (TypeError, ValueError, RecursionError) as error:
            raise AlphaError(
                "mutation journal value cannot be canonicalized") from error
        if canonical_line != line:
            _fail("mutation journal record bytes are not canonical ASCII JSON")
        digest = value.pop("recordSha256")
        try:
            calculated_digest = _sha(_canonical_json_bytes(value))
        except (TypeError, ValueError, RecursionError) as error:
            raise AlphaError(
                "mutation journal payload cannot be canonicalized") from error
        if (type(digest) is not str or HEX.fullmatch(digest) is None or
                digest != calculated_digest):
            _fail("mutation journal record hash differs")
        if (value["authority"] != MUTATION_JOURNAL_AUTHORITY or
                type(value["schemaVersion"]) is not int or
                value["schemaVersion"] != 1 or
                type(value["sequence"]) is not int or
                value["sequence"] != expected_sequence or
                value["previousRecordSha256"] != previous or
                type(value["event"]) is not str or
                type(value["details"]) is not dict or
                type(value["obligations"]) is not dict or
                type(value["sourceAuthorities"]) is not dict or
                type(value["parkingProvisioning"]) is not dict):
            _fail("mutation journal chain or field types differ")
        _validate_journal_snapshot(
            value["obligations"], value["sourceAuthorities"],
            value["parkingProvisioning"])
        target = _validate_journal_details(
            value["event"], value["details"], value["obligations"],
            value["parkingProvisioning"])
        _validate_journal_event_order(
            value["event"], target, seen, value["parkingProvisioning"])
        if expected_sequence == 0:
            if value["event"] != "MANIFEST_CREATED":
                _fail("mutation journal does not begin with its manifest")
            _canonical_uuid(value["journalId"], "mutation journal ID")
            journal_id = value["journalId"]
            initial_obligations = value["obligations"]
            for obligation in initial_obligations.values():
                if obligation != _journal_initial_obligation(obligation):
                    _fail("mutation journal manifest obligations are not pristine")
            if value["parkingProvisioning"] != {
                    "reached": False, "copyAttempted": False,
                    "copyReplyProved": False, "settled": False}:
                _fail("mutation journal manifest parking state is not pristine")
            output_directory = Path(value["details"]["outputDirectory"])
            expected_parent = (
                candidate.parent if candidate.name ==
                ACTIVE_MUTATION_JOURNAL_FILENAME else candidate.parent.parent)
            if (output_directory.parent != expected_parent or
                    candidate.name == MUTATION_JOURNAL_FILENAME and
                    output_directory != candidate.parent):
                _fail("mutation journal run directory binding differs")
        elif value["journalId"] != journal_id:
            _fail("mutation journal ID changed within its chain")
        else:
            _validate_journal_monotonic(parsed[-1], value)
            _validate_journal_operation_delta(
                parsed[-1], value, value["event"], target)
        parsed.append({**value, "recordSha256": digest})
        previous = digest
    if initial_obligations is None:
        _fail("mutation journal lacks initial cleanup obligations")
    return {
        "journalId": journal_id,
        "headSha256": previous,
        "recordCount": len(parsed),
        "fileIdentity": [file_after.st_dev, file_after.st_ino],
        "parentIdentity": [parent_after.st_dev, parent_after.st_ino],
        "initialObligations": initial_obligations,
        "lastRecord": parsed[-1],
        "tornTail": torn_tail is not None,
        "tornTailSize": 0 if torn_tail is None else len(torn_tail),
        "tornTailSha256": None if torn_tail is None else _sha(torn_tail),
    }


def _quarantine_path(target: str, nonce: str) -> str:
    """Derive one hidden, unguessable quarantine leaf without directory scans."""
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        _fail("quarantine nonce is not 128-bit lowercase hexadecimal")
    member = {TARGET_PDF: "pdf", TARGET_MARK: "mark"}.get(target)
    if member is None:
        _fail("quarantine target escaped the disposable fixture")
    result = QUARANTINE_PREFIX + nonce + "-" + member
    match = QUARANTINE_PATTERN.fullmatch(result)
    if match is None or match.group("member") != member:
        _fail("derived quarantine path is outside the closed grammar")
    return result


def _staging_path(target: str, nonce: str) -> str:
    """Derive one hidden, unguessable staging leaf without directory scans."""
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        _fail("staging nonce is not 128-bit lowercase hexadecimal")
    member = {TARGET_PDF: "pdf", TARGET_MARK: "mark"}.get(target)
    if member is None:
        _fail("staging target escaped the disposable fixture")
    result = STAGING_PREFIX + nonce + "-" + member
    match = STAGING_PATTERN.fullmatch(result)
    if match is None or match.group("member") != member:
        _fail("derived staging path is outside the closed grammar")
    return result


def _staging_target(path: str) -> str:
    if type(path) is not str:
        _fail("staging path is not text")
    match = STAGING_PATTERN.fullmatch(path)
    if match is None:
        _fail("staging path is outside the closed grammar")
    return TARGET_PDF if match.group("member") == "pdf" else TARGET_MARK


def _quarantine_target(path: str) -> str:
    if type(path) is not str:
        _fail("quarantine path is not text")
    match = QUARANTINE_PATTERN.fullmatch(path)
    if match is None:
        _fail("quarantine path is outside the closed grammar")
    return TARGET_PDF if match.group("member") == "pdf" else TARGET_MARK


def _root_document_launch_command(display_id: int) -> str:
    """Return the sole admitted privileged activity-launch command.

    ``DocumentActivity`` is non-exported on the pinned firmware, so Android's
    ordinary shell UID cannot start it.  Magisk ``su -c`` is required, but the
    root shell receives no caller text: this function accepts only a strict
    positive display ID and renders every other token from independent pins.
    """
    display = _positive(display_id, "launch display", 1024)
    if (
        DOCUMENT_LAUNCH_USER != _PINNED_ROOT_LAUNCH_USER or
        DOCUMENT_LAUNCH_ACTION != _PINNED_ROOT_LAUNCH_ACTION or
        TARGET_URI != _PINNED_ROOT_LAUNCH_URI or
        DOCUMENT_LAUNCH_MIME != _PINNED_ROOT_LAUNCH_MIME or
        DOCUMENT_COMPONENT != _PINNED_ROOT_LAUNCH_COMPONENT
    ):
        _fail("privileged Document launch authority differs from its pins")
    return " ".join((
        "am", "start", "--user", DOCUMENT_LAUNCH_USER,
        "--display", str(display), "-a", DOCUMENT_LAUNCH_ACTION,
        "-d", TARGET_URI, "-t", DOCUMENT_LAUNCH_MIME,
        "-n", DOCUMENT_COMPONENT,
    ))


def _root_parking_launch_command(display_id: int) -> str:
    """Return the independently pinned privileged parking launch command."""
    display = _positive(display_id, "parking launch display", 1024)
    if (
        DOCUMENT_LAUNCH_USER != _PINNED_ROOT_PARKING_USER or
        DOCUMENT_LAUNCH_ACTION != _PINNED_ROOT_PARKING_ACTION or
        PARKING_URI != _PINNED_ROOT_PARKING_URI or
        DOCUMENT_LAUNCH_MIME != _PINNED_ROOT_PARKING_MIME or
        DOCUMENT_COMPONENT != _PINNED_ROOT_PARKING_COMPONENT
    ):
        _fail("privileged parking launch authority differs from its pins")
    return " ".join((
        "am", "start", "--user", DOCUMENT_LAUNCH_USER,
        "--display", str(display), "-a", DOCUMENT_LAUNCH_ACTION,
        "-d", PARKING_URI, "-t", DOCUMENT_LAUNCH_MIME,
        "-n", DOCUMENT_COMPONENT,
    ))


def _root_command_is_closed(command: str) -> bool:
    """Recognize only reviewed, generated Magisk command strings."""
    if type(command) is not str:
        return False
    proc = re.fullmatch(
        r"(?:cat /proc/([1-9][0-9]{0,6})/(?:stat|status|cmdline)|"
        r"ls -l /proc/([1-9][0-9]{0,6})/fd)",
        command,
    )
    if proc is not None:
        pid = int(proc.group(1) or proc.group(2))
        return pid <= android.MAX_PID
    display = re.fullmatch(
        r"am start --user 0 --display ([1-9][0-9]{0,3}) "
        r"-a android\.intent\.action\.VIEW "
        r"-d file:///storage/emulated/0/Download/"
        r"(?:NativeViewportVisualOnly-Alpha-2eeadd7|"
        r"\.NativeViewportParking-Alpha-2eeadd7)\.pdf "
        r"-t application/pdf "
        r"-n com\.supernote\.document/"
        r"com\.supernote\.document\.document\.DocumentActivity",
        command,
    )
    return display is not None and int(display.group(1)) <= 1024


def _is_shell_executable_alias(token: str) -> bool:
    """Identify shell/root launchers regardless of casing or absolute path."""
    if type(token) is not str:
        return False
    basename = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return basename in {
        "su", "sh", "ash", "bash", "dash", "fish", "ksh", "mksh", "zsh",
    }


def _safe_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if type(argv) not in (tuple, list) or not argv:
        _fail("ADB argv is absent")
    result = tuple(argv)
    if any(type(item) is not str or not item for item in result):
        _fail("ADB argv contains an empty/non-text token")
    for item in result:
        lowered = item.lower()
        if lowered in FORBIDDEN_TOKENS or item == "-S":
            _fail("forbidden Android mutation primitive: " + item)
        if any(character in item for character in (
                "\x00", "\r", "\n", ";", "&", "|", "`", "$", ">", "<")):
            _fail("ADB argv contains shell syntax")
    try:
        marker = result.index("-s")
    except ValueError as error:
        raise AlphaError("ADB command lacks an explicit serial") from error
    if (result.count("-s") != 1 or marker != 1 or marker + 1 >= len(result) or
            result[marker + 1] != AUTHORIZED_SERIAL):
        _fail("ADB command targets anything other than the authorized Nomad")
    exact_root_prefix = result[3:6] == ("shell", "su", "-c")
    if exact_root_prefix:
        if (len(result) != 7 or result.count("su") != 1 or
                not _root_command_is_closed(result[6])):
            _fail("Magisk command escaped the closed root-command set")
    elif (any(_is_shell_executable_alias(item) for item in result[3:]) or
          any(any(character.isspace() for character in item)
              for item in result[3:])):
        _fail("unreviewed shell/root executable or combined command is forbidden")
    return result


def host_command_argv(
        adb: str, status: "HostStatus", sequence: int, action: str,
        foreign: host.ForeignIdentity | None = None,
        absence_sha256: str | None = None) -> tuple[str, ...]:
    """Render one closed host protocol command; accepts no command text."""
    if action not in HOST_ACTIONS:
        _fail("host action is outside the closed alpha protocol")
    _positive(sequence, "host command sequence", 2_147_483_647)
    status.validate()
    body: list[str] = [
        adb, "-s", AUTHORIZED_SERIAL, "shell", "am", "start", "--user", "0",
        "--display", "0", "-a", action, "-n", HOST_COMPONENT,
        "--es", "session", status.session,
        "--el", "generation", str(status.generation),
        "--ei", "display", str(status.display_id),
        "--el", "sequence", str(sequence),
    ]
    if action in (ACTION_ATTACH, ACTION_DESTROYED):
        if type(foreign) is not host.ForeignIdentity:
            _fail("foreign task identity is required by this host action")
        process = foreign.process
        if (type(process) is not host.ProcessIdentity or
                process.package != DOCUMENT_PACKAGE or process.uid != 1000 or
                foreign.component != DOCUMENT_COMPONENT):
            _fail("foreign task escaped the exact stock identity domain")
        _positive(process.pid, "foreign PID", android.MAX_PID)
        _positive(process.start_ticks, "foreign process start ticks", 10**32 - 1)
        _positive(foreign.task_id, "foreign task")
        _hex(foreign.evidence_sha256, "foreign evidence")
        body.extend([
            "--es", "foreignPackage", DOCUMENT_PACKAGE,
            "--es", "foreignComponent", DOCUMENT_COMPONENT,
            "--ei", "foreignTask", str(foreign.task_id),
            "--ei", "foreignPid", str(process.pid),
            "--ei", "foreignUid", "1000",
            "--es", "foreignStartTicks", str(process.start_ticks),
            "--es", "foreignEvidenceSha256", foreign.evidence_sha256,
        ])
    elif action == ACTION_EMPTY_PRE_ATTACH:
        if absence_sha256 is None:
            _fail("pre-attach abort requires an exact absence digest")
        body.extend([
            "--es", "absenceEvidenceSha256",
            _hex(absence_sha256, "pre-attach absence"),
        ])
    elif foreign is not None or absence_sha256 is not None:
        _fail("host action received an ineligible payload")
    return _safe_argv(body)


def document_launch_argv(adb: str, display_id: int) -> tuple[str, ...]:
    command = _root_document_launch_command(display_id)
    return _safe_argv((
        adb, "-s", AUTHORIZED_SERIAL, "shell", "su", "-c", command,
    ))


def parking_document_launch_argv(adb: str, display_id: int) -> tuple[str, ...]:
    command = _root_parking_launch_command(display_id)
    return _safe_argv((
        adb, "-s", AUTHORIZED_SERIAL, "shell", "su", "-c", command,
    ))


def exact_task_remove_argv(adb: str, task_id: int) -> tuple[str, ...]:
    # Android 11's `am stack remove` dispatches ActivityTaskManager.removeTask
    # for the supplied root-task ID.  The strict firmware parser requires the
    # retained Document task ID and stack/root-task ID to be identical.
    _positive(task_id, "retained task")
    return _safe_argv((
        adb, "-s", AUTHORIZED_SERIAL, "shell", "am", "stack",
        "remove", str(task_id),
    ))


@dataclass(frozen=True)
class CommandResult:
    operation: str
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class Executor(Protocol):
    def __call__(self, argv: Sequence[str], *, capture_output: bool,
                 timeout: float, check: bool) -> subprocess.CompletedProcess[bytes]: ...


@dataclass(frozen=True)
class DeviceFile:
    path: str
    kind: str
    size: int
    uid: int
    gid: int
    inode: int
    device: int
    sha256: str

    def same_object(self, other: "DeviceFile") -> bool:
        return (
            type(other) is DeviceFile and self.path == other.path and
            self.kind == other.kind == "regular file" and
            (self.uid, self.gid, self.inode, self.device) ==
            (other.uid, other.gid, other.inode, other.device)
        )

    def same_renamed_object(self, other: "DeviceFile") -> bool:
        """Prove this exact object/content at a distinct quarantine pathname."""
        return (
            type(other) is DeviceFile and self.path != other.path and
            self.kind == other.kind == "regular file" and
            (self.size, self.uid, self.gid, self.inode, self.device,
             self.sha256) ==
            (other.size, other.uid, other.gid, other.inode, other.device,
             other.sha256)
        )


@dataclass
class FixtureObligation:
    source: str
    target: str
    expected_sha256: str
    staging_path: str
    quarantine_path: str
    pre_copy_absence_sha256: str | None = None
    staging_pre_absence_sha256: str | None = None
    staging_preexisting_observed: DeviceFile | None = None
    copy_attempted: bool = False
    copy_reply_proved: bool = False
    staging_post_copy_observed: DeviceFile | None = None
    staging_retained: DeviceFile | None = None
    staging_ownership_ambiguous: bool = False
    publish_move_attempted: bool = False
    publish_move_reply_proved: bool = False
    publish_move_transport_error: str | None = None
    publish_move_postcondition: str | None = None
    publish_move_source_observed: DeviceFile | None = None
    publish_move_target_observed: DeviceFile | None = None
    staging_cleanup_attempted: bool = False
    staging_cleanup_reply_proved: bool = False
    staging_cleanup_transport_error: str | None = None
    staging_cleanup_pre_observed: DeviceFile | None = None
    staging_cleanup_post_observed: DeviceFile | None = None
    staging_cleanup_absence_observations: int = 0
    staging_resolved_absent: bool = False
    retained: DeviceFile | None = None
    ownership_ambiguous: bool = False
    quarantine_pre_absence_sha256: str | None = None
    quarantine_preexisting_observed: DeviceFile | None = None
    quarantine_move_attempted: bool = False
    quarantine_move_reply_proved: bool = False
    quarantine_move_transport_error: str | None = None
    quarantine_move_postcondition: str | None = None
    quarantine_move_source_observed: DeviceFile | None = None
    quarantine_move_destination_observed: DeviceFile | None = None
    quarantine_retained: DeviceFile | None = None
    quarantine_remove_attempted: bool = False
    quarantine_remove_reply_proved: bool = False
    quarantine_remove_transport_error: str | None = None
    quarantine_remove_precondition: str | None = None
    quarantine_remove_source_observed: DeviceFile | None = None
    quarantine_remove_postcondition: str | None = None
    quarantine_remove_pre_observed: DeviceFile | None = None
    quarantine_remove_post_observed: DeviceFile | None = None
    quarantine_remove_absence_observations: int = 0
    quarantine_resolved_absent: bool = False
    resolved_absent: bool = False
    parking_recreated_or_replaced: bool = False
    parking_absent_before_switch: bool = False
    pre_parking_retained: DeviceFile | None = None


def _validate_journal_snapshot(
        obligations: dict[str, Any], sources: dict[str, Any],
        parking: dict[str, Any],
        ) -> None:
    """Validate the complete closed wire snapshot, not merely its topology."""
    expected_members = {
        TARGET_PDF: (SOURCE_PDF, SOURCE_PDF_SHA256),
        TARGET_MARK: (SOURCE_MARK, SOURCE_MARK_SHA256),
    }
    if set(obligations) != set(expected_members):
        _fail("mutation journal obligation topology differs")
    obligation_fields = set(asdict(FixtureObligation(
        SOURCE_PDF, TARGET_PDF, SOURCE_PDF_SHA256,
        _staging_path(TARGET_PDF, "0" * 32),
        _quarantine_path(TARGET_PDF, "1" * 32))))
    boolean_fields = {
        "copy_attempted", "copy_reply_proved",
        "staging_ownership_ambiguous", "publish_move_attempted",
        "publish_move_reply_proved", "staging_cleanup_attempted",
        "staging_cleanup_reply_proved", "staging_resolved_absent",
        "ownership_ambiguous", "quarantine_move_attempted",
        "quarantine_move_reply_proved", "quarantine_remove_attempted",
        "quarantine_remove_reply_proved", "quarantine_resolved_absent",
        "resolved_absent", "parking_recreated_or_replaced",
        "parking_absent_before_switch",
    }
    integer_fields = {
        "staging_cleanup_absence_observations",
        "quarantine_remove_absence_observations",
    }
    digest_fields = {
        "pre_copy_absence_sha256", "staging_pre_absence_sha256",
        "quarantine_pre_absence_sha256",
    }
    text_fields = {
        "publish_move_transport_error", "publish_move_postcondition",
        "staging_cleanup_transport_error",
        "quarantine_move_transport_error", "quarantine_move_postcondition",
        "quarantine_remove_transport_error",
        "quarantine_remove_precondition", "quarantine_remove_postcondition",
    }
    device_paths = {
        "staging_preexisting_observed": "staging",
        "staging_post_copy_observed": "staging",
        "staging_retained": "staging",
        "publish_move_source_observed": "staging",
        "publish_move_target_observed": "target",
        "staging_cleanup_pre_observed": "staging",
        "staging_cleanup_post_observed": "staging",
        "retained": "target",
        "quarantine_preexisting_observed": "quarantine",
        "quarantine_move_source_observed": "target",
        "quarantine_move_destination_observed": "quarantine",
        "quarantine_retained": "quarantine",
        "quarantine_remove_source_observed": "target",
        "quarantine_remove_pre_observed": "quarantine",
        "quarantine_remove_post_observed": "quarantine",
        "pre_parking_retained": "target",
    }
    all_capabilities: list[str] = []
    for target, (source, expected_hash) in expected_members.items():
        value = obligations[target]
        if (type(value) is not dict or set(value) != obligation_fields or
                value["source"] != source or value["target"] != target or
                value["expected_sha256"] != expected_hash or
                _staging_target(value["staging_path"]) != target or
                _quarantine_target(value["quarantine_path"]) != target):
            _fail("mutation journal obligation identity differs")
        all_capabilities.extend((value["staging_path"],
                                 value["quarantine_path"]))
        for field in boolean_fields:
            if type(value[field]) is not bool:
                _fail("mutation journal obligation boolean differs: " + field)
        for field in integer_fields:
            if (type(value[field]) is not int or
                    not 0 <= value[field] <= 2):
                _fail("mutation journal absence count differs: " + field)
        for field in digest_fields:
            item = value[field]
            if item is not None:
                _hex(item, "mutation journal " + field)
        for field in text_fields:
            item = value[field]
            if (item is not None and
                    (type(item) is not str or not item or len(item) > 4096 or
                     any(character in item for character in "\x00\r\n"))):
                _fail("mutation journal optional text differs: " + field)
        allowed_postconditions = {
            "publish_move_postcondition": {
                "stage-present/target-present", "stage-present/target-absent",
                "stage-absent/target-present", "stage-absent/target-absent",
                "stage-absent/target-exact"},
            "quarantine_move_postcondition": {
                "source-present/destination-present",
                "source-present/destination-absent",
                "source-absent/destination-present",
                "source-absent/destination-absent",
                "source-absent/destination-exact"},
            "quarantine_remove_precondition": {
                "source-present/destination-present",
                "source-present/destination-absent",
                "source-absent/destination-present",
                "source-absent/destination-absent",
                "source-absent/destination-exact"},
            "quarantine_remove_postcondition": {
                "destination-present", "destination-absent"},
        }
        for field, allowed in allowed_postconditions.items():
            if value[field] is not None and value[field] not in allowed:
                _fail("mutation journal obligation state grammar differs: " + field)
        expected_digests = {
            "pre_copy_absence_sha256": {
                "authority": AUTHORITY, "kind": "pre-copy-target-absence",
                "source": source, "target": target,
                "expectedSha256": expected_hash},
            "staging_pre_absence_sha256": {
                "authority": AUTHORITY, "kind": "pre-copy-staging-absence",
                "source": source, "target": target,
                "staging": value["staging_path"],
                "expectedSha256": expected_hash, "observations": 2},
            "quarantine_pre_absence_sha256": {
                "authority": AUTHORITY, "kind": "pre-quarantine-absence",
                "target": target, "quarantine": value["quarantine_path"],
                "expectedSha256": expected_hash, "observations": 2},
        }
        for field, digest_payload in expected_digests.items():
            if (value[field] is not None and
                    value[field] != _canonical_sha(digest_payload)):
                _fail("mutation journal absence digest differs: " + field)
        expected_paths = {
            "staging": value["staging_path"],
            "target": target,
            "quarantine": value["quarantine_path"],
        }
        for field, path_kind in device_paths.items():
            item = value[field]
            if item is not None:
                _validate_journal_device_file(
                    item, expected_paths[path_kind], field)
        for field in (
                "staging_retained", "retained", "quarantine_retained",
                "pre_parking_retained"):
            if (value[field] is not None and
                    value[field]["sha256"] != expected_hash):
                _fail("mutation journal retained content hash differs: " + field)
        if (value["copy_reply_proved"] and not value["copy_attempted"] or
                value["staging_retained"] is not None and
                not value["copy_reply_proved"] or
                value["publish_move_reply_proved"] and
                not value["publish_move_attempted"] or
                value["staging_cleanup_reply_proved"] and
                not value["staging_cleanup_attempted"] or
                value["staging_resolved_absent"] and
                value["staging_cleanup_absence_observations"] != 2 or
                value["quarantine_move_reply_proved"] and
                not value["quarantine_move_attempted"] or
                value["quarantine_remove_reply_proved"] and
                not value["quarantine_remove_attempted"] or
                value["quarantine_resolved_absent"] and
                value["quarantine_remove_attempted"] and
                value["quarantine_remove_absence_observations"] != 2 or
                value["quarantine_resolved_absent"] and
                not value["quarantine_move_attempted"] and
                value["quarantine_pre_absence_sha256"] is None or
                value["resolved_absent"] and
                (not value["staging_resolved_absent"] or
                 not value["quarantine_resolved_absent"]) or
                value["parking_recreated_or_replaced"] and
                (value["pre_parking_retained"] is None or
                 value["retained"] is None)):
            _fail("mutation journal obligation implications differ")
    forbidden_capabilities = {
        SOURCE_PDF, SOURCE_MARK, TARGET_PDF, TARGET_MARK,
        PARKING_PDF, PARKING_MARK,
    }
    if (len(set(all_capabilities)) != len(all_capabilities) or
            set(all_capabilities) & forbidden_capabilities):
        _fail("mutation journal mutation capabilities are not unique")
    if set(sources) != {"pdf", "mark"}:
        _fail("mutation journal source authority topology differs")
    for label, expected_path, expected_hash in (
            ("pdf", SOURCE_PDF, SOURCE_PDF_SHA256),
            ("mark", SOURCE_MARK, SOURCE_MARK_SHA256)):
        value = sources[label]
        _validate_journal_device_file(value, expected_path, label)
        if value["sha256"] != expected_hash:
            _fail("mutation journal source authority differs")
    if (set(parking) != {
            "reached", "copyAttempted", "copyReplyProved", "settled"} or
            any(type(value) is not bool for value in parking.values())):
        _fail("mutation journal parking state topology differs")
    if (parking["copyAttempted"] and not parking["reached"] or
            parking["copyReplyProved"] and not parking["copyAttempted"] or
            parking["settled"] and not parking["reached"]):
        _fail("mutation journal parking state implications differ")


def _validate_journal_device_file(
        value: Any, expected_path: str, label: str) -> None:
    fields = {
        "path", "kind", "size", "uid", "gid", "inode", "device",
        "sha256",
    }
    if (type(value) is not dict or set(value) != fields or
            value["path"] != expected_path or
            value["kind"] != "regular file"):
        _fail("mutation journal device identity differs: " + label)
    for field in ("size", "inode", "device"):
        if (type(value[field]) is not int or
                not 1 <= value[field] <= 2**63 - 1):
            _fail("mutation journal device integer differs: " + label)
    for field in ("uid", "gid"):
        if (type(value[field]) is not int or
                not 0 <= value[field] <= 2**31 - 1):
            _fail("mutation journal device ownership differs: " + label)
    _hex(value["sha256"], "mutation journal device hash")


def _journal_initial_obligation(value: dict[str, Any]) -> dict[str, Any]:
    return asdict(FixtureObligation(
        source=value["source"], target=value["target"],
        expected_sha256=value["expected_sha256"],
        staging_path=value["staging_path"],
        quarantine_path=value["quarantine_path"]))


def _journal_detail_text(value: Any, label: str) -> str:
    if (type(value) is not str or not value or len(value) > 4096 or
            any(character in value for character in "\x00\r\n")):
        _fail("mutation journal detail text differs: " + label)
    return value


def _validate_reply_error_pair(
        reply_proved: Any, transport_error: Any, label: str) -> None:
    if (type(reply_proved) is not bool or
            reply_proved and transport_error is not None or
            not reply_proved and transport_error is None):
        _fail("mutation journal reply/error evidence differs: " + label)
    if transport_error is not None:
        _journal_detail_text(transport_error, label)


def _journal_presence_postcondition(
        source: Any, destination: Any, *, publish: bool) -> str:
    if source is not None and type(source) is not dict:
        _fail("mutation journal source observation differs")
    if destination is not None and type(destination) is not dict:
        _fail("mutation journal destination observation differs")
    if publish:
        return (
            ("stage-present" if source is not None else "stage-absent") +
            "/" +
            ("target-present" if destination is not None else
             "target-absent"))
    return (
        ("source-present" if source is not None else "source-absent") +
        "/" +
        ("destination-present" if destination is not None else
         "destination-absent"))


def _journal_same_renamed_object(source: Any, destination: Any) -> bool:
    if type(source) is not dict or type(destination) is not dict:
        return False
    return DeviceFile(**source).same_renamed_object(DeviceFile(**destination))


def _validate_journal_details(
        event: str, details: dict[str, Any],
        obligations: dict[str, Any], parking: dict[str, Any]) -> str | None:
    """Validate the closed event/detail wire and return its target, if any."""
    schemas: dict[str, set[str]] = {
        "MANIFEST_CREATED": {
            "checkpoint", "authorizedSerial", "sourcePdfSha256",
            "sourceMarkSha256", "parkingPdf", "parkingMark",
            "outputDirectory", "neverScanForCapabilities",
        },
        "PARKING_PROVISIONING_REACHED": {"path", "markPath"},
        "PARKING_COPY_ATTEMPTED": {"source", "target", "retryAllowed"},
        "PARKING_PROVISIONING_SETTLED": {
            "path", "copied", "copyTransportError", "retained"},
        "FIXTURE_COPY_ATTEMPTED": {
            "source", "target", "staging", "retryAllowed"},
        "FIXTURE_COPY_SETTLED": {
            "source", "target", "staging", "retained"},
        "FIXTURE_PUBLISH_ATTEMPTED": {
            "source", "target", "retryAllowed"},
        "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS": {
            "source", "target", "error"},
        "FIXTURE_PUBLISH_SETTLED": {
            "source", "target", "retained", "moveReplyProved",
            "moveTransportError"},
        "FIXTURE_PUBLISH_UNSETTLED": {
            "source", "target", "postcondition", "detail"},
        "FIXTURE_STAGED": {"uri", "pdfSha256", "markSha256"},
        "STAGING_REMOVE_ATTEMPTED": {
            "staging", "target", "retained", "retryAllowed"},
        "STAGING_REMOVE_SETTLED": {
            "staging", "target", "removeReplyProved",
            "removeTransportError", "absenceObservations"},
        "QUARANTINE_MOVE_ATTEMPTED": {
            "source", "quarantine", "retained", "retryAllowed"},
        "QUARANTINE_MOVE_SETTLED": {
            "source", "quarantine", "retained", "moveReplyProved",
            "moveTransportError"},
        "QUARANTINE_MOVE_UNSETTLED": {
            "source", "quarantine", "postcondition", "detail"},
        "QUARANTINE_REMOVE_ATTEMPTED": {
            "source", "quarantine", "retained", "retryAllowed"},
        "QUARANTINE_REMOVE_SETTLED": {
            "source", "quarantine", "removeReplyProved",
            "removeTransportError", "absenceObservations"},
        "DEVICE_MUTATIONS_SETTLED": {
            "fixtureRemoved", "sourceFixtureUnchanged",
            "parkingFixtureUnchanged"},
    }
    if event not in schemas or set(details) != schemas[event]:
        _fail("mutation journal event/detail grammar differs: " + event)
    if event == "MANIFEST_CREATED":
        if (details["checkpoint"] != CHECKPOINT or
                details["authorizedSerial"] != AUTHORIZED_SERIAL or
                details["sourcePdfSha256"] != SOURCE_PDF_SHA256 or
                details["sourceMarkSha256"] != SOURCE_MARK_SHA256 or
                details["parkingPdf"] != PARKING_PDF or
                details["parkingMark"] != PARKING_MARK or
                details["neverScanForCapabilities"] is not True or
                type(details["outputDirectory"]) is not str or
                not 0 < len(details["outputDirectory"]) <= 4096 or
                any(character in details["outputDirectory"]
                    for character in "\x00\r\n") or
                not Path(details["outputDirectory"]).is_absolute() or
                str(Path(details["outputDirectory"])) !=
                details["outputDirectory"] or
                not Path(details["outputDirectory"]).name.startswith("alpha-")):
            _fail("mutation journal manifest details differ")
        return None
    if event == "PARKING_PROVISIONING_REACHED":
        if details != {"path": PARKING_PDF, "markPath": PARKING_MARK}:
            _fail("mutation journal parking-reached details differ")
        if any(value != _journal_initial_obligation(value)
               for value in obligations.values()):
            _fail("mutation journal parking event carries fixture mutation state")
        return None
    if event == "PARKING_COPY_ATTEMPTED":
        if (details != {"source": SOURCE_PDF, "target": PARKING_PDF,
                        "retryAllowed": False} or
                details["retryAllowed"] is not False):
            _fail("mutation journal parking-copy details differ")
        if any(value != _journal_initial_obligation(value)
               for value in obligations.values()):
            _fail("mutation journal parking event carries fixture mutation state")
        return None
    if event == "PARKING_PROVISIONING_SETTLED":
        if (details["path"] != PARKING_PDF or
                type(details["copied"]) is not bool or
                details["copyTransportError"] is not None and
                type(details["copyTransportError"]) is not str):
            _fail("mutation journal parking-settled details differ")
        if details["copyTransportError"] is not None:
            _journal_detail_text(details["copyTransportError"], event)
        if any(value != _journal_initial_obligation(value)
               for value in obligations.values()):
            _fail("mutation journal parking event carries fixture mutation state")
        _validate_journal_device_file(
            details["retained"], PARKING_PDF, event)
        if (details["retained"]["sha256"] != SOURCE_PDF_SHA256 or
                details["copied"] != parking["copyAttempted"]):
            _fail("mutation journal parking settlement evidence differs")
        if details["copied"]:
            _validate_reply_error_pair(
                parking["copyReplyProved"],
                details["copyTransportError"], event)
        elif (parking["copyReplyProved"] or
                details["copyTransportError"] is not None):
            _fail("mutation journal no-copy parking settlement differs")
        return None
    if event == "FIXTURE_STAGED":
        if details != {"uri": TARGET_URI, "pdfSha256": SOURCE_PDF_SHA256,
                       "markSha256": SOURCE_MARK_SHA256}:
            _fail("mutation journal fixture-staged details differ")
        return None
    if event == "DEVICE_MUTATIONS_SETTLED":
        if (details["fixtureRemoved"] is not True or
                details["sourceFixtureUnchanged"] is not True or
                details["parkingFixtureUnchanged"] is not True):
            _fail("mutation journal final-settlement details differ")
        if not all(
                value["resolved_absent"] and
                value["staging_resolved_absent"] and
                value["quarantine_resolved_absent"]
                for value in obligations.values()):
            _fail("mutation journal final settlement retains obligations")
        return None

    target = details.get("target", details.get("source"))
    if event.startswith("QUARANTINE_"):
        target = details["source"]
    if type(target) is not str or target not in obligations:
        _fail("mutation journal event target differs: " + event)
    obligation = obligations[target]
    if "source" in details:
        expected_source = (
            obligation["source"] if event.startswith("FIXTURE_COPY_") else
            obligation["staging_path"] if event.startswith("FIXTURE_PUBLISH_") else
            target)
        if details["source"] != expected_source:
            _fail("mutation journal event source differs: " + event)
    if "target" in details and details["target"] != target:
        _fail("mutation journal event fixed target differs: " + event)
    if "staging" in details and details["staging"] != obligation["staging_path"]:
        _fail("mutation journal event staging differs: " + event)
    if ("quarantine" in details and
            details["quarantine"] != obligation["quarantine_path"]):
        _fail("mutation journal event quarantine differs: " + event)
    for field in ("retryAllowed",):
        if field in details and details[field] is not False:
            _fail("mutation journal retry authority differs: " + event)
    for field in ("moveReplyProved", "removeReplyProved"):
        if field in details and type(details[field]) is not bool:
            _fail("mutation journal reply evidence differs: " + event)
    for field in ("moveTransportError", "removeTransportError"):
        if field in details and details[field] is not None:
            _journal_detail_text(details[field], field)
    if "retained" in details:
        expected_path = (
            obligation["staging_path"] if event.startswith("FIXTURE_COPY_") or
            event.startswith("STAGING_") else
            obligation["quarantine_path"] if
            event == "QUARANTINE_MOVE_SETTLED" or
            event.startswith("QUARANTINE_REMOVE_") else target)
        _validate_journal_device_file(details["retained"], expected_path, event)
    if "error" in details:
        _journal_detail_text(details["error"], event)
    if "detail" in details:
        _journal_detail_text(details["detail"], event)
    if "postcondition" in details:
        _journal_detail_text(details["postcondition"], event)
        allowed = (
            {"stage-present/target-present", "stage-present/target-absent",
             "stage-absent/target-present", "stage-absent/target-absent",
             "stage-absent/target-exact"}
            if event.startswith("FIXTURE_PUBLISH_") else
            {"source-present/destination-present",
             "source-present/destination-absent",
             "source-absent/destination-present",
             "source-absent/destination-absent",
             "source-absent/destination-exact"})
        if details["postcondition"] not in allowed:
            _fail("mutation journal postcondition grammar differs: " + event)
    if ("absenceObservations" in details and
            details["absenceObservations"] != 2):
        _fail("mutation journal absence settlement differs: " + event)
    required_state = {
        "FIXTURE_COPY_ATTEMPTED": "copy_attempted",
        "FIXTURE_COPY_SETTLED": "staging_retained",
        "FIXTURE_PUBLISH_ATTEMPTED": "publish_move_attempted",
        "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS":
            "staging_ownership_ambiguous",
        "FIXTURE_PUBLISH_SETTLED": "retained",
        "STAGING_REMOVE_ATTEMPTED": "staging_cleanup_attempted",
        "STAGING_REMOVE_SETTLED": "staging_resolved_absent",
        "QUARANTINE_MOVE_ATTEMPTED": "quarantine_move_attempted",
        "QUARANTINE_MOVE_SETTLED": "quarantine_retained",
        "QUARANTINE_REMOVE_ATTEMPTED": "quarantine_remove_attempted",
        "QUARANTINE_REMOVE_SETTLED": "quarantine_resolved_absent",
    }.get(event)
    if required_state is not None and not obligation[required_state]:
        _fail("mutation journal event is not reflected in its snapshot: " + event)
    if event == "FIXTURE_PUBLISH_UNSETTLED" and not (
            obligation["publish_move_attempted"] and
            obligation["publish_move_postcondition"] is not None):
        _fail("mutation journal unsettled publication snapshot differs")
    if event == "QUARANTINE_MOVE_UNSETTLED" and not (
            obligation["quarantine_move_attempted"] and
            obligation["quarantine_move_postcondition"] is not None):
        _fail("mutation journal unsettled quarantine snapshot differs")
    retained_field = {
        "FIXTURE_COPY_SETTLED": "staging_retained",
        "FIXTURE_PUBLISH_SETTLED": "retained",
        "STAGING_REMOVE_ATTEMPTED": "staging_retained",
        "QUARANTINE_MOVE_ATTEMPTED": "retained",
        "QUARANTINE_MOVE_SETTLED": "quarantine_retained",
        "QUARANTINE_REMOVE_ATTEMPTED": "quarantine_retained",
    }.get(event)
    if (retained_field is not None and
            details["retained"] != obligation[retained_field]):
        _fail("mutation journal retained event evidence differs: " + event)
    evidence_fields = {
        "FIXTURE_PUBLISH_SETTLED": (
            "publish_move_reply_proved", "publish_move_transport_error"),
        "STAGING_REMOVE_SETTLED": (
            "staging_cleanup_reply_proved",
            "staging_cleanup_transport_error"),
        "QUARANTINE_MOVE_SETTLED": (
            "quarantine_move_reply_proved",
            "quarantine_move_transport_error"),
        "QUARANTINE_REMOVE_SETTLED": (
            "quarantine_remove_reply_proved",
            "quarantine_remove_transport_error"),
    }.get(event)
    if evidence_fields is not None:
        reply_field, error_field = evidence_fields
        is_move = event in {
            "FIXTURE_PUBLISH_SETTLED", "QUARANTINE_MOVE_SETTLED"}
        reply_key = "moveReplyProved" if is_move else "removeReplyProved"
        error_key = "moveTransportError" if is_move else "removeTransportError"
        if (details[reply_key] != obligation[reply_field] or
                details[error_key] != obligation[error_field]):
            _fail("mutation journal settlement evidence differs: " + event)
        _validate_reply_error_pair(
            obligation[reply_field], obligation[error_field], event)
    if event in {
            "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS",
            "FIXTURE_PUBLISH_UNSETTLED"}:
        _validate_reply_error_pair(
            obligation["publish_move_reply_proved"],
            obligation["publish_move_transport_error"], event)
    if event == "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS":
        if (obligation["publish_move_postcondition"] is not None or
                obligation["publish_move_source_observed"] is not None or
                obligation["publish_move_target_observed"] is not None):
            _fail("mutation journal ambiguous publication carries observations")
    elif event == "FIXTURE_PUBLISH_UNSETTLED":
        postcondition = _journal_presence_postcondition(
            obligation["publish_move_source_observed"],
            obligation["publish_move_target_observed"], publish=True)
        exact = (
            obligation["publish_move_source_observed"] is None and
            _journal_same_renamed_object(
                obligation["staging_retained"],
                obligation["publish_move_target_observed"]))
        if (details["postcondition"] !=
                obligation["publish_move_postcondition"] or
                obligation["publish_move_postcondition"] != postcondition or
                exact or details["postcondition"] ==
                "stage-absent/target-exact"):
            _fail("mutation journal unsettled publication outcome differs")
    if event == "QUARANTINE_MOVE_UNSETTLED":
        _validate_reply_error_pair(
            obligation["quarantine_move_reply_proved"],
            obligation["quarantine_move_transport_error"], event)
        postcondition = _journal_presence_postcondition(
            obligation["quarantine_move_source_observed"],
            obligation["quarantine_move_destination_observed"],
            publish=False)
        exact = (
            obligation["quarantine_move_source_observed"] is None and
            _journal_same_renamed_object(
                obligation["retained"],
                obligation["quarantine_move_destination_observed"]))
        if (details["postcondition"] !=
                obligation["quarantine_move_postcondition"] or
                obligation["quarantine_move_postcondition"] != postcondition or
                exact or details["postcondition"] ==
                "source-absent/destination-exact"):
            _fail("mutation journal unsettled quarantine outcome differs")
    if event == "FIXTURE_COPY_SETTLED":
        if (not obligation["copy_attempted"] or
                obligation["copy_reply_proved"] is not True or
                obligation["staging_post_copy_observed"] !=
                obligation["staging_retained"] or
                obligation["staging_retained"] is None):
            _fail("mutation journal copy settlement snapshot differs")
    elif event == "FIXTURE_PUBLISH_SETTLED":
        if (obligation["publish_move_postcondition"] !=
                "stage-absent/target-exact" or
                obligation["publish_move_source_observed"] is not None or
                obligation["publish_move_target_observed"] !=
                obligation["retained"] or
                obligation["retained"] is None or
                obligation["ownership_ambiguous"] or
                obligation["staging_ownership_ambiguous"]):
            _fail("mutation journal publication settlement snapshot differs")
    elif event == "STAGING_REMOVE_SETTLED":
        if (obligation["staging_cleanup_pre_observed"] !=
                obligation["staging_retained"] or
                obligation["staging_cleanup_post_observed"] is not None or
                obligation["staging_cleanup_absence_observations"] != 2 or
                not obligation["staging_resolved_absent"]):
            _fail("mutation journal staging removal settlement differs")
    elif event == "QUARANTINE_MOVE_SETTLED":
        if (obligation["quarantine_move_postcondition"] !=
                "source-absent/destination-exact" or
                obligation["quarantine_move_source_observed"] is not None or
                obligation["quarantine_move_destination_observed"] !=
                obligation["quarantine_retained"] or
                obligation["quarantine_retained"] is None):
            _fail("mutation journal quarantine move settlement differs")
    elif event == "QUARANTINE_REMOVE_SETTLED":
        if (obligation["quarantine_remove_precondition"] !=
                "source-absent/destination-exact" or
                obligation["quarantine_remove_source_observed"] is not None or
                obligation["quarantine_remove_pre_observed"] !=
                obligation["quarantine_retained"] or
                obligation["quarantine_remove_postcondition"] !=
                "destination-absent" or
                obligation["quarantine_remove_post_observed"] is not None or
                obligation["quarantine_remove_absence_observations"] != 2 or
                not obligation["quarantine_resolved_absent"]):
            _fail("mutation journal quarantine removal settlement differs")
    return target


def _validate_journal_monotonic(
        previous: dict[str, Any], current: dict[str, Any]) -> None:
    if previous["sourceAuthorities"] != current["sourceAuthorities"]:
        _fail("mutation journal source authority changed")
    for field in ("reached", "copyAttempted", "copyReplyProved", "settled"):
        if (previous["parkingProvisioning"][field] and
                not current["parkingProvisioning"][field]):
            _fail("mutation journal parking state moved backward")
    for target in (TARGET_PDF, TARGET_MARK):
        before = previous["obligations"][target]
        after = current["obligations"][target]
        for field in ("source", "target", "expected_sha256", "staging_path",
                      "quarantine_path"):
            if before[field] != after[field]:
                _fail("mutation journal capability changed: " + field)
        for field, old in before.items():
            new = after[field]
            if type(old) is bool and old and not new:
                _fail("mutation journal boolean moved backward: " + field)
            if (field.endswith("_observations") and
                    (type(new) is not int or new < old)):
                _fail("mutation journal observation count moved backward")
            if (old is not None and type(old) not in (bool, int) and
                    new != old and field != "retained"):
                _fail("mutation journal evidence changed after retention: " + field)
        if before["retained"] is not None and after["retained"] != before["retained"]:
            if not (
                    target == TARGET_MARK and
                    not before["parking_recreated_or_replaced"] and
                    after["parking_recreated_or_replaced"] and
                    after["pre_parking_retained"] == before["retained"] and
                    after["retained"] is not None):
                _fail("mutation journal retained target changed")


def _validate_journal_operation_delta(
        previous: dict[str, Any], current: dict[str, Any],
        event: str, target: str | None) -> None:
    """Bind each dispatch/settlement event to its exact target-state delta."""
    for member in (TARGET_PDF, TARGET_MARK):
        if member == target:
            continue
        before_member = previous["obligations"][member]
        after_member = current["obligations"][member]
        changed_member = {
            field for field in before_member
            if before_member[field] != after_member[field]
        }
        allowed_member: set[str] = set()
        if event == "FIXTURE_COPY_ATTEMPTED":
            # Both random staging names are proved absent before the first copy
            # dispatch, so the first target's intent may publish both digests.
            allowed_member = {
                "pre_copy_absence_sha256", "staging_pre_absence_sha256"}
        elif (event == "STAGING_REMOVE_ATTEMPTED" and
              target == TARGET_PDF and member == TARGET_MARK):
            # MARK is visited first.  Its already-absent staging capability may
            # be settled by two observations without a removal attempt/event.
            allowed_member = {
                "staging_cleanup_absence_observations",
                "staging_resolved_absent",
            }
        elif event == "QUARANTINE_MOVE_ATTEMPTED":
            # Staging double-absence and both quarantine preproofs are batched
            # before the first target rename is dispatched.
            allowed_member = {
                "staging_cleanup_absence_observations",
                "staging_resolved_absent",
                "quarantine_pre_absence_sha256",
            }
            if target == TARGET_PDF and member == TARGET_MARK:
                # MARK is visited first and may have been absent twice without
                # any quarantine mutation/event.
                allowed_member.add("quarantine_resolved_absent")
        elif event == "DEVICE_MUTATIONS_SETTLED":
            # A genuinely absent staging/target name has no mutation event.
            # Its two-observation evidence first becomes durable at this final
            # settlement; attempts still require their explicit terminals.
            allowed_member = {
                "staging_cleanup_absence_observations",
                "staging_resolved_absent",
                "quarantine_pre_absence_sha256",
                "quarantine_resolved_absent", "resolved_absent",
            }
        if not changed_member <= allowed_member:
            _fail(
                "mutation journal event carries cross-target state: " + event)
        if changed_member & {
                "staging_cleanup_absence_observations",
                "staging_resolved_absent"}:
            if (after_member["staging_cleanup_attempted"] or
                    after_member["staging_cleanup_absence_observations"] != 2 or
                    not after_member["staging_resolved_absent"]):
                _fail("mutation journal batched staging absence differs")
        if "quarantine_pre_absence_sha256" in changed_member and (
                after_member["quarantine_pre_absence_sha256"] is None):
            _fail("mutation journal batched quarantine preproof differs")
        if "quarantine_resolved_absent" in changed_member and (
                after_member["quarantine_move_attempted"] or
                after_member["quarantine_remove_attempted"] or
                not after_member["quarantine_resolved_absent"]):
            _fail("mutation journal batched quarantine absence differs")
        if "resolved_absent" in changed_member and not after_member[
                "resolved_absent"]:
            _fail("mutation journal final target absence differs")

    if event == "FIXTURE_STAGED":
        for member in (TARGET_PDF, TARGET_MARK):
            obligation = current["obligations"][member]
            expected = _journal_initial_obligation(obligation)
            for field in (
                    "pre_copy_absence_sha256",
                    "staging_pre_absence_sha256",
                    "staging_post_copy_observed", "staging_retained",
                    "publish_move_reply_proved",
                    "publish_move_transport_error",
                    "publish_move_postcondition",
                    "publish_move_source_observed",
                    "publish_move_target_observed", "retained"):
                expected[field] = obligation[field]
            expected.update({
                "copy_attempted": True,
                "copy_reply_proved": True,
                "publish_move_attempted": True,
            })
            if (obligation["pre_copy_absence_sha256"] is None or
                    obligation["staging_pre_absence_sha256"] is None or
                    obligation["staging_post_copy_observed"] !=
                    obligation["staging_retained"] or
                    obligation["staging_retained"] is None or
                    obligation["publish_move_postcondition"] !=
                    "stage-absent/target-exact" or
                    obligation["publish_move_source_observed"] is not None or
                    obligation["publish_move_target_observed"] !=
                    obligation["retained"] or
                    obligation["retained"] is None or
                    obligation != expected):
                _fail("mutation journal staged checkpoint state differs")
            _validate_reply_error_pair(
                obligation["publish_move_reply_proved"],
                obligation["publish_move_transport_error"],
                "FIXTURE_STAGED")
        return
    if target is None:
        return
    before = previous["obligations"][target]
    after = current["obligations"][target]
    allowed_changes: dict[str, set[str]] = {
        "FIXTURE_COPY_ATTEMPTED": {
            "pre_copy_absence_sha256", "staging_pre_absence_sha256",
            "copy_attempted",
        },
        "FIXTURE_COPY_SETTLED": {
            "copy_reply_proved", "staging_post_copy_observed",
            "staging_retained",
        },
        "FIXTURE_PUBLISH_ATTEMPTED": {"publish_move_attempted"},
        "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS": {
            "publish_move_reply_proved", "publish_move_transport_error",
            "staging_ownership_ambiguous", "ownership_ambiguous",
        },
        "FIXTURE_PUBLISH_SETTLED": {
            "publish_move_reply_proved", "publish_move_transport_error",
            "publish_move_postcondition", "publish_move_source_observed",
            "publish_move_target_observed", "retained",
        },
        "FIXTURE_PUBLISH_UNSETTLED": {
            "publish_move_reply_proved", "publish_move_transport_error",
            "publish_move_postcondition", "publish_move_source_observed",
            "publish_move_target_observed", "staging_ownership_ambiguous",
            "ownership_ambiguous",
        },
        "STAGING_REMOVE_ATTEMPTED": {
            "staging_cleanup_attempted", "staging_cleanup_pre_observed",
            "ownership_ambiguous",
        },
        "STAGING_REMOVE_SETTLED": {
            "staging_cleanup_reply_proved",
            "staging_cleanup_transport_error",
            "staging_cleanup_post_observed",
            "staging_cleanup_absence_observations",
            "staging_resolved_absent",
        },
        "QUARANTINE_MOVE_ATTEMPTED": {
            "staging_cleanup_absence_observations",
            "staging_resolved_absent",
            "quarantine_pre_absence_sha256", "quarantine_move_attempted",
            "retained", "parking_recreated_or_replaced",
            "parking_absent_before_switch", "pre_parking_retained",
        },
        "QUARANTINE_MOVE_SETTLED": {
            "quarantine_move_reply_proved",
            "quarantine_move_transport_error",
            "quarantine_move_postcondition",
            "quarantine_move_source_observed",
            "quarantine_move_destination_observed",
            "quarantine_retained",
        },
        "QUARANTINE_MOVE_UNSETTLED": {
            "quarantine_move_reply_proved",
            "quarantine_move_transport_error",
            "quarantine_move_postcondition",
            "quarantine_move_source_observed",
            "quarantine_move_destination_observed",
        },
        "QUARANTINE_REMOVE_ATTEMPTED": {
            "quarantine_remove_attempted",
            "quarantine_remove_precondition",
            "quarantine_remove_source_observed",
            "quarantine_remove_pre_observed",
        },
        "QUARANTINE_REMOVE_SETTLED": {
            "quarantine_remove_reply_proved",
            "quarantine_remove_transport_error",
            "quarantine_remove_postcondition",
            "quarantine_remove_post_observed",
            "quarantine_remove_absence_observations",
            "quarantine_resolved_absent",
        },
    }
    allowed = allowed_changes.get(event)
    if allowed is None:
        return
    changed = {
        field for field in before
        if before[field] != after[field]
    }
    if not changed <= allowed:
        _fail("mutation journal event carries out-of-phase target state: " + event)

    if event == "FIXTURE_COPY_ATTEMPTED":
        expected = _journal_initial_obligation(after)
        for field in ("pre_copy_absence_sha256",
                      "staging_pre_absence_sha256"):
            if after[field] is None:
                _fail("mutation journal copy intent lacks absence authority")
            expected[field] = after[field]
        expected["copy_attempted"] = True
        if before["copy_attempted"] or after != expected:
            _fail("mutation journal copy intent snapshot differs")
    elif event == "FIXTURE_PUBLISH_ATTEMPTED":
        expected = _journal_initial_obligation(after)
        for field in (
                "pre_copy_absence_sha256", "staging_pre_absence_sha256",
                "staging_post_copy_observed", "staging_retained"):
            expected[field] = after[field]
        expected.update({
            "copy_attempted": True,
            "copy_reply_proved": True,
            "publish_move_attempted": True,
        })
        if (before["publish_move_attempted"] or
                after["staging_retained"] is None or
                after["staging_post_copy_observed"] !=
                after["staging_retained"] or after != expected):
            _fail("mutation journal publish intent snapshot differs")
    elif event == "STAGING_REMOVE_ATTEMPTED":
        if (before["staging_cleanup_attempted"] or
                after["staging_cleanup_pre_observed"] !=
                after["staging_retained"] or
                after["staging_retained"] is None or
                not after["staging_cleanup_attempted"] or
                after["staging_cleanup_reply_proved"] or
                after["staging_cleanup_transport_error"] is not None or
                after["staging_cleanup_post_observed"] is not None or
                after["staging_cleanup_absence_observations"] != 0 or
                after["staging_resolved_absent"]):
            _fail("mutation journal staging-removal intent snapshot differs")
    elif event == "QUARANTINE_MOVE_ATTEMPTED":
        if (before["quarantine_move_attempted"] or
                after["staging_cleanup_absence_observations"] != 2 or
                not after["staging_resolved_absent"] or
                after["quarantine_pre_absence_sha256"] is None or
                not after["quarantine_move_attempted"] or
                after["quarantine_move_reply_proved"] or
                after["quarantine_move_transport_error"] is not None or
                after["quarantine_move_postcondition"] is not None or
                after["quarantine_move_source_observed"] is not None or
                after["quarantine_move_destination_observed"] is not None or
                after["quarantine_retained"] is not None or
                after["quarantine_remove_attempted"] or
                after["quarantine_remove_reply_proved"] or
                after["quarantine_remove_transport_error"] is not None or
                after["quarantine_remove_precondition"] is not None or
                after["quarantine_remove_source_observed"] is not None or
                after["quarantine_remove_pre_observed"] is not None or
                after["quarantine_remove_postcondition"] is not None or
                after["quarantine_remove_post_observed"] is not None or
                after["quarantine_remove_absence_observations"] != 0 or
                after["quarantine_resolved_absent"]):
            _fail("mutation journal quarantine-move intent snapshot differs")
    elif event == "QUARANTINE_REMOVE_ATTEMPTED":
        if (before["quarantine_remove_attempted"] or
                not after["quarantine_remove_attempted"] or
                after["quarantine_remove_precondition"] !=
                "source-absent/destination-exact" or
                after["quarantine_remove_source_observed"] is not None or
                after["quarantine_remove_pre_observed"] !=
                after["quarantine_retained"] or
                after["quarantine_retained"] is None or
                after["quarantine_remove_reply_proved"] or
                after["quarantine_remove_transport_error"] is not None or
                after["quarantine_remove_postcondition"] is not None or
                after["quarantine_remove_post_observed"] is not None or
                after["quarantine_remove_absence_observations"] != 0 or
                after["quarantine_resolved_absent"]):
            _fail("mutation journal quarantine-removal intent snapshot differs")


def _validate_journal_event_order(
        event: str, target: str | None, seen: dict[str, set[str]],
        parking: dict[str, Any]) -> None:
    if seen["final"]:
        _fail("mutation journal contains records after final settlement")
    if event == "MANIFEST_CREATED":
        if seen["manifest"]:
            _fail("mutation journal repeats its manifest")
        seen["manifest"].add(event)
        return
    if event.startswith("PARKING_"):
        if event in seen["parking"]:
            _fail("mutation journal repeats a parking transition")
        if (event == "PARKING_COPY_ATTEMPTED" and
                "PARKING_PROVISIONING_REACHED" not in seen["parking"] or
                event == "PARKING_PROVISIONING_SETTLED" and
                "PARKING_PROVISIONING_REACHED" not in seen["parking"] or
                event == "PARKING_PROVISIONING_SETTLED" and
                parking["copyAttempted"] and
                "PARKING_COPY_ATTEMPTED" not in seen["parking"]):
            _fail("mutation journal parking order differs")
        expected_state = {
            "PARKING_PROVISIONING_REACHED": "reached",
            "PARKING_COPY_ATTEMPTED": "copyAttempted",
            "PARKING_PROVISIONING_SETTLED": "settled",
        }[event]
        if not parking[expected_state]:
            _fail("mutation journal parking event is absent from its snapshot")
        if (event == "PARKING_PROVISIONING_REACHED" and parking != {
                "reached": True, "copyAttempted": False,
                "copyReplyProved": False, "settled": False} or
                event == "PARKING_COPY_ATTEMPTED" and parking != {
                    "reached": True, "copyAttempted": True,
                    "copyReplyProved": False, "settled": False} or
                event == "PARKING_PROVISIONING_SETTLED" and
                (not parking["reached"] or not parking["settled"] or
                 parking["copyReplyProved"] and
                 not parking["copyAttempted"])):
            _fail("mutation journal parking transition snapshot differs")
        seen["parking"].add(event)
        return
    if event == "FIXTURE_STAGED":
        if (seen["fixture_staged"] or
                seen["publish_settled"] != {TARGET_PDF, TARGET_MARK}):
            _fail("mutation journal staged summary order differs")
        seen["fixture_staged"].add(event)
        return
    if event == "DEVICE_MUTATIONS_SETTLED":
        if seen["final"] or not parking["settled"]:
            _fail("mutation journal final settlement order differs")
        for member in (TARGET_PDF, TARGET_MARK):
            events = seen["target_events"]
            required = (
                ("FIXTURE_COPY_ATTEMPTED", "FIXTURE_COPY_SETTLED"),
                ("STAGING_REMOVE_ATTEMPTED", "STAGING_REMOVE_SETTLED"),
                ("QUARANTINE_MOVE_ATTEMPTED", "QUARANTINE_MOVE_SETTLED"),
                ("QUARANTINE_REMOVE_ATTEMPTED",
                 "QUARANTINE_REMOVE_SETTLED"),
            )
            for attempted, settled in required:
                if (attempted + "\x00" + member in events and
                        settled + "\x00" + member not in events):
                    _fail(
                        "mutation journal final settlement omits an attempted "
                        "operation terminal: " + attempted)
            if ("FIXTURE_PUBLISH_ATTEMPTED\x00" + member in events and
                    member not in seen["publish_terminal"]):
                _fail(
                    "mutation journal final settlement omits a publication "
                    "terminal")
        seen["final"].add(event)
        return
    if target is None:
        _fail("mutation journal transition lacks a target")
    key = event + "\x00" + target
    if key in seen["target_events"]:
        _fail("mutation journal repeats a target transition")
    if (event == "FIXTURE_COPY_ATTEMPTED" and not parking["settled"] or
            event == "FIXTURE_COPY_SETTLED" and
            "FIXTURE_COPY_ATTEMPTED\x00" + target not in seen["target_events"] or
            event == "FIXTURE_PUBLISH_ATTEMPTED" and
            "FIXTURE_COPY_SETTLED\x00" + target not in seen["target_events"] or
            event.startswith("FIXTURE_PUBLISH_") and
            event != "FIXTURE_PUBLISH_ATTEMPTED" and
            "FIXTURE_PUBLISH_ATTEMPTED\x00" + target not in seen["target_events"] or
            event == "STAGING_REMOVE_ATTEMPTED" and
            "FIXTURE_COPY_SETTLED\x00" + target not in seen["target_events"] or
            event == "STAGING_REMOVE_SETTLED" and
            "STAGING_REMOVE_ATTEMPTED\x00" + target not in seen["target_events"] or
            event == "QUARANTINE_MOVE_ATTEMPTED" and
            "FIXTURE_PUBLISH_SETTLED\x00" + target not in seen["target_events"] or
            event.startswith("QUARANTINE_MOVE_") and
            event != "QUARANTINE_MOVE_ATTEMPTED" and
            "QUARANTINE_MOVE_ATTEMPTED\x00" + target not in seen["target_events"] or
            event == "QUARANTINE_REMOVE_ATTEMPTED" and
            "QUARANTINE_MOVE_SETTLED\x00" + target not in seen["target_events"] or
            event == "QUARANTINE_REMOVE_SETTLED" and
            "QUARANTINE_REMOVE_ATTEMPTED\x00" + target not in seen["target_events"]):
        _fail("mutation journal target transition order differs: " + event)
    if event in {
            "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS",
            "FIXTURE_PUBLISH_SETTLED", "FIXTURE_PUBLISH_UNSETTLED"}:
        if target in seen["publish_terminal"]:
            _fail("mutation journal repeats a publication terminal state")
        seen["publish_terminal"].add(target)
    if event in {"QUARANTINE_MOVE_SETTLED", "QUARANTINE_MOVE_UNSETTLED"}:
        if target in seen["quarantine_terminal"]:
            _fail("mutation journal repeats a quarantine terminal state")
        seen["quarantine_terminal"].add(target)
    if event == "FIXTURE_PUBLISH_SETTLED":
        seen["publish_settled"].add(target)
    seen["target_events"].add(key)


@dataclass(frozen=True)
class HostStatus:
    session: str
    generation: int
    display_id: int
    state: str
    text: str

    def validate(self) -> None:
        _canonical_uuid(self.session, "host session")
        _positive(self.generation, "host generation", 2**63 - 1)
        _positive(self.display_id, "host display", 1024)
        if (type(self.state) is not str or
                self.state not in {
                    "DISPLAY_ALLOCATED", "WAITING_FOR_FOREIGN_ATTACH", "ACTIVE",
                    "PLACEMENT_PENDING", "WAITING_FOR_FOREIGN_DESTROY",
                    "RELEASE_AUTHORIZED", "FAILED", "RELEASED",
                }):
            _fail("host state is outside the known lifecycle")

    @property
    def display_name(self) -> str:
        self.validate()
        return f"NativePageVisualOnly-{self.session}-{self.generation}"


@dataclass(frozen=True)
class Screenshot:
    name: str
    width: int
    height: int
    size: int
    sha256: str


@dataclass(frozen=True)
class HostArtifact:
    signed_apk_sha256: str
    signer_certificate_sha256: str
    unsigned_apk_sha256: str
    unsigned_authority_sha256: str
    dex_sha256: str
    source: str

    def validate(self) -> None:
        expected = (
            ALPHA_SIGNED_APK_SHA256, ALPHA_SIGNER_CERT_SHA256,
            REVIEWED_UNSIGNED_APK_SHA256,
            REVIEWED_UNSIGNED_AUTHORITY_SHA256, ALPHA_DEX_SHA256,
            "independent-fixed-alpha-pins",
        )
        if (self.signed_apk_sha256, self.signer_certificate_sha256,
                self.unsigned_apk_sha256, self.unsigned_authority_sha256,
                self.dex_sha256, self.source) != expected:
            _fail("host artifact differs from the independent fixed alpha pins")


def _fixed_host_artifact() -> HostArtifact:
    result = HostArtifact(
        ALPHA_SIGNED_APK_SHA256, ALPHA_SIGNER_CERT_SHA256,
        REVIEWED_UNSIGNED_APK_SHA256, REVIEWED_UNSIGNED_AUTHORITY_SHA256,
        ALPHA_DEX_SHA256, "independent-fixed-alpha-pins",
    )
    result.validate()
    return result


def _apk_classes_dex_sha256(apk_raw: bytes) -> str:
    if type(apk_raw) is not bytes or not 0 < len(apk_raw) <= 64 * 1024 * 1024:
        _fail("signed alpha APK bytes are absent or oversized")
    try:
        with zipfile.ZipFile(io.BytesIO(apk_raw), "r") as archive:
            matches = [
                value for value in archive.infolist()
                if re.fullmatch(
                    r"classes(?:[1-9][0-9]*)?\.dex",
                    value.filename.replace("\\", "/").rsplit("/", 1)[-1])
            ]
            if (len(matches) != 1 or matches[0].filename != "classes.dex"):
                _fail("signed alpha APK does not contain only one exact classes.dex")
            info = matches[0]
            if (info.flag_bits & 0x1 or not 0 < info.file_size <= 32 * 1024 * 1024 or
                    not 0 < info.compress_size <= 32 * 1024 * 1024):
                _fail("signed alpha classes.dex framing is outside the fixed bounds")
            with archive.open(info, "r") as stream:
                dex = stream.read(32 * 1024 * 1024 + 1)
            if len(dex) != info.file_size:
                _fail("signed alpha classes.dex size differs from its ZIP authority")
    except (OSError, EOFError, zipfile.BadZipFile, RuntimeError) as error:
        raise AlphaError("signed alpha APK/DEX ZIP validation failed") from error
    return _sha(dex)


def load_host_artifact(metadata_path: Path) -> HostArtifact:
    """Require metadata and APK bytes to match independent fixed alpha pins."""
    path = metadata_path.expanduser().resolve(strict=True)
    if not path.is_file() or path.name != "native-page-host-alpha.json":
        _fail("alpha host metadata must be native-page-host-alpha.json")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise AlphaError("cannot read alpha host metadata") from error
    if not 0 < len(raw) <= 16_384 or b"\x00" in raw:
        _fail("alpha host metadata is absent or oversized")
    try:
        value = json.loads(raw.decode("utf-8", "strict"),
                           object_pairs_hook=_unique_json_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AlphaError("alpha host metadata is not strict JSON") from error
    expected = {
        "schema", "package", "versionCode", "versionName", "signedApkPath",
        "signedApkSha256", "signerCertSha256", "reviewedUnsignedApkSha256",
        "reviewedUnsignedAuthoritySha256", "dexSha256", "checkpoint",
        "diagnosticOnly",
        "reproducibleUnsignedAuthorityPreserved", "formalReleaseArtifact",
    }
    if type(value) is not dict or set(value) != expected:
        _fail("alpha host metadata topology differs")
    if (value["schema"] != "native-page-host-local-alpha-apk-v1" or
            value["package"] != HOST_PACKAGE or
            type(value["versionCode"]) is not int or
            value["versionCode"] != ALPHA_HOST_VERSION_CODE or
            value["versionName"] != ALPHA_HOST_VERSION_NAME or
            value["signedApkPath"] != "native-page-host-alpha.apk" or
            value["signedApkSha256"] != ALPHA_SIGNED_APK_SHA256 or
            value["signerCertSha256"] != ALPHA_SIGNER_CERT_SHA256 or
            value["reviewedUnsignedApkSha256"] !=
            REVIEWED_UNSIGNED_APK_SHA256 or
            value["reviewedUnsignedAuthoritySha256"] !=
            REVIEWED_UNSIGNED_AUTHORITY_SHA256 or
            value["dexSha256"] != ALPHA_DEX_SHA256 or
            value["checkpoint"] != CHECKPOINT or
            value["diagnosticOnly"] is not True or
            value["reproducibleUnsignedAuthorityPreserved"] is not True or
            value["formalReleaseArtifact"] is not False):
        _fail("alpha host metadata policy/package/version differs")
    apk = path.with_name("native-page-host-alpha.apk")
    if (not apk.is_file() or apk.is_symlink() or
            not 0 < apk.stat().st_size <= 64 * 1024 * 1024):
        _fail("signed alpha APK is absent or is a link")
    apk_raw = apk.read_bytes()
    if _sha(apk_raw) != ALPHA_SIGNED_APK_SHA256:
        _fail("signed alpha APK bytes differ from the independent fixed pin")
    if _apk_classes_dex_sha256(apk_raw) != ALPHA_DEX_SHA256:
        _fail("signed alpha embedded classes.dex differs from the fixed pin")
    result = _fixed_host_artifact()
    return result


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlphaError("alpha host metadata contains duplicate keys")
        result[key] = value
    return result


class AdbNomad:
    """The concrete fixed-operation transport for this disposable alpha."""

    def __init__(self, adb: Path, serial: str, *,
                 executor: Executor = subprocess.run):
        if serial != AUTHORIZED_SERIAL:
            _fail("standalone runner serial is not the authorized Nomad")
        resolved = adb.expanduser().resolve(strict=True)
        if not resolved.is_file() or resolved.name.lower() != "adb.exe":
            _fail("--adb must identify an existing adb.exe")
        self.adb = str(resolved)
        self._executor = executor
        self.history: list[dict[str, Any]] = []

    def _invoke(self, operation: str, tail: Sequence[str], *,
                timeout: float = STEP_TIMEOUT_SECONDS,
                maximum: int = MAX_TEXT_BYTES) -> CommandResult:
        argv = _safe_argv((self.adb, "-s", AUTHORIZED_SERIAL, *tail))
        started = time.monotonic_ns()
        try:
            completed = self._executor(
                argv, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            self.history.append({
                "operation": operation, "argv": list(argv),
                "startedNs": str(started), "finishedNs": str(time.monotonic_ns()),
                "returncode": None, "timeout": True,
            })
            raise AlphaError(operation + " timed out; side effect is uncertain") from error
        stdout = bytes(completed.stdout or b"")
        stderr = bytes(completed.stderr or b"")
        if len(stdout) > maximum or len(stderr) > MAX_TEXT_BYTES:
            _fail(operation + " returned oversized output")
        result = CommandResult(
            operation, argv, int(completed.returncode), stdout, stderr)
        self.history.append({
            "operation": operation, "argv": list(argv),
            "startedNs": str(started), "finishedNs": str(time.monotonic_ns()),
            "returncode": result.returncode,
            "stdoutSha256": _sha(stdout), "stderrSha256": _sha(stderr),
        })
        return result

    @staticmethod
    def _require_zero(result: CommandResult) -> bytes:
        if result.returncode != 0:
            detail = _decode_text(
                (result.stdout + b"\n" + result.stderr)[:MAX_TEXT_BYTES],
                result.operation,
            ).strip()
            raise AlphaError(
                f"{result.operation} failed ({result.returncode}): {detail[:500]}")
        return result.stdout

    def text(self, operation: str, tail: Sequence[str], *,
             timeout: float = STEP_TIMEOUT_SECONDS) -> str:
        raw = self._require_zero(self._invoke(operation, tail, timeout=timeout))
        return _decode_text(raw, operation)

    def get_state(self) -> str:
        return self.text("get_state", ("get-state",)).strip()

    def get_serial(self) -> str:
        return self.text("get_serial", ("get-serialno",)).strip()

    def getprop(self, name: str) -> str:
        if name not in {
                "ro.product.model", "ro.build.version.sdk", "ro.build.fingerprint"}:
            _fail("getprop key is outside the fixed preflight set")
        return self.text("getprop_" + name.rsplit(".", 1)[-1],
                         ("shell", "getprop", name)).strip()

    def current_user(self) -> str:
        return self.text(
            "current_user", ("shell", "am", "get-current-user")).strip()

    def package_dump(self, package: str) -> str:
        if package not in {HOST_PACKAGE, DOCUMENT_PACKAGE}:
            _fail("package dump escaped the exact alpha package set")
        return self.text(
            "package_" + package, ("shell", "dumpsys", "package", package))

    def package_path(self, package: str) -> str:
        if package not in {HOST_PACKAGE, DOCUMENT_PACKAGE}:
            _fail("package path escaped the exact alpha package set")
        output = self.text(
            "package_path_" + package, ("shell", "pm", "path", package))
        rows = [line for line in output.splitlines() if line]
        if len(rows) != 1 or not rows[0].startswith("package:"):
            _fail(package + " does not have one exact base APK")
        path = rows[0][len("package:"):]
        if SAFE_APK.fullmatch(path) is None or ".." in path:
            _fail(package + " returned an unsafe APK path")
        return path

    def activities(self) -> bytes:
        result = self._invoke(
            "activities", ("shell", "dumpsys", "activity", "activities"))
        return self._require_zero(result)

    def windows(self) -> bytes:
        result = self._invoke(
            "windows", ("shell", "dumpsys", "window", "windows"))
        return self._require_zero(result)

    def window_displays(self) -> bytes:
        result = self._invoke(
            "window_displays", ("shell", "dumpsys", "window", "displays"))
        return self._require_zero(result)

    def displays(self) -> bytes:
        result = self._invoke("displays", ("shell", "dumpsys", "display"))
        return self._require_zero(result)

    def pidof(self, package: str) -> tuple[int, ...]:
        if package not in {HOST_PACKAGE, DOCUMENT_PACKAGE}:
            _fail("pid lookup escaped the exact alpha package set")
        result = self._invoke("pidof_" + package, ("shell", "pidof", package))
        if result.returncode not in (0, 1):
            self._require_zero(result)
        output = _decode_text(result.stdout, result.operation).strip()
        if not output:
            return ()
        values: list[int] = []
        for item in output.split():
            if re.fullmatch(r"[1-9][0-9]{0,6}", item) is None:
                _fail("pidof returned a malformed PID")
            values.append(_positive(int(item), "process PID", android.MAX_PID))
        if len(values) != len(set(values)):
            _fail("pidof returned duplicate PIDs")
        return tuple(sorted(values))

    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity:
        _positive(pid, "process PID", android.MAX_PID)
        if package not in {HOST_PACKAGE, DOCUMENT_PACKAGE}:
            _fail("process lookup escaped the exact alpha package set")
        stat_raw = self._root_proc_file(pid, "stat")
        status_raw = self._root_proc_file(pid, "status")
        cmdline_raw = self._root_proc_file(pid, "cmdline")
        stat = _decode_text(stat_raw, "proc_stat").strip()
        close = stat.rfind(")")
        if (close < 3 or not stat.startswith(str(pid) + " (") or
                len(stat[close + 2:].split()) < 20):
            _fail("/proc stat framing differs")
        tail = stat[close + 2:].split()
        start_text = tail[19]
        if re.fullmatch(r"[1-9][0-9]{0,31}", start_text) is None:
            _fail("/proc start ticks are not canonical")
        status = _decode_text(status_raw, "proc_status")
        matches = re.findall(
            r"^Uid:\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$",
            status, re.MULTILINE)
        if len(matches) != 1 or len(set(matches[0])) != 1:
            _fail("/proc UID identity is absent or ambiguous")
        uid = int(matches[0][0])
        expected_uid = 1000 if package == DOCUMENT_PACKAGE else None
        if expected_uid is not None and uid != expected_uid:
            _fail("stock Document process UID differs")
        parts = cmdline_raw.split(b"\x00")
        if (len(parts) < 2 or parts[-1] != b"" or
                parts[0] != package.encode("ascii") or any(parts[1:-1])):
            _fail("/proc cmdline differs from the exact package process")
        return host.ProcessIdentity(pid, int(start_text), uid, package)

    def _root_proc_file(self, pid: int, name: str) -> bytes:
        _positive(pid, "process PID", android.MAX_PID)
        if name not in {"stat", "status", "cmdline"}:
            _fail("root process read escaped the exact file set")
        # Magisk on the pinned Nomad treats `su 0 cat ...` as a root shell with
        # positional arguments and returns no file content. Its documented
        # command form is `su -c <one command>`. The command is generated solely
        # from a validated positive PID and this closed filename set.
        command = f"cat /proc/{pid}/{name}"
        return self._require_zero(self._invoke(
            "proc_" + name, ("shell", "su", "-c", command)))

    def process_fd_links(self, pid: int) -> str:
        _positive(pid, "Document PID", android.MAX_PID)
        return self.text(
            "proc_fd_links",
            ("shell", "su", "-c", f"ls -l /proc/{pid}/fd"))

    def sha256_file(self, path: str) -> str:
        allowed = {
            SOURCE_PDF, SOURCE_MARK, TARGET_PDF, TARGET_MARK,
            PARKING_PDF, PARKING_MARK, DOCUMENT_APK,
        }
        if (path not in allowed and SAFE_APK.fullmatch(path) is None and
                STAGING_PATTERN.fullmatch(path) is None and
                QUARANTINE_PATTERN.fullmatch(path) is None):
            _fail("file hash escaped the exact alpha path set")
        output = self.text(
            "sha256_" + Path(path).name,
            ("shell", "sha256sum", path)).strip()
        match = re.fullmatch(r"([0-9a-f]{64})\s+" + re.escape(path), output)
        if match is None:
            _fail("sha256sum output differs for " + path)
        return match.group(1)

    def stat_file(self, path: str, *, absent_ok: bool = False) -> DeviceFile | None:
        allowed = {
            SOURCE_PDF, SOURCE_MARK, TARGET_PDF, TARGET_MARK,
            PARKING_PDF, PARKING_MARK, DOCUMENT_APK,
        }
        if (path not in allowed and SAFE_APK.fullmatch(path) is None and
                STAGING_PATTERN.fullmatch(path) is None and
                QUARANTINE_PATTERN.fullmatch(path) is None):
            _fail("stat escaped the exact alpha path set")
        result = self._invoke(
            "stat_" + Path(path).name,
            ("shell", "stat", "-c", "%F,%s,%u,%g,%i,%d", path))
        if result.returncode != 0:
            combined = _decode_text(
                result.stdout + b"\n" + result.stderr, result.operation)
            if absent_ok and "No such file or directory" in combined:
                return None
            self._require_zero(result)
        output = _decode_text(result.stdout, result.operation).strip()
        fields = output.split(",")
        if (len(fields) != 6 or fields[0] != "regular file" or
                any(re.fullmatch(r"0|[1-9][0-9]{0,19}", item) is None
                    for item in fields[1:])):
            _fail("stat identity differs for " + path)
        size, uid, gid, inode, device = map(int, fields[1:])
        return DeviceFile(
            path, fields[0], size, uid, gid, inode, device,
            self.sha256_file(path),
        )

    def copy_fixture_member(self, source: str, staging: str) -> CommandResult:
        target = _staging_target(staging)
        if (source, target) not in {
                (SOURCE_PDF, TARGET_PDF), (SOURCE_MARK, TARGET_MARK)}:
            _fail("copy escaped the exact source/staging fixture pair")
        result = self._invoke(
            "copy_staging_" + Path(staging).name,
            ("exec-out", "toybox", "cp", "-n", "-T", "-v", source,
             staging))
        self._require_zero(result)
        # Pinned raw exec-out dialect: a created copy emits this one source-only
        # LF receipt without adb-shell's Windows CRLF rendering. A no-clobber
        # skip exits zero with no stdout and therefore cannot become ownership
        # authority. Compare raw bytes: splitlines() would wrongly normalize
        # CRLF, VT, FF, and other control mutations.
        expected_stdout = ("cp '" + source + "'\n").encode("ascii")
        if result.stdout != expected_stdout or result.stderr != b"":
            _fail("fixture copy lacks the exact created-copy receipt")
        return result

    def publish_fixture_member(
            self, staging: str, target: str) -> CommandResult:
        if _staging_target(staging) != target:
            _fail("fixture publication escaped the exact staging/target pair")
        result = self._invoke(
            "publish_" + Path(target).name,
            ("shell", "toybox", "mv", "-n", "-T", "-v", staging, target))
        self._require_zero(result)
        # The pinned firmware produces no bytes for either a successful rename
        # or a no-clobber skip. The caller settles from both path identities.
        if result.stdout != b"" or result.stderr != b"":
            _fail("fixture publication output differs from the pinned dialect")
        return result

    def copy_parking_pdf(self) -> CommandResult:
        # `-n` is defense in depth against a name appearing between the
        # absence observation and copy dispatch.  Such a raced-in file is
        # never overwritten and must independently pass the exact identity
        # checks before it can become parking authority.
        result = self._invoke(
            "copy_parking_pdf",
            ("shell", "cp", "-n", SOURCE_PDF, PARKING_PDF))
        self._require_zero(result)
        return result

    def move_fixture_to_quarantine(
            self, path: str, quarantine: str) -> CommandResult:
        if (path not in {TARGET_PDF, TARGET_MARK} or
                _quarantine_target(quarantine) != path):
            _fail("quarantine move escaped the exact disposable fixture pair")
        result = self._invoke(
            "quarantine_" + Path(path).name,
            ("shell", "toybox", "mv", "-n", "-T", "-v", path, quarantine))
        self._require_zero(result)
        # On the pinned firmware both successful rename and no-clobber skip
        # return zero with no output.  The caller must settle the mutation from
        # the exact source/destination postcondition matrix.
        if (_decode_text(result.stdout, result.operation) != "" or
                _decode_text(result.stderr, result.operation + " stderr") != ""):
            _fail("quarantine move output differs from the pinned dialect")
        return result

    def remove_quarantine_member(self, quarantine: str) -> CommandResult:
        _quarantine_target(quarantine)
        result = self._invoke(
            "remove_quarantine_" + Path(quarantine).name,
            ("shell", "toybox", "rm", "-f", quarantine))
        self._require_zero(result)
        if (_decode_text(result.stdout, result.operation) != "" or
                _decode_text(result.stderr, result.operation + " stderr") != ""):
            _fail("quarantine removal output differs from the pinned dialect")
        return result

    def remove_staging_member(self, staging: str) -> CommandResult:
        _staging_target(staging)
        result = self._invoke(
            "remove_staging_" + Path(staging).name,
            ("shell", "toybox", "rm", "-f", staging))
        self._require_zero(result)
        if result.stdout != b"" or result.stderr != b"":
            _fail("staging removal output differs from the pinned dialect")
        return result

    def start_host(self) -> CommandResult:
        result = self._invoke(
            "start_host", (
                "shell", "am", "start", "--user", "0", "--display", "0",
                "-a", "android.intent.action.MAIN", "-c",
                "android.intent.category.LAUNCHER", "-n", HOST_COMPONENT,
            ))
        self._require_zero(result)
        return result

    def ui_dump(self) -> bytes:
        result = self._invoke(
            "ui_dump", ("exec-out", "uiautomator", "dump", "/dev/tty"),
            timeout=8.0)
        return self._require_zero(result)

    def host_logs(self, pid: int) -> str:
        _positive(pid, "host PID", android.MAX_PID)
        return self.text(
            "host_logs", (
                "shell", "logcat", "-d", "-v", "brief", "-t", "200",
                "--pid", str(pid), "NATIVE_PAGE_HOST:I", "*:S",
            ))

    def send_host(self, status: HostStatus, sequence: int, action: str,
                  *, foreign: host.ForeignIdentity | None = None,
                  absence_sha256: str | None = None) -> CommandResult:
        argv = host_command_argv(
            self.adb, status, sequence, action, foreign, absence_sha256)
        # Strip the already-audited adb/serial prefix before the one retained
        # invocation path reconstructs and rechecks it.
        return self._invoke(
            "host_" + action.rsplit(".", 1)[-1].lower(), argv[3:])

    def launch_document(self, display_id: int) -> CommandResult:
        argv = document_launch_argv(self.adb, display_id)
        return self._invoke("launch_document", argv[3:], timeout=15.0)

    def launch_parking_document(self, display_id: int) -> CommandResult:
        argv = parking_document_launch_argv(self.adb, display_id)
        return self._invoke("launch_parking_document", argv[3:], timeout=15.0)

    def remove_exact_task(self, task_id: int) -> CommandResult:
        argv = exact_task_remove_argv(self.adb, task_id)
        return self._invoke("remove_exact_task", argv[3:], timeout=15.0)

    def screenshot(self) -> bytes:
        result = self._invoke(
            "screenshot", ("exec-out", "screencap", "-p"),
            timeout=10.0, maximum=MAX_SCREENSHOT_BYTES)
        return self._require_zero(result)


def parse_host_status(raw: bytes) -> HostStatus:
    text = _decode_text(raw, "ui_dump")
    begin, end = text.find("<hierarchy"), text.rfind("</hierarchy>")
    if begin < 0 or end < begin:
        _fail("UI dump does not contain one hierarchy")
    try:
        root = ET.fromstring(text[begin:end + len("</hierarchy>")])
    except ET.ParseError as error:
        raise AlphaError("UI hierarchy is malformed") from error
    candidates = [
        node.attrib.get("text", "") for node in root.iter("node")
        if "NATIVE PAGE HOST" in node.attrib.get("text", "")
    ]
    if len(candidates) != 1:
        _fail("exact host status node is absent or ambiguous")
    value = candidates[0]
    session = re.findall(
        r"(?:^|\n)session=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12})(?:\n|$)", value)
    generation = re.findall(r"(?:^|\n)generation=([1-9][0-9]*) display=([1-9][0-9]*)(?:\n|$)", value)
    state = re.findall(r"(?:^|\n)state=([A-Z_]+)(?:\n|$)", value)
    if len(session) != 1 or len(generation) != 1 or len(state) != 1:
        _fail("host status fields are absent or ambiguous")
    result = HostStatus(
        _canonical_uuid(session[0], "host status session"),
        _positive(int(generation[0][0]), "host status generation", 2**63 - 1),
        _positive(int(generation[0][1]), "host status display", 1024),
        state[0], value,
    )
    result.validate()
    return result


def parse_parking_ui_witness(raw: bytes) -> dict[str, Any]:
    """Bind the post-switch UI to the fixed parking filename.

    The task intent is intentionally not parking authority on this firmware:
    ActivityManager keeps the original target intent after `onNewIntent`.
    """
    text = _decode_text(raw, "parking ui_dump")
    begin, end = text.find("<hierarchy"), text.rfind("</hierarchy>")
    if begin < 0 or end < begin:
        _fail("parking UI hierarchy is absent")
    try:
        root = ET.fromstring(text[begin:end + len("</hierarchy>")])
    except ET.ParseError as error:
        raise AlphaError("parking UI hierarchy is malformed") from error
    rotation_text = root.attrib.get("rotation", "")
    if not re.fullmatch(r"[0-3]", rotation_text):
        _fail("parking UI hierarchy lacks one physical rotation")
    rotation = int(rotation_text)
    screen_width, screen_height = (
        (1872, 1404) if rotation in (1, 3) else (1404, 1872))
    filename = Path(PARKING_PDF).name
    target_filename = Path(TARGET_PDF).name
    values: list[str] = []
    filename_nodes: list[ET.Element] = []
    target_nodes: list[ET.Element] = []
    for node in root.iter("node"):
        node_values: list[str] = []
        for name in ("text", "content-desc"):
            value = node.attrib.get(name, "")
            if value:
                values.append(value)
                node_values.append(value)
        if filename in node_values:
            filename_nodes.append(node)
        if any(target_filename in value for value in node_values):
            target_nodes.append(node)
    if len(filename_nodes) != 1 or target_nodes:
        _fail("parking UI filename authority is absent, duplicated, or still target-bound")
    filename_node = filename_nodes[0]
    if filename_node.attrib.get("displayed") != "true":
        _fail("parking UI filename authority is not displayed")
    package = filename_node.attrib.get("package")
    if package not in (None, "", DOCUMENT_PACKAGE):
        _fail("parking UI filename authority belongs to another package")
    bounds_text = filename_node.attrib.get("bounds", "")
    bounds_match = re.fullmatch(
        r"\[([0-9]{1,7}),([0-9]{1,7})\]"
        r"\[([0-9]{1,7}),([0-9]{1,7})\]", bounds_text)
    if bounds_match is None:
        _fail("parking UI filename authority lacks canonical bounds")
    left, top, right, bottom = map(int, bounds_match.groups())
    if (not 0 <= left < right <= screen_width or
            not 0 <= top < bottom <= screen_height):
        _fail("parking UI filename authority is empty or off-screen")
    counts = sorted(set(
        match.group(0).replace(" ", "")
        for value in values
        for match in re.finditer(r"(?<![0-9])[1-9][0-9]{0,6}\s*/\s*[1-9][0-9]{0,6}(?![0-9])", value)
    ))
    if len(counts) > 1:
        _fail("parking UI page-count witness is ambiguous")
    return {
        "filename": filename,
        "pageCount": None if not counts else counts[0],
        "bounds": [left, top, right, bottom],
        "package": package,
        "rotation": rotation,
        "sha256": _sha(raw),
    }


def parse_png(raw: bytes, name: str) -> Screenshot:
    if (type(raw) is not bytes or not 57 <= len(raw) <= MAX_SCREENSHOT_BYTES or
            not raw.startswith(PNG_SIGNATURE)):
        _fail("screenshot is not one complete bounded PNG")
    offset = len(PNG_SIGNATURE)
    chunk_count = 0
    ihdr: bytes | None = None
    idat: list[bytes] = []
    idat_closed = False
    iend_seen = False
    plte_seen = False
    while offset < len(raw):
        chunk_count += 1
        if chunk_count > 4096 or len(raw) - offset < 12:
            _fail("PNG chunk framing is truncated or excessive")
        length = struct.unpack(">I", raw[offset:offset + 4])[0]
        if length > MAX_SCREENSHOT_BYTES or length > len(raw) - offset - 12:
            _fail("PNG chunk length escapes the bounded screenshot")
        kind = raw[offset + 4:offset + 8]
        if len(kind) != 4 or any(
                not (65 <= value <= 90 or 97 <= value <= 122)
                for value in kind):
            _fail("PNG chunk type is not four ASCII letters")
        if not 65 <= kind[2] <= 90:
            _fail("PNG chunk type uses a nonzero reserved bit")
        data_begin = offset + 8
        data_end = data_begin + length
        data = raw[data_begin:data_end]
        crc = struct.unpack(">I", raw[data_end:data_end + 4])[0]
        if (zlib.crc32(kind + data) & 0xffffffff) != crc:
            _fail("PNG chunk CRC differs")
        offset = data_end + 4

        if chunk_count == 1 and kind != b"IHDR":
            _fail("PNG IHDR is not the first chunk")
        if kind == b"IHDR":
            if chunk_count != 1 or ihdr is not None or length != 13:
                _fail("PNG has duplicate or malformed IHDR")
            ihdr = data
        elif kind == b"PLTE":
            if ihdr is None or idat or plte_seen or not 3 <= length <= 768 or length % 3:
                _fail("PNG PLTE placement/length differs")
            plte_seen = True
        elif kind == b"IDAT":
            if ihdr is None or iend_seen or idat_closed or length == 0:
                _fail("PNG IDAT stream is absent, empty, or noncontiguous")
            idat.append(data)
            if sum(len(value) for value in idat) > MAX_SCREENSHOT_BYTES:
                _fail("PNG compressed stream is oversized")
        elif kind == b"IEND":
            if ihdr is None or not idat or iend_seen or length != 0:
                _fail("PNG IEND is missing, duplicate, or malformed")
            iend_seen = True
            if offset != len(raw):
                _fail("PNG contains bytes or chunks after IEND")
        else:
            if 65 <= kind[0] <= 90:
                _fail("PNG contains an unknown critical chunk")
            if idat:
                idat_closed = True
    if not iend_seen or ihdr is None or not idat or offset != len(raw):
        _fail("PNG does not terminate with one complete image")

    width, height, bit_depth, color_type, compression, filtering, interlace = (
        struct.unpack(">IIBBBBB", ihdr))
    expected = _screen_dimensions(name)
    if (width, height) != expected:
        _fail("screenshot dimensions differ for " + name)
    if (bit_depth != 8 or color_type not in (2, 6) or
            compression != 0 or filtering != 0 or interlace != 0):
        _fail("PNG encoding is not noninterlaced 8-bit RGB/RGBA")
    channels = 3 if color_type == 2 else 4
    row_bytes = width * channels
    inflated_size = (row_bytes + 1) * height
    if not 0 < inflated_size <= MAX_SCREENSHOT_BYTES:
        _fail("PNG inflated image size is outside the fixed bound")
    compressed = b"".join(idat)
    try:
        inflater = zlib.decompressobj()
        inflated = inflater.decompress(compressed, inflated_size + 1)
        if len(inflated) > inflated_size or inflater.unconsumed_tail:
            _fail("PNG zlib stream expands beyond the exact image size")
        tail = inflater.flush()
    except zlib.error as error:
        raise AlphaError("PNG IDAT zlib stream is invalid") from error
    inflated += tail
    if (not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or
            len(inflated) != inflated_size):
        _fail("PNG IDAT does not decode to the exact image rows")
    if any(inflated[offset] > 4
           for offset in range(0, inflated_size, row_bytes + 1)):
        _fail("PNG row uses an invalid filter type")
    return Screenshot(name, width, height, len(raw), _sha(raw))


def _screen_dimensions(name: str) -> tuple[int, int]:
    expected = {
        "full": (1872, 1404),
        "left": (1872, 1404),
        "right": (1872, 1404),
        "full_return": (1872, 1404),
        "portrait": (1404, 1872),
        "landscape_return": (1872, 1404),
    }
    if name not in expected:
        _fail("screenshot name is outside the alpha set")
    return expected[name]


def _package_version(raw: str, code: str, name: str, label: str) -> None:
    code_rows = re.findall(r"^\s*versionCode=([0-9]+)(?:\s|$)", raw, re.MULTILINE)
    name_rows = re.findall(r"^\s*versionName=([^\s]+)\s*$", raw, re.MULTILINE)
    if code_rows != [code] or name_rows != [name]:
        _fail(label + " package version differs")


def _physical_orientation(raw: bytes) -> int:
    """Parse one internally consistent physical display-0 WM record.

    Nomad's InputManager repeats a stale ``SurfaceOrientation`` value, so it is
    not an orientation authority.  The Android 11 WindowManager display dump
    instead exposes the display's current/app dimensions plus three independent
    rotation fields.  All are scoped to one exact display-0 block and must
    agree before the value can drive either the landscape preflight or manual
    rotation gates.
    """
    text = _decode_text(raw, "WindowManager display inventory")
    candidate_header_pattern = re.compile(
        r"^[ \t]*Display:[^\r\n]*$", re.MULTILINE)
    header_pattern = re.compile(
        r"^[ \t]*Display:[ \t]+mDisplayId=(0|[1-9][0-9]*)[ \t]+"
        r"stacks=(0|[1-9][0-9]*)[ \t]*$",
        re.MULTILINE)
    candidate_headers = list(candidate_header_pattern.finditer(text))
    headers = list(header_pattern.finditer(text))
    if not candidate_headers or len(candidate_headers) != len(headers):
        _fail("WindowManager display header suffix is missing or malformed")
    display_zero = [value for value in headers if value.group(1) == "0"]
    if len(display_zero) != 1:
        _fail("physical display-0 WindowManager record is absent or duplicated")
    selected = display_zero[0]
    following = [value.start() for value in headers
                 if value.start() > selected.start()]
    block = text[selected.start():min(following, default=len(text))]

    prefixes = {
        "display metrics": r"^[ \t]*init=",
        "display info": r"^[ \t]*mDisplayInfo=",
        "display frames": r"^[ \t]*DisplayFrames\b",
        "display rotation": r"^[ \t]*mRotation=",
    }
    for label, pattern in prefixes.items():
        if len(re.findall(pattern, block, re.MULTILINE)) != 1:
            _fail("display-0 " + label + " is absent or duplicated")
    for token in ("init", "cur", "app", "mRotation"):
        if len(re.findall(
                r"(?<![A-Za-z0-9_])" + token + r"=", block)) != 1:
            _fail("display-0 contains a misplaced or duplicate authority token")
    if len(re.findall(
            r"(?<![A-Za-z0-9_])rotation[ \t]+[0-3](?=[, }\]]|$)",
            block)) != 1:
        _fail("display-0 contains a misplaced or duplicate rotation authority")

    metric_lines = re.findall(
        r"^[ \t]*init=[^\r\n]+$", block, re.MULTILINE)
    info_lines = re.findall(
        r"^[ \t]*mDisplayInfo=([^\r\n]+)$", block, re.MULTILINE)
    frame_lines = re.findall(
        r"^[ \t]*DisplayFrames\b[^\r\n]*$", block, re.MULTILINE)
    if (len(metric_lines) != 1 or len(info_lines) != 1 or
            len(frame_lines) != 1):
        _fail("display-0 WindowManager authority lines are ambiguous")
    for token in ("init", "cur", "app"):
        if len(re.findall(
                r"(?<![A-Za-z0-9_])" + token + r"=", metric_lines[0])) != 1:
            _fail("display-0 metrics contain duplicate authority tokens")
    for token in ("w", "h", "r"):
        if len(re.findall(
                r"(?<![A-Za-z0-9_])" + token + r"=", frame_lines[0])) != 1:
            _fail("display-0 frames contain duplicate authority tokens")

    metrics = re.findall(
        r"^[ \t]*init=([0-9]{1,5})x([0-9]{1,5})[ \t]+"
        r"([0-9]{1,5})dpi[ \t]+cur=([0-9]{1,5})x([0-9]{1,5})[ \t]+"
        r"app=([0-9]{1,5})x([0-9]{1,5})"
        r"(?:[ \t]+rng=[0-9]{1,5}x[0-9]{1,5}-[0-9]{1,5}x[0-9]{1,5})?$",
        block, re.MULTILINE)
    frames = re.findall(
        r"^[ \t]*DisplayFrames[ \t]+w=([0-9]{1,5})[ \t]+"
        r"h=([0-9]{1,5})[ \t]+r=([0-3])[ \t]*$",
        block, re.MULTILINE)
    rotations = re.findall(
        r"^[ \t]*mRotation=([0-3])"
        r"(?:[ \t]+mDeferredRotationPauseCount=0)?[ \t]*$",
        block, re.MULTILINE)
    deferred_rotation_tokens = re.findall(
        r"(?<![A-Za-z0-9_])mDeferredRotationPauseCount=", block)
    stable_deferred_rotation_lines = re.findall(
        r"^[ \t]*mRotation=[0-3][ \t]+"
        r"mDeferredRotationPauseCount=0[ \t]*$", block, re.MULTILINE)
    if (len(deferred_rotation_tokens) > 1 or
            (len(deferred_rotation_tokens) == 1 and
             len(stable_deferred_rotation_lines) != 1)):
        _fail("display-0 deferred rotation state is misplaced or ambiguous")
    if (len(metrics) != 1 or len(info_lines) != 1 or
            len(frames) != 1 or len(rotations) != 1):
        _fail("display-0 WindowManager fields do not match the pinned dialect")
    info_rotations = re.findall(
        r"(?<![A-Za-z0-9_])rotation[ \t]+([0-3])(?=[, }\]]|$)",
        info_lines[0])
    info_display_ids = re.findall(
        r"(?<![A-Za-z0-9_])displayId[ \t]+([0-9]+)(?=[, }\]]|$)",
        info_lines[0])
    if len(info_rotations) != 1:
        _fail("display-0 DisplayInfo rotation is absent or ambiguous")
    if info_display_ids != ["0"]:
        _fail("display-0 DisplayInfo identity is absent, duplicated, or different")

    (init_width, init_height, density, current_width, current_height,
     app_width, app_height) = map(int, metrics[0])
    frame_width, frame_height = map(int, frames[0][:2])
    rotation_values = (
        int(info_rotations[0]), int(frames[0][2]), int(rotations[0]))
    if len(set(rotation_values)) != 1:
        _fail("display-0 WindowManager rotation fields disagree")
    rotation = rotation_values[0]
    if (init_width, init_height, density) != (1404, 1872, 300):
        _fail("display-0 initial dimensions or density differ from Nomad")
    dimensions = (current_width, current_height)
    if (dimensions != (app_width, app_height) or
            dimensions != (frame_width, frame_height)):
        _fail("display-0 current/app/frame dimensions disagree")
    expected = (1872, 1404) if rotation in (1, 3) else (1404, 1872)
    if dimensions != expected:
        _fail("display-0 dimensions disagree with its physical rotation")
    return rotation


def _starting_landscape_orientation(raw: bytes) -> int:
    orientation = _physical_orientation(raw)
    if orientation not in (1, 3):
        _fail("rotate the Nomad to landscape before running the visual alpha")
    return orientation


def _contains_component(raw: bytes, components: Sequence[str]) -> bool:
    text = _decode_text(raw, "Android inventory")
    return any(component in text for component in components)


def _contains_document_task_or_window(raw: bytes) -> bool:
    """Recognize package-wide stock Document task/window evidence.

    Exact ``DocumentActivity`` spellings remain mandatory when establishing
    launch/removal ownership. Absence gates are deliberately broader so a
    vendor transition to another activity in the same package cannot be
    mistaken for global Document absence. ActivityManager's validated
    post-boundary supervisor suffix remains non-authoritative for task
    selection, but any Document evidence there still defeats an unqualified
    absence claim. Only the separately retained-identity gate may exempt the
    one exact post-removal supervisor ghost.
    """
    text = _decode_text(raw, "Document task/window inventory")
    if text.startswith("ACTIVITY MANAGER"):
        # Validate the boundary/dialect before inspecting the entire wire.
        # The returned canonical region is intentionally discarded here:
        # supervisor records cannot select a task, but they are still presence
        # evidence unless the exact retained ghost proof below is available.
        activity_text, _ = android._wire(raw)  # type: ignore[attr-defined]
        android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            activity_text)
        text = activity_text
    return re.search(
        r"(?<![A-Za-z0-9_.])" + re.escape(DOCUMENT_PACKAGE) +
        r"(?=/|[\s}:,\]]|$)", text) is not None


def _is_exact_stale_document_supervisor_ghost(
        text: str, foreign: host.ForeignIdentity,
        retained_authority: android.DocumentTaskAuthority | None,
        ) -> bool:
    """Admit only the pinned post-removal, empty supervisor history.

    Activity selection deliberately ignores the validated supervisor suffix.
    Global-absence authority is narrower: a suffix that still names Document
    is ignored only when every target-bearing record is the exact retained
    task/activity identity and both task summaries are invisible and empty.
    """
    if (type(retained_authority) is not android.DocumentTaskAuthority or
            retained_authority.task_id != foreign.task_id or
            retained_authority.activity_token != foreign.activity_token or
            retained_authority.pid != foreign.process.pid or
            retained_authority.uid != android.SYSTEM_UID or
            foreign.process.uid != android.SYSTEM_UID or
            retained_authority.package_name != DOCUMENT_PACKAGE or
            retained_authority.process_name != DOCUMENT_PACKAGE or
            retained_authority.component not in _document_components() or
            foreign.process.package != DOCUMENT_PACKAGE or
            foreign.component != DOCUMENT_COMPONENT):
        return False

    boundary = "ActivityStackSupervisor state:\n"
    if text.count(boundary) != 1:
        return False
    canonical, suffix = text.split(boundary, 1)
    lines = suffix.splitlines()
    task = str(foreign.task_id)
    target_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])" + re.escape(DOCUMENT_PACKAGE) +
        r"(?=/|[\s}:,\]]|$)")

    def exact_task_summary(line: str, label: str) -> bool:
        return re.fullmatch(
            r"  " + re.escape(label) + r"=Task\{" +
            re.escape(retained_authority.task_token) + r" #" +
            re.escape(task) + r" visible=false A=" +
            re.escape(str(android.SYSTEM_UID)) + r":" +
            re.escape(DOCUMENT_PACKAGE) + r" sz=0\}", line) is not None

    def exact_activity_summary(line: str, label: str) -> bool:
        return re.fullmatch(
            r"  " + re.escape(label) + r"=ActivityRecord\{" +
            re.escape(foreign.activity_token) + r" u0 " +
            re.escape(retained_authority.component) + r" t" +
            re.escape(task) + r"\}", line) is not None

    predicates = (
        lambda line: exact_task_summary(line, "topDisplayFocusedStack"),
        lambda line: exact_activity_summary(line, "mLastOrientationSource"),
        lambda line: exact_activity_summary(
            line, "deepestLastOrientationSource"),
        lambda line: exact_task_summary(line, "mLastFocusedStack"),
    )
    recognized_indexes: list[int] = []
    for predicate in predicates:
        matches = [index for index, line in enumerate(lines) if predicate(line)]
        if len(matches) != 1:
            return False
        recognized_indexes.append(matches[0])
    target_indexes = [
        index for index, line in enumerate(lines)
        if target_pattern.search(line) is not None
    ]
    if (recognized_indexes != [0, 1, 2, 3] or
            target_indexes != recognized_indexes):
        return False

    canonical_decimal = r"0|[1-9][0-9]{0,9}"

    def bounded_decimal(value: str, maximum: int) -> int | None:
        if re.fullmatch(canonical_decimal, value) is None:
            return None
        number = int(value, 10)
        return number if number <= maximum else None

    display_header = re.compile(
        r"^Display #(" + canonical_decimal +
        r") \(activities from top to bottom\):$")
    header_ids: list[int] = []
    for line in canonical.splitlines():
        match = display_header.fullmatch(line)
        if match is not None:
            display_id = bounded_decimal(match.group(1), 1024)
            if display_id is None or display_id in header_ids:
                return False
            header_ids.append(display_id)
    if not header_ids:
        return False

    display_summary = re.compile(
        r"^  Display: mDisplayId=(" + canonical_decimal +
        r") stacks=0$")
    display_area = re.compile(
        r"^  (?P<label>mLastOrientationSource|"
        r"deepestLastOrientationSource)=DefaultTaskDisplayArea@(" +
        canonical_decimal + r")$")
    summary_ids: list[int] = []
    pair_displays: set[int] = set()
    pair_identities: set[int] = set()
    index = 4
    while index < len(lines):
        summary = display_summary.fullmatch(lines[index])
        if summary is not None:
            display_id = bounded_decimal(summary.group(1), 1024)
            if display_id is None or display_id in summary_ids:
                return False
            summary_ids.append(display_id)
            index += 1
            continue

        if index + 2 >= len(lines):
            return False
        last = display_area.fullmatch(lines[index])
        deepest = display_area.fullmatch(lines[index + 1])
        summary = display_summary.fullmatch(lines[index + 2])
        if (last is None or deepest is None or summary is None or
                last.group("label") != "mLastOrientationSource" or
                deepest.group("label") != "deepestLastOrientationSource"):
            return False
        last_identity = bounded_decimal(last.group(2), 2_147_483_647)
        deepest_identity = bounded_decimal(deepest.group(2), 2_147_483_647)
        display_id = bounded_decimal(summary.group(1), 1024)
        if (last_identity is None or deepest_identity is None or
                last_identity != deepest_identity or display_id is None or
                display_id == 0 or display_id in summary_ids or
                display_id in pair_displays or
                last_identity in pair_identities):
            return False
        pair_displays.add(display_id)
        pair_identities.add(last_identity)
        summary_ids.append(display_id)
        index += 3

    return bool(summary_ids) and summary_ids == header_ids


def _contains_document_scope_for_global_absence(
        raw: bytes, foreign: host.ForeignIdentity | None,
        retained_authority: android.DocumentTaskAuthority | None,
        ) -> bool:
    """Return whether global Document absence is unproved by this inventory."""
    text = _decode_text(raw, "global Document task/window inventory")
    if not text.startswith("ACTIVITY MANAGER"):
        return _contains_document_task_or_window(raw)
    full_text, _ = android._wire(raw)  # type: ignore[attr-defined]
    canonical = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
        full_text)
    package_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])" + re.escape(DOCUMENT_PACKAGE) +
        r"(?=/|[\s}:,\]]|$)")
    if package_pattern.search(canonical) is not None:
        return True
    package_present = package_pattern.search(full_text) is not None
    retained_identity_present = False
    if foreign is not None:
        task = re.escape(str(foreign.task_id))
        retained_patterns = (
            re.compile(re.escape(foreign.activity_token)),
            *(re.compile(re.escape(value)) for value in _document_components()),
            re.compile(r"(?<![0-9])#" + task + r"(?![0-9])"),
            re.compile(r"(?<![A-Za-z0-9_])t" + task + r"(?![0-9])"),
            re.compile(
                r"(?:taskId|rootTaskId|stackId|StackId)=" + task +
                r"(?![0-9])"),
        )
        retained_identity_present = any(
            pattern.search(full_text) is not None
            for pattern in retained_patterns)
    if not package_present and not retained_identity_present:
        return False
    return foreign is None or not _is_exact_stale_document_supervisor_ghost(
        full_text, foreign, retained_authority)


def _document_components() -> tuple[str, ...]:
    return (android.SHORT_COMPONENT, android.FULL_COMPONENT)


def _host_components() -> tuple[str, ...]:
    return (HOST_COMPONENT, HOST_PACKAGE + "/.NativePageHostActivity")


def _bounded_observation_error(error: BaseException) -> str:
    rendered = f"{type(error).__name__}: {error}"
    encoded = rendered.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_OBSERVATION_ERROR_BYTES:
        return rendered
    suffix = b"..."
    return (encoded[:MAX_OBSERVATION_ERROR_BYTES - len(suffix)].decode(
        "utf-8", errors="ignore") + suffix.decode("ascii"))


def _document_file_targets(links: str) -> frozenset[str]:
    if type(links) is not str or len(links.encode("utf-8")) > MAX_TEXT_BYTES:
        _fail("Document descriptor inventory is malformed or oversized")
    targets = re.findall(r" -> ([^\r\n]+)$", links, re.MULTILINE)
    relevant: set[str] = set()
    for value in targets:
        candidate = (
            value[:-len(" (deleted)")]
            if value.endswith(" (deleted)") else value
        )
        if candidate.lower().endswith((".pdf", ".mark")):
            # Preserve the raw target so a deleted link never equals the live,
            # exact fixture path.
            relevant.add(value)
    return frozenset(relevant)


def _assert_owned_display_empty(raw: bytes, status: HostStatus) -> None:
    text, _ = android._wire(raw)  # type: ignore[attr-defined]
    text = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
        text)
    occupied = [
        (display_id, stack_id)
        for display_id, stack_id, _
        in android._display_stack_blocks(text)  # type: ignore[attr-defined]
        if display_id == status.display_id
    ]
    if occupied:
        _fail("owned virtual display still contains an Activity Manager root task")


def _assert_owned_display_windows_empty(raw: bytes, status: HostStatus) -> None:
    text = _decode_text(raw, "window inventory")
    display_ids = re.findall(
        r"^\s*mDisplayId\s*=\s*([0-9]+)(?:\s|$)", text, re.MULTILINE)
    if str(status.display_id) in display_ids:
        _fail("owned virtual display still contains a Window Manager window")


def _virtual_display_present(raw: bytes, status: HostStatus) -> bool:
    text = _decode_text(raw, "display inventory")
    return status.display_name in text


def _host_event_present(logs: str, status: HostStatus, kind: str,
                        required: Sequence[str] = ()) -> bool:
    if not re.fullmatch(r"[A-Z_]+", kind):
        _fail("host event name is malformed")
    needle = f"{kind} session={status.session} generation={status.generation} "
    return any(needle in line and all(item in line for item in required)
               for line in logs.splitlines())


def _host_failure(logs: str, status: HostStatus) -> str | None:
    for line in logs.splitlines():
        identity = f"session={status.session} generation={status.generation} "
        if identity in line and any(
                event + " " + identity in line
                for event in ("FAILED", "TIMEOUT", "RELEASE_FAILED")):
            return line.strip()
    return None


class AlphaSession:
    """One-shot coordinator.  Instances cannot target another scope."""

    def __init__(self, device: AdbNomad, output_root: Path,
                 host_artifact: HostArtifact | None = None,
                 *, rotation_authority: str = ROTATION_MANUAL_PHYSICAL,
                 rotation_controller_run_id: str | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], float] = time.monotonic):
        self.device = device
        self.host_artifact = (
            _fixed_host_artifact() if host_artifact is None else host_artifact)
        self.host_artifact.validate()
        if (type(rotation_authority) is not str or
                rotation_authority not in ROTATION_AUTHORITIES):
            _fail("rotation authority is outside the closed alpha choices")
        self.rotation_authority = rotation_authority
        if rotation_authority == ROTATION_MANUAL_PHYSICAL:
            if rotation_controller_run_id is not None:
                _fail("manual rotation cannot carry a controller run ID")
        elif (type(rotation_controller_run_id) is not str or
              ROTATION_CONTROLLER_ID.fullmatch(rotation_controller_run_id) is None):
            _fail("ADB rotation requires one exact controller run ID")
        self.rotation_controller_run_id = rotation_controller_run_id
        self.rotation_controller_phases: list[str] = []
        declared_output_root = Path(os.path.abspath(os.fspath(
            output_root.expanduser())))
        try:
            declared_stat = os.lstat(declared_output_root)
            resolved_output_root = declared_output_root.resolve(strict=True)
        except OSError as error:
            raise AlphaError(
                "alpha output root cannot be retained") from error
        if (os.path.normcase(str(resolved_output_root)) !=
                os.path.normcase(str(declared_output_root)) or
                stat_module.S_ISLNK(declared_stat.st_mode) or
                not stat_module.S_ISDIR(declared_stat.st_mode)):
            _fail("alpha output root must be one preexisting real directory")
        self.output_root = declared_output_root
        self.sleep = sleep
        self.now = now
        self.output_dir: Path | None = None
        self.status: HostStatus | None = None
        self.host_pid: int | None = None
        self.foreign: host.ForeignIdentity | None = None
        self.foreign_authority: android.DocumentTaskAuthority | None = None
        self.unowned_foreign_candidate: host.ForeignIdentity | None = None
        self.last_foreign_capture_error: str | None = None
        self.foreign_fixture_bound = False
        self.parking_file: DeviceFile | None = None
        self.parking_ui_witness: dict[str, Any] | None = None
        self.source_pdf_file: DeviceFile | None = None
        self.source_mark_file: DeviceFile | None = None
        self.parking_switch_attempted = False
        self.parking_bound = False
        self.prelaunch_absence_sha256: str | None = None
        self.launch_owned = False
        self.document_launch_attempted = False
        self.sequence = 0
        self.pending_host_command: tuple[str, int] | None = None
        self.attached = False
        self.close_started = False
        self.task_absence_sha256: str | None = None
        self.initial_orientation: int | None = None
        self.starting_orientation: int | None = None
        self.portrait_orientation: int | None = None
        self.returned_orientation: int | None = None
        self.source_fixture_unchanged: bool | None = None
        self.parking_fixture_unchanged: bool | None = None
        self.parking_provisioning_reached = False
        self.parking_copy_attempted = False
        self.parking_copy_reply_proved = False
        self.parking_provisioning_settled = False
        self.host_start_attempted = False
        self.attach_command_attempted = False
        self.fixture_obligations: dict[str, FixtureObligation] = {}
        self.mutation_journal_path: Path | None = None
        self.mutation_journal_id: str | None = None
        self.mutation_journal_head_sha256: str | None = None
        self.mutation_journal_file_sha256: str | None = None
        self.mutation_journal_sequence = 0
        self.mutation_journal_size = 0
        self.mutation_journal_identity: tuple[int, int] | None = None
        self.mutation_journal_directory_durable = False
        self.mutation_journal_retired = False
        self.screenshots: list[Screenshot] = []
        self.events: list[dict[str, Any]] = []
        self.primary_error: str | None = None
        self.cleanup_errors: list[str] = []
        self.cleanup = {
            "taskAbsent": False,
            "stockProcessAlive": False,
            "documentGloballyAbsent": False,
            "documentParked": False,
            "disposableDescriptorsClosed": False,
            "displayAbsent": False,
            "hostTaskAbsent": False,
            "fixtureRemoved": False,
        }

    def _event(self, name: str, **details: Any) -> None:
        self.events.append({
            "name": name, "observedNs": str(time.monotonic_ns()), **details,
        })

    def _emit_rotation_controller_phase(self, phase: str) -> None:
        """Publish one exact, flushed request to the owning controller.

        The record is emitted only after the runner has reached the matching
        orientation wait.  It contains no command or setting value; the
        external controller maps this closed phase name to its own literal,
        durably journaled mutation.
        """
        if self.rotation_authority != ROTATION_ADB_SYSTEM_SETTINGS:
            _fail("rotation phase emission is forbidden in manual mode")
        sequence = len(self.rotation_controller_phases) + 1
        if (sequence > len(ROTATION_CONTROLLER_PHASES) or
                phase != ROTATION_CONTROLLER_PHASES[sequence - 1] or
                type(self.rotation_controller_run_id) is not str or
                ROTATION_CONTROLLER_ID.fullmatch(
                    self.rotation_controller_run_id) is None):
            _fail("rotation controller phase is absent, duplicated, or out of order")
        wire = {
            "authority": ROTATION_CONTROLLER_PHASE_AUTHORITY,
            "controllerId": self.rotation_controller_run_id,
            "phase": phase,
            "sequence": sequence,
        }
        raw = (ROTATION_CONTROLLER_PHASE_PREFIX +
               _canonical_json_bytes(wire) + b"\n")
        stream = sys.stdout.buffer
        written = 0
        try:
            while written < len(raw):
                count = stream.write(raw[written:])
                if (type(count) is not int or count <= 0 or
                        count > len(raw) - written):
                    _fail("rotation phase output made invalid write progress")
                written += count
            stream.flush()
        except OSError as error:
            raise AlphaError(
                "rotation phase could not be flushed to its controller") from error
        self.rotation_controller_phases.append(phase)
        self._event(
            "adb_rotation_phase_emitted", phase=phase, sequence=sequence,
            controllerId=self.rotation_controller_run_id)

    def _ensure_output_dir(self) -> Path:
        if self.output_dir is None:
            active = self.output_root / ACTIVE_MUTATION_JOURNAL_FILENAME
            if active.exists() or active.is_symlink():
                _fail(
                    "an unresolved active mutation journal already exists; "
                    "recovery is required before another alpha run")
            stamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime())
            self.output_dir = self.output_root / (
                "alpha-" + stamp + "-" + uuid.uuid4().hex[:8])
            self.output_dir.mkdir(parents=True, exist_ok=False)
        if (not self.output_dir.is_dir() or self.output_dir.is_symlink()):
            _fail("alpha output directory is absent or linked")
        return self.output_dir

    def _parking_provisioning_wire(self) -> dict[str, bool]:
        return {
            "reached": self.parking_provisioning_reached,
            "copyAttempted": self.parking_copy_attempted,
            "copyReplyProved": self.parking_copy_reply_proved,
            "settled": self.parking_provisioning_settled,
        }

    def _journal_payload(
            self, event: str, details: dict[str, Any],
            ) -> dict[str, Any]:
        if (self.mutation_journal_id is None or
                type(event) is not str or not event or
                type(details) is not dict):
            _fail("mutation journal transition lacks retained authority")
        return {
            "authority": MUTATION_JOURNAL_AUTHORITY,
            "schemaVersion": 1,
            "journalId": self.mutation_journal_id,
            "sequence": self.mutation_journal_sequence,
            "previousRecordSha256": self.mutation_journal_head_sha256,
            "event": event,
            "details": details,
            "obligations": {
                path: asdict(value)
                for path, value in self.fixture_obligations.items()
            },
            "sourceAuthorities": {
                "pdf": (None if self.source_pdf_file is None else
                        asdict(self.source_pdf_file)),
                "mark": (None if self.source_mark_file is None else
                         asdict(self.source_mark_file)),
            },
            "parkingProvisioning": self._parking_provisioning_wire(),
        }

    def _initialize_mutation_journal(self) -> None:
        """Durably register all device mutation capabilities before use."""
        if (self.mutation_journal_path is not None or
                self.fixture_obligations):
            _fail("mutation journal/fixture obligations cannot be reused")
        if self.source_pdf_file is None or self.source_mark_file is None:
            _fail("mutation journal lacks retained source identities")
        members = (
            (SOURCE_PDF, TARGET_PDF, SOURCE_PDF_SHA256),
            (SOURCE_MARK, TARGET_MARK, SOURCE_MARK_SHA256),
        )
        for source, target, expected in members:
            staging_nonce = secrets.token_hex(16)
            quarantine_nonce = secrets.token_hex(16)
            if (re.fullmatch(r"[0-9a-f]{32}", staging_nonce) is None or
                    re.fullmatch(r"[0-9a-f]{32}", quarantine_nonce) is None):
                _fail("cryptographic staging/quarantine nonce generation failed")
            self.fixture_obligations[target] = FixtureObligation(
                source=source, target=target, expected_sha256=expected,
                staging_path=_staging_path(target, staging_nonce),
                quarantine_path=_quarantine_path(target, quarantine_nonce))

        directory = self._ensure_output_dir()
        self.mutation_journal_path = (
            self.output_root / ACTIVE_MUTATION_JOURNAL_FILENAME)
        self.mutation_journal_id = str(uuid.uuid4())
        payload = self._journal_payload(
            "MANIFEST_CREATED", {
                "checkpoint": CHECKPOINT,
                "authorizedSerial": AUTHORIZED_SERIAL,
                "sourcePdfSha256": SOURCE_PDF_SHA256,
                "sourceMarkSha256": SOURCE_MARK_SHA256,
                "parkingPdf": PARKING_PDF,
                "parkingMark": PARKING_MARK,
                "outputDirectory": str(directory),
                "neverScanForCapabilities": True,
            })
        raw, digest = _journal_record_bytes(payload)
        temp = self.output_root / (
            ".native-page-alpha-active-" + secrets.token_hex(16) + ".tmp")
        try:
            with temp.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _publish_local_file_exclusive(temp, self.mutation_journal_path)
        except BaseException:
            # This is still before the first device mutation. Preserve any
            # exact or raced local temp path for inspection; never unlink a
            # pathname whose identity was not retained for cleanup authority.
            raise
        observed = os.lstat(self.mutation_journal_path)
        if (not stat_module.S_ISREG(observed.st_mode) or
                self.mutation_journal_path.is_symlink() or
                observed.st_size != len(raw) or
                self.mutation_journal_path.read_bytes() != raw):
            _fail("published mutation journal identity/bytes differ")
        self.mutation_journal_identity = (
            observed.st_dev, observed.st_ino)
        self.mutation_journal_size = len(raw)
        self.mutation_journal_head_sha256 = digest
        self.mutation_journal_file_sha256 = _sha(raw)
        self.mutation_journal_sequence = 1
        self.mutation_journal_directory_durable = True
        recovered = recover_mutation_journal(self.mutation_journal_path)
        if (recovered["tornTail"] or
                recovered["journalId"] != self.mutation_journal_id or
                recovered["headSha256"] != digest or
                recovered["recordCount"] != 1):
            _fail("published mutation journal failed immediate recovery")
        self._event(
            "mutation_journal_durable", path=str(self.mutation_journal_path),
            journalId=self.mutation_journal_id, headSha256=digest)

    def _journal_transition(self, event: str, **details: Any) -> None:
        path = self.mutation_journal_path
        retained = self.mutation_journal_identity
        if (path is None or retained is None or
                self.mutation_journal_head_sha256 is None or
                self.mutation_journal_file_sha256 is None or
                not self.mutation_journal_directory_durable):
            _fail("device mutation lacks durable local journal authority")
        payload = self._journal_payload(event, details)
        raw, digest = _journal_record_bytes(payload)
        try:
            before = os.lstat(path)
            if (path.is_symlink() or not stat_module.S_ISREG(before.st_mode) or
                    (before.st_dev, before.st_ino) != retained or
                    before.st_size != self.mutation_journal_size):
                _fail("mutation journal identity changed before append")
            recovered = recover_mutation_journal(path)
            if (recovered["tornTail"] or
                    recovered["journalId"] != self.mutation_journal_id or
                    recovered["headSha256"] !=
                    self.mutation_journal_head_sha256 or
                    recovered["recordCount"] !=
                    self.mutation_journal_sequence):
                _fail("mutation journal chain changed before append")
            with path.open("r+b") as stream:
                opened = os.fstat(stream.fileno())
                if ((opened.st_dev, opened.st_ino) != retained or
                        opened.st_size != self.mutation_journal_size):
                    _fail("mutation journal was replaced at append boundary")
                current_raw = stream.read(self.mutation_journal_size + 1)
                if (len(current_raw) != self.mutation_journal_size or
                        _sha(current_raw) !=
                        self.mutation_journal_file_sha256):
                    _fail("mutation journal bytes changed at append boundary")
                stream.seek(0, os.SEEK_END)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            after = os.lstat(path)
        except OSError as error:
            raise AlphaError("mutation journal append failed") from error
        expected_size = self.mutation_journal_size + len(raw)
        if ((after.st_dev, after.st_ino) != retained or
                after.st_size != expected_size):
            _fail("mutation journal append postcondition differs")
        self.mutation_journal_size = expected_size
        self.mutation_journal_head_sha256 = digest
        self.mutation_journal_file_sha256 = _sha(current_raw + raw)
        self.mutation_journal_sequence += 1

    def _mutation_journal_current(self) -> bool:
        if not self.fixture_obligations:
            return self.mutation_journal_path is None
        path = self.mutation_journal_path
        retained = self.mutation_journal_identity
        if (path is None or retained is None or
                self.mutation_journal_head_sha256 is None or
                self.mutation_journal_file_sha256 is None or
                not self.mutation_journal_directory_durable):
            return False
        try:
            observed = os.lstat(path)
            recovered = recover_mutation_journal(path)
            raw = path.read_bytes()
        except BaseException:
            return False
        return (
            not path.is_symlink() and
            stat_module.S_ISREG(observed.st_mode) and
            (observed.st_dev, observed.st_ino) == retained and
            observed.st_size == self.mutation_journal_size and
            _sha(raw) == self.mutation_journal_file_sha256 and
            not recovered["tornTail"] and
            recovered["journalId"] == self.mutation_journal_id and
            recovered["headSha256"] == self.mutation_journal_head_sha256 and
            recovered["recordCount"] == self.mutation_journal_sequence)

    def _retire_mutation_journal(self) -> None:
        """Move the fixed active authority aside only after proved cleanup."""
        path = self.mutation_journal_path
        retained = self.mutation_journal_identity
        if (path is None or retained is None or self.output_dir is None or
                path != self.output_root / ACTIVE_MUTATION_JOURNAL_FILENAME or
                not self._mutation_journal_current()):
            _fail("active mutation journal lacks exact retirement authority")
        archive = self.output_dir / MUTATION_JOURNAL_FILENAME
        if archive.exists() or archive.is_symlink():
            _fail("archived mutation journal path already exists")
        move_error: BaseException | None = None
        try:
            _publish_local_file_exclusive(path, archive)
        except BaseException as error:
            move_error = error
        try:
            active_after = None if not path.exists() else os.lstat(path)
            archive_after = os.lstat(archive)
            archive_raw = archive.read_bytes()
        except OSError as error:
            raise AlphaError(
                "mutation journal retirement postcondition is ambiguous") from error
        if (active_after is not None or archive.is_symlink() or
                not stat_module.S_ISREG(archive_after.st_mode) or
                (archive_after.st_dev, archive_after.st_ino) != retained or
                archive_after.st_size != self.mutation_journal_size or
                _sha(archive_raw) != self.mutation_journal_file_sha256):
            if move_error is not None:
                raise AlphaError(
                    "mutation journal retirement failed and did not settle") from move_error
            _fail("mutation journal retirement identity differs")
        self.mutation_journal_path = archive
        self.mutation_journal_retired = True
        self._event(
            "mutation_journal_retired", path=str(archive),
            headSha256=self.mutation_journal_head_sha256,
            moveTransportError=(None if move_error is None else str(move_error)))

    def _until(self, label: str, seconds: float,
               function: Callable[[], Any]) -> Any:
        deadline = self.now() + seconds
        last: BaseException | None = None
        while self.now() < deadline:
            try:
                value = function()
                if value is not None and value is not False:
                    return value
            except BaseException as error:
                last = error
            self.sleep(POLL_SECONDS)
        detail = "" if last is None else ": " + str(last)
        raise AlphaError(label + " was not observed before the deadline" + detail)

    def _assert_parking_file_current(self) -> DeviceFile:
        if self.parking_file is None:
            _fail("parking PDF authority has not been retained")
        current = self.device.stat_file(PARKING_PDF)
        if (current is None or not self.parking_file.same_object(current) or
                current.size != self.parking_file.size or
                current.sha256 != SOURCE_PDF_SHA256):
            _fail("persistent parking PDF identity changed")
        if self.device.stat_file(PARKING_MARK, absent_ok=True) is not None:
            _fail("persistent parking PDF unexpectedly has a .mark sidecar")
        return current

    def _assert_idle_document_fds(self, pid: int) -> frozenset[str]:
        targets = _document_file_targets(self.device.process_fd_links(pid))
        if targets not in (frozenset(), frozenset((PARKING_PDF,))):
            _fail("idle stock Document retains a non-parking PDF/mark")
        if targets:
            self._assert_parking_file_current()
        return targets

    def _assert_source_files_current(self) -> None:
        sources = (
            (SOURCE_PDF, self.source_pdf_file, SOURCE_PDF_SHA256),
            (SOURCE_MARK, self.source_mark_file, SOURCE_MARK_SHA256),
        )
        for path, retained, expected in sources:
            current = self.device.stat_file(path)
            if (retained is None or current is None or
                    not retained.same_object(current) or
                    retained.size != current.size or current.sha256 != expected):
                _fail("pinned source identity changed: " + path)

    def _final_revalidate_source_and_parking(self) -> None:
        """Set report tri-states only from fresh final observations."""
        errors: list[str] = []
        if self.source_pdf_file is not None or self.source_mark_file is not None:
            try:
                current_pdf = self.device.stat_file(SOURCE_PDF)
                current_mark = self.device.stat_file(SOURCE_MARK)
            except BaseException as error:
                self.source_fixture_unchanged = None
                errors.append("source identity revalidation is ambiguous: " +
                              str(error))
            else:
                source_ok = (
                    self.source_pdf_file is not None and
                    self.source_mark_file is not None and
                    current_pdf is not None and current_mark is not None and
                    self.source_pdf_file.same_object(current_pdf) and
                    self.source_mark_file.same_object(current_mark) and
                    self.source_pdf_file.size == current_pdf.size and
                    self.source_mark_file.size == current_mark.size and
                    current_pdf.sha256 == SOURCE_PDF_SHA256 and
                    current_mark.sha256 == SOURCE_MARK_SHA256)
                self.source_fixture_unchanged = source_ok
                if not source_ok:
                    errors.append("pinned source identity changed during alpha")
        if self.parking_file is not None:
            try:
                current_parking = self.device.stat_file(PARKING_PDF)
                current_mark = self.device.stat_file(
                    PARKING_MARK, absent_ok=True)
            except BaseException as error:
                self.parking_fixture_unchanged = None
                errors.append("parking identity revalidation is ambiguous: " +
                              str(error))
            else:
                parking_ok = (
                    current_parking is not None and current_mark is None and
                    self.parking_file.same_object(current_parking) and
                    self.parking_file.size == current_parking.size and
                    current_parking.sha256 == SOURCE_PDF_SHA256)
                self.parking_fixture_unchanged = parking_ok
                if not parking_ok:
                    errors.append("persistent parking identity changed during alpha")
        if errors:
            raise CleanupUncertain("; ".join(errors))

    def _assert_target_file_current(self, path: str) -> DeviceFile:
        if path not in {TARGET_PDF, TARGET_MARK}:
            _fail("target identity check escaped the disposable fixture")
        obligation = self.fixture_obligations.get(path)
        current = self.device.stat_file(path)
        if (obligation is None or obligation.retained is None or
                current is None or
                not obligation.retained.same_object(current) or
                obligation.retained.size != current.size or
                current.sha256 != obligation.expected_sha256):
            _fail("disposable target identity changed: " + path)
        return current

    def _assert_target_mark_before_parking(self) -> None:
        obligation = self.fixture_obligations.get(TARGET_MARK)
        if (obligation is None or obligation.retained is None or
                obligation.pre_copy_absence_sha256 is None or
                not obligation.copy_attempted or
                not obligation.copy_reply_proved or
                obligation.ownership_ambiguous):
            _fail("pre-parking target mark lacks exact staged-file ownership")
        current = self.device.stat_file(TARGET_MARK, absent_ok=True)
        if current is None:
            obligation.parking_absent_before_switch = True
            self._event("target_mark_absent_before_parking", path=TARGET_MARK)
            return
        if (not obligation.retained.same_object(current) or
                obligation.retained.size != current.size or
                current.sha256 != obligation.expected_sha256):
            _fail("target mark changed before authenticated parking switch")

    def _authorize_target_mark_after_parking(self) -> DeviceFile:
        """Admit at most one exact stock-save replacement at parking boundary."""
        if (not self.parking_switch_attempted or not self.close_started or
                not self.attached or self.foreign is None):
            _fail("target mark refresh lacks authenticated parking authority")
        obligation = self.fixture_obligations.get(TARGET_MARK)
        if (obligation is None or obligation.retained is None or
                obligation.pre_copy_absence_sha256 is None or
                not obligation.copy_attempted or
                not obligation.copy_reply_proved or
                obligation.ownership_ambiguous):
            _fail("target mark refresh lacks exact staged-file ownership")
        current = self.device.stat_file(TARGET_MARK)
        if (current is None or current.kind != "regular file" or
                self.source_mark_file is None or
                current.size != self.source_mark_file.size or
                current.sha256 != SOURCE_MARK_SHA256):
            _fail("stock parking save produced an ineligible target mark")
        if (obligation.retained.same_object(current) and
                (not obligation.parking_absent_before_switch or
                 obligation.parking_recreated_or_replaced)):
            if obligation.retained.size != current.size:
                _fail("target mark size changed without an identity change")
            return current
        if obligation.pre_parking_retained is not None:
            _fail("target mark changed more than once at the parking boundary")
        obligation.pre_parking_retained = obligation.retained
        obligation.retained = current
        obligation.parking_recreated_or_replaced = True
        self._event(
            "target_mark_recreated_or_replaced_at_parking",
            path=TARGET_MARK, size=current.size, sha256=current.sha256,
            absentBeforeSwitch=obligation.parking_absent_before_switch,
            previousInode=obligation.pre_parking_retained.inode,
            currentInode=current.inode,
        )
        return current

    def _provision_parking(self, source_pdf: DeviceFile) -> None:
        if self.parking_file is not None:
            _fail("parking PDF provisioning cannot be repeated")
        if (source_pdf.path != SOURCE_PDF or
                source_pdf.sha256 != SOURCE_PDF_SHA256):
            _fail("parking PDF provisioning lacks the pinned source")
        if self.mutation_journal_path is None:
            self._initialize_mutation_journal()
        self.parking_provisioning_reached = True
        self._journal_transition(
            "PARKING_PROVISIONING_REACHED", path=PARKING_PDF,
            markPath=PARKING_MARK)
        if self.device.stat_file(PARKING_MARK, absent_ok=True) is not None:
            _fail("parking .mark exists before alpha provisioning")
        current = self.device.stat_file(PARKING_PDF, absent_ok=True)
        copied = False
        copy_error: BaseException | None = None
        if current is None:
            copied = True
            self.parking_copy_attempted = True
            self._journal_transition(
                "PARKING_COPY_ATTEMPTED", source=SOURCE_PDF,
                target=PARKING_PDF, retryAllowed=False)
            try:
                self.device.copy_parking_pdf()
                self.parking_copy_reply_proved = True
            except BaseException as error:
                # Never retry this mutation.  A lost reply can be settled only
                # by the exact fixed path/hash proof below.
                copy_error = error
            current = self.device.stat_file(PARKING_PDF, absent_ok=True)
        if (current is None or current.kind != "regular file" or
                current.sha256 != SOURCE_PDF_SHA256):
            _fail("persistent parking PDF is absent or differs from its pin")
        if self.device.stat_file(PARKING_MARK, absent_ok=True) is not None:
            _fail("parking .mark appeared during provisioning")
        self.parking_file = current
        self.parking_provisioning_settled = True
        self._journal_transition(
            "PARKING_PROVISIONING_SETTLED", path=PARKING_PDF,
            copied=copied,
            copyTransportError=(None if copy_error is None else str(copy_error)),
            retained=asdict(current))
        self._event(
            "parking_pdf_verified", path=PARKING_PDF,
            sha256=current.sha256, copied=copied,
            copyTransportError=(None if copy_error is None else str(copy_error)),
        )

    def _preflight(self) -> None:
        if self.device.get_state() != "device":
            _fail("authorized Nomad is not online and ADB-authorized")
        if self.device.get_serial() != AUTHORIZED_SERIAL:
            _fail("ADB serial response differs from the authorized Nomad")
        if self.device.getprop("ro.product.model") != MODEL:
            _fail("connected model is not the pinned Nomad")
        if self.device.getprop("ro.build.version.sdk") != SDK:
            _fail("connected Android SDK differs from the pinned build")
        if self.device.getprop("ro.build.fingerprint") != FINGERPRINT:
            _fail("connected firmware fingerprint differs from the pinned build")
        if self.device.current_user() != "0":
            _fail("the exact owner user is not active")
        # Supernote's launcher is portrait-only even while the Nomad is held in
        # landscape.  Admit either strict physical-display presentation here;
        # after the orientation-responsive visual host is foreground, require
        # and retain the real starting landscape rotation before Document opens.
        orientation = _physical_orientation(self.device.window_displays())
        self.initial_orientation = orientation

        host_dump = self.device.package_dump(HOST_PACKAGE)
        _package_version(
            host_dump, HOST_VERSION_CODE, HOST_VERSION_NAME, "visual host")
        host_apk = self.device.package_path(HOST_PACKAGE)
        if self.device.sha256_file(host_apk) != self.host_artifact.signed_apk_sha256:
            _fail("installed visual host APK hash differs")

        document_dump = self.device.package_dump(DOCUMENT_PACKAGE)
        _package_version(
            document_dump, DOCUMENT_VERSION_CODE, DOCUMENT_VERSION_NAME,
            "stock Document")
        if self.device.package_path(DOCUMENT_PACKAGE) != DOCUMENT_APK:
            _fail("stock Document APK path differs")
        document_stat = self.device.stat_file(DOCUMENT_APK)
        if (document_stat is None or document_stat.size != DOCUMENT_APK_SIZE or
                document_stat.sha256 != DOCUMENT_APK_SHA256):
            _fail("stock Document APK identity differs")

        activities = self.device.activities()
        windows = self.device.windows()
        displays = self.device.displays()
        if (_contains_document_task_or_window(activities) or
                _contains_document_task_or_window(windows)):
            _fail("close the stock Document task before starting the alpha")
        if (_contains_component(activities, _host_components()) or
                _contains_component(windows, _host_components())):
            _fail("a visual host task already exists; no guessed recovery is allowed")
        if (BOOX_PACKAGE in _decode_text(activities, "activity inventory") or
                BOOX_PACKAGE in _decode_text(windows, "window inventory")):
            _fail("close the BOOX planner task before starting the native-page alpha")
        if "NativePageVisualOnly-" in _decode_text(displays, "display inventory"):
            _fail("a prior visual-host display exists; no guessed recovery is allowed")
        if self.device.pidof(HOST_PACKAGE):
            _fail("a visual-host process already exists; no guessed recovery is allowed")
        source_pdf = self.device.stat_file(SOURCE_PDF)
        source_mark = self.device.stat_file(SOURCE_MARK)
        if (source_pdf is None or source_pdf.sha256 != SOURCE_PDF_SHA256 or
                source_mark is None or source_mark.sha256 != SOURCE_MARK_SHA256):
            _fail("pinned stock fixture PDF/mark identity differs")
        self.source_pdf_file = source_pdf
        self.source_mark_file = source_mark
        self._provision_parking(source_pdf)
        document_pids = self.device.pidof(DOCUMENT_PACKAGE)
        if len(document_pids) > 1:
            _fail("stock Document processes are ambiguous before launch")
        if document_pids:
            self.device.process_identity(document_pids[0], DOCUMENT_PACKAGE)
            self._assert_idle_document_fds(document_pids[0])
        if (self.device.stat_file(TARGET_PDF, absent_ok=True) is not None or
                self.device.stat_file(TARGET_MARK, absent_ok=True) is not None):
            _fail("fixed disposable Download fixture already exists")
        self._event("preflight_complete", initialOrientation=orientation,
                    hostApkSha256=self.host_artifact.signed_apk_sha256,
                    documentApkSha256=DOCUMENT_APK_SHA256)

    def _publish_staged_fixture(self, obligation: FixtureObligation) -> None:
        retained = obligation.staging_retained
        if retained is None:
            _fail("fixture publication lacks retained staging authority")
        try:
            staging_now = self.device.stat_file(obligation.staging_path)
            target_now = self.device.stat_file(
                obligation.target, absent_ok=True)
        except BaseException:
            obligation.staging_ownership_ambiguous = True
            obligation.ownership_ambiguous = True
            raise
        if (staging_now is None or not retained.same_object(staging_now) or
                staging_now.size != retained.size or
                staging_now.sha256 != obligation.expected_sha256):
            obligation.staging_ownership_ambiguous = True
            _fail("staging identity changed before fixture publication: " +
                  obligation.staging_path)
        if target_now is not None:
            obligation.ownership_ambiguous = True
            _fail("fixed disposable target appeared before publication: " +
                  obligation.target)

        obligation.publish_move_attempted = True
        self._journal_transition(
            "FIXTURE_PUBLISH_ATTEMPTED", source=obligation.staging_path,
            target=obligation.target, retryAllowed=False)
        move_error: BaseException | None = None
        try:
            self.device.publish_fixture_member(
                obligation.staging_path, obligation.target)
            obligation.publish_move_reply_proved = True
        except BaseException as error:
            obligation.publish_move_transport_error = str(error)
            move_error = error
        try:
            staging_after = self.device.stat_file(
                obligation.staging_path, absent_ok=True)
            target_after = self.device.stat_file(
                obligation.target, absent_ok=True)
        except BaseException as error:
            obligation.staging_ownership_ambiguous = True
            obligation.ownership_ambiguous = True
            self._journal_transition(
                "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS",
                source=obligation.staging_path, target=obligation.target,
                error=str(error))
            raise AlphaError(
                "fixture publication postconditions are ambiguous: " +
                obligation.target) from error
        obligation.publish_move_source_observed = staging_after
        obligation.publish_move_target_observed = target_after
        obligation.publish_move_postcondition = (
            ("stage-present" if staging_after is not None else "stage-absent") +
            "/" +
            ("target-present" if target_after is not None else "target-absent"))
        if (staging_after is None and target_after is not None and
                retained.same_renamed_object(target_after) and
                target_after.path == obligation.target and
                target_after.sha256 == obligation.expected_sha256):
            obligation.retained = target_after
            obligation.publish_move_postcondition = "stage-absent/target-exact"
            self._journal_transition(
                "FIXTURE_PUBLISH_SETTLED", source=obligation.staging_path,
                target=obligation.target, retained=asdict(target_after),
                moveReplyProved=obligation.publish_move_reply_proved,
                moveTransportError=obligation.publish_move_transport_error)
            self._event(
                "fixture_published", source=obligation.source,
                staging=obligation.staging_path, target=obligation.target,
                inode=target_after.inode, device=target_after.device,
                sha256=target_after.sha256,
                moveReplyProved=obligation.publish_move_reply_proved,
                moveTransportError=obligation.publish_move_transport_error,
                retryUsed=False)
            return

        if (staging_after is not None and
                not retained.same_object(staging_after)):
            obligation.staging_ownership_ambiguous = True
        if target_after is not None:
            obligation.ownership_ambiguous = True
        detail = "fixture publication did not settle to stage-absent/target-exact"
        if target_after is not None and not retained.same_renamed_object(
                target_after):
            detail = "fixed target contains a different object and will be preserved"
        elif move_error is not None:
            detail = "fixture publication reply and postconditions are uncertain"
        self._journal_transition(
            "FIXTURE_PUBLISH_UNSETTLED", source=obligation.staging_path,
            target=obligation.target,
            postcondition=obligation.publish_move_postcondition,
            detail=detail)
        raise AlphaError(detail + ": " + obligation.target)

    def _stage_fixture(self) -> None:
        members = (
                (SOURCE_PDF, TARGET_PDF, SOURCE_PDF_SHA256),
                (SOURCE_MARK, TARGET_MARK, SOURCE_MARK_SHA256))
        if (self.mutation_journal_path is None or
                set(self.fixture_obligations) != {TARGET_PDF, TARGET_MARK} or
                any(value.copy_attempted or value.retained is not None
                    for value in self.fixture_obligations.values())):
            _fail("fixture staging lacks fresh durable mutation authority")

        # Prove both names absent only after both obligations exist. If even
        # the first observation is ambiguous, cleanup/report still carries the
        # complete target topology and can never claim diagnostic-clean.
        for obligation in self.fixture_obligations.values():
            try:
                current = self.device.stat_file(
                    obligation.target, absent_ok=True)
            except BaseException:
                obligation.ownership_ambiguous = True
                raise
            if current is not None:
                obligation.ownership_ambiguous = True
                _fail("disposable fixture target appeared before copy: " +
                      obligation.target)
            obligation.pre_copy_absence_sha256 = _canonical_sha({
                "authority": AUTHORITY,
                "kind": "pre-copy-target-absence",
                "source": obligation.source,
                "target": obligation.target,
                "expectedSha256": obligation.expected_sha256,
            })
            for observation in range(2):
                try:
                    staging = self.device.stat_file(
                        obligation.staging_path, absent_ok=True)
                except BaseException:
                    obligation.staging_ownership_ambiguous = True
                    raise
                if staging is not None:
                    obligation.staging_preexisting_observed = staging
                    obligation.staging_ownership_ambiguous = True
                    _fail("random staging leaf already exists and will not be touched: " +
                          obligation.staging_path)
                if observation == 0:
                    self.sleep(POLL_SECONDS)
            obligation.staging_pre_absence_sha256 = _canonical_sha({
                "authority": AUTHORITY,
                "kind": "pre-copy-staging-absence",
                "source": obligation.source,
                "target": obligation.target,
                "staging": obligation.staging_path,
                "expectedSha256": obligation.expected_sha256,
                "observations": 2,
            })

        for source, target, expected in members:
            obligation = self.fixture_obligations[target]
            # Narrow both observation-to-copy edges. A staged or fixed name that
            # appears here is unowned and is neither overwritten nor deleted.
            try:
                current = self.device.stat_file(target, absent_ok=True)
                staging = self.device.stat_file(
                    obligation.staging_path, absent_ok=True)
            except BaseException:
                obligation.ownership_ambiguous = True
                obligation.staging_ownership_ambiguous = True
                raise
            if current is not None:
                obligation.ownership_ambiguous = True
                _fail("disposable fixture target appeared at copy dispatch: " +
                      target)
            if staging is not None:
                obligation.staging_preexisting_observed = staging
                obligation.staging_ownership_ambiguous = True
                _fail("random staging leaf appeared at copy dispatch: " +
                      obligation.staging_path)
            obligation.copy_attempted = True
            self._journal_transition(
                "FIXTURE_COPY_ATTEMPTED", source=source, target=target,
                staging=obligation.staging_path, retryAllowed=False)
            try:
                self.device.copy_fixture_member(source, obligation.staging_path)
                obligation.copy_reply_proved = True
            except BaseException:
                # Missing/ambiguous receipt includes a zero-exit `cp -n` skip.
                # Even byte-identical content at the random path is unowned and
                # must never be published or deleted by this run.
                obligation.staging_ownership_ambiguous = True
                raise
            try:
                value = self.device.stat_file(obligation.staging_path)
            except BaseException:
                obligation.staging_ownership_ambiguous = True
                raise
            obligation.staging_post_copy_observed = value
            source_retained = (
                self.source_pdf_file if source == SOURCE_PDF else
                self.source_mark_file)
            if (value is None or source_retained is None or
                    value.kind != "regular file" or
                    value.size != source_retained.size or
                    value.sha256 != expected):
                obligation.staging_ownership_ambiguous = True
                _fail("disposable staging copy identity differs: " +
                      obligation.staging_path)
            obligation.staging_retained = value
            self._journal_transition(
                "FIXTURE_COPY_SETTLED", source=source, target=target,
                staging=obligation.staging_path, retained=asdict(value))
            self._publish_staged_fixture(obligation)
        self._journal_transition(
            "FIXTURE_STAGED", uri=TARGET_URI,
            pdfSha256=SOURCE_PDF_SHA256, markSha256=SOURCE_MARK_SHA256)
        self._event("fixture_staged", uri=TARGET_URI,
                    pdfSha256=SOURCE_PDF_SHA256,
                    markSha256=SOURCE_MARK_SHA256)

    def _read_status(self) -> HostStatus:
        value = parse_host_status(self.device.ui_dump())
        if self.status is not None and (
                value.session, value.generation, value.display_id) != (
                    self.status.session, self.status.generation,
                    self.status.display_id):
            _fail("host status identity drifted")
        return value

    def _wait_status(self, states: set[str], seconds: float = STEP_TIMEOUT_SECONDS) -> HostStatus:
        def observe() -> HostStatus | None:
            value = self._read_status()
            if value.state == "FAILED":
                raise AlphaError("visual host entered sticky FAILED state")
            return value if value.state in states else None
        return self._until("host state " + "/".join(sorted(states)), seconds, observe)

    def _start_host(self) -> None:
        self.host_start_attempted = True
        self.device.start_host()

        def observe_fresh_host() -> HostStatus | None:
            value = self._read_status()
            # Retain the first allocated identity even before readiness, so a
            # timeout still has a bounded session/display cleanup target.
            self.status = value
            if value.state == "DISPLAY_ALLOCATED":
                return None
            if value.state != "WAITING_FOR_FOREIGN_ATTACH":
                _fail("fresh host entered an ineligible pre-attach state")
            return value

        self.status = self._until(
            "fresh visual-host WAITING_FOR_FOREIGN_ATTACH status",
            HOST_START_TIMEOUT_SECONDS, observe_fresh_host)
        if not _virtual_display_present(self.device.displays(), self.status):
            _fail("exact session/generation display name is not present")
        pids = self.device.pidof(HOST_PACKAGE)
        if len(pids) != 1:
            _fail("visual host process is absent or ambiguous")
        process = self.device.process_identity(pids[0], HOST_PACKAGE)
        if process.uid < 10_000:
            _fail("visual host does not run under an ordinary app UID")
        self.host_pid = process.pid
        logs = self.device.host_logs(process.pid)
        if (not _host_event_present(logs, self.status, "DISPLAY_READY",
                                    (f"display={self.status.display_id}",
                                     "readiness=WAITING_FOR_FOREIGN_ACK")) or
                _host_failure(logs, self.status) is not None):
            _fail("fresh DISPLAY_READY event is absent or contradicted")
        self._event("host_ready", session=self.status.session,
                    generation=self.status.generation,
                    displayId=self.status.display_id,
                    hostPid=process.pid, hostStartTicks=str(process.start_ticks))

    def _wait_starting_landscape(self) -> int:
        """Record the first landscape presentation after foreign attachment.

        The stock launcher remains portrait-only.  The host and fixed virtual
        display therefore start safely in portrait, the disposable Document
        task is authenticated and attached, and only then does this already
        supported host rotation path wait for the physical sensor.  Attaching
        first avoids spending the host's bounded pre-attach watchdog on a human
        rotation while the virtual Document display itself stays 1404x1872.
        """
        if (self.status is None or self.foreign is None or
                not self.attached):
            _fail("starting-landscape gate lacks attached foreign authority")

        def observe() -> int | None:
            orientation = _physical_orientation(self.device.window_displays())
            return orientation if orientation in (1, 3) else None

        mode = ("manual" if
                self.rotation_authority == ROTATION_MANUAL_PHYSICAL else
                "externally controlled ADB")
        orientation = self._until(
            mode + " starting landscape orientation",
            MANUAL_ROTATION_TIMEOUT_SECONDS, observe)
        self.status = self._wait_status({"ACTIVE"})
        self._reverify_foreign()
        self.starting_orientation = orientation
        if self.rotation_authority == ROTATION_MANUAL_PHYSICAL:
            self._event(
                "physical_orientation_observed", orientation=orientation,
                expected="starting landscape", phase="post_attach")
        else:
            self._event(
                "adb_rotation_orientation_observed", orientation=orientation,
                expected="starting landscape", phase="post_attach",
                rotationAuthority=self.rotation_authority)
        return orientation

    def _prove_prelaunch_absence(self) -> str:
        if self.status is None:
            _fail("prelaunch absence lacks the retained host display")
        activities = self.device.activities()
        windows = self.device.windows()
        _assert_owned_display_empty(activities, self.status)
        _assert_owned_display_windows_empty(windows, self.status)
        if (_contains_document_task_or_window(activities) or
                _contains_document_task_or_window(windows)):
            _fail("a Document task/window appeared before exact launch dispatch")
        pids = self.device.pidof(DOCUMENT_PACKAGE)
        if len(pids) > 1:
            _fail("Document process scope is ambiguous immediately before launch")
        process: host.ProcessIdentity | None = None
        idle_targets: frozenset[str] = frozenset()
        if pids:
            process = self.device.process_identity(pids[0], DOCUMENT_PACKAGE)
            idle_targets = self._assert_idle_document_fds(pids[0])
        parking = self._assert_parking_file_current()
        fixture: dict[str, dict[str, Any]] = {}
        for target in (TARGET_PDF, TARGET_MARK):
            obligation = self.fixture_obligations.get(target)
            if (obligation is None or obligation.retained is None or
                    obligation.pre_copy_absence_sha256 is None or
                    not obligation.copy_reply_proved or
                    obligation.ownership_ambiguous):
                _fail("prelaunch fixture ownership is absent or ambiguous")
            current = self.device.stat_file(target)
            if (current is None or not obligation.retained.same_object(current) or
                    current.sha256 != obligation.expected_sha256):
                _fail("staged fixture identity changed before launch")
            fixture[target] = asdict(current)
        digest = _canonical_sha({
            "authority": AUTHORITY,
            "kind": "immediate-prelaunch-absence",
            "session": self.status.session,
            "generation": self.status.generation,
            "displayId": self.status.display_id,
            "activitySha256": _sha(activities),
            "windowSha256": _sha(windows),
            "baselineDocumentProcess": (
                None if process is None else asdict(process)),
            "baselineDocumentFileTargets": sorted(idle_targets),
            "parking": asdict(parking),
            "fixture": fixture,
        })
        self.prelaunch_absence_sha256 = digest
        self._event("prelaunch_absence_retained", evidenceSha256=digest)
        return digest

    def _capture_foreign(
            self, *, require_fd: bool = True,
            ) -> tuple[host.ForeignIdentity, android.DocumentTaskAuthority]:
        if self.status is None:
            _fail("foreign capture lacks a retained host display")
        pids = self.device.pidof(DOCUMENT_PACKAGE)
        if len(pids) != 1:
            _fail("stock Document process is absent or ambiguous")
        process_before = self.device.process_identity(pids[0], DOCUMENT_PACKAGE)
        raw = self.device.activities()
        authority = android.parse_document_task_authority(
            raw, expected_pid=process_before.pid, require_live=True)
        if (authority.display_id != self.status.display_id or
                authority.stack_id != authority.task_id or
                (authority.width, authority.height, authority.density_dpi,
                 authority.rotation) != (1404, 1872, 300, 0) or
                authority.base_apk_path != DOCUMENT_APK):
            _fail("strict Document task authority differs from the alpha viewport")
        task_block = self._assert_exact_stack_scope(raw, authority)
        self._assert_exact_fixture_intent(task_block)
        evidence = android.stable_authority_sha256(authority)
        foreign = host.ForeignIdentity(
            process_before, authority.task_id, authority.activity_token,
            evidence, DOCUMENT_COMPONENT)
        if self.unowned_foreign_candidate is None:
            self.unowned_foreign_candidate = foreign
        self._assert_parking_file_current()
        if require_fd:
            self._assert_exact_fixture_fds(process_before.pid)
        process_after = self.device.process_identity(pids[0], DOCUMENT_PACKAGE)
        if process_before != process_after:
            _fail("stock Document process identity changed during capture")
        if require_fd:
            if (not self.document_launch_attempted or
                    self.prelaunch_absence_sha256 is None):
                _fail("foreign task lacks immediate prelaunch absence ownership")
            if self.foreign is None:
                self.foreign = foreign
                self.foreign_authority = authority
                self.launch_owned = True
                self._event("foreign_launch_ownership_retained",
                            taskId=foreign.task_id, pid=foreign.process.pid,
                            prelaunchAbsenceSha256=self.prelaunch_absence_sha256)
            elif (foreign != self.foreign or self.foreign_authority is None or
                    not android.stable_authority(
                        self.foreign_authority, authority)):
                _fail("retained Document launch ownership drifted")
            self.foreign_fixture_bound = True
        elif (self.foreign is None or not self.launch_owned or
                foreign != self.foreign or self.foreign_authority is None or
                not android.stable_authority(self.foreign_authority, authority)):
            _fail("cleanup revalidation cannot create or alter launch ownership")
        return foreign, authority

    @staticmethod
    def _assert_exact_stack_scope(
            raw: bytes, authority: android.DocumentTaskAuthority) -> str:
        """Bind Android 11's root-task removal to one exact child task.

        ``am stack remove`` calls ``removeTask(rootTaskId)`` on this firmware.
        The public strict parser proves the selected task identity; these same-
        checkpoint structural helpers additionally prove that the selected
        root task has no second child that could be removed with it.
        """
        text, _ = android._wire(raw)  # type: ignore[attr-defined]
        text = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            text)
        display_stacks = [
            (display_id, stack_id, block)
            for display_id, stack_id, block
            in android._display_stack_blocks(text)  # type: ignore[attr-defined]
            if display_id == authority.display_id
        ]
        if (len(display_stacks) != 1 or
                display_stacks[0][1] != authority.stack_id):
            _fail("owned display does not contain exactly the retained root task")
        display_id, stack_id, block = display_stacks[0]
        task_headers = list(re.finditer(
            r"^    \* Task\{[^\n]*\}$", block, re.MULTILINE))
        if len(task_headers) != 1:
            _fail("root-task removal scope is not one exact Document child task")

        # Android 11 appends this parent-level resume summary after the final
        # task on the pinned firmware.  It is not a child of the selected root
        # task.  Only recognize its exact framing after the one task; same-
        # indentation stack fields before the task remain in the checked scope.
        postamble_header = (
            "  Resumed activities in task display areas (from top to bottom):\n")
        lines = block.splitlines(keepends=True)
        postamble_indexes = [
            index for index, line in enumerate(lines)
            if line == postamble_header
        ]
        task_line_index = block[:task_headers[0].start()].count("\n")
        post_task_parent_lines = [
            index for index, line in enumerate(lines[task_line_index + 1:],
                                               task_line_index + 1)
            if line.strip() and len(line) - len(line.lstrip(" ")) < 4
        ]
        if postamble_indexes:
            if (len(postamble_indexes) != 1 or
                    postamble_indexes[0] not in post_task_parent_lines):
                _fail("root-task parent resume postamble is malformed")
            postamble_index = postamble_indexes[0]
            if post_task_parent_lines != [postamble_index,
                                          postamble_index + 3]:
                _fail("root-task parent resume postamble is malformed")
            postamble = lines[postamble_index:]
            document_components = "|".join(
                re.escape(value) for value in _document_components())
            host_components = "|".join(
                re.escape(value) for value in _host_components())
            document_resume = re.fullmatch(
                r"    Resumed: ActivityRecord\{([0-9a-f]+) u0 (?:" +
                document_components + r") t([0-9]+)\}\n",
                postamble[1] if len(postamble) > 1 else "")
            host_resume = re.fullmatch(
                r"  ResumedActivity: ActivityRecord\{[0-9a-f]+ u0 (?:" +
                host_components + r") t([0-9]+)\}\n",
                postamble[3] if len(postamble) > 3 else "")
            if (len(postamble) != 5 or postamble[2] != "\n" or
                    postamble[4] != "\n" or document_resume is None or
                    document_resume.group(1) != authority.activity_token or
                    document_resume.group(2) != str(authority.task_id) or
                    host_resume is None or
                    not 0 <= int(host_resume.group(1)) <= MAX_ID or
                    int(host_resume.group(1)) == authority.task_id):
                _fail("root-task parent resume postamble is malformed")
            block = "".join(lines[:postamble_index])
        elif post_task_parent_lines:
            _fail("root-task parent resume postamble is malformed")

        tasks = android._task_blocks(block)  # type: ignore[attr-defined]
        if (display_id != authority.display_id or stack_id != authority.task_id or
                len(tasks) != 1 or
                not any(component in tasks[0] for component in _document_components()) or
                any(component in block for component in _host_components())):
            _fail("root-task removal scope is not one exact Document child task")

        return tasks[0]

    @staticmethod
    def _assert_exact_fixture_intent(task_block: str) -> None:
        AlphaSession._assert_exact_document_intent(task_block, "fixture")

    @staticmethod
    def _assert_exact_document_intent(task_block: str, binding: str) -> None:
        # The explicit launch must remain the activity's retained ACTION_VIEW
        # intent.  Parse one envelope so fields elsewhere in the task cannot be
        # borrowed to manufacture authority for a vendor fallback document.
        if binding != "fixture":
            _fail("Document intent binding escaped the closed authority set")
        expected_uri = TARGET_URI
        if type(task_block) is not str or "\r" in task_block:
            _fail("Document task retained intent framing is malformed")
        candidates = list(re.finditer(
            r"^[ \t]*intent[ \t]*=", task_block,
            re.MULTILINE | re.IGNORECASE,
        ))
        openers = list(re.finditer(
            r"^[ \t]*intent=\{", task_block, re.MULTILINE,
        ))
        if (len(candidates) != 1 or len(openers) != 1 or
                candidates[0].start() != openers[0].start()):
            _fail("Document task does not retain one exact ACTION_VIEW intent")

        opening = openers[0].end() - 1
        closing: int | None = None
        for offset in range(opening + 1, len(task_block)):
            character = task_block[offset]
            if character == "{":
                _fail("Document task retained intent envelope is nested")
            if character == "}":
                closing = offset
                break
        if closing is None:
            _fail("Document task retained intent envelope is unbalanced")
        line_end = task_block.find("\n", closing + 1)
        if line_end < 0:
            line_end = len(task_block)
        if task_block[closing + 1:line_end].strip(" \t"):
            _fail("Document task retained intent has trailing line content")

        payload = task_block[opening + 1:closing]
        encoded_size = len(payload.encode("utf-8"))
        if (not payload or payload != payload.strip(" \t\n") or
                encoded_size > 4096 or payload.count("\n") > 16 or
                re.search(r"[ \t\n]{257,}", payload) is not None):
            _fail("Document task retained intent payload is malformed")
        tokens = re.split(r"[ \t\n]+", payload)
        if not 1 <= len(tokens) <= 64:
            _fail("Document task retained intent field count is outside bounds")
        fields: dict[str, str] = {}
        for token in tokens:
            match = re.fullmatch(
                r"([A-Za-z][A-Za-z0-9_]*)=([^\s={}]+)", token)
            if match is None or match.group(1) in fields:
                _fail("Document task retained intent fields are malformed or duplicated")
            fields[match.group(1)] = match.group(2)
        if (
            fields.get("act") != DOCUMENT_LAUNCH_ACTION or
            fields.get("dat") != expected_uri or
            fields.get("typ") != DOCUMENT_LAUNCH_MIME or
            fields.get("cmp") not in _document_components()
        ):
            _fail("Document task does not retain the exact " + binding +
                  " ACTION_VIEW intent")

    def _assert_exact_fixture_fds(self, pid: int) -> None:
        targets = _document_file_targets(self.device.process_fd_links(pid))
        if TARGET_PDF not in targets or not targets.issubset(
                {TARGET_PDF, TARGET_MARK}):
            _fail("Document process PDF/mark descriptors escape the alpha fixture")

    def _assert_exact_fixture_binding(self, task_block: str, pid: int) -> None:
        self._assert_exact_fixture_intent(task_block)
        self._assert_exact_fixture_fds(pid)

    def _assert_exact_parking_fds(self, pid: int) -> None:
        targets = _document_file_targets(self.device.process_fd_links(pid))
        if targets != frozenset((PARKING_PDF,)):
            _fail("Document process does not retain only the exact parking PDF")

    def _capture_parked_foreign(
            self,
            ) -> tuple[host.ForeignIdentity, android.DocumentTaskAuthority]:
        if (self.status is None or self.foreign is None or
                self.foreign_authority is None or
                not self.parking_switch_attempted):
            _fail("parking capture lacks retained switch authority")
        pids = self.device.pidof(DOCUMENT_PACKAGE)
        if pids != (self.foreign.process.pid,):
            _fail("stock Document process changed during parking switch")
        process_before = self.device.process_identity(
            pids[0], DOCUMENT_PACKAGE)
        if process_before != self.foreign.process:
            _fail("stock Document PID/starttime changed during parking switch")
        raw = self.device.activities()
        authority = android.parse_document_task_authority(
            raw, expected_pid=process_before.pid, require_live=True)
        if (authority.display_id != self.status.display_id or
                authority.stack_id != authority.task_id or
                (authority.width, authority.height, authority.density_dpi,
                 authority.rotation) != (1404, 1872, 300, 0) or
                authority.base_apk_path != DOCUMENT_APK):
            _fail("parked Document authority differs from the owned viewport")
        task_block = self._assert_exact_stack_scope(raw, authority)
        # Firmware 1.02.446 delivers the new ACTION_VIEW to the same activity
        # without rewriting either retained task/activity intent.  The stale
        # original intent is therefore continuity evidence only; the exact
        # parking command, UI witness, and FD authority below prove the switch.
        self._assert_exact_fixture_intent(task_block)
        fresh = host.ForeignIdentity(
            process_before, authority.task_id, authority.activity_token,
            android.stable_authority_sha256(authority), DOCUMENT_COMPONENT)
        if (fresh != self.foreign or
                not android.stable_authority(self.foreign_authority, authority)):
            _fail("parking switch recreated, moved, or replaced the owned task")
        self._assert_exact_parking_fds(process_before.pid)
        self.parking_ui_witness = parse_parking_ui_witness(
            self.device.ui_dump())
        self._assert_parking_file_current()
        self._assert_source_files_current()
        self._assert_target_file_current(TARGET_PDF)
        self._authorize_target_mark_after_parking()
        process_after = self.device.process_identity(
            pids[0], DOCUMENT_PACKAGE)
        if process_after != process_before:
            _fail("stock Document process changed during parking capture")
        self.parking_bound = True
        self.cleanup["documentParked"] = True
        return fresh, authority

    def _reverify_parked_foreign(self) -> None:
        fresh, authority = self._capture_parked_foreign()
        if (self.foreign is None or self.foreign_authority is None or
                fresh != self.foreign or
                not android.stable_authority(self.foreign_authority, authority)):
            _fail("retained parked Document identity drifted")

    def _park_document(self) -> None:
        if self.foreign is None:
            return
        if (not self.attached or not self.close_started or
                not self.foreign_fixture_bound or not self.launch_owned or
                self.status is None):
            raise CleanupUncertain(
                "parking switch lacks the authenticated owned close state")
        dispatch: CommandResult | None = None
        dispatch_error: BaseException | None = None
        if not self.parking_switch_attempted:
            # BEGIN_CLOSE is authenticated, but the owned target task must
            # still be exactly present before the sole parking mutation.
            self._reverify_foreign(require_fd=False)
            self._assert_parking_file_current()
            self._assert_source_files_current()
            self._assert_target_file_current(TARGET_PDF)
            self._assert_target_mark_before_parking()
            self.parking_switch_attempted = True
            try:
                dispatch = self.device.launch_parking_document(
                    self.status.display_id)
            except BaseException as error:
                # Never retry.  A lost reply is settled from fresh retained
                # task/process/intent/FD authority below.
                dispatch_error = error

        def observe() -> bool | None:
            try:
                self._capture_parked_foreign()
                return True
            except (AlphaError, android.AndroidAuthorityError):
                return None

        try:
            self._until(
                "same owned Document task bound to parking PDF",
                STEP_TIMEOUT_SECONDS, observe)
        except AlphaError as error:
            raise CleanupUncertain(
                "parking launch was attempted once but exact binding is uncertain") from error
        self._event(
            "document_parked", taskId=self.foreign.task_id,
            displayId=self.status.display_id,
            parkingUri=PARKING_URI,
            launchReturncode=(None if dispatch is None else dispatch.returncode),
            launchTransportError=(None if dispatch_error is None
                                  else str(dispatch_error)),
            retainedIntent="stale-original-target-by-firmware",
            uiWitness=self.parking_ui_witness,
            retryUsed=False,
        )

    def _launch_foreign(self) -> None:
        if self.status is None:
            _fail("document launch lacks an exact display")
        self._prove_prelaunch_absence()
        self.document_launch_attempted = True
        dispatch: CommandResult | None = None
        dispatch_error: BaseException | None = None
        try:
            dispatch = self.device.launch_document(self.status.display_id)
        except BaseException as error:
            # A transport timeout is not proof that ActivityTaskManager did not
            # dispatch.  Continue with read-only exact-identity collection.
            dispatch_error = error

        def observe() -> tuple[host.ForeignIdentity, android.DocumentTaskAuthority] | None:
            try:
                return self._capture_foreign()
            except (AlphaError, android.AndroidAuthorityError) as error:
                self.last_foreign_capture_error = _bounded_observation_error(error)
                return None

        try:
            foreign, authority = self._until(
                "strict foreign task identity", STEP_TIMEOUT_SECONDS, observe)
        except AlphaError as error:
            first, second = self.device.activities(), self.device.activities()
            no_document_scope = (
                not _contains_document_task_or_window(first) and
                not _contains_document_task_or_window(second))
            if (dispatch is not None and dispatch.returncode != 0 and
                    no_document_scope):
                raise AlphaError("exact Document launch was not created") from error
            if dispatch_error is not None and no_document_scope:
                raise AlphaError(
                    "Document launch transport failed and two observations prove no task") from dispatch_error
            raise CleanupUncertain(
                "Document launch may have occurred but no exact task identity was derivable; "
                "no guessed task cleanup was attempted") from error
        self.foreign, self.foreign_authority = foreign, authority
        self.foreign_fixture_bound = True
        self.launch_owned = True
        self._event("foreign_retained", taskId=foreign.task_id,
                    pid=foreign.process.pid,
                    startTicks=str(foreign.process.start_ticks),
                    taskAuthoritySha256=foreign.evidence_sha256,
                    launchReturncode=(None if dispatch is None else dispatch.returncode),
                    launchTransportError=(None if dispatch_error is None
                                          else str(dispatch_error)))

    def _send(self, action: str, *, foreign: host.ForeignIdentity | None = None,
              absence: str | None = None) -> CommandResult:
        if self.status is None:
            _fail("host command lacks exact session authority")
        if self.pending_host_command is not None:
            _fail("a prior host command sequence is not independently settled")
        self.sequence += 1
        self.pending_host_command = (action, self.sequence)
        return self.device.send_host(
            self.status, self.sequence, action, foreign=foreign,
            absence_sha256=absence)

    def _settle_host_command(self, action: str) -> None:
        if self.pending_host_command != (action, self.sequence):
            _fail("host command settlement does not match the attempted envelope")
        self.pending_host_command = None

    def _wait_event(self, kind: str, required: Sequence[str],
                    seconds: float = STEP_TIMEOUT_SECONDS) -> str:
        if self.status is None or self.host_pid is None:
            _fail("host event wait lacks retained identity")

        def observe() -> str | None:
            logs = self.device.host_logs(self.host_pid)
            failure = _host_failure(logs, self.status)
            if failure is not None:
                raise AlphaError("host failure: " + failure)
            return logs if _host_event_present(
                logs, self.status, kind, required) else None
        return self._until("host event " + kind, seconds, observe)

    def _attach(self) -> None:
        if self.foreign is None or not self.foreign_fixture_bound:
            _fail("attach lacks exact fixture-bound foreign identity")
        self.attach_command_attempted = True
        result: CommandResult | None = None
        transport_error: BaseException | None = None
        try:
            result = self._send(ACTION_ATTACH, foreign=self.foreign)
        except BaseException as error:
            transport_error = error
        try:
            self.status = self._wait_status({"ACTIVE"})
            self._wait_event("READY", (
                f"foreignTask={self.foreign.task_id}",
                f"foreignPid={self.foreign.process.pid}",
                "readiness=ACTIVE",
            ))
            self._settle_host_command(ACTION_ATTACH)
            self.attached = True
        except BaseException as error:
            if transport_error is not None:
                raise CleanupUncertain(
                    "attach transport and authenticated settlement are uncertain") from error
            raise
        if result is not None and result.returncode != 0:
            self._event("attach_transport_nonzero_but_acknowledged",
                        returncode=result.returncode)
        if transport_error is not None:
            self._event("attach_transport_error_but_acknowledged",
                        error=str(transport_error))
        self._event("foreign_attached", sequence=self.sequence)

    def _reverify_foreign(self, *, require_fd: bool = True) -> None:
        if self.foreign is None or self.foreign_authority is None:
            _fail("foreign revalidation lacks retained authority")
        fresh, authority = self._capture_foreign(
            require_fd=require_fd)
        if (fresh != self.foreign or
                not android.stable_authority(self.foreign_authority, authority)):
            _fail("retained Document task identity drifted")

    def _capture_placement(self, placement: host.Placement, name: str) -> None:
        if self.status is None:
            _fail("placement lacks exact host identity")
        action = {
            host.Placement.FULL: ACTION_FULL,
            host.Placement.LEFT: ACTION_LEFT,
            host.Placement.RIGHT: ACTION_RIGHT,
        }[placement]
        self._reverify_foreign()
        result: CommandResult | None = None
        transport_error: BaseException | None = None
        try:
            result = self._send(action)
        except BaseException as error:
            transport_error = error
        physical_width, physical_height = _screen_dimensions(name)
        _, rect = host.placement_frame(
            placement, physical_width, physical_height)
        try:
            self._wait_event("PLACEMENT_READY", (
                f"sequence={self.sequence}", f"requested={placement.value}",
                f"effective={placement.value}",
                "rect=" + ",".join(str(item) for item in rect.wire()),
            ))
            self.status = self._wait_status({"ACTIVE"})
            self._settle_host_command(action)
        except BaseException as error:
            if transport_error is not None:
                raise CleanupUncertain(
                    "placement transport and authenticated settlement are uncertain") from error
            raise
        if result is not None and result.returncode != 0:
            self._event("placement_transport_nonzero_but_acknowledged",
                        placement=placement.value, returncode=result.returncode)
        if transport_error is not None:
            self._event("placement_transport_error_but_acknowledged",
                        placement=placement.value, error=str(transport_error))
        self._reverify_foreign()
        raw = self.device.screenshot()
        self._reverify_foreign()
        screenshot = parse_png(raw, name)
        if self.output_dir is None:
            _fail("screenshot output directory is absent")
        path = self.output_dir / (name + ".png")
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
        self.screenshots.append(screenshot)
        self._event("placement_captured", placement=placement.value,
                    sequence=self.sequence, screenshot=asdict(screenshot))

    def _wait_physical_orientation(self, *, portrait: bool,
                                   exact: int | None = None) -> int:
        label = "portrait" if portrait else "starting landscape"

        def observe() -> int | None:
            value = _physical_orientation(self.device.window_displays())
            if portrait and value in (0, 2):
                return value
            if not portrait and value in (1, 3) and (exact is None or value == exact):
                return value
            return None
        mode = ("manual" if
                self.rotation_authority == ROTATION_MANUAL_PHYSICAL else
                "externally controlled ADB")
        value = self._until(
            mode + " " + label + " orientation",
            MANUAL_ROTATION_TIMEOUT_SECONDS,
            observe)
        self.status = self._wait_status({"ACTIVE"})
        self._reverify_foreign()
        if portrait:
            self.portrait_orientation = value
        else:
            self.returned_orientation = value
        if self.rotation_authority == ROTATION_MANUAL_PHYSICAL:
            self._event(
                "physical_orientation_observed", orientation=value,
                expected=label)
        else:
            self._event(
                "adb_rotation_orientation_observed", orientation=value,
                expected=label, rotationAuthority=self.rotation_authority)
        return value

    def _prove_task_absent(self) -> str:
        if self.foreign is None or self.status is None:
            _fail("task absence lacks retained identities")
        raw_activity = self.device.activities()
        raw_window = self.device.windows()
        _assert_owned_display_empty(raw_activity, self.status)
        _assert_owned_display_windows_empty(raw_window, self.status)
        # Task/token checks use only ActivityManager's canonical display list.
        # The pinned firmware retains a post-boundary supervisor ghost for the
        # just-removed Document task; it is corroborative history, not a live
        # task.  The strict authority helper validates and removes that suffix.
        activity_text, _ = android._wire(  # type: ignore[attr-defined]
            raw_activity)
        activity_text = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            activity_text)
        window_text = _decode_text(raw_window, "window absence")
        task = str(self.foreign.task_id)
        forbidden_patterns = (
            re.compile(re.escape(self.foreign.activity_token)),
            re.compile(r"(?<![0-9])#" + re.escape(task) + r"(?![0-9])"),
            re.compile(r"(?<![0-9])t" + re.escape(task) + r"(?![0-9])"),
            re.compile(r"taskId=" + re.escape(task) + r"(?![0-9])"),
            *(re.compile(re.escape(value)) for value in _document_components()),
        )
        try:
            document_scope_present = (
                _contains_document_scope_for_global_absence(
                    raw_activity, self.foreign, self.foreign_authority) or
                _contains_document_scope_for_global_absence(
                    raw_window, self.foreign, self.foreign_authority))
        except (AlphaError, android.AndroidAuthorityError) as error:
            raise AlphaError(
                "post-removal Document inventory is ambiguous") from error
        if (document_scope_present or
                any(pattern.search(activity_text) or pattern.search(window_text)
                    for pattern in forbidden_patterns)):
            _fail("exact/recreated Document task or window is still present")
        pids = self.device.pidof(DOCUMENT_PACKAGE)
        if pids != (self.foreign.process.pid,):
            _fail("stock process did not remain exactly alive after task removal")
        if self.device.process_identity(pids[0], DOCUMENT_PACKAGE) != self.foreign.process:
            _fail("stock process identity changed after task removal")
        if not _virtual_display_present(self.device.displays(), self.status):
            _fail("host display disappeared before exact task absence ACK")
        digest = _canonical_sha({
            "authority": AUTHORITY,
            "kind": "exact-task-absence-alpha",
            "session": self.status.session,
            "generation": self.status.generation,
            "displayId": self.status.display_id,
            "taskId": self.foreign.task_id,
            "activityToken": self.foreign.activity_token,
            "activitySha256": _sha(raw_activity),
            "windowSha256": _sha(raw_window),
            "stockProcess": asdict(self.foreign.process),
        })
        self.cleanup["taskAbsent"] = True
        self.cleanup["stockProcessAlive"] = True
        self.task_absence_sha256 = digest
        return digest

    def _remove_foreign(self) -> None:
        if self.foreign is None:
            return
        if (not self.foreign_fixture_bound or not self.launch_owned or
                self.prelaunch_absence_sha256 is None):
            raise CleanupUncertain(
                "task removal lacks exact session-created fixture ownership")
        if self.parking_switch_attempted:
            if not self.parking_bound:
                raise CleanupUncertain(
                    "task removal is forbidden until parking binding is exact")
            self._reverify_parked_foreign()
        else:
            # Ambiguous/unattached launch cleanup retains the old bounded path;
            # parking may never manufacture ownership for such a task.
            self._reverify_foreign(require_fd=False)
        result: CommandResult | None = None
        remove_error: BaseException | None = None
        try:
            result = self.device.remove_exact_task(self.foreign.task_id)
        except BaseException as error:
            # Never retry a task mutation.  A lost reply can still be resolved
            # by fresh exact absence and unchanged-process observations.
            remove_error = error

        def observe() -> str | None:
            try:
                return self._prove_task_absent()
            except AlphaError:
                return None

        digest = self._until(
            "exact task absence with stock process alive", STEP_TIMEOUT_SECONDS,
            observe)
        # One second independent observation narrows the common removeTask race.
        self.sleep(POLL_SECONDS)
        repeated = self._prove_task_absent()
        self._event("foreign_removed", taskId=self.foreign.task_id,
                    absenceSha256=repeated,
                    removeReturncode=(None if result is None else result.returncode),
                    removeTransportError=(None if remove_error is None
                                          else str(remove_error)),
                    processKillUsed=False, broadScopeUsed=False)

    def _settle_attach_for_cleanup(self) -> None:
        if (not self.attach_command_attempted or self.attached or
                self.status is None or self.foreign is None):
            return
        try:
            current = self._read_status()
            if current.state in {
                    "ACTIVE", "PLACEMENT_PENDING",
                    "WAITING_FOR_FOREIGN_DESTROY"}:
                if self.host_pid is None:
                    _fail("attach settlement lacks the retained host process")
                logs = self.device.host_logs(self.host_pid)
                if not _host_event_present(logs, current, "READY", (
                        f"foreignTask={self.foreign.task_id}",
                        f"foreignPid={self.foreign.process.pid}",
                        "readiness=ACTIVE")):
                    _fail("attach settlement lacks the exact authenticated READY event")
                self.status = current
                self.attached = True
                self.close_started = current.state == "WAITING_FOR_FOREIGN_DESTROY"
                if self.pending_host_command == (ACTION_ATTACH, self.sequence):
                    self.pending_host_command = None
                return
            # This is an exact replay of the already-attempted sequence/body,
            # never a fresh command or a renewed launch.
            self.device.send_host(
                self.status, self.sequence, ACTION_ATTACH,
                foreign=self.foreign)
            current = self._until(
                "exact attach replay settlement", 4.0,
                lambda: (
                    (value := self._read_status())
                    if value.state in {
                        "ACTIVE", "PLACEMENT_PENDING",
                        "WAITING_FOR_FOREIGN_DESTROY"}
                    else None))
            self.status = current
            if self.host_pid is None:
                _fail("attach replay settlement lacks the host process")
            logs = self.device.host_logs(self.host_pid)
            if not _host_event_present(logs, current, "READY", (
                    f"foreignTask={self.foreign.task_id}",
                    f"foreignPid={self.foreign.process.pid}",
                    "readiness=ACTIVE")):
                _fail("attach replay lacks the exact authenticated READY event")
            self.attached = True
            self.close_started = current.state == "WAITING_FOR_FOREIGN_DESTROY"
            self._settle_host_command(ACTION_ATTACH)
        except BaseException as error:
            self._event("attach_cleanup_settlement_uncertain", error=str(error))

    def _settle_placement_for_cleanup(self) -> None:
        if self.pending_host_command is None:
            return
        action, sequence = self.pending_host_command
        placements = {
            ACTION_FULL: host.Placement.FULL,
            ACTION_LEFT: host.Placement.LEFT,
            ACTION_RIGHT: host.Placement.RIGHT,
        }
        placement = placements.get(action)
        if placement is None or self.status is None or self.host_pid is None:
            return
        try:
            current = self._read_status()
            if current.state != "ACTIVE":
                return
            logs = self.device.host_logs(self.host_pid)
            if not _host_event_present(logs, current, "PLACEMENT_READY", (
                    f"sequence={sequence}",
                    f"requested={placement.value}",
                    f"effective={placement.value}")):
                return
            self.status = current
            self.pending_host_command = None
            self._event("placement_cleanup_settled_read_only",
                        placement=placement.value, sequence=sequence)
        except BaseException as error:
            self._event("placement_cleanup_settlement_uncertain",
                        error=str(error))

    def _begin_close(self) -> None:
        if not self.attached or self.close_started:
            return
        if (not self.foreign_fixture_bound or not self.launch_owned or
                self.prelaunch_absence_sha256 is None):
            raise CleanupUncertain(
                "begin-close lacks exact session-created fixture ownership")
        self._reverify_foreign(require_fd=True)
        result: CommandResult | None = None
        transport_error: BaseException | None = None
        try:
            result = self._send(ACTION_CLOSE)
        except BaseException as error:
            transport_error = error
        try:
            self.status = self._wait_status({"WAITING_FOR_FOREIGN_DESTROY"})
            self._wait_event("WAIT_FOREIGN_DESTROY", (
                f"foreignTask={self.foreign.task_id}" if self.foreign else "foreign=none",
            ))
            self._settle_host_command(ACTION_CLOSE)
            self.close_started = True
        except BaseException as error:
            if transport_error is not None:
                raise CleanupUncertain(
                    "close transport and authenticated settlement are uncertain") from error
            raise
        if result is not None and result.returncode != 0:
            self._event("close_transport_nonzero_but_acknowledged",
                        returncode=result.returncode)
        if transport_error is not None:
            self._event("close_transport_error_but_acknowledged",
                        error=str(transport_error))

    def _release_after_destroy(self) -> None:
        if self.foreign is None or self.status is None:
            _fail("destroy ACK lacks retained identity")
        result: CommandResult | None = None
        transport_error: BaseException | None = None
        try:
            result = self._send(ACTION_DESTROYED, foreign=self.foreign)
        except BaseException as error:
            transport_error = error
        try:
            self._wait_event("FOREIGN_DESTROYED", (
                f"foreignTask={self.foreign.task_id}",
            ))
            self._wait_event("DISPLAY_RELEASED", (
                f"display={self.status.display_id}", "mode=acknowledged_cleanup",
            ))
            self._settle_host_command(ACTION_DESTROYED)
        except BaseException as error:
            if transport_error is not None:
                raise CleanupUncertain(
                    "destroy ACK transport and settlement are uncertain") from error
            raise
        if result is not None and result.returncode != 0:
            self._event("destroy_ack_transport_nonzero_but_acknowledged",
                        returncode=result.returncode)
        if transport_error is not None:
            self._event("destroy_ack_transport_error_but_acknowledged",
                        error=str(transport_error))
        self._prove_host_gone()

    def _empty_display_digest(self) -> str:
        if self.status is None:
            _fail("empty display proof lacks retained host identity")
        first_a, first_w = self.device.activities(), self.device.windows()
        _assert_owned_display_empty(first_a, self.status)
        _assert_owned_display_windows_empty(first_w, self.status)
        if (_contains_document_task_or_window(first_a) or
                _contains_document_task_or_window(first_w)):
            _fail("pre-attach display is not Document-task empty")
        if not _virtual_display_present(self.device.displays(), self.status):
            _fail("pre-attach empty proof lacks the exact display")
        return _canonical_sha({
            "authority": AUTHORITY, "kind": "pre-attach-empty-alpha",
            "session": self.status.session,
            "generation": self.status.generation,
            "displayId": self.status.display_id,
            "activitySha256": _sha(first_a), "windowSha256": _sha(first_w),
        })

    def _abort_empty_host(self) -> None:
        if self.status is None:
            return
        current = self._read_status()
        if current.state not in {"DISPLAY_ALLOCATED", "WAITING_FOR_FOREIGN_ATTACH"}:
            _fail("host is not eligible for a healthy empty-display abort")
        absence = self._empty_display_digest()
        result: CommandResult | None = None
        transport_error: BaseException | None = None
        try:
            result = self._send(ACTION_EMPTY_PRE_ATTACH, absence=absence)
        except BaseException as error:
            transport_error = error
        try:
            self._wait_event("EMPTY_PRE_ATTACH_ABORT", (
                "absenceEvidenceSha256=" + absence,
            ))
            self._wait_event("DISPLAY_RELEASED", (
                f"display={self.status.display_id}", "mode=acknowledged_cleanup",
            ))
            self._settle_host_command(ACTION_EMPTY_PRE_ATTACH)
        except BaseException as error:
            if transport_error is not None:
                raise CleanupUncertain(
                    "empty-abort transport and settlement are uncertain") from error
            raise
        if result is not None and result.returncode != 0:
            self._event("empty_abort_transport_nonzero_but_acknowledged",
                        returncode=result.returncode)
        if transport_error is not None:
            self._event("empty_abort_transport_error_but_acknowledged",
                        error=str(transport_error))
        self._prove_host_gone()

    def _prove_host_gone(self) -> None:
        if self.status is None:
            return

        def observe() -> bool | None:
            activities = self.device.activities()
            windows = self.device.windows()
            displays = self.device.displays()
            if (_contains_component(activities, _host_components()) or
                    _contains_component(windows, _host_components()) or
                    _virtual_display_present(displays, self.status)):
                return None
            if self.document_launch_attempted and (
                    _contains_document_scope_for_global_absence(
                        activities, self.foreign, self.foreign_authority) or
                    _contains_document_scope_for_global_absence(
                        windows, self.foreign, self.foreign_authority)):
                return None
            return True
        self._until("exact host task/display absence", STEP_TIMEOUT_SECONDS, observe)
        self.cleanup["displayAbsent"] = True
        self.cleanup["hostTaskAbsent"] = True
        if self.document_launch_attempted:
            self._prove_global_document_absence()

    def _prove_global_document_absence(self) -> None:
        for observation in range(2):
            activities = self.device.activities()
            windows = self.device.windows()
            try:
                document_present = (
                    _contains_document_scope_for_global_absence(
                        activities, self.foreign, self.foreign_authority) or
                    _contains_document_scope_for_global_absence(
                        windows, self.foreign, self.foreign_authority))
            except (AlphaError, android.AndroidAuthorityError) as error:
                raise CleanupUncertain(
                    "global Document absence inventory is ambiguous") from error
            if document_present:
                raise CleanupUncertain(
                    "a Document task/window remains after launch attempt")
            if observation == 0:
                self.sleep(POLL_SECONDS)
        self.cleanup["documentGloballyAbsent"] = True

    def _prove_disposable_descriptors_closed(self) -> None:
        if not self.document_launch_attempted:
            return
        if (self.foreign is None or not self.parking_bound or
                not self.cleanup["documentParked"]):
            raise CleanupUncertain(
                "disposable descriptor proof lacks exact parked ownership")
        for observation in range(2):
            pids = self.device.pidof(DOCUMENT_PACKAGE)
            if pids != (self.foreign.process.pid,):
                raise CleanupUncertain(
                    "retained stock Document process changed before fixture deletion")
            process = self.device.process_identity(pids[0], DOCUMENT_PACKAGE)
            if process != self.foreign.process:
                raise CleanupUncertain(
                    "stock Document PID/starttime changed before fixture deletion")
            targets = _document_file_targets(
                self.device.process_fd_links(pids[0]))
            if targets != frozenset((PARKING_PDF,)):
                raise CleanupUncertain(
                    "Document does not retain only parking after task removal")
            self._assert_parking_file_current()
            if observation == 0:
                self.sleep(POLL_SECONDS)
        self.cleanup["disposableDescriptorsClosed"] = True
        self._event("disposable_descriptors_closed_with_parking_retained")

    def _prove_no_unretained_host_scope(self) -> None:
        """Never infer host absence merely because this run did not start it."""
        for observation in range(2):
            activities = self.device.activities()
            windows = self.device.windows()
            displays = self.device.displays()
            if (_contains_component(activities, _host_components()) or
                    _contains_component(windows, _host_components()) or
                    "NativePageVisualOnly-" in
                    _decode_text(displays, "display inventory") or
                    self.device.pidof(HOST_PACKAGE)):
                raise CleanupUncertain(
                    "unretained visual-host scope is present or ambiguous")
            if observation == 0:
                self.sleep(POLL_SECONDS)
        self.cleanup["displayAbsent"] = True
        self.cleanup["hostTaskAbsent"] = True

    def _prove_joint_fixture_absence(self) -> None:
        """Require two fresh observations of every disposable capability name."""
        paths = [TARGET_MARK, TARGET_PDF]
        paths.extend(
            self.fixture_obligations[target].staging_path
            for target in (TARGET_MARK, TARGET_PDF)
            if target in self.fixture_obligations)
        paths.extend(
            self.fixture_obligations[target].quarantine_path
            for target in (TARGET_MARK, TARGET_PDF)
            if target in self.fixture_obligations)
        for observation in range(2):
            try:
                present = [
                    path for path in paths
                    if self.device.stat_file(path, absent_ok=True) is not None
                ]
            except BaseException as error:
                raise CleanupUncertain(
                    "joint disposable/quarantine absence is ambiguous") from error
            if present:
                raise CleanupUncertain(
                    "disposable/quarantine name reappeared during joint absence proof: " +
                    ", ".join(present))
            if observation == 0:
                self.sleep(POLL_SECONDS)
        self._event(
            "joint_fixture_absence_proved",
            paths=paths, observations=2)

    def _resolve_staging_capabilities(self) -> None:
        """Remove only exact owned random staging leftovers, at most once."""
        for path in (TARGET_MARK, TARGET_PDF):
            obligation = self.fixture_obligations.get(path)
            if obligation is None:
                raise CleanupUncertain(
                    "fixture staging obligation topology is incomplete")
            if _staging_target(obligation.staging_path) != path:
                raise CleanupUncertain(
                    "fixture staging path does not match its target")
            try:
                current = self.device.stat_file(
                    obligation.staging_path, absent_ok=True)
            except BaseException as error:
                raise CleanupUncertain(
                    "staging cleanup observation is ambiguous: " +
                    obligation.staging_path) from error
            if current is None:
                self.sleep(POLL_SECONDS)
                try:
                    if self.device.stat_file(
                            obligation.staging_path,
                            absent_ok=True) is not None:
                        raise CleanupUncertain(
                            "staging leaf reappeared during absence proof: " +
                            obligation.staging_path)
                except CleanupUncertain:
                    raise
                except BaseException as error:
                    raise CleanupUncertain(
                        "second staging absence proof is ambiguous: " +
                        obligation.staging_path) from error
                obligation.staging_cleanup_absence_observations = 2
                obligation.staging_resolved_absent = True
                continue

            retained = obligation.staging_retained
            obligation.staging_cleanup_pre_observed = current
            if (retained is None or obligation.staging_ownership_ambiguous or
                    obligation.staging_pre_absence_sha256 is None or
                    not obligation.copy_attempted or
                    not obligation.copy_reply_proved or
                    not retained.same_object(current) or
                    current.sha256 != obligation.expected_sha256):
                raise CleanupUncertain(
                    "unowned/replaced staging leaf will not be deleted: " +
                    obligation.staging_path)

            # As with quarantine cleanup, POSIX cannot unlink by inode. This
            # one removal relies on the independently random, never-scanned
            # staging leaf remaining an unguessable capability after its exact
            # identity revalidation. Never retry an uncertain mutation.
            obligation.staging_cleanup_attempted = True
            self._journal_transition(
                "STAGING_REMOVE_ATTEMPTED", staging=obligation.staging_path,
                target=obligation.target, retained=asdict(retained),
                retryAllowed=False)
            remove_error: BaseException | None = None
            try:
                self.device.remove_staging_member(obligation.staging_path)
                obligation.staging_cleanup_reply_proved = True
            except BaseException as error:
                obligation.staging_cleanup_transport_error = str(error)
                remove_error = error
            try:
                remaining = self.device.stat_file(
                    obligation.staging_path, absent_ok=True)
            except BaseException as error:
                raise CleanupUncertain(
                    "staging removal postcondition is ambiguous: " +
                    obligation.staging_path) from error
            obligation.staging_cleanup_post_observed = remaining
            if remaining is not None:
                detail = (
                    "staging removal reply and absence are uncertain" if
                    remove_error is not None else
                    "verified staging leaf remains after one removal attempt")
                if not retained.same_object(remaining):
                    detail = (
                        "staging leaf was replaced during removal and will not "
                        "be retried")
                raise CleanupUncertain(
                    detail + ": " + obligation.staging_path)
            obligation.staging_cleanup_absence_observations = 1
            self.sleep(POLL_SECONDS)
            try:
                if self.device.stat_file(
                        obligation.staging_path, absent_ok=True) is not None:
                    raise CleanupUncertain(
                        "staging leaf reappeared after removal: " +
                        obligation.staging_path)
            except CleanupUncertain:
                raise
            except BaseException as error:
                raise CleanupUncertain(
                    "second staging absence proof is ambiguous: " +
                    obligation.staging_path) from error
            obligation.staging_cleanup_absence_observations = 2
            obligation.staging_resolved_absent = True
            self._journal_transition(
                "STAGING_REMOVE_SETTLED", staging=obligation.staging_path,
                target=obligation.target,
                removeReplyProved=obligation.staging_cleanup_reply_proved,
                removeTransportError=obligation.staging_cleanup_transport_error,
                absenceObservations=2)
            self._event(
                "staging_capability_removed", path=obligation.staging_path,
                target=obligation.target,
                removeReplyProved=obligation.staging_cleanup_reply_proved,
                removeTransportError=obligation.staging_cleanup_transport_error,
                retryUsed=False)

    def _prepare_quarantines(self) -> None:
        """Prove every pre-generated random quarantine leaf absent before mutation."""
        for path in (TARGET_MARK, TARGET_PDF):
            obligation = self.fixture_obligations.get(path)
            if obligation is None:
                raise CleanupUncertain(
                    "fixture cleanup obligation topology is incomplete")
            if _quarantine_target(obligation.quarantine_path) != path:
                raise CleanupUncertain(
                    "fixture quarantine path does not match its target")
            for observation in range(2):
                try:
                    current = self.device.stat_file(
                        obligation.quarantine_path, absent_ok=True)
                except BaseException as error:
                    raise CleanupUncertain(
                        "quarantine pre-absence is ambiguous: " +
                        obligation.quarantine_path) from error
                if current is not None:
                    obligation.quarantine_preexisting_observed = current
                    raise CleanupUncertain(
                        "random quarantine leaf already exists and will not be touched: " +
                        obligation.quarantine_path)
                if observation == 0:
                    self.sleep(POLL_SECONDS)
            obligation.quarantine_pre_absence_sha256 = _canonical_sha({
                "authority": AUTHORITY,
                "kind": "pre-quarantine-absence",
                "target": path,
                "quarantine": obligation.quarantine_path,
                "expectedSha256": obligation.expected_sha256,
                "observations": 2,
            })

    def _move_owned_fixture_to_quarantine(
            self, obligation: FixtureObligation, retained: DeviceFile,
            ) -> DeviceFile:
        """Attempt one no-clobber rename and settle it without retry."""
        obligation.quarantine_move_attempted = True
        self._journal_transition(
            "QUARANTINE_MOVE_ATTEMPTED", source=obligation.target,
            quarantine=obligation.quarantine_path, retained=asdict(retained),
            retryAllowed=False)
        move_error: BaseException | None = None
        try:
            self.device.move_fixture_to_quarantine(
                obligation.target, obligation.quarantine_path)
            obligation.quarantine_move_reply_proved = True
        except BaseException as error:
            obligation.quarantine_move_transport_error = str(error)
            move_error = error

        try:
            source_now = self.device.stat_file(
                obligation.target, absent_ok=True)
            quarantine_now = self.device.stat_file(
                obligation.quarantine_path, absent_ok=True)
        except BaseException as error:
            raise CleanupUncertain(
                "quarantine move postconditions are ambiguous: " +
                obligation.target) from error
        obligation.quarantine_move_source_observed = source_now
        obligation.quarantine_move_destination_observed = quarantine_now
        obligation.quarantine_move_postcondition = (
            ("source-present" if source_now is not None else "source-absent") +
            "/" +
            ("destination-present" if quarantine_now is not None else
             "destination-absent"))

        if (source_now is None and quarantine_now is not None and
                retained.same_renamed_object(quarantine_now) and
                quarantine_now.path == obligation.quarantine_path and
                quarantine_now.sha256 == obligation.expected_sha256):
            obligation.quarantine_retained = quarantine_now
            obligation.quarantine_move_postcondition = (
                "source-absent/destination-exact")
            self._journal_transition(
                "QUARANTINE_MOVE_SETTLED", source=obligation.target,
                quarantine=obligation.quarantine_path,
                retained=asdict(quarantine_now),
                moveReplyProved=obligation.quarantine_move_reply_proved,
                moveTransportError=obligation.quarantine_move_transport_error)
            self._event(
                "fixture_quarantined", path=obligation.target,
                quarantine=obligation.quarantine_path,
                inode=quarantine_now.inode, device=quarantine_now.device,
                sha256=quarantine_now.sha256,
                moveReplyProved=obligation.quarantine_move_reply_proved,
                moveTransportError=obligation.quarantine_move_transport_error,
                retryUsed=False)
            return quarantine_now

        # Every other matrix row preserves all remaining paths.  In particular,
        # a zero-output no-clobber skip leaves the source present, while a
        # mismatched destination can never become deletion authority.
        detail = (
            "quarantine move did not settle to source-absent/exact-destination")
        if quarantine_now is not None and not retained.same_renamed_object(
                quarantine_now):
            detail = "quarantine contains a different object and will not be deleted"
        elif source_now is not None and not retained.same_object(source_now):
            detail = "fixture target was replaced during quarantine move"
        elif move_error is not None:
            detail = "quarantine move reply and postconditions are uncertain"
        self._journal_transition(
            "QUARANTINE_MOVE_UNSETTLED", source=obligation.target,
            quarantine=obligation.quarantine_path,
            postcondition=obligation.quarantine_move_postcondition,
            detail=detail)
        raise CleanupUncertain(detail + ": " + obligation.target)

    def _remove_verified_quarantine(
            self, obligation: FixtureObligation, retained: DeviceFile,
            ) -> None:
        """Remove one random-capability quarantine after exact revalidation."""
        try:
            source_now = self.device.stat_file(
                obligation.target, absent_ok=True)
            quarantine_now = self.device.stat_file(obligation.quarantine_path)
        except BaseException as error:
            raise CleanupUncertain(
                "pre-removal quarantine identity is ambiguous: " +
                obligation.quarantine_path) from error
        obligation.quarantine_remove_source_observed = source_now
        obligation.quarantine_remove_pre_observed = quarantine_now
        obligation.quarantine_remove_precondition = (
            ("source-present" if source_now is not None else "source-absent") +
            "/" +
            ("destination-present" if quarantine_now is not None else
             "destination-absent"))
        if source_now is not None:
            raise CleanupUncertain(
                "fixture target reappeared before quarantine removal: " +
                obligation.target)
        if (quarantine_now is None or
                quarantine_now.path != obligation.quarantine_path or
                not retained.same_renamed_object(quarantine_now) or
                quarantine_now.sha256 != obligation.expected_sha256):
            raise CleanupUncertain(
                "quarantine identity changed; refusing to delete it: " +
                obligation.quarantine_path)
        obligation.quarantine_remove_precondition = (
            "source-absent/destination-exact")

        # POSIX has no unlink-by-inode operation.  This final unlink relies on
        # the 128-bit, never-scanned leaf remaining an unguessable capability
        # between this exact revalidation and toybox rm.  The assumption is
        # explicit in the report and does not authorize any fixed or discovered
        # path.  The mutation is issued at most once.
        obligation.quarantine_remove_attempted = True
        self._journal_transition(
            "QUARANTINE_REMOVE_ATTEMPTED", source=obligation.target,
            quarantine=obligation.quarantine_path,
            retained=asdict(quarantine_now), retryAllowed=False)
        remove_error: BaseException | None = None
        try:
            self.device.remove_quarantine_member(obligation.quarantine_path)
            obligation.quarantine_remove_reply_proved = True
        except BaseException as error:
            obligation.quarantine_remove_transport_error = str(error)
            remove_error = error

        try:
            remaining = self.device.stat_file(
                obligation.quarantine_path, absent_ok=True)
        except BaseException as error:
            raise CleanupUncertain(
                "quarantine removal postcondition is ambiguous: " +
                obligation.quarantine_path) from error
        obligation.quarantine_remove_post_observed = remaining
        obligation.quarantine_remove_postcondition = (
            "destination-present" if remaining is not None else
            "destination-absent")
        if remaining is not None:
            if not retained.same_renamed_object(remaining):
                raise CleanupUncertain(
                    "quarantine was replaced during removal and will not be retried: " +
                    obligation.quarantine_path)
            detail = ("quarantine removal reply and absence are uncertain" if
                      remove_error is not None else
                      "verified quarantine remains after one removal attempt")
            raise CleanupUncertain(detail + ": " + obligation.quarantine_path)
        obligation.quarantine_remove_absence_observations = 1

        self.sleep(POLL_SECONDS)
        try:
            if self.device.stat_file(
                    obligation.quarantine_path, absent_ok=True) is not None:
                raise CleanupUncertain(
                    "quarantine reappeared after removal: " +
                    obligation.quarantine_path)
        except CleanupUncertain:
            raise
        except BaseException as error:
            raise CleanupUncertain(
                "second quarantine absence proof is ambiguous: " +
                obligation.quarantine_path) from error
        obligation.quarantine_remove_absence_observations = 2
        obligation.quarantine_resolved_absent = True
        self._journal_transition(
            "QUARANTINE_REMOVE_SETTLED", source=obligation.target,
            quarantine=obligation.quarantine_path,
            removeReplyProved=obligation.quarantine_remove_reply_proved,
            removeTransportError=obligation.quarantine_remove_transport_error,
            absenceObservations=2)
        if remove_error is not None:
            self._event(
                "quarantine_remove_transport_error_but_absent",
                path=obligation.target,
                quarantine=obligation.quarantine_path,
                error=str(remove_error), retryUsed=False)

    def _remove_fixture(self) -> None:
        if not self.fixture_obligations:
            if (self.parking_file is not None or
                    self.source_pdf_file is not None or
                    self.source_mark_file is not None):
                self._final_revalidate_source_and_parking()
            self.cleanup["fixtureRemoved"] = True
            return
        if not (self.cleanup["displayAbsent"] and self.cleanup["hostTaskAbsent"]):
            raise CleanupUncertain(
                "disposable fixture retained because task/display cleanup is unresolved")
        if self.document_launch_attempted:
            if not self.cleanup["documentGloballyAbsent"]:
                raise CleanupUncertain(
                    "fixture retained until global Document absence is proved")
            if not self.cleanup["documentParked"]:
                raise CleanupUncertain(
                    "fixture retained until exact parking binding is proved")
            self._prove_disposable_descriptors_closed()
        self._resolve_staging_capabilities()
        self._prepare_quarantines()
        for path in (TARGET_MARK, TARGET_PDF):
            obligation = self.fixture_obligations.get(path)
            if obligation is None:
                raise CleanupUncertain(
                    "fixture cleanup obligation topology is incomplete")
            current = self.device.stat_file(path, absent_ok=True)
            if current is None:
                self.sleep(POLL_SECONDS)
                if self.device.stat_file(path, absent_ok=True) is not None:
                    raise CleanupUncertain(
                        "disposable target reappeared during absence proof: " + path)
                obligation.quarantine_resolved_absent = True
                continue
            retained = obligation.retained
            if (retained is None or obligation.ownership_ambiguous or
                    obligation.pre_copy_absence_sha256 is None or
                    not obligation.copy_attempted or
                    not obligation.copy_reply_proved):
                raise CleanupUncertain(
                    "unowned/ambiguous disposable target will not be quarantined: " +
                    path)
            if not retained.same_object(current):
                raise CleanupUncertain(
                    "disposable fixture inode changed; refusing to quarantine replacement: " +
                    path)
            if current.sha256 != obligation.expected_sha256:
                raise CleanupUncertain(
                    "disposable fixture bytes changed; refusing to quarantine replacement: " +
                    path)
            quarantined = self._move_owned_fixture_to_quarantine(
                obligation, retained)
            self._remove_verified_quarantine(obligation, retained)
            if obligation.quarantine_retained != quarantined:
                raise CleanupUncertain(
                    "retained quarantine identity changed in coordinator state")
        self._prove_joint_fixture_absence()
        for obligation in self.fixture_obligations.values():
            obligation.resolved_absent = True
        if not all(value.resolved_absent and value.staging_resolved_absent and
                   value.quarantine_resolved_absent
                   for value in self.fixture_obligations.values()):
            raise CleanupUncertain(
                "not every target/staging/quarantine obligation is absent")
        # The established stock source pair is read-only input and must remain
        # byte-identical even though the alpha opened only its Download copy.
        self._final_revalidate_source_and_parking()
        self._journal_transition(
            "DEVICE_MUTATIONS_SETTLED", fixtureRemoved=True,
            sourceFixtureUnchanged=self.source_fixture_unchanged,
            parkingFixtureUnchanged=self.parking_fixture_unchanged)
        self.cleanup["fixtureRemoved"] = True
        self._event("fixture_removed")

    def _cleanup(self) -> None:
        if self.status is None and self.host_start_attempted:
            try:
                self.status = self._read_status()
                pids = self.device.pidof(HOST_PACKAGE)
                if len(pids) != 1:
                    raise CleanupUncertain(
                        "started host process is absent or ambiguous")
                self.host_pid = pids[0]
            except BaseException as error:
                self.cleanup_errors.append(
                    "host launch was attempted but exact session recovery failed: " +
                    str(error))
        self._settle_attach_for_cleanup()
        self._settle_placement_for_cleanup()
        try:
            if self.pending_host_command is not None:
                raise CleanupUncertain(
                    "an attempted host command is not settled; no different cleanup "
                    "sequence was sent")
            if self.foreign is not None:
                if not self.attached:
                    # No host attach ACK was admitted.  Remove the retained task,
                    # then stop: an attempted-but-unsettled attach makes the host
                    # sequence ambiguous, so a different empty-abort envelope is
                    # forbidden even after task absence.
                    self._remove_foreign()
                    if self.attach_command_attempted:
                        raise CleanupUncertain(
                            "attach sequence is unresolved; exact task was removed but "
                            "no equivocated host-abort command was sent")
                    self._abort_empty_host()
                else:
                    self._begin_close()
                    self._park_document()
                    self._remove_foreign()
                    self._release_after_destroy()
            elif self.status is not None:
                self._abort_empty_host()
            else:
                if self.host_start_attempted:
                    raise CleanupUncertain(
                        "host start was attempted without recoverable session identity")
                self._prove_no_unretained_host_scope()
        except BaseException as error:
            self.cleanup_errors.append(str(error))
        try:
            self._remove_fixture()
        except BaseException as error:
            self.cleanup_errors.append(str(error))

    def _report(self) -> dict[str, Any]:
        def obligation_certain(value: FixtureObligation) -> bool:
            if not value.copy_attempted:
                return (
                    value.resolved_absent and value.staging_resolved_absent and
                    value.quarantine_resolved_absent and
                    not value.staging_ownership_ambiguous and
                    not value.ownership_ambiguous)
            return (
                value.pre_copy_absence_sha256 is not None and
                value.staging_pre_absence_sha256 is not None and
                value.copy_reply_proved and
                value.staging_retained is not None and
                value.publish_move_attempted and
                value.publish_move_postcondition ==
                "stage-absent/target-exact" and
                value.retained is not None and
                not value.staging_ownership_ambiguous and
                not value.ownership_ambiguous)

        journal_current = self._mutation_journal_current()
        fixture_ownership_certain = (
            journal_current and
            all(obligation_certain(value)
                for value in self.fixture_obligations.values()))
        parking_cleanup_certain = (
            not self.parking_provisioning_reached or (
                self.parking_provisioning_settled and
                self.parking_file is not None and
                self.parking_fixture_unchanged is True))
        launch_cleanup_complete = (
            not self.document_launch_attempted or (
                self.cleanup["documentGloballyAbsent"] and
                self.cleanup["documentParked"] and
                self.cleanup["disposableDescriptorsClosed"]))
        cleanup_complete = (
            not self.cleanup_errors and
            fixture_ownership_certain and launch_cleanup_complete and
            self.cleanup["displayAbsent"] and
            self.cleanup["hostTaskAbsent"] and
            self.cleanup["fixtureRemoved"] and
            parking_cleanup_certain and
            (self.foreign is None or (
                self.cleanup["taskAbsent"] and
                self.cleanup["stockProcessAlive"]))
        )
        captured_clean = (
            self.primary_error is None and cleanup_complete and
            self.foreign is not None and self.foreign_fixture_bound and
            self.source_fixture_unchanged is True and
            self.parking_fixture_unchanged is True and
            self.portrait_orientation in (0, 2) and
            self.returned_orientation == self.starting_orientation and
            [value.name for value in self.screenshots] == [
                "full", "left", "right", "full_return", "portrait",
                "landscape_return",
            ] and (
                (self.rotation_authority == ROTATION_MANUAL_PHYSICAL and
                 self.rotation_controller_run_id is None and
                 self.rotation_controller_phases == []) or
                (self.rotation_authority == ROTATION_ADB_SYSTEM_SETTINGS and
                 type(self.rotation_controller_run_id) is str and
                 ROTATION_CONTROLLER_ID.fullmatch(
                     self.rotation_controller_run_id) is not None and
                 self.rotation_controller_phases ==
                 list(ROTATION_CONTROLLER_PHASES))))
        return {
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "checkpoint": CHECKPOINT,
            "diagnosticOnly": True,
            "formalAdmission": False,
            "rotationAuthority": self.rotation_authority,
            "rotationController": (
                None if self.rotation_authority == ROTATION_MANUAL_PHYSICAL else {
                    "authority": ROTATION_CONTROLLER_PHASE_AUTHORITY,
                    "runId": self.rotation_controller_run_id,
                    "phases": list(self.rotation_controller_phases),
                }),
            "authorizedSerial": AUTHORIZED_SERIAL,
            "fixture": {
                "uri": TARGET_URI,
                "pdfSha256": SOURCE_PDF_SHA256,
                "markSha256": SOURCE_MARK_SHA256,
                "sourceWasModified": (
                    None if self.source_fixture_unchanged is None else
                    not self.source_fixture_unchanged),
                "foreignFixtureBound": self.foreign_fixture_bound,
                "cleanupObligations": {
                    path: asdict(value)
                    for path, value in self.fixture_obligations.items()
                },
                "mutationJournal": {
                    "authority": MUTATION_JOURNAL_AUTHORITY,
                    "path": (None if self.mutation_journal_path is None else
                             str(self.mutation_journal_path)),
                    "journalId": self.mutation_journal_id,
                    "headSha256": self.mutation_journal_head_sha256,
                    "fileSha256": self.mutation_journal_file_sha256,
                    "recordCount": self.mutation_journal_sequence,
                    "size": self.mutation_journal_size,
                    "directoryDurable":
                    self.mutation_journal_directory_durable,
                    "retired": self.mutation_journal_retired,
                    "current": journal_current,
                    "discoveryByDirectoryScan": False,
                    "appendOnly": True,
                    "neverOverwrittenOrReused": True,
                },
                "stagingPolicy": {
                    "authority": "random-capability-staging-v1",
                    "nonceBits": 128,
                    "independentNoncePerMember": True,
                    "sameDirectoryPublish": True,
                    "discoveryByDirectoryScan": False,
                    "copyNoClobber": True,
                    "copyReceiptEncoding": "exact-ascii-lf",
                    "copyObservationAssumption": (
                        "the cryptographically random staging leaf remains "
                        "unguessable from exact copy receipt through its first "
                        "complete identity observation"),
                    "publishNoClobber": True,
                    "publishRetryAllowed": False,
                    "removeRetryAllowed": False,
                    "leftoverRemovalAssumption": (
                        "the cryptographically random staging leaf remains "
                        "unguessable between exact identity revalidation and unlink"),
                },
                "quarantinePolicy": {
                    "authority": "random-capability-quarantine-v1",
                    "nonceBits": 128,
                    "independentNoncePerMember": True,
                    "sameDirectoryRename": True,
                    "discoveryByDirectoryScan": False,
                    "moveNoClobber": True,
                    "moveRetryAllowed": False,
                    "removeRetryAllowed": False,
                    "immediateRemovalAssumption": (
                        "the cryptographically random quarantine leaf remains "
                        "unguessable between exact identity revalidation and unlink"),
                },
            },
            "host": None if self.status is None else {
                "session": self.status.session,
                "generation": self.status.generation,
                "displayId": self.status.display_id,
                "hostPid": self.host_pid,
            },
            "hostArtifact": asdict(self.host_artifact),
            "foreign": None if self.foreign is None else {
                **self.foreign.wire(),
                "activityToken": self.foreign.activity_token,
            },
            "unownedForeignCandidate": (
                None if self.unowned_foreign_candidate is None else {
                    **self.unowned_foreign_candidate.wire(),
                    "activityToken":
                    self.unowned_foreign_candidate.activity_token,
                }),
            "lastForeignCaptureError": self.last_foreign_capture_error,
            "prelaunchAbsenceSha256": self.prelaunch_absence_sha256,
            "launchOwned": self.launch_owned,
            "documentLaunchAttempted": self.document_launch_attempted,
            "parking": {
                "path": PARKING_PDF,
                "uri": PARKING_URI,
                "sha256": SOURCE_PDF_SHA256,
                "switchAttempted": self.parking_switch_attempted,
                "bound": self.parking_bound,
                "retainedIntent": (
                    "stale-original-target-by-firmware"
                    if self.parking_switch_attempted else None),
                "uiWitness": self.parking_ui_witness,
                "persistentNeverRemoved": True,
                "provisioningReached": self.parking_provisioning_reached,
                "copyAttempted": self.parking_copy_attempted,
                "copyReplyProved": self.parking_copy_reply_proved,
                "provisioningSettled":
                self.parking_provisioning_settled,
                "cleanupCertain": parking_cleanup_certain,
                "wasModified": (
                    None if self.parking_fixture_unchanged is None else
                    not self.parking_fixture_unchanged),
            },
            "screenshots": [asdict(value) for value in self.screenshots],
            "manualPhysicalRotation": (
                self.rotation_authority == ROTATION_MANUAL_PHYSICAL and
                self.portrait_orientation is not None and
                self.returned_orientation is not None),
            "initialOrientation": self.initial_orientation,
            "startingOrientation": self.starting_orientation,
            "portraitOrientation": self.portrait_orientation,
            "returnedOrientation": self.returned_orientation,
            "cleanup": dict(self.cleanup),
            "packageRollbackSafe": cleanup_complete,
            "pendingHostCommand": (
                None if self.pending_host_command is None else {
                    "action": self.pending_host_command[0],
                    "sequence": self.pending_host_command[1],
                }),
            "primaryError": self.primary_error,
            "cleanupErrors": list(self.cleanup_errors),
            "commands": list(self.device.history),
            "events": list(self.events),
            "result": (
                ("ALPHA_VISUAL_CAPTURED_CLEAN" if
                 self.rotation_authority == ROTATION_MANUAL_PHYSICAL else
                 "ALPHA_ADB_ROTATION_CAPTURED_CLEAN") if captured_clean else
                "ALPHA_DIAGNOSTIC_FAILED_CLEAN" if cleanup_complete else
                "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN"
            ),
        }

    def _write_report(self) -> Path:
        self._ensure_output_dir()
        assert self.output_dir is not None
        report = self._report()
        raw = json.dumps(
            report, ensure_ascii=True, allow_nan=False, sort_keys=True,
            indent=2,
        ).encode("ascii") + b"\n"
        path = self.output_dir / "report.json"
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return path

    def run(self) -> Path:
        try:
            # Establish the never-reused local evidence directory before any
            # preflight path can provision the persistent parking PDF.
            self._ensure_output_dir()
            self._preflight()
            self._stage_fixture()
            self._start_host()
            self._launch_foreign()
            self._attach()
            if self.rotation_authority == ROTATION_MANUAL_PHYSICAL:
                print("Hold the Nomad in landscape; the attached alpha host is waiting for the physical sensor.")
            else:
                print("Waiting for the external ADB rotation controller to present landscape.")
                self._emit_rotation_controller_phase("START_LANDSCAPE")
            self._wait_starting_landscape()
            for placement, name in (
                    (host.Placement.FULL, "full"),
                    (host.Placement.LEFT, "left"),
                    (host.Placement.RIGHT, "right"),
                    (host.Placement.FULL, "full_return")):
                self._capture_placement(placement, name)
            if self.rotation_authority == ROTATION_MANUAL_PHYSICAL:
                print("Rotate the Nomad to portrait; the alpha is waiting without changing settings.")
            else:
                print("Waiting for the external ADB rotation controller to present portrait.")
                self._emit_rotation_controller_phase("PORTRAIT")
            self._wait_physical_orientation(portrait=True)
            self._capture_placement(host.Placement.FULL, "portrait")
            if self.rotation_authority == ROTATION_MANUAL_PHYSICAL:
                print("Rotate the Nomad back to its starting landscape orientation.")
            else:
                print("Waiting for the external ADB rotation controller to restore the starting landscape orientation.")
                self._emit_rotation_controller_phase("RETURN_LANDSCAPE")
            if self.starting_orientation not in (1, 3):
                _fail("starting landscape orientation was not retained")
            self._wait_physical_orientation(
                portrait=False, exact=self.starting_orientation)
            self._capture_placement(
                host.Placement.FULL, "landscape_return")
        except BaseException as error:
            self.primary_error = f"{type(error).__name__}: {error}"
        finally:
            self._cleanup()
            if (self.mutation_journal_path is not None and
                    self._report()["packageRollbackSafe"]):
                try:
                    self._retire_mutation_journal()
                except BaseException as error:
                    self.cleanup_errors.append(str(error))
            report_path = self._write_report()
        report = self._report()
        if report["result"] in (
                "ALPHA_VISUAL_CAPTURED_CLEAN",
                "ALPHA_ADB_ROTATION_CAPTURED_CLEAN"):
            return report_path
        if report["result"] == "ALPHA_DIAGNOSTIC_FAILED_CLEAN":
            raise DiagnosticFailedClean(report_path)
        raise CleanupUncertain(
            "alpha did not finish cleanly; inspect " + str(report_path))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the fixed visual-only Nomad alpha. This is diagnostic-only "
            "and cannot establish formal hardware admission."
        ))
    parser.add_argument("--adb", required=True, type=Path,
                        help="Path to the Android SDK adb.exe")
    parser.add_argument(
        "--serial", required=True, choices=(AUTHORIZED_SERIAL,),
        help="Exact hardware serial admitted by this disposable alpha")
    parser.add_argument("--output-root", required=True, type=Path,
                        help="Local directory for screenshots and report.json")
    parser.add_argument(
        "--host-metadata", required=True, type=Path,
        help=(
            "Exact native-page-host-alpha.json emitted alongside the fixed, "
            "independently pinned local alpha APK."
        ))
    parser.add_argument(
        "--rotation-authority", choices=ROTATION_AUTHORITIES,
        default=ROTATION_MANUAL_PHYSICAL,
        help=(
            "Orientation authority. The default requires manual physical "
            "rotation; adb-system-settings-v1 only observes a separately "
            "journaled external controller and remains non-admissible."
        ))
    parser.add_argument(
        "--rotation-controller-run-id",
        help=(
            "Exact 128-bit lowercase-hex nonce supplied by the external "
            "controller. Required only for adb-system-settings-v1 and "
            "forbidden in manual mode."
        ))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        artifact = load_host_artifact(arguments.host_metadata)
        device = AdbNomad(arguments.adb, arguments.serial)
        session = AlphaSession(
            device, arguments.output_root, host_artifact=artifact,
            rotation_authority=arguments.rotation_authority,
            rotation_controller_run_id=arguments.rotation_controller_run_id)
    except (AlphaError, OSError) as error:
        print("ALPHA SETUP STOPPED before device dispatch: " + str(error),
              file=sys.stderr)
        # No report-backed device absence proof exists at this layer.  The
        # one-click wrapper must retain a newly installed host for inspection.
        return 2
    try:
        report = session.run()
    except DiagnosticFailedClean as error:
        print("ALPHA DIAGNOSTIC FAILED, CLEANUP PROVED: " + str(error),
              file=sys.stderr)
        return 3
    except (AlphaError, OSError) as error:
        print("ALPHA STOPPED: " + str(error), file=sys.stderr)
        return 2
    print("Visual alpha captured and cleaned. Diagnostic report: " + str(report))
    print("This result is diagnostic-only; it is not formal hardware admission.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
