"""Fail-closed coordinator for the read-only native page snapshot observer.

The production CLI intentionally stops at hardware admission until a reviewed
pinned-firmware graph observer and an independently authenticated file/module
evidence provider are connected.  The ``run_snapshot`` v1 integration-test
boundary is injectable so adapters can be reviewed without weakening that gate.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Protocol, Sequence


SCHEMA_VERSION = 1
RUNNER_AUTHORITY = "rtl-reader-native-page-snapshot-runner-v1"
MANIFEST_AUTHORITY = "rtl-reader-native-page-snapshot-manifest-v1"
EVIDENCE_AUTHORITY = "rtl-reader-native-page-external-evidence-v1"
EVIDENCE_PROVIDER_AUTHORITY = "rtl-reader-native-page-evidence-provider-v1"
OBSERVER_SCHEMA_ADAPTER_AUTHORITY = "rtl-reader-native-page-snapshot-v1-adapter"
PRODUCTION_BLOCK_REASON = (
    "PINNED_FIRMWARE_V2_GRAPH_OBSERVER_AND_AUTHENTICATED_EVIDENCE_PROVIDER_UNAVAILABLE"
)
PACKAGE_NAME = "com.supernote.document"
PROCESS_NAME = "Document"
EXPECTED_OBSERVER_SHA256 = (
    "57ba82e831e3e3299819c98f4cf7aae9a7a4f4f35b66062760b88819fe9293d7"
)
MAX_MANIFEST_BYTES = 131_072
MAX_OBSERVER_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 524_288
MAX_MESSAGE_BYTES = 2_097_152
MAX_ADB_OUTPUT_BYTES = 16_384
MAX_STRING_BYTES = 4_096
MAX_MODULE_BYTES = 536_870_912
MAX_PAGE_COUNT = 10_000_000
MIN_DEADLINE_MS = 250
MAX_DEADLINE_MS = 10_000
MAX_SAFE_INTEGER = (1 << 53) - 1
SERIAL_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
SESSION_RE = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
START_RE = re.compile(r"[1-9][0-9]{0,19}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BINARY64_RE = re.compile(r"0x[0-9a-f]{16}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,39}\Z")
DECIMAL_ZERO_RE = re.compile(r"(?:0|[1-9][0-9]{0,39})\Z")
CLASS_RE = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+\Z")
FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
ROLE_FIELDS: dict[str, dict[str, str]] = {
    "activity": {
        "identity": "string", "taskId": "int32", "displayId": "int32",
        "sessionGeneration": "safeInt",
    },
    "viewModel": {
        "identity": "string", "uri": "string", "currentPageIndex": "int32",
        "pageCount": "int32",
    },
    "pageInfo": {
        "identity": "string", "pageIndex": "int32", "width": "finite",
        "height": "finite", "cropLeft": "finite", "cropTop": "finite",
        "cropRight": "finite", "cropBottom": "finite", "ctmA": "finite",
        "ctmB": "finite", "ctmC": "finite", "ctmD": "finite",
        "ctmE": "finite", "ctmF": "finite", "inverseA": "finite",
        "inverseB": "finite", "inverseC": "finite", "inverseD": "finite",
        "inverseE": "finite", "inverseF": "finite", "offsetX": "finite",
        "offsetY": "finite", "bitmapWidth": "int32", "bitmapHeight": "int32",
    },
    "presenter": {
        "identity": "string", "currentPageIndex": "int32",
        "markPath": "nullableString", "rotation": "int32",
        "noteIdentity": "string", "clientIdentity": "string",
        "binderIdentity": "string",
    },
    "layers": {
        "identity": "string", "backgroundIdentity": "string",
        "committedHandwritingIdentity": "string", "digestLayerIdentity": "string",
    },
}


class SnapshotRunnerError(RuntimeError):
    """The snapshot cannot be admitted or trusted."""


class HardwareAdmissionBlocked(SnapshotRunnerError):
    """A required production authority is deliberately unavailable."""


class SnapshotDeadlineExceeded(SnapshotRunnerError):
    """The externally enforced observation deadline expired."""


class SnapshotRejected(SnapshotRunnerError):
    """The observer emitted a negative or malformed terminal sequence."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class LoadedJson:
    raw: bytes
    value: dict[str, Any]
    sha256: str


@dataclass(frozen=True)
class RunBinding:
    serial: str
    pid: int
    start_time_ticks: str
    observer_session_id: str
    deadline_ms: int


@dataclass(frozen=True)
class EvidenceRequest:
    phase: str
    manifest_sha256: str
    binding: RunBinding
    package_name: str
    apk: dict[str, Any]
    module: dict[str, Any]
    original_pdf: dict[str, Any]
    mark: dict[str, Any]
    uri_resolution: dict[str, Any]


@dataclass(frozen=True)
class AuthenticatedEvidence:
    """Exact independently acquired evidence bytes plus detached authority."""

    raw: bytes
    sha256: str


class AdbAdapter(Protocol):
    def run(self, arguments: Sequence[str], timeout_ms: int) -> CommandResult:
        ...


class EvidenceProvider(Protocol):
    """Capture evidence independently; implementations must not echo a manifest."""

    def admission(self) -> dict[str, Any]:
        ...

    def capture(self, request: EvidenceRequest) -> AuthenticatedEvidence:
        ...


class FridaSession(Protocol):
    def load(self, source: str, on_message: Callable[[Any, Any], None]) -> None:
        ...

    def unload(self) -> None:
        ...

    def detach(self) -> None:
        """Detach and return only after the message callback is quiescent."""
        ...


class FridaAdapter(Protocol):
    def attach(self, serial: str, pid: int) -> FridaSession:
        ...


class SubprocessAdbAdapter:
    """ADB adapter that accepts only an argv vector and never invokes a shell."""

    def __init__(self, executable: Path):
        path = Path(executable)
        raw, _ = _read_regular_snapshot(path, 64 * 1024 * 1024)
        if not raw:
            raise SnapshotRunnerError("ADB executable is empty")
        self.executable = str(path.resolve(strict=True))

    def run(self, arguments: Sequence[str], timeout_ms: int) -> CommandResult:
        if (type(timeout_ms) is not int or timeout_ms < MIN_DEADLINE_MS or
                timeout_ms > MAX_DEADLINE_MS or type(arguments) not in (tuple, list) or
                any(type(item) is not str or not item or "\x00" in item
                    for item in arguments)):
            raise SnapshotRunnerError("invalid ADB argv contract")
        try:
            result = subprocess.run(
                [self.executable, *arguments], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout_ms / 1000.0, shell=False, close_fds=True,
                check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise SnapshotRunnerError("ADB command failed") from error
        if (len(result.stdout) > MAX_ADB_OUTPUT_BYTES or
                len(result.stderr) > MAX_ADB_OUTPUT_BYTES):
            raise SnapshotRunnerError("ADB output exceeds bound")
        return CommandResult(result.returncode, result.stdout, result.stderr)


class PythonFridaAdapter:
    """Small adapter over Frida's Python API; the coordinator owns its deadline."""

    def __init__(self, frida_module: Any | None = None):
        if frida_module is None:
            try:
                import frida as frida_module  # type: ignore[import-not-found]
            except ImportError as error:
                raise HardwareAdmissionBlocked("FRIDA_PYTHON_ADAPTER_UNAVAILABLE") from error
        self._frida = frida_module

    def attach(self, serial: str, pid: int) -> FridaSession:
        device = self._frida.get_device(serial, timeout=MAX_DEADLINE_MS)
        return _PythonFridaSession(device.attach(pid))


class _PythonFridaSession:
    def __init__(self, session: Any):
        self._session = session
        self._script: Any | None = None
        self._message_wrapper: Callable[[Any, Any], None] | None = None
        self._condition = threading.Condition()
        self._accepting_messages = False
        self._active_callbacks = 0

    def load(self, source: str, on_message: Callable[[Any, Any], None]) -> None:
        if self._script is not None:
            raise SnapshotRunnerError("Frida script was loaded twice")
        script = self._session.create_script(source)
        self._script = script

        def guarded_message(message: Any, data: Any) -> None:
            with self._condition:
                if not self._accepting_messages:
                    return
                self._active_callbacks += 1
            try:
                on_message(message, data)
            finally:
                with self._condition:
                    self._active_callbacks -= 1
                    self._condition.notify_all()

        self._message_wrapper = guarded_message
        with self._condition:
            self._accepting_messages = True
        try:
            script.on("message", guarded_message)
            script.load()
        except BaseException:
            with self._condition:
                self._accepting_messages = False
            raise

    def _close_message_gate(self) -> None:
        with self._condition:
            self._accepting_messages = False
            while self._active_callbacks:
                self._condition.wait()

    def unload(self) -> None:
        script, self._script = self._script, None
        with self._condition:
            self._accepting_messages = False
        if script is not None:
            wrapper, self._message_wrapper = self._message_wrapper, None
            try:
                if wrapper is not None:
                    script.off("message", wrapper)
            finally:
                script.unload()
        self._close_message_gate()

    def detach(self) -> None:
        with self._condition:
            self._accepting_messages = False
        self._session.detach()
        self._close_message_gate()


class UnavailableEvidenceProvider:
    """Production fail-closed default until independent capture is implemented."""

    def admission(self) -> dict[str, Any]:
        raise HardwareAdmissionBlocked(
            "AUTHENTICATED_EXTERNAL_EVIDENCE_PROVIDER_UNAVAILABLE")

    def capture(self, request: EvidenceRequest) -> AuthenticatedEvidence:
        del request
        raise HardwareAdmissionBlocked(
            "AUTHENTICATED_EXTERNAL_EVIDENCE_PROVIDER_UNAVAILABLE")


def _identity(value: os.stat_result) -> tuple[Any, ...]:
    fields: tuple[Any, ...] = (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        getattr(value, "st_uid", 0), getattr(value, "st_gid", 0),
        getattr(value, "st_rdev", 0), value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_file_attributes", 0),
    )
    if os.name == "posix":
        fields += (getattr(value, "st_ctime_ns",
                           int(value.st_ctime * 1_000_000_000)),)
    return fields


def _read_regular_snapshot(path: Path, limit: int) -> tuple[bytes, Path]:
    if type(limit) is not int or limit < 1:
        raise SnapshotRunnerError("invalid file bound")
    descriptor: int | None = None
    path = Path(path)
    try:
        named = os.lstat(path)
        if (not stat.S_ISREG(named.st_mode) or named.st_size < 1 or
                named.st_size > limit or
                getattr(named, "st_file_attributes", 0) & 0x400):
            raise SnapshotRunnerError("input is not one bounded regular file")
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                _identity(opened) != _identity(named)):
            raise SnapshotRunnerError("input identity changed during open")
        chunks: list[bytes] = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        final_named = os.lstat(path)
        if (len(raw) != opened.st_size or _identity(after) != _identity(opened) or
                _identity(final_named) != _identity(opened)):
            raise SnapshotRunnerError("input identity changed during capture")
        return raw, path.resolve(strict=True)
    except (OSError, OverflowError, TypeError, ValueError) as error:
        if isinstance(error, SnapshotRunnerError):
            raise
        raise SnapshotRunnerError("input capture failed") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                raise SnapshotRunnerError("input descriptor close failed") from error


def _strict_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise SnapshotRunnerError("duplicate JSON field")
        result[key] = value
    return result


def _reject_number(_: str) -> Any:
    raise SnapshotRunnerError("JSON floating-point values are not admitted")


def _parse_integer(wire: str) -> int:
    if len(wire) > 17:
        raise SnapshotRunnerError("JSON integer wire exceeds safe bound")
    value = int(wire, 10)
    if abs(value) > MAX_SAFE_INTEGER:
        raise SnapshotRunnerError("JSON integer exceeds safe range")
    return value


def _validate_json_domain(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise SnapshotRunnerError("JSON depth exceeds bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise SnapshotRunnerError("JSON integer exceeds safe range")
        return
    if type(value) is str:
        if "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF
                                   for character in value):
            raise SnapshotRunnerError("JSON string is not canonical Unicode")
        return
    if type(value) is list:
        if len(value) > 100_000:
            raise SnapshotRunnerError("JSON array exceeds bound")
        for item in value:
            _validate_json_domain(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > 100_000:
            raise SnapshotRunnerError("JSON object exceeds bound")
        for key, item in value.items():
            _validate_json_domain(key, depth + 1)
            _validate_json_domain(item, depth + 1)
        return
    raise SnapshotRunnerError("unsupported JSON value")


def _canonical_json_bytes(value: Any) -> bytes:
    _validate_json_domain(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8", "strict")
    except (UnicodeError, ValueError, TypeError) as error:
        raise SnapshotRunnerError("JSON canonicalization failed") from error


def _json_exact_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (set(left) == set(right) and
                all(_json_exact_equal(left[key], right[key]) for key in left))
    if type(left) is list:
        return (len(left) == len(right) and
                all(_json_exact_equal(a, b) for a, b in zip(left, right)))
    return bool(left == right)


def _bounded_json_cost(value: Any, budget: int, depth: int = 0) -> int:
    """Conservatively bound a callback object before allocating its JSON wire."""
    if budget < 0 or depth > 64:
        raise SnapshotRunnerError("JSON value exceeds wire bound")
    if value is None:
        return 4
    if type(value) is bool:
        return 5
    if type(value) is int:
        _validate_json_domain(value, depth)
        return len(str(value))
    if type(value) is str:
        if len(value) > budget:
            raise SnapshotRunnerError("JSON string exceeds wire bound")
        _validate_json_domain(value, depth)
        encoded = len(value.encode("utf-8", "strict")) + 2
        # Escaping can expand each Unicode scalar by at most six bytes.
        return max(encoded, len(value) * 6 + 2)
    if type(value) is list:
        if len(value) > 100_000:
            raise SnapshotRunnerError("JSON array exceeds bound")
        used = 2 + max(0, len(value) - 1)
        for item in value:
            used += _bounded_json_cost(item, budget - used, depth + 1)
            if used > budget:
                raise SnapshotRunnerError("JSON value exceeds wire bound")
        return used
    if type(value) is dict:
        if len(value) > 100_000:
            raise SnapshotRunnerError("JSON object exceeds bound")
        used = 2 + max(0, len(value) - 1)
        for key, item in value.items():
            if type(key) is not str:
                raise SnapshotRunnerError("JSON object key is not a string")
            used += _bounded_json_cost(key, budget - used, depth + 1) + 1
            used += _bounded_json_cost(item, budget - used, depth + 1)
            if used > budget:
                raise SnapshotRunnerError("JSON value exceeds wire bound")
        return used
    raise SnapshotRunnerError("unsupported JSON value")


def _bounded_canonical_json_bytes(value: Any, limit: int) -> bytes:
    _bounded_json_cost(value, limit)
    raw = _canonical_json_bytes(value)
    if len(raw) > limit:
        raise SnapshotRunnerError("JSON value exceeds exact wire bound")
    return raw


def _load_canonical_json_bytes(raw: bytes, limit: int) -> LoadedJson:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise SnapshotRunnerError("JSON wire is empty or oversized")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text, object_pairs_hook=_strict_pairs, parse_float=_reject_number,
            parse_int=_parse_integer, parse_constant=_reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise SnapshotRunnerError("JSON wire is invalid UTF-8 JSON") from error
    if type(value) is not dict:
        raise SnapshotRunnerError("JSON wire must contain one object")
    canonical = _canonical_json_bytes(value)
    if canonical != raw:
        raise SnapshotRunnerError("JSON wire is not byte-exact canonical JSON")
    return LoadedJson(raw, value, hashlib.sha256(raw).hexdigest())


def load_manifest(path: Path) -> LoadedJson:
    raw, _ = _read_regular_snapshot(path, MAX_MANIFEST_BYTES)
    loaded = _load_canonical_json_bytes(raw, MAX_MANIFEST_BYTES)
    _validate_manifest_envelope(loaded.value)
    return loaded


def _revalidate_loaded_manifest(manifest: LoadedJson) -> None:
    if type(manifest) is not LoadedJson:
        raise SnapshotRunnerError("manifest wrapper type is invalid")
    parsed = _load_canonical_json_bytes(manifest.raw, MAX_MANIFEST_BYTES)
    if (parsed.sha256 != manifest.sha256 or
            not _json_exact_equal(parsed.value, manifest.value)):
        raise SnapshotRunnerError("manifest wrapper differs from canonical wire")
    _validate_manifest_envelope(parsed.value)


def load_observer_source(path: Path) -> tuple[bytes, str]:
    raw, _ = _read_regular_snapshot(path, MAX_OBSERVER_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_OBSERVER_SHA256:
        raise SnapshotRunnerError("observer source differs from exact authority")
    try:
        raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SnapshotRunnerError("observer source is not UTF-8") from error
    return raw, digest


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise SnapshotRunnerError(label + " fields differ from exact contract")


def _checked_string(value: Any, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if (type(value) is not str or not value or "\x00" in value or
            len(value.encode("utf-8", "strict")) > MAX_STRING_BYTES):
        raise SnapshotRunnerError(label + " is not one bounded nonempty string")


def _checked_integer(value: Any, label: str, *, minimum: int | None = None,
                     maximum: int | None = None) -> None:
    if (type(value) is not int or abs(value) > MAX_SAFE_INTEGER or
            (minimum is not None and value < minimum) or
            (maximum is not None and value > maximum)):
        raise SnapshotRunnerError(label + " is not an admitted integer")


def _checked_decimal(value: Any, label: str, *, allow_zero: bool) -> None:
    expression = DECIMAL_ZERO_RE if allow_zero else DECIMAL_RE
    if type(value) is not str or expression.fullmatch(value) is None:
        raise SnapshotRunnerError(label + " is not a bounded decimal integer")


def _validate_file_descriptor(descriptor: Any, label: str, *, must_be_present: bool,
                              original_pdf: bool) -> None:
    keys = {"present", "path", "size", "sha256", "stat"}
    if original_pdf:
        keys.update({"documentUri", "uriResolution"})
    _exact_keys(descriptor, keys, label)
    if type(descriptor["present"]) is not bool:
        raise SnapshotRunnerError(label + " present is not boolean")
    if must_be_present and descriptor["present"] is not True:
        raise SnapshotRunnerError(label + " must be present")
    if not descriptor["present"]:
        if any(descriptor[name] is not None
               for name in ("path", "size", "sha256", "stat")):
            raise SnapshotRunnerError(label + " absent values are not explicit nulls")
        return
    _checked_string(descriptor["path"], label + " path")
    _checked_decimal(descriptor["size"], label + " size", allow_zero=False)
    if type(descriptor["sha256"]) is not str or SHA256_RE.fullmatch(
            descriptor["sha256"]) is None:
        raise SnapshotRunnerError(label + " digest is invalid")
    stat_value = descriptor["stat"]
    _exact_keys(stat_value, {"device", "inode", "mode", "uid", "gid",
                             "mtimeNs", "ctimeNs"}, label + " stat")
    _checked_decimal(stat_value["device"], label + " device", allow_zero=True)
    _checked_decimal(stat_value["inode"], label + " inode", allow_zero=False)
    _checked_decimal(stat_value["mode"], label + " mode", allow_zero=False)
    _checked_integer(stat_value["uid"], label + " uid", minimum=0)
    _checked_integer(stat_value["gid"], label + " gid", minimum=0)
    _checked_decimal(stat_value["mtimeNs"], label + " mtime", allow_zero=True)
    _checked_decimal(stat_value["ctimeNs"], label + " ctime", allow_zero=True)
    if not original_pdf:
        return
    _checked_string(descriptor["documentUri"], "original PDF document URI")
    resolution = descriptor["uriResolution"]
    if descriptor["documentUri"].startswith("file://"):
        _exact_keys(resolution, {"authority", "documentUri", "resolvedPath",
                                 "evidenceSha256"}, "file URI resolution")
        if (resolution["authority"] != "rtl-reader-file-uri-resolution-v1" or
                resolution["documentUri"] != descriptor["documentUri"] or
                resolution["resolvedPath"] != descriptor["path"] or
                type(resolution["evidenceSha256"]) is not str or
                SHA256_RE.fullmatch(resolution["evidenceSha256"]) is None):
            raise SnapshotRunnerError("file URI resolution authority is invalid")
        return
    if not descriptor["documentUri"].startswith("content://"):
        raise SnapshotRunnerError("original PDF URI scheme is unsupported")
    _exact_keys(resolution, {"authority", "documentUri", "resolvedPath",
                             "providerPackage", "providerApkSha256",
                             "evidenceSha256"}, "content URI resolution")
    _checked_string(resolution["providerPackage"], "content provider package")
    if (resolution["authority"] != "rtl-reader-content-uri-resolution-v1" or
            resolution["documentUri"] != descriptor["documentUri"] or
            resolution["resolvedPath"] != descriptor["path"] or
            type(resolution["providerApkSha256"]) is not str or
            SHA256_RE.fullmatch(resolution["providerApkSha256"]) is None or
            type(resolution["evidenceSha256"]) is not str or
            SHA256_RE.fullmatch(resolution["evidenceSha256"]) is None):
        raise SnapshotRunnerError("content URI resolution authority is invalid")


def _validate_role_binding(role: str, binding: Any, *, allow_unavailable: bool) -> None:
    if (allow_unavailable and type(binding) is dict and
            binding.get("status") == "unavailable"):
        _exact_keys(binding, {"status", "reasonCode", "evidenceId"},
                    "layers binding")
        _checked_string(binding["reasonCode"], "layers reason code")
        _checked_string(binding["evidenceId"], "layers evidence ID")
        return
    keys = {"className", "fields", "selector"}
    if allow_unavailable:
        keys.add("status")
    _exact_keys(binding, keys, role + " binding")
    if allow_unavailable and binding["status"] != "bound":
        raise SnapshotRunnerError("layers binding status is invalid")
    _checked_string(binding["className"], role + " class name")
    if CLASS_RE.fullmatch(binding["className"]) is None:
        raise SnapshotRunnerError(role + " class name is invalid")
    field_types = ROLE_FIELDS[role]
    _exact_keys(binding["fields"], set(field_types), role + " fields")
    for output_name, expected_type in field_types.items():
        descriptor = binding["fields"][output_name]
        _exact_keys(descriptor, {"field", "type"}, role + " field descriptor")
        _checked_string(descriptor["field"], role + " field")
        if (descriptor["type"] != expected_type or
                FIELD_RE.fullmatch(descriptor["field"]) is None or
                descriptor["field"] in {"__proto__", "constructor", "prototype"}):
            raise SnapshotRunnerError(role + " field authority is invalid")
    selector = binding["selector"]
    if (type(selector) is not dict or not 0 < len(selector) <= len(field_types) or
            "identity" not in selector or any(name not in field_types for name in selector)):
        raise SnapshotRunnerError(role + " selector is invalid")
    for name, value in selector.items():
        expected_type = field_types[name]
        if expected_type == "string":
            _checked_string(value, role + " selector " + name)
        elif expected_type == "nullableString":
            _checked_string(value, role + " selector " + name, nullable=True)
        elif expected_type == "int32":
            _checked_integer(value, role + " selector " + name,
                             minimum=-(1 << 31), maximum=(1 << 31) - 1)
        elif expected_type == "safeInt":
            _checked_integer(value, role + " selector " + name)
        elif expected_type == "finite":
            _checked_integer(value, role + " selector " + name,
                             minimum=-1_000_000_000_000,
                             maximum=1_000_000_000_000)
        else:
            raise SnapshotRunnerError(role + " selector type is unsupported")


def _validate_manifest_envelope(manifest: dict[str, Any]) -> None:
    _exact_keys(manifest, {"schemaVersion", "authority", "attachment", "files",
                           "coordinator", "expected", "bindings"}, "manifest")
    if (type(manifest["schemaVersion"]) is not int or
            manifest["schemaVersion"] != SCHEMA_VERSION or
            manifest["authority"] != MANIFEST_AUTHORITY):
        raise SnapshotRunnerError("manifest authority mismatch")
    attachment = manifest["attachment"]
    _exact_keys(attachment, {"packageName", "processName", "pid",
                             "startTimeTicks", "apk", "module"}, "attachment")
    if (attachment["packageName"] != PACKAGE_NAME or
            attachment["processName"] != PROCESS_NAME or
            type(attachment["pid"]) is not int or attachment["pid"] <= 0 or
            type(attachment["startTimeTicks"]) is not str or
            START_RE.fullmatch(attachment["startTimeTicks"]) is None):
        raise SnapshotRunnerError("manifest process binding is invalid")
    _exact_keys(attachment["apk"], {"path", "size", "sha256"}, "APK identity")
    _checked_string(attachment["apk"]["path"], "APK path")
    _checked_integer(attachment["apk"]["size"], "APK size", minimum=1,
                     maximum=MAX_MODULE_BYTES)
    if (type(attachment["apk"]["sha256"]) is not str or
            SHA256_RE.fullmatch(attachment["apk"]["sha256"]) is None):
        raise SnapshotRunnerError("APK digest is invalid")
    _exact_keys(attachment["module"], {"name", "path", "size", "sha256"},
                "module identity")
    _checked_string(attachment["module"]["name"], "module name")
    _checked_string(attachment["module"]["path"], "module path")
    _checked_integer(attachment["module"]["size"], "module size", minimum=1,
                     maximum=MAX_MODULE_BYTES)
    if (type(attachment["module"]["sha256"]) is not str or
            SHA256_RE.fullmatch(attachment["module"]["sha256"]) is None):
        raise SnapshotRunnerError("module digest is invalid")
    coordinator = manifest["coordinator"]
    _exact_keys(coordinator, {"authority", "observerSessionId", "hardDeadlineMs",
                              "maxJavaChooseWalks", "detachOnDeadline",
                              "abortOnAnyError", "verifyTargetLivenessAfter"},
                "coordinator")
    if (coordinator["authority"] !=
            "rtl-reader-native-page-snapshot-coordinator-v1" or
            type(coordinator["observerSessionId"]) is not str or
            SESSION_RE.fullmatch(coordinator["observerSessionId"]) is None or
            type(coordinator["hardDeadlineMs"]) is not int or
            not MIN_DEADLINE_MS <= coordinator["hardDeadlineMs"] <= MAX_DEADLINE_MS or
            coordinator["maxJavaChooseWalks"] != 10 or
            coordinator["detachOnDeadline"] is not True or
            coordinator["abortOnAnyError"] is not True or
            coordinator["verifyTargetLivenessAfter"] is not True):
        raise SnapshotRunnerError("manifest coordinator contract is invalid")
    files = manifest["files"]
    _exact_keys(files, {"authority", "verification", "originalPdf", "mark"},
                "files")
    if (files["authority"] != "rtl-reader-native-page-file-authority-v1" or
            files["verification"] != "external-before-and-after-exact" or
            type(files["originalPdf"]) is not dict or
            type(files["mark"]) is not dict):
        raise SnapshotRunnerError("manifest file authority is invalid")
    _validate_file_descriptor(files["originalPdf"], "original PDF",
                              must_be_present=True, original_pdf=True)
    _validate_file_descriptor(files["mark"], "mark file", must_be_present=False,
                              original_pdf=False)
    expected = manifest["expected"]
    _exact_keys(expected, {"taskId", "displayId", "sessionGeneration", "uri",
                           "currentPageIndex", "pageCount"}, "expected")
    _checked_integer(expected["taskId"], "expected task ID", minimum=0)
    _checked_integer(expected["displayId"], "expected display ID", minimum=0,
                     maximum=1024)
    _checked_integer(expected["sessionGeneration"], "expected generation", minimum=0)
    _checked_string(expected["uri"], "expected URI")
    _checked_integer(expected["pageCount"], "expected page count", minimum=1,
                     maximum=MAX_PAGE_COUNT)
    _checked_integer(expected["currentPageIndex"], "expected current page", minimum=0,
                     maximum=expected["pageCount"] - 1)
    if files["originalPdf"]["documentUri"] != expected["uri"]:
        raise SnapshotRunnerError("original PDF URI differs from expected session")
    bindings = manifest["bindings"]
    _exact_keys(bindings, {"activity", "viewModel", "pageInfo", "presenter",
                           "layers"}, "bindings")
    for role in ("activity", "viewModel", "pageInfo", "presenter"):
        _validate_role_binding(role, bindings[role], allow_unavailable=False)
    _validate_role_binding("layers", bindings["layers"], allow_unavailable=True)


def validate_binding(manifest: LoadedJson, binding: RunBinding) -> None:
    value = manifest.value
    attachment = value["attachment"]
    coordinator = value["coordinator"]
    if (type(binding.serial) is not str or SERIAL_RE.fullmatch(binding.serial) is None or
            type(binding.pid) is not int or binding.pid <= 0 or
            type(binding.start_time_ticks) is not str or
            START_RE.fullmatch(binding.start_time_ticks) is None or
            type(binding.observer_session_id) is not str or
            SESSION_RE.fullmatch(binding.observer_session_id) is None or
            type(binding.deadline_ms) is not int or
            not MIN_DEADLINE_MS <= binding.deadline_ms <= MAX_DEADLINE_MS):
        raise SnapshotRunnerError("run binding is invalid")
    if (attachment["pid"] != binding.pid or
            attachment["startTimeTicks"] != binding.start_time_ticks or
            coordinator["observerSessionId"] != binding.observer_session_id or
            coordinator["hardDeadlineMs"] != binding.deadline_ms):
        raise SnapshotRunnerError("run binding differs from manifest authority")


def build_injected_observer(manifest: LoadedJson, observer_raw: bytes) -> str:
    _revalidate_loaded_manifest(manifest)
    byte_wire = ",".join(str(value) for value in manifest.raw)
    prefix = (
        "globalThis.NATIVE_PAGE_SNAPSHOT_MANIFEST_UTF8=Object.freeze([" +
        byte_wire + "]);\n" +
        "globalThis.NATIVE_PAGE_SNAPSHOT_MANIFEST_SHA256='" +
        manifest.sha256 + "';\n")
    try:
        observer = observer_raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SnapshotRunnerError("observer source is not strict UTF-8") from error
    return prefix + observer


def _require_adb_result(result: CommandResult, expected: bytes, label: str) -> None:
    if (type(result) is not CommandResult or result.returncode != 0 or
            result.stderr != b"" or result.stdout != expected):
        raise SnapshotRunnerError(label + " differs from exact ADB result")


def _parse_proc_start_time(raw: bytes, pid: int) -> str:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or len(raw) > 4096:
        raise SnapshotRunnerError("process stat wire is invalid")
    row = raw[:-1]
    prefix = str(pid).encode("ascii") + b" ("
    if not row.startswith(prefix):
        raise SnapshotRunnerError("process stat PID mismatch")
    close = row.rfind(b") ")
    if close < len(prefix):
        raise SnapshotRunnerError("process stat comm field is invalid")
    fields = row[close + 2:].split(b" ")
    if len(fields) < 20 or any(not field for field in fields):
        raise SnapshotRunnerError("process stat field count is invalid")
    try:
        start = fields[19].decode("ascii", "strict")
    except UnicodeError as error:
        raise SnapshotRunnerError("process start time is not ASCII") from error
    if START_RE.fullmatch(start) is None:
        raise SnapshotRunnerError("process start time is invalid")
    return start


def verify_target(adb: AdbAdapter, binding: RunBinding,
                  package_name: str = PACKAGE_NAME) -> None:
    timeout = max(MIN_DEADLINE_MS, min(binding.deadline_ms, MAX_DEADLINE_MS))
    prefix = ("-s", binding.serial)
    _require_adb_result(adb.run((*prefix, "get-serialno"), timeout),
                        (binding.serial + "\n").encode("ascii"), "device serial")
    _require_adb_result(adb.run((*prefix, "get-state"), timeout), b"device\n",
                        "device state")
    stat_result = adb.run(
        (*prefix, "exec-out", "cat", f"/proc/{binding.pid}/stat"), timeout)
    if (stat_result.returncode != 0 or stat_result.stderr or
            len(stat_result.stdout) > MAX_ADB_OUTPUT_BYTES or
            _parse_proc_start_time(stat_result.stdout, binding.pid) !=
            binding.start_time_ticks):
        raise SnapshotRunnerError("target PID/starttime is not live")
    _require_adb_result(
        adb.run((*prefix, "exec-out", "cat", f"/proc/{binding.pid}/cmdline"),
                timeout), package_name.encode("utf-8") + b"\x00", "process name")


def make_evidence_request(phase: str, manifest: LoadedJson,
                          binding: RunBinding) -> EvidenceRequest:
    if phase not in ("before", "after"):
        raise SnapshotRunnerError("invalid evidence phase")
    value = manifest.value
    original = value["files"]["originalPdf"]
    return EvidenceRequest(
        phase, manifest.sha256, binding, value["attachment"]["packageName"],
        copy.deepcopy(value["attachment"]["apk"]),
        copy.deepcopy(value["attachment"]["module"]), copy.deepcopy(original),
        copy.deepcopy(value["files"]["mark"]),
        copy.deepcopy(original["uriResolution"]))


def capture_evidence(provider: EvidenceProvider, phase: str, manifest: LoadedJson,
                     binding: RunBinding) -> LoadedJson:
    # Capture and validation receive distinct deep snapshots so an adapter cannot
    # rewrite the expected record through a mutable request object.
    capture_request = make_evidence_request(phase, manifest, binding)
    expected_request = make_evidence_request(phase, manifest, binding)
    return validate_evidence(provider.capture(capture_request), expected_request)


def validate_evidence_provider(provider: EvidenceProvider) -> None:
    try:
        admission = provider.admission()
    except HardwareAdmissionBlocked:
        raise
    except BaseException as error:
        raise SnapshotRunnerError("evidence provider admission failed") from error
    _exact_keys(admission, {"schemaVersion", "authority", "recordAuthority",
                            "captureMode", "captures"}, "evidence provider admission")
    if admission != {
            "schemaVersion": 1,
            "authority": EVIDENCE_PROVIDER_AUTHORITY,
            "recordAuthority": EVIDENCE_AUTHORITY,
            "captureMode": "independent-before-and-after-exact",
            "captures": ["apk", "module", "originalPdf", "mark", "uriResolution"],
    }:
        raise SnapshotRunnerError("evidence provider is not admitted")


def validate_evidence(evidence: AuthenticatedEvidence,
                      request: EvidenceRequest) -> LoadedJson:
    if (type(evidence) is not AuthenticatedEvidence or
            type(evidence.sha256) is not str or
            SHA256_RE.fullmatch(evidence.sha256) is None):
        raise SnapshotRunnerError("external evidence wrapper is invalid")
    loaded = _load_canonical_json_bytes(evidence.raw, MAX_EVIDENCE_BYTES)
    if loaded.sha256 != evidence.sha256:
        raise SnapshotRunnerError("external evidence detached digest mismatch")
    value = loaded.value
    _exact_keys(value, {"schemaVersion", "authority", "phase", "manifestSha256",
                        "serial", "pid", "startTimeTicks", "observerSessionId",
                        "packageName", "apk", "module", "originalPdf", "mark",
                        "uriResolution"}, "external evidence")
    expected = {
        "schemaVersion": SCHEMA_VERSION,
        "authority": EVIDENCE_AUTHORITY,
        "phase": request.phase,
        "manifestSha256": request.manifest_sha256,
        "serial": request.binding.serial,
        "pid": request.binding.pid,
        "startTimeTicks": request.binding.start_time_ticks,
        "observerSessionId": request.binding.observer_session_id,
        "packageName": request.package_name,
        "apk": request.apk,
        "module": request.module,
        "originalPdf": request.original_pdf,
        "mark": request.mark,
        "uriResolution": request.uri_resolution,
    }
    if (type(value["schemaVersion"]) is not int or
            not _json_exact_equal(value, expected)):
        raise SnapshotRunnerError("external evidence differs from exact authority")
    return loaded


def _evidence_stable(before: LoadedJson, after: LoadedJson) -> None:
    left = dict(before.value)
    right = dict(after.value)
    if (left.pop("phase", None) != "before" or
            right.pop("phase", None) != "after" or
            not _json_exact_equal(left, right)):
        raise SnapshotRunnerError("external file/module authority changed during snapshot")


def _decoded_binary64(value: Any, label: str) -> float:
    _exact_keys(value, {"binary64"}, label)
    wire = value["binary64"]
    if type(wire) is not str or BINARY64_RE.fullmatch(wire) is None:
        raise SnapshotRejected(label + " binary64 wire is invalid")
    number = struct.unpack(">d", bytes.fromhex(wire[2:]))[0]
    if not (-1_000_000_000_000 <= number <= 1_000_000_000_000):
        raise SnapshotRejected(label + " binary64 value is nonfinite or out of range")
    return number


def _decoded_array(value: Any, length: int, label: str) -> list[float]:
    if type(value) is not list or len(value) != length:
        raise SnapshotRejected(label + " array shape is invalid")
    return [_decoded_binary64(item, label + " item") for item in value]


def _validate_page_info(value: Any, expected_page: int,
                        manifest: LoadedJson) -> None:
    _exact_keys(value, {"identity", "pageIndex", "size", "crop", "ctm", "inverse",
                        "offset", "bitmapDimensions"}, "snapshot page info")
    _checked_string(value["identity"], "snapshot page identity")
    if (value["identity"] !=
            manifest.value["bindings"]["pageInfo"]["selector"]["identity"] or
            type(value["pageIndex"]) is not int or value["pageIndex"] != expected_page):
        raise SnapshotRejected("snapshot page-info index mismatch")
    size = _decoded_array(value["size"], 2, "snapshot page size")
    crop = _decoded_array(value["crop"], 4, "snapshot page crop")
    forward = _decoded_array(value["ctm"], 6, "snapshot page CTM")
    inverse = _decoded_array(value["inverse"], 6, "snapshot page inverse")
    _decoded_array(value["offset"], 2, "snapshot page offset")
    dimensions = value["bitmapDimensions"]
    if (not 0 < size[0] <= 10_000_000 or not 0 < size[1] <= 10_000_000 or
            not crop[2] > crop[0] or not crop[3] > crop[1] or
            type(dimensions) is not list or len(dimensions) != 2 or
            any(type(item) is not int or not 0 < item <= 10_000_000
                for item in dimensions)):
        raise SnapshotRejected("snapshot page geometry is invalid")
    determinant = forward[0] * forward[3] - forward[1] * forward[2]
    linear_norm = max(abs(forward[0]), abs(forward[1]), abs(forward[2]),
                      abs(forward[3]))
    epsilon = 2.220446049250313e-16
    if (linear_norm <= 0 or
            abs(determinant) <= epsilon * linear_norm * linear_norm * 64):
        raise SnapshotRejected("snapshot CTM is singular or unstable")
    expected_inverse = [
        forward[3] / determinant, -forward[1] / determinant,
        -forward[2] / determinant, forward[0] / determinant,
        (forward[2] * forward[5] - forward[3] * forward[4]) / determinant,
        (forward[1] * forward[4] - forward[0] * forward[5]) / determinant,
    ]
    if any(not (-1_000_000_000_000 <= item <= 1_000_000_000_000)
           for item in expected_inverse):
        raise SnapshotRejected("snapshot derived inverse is out of range")
    inverse_norm = max(abs(inverse[0]), abs(inverse[1]), abs(inverse[2]),
                       abs(inverse[3]))
    if linear_norm * inverse_norm > 1_000_000_000_000:
        raise SnapshotRejected("snapshot CTM condition bound is exceeded")
    for index, (actual, expected) in enumerate(zip(inverse, expected_inverse)):
        multiplier = 256 if index < 4 else 512
        tolerance = epsilon * multiplier * max(1, abs(actual), abs(expected))
        if abs(actual - expected) > tolerance:
            raise SnapshotRejected("snapshot CTM inverse mismatch")


def _validate_presenter(value: Any, manifest: LoadedJson) -> None:
    _exact_keys(value, set(ROLE_FIELDS["presenter"]), "snapshot presenter")
    for name in ("identity", "noteIdentity", "clientIdentity", "binderIdentity"):
        _checked_string(value[name], "snapshot presenter " + name)
    expected_page = manifest.value["expected"]["currentPageIndex"]
    if (value["identity"] !=
            manifest.value["bindings"]["presenter"]["selector"]["identity"] or
            type(value["currentPageIndex"]) is not int or
            value["currentPageIndex"] != expected_page or
            type(value["rotation"]) is not int or
            not -360 <= value["rotation"] <= 360):
        raise SnapshotRejected("snapshot presenter page/rotation is invalid")
    mark = manifest.value["files"]["mark"]
    expected_mark = mark["path"] if mark["present"] else None
    if value["markPath"] != expected_mark:
        raise SnapshotRejected("snapshot presenter mark path mismatch")


def _validate_layers(value: Any, manifest: LoadedJson) -> None:
    binding = manifest.value["bindings"]["layers"]
    if binding.get("status") == "unavailable":
        expected = {
            "status": "unavailable", "reasonCode": binding["reasonCode"],
            "evidenceId": binding["evidenceId"],
        }
        if not _json_exact_equal(value, expected):
            raise SnapshotRejected("snapshot unavailable-layer authority mismatch")
        return
    _exact_keys(value, set(ROLE_FIELDS["layers"]), "snapshot layers")
    for name in ROLE_FIELDS["layers"]:
        _checked_string(value[name], "snapshot layer " + name)
    if value["identity"] != binding["selector"]["identity"]:
        raise SnapshotRejected("snapshot layer selector identity mismatch")


class _V1MessageCollector:
    """Exact schema adapter for the pinned v1 observer; not firmware admission."""

    def __init__(self, manifest: LoadedJson, binding: RunBinding,
                 deadline_ns: int, clock_ns: Callable[[], int]):
        self.manifest = manifest
        self.binding = binding
        self.deadline_ns = deadline_ns
        self.clock_ns = clock_ns
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.messages = 0
        self.snapshot: dict[str, Any] | None = None
        self.error_payload: dict[str, Any] | None = None
        self.terminal: dict[str, Any] | None = None
        self.violation: str | None = None
        self.closed = False
        self.terminal_received_ns: int | None = None

    def receive(self, message: Any, data: Any) -> None:
        with self.lock:
            try:
                received_ns = self.clock_ns()
                if received_ns > self.deadline_ns:
                    raise SnapshotDeadlineExceeded(
                        "observer frame arrived after hard deadline")
                if self.closed:
                    raise SnapshotRejected("message arrived after detach")
                self.messages += 1
                if self.messages > 3:
                    raise SnapshotRejected("observer message count exceeds bound")
                if data is not None:
                    raise SnapshotRejected("observer emitted binary data")
                if (type(message) is not dict or
                        set(message) != {"type", "payload"} or
                        message["type"] != "send" or
                        type(message["payload"]) is not dict):
                    raise SnapshotRejected("Frida message envelope is invalid")
                _bounded_canonical_json_bytes(message, MAX_MESSAGE_BYTES)
                payload = message["payload"]
                event = payload.get("event")
                if event == "native_page_snapshot":
                    if self.snapshot is not None or self.error_payload is not None or \
                            self.terminal is not None:
                        raise SnapshotRejected("snapshot frame is duplicated or out of order")
                    self._validate_snapshot(payload)
                    self.snapshot = payload
                elif event == "native_page_snapshot_error":
                    if self.snapshot is not None or self.error_payload is not None or \
                            self.terminal is not None:
                        raise SnapshotRejected("error frame is duplicated or out of order")
                    _exact_keys(payload, {"event", "schemaVersion", "code", "message"},
                                "snapshot error")
                    if (payload["schemaVersion"] != SCHEMA_VERSION or
                            payload["code"] != "SNAPSHOT_REJECTED" or
                            type(payload["message"]) is not str or
                            len(payload["message"]) > 512):
                        raise SnapshotRejected("snapshot error frame is invalid")
                    self.error_payload = payload
                elif event == "native_page_snapshot_complete":
                    if self.terminal is not None:
                        raise SnapshotRejected("terminal frame is duplicated")
                    _exact_keys(payload, {"event", "success"}, "snapshot terminal")
                    if type(payload["success"]) is not bool:
                        raise SnapshotRejected("terminal success is not boolean")
                    if ((payload["success"] is True and
                         (self.snapshot is None or self.error_payload is not None)) or
                            (payload["success"] is False and
                             (self.error_payload is None or self.snapshot is not None))):
                        raise SnapshotRejected("terminal frame disagrees with prior frame")
                    terminal_completed_ns = self.clock_ns()
                    if terminal_completed_ns > self.deadline_ns:
                        raise SnapshotDeadlineExceeded(
                            "terminal frame completed after hard deadline")
                    self.terminal = payload
                    self.terminal_received_ns = terminal_completed_ns
                    self.event.set()
                else:
                    raise SnapshotRejected("observer event is unknown")
            except (SnapshotRunnerError, TypeError, ValueError) as error:
                self.violation = str(error)
                self.event.set()

    def _validate_snapshot(self, payload: dict[str, Any]) -> None:
        _exact_keys(payload, {"event", "schemaVersion", "authority",
                              "manifestSha256", "observationOnly", "atomic",
                              "attachment", "fileAuthority", "coordinator", "session",
                              "document", "presenter", "layers",
                              "drawPathPrerequisite"}, "snapshot")
        if (type(payload["schemaVersion"]) is not int or
                payload["schemaVersion"] != SCHEMA_VERSION or
                payload["authority"] != "rtl-reader-native-page-snapshot-v1" or
                payload["manifestSha256"] != self.manifest.sha256 or
                payload["observationOnly"] is not True or payload["atomic"] is not False):
            raise SnapshotRejected("snapshot authority is invalid")
        attachment = payload["attachment"]
        _exact_keys(attachment, {"packageName", "processName", "pid",
                                 "processStartTimeTicks", "architecture", "pointerSize",
                                 "apk", "module"}, "snapshot attachment")
        expected_apk = self.manifest.value["attachment"]["apk"]
        expected_module = self.manifest.value["attachment"]["module"]
        _exact_keys(attachment["apk"], {"path", "size", "externallyVerifiedSha256"},
                    "snapshot APK")
        _exact_keys(attachment["module"],
                    {"name", "path", "size", "externallyVerifiedSha256"},
                    "snapshot module")
        if (attachment["packageName"] != PACKAGE_NAME or
                attachment["processName"] != PROCESS_NAME or
                type(attachment["pid"]) is not int or
                attachment["pid"] != self.binding.pid or
                attachment["processStartTimeTicks"] != self.binding.start_time_ticks or
                attachment["architecture"] != "arm64" or
                attachment["pointerSize"] != 8 or
                type(attachment["apk"]["size"]) is not int or
                type(attachment["module"]["size"]) is not int or
                attachment["apk"] != {
                    "path": expected_apk["path"], "size": expected_apk["size"],
                    "externallyVerifiedSha256": expected_apk["sha256"],
                } or
                attachment["module"] != {
                    "name": expected_module["name"], "path": expected_module["path"],
                    "size": expected_module["size"],
                    "externallyVerifiedSha256": expected_module["sha256"],
                }):
            raise SnapshotRejected("snapshot process authority mismatch")
        coordinator = payload["coordinator"]
        _exact_keys(coordinator, {"authority", "observerSessionId", "hardDeadlineMs",
                                  "javaChooseWalks", "externalDetachOnDeadline",
                                  "externalTargetLivenessPostconditionRequired"},
                    "snapshot coordinator")
        expected_walks = (10 if self.manifest.value["bindings"]["layers"].get(
            "status") == "bound" else 8)
        if (coordinator["authority"] !=
                "rtl-reader-native-page-snapshot-coordinator-v1" or
                coordinator["observerSessionId"] != self.binding.observer_session_id or
                coordinator["hardDeadlineMs"] != self.binding.deadline_ms or
                coordinator["externalDetachOnDeadline"] is not True or
                coordinator["externalTargetLivenessPostconditionRequired"] is not True or
                type(coordinator["javaChooseWalks"]) is not int or
                coordinator["javaChooseWalks"] != expected_walks):
            raise SnapshotRejected("snapshot coordinator authority mismatch")
        if not _json_exact_equal(payload["fileAuthority"],
                                 self.manifest.value["files"]):
            raise SnapshotRejected("snapshot echoed file authority mismatch")
        session = payload["session"]
        document = payload["document"]
        expected = self.manifest.value["expected"]
        _exact_keys(session, {"activityIdentity", "taskId", "displayId", "generation"},
                    "snapshot session")
        _exact_keys(document, {"viewModelIdentity", "uri", "currentPageIndex",
                               "pageCount", "pageInfo"}, "snapshot document")
        if (any(type(session[name]) is not int
                for name in ("taskId", "displayId", "generation")) or
                any(type(document[name]) is not int
                    for name in ("currentPageIndex", "pageCount")) or
                type(document["uri"]) is not str or
                session["taskId"] != expected["taskId"] or
                session["displayId"] != expected["displayId"] or
                session["generation"] != expected["sessionGeneration"] or
                document["uri"] != expected["uri"] or
                document["currentPageIndex"] != expected["currentPageIndex"] or
                document["pageCount"] != expected["pageCount"]):
            raise SnapshotRejected("snapshot session/document binding mismatch")
        _checked_string(session["activityIdentity"], "snapshot activity identity")
        _checked_string(document["viewModelIdentity"], "snapshot view-model identity")
        if (session["activityIdentity"] !=
                self.manifest.value["bindings"]["activity"]["selector"]["identity"] or
                document["viewModelIdentity"] !=
                self.manifest.value["bindings"]["viewModel"]["selector"]["identity"]):
            raise SnapshotRejected("snapshot mandatory selector identity mismatch")
        _validate_page_info(document["pageInfo"], expected["currentPageIndex"],
                            self.manifest)
        _validate_presenter(payload["presenter"], self.manifest)
        _validate_layers(payload["layers"], self.manifest)
        prerequisite = payload["drawPathPrerequisite"]
        _exact_keys(prerequisite, {"status", "authority", "required", "requiredFields",
                                   "note"}, "draw-path prerequisite")
        if not _json_exact_equal(prerequisite, {
                "status": "external-prerequisite",
                "authority": "rtl-reader-drawpath-scalar-snapshot-v1",
                "required": True,
                "requiredFields": ["pid", "startTimeTicks", "screenWidth",
                                   "screenHeight", "documentImageWidth",
                                   "documentImageHeight"],
                "note": ("Capture independently from the pinned DrawPath process; "
                         "no offsets are inferred here."),
        }):
            raise SnapshotRejected("draw-path prerequisite contract mismatch")

    def close_and_result(self) -> dict[str, Any]:
        with self.lock:
            self.closed = True
            if self.violation is not None:
                raise SnapshotRejected(self.violation)
            if self.terminal is None:
                raise SnapshotRejected("observer terminal frame is missing")
            if self.terminal["success"] is not True or self.snapshot is None:
                raise SnapshotRejected("observer rejected the snapshot")
            if (self.terminal_received_ns is None or
                    self.terminal_received_ns > self.deadline_ns):
                raise SnapshotDeadlineExceeded("terminal frame missed hard deadline")
            return self.snapshot

    def assert_quiescent(self) -> None:
        with self.lock:
            if self.violation is not None:
                raise SnapshotRejected(self.violation)


def _remaining_seconds(deadline_ns: int, clock_ns: Callable[[], int]) -> float:
    return max(0.0, (deadline_ns - clock_ns()) / 1_000_000_000.0)


def _call_until(operation: Callable[[], Any], deadline_ns: int,
                clock_ns: Callable[[], int], label: str,
                late_cleanup: Callable[[Any], None] | None = None) -> Any:
    done = threading.Event()
    lock = threading.Lock()
    state: dict[str, Any] = {"abandoned": False}

    def worker() -> None:
        cleanup_value: Any | None = None
        try:
            value = operation()
            completed_ns = clock_ns()
            with lock:
                state["value"] = value
                state["completed_ns"] = completed_ns
                if state["abandoned"] and late_cleanup is not None:
                    state["cleanup_claimed"] = True
                    cleanup_value = value
            if cleanup_value is not None:
                try:
                    late_cleanup(cleanup_value)
                except BaseException:
                    pass
        except BaseException as error:
            completed_ns = clock_ns()
            with lock:
                state["error"] = error
                state["completed_ns"] = completed_ns
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True,
                     name="native-page-snapshot-" + label).start()
    remaining = _remaining_seconds(deadline_ns, clock_ns)
    completed = done.is_set() if remaining <= 0 else done.wait(remaining)
    if not completed:
        cleanup_value: Any | None = None
        with lock:
            state["abandoned"] = True
            if (late_cleanup is not None and "value" in state and
                    not state.get("cleanup_claimed", False)):
                state["cleanup_claimed"] = True
                cleanup_value = state["value"]
        if cleanup_value is not None:
            try:
                late_cleanup(cleanup_value)
            except BaseException:
                pass
        raise SnapshotDeadlineExceeded(label + " exceeded hard deadline")
    with lock:
        completed_ns = state.get("completed_ns")
        value = state.get("value")
    if type(completed_ns) is not int or completed_ns > deadline_ns:
        if late_cleanup is not None and value is not None:
            try:
                late_cleanup(value)
            except BaseException:
                pass
        raise SnapshotDeadlineExceeded(label + " exceeded hard deadline")
    if "error" in state:
        raise SnapshotRunnerError(label + " failed") from state["error"]
    return state.get("value")


def _late_session_cleanup(session: FridaSession) -> None:
    _cleanup_session(session, MIN_DEADLINE_MS)


def _cleanup_session(session: FridaSession, timeout_ms: int) -> list[str]:
    errors: list[str] = []
    for label, action in (("unload", session.unload), ("detach", session.detach)):
        deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        try:
            _call_until(action, deadline, time.monotonic_ns, "Frida " + label)
        except SnapshotRunnerError:
            errors.append(label)
    return errors


def run_snapshot(*, manifest: LoadedJson, observer_raw: bytes, binding: RunBinding,
                 adb: AdbAdapter, frida: FridaAdapter,
                 evidence_provider: EvidenceProvider,
                 clock_ns: Callable[[], int] = time.monotonic_ns) -> dict[str, Any]:
    """Integration-test seam for one v1 observation; there is no retry path.

    This callable does not itself establish provider authenticity. Its provider
    implementation is part of the trusted launcher and must pass the explicit
    admission contract. The production CLI remains blocked pending both that
    reviewed provider and a pinned-firmware v2 graph observer.
    """
    _revalidate_loaded_manifest(manifest)
    validate_binding(manifest, binding)
    observer_digest = hashlib.sha256(observer_raw).hexdigest()
    if observer_digest != EXPECTED_OBSERVER_SHA256:
        raise SnapshotRunnerError("observer source differs from exact authority")
    source = build_injected_observer(manifest, observer_raw)
    validate_evidence_provider(evidence_provider)
    verify_target(adb, binding)
    before = capture_evidence(evidence_provider, "before", manifest, binding)

    deadline_ns = clock_ns() + binding.deadline_ms * 1_000_000
    collector = _V1MessageCollector(manifest, binding, deadline_ns, clock_ns)
    session: FridaSession | None = None
    operation_error: BaseException | None = None
    cleanup_errors: list[str] = []
    after: LoadedJson | None = None
    snapshot: dict[str, Any] | None = None
    try:
        session = _call_until(
            lambda: frida.attach(binding.serial, binding.pid), deadline_ns, clock_ns,
            "Frida attach", late_cleanup=_late_session_cleanup)
        _call_until(lambda: session.load(source, collector.receive), deadline_ns,
                    clock_ns, "Frida script load")
        remaining = _remaining_seconds(deadline_ns, clock_ns)
        if remaining <= 0 or not collector.event.wait(remaining):
            raise SnapshotDeadlineExceeded("observer exceeded hard deadline")
    except BaseException as error:
        operation_error = error
    finally:
        if session is not None:
            cleanup_errors = _cleanup_session(session, MIN_DEADLINE_MS)
        # Seal the callback channel immediately after the detach attempt. Any
        # callback racing with the postconditions becomes a fatal violation.
        try:
            snapshot = collector.close_and_result()
        except BaseException as error:
            operation_error = operation_error or error
        try:
            verify_target(adb, binding)
        except BaseException as error:
            operation_error = operation_error or error
        try:
            after = capture_evidence(evidence_provider, "after", manifest, binding)
        except BaseException as error:
            operation_error = operation_error or error

    if cleanup_errors:
        operation_error = operation_error or SnapshotRunnerError(
            "Frida cleanup failed: " + ",".join(cleanup_errors))
    if after is None:
        operation_error = operation_error or SnapshotRunnerError(
            "after evidence is unavailable")
    else:
        try:
            _evidence_stable(before, after)
        except BaseException as error:
            operation_error = operation_error or error
    try:
        collector.assert_quiescent()
    except BaseException as error:
        operation_error = operation_error or error
    if operation_error is not None:
        if isinstance(operation_error, SnapshotRunnerError):
            raise operation_error
        raise SnapshotRunnerError("snapshot operation failed") from operation_error
    assert snapshot is not None and after is not None
    return {
        "status": "PASS",
        "authority": RUNNER_AUTHORITY,
        "serial": binding.serial,
        "pid": binding.pid,
        "startTimeTicks": binding.start_time_ticks,
        "observerSessionId": binding.observer_session_id,
        "deadlineMs": binding.deadline_ms,
        "manifestSha256": manifest.sha256,
        "observerSha256": observer_digest,
        "observerSchemaAdapter": OBSERVER_SCHEMA_ADAPTER_AUTHORITY,
        "evidenceBeforeSha256": before.sha256,
        "evidenceAfterSha256": after.sha256,
        "snapshot": snapshot,
    }


def _terminal(status: str, reason: str) -> bytes:
    return _canonical_json_bytes({
        "authority": RUNNER_AUTHORITY, "reasonCode": reason, "status": status}) + b"\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--observer-source", required=True, type=Path)
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--start-time-ticks", required=True)
    parser.add_argument("--observer-session-id", required=True)
    parser.add_argument("--deadline-ms", required=True, type=int)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(arguments)
        manifest = load_manifest(args.manifest)
        load_observer_source(args.observer_source)
        binding = RunBinding(args.serial, args.pid, args.start_time_ticks,
                             args.observer_session_id, args.deadline_ms)
        validate_binding(manifest, binding)
        # Known blockers are reported before ADB or Frida is touched. There is
        # intentionally no CLI switch that weakens either missing authority.
        raise HardwareAdmissionBlocked(PRODUCTION_BLOCK_REASON)
    except HardwareAdmissionBlocked as error:
        reason = str(error)
        if reason != PRODUCTION_BLOCK_REASON:
            reason = "PRODUCTION_HARDWARE_AUTHORITY_UNAVAILABLE"
        sys.stdout.buffer.write(_terminal(
            "HARDWARE_ADMISSION_BLOCKED", reason))
        return 2
    except (SnapshotRunnerError, OSError, OverflowError, TypeError, ValueError):
        sys.stdout.buffer.write(_terminal("REJECTED", "SNAPSHOT_RUNNER_REJECTED"))
        return 2
    sys.stdout.buffer.write(_terminal("REJECTED", "UNREACHABLE_ADMISSION_STATE"))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
