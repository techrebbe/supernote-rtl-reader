"""Fail-closed single-stage runner for the native page graph v2 observer.

The callable integration seam is complete and injectable.  The CLI remains
blocked until reviewed production implementations exist for the locked private
ADB channel, external authorities, and authenticated Frida lifecycle.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

from native_page_android_authority import (
    AUTHORITY as ANDROID_TASK_AUTHORITY,
    DocumentTaskAuthority,
    FULL_COMPONENT as DOCUMENT_ACTIVITY_FULL_COMPONENT,
    MAX_PID as ANDROID_MAX_PID,
    PACKAGE as ANDROID_PACKAGE_NAME,
    PROCESS as ANDROID_PROCESS_NAME,
    SHORT_COMPONENT as DOCUMENT_ACTIVITY_SHORT_COMPONENT,
    SYSTEM_UID as ANDROID_SYSTEM_UID,
)
from native_page_windows_tool_authority import (
    AUTHORITY as WINDOWS_TOOL_AUTHORITY,
    FILENAMES as WINDOWS_TOOL_FILENAMES,
    ToolAuthorityError,
)


SCHEMA_VERSION = 2
RUNNER_AUTHORITY = "rtl-reader-native-page-graph-runner-v2"
MANIFEST_AUTHORITY = "rtl-reader-native-page-graph-manifest-v2"
SNAPSHOT_AUTHORITY = "rtl-reader-native-page-graph-snapshot-v2"
COORDINATOR_AUTHORITY = "rtl-reader-native-page-graph-coordinator-v2"
EXTERNAL_SESSION_AUTHORITY = "rtl-reader-native-page-external-session-v2"
CALIBRATION_AUTHORITY = "rtl-reader-native-page-calibration-raw-v1"
FILE_AUTHORITY = "rtl-reader-native-page-file-authority-v1"
PROVIDER_ADMISSION_AUTHORITY = "rtl-reader-native-page-provider-admission-v2"
STAGE_AUTHORITY = "rtl-reader-native-page-external-stage-authority-v2"
STAGE_RECEIPT_AUTHORITY = "rtl-reader-native-page-stage-receipt-v2"
STAGE_POLICY_AUTHORITY = "rtl-reader-native-page-stage-policy-v2"
TARGET_AUTHORITY = "rtl-reader-target-process-authority-v2"
HOST_AUTHORITY = "rtl-reader-native-host-surface-authority-v2"
PEN_LEASE_AUTHORITY = "rtl-reader-live-pen-lease-v1"
ADB_SERVER_AUTHORITY = "rtl-reader-private-adb-server-authority-v1"
FRIDA_AUTHORITY = "rtl-reader-frida-lifecycle-authority-v1"
CAPABILITY_CAPTURE_OPERATION_ID_V2 = "frida.collect_native_page.v2"
CAPABILITY_CAPTURE_PURPOSE_V2 = "visual.capture_native_page.v2"
CAPABILITY_CLEANUP_OPERATION_ID_V2 = "frida.cleanup_native_page.v2"
CAPABILITY_CLEANUP_PURPOSE_V2 = "visual.cleanup_after_capture.v2"
CAPABILITY_SESSION_CLOSE_OPERATION_ID_V2 = "session.close_successfully.v2"
CAPABILITY_SESSION_CLOSE_PURPOSE_V2 = "visual.successful_session_closure.v2"
CAPABILITY_OPERATION_IDLE_PURPOSE_V2 = "visual.open_operation_idle.v2"
PRODUCTION_BLOCK_REASON = "V2_AUTHENTICATED_PROVIDERS_UNAVAILABLE"
PACKAGE_NAME = "com.supernote.document"
# Frozen observer label. Android's real process/cmdline is PACKAGE_NAME.
OBSERVER_PROCESS_LABEL = "Document"
AUTHORIZED_SERIAL = "SN078C10015092"
EXPECTED_OBSERVER_SHA256 = (
    "46b674674ac78c6d4d22b770ee29a0d9371051bac76c9240ce7174d736b3282d"
)
FIRMWARE_FINGERPRINT = (
    "Supernote/Supernote/Supernote:11/RQ2A.210505.003/"
    "eng.supern.20260616.100032:user/release-keys"
)
APK_SIZE = 138_486_560
APK_SHA256 = "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482"
FRAMEWORK_SIZE = 30_186_065
FRAMEWORK_SHA256 = "c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_MANIFEST_BYTES = 131_072
MAX_OBSERVER_BYTES = 1_048_576
MAX_AUTHORITY_BYTES = 524_288
MAX_MESSAGE_BYTES = 2_097_152
MAX_STRING_BYTES = 4_096
MAX_PAGE_COUNT = 10_000_000
MAX_DIMENSION = 10_000_000
MAX_NUMERIC_ABS = 1_000_000_000_000.0
MIN_DEADLINE_MS = 250
MAX_DEADLINE_MS = 10_000
CLEANUP_TIMEOUT_MS = 250
CLEANUP_STEP_TIMEOUT_MS = 25
VIRTUAL_DISPLAY_WIDTH = 1404
VIRTUAL_DISPLAY_HEIGHT = 1872
VIRTUAL_DISPLAY_DENSITY_DPI = 300
VIRTUAL_DISPLAY_ROTATION = 0
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,39}\Z")
DECIMAL_ZERO_RE = re.compile(r"(?:0|[1-9][0-9]{0,39})\Z")
BINARY64_RE = re.compile(r"0x[0-9a-f]{16}\Z")
ANDROID_TOKEN_RE = re.compile(r"[0-9a-f]{1,16}\Z")
STAGES = frozenset(("FULL", "LEFT", "RIGHT"))
ADB_OVERRIDE_NAMES = (
    "ADB_SERVER_SOCKET", "ANDROID_ADB_SERVER_PORT", "ANDROID_SERIAL",
    "ADB_VENDOR_KEYS", "ANDROID_SDK_HOME", "ANDROID_USER_HOME",
)
REVIEWED_ADB_SHA256 = {
    "adb.exe": "b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f",
    "AdbWinApi.dll": "c1d653030b4bde65d3e07e4d0b0979e17be56df1436cdd15528630f27808050d",
    "AdbWinUsbApi.dll": "0710e894d9b40f71a670c13c694079d564c92c1279da382cfe4850983aaebe1b",
}


class GraphRunnerError(RuntimeError):
    """The stage cannot be executed or its result cannot be trusted."""


class HardwareAdmissionBlocked(GraphRunnerError):
    """A production authority is intentionally unavailable."""


class DeadlineExceeded(GraphRunnerError):
    """The sole external monotonic hard deadline expired."""


class SnapshotRejected(GraphRunnerError):
    """The observer framing or payload was negative or malformed."""


class ProviderQuiescenceFailure(GraphRunnerError):
    """A provider channel must be killed/joined before any further use."""


class AuthorityProviderQuiescenceFailure(ProviderQuiescenceFailure):
    """The external-authority provider channel is no longer reusable."""


class FridaProviderQuiescenceFailure(ProviderQuiescenceFailure):
    """The Frida provider channel is no longer reusable."""


class AuthorityReceiptFailure(AuthorityProviderQuiescenceFailure):
    """A fresh authority receipt was not authenticated or correctly chained."""


class CapabilityProviderQuiescenceFailure(ProviderQuiescenceFailure):
    """The v2 capability operation owner is no longer safely reusable."""


class CapabilityClosureUncertain(CapabilityProviderQuiescenceFailure):
    """Exact authenticated terminal closure could not be established."""


@dataclass(frozen=True)
class LoadedJson:
    raw: bytes
    value: dict[str, Any]
    sha256: str


@dataclass(frozen=True)
class CanonicalAuthority:
    raw: bytes
    sha256: str


@dataclass(frozen=True)
class StageBinding:
    serial: str
    pid: int
    start_time_ticks: str
    observer_session_id: str
    deadline_ms: int
    absolute_deadline_ns: int
    stage: str


@dataclass(frozen=True)
class AuthorityRequest:
    phase: str
    manifest_sha256: str
    binding: StageBinding
    absolute_deadline_ns: int
    tool_bundle_sha256: str
    run_nonce: str
    sequence: int
    previous_receipt_sha256: str | None


@dataclass(frozen=True)
class StageAuthorityCapture:
    record: CanonicalAuthority
    task: DocumentTaskAuthority
    receipt: CanonicalAuthority


@dataclass(frozen=True)
class TrustedPins:
    """Immutable/run-policy digests established before any live capture."""
    tool_bundle_sha256: str
    manifest_sha256: str
    provider_admission_sha256: str
    frida_admission_sha256: str
    stage_policy_sha256: str
    receipt_hmac_key: bytes = field(repr=False)


class OperationStartPermit:
    """Runner-owned, single-use operation-registration state machine.

    ``register`` is executed outside the permit mutex.  That is essential:
    deadline expiry must remain able to close admission while a provider IPC
    registration is blocked.  A provider is admissible only when registration
    occurs inside its retained isolated process and the runner's terminal
    fail-stop kills and joins that process.  Thus, once REGISTERING wins, the
    complete claim-to-callback interval is terminal-cancellation-owned.
    """
    def __init__(self, deadline_ns: int, clock_ns: Callable[[], int],
                 failure_type: type[ProviderQuiescenceFailure] =
                 ProviderQuiescenceFailure) -> None:
        self._lock = threading.Lock()
        self._sealed = False
        self._expired = False
        self._starts = 0
        self._state = "OPEN"
        self._contract_violation: str | None = None
        self._settled = threading.Event()
        self._owner_thread_id = threading.get_ident()
        self._deadline_ns = deadline_ns
        self._clock_ns = clock_ns
        self._failure_type = failure_type

    def start(self, register: Callable[[], Any]) -> Any:
        if not callable(register):
            raise self._failure_type("operation registration is not callable")
        with self._lock:
            if threading.get_ident() != self._owner_thread_id:
                self._contract_violation = "operation start attempted from a foreign thread"
                raise self._failure_type(self._contract_violation)
            try:
                now = self._clock_ns()
            except BaseException as error:
                self._sealed = True
                self._expired = True
                raise DeadlineExceeded("operation start clock failed closed") from error
            if type(now) is not int or now >= self._deadline_ns:
                self._sealed = True
                self._expired = True
            if self._expired:
                raise DeadlineExceeded("operation start denied after deadline")
            if self._sealed:
                raise self._failure_type("operation start denied after permit seal")
            if self._state != "OPEN" or self._starts != 0:
                self._contract_violation = "operation start permit was reused"
                raise self._failure_type("operation start permit was reused")
            self._starts = 1
            self._state = "REGISTERING"
        try:
            result = register()
        except BaseException:
            with self._lock:
                self._state = "REGISTER_FAILED"
                self._settled.set()
            raise
        with self._lock:
            self._state = "REGISTERED"
            self._settled.set()
            expired = self._expired
            sealed = self._sealed
            violation = self._contract_violation
        if expired:
            raise DeadlineExceeded("operation registration completed after deadline")
        if sealed or violation is not None:
            raise self._failure_type(
                violation or "operation registration completed after permit seal")
        return result

    def expire(self) -> None:
        with self._lock:
            self._sealed = True
            self._expired = True

    def seal(self) -> None:
        """Deny retained late starts without misclassifying normal completion."""
        with self._lock:
            self._sealed = True

    @property
    def registering(self) -> bool:
        with self._lock:
            return self._state == "REGISTERING"

    def require_exact_start(self, failure_type: type[ProviderQuiescenceFailure]) -> None:
        with self._lock:
            if (self._starts != 1 or self._state != "REGISTERED" or
                    not self._settled.is_set() or
                    self._contract_violation is not None):
                raise failure_type("provider did not atomically consume operation start permit")


class LockedToolBundle(Protocol):
    @property
    def executable(self) -> str: ...

    def verify(self) -> None: ...

    def canonical_bytes(self) -> bytes: ...


class AuthorityProvider(Protocol):
    """Isolated provider whose fail-stop method owns its process kill/join.

    All ordinary calls are synchronous and self-bounded.  They may return or
    raise only after any operation they started is quiescent.  The separately
    reviewed production adapter must implement ``fail_stop_and_quiesce`` by
    terminating and joining its retained isolated process handle; this runner
    remains hardware-blocked until that adapter exists.  The coordinator also
    provisions a per-run 256-bit receipt HMAC capability to that retained
    process over private IPC.  The key is never emitted in evidence; the
    provider may authenticate only records it acquired itself.
    """
    def admission(self, timeout_ms: int,
                  start_permit: OperationStartPermit) -> CanonicalAuthority: ...

    def capture(self, request: AuthorityRequest, timeout_ms: int,
                start_permit: OperationStartPermit) -> StageAuthorityCapture: ...

    def cancel_and_quiesce(self, timeout_ms: int) -> None: ...

    def assert_quiescent(self, timeout_ms: int) -> None: ...

    def fail_stop_and_quiesce(self, timeout_ms: int) -> None: ...


class FridaSession(Protocol):
    def load(self, source: str, on_message: Callable[[Any, Any], None], timeout_ms: int,
             start_permit: OperationStartPermit) -> None: ...

    def seal_callbacks(self, timeout_ms: int) -> None: ...

    def unload(self, timeout_ms: int) -> None: ...

    def detach(self, timeout_ms: int) -> None: ...

    def assert_quiescent(self, timeout_ms: int) -> None: ...


class FridaProvider(Protocol):
    """Isolated Frida owner with exact process/file teardown.

    ``teardown`` is the fail-stop boundary: it may report an evidence error,
    but may not return or raise until its retained host/device process handles
    are killed and joined and callbacks are sealed.  Production remains
    blocked until a reviewed implementation proves that invariant.
    """
    def admission(self, timeout_ms: int,
                  start_permit: OperationStartPermit) -> CanonicalAuthority: ...

    def attach(self, serial: str, pid: int, timeout_ms: int,
               start_permit: OperationStartPermit) -> FridaSession: ...

    def teardown(self, timeout_ms: int) -> None: ...

    def assert_quiescent(self, timeout_ms: int) -> None: ...


class CapabilityOperationStartPermitV2:
    """Read-only operation identity wrapped around the runner's start permit.

    The external operation owner must consume this exact object once.  Its
    execution deadline is the effect deadline for capture and the closure
    deadline for cleanup, while ``request_deadline_ns`` remains the original
    effect deadline in both cases.  This prevents cleanup grace from silently
    becoming a new request authority.
    """

    __slots__ = (
        "_permit", "_operation_id", "_operation_purpose", "_sequence",
        "_request_deadline_ns", "_execution_deadline_ns", "_session_id",
        "_session_epoch")

    def __init__(self, permit: OperationStartPermit, *, operation_id: str,
                 operation_purpose: str, sequence: int,
                 request_deadline_ns: int, execution_deadline_ns: int,
                 session_id: str, session_epoch: str) -> None:
        if type(permit) is not OperationStartPermit:
            raise CapabilityProviderQuiescenceFailure(
                "capability operation start permit type differs")
        object.__setattr__(self, "_permit", permit)
        object.__setattr__(self, "_operation_id", operation_id)
        object.__setattr__(self, "_operation_purpose", operation_purpose)
        object.__setattr__(self, "_sequence", sequence)
        object.__setattr__(self, "_request_deadline_ns", request_deadline_ns)
        object.__setattr__(self, "_execution_deadline_ns", execution_deadline_ns)
        object.__setattr__(self, "_session_id", session_id)
        object.__setattr__(self, "_session_epoch", session_epoch)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("capability operation start permit is immutable")

    @property
    def operation_id(self) -> str:
        return self._operation_id

    @property
    def operation_purpose(self) -> str:
        return self._operation_purpose

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def request_deadline_ns(self) -> int:
        return self._request_deadline_ns

    @property
    def execution_deadline_ns(self) -> int:
        return self._execution_deadline_ns

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def session_epoch(self) -> str:
        return self._session_epoch

    def start(self, register: Callable[[], Any]) -> Any:
        return self._permit.start(register)


@dataclass(frozen=True)
class CapabilityOperationCompletionV2:
    """Retained authenticated OPEN-idle evidence for one exact operation."""

    sequence: int
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    generation: int
    outcome: Any
    open_idle_receipt: Any


@dataclass(frozen=True)
class CapabilityTerminalClosureV2:
    """Retained typed terminal evidence; OPEN-idle is never accepted here."""

    generation: int
    component_receipts: tuple[Any, ...]
    session_receipt: Any


@dataclass(frozen=True)
class _CapabilityApiV2:
    binding_type: type
    session_type: type
    lease_type: type
    detached_payload_type: type
    callback_type: type
    outcome_type: type
    open_idle_receipt_type: type
    component_closure_receipt_type: type
    successful_closure_receipt_type: type
    frida_factory_id: str


def _load_capability_api_v2() -> _CapabilityApiV2:
    """Load the frozen capability types without changing the v1 import path."""

    try:
        module = __import__("native_page_worker_capability_ipc", fromlist=("*",))
        names = (
            "CapabilityBindingBodyV2", "CapabilitySessionV2", "OperationLeaseV2",
            "DetachedPayloadV2", "CallbackRecordV2", "OperationOutcomeV2",
            "OpenOperationIdleReceiptV2", "ClosureComponentReceiptV2",
            "SuccessfulSessionClosureReceiptV2",
        )
        values = tuple(getattr(module, name) for name in names)
        frida_factory_id = getattr(module, "FRIDA_FACTORY_ID")
        operation_constants = tuple(getattr(module, name) for name in (
            "FRIDA_CAPTURE_OPERATION_V2", "FRIDA_CAPTURE_PURPOSE_V2",
            "FRIDA_CLEANUP_OPERATION_V2", "FRIDA_CLEANUP_PURPOSE_V2",
            "SESSION_CLOSE_OPERATION_V2", "SESSION_CLOSE_PURPOSE_V2",
            "OPERATION_IDLE_PURPOSE_V2"))
    except (ImportError, AttributeError) as error:
        raise HardwareAdmissionBlocked(
            "the frozen capability-v2 API is unavailable") from error
    if (any(type(value) is not type for value in values) or
            type(frida_factory_id) is not str or not frida_factory_id):
        raise HardwareAdmissionBlocked(
            "the frozen capability-v2 API type surface differs")
    if operation_constants != (
            CAPABILITY_CAPTURE_OPERATION_ID_V2, CAPABILITY_CAPTURE_PURPOSE_V2,
            CAPABILITY_CLEANUP_OPERATION_ID_V2, CAPABILITY_CLEANUP_PURPOSE_V2,
            CAPABILITY_SESSION_CLOSE_OPERATION_ID_V2,
            CAPABILITY_SESSION_CLOSE_PURPOSE_V2,
            CAPABILITY_OPERATION_IDLE_PURPOSE_V2):
        raise HardwareAdmissionBlocked(
            "the frozen capability-v2 operation table differs")
    return _CapabilityApiV2(*values, frida_factory_id)


def _fail(message: str) -> None:
    raise GraphRunnerError(message)


def _exact(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != names:
        _fail(label + " has unknown or missing fields")
    return value


def _string(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or not value or "\x00" in value:
        _fail(label + " is not a nonempty string")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise GraphRunnerError(label + " is not UTF-8") from error
    if len(encoded) > MAX_STRING_BYTES:
        _fail(label + " exceeds its byte bound")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(label + " is not one bounded integer")
    return value


def _decimal(value: Any, label: str, *, zero: bool = False, digits: int = 40) -> str:
    expression = DECIMAL_ZERO_RE if zero else DECIMAL_RE
    if type(value) is not str or len(value) > digits or expression.fullmatch(value) is None:
        _fail(label + " is not canonical decimal")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        _fail(label + " is not lowercase SHA-256")
    return value


def _validate_domain(value: Any, depth: int = 0, wire_budget: list[int] | None = None) -> None:
    def consume(amount: int) -> None:
        if wire_budget is not None:
            wire_budget[0] -= amount
            if wire_budget[0] < 0:
                _fail("canonical JSON exceeds byte bound")

    if depth > 64:
        _fail("JSON depth exceeds bound")
    if value is None:
        consume(4)
        return
    if type(value) is bool:
        consume(4 if value else 5)
        return
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            _fail("JSON integer exceeds safe range")
        consume(len(str(value)))
        return
    if type(value) is str:
        _string(value, "JSON string")
        consume(len(json.dumps(value, ensure_ascii=False).encode("utf-8", "strict")))
        return
    if type(value) is list:
        if len(value) > 100_000:
            _fail("JSON array exceeds bound")
        consume(2 + max(0, len(value) - 1))
        for item in value:
            _validate_domain(item, depth + 1, wire_budget)
        return
    if type(value) is dict:
        if len(value) > 100_000:
            _fail("JSON object exceeds bound")
        consume(2 + max(0, len(value) - 1))
        for key, item in value.items():
            _string(key, "JSON key")
            consume(len(json.dumps(key, ensure_ascii=False).encode("utf-8", "strict")) + 1)
            _validate_domain(item, depth + 1, wire_budget)
        return
    _fail("unsupported JSON value")


def canonical_bytes(value: Any, limit: int | None = None) -> bytes:
    if limit is not None and (type(limit) is not int or limit < 1):
        _fail("canonical JSON byte bound differs")
    _validate_domain(value, wire_budget=None if limit is None else [limit])
    try:
        wire = json.dumps(value, ensure_ascii=False, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("utf-8", "strict")
    except (UnicodeError, ValueError, TypeError) as error:
        raise GraphRunnerError("JSON canonicalization failed") from error
    if limit is not None and len(wire) > limit:
        _fail("canonical JSON exceeds byte bound")
    return wire


def _wire_equal(left: Any, right: Any) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def _strict_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            _fail("duplicate JSON key")
        value[key] = item
    return value


def _reject_float(_: str) -> Any:
    _fail("JSON floating point is not admitted")


def _parse_int(wire: str) -> int:
    if len(wire) > 17:
        _fail("JSON integer wire exceeds bound")
    value = int(wire, 10)
    if abs(value) > MAX_SAFE_INTEGER:
        _fail("JSON integer exceeds safe range")
    return value


def load_canonical(raw: bytes, limit: int) -> LoadedJson:
    if type(raw) is not bytes or not 0 < len(raw) <= limit or b"\x00" in raw:
        _fail("canonical JSON wire is empty, oversized, or contains NUL")
    try:
        value = json.loads(raw.decode("utf-8", "strict"),
                           object_pairs_hook=_strict_pairs,
                           parse_float=_reject_float, parse_int=_parse_int,
                           parse_constant=_reject_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise GraphRunnerError("canonical JSON wire is invalid") from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        _fail("JSON wire is not one byte-exact canonical object")
    return LoadedJson(raw, value, hashlib.sha256(raw).hexdigest())


def _authority(value: CanonicalAuthority) -> LoadedJson:
    if type(value) is not CanonicalAuthority:
        _fail("authority wrapper type differs")
    loaded = load_canonical(value.raw, MAX_AUTHORITY_BYTES)
    if value.sha256 != loaded.sha256:
        _fail("authority detached digest differs")
    return loaded


def _validate_stat(value: Any, label: str) -> None:
    item = _exact(value, {"device", "inode", "mode", "uid", "gid",
                          "mtimeNs", "ctimeNs"}, label)
    _decimal(item["device"], label + ".device", zero=True)
    _decimal(item["inode"], label + ".inode")
    _decimal(item["mode"], label + ".mode")
    _integer(item["uid"], label + ".uid", 0, 2_147_483_647)
    _integer(item["gid"], label + ".gid", 0, 2_147_483_647)
    _decimal(item["mtimeNs"], label + ".mtimeNs", zero=True)
    _decimal(item["ctimeNs"], label + ".ctimeNs", zero=True)


def _validate_file(value: Any, label: str, *, original: bool,
                   required: bool) -> None:
    keys = {"present", "path", "size", "sha256", "stat"}
    if original:
        keys |= {"documentUri", "uriResolution"}
    item = _exact(value, keys, label)
    if type(item["present"]) is not bool:
        _fail(label + ".present is not boolean")
    if required and not item["present"]:
        _fail(label + " must be present")
    if not item["present"]:
        if any(item[name] is not None for name in ("path", "size", "sha256", "stat")):
            _fail(label + " absent payload is not null")
        if original:
            _fail(label + " original PDF cannot be absent")
        return
    path = _string(item["path"], label + ".path")
    _decimal(item["size"], label + ".size")
    _sha(item["sha256"], label + ".sha256")
    _validate_stat(item["stat"], label + ".stat")
    if not original:
        return
    uri = _string(item["documentUri"], label + ".documentUri")
    resolution = item["uriResolution"]
    if uri.startswith("file://"):
        resolution = _exact(resolution, {"authority", "documentUri", "resolvedPath",
                                         "evidenceSha256"}, label + ".uriResolution")
        if (resolution["authority"] != "rtl-reader-file-uri-resolution-v1" or
                resolution["documentUri"] != uri or resolution["resolvedPath"] != path):
            _fail(label + " file URI authority differs")
        _sha(resolution["evidenceSha256"], label + ".uriResolution.evidenceSha256")
        return
    if not uri.startswith("content://"):
        _fail(label + " URI scheme is not admitted")
    resolution = _exact(resolution, {"authority", "documentUri", "resolvedPath",
                                     "providerPackage", "providerApkSha256",
                                     "evidenceSha256"}, label + ".uriResolution")
    if (resolution["authority"] != "rtl-reader-content-uri-resolution-v1" or
            resolution["documentUri"] != uri or resolution["resolvedPath"] != path):
        _fail(label + " content URI authority differs")
    _string(resolution["providerPackage"], label + ".providerPackage")
    _sha(resolution["providerApkSha256"], label + ".providerApkSha256")
    _sha(resolution["evidenceSha256"], label + ".evidenceSha256")


def _validate_binary_file(value: Any, label: str, *, name: bool) -> None:
    keys = {"path", "size", "sha256"} | ({"name"} if name else set())
    item = _exact(value, keys, label)
    if name:
        _string(item["name"], label + ".name")
    _string(item["path"], label + ".path")
    _integer(item["size"], label + ".size", 1, MAX_SAFE_INTEGER)
    _sha(item["sha256"], label + ".sha256")


def validate_manifest(loaded: LoadedJson, binding: StageBinding,
                      observer_sha256: str) -> dict[str, Any]:
    if type(loaded) is not LoadedJson:
        _fail("manifest wrapper type differs")
    value = _exact(loaded.value, {"schemaVersion", "authority", "attachment",
                                  "externalSession", "files", "coordinator",
                                  "expected"}, "manifest")
    if value["schemaVersion"] != SCHEMA_VERSION or value["authority"] != MANIFEST_AUTHORITY:
        _fail("manifest identity differs")
    attachment = _exact(value["attachment"], {"packageName", "processName", "pid",
                                               "startTimeTicks", "firmwareFingerprint",
                                               "apk", "framework", "module",
                                               "observerSha256"}, "manifest.attachment")
    if (attachment["packageName"] != PACKAGE_NAME or attachment["processName"] != OBSERVER_PROCESS_LABEL or
            attachment["firmwareFingerprint"] != FIRMWARE_FINGERPRINT):
        _fail("manifest attachment pin differs")
    _integer(attachment["pid"], "manifest.attachment.pid", 1, 4_194_304)
    _decimal(attachment["startTimeTicks"], "manifest.attachment.startTimeTicks", digits=20)
    _validate_binary_file(attachment["apk"], "manifest.attachment.apk", name=False)
    _validate_binary_file(attachment["framework"], "manifest.attachment.framework", name=False)
    _validate_binary_file(attachment["module"], "manifest.attachment.module", name=True)
    if (attachment["apk"]["size"] != APK_SIZE or attachment["apk"]["sha256"] != APK_SHA256 or
            attachment["framework"]["size"] != FRAMEWORK_SIZE or
            attachment["framework"]["sha256"] != FRAMEWORK_SHA256):
        _fail("manifest firmware bytes differ")
    if (_sha(attachment["observerSha256"], "manifest.attachment.observerSha256") !=
            EXPECTED_OBSERVER_SHA256 or observer_sha256 != EXPECTED_OBSERVER_SHA256):
        _fail("observer source pin differs")
    external = _exact(value["externalSession"], {"authority", "authorizedSerial", "taskId",
                                                  "displayId", "hostSessionId",
                                                  "displayGeneration"}, "manifest.externalSession")
    if external["authority"] != EXTERNAL_SESSION_AUTHORITY or external["authorizedSerial"] != AUTHORIZED_SERIAL:
        _fail("external session identity differs")
    _integer(external["taskId"], "manifest.externalSession.taskId", 0, 10_000_000)
    _integer(external["displayId"], "manifest.externalSession.displayId", 1, 1024)
    if TOKEN_RE.fullmatch(_string(external["hostSessionId"], "manifest.externalSession.hostSessionId")) is None:
        _fail("host session ID syntax differs")
    _integer(external["displayGeneration"], "manifest.externalSession.displayGeneration", 1,
             MAX_SAFE_INTEGER)
    files = _exact(value["files"], {"authority", "verification", "originalPdf", "mark"},
                   "manifest.files")
    if files["authority"] != FILE_AUTHORITY or files["verification"] != "external-before-and-after-exact":
        _fail("manifest file authority differs")
    _validate_file(files["originalPdf"], "manifest.files.originalPdf", original=True, required=True)
    _validate_file(files["mark"], "manifest.files.mark", original=False, required=False)
    coordinator = _exact(value["coordinator"], {"authority", "observerSessionId",
                                                 "absoluteMonotonicDeadlineNs", "hardDeadlineMs",
                                                 "maxJavaChooseWalks", "retainedRootSamples",
                                                 "detachOnDeadline", "abortOnAnyError",
                                                 "verifyTargetLivenessAfter", "noRetry"},
                         "manifest.coordinator")
    if coordinator["authority"] != COORDINATOR_AUTHORITY:
        _fail("coordinator authority differs")
    if TOKEN_RE.fullmatch(_string(coordinator["observerSessionId"],
                                  "manifest.coordinator.observerSessionId")) is None:
        _fail("observer session ID syntax differs")
    _decimal(coordinator["absoluteMonotonicDeadlineNs"],
             "manifest.coordinator.absoluteMonotonicDeadlineNs", digits=30)
    _integer(coordinator["hardDeadlineMs"], "manifest.coordinator.hardDeadlineMs",
             MIN_DEADLINE_MS, MAX_DEADLINE_MS)
    fixed = {"maxJavaChooseWalks": 1, "retainedRootSamples": 2,
             "detachOnDeadline": True, "abortOnAnyError": True,
             "verifyTargetLivenessAfter": True, "noRetry": True}
    if any(type(coordinator[name]) is not type(expected) or coordinator[name] != expected
           for name, expected in fixed.items()):
        _fail("coordinator invariant differs")
    expected = _exact(value["expected"], {"documentUri", "calibrationProfile"},
                      "manifest.expected")
    _string(expected["documentUri"], "manifest.expected.documentUri")
    profile = _exact(expected["calibrationProfile"], {"authority", "status",
                                                       "pageIndexSemantics",
                                                       "matrixSemantics"},
                     "manifest.expected.calibrationProfile")
    if profile != {"authority": CALIBRATION_AUTHORITY, "status": "calibration-only",
                   "pageIndexSemantics": "independent-raw",
                   "matrixSemantics": "independent-raw"}:
        _fail("calibration profile differs")
    if files["originalPdf"]["documentUri"] != expected["documentUri"]:
        _fail("expected URI differs from file authority")
    if (type(binding) is not StageBinding or type(binding.serial) is not str or
            type(binding.pid) is not int or type(binding.start_time_ticks) is not str or
            type(binding.observer_session_id) is not str or
            type(binding.deadline_ms) is not int or
            type(binding.absolute_deadline_ns) is not int or
            type(binding.stage) is not str or binding.stage not in STAGES):
        _fail("stage binding differs")
    if (binding.serial != external["authorizedSerial"] or binding.pid != attachment["pid"] or
            binding.start_time_ticks != attachment["startTimeTicks"] or
            binding.observer_session_id != coordinator["observerSessionId"] or
            binding.deadline_ms != coordinator["hardDeadlineMs"] or
            str(binding.absolute_deadline_ns) != coordinator["absoluteMonotonicDeadlineNs"]):
        _fail("manifest differs from run binding")
    return value


def _read_regular_snapshot(path: Path, limit: int, label: str) -> bytes:
    try:
        selected = Path(path)
        before = os.lstat(selected)
        reparse = getattr(before, "st_file_attributes", 0) & 0x400
        if not os.path.isfile(selected) or os.path.islink(selected) or reparse:
            _fail(label + " is not one direct regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(selected, flags)
        try:
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino, opened.st_size,
                        getattr(opened, "st_mtime_ns", int(opened.st_mtime * 1e9)))
            expected = (before.st_dev, before.st_ino, before.st_size,
                        getattr(before, "st_mtime_ns", int(before.st_mtime * 1e9)))
            if identity != expected or opened.st_size <= 0 or opened.st_size > limit:
                _fail(label + " identity or size differs")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    _fail(label + " ended early")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                _fail(label + " grew during read")
            after_handle = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = os.lstat(selected)
        final_handle = (after_handle.st_dev, after_handle.st_ino, after_handle.st_size,
                        getattr(after_handle, "st_mtime_ns", int(after_handle.st_mtime * 1e9)))
        final_path = (after_path.st_dev, after_path.st_ino, after_path.st_size,
                      getattr(after_path, "st_mtime_ns", int(after_path.st_mtime * 1e9)))
        if final_handle != identity or final_path != identity or os.path.islink(selected) or \
                (getattr(after_path, "st_file_attributes", 0) & 0x400):
            _fail(label + " changed during retained read")
        return b"".join(chunks)
    except GraphRunnerError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise GraphRunnerError(label + " retained read failed") from error


def load_manifest(path: Path, binding: StageBinding, observer_sha256: str) -> LoadedJson:
    raw = _read_regular_snapshot(path, MAX_MANIFEST_BYTES, "manifest")
    loaded = load_canonical(raw, MAX_MANIFEST_BYTES)
    validate_manifest(loaded, binding, observer_sha256)
    return loaded


def load_observer_source(path: Path) -> tuple[str, str]:
    raw = _read_regular_snapshot(path, MAX_OBSERVER_BYTES, "observer source")
    if not 0 < len(raw) <= MAX_OBSERVER_BYTES or b"\x00" in raw:
        _fail("observer source is empty, oversized, or contains NUL")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_OBSERVER_SHA256:
        _fail("observer source digest differs")
    try:
        return raw.decode("utf-8", "strict"), digest
    except UnicodeError as error:
        raise GraphRunnerError("observer source is not UTF-8") from error


def build_injected_observer(manifest: LoadedJson, source: str) -> str:
    if type(source) is not str or not source:
        _fail("observer source type differs")
    prefix = ("globalThis.NATIVE_PAGE_GRAPH_MANIFEST_UTF8=Object.freeze(" +
              json.dumps(list(manifest.raw), separators=(",", ":")) + ");\n" +
              "globalThis.NATIVE_PAGE_GRAPH_MANIFEST_SHA256=" +
              json.dumps(manifest.sha256) + ";\n")
    result = prefix + source
    if len(result.encode("utf-8", "strict")) > MAX_OBSERVER_BYTES + MAX_MANIFEST_BYTES * 4:
        _fail("injected source exceeds bound")
    return result


def _validate_provider_admission(value: CanonicalAuthority, pins: TrustedPins) -> LoadedJson:
    loaded = _authority(value)
    if loaded.sha256 != pins.provider_admission_sha256:
        _fail("provider admission differs from trusted pin")
    item = _exact(loaded.value, {"schemaVersion", "authority", "implementationSha256",
                                 "providerSessionId",
                                 "independentCapture", "doesNotEchoManifest",
                                 "usesLockedAdbBundle", "privateAdbServer",
                                 "serverNodaemon", "serverProcessHandleRetained",
                                 "fixedMinimalEnvironment", "explicitSerialEveryCommand",
                                 "rejectsAmbientOverrides", "noSharedServer",
                                 "authenticatesFridaHostAndServer", "exactFridaTeardown",
                                 "capturesBeforeAndAfter", "providerProcessIsolated",
                                 "failurePathKillAndJoin",
                                 "failureReturnsOnlyAfterQuiescence",
                                 "atomicStartPermit", "challengeBoundReceipts",
                                 "freshCaptureIds", "receiptSequenceChain",
                                 "receiptMacAlgorithm", "receiptKeyId",
                                 "receiptAcquisitionOwnsSources"},
                  "provider admission")
    if item["schemaVersion"] != 2 or item["authority"] != PROVIDER_ADMISSION_AUTHORITY:
        _fail("provider admission identity differs")
    _sha(item["implementationSha256"], "provider implementation digest")
    expected_key_id = hashlib.sha256(pins.receipt_hmac_key).hexdigest()
    if (item["receiptMacAlgorithm"] != "HMAC-SHA256" or
            item["receiptKeyId"] != expected_key_id or
            item["receiptAcquisitionOwnsSources"] is not True):
        _fail("authority receipt authenticator admission differs")
    if TOKEN_RE.fullmatch(_string(item["providerSessionId"],
                                  "authority provider session")) is None:
        _fail("authority provider session differs")
    for name in ("independentCapture", "doesNotEchoManifest", "usesLockedAdbBundle",
                 "privateAdbServer", "serverNodaemon", "serverProcessHandleRetained",
                 "fixedMinimalEnvironment", "explicitSerialEveryCommand", "noSharedServer",
                 "authenticatesFridaHostAndServer", "exactFridaTeardown",
                 "capturesBeforeAndAfter", "providerProcessIsolated",
                 "failurePathKillAndJoin", "failureReturnsOnlyAfterQuiescence",
                 "atomicStartPermit", "challengeBoundReceipts", "freshCaptureIds",
                 "receiptSequenceChain", "receiptAcquisitionOwnsSources"):
        if item[name] is not True:
            _fail("provider admission property differs: " + name)
    if item["rejectsAmbientOverrides"] != list(ADB_OVERRIDE_NAMES):
        _fail("provider ADB override policy differs")
    return loaded


def _validate_frida_admission(value: CanonicalAuthority, pins: TrustedPins) -> LoadedJson:
    loaded = _authority(value)
    if loaded.sha256 != pins.frida_admission_sha256:
        _fail("Frida provider admission differs from trusted pin")
    item = _exact(loaded.value, {"schemaVersion", "authority", "implementationSha256",
                                 "providerSessionId", "isolatedCancellableLifecycle",
                                 "callbackQuiescenceBarrier", "singleAttach", "singleLoad",
                                 "exactTeardown", "teardownReturnsOnlyAfterKillJoin",
                                 "callbackChannelSealedBeforeReturn", "atomicStartPermit",
                                 "noRetry"},
                  "Frida provider admission")
    if (type(item["schemaVersion"]) is not int or item["schemaVersion"] != 1 or
            item["authority"] !=
            "rtl-reader-frida-provider-admission-v1"):
        _fail("Frida provider admission identity differs")
    _sha(item["implementationSha256"], "Frida provider implementation digest")
    if TOKEN_RE.fullmatch(_string(item["providerSessionId"], "Frida provider session")) is None:
        _fail("Frida provider session differs")
    for name in ("isolatedCancellableLifecycle", "callbackQuiescenceBarrier", "singleAttach",
                 "singleLoad", "exactTeardown", "teardownReturnsOnlyAfterKillJoin",
                 "callbackChannelSealedBeforeReturn", "atomicStartPermit", "noRetry"):
        if item[name] is not True:
            _fail("Frida provider admission property differs: " + name)
    return loaded


def _validate_trusted_pins(pins: TrustedPins) -> None:
    if type(pins) is not TrustedPins:
        _fail("trusted pins wrapper differs")
    for name in ("tool_bundle_sha256", "manifest_sha256", "provider_admission_sha256",
                 "frida_admission_sha256", "stage_policy_sha256"):
        _sha(getattr(pins, name), "trusted pin " + name)
    if type(pins.receipt_hmac_key) is not bytes or len(pins.receipt_hmac_key) != 32:
        _fail("trusted receipt HMAC capability differs")


def stage_policy_sha256(stage: dict[str, Any]) -> str:
    """Hash the independently constructible run policy, never a future receipt.

    Capture IDs, task raw-record hashes, measured lease countdown, and Frida's
    before/after teardown state are fresh output evidence.  Every other field
    remains in this policy projection and must be fixed by the external
    coordinator before the first capture.
    """
    if type(stage) is not dict:
        _fail("stage policy source differs")
    private = load_canonical(canonical_bytes(stage, MAX_AUTHORITY_BYTES),
                             MAX_AUTHORITY_BYTES).value
    for name in ("phase", "captureId", "taskAuthoritySha256"):
        private.pop(name, None)
    lease = dict(private.get("penLease", {}))
    lease.pop("remainingLeaseMs", None)
    private["penLease"] = lease
    frida = dict(private.get("frida", {}))
    for name in ("serverState", "processAbsent", "fileAbsent", "teardownOfSessionId"):
        frida.pop(name, None)
    private["frida"] = frida
    policy = {"schemaVersion": 2, "authority": STAGE_POLICY_AUTHORITY,
              "stageAuthority": private}
    return hashlib.sha256(canonical_bytes(policy)).hexdigest()


def _validate_capture_receipt(capture: StageAuthorityCapture, request: AuthorityRequest,
                              provider_admission: LoadedJson,
                              pins: TrustedPins) -> LoadedJson:
    if type(capture) is not StageAuthorityCapture:
        raise AuthorityReceiptFailure("stage capture wrapper differs")
    try:
        capture_loaded = _authority(capture.record)
        receipt = _authority(capture.receipt)
        item = _exact(receipt.value, {"schemaVersion", "authority",
                                      "providerImplementationSha256", "providerSessionId",
                                      "runNonce", "manifestSha256", "observerSessionId",
                                      "stage", "phase", "sequence",
                                      "previousReceiptSha256", "captureSha256",
                                      "absoluteMonotonicDeadlineNs", "receiptKeyId",
                                      "authenticator"}, "stage receipt")
        admission = provider_admission.value
        authenticated_body = dict(item)
        authenticator = authenticated_body.pop("authenticator")
        expected_authenticator = hmac.new(pins.receipt_hmac_key,
                                          canonical_bytes(authenticated_body,
                                                          MAX_AUTHORITY_BYTES),
                                          hashlib.sha256).hexdigest()
        if (type(authenticator) is not str or
                not hmac.compare_digest(authenticator, expected_authenticator)):
            raise AuthorityReceiptFailure("stage receipt authenticator differs")
        _integer(item["schemaVersion"], "receipt schema version", 2, 2)
        _integer(item["sequence"], "receipt sequence", 1, 2)
        for name in ("authority", "providerSessionId", "runNonce", "observerSessionId",
                     "stage", "phase", "absoluteMonotonicDeadlineNs"):
            _string(item[name], "receipt " + name)
        if (item["authority"] != STAGE_RECEIPT_AUTHORITY or
                item["providerImplementationSha256"] != admission["implementationSha256"] or
                item["providerSessionId"] != admission["providerSessionId"] or
                item["runNonce"] != request.run_nonce or
                item["manifestSha256"] != request.manifest_sha256 or
                item["observerSessionId"] != request.binding.observer_session_id or
                item["stage"] != request.binding.stage or item["phase"] != request.phase or
                item["sequence"] != request.sequence or
                item["previousReceiptSha256"] != request.previous_receipt_sha256 or
                item["captureSha256"] != capture_loaded.sha256 or
                item["absoluteMonotonicDeadlineNs"] != str(request.absolute_deadline_ns) or
                item["receiptKeyId"] != admission["receiptKeyId"]):
            raise AuthorityReceiptFailure("stage receipt binding differs")
        _sha(item["providerImplementationSha256"], "receipt provider implementation digest")
        _sha(item["manifestSha256"], "receipt manifest digest")
        _sha(item["captureSha256"], "receipt capture digest")
        _sha(item["receiptKeyId"], "receipt key ID")
        _sha(item["authenticator"], "receipt authenticator")
        if item["previousReceiptSha256"] is not None:
            _sha(item["previousReceiptSha256"], "receipt predecessor digest")
        if re.fullmatch(r"[0-9a-f]{64}", _string(item["runNonce"],
                                                  "receipt run nonce")) is None:
            raise AuthorityReceiptFailure("receipt run nonce differs")
        return receipt
    except AuthorityReceiptFailure:
        raise
    except BaseException as error:
        raise AuthorityReceiptFailure("stage receipt validation failed") from error


def _validate_tool_bundle(bundle: LockedToolBundle, pins: TrustedPins) -> tuple[LoadedJson, str]:
    try:
        bundle.verify()
        executable = bundle.executable
        raw = bundle.canonical_bytes()
        bundle.verify()
    except Exception as error:
        raise GraphRunnerError("locked ADB bundle verification failed") from error
    _string(executable, "locked ADB executable")
    loaded = load_canonical(raw, MAX_AUTHORITY_BYTES)
    if loaded.sha256 != pins.tool_bundle_sha256:
        _fail("locked ADB bundle differs from trusted pin")
    item = _exact(loaded.value, {"authority", "files"}, "locked ADB bundle")
    if item["authority"] != WINDOWS_TOOL_AUTHORITY or type(item["files"]) is not dict or \
            set(item["files"]) != set(WINDOWS_TOOL_FILENAMES):
        _fail("locked ADB bundle identity differs")
    for basename in WINDOWS_TOOL_FILENAMES:
        record = item["files"][basename]
        if type(record) is not dict or record.get("basename") != basename:
            _fail("locked ADB file identity differs")
        _sha(record.get("sha256"), "locked ADB file digest")
        if record["sha256"] != REVIEWED_ADB_SHA256[basename]:
            _fail("locked ADB file digest differs from reviewed pin")
        _integer(record.get("size"), "locked ADB file size", 1, MAX_SAFE_INTEGER)
        _string(record.get("path"), "locked ADB file path")
    if os.path.normcase(os.path.abspath(executable)) != \
            os.path.normcase(os.path.abspath(item["files"]["adb.exe"]["path"])):
        _fail("locked ADB executable property differs from retained authority")
    return loaded, loaded.sha256


def _validate_pointer(value: Any, label: str) -> None:
    item = _exact(value, {"present", "value"}, label)
    if type(item["present"]) is not bool:
        _fail(label + ".present differs")
    if not item["present"]:
        if item["value"] is not None:
            _fail(label + " absent value is non-null")
    elif type(item["value"]) is not str or re.fullmatch(r"0x[0-9a-f]{16}", item["value"]) is None \
            or item["value"] == "0x0000000000000000":
        _fail(label + " pointer wire differs")


def _binary64(value: Any, label: str) -> float:
    item = _exact(value, {"binary64"}, label)
    wire = item["binary64"]
    if type(wire) is not str or BINARY64_RE.fullmatch(wire) is None:
        _fail(label + " binary64 wire differs")
    number = struct.unpack(">d", bytes.fromhex(wire[2:]))[0]
    if not math.isfinite(number) or abs(number) > MAX_NUMERIC_ABS:
        _fail(label + " binary64 value differs")
    return number


def _validate_rect(value: Any, label: str) -> list[float]:
    if type(value) is not list or len(value) != 4:
        _fail(label + " rectangle shape differs")
    numbers = [_binary64(item, label + "[" + str(index) + "]")
               for index, item in enumerate(value)]
    if not numbers[2] > numbers[0] or not numbers[3] > numbers[1]:
        _fail(label + " rectangle is empty")
    return numbers


def _validate_matrix(value: Any, label: str) -> list[float]:
    if type(value) is not list or len(value) != 6:
        _fail(label + " matrix shape differs")
    numbers = [_binary64(item, label + "[" + str(index) + "]")
               for index, item in enumerate(value)]
    determinant = numbers[0] * numbers[3] - numbers[1] * numbers[2]
    norm = max(abs(number) for number in numbers[:4])
    if (not norm > 0 or not abs(determinant) > math.ulp(1.0) * norm * norm * 64 or
            (norm * norm) / abs(determinant) > MAX_NUMERIC_ABS):
        _fail(label + " matrix is singular or unstable")
    return numbers


def _validate_bitmap(value: Any, label: str) -> None:
    item = _exact(value, {"present", "width", "height", "nativePointer"}, label)
    if type(item["present"]) is not bool:
        _fail(label + ".present differs")
    if not item["present"]:
        if any(item[name] is not None for name in ("width", "height", "nativePointer")):
            _fail(label + " absent payload is non-null")
        return
    _integer(item["width"], label + ".width", 1, MAX_DIMENSION)
    _integer(item["height"], label + ".height", 1, MAX_DIMENSION)
    _validate_pointer(item["nativePointer"], label + ".nativePointer")


_VIEW_CLASSES = {
    "handWriteView": "com.supernote.document.handwrite.HandWriteView",
    "documentImage": "com.supernote.document.utils.view.DocumentImageView",
    "digestImage": "com.supernote.document.utils.view.DigestImageView",
    "contentView": "android.view.View",
    "documentLayout": "android.widget.RelativeLayout",
}


def _validate_view(value: Any, name: str) -> None:
    label = "snapshot.views." + name
    item = _exact(value, {"className", "bounds", "scroll", "windowAttachCount",
                          "attached", "referenceStable", "attachInfoStable"}, label)
    if item["className"] != _VIEW_CLASSES[name]:
        _fail(label + " class differs")
    bounds = item["bounds"]
    if type(bounds) is not list or len(bounds) != 4:
        _fail(label + " bounds shape differs")
    for index, number in enumerate(bounds):
        _integer(number, label + ".bounds[" + str(index) + "]", -2_147_483_648, 2_147_483_647)
    if bounds[2] <= bounds[0] or bounds[3] <= bounds[1]:
        _fail(label + " bounds are empty")
    scroll = item["scroll"]
    if type(scroll) is not list or len(scroll) != 2:
        _fail(label + " scroll shape differs")
    for index, number in enumerate(scroll):
        _integer(number, label + ".scroll[" + str(index) + "]", -2_147_483_648, 2_147_483_647)
    _integer(item["windowAttachCount"], label + ".windowAttachCount", 0, 2_147_483_647)
    if item["attached"] is not True or item["referenceStable"] is not True or \
            item["attachInfoStable"] is not True:
        _fail(label + " attachment stability differs")


def validate_snapshot(payload: Any, manifest: LoadedJson,
                      external_record: dict[str, Any]) -> dict[str, Any]:
    value = _exact(payload, {"event", "schemaVersion", "authority", "manifestSha256",
                             "observationOnly", "atomic", "attachment", "externalSession",
                             "fileAuthority", "coordinator", "calibrationProfile", "lifecycle",
                             "document", "pageInfo", "presenter", "views", "layers"}, "snapshot")
    if (value["event"] != "native_page_graph_snapshot" or value["schemaVersion"] != 2 or
            value["authority"] != SNAPSHOT_AUTHORITY or value["manifestSha256"] != manifest.sha256 or
            value["observationOnly"] is not True or value["atomic"] is not False):
        _fail("snapshot identity differs")
    expected = manifest.value
    attachment = _exact(value["attachment"], {"packageName", "processName", "pid",
                                               "processStartTimeTicks", "architecture", "pointerSize",
                                               "firmwareFingerprint", "apk", "framework", "module",
                                               "observerExternallyVerifiedSha256"}, "snapshot.attachment")
    ma = expected["attachment"]
    for name in ("packageName", "processName", "architecture", "firmwareFingerprint"):
        _string(attachment[name], "snapshot.attachment." + name)
    _integer(attachment["pid"], "snapshot.attachment.pid", 1, ANDROID_MAX_PID)
    _decimal(attachment["processStartTimeTicks"],
             "snapshot.attachment.processStartTimeTicks", digits=20)
    _integer(attachment["pointerSize"], "snapshot.attachment.pointerSize", 1, 16)
    _sha(attachment["observerExternallyVerifiedSha256"],
         "snapshot.attachment.observerExternallyVerifiedSha256")
    if (attachment["packageName"] != ma["packageName"] or attachment["processName"] != ma["processName"] or
            attachment["pid"] != ma["pid"] or attachment["processStartTimeTicks"] != ma["startTimeTicks"] or
            attachment["architecture"] != "arm64" or attachment["pointerSize"] != 8 or
            attachment["firmwareFingerprint"] != ma["firmwareFingerprint"] or
            attachment["observerExternallyVerifiedSha256"] != ma["observerSha256"]):
        _fail("snapshot attachment differs")
    for name in ("apk", "framework", "module"):
        out_keys = {"path", "size", "externallyVerifiedSha256"} | ({"name"} if name == "module" else set())
        record = _exact(attachment[name], out_keys, "snapshot.attachment." + name)
        source = ma[name]
        _string(record["path"], "snapshot.attachment." + name + ".path")
        _integer(record["size"], "snapshot.attachment." + name + ".size", 1,
                 MAX_SAFE_INTEGER)
        _sha(record["externallyVerifiedSha256"],
             "snapshot.attachment." + name + ".externallyVerifiedSha256")
        if name == "module":
            _string(record["name"], "snapshot.attachment.module.name")
        if any(record[key] != source[key] for key in ("path", "size")) or \
                record["externallyVerifiedSha256"] != source["sha256"] or \
                (name == "module" and record["name"] != source["name"]):
            _fail("snapshot binary attachment differs")
    external = _exact(value["externalSession"], {"authority", "source", "authorizedSerial",
                                                  "taskId", "displayId", "hostSessionId",
                                                  "displayGeneration"}, "snapshot.externalSession")
    me = expected["externalSession"]
    if not _wire_equal(external, {"authority": me["authority"], "source": "external-coordinator",
                                 "authorizedSerial": me["authorizedSerial"], "taskId": me["taskId"],
                                 "displayId": me["displayId"], "hostSessionId": me["hostSessionId"],
                                 "displayGeneration": me["displayGeneration"]}):
        _fail("snapshot external session differs")
    if (not _wire_equal(value["fileAuthority"], expected["files"]) or
            not _wire_equal(external_record["files"], expected["files"])):
        _fail("snapshot file authority differs")
    coordinator = _exact(value["coordinator"], {"authority", "observerSessionId",
                                                 "absoluteMonotonicDeadlineNs", "hardDeadlineMs",
                                                 "heapWalks", "retainedRootSamples",
                                                 "externalDetachOnDeadline",
                                                 "externalTargetLivenessPostconditionRequired",
                                                 "noRetry"}, "snapshot.coordinator")
    mc = expected["coordinator"]
    if not _wire_equal(coordinator, {"authority": mc["authority"],
                                    "observerSessionId": mc["observerSessionId"],
                                    "absoluteMonotonicDeadlineNs": mc["absoluteMonotonicDeadlineNs"],
                                    "hardDeadlineMs": mc["hardDeadlineMs"], "heapWalks": 1,
                                    "retainedRootSamples": 2, "externalDetachOnDeadline": True,
                                    "externalTargetLivenessPostconditionRequired": True,
                                    "noRetry": True}):
        _fail("snapshot coordinator differs")
    if not _wire_equal(value["calibrationProfile"], expected["expected"]["calibrationProfile"]):
        _fail("snapshot calibration profile differs")
    if not _wire_equal(value["lifecycle"], {"resumed": True, "finished": False,
                                           "destroyed": False, "graphStable": True}):
        _fail("snapshot lifecycle differs")
    document = _exact(value["document"], {"uri", "rawCurrentPage", "pageCount",
                                           "rawPageInfoPage", "rectangles"}, "snapshot.document")
    if document["uri"] != expected["expected"]["documentUri"]:
        _fail("snapshot document URI differs")
    count = _integer(document["pageCount"], "snapshot.document.pageCount", 1, MAX_PAGE_COUNT)
    _integer(document["rawCurrentPage"], "snapshot.document.rawCurrentPage", 0, count)
    _integer(document["rawPageInfoPage"], "snapshot.document.rawPageInfoPage", 0, count)
    rectangles = _exact(document["rectangles"], {"scaleRect", "portraitScaleRect",
                                                  "landscapeScaleRect", "showRect", "trimmingRect",
                                                  "landscapeTrimmingRect"}, "snapshot.document.rectangles")
    for name, record in rectangles.items():
        _validate_rect(record, "snapshot.document.rectangles." + name)
    page = _exact(value["pageInfo"], {"ctm", "revertCtm", "offset", "scale",
                                      "trimmingRect", "bitmaps"}, "snapshot.pageInfo")
    _validate_matrix(page["ctm"], "snapshot.pageInfo.ctm")
    _validate_matrix(page["revertCtm"], "snapshot.pageInfo.revertCtm")
    if type(page["offset"]) is not list or len(page["offset"]) != 2:
        _fail("snapshot page offset differs")
    for index, number in enumerate(page["offset"]):
        _integer(number, "snapshot.pageInfo.offset[" + str(index) + "]", -2_147_483_648, 2_147_483_647)
    _binary64(page["scale"], "snapshot.pageInfo.scale")
    _validate_rect(page["trimmingRect"], "snapshot.pageInfo.trimmingRect")
    bitmaps = _exact(page["bitmaps"], {"originBitmap", "displayBitmap", "digestBitmap"},
                     "snapshot.pageInfo.bitmaps")
    for name, record in bitmaps.items():
        _validate_bitmap(record, "snapshot.pageInfo.bitmaps." + name)
    presenter = _exact(value["presenter"], {"uri", "rawPresenterPage", "markPath",
                                             "rawRotationCode", "bitmap", "notePointer", "binders"},
                       "snapshot.presenter")
    if presenter["uri"] != document["uri"] or presenter["markPath"] != \
            (expected["files"]["mark"]["path"] if expected["files"]["mark"]["present"] else None):
        _fail("snapshot presenter authority differs")
    _integer(presenter["rawPresenterPage"], "snapshot.presenter.rawPresenterPage", 0, count)
    _integer(presenter["rawRotationCode"], "snapshot.presenter.rawRotationCode",
             -2_147_483_648, 2_147_483_647)
    _validate_bitmap(presenter["bitmap"], "snapshot.presenter.bitmap")
    _validate_pointer(presenter["notePointer"], "snapshot.presenter.notePointer")
    binders = _exact(presenter["binders"], {"iBinder", "mSFBinder"}, "snapshot.presenter.binders")
    for name, record in binders.items():
        record = _exact(record, {"present", "referenceStable"}, "snapshot.presenter.binders." + name)
        if type(record["present"]) is not bool or record["referenceStable"] is not True:
            _fail("snapshot binder stability differs")
    views = _exact(value["views"], set(_VIEW_CLASSES), "snapshot.views")
    for name, record in views.items():
        _validate_view(record, name)
    if not _wire_equal(value["layers"], {"status": "unavailable",
                                        "reasonCode": "DIRECT_LAYER_PROVENANCE_NOT_PINNED",
                                        "evidenceId": "native-page-graph-v2-static-map"}):
        _fail("snapshot layer authority differs")
    return value


def _validate_private_adb(value: Any, tool: LoadedJson) -> dict[str, Any]:
    item = _exact(value, {"authority", "host", "port", "pid", "processCreationFileTime",
                          "executablePath", "executableSha256", "serverSessionId",
                          "launchMode", "processHandleRetained", "fixedMinimalEnvironment",
                          "minimalEnvironmentSha256", "explicitSerialEveryCommand",
                          "rejectsAmbientOverrides", "noSharedServer", "toolBundleSha256",
                          "state"}, "stage.privateAdbServer")
    if (item["authority"] != ADB_SERVER_AUTHORITY or item["host"] != "127.0.0.1" or
            item["launchMode"] != "server-nodaemon" or item["state"] != "ready" or
            item["processHandleRetained"] is not True or
            item["fixedMinimalEnvironment"] is not True or
            item["explicitSerialEveryCommand"] is not True or item["noSharedServer"] is not True or
            item["toolBundleSha256"] != tool.sha256 or
            item["rejectsAmbientOverrides"] != list(ADB_OVERRIDE_NAMES)):
        _fail("private ADB server authority differs")
    _integer(item["port"], "stage.privateAdbServer.port", 1024, 65535)
    _integer(item["pid"], "stage.privateAdbServer.pid", 1, 4_194_304)
    _decimal(item["processCreationFileTime"],
             "stage.privateAdbServer.processCreationFileTime", zero=True, digits=20)
    _string(item["executablePath"], "stage.privateAdbServer.executablePath")
    _sha(item["executableSha256"], "stage.privateAdbServer.executableSha256")
    retained_adb = tool.value["files"]["adb.exe"]
    if (item["executablePath"] != retained_adb["path"] or
            item["executableSha256"] != retained_adb["sha256"]):
        _fail("private ADB server executable differs from retained client")
    if TOKEN_RE.fullmatch(_string(item["serverSessionId"], "stage.privateAdbServer.serverSessionId")) is None:
        _fail("private ADB server session differs")
    _sha(item["minimalEnvironmentSha256"], "stage.privateAdbServer.minimalEnvironmentSha256")
    return item


def _validate_target(value: Any, binding: StageBinding) -> dict[str, Any]:
    item = _exact(value, {"authority", "serial", "pid", "startTimeTicks", "cmdline",
                          "cmdlineSha256", "packageName", "processName", "alive"}, "stage.target")
    for name in ("authority", "serial", "startTimeTicks", "packageName", "processName"):
        _string(item[name], "stage.target." + name)
    _integer(item["pid"], "stage.target.pid", 1, ANDROID_MAX_PID)
    _decimal(item["startTimeTicks"], "stage.target.startTimeTicks", digits=20)
    if (item["authority"] != TARGET_AUTHORITY or item["serial"] != binding.serial or
            item["pid"] != binding.pid or item["startTimeTicks"] != binding.start_time_ticks or
            item["packageName"] != PACKAGE_NAME or item["processName"] != PACKAGE_NAME or
            item["alive"] is not True):
        _fail("target process authority differs")
    cmdline = _string(item["cmdline"], "stage.target.cmdline")
    if cmdline != PACKAGE_NAME or hashlib.sha256(cmdline.encode("utf-8")).hexdigest() != \
            _sha(item["cmdlineSha256"], "stage.target.cmdlineSha256"):
        _fail("target process command line differs")
    return item


def _validate_firmware(value: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    item = _exact(value, {"fingerprint", "apk", "framework", "module"}, "stage.firmware")
    if item["fingerprint"] != FIRMWARE_FINGERPRINT:
        _fail("stage firmware fingerprint differs")
    for name in ("apk", "framework", "module"):
        _validate_binary_file(item[name], "stage.firmware." + name, name=(name == "module"))
        if item[name] != manifest["attachment"][name]:
            _fail("stage firmware bytes differ")
    return item


def _validate_host(value: Any, manifest: dict[str, Any], binding: StageBinding) -> dict[str, Any]:
    item = _exact(value, {"authority", "hostSessionId", "stage", "displayId",
                          "defaultDisplayId", "displayGeneration", "placementRequestGeneration",
                          "placementReadyGeneration", "hostPackageName",
                          "hostApkSha256", "hostTaskId", "hostActivityToken", "displaySize",
                          "densityDpi", "requestedFrame", "measuredGlobalFrame", "applied",
                          "activityResumed", "activityVisible", "activityFocused",
                          "surfaceAttached", "surfaceValid"}, "stage.host")
    external = manifest["externalSession"]
    _integer(item["displayId"], "stage.host.displayId", 1, 1024)
    _integer(item["defaultDisplayId"], "stage.host.defaultDisplayId", 0, 1024)
    _integer(item["displayGeneration"], "stage.host.displayGeneration", 1, MAX_SAFE_INTEGER)
    if (item["authority"] != HOST_AUTHORITY or item["hostSessionId"] != external["hostSessionId"] or
            item["stage"] != binding.stage or item["displayId"] != external["displayId"] or
            item["defaultDisplayId"] != 0 or item["displayGeneration"] != external["displayGeneration"] or
            item["applied"] is not True or item["activityResumed"] is not True or
            item["activityVisible"] is not True or item["activityFocused"] is not True or
            item["surfaceAttached"] is not True or item["surfaceValid"] is not True):
        _fail("host placement authority differs")
    requested_generation = _integer(item["placementRequestGeneration"],
                                    "stage.host.placementRequestGeneration", 1, MAX_SAFE_INTEGER)
    ready_generation = _integer(item["placementReadyGeneration"],
                                "stage.host.placementReadyGeneration", 1, MAX_SAFE_INTEGER)
    if requested_generation != ready_generation:
        _fail("host placement acknowledgement is stale")
    _string(item["hostPackageName"], "stage.host.hostPackageName")
    _sha(item["hostApkSha256"], "stage.host.hostApkSha256")
    _integer(item["hostTaskId"], "stage.host.hostTaskId", 0, 10_000_000)
    _string(item["hostActivityToken"], "stage.host.hostActivityToken")
    dimensions = item["displaySize"]
    if type(dimensions) is not list or len(dimensions) != 2:
        _fail("host display size differs")
    _integer(dimensions[0], "stage.host.displaySize[0]", 1, MAX_DIMENSION)
    _integer(dimensions[1], "stage.host.displaySize[1]", 1, MAX_DIMENSION)
    density_dpi = _integer(item["densityDpi"], "stage.host.densityDpi", 1, 10_000)
    if (dimensions != [VIRTUAL_DISPLAY_WIDTH, VIRTUAL_DISPLAY_HEIGHT] or
            density_dpi != VIRTUAL_DISPLAY_DENSITY_DPI):
        _fail("host fixed VirtualDisplay configuration differs")
    for name in ("requestedFrame", "measuredGlobalFrame"):
        frame = item[name]
        if type(frame) is not list or len(frame) != 4:
            _fail("host frame differs")
        for index, number in enumerate(frame):
            _integer(number, "stage.host." + name + "[" + str(index) + "]",
                     -2_147_483_648, 2_147_483_647)
        if frame[2] <= 0 or frame[3] <= 0:
            _fail("host frame is empty")
    if item["requestedFrame"] != item["measuredGlobalFrame"]:
        _fail("host requested and measured frames differ")
    return item


def _validate_pen_lease(value: Any, binding: StageBinding, phase: str) -> dict[str, Any]:
    item = _exact(value, {"authority", "leaseId", "serial", "helperPid",
                          "helperStartTimeTicks", "holderSessionId", "mode",
                          "deviceClockDomain", "remainingLeaseMs", "active"}, "stage.penLease")
    if (item["authority"] != PEN_LEASE_AUTHORITY or item["serial"] != binding.serial or
            item["holderSessionId"] != binding.observer_session_id or
            item["mode"] != "observation-only" or item["active"] is not True):
        _fail("pen lease authority differs")
    if TOKEN_RE.fullmatch(_string(item["leaseId"], "stage.penLease.leaseId")) is None:
        _fail("pen lease ID differs")
    _integer(item["helperPid"], "stage.penLease.helperPid", 1, 4_194_304)
    _decimal(item["helperStartTimeTicks"], "stage.penLease.helperStartTimeTicks", digits=20)
    if item["deviceClockDomain"] != "android-boottime-v1":
        _fail("pen lease device clock domain differs")
    remaining = _integer(item["remainingLeaseMs"], "stage.penLease.remainingLeaseMs", 1, 600_000)
    required = (binding.deadline_ms + CLEANUP_TIMEOUT_MS
                if phase == "before" else CLEANUP_TIMEOUT_MS)
    if remaining < required:
        _fail("pen lease remaining duration is insufficient")
    return item


def _validate_frida(value: Any, binding: StageBinding, phase: str) -> dict[str, Any]:
    item = _exact(value, {"authority", "providerSessionId", "hostPythonPath",
                          "hostPythonSha256", "hostFridaVersion", "hostFridaPackageSha256",
                          "hostNativeDependenciesSha256", "serverPath", "serverSha256",
                          "serverUid", "serverPid", "serverStartTimeTicks", "serverCmdline",
                          "serverVersion", "serverSessionId", "serverState",
                          "exactTeardownRequired", "processAbsent", "fileAbsent",
                          "teardownOfSessionId"}, "stage.frida")
    if item["authority"] != FRIDA_AUTHORITY or item["exactTeardownRequired"] is not True:
        _fail("Frida authority differs")
    for name in ("providerSessionId", "hostPythonPath", "hostFridaVersion", "serverPath",
                 "serverCmdline", "serverVersion", "serverSessionId"):
        _string(item[name], "stage.frida." + name)
    if TOKEN_RE.fullmatch(item["providerSessionId"]) is None or TOKEN_RE.fullmatch(item["serverSessionId"]) is None:
        _fail("Frida session token differs")
    for name in ("hostPythonSha256", "hostFridaPackageSha256", "hostNativeDependenciesSha256",
                 "serverSha256"):
        _sha(item[name], "stage.frida." + name)
    server_uid = _integer(item["serverUid"], "stage.frida.serverUid", 0, 2_147_483_647)
    _integer(item["serverPid"], "stage.frida.serverPid", 1, 4_194_304)
    _decimal(item["serverStartTimeTicks"], "stage.frida.serverStartTimeTicks", digits=20)
    if server_uid != 0:
        _fail("Frida server is not the authenticated temporary root server")
    if phase == "before":
        if (item["serverState"] != "ready" or item["processAbsent"] is not False or
                item["fileAbsent"] is not False or item["teardownOfSessionId"] is not None):
            _fail("Frida before lifecycle differs")
    else:
        if (item["serverState"] != "torn-down" or item["processAbsent"] is not True or
                item["fileAbsent"] is not True or item["teardownOfSessionId"] != item["serverSessionId"]):
            _fail("Frida teardown evidence differs")
    return item


_DOCUMENT_TASK_BOOLEAN_FIELDS = (
    "resumed", "stopped", "delayed_resume", "finishing", "task_visible",
    "visible_requested", "visible", "client_visible", "reported_drawn",
    "reported_visible", "now_visible",
)
_DOCUMENT_TASK_FIELDS = (
    "authority", "raw_sha256", "display_id", "stack_id", "task_id", "task_token",
    "activity_token", "pid", "uid", "package_name", "process_name", "component",
    "base_apk_path", "state", *_DOCUMENT_TASK_BOOLEAN_FIELDS, "width", "height",
    "density_dpi", "rotation",
)
_DOCUMENT_TASK_SEMANTIC_FIELDS = tuple(
    name for name in _DOCUMENT_TASK_FIELDS if name != "raw_sha256"
)


def _validate_document_task_authority(task: DocumentTaskAuthority,
                                      manifest: dict[str, Any],
                                      binding: StageBinding) -> DocumentTaskAuthority:
    """Validate every parser output before its detached digest is trusted.

    ``DocumentTaskAuthority`` is deliberately a transport dataclass: callers can
    construct one without invoking the strict ActivityManager parser.  The runner
    therefore repeats the parser's closed output-domain checks and its live-task
    invariants.  In particular, Python bool/int aliases and truthy strings must
    never become authenticated Android authority.
    """
    if type(task) is not DocumentTaskAuthority:
        _fail("Android document task wrapper differs")
    if tuple(DocumentTaskAuthority.__dataclass_fields__) != _DOCUMENT_TASK_FIELDS:
        _fail("Android document task schema differs")
    _string(task.authority, "Android task authority")
    _sha(task.raw_sha256, "Android task raw capture digest")
    display_id = _integer(task.display_id, "Android task display ID", 1, 1024)
    stack_id = _integer(task.stack_id, "Android task stack ID", 0, 10_000_000)
    task_id = _integer(task.task_id, "Android task ID", 0, 10_000_000)
    for name in ("task_token", "activity_token"):
        token = _string(getattr(task, name), "Android task " + name)
        if ANDROID_TOKEN_RE.fullmatch(token) is None:
            _fail("Android task " + name + " is not one canonical framework token")
    pid = _integer(task.pid, "Android task PID", 1, ANDROID_MAX_PID)
    uid = _integer(task.uid, "Android task UID", 0, 2_147_483_647)
    for name in ("package_name", "process_name", "component", "base_apk_path", "state"):
        _string(getattr(task, name), "Android task " + name)
    for name in _DOCUMENT_TASK_BOOLEAN_FIELDS:
        if type(getattr(task, name)) is not bool:
            _fail("Android task " + name + " is not boolean")
    width = _integer(task.width, "Android task width", 1, 32768)
    height = _integer(task.height, "Android task height", 1, 32768)
    density_dpi = _integer(task.density_dpi, "Android task density", 72, 1280)
    rotation = _integer(task.rotation, "Android task rotation", 0, 3)

    external = manifest["externalSession"]
    attachment = manifest["attachment"]
    if (task.authority != ANDROID_TASK_AUTHORITY or
            ANDROID_PACKAGE_NAME != PACKAGE_NAME or
            ANDROID_PROCESS_NAME != PACKAGE_NAME or
            task.package_name != ANDROID_PACKAGE_NAME or
            task.process_name != ANDROID_PROCESS_NAME or
            task.component not in (DOCUMENT_ACTIVITY_SHORT_COMPONENT,
                                   DOCUMENT_ACTIVITY_FULL_COMPONENT) or
            task.base_apk_path != attachment["apk"]["path"] or
            uid != ANDROID_SYSTEM_UID or task.state != "RESUMED" or not task.resumed or
            task.stopped or task.delayed_resume or task.finishing or
            not task.task_visible or not task.visible_requested or not task.visible or
            not task.client_visible or not task.reported_drawn or
            not task.reported_visible or not task.now_visible or
            pid != binding.pid or display_id != external["displayId"] or
            task_id != external["taskId"] or stack_id != task_id or
            width != VIRTUAL_DISPLAY_WIDTH or height != VIRTUAL_DISPLAY_HEIGHT or
            density_dpi != VIRTUAL_DISPLAY_DENSITY_DPI or
            rotation != VIRTUAL_DISPLAY_ROTATION):
        _fail("Android document task authority differs")
    return task


def _document_task_semantics_equal(before: DocumentTaskAuthority,
                                   after: DocumentTaskAuthority) -> bool:
    """Compare all non-wire task fields with type-exact equality."""
    if type(before) is not DocumentTaskAuthority or type(after) is not DocumentTaskAuthority:
        return False
    for name in _DOCUMENT_TASK_SEMANTIC_FIELDS:
        left = getattr(before, name)
        right = getattr(after, name)
        if type(left) is not type(right) or left != right:
            return False
    return True


def _snapshot_stage_capture(capture: StageAuthorityCapture) -> StageAuthorityCapture:
    """Detach all provider-owned wrapper objects before retaining evidence."""
    if (type(capture) is not StageAuthorityCapture or
            type(capture.record) is not CanonicalAuthority or
            type(capture.receipt) is not CanonicalAuthority or
            type(capture.task) is not DocumentTaskAuthority):
        _fail("stage capture wrapper differs")
    for label, authority in (("record", capture.record), ("receipt", capture.receipt)):
        if type(authority.raw) is not bytes or type(authority.sha256) is not str:
            _fail("stage capture " + label + " wrapper differs")
    if tuple(DocumentTaskAuthority.__dataclass_fields__) != _DOCUMENT_TASK_FIELDS:
        _fail("Android document task schema differs")
    detached_task = DocumentTaskAuthority(
        *(getattr(capture.task, name) for name in _DOCUMENT_TASK_FIELDS)
    )
    return StageAuthorityCapture(
        CanonicalAuthority(capture.record.raw, capture.record.sha256),
        detached_task,
        CanonicalAuthority(capture.receipt.raw, capture.receipt.sha256),
    )


def _isolated_authority_request(request: AuthorityRequest) -> AuthorityRequest:
    """Give an untrusted provider no reference to retained runner authority."""
    binding = request.binding
    return AuthorityRequest(
        request.phase, request.manifest_sha256,
        StageBinding(binding.serial, binding.pid, binding.start_time_ticks,
                     binding.observer_session_id, binding.deadline_ms,
                     binding.absolute_deadline_ns, binding.stage),
        request.absolute_deadline_ns, request.tool_bundle_sha256, request.run_nonce,
        request.sequence, request.previous_receipt_sha256,
    )


def validate_stage_authority(capture: StageAuthorityCapture, request: AuthorityRequest,
                             manifest: LoadedJson, pins: TrustedPins, tool: LoadedJson,
                             provider_admission: LoadedJson,
                             frida_admission: LoadedJson | None) -> LoadedJson:
    if type(capture) is not StageAuthorityCapture or type(capture.task) is not DocumentTaskAuthority:
        _fail("stage authority wrapper differs")
    loaded = _authority(capture.record)
    item = _exact(loaded.value, {"schemaVersion", "authority", "phase", "captureId",
                                 "providerSessionId", "manifestSha256", "toolBundleSha256",
                                 "taskAuthoritySha256", "privateAdbServer", "target", "firmware",
                                 "files", "host", "penLease", "frida"}, "stage authority")
    if (item["schemaVersion"] != 2 or item["authority"] != STAGE_AUTHORITY or
            item["phase"] != request.phase or item["manifestSha256"] != request.manifest_sha256 or
            item["toolBundleSha256"] != request.tool_bundle_sha256):
        _fail("stage authority identity differs")
    for name in ("captureId", "providerSessionId"):
        if TOKEN_RE.fullmatch(_string(item[name], "stage." + name)) is None:
            _fail("stage token syntax differs")
    if item["providerSessionId"] != provider_admission.value["providerSessionId"]:
        _fail("stage provider session differs from admitted retained channel")
    if stage_policy_sha256(item) != pins.stage_policy_sha256:
        _fail("stage authority differs from independently trusted run policy")
    task = _validate_document_task_authority(capture.task, manifest.value, request.binding)
    task_loaded = load_canonical(task.canonical_bytes(), MAX_AUTHORITY_BYTES)
    if item["taskAuthoritySha256"] != task_loaded.sha256:
        _fail("task authority detached digest differs")
    _validate_private_adb(item["privateAdbServer"], tool)
    _validate_target(item["target"], request.binding)
    _validate_firmware(item["firmware"], manifest.value)
    if not _wire_equal(item["files"], manifest.value["files"]):
        _fail("external file authority differs from manifest")
    host = _validate_host(item["host"], manifest.value, request.binding)
    if ([task.width, task.height] != host["displaySize"] or
            task.density_dpi != host["densityDpi"]):
        _fail("Android task configuration differs from authenticated host display")
    _validate_pen_lease(item["penLease"], request.binding, request.phase)
    frida_record = _validate_frida(item["frida"], request.binding, request.phase)
    if (item["providerSessionId"] != frida_record["providerSessionId"] or
            (frida_admission is not None and
             frida_record["providerSessionId"] != frida_admission.value["providerSessionId"])):
        _fail("Frida/provider session authority differs")
    return loaded


def require_stage_stability(before: StageAuthorityCapture, after: StageAuthorityCapture,
                            before_loaded: LoadedJson, after_loaded: LoadedJson) -> None:
    if not _document_task_semantics_equal(before.task, after.task):
        _fail("Android task authority changed")
    left = dict(before_loaded.value)
    right = dict(after_loaded.value)
    if left.get("captureId") == right.get("captureId"):
        _fail("fresh before/after capture IDs are not distinct")
    for item in (left, right):
        item.pop("phase", None)
        item.pop("captureId", None)
        item.pop("taskAuthoritySha256", None)
    left_frida = dict(left["frida"])
    right_frida = dict(right["frida"])
    for item in (left_frida, right_frida):
        for name in ("serverState", "processAbsent", "fileAbsent", "teardownOfSessionId"):
            item.pop(name, None)
    left["frida"] = left_frida
    right["frida"] = right_frida
    left_lease = dict(left["penLease"])
    right_lease = dict(right["penLease"])
    before_remaining = left_lease.pop("remainingLeaseMs")
    after_remaining = right_lease.pop("remainingLeaseMs")
    if after_remaining > before_remaining:
        _fail("pen lease remaining duration moved backwards")
    left["penLease"] = left_lease
    right["penLease"] = right_lease
    if left != right:
        _fail("external before/after authority changed")


class _V2MessageCollector:
    def __init__(self, manifest: LoadedJson, external_record: dict[str, Any],
                 deadline_ns: int, clock_ns: Callable[[], int]):
        self._manifest = manifest
        self._external_record = external_record
        self._deadline_ns = deadline_ns
        self._clock_ns = clock_ns
        self._lock = threading.Lock()
        self._terminal = threading.Event()
        self._frames: list[dict[str, Any]] = []
        self._error: BaseException | None = None
        self._sealed = False

    def _record_error(self, error: BaseException) -> None:
        if self._error is None:
            self._error = error
        self._terminal.set()

    def on_message(self, message: Any, data: Any) -> None:
        try:
            now = self._clock_ns()
            if type(now) is not int or now >= self._deadline_ns:
                raise DeadlineExceeded("observer callback arrived after hard deadline")
            with self._lock:
                if self._sealed:
                    raise SnapshotRejected("observer callback arrived after channel seal")
                if data is not None:
                    raise SnapshotRejected("binary Frida data is not admitted")
                envelope = _exact(message, {"type", "payload"}, "Frida message envelope")
                if envelope["type"] != "send":
                    raise SnapshotRejected("Frida message type is not send")
                payload = envelope["payload"]
                wire = canonical_bytes(payload, MAX_MESSAGE_BYTES)
                # Retain a private canonical snapshot, never the mutable object
                # owned by a Frida adapter or callback thread.
                payload = load_canonical(wire, MAX_MESSAGE_BYTES).value
                if len(self._frames) >= 2:
                    raise SnapshotRejected("observer emitted extra frame")
                if not self._frames:
                    if type(payload) is not dict or payload.get("event") not in (
                            "native_page_graph_snapshot", "native_page_graph_snapshot_error"):
                        raise SnapshotRejected("observer first frame differs")
                else:
                    complete = _exact(payload, {"event", "success"}, "observer terminal frame")
                    if complete["event"] != "native_page_graph_snapshot_complete" or \
                            type(complete["success"]) is not bool:
                        raise SnapshotRejected("observer terminal frame differs")
                    first_success = self._frames[0].get("event") == "native_page_graph_snapshot"
                    if complete["success"] is not first_success:
                        raise SnapshotRejected("observer terminal success disagrees")
                self._frames.append(payload)
                if len(self._frames) == 2:
                    self._terminal.set()
        except BaseException as error:
            with self._lock:
                self._record_error(error)

    def wait(self) -> None:
        while True:
            try:
                wait_seconds = _remaining_seconds(self._deadline_ns, self._clock_ns)
            except BaseException as error:
                raise DeadlineExceeded(
                    "hard deadline expired before observer completion") from error
            # A relative Event wait is only a wake-up mechanism.  Resample the
            # authoritative clock after every timeout; only its expiry (or a
            # clock fault) proves that observer completion missed the deadline.
            if self._terminal.wait(wait_seconds):
                return

    def seal(self) -> None:
        with self._lock:
            self._sealed = True

    def result(self) -> dict[str, Any]:
        with self._lock:
            if self._error is not None:
                raise self._error
            if len(self._frames) != 2:
                raise SnapshotRejected("observer framing is incomplete")
            first = self._frames[0]
            if first.get("event") == "native_page_graph_snapshot_error":
                if first != {"event": "native_page_graph_snapshot_error", "schemaVersion": 2,
                             "code": "GRAPH_SNAPSHOT_REJECTED"}:
                    raise SnapshotRejected("observer rejection frame differs")
                raise SnapshotRejected("observer rejected the graph snapshot")
            return validate_snapshot(first, self._manifest, self._external_record)

    def assert_clean_after_quiescence(self) -> None:
        with self._lock:
            if self._error is not None:
                raise self._error


class _TeardownOnce:
    def __init__(self, provider: FridaProvider):
        self._provider = provider
        self._lock = threading.Lock()
        self._called = False
        self._error: BaseException | None = None

    def call(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= CLEANUP_TIMEOUT_MS:
            _fail("Frida teardown timeout differs")
        with self._lock:
            if not self._called:
                self._called = True
                try:
                    self._provider.teardown(timeout_ms)
                except BaseException as error:
                    self._error = error
            if self._error is not None:
                raise GraphRunnerError("exact Frida teardown failed") from self._error

    @property
    def called(self) -> bool:
        with self._lock:
            return self._called


class _AuthorityFailStopOnce:
    """Thread-safe terminal kill/join fence for the isolated authority owner."""

    def __init__(self, provider: AuthorityProvider):
        self._provider = provider
        self._lock = threading.Lock()
        self._called = False
        self._error: BaseException | None = None

    def call(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= CLEANUP_TIMEOUT_MS:
            _fail("authority fail-stop timeout differs")
        with self._lock:
            if not self._called:
                self._called = True
                try:
                    self._provider.fail_stop_and_quiesce(timeout_ms)
                except BaseException as error:
                    self._error = error
            if self._error is not None:
                raise AuthorityProviderQuiescenceFailure(
                    "isolated authority provider fail-stop failed") from self._error

    @property
    def called(self) -> bool:
        with self._lock:
            return self._called


class _MonotonicGuard:
    def __init__(self, clock_ns: Callable[[], int]):
        self._clock_ns = clock_ns
        self._last: int | None = None
        self._lock = threading.Lock()

    def __call__(self) -> int:
        with self._lock:
            value = self._clock_ns()
            if type(value) is not int:
                _fail("monotonic clock returned a non-integer")
            if self._last is not None and value < self._last:
                _fail("monotonic clock moved backwards")
            self._last = value
        return value


class _CleanupBudget:
    """One absolute cleanup grace anchored after the authenticated deadline."""

    def __init__(self, hard_deadline_ns: int, clock_ns: Callable[[], int]):
        self._hard_deadline_ns = hard_deadline_ns
        self._clock_ns = clock_ns
        self._deadline_ns = hard_deadline_ns + CLEANUP_TIMEOUT_MS * 1_000_000

    def deadline_ns(self) -> int:
        return self._deadline_ns

    def sample_ns(self) -> int:
        return self._clock_ns()

    def remaining_millis(self) -> int:
        return _remaining_millis(self.deadline_ns(), self._clock_ns,
                                 maximum=CLEANUP_TIMEOUT_MS)

    def step_timeout_millis(self) -> tuple[int, bool]:
        """Return a bounded cleanup slice and whether the shared grace expired.

        Every cleanup operation is still attempted with a one-millisecond
        self-bound after expiry.  A reviewed provider must obey that bound;
        the runner never silently skips detach or quiescence.
        """
        deadline = self.deadline_ns()
        now = self._clock_ns()
        expired = now >= deadline
        if expired:
            return 1, True
        remaining = max(1, (deadline - now + 999_999) // 1_000_000)
        return min(CLEANUP_STEP_TIMEOUT_MS, remaining), False


def _remaining_seconds(deadline_ns: int, clock_ns: Callable[[], int]) -> float:
    now = clock_ns()
    if type(now) is not int:
        _fail("monotonic clock returned a non-integer")
    if now >= deadline_ns:
        raise DeadlineExceeded("hard deadline expired")
    return (deadline_ns - now) / 1_000_000_000


def _remaining_millis(deadline_ns: int, clock_ns: Callable[[], int],
                      *, maximum: int = MAX_DEADLINE_MS) -> int:
    remaining_ns = deadline_ns - clock_ns()
    if remaining_ns <= 0:
        raise DeadlineExceeded("hard deadline expired")
    return max(1, min(maximum, (remaining_ns + 999_999) // 1_000_000))


def _watchdog_reached_deadline(stop: threading.Event, deadline_ns: int,
                               clock_ns: Callable[[], int]) -> bool:
    """Wait only for the time still remaining when the watchdog actually runs.

    Thread creation and scheduling are outside the authenticated budget.  A
    delayed watchdog therefore resamples the absolute deadline in its own
    thread instead of trusting a relative duration captured before start.
    Clock failure is treated as expiry so cancellation/fail-stop begins now.
    """
    while True:
        if stop.is_set():
            return False
        try:
            wait_seconds = _remaining_seconds(deadline_ns, clock_ns)
        except BaseException:
            return not stop.is_set()
        # A relative Event wait is only a wake-up mechanism.  It cannot prove
        # that an injected authoritative clock reached its absolute deadline.
        # Resample that clock after every timeout; a signalled stop wins.
        if stop.wait(wait_seconds):
            return False


def _bounded_call(function: Callable[[OperationStartPermit], Any], deadline_ns: int,
                  clock_ns: Callable[[], int], label: str,
                  cancel: Callable[[], None] | None = None,
                  quiesce: Callable[[], None] | None = None,
                  quiescence_failure: type[ProviderQuiescenceFailure] =
                  ProviderQuiescenceFailure,
                  terminal_cancel: Callable[[], None] | None = None) -> Any:
    """Call synchronously; a sole runner watchdog requests exact cancellation.

    Reviewed production implementations must make cancellation unblock the
    operation.  Keeping the operation on this thread means this function can
    never return while an abandoned worker can still issue device commands.
    """
    stop = threading.Event()
    expired = threading.Event()
    watchdog_error: list[BaseException] = []
    _remaining_seconds(deadline_ns, clock_ns)
    cancel_lock = threading.Lock()
    cancel_invoked = False
    terminal_cancel_invoked = False
    start_permit = OperationStartPermit(deadline_ns, clock_ns, quiescence_failure)

    def request_cancel() -> None:
        nonlocal cancel_invoked
        if cancel is None:
            return
        with cancel_lock:
            if cancel_invoked or terminal_cancel_invoked:
                return
            cancel_invoked = True
        cancel()

    def request_terminal_cancel() -> None:
        nonlocal terminal_cancel_invoked
        operation = terminal_cancel if terminal_cancel is not None else cancel
        if operation is None:
            raise quiescence_failure(label + " has no terminal cancellation fence")
        with cancel_lock:
            if terminal_cancel_invoked:
                return
            terminal_cancel_invoked = True
        operation()

    def watchdog() -> None:
        if _watchdog_reached_deadline(stop, deadline_ns, clock_ns):
            start_permit.expire()
            # Publish the terminal witness before a late stop can suppress the
            # redundant destructive cancellation.  A proven expiry can never
            # be converted back into a successful call during join.
            expired.set()
            if stop.is_set():
                return
            try:
                request_terminal_cancel()
            except BaseException as error:
                watchdog_error.append(error)

    thread = threading.Thread(target=watchdog, name="native-page-v2-watchdog-" + label,
                              daemon=True)
    thread.start()
    output: Any = None
    failure: BaseException | None = None
    try:
        output = function(start_permit)
    except BaseException as error:
        failure = error
    finally:
        # Seal registration before any cancellation/quiescence or return.  A
        # provider retaining an unused permit can never create late work.
        start_permit.seal()
        stop.set()
        # A verified provider must make cancellation terminate.  Never return
        # while a watchdog might still be issuing an authority operation.
        thread.join()
    cancel_error: BaseException | None = None
    if failure is not None:
        try:
            request_cancel()
        except BaseException as error:
            cancel_error = error
    permit_error: BaseException | None = None
    try:
        start_permit.require_exact_start(quiescence_failure)
    except BaseException as error:
        permit_error = error
        try:
            # A missing, failed, or still-registering operation crosses the
            # claim-to-callback uncertainty boundary.  Only the isolated
            # owner process's terminal kill/join fence is sufficient.
            request_terminal_cancel()
        except BaseException as terminal_error:
            if cancel_error is None:
                cancel_error = terminal_error
    if quiesce is not None:
        try:
            quiesce()
        except BaseException as error:
            try:
                request_cancel()
                quiesce()
            except BaseException as final_error:
                raise quiescence_failure(label + " provider did not quiesce") from final_error
            raise quiescence_failure(
                label + " provider initially failed quiescence") from error
    if watchdog_error:
        raise quiescence_failure(label + " cancellation failed") from watchdog_error[0]
    if cancel_error is not None:
        raise quiescence_failure(label + " cancellation failed") from cancel_error
    # Preserve a direct fatal channel failure even if its final quiescence
    # sample lands on the hard-deadline boundary.  Callers use this exact type
    # to terminally kill/join the isolated provider; downgrading it to a plain
    # deadline error could otherwise leave an after-capture channel reusable.
    if isinstance(failure, ProviderQuiescenceFailure):
        raise failure
    if expired.is_set() or clock_ns() >= deadline_ns:
        raise DeadlineExceeded(label + " exceeded hard deadline")
    if permit_error is not None:
        if isinstance(permit_error, ProviderQuiescenceFailure):
            raise permit_error
        raise quiescence_failure(label + " operation registration failed") from permit_error
    if failure is not None:
        raise GraphRunnerError(label + " failed") from failure
    return output


def _cleanup_call(function: Callable[[int], Any], label: str,
                  budget: _CleanupBudget) -> BaseException | None:
    errors: list[BaseException] = []
    timeout_ms = 1
    already_expired = True
    started_ns: int | None = None
    try:
        timeout_ms, already_expired = budget.step_timeout_millis()
    except BaseException as error:
        errors.append(error)
    try:
        started_ns = budget.sample_ns()
    except BaseException as error:
        errors.append(error)
    try:
        function(timeout_ms)
    except BaseException as error:
        errors.append(error)
    finished_ns: int | None = None
    try:
        finished_ns = budget.sample_ns()
    except BaseException as error:
        errors.append(error)
    expired_after = True
    try:
        _, expired_after = budget.step_timeout_millis()
    except BaseException as error:
        errors.append(error)
    if (started_ns is not None and finished_ns is not None and
            finished_ns - started_ns >= timeout_ms * 1_000_000):
        errors.append(DeadlineExceeded(label + " exceeded its cleanup slice"))
    if already_expired or expired_after:
        errors.append(DeadlineExceeded(label + " exceeded shared cleanup grace"))
    if errors:
        return GraphRunnerError(label + " cleanup failed")
    return None


def _require_cleanup_call(function: Callable[[int], Any], label: str,
                          budget: _CleanupBudget) -> None:
    failure = _cleanup_call(function, label, budget)
    if failure is not None:
        raise failure


def _capability_binding_identity_v2(binding: Any, api: _CapabilityApiV2) -> tuple[Any, ...]:
    if type(binding) is not api.binding_type:
        raise CapabilityProviderQuiescenceFailure(
            "capability session binding type differs")
    string_fields = ("authority", "factory_id", "role")
    digest_fields = (
        "session_id", "key_id",
        "resource_binding_sha256", "operation_table_sha256",
        "transport_attestation_sha256", "epoch_attestation_sha256",
    )
    values: list[Any] = []
    for name in string_fields:
        value = getattr(binding, name, None)
        if type(value) is not str or not value:
            raise CapabilityProviderQuiescenceFailure(
                "capability binding " + name + " differs")
        values.append(value)
    for name in digest_fields:
        value = getattr(binding, name, None)
        if type(value) is not str or SHA_RE.fullmatch(value) is None:
            raise CapabilityProviderQuiescenceFailure(
                "capability binding " + name + " differs")
        values.append(value)
    epoch = getattr(binding, "session_epoch", None)
    if type(epoch) is not str or SHA_RE.fullmatch(epoch) is None:
        raise CapabilityProviderQuiescenceFailure(
            "capability binding session epoch differs")
    version = getattr(binding, "version", None)
    if type(version) is not int or version != 2:
        raise CapabilityProviderQuiescenceFailure(
            "capability binding version differs")
    effect_deadline_ns = getattr(binding, "effect_deadline_ns", None)
    closure_deadline_ns = getattr(binding, "closure_deadline_ns", None)
    if (type(effect_deadline_ns) is not int or type(closure_deadline_ns) is not int or
            effect_deadline_ns < 1 or closure_deadline_ns <= effect_deadline_ns):
        raise CapabilityProviderQuiescenceFailure(
            "capability binding deadlines differ")
    # These detached hashes bind the nested owner/resources/attestations.  The
    # capability session independently revalidates the complete frozen body;
    # the graph runner pins every scalar identity used for routing.
    return (version, *values, epoch, effect_deadline_ns, closure_deadline_ns)


def _capability_session_generation_v2(session: Any) -> int:
    generation = getattr(session, "generation", None)
    if type(generation) is not int or generation < 0:
        raise CapabilityProviderQuiescenceFailure(
            "capability session generation differs")
    return generation


class CapabilityGraphSequencerV2:
    """Additive typed adapter from graph operations to one capability session.

    The v1 runner remains untouched.  This adapter accepts only the concrete
    frozen v2 types, never mints a lease or an outcome, and never translates a
    v1 operation.  The capability owner authenticates those objects; this
    sequencer supplies strict ordering, an exact operation-bound start permit,
    absolute-deadline publication fences, and retained terminal evidence.
    """

    def __init__(self, session: Any, clock_ns: Callable[[], int]) -> None:
        if not callable(clock_ns):
            raise CapabilityProviderQuiescenceFailure(
                "capability clock is not callable")
        self._api = _load_capability_api_v2()
        if type(session) is not self._api.session_type:
            raise CapabilityProviderQuiescenceFailure(
                "capability session type differs")
        self._session = session
        self._clock_ns = _MonotonicGuard(clock_ns)
        self._binding = session.binding
        self._binding_identity = _capability_binding_identity_v2(
            self._binding, self._api)
        if (self._binding.factory_id != self._api.frida_factory_id or
                getattr(session, "_construction_kind", None) != "production"):
            raise HardwareAdmissionBlocked(
                "a production Frida capability-v2 session is unavailable")
        self._effect_deadline_ns = self._binding.effect_deadline_ns
        self._closure_deadline_ns = self._binding.closure_deadline_ns
        self._binding_sha256: str | None = None
        self._generation = _capability_session_generation_v2(session)
        completed = getattr(session, "completed_purposes", None)
        partial = getattr(session, "partial_closure_receipts", None)
        if (self._generation != 0 or completed != () or
                getattr(session, "state", None) != "OPEN" or
                getattr(session, "successful_closure_receipt", None) is not None or
                partial != ()):
            raise CapabilityProviderQuiescenceFailure(
                "capability session is not one fresh OPEN session")
        self._lock = threading.Lock()
        self._operations: list[CapabilityOperationCompletionV2] = []
        self._rejected_completed_purposes: tuple[str, ...] = ()
        self._terminal_closure: CapabilityTerminalClosureV2 | None = None
        self._retained_partial_closure_receipts: tuple[Any, ...] = ()
        self._publication_failure: BaseException | None = None

    @property
    def operations(self) -> tuple[CapabilityOperationCompletionV2, ...]:
        return tuple(self._operations)

    @property
    def terminal_closure(self) -> CapabilityTerminalClosureV2 | None:
        return self._terminal_closure

    @property
    def retained_partial_closure_receipts(self) -> tuple[Any, ...]:
        return self._retained_partial_closure_receipts

    @property
    def publication_failure(self) -> BaseException | None:
        return self._publication_failure

    def _enter(self, label: str) -> None:
        if not self._lock.acquire(blocking=False):
            raise CapabilityProviderQuiescenceFailure(
                "reentrant capability " + label + " is forbidden")

    def _leave(self) -> None:
        self._lock.release()

    def _require_binding_unchanged(self) -> None:
        if self._session.binding is not self._binding:
            raise CapabilityProviderQuiescenceFailure(
                "capability session binding object changed")
        if (_capability_binding_identity_v2(self._binding, self._api) !=
                self._binding_identity):
            raise CapabilityProviderQuiescenceFailure(
                "capability session binding changed")

    def _expected_operation(self) -> tuple[int, str, str]:
        purposes = getattr(self._session, "completed_purposes", None)
        if purposes == ():
            return (1, CAPABILITY_CAPTURE_OPERATION_ID_V2,
                    CAPABILITY_CAPTURE_PURPOSE_V2)
        if purposes == (CAPABILITY_CAPTURE_PURPOSE_V2,):
            return (2, CAPABILITY_CLEANUP_OPERATION_ID_V2,
                    CAPABILITY_CLEANUP_PURPOSE_V2)
        raise CapabilityProviderQuiescenceFailure(
            "capability completed-purpose sequence differs")

    def _require_lease(self, lease: Any, sequence: int, operation_id: str,
                       operation_purpose: str) -> None:
        if type(lease) is not self._api.lease_type:
            raise CapabilityProviderQuiescenceFailure(
                "capability operation lease type differs")
        exact = {
            "session_id": self._binding.session_id,
            "session_epoch": self._binding.session_epoch,
            "factory_id": self._binding.factory_id,
            "role": self._binding.role,
            "sequence": sequence,
            "operation_id": operation_id,
            "operation_purpose": operation_purpose,
            "effect_deadline_ns": self._effect_deadline_ns,
            "closure_deadline_ns": self._closure_deadline_ns,
        }
        for name, expected in exact.items():
            if type(getattr(lease, name, None)) is not type(expected) or \
                    getattr(lease, name, None) != expected:
                raise CapabilityProviderQuiescenceFailure(
                    "capability operation lease " + name + " differs")
        binding_sha256 = getattr(lease, "binding_sha256", None)
        request_id = getattr(lease, "request_id", None)
        challenge = getattr(lease, "challenge", None)
        if (type(binding_sha256) is not str or SHA_RE.fullmatch(binding_sha256) is None or
                type(request_id) is not str or SHA_RE.fullmatch(request_id) is None or
                type(challenge) is not str or SHA_RE.fullmatch(challenge) is None):
            raise CapabilityProviderQuiescenceFailure(
                "capability operation lease digest identity differs")
        if self._binding_sha256 is None:
            self._binding_sha256 = binding_sha256
        elif self._binding_sha256 != binding_sha256:
            raise CapabilityProviderQuiescenceFailure(
                "capability operation binding digest changed")

    def _require_outcome(self, outcome: Any, lease: Any, sequence: int,
                         operation_id: str, operation_purpose: str) -> None:
        if type(outcome) is not self._api.outcome_type:
            raise CapabilityProviderQuiescenceFailure(
                "capability operation outcome type differs")
        if outcome.lease != lease:
            raise CapabilityProviderQuiescenceFailure(
                "capability operation outcome lease differs")
        exact = {
            "binding_sha256": self._binding_sha256,
            "request_id": lease.request_id,
            "operation_id": operation_id,
            "operation_purpose": operation_purpose,
            "effect_deadline_ns": self._effect_deadline_ns,
            "closure_deadline_ns": self._closure_deadline_ns,
        }
        for name, expected in exact.items():
            if type(getattr(outcome, name, None)) is not type(expected) or \
                    getattr(outcome, name, None) != expected:
                raise CapabilityProviderQuiescenceFailure(
                    "capability operation outcome " + name + " differs")
        if sequence == 2 and getattr(outcome, "cleanup_completed", None) is not True:
            raise CapabilityProviderQuiescenceFailure(
                "cleanup outcome lacks exact completion evidence")

    def _require_open_idle(self, receipt: Any, generation: int) -> None:
        if type(receipt) is not self._api.open_idle_receipt_type:
            raise CapabilityProviderQuiescenceFailure(
                "OPEN-idle receipt type differs")
        exact = {
            "binding_sha256": self._binding_sha256,
            "session_id": self._binding.session_id,
            "session_epoch": self._binding.session_epoch,
            "generation": generation,
            "state": "OPEN",
            "operation_purpose": CAPABILITY_OPERATION_IDLE_PURPOSE_V2,
            "effect_deadline_ns": self._effect_deadline_ns,
            "closure_deadline_ns": self._closure_deadline_ns,
            "active_operations": 0,
            "live_callbacks": 0,
            "terminal": False,
        }
        for name, expected in exact.items():
            if type(getattr(receipt, name, None)) is not type(expected) or \
                    getattr(receipt, name, None) != expected:
                raise CapabilityProviderQuiescenceFailure(
                    "OPEN-idle receipt " + name + " differs")
        # OPEN-idle is deliberately nonterminal.  A session closure receipt is
        # a different concrete type and is accepted only by close_terminal().
        if type(receipt) is self._api.successful_closure_receipt_type:
            raise CapabilityProviderQuiescenceFailure(
                "terminal closure was confused with OPEN-idle")

    def execute_operation(
            self, *, lease: Any, request_value: Any,
            invoke: Callable[[Any, Callable[[Any], None],
                              CapabilityOperationStartPermitV2], Any],
            cancel: Callable[[], None], quiesce: Callable[[], None],
            terminal_cancel: Callable[[], None]) -> CapabilityOperationCompletionV2:
        """Execute the next closed-table operation and retain its idle proof."""

        for value, label in ((invoke, "invoke"), (cancel, "cancel"),
                             (quiesce, "quiesce"),
                             (terminal_cancel, "terminal cancel")):
            if not callable(value):
                raise CapabilityProviderQuiescenceFailure(
                    "capability operation " + label + " is not callable")
        self._enter("operation")
        holder: dict[str, Any] = {}
        terminal_lock = threading.Lock()
        terminal_invoked = False
        terminal_errors: list[BaseException] = []

        def request_terminal_cancel() -> None:
            nonlocal terminal_invoked
            with terminal_lock:
                if terminal_invoked:
                    return
                terminal_invoked = True
            try:
                terminal_cancel()
            except BaseException as error:
                terminal_errors.append(error)
                raise

        try:
            if self._terminal_closure is not None:
                raise CapabilityProviderQuiescenceFailure(
                    "operation attempted after terminal closure")
            self._require_binding_unchanged()
            if getattr(self._session, "state", None) != "OPEN":
                raise CapabilityProviderQuiescenceFailure(
                    "capability session is not OPEN at operation start")
            if _capability_session_generation_v2(self._session) != self._generation:
                raise CapabilityProviderQuiescenceFailure(
                    "capability session generation changed")
            completed_at_start = getattr(self._session, "completed_purposes", None)
            if (self._publication_failure is not None and
                    completed_at_start != (CAPABILITY_CAPTURE_PURPOSE_V2,)):
                # An invalid lease/outcome or a failed capture is a terminal
                # publication decision.  The sole exception is the closed-table
                # cleanup row after an authenticated capture completed too late:
                # cleanup must still run under the original closure cap, but the
                # rejected capture may never be retried or published as success.
                raise CapabilityProviderQuiescenceFailure(
                    "failed capability session cannot retry an operation")
            sequence, operation_id, operation_purpose = self._expected_operation()
            self._require_lease(lease, sequence, operation_id, operation_purpose)
            execution_deadline_ns = (self._effect_deadline_ns if sequence == 1
                                     else self._closure_deadline_ns)
            _remaining_seconds(execution_deadline_ns, self._clock_ns)
            generation_before = self._generation
            payload = self._session.begin_operation(lease, request_value)
            if type(payload) is not self._api.detached_payload_type:
                raise CapabilityProviderQuiescenceFailure(
                    "capability detached request payload type differs")
            if (getattr(self._session, "state", None) != "ACTIVE" or
                    _capability_session_generation_v2(self._session) !=
                    generation_before + 1):
                raise CapabilityProviderQuiescenceFailure(
                    "capability begin transition differs")
            self._require_binding_unchanged()

            def perform(start_permit: OperationStartPermit) -> tuple[Any, Any]:
                capability_permit = CapabilityOperationStartPermitV2(
                    start_permit, operation_id=operation_id,
                    operation_purpose=operation_purpose, sequence=sequence,
                    request_deadline_ns=self._effect_deadline_ns,
                    execution_deadline_ns=execution_deadline_ns,
                    session_id=self._binding.session_id,
                    session_epoch=self._binding.session_epoch)
                outcome = invoke(payload, self._session.note_callback,
                                 capability_permit)
                self._require_outcome(outcome, lease, sequence, operation_id,
                                      operation_purpose)
                self._session.complete_operation(outcome)
                idle = self._session.verify_operation_idle()
                holder["outcome"] = outcome
                holder["idle"] = idle
                return outcome, idle

            outcome, idle = _bounded_call(
                perform, execution_deadline_ns, self._clock_ns,
                "capability " + operation_purpose, cancel, quiesce,
                CapabilityProviderQuiescenceFailure, request_terminal_cancel)
            self._require_binding_unchanged()
            expected_generation = generation_before + 2
            if (getattr(self._session, "state", None) != "OPEN" or
                    _capability_session_generation_v2(self._session) !=
                    expected_generation):
                raise CapabilityProviderQuiescenceFailure(
                    "capability completion transition differs")
            expected_purposes = ((CAPABILITY_CAPTURE_PURPOSE_V2,) if sequence == 1 else
                                 (CAPABILITY_CAPTURE_PURPOSE_V2,
                                  CAPABILITY_CLEANUP_PURPOSE_V2))
            if getattr(self._session, "completed_purposes", None) != expected_purposes:
                raise CapabilityProviderQuiescenceFailure(
                    "capability completed-purpose publication differs")
            self._require_open_idle(idle, expected_generation)
            if (getattr(self._session, "successful_closure_receipt", None) is not None or
                    getattr(self._session, "partial_closure_receipts", None) != ()):
                raise CapabilityProviderQuiescenceFailure(
                    "operation published closure evidence while still OPEN")
            completion = CapabilityOperationCompletionV2(
                sequence, operation_id, operation_purpose,
                self._effect_deadline_ns, self._closure_deadline_ns,
                expected_generation, outcome, idle)
            self._operations.append(completion)
            self._generation = expected_generation
            return completion
        except BaseException as error:
            # If the capability session itself completed just before the
            # runner's exclusive deadline sample, preserve that state only to
            # permit the mandatory cleanup operation.  Never publish it as a
            # successful graph operation.
            purposes = getattr(self._session, "completed_purposes", None)
            state = getattr(self._session, "state", None)
            generation = getattr(self._session, "generation", None)
            if (state == "OPEN" and type(purposes) is tuple and
                    type(generation) is int and generation >= self._generation):
                self._rejected_completed_purposes = purposes
                self._generation = generation
            elif state not in ("CLOSED", "CLOSURE_UNCERTAIN"):
                try:
                    request_terminal_cancel()
                except BaseException as terminal_error:
                    raise CapabilityProviderQuiescenceFailure(
                        "capability terminal cancellation failed") from terminal_error
            if terminal_errors:
                raise CapabilityProviderQuiescenceFailure(
                    "capability terminal cancellation failed") from terminal_errors[0]
            self._publication_failure = error
            raise
        finally:
            self._leave()

    def _snapshot_partial_closure_receipts(self) -> tuple[Any, ...]:
        value = getattr(self._session, "partial_closure_receipts", None)
        if type(value) is not tuple:
            raise CapabilityClosureUncertain(
                "partial closure receipt collection differs")
        if any(type(item) is not self._api.component_closure_receipt_type
               for item in value):
            raise CapabilityClosureUncertain(
                "partial closure receipt type differs")
        return value

    def _require_terminal_receipt(self, receipt: Any) -> CapabilityTerminalClosureV2:
        if type(receipt) is not self._api.successful_closure_receipt_type:
            raise CapabilityClosureUncertain(
                "successful session closure receipt type differs")
        generation = _capability_session_generation_v2(self._session)
        exact = {
            "binding_sha256": self._binding_sha256,
            "session_id": self._binding.session_id,
            "session_epoch": self._binding.session_epoch,
            "factory_id": self._binding.factory_id,
            "role": self._binding.role,
            "generation": generation,
            "operation_id": CAPABILITY_SESSION_CLOSE_OPERATION_ID_V2,
            "operation_purpose": CAPABILITY_SESSION_CLOSE_PURPOSE_V2,
            "effect_deadline_ns": self._effect_deadline_ns,
            "closure_deadline_ns": self._closure_deadline_ns,
            "active_operations": 0,
            "live_callbacks": 0,
            "owner_closed": True,
        }
        for name, expected in exact.items():
            if type(getattr(receipt, name, None)) is not type(expected) or \
                    getattr(receipt, name, None) != expected:
                raise CapabilityClosureUncertain(
                    "successful closure receipt " + name + " differs")
        components = getattr(receipt, "component_receipts", None)
        if (type(components) is not tuple or not components or
                any(type(item) is not self._api.component_closure_receipt_type
                    for item in components)):
            raise CapabilityClosureUncertain(
                "successful closure component receipts differ")
        if (getattr(self._session, "state", None) != "CLOSED" or
                getattr(self._session, "successful_closure_receipt", None) != receipt):
            raise CapabilityClosureUncertain(
                "successful closure was not retained by the session")
        return CapabilityTerminalClosureV2(generation, components, receipt)

    def close_terminal(self, *, cancel: Callable[[], None],
                       quiesce: Callable[[], None],
                       terminal_cancel: Callable[[], None]) -> CapabilityTerminalClosureV2:
        """Close the session under the closure cap and retain exact receipts."""

        for value, label in ((cancel, "cancel"), (quiesce, "quiesce"),
                             (terminal_cancel, "terminal cancel")):
            if not callable(value):
                raise CapabilityClosureUncertain(
                    "capability closure " + label + " is not callable")
        self._enter("closure")
        holder: dict[str, Any] = {}
        terminal_lock = threading.Lock()
        terminal_invoked = False

        def request_terminal_cancel() -> None:
            nonlocal terminal_invoked
            with terminal_lock:
                if terminal_invoked:
                    return
                terminal_invoked = True
            terminal_cancel()

        try:
            if self._terminal_closure is not None:
                raise CapabilityClosureUncertain(
                    "terminal closure was requested twice")
            self._require_binding_unchanged()
            if getattr(self._session, "state", None) != "OPEN":
                raise CapabilityClosureUncertain(
                    "capability session is not OPEN at closure start")
            if _capability_session_generation_v2(self._session) != self._generation:
                raise CapabilityClosureUncertain(
                    "capability generation changed before closure")

            def perform(start_permit: OperationStartPermit) -> Any:
                receipt = start_permit.start(self._session.close_successfully)
                holder["receipt"] = receipt
                return receipt

            receipt = _bounded_call(
                perform, self._closure_deadline_ns, self._clock_ns,
                "capability terminal closure", cancel, quiesce,
                CapabilityClosureUncertain, request_terminal_cancel)
            self._require_binding_unchanged()
            terminal = self._require_terminal_receipt(receipt)
            self._retained_partial_closure_receipts = \
                self._snapshot_partial_closure_receipts()
            self._terminal_closure = terminal
            self._generation = terminal.generation
            return terminal
        except BaseException as error:
            retained_terminal = False
            try:
                self._retained_partial_closure_receipts = \
                    self._snapshot_partial_closure_receipts()
                candidate = holder.get("receipt")
                if candidate is not None and \
                        type(candidate) is self._api.successful_closure_receipt_type:
                    self._terminal_closure = self._require_terminal_receipt(candidate)
                    retained_terminal = True
            except BaseException:
                pass
            if retained_terminal and isinstance(error, DeadlineExceeded):
                raise
            if not retained_terminal:
                try:
                    request_terminal_cancel()
                except BaseException as terminal_error:
                    raise CapabilityClosureUncertain(
                        "capability closure terminal cancellation failed") \
                        from terminal_error
            if isinstance(error, CapabilityClosureUncertain):
                raise
            raise CapabilityClosureUncertain(
                "capability terminal closure is not exact") from error
        finally:
            self._leave()


def _run_frida_lifecycle(frida: FridaProvider, source: str, binding: StageBinding,
                         manifest: LoadedJson, external_record: dict[str, Any],
                         deadline_ns: int, clock_ns: Callable[[], int],
                         teardown: _TeardownOnce,
                         cleanup_budget: _CleanupBudget) -> dict[str, Any]:
    collector = _V2MessageCollector(manifest, external_record, deadline_ns, clock_ns)
    result: dict[str, Any] | None = None
    primary: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    session: FridaSession | None = None
    stop = threading.Event()
    expired = threading.Event()
    watchdog_errors: list[BaseException] = []
    _remaining_seconds(deadline_ns, clock_ns)
    attach_permit = OperationStartPermit(deadline_ns, clock_ns,
                                         FridaProviderQuiescenceFailure)
    load_permit = OperationStartPermit(deadline_ns, clock_ns,
                                       FridaProviderQuiescenceFailure)

    def watchdog() -> None:
        if _watchdog_reached_deadline(stop, deadline_ns, clock_ns):
            attach_permit.expire()
            load_permit.expire()
            # As in _bounded_call, commit the expiry witness before honoring a
            # late stop that merely suppresses duplicate teardown.
            expired.set()
            if stop.is_set():
                return
            failure = _cleanup_call(teardown.call, "deadline Frida teardown",
                                    cleanup_budget)
            if failure is not None:
                watchdog_errors.append(failure)

    watcher = threading.Thread(target=watchdog, name="native-page-v2-frida-watchdog",
                               daemon=True)
    watcher.start()
    try:
        try:
            session = frida.attach(binding.serial, binding.pid,
                                   _remaining_millis(deadline_ns, clock_ns), attach_permit)
        finally:
            attach_permit.seal()
        attach_permit.require_exact_start(FridaProviderQuiescenceFailure)
        if clock_ns() >= deadline_ns:
            raise DeadlineExceeded("Frida attach completed after hard deadline")
        try:
            session.load(source, collector.on_message,
                         _remaining_millis(deadline_ns, clock_ns), load_permit)
        finally:
            load_permit.seal()
        load_permit.require_exact_start(FridaProviderQuiescenceFailure)
        if clock_ns() >= deadline_ns:
            raise DeadlineExceeded("Frida load completed after hard deadline")
        collector.wait()
        result = collector.result()
    except BaseException as error:
        primary = error
    finally:
        attach_permit.seal()
        load_permit.seal()
        collector.seal()
        if session is not None:
            for label, operation in (
                    ("seal callbacks", session.seal_callbacks),
                    ("unload", session.unload),
                    ("detach", session.detach),
                    ("callback quiescence", session.assert_quiescent)):
                failure = _cleanup_call(operation, label, cleanup_budget)
                if failure is not None:
                    cleanup_errors.append(failure)
        failure = _cleanup_call(teardown.call, "Frida provider teardown", cleanup_budget)
        if failure is not None:
            cleanup_errors.append(failure)
        failure = _cleanup_call(frida.assert_quiescent, "Frida provider quiescence",
                                cleanup_budget)
        if failure is not None:
            cleanup_errors.append(failure)
        try:
            collector.assert_clean_after_quiescence()
        except BaseException as error:
            cleanup_errors.append(error)
        stop.set()
        # A verified isolated provider must make exact teardown terminate.
        # Fail-stop rather than return with a live device-operation worker.
        watcher.join()
        cleanup_errors.extend(watchdog_errors)
    if expired.is_set() and primary is None:
        primary = DeadlineExceeded("Frida lifecycle exceeded hard deadline")
    if cleanup_errors:
        raise GraphRunnerError("Frida lifecycle cleanup was not exact") from cleanup_errors[0]
    if primary is not None:
        if isinstance(primary, GraphRunnerError):
            raise primary
        raise GraphRunnerError("Frida lifecycle failed") from primary
    if result is None:
        _fail("Frida lifecycle produced no unique result")
    return result


def _reject_ambient_adb_overrides(environment: dict[str, str]) -> None:
    if type(environment) is not dict or any(type(key) is not str or type(value) is not str
                                             for key, value in environment.items()):
        _fail("ambient environment contract differs")
    folded = {key.upper() for key in environment}
    present = sorted(set(ADB_OVERRIDE_NAMES) & folded)
    if present:
        _fail("ambient ADB override is present: " + present[0])


def run_one_stage(*, manifest: LoadedJson, observer_source: str,
                  observer_sha256: str, binding: StageBinding,
                  tool_bundle: LockedToolBundle, authority_provider: AuthorityProvider,
                  frida_provider: FridaProvider, trusted_pins: TrustedPins,
                  ambient_environment: dict[str, str],
                  clock_ns: Callable[[], int] = time.monotonic_ns,
                  nonce_factory: Callable[[], str] = lambda: secrets.token_hex(32)) -> dict[str, Any]:
    """Run one authenticated stage. Caller retains/owns the locked bundle handles."""
    if type(binding) is not StageBinding:
        _fail("stage binding differs")
    binding = StageBinding(
        binding.serial, binding.pid, binding.start_time_ticks,
        binding.observer_session_id, binding.deadline_ms,
        binding.absolute_deadline_ns, binding.stage,
    )
    if type(trusted_pins) is not TrustedPins:
        _fail("trusted pins wrapper differs")
    trusted_pins = TrustedPins(
        trusted_pins.tool_bundle_sha256, trusted_pins.manifest_sha256,
        trusted_pins.provider_admission_sha256,
        trusted_pins.frida_admission_sha256, trusted_pins.stage_policy_sha256,
        trusted_pins.receipt_hmac_key,
    )
    guarded_clock = _MonotonicGuard(clock_ns)
    started_ns = guarded_clock()
    _reject_ambient_adb_overrides(ambient_environment)
    _validate_trusted_pins(trusted_pins)
    if type(manifest) is not LoadedJson:
        _fail("manifest wrapper type differs")
    private_manifest = load_canonical(manifest.raw, MAX_MANIFEST_BYTES)
    if (private_manifest.sha256 != manifest.sha256 or
            private_manifest.sha256 != trusted_pins.manifest_sha256):
        _fail("manifest detached digest differs")
    manifest = private_manifest
    if type(observer_source) is not str:
        _fail("observer source is not exact text")
    try:
        observer_raw = observer_source.encode("utf-8", "strict")
    except (AttributeError, UnicodeError) as error:
        raise GraphRunnerError("observer source is not exact UTF-8 text") from error
    _sha(observer_sha256, "observer source digest")
    if (hashlib.sha256(observer_raw).hexdigest() != observer_sha256 or
            observer_sha256 != EXPECTED_OBSERVER_SHA256 or
            not 0 < len(observer_raw) <= MAX_OBSERVER_BYTES):
        _fail("observer source bytes differ from reviewed pin")
    validate_manifest(manifest, binding, observer_sha256)
    deadline_ns = int(manifest.value["coordinator"]["absoluteMonotonicDeadlineNs"])
    if (deadline_ns != binding.absolute_deadline_ns or deadline_ns <= started_ns or
            deadline_ns - started_ns > binding.deadline_ms * 1_000_000):
        _fail("absolute monotonic deadline binding differs")
    try:
        run_nonce = nonce_factory()
    except BaseException as error:
        raise GraphRunnerError("runner challenge nonce generation failed") from error
    if type(run_nonce) is not str or re.fullmatch(r"[0-9a-f]{64}", run_nonce) is None:
        _fail("runner challenge nonce differs")
    tool, tool_sha256 = _validate_tool_bundle(tool_bundle, trusted_pins)
    before_request = AuthorityRequest("before", manifest.sha256, binding, deadline_ns,
                                      tool_sha256, run_nonce, 1, None)
    admission: LoadedJson | None = None
    frida_admission: LoadedJson | None = None
    before: StageAuthorityCapture | None = None
    before_loaded: LoadedJson | None = None
    before_receipt: LoadedJson | None = None
    after: StageAuthorityCapture | None = None
    after_loaded: LoadedJson | None = None
    after_receipt: LoadedJson | None = None
    snapshot: dict[str, Any] | None = None
    operation_error: BaseException | None = None
    final_errors: list[BaseException] = []
    teardown = _TeardownOnce(frida_provider)
    authority_fail_stop = _AuthorityFailStopOnce(authority_provider)
    cleanup_budget = _CleanupBudget(deadline_ns, guarded_clock)
    authority_channel_safe = True
    authority_admitted = False

    def fail_stop_authority_channel() -> None:
        failure = _cleanup_call(authority_fail_stop.call,
                                "authority provider fail-stop", cleanup_budget)
        if failure is not None:
            final_errors.append(failure)
        failure = _cleanup_call(authority_provider.assert_quiescent,
                                "authority provider post-fail-stop quiescence",
                                cleanup_budget)
        if failure is not None:
            final_errors.append(failure)

    try:
        admission = _validate_provider_admission(
            _bounded_call(lambda permit: authority_provider.admission(
                              _remaining_millis(deadline_ns, guarded_clock), permit),
                          deadline_ns, guarded_clock, "provider admission",
                          lambda: _require_cleanup_call(
                              authority_provider.cancel_and_quiesce,
                              "provider admission cancellation", cleanup_budget),
                          lambda: authority_provider.assert_quiescent(
                              _remaining_millis(deadline_ns, guarded_clock)),
                          AuthorityProviderQuiescenceFailure,
                          terminal_cancel=lambda: _require_cleanup_call(
                              authority_fail_stop.call,
                              "provider admission terminal fail-stop", cleanup_budget)),
            trusted_pins)
        authority_admitted = True
        frida_admission = _validate_frida_admission(
            _bounded_call(lambda permit: frida_provider.admission(
                              _remaining_millis(deadline_ns, guarded_clock), permit),
                          deadline_ns, guarded_clock, "Frida provider admission",
                          lambda: _require_cleanup_call(
                              teardown.call, "Frida admission cancellation", cleanup_budget),
                          lambda: frida_provider.assert_quiescent(
                              _remaining_millis(deadline_ns, guarded_clock)),
                          FridaProviderQuiescenceFailure,
                          terminal_cancel=lambda: _require_cleanup_call(
                              teardown.call, "Frida admission terminal teardown",
                              cleanup_budget)),
            trusted_pins)
        _validate_tool_bundle(tool_bundle, trusted_pins)
        before = _snapshot_stage_capture(_bounded_call(
                               lambda permit: authority_provider.capture(
                                   _isolated_authority_request(before_request),
                                   _remaining_millis(deadline_ns, guarded_clock), permit), deadline_ns,
                               guarded_clock, "before authority capture",
                               lambda: _require_cleanup_call(
                                   authority_provider.cancel_and_quiesce,
                                   "before authority cancellation", cleanup_budget),
                               lambda: authority_provider.assert_quiescent(
                                   _remaining_millis(deadline_ns, guarded_clock)),
                               AuthorityProviderQuiescenceFailure,
                               terminal_cancel=lambda: _require_cleanup_call(
                                   authority_fail_stop.call,
                                   "before authority terminal fail-stop",
                                   cleanup_budget)))
        before_receipt = _validate_capture_receipt(before, before_request, admission,
                                                   trusted_pins)
        before_loaded = validate_stage_authority(before, before_request, manifest, trusted_pins,
                                                 tool, admission, frida_admission)
        _validate_tool_bundle(tool_bundle, trusted_pins)
        injected = build_injected_observer(manifest, observer_source)
        snapshot = _run_frida_lifecycle(frida_provider, injected, binding, manifest,
                                        before_loaded.value, deadline_ns, guarded_clock, teardown,
                                        cleanup_budget)
    except BaseException as error:
        operation_error = error
        if not authority_admitted or isinstance(error, AuthorityProviderQuiescenceFailure):
            authority_channel_safe = False
    finally:
        if not teardown.called:
            failure = _cleanup_call(teardown.call, "Frida provider teardown", cleanup_budget)
            if failure is not None:
                final_errors.append(failure)
        after_request = AuthorityRequest("after", manifest.sha256, binding, deadline_ns,
                                         tool_sha256, run_nonce, 2,
                                         before_receipt.sha256 if before_receipt is not None else None)
        if before_receipt is None:
            authority_channel_safe = False
        if not authority_channel_safe:
            fail_stop_authority_channel()
            final_errors.append(GraphRunnerError(
                "postcondition capture suppressed after authority channel failure"))
        else:
            try:
                if guarded_clock() < deadline_ns:
                    after = _snapshot_stage_capture(_bounded_call(
                                          lambda permit: authority_provider.capture(
                                              _isolated_authority_request(after_request),
                                              _remaining_millis(deadline_ns, guarded_clock), permit),
                                          deadline_ns, guarded_clock,
                                          "after authority capture",
                                          lambda: _require_cleanup_call(
                                              authority_provider.cancel_and_quiesce,
                                              "after authority cancellation", cleanup_budget),
                                          lambda: authority_provider.assert_quiescent(
                                              _remaining_millis(deadline_ns, guarded_clock)),
                                          AuthorityProviderQuiescenceFailure,
                                          terminal_cancel=lambda: _require_cleanup_call(
                                              authority_fail_stop.call,
                                              "after authority terminal fail-stop",
                                              cleanup_budget)))
                else:
                    final_errors.append(DeadlineExceeded(
                        "hard deadline expired before postcondition capture"))
                    cleanup_deadline = cleanup_budget.deadline_ns()
                    after = _snapshot_stage_capture(_bounded_call(
                                          lambda permit: authority_provider.capture(
                                              _isolated_authority_request(after_request),
                                              cleanup_budget.step_timeout_millis()[0], permit),
                                          cleanup_deadline, guarded_clock,
                                          "after authority cleanup capture",
                                          lambda: _require_cleanup_call(
                                              authority_provider.cancel_and_quiesce,
                                              "cleanup authority cancellation", cleanup_budget),
                                          lambda: _require_cleanup_call(
                                              authority_provider.assert_quiescent,
                                              "cleanup authority quiescence", cleanup_budget),
                                          AuthorityProviderQuiescenceFailure,
                                          terminal_cancel=lambda: _require_cleanup_call(
                                              authority_fail_stop.call,
                                              "cleanup authority terminal fail-stop",
                                              cleanup_budget)))
                after_receipt = _validate_capture_receipt(after, after_request, admission,
                                                          trusted_pins)
                after_loaded = validate_stage_authority(
                    after, after_request, manifest, trusted_pins, tool, admission,
                    frida_admission)
            except BaseException as error:
                final_errors.append(error)
                if isinstance(error, AuthorityProviderQuiescenceFailure):
                    authority_channel_safe = False
                    fail_stop_authority_channel()
        failure = _cleanup_call(frida_provider.assert_quiescent,
                                "final Frida provider quiescence", cleanup_budget)
        if failure is not None:
            final_errors.append(failure)
        try:
            _validate_tool_bundle(tool_bundle, trusted_pins)
        except BaseException as error:
            final_errors.append(error)
        if before is not None and before_loaded is not None and after is not None and after_loaded is not None:
            try:
                require_stage_stability(before, after, before_loaded, after_loaded)
            except BaseException as error:
                final_errors.append(error)
    if final_errors:
        raise GraphRunnerError("postcondition authority or cleanup failed") from final_errors[0]
    if operation_error is not None:
        if isinstance(operation_error, GraphRunnerError):
            raise operation_error
        raise GraphRunnerError("stage operation failed") from operation_error
    if snapshot is None or before_loaded is None or after_loaded is None or \
            admission is None or frida_admission is None or before_receipt is None or \
            after_receipt is None:
        _fail("stage result is incomplete")
    result = {
        "schemaVersion": 2, "authority": RUNNER_AUTHORITY, "stage": binding.stage,
        "manifestSha256": manifest.sha256, "observerSha256": observer_sha256,
        "runNonce": run_nonce,
        "providerAdmissionSha256": admission.sha256,
        "fridaAdmissionSha256": frida_admission.sha256,
        "beforeAuthoritySha256": before_loaded.sha256,
        "afterAuthoritySha256": after_loaded.sha256,
        "beforeReceiptSha256": before_receipt.sha256,
        "afterReceiptSha256": after_receipt.sha256,
        "toolBundleSha256": tool_sha256, "snapshot": snapshot,
    }
    canonical_bytes(result)
    if guarded_clock() >= deadline_ns:
        raise DeadlineExceeded("hard deadline expired before stage result publication")
    return result


def _blocked_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Native page graph v2 runner (production blocked)")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--observer", required=True)
    parser.parse_args(argv)
    record = {"schemaVersion": 2, "authority": RUNNER_AUTHORITY, "success": False,
              "code": "HARDWARE_ADMISSION_BLOCKED", "reason": PRODUCTION_BLOCK_REASON}
    sys.stdout.buffer.write(canonical_bytes(record) + b"\n")
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    return _blocked_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
