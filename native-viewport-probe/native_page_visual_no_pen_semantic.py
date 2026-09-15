"""Observation-only semantic authority for the visual-session harness.

This module is deliberately a high-level, injected-backend boundary.  It has
no ADB, Frida, shell, process, filesystem, device-discovery, input, writer,
event-device, or pen-lease implementation.  The backend surface has one fixed
capture operation and a quiescence barrier.  A capture is released only after
the adapter independently validates the graph-v2 manifest and snapshot, two
fresh external authority records, an authenticated receipt chain, and five
redundant zero-operation attestations.

The legacy result field names required by ``SemanticCapture`` are retained as
a compatibility envelope.  They bind this no-pen route's backend admission,
observer admission, external records, and authenticated receipts; this module
does not call ``native_page_graph_v2_runner.run_one_stage`` because that route
requires an active pen lease.

No production fixed backend/bootstrap or exact-head hardware evidence exists
in this module.  ``admission_status`` therefore remains fail-closed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import copy
import hashlib
import hmac
import json
import re
import secrets
import struct
import threading
from typing import Any, NoReturn, Protocol
import uuid

import native_page_android_authority as android
import native_page_graph_v2_runner as graph
import native_page_host_authority as host
import native_page_visual_session_harness as harness


AUTHORITY = "rtl-reader-native-page-no-pen-semantic-adapter-v1"
PLAN_AUTHORITY = "rtl-reader-native-page-no-pen-semantic-plan-v1"
BACKEND_AUTHORITY = "rtl-reader-fixed-no-pen-semantic-backend-v1"
REQUEST_AUTHORITY = "rtl-reader-native-page-no-pen-semantic-request-v1"
EXTERNAL_AUTHORITY = "rtl-reader-native-page-no-pen-external-authority-v1"
RECEIPT_AUTHORITY = "rtl-reader-native-page-no-pen-semantic-receipt-v1"
STAGE_RECEIPT_AUTHORITY = (
    "rtl-reader-native-page-no-pen-semantic-stage-receipt-v1"
)
TRANSCRIPT_AUTHORITY = "rtl-reader-native-page-no-pen-semantic-transcript-v1"
OBSERVER_ADMISSION_AUTHORITY = (
    "rtl-reader-native-page-no-pen-observer-admission-v1"
)
MONOTONIC_CLOCK_AUTHORITY = (
    "rtl-reader-retained-host-monotonic-clock-authority-v1"
)
INTERNAL_IDENTITY_AUTHORITY = (
    "rtl-reader-native-page-no-pen-internal-identity-authority-v1"
)

WIRE_MAGIC = b"NPSEM001"
WIRE_TERMINAL_TAG = 0
WIRE_MEMBERS = (
    (1, "manifest", graph.MAX_MANIFEST_BYTES),
    (2, "before", graph.MAX_AUTHORITY_BYTES),
    (3, "snapshot", graph.MAX_MESSAGE_BYTES),
    (4, "after", graph.MAX_AUTHORITY_BYTES),
    (5, "transcript", 262_144),
    (6, "receipt", graph.MAX_AUTHORITY_BYTES),
)
WIRE_HEADER = struct.Struct(">BI32s")
MAX_WIRE_BYTES = 4_194_304
MAX_CAPTURE_BUDGET_MS = graph.MAX_DEADLINE_MS
MIN_CAPTURE_BUDGET_MS = graph.MIN_DEADLINE_MS
MAX_CAPTURE_IDENTITIES = 1_000_000
MAX_CLOCK_AUTHORITY_BYTES = 16_384

REAL_FIXED_BACKEND_IMPLEMENTED = False
HARDWARE_EVIDENCE_COMPLETE = False
UNRESOLVED_BLOCKERS = (
    "reviewed fixed no-pen semantic backend/bootstrap is not implemented",
    "backend executable and private transport identity are not pinned",
    "integrated exact-head hardware evidence is not complete",
)

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_ANDROID_TOKEN = re.compile(r"[0-9a-f]{1,16}\Z")
_MODULE_NAME = re.compile(r"[A-Za-z0-9._+-]{1,128}\Z")


class NoPenSemanticError(RuntimeError):
    """Semantic authority or evidence was rejected."""


class NoPenSemanticUncertain(NoPenSemanticError):
    """A dispatched capture, retained backend, or quiescence is uncertain."""


def _fail(message: str) -> NoReturn:
    raise NoPenSemanticError(message)


def _need(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _sha(raw: bytes) -> str:
    _need(type(raw) is bytes, "digest input is not exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _hex(value: Any, label: str) -> str:
    _need(type(value) is str and _HEX.fullmatch(value) is not None,
          label + " is not one lowercase SHA-256")
    return value


def _token(value: Any, label: str) -> str:
    _need(type(value) is str and _TOKEN.fullmatch(value) is not None,
          label + " is not one bounded token")
    return value


def _canonical_uuid(value: Any, label: str) -> str:
    _need(type(value) is str, label + " is not text")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as error:
        raise NoPenSemanticError(label + " is not a UUID") from error
    _need(value == canonical, label + " is not a canonical lowercase UUID")
    return value


def _integer(value: Any, label: str, minimum: int,
             maximum: int = 2**63 - 1) -> int:
    _need(type(value) is int and minimum <= value <= maximum,
          label + " is outside exact integer bounds")
    return value


def _bounded_text(value: Any, label: str, maximum: int = 4096) -> str:
    _need(type(value) is str and value and
          all(ord(character) >= 0x20 and ord(character) != 0x7f
              for character in value),
          label + " is not bounded text")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise NoPenSemanticError(label + " is not UTF-8") from error
    _need(len(raw) <= maximum, label + " is oversized")
    return value


def _canonical(value: Any, maximum: int = graph.MAX_AUTHORITY_BYTES) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise NoPenSemanticError("authority is not canonical strict JSON") from error
    _need(0 < len(raw) <= maximum, "canonical authority is absent or oversized")
    return raw


def _loaded(raw: bytes, maximum: int, label: str) -> graph.LoadedJson:
    try:
        return graph.load_canonical(raw, maximum)
    except graph.GraphRunnerError as error:
        raise NoPenSemanticError(label + " is not canonical graph-v2 JSON") from error


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == keys,
          label + " topology differs")
    return value


def _wire_equal(left: Any, right: Any) -> bool:
    """Type-exact JSON equality (Python's ``True == 1`` is insufficient)."""
    try:
        return _canonical(left) == _canonical(right)
    except NoPenSemanticError:
        return False


class _RetainedInternalIdentityAuthority:
    """Non-injectable cryptographic identity source retained by the adapter.

    Production identity creation deliberately has no caller-supplied callable
    or backend execution seam.  Each identity consumes one 256-bit draw from
    ``SystemRandom``.  A collision is rejected rather than retried so a broken
    or substituted provider cannot hide behind an unbounded retry loop.
    """

    __slots__ = ("__rng", "__canonical", "__issued")

    def __init__(self) -> None:
        self.__rng = secrets.SystemRandom()
        self.__canonical = _canonical({
            "authority": INTERNAL_IDENTITY_AUTHORITY,
            "schemaVersion": 1,
            "provider": "python-secrets.SystemRandom",
            "bitsPerIdentity": 256,
            "oneDrawPerIdentity": True,
            "callerSupplied": False,
            "collisionRetry": False,
        })
        self.__issued: set[str] = set()

    def verify(self) -> None:
        _need(type(self.__rng) is secrets.SystemRandom,
              "internal identity randomness authority was substituted")
        _need(self.__canonical == _canonical({
            "authority": INTERNAL_IDENTITY_AUTHORITY,
            "schemaVersion": 1,
            "provider": "python-secrets.SystemRandom",
            "bitsPerIdentity": 256,
            "oneDrawPerIdentity": True,
            "callerSupplied": False,
            "collisionRetry": False,
        }), "internal identity randomness authority drifted")

    def canonical_bytes(self) -> bytes:
        self.verify()
        return self.__canonical

    def fresh_hex(self) -> str:
        self.verify()
        try:
            value = f"{self.__rng.getrandbits(256):064x}"
        except BaseException as error:
            raise NoPenSemanticUncertain(
                "internal identity randomness authority failed") from error
        _need(_HEX.fullmatch(value) is not None and len(value) == 64,
              "internal identity randomness authority returned bad entropy")
        _need(value not in self.__issued and
              len(self.__issued) < MAX_CAPTURE_IDENTITIES * 3,
              "internal identity randomness authority repeated an identity")
        self.__issued.add(value)
        return value


def admission_status() -> dict[str, Any]:
    """Protocol availability is not live-device admission authority."""
    return {
        "admitted": False,
        "observationOnly": True,
        "noPenLease": True,
        "realFixedBackendImplemented": REAL_FIXED_BACKEND_IMPLEMENTED,
        "hardwareEvidenceComplete": HARDWARE_EVIDENCE_COMPLETE,
        "blockers": list(UNRESOLVED_BLOCKERS),
    }


@dataclass(frozen=True)
class NoPenSemanticPlan:
    session_id: str
    serial: str
    fixture_uri: str
    fixture_sha256: str
    host_task_id: int
    host_activity_token: str
    framework_path: str
    module_name: str
    module_path: str
    module_size: int
    module_sha256: str
    clock_authority_sha256: str
    monotonic_domain_sha256: str
    capture_budget_ms: int = 1_000

    def validate(self) -> None:
        _canonical_uuid(self.session_id, "semantic plan session")
        _need(self.serial == harness.AUTHORIZED_SERIAL,
              "semantic plan serial differs")
        _bounded_text(self.fixture_uri, "semantic plan fixture URI")
        _need(harness.FIXTURE_URI.fullmatch(self.fixture_uri) is not None and
              ".." not in self.fixture_uri,
              "semantic plan fixture URI escaped disposable scope")
        _hex(self.fixture_sha256, "semantic plan fixture")
        _integer(self.host_task_id, "semantic plan host task", 0, 10_000_000)
        _token(self.host_activity_token, "semantic plan host activity token")
        _bounded_text(self.framework_path, "semantic plan framework path")
        _need(self.framework_path.startswith("/system/"),
              "semantic plan framework path differs")
        _need(type(self.module_name) is str and
              _MODULE_NAME.fullmatch(self.module_name) is not None,
              "semantic plan module name differs")
        _bounded_text(self.module_path, "semantic plan module path")
        _need(self.module_path.startswith("/"),
              "semantic plan module path is not absolute")
        _integer(self.module_size, "semantic plan module size", 1,
                 graph.MAX_SAFE_INTEGER)
        _hex(self.module_sha256, "semantic plan module")
        _hex(self.clock_authority_sha256,
             "semantic plan retained clock authority")
        _hex(self.monotonic_domain_sha256,
             "semantic plan monotonic domain")
        _need(self.clock_authority_sha256 != self.monotonic_domain_sha256,
              "semantic plan clock authority/domain identities alias")
        _integer(self.capture_budget_ms, "semantic plan capture budget",
                 MIN_CAPTURE_BUDGET_MS, MAX_CAPTURE_BUDGET_MS)

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "authority": PLAN_AUTHORITY,
            "schemaVersion": 1,
            "sessionId": self.session_id,
            "serial": self.serial,
            "fixtureUri": self.fixture_uri,
            "fixtureSha256": self.fixture_sha256,
            "hostTaskId": self.host_task_id,
            "hostActivityToken": self.host_activity_token,
            "framework": {
                "path": self.framework_path,
                "size": graph.FRAMEWORK_SIZE,
                "sha256": graph.FRAMEWORK_SHA256,
            },
            "module": {
                "name": self.module_name,
                "path": self.module_path,
                "size": self.module_size,
                "sha256": self.module_sha256,
            },
            "observerSha256": graph.EXPECTED_OBSERVER_SHA256,
            "clockAuthoritySha256": self.clock_authority_sha256,
            "monotonicDomainSha256": self.monotonic_domain_sha256,
            "captureBudgetMs": self.capture_budget_ms,
            "observationOnly": True,
            "inputCalls": 0,
            "writerCalls": 0,
            "penOperations": 0,
            "penLeaseAcquisitions": 0,
            "penLeaseTouches": 0,
            "retryAllowed": False,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical(self.wire())

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class NoPenBackendIdentity:
    authority: str
    backend_instance_id: str
    serial: str
    boot_id: str
    private_adb_session_id: str
    worker_session_id: str
    worker_pid: int
    worker_start_ticks: int
    worker_image_sha256: str
    tool_bundle_sha256: str
    observer_sha256: str
    receipt_key_id: str
    clock_authority_sha256: str
    monotonic_domain_sha256: str
    retained_private_adb_handle: bool
    retained_worker_handle: bool
    private_transport: bool
    explicit_serial: bool
    fixed_capture_only: bool
    complete_graph_capture: bool
    independent_external_capture: bool
    fresh_reply_channel: bool
    late_reply_sealed: bool
    failure_returns_after_quiescence: bool
    read_only: bool
    input_capability: bool
    writer_capability: bool
    pen_operation_capability: bool
    pen_lease_acquisition_capability: bool
    pen_lease_touch_capability: bool
    accepts_general_commands: bool
    accepts_caller_argv: bool
    user_document_selection: bool

    def validate(self, plan: NoPenSemanticPlan) -> None:
        plan.validate()
        _need(self.authority == BACKEND_AUTHORITY,
              "semantic backend authority differs")
        for value, label in (
                (self.backend_instance_id, "semantic backend instance"),
                (self.private_adb_session_id, "semantic private ADB session"),
                (self.worker_session_id, "semantic worker session"),
                (self.worker_image_sha256, "semantic worker image"),
                (self.tool_bundle_sha256, "semantic tool bundle"),
                (self.receipt_key_id, "semantic receipt key"),
                (self.clock_authority_sha256,
                 "semantic backend retained clock authority"),
                (self.monotonic_domain_sha256,
                 "semantic backend monotonic domain")):
            _hex(value, label)
        _need(self.serial == plan.serial, "semantic backend serial differs")
        _canonical_uuid(self.boot_id, "semantic backend boot ID")
        _integer(self.worker_pid, "semantic worker PID", 1, 4_194_304)
        _integer(self.worker_start_ticks, "semantic worker start ticks", 1)
        _need(self.observer_sha256 == graph.EXPECTED_OBSERVER_SHA256,
              "semantic backend observer pin differs")
        _need(self.clock_authority_sha256 == plan.clock_authority_sha256 and
              self.monotonic_domain_sha256 ==
              plan.monotonic_domain_sha256,
              "semantic backend monotonic authority differs")
        exact_true = (
            self.retained_private_adb_handle,
            self.retained_worker_handle,
            self.private_transport,
            self.explicit_serial,
            self.fixed_capture_only,
            self.complete_graph_capture,
            self.independent_external_capture,
            self.fresh_reply_channel,
            self.late_reply_sealed,
            self.failure_returns_after_quiescence,
            self.read_only,
        )
        exact_false = (
            self.input_capability,
            self.writer_capability,
            self.pen_operation_capability,
            self.pen_lease_acquisition_capability,
            self.pen_lease_touch_capability,
            self.accepts_general_commands,
            self.accepts_caller_argv,
            self.user_document_selection,
        )
        _need(all(type(value) is bool for value in exact_true + exact_false),
              "semantic backend flags are not exact booleans")
        _need(all(exact_true) and not any(exact_false),
              "semantic backend escapes observation-only authority")

    def canonical_bytes(self) -> bytes:
        return _canonical(asdict(self))

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class NoPenCaptureRequest:
    authority: str
    session_id: str
    serial: str
    boot_id: str
    sample_id: str
    observer_session_id: str
    run_nonce: str
    phase: str
    ordinal: int
    issued_ns: int
    deadline_ns: int
    plan_sha256: str
    backend_sha256: str
    clock_authority_sha256: str
    monotonic_domain_sha256: str
    manifest_sha256: str
    foreign_sha256: str
    placement_sha256: str
    task_authority_sha256: str
    task_stable_authority_sha256: str
    files_authority_sha256: str

    def wire(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "sessionId": self.session_id,
            "serial": self.serial,
            "bootId": self.boot_id,
            "sampleId": self.sample_id,
            "observerSessionId": self.observer_session_id,
            "runNonce": self.run_nonce,
            "phase": self.phase,
            "ordinal": self.ordinal,
            "issuedNs": str(self.issued_ns),
            "deadlineNs": str(self.deadline_ns),
            "planSha256": self.plan_sha256,
            "backendSha256": self.backend_sha256,
            "clockAuthoritySha256": self.clock_authority_sha256,
            "monotonicDomainSha256": self.monotonic_domain_sha256,
            "manifestSha256": self.manifest_sha256,
            "foreignSha256": self.foreign_sha256,
            "placementSha256": self.placement_sha256,
            "taskAuthoritySha256": self.task_authority_sha256,
            "taskStableAuthoritySha256": self.task_stable_authority_sha256,
            "filesAuthoritySha256": self.files_authority_sha256,
            "observationOnly": True,
            "inputCallsAuthorized": 0,
            "writerCallsAuthorized": 0,
            "penOperationsAuthorized": 0,
            "penLeaseAcquisitionsAuthorized": 0,
            "penLeaseTouchesAuthorized": 0,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical(self.wire())

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class NoPenCaptureScope:
    request: NoPenCaptureRequest
    manifest_raw: bytes


@dataclass(frozen=True)
class NoPenBackendTransportResult:
    wire: bytes
    started_ns: int
    captured_ns: int
    finished_ns: int
    stderr: bytes
    exit_code: int
    eof: bool
    input_events_generated: int
    writer_calls: int
    pen_operations: int
    pen_lease_acquisitions: int
    pen_lease_touches: int
    quiescent_before_return: bool


class FixedNoPenSemanticBackend(Protocol):
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def identity(self) -> NoPenBackendIdentity: ...
    def capture_no_pen(self, request: NoPenCaptureRequest,
                       scope: NoPenCaptureScope,
                       deadline_ns: int) -> NoPenBackendTransportResult: ...
    def assert_quiescent(self, deadline_ns: int) -> None: ...


class RetainedNoPenMonotonicClock(Protocol):
    """Exact retained provider shared with ``HostAuthority``.

    ``monotonic_domain_identity`` is canonical opaque evidence, not a caller
    boolean claiming that two clocks share a domain.  Production bootstrap
    must obtain this object from the same retained provider instance used by
    ``HostAuthority`` and pin both byte identities in the immutable plan.
    """

    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def monotonic_domain_identity(self) -> bytes: ...
    def now_ns(self) -> int: ...


def observer_admission(plan: NoPenSemanticPlan,
                       backend: NoPenBackendIdentity) -> dict[str, Any]:
    plan.validate()
    backend.validate(plan)
    return {
        "authority": OBSERVER_ADMISSION_AUTHORITY,
        "schemaVersion": 1,
        "observerSha256": graph.EXPECTED_OBSERVER_SHA256,
        "module": copy.deepcopy(plan.wire()["module"]),
        "backendSha256": backend.sha256,
        "toolBundleSha256": backend.tool_bundle_sha256,
        "clockAuthoritySha256": plan.clock_authority_sha256,
        "monotonicDomainSha256": plan.monotonic_domain_sha256,
        "observationOnly": True,
        "singleGraphWalk": True,
        "externalTaskLivenessRequired": True,
        "exactDetachAndQuiescence": True,
        "inputCalls": 0,
        "writerCalls": 0,
        "penOperations": 0,
        "penLeaseAcquisitions": 0,
        "penLeaseTouches": 0,
        "retryAllowed": False,
    }


def encode_no_pen_wire(manifest: bytes, before: bytes, snapshot: bytes,
                       after: bytes, transcript: bytes, receipt: bytes) -> bytes:
    """Test/backend helper for the one exact ordered aggregate wire."""
    payloads = (manifest, before, snapshot, after, transcript, receipt)
    output = bytearray(WIRE_MAGIC)
    for (tag, _label, maximum), payload in zip(WIRE_MEMBERS, payloads):
        _need(type(payload) is bytes and 0 < len(payload) <= maximum,
              "wire member is absent or oversized")
        output.extend(WIRE_HEADER.pack(tag, len(payload),
                                       hashlib.sha256(payload).digest()))
        output.extend(payload)
    _need(len(output) + 33 <= MAX_WIRE_BYTES, "semantic wire is oversized")
    aggregate = hashlib.sha256(output).digest()
    output.append(WIRE_TERMINAL_TAG)
    output.extend(aggregate)
    return bytes(output)


def decode_no_pen_wire(raw: bytes) -> tuple[bytes, bytes, bytes, bytes,
                                             bytes, bytes]:
    _need(type(raw) is bytes and
          len(WIRE_MAGIC) + 33 < len(raw) <= MAX_WIRE_BYTES,
          "semantic wire is absent or oversized")
    _need(raw.startswith(WIRE_MAGIC), "semantic wire magic differs")
    offset = len(WIRE_MAGIC)
    members: list[bytes] = []
    for expected_tag, label, maximum in WIRE_MEMBERS:
        _need(len(raw) - offset >= WIRE_HEADER.size,
              label + " wire header is truncated")
        tag, size, digest = WIRE_HEADER.unpack_from(raw, offset)
        _need(tag == expected_tag,
              label + " member is absent, duplicated, or reordered")
        offset += WIRE_HEADER.size
        _need(0 < size <= maximum, label + " member is empty or oversized")
        _need(size <= len(raw) - offset, label + " member is truncated")
        payload = raw[offset:offset + size]
        _need(hashlib.sha256(payload).digest() == digest,
              label + " member digest differs")
        members.append(payload)
        offset += size
    _need(len(raw) - offset == 33 and raw[offset] == WIRE_TERMINAL_TAG,
          "semantic wire terminal is missing or has trailing data")
    _need(hashlib.sha256(raw[:offset]).digest() == raw[offset + 1:],
          "semantic wire aggregate digest differs")
    return tuple(members)  # type: ignore[return-value]


class NoPenSemanticAdapter:
    """Production-shaped ``SemanticAuthority`` with no pen authority."""

    def __init__(self, plan: NoPenSemanticPlan,
                 backend: FixedNoPenSemanticBackend,
                 receipt_hmac_key: bytes, *,
                 clock: RetainedNoPenMonotonicClock):
        _need(type(plan) is NoPenSemanticPlan,
              "semantic plan wrapper differs")
        plan.validate()
        _need(type(receipt_hmac_key) is bytes and len(receipt_hmac_key) == 32,
              "semantic receipt capability differs")
        _need(clock is not None, "retained semantic clock authority is absent")
        self._plan = plan
        self._backend = backend
        self._receipt_key = bytes(receipt_hmac_key)
        self._clock_authority = clock
        self._identity_authority = _RetainedInternalIdentityAuthority()
        self._identity_authority_canonical = (
            self._identity_authority.canonical_bytes())
        self._mutex = threading.Lock()
        self._failed: str | None = None
        self._last_clock_ns = -1
        self._samples: set[str] = set()
        self._observers: set[str] = set()
        self._nonces: set[str] = set()
        self._capture_ids: set[str] = set()
        self._receipt_ids: set[str] = set()
        self._receipt_digests: set[str] = set()
        self._plan_canonical = plan.canonical_bytes()
        (self._clock_canonical,
         self._monotonic_domain_canonical) = self._read_clock_authority()
        _need(_sha(self._clock_canonical) == plan.clock_authority_sha256 and
              _sha(self._monotonic_domain_canonical) ==
              plan.monotonic_domain_sha256,
              "retained semantic clock differs from HostAuthority plan")
        self._backend_canonical = self._backend.canonical_bytes()
        _need(type(self._backend_canonical) is bytes and
              self._backend_canonical,
              "semantic backend canonical authority is absent")
        self._backend_identity = self._backend.identity()
        _need(type(self._backend_identity) is NoPenBackendIdentity,
              "semantic backend identity wrapper differs")
        self._backend_identity.validate(plan)
        _need(self._backend_identity.sha256 ==
              _sha(self._backend_canonical) and
              self._backend_canonical ==
              self._backend_identity.canonical_bytes(),
              "semantic backend identity/canonical digest differs")
        _need(self._backend_identity.receipt_key_id ==
              hashlib.sha256(self._receipt_key).hexdigest(),
              "semantic backend receipt capability differs")
        self._observer_admission = observer_admission(
            plan, self._backend_identity)
        self._observer_admission_sha = _sha(
            _canonical(self._observer_admission))
        self._canonical = _canonical({
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "plan": plan.wire(),
            "backend": asdict(self._backend_identity),
            "backendCanonicalSha256": _sha(self._backend_canonical),
            "clockAuthority": graph.load_canonical(
                self._clock_canonical, MAX_CLOCK_AUTHORITY_BYTES).value,
            "clockAuthoritySha256": _sha(self._clock_canonical),
            "monotonicDomain": graph.load_canonical(
                self._monotonic_domain_canonical,
                MAX_CLOCK_AUTHORITY_BYTES).value,
            "monotonicDomainSha256": _sha(
                self._monotonic_domain_canonical),
            "internalIdentityAuthority": graph.load_canonical(
                self._identity_authority_canonical,
                MAX_CLOCK_AUTHORITY_BYTES).value,
            "internalIdentityAuthoritySha256": _sha(
                self._identity_authority_canonical),
            "observerAdmission": self._observer_admission,
            "wireMagicHex": WIRE_MAGIC.hex(),
            "wireMemberOrder": [name for _tag, name, _maximum in WIRE_MEMBERS],
            "wireMemberMaximumBytes": {
                name: maximum for _tag, name, maximum in WIRE_MEMBERS
            },
            "wireMaximumBytes": MAX_WIRE_BYTES,
            "observationOnly": True,
            "inputCalls": 0,
            "writerCalls": 0,
            "penOperations": 0,
            "penLeaseAcquisitions": 0,
            "penLeaseTouches": 0,
            "hardwareAdmitted": False,
        })
        self._clock()
        self._verify_backend_locked()

    def _poison(self, message: str) -> None:
        if self._failed is None:
            self._failed = message

    def _enter(self) -> None:
        if not self._mutex.acquire(blocking=False):
            self._poison("semantic adapter concurrent or reentrant use")
            raise NoPenSemanticUncertain(
                "semantic adapter concurrent or reentrant use")

    def _read_clock_authority(self) -> tuple[bytes, bytes]:
        try:
            result = self._clock_authority.verify()
            _need(result is None,
                  "retained semantic clock verification returned data")
            canonical = self._clock_authority.canonical_bytes()
            domain = self._clock_authority.monotonic_domain_identity()
            _need(type(canonical) is bytes and type(domain) is bytes and
                  canonical != domain,
                  "retained semantic clock identities differ")
            clock_loaded = _loaded(
                canonical, MAX_CLOCK_AUTHORITY_BYTES,
                "retained semantic clock authority")
            domain_loaded = _loaded(
                domain, MAX_CLOCK_AUTHORITY_BYTES,
                "retained semantic monotonic domain")
            clock_item = _exact(clock_loaded.value, {
                "authority", "schemaVersion", "kind",
                "providerInstanceId", "providerImageSha256",
            }, "retained semantic clock authority")
            domain_item = _exact(domain_loaded.value, {
                "authority", "schemaVersion", "kind", "domainId",
                "providerInstanceId", "unit",
            }, "retained semantic monotonic domain")
            _need(clock_item["authority"] == MONOTONIC_CLOCK_AUTHORITY and
                  type(clock_item["schemaVersion"]) is int and
                  clock_item["schemaVersion"] == 1 and
                  clock_item["kind"] == "retained-provider-authority" and
                  domain_item["authority"] == MONOTONIC_CLOCK_AUTHORITY and
                  type(domain_item["schemaVersion"]) is int and
                  domain_item["schemaVersion"] == 1 and
                  domain_item["kind"] == "monotonic-domain-identity" and
                  domain_item["unit"] == "nanoseconds" and
                  domain_item["providerInstanceId"] ==
                  clock_item["providerInstanceId"],
                  "retained semantic clock authority namespace differs")
            for value, label in (
                    (clock_item["providerInstanceId"],
                     "retained clock provider instance"),
                    (clock_item["providerImageSha256"],
                     "retained clock provider image"),
                    (domain_item["domainId"],
                     "retained monotonic domain")):
                _hex(value, label)
            return clock_loaded.raw, domain_loaded.raw
        except BaseException as error:
            if isinstance(error, NoPenSemanticError):
                raise
            raise NoPenSemanticUncertain(
                "retained semantic clock verification failed") from error

    def _verify_clock_locked(self) -> None:
        canonical, domain = self._read_clock_authority()
        _need(canonical == self._clock_canonical and
              domain == self._monotonic_domain_canonical and
              _sha(canonical) == self._plan.clock_authority_sha256 and
              _sha(domain) == self._plan.monotonic_domain_sha256,
              "retained semantic clock authority drifted")

    def _clock(self) -> int:
        try:
            self._verify_clock_locked()
            value = self._clock_authority.now_ns()
            self._verify_clock_locked()
        except BaseException as error:
            self._poison("semantic monotonic clock failed")
            raise NoPenSemanticUncertain(
                "semantic monotonic clock failed") from error
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            self._poison("semantic monotonic clock is invalid")
            raise NoPenSemanticUncertain(
                "semantic monotonic clock is invalid")
        if value < self._last_clock_ns:
            self._poison("semantic monotonic clock regressed")
            raise NoPenSemanticUncertain("semantic monotonic clock regressed")
        self._last_clock_ns = value
        return value

    def _verify_backend_locked(self) -> None:
        _need(self._failed is None, "semantic adapter is sealed")
        _need(self._plan.canonical_bytes() == self._plan_canonical,
              "semantic plan authority drifted")
        self._verify_clock_locked()
        _need(self._identity_authority.canonical_bytes() ==
              self._identity_authority_canonical,
              "internal identity randomness authority drifted")
        self._backend.verify()
        identity = self._backend.identity()
        canonical = self._backend.canonical_bytes()
        _need(type(identity) is NoPenBackendIdentity,
              "semantic backend retained identity wrapper differs")
        identity.validate(self._plan)
        _need(type(canonical) is bytes and canonical and
              identity == self._backend_identity and
              canonical == self._backend_canonical and
              canonical == identity.canonical_bytes() and
              identity.sha256 == _sha(canonical),
              "semantic backend retained identity drifted")

    def verify(self) -> None:
        self._enter()
        try:
            try:
                self._verify_backend_locked()
            except BaseException as error:
                self._poison("semantic backend verification failed")
                if isinstance(error, NoPenSemanticError):
                    raise
                raise NoPenSemanticUncertain(
                    "semantic backend verification failed") from error
        finally:
            self._mutex.release()

    def monotonic_domain_identity(self) -> str:
        """Return the retained HostAuthority-compatible clock-domain digest."""
        self._enter()
        try:
            try:
                _need(self._failed is None, "semantic adapter is sealed")
                self._verify_clock_locked()
                return self._plan.monotonic_domain_sha256
            except BaseException as error:
                self._poison("semantic monotonic domain verification failed")
                if isinstance(error, NoPenSemanticError):
                    raise
                raise NoPenSemanticUncertain(
                    "semantic monotonic domain verification failed") from error
        finally:
            self._mutex.release()

    def canonical_bytes(self) -> bytes:
        self.verify()
        return self._canonical

    def _validate_inputs(self, phase: harness.Phase, ordinal: int,
                         foreign: host.ForeignIdentity,
                         applied: host.AppliedPlacement,
                         task: android.DocumentTaskAuthority,
                         files_authority: dict[str, Any],
                         deadline_ns: int) -> tuple[dict[str, Any], str, str]:
        _need(type(phase) is harness.Phase and any(
                  _wire_equal(phase.wire(), expected.wire())
                  for expected in self._plan_phases()),
              "semantic phase differs from the closed harness plan")
        _integer(ordinal, "semantic ordinal", 1, 2)
        _need(type(foreign) is host.ForeignIdentity,
              "semantic foreign identity wrapper differs")
        _need(type(foreign.process) is host.ProcessIdentity and
              type(foreign.process.pid) is int and foreign.process.pid > 0 and
              type(foreign.process.start_ticks) is int and
              foreign.process.start_ticks > 0 and
              type(foreign.process.uid) is int and
              foreign.process.uid == graph.ANDROID_SYSTEM_UID and
              foreign.process.package == graph.PACKAGE_NAME and
              foreign.component == host.FOREIGN_COMPONENT and
              type(foreign.task_id) is int and foreign.task_id >= 0 and
              type(foreign.activity_token) is str and
              _ANDROID_TOKEN.fullmatch(foreign.activity_token) is not None,
              "semantic foreign identity differs")
        _need(type(task) is android.DocumentTaskAuthority,
              "semantic task authority wrapper differs")
        # ``stable_authority`` validates every dataclass field's exact scalar
        # type before the adapter relies on the detached semantic digest.
        try:
            android.stable_authority(task, task)
            task_stable_sha = android.stable_authority_sha256(task)
        except android.AndroidAuthorityError as error:
            raise NoPenSemanticError(
                "semantic task authority scalar domain differs") from error
        _hex(task.raw_sha256, "semantic task raw capture")
        for token_value, token_label in (
                (task.task_token, "semantic task token"),
                (task.activity_token, "semantic activity token")):
            _need(_ANDROID_TOKEN.fullmatch(token_value) is not None,
                  token_label + " differs")
        exact_live = (
            task.state == "RESUMED", task.resumed, not task.stopped,
            not task.delayed_resume, not task.finishing, task.task_visible,
            task.visible_requested, task.visible, task.client_visible,
            task.reported_drawn, task.reported_visible, task.now_visible,
        )
        _need(all(exact_live) and
              task.authority == graph.ANDROID_TASK_AUTHORITY and
              task.display_id == applied.display_id and
              task.stack_id == task.task_id == foreign.task_id and
              task.activity_token == foreign.activity_token and
              task.pid == foreign.process.pid and
              task.uid == foreign.process.uid and
              task.package_name == graph.PACKAGE_NAME and
              task.process_name == graph.PACKAGE_NAME and
              task.component in (graph.DOCUMENT_ACTIVITY_SHORT_COMPONENT,
                                 graph.DOCUMENT_ACTIVITY_FULL_COMPONENT) and
              task.base_apk_path.startswith("/") and
              task.width == graph.VIRTUAL_DISPLAY_WIDTH and
              task.height == graph.VIRTUAL_DISPLAY_HEIGHT and
              task.density_dpi == graph.VIRTUAL_DISPLAY_DENSITY_DPI and
              task.rotation == graph.VIRTUAL_DISPLAY_ROTATION and
              foreign.evidence_sha256 == task_stable_sha,
              "semantic task/foreign authority differs")
        _need(type(applied) is host.AppliedPlacement and
              applied.session == self._plan.session_id and
              type(applied.generation) is int and applied.generation > 0 and
              type(applied.display_id) is int and 1 <= applied.display_id <= 1024 and
              type(applied.sequence) is int and applied.sequence > 0 and
              applied.requested is phase.placement and
              applied.effective is phase.placement and
              applied.rect == phase.rect,
              "semantic host placement authority differs")
        _need(type(deadline_ns) is int and 0 < deadline_ns <= 2**63 - 1,
              "semantic caller deadline differs")
        try:
            files = graph.load_canonical(
                graph.canonical_bytes(files_authority,
                                      graph.MAX_AUTHORITY_BYTES),
                graph.MAX_AUTHORITY_BYTES).value
        except graph.GraphRunnerError as error:
            raise NoPenSemanticError(
                "semantic file authority is not canonical graph-v2 JSON") from error
        _need(type(files) is dict,
              "semantic file authority wrapper differs")
        return files, _sha(task.canonical_bytes()), task_stable_sha

    @staticmethod
    def _plan_phases() -> tuple[harness.Phase, ...]:
        return harness.BASE_PHASES + harness.ROTATION_PHASES

    def _build_manifest(self, phase: harness.Phase,
                        foreign: host.ForeignIdentity,
                        applied: host.AppliedPlacement,
                        task: android.DocumentTaskAuthority,
                        files: dict[str, Any],
                        observer_session_id: str,
                        operation_deadline_ns: int,
                        deadline_ms: int) -> graph.LoadedJson:
        value = {
            "schemaVersion": 2,
            "authority": graph.MANIFEST_AUTHORITY,
            "attachment": {
                "packageName": graph.PACKAGE_NAME,
                "processName": graph.OBSERVER_PROCESS_LABEL,
                "pid": foreign.process.pid,
                "startTimeTicks": str(foreign.process.start_ticks),
                "firmwareFingerprint": graph.FIRMWARE_FINGERPRINT,
                "apk": {
                    "path": task.base_apk_path,
                    "size": graph.APK_SIZE,
                    "sha256": graph.APK_SHA256,
                },
                "framework": {
                    "path": self._plan.framework_path,
                    "size": graph.FRAMEWORK_SIZE,
                    "sha256": graph.FRAMEWORK_SHA256,
                },
                "module": {
                    "name": self._plan.module_name,
                    "path": self._plan.module_path,
                    "size": self._plan.module_size,
                    "sha256": self._plan.module_sha256,
                },
                "observerSha256": graph.EXPECTED_OBSERVER_SHA256,
            },
            "externalSession": {
                "authority": graph.EXTERNAL_SESSION_AUTHORITY,
                "authorizedSerial": self._plan.serial,
                "taskId": foreign.task_id,
                "displayId": applied.display_id,
                "hostSessionId": self._plan.session_id,
                "displayGeneration": applied.generation,
            },
            "files": copy.deepcopy(files),
            "coordinator": {
                "authority": graph.COORDINATOR_AUTHORITY,
                "observerSessionId": observer_session_id,
                "absoluteMonotonicDeadlineNs": str(operation_deadline_ns),
                "hardDeadlineMs": deadline_ms,
                "maxJavaChooseWalks": 1,
                "retainedRootSamples": 2,
                "detachOnDeadline": True,
                "abortOnAnyError": True,
                "verifyTargetLivenessAfter": True,
                "noRetry": True,
            },
            "expected": {
                "documentUri": self._plan.fixture_uri,
                "calibrationProfile": {
                    "authority": graph.CALIBRATION_AUTHORITY,
                    "status": "calibration-only",
                    "pageIndexSemantics": "independent-raw",
                    "matrixSemantics": "independent-raw",
                },
            },
        }
        loaded = _loaded(_canonical(value, graph.MAX_MANIFEST_BYTES),
                         graph.MAX_MANIFEST_BYTES, "semantic manifest")
        binding = graph.StageBinding(
            self._plan.serial, foreign.process.pid,
            str(foreign.process.start_ticks), observer_session_id,
            deadline_ms, operation_deadline_ns, phase.placement.value)
        try:
            graph.validate_manifest(
                loaded, binding, graph.EXPECTED_OBSERVER_SHA256)
        except graph.GraphRunnerError as error:
            raise NoPenSemanticError(
                "semantic manifest failed graph-v2 validation") from error
        original = loaded.value["files"]["originalPdf"]
        _need(original["documentUri"] == self._plan.fixture_uri and
              original["sha256"] == self._plan.fixture_sha256,
              "semantic file authority differs from immutable fixture plan")
        return loaded

    def _expected_host(self, phase: harness.Phase,
                       applied: host.AppliedPlacement) -> dict[str, Any]:
        return {
            "authority": graph.HOST_AUTHORITY,
            "hostSessionId": self._plan.session_id,
            "stage": phase.placement.value,
            "displayId": applied.display_id,
            "defaultDisplayId": 0,
            "displayGeneration": applied.generation,
            "placementRequestGeneration": applied.sequence,
            "placementReadyGeneration": applied.sequence,
            "hostPackageName": host.HOST_PACKAGE,
            "hostApkSha256": host.APK_SHA256,
            "hostTaskId": self._plan.host_task_id,
            "hostActivityToken": self._plan.host_activity_token,
            "displaySize": [graph.VIRTUAL_DISPLAY_WIDTH,
                            graph.VIRTUAL_DISPLAY_HEIGHT],
            "densityDpi": graph.VIRTUAL_DISPLAY_DENSITY_DPI,
            "requestedFrame": phase.rect.wire(),
            "measuredGlobalFrame": phase.rect.wire(),
            "applied": True,
            "activityResumed": True,
            "activityVisible": True,
            "activityFocused": True,
            "surfaceAttached": True,
            "surfaceValid": True,
        }

    def _expected_target(self, foreign: host.ForeignIdentity,
                         applied: host.AppliedPlacement) -> dict[str, Any]:
        return {
            "packageName": graph.PACKAGE_NAME,
            "processName": graph.PACKAGE_NAME,
            "component": foreign.component,
            "pid": foreign.process.pid,
            "uid": foreign.process.uid,
            "startTimeTicks": str(foreign.process.start_ticks),
            "taskId": foreign.task_id,
            "activityToken": foreign.activity_token,
            "displayId": applied.display_id,
            "alive": True,
            "resumed": True,
            "visible": True,
        }

    @staticmethod
    def _zero_observation() -> dict[str, Any]:
        return {
            "readOnly": True,
            "inputEventsGenerated": 0,
            "writerCalls": 0,
            "penOperations": 0,
            "penLeaseAcquisitions": 0,
            "penLeaseTouches": 0,
        }

    def _validate_external(self, value: dict[str, Any], *, phase_name: str,
                           request: NoPenCaptureRequest,
                           manifest: graph.LoadedJson,
                           foreign: host.ForeignIdentity,
                           applied: host.AppliedPlacement,
                           phase: harness.Phase,
                           task_sha: str, task_stable_sha: str,
                           captured_min: int, captured_max: int) -> tuple[str, int]:
        item = _exact(value, {
            "authority", "schemaVersion", "phase", "captureId",
            "sampleId", "observerSessionId", "runNonce", "requestSha256",
            "manifestSha256", "backendSha256", "clockAuthoritySha256",
            "monotonicDomainSha256", "serial", "capturedNs",
            "taskAuthoritySha256", "taskStableAuthoritySha256", "target",
            "files", "host", "observation",
        }, "semantic external " + phase_name)
        _need(item["authority"] == EXTERNAL_AUTHORITY and
              item["schemaVersion"] == 1 and item["phase"] == phase_name and
              item["sampleId"] == request.sample_id and
              item["observerSessionId"] == request.observer_session_id and
              item["runNonce"] == request.run_nonce and
              item["requestSha256"] == request.sha256 and
              item["manifestSha256"] == manifest.sha256 and
              item["backendSha256"] == self._backend_identity.sha256 and
              item["clockAuthoritySha256"] ==
              self._plan.clock_authority_sha256 and
              item["monotonicDomainSha256"] ==
              self._plan.monotonic_domain_sha256 and
              item["serial"] == self._plan.serial and
              item["taskAuthoritySha256"] == task_sha and
              item["taskStableAuthoritySha256"] == task_stable_sha and
              _wire_equal(item["target"],
                          self._expected_target(foreign, applied)) and
              _wire_equal(item["files"], manifest.value["files"]) and
              _wire_equal(item["host"],
                          self._expected_host(phase, applied)) and
              _wire_equal(item["observation"], self._zero_observation()),
              "semantic external authority binding differs")
        _need(type(item["schemaVersion"]) is int and
              all(type(item[name]) is str for name in (
                  "authority", "phase", "captureId", "sampleId",
                  "observerSessionId", "runNonce", "requestSha256",
                  "manifestSha256", "backendSha256",
                  "clockAuthoritySha256", "monotonicDomainSha256", "serial",
                  "capturedNs", "taskAuthoritySha256",
                  "taskStableAuthoritySha256")),
              "semantic external scalar types differ")
        capture_id = _canonical_uuid(item["captureId"],
                                     "semantic external capture ID")
        _need(type(item["capturedNs"]) is str and
              len(item["capturedNs"]) <= 19 and
              re.fullmatch(r"0|[1-9][0-9]*", item["capturedNs"]) is not None,
              "semantic external capture time differs")
        captured = int(item["capturedNs"])
        _need(captured <= 2**63 - 1 and
              captured_min <= captured <= captured_max,
              "semantic external capture escaped transport bracket")
        return capture_id, captured

    def _validate_transcript(self, value: dict[str, Any],
                             request: NoPenCaptureRequest) -> None:
        item = _exact(value, {
            "authority", "schemaVersion", "sampleId", "observerSessionId",
            "runNonce", "requestSha256", "operation", "observationOnly",
            "complete", "readOnly", "inputEventsGenerated", "writerCalls",
            "penOperations", "penLeaseAcquisitions", "penLeaseTouches",
        }, "semantic transcript")
        expected = {
            "authority": TRANSCRIPT_AUTHORITY,
            "schemaVersion": 1,
            "sampleId": request.sample_id,
            "observerSessionId": request.observer_session_id,
            "runNonce": request.run_nonce,
            "requestSha256": request.sha256,
            "operation": "capture-native-page-graph-v2-without-pen",
            "observationOnly": True,
            "complete": True,
            "readOnly": True,
            "inputEventsGenerated": 0,
            "writerCalls": 0,
            "penOperations": 0,
            "penLeaseAcquisitions": 0,
            "penLeaseTouches": 0,
        }
        _need(_wire_equal(item, expected),
              "semantic transcript authority differs")

    def _validate_stage_receipt(self, value: dict[str, Any], *, sequence: int,
                                phase_name: str, previous: str | None,
                                record_sha: str,
                                request: NoPenCaptureRequest) -> str:
        item = _exact(value, {
            "authority", "schemaVersion", "receiptId", "sequence", "phase",
            "previousReceiptSha256", "recordSha256", "requestSha256",
            "sampleId", "observerSessionId", "runNonce", "backendSha256",
            "receiptKeyId", "authenticator",
        }, "semantic stage receipt")
        body = dict(item)
        authenticator = body.pop("authenticator")
        expected_mac = hmac.new(
            self._receipt_key, _canonical(body), hashlib.sha256).hexdigest()
        _need(type(authenticator) is str and
              hmac.compare_digest(authenticator, expected_mac),
              "semantic stage receipt authenticator differs")
        _need(item["authority"] == STAGE_RECEIPT_AUTHORITY and
              item["schemaVersion"] == 1 and item["sequence"] == sequence and
              item["phase"] == phase_name and
              item["previousReceiptSha256"] == previous and
              item["recordSha256"] == record_sha and
              item["requestSha256"] == request.sha256 and
              item["sampleId"] == request.sample_id and
              item["observerSessionId"] == request.observer_session_id and
              item["runNonce"] == request.run_nonce and
              item["backendSha256"] == self._backend_identity.sha256 and
              item["receiptKeyId"] == self._backend_identity.receipt_key_id,
              "semantic stage receipt binding differs")
        _need(type(item["schemaVersion"]) is int and
              type(item["sequence"]) is int and
              all(type(item[name]) is str for name in (
                  "authority", "receiptId", "phase", "recordSha256",
                  "requestSha256", "sampleId", "observerSessionId",
                  "runNonce", "backendSha256", "receiptKeyId",
                  "authenticator")) and
              (item["previousReceiptSha256"] is None or
               type(item["previousReceiptSha256"]) is str),
              "semantic stage receipt scalar types differ")
        receipt_id = _canonical_uuid(item["receiptId"],
                                     "semantic stage receipt ID")
        _hex(record_sha, "semantic stage record")
        if previous is not None:
            _hex(previous, "semantic previous stage receipt")
        raw = _canonical(item)
        digest = _sha(raw)
        _need(receipt_id not in self._receipt_ids and
              digest not in self._receipt_digests,
              "semantic stage receipt identity was reused")
        return digest

    def _validate_receipt(self, value: dict[str, Any], *,
                          request: NoPenCaptureRequest,
                          members: tuple[bytes, bytes, bytes, bytes, bytes],
                          transport: NoPenBackendTransportResult) -> tuple[str, str]:
        item = _exact(value, {
            "authority", "schemaVersion", "requestSha256", "backendSha256",
            "observerAdmissionSha256", "sampleId", "observerSessionId",
            "runNonce", "phase", "ordinal", "manifestSha256",
            "beforeSha256", "snapshotSha256", "afterSha256",
            "transcriptSha256", "startedNs", "capturedNs", "finishedNs",
            "beforeReceipt", "afterReceipt", "observationOnly", "complete",
            "readOnly", "inputEventsGenerated", "writerCalls",
            "penOperations", "penLeaseAcquisitions", "penLeaseTouches",
            "quiescentBeforeReturn", "authenticator",
        }, "semantic receipt")
        body = dict(item)
        authenticator = body.pop("authenticator")
        expected_mac = hmac.new(
            self._receipt_key, _canonical(body), hashlib.sha256).hexdigest()
        _need(type(authenticator) is str and
              hmac.compare_digest(authenticator, expected_mac),
              "semantic receipt authenticator differs")
        manifest_raw, before_raw, snapshot_raw, after_raw, transcript_raw = members
        _need(type(item["schemaVersion"]) is int and
              type(item["ordinal"]) is int and
              all(type(item[name]) is str for name in (
                  "authority", "requestSha256", "backendSha256",
                  "observerAdmissionSha256", "sampleId",
                  "observerSessionId", "runNonce", "phase",
                  "manifestSha256", "beforeSha256", "snapshotSha256",
                  "afterSha256", "transcriptSha256", "startedNs",
                  "capturedNs", "finishedNs", "authenticator")) and
              all(type(item[name]) is bool for name in (
                  "observationOnly", "complete", "readOnly",
                  "quiescentBeforeReturn")) and
              all(type(item[name]) is int for name in (
                  "inputEventsGenerated", "writerCalls", "penOperations",
                  "penLeaseAcquisitions", "penLeaseTouches")),
              "semantic receipt scalar types differ")
        _need(type(item["beforeReceipt"]) is dict and
              type(item["afterReceipt"]) is dict and
              item["beforeReceipt"].get("receiptId") !=
              item["afterReceipt"].get("receiptId"),
              "semantic stage receipt identities are not distinct")
        _need(item["authority"] == RECEIPT_AUTHORITY and
              item["schemaVersion"] == 1 and
              item["requestSha256"] == request.sha256 and
              item["backendSha256"] == self._backend_identity.sha256 and
              item["observerAdmissionSha256"] == self._observer_admission_sha and
              item["sampleId"] == request.sample_id and
              item["observerSessionId"] == request.observer_session_id and
              item["runNonce"] == request.run_nonce and
              item["phase"] == request.phase and
              item["ordinal"] == request.ordinal and
              item["manifestSha256"] == _sha(manifest_raw) and
              item["beforeSha256"] == _sha(before_raw) and
              item["snapshotSha256"] == _sha(snapshot_raw) and
              item["afterSha256"] == _sha(after_raw) and
              item["transcriptSha256"] == _sha(transcript_raw) and
              item["startedNs"] == str(transport.started_ns) and
              item["capturedNs"] == str(transport.captured_ns) and
              item["finishedNs"] == str(transport.finished_ns) and
              item["observationOnly"] is True and item["complete"] is True and
              item["readOnly"] is True and
              item["inputEventsGenerated"] == 0 and
              item["writerCalls"] == 0 and item["penOperations"] == 0 and
              item["penLeaseAcquisitions"] == 0 and
              item["penLeaseTouches"] == 0 and
              item["quiescentBeforeReturn"] is True,
              "semantic receipt binding differs")
        before_digest = self._validate_stage_receipt(
            item["beforeReceipt"], sequence=1, phase_name="before",
            previous=None, record_sha=_sha(before_raw), request=request)
        after_digest = self._validate_stage_receipt(
            item["afterReceipt"], sequence=2, phase_name="after",
            previous=before_digest, record_sha=_sha(after_raw), request=request)
        return before_digest, after_digest

    def capture(self, phase: harness.Phase, ordinal: int,
                foreign: host.ForeignIdentity,
                applied: host.AppliedPlacement,
                task: android.DocumentTaskAuthority,
                files_authority: dict[str, Any],
                deadline_ns: int) -> harness.SemanticCapture:
        self._enter()
        dispatched = False
        backend_touched = False
        try:
            try:
                self._verify_backend_locked()
            except BaseException as error:
                self._poison("semantic backend verification failed")
                if isinstance(error, NoPenSemanticError):
                    raise
                raise NoPenSemanticUncertain(
                    "semantic backend verification failed") from error
            files, task_sha, task_stable_sha = self._validate_inputs(
                phase, ordinal, foreign, applied, task, files_authority,
                deadline_ns)
            issued = self._clock()
            remaining_ms = min(
                self._plan.capture_budget_ms,
                (deadline_ns - issued) // 1_000_000,
            )
            _need(remaining_ms >= MIN_CAPTURE_BUDGET_MS,
                  "semantic capture deadline is expired or too short")
            operation_deadline = issued + remaining_ms * 1_000_000
            try:
                sample_id = _token(
                    "semantic-sample:" +
                    self._identity_authority.fresh_hex(),
                    "semantic sample ID")
                observer_id = _token(
                    "no-pen-observer:" +
                    self._identity_authority.fresh_hex(),
                    "semantic observer session")
                nonce = _hex(self._identity_authority.fresh_hex(),
                             "semantic run nonce")
            except BaseException as error:
                self._poison("semantic internal identity authority failed")
                if isinstance(error, NoPenSemanticError):
                    raise
                raise NoPenSemanticUncertain(
                    "semantic internal identity authority failed") from error
            _need(sample_id not in self._samples and
                  observer_id not in self._observers and
                  nonce not in self._nonces and
                  len(self._samples) < MAX_CAPTURE_IDENTITIES and
                  len(self._capture_ids) <= MAX_CAPTURE_IDENTITIES * 2 - 2 and
                  len(self._receipt_ids) <= MAX_CAPTURE_IDENTITIES * 2 - 2,
                  "semantic independent identity was reused")
            manifest = self._build_manifest(
                phase, foreign, applied, task, files, observer_id,
                operation_deadline, remaining_ms)
            foreign_sha = _sha(_canonical(foreign.wire()))
            placement_sha = _sha(_canonical({
                "session": applied.session,
                "generation": applied.generation,
                "displayId": applied.display_id,
                "sequence": applied.sequence,
                "requested": applied.requested.value,
                "effective": applied.effective.value,
                "rect": applied.rect.wire(),
            }))
            request = NoPenCaptureRequest(
                REQUEST_AUTHORITY, self._plan.session_id, self._plan.serial,
                self._backend_identity.boot_id, sample_id, observer_id, nonce,
                phase.placement.value, ordinal, issued, operation_deadline,
                self._plan.sha256, self._backend_identity.sha256,
                self._plan.clock_authority_sha256,
                self._plan.monotonic_domain_sha256,
                manifest.sha256, foreign_sha, placement_sha, task_sha,
                task_stable_sha, _sha(graph.canonical_bytes(files)),
            )
            # The quiescence barrier is established before any new fixed
            # capture can be dispatched.
            backend_touched = True
            self._backend.assert_quiescent(operation_deadline)
            after_pre_capture_quiescence = self._clock()
            _need(after_pre_capture_quiescence < operation_deadline,
                  "semantic pre-capture quiescence missed its deadline")
            self._verify_backend_locked()
            before_call = self._clock()
            _need(after_pre_capture_quiescence <= before_call <
                  operation_deadline,
                  "semantic dispatch missed its post-quiescence deadline")
            dispatched = True
            transport = self._backend.capture_no_pen(
                request, NoPenCaptureScope(request, manifest.raw),
                operation_deadline)
            after_call = self._clock()
            _need(type(transport) is NoPenBackendTransportResult,
                  "semantic backend transport wrapper differs")
            _need(type(transport.wire) is bytes and transport.wire and
                  type(transport.stderr) is bytes and transport.stderr == b"" and
                  type(transport.exit_code) is int and transport.exit_code == 0 and
                  type(transport.eof) is bool and
                  transport.eof is True and
                  type(transport.started_ns) is int and
                  type(transport.captured_ns) is int and
                  type(transport.finished_ns) is int and
                  before_call < after_call and
                  before_call <= transport.started_ns <=
                  transport.captured_ns <= transport.finished_ns <=
                  after_call < operation_deadline and
                  all(type(value) is int for value in (
                      transport.input_events_generated,
                      transport.writer_calls, transport.pen_operations,
                      transport.pen_lease_acquisitions,
                      transport.pen_lease_touches)) and
                  transport.input_events_generated == 0 and
                  transport.writer_calls == 0 and
                  transport.pen_operations == 0 and
                  transport.pen_lease_acquisitions == 0 and
                  transport.pen_lease_touches == 0 and
                  type(transport.quiescent_before_return) is bool and
                  transport.quiescent_before_return is True,
                  "semantic backend result is incomplete, late, or not no-pen")
            self._backend.assert_quiescent(operation_deadline)
            _need(self._clock() < operation_deadline,
                  "semantic post-capture quiescence missed its deadline")
            self._verify_backend_locked()
            (manifest_raw, before_raw, snapshot_raw, after_raw,
             transcript_raw, receipt_raw) = decode_no_pen_wire(transport.wire)
            _need(manifest_raw == manifest.raw,
                  "semantic backend manifest differs from fixed request")
            returned_manifest = _loaded(
                manifest_raw, graph.MAX_MANIFEST_BYTES, "semantic manifest")
            binding = graph.StageBinding(
                self._plan.serial, foreign.process.pid,
                str(foreign.process.start_ticks), observer_id, remaining_ms,
                operation_deadline, phase.placement.value)
            try:
                graph.validate_manifest(
                    returned_manifest, binding,
                    graph.EXPECTED_OBSERVER_SHA256)
            except graph.GraphRunnerError as error:
                raise NoPenSemanticError(
                    "returned manifest failed graph-v2 validation") from error
            before = _loaded(before_raw, graph.MAX_AUTHORITY_BYTES,
                             "semantic before authority")
            after = _loaded(after_raw, graph.MAX_AUTHORITY_BYTES,
                            "semantic after authority")
            before_id, before_time = self._validate_external(
                before.value, phase_name="before", request=request,
                manifest=returned_manifest, foreign=foreign, applied=applied,
                phase=phase, task_sha=task_sha,
                task_stable_sha=task_stable_sha,
                captured_min=transport.started_ns,
                captured_max=transport.captured_ns)
            after_id, after_time = self._validate_external(
                after.value, phase_name="after", request=request,
                manifest=returned_manifest, foreign=foreign, applied=applied,
                phase=phase, task_sha=task_sha,
                task_stable_sha=task_stable_sha,
                captured_min=transport.captured_ns,
                captured_max=transport.finished_ns)
            _need(before_time <= transport.captured_ns <= after_time and
                  before_id != after_id and
                  before_id not in self._capture_ids and
                  after_id not in self._capture_ids,
                  "semantic before/after capture independence differs")
            stable_before = copy.deepcopy(before.value)
            stable_after = copy.deepcopy(after.value)
            for item in (stable_before, stable_after):
                item.pop("phase")
                item.pop("captureId")
                item.pop("capturedNs")
            _need(_wire_equal(stable_before, stable_after),
                  "semantic external authority drifted during capture")
            snapshot = _loaded(snapshot_raw, graph.MAX_MESSAGE_BYTES,
                               "semantic snapshot")
            try:
                validated_snapshot = graph.validate_snapshot(
                    snapshot.value, returned_manifest, before.value)
            except graph.GraphRunnerError as error:
                raise NoPenSemanticError(
                    "semantic snapshot failed graph-v2 validation") from error
            transcript = _loaded(transcript_raw, 262_144,
                                 "semantic transcript")
            self._validate_transcript(transcript.value, request)
            receipt = _loaded(receipt_raw, graph.MAX_AUTHORITY_BYTES,
                              "semantic receipt")
            before_receipt, after_receipt = self._validate_receipt(
                receipt.value, request=request,
                members=(manifest_raw, before_raw, snapshot_raw, after_raw,
                         transcript_raw), transport=transport)
            _need(receipt.sha256 not in self._receipt_digests,
                  "semantic aggregate receipt was reused")
            result = {
                "schemaVersion": 2,
                "authority": graph.RUNNER_AUTHORITY,
                "stage": phase.placement.value,
                "manifestSha256": returned_manifest.sha256,
                "observerSha256": graph.EXPECTED_OBSERVER_SHA256,
                "runNonce": nonce,
                "providerAdmissionSha256": self._backend_identity.sha256,
                "fridaAdmissionSha256": self._observer_admission_sha,
                "beforeAuthoritySha256": before.sha256,
                "afterAuthoritySha256": after.sha256,
                "beforeReceiptSha256": before_receipt,
                "afterReceiptSha256": after_receipt,
                "toolBundleSha256": self._backend_identity.tool_bundle_sha256,
                "snapshot": validated_snapshot,
            }
            graph.canonical_bytes(result, graph.MAX_MESSAGE_BYTES)
            _need(self._clock() < operation_deadline,
                  "semantic result publication missed its deadline")
            self._samples.add(sample_id)
            self._observers.add(observer_id)
            self._nonces.add(nonce)
            self._capture_ids.update((before_id, after_id))
            self._receipt_ids.update((
                receipt.value["beforeReceipt"]["receiptId"],
                receipt.value["afterReceipt"]["receiptId"],
            ))
            self._receipt_digests.update(
                (before_receipt, after_receipt, receipt.sha256))
            return harness.SemanticCapture(
                sample_id, receipt.sha256, returned_manifest,
                before.value, result, transport.wire, 0, 0, 0)
        except BaseException as error:
            if dispatched or backend_touched:
                self._poison("semantic backend operation became uncertain")
                try:
                    self._backend.assert_quiescent(deadline_ns)
                except BaseException:
                    pass
                if isinstance(error, NoPenSemanticError):
                    raise
                raise NoPenSemanticUncertain(
                    "semantic backend operation failed closed") from error
            if isinstance(error, NoPenSemanticError):
                raise
            raise NoPenSemanticError(
                "semantic local validation failed closed") from error
        finally:
            self._mutex.release()

    def assert_quiescent(self, deadline_ns: int) -> None:
        self._enter()
        try:
            now = self._clock()
            _need(type(deadline_ns) is int and now < deadline_ns,
                  "semantic quiescence deadline differs")
            try:
                self._backend.assert_quiescent(deadline_ns)
                _need(self._clock() < deadline_ns,
                      "semantic quiescence completed after its deadline")
                self._verify_backend_locked()
                _need(self._clock() < deadline_ns,
                      "semantic quiescence verification missed its deadline")
            except BaseException as error:
                self._poison("semantic backend quiescence is uncertain")
                raise NoPenSemanticUncertain(
                    "semantic backend quiescence is uncertain") from error
            if self._failed is not None:
                raise NoPenSemanticUncertain(
                    "semantic adapter remains sealed after uncertain capture")
        finally:
            self._mutex.release()


__all__ = [
    "AUTHORITY", "PLAN_AUTHORITY", "BACKEND_AUTHORITY",
    "REQUEST_AUTHORITY", "EXTERNAL_AUTHORITY", "RECEIPT_AUTHORITY",
    "STAGE_RECEIPT_AUTHORITY", "TRANSCRIPT_AUTHORITY",
    "OBSERVER_ADMISSION_AUTHORITY", "WIRE_MAGIC", "WIRE_MEMBERS",
    "MAX_WIRE_BYTES", "REAL_FIXED_BACKEND_IMPLEMENTED",
    "HARDWARE_EVIDENCE_COMPLETE", "UNRESOLVED_BLOCKERS",
    "NoPenSemanticError", "NoPenSemanticUncertain",
    "NoPenSemanticPlan", "NoPenBackendIdentity", "NoPenCaptureRequest",
    "NoPenCaptureScope", "NoPenBackendTransportResult",
    "FixedNoPenSemanticBackend", "NoPenSemanticAdapter",
    "observer_admission", "encode_no_pen_wire", "decode_no_pen_wire",
    "admission_status",
]
