"""Closed, platform-neutral worker capability IPC authority.

This module defines the authenticated protocol boundary shared by future
``frida_worker-v1`` and ``authority_worker-v1`` adapters.  It deliberately
does not open pipes, processes, files, devices, paths, modules, or command
interpreters.  A platform adapter must supply already-retained handles, a
packet transport, a monotonic clock, cryptography, and callback-drain proof.

The wire order for one operation is exact::

    request -> callback* -> barrier -> reply -> eof

Every item is independently HMAC authenticated and binds the immutable
factory/session/resource/owner/operation authority, fresh challenge, request
sequence, message ordinal, and original absolute deadline.  Payload bytes are
detached from the JSON frame but their exact length and SHA-256 digest are
authenticated by it.

The object-capability boundary assumes the admitted worker backend receives
only :class:`ChildOperation` and uses its documented public methods.  Arbitrary
same-process module-private introspection or memory modification is outside
this platform-neutral Python model and must be prevented by the real isolated
worker runtime.  Within that boundary, the public handle exposes no retained
session, key, transport, owner, resource handle, closure, or nested sink.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
import hashlib
import json
import re
import threading
import unicodedata
import weakref
from types import MappingProxyType
from typing import Any, Callable, Mapping, NoReturn, Protocol


PROTOCOL_VERSION = 1
AUTHORITY = "rtl-reader-worker-capability-ipc-v1"
BINDING_AUTHORITY = "rtl-reader-worker-capability-binding-v1"
HANDLE_AUTHORITY = "rtl-reader-preopened-handle-v1"
TRANSPORT_AUTHORITY = "rtl-reader-worker-packet-transport-v1"
CALLBACK_AUTHORITY = "rtl-reader-authenticated-callback-sink-v1"
LEASE_AUTHORITY = "rtl-reader-worker-operation-lease-v1"
OUTCOME_AUTHORITY = "rtl-reader-worker-operation-outcome-v1"
OWNER_BINDING_AUTHORITY = "rtl-reader-retained-operation-owner-v1"
SESSION_EPOCH_AUTHORITY = "rtl-reader-one-shot-session-epoch-v1"
QUIESCENCE_CHALLENGE_AUTHORITY = "rtl-reader-worker-quiescence-challenge-v1"
QUIESCENCE_RECEIPT_AUTHORITY = "rtl-reader-worker-quiescence-receipt-v1"

FRIDA_FACTORY_ID = "frida_worker-v1"
AUTHORITY_FACTORY_ID = "authority_worker-v1"
FRIDA_ROLE = "frida_worker"
AUTHORITY_ROLE = "authority_worker"

REAL_TRANSPORT_IMPLEMENTED = False
REAL_EPOCH_ADMISSION_IMPLEMENTED = False
UNRESOLVED_BLOCKERS = (
    "real retained OS packet transport and shared-generation owner/transport/drain "
    "quiescence receipts are not implemented",
    "real retained one-shot session-epoch admission and revocation are not implemented",
)

MAX_FRAME_BYTES = 1_048_576
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 16_384
MAX_STRING_CHARS = 262_144
MAX_SESSION_REQUESTS = 2**31 - 1
MAX_CALLBACKS = 256

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_FRAME_KINDS = frozenset({"request", "reply", "callback", "barrier", "terminal", "eof"})
_QUIESCENCE_COMPONENTS = frozenset({"callback_drain", "operation_owner", "transport"})
_HEADER_KEYS = frozenset({
    "authority", "binding_sha256", "body", "challenge", "deadline_ns", "factory_id",
    "kind", "message_sequence", "operation_id", "owner_object_id", "payload_bytes",
    "payload_sha256", "request_id", "role", "sequence", "session_epoch",
    "session_id", "version",
})


class CapabilityIpcError(RuntimeError):
    """An authority, framing, lifecycle, or policy invariant failed."""


class CapabilityQuiescenceError(CapabilityIpcError):
    """Revocation completed without exact quiescence proof."""


def _fail(message: str) -> NoReturn:
    raise CapabilityIpcError(message)


def _exact(value: Any, expected: type, label: str) -> None:
    if type(value) is not expected:
        _fail(label + " has an inexact type")


def _token(value: Any, label: str) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        _fail(label + " is not an exact protocol token")
    return value


def _hex64(value: Any, label: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        _fail(label + " is not an exact SHA-256 identifier")
    return value


def _positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        _fail(label + " is not an exact bounded integer")
    return value


def _validate_json(value: Any, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_ITEMS or depth > MAX_JSON_DEPTH:
        _fail("canonical JSON exceeds its structural bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            _fail("canonical JSON integer exceeds signed 64-bit range")
        return
    if type(value) is str:
        if (len(value) > MAX_STRING_CHARS or "\x00" in value or
                any(0xD800 <= ord(character) <= 0xDFFF for character in value) or
                unicodedata.normalize("NFC", value) != value):
            _fail("canonical JSON string is oversized, invalid Unicode, contains NUL, or is not NFC")
        return
    if type(value) is list:
        for item in value:
            _validate_json(item, depth=depth + 1, counter=counter)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 128 or "\x00" in key:
                _fail("canonical JSON object key is invalid")
            if (any(0xD800 <= ord(character) <= 0xDFFF for character in key) or
                    unicodedata.normalize("NFC", key) != key):
                _fail("canonical JSON object key is not NFC")
            _validate_json(item, depth=depth + 1, counter=counter)
        return
    _fail("canonical JSON permits only exact null/bool/int/string/list/object values")


def canonical_json(value: Any) -> bytes:
    """Encode exact, bounded JSON; floats, subclasses, NaN, and objects fail."""

    _validate_json(value)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    if not 1 <= len(raw) <= MAX_PAYLOAD_BYTES:
        _fail("canonical JSON payload exceeds its byte bound")
    return raw


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            _fail("canonical JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail("canonical JSON contains a non-finite number: " + value)


def decode_canonical_json(raw: bytes) -> Any:
    """Decode only the byte-for-byte canonical form accepted by ``canonical_json``."""

    _exact(raw, bytes, "canonical JSON input")
    if not 1 <= len(raw) <= MAX_PAYLOAD_BYTES:
        _fail("canonical JSON input exceeds its byte bound")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                           parse_constant=_reject_constant)
    except CapabilityIpcError:
        raise
    except BaseException as error:
        raise CapabilityIpcError("malformed canonical JSON") from error
    _validate_json(value)
    if canonical_json(value) != raw:
        _fail("JSON input is valid but not canonical")
    return value


class Clock(Protocol):
    def now_ns(self) -> int: ...


class CryptoProvider(Protocol):
    def challenge(self, size: int) -> bytes: ...
    def sha256(self, payload: bytes) -> bytes: ...
    def hmac_sha256(self, key: bytes, payload: bytes) -> bytes: ...
    def compare_digest(self, left: bytes, right: bytes) -> bool: ...


@dataclass(frozen=True)
class HandleIdentity:
    authority: str
    capability_id: str
    numeric_value: int
    object_id: str
    owner_pid: int
    owner_creation_ticks: int
    kind: str
    rights: tuple[str, ...]
    preopened: bool
    retained: bool

    def validate(self, *, expected_id: str | None = None, expected_kind: str | None = None) -> None:
        if type(self) is not HandleIdentity:
            _fail("handle identity is substituted")
        if self.authority != HANDLE_AUTHORITY:
            _fail("handle identity authority is invalid")
        _token(self.capability_id, "handle capability ID")
        if expected_id is not None and self.capability_id != expected_id:
            _fail("preopened handle capability ID differs from fixed policy")
        _positive_int(self.numeric_value, "handle numeric value", allow_zero=True)
        _hex64(self.object_id, "handle object ID")
        _positive_int(self.owner_pid, "handle owner PID")
        _positive_int(self.owner_creation_ticks, "handle owner creation ticks")
        if type(self.kind) is not str or self.kind not in {"owner", "resource", "transport"}:
            _fail("handle kind is invalid")
        if expected_kind is not None and self.kind != expected_kind:
            _fail("handle kind differs from fixed policy")
        if (type(self.rights) is not tuple or not self.rights or
                any(type(item) is not str or not _TOKEN.fullmatch(item) for item in self.rights) or
                tuple(sorted(set(self.rights))) != self.rights):
            _fail("handle rights are not an exact sorted capability tuple")
        if self.preopened is not True or self.retained is not True:
            _fail("handle is not preopened and retained")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "authority": self.authority, "capability_id": self.capability_id,
            "kind": self.kind, "numeric_value": self.numeric_value,
            "object_id": self.object_id, "owner_creation_ticks": self.owner_creation_ticks,
            "owner_pid": self.owner_pid, "preopened": self.preopened,
            "retained": self.retained, "rights": list(self.rights),
        }


@dataclass(frozen=True)
class RetainedCapability:
    identity: HandleIdentity
    handle: Any = field(compare=False, repr=False)

    def validate(self, expected_id: str) -> None:
        if type(self) is not RetainedCapability or self.handle is None:
            _fail("retained capability is missing or substituted")
        self.identity.validate(expected_id=expected_id, expected_kind="resource")


class HandleAuthority(Protocol):
    def identity(self, retained_handle: Any) -> HandleIdentity: ...


@dataclass(frozen=True)
class TransportBinding:
    authority: str
    channel_id: str
    endpoints: tuple[HandleIdentity, ...]
    packet_framed: bool
    fresh_request_challenges: bool
    supports_authenticated_eof: bool
    supports_nonmutating_quiescence: bool
    real_transport: bool

    _ENDPOINT_IDS = ("child_receive", "child_send", "parent_receive", "parent_send")

    def validate(self) -> None:
        if type(self) is not TransportBinding or self.authority != TRANSPORT_AUTHORITY:
            _fail("transport binding authority is invalid or substituted")
        _hex64(self.channel_id, "transport channel ID")
        if type(self.endpoints) is not tuple or len(self.endpoints) != len(self._ENDPOINT_IDS):
            _fail("transport endpoint set is incomplete or oversized")
        ids = tuple(item.capability_id for item in self.endpoints)
        if ids != self._ENDPOINT_IDS:
            _fail("transport endpoint set differs from exact fixed policy")
        for item, expected in zip(self.endpoints, self._ENDPOINT_IDS):
            item.validate(expected_id=expected, expected_kind="transport")
            expected_rights = ("read",) if expected.endswith("receive") else ("write",)
            if item.rights != expected_rights:
                _fail("transport endpoint rights exceed or differ from fixed direction")
        _validate_distinct_identities(self.endpoints, "transport endpoints")
        if (self.packet_framed is not True or self.fresh_request_challenges is not True or
                self.supports_authenticated_eof is not True or
                self.supports_nonmutating_quiescence is not True or
                type(self.real_transport) is not bool):
            _fail("transport binding lacks an exact required property")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "authority": self.authority, "channel_id": self.channel_id,
            "endpoints": [item.wire() for item in self.endpoints],
            "fresh_request_challenges": self.fresh_request_challenges,
            "packet_framed": self.packet_framed, "real_transport": self.real_transport,
            "supports_authenticated_eof": self.supports_authenticated_eof,
            "supports_nonmutating_quiescence": self.supports_nonmutating_quiescence,
        }


class PacketTransport(Protocol):
    side: str
    def binding(self) -> TransportBinding: ...
    def verify(self, expected: TransportBinding) -> None: ...
    def send(self, packet: "WirePacket", deadline_ns: int) -> None: ...
    def receive(self, deadline_ns: int) -> "WirePacket | None": ...
    def seal_send(self, request_id: str, deadline_ns: int) -> None: ...
    def verify_send_sealed(self, request_id: str) -> None: ...
    def revoke(self, request_id: str | None, deadline_ns: int) -> None: ...
    def verify_quiescent(self, request_id: str | None,
                         challenge: "QuiescenceChallenge") -> "QuiescenceReceipt": ...


@dataclass(frozen=True)
class SessionEpochBinding:
    """Immutable identity of a retained, one-shot session admission."""

    authority: str
    epoch_id: str
    admission_id: str
    session_id: str
    factory_id: str
    role: str
    owner_object_id: str
    one_shot: bool
    retained: bool

    def validate(self, *, session_id: str, factory_id: str, role: str,
                 owner_object_id: str) -> None:
        if type(self) is not SessionEpochBinding or self.authority != SESSION_EPOCH_AUTHORITY:
            _fail("session epoch binding authority is invalid or substituted")
        _hex64(self.epoch_id, "session epoch ID")
        _hex64(self.admission_id, "session epoch admission ID")
        expected = {
            "session_id": session_id, "factory_id": factory_id, "role": role,
            "owner_object_id": owner_object_id,
        }
        for name, value in expected.items():
            current = getattr(self, name)
            if type(current) is not str or current != value:
                _fail("session epoch " + name + " differs from immutable capability binding")
        if self.one_shot is not True or self.retained is not True:
            _fail("session epoch lacks exact retained one-shot admission guarantees")

    def wire(self) -> dict[str, Any]:
        return {
            "admission_id": self.admission_id, "authority": self.authority,
            "epoch_id": self.epoch_id, "factory_id": self.factory_id,
            "one_shot": self.one_shot, "owner_object_id": self.owner_object_id,
            "retained": self.retained, "role": self.role,
            "session_id": self.session_id,
        }


class SessionEpochAdmissionAuthority(Protocol):
    def binding(self) -> SessionEpochBinding: ...
    def admit(self, expected: SessionEpochBinding, side: str) -> None: ...
    def verify_admitted(self, expected: SessionEpochBinding, side: str) -> None: ...
    def revoke(self, expected: SessionEpochBinding, side: str) -> None: ...
    def verify_revoked(self, expected: SessionEpochBinding, side: str) -> None: ...


def _make_epoch_claim_registry() -> Callable[[SessionEpochBinding, Any, str], None]:
    lock = threading.Lock()
    claims: dict[tuple[str, str], tuple[Any, set[str]]] = {}

    def claim(binding: SessionEpochBinding, admission: Any, side: str) -> None:
        key = (binding.epoch_id, binding.admission_id)
        with lock:
            current = claims.get(key)
            if current is None:
                claims[key] = (admission, {side})
                return
            retained_admission, used_sides = current
            if retained_admission is not admission or side in used_sides:
                _fail("session epoch was replayed across retained session instances")
            used_sides.add(side)

    return claim


_CLAIM_SESSION_EPOCH = _make_epoch_claim_registry()


@dataclass(frozen=True)
class OperationPolicy:
    operation_id: str
    required_resources: tuple[str, ...]
    request_fields: tuple[str, ...]
    callback_events: tuple[str, ...]
    max_callbacks: int
    max_callback_bytes: int
    max_result_bytes: int

    def validate(self) -> None:
        if type(self) is not OperationPolicy:
            _fail("operation policy is substituted")
        _token(self.operation_id, "operation ID")
        for name, values in (("resource", self.required_resources),
                             ("request field", self.request_fields),
                             ("callback event", self.callback_events)):
            if (type(values) is not tuple or
                    any(type(item) is not str or not _TOKEN.fullmatch(item) for item in values) or
                    tuple(sorted(set(values))) != values):
                _fail(name + " policy is not an exact sorted tuple")
        _positive_int(self.max_callbacks, "callback maximum", allow_zero=True)
        if self.max_callbacks > MAX_CALLBACKS:
            _fail("callback maximum exceeds protocol policy")
        _positive_int(self.max_callback_bytes, "callback byte maximum")
        _positive_int(self.max_result_bytes, "result byte maximum")
        if (self.max_callback_bytes > MAX_PAYLOAD_BYTES or
                self.max_result_bytes > MAX_PAYLOAD_BYTES):
            _fail("operation payload maximum exceeds the protocol maximum")
        if (not self.callback_events) != (self.max_callbacks == 0):
            _fail("callback event policy and callback bound disagree")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "callback_events": list(self.callback_events),
            "max_callback_bytes": self.max_callback_bytes,
            "max_callbacks": self.max_callbacks, "max_result_bytes": self.max_result_bytes,
            "operation_id": self.operation_id,
            "request_fields": list(self.request_fields),
            "required_resources": list(self.required_resources),
        }


@dataclass(frozen=True)
class FactoryPolicy:
    factory_id: str
    role: str
    resource_ids: tuple[str, ...]
    resource_rights: tuple[tuple[str, ...], ...]
    operations: tuple[OperationPolicy, ...]

    def validate(self) -> None:
        if type(self) is not FactoryPolicy:
            _fail("factory policy is substituted")
        if ((self.factory_id, self.role) not in {
                (FRIDA_FACTORY_ID, FRIDA_ROLE),
                (AUTHORITY_FACTORY_ID, AUTHORITY_ROLE)}):
            _fail("factory ID and worker role are not an exact registered pair")
        if (type(self.resource_ids) is not tuple or not self.resource_ids or
                any(type(item) is not str or not _TOKEN.fullmatch(item)
                    for item in self.resource_ids) or
                tuple(sorted(set(self.resource_ids))) != self.resource_ids):
            _fail("factory resource table is not an exact sorted tuple")
        if (type(self.resource_rights) is not tuple or
                len(self.resource_rights) != len(self.resource_ids)):
            _fail("factory resource-rights table is incomplete or mutable")
        for rights in self.resource_rights:
            if (type(rights) is not tuple or not rights or
                    any(type(item) is not str or not _TOKEN.fullmatch(item) for item in rights) or
                    tuple(sorted(set(rights))) != rights):
                _fail("factory resource rights are not an exact sorted tuple")
        if type(self.operations) is not tuple or not self.operations:
            _fail("factory operation table is empty or mutable")
        for operation in self.operations:
            operation.validate()
            if not set(operation.required_resources).issubset(self.resource_ids):
                _fail("operation requires a resource outside its factory binding")
        operation_ids = tuple(item.operation_id for item in self.operations)
        if tuple(sorted(set(operation_ids))) != operation_ids:
            _fail("factory operation table is not sorted and unique")
        if _factory_policy_signature(self) != _registered_factory_policy_signature(
                self.factory_id):
            _fail("factory policy differs from its exact immutable registered table")

    def operation(self, operation_id: str) -> OperationPolicy:
        _token(operation_id, "requested operation ID")
        for item in self.operations:
            if item.operation_id == operation_id:
                return item
        _fail("operation is outside the immutable factory registry")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "factory_id": self.factory_id, "operations": [item.wire() for item in self.operations],
            "resource_ids": list(self.resource_ids),
            "resource_rights": [list(item) for item in self.resource_rights],
            "role": self.role,
        }


_FRIDA_POLICY = FactoryPolicy(
    FRIDA_FACTORY_ID, FRIDA_ROLE,
    ("frida_device", "target_process"),
    (("query", "read"), ("query", "read")),
    (OperationPolicy(
        "frida.collect_native_page.v1", ("frida_device", "target_process"), (),
        ("native_page_event.v1",), 64, 262_144, MAX_PAYLOAD_BYTES),),
)

_AUTHORITY_OPERATION_IDS = (
    "authority.read_activity_dump.v1", "authority.read_device_state.v1",
    "authority.read_display_dump.v1", "authority.read_framework.v1",
    "authority.read_module_apk.v1", "authority.read_nullable_mark.v1",
    "authority.read_original_pdf.v1", "authority.read_target_base_apk.v1",
    "authority.read_target_process.v1", "authority.read_window_dump.v1",
)
_AUTHORITY_POLICY = FactoryPolicy(
    AUTHORITY_FACTORY_ID, AUTHORITY_ROLE,
    ("private_adb", "root_reader", "target_process"),
    (("query", "read"), ("query", "read"), ("query", "read")),
    tuple(OperationPolicy(
        operation_id,
        (("private_adb", "root_reader") if operation_id in {
            "authority.read_framework.v1", "authority.read_module_apk.v1",
            "authority.read_target_base_apk.v1"} else
         ("private_adb", "target_process") if operation_id in {
             "authority.read_activity_dump.v1", "authority.read_display_dump.v1",
             "authority.read_target_process.v1", "authority.read_window_dump.v1"} else
         ("private_adb",)),
        (), (), 0, 1, MAX_PAYLOAD_BYTES)
          for operation_id in _AUTHORITY_OPERATION_IDS),
)


def _factory_policy_signature(policy: FactoryPolicy) -> tuple[Any, ...]:
    """Return an immutable, code-owned value for exact registry comparison."""

    return (
        policy.factory_id, policy.role, policy.resource_ids, policy.resource_rights,
        tuple((
            item.operation_id, item.required_resources, item.request_fields,
            item.callback_events, item.max_callbacks, item.max_callback_bytes,
            item.max_result_bytes,
        ) for item in policy.operations),
    )


def _registered_factory_policy_signature(
        factory_id: str,
        _frida: tuple[Any, ...] = _factory_policy_signature(_FRIDA_POLICY),
        _authority: tuple[Any, ...] = _factory_policy_signature(_AUTHORITY_POLICY),
        _frida_id: str = FRIDA_FACTORY_ID,
        _authority_id: str = AUTHORITY_FACTORY_ID) -> tuple[Any, ...]:
    if factory_id == _frida_id:
        return _frida
    if factory_id == _authority_id:
        return _authority
    _fail("factory is outside the immutable v1 registry")


_FRIDA_POLICY.validate()
_AUTHORITY_POLICY.validate()
FACTORY_POLICIES: Mapping[str, FactoryPolicy] = MappingProxyType({
    FRIDA_FACTORY_ID: _FRIDA_POLICY,
    AUTHORITY_FACTORY_ID: _AUTHORITY_POLICY,
})


def factory_policy(factory_id: str, _frida: FactoryPolicy = _FRIDA_POLICY,
                   _authority: FactoryPolicy = _AUTHORITY_POLICY,
                   _frida_id: str = FRIDA_FACTORY_ID,
                   _authority_id: str = AUTHORITY_FACTORY_ID) -> FactoryPolicy:
    if type(factory_id) is not str:
        _fail("factory is outside the immutable v1 registry")
    # Deliberately select the closed constants, rather than consulting the
    # exported read-only view at runtime.  Rebinding an imported module name
    # therefore cannot dynamically register or replace an operation table.
    if factory_id == _frida_id:
        _frida.validate()
        return _frida
    if factory_id == _authority_id:
        _authority.validate()
        return _authority
    _fail("factory is outside the immutable v1 registry")


def _validate_distinct_identities(values: tuple[HandleIdentity, ...], label: str) -> None:
    numeric = [item.numeric_value for item in values]
    objects = [item.object_id for item in values]
    if len(set(numeric)) != len(numeric) or len(set(objects)) != len(objects):
        _fail(label + " contain a duplicate or aliased handle identity")


def _crypto_bytes(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail(label + " did not return exact 32-byte output")
    return value


def _sha256(crypto: CryptoProvider, payload: bytes) -> bytes:
    _exact(payload, bytes, "digest payload")
    return _crypto_bytes(
        _call_unretained_provider(crypto, "sha256", payload),
        "SHA-256 provider")


def _digest_hex(crypto: CryptoProvider, payload: bytes) -> str:
    return _sha256(crypto, payload).hex()


def _challenge_id(crypto: CryptoProvider, binding_sha256: str, session_epoch: str,
                  nonce: str, sequence: int) -> str:
    return _digest_hex(crypto, canonical_json({
        "binding": binding_sha256, "nonce": nonce, "sequence": sequence,
        "session_epoch": session_epoch,
    }))


def _request_id(crypto: CryptoProvider, binding_sha256: str, session_epoch: str,
                challenge: str, deadline_ns: int, operation_id: str,
                sequence: int) -> str:
    return _digest_hex(crypto, canonical_json({
        "binding": binding_sha256, "challenge": challenge,
        "deadline_ns": deadline_ns, "operation_id": operation_id,
        "sequence": sequence, "session_epoch": session_epoch,
    }))


@dataclass(frozen=True)
class CapabilityBinding:
    authority: str
    version: int
    factory_id: str
    role: str
    session_id: str
    session_epoch: SessionEpochBinding
    absolute_deadline_ns: int
    key_id: str
    owner: HandleIdentity
    resources: tuple[HandleIdentity, ...]
    resource_binding_sha256: str
    operation_table_sha256: str
    transport: TransportBinding
    transport_binding_sha256: str
    real_transport: bool

    def validate(self, crypto: CryptoProvider) -> None:
        if type(self) is not CapabilityBinding or self.authority != BINDING_AUTHORITY:
            _fail("capability binding authority is invalid or substituted")
        if type(self.version) is not int or self.version != PROTOCOL_VERSION:
            _fail("capability binding version is invalid")
        policy = factory_policy(self.factory_id)
        if self.role != policy.role:
            _fail("capability binding factory/role pair is invalid")
        _hex64(self.session_id, "capability session ID")
        if type(self.owner) is not HandleIdentity:
            _fail("capability owner identity is substituted")
        self.owner.validate(expected_id="parent_owner", expected_kind="owner")
        self.session_epoch.validate(
            session_id=self.session_id, factory_id=self.factory_id, role=self.role,
            owner_object_id=self.owner.object_id)
        _positive_int(self.absolute_deadline_ns, "capability absolute deadline")
        _hex64(self.key_id, "capability HMAC key ID")
        if self.owner.rights != ("query", "terminate"):
            _fail("parent owner rights differ from exact retained-owner policy")
        if type(self.resources) is not tuple:
            _fail("capability resources are mutable or substituted")
        ids = tuple(item.capability_id for item in self.resources)
        if ids != policy.resource_ids:
            _fail("capability resources are missing, extra, reordered, or substituted")
        for item, expected, rights in zip(
                self.resources, policy.resource_ids, policy.resource_rights):
            item.validate(expected_id=expected, expected_kind="resource")
            if item.rights != rights:
                _fail("preopened resource rights differ from fixed factory policy")
        self.transport.validate()
        identities = (self.owner,) + self.resources + self.transport.endpoints
        _validate_distinct_identities(identities, "bound owner/resources/endpoints")
        resource_wire = [item.wire() for item in self.resources]
        if _digest_hex(crypto, canonical_json(resource_wire)) != self.resource_binding_sha256:
            _fail("resource binding digest is invalid")
        if _digest_hex(crypto, canonical_json(policy.wire())) != self.operation_table_sha256:
            _fail("operation table digest is invalid")
        if _digest_hex(crypto, canonical_json(self.transport.wire())) != self.transport_binding_sha256:
            _fail("transport binding digest is invalid")
        if type(self.real_transport) is not bool or self.real_transport != self.transport.real_transport:
            _fail("real-transport declaration differs from retained transport authority")

    def wire(self) -> dict[str, Any]:
        return {
            "absolute_deadline_ns": self.absolute_deadline_ns, "authority": self.authority,
            "factory_id": self.factory_id, "key_id": self.key_id,
            "operation_table_sha256": self.operation_table_sha256,
            "owner": self.owner.wire(), "real_transport": self.real_transport,
            "resource_binding_sha256": self.resource_binding_sha256,
            "resources": [item.wire() for item in self.resources], "role": self.role,
            "session_epoch": self.session_epoch.wire(), "session_id": self.session_id,
            "transport": self.transport.wire(),
            "transport_binding_sha256": self.transport_binding_sha256,
            "version": self.version,
        }


def make_capability_binding(*, factory_id: str, session_id: str,
                            session_epoch: SessionEpochBinding,
                            absolute_deadline_ns: int, key_id: str,
                            owner: HandleIdentity,
                            resources: tuple[HandleIdentity, ...],
                            transport: TransportBinding,
                            crypto: CryptoProvider) -> CapabilityBinding:
    """Construct the exact immutable binding for one registered v1 factory."""

    policy = factory_policy(factory_id)
    if type(resources) is not tuple:
        _fail("preopened resource identities must be an exact tuple")
    if type(owner) is not HandleIdentity:
        _fail("preopened owner identity is substituted")
    if type(session_epoch) is not SessionEpochBinding:
        _fail("session epoch binding is substituted")
    if type(transport) is not TransportBinding:
        _fail("preopened transport identity is substituted")
    for item in resources:
        if type(item) is not HandleIdentity:
            _fail("preopened resource identity is substituted")
    binding = CapabilityBinding(
        BINDING_AUTHORITY, PROTOCOL_VERSION, factory_id, policy.role, session_id,
        session_epoch, absolute_deadline_ns, key_id, owner, resources,
        _digest_hex(crypto, canonical_json([item.wire() for item in resources])),
        _digest_hex(crypto, canonical_json(policy.wire())), transport,
        _digest_hex(crypto, canonical_json(transport.wire())), transport.real_transport)
    binding.validate(crypto)
    return binding


@dataclass(frozen=True)
class DetachedPayload:
    canonical: bytes
    sha256: str

    @classmethod
    def from_value(cls, value: Any, crypto: CryptoProvider, maximum: int) -> "DetachedPayload":
        raw = canonical_json(value)
        if len(raw) > maximum:
            _fail("detached payload exceeds its operation policy")
        return cls(raw, _digest_hex(crypto, raw))

    @classmethod
    def from_wire(cls, raw: bytes, crypto: CryptoProvider, maximum: int) -> "DetachedPayload":
        _exact(raw, bytes, "detached payload")
        if not raw or len(raw) > maximum:
            _fail("detached payload is absent or oversized")
        decode_canonical_json(raw)
        return cls(raw, _digest_hex(crypto, raw))

    def decode(self) -> Any:
        return decode_canonical_json(self.canonical)


@dataclass(frozen=True)
class WirePacket:
    frame: bytes
    payload: bytes


def _binding_sha256(binding: CapabilityBinding, crypto: CryptoProvider) -> str:
    return _digest_hex(crypto, canonical_json(binding.wire()))


@dataclass(frozen=True)
class OperationOwnerBinding:
    authority: str
    capability_binding_sha256: str
    session_id: str
    factory_id: str
    role: str
    owner_object_id: str
    retained_owner_handle: bool
    exact_lease_admission: bool
    settlement_after_barrier: bool
    revoke_on_failure: bool
    nonmutating_quiescence: bool

    def validate(self, capability: CapabilityBinding, crypto: CryptoProvider) -> None:
        if type(self) is not OperationOwnerBinding or self.authority != OWNER_BINDING_AUTHORITY:
            _fail("operation owner binding authority is invalid or substituted")
        expected = {
            "capability_binding_sha256": _binding_sha256(capability, crypto),
            "session_id": capability.session_id, "factory_id": capability.factory_id,
            "role": capability.role, "owner_object_id": capability.owner.object_id,
        }
        for name, value in expected.items():
            current = getattr(self, name)
            if type(current) is not str or current != value:
                _fail("operation owner " + name + " differs from immutable capability binding")
        if (self.retained_owner_handle is not True or self.exact_lease_admission is not True or
                self.settlement_after_barrier is not True or
                self.revoke_on_failure is not True or
                self.nonmutating_quiescence is not True):
            _fail("operation owner lacks an exact required ownership guarantee")

    def wire(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "capability_binding_sha256": self.capability_binding_sha256,
            "exact_lease_admission": self.exact_lease_admission,
            "factory_id": self.factory_id,
            "nonmutating_quiescence": self.nonmutating_quiescence,
            "owner_object_id": self.owner_object_id,
            "retained_owner_handle": self.retained_owner_handle,
            "revoke_on_failure": self.revoke_on_failure,
            "role": self.role,
            "session_id": self.session_id,
            "settlement_after_barrier": self.settlement_after_barrier,
        }


def make_operation_owner_binding(capability: CapabilityBinding,
                                 crypto: CryptoProvider) -> OperationOwnerBinding:
    _exact(capability, CapabilityBinding, "owner capability binding")
    capability.validate(crypto)
    value = OperationOwnerBinding(
        OWNER_BINDING_AUTHORITY, _binding_sha256(capability, crypto),
        capability.session_id, capability.factory_id, capability.role,
        capability.owner.object_id, True, True, True, True, True)
    value.validate(capability, crypto)
    return value


def _mac_payload(header: dict[str, Any]) -> bytes:
    return b"rtl-reader-worker-capability-ipc-v1\x00" + canonical_json(header)


def _make_packet(*, binding: CapabilityBinding, sequence: int, message_sequence: int,
                 kind: str, operation_id: str, request_id: str, challenge: str,
                 deadline_ns: int, body: dict[str, Any], payload: bytes,
                 key: bytes, crypto: CryptoProvider) -> WirePacket:
    if type(kind) is not str or kind not in _FRAME_KINDS:
        _fail("frame kind is outside the closed registry")
    _positive_int(sequence, "frame request sequence")
    _positive_int(message_sequence, "frame message sequence", allow_zero=True)
    _token(operation_id, "frame operation ID")
    _hex64(request_id, "frame request ID")
    _hex64(challenge, "frame challenge")
    _positive_int(deadline_ns, "frame deadline")
    _exact(body, dict, "frame body")
    _exact(payload, bytes, "detached frame payload")
    if len(payload) > MAX_PAYLOAD_BYTES:
        _fail("detached frame payload exceeds protocol maximum")
    header = {
        "authority": AUTHORITY, "binding_sha256": _binding_sha256(binding, crypto),
        "body": body, "challenge": challenge, "deadline_ns": deadline_ns,
        "factory_id": binding.factory_id, "kind": kind,
        "message_sequence": message_sequence, "operation_id": operation_id,
        "owner_object_id": binding.owner.object_id, "payload_bytes": len(payload),
        "payload_sha256": _digest_hex(crypto, payload), "request_id": request_id,
        "role": binding.role, "sequence": sequence,
        "session_epoch": binding.session_epoch.epoch_id,
        "session_id": binding.session_id,
        "version": PROTOCOL_VERSION,
    }
    unsigned = _mac_payload(header)
    _exact(key, bytes, "HMAC session key")
    mac = _crypto_bytes(
        _call_unretained_provider(crypto, "hmac_sha256", key, unsigned),
        "HMAC provider")
    raw = canonical_json({"header": header, "mac": mac.hex()})
    if len(raw) > MAX_FRAME_BYTES:
        _fail("authenticated frame exceeds protocol maximum")
    return WirePacket(len(raw).to_bytes(4, "big") + raw, payload)


def _open_packet(packet: WirePacket, *, key: bytes, crypto: CryptoProvider
                 ) -> tuple[dict[str, Any], bytes]:
    if type(packet) is not WirePacket:
        _fail("wire packet is substituted")
    _exact(packet.frame, bytes, "wire frame")
    _exact(packet.payload, bytes, "wire detached payload")
    if len(packet.frame) < 5:
        _fail("wire frame is partial")
    size = int.from_bytes(packet.frame[:4], "big")
    if size < 1 or size > MAX_FRAME_BYTES or len(packet.frame) != size + 4:
        _fail("wire frame is partial, oversized, or has trailing bytes")
    value = decode_canonical_json(packet.frame[4:])
    if type(value) is not dict or set(value) != {"header", "mac"}:
        _fail("authenticated frame envelope has missing or extra fields")
    header, mac_hex = value["header"], value["mac"]
    if type(header) is not dict or set(header) != _HEADER_KEYS:
        _fail("authenticated frame header has missing or extra fields")
    _hex64(mac_hex, "frame HMAC")
    actual = _crypto_bytes(
        _call_unretained_provider(
            crypto, "hmac_sha256", key, _mac_payload(header)),
        "HMAC provider")
    comparison = _call_unretained_provider(
        crypto, "compare_digest", bytes.fromhex(mac_hex), actual)
    if type(comparison) is not bool or not comparison:
        _fail("authenticated frame HMAC is invalid")
    if (type(header["payload_bytes"]) is not int or
            header["payload_bytes"] != len(packet.payload) or
            header["payload_bytes"] > MAX_PAYLOAD_BYTES or
            header["payload_sha256"] != _digest_hex(crypto, packet.payload)):
        _fail("detached payload length or digest is invalid")
    return header, packet.payload


@dataclass(frozen=True)
class OperationLease:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    sequence: int
    operation_id: str
    request_id: str
    challenge: str
    deadline_ns: int
    owner_object_id: str

    def validate(self) -> None:
        if type(self) is not OperationLease or self.authority != LEASE_AUTHORITY:
            _fail("operation lease authority is invalid or substituted")
        _hex64(self.binding_sha256, "operation lease binding")
        _hex64(self.session_id, "operation lease session")
        _hex64(self.session_epoch, "operation lease epoch")
        _positive_int(self.sequence, "operation lease sequence")
        _token(self.operation_id, "operation lease operation")
        _hex64(self.request_id, "operation lease request")
        _hex64(self.challenge, "operation lease challenge")
        _positive_int(self.deadline_ns, "operation lease deadline")
        _hex64(self.owner_object_id, "operation lease owner")


class OperationOwnerAuthority(Protocol):
    def binding(self, retained_owner: Any) -> OperationOwnerBinding: ...
    def verify(self, expected: OperationOwnerBinding) -> None: ...
    def admit(self, retained_owner: Any, expected: OperationOwnerBinding,
              lease: OperationLease) -> None: ...
    def settle(self, retained_owner: Any, expected: OperationOwnerBinding,
               lease: OperationLease) -> None: ...
    def revoke(self, retained_owner: Any, expected: OperationOwnerBinding,
               request_id: str | None, deadline_ns: int) -> None: ...
    def verify_quiescent(self, retained_owner: Any, expected: OperationOwnerBinding,
                         request_id: str | None,
                         challenge: "QuiescenceChallenge") -> "QuiescenceReceipt": ...


@dataclass(frozen=True)
class CallbackBinding:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    sequence: int
    operation_id: str
    request_id: str
    challenge: str
    deadline_ns: int
    owner_object_id: str
    allowed_events: tuple[str, ...]
    maximum_callbacks: int
    maximum_payload_bytes: int

    def validate(self) -> None:
        if type(self) is not CallbackBinding or self.authority != CALLBACK_AUTHORITY:
            _fail("callback binding authority is invalid or substituted")
        lease = OperationLease(
            LEASE_AUTHORITY, self.binding_sha256, self.session_id,
            self.session_epoch, self.sequence, self.operation_id, self.request_id,
            self.challenge, self.deadline_ns, self.owner_object_id)
        lease.validate()
        if (type(self.allowed_events) is not tuple or
                any(type(item) is not str or not _TOKEN.fullmatch(item)
                    for item in self.allowed_events) or
                tuple(sorted(set(self.allowed_events))) != self.allowed_events):
            _fail("callback binding events are not an exact sorted tuple")
        _positive_int(self.maximum_callbacks, "callback binding maximum", allow_zero=True)
        _positive_int(self.maximum_payload_bytes, "callback binding payload maximum")
        if (self.maximum_callbacks > MAX_CALLBACKS or
                self.maximum_payload_bytes > MAX_PAYLOAD_BYTES or
                (not self.allowed_events) != (self.maximum_callbacks == 0)):
            _fail("callback binding events and maximum disagree")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "allowed_events": list(self.allowed_events),
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "challenge": self.challenge,
            "deadline_ns": self.deadline_ns,
            "maximum_callbacks": self.maximum_callbacks,
            "maximum_payload_bytes": self.maximum_payload_bytes,
            "operation_id": self.operation_id,
            "owner_object_id": self.owner_object_id,
            "request_id": self.request_id,
            "sequence": self.sequence,
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
        }


class _QuiescenceFence:
    """Shared monotonic fence for one retained multi-authority proof round."""

    __slots__ = ("__generation", "__lock", "__sealed")

    def __init__(self, generation: int) -> None:
        _positive_int(generation, "quiescence fence generation", allow_zero=True)
        object.__setattr__(self, "_QuiescenceFence__generation", generation)
        object.__setattr__(self, "_QuiescenceFence__lock", threading.RLock())
        object.__setattr__(self, "_QuiescenceFence__sealed", False)

    def advance(self) -> None:
        lock = object.__getattribute__(self, "_QuiescenceFence__lock")
        with lock:
            if object.__getattribute__(self, "_QuiescenceFence__sealed"):
                _fail("quiescence fence mutated after terminal comparison")
            generation = object.__getattribute__(self, "_QuiescenceFence__generation")
            object.__setattr__(self, "_QuiescenceFence__generation", generation + 1)

    def snapshot(self) -> int:
        lock = object.__getattribute__(self, "_QuiescenceFence__lock")
        with lock:
            return object.__getattribute__(self, "_QuiescenceFence__generation")

    def seal(self, generation: int) -> None:
        lock = object.__getattribute__(self, "_QuiescenceFence__lock")
        with lock:
            if (object.__getattribute__(self, "_QuiescenceFence__generation") !=
                    generation):
                _fail("quiescence authority mutated during the shared proof round")
            object.__setattr__(self, "_QuiescenceFence__sealed", True)


@dataclass(frozen=True)
class QuiescenceChallenge:
    """One exact, fresh proof round shared by all required authorities.

    A real adapter must serialize every participant named by ``participants``
    against the same retained generation while it produces its receipt.  If a
    participant mutates during another participant's proof, the adapter must
    advance the shared generation or refuse to attest.  The Python protocol
    validates that every receipt binds this exact round; it does not infer
    native quiescence from mutable booleans.
    """

    authority: str
    binding_sha256: str
    session_epoch: str
    side: str
    phase: str
    request_id: str | None
    generation: int
    nonce: str
    participants: tuple[tuple[str, str], ...]
    challenge_id: str
    _fence: _QuiescenceFence = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_fence", _QuiescenceFence(self.generation))

    def note_component_mutation(self, component: str) -> None:
        """Required adapter hook for any participant mutation during proof."""

        if (type(component) is not str or component not in _QUIESCENCE_COMPONENTS or
                component not in {name for name, _digest in self.participants}):
            _fail("quiescence mutation component is outside this proof round")
        self._fence.advance()

    def _receipt_generation(self) -> int:
        return self._fence.snapshot()

    def _seal_fence(self) -> None:
        self._fence.seal(self.generation)

    def wire(self, *, include_id: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "generation": self.generation,
            "nonce": self.nonce,
            "participants": [[name, digest_value]
                             for name, digest_value in self.participants],
            "phase": self.phase,
            "request_id": self.request_id,
            "session_epoch": self.session_epoch,
            "side": self.side,
        }
        if include_id:
            value["challenge_id"] = self.challenge_id
        return value

    def validate(self, crypto: CryptoProvider) -> None:
        if (type(self) is not QuiescenceChallenge or
                type(self.authority) is not str or
                self.authority != QUIESCENCE_CHALLENGE_AUTHORITY):
            _fail("quiescence challenge authority is invalid or substituted")
        _hex64(self.binding_sha256, "quiescence binding")
        _hex64(self.session_epoch, "quiescence epoch")
        if type(self.side) is not str or self.side not in {"parent", "child"}:
            _fail("quiescence side is outside the fixed endpoint registry")
        _token(self.phase, "quiescence phase")
        if self.request_id is not None:
            _hex64(self.request_id, "quiescence request")
        _positive_int(self.generation, "quiescence generation", allow_zero=True)
        _hex64(self.nonce, "quiescence nonce")
        if type(self.participants) is not tuple or not self.participants:
            _fail("quiescence participant set is not an exact nonempty tuple")
        names: list[str] = []
        for item in self.participants:
            if type(item) is not tuple or len(item) != 2:
                _fail("quiescence participant record is substituted")
            name, digest_value = item
            if type(name) is not str or name not in _QUIESCENCE_COMPONENTS:
                _fail("quiescence participant is outside the fixed registry")
            _hex64(digest_value, "quiescence participant binding")
            names.append(name)
        if (tuple(sorted(self.participants)) != self.participants or
                len(set(names)) != len(self.participants)):
            _fail("quiescence participant set is not exact, sorted, and unique")
        _hex64(self.challenge_id, "quiescence challenge ID")
        if self.challenge_id != _digest_hex(
                crypto, b"rtl-reader-worker-quiescence-round-v1\x00" +
                canonical_json(self.wire(include_id=False))):
            _fail("quiescence challenge ID is not derived from its exact authority")
        if (type(self._fence) is not _QuiescenceFence or
                self._fence.snapshot() < self.generation):
            _fail("quiescence shared generation fence is substituted")


@dataclass(frozen=True)
class QuiescenceReceipt:
    """Typed attestation returned by one retained proof participant."""

    authority: str
    challenge_id: str
    component: str
    component_binding_sha256: str
    request_id: str | None
    generation: int
    component_generation: int
    quiescent: bool

    def wire(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "challenge_id": self.challenge_id,
            "component": self.component,
            "component_binding_sha256": self.component_binding_sha256,
            "component_generation": self.component_generation,
            "generation": self.generation,
            "quiescent": self.quiescent,
            "request_id": self.request_id,
        }

    def validate(self, expected: QuiescenceChallenge,
                 component: str) -> None:
        if (type(self) is not QuiescenceReceipt or
                type(self.authority) is not str or
                self.authority != QUIESCENCE_RECEIPT_AUTHORITY):
            _fail("quiescence receipt authority is invalid or substituted")
        if type(expected) is not QuiescenceChallenge:
            _fail("quiescence receipt expected challenge is substituted")
        if type(component) is not str or component not in _QUIESCENCE_COMPONENTS:
            _fail("quiescence receipt component is outside the fixed registry")
        if type(self.component) is not str:
            _fail("quiescence receipt component scalar is inexact")
        _hex64(self.challenge_id, "quiescence receipt challenge")
        _hex64(self.component_binding_sha256,
               "quiescence receipt component binding")
        if self.request_id is not None:
            _hex64(self.request_id, "quiescence receipt request")
        _positive_int(self.generation, "quiescence receipt generation",
                      allow_zero=True)
        _positive_int(self.component_generation,
                      "quiescence receipt component generation",
                      allow_zero=True)
        if type(self.quiescent) is not bool:
            _fail("quiescence receipt status scalar is inexact")
        bindings = dict(expected.participants)
        if (component not in bindings or self.component != component or
                self.component_binding_sha256 != bindings[component]):
            _fail("quiescence receipt component binding differs from its proof round")
        if (self.challenge_id != expected.challenge_id or
                self.request_id != expected.request_id or
                type(self.generation) is not int or
                self.generation != expected.generation or
                type(self.component_generation) is not int or
                self.component_generation != expected.generation or
                self.quiescent is not True):
            _fail("quiescence receipt differs from its exact request generation")


def make_quiescence_receipt(challenge: QuiescenceChallenge,
                            component: str) -> QuiescenceReceipt:
    """Construct a typed receipt; only the retained adapter may vouch for it."""

    if type(challenge) is not QuiescenceChallenge:
        _fail("quiescence receipt challenge is substituted")
    if type(component) is not str or component not in _QUIESCENCE_COMPONENTS:
        _fail("quiescence receipt component is outside the fixed registry")
    bindings = dict(challenge.participants)
    if component not in bindings:
        _fail("quiescence component was not admitted to this proof round")
    return QuiescenceReceipt(
        QUIESCENCE_RECEIPT_AUTHORITY, challenge.challenge_id, component,
        bindings[component], challenge.request_id, challenge.generation,
        challenge._receipt_generation(), True)


def _open_quiescence_proof(value: Any, crypto: CryptoProvider) -> tuple[
        QuiescenceChallenge, tuple[QuiescenceReceipt, ...]]:
    """Decode an authenticated child proof without accepting loose JSON types."""

    if type(value) is not dict or set(value) != {"challenge", "receipts"}:
        _fail("quiescence proof has missing or extra fields")
    challenge_wire = value["challenge"]
    if type(challenge_wire) is not dict or set(challenge_wire) != {
            "authority", "binding_sha256", "challenge_id", "generation", "nonce",
            "participants", "phase", "request_id", "session_epoch", "side"}:
        _fail("quiescence challenge wire form has missing or extra fields")
    raw_participants = challenge_wire["participants"]
    if type(raw_participants) is not list:
        _fail("quiescence participant wire table is not an exact list")
    participants: list[tuple[str, str]] = []
    for item in raw_participants:
        if type(item) is not list or len(item) != 2:
            _fail("quiescence participant wire record is malformed")
        name, digest_value = item
        if type(name) is not str or type(digest_value) is not str:
            _fail("quiescence participant wire scalar is inexact")
        participants.append((name, digest_value))
    challenge = QuiescenceChallenge(
        challenge_wire["authority"], challenge_wire["binding_sha256"],
        challenge_wire["session_epoch"], challenge_wire["side"],
        challenge_wire["phase"], challenge_wire["request_id"],
        challenge_wire["generation"], challenge_wire["nonce"],
        tuple(participants), challenge_wire["challenge_id"])
    challenge.validate(crypto)
    receipt_values = value["receipts"]
    if type(receipt_values) is not list:
        _fail("quiescence receipt wire table is not an exact list")
    receipts: list[QuiescenceReceipt] = []
    for receipt_wire in receipt_values:
        if type(receipt_wire) is not dict or set(receipt_wire) != {
                "authority", "challenge_id", "component",
                "component_binding_sha256", "component_generation", "generation",
                "quiescent", "request_id"}:
            _fail("quiescence receipt wire form has missing or extra fields")
        receipt = QuiescenceReceipt(
            receipt_wire["authority"], receipt_wire["challenge_id"],
            receipt_wire["component"], receipt_wire["component_binding_sha256"],
            receipt_wire["request_id"], receipt_wire["generation"],
            receipt_wire["component_generation"], receipt_wire["quiescent"])
        receipt.validate(challenge, receipt.component)
        receipts.append(receipt)
    challenge._seal_fence()
    return challenge, tuple(receipts)


def _operation_owner_binding_digest(binding: OperationOwnerBinding,
                                    crypto: CryptoProvider) -> str:
    if type(binding) is not OperationOwnerBinding:
        _fail("operation owner quiescence binding is substituted")
    return _digest_hex(crypto, canonical_json(binding.wire()))


def _callback_binding_digest(binding: CallbackBinding,
                             crypto: CryptoProvider) -> str:
    if type(binding) is not CallbackBinding:
        _fail("callback quiescence binding is substituted")
    return _digest_hex(crypto, canonical_json(binding.wire()))


@dataclass(frozen=True)
class CallbackRecord:
    binding: CallbackBinding
    ordinal: int
    event: str
    payload: DetachedPayload


@dataclass(frozen=True)
class OperationOutcome:
    authority: str
    lease: OperationLease
    result: DetachedPayload
    callbacks: tuple[CallbackRecord, ...]
    barrier_verified: bool
    eof_verified: bool


_PROVIDER_FAILURE_CODES = frozenset({
    "provider_exception", "provider_exception_graph_oversized",
})
_MAX_PROVIDER_EXCEPTION_GRAPH = 1024

# These are the concrete CPython base slots, not normal attribute lookups.
# Calling BaseException.__getattribute__/__setattr__ is insufficient: those
# functions still honor a malicious subclass data descriptor with the same
# name.  Freeze and validate the exact built-in descriptors once, then invoke
# them directly so provider code cannot observe the scrubber's stack.
_BASE_EXCEPTION_TRACEBACK_SLOT = BaseException.__dict__["__traceback__"]
_BASE_EXCEPTION_CONTEXT_SLOT = BaseException.__dict__["__context__"]
_BASE_EXCEPTION_CAUSE_SLOT = BaseException.__dict__["__cause__"]
_BASE_EXCEPTION_SLOT_TYPE = type(_BASE_EXCEPTION_TRACEBACK_SLOT)
_BASE_EXCEPTION_GROUP_EXCEPTIONS_SLOT = BaseExceptionGroup.__dict__["exceptions"]
_BASE_EXCEPTION_GROUP_SLOT_TYPE = type(_BASE_EXCEPTION_GROUP_EXCEPTIONS_SLOT)


def _validate_exception_slot_authority(
        traceback_slot: Any = _BASE_EXCEPTION_TRACEBACK_SLOT,
        context_slot: Any = _BASE_EXCEPTION_CONTEXT_SLOT,
        cause_slot: Any = _BASE_EXCEPTION_CAUSE_SLOT,
        exception_slot_type: type = _BASE_EXCEPTION_SLOT_TYPE,
        group_slot: Any = _BASE_EXCEPTION_GROUP_EXCEPTIONS_SLOT,
        group_slot_type: type = _BASE_EXCEPTION_GROUP_SLOT_TYPE) -> None:
    if (type(traceback_slot) is not exception_slot_type or
            type(context_slot) is not exception_slot_type or
            type(cause_slot) is not exception_slot_type or
            traceback_slot is not BaseException.__dict__["__traceback__"] or
            context_slot is not BaseException.__dict__["__context__"] or
            cause_slot is not BaseException.__dict__["__cause__"] or
            type(group_slot) is not group_slot_type or
            group_slot is not BaseExceptionGroup.__dict__["exceptions"]):
        _fail("built-in exception slot authority is unavailable or substituted")


_validate_exception_slot_authority()


def _scrub_provider_exception_graph(
        error: BaseException,
        traceback_slot: Any = _BASE_EXCEPTION_TRACEBACK_SLOT,
        context_slot: Any = _BASE_EXCEPTION_CONTEXT_SLOT,
        cause_slot: Any = _BASE_EXCEPTION_CAUSE_SLOT,
        group_slot: Any = _BASE_EXCEPTION_GROUP_EXCEPTIONS_SLOT) -> bool:
    """Detach every reachable exception frame/link without invoking overrides.

    The caller is the root-free provider trampoline.  This routine deliberately
    invokes only the frozen concrete base slots, integer identity, and exact
    tuples; it never formats, compares, hashes, or performs normal/overridden
    attribute access on an untrusted exception.  Returning ``False`` is a fixed
    failure signal, not permission to propagate the provider-owned object.
    """

    _validate_exception_slot_authority(
        traceback_slot, context_slot, cause_slot, group_slot=group_slot)
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    complete = True
    while pending:
        if len(seen) >= _MAX_PROVIDER_EXCEPTION_GRAPH:
            complete = False
            break
        current = pending.pop()
        if not isinstance(current, BaseException):
            complete = False
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        linked: list[BaseException] = []
        for slot in (context_slot, cause_slot):
            try:
                value = slot.__get__(current, BaseException)
            except BaseException:
                complete = False
            else:
                if isinstance(value, BaseException):
                    linked.append(value)
                elif value is not None:
                    complete = False
        if isinstance(current, BaseExceptionGroup):
            try:
                children = group_slot.__get__(current, BaseExceptionGroup)
            except BaseException:
                complete = False
            else:
                if type(children) is not tuple:
                    complete = False
                else:
                    for child in children:
                        if isinstance(child, BaseException):
                            linked.append(child)
                        else:
                            complete = False
        for slot in (traceback_slot, context_slot, cause_slot):
            try:
                slot.__set__(current, None)
            except BaseException:
                complete = False
        pending.extend(linked)
    return complete


def _provider_failure_result(error: BaseException) -> tuple[bool, None, str]:
    """Consume one provider-owned exception and return a closed primitive code."""

    try:
        complete = _scrub_provider_exception_graph(error)
    except BaseException as scrub_error:
        # This fallback is intentionally best effort and still never lets either
        # exception object leave the root-free trampoline.
        try:
            _scrub_provider_exception_graph(scrub_error)
        except BaseException:
            pass
        complete = False
    code = ("provider_exception" if complete
            else "provider_exception_graph_oversized")
    return False, None, code


def _invoke_provider_no_throw(callable_value: Callable[..., Any],
                              arguments: tuple[Any, ...]) -> tuple[bool, Any, str | None]:
    """Invoke exactly one provider method without propagating its exception."""

    try:
        return True, callable_value(*arguments), None
    except BaseException as error:
        return _provider_failure_result(error)


def _read_provider_attribute_no_throw(owner: Any, name: str) -> tuple[
        bool, Any, str | None]:
    """Read one provider attribute in a frame that contains no session root."""

    try:
        return True, getattr(owner, name), None
    except BaseException as error:
        return _provider_failure_result(error)


def _snapshot_provider_method_no_throw(owner: Any, name: str) -> tuple[
        bool, Any, str | None]:
    """Capture callable identity entirely inside the root-free boundary."""

    try:
        method = getattr(owner, name)
        if not callable(method):
            return False, None, "provider_exception"
        bound_self = getattr(method, "__self__", None)
        function = getattr(method, "__func__", method)
        return True, (method, type(method), bound_self, function), None
    except BaseException as error:
        return _provider_failure_result(error)


def _provider_result_value(result: tuple[bool, Any, str | None],
                           label: str) -> Any:
    """Open a no-throw result without ever accepting an exception object."""

    if (type(result) is not tuple or len(result) != 3 or
            type(result[0]) is not bool or type(label) is not str):
        _fail("provider trampoline returned an inexact result")
    succeeded, value, failure_code = result
    if succeeded:
        if failure_code is not None:
            _fail("successful provider trampoline returned a failure code")
        return value
    if (value is not None or type(failure_code) is not str or
            failure_code not in _PROVIDER_FAILURE_CODES):
        _fail("provider trampoline returned a malformed failure")
    raise CapabilityIpcError(
        label + " failed inside the no-throw provider boundary (" +
        failure_code + ")") from None


def _provider_attribute(owner: Any, name: str, label: str) -> Any:
    return _provider_result_value(
        _read_provider_attribute_no_throw(owner, name), label)


def _call_unretained_provider(owner: Any, name: str, *args: Any) -> Any:
    """Call one pre-admission provider without propagating its exception.

    Retained sessions use their frozen method table.  Construction-time and
    standalone protocol helpers cannot yet have that table, but still route the
    provider call through the same root-free exception boundary.
    """

    snapshot = _provider_result_value(
        _snapshot_provider_method_no_throw(owner, name),
        "provider method capture")
    if type(snapshot) is not tuple or len(snapshot) != 4:
        _fail("provider method snapshot is malformed")
    method = snapshot[0]
    return _provider_result_value(
        _invoke_provider_no_throw(method, tuple(args)),
        "provider invocation")


_FAILURE_CODES = frozenset({
    "cancelled", "capability_failure", "internal_failure",
    "quiescence_failure", "terminal_requested",
})


def _primitive_failure_code(error: BaseException) -> str:
    """Reduce an internal failure to a fixed scalar and scrub it defensively."""

    if type(error) is CapabilityQuiescenceError:
        code = "quiescence_failure"
    elif type(error) is CapabilityIpcError:
        code = "capability_failure"
    else:
        code = "internal_failure"
    try:
        _scrub_provider_exception_graph(error)
    except BaseException as scrub_error:
        try:
            _scrub_provider_exception_graph(scrub_error)
        except BaseException:
            pass
        code = "internal_failure"
    return code


def _validate_failure_code(value: Any) -> str:
    if type(value) is not str or value not in _FAILURE_CODES:
        _fail("terminal failure code is outside the fixed registry")
    return value


@dataclass(frozen=True)
class _MethodBinding:
    owner: Any
    name: str
    method_type: type
    bound_self: Any
    function: Any
    callable_value: Callable[..., Any] = field(compare=False, repr=False)

    @classmethod
    def capture(cls, owner: Any, name: str) -> "_MethodBinding":
        snapshot = _provider_result_value(
            _snapshot_provider_method_no_throw(owner, name),
            "retained authority method capture")
        if type(snapshot) is not tuple or len(snapshot) != 4:
            _fail("retained authority method snapshot is malformed")
        method, method_type, bound_self, function = snapshot
        if (not callable(method) or type(method_type) is not type or
                type(method) is not method_type):
            _fail("retained authority method snapshot is inexact")
        return cls(owner, name, method_type, bound_self, function, method)

    def resolve(self) -> Callable[..., Any]:
        snapshot = _provider_result_value(
            _snapshot_provider_method_no_throw(self.owner, self.name),
            "retained authority method resolution")
        if type(snapshot) is not tuple or len(snapshot) != 4:
            _fail("retained authority method snapshot is malformed")
        method, method_type, bound_self, function = snapshot
        if (not callable(method) or method_type is not self.method_type or
                type(method) is not self.method_type or
                bound_self is not self.bound_self or function is not self.function):
            _fail("retained authority method " + self.name + " was substituted")
        return method

    def verify(self) -> None:
        self.resolve()


@dataclass(frozen=True)
class _TerminalReceipt:
    """Exact terminal authority retained for later quiescence proofs."""

    binding_sha256: str
    session_epoch: str
    request_id: str | None
    generation: int
    disposition: str

    def validate(self, binding_sha256: str, session_epoch: str) -> None:
        if type(self) is not _TerminalReceipt:
            _fail("terminal receipt is substituted")
        _hex64(self.binding_sha256, "terminal receipt binding")
        _hex64(self.session_epoch, "terminal receipt epoch")
        if self.binding_sha256 != binding_sha256 or self.session_epoch != session_epoch:
            _fail("terminal receipt differs from its retained session authority")
        if self.request_id is not None:
            _hex64(self.request_id, "terminal receipt request")
        _positive_int(self.generation, "terminal receipt generation", allow_zero=True)
        if type(self.disposition) is not str or self.disposition not in {"settled", "revoked"}:
            _fail("terminal receipt disposition is invalid")


def _verify_terminal_receipt(receipt: _TerminalReceipt | None,
                             authority: "_SessionAuthorities",
                             generation: int, state: str) -> None:
    """Bind quiescence to the exact terminal transition being attested."""

    if receipt is None:
        if state == "REVOKED":
            _fail("revoked session lacks an exact terminal receipt")
        return
    receipt.validate(authority.binding_digest, authority.epoch_binding.epoch_id)
    expected_disposition = "revoked" if state == "REVOKED" else "settled"
    if (receipt.generation != generation or
            receipt.disposition != expected_disposition):
        _fail("terminal receipt differs from the current session generation")


@dataclass(frozen=True)
class _StateRecord:
    ordinal: int
    reason: str
    previous_sha256: str
    snapshot: bytes
    record_sha256: str


def _state_value(value: Any) -> Any:
    """Return a canonical, non-authoritative description of private state."""

    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is tuple:
        return [_state_value(item) for item in value]
    if type(value) is frozenset:
        return sorted(_state_value(item) for item in value)
    if type(value) is _TerminalReceipt:
        return {
            "binding_sha256": value.binding_sha256,
            "disposition": value.disposition,
            "generation": value.generation,
            "request_id": value.request_id,
            "session_epoch": value.session_epoch,
        }
    if type(value) is _Outstanding:
        return {
            "generation": value.generation,
            "request_id": value.lease.request_id,
            "type": "outstanding",
        }
    if type(value) is ChildOperation:
        return _DISPATCH_CHILD_OPERATION(value, "state_record")
    if type(value) is CallbackBinding:
        return {"request_id": value.request_id, "sequence": value.sequence,
                "type": "callback_binding"}
    _fail("private state contains an unsupported authority value")


class _StickyTerminalSignal:
    """A one-way signal; unlike ``Event``, it has no clear operation."""

    __slots__ = ("__dynamic",)

    def __init__(self, dynamic: "_SessionDynamic") -> None:
        object.__setattr__(self, "_StickyTerminalSignal__dynamic", weakref.ref(dynamic))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("terminal generation signal is private and append-only")

    def set(self) -> None:
        dynamic = object.__getattribute__(self, "_StickyTerminalSignal__dynamic")()
        if dynamic is None:
            _fail("terminal generation signal lost its retained state")
        dynamic._request_terminal()

    def is_set(self) -> bool:
        dynamic = object.__getattribute__(self, "_StickyTerminalSignal__dynamic")()
        if dynamic is None:
            return True
        return dynamic._terminal_is_set()


class _SessionDynamic:
    """Closure-held state with monotonic fields and an append-only hash chain."""

    __slots__ = ("__binding", "__epoch", "__history", "__lock", "__signal",
                 "__values", "__weakref__")
    _FIELDS = frozenset({
        "active", "cleanup_obligations", "entry_owner", "generation",
        "last_callback_binding", "last_completed_request", "last_now",
        "last_settled_request", "outstanding", "sequence", "state",
        "terminal_receipt",
    })
    _STATE_TRANSITIONS = {
        "OPEN": frozenset({"OPEN", "ACTIVE", "OUTSTANDING", "REVOKED",
                           "QUIESCENCE_UNCERTAIN"}),
        "ACTIVE": frozenset({"ACTIVE", "OPEN", "REVOKED", "QUIESCENCE_UNCERTAIN"}),
        "OUTSTANDING": frozenset({"OUTSTANDING", "OPEN", "REVOKED",
                                  "QUIESCENCE_UNCERTAIN"}),
        "REVOKED": frozenset({"REVOKED", "QUIESCENCE_UNCERTAIN"}),
        "QUIESCENCE_UNCERTAIN": frozenset({"QUIESCENCE_UNCERTAIN"}),
    }

    def __init__(self, binding_sha256: str, session_epoch: str) -> None:
        _hex64(binding_sha256, "private state binding")
        _hex64(session_epoch, "private state epoch")
        object.__setattr__(self, "_SessionDynamic__binding", binding_sha256)
        object.__setattr__(self, "_SessionDynamic__epoch", session_epoch)
        object.__setattr__(self, "_SessionDynamic__history", [])
        object.__setattr__(self, "_SessionDynamic__lock", threading.RLock())
        object.__setattr__(self, "_SessionDynamic__values", {
            "active": None, "challenges": frozenset(),
            "challenge_nonces": frozenset(), "cleanup_obligations": (),
            "entry_owner": None, "generation": 0,
            "last_callback_binding": None, "last_completed_request": None,
            "last_now": -1, "last_settled_request": None,
            "outstanding": None, "sequence": 0, "state": "OPEN",
            "terminal": False, "terminal_receipt": None,
        })
        object.__setattr__(self, "_SessionDynamic__signal", _StickyTerminalSignal(self))
        self._commit("initialize")

    def __setattr__(self, name: str, value: Any) -> None:
        if name not in self._FIELDS:
            raise AttributeError("private protocol state is closed and append-only")
        self._set(name, value)

    def __getattr__(self, name: str) -> Any:
        values = object.__getattribute__(self, "_SessionDynamic__values")
        if name == "terminal_requested":
            return object.__getattribute__(self, "_SessionDynamic__signal")
        if name in {"challenges", "challenge_nonces"}:
            return values[name]
        if name in self._FIELDS:
            return values[name]
        raise AttributeError(name)

    def _snapshot(self) -> bytes:
        values = object.__getattribute__(self, "_SessionDynamic__values")
        return canonical_json({key: _state_value(value) for key, value in sorted(values.items())})

    def _commit(self, reason: str) -> None:
        _token(reason, "private state transition reason")
        history = object.__getattribute__(self, "_SessionDynamic__history")
        previous = history[-1].record_sha256 if history else "0" * 64
        snapshot = self._snapshot()
        ordinal = len(history) + 1
        binding = object.__getattribute__(self, "_SessionDynamic__binding")
        epoch = object.__getattribute__(self, "_SessionDynamic__epoch")
        record_sha256 = hashlib.sha256(
            b"rtl-reader-worker-state-v1\x00" + canonical_json({
                "binding": binding, "epoch": epoch, "ordinal": ordinal,
                "previous": previous, "reason": reason,
                "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
            })).hexdigest()
        history.append(_StateRecord(ordinal, reason, previous, snapshot, record_sha256))

    def _set(self, name: str, value: Any) -> None:
        lock = object.__getattribute__(self, "_SessionDynamic__lock")
        with lock:
            values = object.__getattribute__(self, "_SessionDynamic__values")
            old = values[name]
            if name in {"generation", "sequence"}:
                if type(value) is not int or value < old:
                    _fail("private monotonic counter cannot be reset or substituted")
            elif name == "last_now":
                if type(value) is not int or value < old:
                    _fail("private monotonic time cannot be reset or substituted")
            elif name == "entry_owner":
                if value is not None and (type(value) is not int or value <= 0):
                    _fail("private entry owner is inexact")
            elif name == "state":
                if (type(value) is not str or value not in self._STATE_TRANSITIONS.get(old, ())):
                    _fail("private session state transition is invalid or terminal")
            elif name == "cleanup_obligations":
                if (type(value) is not tuple or
                        any(type(item) is not str or not item for item in value)):
                    _fail("cleanup obligations are not an exact tuple")
                if values["state"] == "QUIESCENCE_UNCERTAIN" and old and value != old:
                    _fail("uncertain cleanup obligations are sticky")
            elif name in {"last_completed_request", "last_settled_request"}:
                if value is not None:
                    _hex64(value, "private terminal request")
            elif name == "last_callback_binding":
                if value is not None and type(value) is not CallbackBinding:
                    _fail("private callback terminal binding is substituted")
            elif name == "terminal_receipt":
                if value is not None:
                    value.validate(object.__getattribute__(self, "_SessionDynamic__binding"),
                                   object.__getattribute__(self, "_SessionDynamic__epoch"))
            values[name] = value
            self._commit("set_" + name)

    def _request_terminal(self) -> None:
        lock = object.__getattribute__(self, "_SessionDynamic__lock")
        with lock:
            values = object.__getattribute__(self, "_SessionDynamic__values")
            if not values["terminal"]:
                values["terminal"] = True
                self._commit("request_terminal")

    def _terminal_is_set(self) -> bool:
        lock = object.__getattribute__(self, "_SessionDynamic__lock")
        with lock:
            return object.__getattribute__(self, "_SessionDynamic__values")["terminal"]

    def add_challenge(self, value: str) -> None:
        self._add_unique("challenges", value)

    def add_challenge_nonce(self, value: str) -> None:
        self._add_unique("challenge_nonces", value)

    def _add_unique(self, name: str, value: str) -> None:
        _hex64(value, "private challenge authority")
        lock = object.__getattribute__(self, "_SessionDynamic__lock")
        with lock:
            values = object.__getattribute__(self, "_SessionDynamic__values")
            if value in values[name]:
                _fail("private challenge authority was replayed")
            values[name] = values[name] | frozenset({value})
            self._commit("append_" + name)

    def verify(self, binding_sha256: str, session_epoch: str) -> None:
        lock = object.__getattribute__(self, "_SessionDynamic__lock")
        with lock:
            if (binding_sha256 != object.__getattribute__(self, "_SessionDynamic__binding") or
                    session_epoch != object.__getattribute__(self, "_SessionDynamic__epoch")):
                _fail("private state authority was rebound")
            history = object.__getattribute__(self, "_SessionDynamic__history")
            if type(history) is not list or not history:
                _fail("private state history is absent or substituted")
            previous = "0" * 64
            for ordinal, record in enumerate(history, 1):
                if (type(record) is not _StateRecord or record.ordinal != ordinal or
                        record.previous_sha256 != previous):
                    _fail("private state history is reordered or substituted")
                expected = hashlib.sha256(
                    b"rtl-reader-worker-state-v1\x00" + canonical_json({
                        "binding": binding_sha256, "epoch": session_epoch,
                        "ordinal": ordinal, "previous": previous,
                        "reason": record.reason,
                        "snapshot_sha256": hashlib.sha256(record.snapshot).hexdigest(),
                    })).hexdigest()
                if record.record_sha256 != expected:
                    _fail("private state hash chain is invalid")
                previous = expected
            if history[-1].snapshot != self._snapshot():
                _fail("private state differs from its append-only terminal record")


@dataclass(frozen=True)
class _RetainedCrypto:
    owner: CryptoProvider
    methods: tuple[_MethodBinding, ...]

    def _call(self, name: str, *args: Any) -> Any:
        for method in self.methods:
            if method.name == name:
                return _provider_result_value(
                    _invoke_provider_no_throw(method.resolve(), tuple(args)),
                    "retained cryptographic provider")
        _fail("cryptographic method is outside the retained authority registry")

    def challenge(self, size: int) -> bytes:
        return self._call("challenge", size)

    def sha256(self, payload: bytes) -> bytes:
        return self._call("sha256", payload)

    def hmac_sha256(self, key: bytes, payload: bytes) -> bytes:
        return self._call("hmac_sha256", key, payload)

    def compare_digest(self, left: bytes, right: bytes) -> bool:
        return self._call("compare_digest", left, right)


@dataclass(frozen=True)
class _SessionAuthorities:
    binding: CapabilityBinding
    binding_wire: bytes
    binding_digest: str
    policy: FactoryPolicy
    policy_signature: tuple[Any, ...]
    policy_digest: str
    resources: tuple[RetainedCapability, ...]
    resource_snapshots: tuple[tuple[RetainedCapability, HandleIdentity, Any], ...]
    owner_handle: Any
    handle_authority: HandleAuthority
    transport: PacketTransport
    clock: Clock
    crypto: CryptoProvider
    secure_crypto: _RetainedCrypto
    key: bytes
    entry_lock: Any
    expected_side: str
    epoch_admission: SessionEpochAdmissionAuthority
    epoch_binding: SessionEpochBinding
    operation_owner: OperationOwnerAuthority | None
    operation_owner_binding: OperationOwnerBinding | None
    callback_drain: CallbackDrainAuthority | None
    methods: tuple[_MethodBinding, ...]
    dynamic: _SessionDynamic

    def call(self, owner: Any, name: str, *args: Any) -> Any:
        for method in self.methods:
            if method.owner is owner and method.name == name:
                return _provider_result_value(
                    _invoke_provider_no_throw(method.resolve(), tuple(args)),
                    "retained authority provider")
        _fail("method is outside the retained authority registry: " + name)

    def cleanup_call(self, owner: Any, name: str, *args: Any) -> Any:
        """Invoke the originally retained cleanup method after substitution is detected."""

        for method in self.methods:
            if method.owner is owner and method.name == name:
                return _provider_result_value(
                    _invoke_provider_no_throw(method.callable_value, tuple(args)),
                    "retained cleanup provider")
        _fail("cleanup method is outside the retained authority registry: " + name)


def _make_private_authority_store() -> tuple[
        Callable[[Any, Any], None], Callable[[Any, type], Any]]:
    """Keep authority roots outside capability objects and seal construction identity.

    The returned lookup performs no caller-supplied callback and never hands a root
    to a backend.  It is used only by this module's fixed state-machine methods.
    """

    lock = threading.RLock()
    roots: dict[int, tuple[weakref.ReferenceType[Any], int, Any,
                           tuple[Any, ...]]] = {}
    next_nonce = 0

    def seal_value(value: Any) -> Any:
        if value is None or type(value) in {bool, int, str, bytes, type}:
            return (type(value), value)
        if type(value) is tuple:
            return (tuple, tuple(seal_value(item) for item in value))
        if type(value) is _MethodBinding:
            return (
                _MethodBinding, id(value), id(value.owner), value.name,
                value.method_type, id(value.bound_self), id(value.function),
                id(value.callable_value),
            )
        # Other retained objects have their own exact verification.  The root
        # nevertheless binds their original identity so it cannot self-validate
        # a replacement object and replacement method table.
        return (type(value), id(value))

    def root_seal(root: Any) -> tuple[Any, ...]:
        if not is_dataclass(root):
            _fail("private authority root is not an exact dataclass")
        return (type(root), id(root), tuple(
            (item.name, seal_value(getattr(root, item.name))) for item in fields(root)))

    def install(owner: Any, root: Any) -> None:
        nonlocal next_nonce
        with lock:
            owner_id = id(owner)
            current = roots.get(owner_id)
            if current is not None and current[0]() is owner:
                _fail("private authority root was installed more than once")
            next_nonce += 1
            nonce = next_nonce
            # A callback-bearing weakref would itself expose a closure leading
            # back to this authority registry through ordinary weakref APIs.
            # Stale entries are instead rejected/overwritten by exact referent
            # identity and the monotonic installation nonce.
            reference = weakref.ref(owner)
            roots[owner_id] = (reference, nonce, root,
                               (nonce, root_seal(root)))

    def lookup(owner: Any, expected: type) -> Any:
        with lock:
            entry = roots.get(id(owner))
            if entry is None or entry[0]() is not owner:
                raise CapabilityIpcError(
                    "capability object has no retained private authority")
            _reference, nonce, root, seal = entry
            if (type(root) is not expected or seal != (nonce, root_seal(root))):
                _fail("private authority root or construction dependency was substituted")
            return root

    return install, lookup


_INSTALL_PRIVATE_AUTHORITY, _LOOKUP_PRIVATE_AUTHORITY = _make_private_authority_store()


def _session_authority(session: Any) -> _SessionAuthorities:
    return _LOOKUP_PRIVATE_AUTHORITY(session, _SessionAuthorities)


@dataclass(frozen=True)
class _Outstanding:
    lease: OperationLease
    policy: OperationPolicy
    generation: int


def _serialized(method: Callable[..., Any]) -> Callable[..., Any]:
    def guarded(self: Any, *args: Any, **kwargs: Any) -> Any:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        caller = threading.get_ident()
        if dynamic.entry_owner == caller:
            _fail("reentrant capability IPC entry is not permitted")
        if not authority.entry_lock.acquire(blocking=False):
            _fail("concurrent capability IPC entry is not permitted")
        dynamic.entry_owner = caller
        try:
            return method(self, *args, **kwargs)
        finally:
            try:
                self._honor_terminal_request()
            finally:
                dynamic.entry_owner = None
                authority.entry_lock.release()
    guarded.__name__ = method.__name__
    guarded.__doc__ = method.__doc__
    return guarded


class _SessionBase:
    __slots__ = ("__weakref__",)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("capability session storage is private and read-only")

    def __copy__(self) -> NoReturn:
        _fail("capability sessions cannot be copied or aliased")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        _fail("capability sessions cannot be copied or aliased")

    def __reduce__(self) -> NoReturn:
        _fail("capability sessions cannot be serialized or reconstructed")

    def __reduce_ex__(self, _protocol: int) -> NoReturn:
        _fail("capability sessions cannot be serialized or reconstructed")

    def __getstate__(self) -> NoReturn:
        _fail("capability sessions expose no serializable state")

    @property
    def binding(self) -> CapabilityBinding:
        return _session_authority(self).binding

    @property
    def state(self) -> str:
        return _session_authority(self).dynamic.state

    @property
    def cleanup_obligations(self) -> tuple[str, ...]:
        return _session_authority(self).dynamic.cleanup_obligations

    def _initialize(self, *, binding: CapabilityBinding,
                    resources: tuple[RetainedCapability, ...], owner_handle: Any,
                    handle_authority: HandleAuthority, transport: PacketTransport,
                    epoch_admission: SessionEpochAdmissionAuthority,
                    clock: Clock, crypto: CryptoProvider, session_key: bytes,
                    expected_side: str,
                    operation_owner: OperationOwnerAuthority | None = None,
                    operation_owner_binding: OperationOwnerBinding | None = None,
                    callback_drain: CallbackDrainAuthority | None = None,
                    allow_unproven_transport_for_tests: bool = False,
                    _real_transport_implemented: bool = REAL_TRANSPORT_IMPLEMENTED,
                    _real_epoch_implemented: bool = REAL_EPOCH_ADMISSION_IMPLEMENTED,
                    _epoch_claim: Callable[[SessionEpochBinding, Any, str], None] =
                    _CLAIM_SESSION_EPOCH) -> None:
        _exact(allow_unproven_transport_for_tests, bool, "test-only transport admission flag")
        if not _real_transport_implemented and not allow_unproven_transport_for_tests:
            _fail("real worker capability transport is unavailable")
        if not _real_epoch_implemented and not allow_unproven_transport_for_tests:
            _fail("real one-shot session epoch admission is unavailable")
        if any(item is None for item in (
                binding, owner_handle, handle_authority, transport, epoch_admission,
                clock, crypto, session_key)):
            _fail("all retained capability IPC authorities are required")
        _exact(binding, CapabilityBinding, "capability binding")
        _exact(binding.session_epoch, SessionEpochBinding, "session epoch binding")
        _exact(session_key, bytes, "HMAC session key")
        if type(resources) is not tuple:
            _fail("retained capabilities are not an exact tuple")
        if type(expected_side) is not str or expected_side not in {"parent", "child"}:
            _fail("session side is outside the exact endpoint registry")
        if ((expected_side == "parent") != (operation_owner is not None) or
                (expected_side == "parent") != (operation_owner_binding is not None) or
                (expected_side == "child") != (callback_drain is not None)):
            _fail("session lifecycle authorities differ from the exact endpoint role")

        method_names = (
            (handle_authority, ("identity",)),
            (transport, ("binding", "verify", "send", "receive", "seal_send",
                         "verify_send_sealed", "revoke", "verify_quiescent")),
            (clock, ("now_ns",)),
            (crypto, ("challenge", "sha256", "hmac_sha256", "compare_digest")),
            (epoch_admission, ("binding", "admit", "verify_admitted", "revoke",
                               "verify_revoked")),
        )
        methods = tuple(_MethodBinding.capture(owner, name)
                        for owner, names in method_names for name in names)
        if operation_owner is not None:
            methods += tuple(_MethodBinding.capture(operation_owner, name) for name in (
                "binding", "verify", "admit", "settle", "revoke", "verify_quiescent"))
        if callback_drain is not None:
            methods += (_MethodBinding.capture(callback_drain, "verify_drained"),)
        for method in methods:
            method.verify()
        crypto_methods = tuple(method for method in methods if method.owner is crypto)
        secure_crypto = _RetainedCrypto(crypto, crypto_methods)

        binding.validate(secure_crypto)
        if (binding.real_transport and not _real_transport_implemented) or (
                not binding.real_transport and not allow_unproven_transport_for_tests):
            _fail("transport reality is unproven for this admission mode")
        if len(session_key) < 32 or _digest_hex(secure_crypto, session_key) != binding.key_id:
            _fail("HMAC session key does not match its immutable binding")
        policy = factory_policy(binding.factory_id)
        if tuple(item.identity for item in resources) != binding.resources:
            _fail("retained capabilities differ from immutable resource binding")
        retained_objects: list[Any] = [owner_handle]
        snapshots: list[tuple[RetainedCapability, HandleIdentity, Any]] = []
        for item, expected_id in zip(resources, policy.resource_ids):
            item.validate(expected_id)
            retained_objects.append(item.handle)
            snapshots.append((item, item.identity, item.handle))
        if len({id(item) for item in retained_objects}) != len(retained_objects):
            _fail("owner and resource capabilities alias the same retained object")
        transport_side = _provider_attribute(
            transport, "side", "packet transport endpoint role")
        if type(transport_side) is not str or transport_side != expected_side:
            _fail("packet transport endpoint has the wrong parent/child role")
        transport_binding_method = next(
            method for method in methods
            if method.owner is transport and method.name == "binding")
        transport_binding = _provider_result_value(
            _invoke_provider_no_throw(transport_binding_method.resolve(), ()),
            "packet transport binding provider")
        _exact(transport_binding, TransportBinding, "current transport binding")
        if transport_binding is not binding.transport or transport_binding != binding.transport:
            _fail("packet transport identity differs from immutable binding")
        epoch_binding_method = next(
            method for method in methods
            if method.owner is epoch_admission and method.name == "binding")
        epoch_binding = _provider_result_value(
            _invoke_provider_no_throw(epoch_binding_method.resolve(), ()),
            "session epoch binding provider")
        _exact(epoch_binding, SessionEpochBinding, "current session epoch binding")
        if epoch_binding is not binding.session_epoch or epoch_binding != binding.session_epoch:
            _fail("session epoch authority differs from immutable capability binding")
        epoch_binding.validate(
            session_id=binding.session_id, factory_id=binding.factory_id,
            role=binding.role, owner_object_id=binding.owner.object_id)

        binding_digest = _binding_sha256(binding, secure_crypto)
        dynamic = _SessionDynamic(binding_digest, epoch_binding.epoch_id)
        authority = _SessionAuthorities(
            binding, canonical_json(binding.wire()),
            binding_digest, policy,
            _factory_policy_signature(policy),
            _digest_hex(secure_crypto, canonical_json(policy.wire())), resources,
            tuple(snapshots), owner_handle, handle_authority, transport, clock,
            crypto, secure_crypto, session_key, threading.Lock(), expected_side,
            epoch_admission, epoch_binding, operation_owner,
            operation_owner_binding, callback_drain, methods, dynamic)
        _INSTALL_PRIVATE_AUTHORITY(self, authority)
        claimed = False
        dynamic.cleanup_obligations = ("session epoch admission dispatch pending",)
        try:
            claim_result = _epoch_claim(epoch_binding, epoch_admission, expected_side)
            claimed = True
            if claim_result is not None:
                _fail("session epoch claim returned unexpected data")
            if authority.call(epoch_admission, "admit", epoch_binding, expected_side) is not None:
                _fail("session epoch admission returned unexpected data")
            if authority.call(
                    epoch_admission, "verify_admitted", epoch_binding,
                    expected_side) is not None:
                _fail("session epoch verification returned unexpected data")
            self._verify_authorities()
            if self._now() >= self.binding.absolute_deadline_ns:
                _fail("capability session absolute deadline is already expired")
            dynamic.cleanup_obligations = ()
        except BaseException as cause:
            cause_code = _primitive_failure_code(cause)
            dynamic.terminal_requested.set()
            dynamic.generation += 1
            dynamic.state = "REVOKED"
            obligations: list[str] = []
            if claimed:
                try:
                    if authority.cleanup_call(
                            epoch_admission, "revoke", epoch_binding,
                            expected_side) is not None:
                        _fail("session epoch revocation returned unexpected data")
                    if authority.cleanup_call(
                            epoch_admission, "verify_revoked", epoch_binding,
                            expected_side) is not None:
                        _fail("session epoch revocation proof returned unexpected data")
                except BaseException as cleanup_error:
                    cleanup_code = _primitive_failure_code(cleanup_error)
                    obligations.append(
                        "ambiguous session epoch admission is not revoked (" +
                        cleanup_code + ")")
            if obligations:
                dynamic.cleanup_obligations = tuple(obligations)
                dynamic.state = "QUIESCENCE_UNCERTAIN"
                raise CapabilityQuiescenceError(
                    "session admission failed and quiescence is not proven (" +
                    cause_code + ")") from None
            dynamic.cleanup_obligations = ()
            raise CapabilityIpcError(
                "session admission failed (" + cause_code + ")") from None

    def _now(self) -> int:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        value = authority.call(authority.clock, "now_ns")
        if type(value) is not int or value < 0 or value < dynamic.last_now:
            _fail("capability IPC monotonic clock regressed or is inexact")
        dynamic.last_now = value
        return value

    def _check_deadline(self, deadline_ns: int) -> None:
        now = self._now()
        if (type(deadline_ns) is not int or
                not now < deadline_ns <= self.binding.absolute_deadline_ns):
            _fail("operation absolute deadline is expired, inexact, or rebased")

    def _verify_authority_integrity(self) -> None:
        """Verify immutable whole-session authority without live handle probes.

        Operation callbacks call this form because their capability is scoped to
        the operation's exact resource tuple.  Live identity probes for the
        owner and every retained resource are reserved for explicit session
        admission/terminal boundaries in ``_verify_authorities``.
        """

        authority = _session_authority(self)
        dynamic = authority.dynamic
        dynamic.verify(authority.binding_digest, authority.epoch_binding.epoch_id)
        for method in authority.methods:
            method.verify()
        if (dynamic.terminal_requested.is_set() and
                dynamic.state not in {"REVOKED", "QUIESCENCE_UNCERTAIN"}):
            _fail("session has a pending terminal generation request")
        if (type(authority.binding) is not CapabilityBinding or
                canonical_json(authority.binding.wire()) != authority.binding_wire or
                _binding_sha256(authority.binding, authority.secure_crypto) !=
                authority.binding_digest):
            _fail("private capability binding storage was substituted")
        authority.binding.validate(authority.secure_crypto)
        canonical_policy = factory_policy(authority.binding.factory_id)
        if (canonical_policy is not authority.policy or
                _factory_policy_signature(authority.policy) != authority.policy_signature or
                _digest_hex(authority.secure_crypto, canonical_json(authority.policy.wire())) !=
                authority.policy_digest or
                authority.policy_digest != authority.binding.operation_table_sha256):
            _fail("private factory policy storage differs from its authenticated canonical table")
        if (type(authority.key) is not bytes or len(authority.key) < 32 or
                _digest_hex(authority.secure_crypto, authority.key) != authority.binding.key_id):
            _fail("private HMAC key storage differs from immutable binding")
        transport_side = _provider_attribute(
            authority.transport, "side", "retained transport endpoint role")
        if (type(transport_side) is not str or
                transport_side != authority.expected_side):
            _fail("retained transport endpoint role was substituted")
        current_epoch = authority.call(authority.epoch_admission, "binding")
        _exact(current_epoch, SessionEpochBinding, "current session epoch binding")
        if current_epoch is not authority.epoch_binding or current_epoch != authority.epoch_binding:
            _fail("retained session epoch binding drifted or was substituted")
        if not dynamic.terminal_requested.is_set():
            if authority.call(
                    authority.epoch_admission, "verify_admitted",
                    authority.epoch_binding, authority.expected_side) is not None:
                _fail("session epoch verification returned unexpected data")
        elif dynamic.state == "REVOKED":
            if authority.call(
                    authority.epoch_admission, "verify_revoked",
                    authority.epoch_binding, authority.expected_side) is not None:
                _fail("session epoch revocation proof returned unexpected data")

        if (len(authority.resource_snapshots) != len(authority.resources) or
                tuple(item for item, _identity, _handle in authority.resource_snapshots) !=
                authority.resources):
            _fail("private retained resource storage was substituted")
        for retained, expected, retained_handle in authority.resource_snapshots:
            if (retained.identity is not expected or retained.identity != expected or
                    retained.handle is not retained_handle):
                _fail("private retained resource object was substituted")
        if authority.call(
                authority.transport, "verify", authority.binding.transport) is not None:
            _fail("transport verification returned unexpected data")
        current_transport = authority.call(authority.transport, "binding")
        _exact(current_transport, TransportBinding, "current transport binding")
        if (current_transport is not authority.binding.transport or
                current_transport != authority.binding.transport):
            _fail("packet transport identity drifted")

    def _verify_live_resource_identity(
            self, retained: RetainedCapability, expected: HandleIdentity,
            retained_handle: Any) -> None:
        authority = _session_authority(self)
        if (type(retained) is not RetainedCapability or
                type(expected) is not HandleIdentity or
                retained.identity is not expected or
                retained.handle is not retained_handle):
            _fail("live resource identity request is outside retained storage")
        current = authority.call(
            authority.handle_authority, "identity", retained_handle)
        _exact(current, HandleIdentity, "current retained resource identity")
        current.validate(expected_id=expected.capability_id, expected_kind="resource")
        if current is not expected or current != expected:
            _fail("preopened resource handle identity is stale or reused")

    def _verify_authorities(self) -> None:
        """Full live session attestation for admission and terminal boundaries."""

        self._verify_authority_integrity()
        authority = _session_authority(self)
        owner = authority.call(
            authority.handle_authority, "identity", authority.owner_handle)
        _exact(owner, HandleIdentity, "current owner identity")
        owner.validate(expected_id="parent_owner", expected_kind="owner")
        if owner is not authority.binding.owner or owner != authority.binding.owner:
            _fail("parent-retained owner identity is stale or reused")
        for retained, expected, retained_handle in authority.resource_snapshots:
            self._verify_live_resource_identity(
                retained, expected, retained_handle)

    def _check_generation(self, generation: int, expected_state: str) -> None:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        dynamic.verify(authority.binding_digest, authority.epoch_binding.epoch_id)
        if (dynamic.terminal_requested.is_set() or dynamic.generation != generation or
                dynamic.state != expected_state):
            _fail("session generation is terminal, stale, or substituted")

    def _honor_terminal_request(self) -> None:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        if (authority.expected_side == "child" and dynamic.terminal_requested.is_set() and
                dynamic.state not in {"REVOKED", "QUIESCENCE_UNCERTAIN"}):
            self._abort_active("terminal_requested")
            raise CapabilityIpcError(
                "concurrent stale child action requested terminal revocation") from None

    def _enter_child_action(self, generation: int) -> None:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        caller = threading.get_ident()
        if (dynamic.entry_owner == caller or
                not authority.entry_lock.acquire(blocking=False)):
            dynamic.terminal_requested.set()
            _fail("concurrent or reentrant child operation action is not permitted")
        dynamic.entry_owner = caller
        try:
            self._check_generation(generation, "ACTIVE")
        except BaseException as error:
            failure_code = _primitive_failure_code(error)
            dynamic.terminal_requested.set()
            try:
                if dynamic.state not in {"REVOKED", "QUIESCENCE_UNCERTAIN"}:
                    self._abort_active(failure_code)
            finally:
                dynamic.entry_owner = None
                authority.entry_lock.release()
            raise CapabilityIpcError(
                "child action admission failed (" + failure_code + ")") from None

    def _leave_child_action(self) -> None:
        authority = _session_authority(self)
        try:
            self._honor_terminal_request()
        finally:
            authority.dynamic.entry_owner = None
            authority.entry_lock.release()

    def _new_quiescence_round(
            self, *, request_id: str | None, generation: int, phase: str,
            participants: tuple[tuple[str, str], ...]) -> QuiescenceChallenge:
        """Mint a fresh proof round while the session generation lock is held."""

        authority = _session_authority(self)
        dynamic = authority.dynamic
        if request_id is not None:
            _hex64(request_id, "quiescence request")
        _positive_int(generation, "quiescence generation", allow_zero=True)
        if generation != dynamic.generation:
            _fail("quiescence proof generation is stale")
        _token(phase, "quiescence phase")
        if type(participants) is not tuple or not participants:
            _fail("quiescence proof participant set is not an exact nonempty tuple")
        for item in participants:
            if (type(item) is not tuple or len(item) != 2 or
                    type(item[0]) is not str or
                    item[0] not in _QUIESCENCE_COMPONENTS):
                _fail("quiescence proof participant is inexact")
            _hex64(item[1], "quiescence proof participant binding")
        if tuple(sorted(participants)) != participants:
            _fail("quiescence proof participant set is not sorted")
        nonce = _crypto_bytes(
            authority.secure_crypto.challenge(32),
            "quiescence challenge provider").hex()
        dynamic.add_challenge_nonce(nonce)
        provisional = QuiescenceChallenge(
            QUIESCENCE_CHALLENGE_AUTHORITY, authority.binding_digest,
            authority.epoch_binding.epoch_id, authority.expected_side, phase,
            request_id, generation, nonce, participants, "0" * 64)
        challenge_id = _digest_hex(
            authority.secure_crypto,
            b"rtl-reader-worker-quiescence-round-v1\x00" +
            canonical_json(provisional.wire(include_id=False)))
        if challenge_id in dynamic.challenges:
            _fail("quiescence challenge was replayed")
        dynamic.add_challenge(challenge_id)
        challenge = QuiescenceChallenge(
            provisional.authority, provisional.binding_sha256,
            provisional.session_epoch, provisional.side, provisional.phase,
            provisional.request_id, provisional.generation, provisional.nonce,
            provisional.participants, challenge_id)
        challenge.validate(authority.secure_crypto)
        return challenge

    def _validate_quiescence_round(
            self, challenge: QuiescenceChallenge,
            receipts: tuple[QuiescenceReceipt, ...], generation: int,
            request_id: str | None) -> None:
        """Locally commit only one receipt for every exact round participant."""

        authority = _session_authority(self)
        dynamic = authority.dynamic
        if (type(challenge) is not QuiescenceChallenge or
                challenge.binding_sha256 != authority.binding_digest or
                challenge.session_epoch != authority.epoch_binding.epoch_id or
                challenge.side != authority.expected_side or
                challenge.request_id != request_id or
                challenge.generation != generation or
                type(receipts) is not tuple or
                len(receipts) != len(challenge.participants)):
            _fail("quiescence round differs from the retained session generation")
        seen: set[str] = set()
        for receipt in receipts:
            if (type(receipt) is not QuiescenceReceipt or
                    type(receipt.component) is not str):
                _fail("quiescence receipt set contains a substituted scalar")
            if receipt.component in seen:
                _fail("quiescence receipt set is substituted or duplicated")
            receipt.validate(challenge, receipt.component)
            seen.add(receipt.component)
        if seen != {name for name, _digest in challenge.participants}:
            _fail("quiescence receipt set is incomplete or contains an extra authority")
        challenge._seal_fence()
        # No external callbacks occur after this comparison and before the
        # caller's local state transition.  A real adapter is required to bind
        # each typed receipt to this shared generation (see the class contract).
        dynamic.verify(authority.binding_digest, authority.epoch_binding.epoch_id)
        if dynamic.generation != generation:
            _fail("quiescence proof raced a session generation transition")

    def _verify_callback_drain(self, drain: CallbackDrainAuthority,
                               binding: CallbackBinding) -> None:
        authority = _session_authority(self)
        if (authority.expected_side != "child" or authority.callback_drain is not drain or
                type(binding) is not CallbackBinding or
                binding.session_epoch != authority.epoch_binding.epoch_id):
            _fail("callback drain differs from its immutable operation epoch authority")
        binding.validate()
        for method in authority.methods:
            if method.owner is drain and method.name == "verify_drained":
                method.verify()
                return
        _fail("callback drain authority is not retained")

    def _check_frame_common(self, header: dict[str, Any], lease: OperationLease,
                            message_sequence: int) -> str:
        lease.validate()
        exact = {
            "authority": AUTHORITY, "binding_sha256": lease.binding_sha256,
            "challenge": lease.challenge, "deadline_ns": lease.deadline_ns,
            "factory_id": self.binding.factory_id, "message_sequence": message_sequence,
            "operation_id": lease.operation_id, "owner_object_id": lease.owner_object_id,
            "request_id": lease.request_id, "role": self.binding.role,
            "sequence": lease.sequence, "session_epoch": lease.session_epoch,
            "session_id": lease.session_id,
            "version": PROTOCOL_VERSION,
        }
        for name, expected in exact.items():
            value = header.get(name)
            if type(value) is not type(expected) or value != expected:
                _fail("authenticated frame " + name + " is stale, replayed, or substituted")
        kind = header.get("kind")
        if type(kind) is not str or kind not in _FRAME_KINDS:
            _fail("authenticated frame kind is invalid")
        if type(header.get("body")) is not dict:
            _fail("authenticated frame body is not an exact object")
        if type(header.get("payload_bytes")) is not int:
            _fail("authenticated payload size is inexact")
        _hex64(header.get("payload_sha256"), "authenticated payload digest")
        return kind

    def _revoke(self, request_id: str | None, deadline_ns: int,
                failure_code: str) -> None:
        _validate_failure_code(failure_code)
        authority = _session_authority(self)
        dynamic = authority.dynamic
        dynamic.terminal_requested.set()
        dynamic.generation += 1
        dynamic.state = "REVOKED"
        obligations: list[str] = []
        operation_owner = authority.operation_owner
        owner_binding = authority.operation_owner_binding
        callback_binding = dynamic.last_callback_binding
        challenge: QuiescenceChallenge | None = None
        try:
            participant_values: list[tuple[str, str]] = [
                ("transport", authority.binding.transport_binding_sha256)]
            if operation_owner is not None and owner_binding is not None:
                participant_values.append((
                    "operation_owner",
                    _operation_owner_binding_digest(
                        owner_binding, authority.secure_crypto)))
            if authority.callback_drain is not None and callback_binding is not None:
                participant_values.append((
                    "callback_drain",
                    _callback_binding_digest(
                        callback_binding, authority.secure_crypto)))
            challenge = self._new_quiescence_round(
                request_id=request_id, generation=dynamic.generation,
                phase=authority.expected_side + ".revoke",
                participants=tuple(sorted(participant_values)))
        except BaseException as error:
            obligations.append(
                "terminal quiescence round could not be minted (" +
                _primitive_failure_code(error) + ")")

        # First issue every fixed revocation while keeping an exact pending
        # obligation.  Proofs are collected only after all revocations and bind
        # the same request, session generation, and participant set.
        if operation_owner is not None and owner_binding is not None:
            try:
                if authority.cleanup_call(
                        operation_owner, "revoke", authority.owner_handle, owner_binding,
                        request_id, deadline_ns) is not None:
                    _fail("operation owner revoke returned unexpected data")
            except BaseException as error:
                obligations.append(
                    "retained operation owner revocation failed (" +
                    _primitive_failure_code(error) + ")")
        try:
            if authority.cleanup_call(
                    authority.transport, "revoke", request_id, deadline_ns) is not None:
                _fail("transport revoke returned unexpected data")
        except BaseException as error:
            obligations.append(
                "transport revocation failed (" +
                _primitive_failure_code(error) + ")")
        try:
            if authority.cleanup_call(
                    authority.epoch_admission, "revoke", authority.epoch_binding,
                    authority.expected_side) is not None:
                _fail("session epoch revocation returned unexpected data")
            if authority.cleanup_call(
                    authority.epoch_admission, "verify_revoked", authority.epoch_binding,
                    authority.expected_side) is not None:
                _fail("session epoch revocation proof returned unexpected data")
        except BaseException as error:
            obligations.append(
                "session epoch revocation is not proven (" +
                _primitive_failure_code(error) + ")")

        receipts: list[QuiescenceReceipt] = []
        if challenge is not None:
            if operation_owner is not None and owner_binding is not None:
                try:
                    receipt = authority.cleanup_call(
                        operation_owner, "verify_quiescent", authority.owner_handle,
                        owner_binding, request_id, challenge)
                    _exact(receipt, QuiescenceReceipt,
                           "operation owner quiescence receipt")
                    receipt.validate(challenge, "operation_owner")
                    receipts.append(receipt)
                except BaseException as error:
                    obligations.append(
                        "retained operation owner is not quiescent (" +
                        _primitive_failure_code(error) + ")")
            if authority.callback_drain is not None and callback_binding is not None:
                try:
                    receipt = authority.cleanup_call(
                        authority.callback_drain, "verify_drained",
                        callback_binding, challenge)
                    _exact(receipt, QuiescenceReceipt,
                           "callback drain quiescence receipt")
                    receipt.validate(challenge, "callback_drain")
                    receipts.append(receipt)
                except BaseException as error:
                    obligations.append(
                        "callback producers are not quiescent (" +
                        _primitive_failure_code(error) + ")")
            try:
                receipt = authority.cleanup_call(
                    authority.transport, "verify_quiescent", request_id, challenge)
                _exact(receipt, QuiescenceReceipt,
                       "transport quiescence receipt")
                receipt.validate(challenge, "transport")
                receipts.append(receipt)
            except BaseException as error:
                obligations.append(
                    "transport quiescence is not proven (" +
                    _primitive_failure_code(error) + ")")
            if not obligations:
                try:
                    self._validate_quiescence_round(
                        challenge, tuple(receipts), dynamic.generation, request_id)
                except BaseException as error:
                    obligations.append(
                        "terminal quiescence receipt set is invalid (" +
                        _primitive_failure_code(error) + ")")
        if obligations:
            dynamic.state = "QUIESCENCE_UNCERTAIN"
            dynamic.cleanup_obligations = tuple(obligations)
            raise CapabilityQuiescenceError(
                "capability IPC failed and terminal quiescence is not proven (" +
                failure_code + ")") from None
        dynamic.cleanup_obligations = ()
        dynamic.terminal_receipt = _TerminalReceipt(
            authority.binding_digest, authority.epoch_binding.epoch_id,
            request_id, dynamic.generation, "revoked")


class ParentCapabilitySession(_SessionBase):
    """Parent-retained owner of one-at-a-time fixed worker operations."""

    __slots__ = ()

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        _fail("parent capability sessions cannot be subclassed")

    def __init__(self, *, binding: CapabilityBinding,
                 resources: tuple[RetainedCapability, ...], owner_handle: Any,
                 handle_authority: HandleAuthority,
                 operation_owner: OperationOwnerAuthority,
                 transport: PacketTransport,
                 epoch_admission: SessionEpochAdmissionAuthority,
                 clock: Clock, crypto: CryptoProvider, session_key: bytes,
                 allow_unproven_transport_for_tests: bool = False):
        if operation_owner is None:
            _fail("retained operation owner authority is required")
        expected_owner = make_operation_owner_binding(binding, crypto)
        current_owner = _call_unretained_provider(
            operation_owner, "binding", owner_handle)
        _exact(current_owner, OperationOwnerBinding, "current operation owner binding")
        current_owner.validate(binding, crypto)
        if current_owner is not expected_owner and current_owner != expected_owner:
            _fail("retained operation owner binding is substituted")
        self._initialize(
            binding=binding, resources=resources, owner_handle=owner_handle,
            handle_authority=handle_authority, transport=transport, clock=clock,
            crypto=crypto, session_key=session_key, expected_side="parent",
            epoch_admission=epoch_admission, operation_owner=operation_owner,
            operation_owner_binding=current_owner,
            allow_unproven_transport_for_tests=allow_unproven_transport_for_tests)
        self._verify_operation_owner()

    def _verify_operation_owner(self) -> None:
        authority = _session_authority(self)
        owner = authority.operation_owner
        owner_binding = authority.operation_owner_binding
        if owner is None or owner_binding is None:
            _fail("retained operation owner authority is absent")
        if authority.call(owner, "verify", owner_binding) is not None:
            _fail("operation owner verification returned unexpected data")
        current = authority.call(owner, "binding", authority.owner_handle)
        _exact(current, OperationOwnerBinding, "current operation owner binding")
        current.validate(authority.binding, authority.secure_crypto)
        if current is not owner_binding or current != owner_binding:
            _fail("retained operation owner binding drifted or was substituted")

    @_serialized
    def begin(self, operation_id: str, payload: dict[str, Any],
              deadline_ns: int) -> OperationLease:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        if self.state != "OPEN" or dynamic.outstanding is not None:
            _fail("capability session already has an outstanding or terminal operation")
        policy = authority.policy.operation(operation_id)
        _exact(payload, dict, "operation request payload")
        if tuple(sorted(payload)) != policy.request_fields:
            _fail("request payload fields differ from immutable operation policy")
        try:
            self._verify_authorities()
            self._verify_operation_owner()
            self._check_deadline(deadline_ns)
            if dynamic.sequence >= MAX_SESSION_REQUESTS:
                _fail("capability session request sequence is exhausted")
            nonce = _crypto_bytes(
                authority.secure_crypto.challenge(32), "challenge provider").hex()
            if nonce in dynamic.challenge_nonces:
                _fail("challenge provider repeated a prior request challenge")
            sequence = dynamic.sequence + 1
            challenge = _challenge_id(
                authority.secure_crypto, authority.binding_digest,
                self.binding.session_epoch.epoch_id, nonce, sequence)
            if challenge in dynamic.challenges:
                _fail("derived request challenge repeated within the retained epoch")
            dynamic.add_challenge_nonce(nonce)
            dynamic.add_challenge(challenge)
            dynamic.sequence = sequence
            request_id = _request_id(
                authority.secure_crypto, authority.binding_digest,
                self.binding.session_epoch.epoch_id, challenge, deadline_ns,
                operation_id, sequence)
            lease = OperationLease(
                LEASE_AUTHORITY, authority.binding_digest, authority.binding.session_id,
                self.binding.session_epoch.epoch_id, sequence, operation_id,
                request_id, challenge, deadline_ns, self.binding.owner.object_id)
            lease.validate()
            detached = DetachedPayload.from_value(
                payload, authority.secure_crypto, MAX_PAYLOAD_BYTES)
            packet = _make_packet(
                binding=self.binding, sequence=lease.sequence, message_sequence=0,
                kind="request", operation_id=operation_id, request_id=request_id,
                challenge=challenge, deadline_ns=deadline_ns, body={},
                payload=detached.canonical, key=authority.key,
                crypto=authority.secure_crypto)
            generation = dynamic.generation + 1
            dynamic.generation = generation
            dynamic.outstanding = _Outstanding(lease, policy, generation)
            dynamic.state = "OUTSTANDING"
            owner = authority.operation_owner
            owner_binding = authority.operation_owner_binding
            if owner is None or owner_binding is None:
                _fail("retained operation owner authority is absent")
            if authority.call(
                    owner, "admit", authority.owner_handle,
                    owner_binding, lease) is not None:
                _fail("operation owner admission returned unexpected data")
            self._verify_operation_owner()
            if authority.call(authority.transport, "send", packet, deadline_ns) is not None:
                _fail("request transport send returned unexpected data")
            self._check_deadline(deadline_ns)
            self._verify_authorities()
            self._verify_operation_owner()
            self._check_generation(generation, "OUTSTANDING")
        except BaseException as error:
            failure_code = _primitive_failure_code(error)
            dynamic.outstanding = None
            failed_request = request_id if "request_id" in locals() else None
            self._revoke(failed_request, deadline_ns, failure_code)
            raise CapabilityIpcError(
                "parent operation admission failed (" + failure_code + ")") from None
        return lease

    @_serialized
    def settle(self, lease: OperationLease) -> OperationOutcome:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        if (self.state != "OUTSTANDING" or dynamic.outstanding is None or
                type(lease) is not OperationLease or
                lease is not dynamic.outstanding.lease):
            _fail("only the exact parent-retained outstanding operation may be settled")
        outstanding = dynamic.outstanding
        callbacks: list[CallbackRecord] = []
        barrier = False
        result: DetachedPayload | None = None
        child_drain_proof: tuple[
            QuiescenceChallenge, tuple[QuiescenceReceipt, ...]] | None = None
        expected_message = 1
        try:
            while True:
                self._check_deadline(lease.deadline_ns)
                self._verify_authorities()
                self._verify_operation_owner()
                self._check_generation(outstanding.generation, "OUTSTANDING")
                packet = authority.call(
                    authority.transport, "receive", lease.deadline_ns)
                if packet is None:
                    _fail("unauthenticated transport EOF revoked the outstanding operation")
                self._check_deadline(lease.deadline_ns)
                self._verify_authorities()
                self._verify_operation_owner()
                header, raw_payload = _open_packet(
                    packet, key=authority.key, crypto=authority.secure_crypto)
                kind = self._check_frame_common(header, lease, expected_message)
                body = header["body"]
                if kind == "callback":
                    if barrier or result is not None:
                        _fail("callback arrived after its authenticated barrier")
                    if set(body) != {"event", "ordinal"}:
                        _fail("callback frame body has missing or extra fields")
                    ordinal, event = body["ordinal"], body["event"]
                    if (type(ordinal) is not int or ordinal != len(callbacks) + 1 or
                            type(event) is not str or event not in outstanding.policy.callback_events or
                            len(callbacks) >= outstanding.policy.max_callbacks):
                        _fail("callback is reordered, unregistered, or exceeds policy")
                    detached = DetachedPayload.from_wire(
                        raw_payload, authority.secure_crypto,
                        outstanding.policy.max_callback_bytes)
                    callback_binding = CallbackBinding(
                        CALLBACK_AUTHORITY, lease.binding_sha256, lease.session_id,
                        lease.session_epoch, lease.sequence, lease.operation_id,
                        lease.request_id, lease.challenge, lease.deadline_ns,
                        lease.owner_object_id,
                        outstanding.policy.callback_events, outstanding.policy.max_callbacks,
                        outstanding.policy.max_callback_bytes)
                    callback_binding.validate()
                    callbacks.append(CallbackRecord(callback_binding, ordinal, event, detached))
                elif kind == "barrier":
                    if barrier or result is not None or raw_payload != b"" or set(body) != {"callback_count"}:
                        _fail("callback barrier is duplicated, malformed, or out of order")
                    if type(body["callback_count"]) is not int or body["callback_count"] != len(callbacks):
                        _fail("callback barrier count differs from the drained callback stream")
                    barrier = True
                elif kind == "reply":
                    if (not barrier or result is not None or
                            set(body) != {"callback_drain_proof", "status"} or
                            body["status"] != "ok"):
                        _fail("operation result arrived before its exact barrier or was duplicated")
                    proof_challenge, proof_receipts = _open_quiescence_proof(
                        body["callback_drain_proof"], authority.secure_crypto)
                    callback_binding = CallbackBinding(
                        CALLBACK_AUTHORITY, lease.binding_sha256, lease.session_id,
                        lease.session_epoch, lease.sequence, lease.operation_id,
                        lease.request_id, lease.challenge, lease.deadline_ns,
                        lease.owner_object_id,
                        outstanding.policy.callback_events,
                        outstanding.policy.max_callbacks,
                        outstanding.policy.max_callback_bytes)
                    expected_participants = ((
                        "callback_drain",
                        _callback_binding_digest(
                            callback_binding, authority.secure_crypto)),)
                    if (proof_challenge.binding_sha256 != authority.binding_digest or
                            proof_challenge.session_epoch !=
                            authority.epoch_binding.epoch_id or
                            proof_challenge.side != "child" or
                            proof_challenge.phase != "child.publish" or
                            proof_challenge.request_id != lease.request_id or
                            proof_challenge.generation != outstanding.generation or
                            proof_challenge.participants != expected_participants or
                            len(proof_receipts) != 1):
                        _fail("child callback-drain proof differs from the outstanding request")
                    proof_receipts[0].validate(
                        proof_challenge, "callback_drain")
                    child_drain_proof = (proof_challenge, proof_receipts)
                    result = DetachedPayload.from_wire(
                        raw_payload, authority.secure_crypto,
                        outstanding.policy.max_result_bytes)
                elif kind == "eof":
                    if (not barrier or result is None or child_drain_proof is None or
                            raw_payload != b"" or body != {}):
                        _fail("authenticated EOF arrived before barrier/result or is malformed")
                    self._verify_authorities()
                    self._verify_operation_owner()
                    self._check_deadline(lease.deadline_ns)
                    owner = authority.operation_owner
                    owner_binding = authority.operation_owner_binding
                    if owner is None or owner_binding is None:
                        _fail("retained operation owner authority is absent")
                    if authority.call(
                            owner, "settle", authority.owner_handle,
                            owner_binding, lease) is not None:
                        _fail("operation owner settlement returned unexpected data")
                    # Validate every retained identity first.  Then obtain owner
                    # and transport receipts for one fresh shared round.  No
                    # external callback occurs after the local receipt-set and
                    # generation comparison and before the OPEN transition.
                    self._verify_operation_owner()
                    self._verify_authorities()
                    self._check_deadline(lease.deadline_ns)
                    # Validate the authenticated child drain witness before
                    # entering the final local owner/transport proof round.
                    # This includes the only remaining cryptographic callback.
                    child_drain_proof[0].validate(authority.secure_crypto)
                    child_drain_proof[1][0].validate(
                        child_drain_proof[0], "callback_drain")
                    participants = tuple(sorted((
                        ("operation_owner", _operation_owner_binding_digest(
                            owner_binding, authority.secure_crypto)),
                        ("transport", authority.binding.transport_binding_sha256),
                    )))
                    terminal_challenge = self._new_quiescence_round(
                        request_id=lease.request_id,
                        generation=outstanding.generation,
                        phase="parent.settle", participants=participants)
                    owner_receipt = authority.call(
                        owner, "verify_quiescent", authority.owner_handle,
                        owner_binding, lease.request_id, terminal_challenge)
                    _exact(owner_receipt, QuiescenceReceipt,
                           "operation owner quiescence receipt")
                    owner_receipt.validate(
                        terminal_challenge, "operation_owner")
                    transport_receipt = authority.call(
                        authority.transport, "verify_quiescent",
                        lease.request_id, terminal_challenge)
                    _exact(transport_receipt, QuiescenceReceipt,
                           "transport quiescence receipt")
                    transport_receipt.validate(terminal_challenge, "transport")
                    self._validate_quiescence_round(
                        terminal_challenge,
                        (owner_receipt, transport_receipt),
                        outstanding.generation, lease.request_id)
                    outcome = OperationOutcome(
                        OUTCOME_AUTHORITY, lease, result, tuple(callbacks), True, True)
                    self._check_generation(outstanding.generation, "OUTSTANDING")
                    dynamic.outstanding = None
                    dynamic.last_settled_request = lease.request_id
                    dynamic.generation += 1
                    dynamic.terminal_receipt = _TerminalReceipt(
                        authority.binding_digest, authority.epoch_binding.epoch_id,
                        lease.request_id, dynamic.generation, "settled")
                    dynamic.state = "OPEN"
                    return outcome
                elif kind == "terminal":
                    _fail("child terminal frame revoked the outstanding operation")
                else:
                    _fail("unexpected frame kind in the child result stream")
                expected_message += 1
                if expected_message > outstanding.policy.max_callbacks + 4:
                    _fail("operation result stream exceeds its exact frame bound")
        except BaseException as error:
            failure_code = _primitive_failure_code(error)
            dynamic.outstanding = None
            self._revoke(lease.request_id, lease.deadline_ns, failure_code)
            raise CapabilityIpcError(
                "parent operation settlement failed (" + failure_code + ")") from None

    @_serialized
    def cancel(self, lease: OperationLease, reason: str = "cancelled") -> None:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        if (self.state != "OUTSTANDING" or dynamic.outstanding is None or
                type(lease) is not OperationLease or
                lease is not dynamic.outstanding.lease):
            _fail("only the exact parent-retained outstanding operation may be cancelled")
        _token(reason, "terminal reason")
        try:
            self._verify_authorities()
            self._verify_operation_owner()
            self._check_generation(dynamic.outstanding.generation, "OUTSTANDING")
            packet = _make_packet(
                binding=self.binding, sequence=lease.sequence, message_sequence=1,
                kind="terminal", operation_id=lease.operation_id,
                request_id=lease.request_id, challenge=lease.challenge,
                deadline_ns=lease.deadline_ns, body={"reason": reason}, payload=b"",
                key=authority.key, crypto=authority.secure_crypto)
            if self._now() < lease.deadline_ns:
                authority.call(
                    authority.transport, "send", packet, lease.deadline_ns)
        except BaseException:
            pass
        dynamic.outstanding = None
        self._revoke(lease.request_id, lease.deadline_ns, "cancelled")

    @_serialized
    def verify_quiescent(self) -> None:
        """Nonmutating proof; it never repairs, seals, clears, or advances state."""

        authority = _session_authority(self)
        dynamic = authority.dynamic
        if (self.state not in {"OPEN", "REVOKED"} or dynamic.outstanding is not None or
                self.cleanup_obligations):
            raise CapabilityQuiescenceError("parent capability session is not exactly quiescent")
        generation = dynamic.generation
        state = self.state
        receipt = dynamic.terminal_receipt
        terminal_request = receipt.request_id if receipt is not None else None
        _verify_terminal_receipt(receipt, authority, generation, state)
        self._verify_authorities()
        self._verify_operation_owner()
        owner = authority.operation_owner
        owner_binding = authority.operation_owner_binding
        if owner is None or owner_binding is None:
            _fail("retained operation owner authority is absent")
        participants = tuple(sorted((
            ("operation_owner", _operation_owner_binding_digest(
                owner_binding, authority.secure_crypto)),
            ("transport", authority.binding.transport_binding_sha256),
        )))
        challenge = self._new_quiescence_round(
            request_id=terminal_request, generation=generation,
            phase="parent.verify", participants=participants)
        owner_receipt = authority.call(
            owner, "verify_quiescent", authority.owner_handle,
            owner_binding, terminal_request, challenge)
        _exact(owner_receipt, QuiescenceReceipt,
               "operation owner quiescence receipt")
        owner_receipt.validate(challenge, "operation_owner")
        transport_receipt = authority.call(
            authority.transport, "verify_quiescent",
            terminal_request, challenge)
        _exact(transport_receipt, QuiescenceReceipt,
               "transport quiescence receipt")
        transport_receipt.validate(challenge, "transport")
        self._validate_quiescence_round(
            challenge, (owner_receipt, transport_receipt), generation,
            terminal_request)
        if (self.state != state or dynamic.terminal_receipt is not receipt):
            _fail("quiescence proof raced a session generation transition")


class CallbackDrainAuthority(Protocol):
    def verify_drained(self, expected: CallbackBinding,
                       challenge: QuiescenceChallenge) -> QuiescenceReceipt: ...


class _ChildOperationDynamic:
    __slots__ = ("callback_count", "callbacks_sealed", "completed")

    def __init__(self) -> None:
        self.callback_count = 0
        self.callbacks_sealed = False
        self.completed = False


@dataclass(frozen=True)
class _ChildOperationAuthorities:
    child: "ChildCapabilitySession"
    lease: OperationLease
    policy: OperationPolicy
    request: DetachedPayload
    resources: tuple[RetainedCapability, ...]
    resource_snapshots: tuple[tuple[RetainedCapability, HandleIdentity, Any], ...]
    generation: int
    callback_binding: CallbackBinding
    dynamic: _ChildOperationDynamic


def _make_child_operation_store() -> tuple[
        Callable[[Any, _ChildOperationAuthorities], None],
        Callable[[dict[str, Callable[..., Any]]], None], Callable[..., Any],
        Callable[[Any], None]]:
    """Retain operation roots by identity behind a closed fixed dispatcher."""

    lock = threading.RLock()
    values: dict[int, tuple[weakref.ReferenceType[Any], int,
                            _ChildOperationAuthorities]] = {}
    next_nonce = 0
    handlers: MappingProxyType[str, Callable[..., Any]] | None = None

    def install(owner: Any, value: _ChildOperationAuthorities) -> None:
        nonlocal next_nonce
        if type(owner) is not ChildOperation or type(value) is not _ChildOperationAuthorities:
            _fail("child operation authority installation is substituted")
        with lock:
            owner_id = id(owner)
            current = values.get(owner_id)
            if current is not None and current[0]() is owner:
                _fail("child operation authority was installed more than once")
            next_nonce += 1
            nonce = next_nonce
            # Never attach a closure-bearing weakref callback to the
            # backend-visible handle.  Exact terminal retirement removes the
            # sensitive root; id reuse is still rejected by referent identity.
            reference = weakref.ref(owner)
            values[owner_id] = (reference, nonce, value)

    def configure(value: dict[str, Callable[..., Any]]) -> None:
        nonlocal handlers
        if (handlers is not None or type(value) is not dict or not value or
                any(type(name) is not str or not _TOKEN.fullmatch(name) or
                    not callable(handler) for name, handler in value.items())):
            _fail("child operation action table is invalid or already configured")
        handlers = MappingProxyType(dict(value))

    def dispatch(owner: Any, action: str, *args: Any) -> Any:
        if type(owner) is not ChildOperation or type(action) is not str:
            _fail("child operation handle or action is substituted")
        with lock:
            entry = values.get(id(owner))
            if entry is None or entry[0]() is not owner:
                raise CapabilityIpcError(
                    "child operation has no retained exact-identity authority")
            root = entry[2]
            table = handlers
        if table is None or action not in table:
            _fail("child operation action is outside the closed dispatch table")
        return table[action](owner, root, *args)

    def retire(owner: Any) -> None:
        if type(owner) is not ChildOperation:
            _fail("child operation retirement handle is substituted")
        with lock:
            entry = values.get(id(owner))
            if entry is None or entry[0]() is not owner:
                return
            del values[id(owner)]

    return install, configure, dispatch, retire


(_INSTALL_CHILD_OPERATION, _CONFIGURE_CHILD_OPERATION,
 _DISPATCH_CHILD_OPERATION, _RETIRE_CHILD_OPERATION) = _make_child_operation_store()


_OPAQUE_DISPATCH_FAILURE_CODES = frozenset({
    "capability", "internal", "quiescence",
})


@dataclass(frozen=True, slots=True)
class _OpaqueDispatchResult:
    """Root-free result passed from the internal dispatcher to the public frame."""

    succeeded: bool
    value: Any
    failure_code: str | None

    def __post_init__(self) -> None:
        if type(self.succeeded) is not bool:
            _fail("opaque dispatch status is inexact")
        if self.succeeded:
            if self.failure_code is not None:
                _fail("successful opaque dispatch contains a failure code")
        elif (self.value is not None or type(self.failure_code) is not str or
              self.failure_code not in _OPAQUE_DISPATCH_FAILURE_CODES):
            _fail("failed opaque dispatch result is malformed")


def _safe_child_operation_dispatch(owner: Any, action: str,
                                   *args: Any) -> _OpaqueDispatchResult:
    """Catch every internal failure and return no exception/root to the backend.

    This frame is allowed to hold the private dispatcher traceback only while it
    is executing.  It returns a closed primitive failure code, never the caught
    exception, its message, traceback, context, or any retained authority.
    """

    try:
        return _OpaqueDispatchResult(
            True, _DISPATCH_CHILD_OPERATION(owner, action, *args), None)
    except BaseException as error:
        if type(error) is CapabilityQuiescenceError:
            code = "quiescence"
        elif type(error) is CapabilityIpcError:
            code = "capability"
        else:
            code = "internal"
        # This is the final root-free boundary.  Even an unexpected internal
        # exception must not retain the private dispatcher's authority graph in
        # a traceback/context chain observable through the public exception.
        try:
            _scrub_provider_exception_graph(error)
        except BaseException as scrub_error:
            try:
                _scrub_provider_exception_graph(scrub_error)
            except BaseException:
                pass
            code = "internal"
        return _OpaqueDispatchResult(False, None, code)


def _call_child_operation(owner: Any, action: str, *args: Any) -> Any:
    """Public root-free boundary: raise only after internal frames are gone."""

    dispatch_result = _safe_child_operation_dispatch(owner, action, *args)
    if type(dispatch_result) is not _OpaqueDispatchResult:
        raise CapabilityIpcError(
            "child operation dispatch returned an inexact result") from None
    if dispatch_result.succeeded:
        return dispatch_result.value
    if dispatch_result.failure_code == "quiescence":
        raise CapabilityQuiescenceError(
            "child operation quiescence could not be proven") from None
    if dispatch_result.failure_code not in {"capability", "internal"}:
        raise CapabilityIpcError(
            "child operation dispatch returned an invalid failure code") from None
    raise CapabilityIpcError(
        "child operation failed inside the retained capability boundary (" +
        dispatch_result.failure_code + ")") from None


class ChildOperation:
    """Opaque operation-scoped handle returned to the fixed worker backend."""

    __slots__ = ("__weakref__",)

    _PUBLIC_MEMBERS = frozenset({
        "callback_count", "callbacks_sealed", "decode_request", "emit_callback",
        "operation_id", "publish_result", "required_resource_ids",
        "seal_callbacks",
    })

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        _fail("child operation handles cannot be subclassed")

    def __init__(self) -> NoReturn:
        _fail("child operation handles are minted only by an admitted child session")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("child operation handle is opaque and read-only")

    def __repr__(self) -> str:
        return "<ChildOperation opaque>"

    def __dir__(self) -> list[str]:
        return sorted(self._PUBLIC_MEMBERS | {"__class__"})

    def __copy__(self) -> NoReturn:
        _fail("child operation handles cannot be copied or aliased")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        _fail("child operation handles cannot be copied or aliased")

    def __reduce__(self) -> NoReturn:
        _fail("child operation handles cannot be serialized or reconstructed")

    def __reduce_ex__(self, _protocol: int) -> NoReturn:
        _fail("child operation handles cannot be serialized or reconstructed")

    def __getstate__(self) -> NoReturn:
        _fail("child operation handles expose no serializable state")

    @property
    def operation_id(self) -> str:
        return _call_child_operation(self, "operation_id")

    def decode_request(self) -> Any:
        return _call_child_operation(self, "decode_request")

    @property
    def required_resource_ids(self) -> tuple[str, ...]:
        return _call_child_operation(self, "required_resource_ids")

    @property
    def callback_count(self) -> int:
        return _call_child_operation(self, "callback_count")

    @property
    def callbacks_sealed(self) -> bool:
        return _call_child_operation(self, "callbacks_sealed")

    def emit_callback(self, event: str, payload: Any) -> None:
        _call_child_operation(self, "emit_callback", event, payload)

    def seal_callbacks(self) -> None:
        _call_child_operation(self, "seal_callbacks")

    def publish_result(self, result: Any) -> None:
        _call_child_operation(self, "publish_result", result)


def _new_child_operation(child: "ChildCapabilitySession", lease: OperationLease,
                         policy: OperationPolicy, request: DetachedPayload,
                         resources: tuple[RetainedCapability, ...]) -> ChildOperation:
    """Mint one opaque handle without exposing its retained authority graph."""

    if (type(child) is not ChildCapabilitySession or type(lease) is not OperationLease or
            type(policy) is not OperationPolicy or type(request) is not DetachedPayload or
            type(resources) is not tuple or
            any(type(item) is not RetainedCapability for item in resources)):
        _fail("child operation authority is substituted")
    authority = _session_authority(child)
    dynamic = authority.dynamic
    lease.validate()
    policy.validate()
    if (lease.binding_sha256 != authority.binding_digest or
            lease.session_id != authority.binding.session_id or
            lease.session_epoch != authority.epoch_binding.epoch_id or
            lease.owner_object_id != authority.binding.owner.object_id or
            authority.policy.operation(lease.operation_id) is not policy or
            tuple(item.identity.capability_id for item in resources) !=
            policy.required_resources):
        _fail("child operation differs from its immutable scoped session authority")
    callback_binding = CallbackBinding(
        CALLBACK_AUTHORITY, lease.binding_sha256, lease.session_id,
        lease.session_epoch, lease.sequence, lease.operation_id, lease.request_id,
        lease.challenge, lease.deadline_ns, lease.owner_object_id,
        policy.callback_events, policy.max_callbacks, policy.max_callback_bytes)
    callback_binding.validate()
    operation = object.__new__(ChildOperation)
    root = _ChildOperationAuthorities(
        child, lease, policy, request, resources,
        tuple((item, item.identity, item.handle) for item in resources),
        dynamic.generation, callback_binding, _ChildOperationDynamic())
    _INSTALL_CHILD_OPERATION(operation, root)
    return operation


class ChildCapabilitySession(_SessionBase):
    """Child verifier/dispatcher for the same immutable fixed factory binding."""

    __slots__ = ()

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        _fail("child capability sessions cannot be subclassed")

    def __init__(self, *, binding: CapabilityBinding,
                 resources: tuple[RetainedCapability, ...], owner_handle: Any,
                 handle_authority: HandleAuthority, transport: PacketTransport,
                 callback_drain: CallbackDrainAuthority,
                 epoch_admission: SessionEpochAdmissionAuthority, clock: Clock,
                 crypto: CryptoProvider, session_key: bytes,
                 allow_unproven_transport_for_tests: bool = False):
        if callback_drain is None:
            _fail("callback drain authority is required")
        self._initialize(
            binding=binding, resources=resources, owner_handle=owner_handle,
            handle_authority=handle_authority, transport=transport, clock=clock,
            crypto=crypto, session_key=session_key, expected_side="child",
            epoch_admission=epoch_admission, callback_drain=callback_drain,
            allow_unproven_transport_for_tests=allow_unproven_transport_for_tests)

    def _verify_callback_drain(self, drain: CallbackDrainAuthority,
                               binding: CallbackBinding) -> None:
        authority = _session_authority(self)
        if drain is not authority.callback_drain:
            _fail("callback drain authority identity was substituted")
        binding.validate()
        for method in authority.methods:
            if method.owner is drain and method.name == "verify_drained":
                method.verify()
                return
        _fail("callback drain authority is outside retained private storage")

    @_serialized
    def receive_request(self) -> ChildOperation:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        if self.state != "OPEN" or dynamic.active is not None:
            _fail("child capability session is active or terminal")
        try:
            self._verify_authorities()
            packet = authority.call(
                authority.transport, "receive", authority.binding.absolute_deadline_ns)
            if packet is None:
                _fail("unauthenticated transport EOF revoked the child session")
            header, raw_payload = _open_packet(
                packet, key=authority.key, crypto=authority.secure_crypto)
            if (type(header.get("sequence")) is not int or
                    header["sequence"] != dynamic.sequence + 1):
                _fail("request sequence is replayed, skipped, or reordered")
            operation_id = header.get("operation_id")
            policy = authority.policy.operation(operation_id)
            deadline_ns = header.get("deadline_ns")
            if type(deadline_ns) is not int:
                _fail("request deadline is inexact")
            lease = OperationLease(
                LEASE_AUTHORITY, authority.binding_digest, authority.binding.session_id,
                authority.epoch_binding.epoch_id, header["sequence"], operation_id,
                header.get("request_id"),
                header.get("challenge"), deadline_ns, self.binding.owner.object_id)
            lease.validate()
            kind = self._check_frame_common(header, lease, 0)
            if kind != "request" or header["body"] != {}:
                _fail("child received a non-request or malformed request frame")
            if lease.request_id != _request_id(
                authority.secure_crypto, lease.binding_sha256, lease.session_epoch,
                    lease.challenge, lease.deadline_ns, lease.operation_id,
                    lease.sequence):
                _fail("request ID is not derived from its exact immutable request authority")
            self._check_deadline(deadline_ns)
            if deadline_ns > authority.binding.absolute_deadline_ns:
                _fail("request deadline exceeds immutable session deadline")
            if lease.challenge in dynamic.challenges:
                _fail("request challenge was replayed")
            detached = DetachedPayload.from_wire(
                raw_payload, authority.secure_crypto, MAX_PAYLOAD_BYTES)
            value = detached.decode()
            if type(value) is not dict or tuple(sorted(value)) != policy.request_fields:
                _fail("request payload differs from immutable operation schema")
            operation_resources = tuple(
                item for item in authority.resources
                if item.identity.capability_id in policy.required_resources)
            self._verify_operation_resources(policy, operation_resources)
            dynamic.sequence = lease.sequence
            dynamic.add_challenge(lease.challenge)
            generation = dynamic.generation + 1
            dynamic.generation = generation
            operation = _new_child_operation(
                self, lease, policy, detached, operation_resources)
            self._check_generation(generation, "OPEN")
            dynamic.active = operation
            dynamic.state = "ACTIVE"
            return operation
        except BaseException as error:
            failure_code = _primitive_failure_code(error)
            dynamic.active = None
            request_id = None
            deadline = authority.binding.absolute_deadline_ns
            if "header" in locals() and type(header) is dict:
                candidate = header.get("request_id")
                if type(candidate) is str and _HEX64.fullmatch(candidate):
                    request_id = candidate
                candidate_deadline = header.get("deadline_ns")
                if (type(candidate_deadline) is int and
                        0 < candidate_deadline <= authority.binding.absolute_deadline_ns):
                    deadline = candidate_deadline
            self._revoke(request_id, deadline, failure_code)
            raise CapabilityIpcError(
                "child request admission failed (" + failure_code + ")") from None

    def _verify_operation_resources(
            self, policy: OperationPolicy,
            operation_resources: tuple[RetainedCapability, ...]) -> None:
        authority = _session_authority(self)
        if authority.policy.operation(policy.operation_id) is not policy:
            _fail("operation policy differs from retained canonical factory policy")
        expected = tuple(
            item for item in authority.resources
            if item.identity.capability_id in policy.required_resources)
        if (type(operation_resources) is not tuple or operation_resources != expected or
                tuple(item.identity.capability_id for item in operation_resources) !=
                policy.required_resources):
            _fail("operation resource scope differs from its exact fixed capability set")
        scoped_snapshots = tuple(
            snapshot for snapshot in authority.resource_snapshots
            if snapshot[1].capability_id in policy.required_resources)
        if (tuple(item for item, _identity, _handle in scoped_snapshots) !=
                operation_resources or
                tuple(identity.capability_id for _item, identity, _handle
                      in scoped_snapshots) != policy.required_resources):
            _fail("operation resource snapshots differ from exact retained scope")
        self._verify_authority_integrity()
        for retained, retained_identity, retained_handle in scoped_snapshots:
            self._verify_live_resource_identity(
                retained, retained_identity, retained_handle)
        # A scoped provider call cannot authorize a whole-session reference
        # change.  Re-attest immutable/session authority without probing any
        # unrelated live handle after the final scoped identity call.
        self._verify_authority_integrity()

    def _check_active(self, operation: ChildOperation, lease: OperationLease,
                      policy: OperationPolicy, generation: int,
                      operation_resources: tuple[RetainedCapability, ...]) -> None:
        dynamic = _session_authority(self).dynamic
        if (type(operation) is not ChildOperation or self.state != "ACTIVE" or
                dynamic.active is not operation or
                lease.sequence != dynamic.sequence or generation != dynamic.generation):
            _fail("callback/result capability is stale, cross-operation, or substituted")
        self._check_generation(generation, "ACTIVE")
        self._check_deadline(lease.deadline_ns)
        self._verify_operation_resources(policy, operation_resources)

    def _send_child_frame(self, operation: ChildOperation, lease: OperationLease,
                          policy: OperationPolicy, generation: int,
                          operation_resources: tuple[RetainedCapability, ...], kind: str,
                          message_sequence: int, body: dict[str, Any], payload: bytes) -> None:
        self._check_active(
            operation, lease, policy, generation, operation_resources)
        authority = _session_authority(self)
        packet = _make_packet(
            binding=authority.binding, sequence=lease.sequence,
            message_sequence=message_sequence, kind=kind,
            operation_id=lease.operation_id, request_id=lease.request_id,
            challenge=lease.challenge, deadline_ns=lease.deadline_ns,
            body=body, payload=payload, key=authority.key,
            crypto=authority.secure_crypto)
        if authority.call(
                authority.transport, "send", packet, lease.deadline_ns) is not None:
            _fail("child packet send returned unexpected data")
        self._check_deadline(lease.deadline_ns)
        self._verify_operation_resources(policy, operation_resources)

    def _complete_active(self, operation: ChildOperation, lease: OperationLease,
                         callback_binding: CallbackBinding, generation: int) -> None:
        authority = _session_authority(self)
        dynamic = authority.dynamic
        if dynamic.active is not operation or self.state != "ACTIVE":
            _fail("completed child operation lost current authority")
        self._check_generation(generation, "ACTIVE")
        dynamic.last_completed_request = lease.request_id
        dynamic.last_callback_binding = callback_binding
        dynamic.active = None
        dynamic.generation += 1
        dynamic.terminal_receipt = _TerminalReceipt(
            authority.binding_digest, authority.epoch_binding.epoch_id,
            lease.request_id, dynamic.generation, "settled")
        dynamic.state = "OPEN"
        _RETIRE_CHILD_OPERATION(operation)

    def _abort_active(self, failure_code: str) -> None:
        _validate_failure_code(failure_code)
        dynamic = _session_authority(self).dynamic
        operation = dynamic.active
        if self.state in {"REVOKED", "QUIESCENCE_UNCERTAIN"}:
            return
        if operation is not None:
            lease, callback_binding, _generation = _DISPATCH_CHILD_OPERATION(
                operation, "terminal_record")
            dynamic.last_callback_binding = callback_binding
        else:
            lease = None
        dynamic.active = None
        if operation is not None:
            _RETIRE_CHILD_OPERATION(operation)
        request_id = lease.request_id if lease is not None else None
        deadline = (lease.deadline_ns if lease is not None
                    else self.binding.absolute_deadline_ns)
        self._revoke(request_id, deadline, failure_code)

    @_serialized
    def verify_quiescent(self) -> None:
        """Nonmutating proof that no child dispatch or callback authority is live."""

        authority = _session_authority(self)
        dynamic = authority.dynamic
        if (self.state not in {"OPEN", "REVOKED"} or dynamic.active is not None or
                self.cleanup_obligations):
            raise CapabilityQuiescenceError("child capability session is not exactly quiescent")
        generation = dynamic.generation
        state = self.state
        receipt = dynamic.terminal_receipt
        terminal_request = receipt.request_id if receipt is not None else None
        callback_binding = dynamic.last_callback_binding
        _verify_terminal_receipt(receipt, authority, generation, state)
        self._verify_authorities()
        participants: list[tuple[str, str]] = [
            ("transport", authority.binding.transport_binding_sha256)]
        if callback_binding is not None:
            drain = authority.callback_drain
            if drain is None:
                _fail("retained callback drain authority is absent")
            participants.append((
                "callback_drain",
                _callback_binding_digest(
                    callback_binding, authority.secure_crypto)))
        challenge = self._new_quiescence_round(
            request_id=terminal_request, generation=generation,
            phase="child.verify", participants=tuple(sorted(participants)))
        receipts: list[QuiescenceReceipt] = []
        if callback_binding is not None:
            drain = authority.callback_drain
            if drain is None:
                _fail("retained callback drain authority is absent")
            drain_receipt = authority.call(
                drain, "verify_drained", callback_binding, challenge)
            _exact(drain_receipt, QuiescenceReceipt,
                   "callback drain quiescence receipt")
            drain_receipt.validate(challenge, "callback_drain")
            receipts.append(drain_receipt)
        transport_receipt = authority.call(
            authority.transport, "verify_quiescent",
            terminal_request, challenge)
        _exact(transport_receipt, QuiescenceReceipt,
               "transport quiescence receipt")
        transport_receipt.validate(challenge, "transport")
        receipts.append(transport_receipt)
        self._validate_quiescence_round(
            challenge, tuple(receipts), generation, terminal_request)
        if (self.state != state or dynamic.terminal_receipt is not receipt or
                dynamic.last_callback_binding is not callback_binding):
            _fail("quiescence proof raced a child generation transition")


def _verify_child_operation_root(operation: ChildOperation,
                                 root: _ChildOperationAuthorities) -> None:
    if type(operation) is not ChildOperation or type(root) is not _ChildOperationAuthorities:
        _fail("child operation authority is substituted")
    authority = _session_authority(root.child)
    root.lease.validate()
    root.policy.validate()
    root.callback_binding.validate()
    expected_binding = CallbackBinding(
        CALLBACK_AUTHORITY, root.lease.binding_sha256, root.lease.session_id,
        root.lease.session_epoch, root.lease.sequence, root.lease.operation_id,
        root.lease.request_id, root.lease.challenge, root.lease.deadline_ns,
        root.lease.owner_object_id, root.policy.callback_events,
        root.policy.max_callbacks, root.policy.max_callback_bytes)
    if (authority.policy.operation(root.lease.operation_id) is not root.policy or
            root.lease.binding_sha256 != authority.binding_digest or
            root.lease.session_epoch != authority.epoch_binding.epoch_id or
            root.callback_binding != expected_binding or
            tuple(item for item, _identity, _handle in root.resource_snapshots) !=
            root.resources or
            tuple(item.identity.capability_id for item in root.resources) !=
            root.policy.required_resources):
        _fail("child operation root differs from its exact scoped authority")
    for item, identity, handle in root.resource_snapshots:
        if (item.identity is not identity or item.handle is not handle or
                identity.capability_id not in root.policy.required_resources):
            _fail("child operation retained a substituted or out-of-scope resource")
    ChildCapabilitySession._verify_operation_resources(
        root.child, root.policy, root.resources)


def _operation_enter(operation: ChildOperation,
                     root: _ChildOperationAuthorities) -> None:
    ChildCapabilitySession._enter_child_action(root.child, root.generation)
    try:
        _verify_child_operation_root(operation, root)
        ChildCapabilitySession._check_active(
            root.child, operation, root.lease, root.policy, root.generation,
            root.resources)
    except BaseException as error:
        failure_code = _primitive_failure_code(error)
        # Once the child action owns the session entry, any failure to
        # re-attest its exact operation/root/resource authority is terminal.
        # Merely releasing the entry lock would otherwise leave a stale or
        # substituted operation ACTIVE and able to try again.
        try:
            ChildCapabilitySession._abort_active(root.child, failure_code)
        finally:
            ChildCapabilitySession._leave_child_action(root.child)
        raise CapabilityIpcError(
            "child operation authority validation failed (" +
            failure_code + ")") from None


def _operation_fail(root: _ChildOperationAuthorities, failure_code: str) -> None:
    _validate_failure_code(failure_code)
    ChildCapabilitySession._abort_active(root.child, failure_code)


def _operation_leave(root: _ChildOperationAuthorities) -> None:
    ChildCapabilitySession._leave_child_action(root.child)


def _dispatch_read_value(operation: ChildOperation,
                         root: _ChildOperationAuthorities,
                         field_name: str) -> Any:
    """Serialize even read-only backend calls against terminal retirement."""

    entered = False
    try:
        _operation_enter(operation, root)
        entered = True
        if field_name == "operation_id":
            return root.lease.operation_id
        if field_name == "request":
            return root.request.decode()
        if field_name == "resource_ids":
            return root.policy.required_resources
        if field_name == "callback_count":
            return root.dynamic.callback_count
        if field_name == "callbacks_sealed":
            return root.dynamic.callbacks_sealed
        _fail("child operation read is outside the fixed dispatch table")
    except BaseException as error:
        failure_code = _primitive_failure_code(error)
        if entered:
            _operation_fail(root, failure_code)
        raise CapabilityIpcError(
            "child operation read failed (" + failure_code + ")") from None
    finally:
        if entered:
            _operation_leave(root)


def _dispatch_operation_id(_operation: ChildOperation,
                           root: _ChildOperationAuthorities) -> str:
    return _dispatch_read_value(_operation, root, "operation_id")


def _dispatch_decode_request(operation: ChildOperation,
                             root: _ChildOperationAuthorities) -> Any:
    return _dispatch_read_value(operation, root, "request")


def _dispatch_required_resource_ids(operation: ChildOperation,
                                    root: _ChildOperationAuthorities) -> tuple[str, ...]:
    return _dispatch_read_value(operation, root, "resource_ids")


def _dispatch_callback_count(operation: ChildOperation,
                             root: _ChildOperationAuthorities) -> int:
    return _dispatch_read_value(operation, root, "callback_count")


def _dispatch_callbacks_sealed(operation: ChildOperation,
                               root: _ChildOperationAuthorities) -> bool:
    return _dispatch_read_value(operation, root, "callbacks_sealed")


def _dispatch_state_record(_operation: ChildOperation,
                           root: _ChildOperationAuthorities) -> dict[str, Any]:
    return {"request_id": root.lease.request_id, "type": "child_operation"}


def _dispatch_terminal_record(operation: ChildOperation,
                              root: _ChildOperationAuthorities) -> tuple[
                                  OperationLease, CallbackBinding, int]:
    # Cleanup must remain able to identify the exact in-flight request even
    # when the normal retained-authority verification is what failed.  The
    # dispatcher already proved exact handle identity; validate only the
    # immutable terminal scalars here and do not call a failing dependency.
    if type(operation) is not ChildOperation:
        _fail("child terminal operation handle is substituted")
    root.lease.validate()
    root.callback_binding.validate()
    _positive_int(root.generation, "child terminal generation", allow_zero=True)
    return root.lease, root.callback_binding, root.generation


def _dispatch_emit_callback(operation: ChildOperation,
                            root: _ChildOperationAuthorities,
                            event: str, payload: Any) -> None:
    entered = False
    try:
        _operation_enter(operation, root)
        entered = True
        dynamic = root.dynamic
        if dynamic.callbacks_sealed:
            _fail("callback channel is sealed")
        if (type(event) is not str or event not in root.policy.callback_events or
                dynamic.callback_count >= root.policy.max_callbacks):
            _fail("callback event is outside the immutable bounded policy")
        authority = _session_authority(root.child)
        detached = DetachedPayload.from_value(
            payload, authority.secure_crypto, root.policy.max_callback_bytes)
        dynamic.callback_count += 1
        ChildCapabilitySession._send_child_frame(
            root.child, operation, root.lease, root.policy, root.generation,
            root.resources, "callback", dynamic.callback_count,
            {"event": event, "ordinal": dynamic.callback_count}, detached.canonical)
    except BaseException as error:
        failure_code = _primitive_failure_code(error)
        if entered:
            _operation_fail(root, failure_code)
        raise CapabilityIpcError(
            "child callback publication failed (" +
            failure_code + ")") from None
    finally:
        if entered:
            _operation_leave(root)


def _dispatch_seal_callbacks(operation: ChildOperation,
                             root: _ChildOperationAuthorities) -> None:
    entered = False
    try:
        _operation_enter(operation, root)
        entered = True
        dynamic = root.dynamic
        if dynamic.callbacks_sealed:
            _fail("callback channel was already sealed")
        dynamic.callbacks_sealed = True
        authority = _session_authority(root.child)
        drain = authority.callback_drain
        if drain is None:
            _fail("retained callback drain authority is absent")
        challenge = ChildCapabilitySession._new_quiescence_round(
            root.child, request_id=root.lease.request_id,
            generation=root.generation, phase="child.barrier",
            participants=((
                "callback_drain",
                _callback_binding_digest(
                    root.callback_binding, authority.secure_crypto)),))
        receipt = authority.call(
            drain, "verify_drained", root.callback_binding, challenge)
        _exact(receipt, QuiescenceReceipt, "callback drain quiescence receipt")
        receipt.validate(challenge, "callback_drain")
        ChildCapabilitySession._validate_quiescence_round(
            root.child, challenge, (receipt,), root.generation,
            root.lease.request_id)
        _verify_child_operation_root(operation, root)
        ChildCapabilitySession._check_active(
            root.child, operation, root.lease, root.policy, root.generation,
            root.resources)
        ChildCapabilitySession._send_child_frame(
            root.child, operation, root.lease, root.policy, root.generation,
            root.resources, "barrier", dynamic.callback_count + 1,
            {"callback_count": dynamic.callback_count}, b"")
    except BaseException as error:
        failure_code = _primitive_failure_code(error)
        if entered:
            _operation_fail(root, failure_code)
        raise CapabilityIpcError(
            "child callback barrier failed (" + failure_code + ")") from None
    finally:
        if entered:
            _operation_leave(root)


def _dispatch_publish_result(operation: ChildOperation,
                             root: _ChildOperationAuthorities, result: Any) -> None:
    entered = False
    try:
        _operation_enter(operation, root)
        entered = True
        dynamic = root.dynamic
        if dynamic.completed or not dynamic.callbacks_sealed:
            _fail("operation result is unavailable before exact callback barrier")
        authority = _session_authority(root.child)
        drain = authority.callback_drain
        if drain is None:
            _fail("retained callback drain authority is absent")
        _verify_child_operation_root(operation, root)
        ChildCapabilitySession._check_active(
            root.child, operation, root.lease, root.policy, root.generation,
            root.resources)
        detached = DetachedPayload.from_value(
            result, authority.secure_crypto, root.policy.max_result_bytes)
        # Repeat the exact drain after every validation and immediately before
        # publication.  The proof is carried in the authenticated reply so the
        # parent can refuse terminal settlement without the same witness.
        challenge = ChildCapabilitySession._new_quiescence_round(
            root.child, request_id=root.lease.request_id,
            generation=root.generation, phase="child.publish",
            participants=((
                "callback_drain",
                _callback_binding_digest(
                    root.callback_binding, authority.secure_crypto)),))
        receipt = authority.call(
            drain, "verify_drained", root.callback_binding, challenge)
        _exact(receipt, QuiescenceReceipt, "callback drain quiescence receipt")
        receipt.validate(challenge, "callback_drain")
        ChildCapabilitySession._validate_quiescence_round(
            root.child, challenge, (receipt,), root.generation,
            root.lease.request_id)
        ordinal = dynamic.callback_count + 2
        proof = {
            "challenge": challenge.wire(),
            "receipts": [receipt.wire()],
        }
        reply_packet = _make_packet(
            binding=authority.binding, sequence=root.lease.sequence,
            message_sequence=ordinal, kind="reply",
            operation_id=root.lease.operation_id,
            request_id=root.lease.request_id, challenge=root.lease.challenge,
            deadline_ns=root.lease.deadline_ns,
            body={"callback_drain_proof": proof, "status": "ok"},
            payload=detached.canonical, key=authority.key,
            crypto=authority.secure_crypto)
        eof_packet = _make_packet(
            binding=authority.binding, sequence=root.lease.sequence,
            message_sequence=ordinal + 1, kind="eof",
            operation_id=root.lease.operation_id,
            request_id=root.lease.request_id, challenge=root.lease.challenge,
            deadline_ns=root.lease.deadline_ns, body={}, payload=b"",
            key=authority.key, crypto=authority.secure_crypto)
        # Packet construction may call retained cryptography.  Recheck the
        # closure-held generation with no further external callback before the
        # first transport publication.
        ChildCapabilitySession._check_generation(
            root.child, root.generation, "ACTIVE")
        if authority.call(
                authority.transport, "send", reply_packet,
                root.lease.deadline_ns) is not None:
            _fail("child reply transport send returned unexpected data")
        ChildCapabilitySession._check_generation(
            root.child, root.generation, "ACTIVE")
        if authority.call(
                authority.transport, "send", eof_packet,
                root.lease.deadline_ns) is not None:
            _fail("child EOF transport send returned unexpected data")
        if authority.call(
                authority.transport, "seal_send", root.lease.request_id,
                root.lease.deadline_ns) is not None:
            _fail("child transport seal returned unexpected data")
        if authority.call(
                authority.transport, "verify_send_sealed",
                root.lease.request_id) is not None:
            _fail("child send-seal verification returned unexpected data")
        ChildCapabilitySession._check_deadline(root.child, root.lease.deadline_ns)
        ChildCapabilitySession._verify_operation_resources(
            root.child, root.policy, root.resources)
        dynamic.completed = True
        ChildCapabilitySession._complete_active(
            root.child, operation, root.lease, root.callback_binding,
            root.generation)
    except BaseException as error:
        failure_code = _primitive_failure_code(error)
        if entered:
            _operation_fail(root, failure_code)
        raise CapabilityIpcError(
            "child result publication failed (" + failure_code + ")") from None
    finally:
        if entered:
            _operation_leave(root)


_CONFIGURE_CHILD_OPERATION({
    "callback_count": _dispatch_callback_count,
    "callbacks_sealed": _dispatch_callbacks_sealed,
    "decode_request": _dispatch_decode_request,
    "emit_callback": _dispatch_emit_callback,
    "operation_id": _dispatch_operation_id,
    "publish_result": _dispatch_publish_result,
    "required_resource_ids": _dispatch_required_resource_ids,
    "seal_callbacks": _dispatch_seal_callbacks,
    "state_record": _dispatch_state_record,
    "terminal_record": _dispatch_terminal_record,
})


# ---------------------------------------------------------------------------
# Additive v2 production contract
# ---------------------------------------------------------------------------
#
# The v1 implementation above is intentionally left intact.  V2 is a separate
# contract for the visual-only hardware gate.  This file still contains no OS
# transport or epoch implementation: production construction succeeds only
# when injected retained authorities return the exact concrete attestation
# profiles and typed admission receipts below.  Deterministic contract fakes
# use different, conspicuous profiles and can never pass the production entry
# point.

PROTOCOL_VERSION_V2 = 2
CAPABILITY_BINDING_BODY_AUTHORITY_V2 = "rtl-reader-capability-binding-body-v2"
OPERATION_PURPOSE_AUTHORITY_V2 = "rtl-reader-operation-purpose-v2"
OPERATION_LEASE_AUTHORITY_V2 = "rtl-reader-operation-lease-v2"
DETACHED_PAYLOAD_AUTHORITY_V2 = "rtl-reader-detached-payload-v2"
WIRE_PACKET_AUTHORITY_V2 = "rtl-reader-worker-packet-v2"
OPERATION_OUTCOME_AUTHORITY_V2 = "rtl-reader-operation-outcome-v2"
OPERATION_SETTLEMENT_EVIDENCE_AUTHORITY_V2 = (
    "rtl-reader-operation-settlement-evidence-v2")
QUIESCENCE_CHALLENGE_AUTHORITY_V2 = "rtl-reader-quiescence-challenge-v2"
QUIESCENCE_RECEIPT_AUTHORITY_V2 = "rtl-reader-quiescence-receipt-v2"
CLEANUP_EXPIRY_RECEIPT_AUTHORITY_V2 = "rtl-reader-cleanup-expiry-receipt-v2"
OPEN_OPERATION_IDLE_RECEIPT_AUTHORITY_V2 = "rtl-reader-open-operation-idle-v2"
SESSION_CLOSURE_REQUEST_AUTHORITY_V2 = "rtl-reader-session-closure-request-v2"
CLOSURE_COMPONENT_RECEIPT_AUTHORITY_V2 = "rtl-reader-closure-component-v2"
SUCCESSFUL_SESSION_CLOSURE_RECEIPT_AUTHORITY_V2 = (
    "rtl-reader-successful-session-closure-v2")
ADMISSION_RECEIPT_AUTHORITY_V2 = "rtl-reader-production-admission-receipt-v2"
ACQUIRED_AUTHORITY_V2 = "rtl-reader-acquired-session-authority-v2"
CONSTRUCTION_RESULT_AUTHORITY_V2 = "rtl-reader-capability-construction-result-v2"
TRANSPORT_ATTESTATION_AUTHORITY_V2 = "rtl-reader-transport-attestation-v2"
EPOCH_ATTESTATION_AUTHORITY_V2 = "rtl-reader-epoch-attestation-v2"

PRODUCTION_TRANSPORT_PROFILE_V2 = "retained_os_packet_transport.v2"
PRODUCTION_EPOCH_PROFILE_V2 = "retained_os_one_shot_epoch.v2"
CONTRACT_FAKE_TRANSPORT_PROFILE_V2 = "contract_fake_packet_transport.v2"
CONTRACT_FAKE_EPOCH_PROFILE_V2 = "contract_fake_one_shot_epoch.v2"
SESSION_LIFECYCLE_PROFILE_V2 = "retained_session_lifecycle.v2"

FRIDA_CAPTURE_OPERATION_V2 = "frida.collect_native_page.v2"
FRIDA_CAPTURE_PURPOSE_V2 = "visual.capture_native_page.v2"
FRIDA_CLEANUP_OPERATION_V2 = "frida.cleanup_native_page.v2"
FRIDA_CLEANUP_PURPOSE_V2 = "visual.cleanup_after_capture.v2"
SESSION_CLOSE_OPERATION_V2 = "session.close_successfully.v2"
SESSION_CLOSE_PURPOSE_V2 = "visual.successful_session_closure.v2"
OPERATION_IDLE_PURPOSE_V2 = "visual.open_operation_idle.v2"

REAL_V2_TRANSPORT_AUTHORITY_IMPLEMENTED = False
REAL_V2_EPOCH_AUTHORITY_IMPLEMENTED = False
V2_UNRESOLVED_BLOCKERS = (
    "a retained OS packet transport must implement PacketTransportAuthorityV2 "
    "and return the concrete production transport attestation profile",
    "a retained one-shot epoch authority must implement SessionEpochAuthorityV2 "
    "and return the concrete production epoch attestation profile",
)

_V2_FRAME_KINDS = frozenset({"request", "callback", "barrier", "reply", "eof"})
_V2_PAYLOAD_ROLES = frozenset({"request", "callback", "result"})
_V2_DIRECTIONS = ("child_to_parent", "parent_to_child")
_V2_EPOCH_SIDES = ("child", "parent")
_V2_ENDPOINT_IDS = ("child_receive", "child_send", "parent_receive", "parent_send")
_V2_HEADER_KEYS = frozenset({
    "authority", "binding_sha256", "body", "challenge",
    "closure_deadline_ns", "effect_deadline_ns", "factory_id", "kind",
    "message_sequence", "operation_id", "operation_purpose", "payload_bytes",
    "payload_role", "payload_sha256", "request_id", "role", "sequence",
    "session_epoch", "session_id", "version",
})


def _v2_authentication_tag(crypto: CryptoProvider, key: bytes, domain: bytes,
                           value: dict[str, Any]) -> str:
    _exact(key, bytes, "v2 authentication key")
    if len(key) < 32:
        _fail("v2 authentication key is shorter than 32 bytes")
    return _crypto_bytes(
        _call_unretained_provider(
            crypto, "hmac_sha256", key, domain + canonical_json(value)),
        "v2 HMAC provider").hex()


def _v2_exact_token_tuple(value: Any, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (type(value) is not tuple or (not value and not allow_empty) or
            any(type(item) is not str or not _TOKEN.fullmatch(item) for item in value) or
            tuple(sorted(set(value))) != value):
        _fail(label + " is not an exact sorted token tuple")
    return value


@dataclass(frozen=True)
class OperationPurposeV2:
    """One row in the immutable visual-gate operation plan."""

    authority: str
    factory_id: str
    role: str
    sequence: int
    operation_id: str
    operation_purpose: str
    phase: str
    required_resources: tuple[str, ...]
    callback_events: tuple[str, ...]
    maximum_callbacks: int
    maximum_payload_bytes: int
    prerequisite_purpose: str | None

    def validate(self) -> None:
        if (type(self) is not OperationPurposeV2 or
                self.authority != OPERATION_PURPOSE_AUTHORITY_V2):
            _fail("v2 operation purpose authority is invalid or substituted")
        policy = factory_policy(self.factory_id)
        if self.role != policy.role:
            _fail("v2 operation purpose factory/role pair is invalid")
        _positive_int(self.sequence, "v2 operation sequence")
        _token(self.operation_id, "v2 operation ID")
        _token(self.operation_purpose, "v2 operation purpose")
        if type(self.phase) is not str or self.phase not in {"effect", "closure"}:
            _fail("v2 operation phase is outside the fixed registry")
        _v2_exact_token_tuple(self.required_resources, "v2 operation resources")
        if not set(self.required_resources).issubset(policy.resource_ids):
            _fail("v2 operation purpose requires an unbound resource")
        _v2_exact_token_tuple(
            self.callback_events, "v2 callback events", allow_empty=True)
        _positive_int(self.maximum_callbacks, "v2 callback maximum", allow_zero=True)
        _positive_int(self.maximum_payload_bytes, "v2 payload maximum")
        if (self.maximum_callbacks > MAX_CALLBACKS or
                self.maximum_payload_bytes > MAX_PAYLOAD_BYTES or
                (not self.callback_events) != (self.maximum_callbacks == 0)):
            _fail("v2 callback/payload policy exceeds its fixed bound")
        if self.prerequisite_purpose is not None:
            _token(self.prerequisite_purpose, "v2 prerequisite purpose")
        if ((self.phase == "effect") != (self.prerequisite_purpose is None)):
            _fail("v2 closure operation lacks its exact effect prerequisite")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "authority": self.authority,
            "callback_events": list(self.callback_events),
            "factory_id": self.factory_id,
            "maximum_callbacks": self.maximum_callbacks,
            "maximum_payload_bytes": self.maximum_payload_bytes,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "phase": self.phase,
            "prerequisite_purpose": self.prerequisite_purpose,
            "required_resources": list(self.required_resources),
            "role": self.role,
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class FactoryOperationTableV2:
    factory_id: str
    role: str
    operations: tuple[OperationPurposeV2, ...]

    def validate(self) -> None:
        if type(self) is not FactoryOperationTableV2:
            _fail("v2 factory operation table is substituted")
        policy = factory_policy(self.factory_id)
        if self.role != policy.role or type(self.operations) is not tuple or not self.operations:
            _fail("v2 factory operation table has an invalid factory or shape")
        for sequence, operation in enumerate(self.operations, 1):
            operation.validate()
            if (operation.factory_id != self.factory_id or operation.role != self.role or
                    operation.sequence != sequence):
                _fail("v2 factory operation table is reordered or cross-factory")
            if operation.prerequisite_purpose is not None:
                prior = tuple(item.operation_purpose for item in self.operations[:sequence - 1])
                if operation.prerequisite_purpose not in prior:
                    _fail("v2 operation prerequisite is not a prior exact plan step")
        ids = tuple(item.operation_id for item in self.operations)
        purposes = tuple(item.operation_purpose for item in self.operations)
        if len(set(ids)) != len(ids) or len(set(purposes)) != len(purposes):
            _fail("v2 factory operation IDs and purposes are not unique")

    def operation(self, operation_id: str, operation_purpose: str) -> OperationPurposeV2:
        _token(operation_id, "v2 requested operation ID")
        _token(operation_purpose, "v2 requested operation purpose")
        for item in self.operations:
            if item.operation_id == operation_id:
                if item.operation_purpose != operation_purpose:
                    _fail("v2 operation purpose differs from the immutable table")
                return item
        _fail("v2 operation is outside the immutable factory table")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "factory_id": self.factory_id,
            "operations": [item.wire() for item in self.operations],
            "role": self.role,
        }


_AUTHORITY_PURPOSE_NAMES_V2 = (
    ("authority.read_activity_dump.v2", "visual.authority_activity_dump.v2",
     ("private_adb", "target_process")),
    ("authority.read_device_state.v2", "visual.authority_device_state.v2",
     ("private_adb",)),
    ("authority.read_display_dump.v2", "visual.authority_display_dump.v2",
     ("private_adb", "target_process")),
    ("authority.read_framework.v2", "visual.authority_framework.v2",
     ("private_adb", "root_reader")),
    ("authority.read_module_apk.v2", "visual.authority_module_apk.v2",
     ("private_adb", "root_reader")),
    ("authority.read_nullable_mark.v2", "visual.authority_nullable_mark.v2",
     ("private_adb",)),
    ("authority.read_original_pdf.v2", "visual.authority_original_pdf.v2",
     ("private_adb",)),
    ("authority.read_target_base_apk.v2", "visual.authority_target_base_apk.v2",
     ("private_adb", "root_reader")),
    ("authority.read_target_process.v2", "visual.authority_target_process.v2",
     ("private_adb", "target_process")),
    ("authority.read_window_dump.v2", "visual.authority_window_dump.v2",
     ("private_adb", "target_process")),
)

_FRIDA_OPERATION_TABLE_V2 = FactoryOperationTableV2(
    FRIDA_FACTORY_ID, FRIDA_ROLE, (
        OperationPurposeV2(
            OPERATION_PURPOSE_AUTHORITY_V2, FRIDA_FACTORY_ID, FRIDA_ROLE, 1,
            FRIDA_CAPTURE_OPERATION_V2, FRIDA_CAPTURE_PURPOSE_V2, "effect",
            ("frida_device", "target_process"), ("native_page_event.v2",),
            64, MAX_PAYLOAD_BYTES, None),
        OperationPurposeV2(
            OPERATION_PURPOSE_AUTHORITY_V2, FRIDA_FACTORY_ID, FRIDA_ROLE, 2,
            FRIDA_CLEANUP_OPERATION_V2, FRIDA_CLEANUP_PURPOSE_V2, "closure",
            ("frida_device", "target_process"), (), 0, MAX_PAYLOAD_BYTES,
            FRIDA_CAPTURE_PURPOSE_V2),
    ))
_AUTHORITY_OPERATION_TABLE_V2 = FactoryOperationTableV2(
    AUTHORITY_FACTORY_ID, AUTHORITY_ROLE,
    tuple(OperationPurposeV2(
        OPERATION_PURPOSE_AUTHORITY_V2, AUTHORITY_FACTORY_ID, AUTHORITY_ROLE,
        sequence, operation_id, purpose, "effect", resources, (), 0,
        MAX_PAYLOAD_BYTES, None)
          for sequence, (operation_id, purpose, resources)
          in enumerate(_AUTHORITY_PURPOSE_NAMES_V2, 1)))
_FRIDA_OPERATION_TABLE_V2.validate()
_AUTHORITY_OPERATION_TABLE_V2.validate()
FACTORY_OPERATION_TABLES_V2: Mapping[str, FactoryOperationTableV2] = MappingProxyType({
    FRIDA_FACTORY_ID: _FRIDA_OPERATION_TABLE_V2,
    AUTHORITY_FACTORY_ID: _AUTHORITY_OPERATION_TABLE_V2,
})


def factory_operation_table_v2(
        factory_id: str,
        _frida: FactoryOperationTableV2 = _FRIDA_OPERATION_TABLE_V2,
        _authority: FactoryOperationTableV2 = _AUTHORITY_OPERATION_TABLE_V2
        ) -> FactoryOperationTableV2:
    if factory_id == FRIDA_FACTORY_ID:
        _frida.validate()
        return _frida
    if factory_id == AUTHORITY_FACTORY_ID:
        _authority.validate()
        return _authority
    _fail("factory is outside the immutable v2 operation registry")


@dataclass(frozen=True)
class TransportAttestationV2:
    authority: str
    profile: str
    attestation_id: str
    session_id: str
    session_epoch: str
    factory_id: str
    role: str
    owner_object_id: str
    channel_id: str
    endpoints: tuple[HandleIdentity, ...]

    def validate(self) -> None:
        if (type(self) is not TransportAttestationV2 or
                self.authority != TRANSPORT_ATTESTATION_AUTHORITY_V2):
            _fail("v2 transport attestation authority is invalid or substituted")
        if type(self.profile) is not str or self.profile not in {
                PRODUCTION_TRANSPORT_PROFILE_V2, CONTRACT_FAKE_TRANSPORT_PROFILE_V2}:
            _fail("v2 transport attestation profile is outside the closed registry")
        _hex64(self.attestation_id, "v2 transport attestation ID")
        _hex64(self.session_id, "v2 transport session")
        _hex64(self.session_epoch, "v2 transport epoch")
        policy = factory_policy(self.factory_id)
        if self.role != policy.role:
            _fail("v2 transport attestation factory/role pair is invalid")
        _hex64(self.owner_object_id, "v2 transport owner")
        _hex64(self.channel_id, "v2 transport channel")
        if type(self.endpoints) is not tuple or len(self.endpoints) != 4:
            _fail("v2 transport attestation endpoint set is incomplete")
        for endpoint, expected_id in zip(self.endpoints, _V2_ENDPOINT_IDS):
            endpoint.validate(expected_id=expected_id, expected_kind="transport")
            expected_rights = ("read",) if expected_id.endswith("receive") else ("write",)
            if endpoint.rights != expected_rights:
                _fail("v2 transport endpoint rights differ from fixed direction")
        _validate_distinct_identities(self.endpoints, "v2 transport endpoints")

    def validate_production(self) -> None:
        self.validate()
        if self.profile != PRODUCTION_TRANSPORT_PROFILE_V2:
            _fail("v2 production transport attestation is not concrete")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "attestation_id": self.attestation_id,
            "authority": self.authority,
            "channel_id": self.channel_id,
            "endpoints": [item.wire() for item in self.endpoints],
            "factory_id": self.factory_id,
            "owner_object_id": self.owner_object_id,
            "profile": self.profile,
            "role": self.role,
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class EpochAttestationV2:
    authority: str
    profile: str
    attestation_id: str
    epoch_id: str
    admission_id: str
    session_id: str
    factory_id: str
    role: str
    owner_object_id: str

    def validate(self) -> None:
        if (type(self) is not EpochAttestationV2 or
                self.authority != EPOCH_ATTESTATION_AUTHORITY_V2):
            _fail("v2 epoch attestation authority is invalid or substituted")
        if type(self.profile) is not str or self.profile not in {
                PRODUCTION_EPOCH_PROFILE_V2, CONTRACT_FAKE_EPOCH_PROFILE_V2}:
            _fail("v2 epoch attestation profile is outside the closed registry")
        _hex64(self.attestation_id, "v2 epoch attestation ID")
        _hex64(self.epoch_id, "v2 epoch ID")
        _hex64(self.admission_id, "v2 epoch admission ID")
        _hex64(self.session_id, "v2 epoch session")
        policy = factory_policy(self.factory_id)
        if self.role != policy.role:
            _fail("v2 epoch attestation factory/role pair is invalid")
        _hex64(self.owner_object_id, "v2 epoch owner")

    def validate_production(self) -> None:
        self.validate()
        if self.profile != PRODUCTION_EPOCH_PROFILE_V2:
            _fail("v2 production epoch attestation is not concrete")

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "admission_id": self.admission_id,
            "attestation_id": self.attestation_id,
            "authority": self.authority,
            "epoch_id": self.epoch_id,
            "factory_id": self.factory_id,
            "owner_object_id": self.owner_object_id,
            "profile": self.profile,
            "role": self.role,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class CapabilityBindingBodyV2:
    """Immutable v2 body; no mutable `real` or test-admission flag exists."""

    authority: str
    version: int
    factory_id: str
    role: str
    session_id: str
    session_epoch: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    key_id: str
    owner: HandleIdentity
    resources: tuple[HandleIdentity, ...]
    resource_binding_sha256: str
    operation_table_sha256: str
    transport_attestation: TransportAttestationV2
    transport_attestation_sha256: str
    epoch_attestation: EpochAttestationV2
    epoch_attestation_sha256: str

    def validate(self, crypto: CryptoProvider) -> None:
        if (type(self) is not CapabilityBindingBodyV2 or
                self.authority != CAPABILITY_BINDING_BODY_AUTHORITY_V2 or
                type(self.version) is not int or self.version != PROTOCOL_VERSION_V2):
            _fail("v2 capability binding authority or version is invalid")
        policy = factory_policy(self.factory_id)
        if self.role != policy.role:
            _fail("v2 capability binding factory/role pair is invalid")
        _hex64(self.session_id, "v2 capability session")
        _hex64(self.session_epoch, "v2 capability epoch")
        _positive_int(self.effect_deadline_ns, "v2 effect deadline")
        _positive_int(self.closure_deadline_ns, "v2 closure deadline")
        if self.effect_deadline_ns >= self.closure_deadline_ns:
            _fail("v2 effect deadline must precede immutable closure deadline")
        _hex64(self.key_id, "v2 capability key ID")
        if type(self.owner) is not HandleIdentity:
            _fail("v2 capability owner is substituted")
        self.owner.validate(expected_id="parent_owner", expected_kind="owner")
        if self.owner.rights != ("query", "terminate"):
            _fail("v2 owner rights differ from fixed policy")
        if type(self.resources) is not tuple:
            _fail("v2 capability resources are mutable or substituted")
        if tuple(item.capability_id for item in self.resources) != policy.resource_ids:
            _fail("v2 capability resources differ from the fixed factory set")
        for item, resource_id, rights in zip(
                self.resources, policy.resource_ids, policy.resource_rights):
            item.validate(expected_id=resource_id, expected_kind="resource")
            if item.rights != rights:
                _fail("v2 resource rights differ from fixed factory policy")
        self.transport_attestation.validate()
        self.epoch_attestation.validate()
        exact = {
            "session_id": self.session_id,
            "session_epoch": self.session_epoch,
            "factory_id": self.factory_id,
            "role": self.role,
            "owner_object_id": self.owner.object_id,
        }
        for name, expected in exact.items():
            transport_name = "session_epoch" if name == "session_epoch" else name
            transport_value = getattr(self.transport_attestation, transport_name)
            if transport_value != expected:
                _fail("v2 transport attestation differs from capability binding")
            epoch_name = "epoch_id" if name == "session_epoch" else name
            epoch_value = getattr(self.epoch_attestation, epoch_name)
            if epoch_value != expected:
                _fail("v2 epoch attestation differs from capability binding")
        identities = (self.owner,) + self.resources + self.transport_attestation.endpoints
        _validate_distinct_identities(identities, "v2 bound authorities")
        if _digest_hex(crypto, canonical_json(
                [item.wire() for item in self.resources])) != self.resource_binding_sha256:
            _fail("v2 resource binding digest is invalid")
        table = factory_operation_table_v2(self.factory_id)
        if _digest_hex(crypto, canonical_json(table.wire())) != self.operation_table_sha256:
            _fail("v2 operation table digest is invalid")
        if _digest_hex(crypto, canonical_json(
                self.transport_attestation.wire())) != self.transport_attestation_sha256:
            _fail("v2 transport attestation digest is invalid")
        if _digest_hex(crypto, canonical_json(
                self.epoch_attestation.wire())) != self.epoch_attestation_sha256:
            _fail("v2 epoch attestation digest is invalid")

    def wire(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "epoch_attestation": self.epoch_attestation.wire(),
            "epoch_attestation_sha256": self.epoch_attestation_sha256,
            "factory_id": self.factory_id,
            "key_id": self.key_id,
            "operation_table_sha256": self.operation_table_sha256,
            "owner": self.owner.wire(),
            "resource_binding_sha256": self.resource_binding_sha256,
            "resources": [item.wire() for item in self.resources],
            "role": self.role,
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
            "transport_attestation": self.transport_attestation.wire(),
            "transport_attestation_sha256": self.transport_attestation_sha256,
            "version": self.version,
        }


def make_capability_binding_body_v2(
        *, factory_id: str, session_id: str, effect_deadline_ns: int,
        closure_deadline_ns: int, key_id: str, owner: HandleIdentity,
        resources: tuple[HandleIdentity, ...],
        transport_attestation: TransportAttestationV2,
        epoch_attestation: EpochAttestationV2,
        crypto: CryptoProvider) -> CapabilityBindingBodyV2:
    policy = factory_policy(factory_id)
    table = factory_operation_table_v2(factory_id)
    if type(resources) is not tuple:
        _fail("v2 binding resources must be an exact tuple")
    if type(transport_attestation) is not TransportAttestationV2:
        _fail("v2 transport attestation is substituted")
    if type(epoch_attestation) is not EpochAttestationV2:
        _fail("v2 epoch attestation is substituted")
    value = CapabilityBindingBodyV2(
        CAPABILITY_BINDING_BODY_AUTHORITY_V2, PROTOCOL_VERSION_V2,
        factory_id, policy.role, session_id, epoch_attestation.epoch_id,
        effect_deadline_ns, closure_deadline_ns, key_id, owner, resources,
        _digest_hex(crypto, canonical_json([item.wire() for item in resources])),
        _digest_hex(crypto, canonical_json(table.wire())),
        transport_attestation,
        _digest_hex(crypto, canonical_json(transport_attestation.wire())),
        epoch_attestation,
        _digest_hex(crypto, canonical_json(epoch_attestation.wire())))
    value.validate(crypto)
    return value


def capability_binding_sha256_v2(binding: CapabilityBindingBodyV2,
                                 crypto: CryptoProvider) -> str:
    _exact(binding, CapabilityBindingBodyV2, "v2 capability binding")
    binding.validate(crypto)
    return _digest_hex(crypto, canonical_json(binding.wire()))


def _operation_request_id_v2(
        crypto: CryptoProvider, binding_sha256: str, session_epoch: str,
        sequence: int, operation_id: str, operation_purpose: str,
        challenge: str, effect_deadline_ns: int, closure_deadline_ns: int) -> str:
    return _digest_hex(crypto, b"rtl-reader-operation-request-v2\x00" + canonical_json({
        "binding_sha256": binding_sha256,
        "challenge": challenge,
        "closure_deadline_ns": closure_deadline_ns,
        "effect_deadline_ns": effect_deadline_ns,
        "operation_id": operation_id,
        "operation_purpose": operation_purpose,
        "sequence": sequence,
        "session_epoch": session_epoch,
    }))


@dataclass(frozen=True)
class OperationLeaseV2:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    factory_id: str
    role: str
    sequence: int
    operation_id: str
    operation_purpose: str
    request_id: str
    challenge: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    owner_object_id: str

    def validate(self, binding: CapabilityBindingBodyV2,
                 crypto: CryptoProvider) -> OperationPurposeV2:
        if type(self) is not OperationLeaseV2 or self.authority != OPERATION_LEASE_AUTHORITY_V2:
            _fail("v2 operation lease authority is invalid or substituted")
        binding.validate(crypto)
        binding_sha256 = capability_binding_sha256_v2(binding, crypto)
        exact = {
            "binding_sha256": binding_sha256,
            "session_id": binding.session_id,
            "session_epoch": binding.session_epoch,
            "factory_id": binding.factory_id,
            "role": binding.role,
            "effect_deadline_ns": binding.effect_deadline_ns,
            "closure_deadline_ns": binding.closure_deadline_ns,
            "owner_object_id": binding.owner.object_id,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 operation lease " + name + " differs from immutable binding")
        _positive_int(self.sequence, "v2 lease sequence")
        _token(self.operation_id, "v2 lease operation")
        _token(self.operation_purpose, "v2 lease purpose")
        _hex64(self.request_id, "v2 lease request")
        _hex64(self.challenge, "v2 lease challenge")
        policy = factory_operation_table_v2(binding.factory_id).operation(
            self.operation_id, self.operation_purpose)
        if self.sequence != policy.sequence:
            _fail("v2 lease sequence differs from immutable operation plan")
        expected_request = _operation_request_id_v2(
            crypto, self.binding_sha256, self.session_epoch, self.sequence,
            self.operation_id, self.operation_purpose, self.challenge,
            self.effect_deadline_ns, self.closure_deadline_ns)
        if self.request_id != expected_request:
            _fail("v2 lease request ID does not bind its deadlines and purpose")
        return policy

    def wire(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "challenge": self.challenge,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "factory_id": self.factory_id,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "owner_object_id": self.owner_object_id,
            "request_id": self.request_id,
            "role": self.role,
            "sequence": self.sequence,
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
        }


def make_operation_lease_v2(
        binding: CapabilityBindingBodyV2, operation_id: str,
        operation_purpose: str, challenge: str,
        crypto: CryptoProvider) -> OperationLeaseV2:
    binding.validate(crypto)
    policy = factory_operation_table_v2(binding.factory_id).operation(
        operation_id, operation_purpose)
    _hex64(challenge, "v2 lease challenge")
    binding_sha256 = capability_binding_sha256_v2(binding, crypto)
    request_id = _operation_request_id_v2(
        crypto, binding_sha256, binding.session_epoch, policy.sequence,
        policy.operation_id, policy.operation_purpose, challenge,
        binding.effect_deadline_ns, binding.closure_deadline_ns)
    value = OperationLeaseV2(
        OPERATION_LEASE_AUTHORITY_V2, binding_sha256, binding.session_id,
        binding.session_epoch, binding.factory_id, binding.role, policy.sequence,
        policy.operation_id, policy.operation_purpose, request_id, challenge,
        binding.effect_deadline_ns, binding.closure_deadline_ns,
        binding.owner.object_id)
    value.validate(binding, crypto)
    return value


@dataclass(frozen=True)
class DetachedPayloadV2:
    authority: str
    binding_sha256: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    payload_role: str
    ordinal: int
    canonical: bytes = field(repr=False)
    sha256: str

    def validate(self, lease: OperationLeaseV2, maximum: int,
                 crypto: CryptoProvider) -> None:
        if type(self) is not DetachedPayloadV2 or self.authority != DETACHED_PAYLOAD_AUTHORITY_V2:
            _fail("v2 detached payload authority is invalid or substituted")
        _positive_int(maximum, "v2 detached payload maximum")
        if maximum > MAX_PAYLOAD_BYTES:
            _fail("v2 detached payload maximum exceeds protocol bound")
        exact = {
            "binding_sha256": lease.binding_sha256,
            "request_id": lease.request_id,
            "operation_id": lease.operation_id,
            "operation_purpose": lease.operation_purpose,
            "effect_deadline_ns": lease.effect_deadline_ns,
            "closure_deadline_ns": lease.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 detached payload " + name + " differs from lease authority")
        if type(self.payload_role) is not str or self.payload_role not in _V2_PAYLOAD_ROLES:
            _fail("v2 detached payload role is outside the fixed registry")
        _positive_int(self.ordinal, "v2 detached payload ordinal", allow_zero=True)
        if (self.payload_role == "callback") != (self.ordinal > 0):
            _fail("v2 detached payload ordinal differs from its role")
        _exact(self.canonical, bytes, "v2 detached payload bytes")
        if not self.canonical or len(self.canonical) > maximum:
            _fail("v2 detached payload is absent or oversized")
        decode_canonical_json(self.canonical)
        _hex64(self.sha256, "v2 detached payload digest")
        if self.sha256 != _digest_hex(crypto, self.canonical):
            _fail("v2 detached payload digest is invalid")

    @classmethod
    def from_value(cls, lease: OperationLeaseV2, payload_role: str,
                   value: Any, maximum: int, crypto: CryptoProvider,
                   ordinal: int = 0) -> "DetachedPayloadV2":
        raw = canonical_json(value)
        result = cls(
            DETACHED_PAYLOAD_AUTHORITY_V2, lease.binding_sha256,
            lease.request_id, lease.operation_id, lease.operation_purpose,
            lease.effect_deadline_ns, lease.closure_deadline_ns, payload_role,
            ordinal, raw, _digest_hex(crypto, raw))
        result.validate(lease, maximum, crypto)
        return result

    @classmethod
    def from_wire(cls, lease: OperationLeaseV2, payload_role: str,
                  raw: bytes, expected_sha256: str, maximum: int,
                  crypto: CryptoProvider, ordinal: int = 0) -> "DetachedPayloadV2":
        result = cls(
            DETACHED_PAYLOAD_AUTHORITY_V2, lease.binding_sha256,
            lease.request_id, lease.operation_id, lease.operation_purpose,
            lease.effect_deadline_ns, lease.closure_deadline_ns, payload_role,
            ordinal, raw, expected_sha256)
        result.validate(lease, maximum, crypto)
        return result

    def decode(self) -> Any:
        return decode_canonical_json(self.canonical)

    def wire(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "ordinal": self.ordinal,
            "payload_bytes": len(self.canonical),
            "payload_role": self.payload_role,
            "payload_sha256": self.sha256,
            "request_id": self.request_id,
        }


@dataclass(frozen=True)
class WirePacketV2:
    frame: bytes
    payload: bytes


def _v2_packet_mac_payload(header: dict[str, Any]) -> bytes:
    return b"rtl-reader-worker-capability-ipc-v2\x00" + canonical_json(header)


def make_wire_packet_v2(
        *, binding: CapabilityBindingBodyV2, lease: OperationLeaseV2,
        message_sequence: int, kind: str, body: dict[str, Any],
        payload: DetachedPayloadV2 | None, key: bytes,
        crypto: CryptoProvider) -> WirePacketV2:
    policy = lease.validate(binding, crypto)
    if type(kind) is not str or kind not in _V2_FRAME_KINDS:
        _fail("v2 frame kind is outside the closed registry")
    _positive_int(message_sequence, "v2 frame message sequence", allow_zero=True)
    _exact(body, dict, "v2 frame body")
    if payload is None:
        if kind not in {"barrier", "eof"}:
            _fail("v2 data frame lacks its detached payload")
        raw_payload = b""
        payload_role = "none"
        payload_sha256 = _digest_hex(crypto, b"")
    else:
        if kind in {"barrier", "eof"}:
            _fail("v2 terminal framing item carries an unexpected payload")
        payload.validate(lease, policy.maximum_payload_bytes, crypto)
        expected_role = {"request": "request", "callback": "callback", "reply": "result"}[kind]
        if payload.payload_role != expected_role:
            _fail("v2 detached payload role differs from its frame kind")
        raw_payload = payload.canonical
        payload_role = payload.payload_role
        payload_sha256 = payload.sha256
    header = {
        "authority": WIRE_PACKET_AUTHORITY_V2,
        "binding_sha256": lease.binding_sha256,
        "body": body,
        "challenge": lease.challenge,
        "closure_deadline_ns": lease.closure_deadline_ns,
        "effect_deadline_ns": lease.effect_deadline_ns,
        "factory_id": lease.factory_id,
        "kind": kind,
        "message_sequence": message_sequence,
        "operation_id": lease.operation_id,
        "operation_purpose": lease.operation_purpose,
        "payload_bytes": len(raw_payload),
        "payload_role": payload_role,
        "payload_sha256": payload_sha256,
        "request_id": lease.request_id,
        "role": lease.role,
        "sequence": lease.sequence,
        "session_epoch": lease.session_epoch,
        "session_id": lease.session_id,
        "version": PROTOCOL_VERSION_V2,
    }
    tag = _v2_authentication_tag(
        crypto, key, b"rtl-reader-worker-capability-ipc-v2\x00", header)
    raw = canonical_json({"header": header, "mac": tag})
    if len(raw) > MAX_FRAME_BYTES:
        _fail("v2 authenticated frame exceeds protocol maximum")
    return WirePacketV2(len(raw).to_bytes(4, "big") + raw, raw_payload)


def open_wire_packet_v2(
        packet: WirePacketV2, *, binding: CapabilityBindingBodyV2,
        lease: OperationLeaseV2, message_sequence: int, key: bytes,
        crypto: CryptoProvider) -> tuple[dict[str, Any], bytes]:
    lease.validate(binding, crypto)
    if type(packet) is not WirePacketV2:
        _fail("v2 wire packet is substituted")
    _exact(packet.frame, bytes, "v2 wire frame")
    _exact(packet.payload, bytes, "v2 wire payload")
    if len(packet.frame) < 5:
        _fail("v2 wire frame is partial")
    size = int.from_bytes(packet.frame[:4], "big")
    if size < 1 or size > MAX_FRAME_BYTES or len(packet.frame) != size + 4:
        _fail("v2 wire frame is partial, oversized, or trailing")
    envelope = decode_canonical_json(packet.frame[4:])
    if type(envelope) is not dict or set(envelope) != {"header", "mac"}:
        _fail("v2 packet envelope has missing or extra fields")
    header = envelope["header"]
    if type(header) is not dict or set(header) != _V2_HEADER_KEYS:
        _fail("v2 packet header has missing or extra fields")
    _hex64(envelope["mac"], "v2 packet HMAC")
    expected_tag = _v2_authentication_tag(
        crypto, key, b"rtl-reader-worker-capability-ipc-v2\x00", header)
    comparison = _call_unretained_provider(
        crypto, "compare_digest", bytes.fromhex(envelope["mac"]),
        bytes.fromhex(expected_tag))
    if type(comparison) is not bool or not comparison:
        _fail("v2 packet HMAC is invalid")
    exact = {
        "authority": WIRE_PACKET_AUTHORITY_V2,
        "binding_sha256": lease.binding_sha256,
        "challenge": lease.challenge,
        "closure_deadline_ns": lease.closure_deadline_ns,
        "effect_deadline_ns": lease.effect_deadline_ns,
        "factory_id": lease.factory_id,
        "message_sequence": message_sequence,
        "operation_id": lease.operation_id,
        "operation_purpose": lease.operation_purpose,
        "request_id": lease.request_id,
        "role": lease.role,
        "sequence": lease.sequence,
        "session_epoch": lease.session_epoch,
        "session_id": lease.session_id,
        "version": PROTOCOL_VERSION_V2,
    }
    for name, expected in exact.items():
        current = header.get(name)
        if type(current) is not type(expected) or current != expected:
            _fail("v2 packet " + name + " differs from immutable lease")
    if (type(header["payload_bytes"]) is not int or
            header["payload_bytes"] != len(packet.payload) or
            header["payload_sha256"] != _digest_hex(crypto, packet.payload)):
        _fail("v2 detached payload length or digest is invalid")
    if type(header["kind"]) is not str or header["kind"] not in _V2_FRAME_KINDS:
        _fail("v2 authenticated frame kind is invalid")
    if type(header["body"]) is not dict:
        _fail("v2 authenticated frame body is inexact")
    kind = header["kind"]
    expected_role = {
        "request": "request", "callback": "callback", "reply": "result",
        "barrier": "none", "eof": "none",
    }[kind]
    if type(header["payload_role"]) is not str or header["payload_role"] != expected_role:
        _fail("v2 authenticated payload role differs from frame kind")
    if kind in {"barrier", "eof"}:
        if packet.payload != b"" or header["payload_sha256"] != _digest_hex(crypto, b""):
            _fail("v2 barrier/EOF frame carries an unexpected payload")
    else:
        ordinal = 0
        if kind == "callback":
            ordinal = header["body"].get("ordinal")
            _positive_int(ordinal, "v2 callback payload ordinal")
        DetachedPayloadV2.from_wire(
            lease, expected_role, packet.payload, header["payload_sha256"],
            factory_operation_table_v2(binding.factory_id).operation(
                lease.operation_id, lease.operation_purpose).maximum_payload_bytes,
            crypto, ordinal)
    return header, packet.payload


@dataclass(frozen=True)
class CallbackRecordV2:
    lease: OperationLeaseV2
    ordinal: int
    event: str
    payload: DetachedPayloadV2

    def validate(self, binding: CapabilityBindingBodyV2,
                 crypto: CryptoProvider) -> None:
        policy = self.lease.validate(binding, crypto)
        _positive_int(self.ordinal, "v2 callback ordinal")
        if type(self.event) is not str or self.event not in policy.callback_events:
            _fail("v2 callback event is outside immutable operation policy")
        if self.ordinal > policy.maximum_callbacks:
            _fail("v2 callback ordinal exceeds immutable operation policy")
        self.payload.validate(self.lease, policy.maximum_payload_bytes, crypto)
        if self.payload.payload_role != "callback" or self.payload.ordinal != self.ordinal:
            _fail("v2 callback payload role or ordinal differs from callback record")

    def wire(self) -> dict[str, Any]:
        return {"event": self.event, "ordinal": self.ordinal,
                "payload": self.payload.wire()}


@dataclass(frozen=True)
class OperationSettlementEvidenceV2:
    """Authenticated callback/barrier/reply/EOF transcript and drain proof."""

    authority: str
    binding_sha256: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    transcript: tuple[WirePacketV2, ...] = field(compare=False, repr=False)
    callback_drain_challenge: "QuiescenceChallengeV2"
    callback_drain_receipt: "QuiescenceReceiptV2"
    transcript_sha256: str
    evidence_sha256: str

    def wire(self, crypto: CryptoProvider, *,
             include_digest: bool = True) -> dict[str, Any]:
        packet_digests = tuple(
            _wire_packet_sha256_v2(item, crypto) for item in self.transcript)
        return _operation_settlement_wire_v2(
            self, packet_digests, include_digest=include_digest)

    def validate(self, binding: CapabilityBindingBodyV2, lease: OperationLeaseV2,
                 key: bytes, crypto: CryptoProvider) -> tuple[
                     tuple[CallbackRecordV2, ...], DetachedPayloadV2]:
        if (type(self) is not OperationSettlementEvidenceV2 or
                self.authority != OPERATION_SETTLEMENT_EVIDENCE_AUTHORITY_V2):
            _fail("v2 operation settlement evidence is invalid or substituted")
        exact = {
            "binding_sha256": lease.binding_sha256,
            "request_id": lease.request_id,
            "operation_id": lease.operation_id,
            "operation_purpose": lease.operation_purpose,
            "effect_deadline_ns": lease.effect_deadline_ns,
            "closure_deadline_ns": lease.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 operation settlement " + name + " differs from lease")
        policy = lease.validate(binding, crypto)
        if (type(self.transcript) is not tuple or len(self.transcript) < 3 or
                len(self.transcript) > policy.maximum_callbacks + 3):
            _fail("v2 operation settlement transcript has an invalid exact bound")
        callback_packets = self.transcript[:-3]
        barrier_packet, reply_packet, eof_packet = self.transcript[-3:]
        callbacks: list[CallbackRecordV2] = []
        message_sequence = 1
        for packet in callback_packets:
            header, raw = open_wire_packet_v2(
                packet, binding=binding, lease=lease,
                message_sequence=message_sequence, key=key, crypto=crypto)
            if (header["kind"] != "callback" or
                    set(header["body"]) != {"event", "ordinal"} or
                    type(header["body"]["ordinal"]) is not int or
                    header["body"]["ordinal"] != message_sequence):
                _fail("v2 callback transcript is reordered or malformed")
            payload = DetachedPayloadV2.from_wire(
                lease, "callback", raw, header["payload_sha256"],
                policy.maximum_payload_bytes, crypto, message_sequence)
            callback = CallbackRecordV2(
                lease, message_sequence, header["body"]["event"], payload)
            callback.validate(binding, crypto)
            callbacks.append(callback)
            message_sequence += 1
        barrier_header, _ = open_wire_packet_v2(
            barrier_packet, binding=binding, lease=lease,
            message_sequence=message_sequence, key=key, crypto=crypto)
        if (barrier_header["kind"] != "barrier" or
                set(barrier_header["body"]) != {"callback_count"} or
                type(barrier_header["body"]["callback_count"]) is not int or
                barrier_header["body"]["callback_count"] != len(callbacks)):
            _fail("v2 callback barrier is absent, reordered, or malformed")
        message_sequence += 1
        reply_header, reply_raw = open_wire_packet_v2(
            reply_packet, binding=binding, lease=lease,
            message_sequence=message_sequence, key=key, crypto=crypto)
        expected_reply_body = {
            "callback_drain_challenge_id": self.callback_drain_challenge.challenge_id,
            "callback_drain_receipt_sha256": self.callback_drain_receipt.receipt_sha256,
            "status": "ok",
        }
        if reply_header["kind"] != "reply" or reply_header["body"] != expected_reply_body:
            _fail("v2 reply lacks exact authenticated callback-drain binding")
        result = DetachedPayloadV2.from_wire(
            lease, "result", reply_raw, reply_header["payload_sha256"],
            policy.maximum_payload_bytes, crypto)
        message_sequence += 1
        eof_header, _ = open_wire_packet_v2(
            eof_packet, binding=binding, lease=lease,
            message_sequence=message_sequence, key=key, crypto=crypto)
        if eof_header["kind"] != "eof" or eof_header["body"] != {}:
            _fail("v2 operation transcript lacks exact authenticated EOF")
        self.callback_drain_challenge.validate(lease, crypto)
        if (self.callback_drain_challenge.phase != "operation.settle" or
                self.callback_drain_challenge.participants != ("callback_drain",)):
            _fail("v2 operation settlement uses the wrong quiescence proof")
        self.callback_drain_receipt.validate(
            self.callback_drain_challenge, "callback_drain", crypto)
        packet_digests = tuple(
            _wire_packet_sha256_v2(item, crypto) for item in self.transcript)
        expected_transcript = _digest_hex(
            crypto, b"rtl-reader-operation-transcript-v2\x00" +
            canonical_json(list(packet_digests)))
        if self.transcript_sha256 != expected_transcript:
            _fail("v2 operation settlement transcript digest is invalid")
        _hex64(self.evidence_sha256, "v2 settlement evidence digest")
        expected_evidence = _digest_hex(
            crypto, b"rtl-reader-operation-settlement-evidence-v2\x00" +
            canonical_json(_operation_settlement_wire_v2(
                self, packet_digests, include_digest=False)))
        if self.evidence_sha256 != expected_evidence:
            _fail("v2 operation settlement evidence digest is invalid")
        return tuple(callbacks), result


def _wire_packet_sha256_v2(packet: WirePacketV2, crypto: CryptoProvider) -> str:
    if type(packet) is not WirePacketV2:
        _fail("v2 transcript packet is substituted")
    return _digest_hex(
        crypto, b"rtl-reader-wire-packet-v2\x00" +
        len(packet.frame).to_bytes(8, "big") + packet.frame + packet.payload)


def _operation_settlement_wire_v2(
        evidence: OperationSettlementEvidenceV2,
        packet_digests: tuple[str, ...], *, include_digest: bool) -> dict[str, Any]:
    value = {
        "authority": evidence.authority,
        "binding_sha256": evidence.binding_sha256,
        "callback_drain_challenge": evidence.callback_drain_challenge.wire(),
        "callback_drain_receipt": evidence.callback_drain_receipt.wire(),
        "closure_deadline_ns": evidence.closure_deadline_ns,
        "effect_deadline_ns": evidence.effect_deadline_ns,
        "operation_id": evidence.operation_id,
        "operation_purpose": evidence.operation_purpose,
        "request_id": evidence.request_id,
        "transcript_packet_sha256": list(packet_digests),
        "transcript_sha256": evidence.transcript_sha256,
    }
    if include_digest:
        value["evidence_sha256"] = evidence.evidence_sha256
    return value


@dataclass(frozen=True)
class OperationOutcomeV2:
    authority: str
    binding_sha256: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    lease: OperationLeaseV2
    result: DetachedPayloadV2
    callbacks: tuple[CallbackRecordV2, ...]
    settlement_evidence: OperationSettlementEvidenceV2
    cleanup_completed: bool
    outcome_sha256: str

    def wire(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "callbacks": [item.wire() for item in self.callbacks],
            "cleanup_completed": self.cleanup_completed,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "lease": self.lease.wire(),
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "request_id": self.request_id,
            "result": self.result.wire(),
            "settlement_evidence_sha256": self.settlement_evidence.evidence_sha256,
        }
        if include_digest:
            value["outcome_sha256"] = self.outcome_sha256
        return value

    def validate(self, binding: CapabilityBindingBodyV2, key: bytes,
                 crypto: CryptoProvider) -> OperationPurposeV2:
        if type(self) is not OperationOutcomeV2 or self.authority != OPERATION_OUTCOME_AUTHORITY_V2:
            _fail("v2 operation outcome authority is invalid or substituted")
        policy = self.lease.validate(binding, crypto)
        exact = {
            "binding_sha256": self.lease.binding_sha256,
            "request_id": self.lease.request_id,
            "operation_id": self.lease.operation_id,
            "operation_purpose": self.lease.operation_purpose,
            "effect_deadline_ns": self.lease.effect_deadline_ns,
            "closure_deadline_ns": self.lease.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 operation outcome " + name + " differs from immutable lease")
        callbacks, result = self.settlement_evidence.validate(
            binding, self.lease, key, crypto)
        self.result.validate(self.lease, policy.maximum_payload_bytes, crypto)
        if self.result.payload_role != "result":
            _fail("v2 operation outcome result has the wrong detached payload role")
        if type(self.callbacks) is not tuple or len(self.callbacks) > policy.maximum_callbacks:
            _fail("v2 operation outcome callback set is mutable or oversized")
        for ordinal, callback in enumerate(self.callbacks, 1):
            callback.validate(binding, crypto)
            if callback.lease != self.lease or callback.ordinal != ordinal:
                _fail("v2 operation outcome callbacks are reordered or cross-lease")
        if self.callbacks != callbacks or self.result != result:
            _fail("v2 outcome differs from its authenticated settlement transcript")
        expected_cleanup = policy.operation_purpose == FRIDA_CLEANUP_PURPOSE_V2
        if type(self.cleanup_completed) is not bool or self.cleanup_completed != expected_cleanup:
            _fail("v2 cleanup outcome does not identify exact seq2 cleanup")
        _hex64(self.outcome_sha256, "v2 operation outcome digest")
        if self.outcome_sha256 != _digest_hex(
                crypto, b"rtl-reader-operation-outcome-v2\x00" +
                canonical_json(self.wire(include_digest=False))):
            _fail("v2 operation outcome digest is invalid")
        return policy


def make_operation_outcome_v2(
        binding: CapabilityBindingBodyV2, lease: OperationLeaseV2,
        transcript: tuple[WirePacketV2, ...],
        callback_drain_challenge: "QuiescenceChallengeV2",
        callback_drain_receipt: "QuiescenceReceiptV2",
        key: bytes, crypto: CryptoProvider) -> OperationOutcomeV2:
    """Verify an authenticated transcript and then materialize its outcome."""

    policy = lease.validate(binding, crypto)
    if type(transcript) is not tuple:
        _fail("v2 settlement transcript must be an exact tuple")
    packet_digests = tuple(_wire_packet_sha256_v2(item, crypto) for item in transcript)
    transcript_digest = _digest_hex(
        crypto, b"rtl-reader-operation-transcript-v2\x00" +
        canonical_json(list(packet_digests)))
    provisional_evidence = OperationSettlementEvidenceV2(
        OPERATION_SETTLEMENT_EVIDENCE_AUTHORITY_V2, lease.binding_sha256,
        lease.request_id, lease.operation_id, lease.operation_purpose,
        lease.effect_deadline_ns, lease.closure_deadline_ns, transcript,
        callback_drain_challenge, callback_drain_receipt, transcript_digest,
        "0" * 64)
    evidence_digest = _digest_hex(
        crypto, b"rtl-reader-operation-settlement-evidence-v2\x00" +
        canonical_json(_operation_settlement_wire_v2(
            provisional_evidence, packet_digests, include_digest=False)))
    evidence = OperationSettlementEvidenceV2(
        provisional_evidence.authority, provisional_evidence.binding_sha256,
        provisional_evidence.request_id, provisional_evidence.operation_id,
        provisional_evidence.operation_purpose,
        provisional_evidence.effect_deadline_ns,
        provisional_evidence.closure_deadline_ns,
        provisional_evidence.transcript,
        provisional_evidence.callback_drain_challenge,
        provisional_evidence.callback_drain_receipt,
        provisional_evidence.transcript_sha256, evidence_digest)
    callbacks, result = evidence.validate(binding, lease, key, crypto)
    provisional = OperationOutcomeV2(
        OPERATION_OUTCOME_AUTHORITY_V2, lease.binding_sha256, lease.request_id,
        lease.operation_id, lease.operation_purpose, lease.effect_deadline_ns,
        lease.closure_deadline_ns, lease, result, callbacks, evidence,
        policy.operation_purpose == FRIDA_CLEANUP_PURPOSE_V2, "0" * 64)
    digest_value = _digest_hex(
        crypto, b"rtl-reader-operation-outcome-v2\x00" +
        canonical_json(provisional.wire(include_digest=False)))
    value = OperationOutcomeV2(
        provisional.authority, provisional.binding_sha256,
        provisional.request_id, provisional.operation_id,
        provisional.operation_purpose, provisional.effect_deadline_ns,
        provisional.closure_deadline_ns, provisional.lease, provisional.result,
        provisional.callbacks, provisional.settlement_evidence,
        provisional.cleanup_completed, digest_value)
    value.validate(binding, key, crypto)
    return value


verify_operation_outcome_v2 = make_operation_outcome_v2


@dataclass(frozen=True)
class QuiescenceChallengeV2:
    authority: str
    binding_sha256: str
    session_epoch: str
    generation: int
    phase: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    participants: tuple[str, ...]
    nonce: str
    challenge_id: str

    def wire(self, *, include_id: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "generation": self.generation,
            "nonce": self.nonce,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "participants": list(self.participants),
            "phase": self.phase,
            "request_id": self.request_id,
            "session_epoch": self.session_epoch,
        }
        if include_id:
            value["challenge_id"] = self.challenge_id
        return value

    def validate(self, lease: OperationLeaseV2,
                 crypto: CryptoProvider) -> None:
        if (type(self) is not QuiescenceChallengeV2 or
                self.authority != QUIESCENCE_CHALLENGE_AUTHORITY_V2):
            _fail("v2 quiescence challenge authority is invalid or substituted")
        exact = {
            "binding_sha256": lease.binding_sha256,
            "session_epoch": lease.session_epoch,
            "request_id": lease.request_id,
            "operation_id": lease.operation_id,
            "operation_purpose": lease.operation_purpose,
            "effect_deadline_ns": lease.effect_deadline_ns,
            "closure_deadline_ns": lease.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 quiescence challenge " + name + " differs from lease")
        _positive_int(self.generation, "v2 quiescence generation", allow_zero=True)
        _token(self.phase, "v2 quiescence phase")
        _v2_exact_token_tuple(self.participants, "v2 quiescence participants")
        _hex64(self.nonce, "v2 quiescence nonce")
        _hex64(self.challenge_id, "v2 quiescence challenge ID")
        if self.challenge_id != _digest_hex(
                crypto, b"rtl-reader-quiescence-challenge-v2\x00" +
                canonical_json(self.wire(include_id=False))):
            _fail("v2 quiescence challenge does not bind deadlines and purpose")


def make_quiescence_challenge_v2(
        lease: OperationLeaseV2, generation: int, phase: str,
        participants: tuple[str, ...], nonce: str,
        crypto: CryptoProvider) -> QuiescenceChallengeV2:
    provisional = QuiescenceChallengeV2(
        QUIESCENCE_CHALLENGE_AUTHORITY_V2, lease.binding_sha256,
        lease.session_epoch, generation, phase, lease.request_id,
        lease.operation_id, lease.operation_purpose, lease.effect_deadline_ns,
        lease.closure_deadline_ns, participants, nonce, "0" * 64)
    challenge_id = _digest_hex(
        crypto, b"rtl-reader-quiescence-challenge-v2\x00" +
        canonical_json(provisional.wire(include_id=False)))
    value = QuiescenceChallengeV2(
        provisional.authority, provisional.binding_sha256,
        provisional.session_epoch, provisional.generation, provisional.phase,
        provisional.request_id, provisional.operation_id,
        provisional.operation_purpose, provisional.effect_deadline_ns,
        provisional.closure_deadline_ns, provisional.participants,
        provisional.nonce, challenge_id)
    value.validate(lease, crypto)
    return value


@dataclass(frozen=True)
class QuiescenceReceiptV2:
    authority: str
    challenge_id: str
    binding_sha256: str
    session_epoch: str
    generation: int
    component: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    evidence_sha256: str
    receipt_sha256: str

    def wire(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "challenge_id": self.challenge_id,
            "closure_deadline_ns": self.closure_deadline_ns,
            "component": self.component,
            "effect_deadline_ns": self.effect_deadline_ns,
            "evidence_sha256": self.evidence_sha256,
            "generation": self.generation,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "request_id": self.request_id,
            "session_epoch": self.session_epoch,
        }
        if include_digest:
            value["receipt_sha256"] = self.receipt_sha256
        return value

    def validate(self, challenge: QuiescenceChallengeV2,
                 component: str, crypto: CryptoProvider) -> None:
        if type(self) is not QuiescenceReceiptV2 or self.authority != QUIESCENCE_RECEIPT_AUTHORITY_V2:
            _fail("v2 quiescence receipt authority is invalid or substituted")
        _token(component, "v2 quiescence component")
        if component not in challenge.participants:
            _fail("v2 quiescence component is outside the challenge")
        exact = {
            "challenge_id": challenge.challenge_id,
            "binding_sha256": challenge.binding_sha256,
            "session_epoch": challenge.session_epoch,
            "generation": challenge.generation,
            "component": component,
            "request_id": challenge.request_id,
            "operation_id": challenge.operation_id,
            "operation_purpose": challenge.operation_purpose,
            "effect_deadline_ns": challenge.effect_deadline_ns,
            "closure_deadline_ns": challenge.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 quiescence receipt " + name + " differs from challenge")
        _hex64(self.evidence_sha256, "v2 quiescence evidence")
        _hex64(self.receipt_sha256, "v2 quiescence receipt digest")
        if self.receipt_sha256 != _digest_hex(
                crypto, b"rtl-reader-quiescence-receipt-v2\x00" +
                canonical_json(self.wire(include_digest=False))):
            _fail("v2 quiescence receipt digest is invalid")


def make_quiescence_receipt_v2(
        challenge: QuiescenceChallengeV2, component: str,
        evidence_sha256: str, crypto: CryptoProvider) -> QuiescenceReceiptV2:
    provisional = QuiescenceReceiptV2(
        QUIESCENCE_RECEIPT_AUTHORITY_V2, challenge.challenge_id,
        challenge.binding_sha256, challenge.session_epoch,
        challenge.generation, component, challenge.request_id,
        challenge.operation_id, challenge.operation_purpose,
        challenge.effect_deadline_ns, challenge.closure_deadline_ns,
        evidence_sha256, "0" * 64)
    digest_value = _digest_hex(
        crypto, b"rtl-reader-quiescence-receipt-v2\x00" +
        canonical_json(provisional.wire(include_digest=False)))
    value = QuiescenceReceiptV2(
        provisional.authority, provisional.challenge_id,
        provisional.binding_sha256, provisional.session_epoch,
        provisional.generation, provisional.component, provisional.request_id,
        provisional.operation_id, provisional.operation_purpose,
        provisional.effect_deadline_ns, provisional.closure_deadline_ns,
        provisional.evidence_sha256, digest_value)
    value.validate(challenge, component, crypto)
    return value


@dataclass(frozen=True)
class CleanupExpiryReceiptV2:
    """Authenticated hand-off from an expired effect to bounded cleanup.

    The original reserved slot and a non-null checkpoint are mandatory; the
    receipt never grants a fresh effect window and is valid only before the
    immutable closure deadline.
    """

    authority: str
    binding_sha256: str
    session_epoch: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    observed_at_ns: int
    original_reserved_slot: int
    checkpoint_sha256: str
    receipt_id: str
    authentication_tag: str

    def wire(self, *, include_authentication: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "checkpoint_sha256": self.checkpoint_sha256,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "observed_at_ns": self.observed_at_ns,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "original_reserved_slot": self.original_reserved_slot,
            "request_id": self.request_id,
            "session_epoch": self.session_epoch,
        }
        if include_authentication:
            value["authentication_tag"] = self.authentication_tag
            value["receipt_id"] = self.receipt_id
        return value

    def validate(self, lease: OperationLeaseV2, key: bytes,
                 crypto: CryptoProvider) -> None:
        if (type(self) is not CleanupExpiryReceiptV2 or
                self.authority != CLEANUP_EXPIRY_RECEIPT_AUTHORITY_V2):
            _fail("v2 cleanup-expiry receipt authority is invalid or substituted")
        exact = {
            "binding_sha256": lease.binding_sha256,
            "session_epoch": lease.session_epoch,
            "request_id": lease.request_id,
            "operation_id": lease.operation_id,
            "operation_purpose": lease.operation_purpose,
            "effect_deadline_ns": lease.effect_deadline_ns,
            "closure_deadline_ns": lease.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 cleanup-expiry " + name + " differs from lease")
        if (lease.sequence != 1 or lease.operation_id != FRIDA_CAPTURE_OPERATION_V2 or
                lease.operation_purpose != FRIDA_CAPTURE_PURPOSE_V2):
            _fail("v2 cleanup-expiry receipt does not hand off expired capture")
        _positive_int(self.observed_at_ns, "v2 cleanup-expiry observation")
        if not self.effect_deadline_ns <= self.observed_at_ns < self.closure_deadline_ns:
            _fail("v2 cleanup-expiry observation is outside the closure-only window")
        _positive_int(self.original_reserved_slot, "v2 cleanup reserved slot")
        if self.original_reserved_slot != 2:
            _fail("v2 cleanup-expiry receipt does not preserve reserved seq2 cleanup")
        _hex64(self.checkpoint_sha256, "v2 cleanup checkpoint")
        _hex64(self.receipt_id, "v2 cleanup-expiry receipt ID")
        _hex64(self.authentication_tag, "v2 cleanup-expiry authentication tag")
        body = self.wire(include_authentication=False)
        expected_id = _digest_hex(
            crypto, b"rtl-reader-cleanup-expiry-receipt-v2\x00" + canonical_json(body))
        if self.receipt_id != expected_id:
            _fail("v2 cleanup-expiry receipt ID is invalid")
        expected_tag = _v2_authentication_tag(
            crypto, key, b"rtl-reader-cleanup-expiry-auth-v2\x00",
            {"body": body, "receipt_id": self.receipt_id})
        comparison = _call_unretained_provider(
            crypto, "compare_digest", bytes.fromhex(self.authentication_tag),
            bytes.fromhex(expected_tag))
        if type(comparison) is not bool or not comparison:
            _fail("v2 cleanup-expiry receipt authentication is invalid")


def make_cleanup_expiry_receipt_v2(
        lease: OperationLeaseV2, observed_at_ns: int,
        original_reserved_slot: int, checkpoint_sha256: str,
        key: bytes, crypto: CryptoProvider) -> CleanupExpiryReceiptV2:
    body = {
        "authority": CLEANUP_EXPIRY_RECEIPT_AUTHORITY_V2,
        "binding_sha256": lease.binding_sha256,
        "checkpoint_sha256": checkpoint_sha256,
        "closure_deadline_ns": lease.closure_deadline_ns,
        "effect_deadline_ns": lease.effect_deadline_ns,
        "observed_at_ns": observed_at_ns,
        "operation_id": lease.operation_id,
        "operation_purpose": lease.operation_purpose,
        "original_reserved_slot": original_reserved_slot,
        "request_id": lease.request_id,
        "session_epoch": lease.session_epoch,
    }
    receipt_id = _digest_hex(
        crypto, b"rtl-reader-cleanup-expiry-receipt-v2\x00" + canonical_json(body))
    tag = _v2_authentication_tag(
        crypto, key, b"rtl-reader-cleanup-expiry-auth-v2\x00",
        {"body": body, "receipt_id": receipt_id})
    value = CleanupExpiryReceiptV2(
        body["authority"], body["binding_sha256"], body["session_epoch"],
        body["request_id"], body["operation_id"], body["operation_purpose"],
        body["effect_deadline_ns"], body["closure_deadline_ns"],
        body["observed_at_ns"], body["original_reserved_slot"],
        body["checkpoint_sha256"], receipt_id, tag)
    value.validate(lease, key, crypto)
    return value


@dataclass(frozen=True)
class OpenOperationIdleReceiptV2:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    generation: int
    state: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    active_operations: int
    live_callbacks: int
    epoch_admitted_sides: tuple[str, ...]
    open_endpoints: tuple[str, ...]
    terminal: bool
    receipt_id: str
    authentication_tag: str

    def wire(self, *, include_authentication: bool = True) -> dict[str, Any]:
        value = {
            "active_operations": self.active_operations,
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "epoch_admitted_sides": list(self.epoch_admitted_sides),
            "generation": self.generation,
            "live_callbacks": self.live_callbacks,
            "open_endpoints": list(self.open_endpoints),
            "operation_purpose": self.operation_purpose,
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
            "state": self.state,
            "terminal": self.terminal,
        }
        if include_authentication:
            value["authentication_tag"] = self.authentication_tag
            value["receipt_id"] = self.receipt_id
        return value

    def validate(self, binding: CapabilityBindingBodyV2, key: bytes,
                 crypto: CryptoProvider) -> None:
        if (type(self) is not OpenOperationIdleReceiptV2 or
                self.authority != OPEN_OPERATION_IDLE_RECEIPT_AUTHORITY_V2):
            _fail("v2 OPEN-idle receipt authority is invalid or substituted")
        exact = {
            "binding_sha256": capability_binding_sha256_v2(binding, crypto),
            "session_id": binding.session_id,
            "session_epoch": binding.session_epoch,
            "effect_deadline_ns": binding.effect_deadline_ns,
            "closure_deadline_ns": binding.closure_deadline_ns,
        }
        for name, expected in exact.items():
            if getattr(self, name) != expected:
                _fail("v2 OPEN-idle receipt differs from immutable binding")
        _positive_int(self.generation, "v2 OPEN-idle generation", allow_zero=True)
        if (self.state != "OPEN" or self.operation_purpose != OPERATION_IDLE_PURPOSE_V2 or
                type(self.active_operations) is not int or self.active_operations != 0 or
                type(self.live_callbacks) is not int or self.live_callbacks != 0 or
                self.epoch_admitted_sides != _V2_EPOCH_SIDES or
                self.open_endpoints != _V2_ENDPOINT_IDS or self.terminal is not False):
            _fail("v2 OPEN-idle receipt was confused with terminal closure")
        body = self.wire(include_authentication=False)
        _hex64(self.receipt_id, "v2 OPEN-idle receipt ID")
        _hex64(self.authentication_tag, "v2 OPEN-idle authentication tag")
        if self.receipt_id != _digest_hex(
                crypto, b"rtl-reader-open-operation-idle-v2\x00" + canonical_json(body)):
            _fail("v2 OPEN-idle receipt ID is invalid")
        expected_tag = _v2_authentication_tag(
            crypto, key, b"rtl-reader-open-operation-idle-auth-v2\x00",
            {"body": body, "receipt_id": self.receipt_id})
        comparison = _call_unretained_provider(
            crypto, "compare_digest", bytes.fromhex(self.authentication_tag),
            bytes.fromhex(expected_tag))
        if type(comparison) is not bool or not comparison:
            _fail("v2 OPEN-idle receipt authentication is invalid")


_V2_CLOSURE_COMPONENT_SPECS = (
    (("authenticated_eof", direction) for direction in _V2_DIRECTIONS),
    (("direction_sealed", direction) for direction in _V2_DIRECTIONS),
    (("direction_drained", direction) for direction in _V2_DIRECTIONS),
    iter((("operations_zero", "session"), ("callbacks_zero", "session"))),
    (("epoch_revoked", side) for side in _V2_EPOCH_SIDES),
    (("endpoint_closed", endpoint) for endpoint in _V2_ENDPOINT_IDS),
    iter((("owner_closed", "parent_owner"),)),
)
_V2_CLOSURE_COMPONENT_SPECS = tuple(
    item for group in _V2_CLOSURE_COMPONENT_SPECS for item in group)


@dataclass(frozen=True)
class SessionClosureRequestV2:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    factory_id: str
    role: str
    generation: int
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    required_components: tuple[tuple[str, str], ...]
    request_id: str
    authentication_tag: str

    def wire(self, *, include_authentication: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "closure_deadline_ns": self.closure_deadline_ns,
            "effect_deadline_ns": self.effect_deadline_ns,
            "factory_id": self.factory_id,
            "generation": self.generation,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "required_components": [list(item) for item in self.required_components],
            "role": self.role,
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
        }
        if include_authentication:
            value["authentication_tag"] = self.authentication_tag
            value["request_id"] = self.request_id
        return value

    def validate(self, binding: CapabilityBindingBodyV2, key: bytes,
                 crypto: CryptoProvider) -> None:
        if (type(self) is not SessionClosureRequestV2 or
                self.authority != SESSION_CLOSURE_REQUEST_AUTHORITY_V2):
            _fail("v2 closure request authority is invalid or substituted")
        exact = {
            "binding_sha256": capability_binding_sha256_v2(binding, crypto),
            "session_id": binding.session_id,
            "session_epoch": binding.session_epoch,
            "factory_id": binding.factory_id,
            "role": binding.role,
            "effect_deadline_ns": binding.effect_deadline_ns,
            "closure_deadline_ns": binding.closure_deadline_ns,
        }
        for name, expected in exact.items():
            if getattr(self, name) != expected:
                _fail("v2 closure request differs from immutable capability binding")
        _positive_int(self.generation, "v2 closure generation")
        if (self.operation_id != SESSION_CLOSE_OPERATION_V2 or
                self.operation_purpose != SESSION_CLOSE_PURPOSE_V2 or
                self.required_components != _V2_CLOSURE_COMPONENT_SPECS):
            _fail("v2 closure request differs from the fixed terminal plan")
        body = self.wire(include_authentication=False)
        _hex64(self.request_id, "v2 closure request ID")
        _hex64(self.authentication_tag, "v2 closure request authentication")
        if self.request_id != _digest_hex(
                crypto, b"rtl-reader-session-closure-request-v2\x00" +
                canonical_json(body)):
            _fail("v2 closure request ID is invalid")
        expected_tag = _v2_authentication_tag(
            crypto, key, b"rtl-reader-session-closure-request-auth-v2\x00",
            {"body": body, "request_id": self.request_id})
        comparison = _call_unretained_provider(
            crypto, "compare_digest", bytes.fromhex(self.authentication_tag),
            bytes.fromhex(expected_tag))
        if type(comparison) is not bool or not comparison:
            _fail("v2 closure request authentication is invalid")


def make_session_closure_request_v2(
        binding: CapabilityBindingBodyV2, generation: int,
        key: bytes, crypto: CryptoProvider) -> SessionClosureRequestV2:
    provisional = SessionClosureRequestV2(
        SESSION_CLOSURE_REQUEST_AUTHORITY_V2,
        capability_binding_sha256_v2(binding, crypto), binding.session_id,
        binding.session_epoch, binding.factory_id, binding.role, generation,
        SESSION_CLOSE_OPERATION_V2, SESSION_CLOSE_PURPOSE_V2,
        binding.effect_deadline_ns, binding.closure_deadline_ns,
        _V2_CLOSURE_COMPONENT_SPECS, "0" * 64, "0" * 64)
    body = provisional.wire(include_authentication=False)
    request_id = _digest_hex(
        crypto, b"rtl-reader-session-closure-request-v2\x00" + canonical_json(body))
    tag = _v2_authentication_tag(
        crypto, key, b"rtl-reader-session-closure-request-auth-v2\x00",
        {"body": body, "request_id": request_id})
    value = SessionClosureRequestV2(
        provisional.authority, provisional.binding_sha256,
        provisional.session_id, provisional.session_epoch,
        provisional.factory_id, provisional.role, provisional.generation,
        provisional.operation_id, provisional.operation_purpose,
        provisional.effect_deadline_ns, provisional.closure_deadline_ns,
        provisional.required_components, request_id, tag)
    value.validate(binding, key, crypto)
    return value


@dataclass(frozen=True)
class ClosureComponentReceiptV2:
    authority: str
    binding_sha256: str
    session_epoch: str
    generation: int
    closure_request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    component: str
    subject: str
    evidence_sha256: str
    receipt_sha256: str

    def wire(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "closure_deadline_ns": self.closure_deadline_ns,
            "closure_request_id": self.closure_request_id,
            "component": self.component,
            "effect_deadline_ns": self.effect_deadline_ns,
            "evidence_sha256": self.evidence_sha256,
            "generation": self.generation,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "session_epoch": self.session_epoch,
            "subject": self.subject,
        }
        if include_digest:
            value["receipt_sha256"] = self.receipt_sha256
        return value

    def validate(self, request: SessionClosureRequestV2,
                 component: str, subject: str, crypto: CryptoProvider) -> None:
        if (type(self) is not ClosureComponentReceiptV2 or
                self.authority != CLOSURE_COMPONENT_RECEIPT_AUTHORITY_V2):
            _fail("v2 closure component receipt is invalid or substituted")
        if (component, subject) not in request.required_components:
            _fail("v2 closure component is outside the fixed terminal plan")
        exact = {
            "binding_sha256": request.binding_sha256,
            "session_epoch": request.session_epoch,
            "generation": request.generation,
            "closure_request_id": request.request_id,
            "operation_id": request.operation_id,
            "operation_purpose": request.operation_purpose,
            "effect_deadline_ns": request.effect_deadline_ns,
            "closure_deadline_ns": request.closure_deadline_ns,
            "component": component,
            "subject": subject,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 closure component " + name + " differs from request")
        _hex64(self.evidence_sha256, "v2 closure component evidence")
        _hex64(self.receipt_sha256, "v2 closure component digest")
        if self.receipt_sha256 != _digest_hex(
                crypto, b"rtl-reader-closure-component-receipt-v2\x00" +
                canonical_json(self.wire(include_digest=False))):
            _fail("v2 closure component receipt digest is invalid")


def make_closure_component_receipt_v2(
        request: SessionClosureRequestV2, component: str, subject: str,
        evidence_sha256: str, crypto: CryptoProvider) -> ClosureComponentReceiptV2:
    provisional = ClosureComponentReceiptV2(
        CLOSURE_COMPONENT_RECEIPT_AUTHORITY_V2, request.binding_sha256,
        request.session_epoch, request.generation, request.request_id,
        request.operation_id, request.operation_purpose,
        request.effect_deadline_ns, request.closure_deadline_ns,
        component, subject, evidence_sha256, "0" * 64)
    digest_value = _digest_hex(
        crypto, b"rtl-reader-closure-component-receipt-v2\x00" +
        canonical_json(provisional.wire(include_digest=False)))
    value = ClosureComponentReceiptV2(
        provisional.authority, provisional.binding_sha256,
        provisional.session_epoch, provisional.generation,
        provisional.closure_request_id, provisional.operation_id,
        provisional.operation_purpose, provisional.effect_deadline_ns,
        provisional.closure_deadline_ns, provisional.component,
        provisional.subject, provisional.evidence_sha256, digest_value)
    value.validate(request, component, subject, crypto)
    return value


@dataclass(frozen=True)
class SuccessfulSessionClosureReceiptV2:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    factory_id: str
    role: str
    generation: int
    closure_request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    sealed_directions: tuple[str, ...]
    authenticated_eof_drained_directions: tuple[str, ...]
    active_operations: int
    live_callbacks: int
    revoked_epoch_sides: tuple[str, ...]
    closed_endpoints: tuple[str, ...]
    owner_closed: bool
    component_receipts: tuple[ClosureComponentReceiptV2, ...]
    component_set_sha256: str
    receipt_id: str
    authentication_tag: str

    def wire(self, *, include_authentication: bool = True) -> dict[str, Any]:
        value = {
            "active_operations": self.active_operations,
            "authenticated_eof_drained_directions": list(
                self.authenticated_eof_drained_directions),
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "closed_endpoints": list(self.closed_endpoints),
            "closure_deadline_ns": self.closure_deadline_ns,
            "closure_request_id": self.closure_request_id,
            "component_receipts": [item.wire() for item in self.component_receipts],
            "component_set_sha256": self.component_set_sha256,
            "effect_deadline_ns": self.effect_deadline_ns,
            "factory_id": self.factory_id,
            "generation": self.generation,
            "live_callbacks": self.live_callbacks,
            "operation_id": self.operation_id,
            "operation_purpose": self.operation_purpose,
            "owner_closed": self.owner_closed,
            "revoked_epoch_sides": list(self.revoked_epoch_sides),
            "role": self.role,
            "sealed_directions": list(self.sealed_directions),
            "session_epoch": self.session_epoch,
            "session_id": self.session_id,
        }
        if include_authentication:
            value["authentication_tag"] = self.authentication_tag
            value["receipt_id"] = self.receipt_id
        return value

    def validate(self, binding: CapabilityBindingBodyV2,
                 request: SessionClosureRequestV2, key: bytes,
                 crypto: CryptoProvider) -> None:
        if (type(self) is not SuccessfulSessionClosureReceiptV2 or
                self.authority != SUCCESSFUL_SESSION_CLOSURE_RECEIPT_AUTHORITY_V2):
            _fail("v2 successful closure receipt authority is invalid or substituted")
        request.validate(binding, key, crypto)
        exact = {
            "binding_sha256": request.binding_sha256,
            "session_id": request.session_id,
            "session_epoch": request.session_epoch,
            "factory_id": request.factory_id,
            "role": request.role,
            "generation": request.generation,
            "closure_request_id": request.request_id,
            "operation_id": request.operation_id,
            "operation_purpose": request.operation_purpose,
            "effect_deadline_ns": request.effect_deadline_ns,
            "closure_deadline_ns": request.closure_deadline_ns,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 successful closure receipt differs from closure request")
        if (self.sealed_directions != _V2_DIRECTIONS or
                self.authenticated_eof_drained_directions != _V2_DIRECTIONS or
                type(self.active_operations) is not int or self.active_operations != 0 or
                type(self.live_callbacks) is not int or self.live_callbacks != 0 or
                self.revoked_epoch_sides != _V2_EPOCH_SIDES or
                self.closed_endpoints != _V2_ENDPOINT_IDS or
                self.owner_closed is not True):
            _fail("v2 successful closure receipt lacks exact terminal effects")
        if (type(self.component_receipts) is not tuple or
                len(self.component_receipts) != len(_V2_CLOSURE_COMPONENT_SPECS)):
            _fail("v2 successful closure component set is incomplete")
        for receipt, (component, subject) in zip(
                self.component_receipts, _V2_CLOSURE_COMPONENT_SPECS):
            receipt.validate(request, component, subject, crypto)
        expected_component_digest = _digest_hex(
            crypto, canonical_json([item.wire() for item in self.component_receipts]))
        if self.component_set_sha256 != expected_component_digest:
            _fail("v2 successful closure component-set digest is invalid")
        body = self.wire(include_authentication=False)
        _hex64(self.receipt_id, "v2 successful closure receipt ID")
        _hex64(self.authentication_tag, "v2 successful closure authentication tag")
        if self.receipt_id != _digest_hex(
                crypto, b"rtl-reader-successful-session-closure-v2\x00" +
                canonical_json(body)):
            _fail("v2 successful closure receipt ID is invalid")
        expected_tag = _v2_authentication_tag(
            crypto, key, b"rtl-reader-successful-session-closure-auth-v2\x00",
            {"body": body, "receipt_id": self.receipt_id})
        comparison = _call_unretained_provider(
            crypto, "compare_digest", bytes.fromhex(self.authentication_tag),
            bytes.fromhex(expected_tag))
        if type(comparison) is not bool or not comparison:
            _fail("v2 successful closure receipt authentication is invalid")


def make_successful_session_closure_receipt_v2(
        binding: CapabilityBindingBodyV2, request: SessionClosureRequestV2,
        component_receipts: tuple[ClosureComponentReceiptV2, ...],
        key: bytes, crypto: CryptoProvider) -> SuccessfulSessionClosureReceiptV2:
    component_digest = _digest_hex(
        crypto, canonical_json([item.wire() for item in component_receipts]))
    provisional = SuccessfulSessionClosureReceiptV2(
        SUCCESSFUL_SESSION_CLOSURE_RECEIPT_AUTHORITY_V2,
        request.binding_sha256, request.session_id, request.session_epoch,
        request.factory_id, request.role, request.generation,
        request.request_id, request.operation_id, request.operation_purpose,
        request.effect_deadline_ns, request.closure_deadline_ns,
        _V2_DIRECTIONS, _V2_DIRECTIONS, 0, 0, _V2_EPOCH_SIDES,
        _V2_ENDPOINT_IDS, True, component_receipts, component_digest,
        "0" * 64, "0" * 64)
    body = provisional.wire(include_authentication=False)
    receipt_id = _digest_hex(
        crypto, b"rtl-reader-successful-session-closure-v2\x00" + canonical_json(body))
    tag = _v2_authentication_tag(
        crypto, key, b"rtl-reader-successful-session-closure-auth-v2\x00",
        {"body": body, "receipt_id": receipt_id})
    value = SuccessfulSessionClosureReceiptV2(
        provisional.authority, provisional.binding_sha256,
        provisional.session_id, provisional.session_epoch,
        provisional.factory_id, provisional.role, provisional.generation,
        provisional.closure_request_id, provisional.operation_id,
        provisional.operation_purpose, provisional.effect_deadline_ns,
        provisional.closure_deadline_ns, provisional.sealed_directions,
        provisional.authenticated_eof_drained_directions,
        provisional.active_operations, provisional.live_callbacks,
        provisional.revoked_epoch_sides, provisional.closed_endpoints,
        provisional.owner_closed, provisional.component_receipts,
        provisional.component_set_sha256, receipt_id, tag)
    value.validate(binding, request, key, crypto)
    return value


@dataclass(frozen=True)
class AdmissionReceiptV2:
    authority: str
    binding_sha256: str
    session_epoch: str
    component: str
    subject: str
    profile: str
    generation: int
    evidence_sha256: str
    receipt_sha256: str

    def wire(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = {
            "authority": self.authority,
            "binding_sha256": self.binding_sha256,
            "component": self.component,
            "evidence_sha256": self.evidence_sha256,
            "generation": self.generation,
            "profile": self.profile,
            "session_epoch": self.session_epoch,
            "subject": self.subject,
        }
        if include_digest:
            value["receipt_sha256"] = self.receipt_sha256
        return value

    def validate(self, binding: CapabilityBindingBodyV2,
                 component: str, subject: str, profile: str,
                 crypto: CryptoProvider) -> None:
        if type(self) is not AdmissionReceiptV2 or self.authority != ADMISSION_RECEIPT_AUTHORITY_V2:
            _fail("v2 admission receipt authority is invalid or substituted")
        exact = {
            "binding_sha256": capability_binding_sha256_v2(binding, crypto),
            "session_epoch": binding.session_epoch,
            "component": component,
            "subject": subject,
            "profile": profile,
            "generation": 0,
        }
        for name, expected in exact.items():
            current = getattr(self, name)
            if type(current) is not type(expected) or current != expected:
                _fail("v2 admission receipt " + name + " differs from construction")
        _hex64(self.evidence_sha256, "v2 admission evidence")
        _hex64(self.receipt_sha256, "v2 admission receipt digest")
        if self.receipt_sha256 != _digest_hex(
                crypto, b"rtl-reader-admission-receipt-v2\x00" +
                canonical_json(self.wire(include_digest=False))):
            _fail("v2 admission receipt digest is invalid")


def make_admission_receipt_v2(
        binding: CapabilityBindingBodyV2, component: str, subject: str,
        profile: str, evidence_sha256: str,
        crypto: CryptoProvider) -> AdmissionReceiptV2:
    provisional = AdmissionReceiptV2(
        ADMISSION_RECEIPT_AUTHORITY_V2,
        capability_binding_sha256_v2(binding, crypto), binding.session_epoch,
        component, subject, profile, 0, evidence_sha256, "0" * 64)
    digest_value = _digest_hex(
        crypto, b"rtl-reader-admission-receipt-v2\x00" +
        canonical_json(provisional.wire(include_digest=False)))
    return AdmissionReceiptV2(
        provisional.authority, provisional.binding_sha256,
        provisional.session_epoch, provisional.component, provisional.subject,
        provisional.profile, provisional.generation,
        provisional.evidence_sha256, digest_value)


class PacketTransportAuthorityV2(Protocol):
    def attestation(self) -> TransportAttestationV2: ...
    def admit(self, binding: CapabilityBindingBodyV2) -> AdmissionReceiptV2: ...
    def send_authenticated_eof(self, request: SessionClosureRequestV2,
                               direction: str) -> ClosureComponentReceiptV2: ...
    def seal_direction(self, request: SessionClosureRequestV2,
                       direction: str) -> ClosureComponentReceiptV2: ...
    def verify_direction_drained(self, request: SessionClosureRequestV2,
                                 direction: str) -> ClosureComponentReceiptV2: ...
    def close_endpoint(self, request: SessionClosureRequestV2,
                       endpoint_id: str) -> ClosureComponentReceiptV2: ...


class SessionEpochAuthorityV2(Protocol):
    def attestation(self) -> EpochAttestationV2: ...
    def admit_side(self, binding: CapabilityBindingBodyV2,
                   side: str) -> AdmissionReceiptV2: ...
    def revoke_side(self, request: SessionClosureRequestV2,
                    side: str) -> ClosureComponentReceiptV2: ...


class SessionLifecycleAuthorityV2(Protocol):
    def admit(self, binding: CapabilityBindingBodyV2) -> AdmissionReceiptV2: ...
    def verify_zero_operations(self, request: SessionClosureRequestV2,
                               subject: str
                               ) -> ClosureComponentReceiptV2: ...
    def verify_zero_callbacks(self, request: SessionClosureRequestV2,
                              subject: str
                              ) -> ClosureComponentReceiptV2: ...
    def close_owner(self, request: SessionClosureRequestV2,
                    subject: str
                    ) -> ClosureComponentReceiptV2: ...


@dataclass(frozen=True)
class AcquiredAuthorityV2:
    """Phase-one result retaining every authority even if phase two fails."""

    authority: str
    acquisition_id: str
    binding_sha256: str
    transport: PacketTransportAuthorityV2 = field(compare=False, repr=False)
    epoch: SessionEpochAuthorityV2 = field(compare=False, repr=False)
    lifecycle: SessionLifecycleAuthorityV2 = field(compare=False, repr=False)
    clock: Clock = field(compare=False, repr=False)
    crypto: CryptoProvider = field(compare=False, repr=False)
    session_key: bytes = field(compare=False, repr=False)

    def validate(self, binding: CapabilityBindingBodyV2) -> None:
        if type(self) is not AcquiredAuthorityV2 or self.authority != ACQUIRED_AUTHORITY_V2:
            _fail("v2 acquired authority is invalid or substituted")
        _hex64(self.acquisition_id, "v2 acquisition ID")
        _hex64(self.binding_sha256, "v2 acquisition binding")
        if any(item is None for item in (
                self.transport, self.epoch, self.lifecycle, self.clock,
                self.crypto, self.session_key)):
            _fail("v2 acquired authority set is incomplete")
        _exact(self.session_key, bytes, "v2 acquired session key")
        if (len(self.session_key) < 32 or
                self.binding_sha256 != capability_binding_sha256_v2(binding, self.crypto) or
                _digest_hex(self.crypto, self.session_key) != binding.key_id):
            _fail("v2 acquired authority differs from immutable binding")


@dataclass(frozen=True)
class CapabilityConstructionResultV2:
    """Phase-two result; failures keep the exact phase-one authority reachable."""

    authority: str
    binding_sha256: str
    status: str
    acquired_authority: AcquiredAuthorityV2 = field(compare=False, repr=False)
    session: "CapabilitySessionV2 | None" = field(compare=False, repr=False)
    failure_code: str | None

    def validate(self) -> None:
        if (type(self) is not CapabilityConstructionResultV2 or
                self.authority != CONSTRUCTION_RESULT_AUTHORITY_V2):
            _fail("v2 construction result authority is invalid or substituted")
        _hex64(self.binding_sha256, "v2 construction binding")
        if type(self.acquired_authority) is not AcquiredAuthorityV2:
            _fail("v2 construction result lost its acquired authority")
        if self.status == "committed":
            if (type(self.session) is not CapabilitySessionV2 or
                    self.failure_code is not None or
                    self.acquired_authority.binding_sha256 != self.binding_sha256 or
                    self.session._construction_kind != "production" or
                    self.session._acquired is not self.acquired_authority or
                    self.session._binding_sha256 != self.binding_sha256):
                _fail("v2 committed construction result is malformed")
        elif self.status == "failed_authority_retained":
            if self.session is not None or self.failure_code != "production_admission_failed":
                _fail("v2 failed construction result is malformed")
        else:
            _fail("v2 construction result status is outside the fixed registry")

    def require_session(self) -> "CapabilitySessionV2":
        self.validate()
        if self.session is None:
            _fail("v2 production session was not admitted; acquired authority is retained")
        return self.session


_V2_PRODUCTION_SESSION_CONSTRUCTION = object()
_V2_CONTRACT_SESSION_CONSTRUCTION = object()


def _serialized_v2(method: Callable[..., Any]) -> Callable[..., Any]:
    def guarded(self: "CapabilitySessionV2", *args: Any, **kwargs: Any) -> Any:
        caller = threading.get_ident()
        if (self._entry_owner == caller or
                not self._entry_lock.acquire(blocking=False)):
            _fail("concurrent or reentrant v2 capability session entry is not permitted")
        object.__setattr__(self, "_entry_owner", caller)
        try:
            return method(self, *args, **kwargs)
        finally:
            object.__setattr__(self, "_entry_owner", None)
            self._entry_lock.release()
    guarded.__name__ = method.__name__
    guarded.__doc__ = method.__doc__
    return guarded


class CapabilitySessionV2:
    """Small state machine for the attested v2 contract.

    This class does not manufacture transport, epoch, callback, owner, or
    endpoint evidence.  Successful closure is possible only when the injected
    retained authorities return every exact-generation typed receipt.
    """

    __slots__ = (
        "_binding", "_binding_sha256", "_acquired", "_admission_receipts",
        "_admission_profile", "_state", "_generation", "_active_lease",
        "_active_callbacks", "_active_callback_records", "_completed_purposes",
        "_closure_receipt", "_partial_closure_receipts", "_last_now",
        "_entry_lock", "_entry_owner", "_construction_kind")

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        _fail("v2 capability sessions cannot be subclassed")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("v2 capability session storage is private and read-only")

    def __init__(self, *, binding: CapabilityBindingBodyV2,
                 acquired: AcquiredAuthorityV2,
                 admission_receipts: tuple[AdmissionReceiptV2, ...],
                 admission_profile: str,
                 _construction_authority: object) -> None:
        if _construction_authority is _V2_PRODUCTION_SESSION_CONSTRUCTION:
            # The platform-neutral module has no installed OS trust root.  A
            # module-private token is an implementation-routing aid, not OS
            # evidence, so even code that discovers it cannot instantiate a
            # production session.  The eventual concrete adapter must replace
            # this closed branch as part of installing its admission primitive.
            _fail("v2 concrete OS admission authority is not implemented")
        elif _construction_authority is _V2_CONTRACT_SESSION_CONSTRUCTION:
            construction_kind = "contract_fake"
        else:
            _fail("v2 session construction is outside the closed admission path")
        acquired.validate(binding)
        if type(admission_receipts) is not tuple or len(admission_receipts) != 4:
            _fail("v2 session admission receipt set is incomplete")
        if admission_profile != binding.transport_attestation.profile:
            _fail("v2 session transport admission profile differs from binding")
        expected = (
            ("transport", "channel", binding.transport_attestation.profile),
            ("epoch", "child", binding.epoch_attestation.profile),
            ("epoch", "parent", binding.epoch_attestation.profile),
            ("lifecycle", "session", SESSION_LIFECYCLE_PROFILE_V2),
        )
        for receipt, (component, subject, profile) in zip(admission_receipts, expected):
            receipt.validate(binding, component, subject, profile, acquired.crypto)
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_binding_sha256", acquired.binding_sha256)
        object.__setattr__(self, "_acquired", acquired)
        object.__setattr__(self, "_admission_receipts", admission_receipts)
        object.__setattr__(self, "_admission_profile", (
            binding.transport_attestation.profile,
            binding.epoch_attestation.profile))
        object.__setattr__(self, "_state", "OPEN")
        object.__setattr__(self, "_generation", 0)
        object.__setattr__(self, "_active_lease", None)
        object.__setattr__(self, "_active_callbacks", 0)
        object.__setattr__(self, "_active_callback_records", ())
        object.__setattr__(self, "_completed_purposes", ())
        object.__setattr__(self, "_closure_receipt", None)
        object.__setattr__(self, "_partial_closure_receipts", ())
        object.__setattr__(self, "_last_now", -1)
        object.__setattr__(self, "_entry_lock", threading.Lock())
        object.__setattr__(self, "_entry_owner", None)
        object.__setattr__(self, "_construction_kind", construction_kind)
        if self._now() >= binding.effect_deadline_ns:
            _fail("v2 session admission occurred after immutable effect deadline")

    @property
    def binding(self) -> CapabilityBindingBodyV2:
        return self._binding

    @property
    def state(self) -> str:
        return self._state

    @property
    def completed_purposes(self) -> tuple[str, ...]:
        return self._completed_purposes

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def successful_closure_receipt(self) -> SuccessfulSessionClosureReceiptV2 | None:
        return self._closure_receipt

    @property
    def partial_closure_receipts(self) -> tuple[ClosureComponentReceiptV2, ...]:
        return self._partial_closure_receipts

    def _now(self) -> int:
        value = _call_unretained_provider(self._acquired.clock, "now_ns")
        if type(value) is not int or value < 0 or value < self._last_now:
            _fail("v2 monotonic time is inexact or regressed")
        object.__setattr__(self, "_last_now", value)
        return value

    @_serialized_v2
    def begin_operation(self, lease: OperationLeaseV2,
                        request_value: Any) -> DetachedPayloadV2:
        if self._state != "OPEN" or self._active_lease is not None:
            _fail("v2 capability session is not operation-idle OPEN")
        entry_generation = self._generation
        policy = lease.validate(self._binding, self._acquired.crypto)
        expected_sequence = len(self._completed_purposes) + 1
        if lease.sequence != expected_sequence:
            _fail("v2 operation is skipped, replayed, or reordered")
        if policy.prerequisite_purpose is not None:
            if (not self._completed_purposes or
                    self._completed_purposes[-1] != policy.prerequisite_purpose):
                _fail("v2 cleanup seq2 was not preceded by successful capture")
        now = self._now()
        if policy.phase == "effect":
            if now >= lease.effect_deadline_ns:
                _fail("v2 effect operation started after immutable effect deadline")
        elif now >= lease.closure_deadline_ns:
            _fail("v2 cleanup operation started after immutable closure deadline")
        payload = DetachedPayloadV2.from_value(
            lease, "request", request_value, policy.maximum_payload_bytes,
            self._acquired.crypto)
        now = self._now()
        deadline = (lease.effect_deadline_ns if policy.phase == "effect"
                    else lease.closure_deadline_ns)
        if (now >= deadline or self._state != "OPEN" or
                self._active_lease is not None or
                self._generation != entry_generation):
            _fail("v2 operation admission raced or exhausted its immutable deadline")
        object.__setattr__(self, "_active_lease", lease)
        object.__setattr__(self, "_active_callbacks", 0)
        object.__setattr__(self, "_active_callback_records", ())
        object.__setattr__(self, "_state", "ACTIVE")
        object.__setattr__(self, "_generation", self._generation + 1)
        return payload

    @_serialized_v2
    def note_callback(self, callback: CallbackRecordV2) -> None:
        lease = self._active_lease
        if self._state != "ACTIVE" or type(lease) is not OperationLeaseV2:
            _fail("v2 callback has no active exact operation")
        policy = factory_operation_table_v2(self._binding.factory_id).operation(
            lease.operation_id, lease.operation_purpose)
        deadline = (lease.effect_deadline_ns if policy.phase == "effect"
                    else lease.closure_deadline_ns)
        if self._now() >= deadline:
            _fail("v2 callback started after immutable operation deadline")
        callback.validate(self._binding, self._acquired.crypto)
        if callback.lease != lease or callback.ordinal != self._active_callbacks + 1:
            _fail("v2 callback is reordered or cross-operation")
        if self._now() >= deadline:
            _fail("v2 callback validation completed after immutable operation deadline")
        object.__setattr__(self, "_active_callback_records",
                           self._active_callback_records + (callback,))
        object.__setattr__(self, "_active_callbacks", callback.ordinal)

    @_serialized_v2
    def complete_operation(self, outcome: OperationOutcomeV2) -> None:
        lease = self._active_lease
        if (self._state != "ACTIVE" or type(lease) is not OperationLeaseV2 or
                type(outcome) is not OperationOutcomeV2 or outcome.lease != lease):
            _fail("v2 outcome has no exact active operation")
        entry_generation = self._generation
        outcome.validate(
            self._binding, self._acquired.session_key, self._acquired.crypto)
        if (outcome.settlement_evidence.callback_drain_challenge.generation !=
                entry_generation):
            _fail("v2 outcome quiescence proof differs from active generation")
        if (outcome.callbacks != self._active_callback_records or
                len(outcome.callbacks) != self._active_callbacks):
            _fail("v2 outcome callbacks differ from exact active callback stream")
        now = self._now()
        policy = factory_operation_table_v2(self._binding.factory_id).operation(
            lease.operation_id, lease.operation_purpose)
        deadline = (lease.effect_deadline_ns if policy.phase == "effect"
                    else lease.closure_deadline_ns)
        if (now >= deadline or self._state != "ACTIVE" or
                self._active_lease != lease or self._generation != entry_generation):
            _fail("v2 operation outcome arrived after its immutable phase deadline")
        object.__setattr__(self, "_completed_purposes",
                           self._completed_purposes + (lease.operation_purpose,))
        object.__setattr__(self, "_active_lease", None)
        object.__setattr__(self, "_active_callbacks", 0)
        object.__setattr__(self, "_active_callback_records", ())
        object.__setattr__(self, "_state", "OPEN")
        object.__setattr__(self, "_generation", self._generation + 1)

    @_serialized_v2
    def verify_operation_idle(self) -> OpenOperationIdleReceiptV2:
        if (self._state != "OPEN" or self._active_lease is not None or
                self._active_callbacks != 0 or self._closure_receipt is not None):
            _fail("v2 session is not nonterminal operation-idle OPEN")
        body = {
            "active_operations": 0,
            "authority": OPEN_OPERATION_IDLE_RECEIPT_AUTHORITY_V2,
            "binding_sha256": self._binding_sha256,
            "closure_deadline_ns": self._binding.closure_deadline_ns,
            "effect_deadline_ns": self._binding.effect_deadline_ns,
            "epoch_admitted_sides": list(_V2_EPOCH_SIDES),
            "generation": self._generation,
            "live_callbacks": 0,
            "open_endpoints": list(_V2_ENDPOINT_IDS),
            "operation_purpose": OPERATION_IDLE_PURPOSE_V2,
            "session_epoch": self._binding.session_epoch,
            "session_id": self._binding.session_id,
            "state": "OPEN",
            "terminal": False,
        }
        receipt_id = _digest_hex(
            self._acquired.crypto, b"rtl-reader-open-operation-idle-v2\x00" +
            canonical_json(body))
        tag = _v2_authentication_tag(
            self._acquired.crypto, self._acquired.session_key,
            b"rtl-reader-open-operation-idle-auth-v2\x00",
            {"body": body, "receipt_id": receipt_id})
        receipt = OpenOperationIdleReceiptV2(
            body["authority"], body["binding_sha256"], body["session_id"],
            body["session_epoch"], body["generation"], body["state"],
            body["operation_purpose"], body["effect_deadline_ns"],
            body["closure_deadline_ns"], body["active_operations"],
            body["live_callbacks"], _V2_EPOCH_SIDES, _V2_ENDPOINT_IDS,
            False, receipt_id, tag)
        receipt.validate(
            self._binding, self._acquired.session_key, self._acquired.crypto)
        return receipt

    @_serialized_v2
    def close_successfully(self) -> SuccessfulSessionClosureReceiptV2:
        if (self._state != "OPEN" or self._active_lease is not None or
                self._active_callbacks != 0 or self._closure_receipt is not None):
            _fail("v2 session is not eligible for successful closure")
        expected_purposes = tuple(
            item.operation_purpose for item in
            factory_operation_table_v2(self._binding.factory_id).operations)
        if self._completed_purposes != expected_purposes:
            _fail("v2 successful closure requires the complete immutable operation plan")
        if self._now() >= self._binding.closure_deadline_ns:
            _fail("v2 successful closure deadline is expired")
        generation = self._generation + 1
        object.__setattr__(self, "_generation", generation)
        object.__setattr__(self, "_state", "CLOSING")
        receipts: list[ClosureComponentReceiptV2] = []
        try:
            request = make_session_closure_request_v2(
                self._binding, generation, self._acquired.session_key,
                self._acquired.crypto)
            def invoke_closure(owner: Any, method_name: str,
                               component: str, subject: str
                               ) -> ClosureComponentReceiptV2:
                # Every effect is independently fenced.  A provider that
                # consumes the remaining budget cannot authorize even the next
                # cleanup effect, and its late receipt is retained only as
                # partial evidence in the CLOSURE_UNCERTAIN session authority.
                if self._now() >= self._binding.closure_deadline_ns:
                    _fail("v2 closure effect started after immutable deadline")
                receipt_value = _call_unretained_provider(
                    owner, method_name, request, subject)
                _exact(receipt_value, ClosureComponentReceiptV2,
                       "v2 typed closure component receipt")
                receipt_value.validate(
                    request, component, subject, self._acquired.crypto)
                receipts.append(receipt_value)
                if self._now() >= self._binding.closure_deadline_ns:
                    _fail("v2 closure effect completed after immutable deadline")
                return receipt_value

            for direction in _V2_DIRECTIONS:
                invoke_closure(
                    self._acquired.transport, "send_authenticated_eof",
                    "authenticated_eof", direction)
            for direction in _V2_DIRECTIONS:
                invoke_closure(
                    self._acquired.transport, "seal_direction",
                    "direction_sealed", direction)
            for direction in _V2_DIRECTIONS:
                invoke_closure(
                    self._acquired.transport, "verify_direction_drained",
                    "direction_drained", direction)
            for method_name, component in (
                    ("verify_zero_operations", "operations_zero"),
                    ("verify_zero_callbacks", "callbacks_zero")):
                invoke_closure(
                    self._acquired.lifecycle, method_name, component, "session")
            for side in _V2_EPOCH_SIDES:
                invoke_closure(
                    self._acquired.epoch, "revoke_side", "epoch_revoked", side)
            for endpoint_id in _V2_ENDPOINT_IDS:
                invoke_closure(
                    self._acquired.transport, "close_endpoint",
                    "endpoint_closed", endpoint_id)
            invoke_closure(
                self._acquired.lifecycle, "close_owner", "owner_closed",
                "parent_owner")
            value = make_successful_session_closure_receipt_v2(
                self._binding, request, tuple(receipts),
                self._acquired.session_key, self._acquired.crypto)
            if (self._now() >= self._binding.closure_deadline_ns or
                    self._state != "CLOSING" or self._generation != generation or
                    self._active_lease is not None or self._active_callbacks != 0):
                _fail("v2 closure receipt publication raced or missed its deadline")
            object.__setattr__(self, "_closure_receipt", value)
            object.__setattr__(self, "_partial_closure_receipts", tuple(receipts))
            object.__setattr__(self, "_state", "CLOSED")
            return value
        except BaseException as error:
            _primitive_failure_code(error)
            object.__setattr__(self, "_partial_closure_receipts", tuple(receipts))
            object.__setattr__(self, "_state", "CLOSURE_UNCERTAIN")
            raise CapabilityQuiescenceError(
                "v2 successful closure could not prove every terminal effect") from None


def _v2_collect_admission_receipts(
        binding: CapabilityBindingBodyV2, acquired: AcquiredAuthorityV2,
        transport_profile: str, epoch_profile: str) -> tuple[AdmissionReceiptV2, ...]:
    current_transport = _call_unretained_provider(acquired.transport, "attestation")
    current_epoch = _call_unretained_provider(acquired.epoch, "attestation")
    if (type(current_transport) is not TransportAttestationV2 or
            current_transport is not binding.transport_attestation or
            type(current_epoch) is not EpochAttestationV2 or
            current_epoch is not binding.epoch_attestation):
        _fail("v2 retained attestation identity differs from immutable binding")
    if (current_transport.profile != transport_profile or
            current_epoch.profile != epoch_profile):
        _fail("v2 retained authority profile differs from construction mode")
    calls = (
        (acquired.transport, "admit", (binding,),
         "transport", "channel", transport_profile),
        (acquired.epoch, "admit_side", (binding, "child"),
         "epoch", "child", epoch_profile),
        (acquired.epoch, "admit_side", (binding, "parent"),
         "epoch", "parent", epoch_profile),
        (acquired.lifecycle, "admit", (binding,),
         "lifecycle", "session", SESSION_LIFECYCLE_PROFILE_V2),
    )
    receipt_values: list[AdmissionReceiptV2] = []
    for owner, method_name, arguments, component, subject, profile in calls:
        receipt = _call_unretained_provider(owner, method_name, *arguments)
        _exact(receipt, AdmissionReceiptV2, "v2 typed admission receipt")
        receipt.validate(binding, component, subject, profile, acquired.crypto)
        # Commit the validated prefix before invoking the next authority.  The
        # providers own their corresponding durable admission records; phase
        # two never assumes a later receipt retroactively validated an earlier
        # effect.
        receipt_values.append(receipt)
    return tuple(receipt_values)


def construct_production_capability_session_v2(
        *, binding: CapabilityBindingBodyV2,
        acquired_authority: AcquiredAuthorityV2) -> CapabilityConstructionResultV2:
    """Phase two: commit only concrete OS transport+epoch attestations.

    Once an exact :class:`AcquiredAuthorityV2` reaches this function it is
    returned in every result.  Expected validation/provider failures therefore
    cannot orphan authority behind an exception.  There is deliberately no
    `allow_unproven`, test flag, module feature flag, or boolean reality claim.
    """

    if type(acquired_authority) is not AcquiredAuthorityV2:
        _fail("v2 phase two requires an exact retained phase-one result")
    claimed_binding = acquired_authority.binding_sha256
    binding_sha256 = (claimed_binding if type(claimed_binding) is str and
                      _HEX64.fullmatch(claimed_binding) else
                      hashlib.sha256(
                          b"rtl-reader-failed-construction-v2\x00" +
                          canonical_json({
                              "acquisition_id": (
                                  acquired_authority.acquisition_id
                                  if type(acquired_authority.acquisition_id) is str
                                  else "invalid"),
                              "claimed_binding_type": type(claimed_binding).__name__,
                          })).hexdigest())
    try:
        acquired_authority.validate(binding)
        binding.transport_attestation.validate_production()
        binding.epoch_attestation.validate_production()
        current_transport = _call_unretained_provider(
            acquired_authority.transport, "attestation")
        current_epoch = _call_unretained_provider(
            acquired_authority.epoch, "attestation")
        if (type(current_transport) is not TransportAttestationV2 or
                current_transport is not binding.transport_attestation or
                type(current_epoch) is not EpochAttestationV2 or
                current_epoch is not binding.epoch_attestation):
            _fail("v2 concrete retained attestation identity is unavailable")
        # The protocol seam above is complete, but this platform-neutral module
        # intentionally ships no OS trust root capable of vouching for these
        # profiles.  Do not turn the exported informational booleans into an
        # admission decision and do not accept a caller-supplied test override.
        # The eventual OS adapter must replace this closed failure with its
        # non-forgeable admission primitive and exact typed receipts.
        _fail("v2 concrete OS admission authority is not implemented")
    except BaseException as error:
        _primitive_failure_code(error)
        result = CapabilityConstructionResultV2(
            CONSTRUCTION_RESULT_AUTHORITY_V2, binding_sha256,
            "failed_authority_retained", acquired_authority, None,
            "production_admission_failed")
    result.validate()
    return result


def _construct_contract_capability_session_v2(
        *, binding: CapabilityBindingBodyV2,
        acquired_authority: AcquiredAuthorityV2) -> CapabilitySessionV2:
    """Private deterministic-fake path; never accepted by production admission."""

    acquired_authority.validate(binding)
    if (binding.transport_attestation.profile != CONTRACT_FAKE_TRANSPORT_PROFILE_V2 or
            binding.epoch_attestation.profile != CONTRACT_FAKE_EPOCH_PROFILE_V2):
        _fail("v2 contract construction requires conspicuous fake attestations")
    receipts = _v2_collect_admission_receipts(
        binding, acquired_authority, CONTRACT_FAKE_TRANSPORT_PROFILE_V2,
        CONTRACT_FAKE_EPOCH_PROFILE_V2)
    return CapabilitySessionV2(
        binding=binding, acquired=acquired_authority,
        admission_receipts=receipts,
        admission_profile=CONTRACT_FAKE_TRANSPORT_PROFILE_V2,
        _construction_authority=_V2_CONTRACT_SESSION_CONSTRUCTION)


__all__ = [
    "AUTHORITY", "AUTHORITY_FACTORY_ID", "AUTHORITY_ROLE",
    "BINDING_AUTHORITY", "CALLBACK_AUTHORITY",
    "CallbackBinding", "CallbackDrainAuthority", "CallbackRecord", "CapabilityBinding",
    "CapabilityIpcError", "CapabilityQuiescenceError", "ChildCapabilitySession",
    "ChildOperation", "Clock", "CryptoProvider", "DetachedPayload", "FACTORY_POLICIES",
    "FRIDA_FACTORY_ID", "FRIDA_ROLE", "FactoryPolicy", "HANDLE_AUTHORITY",
    "HandleAuthority", "HandleIdentity", "LEASE_AUTHORITY", "MAX_CALLBACKS",
    "OUTCOME_AUTHORITY", "OWNER_BINDING_AUTHORITY", "OperationLease",
    "OperationOutcome", "OperationOwnerAuthority", "OperationOwnerBinding",
    "OperationPolicy",
    "QUIESCENCE_CHALLENGE_AUTHORITY", "QUIESCENCE_RECEIPT_AUTHORITY",
    "QuiescenceChallenge", "QuiescenceReceipt",
    "PROTOCOL_VERSION", "PacketTransport", "ParentCapabilitySession",
    "REAL_EPOCH_ADMISSION_IMPLEMENTED", "REAL_TRANSPORT_IMPLEMENTED",
    "RetainedCapability", "SESSION_EPOCH_AUTHORITY", "SessionEpochAdmissionAuthority",
    "SessionEpochBinding", "TRANSPORT_AUTHORITY", "TransportBinding",
    "UNRESOLVED_BLOCKERS", "WirePacket", "canonical_json",
    "decode_canonical_json", "factory_policy", "make_capability_binding",
    "make_operation_owner_binding", "make_quiescence_receipt",
    # Additive v2 contract.  The private deterministic-fake constructor is
    # deliberately not exported.
    "ACQUIRED_AUTHORITY_V2", "ADMISSION_RECEIPT_AUTHORITY_V2",
    "AcquiredAuthorityV2", "AdmissionReceiptV2",
    "CAPABILITY_BINDING_BODY_AUTHORITY_V2",
    "CLEANUP_EXPIRY_RECEIPT_AUTHORITY_V2",
    "CLOSURE_COMPONENT_RECEIPT_AUTHORITY_V2",
    "CONSTRUCTION_RESULT_AUTHORITY_V2",
    "CONTRACT_FAKE_EPOCH_PROFILE_V2", "CONTRACT_FAKE_TRANSPORT_PROFILE_V2",
    "CallbackRecordV2", "CapabilityBindingBodyV2",
    "CapabilityConstructionResultV2", "CapabilitySessionV2",
    "CleanupExpiryReceiptV2", "ClosureComponentReceiptV2",
    "DETACHED_PAYLOAD_AUTHORITY_V2", "DetachedPayloadV2",
    "EPOCH_ATTESTATION_AUTHORITY_V2", "EpochAttestationV2",
    "FACTORY_OPERATION_TABLES_V2", "FRIDA_CAPTURE_OPERATION_V2",
    "FRIDA_CAPTURE_PURPOSE_V2", "FRIDA_CLEANUP_OPERATION_V2",
    "FRIDA_CLEANUP_PURPOSE_V2", "FactoryOperationTableV2",
    "OPEN_OPERATION_IDLE_RECEIPT_AUTHORITY_V2", "OPERATION_IDLE_PURPOSE_V2",
    "OPERATION_LEASE_AUTHORITY_V2", "OPERATION_OUTCOME_AUTHORITY_V2",
    "OPERATION_PURPOSE_AUTHORITY_V2",
    "OPERATION_SETTLEMENT_EVIDENCE_AUTHORITY_V2", "OpenOperationIdleReceiptV2",
    "OperationLeaseV2", "OperationOutcomeV2", "OperationPurposeV2",
    "OperationSettlementEvidenceV2",
    "PRODUCTION_EPOCH_PROFILE_V2", "PRODUCTION_TRANSPORT_PROFILE_V2",
    "PROTOCOL_VERSION_V2", "PacketTransportAuthorityV2",
    "QUIESCENCE_CHALLENGE_AUTHORITY_V2", "QUIESCENCE_RECEIPT_AUTHORITY_V2",
    "QuiescenceChallengeV2", "QuiescenceReceiptV2",
    "REAL_V2_EPOCH_AUTHORITY_IMPLEMENTED",
    "REAL_V2_TRANSPORT_AUTHORITY_IMPLEMENTED",
    "SESSION_CLOSURE_REQUEST_AUTHORITY_V2", "SESSION_CLOSE_OPERATION_V2",
    "SESSION_CLOSE_PURPOSE_V2", "SESSION_LIFECYCLE_PROFILE_V2",
    "SUCCESSFUL_SESSION_CLOSURE_RECEIPT_AUTHORITY_V2",
    "SessionClosureRequestV2", "SessionEpochAuthorityV2",
    "SessionLifecycleAuthorityV2", "SuccessfulSessionClosureReceiptV2",
    "TRANSPORT_ATTESTATION_AUTHORITY_V2", "TransportAttestationV2",
    "V2_UNRESOLVED_BLOCKERS", "WIRE_PACKET_AUTHORITY_V2", "WirePacketV2",
    "capability_binding_sha256_v2", "construct_production_capability_session_v2",
    "factory_operation_table_v2", "make_admission_receipt_v2",
    "make_capability_binding_body_v2", "make_cleanup_expiry_receipt_v2",
    "make_closure_component_receipt_v2", "make_operation_lease_v2",
    "make_operation_outcome_v2", "make_quiescence_challenge_v2",
    "make_quiescence_receipt_v2", "make_session_closure_request_v2",
    "make_successful_session_closure_receipt_v2", "make_wire_packet_v2",
    "open_wire_packet_v2", "verify_operation_outcome_v2",
]
