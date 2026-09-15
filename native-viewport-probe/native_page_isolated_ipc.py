"""Bounded isolated authority/Frida worker ownership and canonical private IPC.

No launcher, import-by-path, pickle, device access, or default runtime exists in
this slice. S6 must provide an authenticated retained image/bootstrap authority,
private pipe peer attestation, and enforced child-creation containment. This
module proves host-operation quiescence only; pen/guardian/device peers belong
to separate owners and are explicitly excluded from generic cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import threading
from typing import Any, Callable, Protocol
import unicodedata

MAX_FRAME = 65536
MAX_CHUNK = 4096
MAX_MESSAGES = 128
MAX_OPERATIONS = 128
MAX_CHILDREN = 16
MAX_CALLBACKS = 64
MAX_SECONDS_NS = 60_000_000_000
POLL_NS = 1_000_000
ROLES = frozenset({"authority_worker", "frida_worker"})
EXCLUDED_ROLES = frozenset({"pen_worker", "pen_guardian", "guardian", "device_peer"})
NAME = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


class IpcError(RuntimeError):
    """The isolated operation cannot be admitted or its output is invalid."""


class WorkerQuiescenceError(IpcError):
    """Broken ownership/adapter contract; quiescence is NOT established."""


def _validate_json(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if depth > 12 or count[0] > 4096:
        raise IpcError("JSON topology exceeds bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2 ** 63) <= value < 2 ** 63:
            raise IpcError("JSON integer exceeds signed 64-bit bound")
        return
    if type(value) is str:
        try:
            valid = len(value.encode("utf-8", "strict")) <= MAX_FRAME and unicodedata.normalize("NFC", value) == value
        except UnicodeError as error:
            raise IpcError("JSON string is not strict UTF-8") from error
        if not valid:
            raise IpcError("JSON string is oversized or non-NFC")
        return
    if type(value) is list:
        for item in value: _validate_json(item, depth + 1, count)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str: raise IpcError("JSON object key is not text")
            _validate_json(key, depth + 1, count)
            _validate_json(item, depth + 1, count)
        return
    raise IpcError("IPC permits only canonical JSON data; floats and objects are forbidden")


def canonical_json(value: Any) -> bytes:
    _validate_json(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 1 <= len(raw) <= MAX_FRAME: raise IpcError("canonical JSON frame exceeds bound")
    return raw


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in values:
        if key in result: raise IpcError("duplicate JSON object key")
        result[key] = value
    return result


def _no_number(value: str) -> None:
    raise IpcError("non-integer JSON number is forbidden")


def decode_json(raw: bytes) -> Any:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_FRAME:
        raise IpcError("JSON capture length exceeds bound")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_float=_no_number, parse_constant=_no_number)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise IpcError("malformed canonical JSON") from error
    if canonical_json(value) != raw:
        raise IpcError("JSON encoding is not canonical")
    return value


def encode_frame(value: Any) -> bytes:
    raw = canonical_json(value)
    return len(raw).to_bytes(4, "big") + raw


class FrameDecoder:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self.sealed = False

    def feed(self, raw: bytes) -> tuple[Any, ...]:
        if self.sealed: raise IpcError("frame callback after decoder seal")
        if type(raw) is not bytes or len(raw) > MAX_CHUNK:
            self.sealed = True
            raise IpcError("IPC chunk exceeds read bound")
        self._buffer.extend(raw)
        frames = []
        try:
            while len(self._buffer) >= 4:
                size = int.from_bytes(self._buffer[:4], "big")
                if not 1 <= size <= MAX_FRAME: raise IpcError("IPC length prefix exceeds bound")
                if len(self._buffer) < size + 4: break
                frames.append(decode_json(bytes(self._buffer[4:size + 4])))
                del self._buffer[:size + 4]
                if len(frames) > MAX_MESSAGES: raise IpcError("IPC message count exceeds bound")
            if len(self._buffer) > MAX_FRAME + 4: raise IpcError("IPC accumulation exceeds bound")
            return tuple(frames)
        except BaseException:
            self.sealed = True
            raise

    def seal(self) -> None:
        self.sealed = True
        if self._buffer: raise IpcError("partial IPC frame at seal/EOF")


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    creation_ticks: int
    image_sha256: str
    bootstrap_sha256: str
    role: str

    def wire(self) -> dict[str, Any]:
        return {"pid": self.pid, "creation_ticks": self.creation_ticks,
                "image_sha256": self.image_sha256, "bootstrap_sha256": self.bootstrap_sha256,
                "role": self.role}


class WorkerImageAuthority(Protocol):
    role: str
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...


class StartPermit(Protocol):
    """Structural use of the frozen runner class; no duplicate permit logic."""
    def start(self, register: Callable[[], Any]) -> Any: ...


@dataclass(frozen=True)
class WorkerLaunch:
    process: Any
    channel: Any


@dataclass(frozen=True)
class ReplyBinding:
    worker: ProcessIdentity
    session: str
    sequence: int
    operation_id: str | None
    registration_sequence: int | None


class Runtime(Protocol):
    """Trusted adapter operations use retained objects, never reopen raw PIDs.

    A spawn must either return its suspended retained handle or fail with no
    process left behind. Handle resume/terminate/join/close are serialized by
    the adapter against handle reuse. The persistent control channel never
    carries replies. Each RPC gets a fresh authenticated reply endpoint bound
    to ReplyBinding; b"" from read_reply means permanent writer EOF, whereas
    None means would-block. No reply endpoint may be reused, or its writer
    duplicated outside the contained worker. Final containment attestation
    independently proves no live unregistered descendants remain even after
    the worker exited. S6 must prove these obligations.
    """
    def now_ns(self) -> int: ...
    def sleep_ns(self, nanoseconds: int) -> None: ...
    def launch_suspended(self, image: WorkerImageAuthority, session: str) -> WorkerLaunch: ...
    def identity(self, process: Any) -> ProcessIdentity: ...
    def attest_image(self, process: Any, image: WorkerImageAuthority) -> None: ...
    def attest_private_channel(self, channel: Any, peer: ProcessIdentity) -> None: ...
    def attest_containment(self, process: Any, registered_children: tuple[ProcessIdentity, ...]) -> None: ...
    def attest_containment_quiescent(self, process: Any, registered_children: tuple[ProcessIdentity, ...]) -> None: ...
    def open_reply_stream(self, control_channel: Any, binding: ReplyBinding, deadline_ns: int) -> Any: ...
    def attest_reply_stream(self, stream: Any, binding: ReplyBinding) -> None: ...
    def read_reply(self, stream: Any, limit: int, deadline_ns: int) -> bytes | None: ...
    def close_reply_stream(self, stream: Any, binding: ReplyBinding) -> None: ...
    def is_suspended(self, process: Any) -> bool: ...
    def resume(self, process: Any) -> None: ...
    def alive(self, process: Any) -> bool: ...
    def write(self, channel: Any, raw: bytes, deadline_ns: int) -> int | None: ...
    def diagnostic_output(self, process: Any, limit: int) -> bytes: ...
    def spawn_child_suspended(self, worker: Any, operation_id: str, image: WorkerImageAuthority) -> Any: ...
    def parent_identity(self, child: Any) -> ProcessIdentity: ...
    def terminate(self, process: Any, expected: ProcessIdentity) -> None: ...
    def join(self, process: Any, expected: ProcessIdentity, deadline_ns: int) -> bool: ...
    def close_process(self, process: Any, expected: ProcessIdentity) -> None: ...
    def close_channel(self, channel: Any) -> None: ...


@dataclass
class _Owned:
    handle: Any
    identity: ProcessIdentity | None
    image: WorkerImageAuthority
    operation_id: str | None = None
    admitted: bool = False


@dataclass(frozen=True)
class OperationTicket:
    session: str
    operation_id: str
    registration_sequence: int


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    value: Any
    callbacks: tuple[Any, ...]


def envelope(session: str, sequence: int, kind: str, operation_id: str | None, body: dict[str, Any]) -> dict[str, Any]:
    return {"v": 1, "session": session, "seq": sequence, "kind": kind, "op": operation_id, "body": body}


def validate_envelope(value: Any, session: str) -> dict[str, Any]:
    if (type(value) is not dict or set(value) != {"v", "session", "seq", "kind", "op", "body"} or
            type(value["v"]) is not int or value["v"] != 1 or value["session"] != session or
            type(value["seq"]) is not int or not 0 <= value["seq"] < 2 ** 31 or
            type(value["kind"]) is not str or NAME.fullmatch(value["kind"]) is None or
            (value["op"] is not None and (type(value["op"]) is not str or not NAME.fullmatch(value["op"]))) or
            type(value["body"]) is not dict):
        raise IpcError("IPC envelope differs from private session authority")
    return value


class IsolatedWorker:
    def __init__(self, image: WorkerImageAuthority, runtime: Runtime, session: str,
                 *, excluded: tuple[ProcessIdentity, ...] = ()):
        if image is None or runtime is None:
            raise IpcError("retained image authority and private runtime are required; no default launcher")
        if image.role not in ROLES or type(session) is not str or not HEX.fullmatch(session):
            raise IpcError("invalid isolated worker role/session")
        if (type(excluded) is not tuple or len(excluded) > 64 or
                any(type(value) is not ProcessIdentity for value in excluded)):
            raise IpcError("excluded ownership identities must be an immutable exact tuple")
        self.image, self.runtime, self.session, self.excluded = image, runtime, session, excluded
        self._lock = threading.RLock()
        self._cleanup_lock = threading.Lock()
        self._spawns_inflight = 0
        self._spawns_settled = threading.Event()
        self._spawns_settled.set()
        self._owner_thread = threading.get_ident()
        self.state = "NEW"
        self._authority: bytes | None = None
        self._worker: _Owned | None = None
        self._owned: list[_Owned] = []
        self._channel: Any = None
        self._reply_stream: Any = None
        self._reply_binding: ReplyBinding | None = None
        self._decoder = FrameDecoder()
        self._messages: list[Any] = []
        self._operations: dict[str, str] = {}
        self._tickets: dict[str, OperationTicket] = {}
        self._sequence = 0
        self._diagnostic_count = 0
        self._callbacks_sealed = False
        self._containment_uncertain = False
        self._known_children: list[ProcessIdentity] = []
        self.cleanup_obligations: tuple[str, ...] = ()

    def _deadline(self, deadline_ns: int) -> None:
        now = self.runtime.now_ns()
        if type(now) is not int or type(deadline_ns) is not int or not now < deadline_ns <= now + MAX_SECONDS_NS:
            raise IpcError("isolated operation deadline exceeded or invalid")

    def _protected(self, value: ProcessIdentity) -> bool:
        return value.role in EXCLUDED_ROLES or any(
            (value.pid, value.creation_ticks) == (item.pid, item.creation_ticks) for item in self.excluded)

    def _spawn_enter(self) -> None:
        with self._lock:
            if self.state not in {"STARTING", "OPEN"}: raise IpcError("spawn attempted after terminal seal")
            self._spawns_inflight += 1
            self._spawns_settled.clear()

    def _spawn_exit(self) -> None:
        with self._lock:
            self._spawns_inflight -= 1
            if not self._spawns_inflight: self._spawns_settled.set()

    def _admit(self, owned: _Owned, role: str) -> None:
        value = self.runtime.identity(owned.handle)
        owned.identity = value
        if (type(value) is not ProcessIdentity or value.role != role or self._protected(value) or
                type(value.pid) is not int or value.pid <= 0 or type(value.creation_ticks) is not int or value.creation_ticks <= 0 or
                not HEX.fullmatch(value.image_sha256) or not HEX.fullmatch(value.bootstrap_sha256)):
            raise IpcError("worker/child identity is excluded or not exact retained authority")
        owned.image.verify()
        self.runtime.attest_image(owned.handle, owned.image)
        if not self.runtime.is_suspended(owned.handle):
            raise IpcError("new worker/child must remain suspended until registration")
        owned.admitted = True

    def _verify_owned(self, owned: _Owned) -> None:
        if (not owned.admitted or owned.identity is None or self._protected(owned.identity) or
                self.runtime.identity(owned.handle) != owned.identity):
            raise WorkerQuiescenceError("retained worker/child identity drift; no PID-based cleanup permitted")
        owned.image.verify()
        self.runtime.attest_image(owned.handle, owned.image)

    def _verify(self) -> None:
        with self._lock:
            if self.state not in {"STARTING", "OPEN"}: raise IpcError("isolated worker admission/callbacks are sealed")
        if self._worker is None: raise IpcError("worker has no retained process")
        self.image.verify()
        if self.image.canonical_bytes() != self._authority: raise IpcError("retained worker bootstrap authority changed")
        self._verify_owned(self._worker)
        if not self.runtime.alive(self._worker.handle): raise IpcError("isolated worker crashed")
        children = tuple(item.identity for item in self._owned if item is not self._worker and item.identity is not None)
        try:
            self.runtime.attest_containment(self._worker.handle, children)
        except BaseException:
            self._containment_uncertain = True
            raise
        with self._lock:
            if self.state not in {"STARTING", "OPEN"}: raise IpcError("authority attestation completed after terminal seal")
            channel = self._channel
        self.runtime.attest_private_channel(channel, self._worker.identity)
        raw = self.runtime.diagnostic_output(self._worker.handle, min(MAX_CHUNK, MAX_FRAME - self._diagnostic_count + 1))
        if type(raw) is not bytes or len(raw) > min(MAX_CHUNK, MAX_FRAME - self._diagnostic_count + 1):
            raise IpcError("worker diagnostic read exceeded bound")
        self._diagnostic_count += len(raw)
        if self._diagnostic_count > MAX_FRAME: raise IpcError("worker diagnostic output flood")

    def start(self, deadline_ns: int) -> "IsolatedWorker":
        if self.state != "NEW": raise IpcError("invalid isolated worker start lifecycle")
        self._deadline(deadline_ns)
        self.state = "STARTING"
        try:
            self.image.verify()
            self._authority = self.image.canonical_bytes()
            if type(self._authority) is not bytes or not 1 <= len(self._authority) <= MAX_FRAME:
                raise IpcError("worker bootstrap authority capture exceeds bound")
            self._spawn_enter()
            try:
                launch = self.runtime.launch_suspended(self.image, self.session)
                self._channel = launch.channel
                self._worker = _Owned(launch.process, None, self.image)
                self._owned.append(self._worker)
                self._admit(self._worker, self.image.role)
            finally:
                self._spawn_exit()
            self._verify()
            self._deadline(deadline_ns)
            self._new_reply(0, None, deadline_ns)
            self._verify()
            with self._lock:
                if self.state != "STARTING": raise IpcError("worker resume denied after terminal seal")
                self._deadline(deadline_ns)
                self.runtime.resume(self._worker.handle)
            ready = self._receive(0, None, deadline_ns)
            if ready["kind"] != "ready" or ready["body"] != {"role": self.image.role}:
                raise IpcError("worker private ready acknowledgement is invalid")
            self._finish_reply(deadline_ns)
            with self._lock:
                if self.state != "STARTING": raise IpcError("worker ready acknowledgement arrived after terminal seal")
                self.state = "OPEN"
            return self
        except BaseException as error:
            self._fail(error)
            raise

    def _send(self, kind: str, op: str | None, body: dict[str, Any], deadline_ns: int) -> int:
        self._deadline(deadline_ns)
        self._verify()
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        self._new_reply(sequence, op, deadline_ns)
        raw = encode_frame(envelope(self.session, sequence, kind, op, body))
        offset = 0
        while offset < len(raw):
            self._deadline(deadline_ns)
            self._verify()
            chunk = raw[offset:offset + MAX_CHUNK]
            written = self.runtime.write(self._channel, chunk, deadline_ns)
            if written is None:
                self.runtime.sleep_ns(min(POLL_NS, deadline_ns - self.runtime.now_ns()))
                continue
            if type(written) is not int or not 1 <= written <= len(chunk): raise IpcError("IPC write made invalid progress")
            offset += written
        return sequence

    def _receive(self, sequence: int, op: str | None, deadline_ns: int) -> dict[str, Any]:
        while True:
            self._deadline(deadline_ns)
            self._verify()
            if self._reply_binding != self._binding(sequence, op):
                raise IpcError("reply stream is not bound to the exact RPC ticket")
            self.runtime.attest_reply_stream(self._reply_stream, self._reply_binding)
            if self._messages:
                value = validate_envelope(self._messages.pop(0), self.session)
                if value["seq"] != sequence or value["op"] != op:
                    raise IpcError("late, duplicate, or misbound worker reply")
                return value
            raw = self.runtime.read_reply(self._reply_stream, MAX_CHUNK, deadline_ns)
            # A blocked read may finish after concurrent cancellation. Do not
            # parse, deliver a callback, or publish a result after the seal.
            with self._lock:
                if self.state not in {"STARTING", "OPEN"}: raise IpcError("late IPC callback after seal")
            if raw is None:
                self.runtime.sleep_ns(min(POLL_NS, deadline_ns - self.runtime.now_ns()))
                continue
            if type(raw) is not bytes or len(raw) > MAX_CHUNK: raise IpcError("IPC output chunk exceeds bound")
            if not raw:
                self._decoder.seal()
                raise IpcError("worker IPC EOF before operation quiescence")
            self._messages.extend(self._decoder.feed(raw))
            if len(self._messages) > MAX_MESSAGES: raise IpcError("worker IPC message flood")

    def _binding(self, sequence: int, op: str | None) -> ReplyBinding:
        assert self._worker is not None and self._worker.identity is not None
        ticket = self._tickets.get(op)
        registration = None if op is None else (ticket.registration_sequence if ticket else sequence)
        return ReplyBinding(self._worker.identity, self.session, sequence, op, registration)

    def _new_reply(self, sequence: int, op: str | None, deadline_ns: int) -> None:
        if self._reply_stream is not None:
            raise IpcError("previous RPC reply stream has not reached exact EOF")
        assert self._worker is not None and self._worker.identity is not None
        binding = self._binding(sequence, op)
        self._spawn_enter()  # Covers delayed endpoint creation across terminal cancellation.
        try:
            self._reply_binding = binding
            self._reply_stream = self.runtime.open_reply_stream(self._channel, binding, deadline_ns)
            self.runtime.attest_reply_stream(self._reply_stream, binding)
            self._decoder = FrameDecoder()
            self._messages = []
        finally:
            self._spawn_exit()

    def _finish_reply(self, deadline_ns: int) -> None:
        """Only a fresh RPC writer's real EOF closes a reply, never would-block."""
        if self._messages or self._decoder._buffer:
            raise IpcError("unread, partial, or trailing reply frame after RPC completion")
        while True:
            self._deadline(deadline_ns)
            self._verify()
            if self._reply_stream is None or self._reply_binding is None:
                raise IpcError("RPC reply stream vanished before exact EOF")
            self.runtime.attest_reply_stream(self._reply_stream, self._reply_binding)
            raw = self.runtime.read_reply(self._reply_stream, MAX_CHUNK, deadline_ns)
            with self._lock:
                if self.state not in {"STARTING", "OPEN"}: raise IpcError("reply EOF arrived after terminal seal")
            if raw is None:
                self.runtime.sleep_ns(min(POLL_NS, deadline_ns - self.runtime.now_ns()))
                continue
            if type(raw) is not bytes or raw:
                raise IpcError("trailing or malformed bytes after exact RPC result")
            self._decoder.seal()
            self.runtime.attest_reply_stream(self._reply_stream, self._reply_binding)
            self.runtime.close_reply_stream(self._reply_stream, self._reply_binding)
            self._reply_stream, self._reply_binding = None, None
            self._deadline(deadline_ns)
            return

    def register_operation(self, operation_id: str, operation: str, payload: dict[str, Any], deadline_ns: int) -> OperationTicket:
        if threading.get_ident() != self._owner_thread: raise IpcError("registration must run on runner owner thread")
        if (type(operation_id) is not str or not NAME.fullmatch(operation_id) or
                type(operation) is not str or not NAME.fullmatch(operation) or type(payload) is not dict):
            raise IpcError("invalid isolated operation registration")
        canonical_json(payload)
        with self._lock:
            if self.state != "OPEN" or self._callbacks_sealed: raise IpcError("late operation registration after seal")
            if operation_id in self._operations: raise IpcError("duplicate operation registration")
            if len(self._operations) >= MAX_OPERATIONS or any(value != "QUIESCENT" for value in self._operations.values()):
                raise IpcError("isolated worker has a pending operation or exhausted registry")
            self._operations[operation_id] = "REGISTERING"
        try:
            sequence = self._send("register", operation_id, {"operation": operation, "payload": payload,
                                                           "deadline_ns": deadline_ns}, deadline_ns)
            reply = self._receive(sequence, operation_id, deadline_ns)
            if reply["kind"] != "registered" or reply["body"] != {"state": "REGISTERED", "inside_worker": True}:
                raise IpcError("registration lacks an authenticated in-worker acknowledgement")
            self._finish_reply(deadline_ns)
            with self._lock:
                if self.state != "OPEN": raise IpcError("registration completed after terminal seal")
                self._operations[operation_id] = "REGISTERED"
            self._deadline(deadline_ns)
            ticket = OperationTicket(self.session, operation_id, sequence)
            self._tickets[operation_id] = ticket
            return ticket
        except BaseException as error:
            self._fail(error)
            raise

    def register_child(self, ticket: OperationTicket, image: WorkerImageAuthority, deadline_ns: int) -> None:
        self._ticket(ticket, "REGISTERED")
        if image.role != "operation_child" or len(self._owned) >= MAX_CHILDREN + 1:
            raise IpcError("child role/ownership exceeds admitted operation domain")
        try:
            assert self._worker is not None
            self._spawn_enter()
            try:
                handle = self.runtime.spawn_child_suspended(self._worker.handle, ticket.operation_id, image)
                child = _Owned(handle, None, image, ticket.operation_id)
                self._owned.append(child)
                self._admit(child, "operation_child")
                if self.runtime.parent_identity(handle) != self._worker.identity:
                    child.admitted = False
                    raise IpcError("operation child escaped retained worker parent authority")
                self._known_children.append(child.identity)
            finally:
                self._spawn_exit()
            sequence = self._send("register_child", ticket.operation_id, {"identity": child.identity.wire()}, deadline_ns)
            reply = self._receive(sequence, ticket.operation_id, deadline_ns)
            if reply["kind"] != "child_registered" or reply["body"] != {"identity": child.identity.wire()}:
                raise IpcError("operation child lacks in-worker registration acknowledgement")
            self._finish_reply(deadline_ns)
        except BaseException as error:
            self._fail(error)
            raise

    def _ticket(self, ticket: OperationTicket, state: str) -> None:
        if (threading.get_ident() != self._owner_thread or type(ticket) is not OperationTicket or ticket.session != self.session or
                self._tickets.get(ticket.operation_id) != ticket or
                self._operations.get(ticket.operation_id) != state or self.state != "OPEN" or self._callbacks_sealed):
            raise IpcError("operation ticket is reused, late, or not registered")

    def execute(self, permit: StartPermit, operation_id: str, operation: str,
                payload: dict[str, Any], deadline_ns: int) -> OperationResult:
        try:
            ticket = permit.start(lambda: self.register_operation(operation_id, operation, payload, deadline_ns))
            return self.begin_and_wait(ticket, deadline_ns)
        except BaseException as error:
            self._fail(error)
            raise

    def begin_and_wait(self, ticket: OperationTicket, deadline_ns: int) -> OperationResult:
        self._ticket(ticket, "REGISTERED")
        try:
            sequence = self._send("begin", ticket.operation_id, {}, deadline_ns)
            reply = self._receive(sequence, ticket.operation_id, deadline_ns)
            if reply["kind"] != "started" or reply["body"] != {"state": "STARTED"}:
                raise IpcError("operation has no in-worker start acknowledgement")
            with self._lock:
                if self.state != "OPEN": raise IpcError("operation start acknowledgement arrived after seal")
                self._operations[ticket.operation_id] = "STARTED"
            for owned in self._owned:
                if owned.operation_id == ticket.operation_id:
                    self._verify_owned(owned)
                    self._verify()
                    with self._lock:
                        if self.state != "OPEN" or self._callbacks_sealed:
                            raise IpcError("child resume denied after terminal seal")
                        self._deadline(deadline_ns)
                        self.runtime.resume(owned.handle)
            callbacks = []
            while True:
                reply = self._receive(sequence, ticket.operation_id, deadline_ns)
                if reply["kind"] == "callback":
                    with self._lock:
                        if self._callbacks_sealed: raise IpcError("worker callback after callback seal")
                    body = reply["body"]
                    if (set(body) != {"ordinal", "value"} or type(body["ordinal"]) is not int or
                            body["ordinal"] != len(callbacks) + 1 or len(callbacks) >= MAX_CALLBACKS):
                        raise IpcError("duplicate/out-of-order callback or callback output flood")
                    callbacks.append(body["value"])
                    continue
                if reply["kind"] != "quiescent" or set(reply["body"]) != {"state", "result"} or reply["body"]["state"] != "QUIESCENT":
                    raise IpcError("operation result lacks worker quiescence acknowledgement")
                self._finish_reply(deadline_ns)
                self._verify()
                self._deadline(deadline_ns)
                for child in tuple(self._owned):
                    if child.operation_id == ticket.operation_id:
                        self._verify_owned(child)
                        if self.runtime.alive(child.handle) or not self.runtime.join(child.handle, child.identity, deadline_ns):
                            raise IpcError("operation child remains live after quiescence reply")
                        self._verify_owned(child)
                        self.runtime.close_process(child.handle, child.identity)
                        self._owned.remove(child)
                if self._messages: raise IpcError("late/duplicate callback or result after quiescence")
                with self._lock:
                    if self.state != "OPEN": raise IpcError("operation completion arrived after terminal seal")
                    self._deadline(deadline_ns)
                    self._operations[ticket.operation_id] = "QUIESCENT"
                    return OperationResult(ticket.operation_id, reply["body"]["result"], tuple(callbacks))
        except BaseException as error:
            self._fail(error)
            raise

    def seal_callbacks(self) -> None:
        with self._lock: self._callbacks_sealed = True

    def assert_quiescent(self) -> None:
        if self.cleanup_obligations or self._containment_uncertain or any(value != "QUIESCENT" for value in self._operations.values()):
            raise WorkerQuiescenceError("started/registered operations are not proven quiescent")
        if self.state == "OPEN": self._verify()
        elif self.state != "CLOSED": raise WorkerQuiescenceError("worker is not quiescent/closed")

    def cancel_and_quiesce(self, timeout_ms: int = 2000) -> None:
        self.fail_stop_and_quiesce(timeout_ms)

    def _fail(self, cause: BaseException) -> None:
        try:
            self.fail_stop_and_quiesce(2000)
        except BaseException as cleanup:
            raise WorkerQuiescenceError(f"operation rejected: {cause}; quiescence NOT established: {cleanup}") from cause

    def fail_stop_and_quiesce(self, timeout_ms: int = 2000) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise IpcError("invalid terminal cleanup bound")
        deadline_ns = self.runtime.now_ns() + timeout_ms * 1_000_000
        with self._lock:
            self._callbacks_sealed = True
            if (self.state == "CLOSED" and not self._owned and not self._spawns_inflight
                    and self._reply_stream is None and not self._containment_uncertain): return
            self.state = "SEALED"
        if not self._cleanup_lock.acquire(timeout=max(0.0, (deadline_ns - self.runtime.now_ns()) / 1_000_000_000)):
            raise WorkerQuiescenceError("concurrent terminal cleanup did not settle")
        try:
            if not self._spawns_settled.wait(max(0.0, (deadline_ns - self.runtime.now_ns()) / 1_000_000_000)):
                self.cleanup_obligations = ("pending retained spawn did not settle; quiescence NOT established",)
                raise WorkerQuiescenceError(self.cleanup_obligations[0])
            errors = []
            if self._reply_stream is not None:
                try:
                    self.runtime.close_reply_stream(self._reply_stream, self._reply_binding)
                    self._reply_stream, self._reply_binding = None, None
                except BaseException as error: errors.append(f"private reply stream: {error}")
            if self._channel is not None:
                try:
                    self.runtime.close_channel(self._channel)
                    self._channel = None
                except BaseException as error: errors.append(f"private channel: {error}")
            for owned in tuple(reversed(self._owned)):
                try:
                    self._verify_owned(owned)
                    if owned is self._worker:
                        self._containment_uncertain = True
                    identity = owned.identity
                    assert identity is not None
                    if self.runtime.alive(owned.handle): self.runtime.terminate(owned.handle, identity)
                    if not self.runtime.join(owned.handle, identity, deadline_ns) or self.runtime.alive(owned.handle):
                        raise WorkerQuiescenceError("registered process did not join within terminal bound")
                    self._verify_owned(owned)
                    if owned is self._worker:
                        self.runtime.attest_containment_quiescent(owned.handle, tuple(self._known_children))
                        self._containment_uncertain = False
                    self.runtime.close_process(owned.handle, identity)
                    self._owned.remove(owned)
                except BaseException as error: errors.append(f"registered process: {error}")
            self.cleanup_obligations = tuple(errors)
            if errors: raise WorkerQuiescenceError("; ".join(errors))
            if self._containment_uncertain:
                self.cleanup_obligations = ("unresolved containment ownership; quiescence NOT established",)
                raise WorkerQuiescenceError(self.cleanup_obligations[0])
            self._operations = {key: "QUIESCENT" for key in self._operations}
            self._messages.clear()
            self._decoder.sealed = True
            self.state = "CLOSED"
        finally:
            self._cleanup_lock.release()


@dataclass(frozen=True)
class Dispatch:
    operation_id: str
    operation: str
    payload: dict[str, Any]


class WorkerRegistry:
    """Worker-side state machine; S6 embeds reviewed bytes, never imports a path.

    The transport writes the registered/started ACK before it calls dispatch().
    Handlers are supplied by the separately reviewed worker image, not by IPC.
    complete() requires the worker adapter to have already joined operation
    children and sealed operation callbacks; a boolean from the caller is not
    accepted as substitute for the adapter's quiescence verifier.
    """
    def __init__(self, session: str, role: str, operations: frozenset[str], clock_ns: Callable[[], int],
                 verify_quiescent: Callable[[str], None]):
        if not HEX.fullmatch(session) or role not in ROLES or type(operations) is not frozenset:
            raise IpcError("invalid embedded worker registry")
        self.session, self.role, self.allowed, self.clock_ns = session, role, operations, clock_ns
        self.verify_quiescent = verify_quiescent
        self.sealed = False
        self.sequence = 0
        self.operations: dict[str, dict[str, Any]] = {}

    def ready(self) -> dict[str, Any]: return envelope(self.session, 0, "ready", None, {"role": self.role})

    def control(self, message: dict[str, Any]) -> dict[str, Any]:
        value = validate_envelope(message, self.session)
        if self.sealed or value["seq"] != self.sequence + 1: raise IpcError("late/duplicate worker control after seal")
        self.sequence = value["seq"]
        op, body, kind = value["op"], value["body"], value["kind"]
        if op is None: raise IpcError("worker operation ID is absent")
        if kind == "register":
            if (set(body) != {"operation", "payload", "deadline_ns"} or body["operation"] not in self.allowed or
                    type(body["payload"]) is not dict or type(body["deadline_ns"]) is not int or
                    self.clock_ns() >= body["deadline_ns"] or op in self.operations or len(self.operations) >= MAX_OPERATIONS or
                    any(record["state"] != "QUIESCENT" for record in self.operations.values())):
                raise IpcError("worker rejects duplicate, late, or unregistered operation")
            canonical_json(body["payload"])
            self.operations[op] = {**body, "state": "REGISTERED", "ack_sent": False, "dispatched": False,
                                   "sequence": value["seq"], "callbacks": 0, "children": []}
            return envelope(self.session, value["seq"], "registered", op, {"state": "REGISTERED", "inside_worker": True})
        record = self.operations.get(op)
        if record is None or record["state"] != "REGISTERED" or not record["ack_sent"] or self.clock_ns() >= record["deadline_ns"]:
            raise IpcError("worker operation has no timely acknowledged registration")
        if kind == "register_child":
            identity = body.get("identity")
            if (set(body) != {"identity"} or type(identity) is not dict or identity.get("role") != "operation_child" or
                    identity in record["children"] or len(record["children"]) >= MAX_CHILDREN):
                raise IpcError("worker child registration is excluded/duplicated")
            record["children"].append(identity)
            return envelope(self.session, value["seq"], "child_registered", op, {"identity": identity})
        if kind != "begin" or body: raise IpcError("unregistered worker control command")
        record.update(state="STARTED", sequence=value["seq"], start_ack_sent=False)
        return envelope(self.session, value["seq"], "started", op, {"state": "STARTED"})

    def acknowledgement_sent(self, reply: dict[str, Any]) -> None:
        if self.sealed: raise IpcError("late registration acknowledgement after seal")
        record = self.operations[reply["op"]]
        if reply["kind"] == "registered": record["ack_sent"] = True
        elif reply["kind"] == "started": record["start_ack_sent"] = True

    def dispatch(self, op: str) -> Dispatch:
        record = self.operations[op]
        if (self.sealed or record["state"] != "STARTED" or not record["start_ack_sent"] or
                record["dispatched"] or self.clock_ns() >= record["deadline_ns"]):
            raise IpcError("external worker dispatch denied before registration ACK/after deadline or seal")
        record["dispatched"] = True
        return Dispatch(op, record["operation"], record["payload"])

    def callback(self, op: str, value: Any) -> dict[str, Any]:
        record = self.operations[op]
        if self.sealed or record["state"] != "STARTED" or not record["dispatched"]:
            raise IpcError("callback after worker operation seal")
        record["callbacks"] += 1
        if record["callbacks"] > MAX_CALLBACKS: raise IpcError("worker callback flood")
        return envelope(self.session, record["sequence"], "callback", op, {"ordinal": record["callbacks"], "value": value})

    def complete(self, op: str, result: Any) -> dict[str, Any]:
        record = self.operations[op]
        if self.sealed or record["state"] != "STARTED" or not record["dispatched"]:
            raise IpcError("late/duplicate worker completion")
        self.verify_quiescent(op)
        canonical_json(result)
        record["state"] = "QUIESCENT"
        return envelope(self.session, record["sequence"], "quiescent", op, {"state": "QUIESCENT", "result": result})

    def seal(self) -> None:
        self.sealed = True
