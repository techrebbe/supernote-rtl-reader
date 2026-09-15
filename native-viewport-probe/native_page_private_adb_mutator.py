"""Closed device-mutation authority for one temporary Frida server.

This module is intentionally *not* an ADB command runner.  It owns one fixed
lifecycle and accepts no caller supplied command, remote path, or payload:

    retained reviewed image -> exact run path -> root guardian -> one server
    -> authenticated handshake -> exact stop/unlink/absence proof

The wire implementation is injected by S6 through ``FixedMutationBackend``.
That adapter must use the retained private ADB server and retained isolated
worker described by the immutable bindings below.  Keeping the adapter behind
typed, operation-specific methods prevents this authority from becoming a
general shell while still allowing deterministic offline fault injection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import wraps
import hashlib
import json
import re
import threading
from typing import Any, Callable, NoReturn, Protocol, TypeVar


AUTHORITY = "rtl-reader-device-frida-authority-v1"
PRIVATE_ADB_AUTHORITY = "rtl-reader-private-adb-authority-v1"
WORKER_AUTHORITY = "rtl-reader-isolated-mutation-worker-v1"
BACKEND_AUTHORITY = "rtl-reader-fixed-device-mutation-backend-v1"
IMAGE_AUTHORITY = "rtl-reader-retained-frida-image-v1"
ACK_AUTHORITY = "rtl-reader-device-mutation-ack-v1"
GUARDIAN_AUTHORITY = "rtl-reader-root-frida-guardian-v1"
SERVER_AUTHORITY = "rtl-reader-device-frida-server-v1"
HANDSHAKE_AUTHORITY = "rtl-reader-frida-handshake-v1"
ABSENCE_AUTHORITY = "rtl-reader-frida-absence-v1"

TARGET_CALL_BUDGET_NS = 25_000_000
TARGET_TOTAL_BUDGET_NS = 250_000_000
HARDWARE_TIMING_PROVEN_OFFLINE = False
MAX_OPERATION_BUDGET_NS = 10_000_000_000
MAX_TOTAL_BUDGET_NS = 60_000_000_000
STAGING_PREFIX = "/data/local/tmp/rtl-reader-native-page"
DEFAULT_ADB_PORT = 5037
DEFAULT_FRIDA_PORT = 27042

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_ENDPOINT = re.compile(r"tcp:127\.0\.0\.1:([0-9]{4,5})\Z")


class DeviceFridaError(RuntimeError):
    """The fixed lifecycle could not be admitted or proven."""


class CleanupUncertain(DeviceFridaError):
    """Exact cleanup cannot be proven; authority is permanently sealed."""


def _fail(message: str) -> NoReturn:
    raise DeviceFridaError(message)


def _exact_type(value: Any, expected: type, label: str) -> None:
    if type(value) is not expected:
        _fail(label + " has an inexact type")


def _hex(value: Any, label: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        _fail(label + " is not a canonical SHA-256/token")
    return value


def _positive_int(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        _fail(label + " is outside its exact integer bounds")
    return value


def _literal(value: Any, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        _fail(label + " differs")
    return value


def _optional_positive_int(value: Any, label: str,
                           maximum: int = 2**63 - 1) -> int | None:
    if value is None:
        return None
    return _positive_int(value, label, maximum)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class PrivateAdbBinding:
    authority: str
    serial: str
    endpoint: str
    server_pid: int
    server_start_ticks: int
    bundle_sha256: str
    session_id: str
    retained_server_handle: bool
    explicit_serial: bool
    private_socket: bool
    shared_server: bool

    def validate(self) -> None:
        _literal(self.authority, PRIVATE_ADB_AUTHORITY, "private ADB authority")
        if (type(self.serial) is not str or _SERIAL.fullmatch(self.serial) is None or
                type(self.endpoint) is not str):
            _fail("private ADB binding identity differs")
        match = _ENDPOINT.fullmatch(self.endpoint)
        if (match is None or not 1024 <= int(match.group(1)) <= 65535 or
                int(match.group(1)) == DEFAULT_ADB_PORT):
            _fail("private ADB endpoint is absent or global")
        _positive_int(self.server_pid, "private ADB PID", 4_194_304)
        _positive_int(self.server_start_ticks, "private ADB start time")
        _hex(self.bundle_sha256, "private ADB bundle digest")
        _hex(self.session_id, "private ADB session")
        if (self.retained_server_handle is not True or self.explicit_serial is not True or
                self.private_socket is not True or self.shared_server is not False):
            _fail("private ADB retained/no-ambient authority differs")


@dataclass(frozen=True)
class WorkerBinding:
    authority: str
    session_id: str
    pid: int
    start_ticks: int
    image_sha256: str
    retained_process_handle: bool
    isolated: bool

    def validate(self) -> None:
        _literal(self.authority, WORKER_AUTHORITY, "isolated worker authority")
        _hex(self.session_id, "worker session")
        _positive_int(self.pid, "worker PID", 4_194_304)
        _positive_int(self.start_ticks, "worker start time")
        _hex(self.image_sha256, "worker image digest")
        if self.retained_process_handle is not True or self.isolated is not True:
            _fail("isolated worker is not retained and private")


@dataclass(frozen=True)
class BackendBinding:
    authority: str
    serial: str
    private_adb_session_id: str
    private_adb_endpoint: str
    private_adb_pid: int
    private_adb_start_ticks: int
    worker_session_id: str
    worker_pid: int
    worker_start_ticks: int
    worker_image_sha256: str
    private_socket: bool
    explicit_serial_every_operation: bool
    accepts_general_commands: bool
    retained_worker_handle: bool
    fresh_reply_channel_per_operation: bool
    late_ack_channel_sealed_before_return: bool
    failure_returns_after_operation_quiescence: bool

    def validate(self, adb: PrivateAdbBinding, worker: WorkerBinding) -> None:
        _literal(self.authority, BACKEND_AUTHORITY, "mutation backend authority")
        for value, expected, label in (
                (self.serial, adb.serial, "mutation backend serial"),
                (self.private_adb_session_id, adb.session_id, "backend ADB session"),
                (self.private_adb_endpoint, adb.endpoint, "backend ADB endpoint"),
                (self.worker_session_id, worker.session_id, "backend worker session"),
                (self.worker_image_sha256, worker.image_sha256, "backend worker image")):
            _literal(value, expected, label)
        _positive_int(self.private_adb_pid, "backend ADB PID", 4_194_304)
        _positive_int(self.private_adb_start_ticks, "backend ADB start time")
        _positive_int(self.worker_pid, "backend worker PID", 4_194_304)
        _positive_int(self.worker_start_ticks, "backend worker start time")
        if (self.serial != adb.serial or
                self.private_adb_session_id != adb.session_id or
                self.private_adb_endpoint != adb.endpoint or
                self.private_adb_pid != adb.server_pid or
                self.private_adb_start_ticks != adb.server_start_ticks or
                self.worker_session_id != worker.session_id or
                self.worker_pid != worker.pid or
                self.worker_start_ticks != worker.start_ticks or
                self.worker_image_sha256 != worker.image_sha256 or
                self.private_socket is not True or
                self.explicit_serial_every_operation is not True or
                self.accepts_general_commands is not False or
                self.retained_worker_handle is not True or
                self.fresh_reply_channel_per_operation is not True or
                self.late_ack_channel_sealed_before_return is not True or
                self.failure_returns_after_operation_quiescence is not True):
            _fail("mutation backend is not bound to the retained private authorities")


@dataclass(frozen=True)
class FridaImageIdentity:
    authority: str
    retained_id: str
    sha256: str
    size: int
    version: str
    protocol: str
    abi: str
    retained_bytes: bool

    def validate(self) -> None:
        _literal(self.authority, IMAGE_AUTHORITY, "Frida image authority")
        _hex(self.retained_id, "Frida retained image ID")
        _hex(self.sha256, "Frida image digest")
        _positive_int(self.size, "Frida image size", 512 * 1024 * 1024)
        if (type(self.version) is not str or _VERSION.fullmatch(self.version) is None or
                type(self.protocol) is not str or _VERSION.fullmatch(self.protocol) is None or
                type(self.abi) is not str or self.abi != "arm64-v8a" or
                self.retained_bytes is not True):
            _fail("Frida image version/protocol/ABI authority differs")


@dataclass(frozen=True)
class RunPolicy:
    session_id: str
    serial: str
    device_port: int
    operation_budget_ns: int = TARGET_CALL_BUDGET_NS
    total_budget_ns: int = TARGET_TOTAL_BUDGET_NS
    staging_uid: int = 2000
    staging_gid: int = 2000
    staged_mode: int = 0o600
    running_mode: int = 0o700

    def validate(self) -> None:
        _hex(self.session_id, "run session")
        if type(self.serial) is not str or _SERIAL.fullmatch(self.serial) is None:
            _fail("run serial differs")
        if (type(self.device_port) is not int or not 30_000 <= self.device_port <= 49_999 or
                self.device_port == DEFAULT_FRIDA_PORT):
            _fail("Frida port is not a fixed private run port")
        if (type(self.operation_budget_ns) is not int or
                not 1 <= self.operation_budget_ns <= MAX_OPERATION_BUDGET_NS or
                type(self.total_budget_ns) is not int or
                not self.operation_budget_ns <= self.total_budget_ns <= MAX_TOTAL_BUDGET_NS):
            _fail("run timing policy differs")
        for value, label in ((self.staging_uid, "staging UID"),
                             (self.staging_gid, "staging GID"),
                             (self.staged_mode, "staged mode"),
                             (self.running_mode, "running mode")):
            if type(value) is not int:
                _fail(label + " has an inexact integer type")
        if (self.staging_uid, self.staging_gid, self.staged_mode, self.running_mode) != (
                2000, 2000, 0o600, 0o700):
            _fail("fixed Android staging ownership/mode policy differs")

    def staging_directory(self) -> str:
        return f"{STAGING_PREFIX}/{self.session_id}"

    def staging_path(self, image: FridaImageIdentity) -> str:
        return f"{self.staging_directory()}/frida-server-{image.sha256[:16]}"

    def server_cmdline(self, image: FridaImageIdentity) -> tuple[str, ...]:
        return (self.staging_path(image), "-l", f"127.0.0.1:{self.device_port}")

    def server_session_id(self, image: FridaImageIdentity) -> str:
        return _digest({"authority": SERVER_AUTHORITY, "runSessionId": self.session_id,
                        "serial": self.serial, "port": self.device_port,
                        "imageSha256": image.sha256})


@dataclass(frozen=True)
class DeviceFileIdentity:
    path: str
    sha256: str
    size: int
    uid: int
    gid: int
    mode: int
    device: int
    inode: int
    nlink: int
    regular: bool
    symlink: bool
    resolved_path: str
    parent_path: str
    parent_uid: int
    parent_gid: int
    parent_mode: int
    parent_device: int
    parent_inode: int
    parent_directory: bool
    parent_symlink: bool
    ancestors_symlink_free: bool


@dataclass(frozen=True)
class GuardianIdentity:
    authority: str
    session_id: str
    serial: str
    pid: int
    start_ticks: int
    uid: int
    gid: int
    cmdline: tuple[str, ...]
    control_channel_id: str
    retained_control_channel: bool
    private_adb_session_id: str
    worker_session_id: str


@dataclass(frozen=True)
class ServerIdentity:
    authority: str
    session_id: str
    guardian_control_channel_id: str
    pid: int
    start_ticks: int
    uid: int
    gid: int
    cmdline: tuple[str, ...]
    executable_path: str
    executable_sha256: str
    executable_device: int
    executable_inode: int
    listen_address: str
    listen_port: int


@dataclass(frozen=True)
class HandshakeIdentity:
    authority: str
    session_id: str
    server_pid: int
    server_start_ticks: int
    version: str
    protocol: str


@dataclass(frozen=True)
class ReadyObservation:
    file: DeviceFileIdentity
    guardian: GuardianIdentity
    server: ServerIdentity
    handshake: HandshakeIdentity
    listener_exclusive: bool
    guardian_active: bool
    guardian_control_channel_active: bool
    server_active: bool


@dataclass(frozen=True)
class MutationRequest:
    authority: str
    session_id: str
    serial: str
    sequence: int
    entry_generation: int
    state_generation: int
    lifecycle_state: str
    operation: str
    issued_ns: int
    deadline_ns: int
    private_adb_session_id: str
    worker_session_id: str
    private_adb_binding_sha256: str
    worker_binding_sha256: str
    backend_binding_sha256: str
    image_identity_sha256: str
    arguments_sha256: str

    def sha256(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class MutationAck:
    authority: str
    session_id: str
    serial: str
    sequence: int
    operation: str
    request_sha256: str
    issued_ns: int
    produced_ns: int


@dataclass(frozen=True)
class SyncReceipt:
    ack: MutationAck
    transferred_bytes: int
    complete: bool
    directory_created_exclusively: bool
    file: DeviceFileIdentity


@dataclass(frozen=True)
class FileReceipt:
    ack: MutationAck
    file: DeviceFileIdentity


@dataclass(frozen=True)
class GuardianReceipt:
    ack: MutationAck
    guardian: GuardianIdentity


@dataclass(frozen=True)
class StartReceipt:
    ack: MutationAck
    file: DeviceFileIdentity
    server: ServerIdentity


@dataclass(frozen=True)
class HandshakeReceipt:
    ack: MutationAck
    handshake: HandshakeIdentity


@dataclass(frozen=True)
class ObservationReceipt:
    ack: MutationAck
    observation: ReadyObservation


@dataclass(frozen=True)
class StopReceipt:
    ack: MutationAck
    guardian: GuardianIdentity
    server: ServerIdentity
    signal_delivered_to_guardian: bool
    killed_exact_server: bool
    joined_exact_server: bool
    server_absent: bool
    listener_absent: bool


@dataclass(frozen=True)
class UnlinkReceipt:
    ack: MutationAck
    file: DeviceFileIdentity
    file_absent: bool
    directory_absent: bool


@dataclass(frozen=True)
class GuardianStopReceipt:
    ack: MutationAck
    guardian: GuardianIdentity
    signal_delivered_to_guardian: bool
    joined_exact_guardian: bool
    guardian_absent: bool


@dataclass(frozen=True)
class AbsenceProof:
    authority: str
    session_id: str
    serial: str
    path: str
    directory_path: str
    server_pid: int | None
    server_start_ticks: int | None
    guardian_pid: int | None
    guardian_start_ticks: int | None
    file_absent: bool
    directory_absent: bool
    server_absent: bool
    guardian_absent: bool
    listener_absent: bool
    server_pid_not_reused: bool
    guardian_pid_not_reused: bool
    path_not_replaced: bool


@dataclass(frozen=True)
class AbsenceReceipt:
    ack: MutationAck
    proof: AbsenceProof


@dataclass(frozen=True)
class DeviceFridaLease:
    authority: str
    session_id: str
    serial: str
    device_port: int
    file: DeviceFileIdentity
    guardian: GuardianIdentity
    server: ServerIdentity
    handshake: HandshakeIdentity


@dataclass(frozen=True)
class DeviceFridaEvidence:
    authority: str
    session_id: str
    serial: str
    staging_path: str
    image_sha256: str
    device_port: int
    ready_lease: DeviceFridaLease | None
    final_absence: AbsenceProof | None
    operation_count: int
    hardware_timing_proven: bool


class Clock(Protocol):
    def now_ns(self) -> int: ...


class RetainedPrivateAdbAuthority(Protocol):
    def binding(self) -> PrivateAdbBinding: ...
    def verify(self, expected: PrivateAdbBinding) -> None: ...


class RetainedIsolatedWorker(Protocol):
    def binding(self) -> WorkerBinding: ...
    def verify(self, expected: WorkerBinding) -> None: ...


class RetainedFridaImage(Protocol):
    def identity(self) -> FridaImageIdentity: ...
    def verify(self, expected: FridaImageIdentity) -> None: ...


class FixedMutationBackend(Protocol):
    """Reviewed S6 adapter.  No method accepts argv, shell text, or free payload."""

    def binding(self) -> BackendBinding: ...
    def verify(self, expected: BackendBinding) -> None: ...
    def assert_operation_quiescent(self, expected: BackendBinding,
                                   sequence: int, deadline_ns: int) -> None: ...
    def assert_all_quiescent(self, expected: BackendBinding,
                             deadline_ns: int) -> None: ...
    def sync_retained_image(self, request: MutationRequest, image: RetainedFridaImage,
                            path: str) -> SyncReceipt: ...
    def inspect_staged_file(self, request: MutationRequest, path: str) -> FileReceipt: ...
    def create_root_guardian(self, request: MutationRequest, path: str,
                             device_port: int) -> GuardianReceipt: ...
    def start_exact_server(self, request: MutationRequest, guardian: GuardianIdentity,
                           file: DeviceFileIdentity, cmdline: tuple[str, ...]) -> StartReceipt: ...
    def handshake_exact_server(self, request: MutationRequest, guardian: GuardianIdentity,
                               server: ServerIdentity) -> HandshakeReceipt: ...
    def observe_ready(self, request: MutationRequest, guardian: GuardianIdentity,
                      server: ServerIdentity, file: DeviceFileIdentity) -> ObservationReceipt: ...
    def stop_exact_server(self, request: MutationRequest, guardian: GuardianIdentity,
                          server: ServerIdentity) -> StopReceipt: ...
    def unlink_exact_file(self, request: MutationRequest, guardian: GuardianIdentity,
                          file: DeviceFileIdentity) -> UnlinkReceipt: ...
    def unlink_unlaunched_file(self, request: MutationRequest,
                               file: DeviceFileIdentity) -> UnlinkReceipt: ...
    def stop_exact_guardian(self, request: MutationRequest,
                            guardian: GuardianIdentity) -> GuardianStopReceipt: ...
    def prove_absent(self, request: MutationRequest, path: str,
                     server: ServerIdentity | None,
                     guardian: GuardianIdentity | None) -> AbsenceReceipt: ...


class DeviceFridaAuthority(Protocol):
    """Narrow interface consumed by S6; it deliberately exposes no ADB primitive."""

    state: str
    cleanup_obligations: tuple[str, ...]

    def start(self, deadline_ns: int) -> DeviceFridaLease: ...
    def verify_ready(self, deadline_ns: int) -> DeviceFridaLease: ...
    def teardown(self, deadline_ns: int) -> DeviceFridaEvidence: ...
    def assert_quiescent(self, deadline_ns: int) -> None: ...
    def evidence(self) -> DeviceFridaEvidence: ...


T = TypeVar("T")


def _serialized(function: Callable[..., T]) -> Callable[..., T]:
    """Reject concurrent lifecycle entry instead of interleaving authority."""
    @wraps(function)
    def guarded(self: "AuthenticatedDeviceFridaAuthority", *args: Any,
                **kwargs: Any) -> T:
        caller = threading.get_ident()
        if (self._active_entry_generation is not None and
                self._entry_owner == caller):
            _fail("reentrant Frida authority entry is not permitted")
        if not self._lock.acquire(blocking=False):
            _fail("concurrent Frida authority entry is not permitted")
        if self._active_entry_generation is not None:
            self._lock.release()
            _fail("concurrent Frida authority entry is not permitted")
        self._entry_generation += 1
        self._active_entry_generation = self._entry_generation
        self._entry_owner = caller
        try:
            return function(self, *args, **kwargs)
        finally:
            self._active_entry_generation = None
            self._entry_owner = None
            self._lock.release()
    return guarded


class AuthenticatedDeviceFridaAuthority:
    """One-shot, fail-closed owner of the exact temporary server lifecycle."""

    _MUTATING = frozenset({
        "sync_image", "create_guardian", "start_server", "stop_server",
        "unlink_file", "unlink_unlaunched_file", "stop_guardian",
    })

    def __init__(self, *, policy: RunPolicy, private_adb: RetainedPrivateAdbAuthority,
                 worker: RetainedIsolatedWorker, image: RetainedFridaImage,
                 backend: FixedMutationBackend, clock: Clock):
        if any(value is None for value in (private_adb, worker, image, backend, clock)):
            _fail("all retained authorities and the monotonic clock are required")
        _exact_type(policy, RunPolicy, "run policy")
        policy.validate()
        self._policy = policy
        self._private_adb_authority = private_adb
        self._worker_authority = worker
        self._image_authority = image
        self._backend_adapter = backend
        self._clock = clock
        self._lock = threading.Lock()
        self._entry_generation = 0
        self._active_entry_generation: int | None = None
        self._entry_owner: int | None = None
        self._last_now_ns = -1
        self._adb = private_adb.binding()
        self._worker = worker.binding()
        self._image = image.identity()
        self._backend = backend.binding()
        _exact_type(self._adb, PrivateAdbBinding, "private ADB binding")
        _exact_type(self._worker, WorkerBinding, "worker binding")
        _exact_type(self._image, FridaImageIdentity, "Frida image identity")
        _exact_type(self._backend, BackendBinding, "backend binding")
        self._adb.validate()
        self._worker.validate()
        self._image.validate()
        self._backend.validate(self._adb, self._worker)
        if policy.serial != self._adb.serial:
            _fail("run serial differs from retained private ADB serial")
        self._sequence = 0
        self.state = "NEW"
        self._state_generation = 0
        self.cleanup_obligations: tuple[str, ...] = ()
        self._file: DeviceFileIdentity | None = None
        self._guardian: GuardianIdentity | None = None
        self._server: ServerIdentity | None = None
        self._handshake: HandshakeIdentity | None = None
        self._lease: DeviceFridaLease | None = None
        self._absence: AbsenceProof | None = None
        self._mutation_started = False
        self._ambiguous_mutation = False
        self._absence_server: ServerIdentity | None = None
        self._absence_guardian: GuardianIdentity | None = None
        self._verify_dependencies()

    @property
    def staging_path(self) -> str:
        return self.policy.staging_path(self._image)

    @property
    def policy(self) -> RunPolicy:
        return self._policy

    def _set_state(self, value: str) -> None:
        if type(value) is not str or value not in {
                "NEW", "STARTING", "READY", "RELEASING", "CLOSED",
                "FAILED", "FAILED_CLEAN", "CLEANUP_UNCERTAIN"}:
            _fail("unknown lifecycle state")
        if value != self.state:
            self.state = value
            self._state_generation += 1

    def _now(self) -> int:
        value = self._clock.now_ns()
        if type(value) is not int or value < 0 or value < self._last_now_ns:
            _fail("monotonic lifecycle clock regressed or has an inexact value")
        self._last_now_ns = value
        return value

    def _verify_dependencies(self) -> None:
        self._private_adb_authority.verify(self._adb)
        current_adb = self._private_adb_authority.binding()
        _exact_type(current_adb, PrivateAdbBinding, "current private ADB binding")
        current_adb.validate()
        if current_adb != self._adb:
            _fail("private ADB retained identity drifted")
        self._worker_authority.verify(self._worker)
        current_worker = self._worker_authority.binding()
        _exact_type(current_worker, WorkerBinding, "current worker binding")
        current_worker.validate()
        if current_worker != self._worker:
            _fail("isolated worker retained identity drifted")
        self._image_authority.verify(self._image)
        current_image = self._image_authority.identity()
        _exact_type(current_image, FridaImageIdentity, "current Frida image identity")
        current_image.validate()
        if current_image != self._image:
            _fail("retained Frida bytes changed")
        self._backend_adapter.verify(self._backend)
        current = self._backend_adapter.binding()
        _exact_type(current, BackendBinding, "current mutation backend binding")
        current.validate(self._adb, self._worker)
        if current != self._backend:
            _fail("mutation backend binding drifted")

    def _lifecycle_deadline(self, deadline_ns: int) -> int:
        now = self._now()
        if (type(deadline_ns) is not int or
                not now < deadline_ns <= now + self.policy.total_budget_ns):
            _fail("lifecycle deadline is expired or outside the frozen run budget")
        return deadline_ns

    def _request(self, operation: str, arguments: Any, lifecycle_deadline: int) -> MutationRequest:
        if operation not in {
                "sync_image", "inspect_file", "create_guardian", "start_server",
                "handshake", "observe_ready", "stop_server", "unlink_file",
                "unlink_unlaunched_file", "stop_guardian", "prove_absent"}:
            _fail("operation is outside the fixed device mutation registry")
        now = self._now()
        if now >= lifecycle_deadline:
            _fail("operation cannot start after the lifecycle deadline")
        if self._sequence >= 2**31 - 1:
            _fail("fixed operation sequence is exhausted")
        if self._active_entry_generation is None or self._entry_owner != threading.get_ident():
            _fail("device operation is outside its serialized public lifecycle entry")
        self._sequence += 1
        return MutationRequest(
            authority=AUTHORITY,
            session_id=self.policy.session_id,
            serial=self.policy.serial,
            sequence=self._sequence,
            entry_generation=self._active_entry_generation,
            state_generation=self._state_generation,
            lifecycle_state=self.state,
            operation=operation,
            issued_ns=now,
            deadline_ns=min(lifecycle_deadline, now + self.policy.operation_budget_ns),
            private_adb_session_id=self._adb.session_id,
            worker_session_id=self._worker.session_id,
            private_adb_binding_sha256=_digest(asdict(self._adb)),
            worker_binding_sha256=_digest(asdict(self._worker)),
            backend_binding_sha256=_digest(asdict(self._backend)),
            image_identity_sha256=_digest(asdict(self._image)),
            arguments_sha256=_digest(arguments),
        )

    def _require_current_request(self, request: MutationRequest) -> None:
        if (self._active_entry_generation != request.entry_generation or
                self._entry_owner != threading.get_ident() or
                self._state_generation != request.state_generation or
                self.state != request.lifecycle_state or self._sequence != request.sequence):
            _fail(request.operation + " request is no longer the current lifecycle authority")

    def _ack(self, request: MutationRequest, ack: MutationAck) -> None:
        _exact_type(ack, MutationAck, request.operation + " ACK")
        _literal(ack.authority, ACK_AUTHORITY, request.operation + " ACK authority")
        _literal(ack.session_id, request.session_id, request.operation + " ACK session")
        _literal(ack.serial, request.serial, request.operation + " ACK serial")
        _literal(ack.operation, request.operation, request.operation + " ACK operation")
        _literal(ack.request_sha256, request.sha256(), request.operation + " ACK digest")
        if type(ack.sequence) is not int or type(ack.issued_ns) is not int:
            _fail(request.operation + " ACK has an inexact integer field")
        now = self._now()
        self._require_current_request(request)
        if (ack.authority != ACK_AUTHORITY or ack.session_id != request.session_id or
                ack.serial != request.serial or type(ack.sequence) is not int or
                ack.sequence != request.sequence or
                ack.operation != request.operation or
                ack.request_sha256 != request.sha256() or
                ack.issued_ns != request.issued_ns or
                type(ack.produced_ns) is not int or
                not request.issued_ns <= ack.produced_ns <= now < request.deadline_ns):
            _fail(request.operation + " ACK is stale, late, substituted, or cross-session")

    def _call(self, operation: str, arguments: Any, lifecycle_deadline: int,
              expected_type: type[T], function: Callable[[MutationRequest], T]) -> T:
        self._verify_dependencies()
        request = self._request(operation, arguments, lifecycle_deadline)
        if operation in self._MUTATING:
            self._mutation_started = True
        try:
            result = function(request)
        except BaseException:
            # The admitted adapter promises that throwing seals the fresh reply
            # channel and settles its retained child.  Recheck that promise so
            # a later ACK cannot be consumed by any subsequent operation.
            self._backend_adapter.assert_operation_quiescent(
                self._backend, request.sequence, request.deadline_ns)
            raise
        _exact_type(result, expected_type, operation + " receipt")
        self._ack(request, result.ack)  # type: ignore[attr-defined]
        self._backend_adapter.assert_operation_quiescent(
            self._backend, request.sequence, request.deadline_ns)
        self._verify_dependencies()
        self._require_current_request(request)
        if self._now() >= request.deadline_ns:
            _fail(operation + " completed after its admitted deadline")
        return result

    def _validate_file(self, value: DeviceFileIdentity, mode: int,
                       *, retained: DeviceFileIdentity | None = None) -> None:
        _exact_type(value, DeviceFileIdentity, "device file identity")
        _literal(value.path, self.staging_path, "device file path")
        _literal(value.sha256, self._image.sha256, "device file digest")
        _literal(value.resolved_path, self.staging_path, "resolved device file path")
        _literal(value.parent_path, self.policy.staging_directory(), "staging parent path")
        for field, label in (
                (value.size, "device file size"), (value.uid, "device file UID"),
                (value.gid, "device file GID"), (value.mode, "device file mode"),
                (value.parent_uid, "staging parent UID"),
                (value.parent_gid, "staging parent GID"),
                (value.parent_mode, "staging parent mode")):
            if type(field) is not int:
                _fail(label + " has an inexact integer type")
        if (value.path != self.staging_path or value.sha256 != self._image.sha256 or
                value.size != self._image.size or value.uid != self.policy.staging_uid or
                value.gid != self.policy.staging_gid or value.mode != mode or
                type(value.device) is not int or value.device <= 0 or
                type(value.inode) is not int or value.inode <= 0 or
                type(value.nlink) is not int or value.nlink != 1 or
                value.regular is not True or value.symlink is not False or
                value.resolved_path != self.staging_path or
                value.parent_path != self.policy.staging_directory() or
                value.parent_uid != self.policy.staging_uid or
                value.parent_gid != self.policy.staging_gid or
                value.parent_mode != 0o700 or
                type(value.parent_device) is not int or value.parent_device != value.device or
                type(value.parent_inode) is not int or value.parent_inode <= 0 or
                value.parent_inode == value.inode or
                value.parent_directory is not True or value.parent_symlink is not False or
                value.ancestors_symlink_free is not True):
            _fail("staged Frida bytes/stat/path/link identity differs")
        if retained is not None and (value.device, value.inode, value.sha256, value.size,
                                     value.uid, value.gid, value.parent_device,
                                     value.parent_inode) != (
                retained.device, retained.inode, retained.sha256, retained.size,
                retained.uid, retained.gid, retained.parent_device,
                retained.parent_inode):
            _fail("staged Frida file was replaced or relinked")

    def _validate_guardian(self, value: GuardianIdentity) -> None:
        _exact_type(value, GuardianIdentity, "guardian identity")
        expected_cmdline = ("rtl-reader-frida-guardian-v1", self.policy.session_id,
                            self.staging_path, str(self.policy.device_port))
        _literal(value.authority, GUARDIAN_AUTHORITY, "guardian authority")
        _literal(value.session_id, self.policy.session_id, "guardian session")
        _literal(value.serial, self.policy.serial, "guardian serial")
        _literal(value.control_channel_id, value.control_channel_id,
                 "guardian control channel")
        _hex(value.control_channel_id, "guardian control channel")
        _literal(value.private_adb_session_id, self._adb.session_id,
                 "guardian ADB session")
        _literal(value.worker_session_id, self._worker.session_id,
                 "guardian worker session")
        if (type(value.cmdline) is not tuple or
                any(type(item) is not str for item in value.cmdline) or
                value.authority != GUARDIAN_AUTHORITY or
                value.session_id != self.policy.session_id or
                value.serial != self.policy.serial or type(value.uid) is not int or
                type(value.gid) is not int or value.uid != 0 or value.gid != 0 or
                value.cmdline != expected_cmdline or
                value.retained_control_channel is not True or
                value.private_adb_session_id != self._adb.session_id or
                value.worker_session_id != self._worker.session_id):
            _fail("root guardian authority differs")
        _positive_int(value.pid, "guardian PID", 4_194_304)
        _positive_int(value.start_ticks, "guardian start time")

    def _validate_server(self, value: ServerIdentity, guardian: GuardianIdentity,
                         file: DeviceFileIdentity) -> None:
        _exact_type(value, ServerIdentity, "Frida server identity")
        _literal(value.authority, SERVER_AUTHORITY, "Frida server authority")
        _literal(value.session_id, self.policy.server_session_id(self._image),
                 "Frida server session")
        _literal(value.guardian_control_channel_id, guardian.control_channel_id,
                 "Frida server guardian channel")
        _literal(value.executable_path, self.staging_path, "Frida executable path")
        _literal(value.executable_sha256, self._image.sha256, "Frida executable digest")
        _literal(value.listen_address, "127.0.0.1", "Frida listen address")
        if (type(value.cmdline) is not tuple or
                any(type(item) is not str for item in value.cmdline) or
                type(value.listen_port) is not int or
                value.authority != SERVER_AUTHORITY or
                value.session_id != self.policy.server_session_id(self._image) or
                value.guardian_control_channel_id != guardian.control_channel_id or
                type(value.uid) is not int or type(value.gid) is not int or
                value.uid != 0 or value.gid != 0 or
                value.cmdline != self.policy.server_cmdline(self._image) or
                value.executable_path != self.staging_path or
                value.executable_sha256 != self._image.sha256 or
                type(value.executable_device) is not int or
                type(value.executable_inode) is not int or
                (value.executable_device, value.executable_inode) != (file.device, file.inode) or
                value.listen_address != "127.0.0.1" or
                value.listen_port != self.policy.device_port or value.pid == guardian.pid):
            _fail("Frida server PID/path/hash/session/listener authority differs")
        _positive_int(value.pid, "Frida server PID", 4_194_304)
        _positive_int(value.start_ticks, "Frida server start time")

    def _validate_handshake(self, value: HandshakeIdentity,
                            server: ServerIdentity) -> None:
        _exact_type(value, HandshakeIdentity, "Frida handshake")
        _literal(value.authority, HANDSHAKE_AUTHORITY, "Frida handshake authority")
        _literal(value.session_id, self.policy.server_session_id(self._image),
                 "Frida handshake session")
        _positive_int(value.server_pid, "Frida handshake PID", 4_194_304)
        _positive_int(value.server_start_ticks, "Frida handshake start time")
        _literal(value.version, self._image.version, "Frida handshake version")
        _literal(value.protocol, self._image.protocol, "Frida handshake protocol")
        if (value.authority != HANDSHAKE_AUTHORITY or
                value.session_id != self.policy.server_session_id(self._image) or
                (value.server_pid, value.server_start_ticks) !=
                (server.pid, server.start_ticks) or
                value.version != self._image.version or
                value.protocol != self._image.protocol):
            _fail("Frida version/protocol handshake differs")

    def _validate_observation(self, value: ReadyObservation) -> None:
        _exact_type(value, ReadyObservation, "ready observation")
        retained_file, retained_guardian = self._file, self._guardian
        retained_server, retained_handshake = self._server, self._handshake
        if (retained_file is None or retained_guardian is None or retained_server is None or
                retained_handshake is None):
            _fail("ready observation was requested before all identities were admitted")
        self._validate_file(value.file, self.policy.running_mode, retained=retained_file)
        self._validate_guardian(value.guardian)
        self._validate_server(value.server, value.guardian, value.file)
        self._validate_handshake(value.handshake, value.server)
        if (value.file != retained_file or value.guardian != retained_guardian or
                value.server != retained_server or value.handshake != retained_handshake or
                value.listener_exclusive is not True or value.guardian_active is not True or
                value.guardian_control_channel_active is not True or
                value.server_active is not True):
            _fail("ready observation differs from retained identities")

    @_serialized
    def start(self, deadline_ns: int) -> DeviceFridaLease:
        if self.state != "NEW":
            _fail("Frida authority is one-shot and cannot start in this state")
        deadline = self._lifecycle_deadline(deadline_ns)
        self._set_state("STARTING")
        try:
            self._ambiguous_mutation = True
            sync = self._call(
                "sync_image", {"image": asdict(self._image), "path": self.staging_path},
                deadline, SyncReceipt,
                lambda request: self._backend_adapter.sync_retained_image(
                    request, self._image_authority,
                                                                  self.staging_path))
            if (type(sync.transferred_bytes) is not int or
                    sync.complete is not True or sync.transferred_bytes != self._image.size or
                    sync.directory_created_exclusively is not True):
                _fail("ADB sync was partial")
            self._validate_file(sync.file, self.policy.staged_mode)
            self._file = sync.file
            self._ambiguous_mutation = False
            inspected = self._call(
                "inspect_file", {"path": self.staging_path, "mode": self.policy.staged_mode},
                deadline, FileReceipt,
                lambda request: self._backend_adapter.inspect_staged_file(
                    request, self.staging_path))
            self._validate_file(inspected.file, self.policy.staged_mode, retained=self._file)
            if inspected.file != self._file:
                _fail("post-sync file identity differs")
            self._ambiguous_mutation = True
            guardian_receipt = self._call(
                "create_guardian", {"path": self.staging_path,
                                     "port": self.policy.device_port},
                deadline, GuardianReceipt,
                lambda request: self._backend_adapter.create_root_guardian(
                    request, self.staging_path, self.policy.device_port))
            self._validate_guardian(guardian_receipt.guardian)
            self._guardian = guardian_receipt.guardian
            self._ambiguous_mutation = False
            inspected = self._call(
                "inspect_file", {"path": self.staging_path,
                                 "mode": self.policy.staged_mode,
                                 "before": "start"}, deadline, FileReceipt,
                lambda request: self._backend_adapter.inspect_staged_file(
                    request, self.staging_path))
            self._validate_file(inspected.file, self.policy.staged_mode, retained=self._file)
            if inspected.file != self._file:
                _fail("file changed before chmod/start")
            self._ambiguous_mutation = True
            started = self._call(
                "start_server", {"guardian": asdict(self._guardian),
                                 "file": asdict(self._file),
                                 "cmdline": self.policy.server_cmdline(self._image)},
                deadline, StartReceipt,
                lambda request: self._backend_adapter.start_exact_server(
                    request, self._guardian, self._file,
                    self.policy.server_cmdline(self._image)))
            self._validate_file(started.file, self.policy.running_mode, retained=self._file)
            if started.file != DeviceFileIdentity(
                    **{**asdict(self._file), "mode": self.policy.running_mode}):
                _fail("chmod/start changed device file authority beyond the exact mode")
            self._file = started.file
            self._validate_server(started.server, self._guardian, self._file)
            self._server = started.server
            self._ambiguous_mutation = False
            handshake = self._call(
                "handshake", {"guardian": asdict(self._guardian),
                              "server": asdict(self._server)}, deadline, HandshakeReceipt,
                lambda request: self._backend_adapter.handshake_exact_server(
                    request, self._guardian, self._server))
            self._validate_handshake(handshake.handshake, self._server)
            self._handshake = handshake.handshake
            observed = self._call(
                "observe_ready", {"guardian": asdict(self._guardian),
                                  "server": asdict(self._server),
                                  "file": asdict(self._file)}, deadline, ObservationReceipt,
                lambda request: self._backend_adapter.observe_ready(
                    request, self._guardian, self._server, self._file))
            self._validate_observation(observed.observation)
            lease = DeviceFridaLease(
                AUTHORITY, self.policy.session_id, self.policy.serial,
                self.policy.device_port, self._file, self._guardian,
                self._server, self._handshake)
            self._set_state("READY")
            if (self.state != "READY" or self._active_entry_generation is None or
                    self._entry_owner != threading.get_ident()):
                _fail("ready lease publication lost serialized lifecycle authority")
            self._lease = lease
            return lease
        except BaseException as error:
            self._seal_failed(error, deadline)
            raise

    def _seal_failed(self, error: BaseException, deadline: int) -> None:
        """Rollback only identities already admitted by an exact ACK + payload.

        An invalid/missing mutation ACK can mean the device changed without a
        trustworthy identity.  Never guess, retry, scan, kill by name, or
        broaden the path/PID authority in that state.  Conversely, a failure
        in a later read-only check must not strand an already admitted exact
        guardian/server; the fixed rollback below closes only those identities.
        """
        if not self._mutation_started:
            self._set_state("FAILED")
            self.cleanup_obligations = ()
            return
        if self._ambiguous_mutation or self._file is None:
            self._set_state("CLEANUP_UNCERTAIN")
            self.cleanup_obligations = (
                "fixed lifecycle failed after device mutation; retain exact evidence and "
                "perform no broader cleanup: " + str(error),
            )
            return
        try:
            self._rollback_exact(deadline)
            self._set_state("FAILED_CLEAN")
            self.cleanup_obligations = ()
        except BaseException as cleanup:
            self._set_state("CLEANUP_UNCERTAIN")
            self.cleanup_obligations = (
                "startup failed and exact rollback is not proven; no retry or broader "
                f"cleanup is authorized: {cleanup}; original failure: {error}",
            )

    def _rollback_exact(self, deadline: int) -> None:
        if self._file is None:
            _fail("startup rollback has no admitted staged-file identity")
        retained_file = self._file
        retained_guardian = self._guardian
        retained_server = self._server
        if retained_server is not None:
            if retained_guardian is None:
                _fail("server identity exists without its guardian authority")
            self._ambiguous_mutation = True
            stopped = self._call(
                "stop_server", {"guardian": asdict(retained_guardian),
                                "server": asdict(retained_server),
                                "purpose": "startup_rollback"}, deadline, StopReceipt,
                lambda request: self._backend_adapter.stop_exact_server(
                    request, retained_guardian, retained_server))
            self._validate_guardian(stopped.guardian)
            self._validate_server(stopped.server, stopped.guardian, retained_file)
            if (stopped.guardian != retained_guardian or stopped.server != retained_server or
                    stopped.signal_delivered_to_guardian is not True or
                    stopped.killed_exact_server is not True or
                    stopped.joined_exact_server is not True or
                    stopped.server_absent is not True or stopped.listener_absent is not True):
                _fail("startup rollback did not kill/join the exact server")
            self._ambiguous_mutation = False
        inspected = self._call(
            "inspect_file", {"path": self.staging_path,
                             "mode": retained_file.mode,
                             "purpose": "startup_rollback"}, deadline, FileReceipt,
            lambda request: self._backend_adapter.inspect_staged_file(
                request, self.staging_path))
        self._validate_file(inspected.file, retained_file.mode, retained=retained_file)
        if inspected.file != retained_file:
            _fail("startup rollback file identity changed")
        self._ambiguous_mutation = True
        if retained_guardian is not None:
            unlinked = self._call(
                "unlink_file", {"guardian": asdict(retained_guardian),
                                "file": asdict(retained_file),
                                "purpose": "startup_rollback"}, deadline, UnlinkReceipt,
                lambda request: self._backend_adapter.unlink_exact_file(
                    request, retained_guardian, retained_file))
        else:
            unlinked = self._call(
                "unlink_unlaunched_file", {"file": asdict(retained_file),
                                           "purpose": "startup_rollback"}, deadline,
                UnlinkReceipt,
                lambda request: self._backend_adapter.unlink_unlaunched_file(
                    request, retained_file))
        self._validate_file(unlinked.file, retained_file.mode, retained=retained_file)
        if (unlinked.file != retained_file or unlinked.file_absent is not True or
                unlinked.directory_absent is not True):
            _fail("startup rollback exact unlink was not proven")
        self._ambiguous_mutation = False
        if retained_guardian is not None:
            self._ambiguous_mutation = True
            stopped_guardian = self._call(
                "stop_guardian", {"guardian": asdict(retained_guardian),
                                  "purpose": "startup_rollback"}, deadline,
                GuardianStopReceipt,
                lambda request: self._backend_adapter.stop_exact_guardian(
                    request, retained_guardian))
            self._validate_guardian(stopped_guardian.guardian)
            if (stopped_guardian.guardian != retained_guardian or
                    stopped_guardian.signal_delivered_to_guardian is not True or
                    stopped_guardian.joined_exact_guardian is not True or
                    stopped_guardian.guardian_absent is not True):
                _fail("startup rollback did not stop the exact guardian")
            self._ambiguous_mutation = False
        absence = self._call(
            "prove_absent", {"path": self.staging_path,
                             "server": asdict(retained_server) if retained_server else None,
                             "guardian": (asdict(retained_guardian)
                                          if retained_guardian else None),
                             "purpose": "startup_rollback"}, deadline, AbsenceReceipt,
            lambda request: self._backend_adapter.prove_absent(
                request, self.staging_path, retained_server, retained_guardian))
        self._validate_absence(absence.proof, retained_server, retained_guardian)
        self._absence = absence.proof
        self._absence_server = retained_server
        self._absence_guardian = retained_guardian

    @_serialized
    def verify_ready(self, deadline_ns: int) -> DeviceFridaLease:
        if self.state != "READY" or self._lease is None:
            _fail("Frida server is not in the retained ready state")
        ready_generation = self._state_generation
        deadline = self._lifecycle_deadline(deadline_ns)
        if self._file is None or self._guardian is None or self._server is None:
            _fail("ready lease is missing retained device identities")
        try:
            receipt = self._call(
                "observe_ready", {"guardian": asdict(self._guardian),
                                  "server": asdict(self._server),
                                  "file": asdict(self._file), "purpose": "verify"},
                deadline, ObservationReceipt,
                lambda request: self._backend_adapter.observe_ready(
                    request, self._guardian, self._server, self._file))
            self._validate_observation(receipt.observation)
            if self.state != "READY" or self._state_generation != ready_generation:
                _fail("ready verification completed after a lifecycle transition")
            return self._lease
        except BaseException as error:
            self._set_state("CLEANUP_UNCERTAIN")
            self.cleanup_obligations = (
                "ready authority changed; mutation is sealed until exact external "
                "reconciliation: " + str(error),
            )
            raise

    def _validate_absence(self, proof: AbsenceProof,
                          server: ServerIdentity | None,
                          guardian: GuardianIdentity | None) -> None:
        _exact_type(proof, AbsenceProof, "absence proof")
        _literal(proof.authority, ABSENCE_AUTHORITY, "absence authority")
        _literal(proof.session_id, self.policy.session_id, "absence session")
        _literal(proof.serial, self.policy.serial, "absence serial")
        _literal(proof.path, self.staging_path, "absence path")
        _literal(proof.directory_path, self.policy.staging_directory(),
                 "absence directory")
        _optional_positive_int(proof.server_pid, "absence server PID", 4_194_304)
        _optional_positive_int(proof.server_start_ticks,
                               "absence server start time")
        _optional_positive_int(proof.guardian_pid, "absence guardian PID", 4_194_304)
        _optional_positive_int(proof.guardian_start_ticks,
                               "absence guardian start time")
        if (proof.server_pid != (server.pid if server else None) or
                proof.server_start_ticks != (server.start_ticks if server else None) or
                proof.guardian_pid != (guardian.pid if guardian else None) or
                proof.guardian_start_ticks != (guardian.start_ticks if guardian else None) or
                proof.file_absent is not True or proof.directory_absent is not True or
                proof.server_absent is not True or proof.guardian_absent is not True or
                proof.listener_absent is not True or
                proof.server_pid_not_reused is not True or
                proof.guardian_pid_not_reused is not True or
                proof.path_not_replaced is not True):
            _fail("exact process/file/directory/listener absence was not proven")

    @_serialized
    def teardown(self, deadline_ns: int) -> DeviceFridaEvidence:
        if self.state in {"CLOSED", "FAILED", "FAILED_CLEAN"}:
            return self._evidence_unlocked()
        if self.state != "READY" or self._lease is None:
            _fail("teardown is unavailable outside the exact ready lifecycle")
        deadline = self._lifecycle_deadline(deadline_ns)
        if self._file is None or self._guardian is None or self._server is None:
            _fail("ready lease is missing retained teardown identities")
        retained_file, retained_guardian, retained_server = (
            self._file, self._guardian, self._server)
        self._set_state("RELEASING")
        try:
            observed = self._call(
                "observe_ready", {"guardian": asdict(retained_guardian),
                                  "server": asdict(retained_server),
                                  "file": asdict(retained_file), "purpose": "teardown"},
                deadline, ObservationReceipt,
                lambda request: self._backend_adapter.observe_ready(
                    request, retained_guardian, retained_server, retained_file))
            self._validate_observation(observed.observation)
            self._ambiguous_mutation = True
            stopped = self._call(
                "stop_server", {"guardian": asdict(retained_guardian),
                                "server": asdict(retained_server)}, deadline, StopReceipt,
                lambda request: self._backend_adapter.stop_exact_server(
                    request, retained_guardian, retained_server))
            self._validate_guardian(stopped.guardian)
            self._validate_server(stopped.server, stopped.guardian, retained_file)
            if (stopped.guardian != retained_guardian or stopped.server != retained_server or
                    stopped.signal_delivered_to_guardian is not True or
                    stopped.killed_exact_server is not True or
                    stopped.joined_exact_server is not True or
                    stopped.server_absent is not True or stopped.listener_absent is not True):
                _fail("exact Frida server kill/join was not proven")
            self._ambiguous_mutation = False
            inspected = self._call(
                "inspect_file", {"path": self.staging_path,
                                 "mode": self.policy.running_mode,
                                 "before": "unlink"}, deadline, FileReceipt,
                lambda request: self._backend_adapter.inspect_staged_file(
                    request, self.staging_path))
            self._validate_file(inspected.file, self.policy.running_mode,
                                retained=retained_file)
            if inspected.file != retained_file:
                _fail("staged file changed before exact unlink")
            self._ambiguous_mutation = True
            unlinked = self._call(
                "unlink_file", {"guardian": asdict(retained_guardian),
                                "file": asdict(retained_file)}, deadline, UnlinkReceipt,
                lambda request: self._backend_adapter.unlink_exact_file(
                    request, retained_guardian, retained_file))
            self._validate_file(unlinked.file, self.policy.running_mode,
                                retained=retained_file)
            if (unlinked.file != retained_file or unlinked.file_absent is not True or
                    unlinked.directory_absent is not True):
                _fail("exact staged file/path unlink was not proven")
            self._ambiguous_mutation = False
            self._ambiguous_mutation = True
            guardian_stopped = self._call(
                "stop_guardian", {"guardian": asdict(retained_guardian)}, deadline,
                GuardianStopReceipt,
                lambda request: self._backend_adapter.stop_exact_guardian(
                    request, retained_guardian))
            self._validate_guardian(guardian_stopped.guardian)
            if (guardian_stopped.guardian != retained_guardian or
                    guardian_stopped.signal_delivered_to_guardian is not True or
                    guardian_stopped.joined_exact_guardian is not True or
                    guardian_stopped.guardian_absent is not True):
                _fail("exact guardian signal/join was not proven")
            self._ambiguous_mutation = False
            absence = self._call(
                "prove_absent", {"path": self.staging_path,
                                 "server": asdict(retained_server),
                                 "guardian": asdict(retained_guardian)}, deadline,
                AbsenceReceipt,
                lambda request: self._backend_adapter.prove_absent(
                    request, self.staging_path, retained_server, retained_guardian))
            self._validate_absence(absence.proof, retained_server, retained_guardian)
            self._absence = absence.proof
            self._absence_server = retained_server
            self._absence_guardian = retained_guardian
            self._set_state("CLOSED")
            self.cleanup_obligations = ()
            return self._evidence_unlocked()
        except BaseException as error:
            self._set_state("CLEANUP_UNCERTAIN")
            self.cleanup_obligations = (
                "exact guardian/server/file cleanup is not proven; no retry or broader "
                "cleanup is authorized: " + str(error),
            )
            raise CleanupUncertain(self.cleanup_obligations[0]) from error

    @_serialized
    def assert_quiescent(self, deadline_ns: int) -> None:
        if self.state == "NEW":
            deadline = self._lifecycle_deadline(deadline_ns)
            self._verify_dependencies()
            self._backend_adapter.assert_all_quiescent(self._backend, deadline)
            return
        if self.state == "FAILED" and not self._mutation_started:
            deadline = self._lifecycle_deadline(deadline_ns)
            self._backend_adapter.assert_all_quiescent(self._backend, deadline)
            return
        if self.state not in {"CLOSED", "FAILED_CLEAN"} or self._absence is None:
            raise CleanupUncertain(
                "authority is not proven quiescent: " + "; ".join(self.cleanup_obligations))
        deadline = self._lifecycle_deadline(deadline_ns)
        try:
            receipt = self._call(
                "prove_absent", {"path": self.staging_path,
                                 "server": (asdict(self._absence_server)
                                            if self._absence_server else None),
                                 "guardian": (asdict(self._absence_guardian)
                                              if self._absence_guardian else None),
                                 "purpose": "quiescence"}, deadline, AbsenceReceipt,
                lambda request: self._backend_adapter.prove_absent(
                    request, self.staging_path, self._absence_server,
                    self._absence_guardian))
            self._validate_absence(receipt.proof, self._absence_server,
                                   self._absence_guardian)
            if receipt.proof != self._absence:
                _fail("quiescence proof changed")
            self._backend_adapter.assert_all_quiescent(self._backend, deadline)
        except BaseException as error:
            self._set_state("CLEANUP_UNCERTAIN")
            self.cleanup_obligations = (
                "post-cleanup absence proof changed; no mutation is authorized: " + str(error),
            )
            raise

    @_serialized
    def evidence(self) -> DeviceFridaEvidence:
        return self._evidence_unlocked()

    def _evidence_unlocked(self) -> DeviceFridaEvidence:
        return DeviceFridaEvidence(
            authority=AUTHORITY,
            session_id=self.policy.session_id,
            serial=self.policy.serial,
            staging_path=self.staging_path,
            image_sha256=self._image.sha256,
            device_port=self.policy.device_port,
            ready_lease=self._lease,
            final_absence=self._absence,
            operation_count=self._sequence,
            hardware_timing_proven=HARDWARE_TIMING_PROVEN_OFFLINE,
        )


__all__ = [
    "ABSENCE_AUTHORITY", "ACK_AUTHORITY", "AUTHORITY", "BACKEND_AUTHORITY",
    "AuthenticatedDeviceFridaAuthority", "BackendBinding", "CleanupUncertain", "Clock",
    "DeviceFileIdentity", "DeviceFridaAuthority",
    "DeviceFridaError", "DeviceFridaEvidence", "DeviceFridaLease",
    "FixedMutationBackend", "FridaImageIdentity", "GUARDIAN_AUTHORITY", "GuardianIdentity",
    "HANDSHAKE_AUTHORITY", "HandshakeIdentity", "HARDWARE_TIMING_PROVEN_OFFLINE",
    "IMAGE_AUTHORITY", "MutationAck", "MutationRequest", "PrivateAdbBinding",
    "PRIVATE_ADB_AUTHORITY", "ReadyObservation", "RetainedFridaImage",
    "RetainedIsolatedWorker", "RetainedPrivateAdbAuthority", "RunPolicy",
    "ServerIdentity", "SERVER_AUTHORITY", "STAGING_PREFIX", "SyncReceipt",
    "FileReceipt", "GuardianReceipt", "StartReceipt", "HandshakeReceipt",
    "ObservationReceipt", "StopReceipt", "UnlinkReceipt", "GuardianStopReceipt",
    "AbsenceProof", "AbsenceReceipt", "TARGET_CALL_BUDGET_NS",
    "TARGET_TOTAL_BUDGET_NS", "WorkerBinding", "WORKER_AUTHORITY",
]
