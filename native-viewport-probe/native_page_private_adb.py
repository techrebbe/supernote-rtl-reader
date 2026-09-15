"""Private, retained-process ADB authority; importing this module performs no I/O.

The caller retains an already-open LockedAdbBundle until close() succeeds. ADB
cannot inherit a listening socket, so reservation-to-listen is deliberately a
fail-closed handoff: a competing listener is never adopted or terminated. Every
command uses one established TCP connection whose actual server-side tuple
owner is proved before any request byte is sent. No per-command ADB CLI process
is launched. This slice admits only its frozen read-only wire services.

The Windows adapter is real but is never exercised by this module's offline
tests. Runtime adapters are a trusted boundary, not untrusted plugin inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import math
import ntpath
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from native_page_windows_tool_authority import FILENAMES, LockedAdbBundle


AUTHORITY = "rtl-reader-private-adb-authority-v1"
MAX_OUTPUT = 1024 * 1024
MAX_SERVER_OUTPUT = 65536
MAX_COMMAND_SECONDS = 60.0
MAX_SHELL_FRAMES = 16384
MAX_PLATFORM_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_PLATFORM_STDERR_BYTES = 64 * 1024
MAX_PLATFORM_SHELL_FRAMES = 65536
POLL_SECONDS = 0.02
TOKEN_RE = re.compile(r"[A-Za-z0-9_./:@+=,-]{1,256}\Z")
NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
# S1 admits USB-style serials only. Colon is a host-protocol delimiter; network
# serial syntax needs a separately reviewed encoder and is not accepted here.
SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PLATFORM_CAPTURE_TRANSPORT_AUTHORITY = (
    "rtl-reader-private-adb-static-platform-transport-v1"
)
# No caller-controlled token, path, package, or shell fragment enters this
# service. A separately reviewed device collector owns this one normalized
# stdout wire and performs no mutation or user-document selection.
PLATFORM_CAPTURE_SERVICE = (
    "shell,v2,raw:exec /system/bin/native-page-platform-collector --wire-v1"
)
PLATFORM_CAPTURE_SERVICE_SHA256 = hashlib.sha256(
    PLATFORM_CAPTURE_SERVICE.encode("ascii")
).hexdigest()


class PrivateAdbError(RuntimeError):
    """An operation cannot be admitted under the private ADB authority."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    creation_time: int
    image_path: str


@dataclass(frozen=True)
class Listener:
    address: str
    port: int
    pid: int


@dataclass(frozen=True)
class ConnectionTuple:
    local_address: str
    local_port: int
    peer_address: str
    peer_port: int


@dataclass(frozen=True)
class PeerOwner:
    connection: ConnectionTuple
    server_pid: int


@dataclass(frozen=True)
class _TcpRow:
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    pid: int
    state: int


@dataclass(frozen=True)
class CleanupObligation:
    role: str
    identity: ProcessIdentity | None
    reason: str


@dataclass(frozen=True)
class ArgumentSlot:
    name: str
    kind: str
    minimum: int = 0
    maximum: int = 0
    choices: tuple[str, ...] = ()

    def validate_definition(self) -> None:
        if type(self.name) is not str or not NAME_RE.fullmatch(self.name):
            raise PrivateAdbError("invalid typed field name")
        if self.kind == "integer":
            if (type(self.minimum) is not int or type(self.maximum) is not int or
                    not 0 <= self.minimum <= self.maximum <= 2147483647 or self.choices):
                raise PrivateAdbError("invalid integer field bounds")
        elif self.kind == "choice":
            if (type(self.choices) is not tuple or not 1 <= len(self.choices) <= 64 or
                    len(set(self.choices)) != len(self.choices) or
                    any(type(v) is not str or not TOKEN_RE.fullmatch(v)
                        for v in self.choices)):
                raise PrivateAdbError("invalid choice field authority")
        else:
            raise PrivateAdbError("unknown typed field kind")

    def render(self, value: object) -> str:
        if self.kind == "integer":
            if type(value) is not int or not self.minimum <= value <= self.maximum:
                raise PrivateAdbError("integer field is outside its exact type/bounds")
            return str(value)
        if type(value) is not str or value not in self.choices:
            raise PrivateAdbError("choice field is outside its exact authority")
        return value


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    argv: tuple[str | ArgumentSlot, ...]
    output_limit: int = 65536
    mutability: str = "read_only"

    def validate(self) -> None:
        if (type(self.command_id) is not str or not NAME_RE.fullmatch(self.command_id) or
                type(self.argv) is not tuple or not 1 <= len(self.argv) <= 64 or
                type(self.argv[0]) is not str or self.argv[0].startswith("-") or
                type(self.output_limit) is not int or not 1 <= self.output_limit <= MAX_OUTPUT or
                self.mutability not in ("read_only", "host_write", "device_write")):
            raise PrivateAdbError("invalid closed command specification")
        names: set[str] = set()
        for value in self.argv:
            if type(value) is ArgumentSlot:
                value.validate_definition()
                if value.name in names:
                    raise PrivateAdbError("duplicate typed field")
                names.add(value.name)
            elif type(value) is not str or not TOKEN_RE.fullmatch(value):
                raise PrivateAdbError("fixed argv token is not shell-safe")
        if self.argv[0] in ("server", "start-server", "kill-server", "nodaemon"):
            raise PrivateAdbError("server lifecycle is not a client command")

    def render(self, fields: Mapping[str, object]) -> tuple[str, ...]:
        if type(fields) is not dict:
            raise PrivateAdbError("typed fields must be an exact dictionary")
        expected = {v.name for v in self.argv if type(v) is ArgumentSlot}
        if set(fields) != expected:
            raise PrivateAdbError("typed fields differ from the frozen specification")
        return tuple(v.render(fields[v.name]) if type(v) is ArgumentSlot else v
                     for v in self.argv)


REFERENCE_COMMANDS = (
    CommandSpec("get_state", ("get-state",), 4096),
    CommandSpec("wm_size", ("shell", "wm", "size"), 4096),
    CommandSpec("wm_density", ("shell", "wm", "density"), 4096),
    CommandSpec("dumpsys_window", ("shell", "dumpsys", "window"), MAX_OUTPUT),
    CommandSpec("dumpsys_activity", ("shell", "dumpsys", "activity"), MAX_OUTPUT),
)


@dataclass(frozen=True)
class CommandResult:
    command_id: str
    returncode: int
    output: bytes
    mutability: str


@dataclass(frozen=True)
class PlatformCaptureTransportIdentity:
    authority: str
    serial: str
    endpoint: str
    server_pid: int
    server_creation_time: int
    server_image_path: str
    bundle_sha256: str
    service_sha256: str
    read_only: bool
    static_service: bool
    explicit_serial: bool
    retained_server: bool
    ambient_discovery: bool


@dataclass(frozen=True)
class PlatformCaptureTransportResult:
    """One complete static-service transaction on the retained private server.

    Successful instances retain the exact shell-v2 stream outcome as evidence,
    even though the admitted platform path requires exit code zero, empty
    stderr, and a clean transport EOF.
    """

    stdout: bytes
    stderr: bytes
    exit_code: int
    eof: bool
    started_ns: int
    captured_ns: int
    finished_ns: int
    transport: PlatformCaptureTransportIdentity


class PortReservation(Protocol):
    port: int
    def release(self) -> None: ...


class Runtime(Protocol):
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def windows_directory(self) -> str: ...
    def reserve(self, port: int) -> PortReservation: ...
    def listeners(self, port: int) -> tuple[Listener, ...]: ...
    def spawn_suspended(self, argv: tuple[str, ...], environment: Mapping[str, str],
                        cwd: str) -> Any: ...
    def identity(self, process: Any) -> ProcessIdentity: ...
    def modules(self, process: Any) -> tuple[str, ...]: ...
    def resume(self, process: Any) -> None: ...
    def poll(self, process: Any) -> int | None: ...
    def read(self, process: Any, limit: int) -> bytes: ...
    def terminate(self, process: Any, expected: ProcessIdentity) -> None: ...
    def close_process(self, process: Any, expected: ProcessIdentity) -> None: ...
    def connect(self, port: int, deadline: float) -> Any: ...
    def connection_tuple(self, connection: Any) -> ConnectionTuple: ...
    def peer_owner(self, connection: Any) -> PeerOwner: ...
    def send(self, connection: Any, raw: bytes, deadline: float) -> int | None: ...
    def receive(self, connection: Any, limit: int, deadline: float) -> bytes | None: ...
    def close_connection(self, connection: Any) -> None: ...


@dataclass
class _OwnedProcess:
    role: str
    process: Any
    identity: ProcessIdentity | None = None
    admitted_image: bool = False


def _path(value: str) -> str:
    if type(value) is not str or not ntpath.isabs(value) or "\x00" in value:
        raise PrivateAdbError("process image path is not absolute")
    return ntpath.normcase(ntpath.normpath(value))


class PrivateAdbServer:
    """Single-run authority, with no default/global-server fallback.

    Only the exact reference read-only services are currently admitted. A
    future mutating wire path requires its own independent review; neither a
    mutability label nor caller-supplied argv can authorize it in this slice.
    No bundle ownership is transferred: this class never closes its bundle.
    """

    def __init__(self, bundle: LockedAdbBundle, serial: str, state_directory: Path,
                 *, runtime: Runtime | None = None, port: int = 0):
        if type(serial) is not str or SERIAL_RE.fullmatch(serial) is None:
            raise PrivateAdbError("authorized serial is invalid")
        if type(port) is not int or (port != 0 and not 1024 <= port <= 65535) or port == 5037:
            raise PrivateAdbError("private port is invalid or the global ADB port")
        state_path = os.fspath(state_directory)
        if not ntpath.isabs(state_path) or "\x00" in state_path:
            raise PrivateAdbError("private state directory must be absolute")
        self.bundle = bundle
        self.serial = serial
        self.state_directory = state_path
        self.runtime: Runtime = runtime if runtime is not None else WindowsRuntime()
        self.requested_port = port
        self.port: int | None = None
        self.state = "new"
        self._mode = "unstarted"
        self._registry: Mapping[str, CommandSpec] = MappingProxyType({})
        self._authority: bytes | None = None
        self._images: dict[str, str] = {}
        self._environment: Mapping[str, str] = MappingProxyType({})
        self._reservation: PortReservation | None = None
        self._owned: list[_OwnedProcess] = []
        self._connections: list[Any] = []
        self._server: _OwnedProcess | None = None
        self._server_output = 0
        self._operation_lock = threading.Lock()
        self.cleanup_obligations: tuple[CleanupObligation, ...] = ()

    @property
    def endpoint(self) -> str:
        if self.port is None:
            raise PrivateAdbError("private endpoint has not been reserved")
        return f"tcp:127.0.0.1:{self.port}"

    def _bundle_verify(self) -> None:
        self.bundle.verify()
        if self._authority is None or self.bundle.canonical_bytes() != self._authority:
            raise PrivateAdbError("reviewed executable/DLL authority changed")
        if _path(self.bundle.executable) != self._images["adb.exe"]:
            raise PrivateAdbError("reviewed executable path changed")

    def _process_verify(self, owned: _OwnedProcess, *, alive: bool = False) -> None:
        current = self.runtime.identity(owned.process)
        if (not owned.admitted_image or owned.identity is None or current != owned.identity or
                _path(current.image_path) != self._images["adb.exe"]):
            raise PrivateAdbError(f"{owned.role} retained process identity/image changed")
        if alive and self.runtime.poll(owned.process) is not None:
            raise PrivateAdbError(f"{owned.role} retained process exited")

    def _spawn(self, role: str, argv: tuple[str, ...]) -> _OwnedProcess:
        self._bundle_verify()
        handle = self.runtime.spawn_suspended(argv, self._environment, str(self.bundle.directory))
        owned = _OwnedProcess(role, handle)
        self._owned.append(owned)
        owned.identity = self.runtime.identity(handle)
        if (type(owned.identity.pid) is not int or owned.identity.pid <= 0 or
                type(owned.identity.creation_time) is not int or owned.identity.creation_time <= 0 or
                _path(owned.identity.image_path) != self._images["adb.exe"]):
            raise PrivateAdbError("spawned process does not have the reviewed image")
        owned.admitted_image = True
        self._bundle_verify()
        self._process_verify(owned, alive=True)
        return owned

    def _server_drain(self) -> None:
        assert self._server is not None
        remaining = MAX_SERVER_OUTPUT - self._server_output
        raw = self.runtime.read(self._server.process, min(4096, remaining + 1))
        if type(raw) is not bytes or len(raw) > min(4096, remaining + 1):
            raise PrivateAdbError("runtime violated bounded output contract")
        self._server_output += len(raw)
        if self._server_output > MAX_SERVER_OUTPUT:
            raise PrivateAdbError("private server output limit exceeded")

    def _listener_verify(self, *, allow_absent: bool = False) -> bool:
        assert self.port is not None and self._server is not None
        self._process_verify(self._server, alive=True)
        listeners = self.runtime.listeners(self.port)
        if not listeners and allow_absent:
            return False
        identity = self._server.identity
        assert identity is not None
        if listeners != (Listener("127.0.0.1", self.port, identity.pid),):
            raise PrivateAdbError("private listener is not exclusively owned by retained server")
        self._process_verify(self._server, alive=True)
        return True

    def _module_verify(self) -> None:
        assert self._server is not None
        modules = self.runtime.modules(self._server.process)
        for name in FILENAMES[1:]:
            matching = [p for p in modules if ntpath.basename(p).lower() == name.lower()]
            if len(matching) != 1 or _path(matching[0]) != self._images[name]:
                raise PrivateAdbError("private server loaded an absent/substituted ADB DLL")

    def start(self, commands: tuple[CommandSpec, ...] = REFERENCE_COMMANDS,
              *, timeout: float = 10.0) -> "PrivateAdbServer":
        """Start the legacy frozen-command authority.

        This remains source-compatible with the original API.  The complete
        platform collector uses :meth:`start_platform_capture` instead, so a
        server instance can never mix legacy command dispatch with the one
        reviewed platform service.
        """
        return self._start(commands, timeout=timeout, mode="commands")

    def start_platform_capture(self, *, timeout: float = 10.0) -> "PrivateAdbServer":
        """Start a dedicated no-parameter platform-capture transport."""
        return self._start((), timeout=timeout, mode="platform_capture")

    def _start(self, commands: tuple[CommandSpec, ...], *, timeout: float,
               mode: str) -> "PrivateAdbServer":
        if self.state != "new":
            raise PrivateAdbError("private server start lifecycle is invalid")
        if (mode not in ("commands", "platform_capture") or
                type(commands) is not tuple or
                (mode == "commands" and not 1 <= len(commands) <= 128) or
                (mode == "platform_capture" and commands != ()) or
                type(timeout) not in (int, float) or not 0 < timeout <= 30):
            raise PrivateAdbError("invalid registry or startup bound")
        registry: dict[str, CommandSpec] = {}
        for spec in commands:
            if type(spec) is not CommandSpec:
                raise PrivateAdbError("command registry contains an untyped specification")
            spec.validate()
            frozen = {value.command_id: value.argv for value in REFERENCE_COMMANDS}
            if (spec.mutability != "read_only" or spec.command_id not in frozen or
                    spec.argv != frozen[spec.command_id] or
                    any(type(value) is not str for value in spec.argv)):
                raise PrivateAdbError("S1 admits only frozen static read-only wire services")
            if spec.command_id in registry:
                raise PrivateAdbError("duplicate command ID")
            registry[spec.command_id] = spec
        self._registry = MappingProxyType(registry)
        self._mode = mode
        self.state = "starting"
        deadline = self.runtime.now() + timeout
        try:
            self.bundle.verify()
            self._authority = self.bundle.canonical_bytes()
            self._images = {name: _path(value.path)
                            for name, value in self.bundle.authorities().items()}
            if set(self._images) != set(FILENAMES):
                raise PrivateAdbError("bundle is incomplete")
            system = self.runtime.windows_directory()
            _path(system)
            # No inherited PATH, ADB_SERVER_SOCKET, ANDROID_SERIAL, PYTHONPATH,
            # COMSPEC, vendor keys, tracing, preload or SDK/user-profile settings.
            self._environment = MappingProxyType({
                "SystemRoot": system, "WINDIR": system,
                "PATH": ntpath.join(system, "System32"),
                "HOME": self.state_directory, "USERPROFILE": self.state_directory,
                "ANDROID_USER_HOME": ntpath.join(self.state_directory, ".android"),
                "TEMP": self.state_directory, "TMP": self.state_directory,
                "ADB_MDNS_AUTO_CONNECT": "0",
            })
            if self.requested_port and self.runtime.listeners(self.requested_port):
                raise PrivateAdbError("requested private port already has a listener")
            self._reservation = self.runtime.reserve(self.requested_port)
            self.port = self._reservation.port
            if (type(self.port) is not int or not 1024 <= self.port <= 65535 or
                    self.port == 5037 or self.runtime.listeners(self.port)):
                raise PrivateAdbError("reserved private endpoint is not exclusive")
            argv = (self.bundle.executable, "-L", self.endpoint, "server", "nodaemon")
            self._server = self._spawn("server", argv)
            if self.runtime.now() >= deadline:
                raise PrivateAdbError("private server startup deadline exceeded before resume")
            self._reservation.release()
            self._reservation = None
            self.runtime.resume(self._server.process)
            while self.runtime.now() < deadline:
                self._server_drain()
                if self._listener_verify(allow_absent=True):
                    self.state = "ready"
                    self.verify()
                    if self.runtime.now() >= deadline:
                        raise PrivateAdbError("private server startup deadline exceeded")
                    return self
                self.runtime.sleep(min(POLL_SECONDS, deadline - self.runtime.now()))
            raise PrivateAdbError("private server startup deadline exceeded")
        except BaseException as error:
            self._abort(error)
            raise

    def verify(self) -> None:
        if self.state != "ready" or self._server is None:
            raise PrivateAdbError("private server is not ready")
        self._bundle_verify()
        self._server_drain()
        self._listener_verify()
        self._module_verify()
        self._listener_verify()
        self._bundle_verify()

    def run(self, command_id: str, typed_args: dict[str, object],
            deadline: float) -> CommandResult:
        if not self._operation_lock.acquire(blocking=False):
            raise PrivateAdbError("private ADB operation is concurrent or reentrant")
        try:
            return self._run_locked(command_id, typed_args, deadline)
        finally:
            self._operation_lock.release()

    def _run_locked(self, command_id: str, typed_args: dict[str, object],
                    deadline: float) -> CommandResult:
        if (self.state != "ready" or self._mode != "commands" or
                type(command_id) is not str or
                command_id not in self._registry):
            raise PrivateAdbError("command ID is not in the ready frozen registry")
        now = self.runtime.now()
        if type(deadline) not in (int, float) or not now < deadline <= now + MAX_COMMAND_SECONDS:
            raise PrivateAdbError("command deadline is outside the admitted bound")
        spec = self._registry[command_id]
        spec.render(typed_args)
        try:
            self.verify()
            self._deadline(deadline)
            assert self.port is not None
            connection = self.runtime.connect(self.port, deadline)
            self._connections.append(connection)
            peer = self._admit_connection(connection, deadline)
            if command_id == "get_state":
                self._request(connection, peer, f"host-serial:{self.serial}:get-state", deadline)
                self._status(connection, deadline)
                size = self._hex_length(connection, deadline)
                if size > spec.output_limit:
                    raise PrivateAdbError("host response output limit exceeded")
                output = self._read_exact(connection, size, deadline)
                self._eof(connection, deadline)
                status = 0
            else:
                self._request(connection, peer, f"host:transport:{self.serial}", deadline)
                self._status(connection, deadline)
                service = "shell,v2,raw:" + " ".join(spec.argv[1:])
                self._request(connection, peer, service, deadline)
                self._status(connection, deadline)
                output, status = self._shell_output(connection, spec.output_limit, deadline)
            self.verify()
            self._deadline(deadline)
            self.runtime.close_connection(connection)
            self._connections.remove(connection)
            return CommandResult(command_id, status, output, spec.mutability)
        except BaseException as error:
            self._abort(error)
            raise

    def platform_transport_identity(self) -> PlatformCaptureTransportIdentity:
        """Return the exact retained identity bound to the static service."""
        if self.state != "ready" or self._mode != "platform_capture":
            raise PrivateAdbError("platform transport is not in dedicated ready mode")
        self.verify()
        assert self._server is not None and self._server.identity is not None
        server = self._server.identity
        assert self._authority is not None
        return PlatformCaptureTransportIdentity(
            PLATFORM_CAPTURE_TRANSPORT_AUTHORITY,
            self.serial,
            self.endpoint,
            server.pid,
            server.creation_time,
            _path(server.image_path),
            hashlib.sha256(self._authority).hexdigest(),
            PLATFORM_CAPTURE_SERVICE_SHA256,
            True,
            True,
            True,
            True,
            False,
        )

    def now_ns(self) -> int:
        """Expose this transport's trusted monotonic clock as nanoseconds."""
        value = self.runtime.now()
        if (type(value) not in (int, float) or
                not math.isfinite(value) or value < 0):
            raise PrivateAdbError("private transport clock is invalid")
        result = int(value * 1_000_000_000)
        if not 0 <= result <= 2**63 - 1:
            raise PrivateAdbError("private transport clock exceeds nanosecond bounds")
        return result

    def capture_platform_wire(self, deadline: float) -> PlatformCaptureTransportResult:
        """Run the one frozen collector service; no command is caller supplied."""
        if not self._operation_lock.acquire(blocking=False):
            raise PrivateAdbError("private ADB operation is concurrent or reentrant")
        try:
            return self._capture_platform_wire_locked(deadline)
        finally:
            self._operation_lock.release()

    def _capture_platform_wire_locked(self,
                                      deadline: float) -> PlatformCaptureTransportResult:
        now = self.runtime.now()
        if (self.state != "ready" or self._mode != "platform_capture" or
                type(deadline) not in (int, float) or
                not now < deadline <= now + MAX_COMMAND_SECONDS):
            raise PrivateAdbError("platform capture deadline/mode is outside authority")
        try:
            before = self.platform_transport_identity()
            started_ns = self.now_ns()
            self._deadline(deadline)
            assert self.port is not None
            connection = self.runtime.connect(self.port, deadline)
            self._connections.append(connection)
            peer = self._admit_connection(connection, deadline)
            self._request(connection, peer, f"host:transport:{self.serial}", deadline)
            self._status(connection, deadline)
            self._request(connection, peer, PLATFORM_CAPTURE_SERVICE, deadline)
            self._status(connection, deadline)
            stdout, stderr, exit_code = self._shell_streams(
                connection,
                stdout_limit=MAX_PLATFORM_CAPTURE_BYTES,
                stderr_limit=MAX_PLATFORM_STDERR_BYTES,
                total_limit=MAX_PLATFORM_CAPTURE_BYTES,
                frame_limit=MAX_PLATFORM_SHELL_FRAMES,
                deadline=deadline,
            )
            captured_ns = self.now_ns()
            if exit_code != 0:
                raise PrivateAdbError("platform collector returned a nonzero exit code")
            if stderr:
                raise PrivateAdbError("platform collector emitted stderr")
            if not stdout:
                raise PrivateAdbError("platform collector returned an empty wire")
            after = self.platform_transport_identity()
            if after != before:
                raise PrivateAdbError("platform transport identity drifted during capture")
            self._deadline(deadline)
            self.runtime.close_connection(connection)
            self._connections.remove(connection)
            finished_ns = self.now_ns()
            self.verify()
            self._deadline(deadline)
            return PlatformCaptureTransportResult(
                stdout, stderr, exit_code, True,
                started_ns, captured_ns, finished_ns, after,
            )
        except BaseException as error:
            self._abort(error)
            raise

    def _deadline(self, deadline: float) -> None:
        if self.runtime.now() >= deadline:
            raise PrivateAdbError("wire command deadline exceeded")

    def _io_check(self, deadline: float) -> None:
        self._deadline(deadline)
        assert self._server is not None
        self._process_verify(self._server, alive=True)
        self._server_drain()

    def _admit_connection(self, connection: Any, deadline: float) -> ConnectionTuple:
        """No send is reachable until the *connected peer* is proven twice."""
        self._io_check(deadline)
        self._bundle_verify()
        peer = self.runtime.connection_tuple(connection)
        if (type(peer) is not ConnectionTuple or peer.local_address != "127.0.0.1" or
                peer.peer_address != "127.0.0.1" or peer.peer_port != self.port or
                type(peer.local_port) is not int or not 1024 <= peer.local_port <= 65535):
            raise PrivateAdbError("connected socket tuple differs from private authority")
        assert self._server is not None and self._server.identity is not None
        expected = PeerOwner(peer, self._server.identity.pid)
        if self.runtime.peer_owner(connection) != expected:
            raise PrivateAdbError("established connection belongs to an unowned peer")
        self._module_verify()
        self._process_verify(self._server, alive=True)
        self._bundle_verify()
        if (self.runtime.connection_tuple(connection) != peer or
                self.runtime.peer_owner(connection) != expected):
            raise PrivateAdbError("established peer changed during admission")
        self._process_verify(self._server, alive=True)
        self._deadline(deadline)
        return peer

    def _request(self, connection: Any, peer: ConnectionTuple,
                 service: str, deadline: float) -> None:
        raw = service.encode("ascii")
        if not 0 < len(raw) <= 4092:
            raise PrivateAdbError("wire service length exceeds bound")
        pending = f"{len(raw):04x}".encode("ascii") + raw
        offset = 0
        while offset < len(pending):
            self._io_check(deadline)
            if self.runtime.connection_tuple(connection) != peer:
                raise PrivateAdbError("established socket changed before request bytes")
            chunk = pending[offset:offset + 4096]
            sent = self.runtime.send(connection, chunk, deadline)
            if sent is None:
                self._pause(deadline)
                continue
            if type(sent) is not int or not 1 <= sent <= len(chunk):
                raise PrivateAdbError("wire send violated bounded progress contract")
            offset += sent
        self._deadline(deadline)

    def _pause(self, deadline: float) -> None:
        self._deadline(deadline)
        self.runtime.sleep(min(POLL_SECONDS, deadline - self.runtime.now()))

    def _read_exact(self, connection: Any, size: int, deadline: float,
                    *, maximum: int = MAX_OUTPUT) -> bytes:
        if (type(maximum) is not int or maximum < 0 or
                type(size) is not int or not 0 <= size <= maximum):
            raise PrivateAdbError("wire read length exceeds bound")
        result = bytearray()
        while len(result) < size:
            self._io_check(deadline)
            limit = min(4096, size - len(result))
            raw = self.runtime.receive(connection, limit, deadline)
            if raw is None:
                self._pause(deadline)
                continue
            if type(raw) is not bytes or len(raw) > limit:
                raise PrivateAdbError("wire receive violated bounded output contract")
            if not raw:
                raise PrivateAdbError("wire EOF before complete response/EXIT")
            result.extend(raw)
        self._deadline(deadline)
        return bytes(result)

    def _hex_length(self, connection: Any, deadline: float) -> int:
        raw = self._read_exact(connection, 4, deadline)
        if re.fullmatch(rb"[0-9a-fA-F]{4}", raw) is None:
            raise PrivateAdbError("wire length prefix is not four hexadecimal digits")
        return int(raw, 16)

    def _status(self, connection: Any, deadline: float) -> None:
        status = self._read_exact(connection, 4, deadline)
        if status == b"OKAY":
            return
        if status == b"FAIL":
            size = self._hex_length(connection, deadline)
            if size > 4096:
                raise PrivateAdbError("wire FAIL response exceeds bound")
            self._read_exact(connection, size, deadline)
            raise PrivateAdbError("private server returned a bounded wire FAIL response")
        raise PrivateAdbError("wire status is neither OKAY nor FAIL")

    def _eof(self, connection: Any, deadline: float) -> None:
        while True:
            self._io_check(deadline)
            raw = self.runtime.receive(connection, 1, deadline)
            if raw is None:
                self._pause(deadline)
                continue
            if type(raw) is not bytes or len(raw) > 1:
                raise PrivateAdbError("wire EOF read violated bounded output contract")
            if raw:
                raise PrivateAdbError("wire response has trailing bytes/frames after completion")
            self._deadline(deadline)
            return

    def _shell_output(self, connection: Any, limit: int, deadline: float) -> tuple[bytes, int]:
        result = bytearray()
        for _ in range(MAX_SHELL_FRAMES):
            header = self._read_exact(connection, 5, deadline)
            stream, size = header[0], int.from_bytes(header[1:], "little")
            if stream in (1, 2):
                if size > limit - len(result):
                    raise PrivateAdbError("aggregate shell output limit exceeded")
                result.extend(self._read_exact(connection, size, deadline))
            elif stream == 3:
                if size != 1:
                    raise PrivateAdbError("shell EXIT must have exactly one byte")
                status = self._read_exact(connection, 1, deadline)[0]
                self._eof(connection, deadline)
                return bytes(result), status
            else:
                raise PrivateAdbError("unexpected shell-v2 stream identifier")
        raise PrivateAdbError("shell-v2 frame count exceeds bound before EXIT")

    def _shell_streams(self, connection: Any, *, stdout_limit: int,
                       stderr_limit: int, total_limit: int, frame_limit: int,
                       deadline: float) -> tuple[bytes, bytes, int]:
        """Parse shell-v2 without merging stdout and stderr.

        EXIT is terminal: the immediately following socket state must be EOF.
        A frame header or body is never allocated/read until its stream-specific
        aggregate limit has admitted it.
        """
        if (type(stdout_limit) is not int or
                not 1 <= stdout_limit <= MAX_PLATFORM_CAPTURE_BYTES or
                type(stderr_limit) is not int or
                not 0 <= stderr_limit <= MAX_PLATFORM_STDERR_BYTES or
                type(total_limit) is not int or
                not 1 <= total_limit <= MAX_PLATFORM_CAPTURE_BYTES or
                stdout_limit > total_limit or stderr_limit > total_limit or
                type(frame_limit) is not int or
                not 1 <= frame_limit <= MAX_PLATFORM_SHELL_FRAMES):
            raise PrivateAdbError("shell-v2 stream bounds are invalid")
        stdout = bytearray()
        stderr = bytearray()
        for _ in range(frame_limit):
            header = self._read_exact(connection, 5, deadline)
            stream, size = header[0], int.from_bytes(header[1:], "little")
            if stream == 1:
                if (size > stdout_limit - len(stdout) or
                        size > total_limit - len(stdout) - len(stderr)):
                    raise PrivateAdbError("platform stdout limit exceeded")
                stdout.extend(self._read_exact(
                    connection, size, deadline, maximum=stdout_limit))
            elif stream == 2:
                if (size > stderr_limit - len(stderr) or
                        size > total_limit - len(stdout) - len(stderr)):
                    raise PrivateAdbError("platform stderr limit exceeded")
                stderr.extend(self._read_exact(
                    connection, size, deadline, maximum=stderr_limit))
            elif stream == 3:
                if size != 1:
                    raise PrivateAdbError("shell EXIT must have exactly one byte")
                status = self._read_exact(connection, 1, deadline)[0]
                self._eof(connection, deadline)
                return bytes(stdout), bytes(stderr), status
            else:
                raise PrivateAdbError("unexpected shell-v2 stream identifier")
        raise PrivateAdbError("shell-v2 frame count exceeds bound before EXIT")

    def _abort(self, cause: BaseException) -> None:
        self.state = "failed"
        try:
            self.close()
        except BaseException as cleanup_error:
            raise PrivateAdbError(
                f"operation rejected: {cause}; cleanup incomplete: {cleanup_error}") from cause

    def close(self) -> None:
        if self.state == "closed":
            return
        self.state = "closing"
        errors: list[str] = []
        obligations: list[CleanupObligation] = []
        for connection in tuple(self._connections):
            try:
                self.runtime.close_connection(connection)
                self._connections.remove(connection)
            except BaseException as error:
                errors.append(str(error))
                obligations.append(CleanupObligation("connection", None, str(error)))
        if self._reservation is not None:
            try:
                self._reservation.release()
                self._reservation = None
            except BaseException as error:
                errors.append(str(error))
                obligations.append(CleanupObligation("reservation", None, str(error)))
        for owned in tuple(reversed(self._owned)):
            try:
                self._bundle_verify()
                self._process_verify(owned)
                identity = owned.identity
                assert identity is not None
                if self.runtime.poll(owned.process) is None:
                    self.runtime.terminate(owned.process, identity)
                    deadline = self.runtime.now() + 2.0
                    while self.runtime.poll(owned.process) is None and self.runtime.now() < deadline:
                        self.runtime.sleep(min(POLL_SECONDS, deadline - self.runtime.now()))
                    if self.runtime.poll(owned.process) is None:
                        raise PrivateAdbError("retained process did not terminate within cleanup bound")
                self._process_verify(owned)
                self._bundle_verify()
                if owned.role == "server" and self.port is not None:
                    if any(item.pid == identity.pid for item in self.runtime.listeners(self.port)):
                        raise PrivateAdbError("terminated server still owns private listener")
                self.runtime.close_process(owned.process, identity)
                self._owned.remove(owned)
            except BaseException as error:
                errors.append(str(error))
                obligations.append(CleanupObligation(owned.role, owned.identity, str(error)))
        self.cleanup_obligations = tuple(obligations)
        self.state = "failed" if errors else "closed"
        if errors:
            raise PrivateAdbError("; ".join(errors))


class _SocketReservation:
    def __init__(self, port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.bind(("127.0.0.1", port))
            self.port = self.socket.getsockname()[1]
        except BaseException:
            self.socket.close()
            raise

    def release(self) -> None:
        self.socket.close()


@dataclass
class _WindowsProcess:
    handle: int
    thread: int
    output: int
    pid: int
    closed: bool = False


class WindowsRuntime:
    """Windows-only adapter using retained kernel handles and bounded pipe reads.

    CreateProcess receives an explicit application, environment and handle list.
    Child-process restriction also prevents the retained server from creating
    unretained children. Commands never invoke an ADB CLI client at all.
    Unsupported Windows security attributes fail closed; there is no fallback.
    """

    def __init__(self) -> None:
        if os.name != "nt":
            raise PrivateAdbError("private ADB production runtime requires Windows")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ip = ctypes.WinDLL("iphlpapi", use_last_error=True)
        self._declare()

    def _declare(self) -> None:
        H, D, P, B = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.BOOL
        signatures = {
            "CloseHandle": ([H], B), "GetProcessId": ([H], D),
            "GetProcessTimes": ([H, P, P, P, P], B),
            "QueryFullProcessImageNameW": ([H, D, wintypes.LPWSTR, P], B),
            "GetWindowsDirectoryW": ([wintypes.LPWSTR, wintypes.UINT], wintypes.UINT),
            "CreatePipe": ([P, P, P, D], B),
            "SetHandleInformation": ([H, D, D], B),
            "CreateFileW": ([wintypes.LPCWSTR, D, D, P, D, D, H], H),
            "InitializeProcThreadAttributeList": ([P, D, D, P], B),
            "UpdateProcThreadAttribute": ([P, D, ctypes.c_size_t, P, ctypes.c_size_t, P, P], B),
            "DeleteProcThreadAttributeList": ([P], None),
            "CreateProcessW": ([wintypes.LPCWSTR, wintypes.LPWSTR, P, P, B, D, P,
                                wintypes.LPCWSTR, P, P], B),
            "ResumeThread": ([H], D), "WaitForSingleObject": ([H, D], D),
            "GetExitCodeProcess": ([H, P], B),
            "PeekNamedPipe": ([H, P, D, P, P, P], B),
            "ReadFile": ([H, P, D, P, P], B),
            "TerminateProcess": ([H, wintypes.UINT], B),
            "CreateToolhelp32Snapshot": ([D, D], H),
            "Module32FirstW": ([H, P], B), "Module32NextW": ([H, P], B),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = args, result
        self.ip.GetExtendedTcpTable.argtypes = [P, P, B, wintypes.ULONG, D, D]
        self.ip.GetExtendedTcpTable.restype = D

    def _check(self, value: object, label: str) -> None:
        if not value:
            raise PrivateAdbError(f"{label} failed with Windows error {ctypes.get_last_error()}")

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(min(seconds, POLL_SECONDS))

    def windows_directory(self) -> str:
        value = ctypes.create_unicode_buffer(32768)
        count = self.k.GetWindowsDirectoryW(value, len(value))
        self._check(0 < count < len(value), "GetWindowsDirectoryW")
        return value.value

    def reserve(self, port: int) -> PortReservation:
        return _SocketReservation(port)

    def _tcp_rows(self, table_class: int) -> tuple[_TcpRow, ...]:
        class Row4(ctypes.Structure):
            _fields_ = [(v, wintypes.DWORD) for v in
                        ("state", "local", "port", "remote", "remote_port", "pid")]

        class Row6(ctypes.Structure):
            _fields_ = [("local", ctypes.c_ubyte * 16), ("scope", wintypes.DWORD),
                        ("port", wintypes.DWORD), ("remote", ctypes.c_ubyte * 16),
                        ("remote_scope", wintypes.DWORD), ("remote_port", wintypes.DWORD),
                        ("state", wintypes.DWORD), ("pid", wintypes.DWORD)]

        found: list[_TcpRow] = []
        for family, row_type in ((socket.AF_INET, Row4), (socket.AF_INET6, Row6)):
            size = wintypes.DWORD()
            result = self.ip.GetExtendedTcpTable(None, ctypes.byref(size), False, family, table_class, 0)
            if result not in (0, 122):
                raise PrivateAdbError(f"listener table sizing failed: {result}")
            for attempt in range(3):
                if not 4 <= size.value <= 8 * 1024 * 1024:
                    raise PrivateAdbError("listener table exceeds admitted bounds")
                buffer = ctypes.create_string_buffer(size.value)
                result = self.ip.GetExtendedTcpTable(buffer, ctypes.byref(size), False, family, table_class, 0)
                if result != 122:
                    break
            if result != 0:
                raise PrivateAdbError(f"listener table read failed: {result}")
            count = wintypes.DWORD.from_buffer_copy(buffer.raw[:4]).value
            stride = ctypes.sizeof(row_type)
            if count > 65536 or 4 + count * stride > len(buffer):
                raise PrivateAdbError("listener table count exceeds capture")
            for index in range(count):
                row = row_type.from_buffer_copy(buffer, 4 + index * stride)
                local_port = socket.ntohs(row.port & 0xffff)
                remote_port = socket.ntohs(row.remote_port & 0xffff)
                address = (socket.inet_ntop(family, int(row.local).to_bytes(4, "little"))
                           if family == socket.AF_INET else socket.inet_ntop(family, bytes(row.local)))
                remote = (socket.inet_ntop(family, int(row.remote).to_bytes(4, "little"))
                          if family == socket.AF_INET else socket.inet_ntop(family, bytes(row.remote)))
                found.append(_TcpRow(address, local_port, remote, remote_port, row.pid, row.state))
        return tuple(found)

    def listeners(self, port: int) -> tuple[Listener, ...]:
        return tuple(sorted((Listener(row.local_address, row.local_port, row.pid)
                             for row in self._tcp_rows(3) if row.local_port == port),
                            key=lambda value: (value.address, value.port, value.pid)))

    def connect(self, port: int, deadline: float) -> socket.socket:
        if type(port) is not int or not 1024 <= port <= 65535 or port == 5037:
            raise PrivateAdbError("invalid private connection port")
        remaining = deadline - self.now()
        if not 0 < remaining <= MAX_COMMAND_SECONDS:
            raise PrivateAdbError("connection deadline is outside admitted bound")
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(remaining)
            # TCP handshake only. No ADB/request bytes precede peer admission.
            connection.connect(("127.0.0.1", port))
            return connection
        except BaseException:
            connection.close()
            raise

    def connection_tuple(self, connection: socket.socket) -> ConnectionTuple:
        if connection.fileno() < 0:
            raise PrivateAdbError("established connection was closed")
        local = connection.getsockname()
        peer = connection.getpeername()
        if len(local) != 2 or len(peer) != 2:
            raise PrivateAdbError("established socket is not the private IPv4 connection")
        return ConnectionTuple(local[0], local[1], peer[0], peer[1])

    def peer_owner(self, connection: socket.socket) -> PeerOwner:
        peer = self.connection_tuple(connection)
        matches = [row for row in self._tcp_rows(4)
                   if (row.local_address, row.local_port, row.remote_address,
                       row.remote_port, row.state) ==
                   (peer.peer_address, peer.peer_port, peer.local_address, peer.local_port, 5)]
        if len(matches) != 1 or matches[0].pid <= 0:
            raise PrivateAdbError("established server-side TCP tuple has no unique owner")
        if self.connection_tuple(connection) != peer:
            raise PrivateAdbError("established connection tuple changed during owner query")
        return PeerOwner(peer, matches[0].pid)

    def _socket_deadline(self, connection: socket.socket, deadline: float) -> None:
        remaining = deadline - self.now()
        if not 0 < remaining <= MAX_COMMAND_SECONDS:
            raise PrivateAdbError("wire socket deadline exceeded")
        connection.settimeout(min(POLL_SECONDS, remaining))

    def send(self, connection: socket.socket, raw: bytes, deadline: float) -> int | None:
        if type(raw) is not bytes or not 1 <= len(raw) <= 4096:
            raise PrivateAdbError("invalid bounded wire send")
        self._socket_deadline(connection, deadline)
        try:
            return connection.send(raw)
        except socket.timeout:
            return None

    def receive(self, connection: socket.socket, limit: int, deadline: float) -> bytes | None:
        if type(limit) is not int or not 1 <= limit <= 4096:
            raise PrivateAdbError("invalid bounded wire receive")
        self._socket_deadline(connection, deadline)
        try:
            return connection.recv(limit)
        except socket.timeout:
            return None

    def close_connection(self, connection: socket.socket) -> None:
        connection.close()

    def spawn_suspended(self, argv: tuple[str, ...], environment: Mapping[str, str],
                        cwd: str) -> _WindowsProcess:
        class Security(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                        ("inherit", wintypes.BOOL)]

        class Startup(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR),
                        ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
                        *[(n, wintypes.DWORD) for n in
                          ("x", "y", "x_size", "y_size", "x_chars", "y_chars", "fill", "flags")],
                        ("show", wintypes.WORD), ("reserved_size", wintypes.WORD),
                        ("reserved_bytes", ctypes.c_void_p), ("stdin", wintypes.HANDLE),
                        ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]

        class StartupEx(ctypes.Structure):
            _fields_ = [("startup", Startup), ("attributes", ctypes.c_void_p)]

        class ProcessInfo(ctypes.Structure):
            _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                        ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]

        security = Security(ctypes.sizeof(Security), None, True)
        read, write = wintypes.HANDLE(), wintypes.HANDLE()
        nul: int | None = None
        attributes = None
        initialized = False
        info = ProcessInfo()
        succeeded = False
        try:
            self._check(self.k.CreatePipe(ctypes.byref(read), ctypes.byref(write),
                                          ctypes.byref(security), 0), "CreatePipe")
            self._check(self.k.SetHandleInformation(read, 1, 0), "SetHandleInformation")
            nul = self.k.CreateFileW("NUL", 0x80000000, 3, ctypes.byref(security), 3, 0, None)
            self._check(nul not in (None, ctypes.c_void_p(-1).value), "open null stdin")
            size = ctypes.c_size_t()
            self.k.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            if not 0 < size.value <= 65536:
                raise PrivateAdbError("process attribute allocation exceeds bound")
            attributes = ctypes.create_string_buffer(size.value)
            self._check(self.k.InitializeProcThreadAttributeList(attributes, 2, 0,
                                                                  ctypes.byref(size)), "initialize attributes")
            initialized = True
            handles = (wintypes.HANDLE * 2)(write.value, nul)
            self._check(self.k.UpdateProcThreadAttribute(attributes, 0, 0x20002, handles,
                         ctypes.sizeof(handles), None, None), "restrict inherited handles")
            no_children = wintypes.DWORD(1)
            self._check(self.k.UpdateProcThreadAttribute(attributes, 0, 0x2000e,
                         ctypes.byref(no_children), ctypes.sizeof(no_children), None, None),
                        "restrict child processes")
            startup = StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x100 | 1  # USESTDHANDLES | USESHOWWINDOW
            startup.startup.show = 0  # SW_HIDE
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = nul, write, write
            startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            env = ctypes.create_unicode_buffer("\x00".join(
                f"{key}={value}" for key, value in sorted(environment.items(), key=lambda item: item[0].upper()))
                + "\x00\x00")
            self._check(self.k.CreateProcessW(argv[0], command, None, None, True,
                         0x4 | 0x8000000 | 0x80000 | 0x400, env, cwd,
                         ctypes.byref(startup), ctypes.byref(info)), "CreateProcessW")
            succeeded = True
            return _WindowsProcess(info.process, info.thread, read.value, info.pid)
        finally:
            if initialized:
                self.k.DeleteProcThreadAttributeList(attributes)
            for handle in (write.value, nul):
                if handle not in (None, ctypes.c_void_p(-1).value):
                    self.k.CloseHandle(handle)
            if not succeeded and read.value:
                self.k.CloseHandle(read)

    def identity(self, process: _WindowsProcess) -> ProcessIdentity:
        if process.closed:
            raise PrivateAdbError("process handle was already closed")
        pid = self.k.GetProcessId(process.handle)
        self._check(pid, "GetProcessId")
        stamps = (ctypes.c_ulonglong * 4)()
        self._check(self.k.GetProcessTimes(process.handle, ctypes.byref(stamps, 0),
                     ctypes.byref(stamps, 8), ctypes.byref(stamps, 16), ctypes.byref(stamps, 24)),
                    "GetProcessTimes")
        image = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(image))
        self._check(self.k.QueryFullProcessImageNameW(process.handle, 0, image,
                                                      ctypes.byref(length)), "QueryFullProcessImageNameW")
        return ProcessIdentity(pid, stamps[0], image.value)

    def modules(self, process: _WindowsProcess) -> tuple[str, ...]:
        class Module(ctypes.Structure):
            _fields_ = [(n, wintypes.DWORD) for n in ("size", "id", "pid", "global_count", "process_count")]
            _fields_ += [("base", ctypes.c_void_p), ("base_size", wintypes.DWORD),
                         ("module", wintypes.HMODULE), ("name", wintypes.WCHAR * 256),
                         ("path", wintypes.WCHAR * 260)]

        before = self.identity(process)
        snapshot = self.k.CreateToolhelp32Snapshot(0x8 | 0x10, before.pid)
        self._check(snapshot not in (None, ctypes.c_void_p(-1).value), "module snapshot")
        try:
            module = Module()
            module.size = ctypes.sizeof(module)
            self._check(self.k.Module32FirstW(snapshot, ctypes.byref(module)), "first process module")
            paths: list[str] = []
            while True:
                if len(paths) >= 4096 or not module.path or len(module.path) >= 259:
                    raise PrivateAdbError("module snapshot exceeds path/count bounds")
                paths.append(module.path)
                if not self.k.Module32NextW(snapshot, ctypes.byref(module)):
                    if ctypes.get_last_error() != 18:
                        raise PrivateAdbError("module snapshot ended unexpectedly")
                    break
            if self.identity(process) != before or self.poll(process) is not None:
                raise PrivateAdbError("process identity changed during module snapshot")
            return tuple(paths)
        finally:
            self.k.CloseHandle(snapshot)

    def resume(self, process: _WindowsProcess) -> None:
        if process.closed or not process.thread:
            raise PrivateAdbError("invalid suspended process lifecycle")
        previous = self.k.ResumeThread(process.thread)
        self._check(previous == 1, "ResumeThread")
        self._check(self.k.CloseHandle(process.thread), "close initial thread")
        process.thread = 0

    def poll(self, process: _WindowsProcess) -> int | None:
        if process.closed:
            raise PrivateAdbError("process handle was already closed")
        result = self.k.WaitForSingleObject(process.handle, 0)
        if result == 258:
            return None
        self._check(result == 0, "poll retained process")
        status = wintypes.DWORD()
        self._check(self.k.GetExitCodeProcess(process.handle, ctypes.byref(status)), "process exit code")
        return status.value

    def read(self, process: _WindowsProcess, limit: int) -> bytes:
        if process.closed or type(limit) is not int or not 1 <= limit <= 4096:
            raise PrivateAdbError("invalid bounded pipe read")
        available = wintypes.DWORD()
        if not self.k.PeekNamedPipe(process.output, None, 0, None, ctypes.byref(available), None):
            if ctypes.get_last_error() == 109:
                return b""
            raise PrivateAdbError("bounded pipe availability failed")
        if not available.value:
            return b""
        count = min(limit, available.value)
        buffer = ctypes.create_string_buffer(count)
        read = wintypes.DWORD()
        self._check(self.k.ReadFile(process.output, buffer, count, ctypes.byref(read), None), "bounded pipe read")
        return buffer.raw[:read.value]

    def terminate(self, process: _WindowsProcess, expected: ProcessIdentity) -> None:
        if self.identity(process) != expected:
            raise PrivateAdbError("exact retained process changed before termination")
        if self.poll(process) is None:
            self._check(self.k.TerminateProcess(process.handle, 137), "terminate retained process")

    def close_process(self, process: _WindowsProcess, expected: ProcessIdentity) -> None:
        if self.identity(process) != expected or self.poll(process) is None:
            raise PrivateAdbError("cannot close an unverified or live process authority")
        for name in ("thread", "output", "handle"):
            handle = getattr(process, name)
            if handle:
                self._check(self.k.CloseHandle(handle), "close retained process resource")
                setattr(process, name, 0)
        process.closed = True
