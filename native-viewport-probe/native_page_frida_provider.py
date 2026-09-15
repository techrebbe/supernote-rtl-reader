"""Fail-closed Frida provider for the frozen native-page graph v2 runner.

This module deliberately has no default Frida import, subprocess launcher, ADB
lookup, or device command.  A caller must provide:

* retained host Python/Frida file authority;
* a reviewed device authority whose authenticated capabilities include the
  mutating private-ADB operations needed to stage and remove one exact server;
* one :class:`native_page_isolated_ipc.IsolatedWorker` constructed inside its
  sole dispatcher thread from a retained ``frida_worker`` image authority.

The current read-only private-ADB implementation cannot satisfy the device
authority contract.  Consequently this is a production-candidate adapter, not
hardware admission.  There is never an ambient adb/frida fallback.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import ntpath
import queue
import re
import threading
import time
from typing import Any, Callable, Mapping, Protocol

import native_page_isolated_ipc as isolated
from native_page_graph_v2_runner import (
    CanonicalAuthority,
    FridaProviderQuiescenceFailure,
    GraphRunnerError,
    OperationStartPermit,
    StageBinding,
    canonical_bytes,
)


HOST_AUTHORITY = "rtl-reader-frida-host-authority-v1"
DEVICE_AUTHORITY = "rtl-reader-frida-device-authority-v1"
ADMISSION_AUTHORITY = "rtl-reader-frida-provider-admission-v1"
STAGE_FRIDA_AUTHORITY = "rtl-reader-frida-lifecycle-authority-v1"
HARDWARE_BLOCK_REASON = "S1B_MUTATING_PRIVATE_ADB_AUTHORITY_UNAVAILABLE"
MAX_SOURCE_BYTES = isolated.MAX_FRAME
MAX_BOOTSTRAP_MS = 10_000
TOKEN = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}\Z")
DEVICE_PATH = re.compile(r"/data/local/tmp/[A-Za-z0-9._/-]{1,220}\Z")
AMBIENT_OVERRIDES = frozenset({
    "ADB_SERVER_SOCKET", "ANDROID_ADB_SERVER_PORT", "ANDROID_SERIAL",
    "ADB_VENDOR_KEYS", "ANDROID_SDK_HOME", "ANDROID_USER_HOME",
    "FRIDA_DEVICE", "FRIDA_HOST", "FRIDA_PORT", "FRIDA_SERVER",
    "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "LD_PRELOAD",
})
DEVICE_CAPABILITIES = (
    "callbackQuiescence",
    "exactChmod",
    "exactHandshake",
    "exactKill",
    "exactPidStartTimeCmdline",
    "exactRootStart",
    "exactUnlink",
    "loadOwnsCallbackLifetime",
    "noAmbientService",
    "noBroadCleanup",
    "privateAdbOnly",
    "retainedProcessIdentity",
    "reviewedStaging",
)
_UNCHANGED = object()
_TERMINAL_STATES = frozenset({"CLOSED", "UNCERTAIN"})


class FridaAuthorityError(GraphRunnerError):
    """An authority or lifecycle result is not exact."""


class FridaLifecycleUncertain(FridaProviderQuiescenceFailure):
    """Exact callback/device/worker quiescence was not established."""


class RetainedAuthority(Protocol):
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...


@dataclass(frozen=True)
class FridaProviderPins:
    provider_implementation_sha256: str
    host_authority_sha256: str
    device_authority_sha256: str
    worker_image_sha256: str
    private_adb_authority_sha256: str

    def validate(self) -> None:
        for value in (
            self.provider_implementation_sha256, self.host_authority_sha256,
            self.device_authority_sha256, self.worker_image_sha256,
            self.private_adb_authority_sha256,
        ):
            if type(value) is not str or HEX.fullmatch(value) is None:
                raise FridaAuthorityError("Frida provider pin is not exact SHA-256")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise FridaAuthorityError(label + " has unknown or missing fields")
    return value


def _text(value: Any, label: str, *, token: bool = False) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise FridaAuthorityError(label + " is not exact text")
    if token and TOKEN.fullmatch(value) is None:
        raise FridaAuthorityError(label + " is not an exact token")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or HEX.fullmatch(value) is None:
        raise FridaAuthorityError(label + " is not lowercase SHA-256")
    return value


def _positive(value: Any, label: str, maximum: int = (1 << 53) - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise FridaAuthorityError(label + " is not a bounded exact integer")
    return value


def _file(value: Any, label: str) -> dict[str, Any]:
    item = _exact(value, {"path", "size", "sha256", "identity", "links",
                          "reparse", "loaded"}, label)
    path = _text(item["path"], label + ".path")
    drive, tail = ntpath.splitdrive(path)
    parts = tuple(part for part in tail.split("\\") if part)
    if (not ntpath.isabs(path) or path.startswith("\\\\") or
            re.fullmatch(r"[A-Za-z]:", drive) is None or
            ntpath.normpath(path) != path or ":" in tail or
            any(part in (".", "..") or part.endswith((" ", ".")) for part in parts)):
        raise FridaAuthorityError(label + " path is not an absolute local file")
    _positive(item["size"], label + ".size")
    _digest(item["sha256"], label + ".sha256")
    _text(item["identity"], label + ".identity", token=True)
    if item["links"] != 1 or item["reparse"] is not False or item["loaded"] is not True:
        raise FridaAuthorityError(label + " is not one retained loaded ordinary file")
    return item


def _authority(authority: RetainedAuthority, expected: str, label: str) -> tuple[bytes, dict[str, Any]]:
    if authority is None:
        raise FridaAuthorityError(label + " retained authority is absent")
    authority.verify()
    raw = authority.canonical_bytes()
    if type(raw) is not bytes or _sha(raw) != expected:
        raise FridaAuthorityError(label + " detached authority digest differs")
    try:
        value = isolated.decode_json(raw)
    except isolated.IpcError as error:
        raise FridaAuthorityError(label + " is not canonical private authority") from error
    authority.verify()
    if authority.canonical_bytes() != raw:
        raise FridaAuthorityError(label + " changed during verification")
    if type(value) is not dict:
        raise FridaAuthorityError(label + " is not an object")
    return raw, value


def _host(value: dict[str, Any]) -> dict[str, Any]:
    item = _exact(value, {"schemaVersion", "authority", "pythonRuntime",
                          "fridaVersion", "protocolVersion", "packageFiles",
                          "nativeExtension", "loadedNativeDependencies",
                          "fridaPackageSha256", "nativeDependenciesSha256",
                          "fixedMinimalEnvironment", "pathResolvedImports"},
                  "host Frida authority")
    if (item["schemaVersion"] != 1 or item["authority"] != HOST_AUTHORITY or
            item["fixedMinimalEnvironment"] is not True or
            item["pathResolvedImports"] is not False):
        raise FridaAuthorityError("host Frida authority policy differs")
    python = _file(item["pythonRuntime"], "host.pythonRuntime")
    _text(item["fridaVersion"], "host.fridaVersion")
    _text(item["protocolVersion"], "host.protocolVersion")
    package = item["packageFiles"]
    dependencies = item["loadedNativeDependencies"]
    if (type(package) is not list or not package or type(dependencies) is not list or
            not dependencies or len(package) > 4096 or len(dependencies) > 256):
        raise FridaAuthorityError("host Frida dependency inventory differs")
    for index, record in enumerate(package):
        _file(record, f"host.packageFiles[{index}]")
    extension = _file(item["nativeExtension"], "host.nativeExtension")
    for index, record in enumerate(dependencies):
        _file(record, f"host.loadedNativeDependencies[{index}]")
    if package != sorted(package, key=lambda record: ntpath.normcase(record["path"])):
        raise FridaAuthorityError("host Frida package inventory order differs")
    if dependencies != sorted(dependencies, key=lambda record: ntpath.normcase(record["path"])):
        raise FridaAuthorityError("host native dependency inventory order differs")
    all_files = [python, *package, extension, *dependencies]
    paths = [ntpath.normcase(ntpath.normpath(record["path"])) for record in all_files]
    identities = [record["identity"] for record in all_files]
    if len(paths) != len(set(paths)) or len(identities) != len(set(identities)):
        raise FridaAuthorityError("host retained file inventory aliases or duplicates")
    if (_digest(item["fridaPackageSha256"], "host.fridaPackageSha256") !=
            _sha(isolated.canonical_json(package))):
        raise FridaAuthorityError("host Frida package aggregate differs")
    native = [extension, *dependencies]
    if (_digest(item["nativeDependenciesSha256"], "host.nativeDependenciesSha256") !=
            _sha(isolated.canonical_json(native))):
        raise FridaAuthorityError("host native dependency aggregate differs")
    return item


def _device(value: dict[str, Any], pins: FridaProviderPins, serial: str,
            provider_session_id: str) -> dict[str, Any]:
    item = _exact(value, {"schemaVersion", "authority", "implementationSha256",
                          "privateAdbAuthoritySha256", "authorizedSerial",
                          "serverPath", "serverSize", "serverSha256",
                          "serverVersion", "protocolVersion", "serverArgv",
                          "reviewState", "capabilities"}, "device Frida authority")
    if (item["schemaVersion"] != 1 or item["authority"] != DEVICE_AUTHORITY or
            item["reviewState"] != "reviewed"):
        raise FridaAuthorityError("device Frida authority is not reviewed")
    _digest(item["implementationSha256"], "device.implementationSha256")
    if (_digest(item["privateAdbAuthoritySha256"], "device.privateAdbAuthoritySha256") !=
            pins.private_adb_authority_sha256 or item["authorizedSerial"] != serial):
        raise FridaAuthorityError("device authority private ADB/serial pin differs")
    path = _text(item["serverPath"], "device.serverPath")
    expected_path = f"/data/local/tmp/rtl-reader-frida/{provider_session_id}/frida-server"
    if DEVICE_PATH.fullmatch(path) is None or path != expected_path:
        raise FridaAuthorityError("temporary Frida server path is not session-bound")
    _positive(item["serverSize"], "device.serverSize")
    _digest(item["serverSha256"], "device.serverSha256")
    _text(item["serverVersion"], "device.serverVersion")
    _text(item["protocolVersion"], "device.protocolVersion")
    argv = item["serverArgv"]
    if (type(argv) is not list or not 2 <= len(argv) <= 16 or argv[0] != path or
            any(type(part) is not str or not part or "\x00" in part or
                any(character.isspace() for character in part) for part in argv)):
        raise FridaAuthorityError("device Frida server argv differs")
    capabilities = _exact(item["capabilities"], set(DEVICE_CAPABILITIES),
                          "device Frida capabilities")
    if any(capabilities[name] is not True for name in DEVICE_CAPABILITIES):
        raise FridaAuthorityError(
            "device Frida authority lacks reviewed mutating private-ADB capability")
    return item


def _server(value: Any, device: dict[str, Any], host: dict[str, Any],
            provider_session_id: str) -> dict[str, Any]:
    item = _exact(value, {"serverSessionId", "path", "size", "sha256", "uid",
                          "pid", "startTimeTicks", "cmdline", "version",
                          "protocol", "state"}, "Frida server result")
    _text(item["serverSessionId"], "server.session", token=True)
    if (item["path"] != device["serverPath"] or item["size"] != device["serverSize"] or
            item["sha256"] != device["serverSha256"] or item["uid"] != 0 or
            item["cmdline"] != " ".join(device["serverArgv"]) or
            item["version"] != device["serverVersion"] or
            item["protocol"] != device["protocolVersion"] or
            item["version"] != host["fridaVersion"] or
            item["protocol"] != host["protocolVersion"] or item["state"] != "ready"):
        raise FridaAuthorityError("Frida client/server identity or handshake differs")
    _positive(item["pid"], "server.pid", 4_194_304)
    if type(item["startTimeTicks"]) is not str or DECIMAL.fullmatch(item["startTimeTicks"]) is None:
        raise FridaAuthorityError("Frida server start time differs")
    if item["serverSessionId"] == provider_session_id:
        raise FridaAuthorityError("provider and device server sessions are not independent")
    return dict(item)


@dataclass
class _Request:
    kind: str
    args: tuple[Any, ...]
    done: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    error: BaseException | None = None


class _WorkerOwner:
    """Sole thread allowed to register and dispatch isolated-worker RPCs."""
    def __init__(self, factory: Callable[[], isolated.IsolatedWorker], session: str,
                 image_sha256: str, bootstrap_timeout_ms: int):
        if not callable(factory) or type(bootstrap_timeout_ms) is not int or not 1 <= bootstrap_timeout_ms <= MAX_BOOTSTRAP_MS:
            raise FridaAuthorityError("isolated worker factory/bootstrap bound differs")
        self._factory = factory
        self._bootstrap_timeout_ms = bootstrap_timeout_ms
        self.session = session
        self.image_sha256 = image_sha256
        self._requests: queue.Queue[_Request] = queue.Queue(maxsize=8)
        self._ready = threading.Event()
        self._candidate_ready = threading.Event()
        self._startup_decision = threading.Event()
        self._startup_done = threading.Event()
        self._startup_accepted = False
        self._worker: isolated.IsolatedWorker | None = None
        self._startup_error: BaseException | None = None
        self._closing = False
        self._closed = False
        self.cleanup_obligations: tuple[str, ...] = ()
        self._thread = threading.Thread(target=self._main, name="native-page-frida-owner", daemon=True)
        self._thread.start()
        candidate_in_time = self._candidate_ready.wait(bootstrap_timeout_ms / 1000)
        self._startup_accepted = candidate_in_time and self._startup_error is None
        self._startup_decision.set()
        # Never return or raise while a delayed factory could still publish a
        # live worker.  A contract-violating factory which never returns keeps
        # construction blocked rather than orphaning an unauthenticated
        # process; the reviewed factory is a non-I/O constructor.
        self._startup_done.wait()
        if not self._startup_accepted:
            self._thread.join()
        if not candidate_in_time:
            if self.cleanup_obligations:
                raise FridaLifecycleUncertain(
                    "isolated Frida worker bootstrap cleanup is uncertain: " +
                    "; ".join(self.cleanup_obligations)) from self._startup_error
            raise FridaAuthorityError("isolated Frida worker bootstrap exceeded caller bound")
        if self._startup_error is not None:
            if self.cleanup_obligations:
                raise FridaLifecycleUncertain(
                    "isolated Frida worker bootstrap cleanup is uncertain: " +
                    "; ".join(self.cleanup_obligations)) from self._startup_error
            raise FridaAuthorityError("isolated Frida worker bootstrap failed") from self._startup_error
        if not self._startup_accepted or not self._ready.is_set():
            raise FridaLifecycleUncertain("isolated Frida worker startup was not atomically admitted")

    def _main(self) -> None:
        worker: isolated.IsolatedWorker | None = None
        try:
            worker = self._factory()
            if type(worker) is not isolated.IsolatedWorker or worker.state != "NEW" or worker.session != self.session:
                raise FridaAuthorityError("factory did not create one fresh exact IsolatedWorker")
            if worker.image.role != "frida_worker":
                raise FridaAuthorityError("isolated worker image role differs")
            worker.image.verify()
            image = worker.image.canonical_bytes()
            if type(image) is not bytes or _sha(image) != self.image_sha256:
                raise FridaAuthorityError("isolated worker image authority differs")
            # Retain the exact worker before its first side effect so a failed
            # bootstrap still has one authenticated cleanup authority.
            self._worker = worker
            worker.start(worker.runtime.now_ns() + self._bootstrap_timeout_ms * 1_000_000)
            worker.image.verify()
            if worker.image.canonical_bytes() != image:
                raise FridaAuthorityError("isolated worker image changed during bootstrap")
        except BaseException as error:
            self._startup_error = error
            if worker is not None:
                try:
                    worker.fail_stop_and_quiesce(self._bootstrap_timeout_ms)
                    worker.assert_quiescent()
                except BaseException as cleanup_error:
                    self.cleanup_obligations = (
                        "bootstrap worker kill/join: " + str(cleanup_error),)
            self._candidate_ready.set()
            self._ready.set()
            self._startup_done.set()
            return
        self._candidate_ready.set()
        self._startup_decision.wait()
        if not self._startup_accepted:
            try:
                worker.fail_stop_and_quiesce(self._bootstrap_timeout_ms)
                worker.assert_quiescent()
            except BaseException as cleanup_error:
                self.cleanup_obligations = (
                    "sealed bootstrap worker kill/join: " + str(cleanup_error),)
            self._startup_error = FridaAuthorityError(
                "isolated worker bootstrap completed after caller deadline")
            self._ready.set()
            self._startup_done.set()
            return
        self._ready.set()
        self._startup_done.set()
        while True:
            request = self._requests.get()
            try:
                if request.kind == "stop":
                    return
                worker = self._worker
                assert worker is not None
                if request.kind == "register":
                    request.result = worker.register_operation(*request.args)
                elif request.kind == "begin":
                    request.result = worker.begin_and_wait(*request.args)
                elif request.kind == "internal":
                    operation_id, operation, payload, deadline_ns = request.args
                    ticket = worker.register_operation(operation_id, operation, payload, deadline_ns)
                    request.result = worker.begin_and_wait(ticket, deadline_ns)
                elif request.kind == "assert":
                    worker.assert_quiescent()
                else:
                    raise FridaAuthorityError("unknown isolated worker owner request")
            except BaseException as error:
                request.error = error
            finally:
                request.done.set()

    def now_ns(self) -> int:
        worker = self._worker
        if worker is None:
            raise FridaLifecycleUncertain("isolated worker clock is unavailable")
        value = worker.runtime.now_ns()
        if type(value) is not int:
            raise FridaLifecycleUncertain("isolated worker clock differs")
        return value

    def _submit(self, kind: str, args: tuple[Any, ...], timeout_ms: int) -> Any:
        if self._closed or self._closing or self._startup_error is not None:
            raise FridaLifecycleUncertain("isolated worker owner is sealed")
        request = _Request(kind, args)
        try:
            self._requests.put_nowait(request)
        except queue.Full as error:
            raise FridaLifecycleUncertain("isolated worker request queue is not bounded/quiescent") from error
        if not request.done.wait(timeout_ms / 1000):
            raise FridaLifecycleUncertain("isolated worker operation exceeded caller bound")
        if request.error is not None:
            if isinstance(request.error, isolated.WorkerQuiescenceError):
                raise FridaLifecycleUncertain("isolated worker quiescence failed") from request.error
            raise FridaAuthorityError("isolated worker operation failed") from request.error
        return request.result

    def register(self, operation_id: str, operation: str, payload: dict[str, Any],
                 deadline_ns: int, timeout_ms: int) -> isolated.OperationTicket:
        return self._submit("register", (operation_id, operation, payload, deadline_ns), timeout_ms)

    def begin(self, ticket: isolated.OperationTicket, deadline_ns: int,
              timeout_ms: int) -> isolated.OperationResult:
        return self._submit("begin", (ticket, deadline_ns), timeout_ms)

    def internal(self, operation_id: str, operation: str, payload: dict[str, Any],
                 deadline_ns: int, timeout_ms: int) -> isolated.OperationResult:
        return self._submit("internal", (operation_id, operation, payload, deadline_ns), timeout_ms)

    def shutdown(self, timeout_ms: int) -> None:
        if self._closed:
            return
        deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        self._closing = True
        errors: list[str] = []
        worker = self._worker
        if worker is not None:
            remaining = max(1, (deadline - time.monotonic_ns() + 999_999) // 1_000_000)
            try:
                worker.fail_stop_and_quiesce(min(timeout_ms, remaining))
            except BaseException as error:
                errors.append("exact isolated worker kill/join: " + str(error))
        try:
            self._requests.put_nowait(_Request("stop", ()))
        except queue.Full:
            errors.append("isolated owner stop queue is blocked")
        remaining_seconds = max(0.0, (deadline - time.monotonic_ns()) / 1_000_000_000)
        self._thread.join(remaining_seconds)
        if self._thread.is_alive():
            errors.append("isolated owner thread did not join")
        if worker is not None:
            try:
                worker.assert_quiescent()
            except BaseException as error:
                errors.append("isolated worker final quiescence: " + str(error))
        self.cleanup_obligations = tuple(errors)
        self._closed = not errors
        if errors:
            raise FridaLifecycleUncertain("; ".join(errors))

    def assert_closed(self) -> None:
        if not self._closed or self._thread.is_alive() or self.cleanup_obligations:
            raise FridaLifecycleUncertain("isolated Frida worker is not exactly closed")


class FridaProvider:
    """Frozen-runner adapter; all Frida/device work is isolated-worker RPC."""
    def __init__(self, *, pins: FridaProviderPins, binding: StageBinding,
                 provider_session_id: str, host_authority: RetainedAuthority,
                 device_authority: RetainedAuthority,
                 worker_factory: Callable[[], isolated.IsolatedWorker],
                 ambient_environment: Mapping[str, str], bootstrap_timeout_ms: int = 1000):
        if type(pins) is not FridaProviderPins or type(binding) is not StageBinding:
            raise FridaAuthorityError("Frida provider pins/stage binding differ")
        pins.validate()
        if type(provider_session_id) is not str or HEX.fullmatch(provider_session_id) is None:
            raise FridaAuthorityError("provider session must be one exact 256-bit token")
        if type(ambient_environment) is not dict or any(type(k) is not str or type(v) is not str
                                                        for k, v in ambient_environment.items()):
            raise FridaAuthorityError("ambient environment contract differs")
        folded = {key.upper() for key in ambient_environment}
        present = sorted(AMBIENT_OVERRIDES & folded)
        if present:
            raise FridaAuthorityError("ambient Frida/ADB routing override is present: " + present[0])
        self.pins = pins
        self.binding = StageBinding(
            serial=binding.serial,
            pid=binding.pid,
            start_time_ticks=binding.start_time_ticks,
            observer_session_id=binding.observer_session_id,
            deadline_ms=binding.deadline_ms,
            absolute_deadline_ns=binding.absolute_deadline_ns,
            stage=binding.stage,
        )
        self.provider_session_id = provider_session_id
        self.host_authority = host_authority
        self.device_authority = device_authority
        self._host_raw, host = _authority(host_authority, pins.host_authority_sha256, "host Frida")
        self._host = _host(host)
        self._device_raw, device = _authority(device_authority, pins.device_authority_sha256,
                                              "device Frida")
        self._device = _device(device, pins, binding.serial, provider_session_id)
        if (self._host["fridaVersion"] != self._device["serverVersion"] or
                self._host["protocolVersion"] != self._device["protocolVersion"]):
            raise FridaAuthorityError("pinned Frida client/server handshake differs")
        self._owner = _WorkerOwner(worker_factory, provider_session_id,
                                   pins.worker_image_sha256, bootstrap_timeout_ms)
        self._operation_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._cleanup_lock = threading.Lock()
        self._counter = 0
        self._state = "NEW"
        self._admission_started = False
        self._server: dict[str, Any] | None = None
        self._server_torn_down = False
        self._sessions: list[FridaSession] = []
        self._cleanup_obligations: list[str] = []
        self._cleanup_measurements: list[tuple[str, int, int]] = []
        self._failure_history: list[str] = []
        self._attempted_operations: set[str] = set()
        self._teardown_requested = False
        # Independent publication arbiter.  It is deliberately not the
        # lifecycle lock: teardown must be able to revoke callback/load
        # publication while a load caller owns lifecycle during a handler.
        self._publication_condition = threading.Condition(threading.Lock())
        self._publication_generation = 0
        self._publication_revoked = False
        self._callbacks_in_flight = 0

    @property
    def cleanup_obligations(self) -> tuple[str, ...]:
        return tuple(self._cleanup_obligations) + self._owner.cleanup_obligations

    @property
    def cleanup_measurements(self) -> tuple[tuple[str, int, int], ...]:
        return tuple(self._cleanup_measurements)

    @property
    def failure_history(self) -> tuple[str, ...]:
        return tuple(self._failure_history)

    def _revalidate(self) -> None:
        raw, value = _authority(self.host_authority, self.pins.host_authority_sha256, "host Frida")
        if raw != self._host_raw or _host(value) != self._host:
            raise FridaAuthorityError("host Frida authority substitution detected")
        raw, value = _authority(self.device_authority, self.pins.device_authority_sha256,
                                "device Frida")
        if (raw != self._device_raw or
                _device(value, self.pins, self.binding.serial, self.provider_session_id) != self._device):
            raise FridaAuthorityError("device Frida authority substitution detected")

    def _timeout(self, timeout_ms: int) -> int:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10_000:
            raise FridaAuthorityError("Frida operation timeout differs")
        return timeout_ms

    def _operation_id(self, label: str) -> str:
        self._counter += 1
        return f"frida.{label}.{self._counter:08d}"

    def _remaining(self, deadline_ns: int, maximum_ms: int) -> int:
        remaining = (deadline_ns - self._owner.now_ns() + 999_999) // 1_000_000
        if remaining <= 0:
            raise FridaLifecycleUncertain("isolated Frida operation exceeded caller deadline")
        return min(maximum_ms, remaining)

    def _wall_remaining(self, deadline_ns: int, maximum_ms: int) -> int:
        remaining = (deadline_ns - time.monotonic_ns() + 999_999) // 1_000_000
        if remaining <= 0:
            raise FridaLifecycleUncertain("Frida operation exceeded total caller budget")
        return min(maximum_ms, remaining)

    def _combined_remaining(self, runtime_deadline_ns: int, wall_deadline_ns: int,
                            maximum_ms: int) -> int:
        return min(self._remaining(runtime_deadline_ns, maximum_ms),
                   self._wall_remaining(wall_deadline_ns, maximum_ms))

    def _acquire_lifecycle(self, wall_deadline_ns: int, label: str,
                           reserve_ms: int = 0) -> None:
        remaining_ns = wall_deadline_ns - time.monotonic_ns() - reserve_ms * 1_000_000
        if remaining_ns <= 0 or not self._lifecycle_lock.acquire(
                timeout=remaining_ns / 1_000_000_000):
            raise FridaLifecycleUncertain(label + " did not acquire lifecycle ownership")

    def _open_publication_generation(self) -> int:
        with self._publication_condition:
            if self._publication_revoked or self._teardown_requested:
                raise FridaLifecycleUncertain(
                    "Frida lifecycle publication generation is revoked")
            return self._publication_generation

    def _transition(self, label: str, *, expected_provider: frozenset[str] | None,
                    provider_state: object = _UNCHANGED,
                    session: "FridaSession | None" = None,
                    expected_session: frozenset[str] | None = None,
                    session_state: object = _UNCHANGED,
                    generation: int | None = None,
                    script_id: object = _UNCHANGED,
                    append_session: bool = False,
                    require_callbacks_quiescent: bool = False,
                    terminal: bool = False) -> None:
        """Atomically validate and publish one lifecycle transition.

        Every state publication following an RPC flows through this arbiter.
        Non-terminal transitions require the still-open generation; terminal
        teardown transitions require revocation and can never overwrite a
        different terminal state.
        """
        if (type(label) is not str or not label or
                (expected_provider is not None and
                 (type(expected_provider) is not frozenset or
                  any(type(item) is not str for item in expected_provider))) or
                type(append_session) is not bool or
                type(require_callbacks_quiescent) is not bool or
                type(terminal) is not bool):
            raise FridaAuthorityError("Frida lifecycle transition contract differs")
        with self._publication_condition:
            current_provider = self._state
            if terminal:
                if (provider_state not in _TERMINAL_STATES or
                        not self._publication_revoked or
                        not self._teardown_requested or
                        session is not None or session_state is not _UNCHANGED or
                        script_id is not _UNCHANGED or append_session or
                        require_callbacks_quiescent):
                    raise FridaAuthorityError(
                        "Frida terminal lifecycle transition differs")
                if (current_provider in _TERMINAL_STATES and
                        current_provider != provider_state):
                    raise FridaLifecycleUncertain(
                        "Frida terminal lifecycle state cannot be overwritten")
                self._state = provider_state
                self._publication_condition.notify_all()
                return
            if (self._publication_revoked or self._teardown_requested or
                    current_provider in _TERMINAL_STATES or
                    (expected_provider is not None and
                     current_provider not in expected_provider) or
                    (generation is not None and
                     (type(generation) is not int or
                      generation != self._publication_generation))):
                raise FridaLifecycleUncertain(
                    label + " publication was fenced by lifecycle teardown")
            if session is None:
                if (expected_session is not None or
                        session_state is not _UNCHANGED or
                        script_id is not _UNCHANGED or append_session):
                    raise FridaAuthorityError(
                        "Frida provider transition contains session mutation")
            else:
                if (expected_session is None or
                        type(expected_session) is not frozenset or
                        any(type(item) is not str for item in expected_session) or
                        session.state not in expected_session):
                    raise FridaLifecycleUncertain(
                        label + " session lifecycle state differs")
                if (require_callbacks_quiescent and
                        (self._callbacks_in_flight != 0 or
                         session._callbacks_sealed)):
                    raise FridaLifecycleUncertain(
                        label + " publication lacks callback quiescence")
                if append_session:
                    if any(item is session for item in self._sessions):
                        raise FridaLifecycleUncertain(
                            "Frida attached session publication is duplicated")
                    self._sessions.append(session)
                if script_id is not _UNCHANGED:
                    if type(script_id) is not str:
                        raise FridaAuthorityError("Frida script transition differs")
                    session.script_id = script_id
                    session._script_cleanup_id = script_id
                if session_state is not _UNCHANGED:
                    if type(session_state) is not str:
                        raise FridaAuthorityError("Frida session state transition differs")
                    session.state = session_state
            if provider_state is not _UNCHANGED:
                if type(provider_state) is not str or provider_state in _TERMINAL_STATES:
                    raise FridaAuthorityError("Frida provider state transition differs")
                self._state = provider_state
            self._publication_condition.notify_all()

    def _mark_failed(self, label: str, error: BaseException) -> None:
        if label not in self._attempted_operations:
            return
        record = f"{label} one-shot operation failed after isolated registration: {type(error).__name__}"
        with self._publication_condition:
            if record not in self._failure_history:
                self._failure_history.append(record)
        # Teardown owns terminal state.  Preserve the one-shot record even
        # when its guarded FAILED transition loses to revocation.
        try:
            self._transition(
                label + " failure", expected_provider=None,
                provider_state="FAILED")
        except FridaLifecycleUncertain:
            pass

    def _revoke_publication(self) -> None:
        """Linearize teardown before any lifecycle wait or worker kill."""
        with self._publication_condition:
            self._teardown_requested = True
            if not self._publication_revoked:
                self._publication_generation += 1
                self._publication_revoked = True
            self._publication_condition.notify_all()

    def _set_terminal_state(self, state: str) -> None:
        if state not in {"CLOSED", "UNCERTAIN"}:
            raise FridaAuthorityError("Frida terminal state differs")
        self._transition(
            "teardown terminal", expected_provider=None,
            provider_state=state, terminal=True)

    def _started(self, permit: OperationStartPermit, label: str, payload: dict[str, Any],
                 timeout_ms: int) -> isolated.OperationResult:
        timeout_ms = self._timeout(timeout_ms)
        if type(permit) is not OperationStartPermit:
            raise FridaAuthorityError("runner operation start permit type differs")
        runtime_deadline_ns = self._owner.now_ns() + timeout_ms * 1_000_000
        wall_deadline_ns = time.monotonic_ns() + timeout_ms * 1_000_000
        if not self._operation_lock.acquire(
                timeout=self._wall_remaining(wall_deadline_ns, timeout_ms) / 1000):
            raise FridaLifecycleUncertain("Frida operation owner did not become available")
        try:
            self._revalidate()
            self._combined_remaining(runtime_deadline_ns, wall_deadline_ns, timeout_ms)
            operation_id = self._operation_id(label)
            ticket = permit.start(lambda: self._owner.register(
                operation_id, "frida_" + label, payload, runtime_deadline_ns,
                self._combined_remaining(runtime_deadline_ns, wall_deadline_ns, timeout_ms)))
            self._attempted_operations.add(label)
            if label == "admission":
                # Registration itself is side-effect free.  Once it has been
                # accepted, however, a lost/malformed begin reply can no
                # longer prove that the device server was never started.
                self._admission_started = True
            result = self._owner.begin(ticket, runtime_deadline_ns,
                                       self._combined_remaining(runtime_deadline_ns,
                                                                wall_deadline_ns, timeout_ms))
            if type(result) is not isolated.OperationResult or result.operation_id != operation_id:
                raise FridaAuthorityError("isolated Frida operation ticket/result differs")
            self._revalidate()
            self._combined_remaining(runtime_deadline_ns, wall_deadline_ns, timeout_ms)
            return result
        finally:
            self._operation_lock.release()

    def _internal(self, label: str, payload: dict[str, Any], timeout_ms: int) -> isolated.OperationResult:
        timeout_ms = self._timeout(timeout_ms)
        runtime_deadline_ns = self._owner.now_ns() + timeout_ms * 1_000_000
        wall_deadline_ns = time.monotonic_ns() + timeout_ms * 1_000_000
        if not self._operation_lock.acquire(
                timeout=self._wall_remaining(wall_deadline_ns, timeout_ms) / 1000):
            raise FridaLifecycleUncertain("Frida cleanup operation owner did not become available")
        try:
            self._revalidate()
            self._combined_remaining(runtime_deadline_ns, wall_deadline_ns, timeout_ms)
            operation_id = self._operation_id(label)
            result = self._owner.internal(operation_id, "frida_" + label, payload,
                                          runtime_deadline_ns,
                                          self._combined_remaining(runtime_deadline_ns,
                                                                   wall_deadline_ns, timeout_ms))
            if type(result) is not isolated.OperationResult or result.operation_id != operation_id:
                raise FridaAuthorityError("isolated Frida cleanup ticket/result differs")
            if result.callbacks:
                raise FridaLifecycleUncertain("callback arrived during/after lifecycle seal")
            self._revalidate()
            self._combined_remaining(runtime_deadline_ns, wall_deadline_ns, timeout_ms)
            return result
        finally:
            self._operation_lock.release()

    def preview_admission(self) -> CanonicalAuthority:
        value = {
            "schemaVersion": 1, "authority": ADMISSION_AUTHORITY,
            "implementationSha256": self.pins.provider_implementation_sha256,
            "providerSessionId": self.provider_session_id,
            "isolatedCancellableLifecycle": True, "callbackQuiescenceBarrier": True,
            "singleAttach": True, "singleLoad": True, "exactTeardown": True,
            "teardownReturnsOnlyAfterKillJoin": True,
            "callbackChannelSealedBeforeReturn": True, "atomicStartPermit": True,
            "noRetry": True,
        }
        raw = canonical_bytes(value)
        return CanonicalAuthority(raw, _sha(raw))

    def admission(self, timeout_ms: int, start_permit: OperationStartPermit) -> CanonicalAuthority:
        timeout_ms = self._timeout(timeout_ms)
        wall_deadline_ns = time.monotonic_ns() + timeout_ms * 1_000_000
        self._acquire_lifecycle(wall_deadline_ns, "Frida admission")
        try:
            if self._state != "NEW":
                raise FridaAuthorityError("Frida provider admission is single-use")
            publication_generation = self._open_publication_generation()
            payload = {
                "providerSessionId": self.provider_session_id,
                "hostAuthoritySha256": self.pins.host_authority_sha256,
                "deviceAuthoritySha256": self.pins.device_authority_sha256,
                "workerImageSha256": self.pins.worker_image_sha256,
                "privateAdbAuthoritySha256": self.pins.private_adb_authority_sha256,
            }
            try:
                result = self._started(
                    start_permit, "admission", payload,
                    self._wall_remaining(wall_deadline_ns, timeout_ms))
                if result.callbacks:
                    raise FridaAuthorityError("Frida admission emitted callbacks")
                item = _exact(result.value, {"state", *payload.keys(), "clientVersion",
                                             "protocolVersion", "server"},
                              "Frida admission result")
                if (item["state"] != "ready" or
                        any(item[name] != payload[name] for name in payload) or
                        item["clientVersion"] != self._host["fridaVersion"] or
                        item["protocolVersion"] != self._host["protocolVersion"]):
                    raise FridaAuthorityError("Frida admission binding differs")
                self._server = _server(item["server"], self._device, self._host,
                                       self.provider_session_id)
                self._wall_remaining(wall_deadline_ns, timeout_ms)
                self._transition(
                    "admission", expected_provider=frozenset({"NEW"}),
                    provider_state="READY", generation=publication_generation)
                return self.preview_admission()
            except BaseException as error:
                self._mark_failed("admission", error)
                raise
        finally:
            self._lifecycle_lock.release()

    def attach(self, serial: str, pid: int, timeout_ms: int,
               start_permit: OperationStartPermit) -> "FridaSession":
        timeout_ms = self._timeout(timeout_ms)
        wall_deadline_ns = time.monotonic_ns() + timeout_ms * 1_000_000
        self._acquire_lifecycle(wall_deadline_ns, "Frida attach")
        try:
            if self._state != "READY" or serial != self.binding.serial or pid != self.binding.pid:
                raise FridaAuthorityError("Frida attach target differs or lifecycle is not ready")
            publication_generation = self._open_publication_generation()
            assert self._server is not None
            payload = {"providerSessionId": self.provider_session_id,
                       "serverSessionId": self._server["serverSessionId"],
                       "serial": serial, "pid": pid,
                       "targetStartTimeTicks": self.binding.start_time_ticks}
            try:
                result = self._started(
                    start_permit, "attach", payload,
                    self._wall_remaining(wall_deadline_ns, timeout_ms))
                if result.callbacks:
                    raise FridaAuthorityError("Frida attach emitted callbacks")
                item = _exact(result.value, {"state", "sessionId", *payload.keys()},
                              "Frida attach result")
                if (item["state"] != "attached" or
                        any(item[name] != payload[name] for name in payload)):
                    raise FridaAuthorityError("Frida attach result differs")
                attached_session_id = _text(
                    item["sessionId"], "Frida attached session", token=True)
                if attached_session_id in (
                        self.provider_session_id, self._server["serverSessionId"]):
                    raise FridaAuthorityError("Frida attached session is not independent")
                self._wall_remaining(wall_deadline_ns, timeout_ms)
                session = FridaSession(self, attached_session_id)
                self._transition(
                    "attach", expected_provider=frozenset({"READY"}),
                    provider_state="ATTACHED", session=session,
                    expected_session=frozenset({"ATTACHED"}),
                    append_session=True, generation=publication_generation)
                return session
            except BaseException as error:
                self._mark_failed("attach", error)
                raise
        finally:
            self._lifecycle_lock.release()

    def _teardown_result(self, value: Any) -> None:
        assert self._server is not None
        expected = {
            "state": "torn-down", "providerSessionId": self.provider_session_id,
            "serverSessionId": self._server["serverSessionId"],
            "serverPath": self._server["path"], "serverPid": self._server["pid"],
            "serverStartTimeTicks": self._server["startTimeTicks"],
            "processAbsent": True, "fileAbsent": True,
            "teardownOfSessionId": self._server["serverSessionId"],
        }
        if (type(value) is not dict or set(value) != set(expected) or
                type(value.get("processAbsent")) is not bool or
                type(value.get("fileAbsent")) is not bool or value != expected):
            raise FridaLifecycleUncertain("exact temporary Frida server teardown differs")
        self._server_torn_down = True

    def teardown(self, timeout_ms: int) -> None:
        timeout_ms = self._timeout(timeout_ms)
        started = time.monotonic_ns()
        deadline = started + timeout_ms * 1_000_000
        # This is the first lock acquired by teardown.  Revocation and epoch
        # advancement are one critical section, before cleanup/lifecycle wait
        # or worker kill.  Callback admission and LOADED commit use this same
        # arbiter, so exactly one side can win.
        self._revoke_publication()
        cleanup_wait = max(0.0, (deadline - time.monotonic_ns()) / 1_000_000_000)
        if not self._cleanup_lock.acquire(timeout=cleanup_wait):
            obligation = "concurrent Frida teardown did not settle"
            if obligation not in self._cleanup_obligations:
                self._cleanup_obligations.append(obligation)
            self._set_terminal_state("UNCERTAIN")
            raise FridaLifecycleUncertain("concurrent Frida teardown did not settle")
        errors: list[str] = []
        lifecycle_owned = False
        try:
            if self._state == "CLOSED" and not self.cleanup_obligations:
                return
            reserve_ms = max(1, min(20, timeout_ms - 1))
            try:
                self._acquire_lifecycle(deadline, "Frida teardown", reserve_ms)
                lifecycle_owned = True
            except BaseException as error:
                errors.append("in-flight lifecycle publication: " + str(error))
                with self._publication_condition:
                    callbacks_in_flight = self._callbacks_in_flight
                if callbacks_in_flight:
                    errors.append(
                        f"in-flight callback publication: {callbacks_in_flight} callback(s)")
                self._set_terminal_state("UNCERTAIN")
            if lifecycle_owned:
                with self._publication_condition:
                    if self._callbacks_in_flight:
                        errors.append(
                            "callback publication remained in flight after lifecycle ownership")
                for session in self._sessions:
                    remaining = max(0, (deadline - time.monotonic_ns() + 999_999) // 1_000_000)
                    if not remaining:
                        errors.append("local callback seal: cleanup budget expired")
                        break
                    try:
                        session._seal_local(min(timeout_ms, remaining))
                    except BaseException as error:
                        errors.append("local callback seal: " + str(error))
                if self._server is not None and not self._server_torn_down:
                    remaining = max(0, (deadline - time.monotonic_ns() + 999_999) // 1_000_000)
                    if remaining:
                        try:
                            result = self._internal("teardown", {
                                "providerSessionId": self.provider_session_id,
                                "serverSessionId": self._server["serverSessionId"],
                                "serverPath": self._server["path"],
                                "serverPid": self._server["pid"],
                                "serverStartTimeTicks": self._server["startTimeTicks"],
                            }, min(timeout_ms, remaining))
                            self._teardown_result(result.value)
                        except BaseException as error:
                            errors.append("exact device server kill/unlink: " + str(error))
                    else:
                        errors.append("exact device server kill/unlink: cleanup budget expired")
                elif self._admission_started and self._server is None:
                    errors.append("device server may have started without authenticated identity")
            elif self._server is not None and not self._server_torn_down:
                errors.append(
                    "exact device server teardown skipped while lifecycle publication is in flight")
            elif self._admission_started and self._server is None:
                errors.append("device server may have started without authenticated identity")
            remaining = max(0, (deadline - time.monotonic_ns() + 999_999) // 1_000_000)
            if remaining:
                try:
                    self._owner.shutdown(min(timeout_ms, remaining))
                except BaseException as error:
                    errors.append("exact host worker kill/join: " + str(error))
            else:
                errors.append("exact host worker kill/join: cleanup budget expired")
            if errors:
                self._cleanup_obligations.extend(error for error in errors
                                                 if error not in self._cleanup_obligations)
                self._set_terminal_state("UNCERTAIN")
                raise FridaLifecycleUncertain("; ".join(errors))
            self._set_terminal_state("CLOSED")
        finally:
            if lifecycle_owned:
                self._lifecycle_lock.release()
            elapsed = time.monotonic_ns() - started
            self._cleanup_measurements.append(("teardown", timeout_ms, elapsed))
            self._cleanup_lock.release()

    def assert_quiescent(self, timeout_ms: int) -> None:
        timeout_ms = self._timeout(timeout_ms)
        started = time.monotonic_ns()
        try:
            if (self._state != "CLOSED" or self.cleanup_obligations or
                    (self._server is not None and not self._server_torn_down)):
                raise FridaLifecycleUncertain("Frida provider has unresolved cleanup authority")
            self._owner.assert_closed()
        finally:
            self._cleanup_measurements.append(
                ("assert_quiescent", timeout_ms, time.monotonic_ns() - started))

    def stage_frida_record(self, phase: str) -> dict[str, Any]:
        if phase not in ("before", "after") or self._server is None:
            raise FridaAuthorityError("Frida evidence phase/server differs")
        self._revalidate()
        if phase == "before":
            if self._state not in ("READY", "ATTACHED") or self._server_torn_down:
                raise FridaAuthorityError("ready Frida evidence is unavailable")
            state, absent, teardown = "ready", False, None
        else:
            if self._state != "CLOSED" or not self._server_torn_down or self.cleanup_obligations:
                raise FridaLifecycleUncertain("torn-down Frida evidence is unavailable")
            state, absent, teardown = "torn-down", True, self._server["serverSessionId"]
        return {
            "authority": STAGE_FRIDA_AUTHORITY,
            "providerSessionId": self.provider_session_id,
            "hostPythonPath": self._host["pythonRuntime"]["path"],
            "hostPythonSha256": self._host["pythonRuntime"]["sha256"],
            "hostFridaVersion": self._host["fridaVersion"],
            "hostFridaPackageSha256": self._host["fridaPackageSha256"],
            "hostNativeDependenciesSha256": self._host["nativeDependenciesSha256"],
            "serverPath": self._server["path"], "serverSha256": self._server["sha256"],
            "serverUid": self._server["uid"], "serverPid": self._server["pid"],
            "serverStartTimeTicks": self._server["startTimeTicks"],
            "serverCmdline": self._server["cmdline"], "serverVersion": self._server["version"],
            "serverSessionId": self._server["serverSessionId"], "serverState": state,
            "exactTeardownRequired": True, "processAbsent": absent, "fileAbsent": absent,
            "teardownOfSessionId": teardown,
        }


class FridaSession:
    def __init__(self, provider: FridaProvider, session_id: str):
        self.provider = provider
        self.session_id = session_id
        self.state = "ATTACHED"
        self.script_id: str | None = None
        self._script_cleanup_id: str | None = None
        self._callbacks_sealed = False
        self._callback_lock = threading.Lock()

    def _seal_local(self, timeout_ms: int) -> None:
        timeout_ms = self.provider._timeout(timeout_ms)
        if not self._callback_lock.acquire(timeout=timeout_ms / 1000):
            raise FridaLifecycleUncertain(
                "in-flight Frida callback did not settle before callback seal")
        try:
            self._callbacks_sealed = True
        finally:
            self._callback_lock.release()

    def _capture_publication_generation(self) -> int:
        with self.provider._publication_condition:
            if (self.provider._publication_revoked or
                    self.provider._teardown_requested or
                    self.provider._state != "ATTACHED" or
                    self.state != "ATTACHED" or self._callbacks_sealed):
                raise FridaLifecycleUncertain(
                    "Frida load began after callback publication fence")
            return self.provider._publication_generation

    def _begin_callback(self, generation: int) -> None:
        """Atomically admit one callback against teardown revocation."""
        with self.provider._publication_condition:
            if (type(generation) is not int or
                    self.provider._publication_generation != generation or
                    self.provider._publication_revoked or
                    self.provider._teardown_requested or
                    self.provider._state != "ATTACHED" or
                    self.state != "ATTACHED" or self._callbacks_sealed):
                raise FridaLifecycleUncertain(
                    "Frida callback publication was fenced by lifecycle teardown")
            self.provider._callbacks_in_flight += 1

    def _end_callback(self, generation: int) -> bool:
        """Release one admitted callback and report whether load may continue."""
        with self.provider._publication_condition:
            if self.provider._callbacks_in_flight <= 0:
                raise FridaLifecycleUncertain(
                    "Frida callback in-flight accounting differs")
            self.provider._callbacks_in_flight -= 1
            still_authorized = (
                self.provider._publication_generation == generation and
                not self.provider._publication_revoked and
                not self.provider._teardown_requested and
                self.provider._state == "ATTACHED" and
                self.state == "ATTACHED" and not self._callbacks_sealed)
            self.provider._publication_condition.notify_all()
            return still_authorized

    def _commit_loaded(self, generation: int, script_id: str) -> None:
        """Check and publish the terminal load state as one arbitration step."""
        self.provider._transition(
            "load", expected_provider=frozenset({"ATTACHED"}),
            provider_state="LOADED", session=self,
            expected_session=frozenset({"ATTACHED"}),
            session_state="LOADED", generation=generation,
            script_id=script_id, require_callbacks_quiescent=True)

    def load(self, source: str, on_message: Callable[[Any, Any], None], timeout_ms: int,
             start_permit: OperationStartPermit) -> None:
        """Load and hold the worker RPC through terminal callback quiescence.

        The reviewed worker implementation must not acknowledge this operation
        merely when ``script.load()`` returns.  It owns the Frida callback
        channel until the observer emits its terminal record, seals that
        channel, and returns every callback in this one bounded result.  Thus
        the runner may receive callbacks synchronously here, while no callback
        can outlive the load operation and race its later cleanup seal.
        """
        if not callable(on_message) or type(source) is not str:
            raise FridaAuthorityError("Frida load lifecycle/source/callback differs")
        timeout_ms = self.provider._timeout(timeout_ms)
        wall_deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        callback_deadline = self.provider._owner.now_ns() + timeout_ms * 1_000_000
        try:
            source_raw = source.encode("utf-8", "strict")
        except UnicodeError as error:
            raise FridaAuthorityError("Frida source is not strict UTF-8") from error
        if not 0 < len(source_raw) <= MAX_SOURCE_BYTES:
            raise FridaAuthorityError("Frida source exceeds reviewed bound")
        source_sha256 = _sha(source_raw)
        self.provider._acquire_lifecycle(wall_deadline, "Frida load")
        try:
            if (self.state != "ATTACHED" or self.provider._state != "ATTACHED" or
                    self.provider._server is None or self.provider._server_torn_down or
                    self.provider._teardown_requested):
                raise FridaAuthorityError("Frida load lifecycle/source/callback differs")
            publication_generation = self._capture_publication_generation()
            payload = {"providerSessionId": self.provider.provider_session_id,
                       "serverSessionId": self.provider._server["serverSessionId"],
                       "sessionId": self.session_id, "source": source,
                       "sourceSha256": source_sha256}
            try:
                isolated.canonical_json(payload)
            except isolated.IpcError as error:
                raise FridaAuthorityError(
                    "Frida source cannot fit one canonical private IPC frame") from error
            try:
                result = self.provider._started(
                    start_permit, "load", payload,
                    self.provider._wall_remaining(wall_deadline, timeout_ms))
                item = _exact(result.value, {"state", "providerSessionId", "sessionId",
                                             "serverSessionId", "scriptId", "sourceSha256"},
                              "Frida load result")
                if (item["state"] != "loaded" or
                        item["providerSessionId"] != self.provider.provider_session_id or
                        item["serverSessionId"] != self.provider._server["serverSessionId"] or
                        item["sessionId"] != self.session_id or
                        item["sourceSha256"] != source_sha256):
                    raise FridaAuthorityError("Frida load result differs")
                script_id = _text(item["scriptId"], "Frida script ID", token=True)
                # Retain authenticated cleanup authority as soon as the
                # worker proves it.  This is not LOADED publication: the
                # public script/state remain unset until the atomic terminal
                # commit, while a later callback failure can still unload the
                # exact script rather than resorting to broad cleanup.
                self._script_cleanup_id = script_id
                for callback in result.callbacks:
                    with self._callback_lock:
                        if (self.provider._owner.now_ns() >= callback_deadline or
                                time.monotonic_ns() >= wall_deadline):
                            raise FridaLifecycleUncertain(
                                "Frida callback delivery exceeded load deadline")
                        record = _exact(callback, {"message", "dataBase64"}, "Frida callback")
                        if self._callbacks_sealed:
                            raise FridaLifecycleUncertain(
                                "Frida callback arrived after callback seal")
                        data_wire = record["dataBase64"]
                        if data_wire is None:
                            data = None
                        elif type(data_wire) is str:
                            try:
                                data = base64.b64decode(data_wire, validate=True)
                            except (ValueError, binascii.Error) as error:
                                raise FridaAuthorityError(
                                    "Frida callback binary frame differs") from error
                            if base64.b64encode(data).decode("ascii") != data_wire:
                                raise FridaAuthorityError(
                                    "Frida callback base64 is not canonical")
                        else:
                            raise FridaAuthorityError("Frida callback data type differs")
                        # Decode is side-effect free.  Callback start is then
                        # admitted under the same arbiter used by teardown;
                        # there is no check-then-call publication gap.
                        self._begin_callback(publication_generation)
                        try:
                            on_message(record["message"], data)
                        finally:
                            still_authorized = self._end_callback(
                                publication_generation)
                        if not still_authorized:
                            raise FridaLifecycleUncertain(
                                "Frida callback completed after lifecycle teardown")
                        if (self.provider._owner.now_ns() >= callback_deadline or
                                time.monotonic_ns() >= wall_deadline):
                            raise FridaLifecycleUncertain(
                                "Frida callback handler exceeded load deadline")
                self.provider._wall_remaining(wall_deadline, timeout_ms)
                self._commit_loaded(publication_generation, script_id)
            except BaseException as error:
                self.provider._mark_failed("load", error)
                raise
        finally:
            self.provider._lifecycle_lock.release()

    def _cleanup_locked(self, label: str, expected: str, timeout_ms: int) -> None:
        if self.provider._server is None:
            raise FridaLifecycleUncertain("Frida session lost exact server authority")
        payload = {"providerSessionId": self.provider.provider_session_id,
                   "sessionId": self.session_id,
                   "scriptId": self._script_cleanup_id,
                   "serverSessionId": self.provider._server["serverSessionId"]}
        result = self.provider._internal(label, payload, timeout_ms)
        wanted = {"state": expected, **payload}
        if result.value != wanted:
            raise FridaLifecycleUncertain("Frida " + label + " acknowledgement differs")

    def seal_callbacks(self, timeout_ms: int) -> None:
        timeout_ms = self.provider._timeout(timeout_ms)
        deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        self.provider._acquire_lifecycle(deadline, "Frida callback seal")
        try:
            if self._callbacks_sealed and self.state in ("SEALED", "UNLOADED", "DETACHED"):
                return
            if self.provider._teardown_requested:
                raise FridaLifecycleUncertain("Frida callback seal began after provider teardown")
            publication_generation = self.provider._open_publication_generation()
            self._seal_local(self.provider._wall_remaining(deadline, timeout_ms))
            self._cleanup_locked(
                "seal", "callbacks-sealed",
                self.provider._wall_remaining(deadline, timeout_ms))
            self.provider._transition(
                "seal", expected_provider=frozenset({"ATTACHED", "FAILED", "LOADED"}),
                session=self, expected_session=frozenset({"ATTACHED", "LOADED"}),
                session_state="SEALED", generation=publication_generation)
        finally:
            self.provider._lifecycle_lock.release()

    def unload(self, timeout_ms: int) -> None:
        timeout_ms = self.provider._timeout(timeout_ms)
        deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        self.provider._acquire_lifecycle(deadline, "Frida unload")
        try:
            if self.state == "UNLOADED" or self.state == "DETACHED":
                return
            if self.state != "SEALED" or self.provider._teardown_requested:
                raise FridaLifecycleUncertain("Frida unload requires callback seal")
            publication_generation = self.provider._open_publication_generation()
            self._cleanup_locked(
                "unload", "unloaded", self.provider._wall_remaining(deadline, timeout_ms))
            self.provider._transition(
                "unload", expected_provider=frozenset({"ATTACHED", "FAILED", "LOADED"}),
                session=self, expected_session=frozenset({"SEALED"}),
                session_state="UNLOADED", generation=publication_generation)
        finally:
            self.provider._lifecycle_lock.release()

    def detach(self, timeout_ms: int) -> None:
        timeout_ms = self.provider._timeout(timeout_ms)
        deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        self.provider._acquire_lifecycle(deadline, "Frida detach")
        try:
            if self.state == "DETACHED":
                return
            if self.state != "UNLOADED" or self.provider._teardown_requested:
                raise FridaLifecycleUncertain("Frida detach requires exact unload")
            publication_generation = self.provider._open_publication_generation()
            self._cleanup_locked(
                "detach", "detached", self.provider._wall_remaining(deadline, timeout_ms))
            self.provider._transition(
                "detach", expected_provider=frozenset({"ATTACHED", "FAILED", "LOADED"}),
                provider_state="DETACHED", session=self,
                expected_session=frozenset({"UNLOADED"}),
                session_state="DETACHED", generation=publication_generation)
        finally:
            self.provider._lifecycle_lock.release()

    def assert_quiescent(self, timeout_ms: int) -> None:
        timeout_ms = self.provider._timeout(timeout_ms)
        deadline = time.monotonic_ns() + timeout_ms * 1_000_000
        self.provider._acquire_lifecycle(deadline, "Frida session quiescence")
        try:
            if not self._callback_lock.acquire(
                    timeout=self.provider._wall_remaining(deadline, timeout_ms) / 1000):
                raise FridaLifecycleUncertain("Frida callback delivery remains in flight")
            try:
                if self.state != "DETACHED" or not self._callbacks_sealed:
                    raise FridaLifecycleUncertain(
                        "Frida session is not detached/callback-sealed")
            finally:
                self._callback_lock.release()
        finally:
            self.provider._lifecycle_lock.release()
