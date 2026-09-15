"""Executable fake-authority tests for the S6 Frida provider boundary.

No test imports Frida, launches adb, uses a device, or opens a network socket.
The real frozen IsolatedWorker and OperationStartPermit state machines run over
retained fake handles so lifecycle/framing failures exercise production code.
"""
from __future__ import annotations

import copy
import hashlib
import sys
import threading
import time
import unittest

import native_page_frida_provider as provider_module
import native_page_graph_v2_runner as runner
import native_page_isolated_ipc as ipc
import test_native_page_isolated_ipc as ipc_fakes


PROVIDER_SESSION = "1" * 64
SERVER_SESSION = "2" * 64
SERIAL = "SN078C10015092"
PID = 2468
START_TICKS = "987654321"
FRIDA_VERSION = "17.2.17"
PROTOCOL_VERSION = "frida-core-v17"
PRIVATE_ADB_SHA256 = "3" * 64
IMPLEMENTATION_SHA256 = "4" * 64


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Authority:
    def __init__(self, value: dict):
        self.raw = ipc.canonical_json(value)
        self.failed = False
        self.verify_count = 0

    def verify(self) -> None:
        self.verify_count += 1
        if self.failed:
            raise provider_module.FridaAuthorityError("retained authority failed")

    def canonical_bytes(self) -> bytes:
        self.verify()
        return self.raw


def file_record(name: str, identity: str) -> dict:
    payload = (name + " retained bytes").encode()
    return {
        "path": "C:\\RetainedFrida\\" + name,
        "size": len(payload),
        "sha256": digest(payload),
        "identity": identity,
        "links": 1,
        "reparse": False,
        "loaded": True,
    }


def host_value() -> dict:
    python = file_record("python.exe", "python-runtime-0001")
    package = [
        file_record("frida\\__init__.py", "frida-package-0001"),
        file_record("frida\\core.py", "frida-package-0002"),
    ]
    extension = file_record("_frida.pyd", "frida-extension-01")
    dependencies = [
        file_record("frida-core.dll", "native-dependency-1"),
        file_record("libglib-2.0.dll", "native-dependency-2"),
    ]
    package.sort(key=lambda record: record["path"].lower())
    dependencies.sort(key=lambda record: record["path"].lower())
    return {
        "schemaVersion": 1,
        "authority": provider_module.HOST_AUTHORITY,
        "pythonRuntime": python,
        "fridaVersion": FRIDA_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "packageFiles": package,
        "nativeExtension": extension,
        "loadedNativeDependencies": dependencies,
        "fridaPackageSha256": digest(ipc.canonical_json(package)),
        "nativeDependenciesSha256": digest(ipc.canonical_json([extension, *dependencies])),
        "fixedMinimalEnvironment": True,
        "pathResolvedImports": False,
    }


def device_value() -> dict:
    path = f"/data/local/tmp/rtl-reader-frida/{PROVIDER_SESSION}/frida-server"
    server = b"reviewed temporary frida-server bytes"
    return {
        "schemaVersion": 1,
        "authority": provider_module.DEVICE_AUTHORITY,
        "implementationSha256": "5" * 64,
        "privateAdbAuthoritySha256": PRIVATE_ADB_SHA256,
        "authorizedSerial": SERIAL,
        "serverPath": path,
        "serverSize": len(server),
        "serverSha256": digest(server),
        "serverVersion": FRIDA_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "serverArgv": [path, "--listen", "127.0.0.1:27042"],
        "reviewState": "reviewed",
        "capabilities": {name: True for name in provider_module.DEVICE_CAPABILITIES},
    }


class FridaRuntime(ipc_fakes.FakeRuntime):
    ALLOWED = frozenset({
        "frida_admission", "frida_attach", "frida_load", "frida_seal",
        "frida_unload", "frida_detach", "frida_teardown",
    })

    def __init__(self, device: dict):
        super().__init__()
        self.device = device
        self.result_mutators: dict[str, object] = {}
        self.callback_values: dict[str, list[dict]] = {}
        self.hang_operations: set[str] = set()
        self.raise_operations: set[str] = set()
        self.dispatched: list[tuple[str, dict]] = []
        self.deadline_budgets_ms: list[tuple[str, int]] = []

    def launch_suspended(self, image, session):
        identity = self.worker_identity_override or self._identity(image, 900)
        self.worker = ipc_fakes.Process(identity)
        self.processes.append(self.worker)
        registry = ipc.WorkerRegistry(
            session, image.role, self.ALLOWED, self.now_ns,
            self.verify_operation_quiescent)
        self.channel = ipc_fakes.Channel(registry)
        if self.on_launch:
            self.on_launch(self)
        return ipc.WorkerLaunch(self.worker, self.channel)

    def _operation(self, operation_id: str) -> tuple[str, dict]:
        record = self.channel.registry.operations[operation_id]
        return record["operation"], record["payload"]

    def read_reply(self, stream, limit, deadline_ns):
        if self.pending is not None:
            operation, _ = self._operation(self.pending)
            if operation in self.hang_operations and not stream.output:
                return None
        return super().read_reply(stream, limit, deadline_ns)

    def _server(self) -> dict:
        return {
            "serverSessionId": SERVER_SESSION,
            "path": self.device["serverPath"],
            "size": self.device["serverSize"],
            "sha256": self.device["serverSha256"],
            "uid": 0,
            "pid": 4242,
            "startTimeTicks": "123456789",
            "cmdline": " ".join(self.device["serverArgv"]),
            "version": self.device["serverVersion"],
            "protocol": self.device["protocolVersion"],
            "state": "ready",
        }

    def _result(self, operation: str, payload: dict) -> dict:
        if operation == "frida_admission":
            return {
                "state": "ready", **payload,
                "clientVersion": FRIDA_VERSION,
                "protocolVersion": PROTOCOL_VERSION,
                "server": self._server(),
            }
        if operation == "frida_attach":
            return {"state": "attached", "sessionId": "attached-session-1", **payload}
        if operation == "frida_load":
            return {
                "state": "loaded", "providerSessionId": payload["providerSessionId"],
                "serverSessionId": payload["serverSessionId"],
                "sessionId": payload["sessionId"], "scriptId": "loaded-script-0001",
                "sourceSha256": payload["sourceSha256"],
            }
        if operation in {"frida_seal", "frida_unload", "frida_detach"}:
            state = {
                "frida_seal": "callbacks-sealed",
                "frida_unload": "unloaded",
                "frida_detach": "detached",
            }[operation]
            return {"state": state, **payload}
        if operation == "frida_teardown":
            return {
                "state": "torn-down",
                "providerSessionId": payload["providerSessionId"],
                "serverSessionId": payload["serverSessionId"],
                "serverPath": payload["serverPath"],
                "serverPid": payload["serverPid"],
                "serverStartTimeTicks": payload["serverStartTimeTicks"],
                "processAbsent": True,
                "fileAbsent": True,
                "teardownOfSessionId": payload["serverSessionId"],
            }
        raise AssertionError("unhandled fake operation " + operation)

    def finish(self):
        operation_id = self.pending
        operation, payload = self._operation(operation_id)
        if operation in self.raise_operations:
            raise ipc.IpcError("injected worker handler fault at " + operation)
        self.pending = None
        self.dispatched.append((operation, copy.deepcopy(payload)))
        record = self.channel.registry.operations[operation_id]
        budget = max(0, (record["deadline_ns"] - self.now_ns()) // 1_000_000)
        self.deadline_budgets_ms.append((operation, budget))
        for child in self.processes[1:]:
            if not child.suspended:
                child.live = False
        for callback in self.callback_values.get(operation, []):
            self.emit(self.channel.registry.callback(operation_id, callback))
        self.active.discard(operation_id)
        value = self._result(operation, payload)
        mutator = self.result_mutators.get(operation)
        if mutator is not None:
            value = mutator(copy.deepcopy(value))
        reply = self.channel.registry.complete(operation_id, value)
        self.emit(reply)
        stream = self.reply_by_sequence[reply["seq"]]
        stream.eof = not self.missing_eof


class Harness:
    def __init__(self, *, ambient=None, host=None, device=None, image=None,
                 runtime=None, worker_factory=None, bootstrap_timeout_ms=100):
        self.host = host or Authority(host_value())
        self.device = device or Authority(device_value())
        self.image = image or ipc_fakes.Image("frida_worker")
        self.runtime = runtime or FridaRuntime(ipc.decode_json(self.device.raw))
        self.pins = provider_module.FridaProviderPins(
            provider_implementation_sha256=IMPLEMENTATION_SHA256,
            host_authority_sha256=digest(self.host.raw),
            device_authority_sha256=digest(self.device.raw),
            worker_image_sha256=digest(self.image.canonical_bytes()),
            private_adb_authority_sha256=PRIVATE_ADB_SHA256,
        )
        self.binding = runner.StageBinding(
            serial=SERIAL, pid=PID, start_time_ticks=START_TICKS,
            observer_session_id="observer-session-01", deadline_ms=250,
            absolute_deadline_ns=9_000_000_000, stage="before")
        if worker_factory is None:
            worker_factory = lambda: ipc.IsolatedWorker(
                self.image, self.runtime, PROVIDER_SESSION)
        self.provider = provider_module.FridaProvider(
            pins=self.pins, binding=self.binding,
            provider_session_id=PROVIDER_SESSION,
            host_authority=self.host, device_authority=self.device,
            worker_factory=worker_factory,
            ambient_environment={} if ambient is None else ambient,
            bootstrap_timeout_ms=bootstrap_timeout_ms,
        )

    def permit(self, timeout_ms=100):
        return runner.OperationStartPermit(
            self.runtime.now_ns() + timeout_ms * 1_000_000,
            self.runtime.now_ns,
            runner.FridaProviderQuiescenceFailure)

    def admit(self):
        return self.provider.admission(100, self.permit())

    def attach(self):
        self.admit()
        return self.provider.attach(SERIAL, PID, 100, self.permit())

    def load(self, callback=None):
        session = self.attach()
        if callback is None:
            callback = lambda message, data: None
        session.load("send({type: 'ready'});", callback, 100, self.permit())
        return session

    def close_success(self, session=None, timeout_ms=25):
        if session is not None:
            session.seal_callbacks(timeout_ms)
            session.unload(timeout_ms)
            session.detach(timeout_ms)
            session.assert_quiescent(timeout_ms)
        self.provider.teardown(timeout_ms)
        self.provider.assert_quiescent(timeout_ms)

    def force_close(self):
        try:
            self.provider.teardown(25)
        except BaseException:
            pass


def invoke_target(harness: Harness, target: str) -> None:
    """Reach exactly one lifecycle edge after the caller injects its fault."""
    if target == "frida_admission":
        harness.admit()
        return
    harness.admit()
    if target == "frida_attach":
        harness.provider.attach(SERIAL, PID, 100, harness.permit())
        return
    session = harness.provider.attach(SERIAL, PID, 100, harness.permit())
    if target == "frida_load":
        session.load("send('x');", lambda *_: None, 100, harness.permit())
        return
    session.load("send('x');", lambda *_: None, 100, harness.permit())
    if target == "frida_seal":
        session.seal_callbacks(25)
        return
    session.seal_callbacks(25)
    if target == "frida_unload":
        session.unload(25)
        return
    session.unload(25)
    if target == "frida_detach":
        session.detach(25)
        return
    session.detach(25)
    if target == "frida_teardown":
        harness.provider.teardown(25)
        return
    raise AssertionError("unknown lifecycle target " + target)


class FridaProviderTests(unittest.TestCase):
    def test_success_executes_real_isolated_worker_and_runner_contract(self):
        harness = Harness()
        received = []
        harness.runtime.callback_values["frida_load"] = [{
            "message": {"type": "send", "payload": "ready"},
            "dataBase64": "AQID",
        }]
        admission = harness.admit()
        pins = runner.TrustedPins(
            tool_bundle_sha256="6" * 64, manifest_sha256="7" * 64,
            provider_admission_sha256="8" * 64,
            frida_admission_sha256=admission.sha256,
            stage_policy_sha256="9" * 64, receipt_hmac_key=b"x" * 32)
        runner._validate_frida_admission(admission, pins)
        before = harness.provider.stage_frida_record("before")
        self.assertEqual(runner._validate_frida(before, harness.binding, "before"), before)
        session = harness.provider.attach(SERIAL, PID, 100, harness.permit())
        session.load("send({type: 'ready'});", lambda message, data: received.append((message, data)),
                     100, harness.permit())
        harness.close_success(session)
        after = harness.provider.stage_frida_record("after")
        self.assertEqual(runner._validate_frida(after, harness.binding, "after"), after)
        self.assertEqual(received, [({"payload": "ready", "type": "send"}, b"\x01\x02\x03")])
        self.assertEqual([name for name, _ in harness.runtime.dispatched], [
            "frida_admission", "frida_attach", "frida_load", "frida_seal",
            "frida_unload", "frida_detach", "frida_teardown"])
        self.assertTrue(harness.runtime.worker.killed)
        self.assertTrue(harness.runtime.worker.joined)
        self.assertTrue(harness.runtime.worker.closed)

    def test_ambient_routing_overrides_are_rejected_before_worker_launch(self):
        with self.assertRaisesRegex(provider_module.FridaAuthorityError, "ambient"):
            Harness(ambient={"Android_Serial": SERIAL})

    def test_host_and_worker_image_substitution_fail_closed(self):
        harness = Harness()
        harness.host.raw = ipc.canonical_json({**host_value(), "fridaVersion": "17.2.18"})
        with self.assertRaises(provider_module.FridaAuthorityError):
            harness.admit()
        harness.force_close()
        self.assertTrue(harness.runtime.worker.killed)

        image = ipc_fakes.Image("frida_worker")
        image.changed = True
        host, device = Authority(host_value()), Authority(device_value())
        pins = provider_module.FridaProviderPins(
            IMPLEMENTATION_SHA256, digest(host.raw), digest(device.raw),
            "a" * 64, PRIVATE_ADB_SHA256)
        with self.assertRaises(provider_module.FridaAuthorityError):
            provider_module.FridaProvider(
                pins=pins,
                binding=runner.StageBinding(SERIAL, PID, START_TICKS, "observer-session-01",
                                            250, 9_000_000_000, "before"),
                provider_session_id=PROVIDER_SESSION, host_authority=host,
                device_authority=device,
                worker_factory=lambda: ipc.IsolatedWorker(
                    image, FridaRuntime(device_value()), PROVIDER_SESSION),
                ambient_environment={}, bootstrap_timeout_ms=100)

    def test_worker_bootstrap_missing_ready_eof_kills_exact_process(self):
        device = Authority(device_value())
        runtime = FridaRuntime(device_value())
        runtime.missing_eof = True
        with self.assertRaises(provider_module.FridaAuthorityError):
            Harness(device=device, runtime=runtime, bootstrap_timeout_ms=100)
        self.assertTrue(runtime.worker.killed)
        self.assertTrue(runtime.worker.joined)
        self.assertTrue(runtime.worker.closed)

    def test_worker_image_attestation_loss_never_degrades_to_pid_cleanup(self):
        device = Authority(device_value())
        runtime = FridaRuntime(device_value())
        runtime.image_bad = True
        with self.assertRaises(provider_module.FridaLifecycleUncertain):
            Harness(device=device, runtime=runtime, bootstrap_timeout_ms=100)
        self.assertFalse(runtime.worker.killed)

    def test_worker_bootstrap_join_ambiguity_is_sticky_uncertainty(self):
        device = Authority(device_value())
        runtime = FridaRuntime(device_value())
        runtime.missing_eof = True
        runtime.join_failure = True
        with self.assertRaises(provider_module.FridaLifecycleUncertain):
            Harness(device=device, runtime=runtime, bootstrap_timeout_ms=100)
        self.assertTrue(runtime.worker.killed)
        self.assertFalse(runtime.worker.joined)

    def test_late_worker_factory_is_sealed_and_exactly_joined_before_constructor_returns(self):
        runtime = FridaRuntime(device_value())
        image = ipc_fakes.Image("frida_worker")
        factory_entered = threading.Event()
        release_factory = threading.Event()
        outcome = []

        def delayed_factory():
            factory_entered.set()
            release_factory.wait(1)
            return ipc.IsolatedWorker(image, runtime, PROVIDER_SESSION)

        def construct():
            try:
                outcome.append(Harness(
                    image=image, runtime=runtime, worker_factory=delayed_factory,
                    bootstrap_timeout_ms=1))
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=construct)
        thread.start()
        self.assertTrue(factory_entered.wait(1))
        # The public constructor has sealed this startup attempt, but may not
        # return while the delayed factory could still publish a live worker.
        time.sleep(0.02)
        self.assertTrue(thread.is_alive())
        self.assertEqual(outcome, [])
        release_factory.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], provider_module.FridaAuthorityError)
        self.assertIsNotNone(runtime.worker)
        self.assertTrue(runtime.worker.killed)
        self.assertTrue(runtime.worker.joined)
        self.assertTrue(runtime.worker.closed)

    def test_host_paths_reject_ads_traversal_and_reparse_aliases(self):
        mutations = []
        value = host_value()
        value["pythonRuntime"]["path"] += ":payload"
        mutations.append(value)
        value = host_value()
        value["pythonRuntime"]["path"] = "C:\\RetainedFrida\\..\\python.exe"
        mutations.append(value)
        value = host_value()
        value["pythonRuntime"]["reparse"] = True
        mutations.append(value)
        for value in mutations:
            with self.subTest(path=value["pythonRuntime"]["path"]):
                with self.assertRaises(provider_module.FridaAuthorityError):
                    Harness(host=Authority(value))

    def test_device_authority_requires_every_reviewed_mutating_capability(self):
        value = device_value()
        value["capabilities"]["exactUnlink"] = False
        device = Authority(value)
        with self.assertRaisesRegex(provider_module.FridaAuthorityError, "capability"):
            Harness(device=device)

    def test_device_server_path_is_exact_and_cannot_traverse_session_directory(self):
        value = device_value()
        value["serverPath"] = (
            f"/data/local/tmp/rtl-reader-frida/{PROVIDER_SESSION}/../frida-server")
        value["serverArgv"][0] = value["serverPath"]
        with self.assertRaisesRegex(provider_module.FridaAuthorityError, "session-bound"):
            Harness(device=Authority(value))

    def test_device_authority_substitution_after_bootstrap_is_sticky(self):
        harness = Harness()
        replacement = device_value()
        replacement["serverSha256"] = "f" * 64
        harness.device.raw = ipc.canonical_json(replacement)
        with self.assertRaises(provider_module.FridaAuthorityError):
            harness.admit()
        harness.close_success()

    def test_registration_hang_never_claims_that_a_server_was_started(self):
        harness = Harness()
        harness.runtime.block_registration = True
        with self.assertRaises(provider_module.FridaAuthorityError):
            harness.admit()
        harness.provider.teardown(25)
        harness.provider.assert_quiescent(25)
        self.assertFalse(any("server may have started" in item
                             for item in harness.provider.cleanup_obligations))
        self.assertTrue(harness.runtime.worker.killed)

    def test_handshake_mismatch_is_sticky_unknown_server_uncertainty(self):
        harness = Harness()
        harness.runtime.result_mutators["frida_admission"] = lambda value: {
            **value, "server": {**value["server"], "protocol": "wrong-protocol"}}
        with self.assertRaisesRegex(provider_module.FridaAuthorityError, "handshake"):
            harness.admit()
        with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain,
                                    "without authenticated identity"):
            harness.provider.teardown(25)
        self.assertTrue(harness.runtime.worker.killed)
        self.assertTrue(any("may have started" in item
                            for item in harness.provider.cleanup_obligations))

    def test_attach_rejects_substitution_and_pid_reuse(self):
        harness = Harness()
        harness.admit()
        with self.assertRaises(provider_module.FridaAuthorityError):
            harness.provider.attach("OTHER", PID, 100, harness.permit())
        with self.assertRaises(provider_module.FridaAuthorityError):
            harness.provider.attach(SERIAL, PID + 1, 100, harness.permit())
        harness.runtime.result_mutators["frida_attach"] = lambda value: {
            **value, "targetStartTimeTicks": "987654322"}
        with self.assertRaisesRegex(provider_module.FridaAuthorityError, "attach"):
            harness.provider.attach(SERIAL, PID, 100, harness.permit())
        harness.force_close()
        attach_calls = [value for name, value in harness.runtime.dispatched
                        if name == "frida_attach"]
        self.assertEqual(len(attach_calls), 1)
        self.assertEqual(attach_calls[0]["targetStartTimeTicks"], START_TICKS)

    def test_attached_session_cannot_alias_provider_or_server_session(self):
        for reused in (PROVIDER_SESSION, SERVER_SESSION):
            with self.subTest(reused=reused):
                harness = Harness()
                harness.admit()
                harness.runtime.result_mutators["frida_attach"] = lambda value, reused=reused: {
                    **value, "sessionId": reused}
                with self.assertRaisesRegex(provider_module.FridaAuthorityError,
                                            "not independent"):
                    harness.provider.attach(SERIAL, PID, 100, harness.permit())
                harness.force_close()

    def test_callback_after_seal_fails_closed_and_is_never_delivered(self):
        harness = Harness()
        session = harness.load()
        harness.runtime.callback_values["frida_seal"] = [{
            "message": {"type": "send", "payload": "late"}, "dataBase64": None}]
        with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain, "callback"):
            session.seal_callbacks(25)
        harness.force_close()
        self.assertTrue(harness.runtime.worker.killed)

    def test_concurrent_seal_cannot_race_an_in_flight_callback(self):
        harness = Harness()
        session = harness.attach()
        harness.runtime.callback_values["frida_load"] = [{
            "message": {"type": "send", "payload": "terminal"},
            "dataBase64": None}]
        entered = threading.Event()
        release = threading.Event()
        outcome = []

        def callback(*_):
            entered.set()
            release.wait(1)

        def load():
            try:
                session.load("send('terminal');", callback, 100, harness.permit())
                outcome.append("loaded")
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=load)
        thread.start()
        self.assertTrue(entered.wait(1))
        with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain,
                                    "lifecycle ownership|in-flight Frida callback"):
            session.seal_callbacks(1)
        release.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome, ["loaded"])
        harness.close_success(session)

    def test_teardown_cannot_race_load_success_publication(self):
        harness = Harness()
        session = harness.attach()
        harness.runtime.callback_values["frida_load"] = [
            {"message": {"type": "send", "payload": "first"},
             "dataBase64": None},
            {"message": {"type": "send", "payload": "second"},
             "dataBase64": None},
        ]
        callback_entered = threading.Event()
        second_callback_entered = threading.Event()
        release_callback = threading.Event()
        outcome = []
        delivered = []

        def callback(message, _data):
            delivered.append(message["payload"])
            if message["payload"] == "first":
                callback_entered.set()
                release_callback.wait(1)
            else:
                second_callback_entered.set()

        def load():
            try:
                session.load("send('terminal');", callback, 100, harness.permit())
                outcome.append("loaded")
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=load)
        thread.start()
        self.assertTrue(callback_entered.wait(1))
        with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain,
                                    "in-flight lifecycle publication"):
            harness.provider.teardown(25)
        # Teardown has returned and the second buffered callback has never
        # begun.  Releasing the already-admitted first callback must make load
        # fail at the publication fence, not drain the remaining callback.
        self.assertFalse(second_callback_entered.is_set())
        release_callback.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], provider_module.FridaLifecycleUncertain)
        self.assertNotEqual(session.state, "LOADED")
        self.assertEqual(harness.provider._state, "UNCERTAIN")
        self.assertEqual(delivered, ["first"])
        self.assertFalse(second_callback_entered.is_set())
        self.assertTrue(harness.provider._publication_revoked)
        self.assertEqual(harness.provider._callbacks_in_flight, 0)
        self.assertTrue(any("in-flight callback publication" in item
                            for item in harness.provider.cleanup_obligations))
        self.assertTrue(any("load one-shot operation failed" in item
                            for item in harness.provider.failure_history))
        self.assertTrue(harness.runtime.worker.killed)
        self.assertTrue(harness.runtime.worker.joined)

    def test_teardown_after_decode_prevents_callback_start(self):
        harness = Harness()
        session = harness.attach()
        harness.runtime.callback_values["frida_load"] = [{
            "message": {"type": "send", "payload": "decoded"},
            "dataBase64": "AQID"}]
        decode_complete = threading.Event()
        release_callback_start = threading.Event()
        delivered = []
        outcome = []
        original_begin = session._begin_callback

        def begin_after_barrier(generation):
            decode_complete.set()
            release_callback_start.wait(1)
            return original_begin(generation)

        session._begin_callback = begin_after_barrier

        def load():
            try:
                session.load("send('decoded');",
                             lambda message, data: delivered.append((message, data)),
                             100, harness.permit())
                outcome.append("loaded")
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=load)
        thread.start()
        self.assertTrue(decode_complete.wait(1))
        with self.assertRaises(provider_module.FridaLifecycleUncertain):
            harness.provider.teardown(25)
        release_callback_start.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(delivered, [])
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], provider_module.FridaLifecycleUncertain)
        self.assertNotEqual(session.state, "LOADED")
        self.assertEqual(harness.provider._state, "UNCERTAIN")

    def test_teardown_after_decode_prevents_loaded_terminal_commit(self):
        harness = Harness()
        session = harness.attach()
        commit_ready = threading.Event()
        release_commit = threading.Event()
        outcome = []
        original_commit = session._commit_loaded

        def commit_after_barrier(generation, script_id):
            # This is exactly the old check/commit gap: all RPC decoding and
            # deadline checks are complete, but no terminal state is written.
            commit_ready.set()
            release_commit.wait(1)
            return original_commit(generation, script_id)

        session._commit_loaded = commit_after_barrier

        def load():
            try:
                session.load("send('ready');", lambda *_: None,
                             100, harness.permit())
                outcome.append("loaded")
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=load)
        thread.start()
        self.assertTrue(commit_ready.wait(1))
        with self.assertRaises(provider_module.FridaLifecycleUncertain):
            harness.provider.teardown(25)
        release_commit.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], provider_module.FridaLifecycleUncertain)
        self.assertIsNone(session.script_id)
        self.assertNotEqual(session.state, "LOADED")
        self.assertEqual(harness.provider._state, "UNCERTAIN")

    def test_loaded_commit_may_win_atomically_before_teardown_revocation(self):
        harness = Harness()
        session = harness.attach()
        commit_won = threading.Event()
        release_load_return = threading.Event()
        load_outcome = []
        teardown_outcome = []
        original_commit = session._commit_loaded

        def commit_then_pause(generation, script_id):
            original_commit(generation, script_id)
            commit_won.set()
            release_load_return.wait(1)

        session._commit_loaded = commit_then_pause

        def load():
            try:
                session.load("send('ready');", lambda *_: None,
                             100, harness.permit())
                load_outcome.append("loaded")
            except BaseException as error:
                load_outcome.append(error)

        def teardown():
            try:
                harness.provider.teardown(100)
                teardown_outcome.append("closed")
            except BaseException as error:
                teardown_outcome.append(error)

        load_thread = threading.Thread(target=load)
        load_thread.start()
        self.assertTrue(commit_won.wait(1))
        self.assertEqual(session.state, "LOADED")
        teardown_thread = threading.Thread(target=teardown)
        teardown_thread.start()
        with harness.provider._publication_condition:
            deadline = time.monotonic() + 1
            while not harness.provider._publication_revoked:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                harness.provider._publication_condition.wait(remaining)
        release_load_return.set()
        load_thread.join(1)
        teardown_thread.join(1)
        self.assertFalse(load_thread.is_alive())
        self.assertFalse(teardown_thread.is_alive())
        self.assertEqual(load_outcome, ["loaded"])
        self.assertEqual(teardown_outcome, ["closed"])
        self.assertEqual(harness.provider._state, "CLOSED")
        harness.provider.assert_quiescent(25)

    def test_all_post_rpc_state_publications_lose_atomically_to_teardown(self):
        expected_session_state = {
            "seal": "LOADED", "unload": "SEALED", "detach": "UNLOADED"}
        for target in ("admission", "attach", "seal", "unload", "detach"):
            with self.subTest(target=target):
                harness = Harness()
                session = None
                if target == "admission":
                    operation = harness.admit
                elif target == "attach":
                    harness.admit()
                    operation = lambda: harness.provider.attach(
                        SERIAL, PID, 100, harness.permit())
                else:
                    session = harness.load()
                    if target in {"unload", "detach"}:
                        session.seal_callbacks(25)
                    if target == "detach":
                        session.unload(25)
                    operation = {
                        "seal": lambda: session.seal_callbacks(100),
                        "unload": lambda: session.unload(100),
                        "detach": lambda: session.detach(100),
                    }[target]
                publication_ready = threading.Event()
                release_publication = threading.Event()
                outcome = []
                original_transition = harness.provider._transition

                def transition_after_barrier(label, **kwargs):
                    if label == target:
                        publication_ready.set()
                        release_publication.wait(1)
                    return original_transition(label, **kwargs)

                harness.provider._transition = transition_after_barrier

                def invoke():
                    try:
                        outcome.append(operation())
                    except BaseException as error:
                        outcome.append(error)

                thread = threading.Thread(target=invoke)
                thread.start()
                self.assertTrue(publication_ready.wait(1))
                with self.assertRaises(provider_module.FridaLifecycleUncertain):
                    harness.provider.teardown(25)
                release_publication.set()
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(outcome), 1)
                self.assertIsInstance(outcome[0], provider_module.FridaLifecycleUncertain)
                self.assertEqual(harness.provider._state, "UNCERTAIN")
                if target == "attach":
                    self.assertEqual(harness.provider._sessions, [])
                if session is not None:
                    self.assertEqual(session.state, expected_session_state[target])

    def test_sys_trace_detach_commit_cannot_overwrite_uncertain_teardown(self):
        harness = Harness()
        session = harness.load()
        session.seal_callbacks(25)
        session.unload(25)
        pre_commit = threading.Event()
        release_commit = threading.Event()
        outcome = []
        transition_code = provider_module.FridaProvider._transition.__code__

        def trace(frame, event, _arg):
            if (event == "call" and frame.f_code is transition_code and
                    frame.f_locals.get("label") == "detach"):
                pre_commit.set()
                release_commit.wait(1)
            return trace

        def detach():
            sys.settrace(trace)
            try:
                session.detach(100)
                outcome.append("detached")
            except BaseException as error:
                outcome.append(error)
            finally:
                sys.settrace(None)

        thread = threading.Thread(target=detach)
        thread.start()
        self.assertTrue(pre_commit.wait(1))
        with self.assertRaises(provider_module.FridaLifecycleUncertain):
            harness.provider.teardown(25)
        release_commit.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], provider_module.FridaLifecycleUncertain)
        self.assertEqual(session.state, "UNLOADED")
        self.assertEqual(harness.provider._state, "UNCERTAIN")

    def test_callback_handler_is_inside_the_load_deadline(self):
        harness = Harness()
        session = harness.attach()
        harness.runtime.callback_values["frida_load"] = [{
            "message": {"type": "send", "payload": "terminal"},
            "dataBase64": None}]

        def late_callback(*_):
            harness.runtime.clock += 101_000_000

        with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain,
                                    "handler exceeded"):
            session.load("send('terminal');", late_callback, 100, harness.permit())
        harness.close_success(session)

    def test_malformed_and_noncanonical_callback_frames_fail_closed(self):
        for callback in (
            {"message": {"type": "send"}, "dataBase64": "A==="},
            {"message": {"type": "send"}, "dataBase64": "AQI"},
            {"message": {"type": "send"}, "dataBase64": 3},
            {"message": {}, "dataBase64": None, "extra": True},
        ):
            with self.subTest(callback=callback):
                harness = Harness()
                harness.runtime.callback_values["frida_load"] = [callback]
                session = harness.attach()
                with self.assertRaises(provider_module.FridaAuthorityError):
                    session.load("send('x');", lambda *_: None, 100, harness.permit())
                harness.force_close()

    def test_start_permit_is_exact_single_use_and_wrong_type_is_rejected(self):
        harness = Harness()
        permit = harness.permit()
        harness.provider.admission(100, permit)
        with self.assertRaises(runner.FridaProviderQuiescenceFailure):
            permit.start(lambda: None)
        harness.force_close()

        harness = Harness()
        with self.assertRaises(provider_module.FridaAuthorityError):
            harness.provider.admission(100, object())
        harness.close_success()

    def test_dispatched_admission_attach_and_load_failures_are_one_shot(self):
        for target in ("admission", "attach", "load"):
            with self.subTest(target=target):
                harness = Harness()
                session = None
                if target == "attach":
                    harness.admit()
                elif target == "load":
                    session = harness.attach()
                operation = "frida_" + target
                harness.runtime.result_mutators[operation] = lambda value: {
                    **value, "state": "malformed-state"}

                def attempt():
                    if target == "admission":
                        harness.provider.admission(100, harness.permit())
                    elif target == "attach":
                        harness.provider.attach(SERIAL, PID, 100, harness.permit())
                    else:
                        assert session is not None
                        session.load("send('x');", lambda *_: None,
                                     100, harness.permit())

                with self.assertRaises((provider_module.FridaAuthorityError,
                                        provider_module.FridaLifecycleUncertain)):
                    attempt()
                dispatched = harness.runtime.external_starts
                self.assertEqual(harness.provider._state, "FAILED")
                self.assertTrue(any(target + " one-shot operation failed" in item
                                    for item in harness.provider.failure_history))
                with self.assertRaises((provider_module.FridaAuthorityError,
                                        provider_module.FridaLifecycleUncertain)):
                    attempt()
                self.assertEqual(harness.runtime.external_starts, dispatched)
                harness.force_close()

    def test_dispatched_quiescence_and_handler_errors_cannot_be_retried(self):
        for mode in ("hang", "handler"):
            with self.subTest(mode=mode):
                harness = Harness()
                if mode == "hang":
                    harness.runtime.hang_operations.add("frida_admission")
                else:
                    harness.runtime.raise_operations.add("frida_admission")
                with self.assertRaises((provider_module.FridaAuthorityError,
                                        provider_module.FridaLifecycleUncertain)):
                    harness.admit()
                starts = harness.runtime.external_starts
                self.assertEqual(starts, 1)
                self.assertEqual(harness.provider._state, "FAILED")
                with self.assertRaises((provider_module.FridaAuthorityError,
                                        provider_module.FridaLifecycleUncertain)):
                    harness.admit()
                self.assertEqual(harness.runtime.external_starts, starts)
                harness.force_close()

    def test_each_lifecycle_operation_hang_is_fail_closed_and_bounded(self):
        steps = (
            "frida_admission", "frida_attach", "frida_load", "frida_seal",
            "frida_unload", "frida_detach", "frida_teardown")
        for target in steps:
            with self.subTest(target=target):
                harness = Harness()
                session = None
                try:
                    if target == "frida_admission":
                        harness.runtime.hang_operations.add(target)
                        with self.assertRaises(provider_module.FridaAuthorityError):
                            harness.admit()
                    else:
                        harness.admit()
                        if target == "frida_attach":
                            harness.runtime.hang_operations.add(target)
                            with self.assertRaises(provider_module.FridaAuthorityError):
                                harness.provider.attach(SERIAL, PID, 100, harness.permit())
                        else:
                            session = harness.provider.attach(SERIAL, PID, 100, harness.permit())
                            if target == "frida_load":
                                harness.runtime.hang_operations.add(target)
                                with self.assertRaises(provider_module.FridaAuthorityError):
                                    session.load("send('x');", lambda *_: None,
                                                 100, harness.permit())
                            else:
                                session.load("send('x');", lambda *_: None,
                                             100, harness.permit())
                                harness.runtime.hang_operations.add(target)
                                if target == "frida_seal":
                                    with self.assertRaises(provider_module.FridaAuthorityError):
                                        session.seal_callbacks(25)
                                elif target == "frida_unload":
                                    session.seal_callbacks(25)
                                    with self.assertRaises(provider_module.FridaAuthorityError):
                                        session.unload(25)
                                elif target == "frida_detach":
                                    session.seal_callbacks(25)
                                    session.unload(25)
                                    with self.assertRaises(provider_module.FridaAuthorityError):
                                        session.detach(25)
                                else:
                                    session.seal_callbacks(25)
                                    session.unload(25)
                                    session.detach(25)
                                    with self.assertRaises(provider_module.FridaLifecycleUncertain):
                                        harness.provider.teardown(25)
                finally:
                    harness.force_close()
                self.assertFalse(harness.runtime.worker.live)

    def test_each_worker_handler_fault_terminates_exact_worker(self):
        for target in (
            "frida_admission", "frida_attach", "frida_load", "frida_seal",
            "frida_unload", "frida_detach", "frida_teardown"):
            with self.subTest(target=target):
                harness = Harness()
                try:
                    harness.runtime.raise_operations.add(target)
                    with self.assertRaises((provider_module.FridaAuthorityError,
                                            provider_module.FridaLifecycleUncertain)):
                        invoke_target(harness, target)
                finally:
                    harness.force_close()
                self.assertTrue(harness.runtime.worker.killed)
                self.assertTrue(harness.runtime.worker.joined)

    def test_json_expansion_is_rejected_before_load_start_permit_or_dispatch(self):
        harness = Harness()
        session = harness.attach()
        permit = harness.permit()
        with self.assertRaisesRegex(provider_module.FridaAuthorityError,
                                    "canonical private IPC frame"):
            session.load("\\" * 40_000, lambda *_: None, 100, permit)
        self.assertFalse(any(name == "frida_load" for name, _ in harness.runtime.dispatched))
        with self.assertRaises(runner.FridaProviderQuiescenceFailure):
            permit.require_exact_start(runner.FridaProviderQuiescenceFailure)
        harness.close_success(session)

    def test_teardown_identity_mismatch_never_claims_or_uses_broad_cleanup(self):
        harness = Harness()
        harness.admit()
        harness.runtime.result_mutators["frida_teardown"] = lambda value: {
            **value, "serverPid": value["serverPid"] + 1}
        with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain,
                                    "kill/unlink"):
            harness.provider.teardown(25)
        teardown = [payload for name, payload in harness.runtime.dispatched
                    if name == "frida_teardown"]
        self.assertEqual(teardown, [{
            "providerSessionId": PROVIDER_SESSION,
            "serverSessionId": SERVER_SESSION,
            "serverPath": device_value()["serverPath"],
            "serverPid": 4242,
            "serverStartTimeTicks": "123456789",
        }])
        self.assertTrue(any("kill/unlink" in item
                            for item in harness.provider.cleanup_obligations))
        self.assertTrue(harness.runtime.worker.killed)

    def test_teardown_absence_evidence_rejects_integer_boolean_aliases(self):
        for field in ("processAbsent", "fileAbsent"):
            for alias in (1, 0):
                with self.subTest(field=field, alias=alias):
                    harness = Harness()
                    harness.admit()
                    harness.runtime.result_mutators["frida_teardown"] = (
                        lambda value, field=field, alias=alias: {
                            **value, field: alias})
                    with self.assertRaisesRegex(provider_module.FridaLifecycleUncertain,
                                                "kill/unlink"):
                        harness.provider.teardown(25)
                    self.assertFalse(harness.provider._server_torn_down)
                    self.assertTrue(any("kill/unlink" in item
                                        for item in harness.provider.cleanup_obligations))
                    self.assertTrue(harness.runtime.worker.killed)
                    self.assertTrue(harness.runtime.worker.joined)

    def test_internal_cleanup_deadline_includes_operation_lock_wait(self):
        harness = Harness()
        session = harness.load()
        harness.provider._operation_lock.acquire()
        released = threading.Event()

        def release_operation_owner():
            time.sleep(0.01)
            # Deterministically consume 20 ms of the frozen worker-clock
            # budget while the cleanup call is waiting for operation owner.
            harness.runtime.clock += 20_000_000
            harness.provider._operation_lock.release()
            released.set()

        releaser = threading.Thread(target=release_operation_owner)
        releaser.start()
        runtime_started = harness.runtime.now_ns()
        started = time.perf_counter()
        session.seal_callbacks(25)
        elapsed = time.perf_counter() - started
        runtime_elapsed_ns = harness.runtime.now_ns() - runtime_started
        releaser.join(1)
        self.assertTrue(released.is_set())
        seal_budgets = [budget for operation, budget
                        in harness.runtime.deadline_budgets_ms
                        if operation == "frida_seal"]
        self.assertEqual(len(seal_budgets), 1)
        self.assertGreater(seal_budgets[0], 0)
        self.assertLessEqual(seal_budgets[0], 5)
        self.assertLessEqual(runtime_elapsed_ns, 25_000_000)
        # The runtime deadline is authoritative; this generous wall ceiling
        # catches accidental rebasing without making Windows timer quantum a
        # source of flakes.
        self.assertLess(elapsed, 0.05)
        harness.close_success(session)

    def test_cleanup_calls_retain_25ms_runner_budget_and_measure_elapsed(self):
        harness = Harness()
        session = harness.load()
        harness.close_success(session, 25)
        cleanup_budgets = [budget for operation, budget in harness.runtime.deadline_budgets_ms
                           if operation in {"frida_seal", "frida_unload", "frida_detach",
                                            "frida_teardown"}]
        self.assertTrue(cleanup_budgets)
        self.assertTrue(all(0 < budget <= 25 for budget in cleanup_budgets))
        measurements = harness.provider.cleanup_measurements
        self.assertEqual([name for name, _, _ in measurements],
                         ["teardown", "assert_quiescent"])
        self.assertTrue(all(bound == 25 and elapsed >= 0
                            for _, bound, elapsed in measurements))
        # This measures adapter return time, not device power-loss durability.
        self.assertLess(measurements[0][2], 250_000_000)

    def test_no_default_runtime_or_ambient_frida_adb_import_exists(self):
        self.assertEqual(provider_module.HARDWARE_BLOCK_REASON,
                         "S1B_MUTATING_PRIVATE_ADB_AUTHORITY_UNAVAILABLE")
        with open(provider_module.__file__, "r", encoding="utf-8") as source_file:
            source = source_file.read()
        for forbidden in ("import frida", "import subprocess", "os.environ",
                          "adb.exe", "shell=True"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
