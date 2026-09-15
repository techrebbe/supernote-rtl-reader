from __future__ import annotations

import copy
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import threading
import time
import struct
import unittest
from unittest import mock

import native_page_snapshot_runner as runner


SERIAL = "SN078C10015092"
PID = 2468
START = "987654321"
SESSION = "snapshot-session-0001"
DEADLINE = 250
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
PDF_PATH = "/storage/emulated/0/Document/snapshot.pdf"
PDF_URI = "file:///storage/emulated/0/Document/snapshot.pdf"


def descriptor_field(name: str, field_type: str) -> dict[str, str]:
    return {"field": "field_" + name, "type": field_type}


def bound_role(role: str) -> dict[str, object]:
    field_types = runner.ROLE_FIELDS[role]
    return {
        "className": "com.supernote.snapshot." + role.capitalize(),
        "fields": {
            name: descriptor_field(name, field_type)
            for name, field_type in field_types.items()
        },
        "selector": {"identity": role + "-identity"},
    }


def file_stat() -> dict[str, object]:
    return {
        "device": "1", "inode": "2", "mode": "33188", "uid": 0, "gid": 0,
        "mtimeNs": "10", "ctimeNs": "11",
    }


def manifest_value(*, layers_bound: bool = False) -> dict[str, object]:
    layers: dict[str, object]
    if layers_bound:
        layers = bound_role("layers")
        layers["status"] = "bound"
    else:
        layers = {
            "status": "unavailable", "reasonCode": "NO_PINNED_LAYER_BINDING",
            "evidenceId": "evidence-layer-unavailable",
        }
    return {
        "schemaVersion": 1,
        "authority": runner.MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": runner.PACKAGE_NAME,
            "processName": runner.PROCESS_NAME,
            "pid": PID,
            "startTimeTicks": START,
            "apk": {"path": "/data/app/document/base.apk", "size": 1234,
                    "sha256": DIGEST_A},
            "module": {"name": "libdocument.so", "path": "/data/lib/libdocument.so",
                       "size": 5678, "sha256": DIGEST_B},
        },
        "files": {
            "authority": "rtl-reader-native-page-file-authority-v1",
            "verification": "external-before-and-after-exact",
            "originalPdf": {
                "present": True, "path": PDF_PATH, "size": "123456",
                "sha256": DIGEST_C, "stat": file_stat(), "documentUri": PDF_URI,
                "uriResolution": {
                    "authority": "rtl-reader-file-uri-resolution-v1",
                    "documentUri": PDF_URI, "resolvedPath": PDF_PATH,
                    "evidenceSha256": DIGEST_D,
                },
            },
            "mark": {"present": False, "path": None, "size": None,
                     "sha256": None, "stat": None},
        },
        "coordinator": {
            "authority": "rtl-reader-native-page-snapshot-coordinator-v1",
            "observerSessionId": SESSION,
            "hardDeadlineMs": DEADLINE,
            "maxJavaChooseWalks": 10,
            "detachOnDeadline": True,
            "abortOnAnyError": True,
            "verifyTargetLivenessAfter": True,
        },
        "expected": {
            "taskId": 7, "displayId": 0, "sessionGeneration": 12,
            "uri": PDF_URI, "currentPageIndex": 2, "pageCount": 10,
        },
        "bindings": {
            "activity": bound_role("activity"),
            "viewModel": bound_role("viewModel"),
            "pageInfo": bound_role("pageInfo"),
            "presenter": bound_role("presenter"),
            "layers": layers,
        },
    }


def loaded_manifest(*, layers_bound: bool = False) -> runner.LoadedJson:
    value = manifest_value(layers_bound=layers_bound)
    raw = runner._canonical_json_bytes(value)
    loaded = runner._load_canonical_json_bytes(raw, runner.MAX_MANIFEST_BYTES)
    runner._validate_manifest_envelope(loaded.value)
    return loaded


def binding(**changes: object) -> runner.RunBinding:
    values: dict[str, object] = {
        "serial": SERIAL, "pid": PID, "start_time_ticks": START,
        "observer_session_id": SESSION, "deadline_ms": DEADLINE,
    }
    values.update(changes)
    return runner.RunBinding(**values)  # type: ignore[arg-type]


def prerequisite() -> dict[str, object]:
    return {
        "status": "external-prerequisite",
        "authority": "rtl-reader-drawpath-scalar-snapshot-v1",
        "required": True,
        "requiredFields": ["pid", "startTimeTicks", "screenWidth", "screenHeight",
                           "documentImageWidth", "documentImageHeight"],
        "note": ("Capture independently from the pinned DrawPath process; "
                 "no offsets are inferred here."),
    }


def binary64(value: float) -> dict[str, str]:
    return {"binary64": "0x" + struct.pack(">d", value).hex()}


def page_info(page_index: int) -> dict[str, object]:
    return {
        "identity": "pageInfo-identity", "pageIndex": page_index,
        "size": [binary64(1000.0), binary64(1400.0)],
        "crop": [binary64(0.0), binary64(0.0), binary64(1000.0),
                 binary64(1400.0)],
        "ctm": [binary64(1.0), binary64(0.0), binary64(0.0), binary64(1.0),
                binary64(0.0), binary64(0.0)],
        "inverse": [binary64(1.0), binary64(0.0), binary64(0.0), binary64(1.0),
                    binary64(0.0), binary64(0.0)],
        "offset": [binary64(0.0), binary64(0.0)],
        "bitmapDimensions": [1872, 1404],
    }


def presenter(page_index: int) -> dict[str, object]:
    return {
        "identity": "presenter-identity", "currentPageIndex": page_index,
        "markPath": None, "rotation": 0, "noteIdentity": "note-identity",
        "clientIdentity": "client-identity", "binderIdentity": "binder-identity",
    }


def snapshot_payload(manifest: runner.LoadedJson) -> dict[str, object]:
    value = manifest.value
    expected = value["expected"]
    apk = value["attachment"]["apk"]
    module = value["attachment"]["module"]
    layers_bound = value["bindings"]["layers"].get("status") == "bound"
    return {
        "event": "native_page_snapshot",
        "schemaVersion": 1,
        "authority": "rtl-reader-native-page-snapshot-v1",
        "manifestSha256": manifest.sha256,
        "observationOnly": True,
        "atomic": False,
        "attachment": {
            "packageName": runner.PACKAGE_NAME,
            "processName": runner.PROCESS_NAME,
            "pid": PID,
            "processStartTimeTicks": START,
            "architecture": "arm64",
            "pointerSize": 8,
            "apk": {"path": apk["path"], "size": apk["size"],
                    "externallyVerifiedSha256": apk["sha256"]},
            "module": {"name": module["name"], "path": module["path"],
                       "size": module["size"],
                       "externallyVerifiedSha256": module["sha256"]},
        },
        "fileAuthority": value["files"],
        "coordinator": {
            "authority": "rtl-reader-native-page-snapshot-coordinator-v1",
            "observerSessionId": SESSION,
            "hardDeadlineMs": DEADLINE,
            "javaChooseWalks": 10 if layers_bound else 8,
            "externalDetachOnDeadline": True,
            "externalTargetLivenessPostconditionRequired": True,
        },
        "session": {
            "activityIdentity": "activity-identity", "taskId": expected["taskId"],
            "displayId": expected["displayId"], "generation": expected["sessionGeneration"],
        },
        "document": {
            "viewModelIdentity": "viewModel-identity", "uri": expected["uri"],
            "currentPageIndex": expected["currentPageIndex"],
            "pageCount": expected["pageCount"],
            "pageInfo": page_info(expected["currentPageIndex"]),
        },
        "presenter": presenter(expected["currentPageIndex"]),
        "layers": ({
            "identity": "layers-identity", "backgroundIdentity": "background-identity",
            "committedHandwritingIdentity": "ink-identity",
            "digestLayerIdentity": "digest-identity",
        } if layers_bound else {
            "status": "unavailable", "reasonCode": "NO_PINNED_LAYER_BINDING",
            "evidenceId": "evidence-layer-unavailable",
        }),
        "drawPathPrerequisite": prerequisite(),
    }


def send(payload: dict[str, object]) -> dict[str, object]:
    return {"type": "send", "payload": payload}


def terminal(success: bool = True) -> dict[str, object]:
    return send({"event": "native_page_snapshot_complete", "success": success})


class FakeAdb:
    def __init__(self, *, second_start: str | None = None,
                 fail_second_stat: bool = False):
        self.calls: list[tuple[str, ...]] = []
        self.stat_calls = 0
        self.second_start = second_start
        self.fail_second_stat = fail_second_stat

    def run(self, arguments: object, timeout_ms: int) -> runner.CommandResult:
        if type(arguments) not in (tuple, list):
            raise AssertionError("ADB adapter did not receive argv")
        args = tuple(arguments)
        self.calls.append(args)
        if timeout_ms != DEADLINE:
            raise AssertionError("unexpected ADB timeout")
        command = args[2:]
        if command == ("get-serialno",):
            return runner.CommandResult(0, (SERIAL + "\n").encode("ascii"), b"")
        if command == ("get-state",):
            return runner.CommandResult(0, b"device\n", b"")
        if command == ("exec-out", "cat", f"/proc/{PID}/stat"):
            self.stat_calls += 1
            if self.fail_second_stat and self.stat_calls == 2:
                return runner.CommandResult(1, b"", b"gone")
            start = (self.second_start if self.stat_calls == 2 and self.second_start
                     else START)
            fields = ["S", *(["1"] * 18), start, "1"]
            wire = f"{PID} (Document worker) {' '.join(fields)}\n".encode("ascii")
            return runner.CommandResult(0, wire, b"")
        if command == ("exec-out", "cat", f"/proc/{PID}/cmdline"):
            return runner.CommandResult(0, runner.PACKAGE_NAME.encode() + b"\x00", b"")
        raise AssertionError("unexpected ADB argv: " + repr(args))


def evidence_record(request: runner.EvidenceRequest) -> dict[str, object]:
    return {
        "schemaVersion": 1, "authority": runner.EVIDENCE_AUTHORITY,
        "phase": request.phase, "manifestSha256": request.manifest_sha256,
        "serial": request.binding.serial, "pid": request.binding.pid,
        "startTimeTicks": request.binding.start_time_ticks,
        "observerSessionId": request.binding.observer_session_id,
        "packageName": request.package_name, "apk": request.apk,
        "module": request.module, "originalPdf": request.original_pdf,
        "mark": request.mark, "uriResolution": request.uri_resolution,
    }


class FakeEvidenceProvider:
    def __init__(self, *, mutate_phase: str | None = None,
                 mutate_field: str = "apk", malformed_digest: bool = False,
                 after_delay: float = 0.0):
        self.phases: list[str] = []
        self.mutate_phase = mutate_phase
        self.mutate_field = mutate_field
        self.malformed_digest = malformed_digest
        self.after_delay = after_delay

    def admission(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "authority": runner.EVIDENCE_PROVIDER_AUTHORITY,
            "recordAuthority": runner.EVIDENCE_AUTHORITY,
            "captureMode": "independent-before-and-after-exact",
            "captures": ["apk", "module", "originalPdf", "mark", "uriResolution"],
        }

    def capture(self, request: runner.EvidenceRequest) -> runner.AuthenticatedEvidence:
        self.phases.append(request.phase)
        if request.phase == "after" and self.after_delay:
            time.sleep(self.after_delay)
        value = copy.deepcopy(evidence_record(request))
        if request.phase == self.mutate_phase:
            if self.mutate_field in {"apk", "module"}:
                value[self.mutate_field]["size"] += 1
            elif self.mutate_field == "originalPdf":
                value["originalPdf"]["sha256"] = "e" * 64
            elif self.mutate_field == "mark":
                value["mark"]["present"] = True
            elif self.mutate_field == "uriResolution":
                value["uriResolution"]["evidenceSha256"] = "e" * 64
            else:
                raise AssertionError("unknown mutation field")
        raw = runner._canonical_json_bytes(value)
        digest = runner.hashlib.sha256(raw).hexdigest()
        if self.malformed_digest:
            digest = "0" * 64
        return runner.AuthenticatedEvidence(raw, digest)


class MutatingRequestEvidenceProvider(FakeEvidenceProvider):
    def capture(self, request: runner.EvidenceRequest) -> runner.AuthenticatedEvidence:
        request.apk["size"] += 1
        value = evidence_record(request)
        raw = runner._canonical_json_bytes(value)
        return runner.AuthenticatedEvidence(raw, runner.hashlib.sha256(raw).hexdigest())


class FakeSession:
    def __init__(self, manifest: runner.LoadedJson, mode: str = "success"):
        self.manifest = manifest
        self.mode = mode
        self.loads = 0
        self.unloads = 0
        self.detaches = 0
        self.callback = None

    def load(self, source: str, on_message: object) -> None:
        self.loads += 1
        self.callback = on_message
        if not source.endswith(observer_bytes().decode("utf-8")):
            raise AssertionError("observer suffix changed")
        if self.mode == "load_error":
            raise RuntimeError("load failed")
        if self.mode in {"hang", "late_on_detach"}:
            return
        payload = snapshot_payload(self.manifest)
        if self.mode == "error":
            on_message(send({"event": "native_page_snapshot_error", "schemaVersion": 1,
                             "code": "SNAPSHOT_REJECTED", "message": "rejected"}), None)
            on_message(terminal(False), None)
            return
        if self.mode == "oversize":
            on_message(send({"event": "native_page_snapshot",
                             "blob": "x" * runner.MAX_MESSAGE_BYTES}), None)
            return
        if self.mode == "race_duplicate":
            barrier = threading.Barrier(3)

            def emit() -> None:
                barrier.wait()
                on_message(send(copy.deepcopy(payload)), None)

            first = threading.Thread(target=emit)
            second = threading.Thread(target=emit)
            first.start()
            second.start()
            barrier.wait()
            first.join()
            second.join()
            on_message(terminal(), None)
            return
        on_message(send(payload), None)
        on_message(terminal(), None)
        if self.mode == "extra_frame":
            on_message(terminal(), None)

    def unload(self) -> None:
        self.unloads += 1
        if self.mode == "late_on_unload" and self.callback is not None:
            self.callback(terminal(), None)
        if self.mode == "unload_failure":
            raise RuntimeError("unload failed")

    def detach(self) -> None:
        self.detaches += 1
        if self.mode == "late_on_detach" and self.callback is not None:
            payload = snapshot_payload(self.manifest)
            self.callback(send(payload), None)
            self.callback(terminal(), None)
        if self.mode == "delayed_after_detach" and self.callback is not None:
            callback = self.callback

            def emit_late() -> None:
                time.sleep(0.01)
                callback(terminal(), None)

            threading.Thread(target=emit_late, daemon=True).start()
        if self.mode == "detach_failure":
            raise RuntimeError("detach failed")


class FakeFrida:
    def __init__(self, session: FakeSession, *, attach_error: bool = False,
                 attach_hang_seconds: float = 0.0):
        self.session = session
        self.attach_error = attach_error
        self.attach_hang_seconds = attach_hang_seconds
        self.attach_calls: list[tuple[str, int]] = []

    def attach(self, serial: str, pid: int) -> FakeSession:
        self.attach_calls.append((serial, pid))
        if self.attach_hang_seconds:
            time.sleep(self.attach_hang_seconds)
        if self.attach_error:
            raise RuntimeError("attach failed")
        return self.session


def observer_bytes() -> bytes:
    return Path(__file__).with_name("native_page_snapshot.js").read_bytes()


def run_with(*, manifest: runner.LoadedJson | None = None, mode: str = "success",
             adb: FakeAdb | None = None, evidence: FakeEvidenceProvider | None = None,
             session: FakeSession | None = None, frida: FakeFrida | None = None,
             run_binding: runner.RunBinding | None = None) -> tuple[dict[str, object],
                                                                    FakeAdb,
                                                                    FakeEvidenceProvider,
                                                                    FakeSession,
                                                                    FakeFrida]:
    manifest = manifest or loaded_manifest()
    adb = adb or FakeAdb()
    evidence = evidence or FakeEvidenceProvider()
    session = session or FakeSession(manifest, mode)
    frida = frida or FakeFrida(session)
    result = runner.run_snapshot(
        manifest=manifest, observer_raw=observer_bytes(),
        binding=run_binding or binding(), adb=adb, frida=frida,
        evidence_provider=evidence)
    return result, adb, evidence, session, frida


class ManifestAndInjectionTests(unittest.TestCase):
    def test_canonical_manifest_and_exact_source_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(runner._canonical_json_bytes(manifest_value()))
            loaded = runner.load_manifest(path)
        raw, digest = runner.load_observer_source(
            Path(__file__).with_name("native_page_snapshot.js"))
        self.assertEqual(digest, runner.EXPECTED_OBSERVER_SHA256)
        injected = runner.build_injected_observer(loaded, raw)
        self.assertTrue(injected.endswith(raw.decode("utf-8")))
        self.assertEqual(injected.count("globalThis.NATIVE_PAGE_SNAPSHOT_MANIFEST_UTF8="), 1)
        self.assertEqual(injected.count("globalThis.NATIVE_PAGE_SNAPSHOT_MANIFEST_SHA256="), 1)

    def test_hostile_manifest_text_is_injected_only_as_bytes(self) -> None:
        value = manifest_value()
        hostile = "file:///tmp/';send({event:'pwn'});//"
        value["files"]["originalPdf"]["documentUri"] = hostile
        value["files"]["originalPdf"]["uriResolution"]["documentUri"] = hostile
        value["expected"]["uri"] = hostile
        raw = runner._canonical_json_bytes(value)
        manifest = runner._load_canonical_json_bytes(raw, runner.MAX_MANIFEST_BYTES)
        runner._validate_manifest_envelope(manifest.value)
        injected = runner.build_injected_observer(manifest, observer_bytes())
        prefix = injected[:-len(observer_bytes().decode("utf-8"))]
        self.assertNotIn("pwn", prefix)
        self.assertRegex(prefix, r"^globalThis\.[A-Z0-9_]+=Object\.freeze\(\[[0-9,]+\]\);\n"
                                 r"globalThis\.[A-Z0-9_]+='[0-9a-f]{64}';\n$")

    def test_noncanonical_duplicate_float_utf8_and_oversize_are_rejected(self) -> None:
        canonical = runner._canonical_json_bytes(manifest_value())
        hostile = [
            canonical + b"\n",
            b'{"authority":"a","authority":"b"}',
            b'{"value":1.0}',
            b'{"value":999999999999999999999999999999999999999}',
            (b'{"value":' + b"[" * 1_100 + b"0" + b"]" * 1_100 + b"}"),
            b'{"value":"\xff"}',
            b"{" + b" " * runner.MAX_MANIFEST_BYTES + b"}",
        ]
        for wire in hostile:
            with self.subTest(wire=wire[:40]):
                with self.assertRaises(runner.SnapshotRunnerError):
                    runner._load_canonical_json_bytes(wire, runner.MAX_MANIFEST_BYTES)

    def test_forged_loaded_manifest_and_manifest_field_mutations_fail_closed(self) -> None:
        manifest = loaded_manifest()
        forged = runner.LoadedJson(manifest.raw, copy.deepcopy(manifest.value),
                                   manifest.sha256)
        forged.value["attachment"]["pid"] += 1
        with self.assertRaises(runner.SnapshotRunnerError):
            runner.build_injected_observer(forged, observer_bytes())
        mutations = []
        for mutate in (
            lambda value: value["attachment"]["module"].pop("name"),
            lambda value: value["files"]["mark"].update({"path": "/tmp/mark"}),
            lambda value: value["expected"].update({"currentPageIndex": 10}),
            lambda value: value["bindings"]["activity"]["selector"].clear(),
        ):
            value = manifest_value()
            mutate(value)
            mutations.append(value)
        for value in mutations:
            raw = runner._canonical_json_bytes(value)
            loaded = runner._load_canonical_json_bytes(raw, runner.MAX_MANIFEST_BYTES)
            with self.assertRaises(runner.SnapshotRunnerError):
                runner._validate_manifest_envelope(loaded.value)


class CoordinatorTests(unittest.TestCase):
    def test_success_uses_exact_adb_argv_and_one_attach(self) -> None:
        result, adb, evidence, session, frida = run_with()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["authority"], runner.RUNNER_AUTHORITY)
        self.assertEqual(result["observerSchemaAdapter"],
                         runner.OBSERVER_SCHEMA_ADAPTER_AUTHORITY)
        self.assertEqual(evidence.phases, ["before", "after"])
        self.assertEqual(frida.attach_calls, [(SERIAL, PID)])
        self.assertEqual((session.loads, session.unloads, session.detaches), (1, 1, 1))
        expected_once = [
            ("-s", SERIAL, "get-serialno"),
            ("-s", SERIAL, "get-state"),
            ("-s", SERIAL, "exec-out", "cat", f"/proc/{PID}/stat"),
            ("-s", SERIAL, "exec-out", "cat", f"/proc/{PID}/cmdline"),
        ]
        self.assertEqual(adb.calls, expected_once + expected_once)

    def test_v1_schema_adapter_rejects_malformed_nested_records(self) -> None:
        manifest = loaded_manifest()
        mutations = [
            lambda value: value["document"].update({"pageInfo": {}}),
            lambda value: value["document"]["pageInfo"]["size"][0].update(
                {"binary64": "0x7ff8000000000000"}),
            lambda value: value["document"]["pageInfo"]["ctm"].__setitem__(
                0, binary64(0.0)),
            lambda value: value["presenter"].update({"currentPageIndex": 3}),
            lambda value: value.update({"layers": {}}),
            lambda value: value["drawPathPrerequisite"].update({"required": False}),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                payload = snapshot_payload(manifest)
                mutate(payload)
                deadline_ns = time.monotonic_ns() + 1_000_000_000
                collector = runner._V1MessageCollector(
                    manifest, binding(), deadline_ns, time.monotonic_ns)
                collector.receive(send(payload), None)
                collector.receive(terminal(), None)
                with self.assertRaises(runner.SnapshotRunnerError):
                    collector.close_and_result()

    def test_completion_and_terminal_timestamps_enforce_exact_boundary(self) -> None:
        deadline_ns = 1_000_000_000

        def boundary_clock() -> int:
            if threading.current_thread().name.startswith("native-page-snapshot-"):
                return deadline_ns
            return 0

        self.assertEqual(runner._call_until(lambda: "ok", deadline_ns,
                                            boundary_clock, "boundary"), "ok")

        cleaned: list[object] = []

        def late_clock() -> int:
            if threading.current_thread().name.startswith("native-page-snapshot-"):
                return deadline_ns + 1
            return 0

        token = object()
        with self.assertRaises(runner.SnapshotDeadlineExceeded):
            runner._call_until(lambda: token, deadline_ns, late_clock, "late",
                               late_cleanup=cleaned.append)
        self.assertEqual(cleaned, [token])

        manifest = loaded_manifest()
        collector = runner._V1MessageCollector(
            manifest, binding(), deadline_ns, lambda: deadline_ns + 1)
        collector.receive(send(snapshot_payload(manifest)), None)
        collector.receive(terminal(), None)
        with self.assertRaises(runner.SnapshotRunnerError):
            collector.close_and_result()

    def test_python_frida_adapter_detach_is_a_callback_quiescence_barrier(self) -> None:
        class Script:
            def __init__(self) -> None:
                self.callback = None
                self.off_calls = 0
                self.unload_calls = 0

            def on(self, event: str, callback: object) -> None:
                self.callback = callback

            def off(self, event: str, callback: object) -> None:
                self.off_calls += 1
                self.asserted_callback = callback

            def load(self) -> None:
                return None

            def unload(self) -> None:
                self.unload_calls += 1

            def emit(self) -> None:
                self.callback({"type": "send", "payload": {}}, None)

        class CoreSession:
            def __init__(self) -> None:
                self.script = Script()
                self.detach_calls = 0

            def create_script(self, source: str) -> Script:
                return self.script

            def detach(self) -> None:
                self.detach_calls += 1

        core = CoreSession()
        adapter = runner._PythonFridaSession(core)
        entered = threading.Event()
        release = threading.Event()
        calls: list[object] = []

        def callback(message: object, data: object) -> None:
            calls.append(message)
            entered.set()
            release.wait(1)

        adapter.load("observer", callback)
        emitter = threading.Thread(target=core.script.emit)
        emitter.start()
        self.assertTrue(entered.wait(1))
        unloader = threading.Thread(target=adapter.unload)
        unloader.start()
        time.sleep(0.02)
        self.assertTrue(unloader.is_alive())
        release.set()
        emitter.join(1)
        unloader.join(1)
        self.assertFalse(unloader.is_alive())
        self.assertEqual((core.script.off_calls, core.script.unload_calls), (1, 1))
        core.script.emit()
        self.assertEqual(len(calls), 1)
        adapter.detach()
        self.assertEqual(core.detach_calls, 1)

    def test_observer_hang_hits_external_deadline_and_cleans_up_without_retry(self) -> None:
        manifest = loaded_manifest()
        session = FakeSession(manifest, "hang")
        frida = FakeFrida(session)
        evidence = FakeEvidenceProvider()
        started = time.monotonic()
        with self.assertRaises(runner.SnapshotDeadlineExceeded):
            runner.run_snapshot(
                manifest=manifest, observer_raw=observer_bytes(), binding=binding(),
                adb=FakeAdb(), frida=frida, evidence_provider=evidence)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.20)
        self.assertLess(elapsed, 0.90)
        self.assertEqual(frida.attach_calls, [(SERIAL, PID)])
        self.assertEqual((session.unloads, session.detaches), (1, 1))
        self.assertEqual(evidence.phases, ["before", "after"])

    def test_late_attach_is_cleaned_after_external_deadline_without_retry(self) -> None:
        manifest = loaded_manifest()
        session = FakeSession(manifest, "hang")
        frida = FakeFrida(session, attach_hang_seconds=0.35)
        started = time.monotonic()
        with self.assertRaises(runner.SnapshotDeadlineExceeded):
            runner.run_snapshot(
                manifest=manifest, observer_raw=observer_bytes(), binding=binding(),
                adb=FakeAdb(), frida=frida,
                evidence_provider=FakeEvidenceProvider())
        self.assertLess(time.monotonic() - started, 0.90)
        self.assertEqual(frida.attach_calls, [(SERIAL, PID)])
        limit = time.monotonic() + 0.75
        while session.detaches == 0 and time.monotonic() < limit:
            time.sleep(0.01)
        self.assertEqual((session.unloads, session.detaches), (1, 1))

    def test_malformed_racing_extra_and_late_frames_fail_closed(self) -> None:
        for mode in ("race_duplicate", "extra_frame", "late_on_unload",
                     "late_on_detach", "oversize", "error"):
            with self.subTest(mode=mode):
                manifest = loaded_manifest()
                session = FakeSession(manifest, mode)
                frida = FakeFrida(session)
                with self.assertRaises(runner.SnapshotRunnerError):
                    runner.run_snapshot(
                        manifest=manifest, observer_raw=observer_bytes(),
                        binding=binding(), adb=FakeAdb(), frida=frida,
                        evidence_provider=FakeEvidenceProvider())
                self.assertEqual(len(frida.attach_calls), 1)
                self.assertGreaterEqual(session.detaches, 1)

        manifest = loaded_manifest()
        delayed_session = FakeSession(manifest, "delayed_after_detach")
        with self.assertRaises(runner.SnapshotRunnerError):
            runner.run_snapshot(
                manifest=manifest, observer_raw=observer_bytes(), binding=binding(),
                adb=FakeAdb(), frida=FakeFrida(delayed_session),
                evidence_provider=FakeEvidenceProvider(after_delay=0.05))

    def test_cleanup_failure_is_fatal_but_postconditions_still_run(self) -> None:
        for mode in ("unload_failure", "detach_failure"):
            with self.subTest(mode=mode):
                manifest = loaded_manifest()
                session = FakeSession(manifest, mode)
                evidence = FakeEvidenceProvider()
                adb = FakeAdb()
                with self.assertRaisesRegex(runner.SnapshotRunnerError,
                                            "Frida cleanup failed"):
                    runner.run_snapshot(
                        manifest=manifest, observer_raw=observer_bytes(),
                        binding=binding(), adb=adb, frida=FakeFrida(session),
                        evidence_provider=evidence)
                self.assertEqual(evidence.phases, ["before", "after"])
                self.assertEqual(adb.stat_calls, 2)

    def test_target_death_or_pid_reuse_after_detach_is_fatal(self) -> None:
        for adb in (FakeAdb(second_start="987654322"),
                    FakeAdb(fail_second_stat=True)):
            with self.subTest(adb=adb):
                with self.assertRaisesRegex(runner.SnapshotRunnerError,
                                            "target PID/starttime is not live"):
                    run_with(adb=adb)

    def test_external_evidence_mismatch_or_detached_digest_is_fatal(self) -> None:
        providers = [
            FakeEvidenceProvider(mutate_phase="before"),
            *(FakeEvidenceProvider(mutate_phase="after", mutate_field=field)
              for field in ("apk", "module", "originalPdf", "mark",
                            "uriResolution")),
            FakeEvidenceProvider(malformed_digest=True),
            MutatingRequestEvidenceProvider(),
        ]
        for provider in providers:
            with self.subTest(provider=provider):
                with self.assertRaises(runner.SnapshotRunnerError):
                    run_with(evidence=provider)

    def test_invalid_binding_and_source_fail_before_adb_attach_or_evidence(self) -> None:
        invalid = [
            binding(serial="SN; shell rm"), binding(pid=0),
            binding(start_time_ticks="0"), binding(observer_session_id="short"),
            binding(observer_session_id=SESSION + ";rm"),
            binding(deadline_ms=249), binding(deadline_ms=10_001),
        ]
        for bad_binding in invalid:
            with self.subTest(binding=bad_binding):
                manifest = loaded_manifest()
                adb = FakeAdb()
                evidence = FakeEvidenceProvider()
                frida = FakeFrida(FakeSession(manifest))
                with self.assertRaises(runner.SnapshotRunnerError):
                    runner.run_snapshot(
                        manifest=manifest, observer_raw=observer_bytes(),
                        binding=bad_binding, adb=adb, frida=frida,
                        evidence_provider=evidence)
                self.assertEqual(adb.calls, [])
                self.assertEqual(frida.attach_calls, [])
                self.assertEqual(evidence.phases, [])
        manifest = loaded_manifest()
        adb = FakeAdb()
        with self.assertRaisesRegex(runner.SnapshotRunnerError,
                                    "observer source differs"):
            runner.run_snapshot(
                manifest=manifest, observer_raw=observer_bytes() + b"\n",
                binding=binding(), adb=adb,
                frida=FakeFrida(FakeSession(manifest)),
                evidence_provider=FakeEvidenceProvider())
        self.assertEqual(adb.calls, [])

    def test_missing_or_false_evidence_provider_admission_blocks_before_adb(self) -> None:
        class MissingAdmission:
            def capture(self, request: runner.EvidenceRequest) -> runner.AuthenticatedEvidence:
                raise AssertionError("capture must not run")

        class FalseAdmission(FakeEvidenceProvider):
            def admission(self) -> dict[str, object]:
                value = super().admission()
                value["captureMode"] = "manifest-echo"
                return value

        manifest = loaded_manifest()
        for provider in (MissingAdmission(), FalseAdmission()):
            with self.subTest(provider=provider):
                adb = FakeAdb()
                frida = FakeFrida(FakeSession(manifest))
                with self.assertRaises(runner.SnapshotRunnerError):
                    runner.run_snapshot(
                        manifest=manifest, observer_raw=observer_bytes(),
                        binding=binding(), adb=adb, frida=frida,
                        evidence_provider=provider)  # type: ignore[arg-type]
                self.assertEqual(adb.calls, [])
                self.assertEqual(frida.attach_calls, [])

    def test_attach_and_load_errors_are_not_retried_and_cleanup_when_possible(self) -> None:
        manifest = loaded_manifest()
        no_session = FakeSession(manifest)
        attach_failure = FakeFrida(no_session, attach_error=True)
        with self.assertRaises(runner.SnapshotRunnerError):
            runner.run_snapshot(
                manifest=manifest, observer_raw=observer_bytes(), binding=binding(),
                adb=FakeAdb(), frida=attach_failure,
                evidence_provider=FakeEvidenceProvider())
        self.assertEqual(len(attach_failure.attach_calls), 1)
        self.assertEqual((no_session.unloads, no_session.detaches), (0, 0))

        load_session = FakeSession(manifest, "load_error")
        load_failure = FakeFrida(load_session)
        with self.assertRaises(runner.SnapshotRunnerError):
            runner.run_snapshot(
                manifest=manifest, observer_raw=observer_bytes(), binding=binding(),
                adb=FakeAdb(), frida=load_failure,
                evidence_provider=FakeEvidenceProvider())
        self.assertEqual(len(load_failure.attach_calls), 1)
        self.assertEqual((load_session.unloads, load_session.detaches), (1, 1))


class CliAdmissionTests(unittest.TestCase):
    class _Output:
        def __init__(self) -> None:
            self.buffer = BytesIO()

        def write(self, value: str) -> int:
            return len(value)

        def flush(self) -> None:
            return None

    def test_production_cli_is_explicitly_blocked_without_evidence_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            adb_path = Path(directory) / "adb.exe"
            manifest_path.write_bytes(runner._canonical_json_bytes(manifest_value()))
            adb_path.write_bytes(b"not executed")
            output = self._Output()
            fake_adb = FakeAdb()
            with mock.patch.object(runner, "SubprocessAdbAdapter",
                                   return_value=fake_adb), \
                    mock.patch.object(runner.sys, "stdout", output):
                status = runner.main([
                    "--manifest", str(manifest_path),
                    "--observer-source", str(Path(__file__).with_name(
                        "native_page_snapshot.js")),
                    "--adb", str(adb_path), "--serial", SERIAL,
                    "--pid", str(PID), "--start-time-ticks", START,
                    "--observer-session-id", SESSION,
                    "--deadline-ms", str(DEADLINE),
                ])
        self.assertEqual(status, 2)
        self.assertEqual(fake_adb.calls, [])
        result = json.loads(output.buffer.getvalue())
        self.assertEqual(result, {
            "authority": runner.RUNNER_AUTHORITY,
            "reasonCode": runner.PRODUCTION_BLOCK_REASON,
            "status": "HARDWARE_ADMISSION_BLOCKED",
        })

    def test_cli_does_not_abbreviate_flags(self) -> None:
        with mock.patch.object(runner.sys, "stderr", StringIO()):
            with self.assertRaises(SystemExit):
                runner._parser().parse_args(["--man", "manifest.json"])


if __name__ == "__main__":
    unittest.main()
