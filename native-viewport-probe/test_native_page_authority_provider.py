"""Offline S7 tests: real frozen parsers/permits/S2 protocol, fake byte sources.

No device, network, shell, filesystem discovery, or production mutation occurs.
Only synthetic firmware pins are patched in memory; no file or evidence pin is
changed. The independent frozen runner fixture reads its exact observer source.
"""
from dataclasses import asdict, replace
import copy
import hashlib
import hmac
import threading
import unittest
from unittest import mock

import native_page_authority_provider as s
import native_page_coordinator_contracts as c
import native_page_graph_v2_runner as r
import native_page_host_authority as h
import native_page_isolated_ipc as ipc
import native_page_pen_peer as p
from native_page_cleanup_ledger import ResourceIdentity
import test_native_page_android_authority as task_fixture
import test_native_page_graph_v2_runner as runner_fixture
import test_native_page_isolated_ipc as ipc_fixture


SESSION = "a" * 64
BOOT = "11111111-2222-4333-8444-555555555555"
KEY = b"K" * 32
BYTES = {"apk": b"independent apk bytes", "framework": b"independent framework bytes",
         "module": b"independent module bytes", "pdf": b"%PDF-independent-original",
         "mark": b"independent saved ink"}


def sha(value):
    return hashlib.sha256(value if type(value) is bytes else value.encode()).hexdigest()


def raw(value):
    return r.canonical_bytes(value)


def remac_stability(value):
    # Independent test oracle, deliberately not the production witness helper.
    witness = s._json(value["stability"].encode())
    witness["captureSha256"], witness["receiptSha256"] = sha(value["record"]), sha(value["receipt"])
    witness.pop("authenticator")
    witness["authenticator"] = hmac.new(KEY, raw(witness), hashlib.sha256).hexdigest()
    value["stability"] = raw(witness).decode()


class IndependentDevice:
    """Synthetic read-only device state; never refers to a manifest or request.

    Expected manifests may be provisioned from this fixture's initial state, but
    subsequent acquisition is from these independently mutable byte/stat/URI
    stores. It cannot repair a mismatch by consulting the expected authority.
    """
    def __init__(self):
        self.contents = dict(BYTES)
        self.paths = dict(apk="/data/app/document/base.apk", framework="/system/framework/framework.jar",
                          module="/apex/runtime/lib64/libart.so", pdf="/storage/emulated/0/Document/graph-v2.pdf",
                          mark="/storage/emulated/0/Document/graph-v2.pdf.mark")
        self.stat_before = {role: {"device": "17", "inode": str(50100 + index), "mode": "33188",
            "uid": 1000, "gid": 1000, "mtimeNs": "1700000000000000000", "ctimeNs": "1700000000000000001"}
            for index, role in enumerate(BYTES)}
        self.stat_after = copy.deepcopy(self.stat_before)
        self.uri_transcript = b"read-only resolver: file URI -> retained original PDF slot"
        self.uri = {"authority": "rtl-reader-file-uri-resolution-v1",
                    "documentUri": "file://" + self.paths["pdf"], "resolvedPath": self.paths["pdf"],
                    "evidenceSha256": sha(self.uri_transcript)}


class Source:
    def __init__(self, fixture, name):
        self.fixture, self.name = fixture, name
        self.reads = []
        self.changed = False
        self.mutate = lambda operation, selector, evidence: evidence
        self.descriptor = dict(authority=s.S1C_AUTHORITY if name == "device_read" else "test-retained-" + name,
            session=SESSION, resource=ResourceIdentity("source", "test-only", name, "retained-1").wire(),
            readOnly=True, operations=list(s.S1C_OPERATIONS) if name == "device_read" else [])

    def verify(self):
        if self.changed:
            raise RuntimeError("independent retained source was replaced")

    def canonical_bytes(self):
        return raw(self.descriptor)

    def read(self, operation, selector, challenge, deadline_ns):
        self.reads.append((operation, copy.deepcopy(selector), challenge))
        value = self.fixture.acquire(operation, selector)
        self.fixture.capture_counter += 1
        evidence = s.ReadEvidence(challenge, sha("source-acquisition-" + str(self.fixture.capture_counter)),
                                  self.fixture.clock(), value)
        return self.mutate(operation, selector, evidence)


class Fixture:
    def __init__(self, *, mark=True, stage_index=0):
        self.clock = runner_fixture.Clock()
        stage = c.STAGE_LAYOUTS[stage_index]
        self.bound = replace(runner_fixture.binding(self.clock), observer_session_id=SESSION, stage=stage[2])
        self.bundle = runner_fixture.FakeBundle()
        self.image = ipc_fixture.Image()
        self.capture_counter = 0
        self.pen_sequence = 0
        self.frida_torn_down = False
        self.device = IndependentDevice()
        self.contents = self.device.contents
        self.mark = mark
        manifest = runner_fixture.manifest_value(self.bound, mark=mark)
        manifest["externalSession"]["displayGeneration"] = 1
        for role in ("apk", "framework", "module"):
            manifest["attachment"][role].update(size=len(self.contents[role]), sha256=sha(self.contents[role]))
        for role, name in (("pdf", "originalPdf"), ("mark", "mark")):
            if role == "mark" and not mark:
                continue
            manifest["files"][name].update(size=str(len(self.contents[role])), sha256=sha(self.contents[role]),
                                           stat=copy.deepcopy(self.device.stat_before[role]))
        manifest["files"]["originalPdf"]["uriResolution"] = copy.deepcopy(self.device.uri)
        self.manifest = r.load_canonical(raw(manifest), r.MAX_MANIFEST_BYTES)
        self.identities = {role: ResourceIdentity("file", c.AUTHORIZED_SERIAL, "file:" + role, "inode-" + role)
                           for role in BYTES}
        fixtures = dict(pdf=dict(identity=self.identities["pdf"].wire(), sha256=sha(self.contents["pdf"]), size=len(self.contents["pdf"])),
                        mark=(dict(identity=self.identities["mark"].wire(), sha256=sha(self.contents["mark"]), size=len(self.contents["mark"]))
                              if mark else None), savedInkSha256=sha("saved-ink"), uriResolutionSha256=sha("uri-resolution"))
        self.contract = c.RunContract.create(run_session_id=SESSION,
            host_session_id=manifest["externalSession"]["hostSessionId"],
            created=c.HostInstant("test-host-clock-0001", self.clock()),
            deadline=c.HostInstant("test-host-clock-0001", self.clock() + 10000000000), fixtures=fixtures)
        self.sources = tuple((name, Source(self, name)) for name in s.SOURCE_NAMES)
        self.source = dict(self.sources)
        self.tool = r.load_canonical(self.bundle.canonical_bytes(), r.MAX_AUTHORITY_BYTES)
        self.task_raw = task_fixture.wire(pid=self.bound.pid, task_id=4538, display_id=7).replace(b"4538", b"41").replace(
            b"/system_ext/app/SupernoteDocument/SupernoteDocument.apk", manifest["attachment"]["apk"]["path"].encode())
        self.task = s.android.parse_document_task_authority(self.task_raw, expected_pid=self.bound.pid)
        self.template = runner_fixture.stage_value(self.manifest, self.bound, self.tool.sha256, "before", self.task)
        self.server = copy.deepcopy(self.template["privateAdbServer"])
        self.frida = copy.deepcopy(self.template["frida"])
        self.frida["providerSessionId"] = SESSION
        self.template["providerSessionId"] = SESSION
        self.template["frida"] = copy.deepcopy(self.frida)
        host_process = h.ProcessIdentity(700, 901, 10000, h.HOST_PACKAGE)
        frame = h.Rect(*stage[5])
        root_frame = h.Rect(0, 0, *stage[4])
        activity = h.ActivityRecord(host_process, 52, h.HOST_COMPONENT, "f00d", 0, True, True)
        window = h.WindowRecord(host_process, 52, "f00d", 0, root_frame, True, True, frame, (1404, 1872))
        display = h.DisplayRecord(7, host_process, "NativePageVisualOnly-" + manifest["externalSession"]["hostSessionId"] + "-1", 1404, 1872, 300,
                                  frozenset(("PUBLIC", "OWN_CONTENT_ONLY", "DESTROY_CONTENT_ON_REMOVAL")))
        target = h.ProcessIdentity(self.bound.pid, int(self.bound.start_time_ticks), 1000, r.PACKAGE_NAME)
        foreign = h.ActivityRecord(target, self.task.task_id, h.FOREIGN_COMPONENT, self.task.activity_token, 7, True, True)
        foreign_window = h.WindowRecord(target, self.task.task_id, self.task.activity_token, 7, h.Rect(0, 0, 1404, 1872), True, True)
        physical = h.DisplayRecord(0, None, "physical", *stage[4], 300, frozenset())
        self.snapshot = h.Snapshot(self.clock(), h.PINNED_PACKAGE, (host_process, target), (activity, foreign),
                                   (window, foreign_window), (physical, display),
                                   sha("am"), sha("window"), sha("display"), sha("process"))
        placement = h.Placement(stage[2])
        self.placement = h.AppliedPlacement(manifest["externalSession"]["hostSessionId"], 1, 7, 12,
                                            placement, placement, frame)
        self.host_event = h.HostEvent(1, self.clock(), host_process, self.placement.session, 1, "PLACEMENT_READY",
                                     dict(sequence=12, requested=stage[2], effective=stage[2], rect=frame.wire()))
        self.template["host"].update(hostPackageName=h.HOST_PACKAGE, hostApkSha256=h.APK_SHA256,
                                     hostActivityToken="f00d", requestedFrame=frame.wire(), measuredGlobalFrame=frame.wire())
        self.pen_binding = p.LeaseBinding(p.StageSession(SESSION), sha("actual lease"), p.ProcessIdentity(400, 10400),
                                          p.ProcessIdentity(401, 10401), p.ProcessIdentity(402, 10402), sha("guardian"), 50000)
        self.template["penLease"].update(leaseId=self.pen_binding.token, helperPid=401, helperStartTimeTicks="10401",
                                         remainingLeaseMs=48999)
        frida_admission = runner_fixture.frida_admission_value()
        frida_admission["providerSessionId"] = SESSION
        self.config = s.Configuration(self.contract, stage_index, self.bound, self.manifest.raw, self.tool.raw, raw(frida_admission),
            sha("reviewed candidate bytes"), sha(self.image.canonical_bytes()), r.stage_policy_sha256(self.template),
            tuple((name, sha(source.canonical_bytes())) for name, source in self.sources), KEY)

    def acquire(self, operation, selector):
        if operation is s.Read.SERVER:
            return raw(self.server)
        if operation is s.Read.TOOL:
            return self.bundle.canonical_bytes()
        if operation is s.Read.PROCESS:
            fields = ["1"] * 19
            fields[18] = self.bound.start_time_ticks
            return s.ProcessRead((str(selector["pid"]) + " (document) R " + " ".join(fields) + "\n").encode(),
                                  r.PACKAGE_NAME.encode() + b"\x00", BOOT)
        if operation is s.Read.FINGERPRINT:
            return (r.FIRMWARE_FINGERPRINT + "\n").encode()
        if operation is s.Read.FILE:
            role = selector["role"]
            if selector["path"] != self.device.paths[role]:
                raise RuntimeError("independent retained device path differs")
            if role == "mark" and not self.mark:
                return s.FileRead(self.device.paths[role], self.identities[role], False, None, None, None, b"captured-exact-absence")
            return s.FileRead(self.device.paths[role], self.identities[role], True, self.contents[role],
                              raw(self.device.stat_before[role]), raw(self.device.stat_after[role]))
        if operation is s.Read.URI:
            return raw(self.device.uri)
        if operation is s.Read.TASK:
            return self.task_raw
        if operation is s.Read.HOST:
            return s.HostRead(replace(self.snapshot, captured_ns=self.clock()), self.placement, self.host_event)
        if operation is s.Read.PEN:
            self.pen_sequence += 1
            now = 1000 + self.pen_sequence
            return p.CaptureLease(self.pen_binding, self.pen_sequence, now, self.pen_binding.deadline_boottime_ms - now)
        if operation is s.Read.FRIDA:
            value = copy.deepcopy(self.frida)
            if self.frida_torn_down:
                value.update(serverState="torn-down", processAbsent=True, fileAbsent=True,
                             teardownOfSessionId=value["serverSessionId"])
            return raw(value)
        if operation is s.Read.LEDGER:
            return raw(dict(runSessionId=SESSION, checkpointSha256=sha("retained-checkpoint")))
        raise AssertionError("unreviewed operation")

    def engine(self):
        return s.AuthorityEngine(self.config, self.sources, self.clock)

    def request(self, phase="before", previous=None):
        return r.AuthorityRequest(phase, self.manifest.sha256, self.bound, self.bound.absolute_deadline_ns,
                                  self.tool.sha256, "e" * 64, 1 if phase == "before" else 2, previous)

    def admit_engine(self, engine):
        return engine.dispatch("authority_admission", {"configurationSha256": engine.configuration_sha256()},
                               self.bound.absolute_deadline_ns)

    def capture_engine(self, engine, phase="before", previous=None):
        if phase == "after":
            self.frida_torn_down = True
        return engine.dispatch("authority_capture", s._request_wire(self.request(phase, previous)),
                               self.bound.absolute_deadline_ns)


class Runtime(ipc_fixture.FakeRuntime):
    """Fake retained process kernel + REAL S2 registration and S7 dispatcher."""
    def __init__(self, fixture):
        super().__init__()
        self.fixture = fixture
        self.mutate_result = lambda operation, value: value
        self.dispatches = []

    def now_ns(self):
        return self.fixture.clock()

    def sleep_ns(self, amount):
        self.fixture.clock.set(self.now_ns() + amount)

    def launch_suspended(self, image, session):
        result = super().launch_suspended(image, session)
        self.channel.registry = ipc.WorkerRegistry(session, image.role,
            frozenset(("authority_admission", "authority_capture")), self.now_ns, self.verify_operation_quiescent)
        self.engine = self.fixture.engine()
        return result

    def finish(self):
        if self.on_finish:
            self.on_finish(self)
        if not self.worker.live:
            raise ipc.IpcError("fake contained worker was killed; no late dispatch")
        operation_id = self.pending
        self.pending = None
        registered = self.channel.registry.operations[operation_id]
        self.dispatches.append(registered["operation"])
        value = self.engine.dispatch(registered["operation"], registered["payload"], registered["deadline_ns"])
        value = self.mutate_result(registered["operation"], value)
        for callback in self.callbacks:
            self.emit(self.channel.registry.callback(operation_id, callback))
        self.active.discard(operation_id)
        reply = self.channel.registry.complete(operation_id, value)
        self.emit(reply)
        if self.duplicate_result:
            self.emit(reply)
        stream = self.reply_by_sequence[reply["seq"]]
        stream.output.extend(self.trailing_result)
        stream.eof = not self.missing_eof


class Tests(unittest.TestCase):
    def setUp(self):
        self.patches = [mock.patch.multiple(r, APK_SHA256=sha(BYTES["apk"]), APK_SIZE=len(BYTES["apk"]),
                                           FRAMEWORK_SHA256=sha(BYTES["framework"]), FRAMEWORK_SIZE=len(BYTES["framework"])),
                        mock.patch.multiple(c, APK_SHA256=sha(BYTES["apk"]), FRAMEWORK_SHA256=sha(BYTES["framework"]))]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def provider(self, fixture=None):
        fixture = fixture or Fixture()
        runtime = Runtime(fixture)
        provider = s.AuthorityProvider(fixture.config, lambda: ipc.IsolatedWorker(fixture.image, runtime, SESSION))
        self.addCleanup(provider.fail_stop_and_quiesce, 250)
        return fixture, runtime, provider

    def permit(self, fixture):
        return r.OperationStartPermit(fixture.bound.absolute_deadline_ns, fixture.clock, r.AuthorityProviderQuiescenceFailure)

    def assert_closed(self, runtime, provider):
        self.assertEqual(provider._state, "CLOSED")
        self.assertFalse(provider._thread.is_alive())
        self.assertTrue(all(item.killed and item.joined and item.closed and not item.live for item in runtime.processes))
        self.assertFalse(provider.cleanup_obligations)

    def logical_clock_transport(self, provider):
        # Boundary tests advance the injected host clock by exact nanoseconds.
        # Allow the fake worker 250ms of real CPU scheduling, without changing
        # the production call budget or the actual S2 absolute RPC deadline.
        # This deliberately does NOT establish a 25ms hardware timing result.
        original = provider._submit
        def submit(action, arguments, milliseconds):
            self.assertLessEqual(milliseconds, 25)
            return original(action, arguments, 250)
        return mock.patch.object(provider, "_submit", side_effect=submit)

    def test_independent_raw_capture_and_exact_hmac_chain(self):
        fixture = Fixture()
        engine = fixture.engine()
        fixture.admit_engine(engine)
        before = fixture.capture_engine(engine)
        after = fixture.capture_engine(engine, "after", sha(before["receipt"]))
        self.assertNotEqual(s._json(before["record"].encode())["captureId"], s._json(after["record"].encode())["captureId"])
        self.assertEqual(s._json(before["record"].encode())["files"]["originalPdf"]["sha256"], sha(BYTES["pdf"]))
        for source in fixture.source.values():
            for _, selector, _ in source.reads:
                self.assertFalse(any("sha" in key.lower() or "manifest" in key.lower() for key in selector))
        self.assertNotIn(KEY.hex(), before["receipt"] + before["record"])
        self.assertEqual(s._json(after["receipt"].encode())["previousReceiptSha256"], sha(before["receipt"]))

    def test_facade_uses_exact_single_worker_and_real_start_permits(self):
        fixture, runtime, provider = self.provider()
        permit = self.permit(fixture)
        provider.admission(250, permit)
        permit.require_exact_start(r.AuthorityProviderQuiescenceFailure)
        before = provider.capture(fixture.request(), 250, self.permit(fixture))
        fixture.frida_torn_down = True
        after = provider.capture(fixture.request("after", before.receipt.sha256), 250, self.permit(fixture))
        provider.assert_quiescent(25)
        self.assertEqual(len(runtime.processes), 1)
        self.assertEqual(runtime.dispatches, ["authority_admission", "authority_capture", "authority_capture"])
        self.assertEqual(r._authority(after.receipt).value["sequence"], 2)
        provider.fail_stop_and_quiesce(250)
        self.assert_closed(runtime, provider)

    def test_manifest_echo_is_not_used_to_repair_mismatching_bytes(self):
        for role in BYTES:
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            fixture.contents[role] += b"substituted after trusted plan"
            with self.subTest(role=role), self.assertRaises(Exception):
                fixture.capture_engine(engine)
            self.assertEqual(engine._state, "SEALED")

    def test_every_server_and_frida_field_substitution_rejected(self):
        for section in ("server", "frida"):
            baseline = getattr(Fixture(), section)
            for key, value in baseline.items():
                fixture = Fixture()
                engine = fixture.engine()
                fixture.admit_engine(engine)
                wrong = not value if type(value) is bool else value + 1 if type(value) is int else (
                    "substituted" if type(value) is str else ["substituted"] if type(value) is list else "not-null")
                getattr(fixture, section)[key] = wrong
                with self.subTest(section=section, field=key), self.assertRaises(Exception):
                    fixture.capture_engine(engine)

    def test_each_raw_read_cannot_be_replaced_with_manifest_or_foreign_reference(self):
        operations = tuple(s.Read)
        for operation in operations:
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            for source in fixture.source.values():
                source.mutate = lambda op, selector, evidence, operation=operation: (
                    replace(evidence, payload=fixture.manifest.value) if op is operation else evidence)
            with self.subTest(operation=operation), self.assertRaises(Exception):
                fixture.capture_engine(engine)

    def test_stale_capture_challenge_and_capture_id_replay(self):
        for kind in ("stale", "future", "challenge", "duplicate"):
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            saved = []
            def mutate(op, selector, evidence):
                if kind == "stale": return replace(evidence, captured_ns=fixture.clock() - 1)
                if kind == "future": return replace(evidence, captured_ns=fixture.clock() + 1)
                if kind == "challenge": return replace(evidence, challenge="0" * 64)
                if not saved: saved.append(evidence.capture_id)
                return replace(evidence, capture_id=saved[0])
            fixture.source["device_read"].mutate = mutate
            with self.subTest(kind=kind), self.assertRaises(Exception): fixture.capture_engine(engine)

    def test_before_after_source_and_file_identity_replacement(self):
        for name in s.SOURCE_NAMES:
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            before = fixture.capture_engine(engine)
            fixture.source[name].changed = True
            with self.subTest(source=name), self.assertRaises(Exception):
                fixture.capture_engine(engine, "after", sha(before["receipt"]))
        for role in BYTES:
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            before = fixture.capture_engine(engine)
            fixture.identities[role] = replace(fixture.identities[role], incarnation="new-inode")
            with self.subTest(file=role), self.assertRaises(Exception):
                fixture.capture_engine(engine, "after", sha(before["receipt"]))

    def test_nullable_mark_requires_fresh_absence_and_rejects_late_creation(self):
        fixture = Fixture(mark=False)
        engine = fixture.engine()
        fixture.admit_engine(engine)
        before = fixture.capture_engine(engine)
        self.assertFalse(s._json(before["record"].encode())["files"]["mark"]["present"])
        fixture.mark = True
        with self.assertRaises(Exception): fixture.capture_engine(engine, "after", sha(before["receipt"]))

    def test_pid_task_host_display_and_pen_drift(self):
        for kind in ("pid", "cmdline", "boot", "task", "display", "ack", "frame", "pen", "pen-replay"):
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            before = fixture.capture_engine(engine)
            if kind in ("pid", "cmdline", "boot"):
                def mutate(op, selector, evidence):
                    if op is not s.Read.PROCESS: return evidence
                    value = evidence.payload
                    if kind == "pid": value = replace(value, stat_bytes=value.stat_bytes.replace(b"3141", b"3142", 1))
                    if kind == "cmdline": value = replace(value, cmdline_bytes=b"other\x00")
                    if kind == "boot": value = replace(value, boot_id="aaaaaaaa-2222-4333-8444-555555555555")
                    return replace(evidence, payload=value)
                fixture.source["device_read"].mutate = mutate
            elif kind == "task": fixture.task_raw = fixture.task_raw.replace(b"11846f4", b"11846f5")
            elif kind == "display": fixture.snapshot = replace(fixture.snapshot, displays=(replace(fixture.snapshot.displays[0], display_id=8),))
            elif kind == "ack": fixture.host_event.body["sequence"] += 1
            elif kind == "frame": fixture.placement = replace(fixture.placement, rect=h.Rect(1, 0, 1404, 1872))
            elif kind == "pen": fixture.pen_binding = replace(fixture.pen_binding, guardian=p.ProcessIdentity(403, 10403))
            elif kind == "pen-replay": fixture.pen_sequence = 0
            with self.subTest(kind=kind), self.assertRaises(Exception): fixture.capture_engine(engine, "after", sha(before["receipt"]))

    def test_receipt_each_field_mac_key_and_capture_substitution_fences_worker(self):
        fixture = Fixture()
        engine = fixture.engine()
        fixture.admit_engine(engine)
        baseline = s._json(fixture.capture_engine(engine)["receipt"].encode())
        for field in baseline:
            fixture, runtime, provider = self.provider()
            provider.admission(250, self.permit(fixture))
            def mutate(operation, value):
                if operation == "authority_capture":
                    receipt = s._json(value["receipt"].encode())
                    old = receipt[field]
                    receipt[field] = old + 1 if type(old) is int else "f" * 64
                    value["receipt"] = raw(receipt).decode()
                return value
            runtime.mutate_result = mutate
            with self.subTest(field=field), self.assertRaises(Exception):
                provider.capture(fixture.request(), 250, self.permit(fixture))
            self.assert_closed(runtime, provider)

    def test_channel_partial_trailing_replay_callback_and_hang_are_killed_joined(self):
        for mode in ("duplicate_result", "missing_eof", "block_registration", "block_operation", "trailing", "callback"):
            fixture, runtime, provider = self.provider()
            provider.admission(250, self.permit(fixture))
            if mode == "trailing": runtime.trailing_result = b"x"
            elif mode == "callback": runtime.callbacks = [{"forbidden": "foreign reference"}]
            else: setattr(runtime, mode, True)
            with self.subTest(mode=mode), self.assertRaises(Exception):
                provider.capture(fixture.request(), 100, self.permit(fixture))
            self.assert_closed(runtime, provider)

    def test_expired_foreign_reused_permit_cannot_start_source_work(self):
        fixture, runtime, provider = self.provider()
        permit = self.permit(fixture)
        permit.expire()
        with self.assertRaises(Exception): provider.admission(250, permit)
        self.assertEqual(runtime.external_starts, 0)
        self.assert_closed(runtime, provider)
        fixture, runtime, provider = self.provider()
        permit = self.permit(fixture)
        errors = []
        def foreign():
            try: provider.admission(250, permit)
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=foreign)
        thread.start(); thread.join(2)
        self.assertTrue(errors)
        self.assertEqual(runtime.external_starts, 0)
        self.assert_closed(runtime, provider)

    def test_cancel_and_post_terminal_use_never_reopens_worker(self):
        fixture, runtime, provider = self.provider()
        provider.admission(250, self.permit(fixture))
        provider.cancel_and_quiesce(250)
        with self.assertRaises(Exception): provider.capture(fixture.request(), 250, self.permit(fixture))
        self.assert_closed(runtime, provider)
        self.assertEqual(runtime.external_starts, 1)

    def test_deadline_crossed_in_final_source_verification_cannot_publish(self):
        fixture = Fixture()
        engine = fixture.engine()
        fixture.admit_engine(engine)
        source = fixture.source["pen"]
        def late(op, selector, evidence):
            fixture.clock.set(fixture.bound.absolute_deadline_ns)
            return evidence
        source.mutate = late
        with self.assertRaises(Exception): fixture.capture_engine(engine)
        self.assertEqual(engine._state, "SEALED")

    def test_frozen_runner_integration_with_independent_sources(self):
        fixture, runtime, provider = self.provider()
        frida = runner_fixture.FakeFrida(fixture.manifest)
        frida.admission_record = r.CanonicalAuthority(fixture.config.frida_admission_raw, sha(fixture.config.frida_admission_raw))
        old_teardown = frida.teardown
        def teardown(timeout_ms):
            old_teardown(timeout_ms)
            fixture.frida_torn_down = True
        frida.teardown = teardown
        result = r.run_one_stage(manifest=fixture.manifest, observer_source=runner_fixture.OBSERVER_TEXT,
            observer_sha256=runner_fixture.OBSERVER_SHA, binding=fixture.bound, tool_bundle=fixture.bundle,
            authority_provider=provider, frida_provider=frida, trusted_pins=fixture.config.pins,
            ambient_environment={}, clock_ns=fixture.clock, nonce_factory=lambda: "e" * 64)
        self.assertIsNotNone(result)
        self.assertEqual(runtime.dispatches.count("authority_capture"), 2)
        provider.fail_stop_and_quiesce(250)
        self.assert_closed(runtime, provider)

    def test_all_four_indexed_s0_s3_layouts_use_surface_not_root_frame(self):
        for index in range(4):
            fixture = Fixture(stage_index=index)
            engine = fixture.engine()
            fixture.admit_engine(engine)
            before = fixture.capture_engine(engine)
            record = s._json(before["record"].encode())
            self.assertEqual(record["host"]["measuredGlobalFrame"], list(c.STAGE_LAYOUTS[index][5]))
            after = fixture.capture_engine(engine, "after", sha(before["receipt"]))
            self.assertEqual(s._json(after["record"].encode())["host"]["stage"], c.STAGE_LAYOUTS[index][2])

    def test_every_capture_and_task_leaf_substitution_rejected_even_with_valid_mac(self):
        fixture = Fixture()
        engine = fixture.engine()
        fixture.admit_engine(engine)
        baseline = fixture.capture_engine(engine)
        def leaves(value, path=()):
            if type(value) is dict:
                for key, child in value.items(): yield from leaves(child, path + (key,))
            elif type(value) is list:
                for index, child in enumerate(value): yield from leaves(child, path + (index,))
            else:
                yield path
        count = 0
        for container in ("record", "task"):
            paths = tuple(leaves(s._json(baseline[container].encode())))
            for path in paths:
                fixture, runtime, provider = self.provider()
                provider.admission(250, self.permit(fixture))
                def mutate(operation, value):
                    if operation != "authority_capture": return value
                    item = s._json(value[container].encode())
                    parent = item
                    for key in path[:-1]: parent = parent[key]
                    old = parent[path[-1]]
                    parent[path[-1]] = "invalid-null-substitution" if old is None else None
                    value[container] = raw(item).decode()
                    if container == "task":
                        record = s._json(value["record"].encode())
                        record["taskAuthoritySha256"] = sha(value["task"])
                        value["record"] = raw(record).decode()
                    receipt = s._json(value["receipt"].encode())
                    receipt["captureSha256"] = sha(value["record"])
                    receipt.pop("authenticator")
                    receipt["authenticator"] = hmac.new(KEY, raw(receipt), hashlib.sha256).hexdigest()
                    value["receipt"] = raw(receipt).decode()
                    remac_stability(value)
                    return value
                runtime.mutate_result = mutate
                with self.subTest(container=container, path=path), self.assertRaises(Exception):
                    provider.capture(fixture.request(), 250, self.permit(fixture))
                self.assert_closed(runtime, provider)
                count += 1
        self.assertGreater(count, 100)

    def test_file_stat_type_content_and_uri_proofs_are_independent(self):
        for kind in ("stat-change", "not-regular", "stat-replaced", "uri-path", "uri-proof", "absence"):
            fixture = Fixture(mark=kind != "absence")
            engine = fixture.engine()
            fixture.admit_engine(engine)
            def mutate(op, selector, evidence):
                value = evidence.payload
                if op is s.Read.FILE and selector["role"] == "pdf" and kind in ("stat-change", "not-regular", "stat-replaced"):
                    metadata = s._json(value.stat_after)
                    metadata["mode" if kind == "not-regular" else "inode"] = "41471" if kind == "not-regular" else "999999"
                    value = replace(value, stat_after=raw(metadata))
                    if kind != "stat-change": value = replace(value, stat_before=raw(metadata))
                if op is s.Read.FILE and selector["role"] == "mark" and kind == "absence":
                    value = replace(value, absence_proof=None)
                if op is s.Read.URI and kind in ("uri-path", "uri-proof"):
                    uri = s._json(value)
                    uri["resolvedPath" if kind == "uri-path" else "evidenceSha256"] = "/different" if kind == "uri-path" else "f" * 64
                    value = raw(uri)
                return replace(evidence, payload=value)
            fixture.source["device_read"].mutate = mutate
            with self.subTest(kind=kind), self.assertRaises(Exception): fixture.capture_engine(engine)

    def test_request_chain_and_capture_id_replay_are_rejected_without_new_sources(self):
        for kind in ("before-replay", "wrong-nonce", "wrong-previous", "after-first", "boolean-sequence", "capture-id"):
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            before = None if kind == "after-first" else fixture.capture_engine(engine)
            if kind == "before-replay": request = fixture.request()
            else:
                request = fixture.request("after", sha(before["receipt"]) if before else "a" * 64)
            if kind == "wrong-nonce": request = replace(request, run_nonce="f" * 64)
            if kind == "wrong-previous": request = replace(request, previous_receipt_sha256="f" * 64)
            if kind == "boolean-sequence": request = replace(request, sequence=True)
            if kind == "capture-id":
                reused = s._json(before["record"].encode())["captureId"]
                def after_last_source(operation, selector, evidence):
                    engine._nonce = lambda: reused
                    return evidence
                fixture.source["pen"].mutate = after_last_source
            fixture.frida_torn_down = True
            with self.subTest(kind=kind), self.assertRaises(Exception):
                engine.dispatch("authority_capture", s._request_wire(request), fixture.bound.absolute_deadline_ns)

    def test_configuration_and_returned_wrappers_detach_caller_references(self):
        fixture, runtime, provider = self.provider()
        provider.admission(250, self.permit(fixture))
        before = provider.capture(fixture.request(), 250, self.permit(fixture))
        original = provider._before.task.pid
        object.__setattr__(before.task, "pid", 999)
        self.assertEqual(provider._before.task.pid, original)
        self.assertEqual(runtime.engine._before.task.pid, original)
        object.__setattr__(fixture.config.binding, "pid", 999)
        self.assertEqual(provider.config.binding.pid, original)
        self.assertEqual(runtime.engine.config.binding.pid, original)

    def test_concurrent_registration_and_source_hang_cancel_never_dispatch_late(self):
        for mode in ("registration", "operation"):
            fixture, runtime, provider = self.provider()
            provider.admission(250, self.permit(fixture))
            entered, released = threading.Event(), threading.Event()
            def hold(rt):
                entered.set()
                if not released.wait(1): raise AssertionError("test hang was not canceled")
            if mode == "registration": runtime.on_register = hold
            else: runtime.on_finish = hold
            runtime.on_terminate = lambda rt, process: released.set()
            errors = []
            def stop():
                try:
                    if not entered.wait(1): raise AssertionError("operation never entered")
                    provider.cancel_and_quiesce(250)
                except Exception as error:
                    errors.append(error)
            stopper = threading.Thread(target=stop)
            stopper.start()
            with self.assertRaises(Exception): provider.capture(fixture.request(), 250, self.permit(fixture))
            stopper.join(2)
            self.assertFalse(stopper.is_alive())
            self.assertFalse(errors)
            self.assert_closed(runtime, provider)
            self.assertEqual(runtime.dispatches, ["authority_admission"])

    def test_s1c_selectors_are_explicit_read_only_and_never_expand_clean_s1(self):
        import native_page_private_adb as s1
        before = tuple((entry.command_id, entry.argv) for entry in s1.REFERENCE_COMMANDS)
        plan = s.s1c_read_plan(Fixture().config)
        self.assertEqual(plan["process"]["statPath"], "/proc/3141/stat")
        self.assertEqual(plan["buildProperty"], "ro.build.fingerprint")
        self.assertEqual(plan["deviceClock"], "CLOCK_BOOTTIME")
        self.assertEqual(len(plan["retainedFiles"]), 5)
        self.assertTrue(plan["fileReadPolicy"]["readOnly"])
        self.assertEqual(before, tuple((entry.command_id, entry.argv) for entry in s1.REFERENCE_COMMANDS))

    def test_coherent_host_process_replacement_is_not_new_authority(self):
        for field in ("pid", "start_ticks", "uid"):
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            before = fixture.capture_engine(engine)
            old = fixture.host_event.producer
            replacement = replace(old, **{field: getattr(old, field) + 1})
            snap = fixture.snapshot
            fixture.snapshot = replace(snap,
                processes=tuple(replacement if item == old else item for item in snap.processes),
                activities=tuple(replace(item, process=replacement) if item.process == old else item for item in snap.activities),
                windows=tuple(replace(item, process=replacement) if item.process == old else item for item in snap.windows),
                displays=tuple(replace(item, owner=replacement) if item.owner == old else item for item in snap.displays))
            fixture.host_event = replace(fixture.host_event, producer=replacement)
            # All fresh AM/window/display/event identities agree with each other.
            # Only the retained first-capture identity distinguishes replacement.
            with self.subTest(field=field), self.assertRaisesRegex(Exception, "retained S3 host process"):
                fixture.capture_engine(engine, "after", sha(before["receipt"]))
            self.assertEqual(engine._state, "SEALED")
            self.assertEqual(engine._host_identity, asdict(old))

    def test_host_stability_witness_mac_binding_replay_and_facade_retention(self):
        for mode in ("mac", "domain", "record", "receipt", "process-type", "process-replaced", "replay"):
            fixture, runtime, provider = self.provider()
            provider.admission(250, self.permit(fixture))
            captured = []
            def save(operation, value):
                if operation == "authority_capture": captured.append(copy.deepcopy(value))
                return value
            runtime.mutate_result = save
            before = provider.capture(fixture.request(), 250, self.permit(fixture))
            fixture.frida_torn_down = True
            def mutate(operation, value):
                if operation != "authority_capture": return value
                witness = s._json(value["stability"].encode())
                if mode == "mac": witness["authenticator"] = "f" * 64
                elif mode == "domain": witness["authority"] = "another-authority"
                elif mode == "record": witness["captureSha256"] = "f" * 64
                elif mode == "receipt": witness["receiptSha256"] = "f" * 64
                elif mode == "process-type": witness["hostProcess"]["pid"] = True
                elif mode == "process-replaced": witness["hostProcess"]["start_ticks"] += 1
                if mode not in ("mac", "replay"):
                    witness.pop("authenticator")
                    witness["authenticator"] = hmac.new(KEY, raw(witness), hashlib.sha256).hexdigest()
                value["stability"] = captured[0]["stability"] if mode == "replay" else raw(witness).decode()
                return value
            runtime.mutate_result = mutate
            with self.subTest(mode=mode), self.assertRaises(Exception):
                provider.capture(fixture.request("after", before.receipt.sha256), 250, self.permit(fixture))
            self.assertEqual(provider._host_identity, asdict(fixture.host_event.producer))
            self.assert_closed(runtime, provider)

    def test_pen_acquisition_invalidating_any_retained_source_cannot_publish(self):
        for name in s.SOURCE_NAMES:
            for mode in ("handle", "descriptor", "object"):
                fixture = Fixture()
                engine = fixture.engine()
                fixture.admit_engine(engine)
                def invalidate(operation, selector, evidence):
                    if mode == "handle": fixture.source[name].changed = True
                    elif mode == "descriptor":
                        fixture.source[name].descriptor["resource"]["incarnation"] = "replacement-2"
                    else: engine._sources[name] = Source(fixture, name)
                    return evidence
                fixture.source["pen"].mutate = invalidate
                with self.subTest(source=name, mode=mode), self.assertRaises(Exception):
                    fixture.capture_engine(engine)
                self.assertEqual(engine._state, "SEALED")
                self.assertIsNone(engine._before)
                self.assertEqual(engine._sequence, 0)

    def test_delayable_worker_validation_cannot_outlive_retained_source(self):
        fixture = Fixture()
        engine = fixture.engine()
        fixture.admit_engine(engine)
        original = r.validate_stage_authority
        def invalidate(*args, **kwargs):
            result = original(*args, **kwargs)
            fixture.source["tool_bundle"].changed = True
            return result
        with mock.patch.object(r, "validate_stage_authority", side_effect=invalidate), self.assertRaises(Exception):
            fixture.capture_engine(engine)
        self.assertEqual(engine._state, "SEALED")
        self.assertIsNone(engine._before)

    def test_complete_host_event_schema_rejects_typed_aliases_and_unknowns(self):
        mutations = []
        for field in ("cursor", "generation", "produced_ns"):
            for bad in (True, False, None, 1.0, 0, -1):
                mutations.append((field + ":" + repr(bad), lambda event, f=field, b=bad: replace(event, **{f: b})))
        mutations.append(("cursor-too-large", lambda event: replace(event, cursor=h.MAX_EVENTS + 1)))
        for field in ("session", "kind"):
            for bad in (None, True, 1, "", "wrong"):
                mutations.append((field + ":" + repr(bad), lambda event, f=field, b=bad: replace(event, **{f: b})))
        for field in ("pid", "start_ticks", "uid", "package"):
            mutations.append(("producer:" + field,
                lambda event, f=field: replace(event, producer=replace(event.producer, **{f: True}))))
        for bad in (None, True, [], {"sequence": 12}, {"extra": 1}):
            mutations.append(("body:" + repr(bad), lambda event, b=bad: replace(event, body=b)))
        for field in ("sequence", "requested", "effective", "rect"):
            mutations.append(("body-field:" + field,
                lambda event, f=field: replace(event, body={**event.body, f: True})))
        for label, mutate in mutations:
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            fixture.host_event = mutate(fixture.host_event)
            with self.subTest(field=label), self.assertRaises(Exception): fixture.capture_engine(engine)
            self.assertEqual(engine._state, "SEALED")

    def test_uri_and_stat_acquisition_do_not_consult_or_echo_expected_manifest(self):
        for mode in ("uri", "stat-before", "stat-after"):
            fixture = Fixture()
            engine = fixture.engine()
            fixture.admit_engine(engine)
            if mode == "uri": fixture.device.uri["evidenceSha256"] = sha(b"new independent resolution")
            elif mode == "stat-before": fixture.device.stat_before["pdf"]["inode"] = "991234"
            else: fixture.device.stat_after["pdf"]["inode"] = "991234"
            with self.subTest(mode=mode), self.assertRaises(Exception): fixture.capture_engine(engine)
        fixture = Fixture()
        expected_uri = copy.deepcopy(fixture.device.uri)
        expected_stat = copy.deepcopy(fixture.device.stat_before["pdf"])
        # Poison only the expected wrapper: raw acquisition still returns the
        # independently injected device state, not these replacement values.
        fixture.manifest = r.load_canonical(raw({"poisonedExpectedManifest": True}), r.MAX_MANIFEST_BYTES)
        self.assertEqual(s._json(fixture.acquire(s.Read.URI, {})), expected_uri)
        acquired = fixture.acquire(s.Read.FILE, {"role": "pdf", "path": fixture.device.paths["pdf"]})
        self.assertEqual(s._json(acquired.stat_before), expected_stat)

    def test_facade_25ms_budget_includes_proofs_mac_and_reference_detachment(self):
        for module, function in ((r, "_validate_capture_receipt"), (r, "validate_stage_authority"),
                                 (r, "_snapshot_stage_capture"), (s, "_validate_stability")):
            for elapsed_ns in (24999999, 25000000, 25000001):
                fixture, runtime, provider = self.provider()
                provider.admission(250, self.permit(fixture))
                original = getattr(module, function)
                caller = threading.get_ident()
                delayed = False
                def delay(*args, **kwargs):
                    nonlocal delayed
                    result = original(*args, **kwargs)
                    if threading.get_ident() == caller and not delayed:
                        delayed = True
                        fixture.clock.set(fixture.clock() + elapsed_ns)
                    return result
                with self.subTest(function=function, elapsed_ns=elapsed_ns), self.logical_clock_transport(provider), mock.patch.object(module, function, side_effect=delay):
                    if elapsed_ns < 25000000:
                        self.assertIsNotNone(provider.capture(fixture.request(), 25, self.permit(fixture)))
                    else:
                        with self.assertRaisesRegex(Exception, "original per-call deadline"):
                            provider.capture(fixture.request(), 25, self.permit(fixture))
                        self.assertIsNone(provider._before)
                        self.assertIsNone(provider._previous)
                        self.assert_closed(runtime, provider)
                self.assertTrue(delayed)

    def test_facade_lock_wait_and_rpc_share_the_original_absolute_budget(self):
        fixture, runtime, provider = self.provider()
        provider.admission(250, self.permit(fixture))
        started_ns = fixture.clock()
        class DelayedLock:
            def acquire(self, timeout):
                fixture.clock.set(fixture.clock() + 10000000)
                return True
            def release(self): pass
        provider._operation_lock = DelayedLock()
        original = r.validate_stage_authority
        caller = threading.get_ident()
        def delay(*args, **kwargs):
            result = original(*args, **kwargs)
            if threading.get_ident() == caller:
                fixture.clock.set(fixture.clock() + 15000001)
            return result
        with self.logical_clock_transport(provider), mock.patch.object(r, "validate_stage_authority", side_effect=delay), self.assertRaisesRegex(Exception, "original per-call deadline"):
            provider.capture(fixture.request(), 25, self.permit(fixture))
        operation = runtime.channel.registry.operations["authority.2"]
        self.assertEqual(operation["deadline_ns"], started_ns + 25000000)
        self.assert_closed(runtime, provider)

    def test_facade_request_validation_time_cannot_be_rebased_before_rpc(self):
        fixture, runtime, provider = self.provider()
        provider.admission(250, self.permit(fixture))
        original = s._request_wire
        def delay(request):
            result = original(request)
            fixture.clock.set(fixture.clock() + 25000001)
            return result
        with mock.patch.object(s, "_request_wire", side_effect=delay), self.assertRaises(Exception):
            provider.capture(fixture.request(), 25, self.permit(fixture))
        self.assertEqual(runtime.dispatches, ["authority_admission"])
        self.assert_closed(runtime, provider)

    def test_admission_remains_hardware_blocked_and_sources_expose_no_mutation(self):
        status = s.admission_status()
        self.assertFalse(status["admitted"])
        self.assertFalse(status["cleanupBudget"]["hardwareProven"])
        self.assertIn("S1C_REVIEWED_READ_ONLY_DEVICE_INTERFACE_UNAVAILABLE", status["blockers"])
        self.assertFalse(status["mutationsAuthorized"])
        self.assertFalse(hasattr(s.AuthorityEngine, "close_pen"))
        self.assertFalse(hasattr(s.ReadOnlySource, "write"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
