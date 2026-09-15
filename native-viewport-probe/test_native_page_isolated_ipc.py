"""Offline fake adapters plus the frozen runner's real OperationStartPermit."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch

import native_page_isolated_ipc as ipc
import native_page_graph_v2_runner as runner

SESSION = "a" * 64


class Image:
    def __init__(self, role="authority_worker"):
        self.role, self.changed = role, False
        self.image_sha256 = hashlib.sha256((role + " executable").encode()).hexdigest()
        self.bootstrap_sha256 = hashlib.sha256((role + " reviewed bootstrap bytes").encode()).hexdigest()

    def verify(self):
        if self.changed: raise ipc.IpcError("retained image/bootstrap changed")

    def canonical_bytes(self):
        self.verify()
        return ipc.canonical_json({"role": self.role, "image": self.image_sha256, "bootstrap": self.bootstrap_sha256})


@dataclass
class Process:
    identity: ipc.ProcessIdentity
    parent: ipc.ProcessIdentity | None = None
    suspended: bool = True
    live: bool = True
    killed: bool = False
    joined: bool = False
    closed: bool = False


@dataclass
class Channel:
    registry: ipc.WorkerRegistry
    decoder: ipc.FrameDecoder = field(default_factory=ipc.FrameDecoder)
    closed: bool = False


@dataclass
class ReplyStream:
    binding: ipc.ReplyBinding
    output: bytearray = field(default_factory=bytearray)
    closed: bool = False
    eof: bool = False


class FakeRuntime:
    def __init__(self):
        self.clock = 1_000_000_000
        self.processes = []
        self.unregistered_children = []
        self.reply_streams = []
        self.reply_by_sequence = {}
        self.worker = self.channel = None
        self.external_starts = 0
        self.active = set()
        self.pending = None
        self.fragment = ipc.MAX_CHUNK
        self.block_registration = self.block_operation = False
        self.private_bad = self.containment_bad = self.image_bad = False
        self.diagnostic_flood = self.join_failure = self.close_channel_failure = False
        self.on_register = self.on_finish = self.on_read = self.on_terminate = None
        self.on_launch = self.on_child_spawn = None
        self.on_containment = self.on_attest_image = self.on_open_reply = None
        self.after_terminate = self.on_join = None
        self.child_identity_override = self.child_parent_override = self.worker_identity_override = None
        self.callbacks = []
        self.duplicate_ack = self.duplicate_result = False
        self.raw_output_override = None
        self.trailing_result = b""
        self.missing_eof = False
        self.messages = []

    def now_ns(self): return self.clock

    def sleep_ns(self, nanoseconds):
        if nanoseconds <= 0: raise ipc.IpcError("deadline reached during fake wait")
        self.clock += nanoseconds

    def _identity(self, image, pid):
        return ipc.ProcessIdentity(pid, pid * 1000, image.image_sha256, image.bootstrap_sha256, image.role)

    def launch_suspended(self, image, session):
        identity = self.worker_identity_override or self._identity(image, 900)
        self.worker = Process(identity)
        self.processes.append(self.worker)
        registry = ipc.WorkerRegistry(session, image.role, frozenset({"admission", "capture", "attach", "load"}),
                                      self.now_ns, self.verify_operation_quiescent)
        self.channel = Channel(registry)
        if self.on_launch: self.on_launch(self)
        return ipc.WorkerLaunch(self.worker, self.channel)

    def identity(self, process):
        if process.closed: raise ipc.IpcError("closed retained process handle")
        return process.identity

    def attest_image(self, process, image):
        if self.on_attest_image: self.on_attest_image(self, process)
        if self.image_bad or (process.identity.image_sha256, process.identity.bootstrap_sha256) != (image.image_sha256, image.bootstrap_sha256):
            raise ipc.IpcError("image/bootstrap attestation failed")

    def attest_private_channel(self, channel, peer):
        if self.private_bad or channel is not self.channel or channel.closed or peer != self.worker.identity:
            raise ipc.IpcError("private channel peer ownership failed")

    def attest_containment(self, process, registered_children):
        if self.on_containment: self.on_containment(self)
        if self.containment_bad: raise ipc.IpcError("child escape containment absent")
        for child in self.processes[1:] + self.unregistered_children:
            if child.live and child.identity not in registered_children:
                raise ipc.IpcError("unregistered operation child")

    def attest_containment_quiescent(self, process, registered_children):
        if process.live or self.containment_bad or any(p.live for p in self.processes[1:] + self.unregistered_children):
            raise ipc.WorkerQuiescenceError("unregistered/escaped child may survive owned joins")

    def open_reply_stream(self, control_channel, binding, deadline_ns):
        if control_channel is not self.channel or control_channel.closed or binding.sequence in self.reply_by_sequence:
            raise ipc.IpcError("reply endpoint is not fresh for exact control authority")
        stream = ReplyStream(binding)
        self.reply_streams.append(stream)
        self.reply_by_sequence[binding.sequence] = stream
        if self.on_open_reply: self.on_open_reply(self, stream)
        return stream

    def attest_reply_stream(self, stream, binding):
        if (not isinstance(stream, ReplyStream) or stream.closed or stream.binding != binding or
                self.reply_by_sequence.get(binding.sequence) is not stream or binding.worker != self.worker.identity):
            raise ipc.IpcError("reply stream/ticket producer authentication failed")

    def close_reply_stream(self, stream, binding):
        # Closing our retained local endpoint does not grant process authority.
        if not any(item is stream for item in self.reply_streams):
            raise ipc.IpcError("not an owned reply endpoint")
        stream.closed = True

    def is_suspended(self, process): return process.suspended
    def alive(self, process): return process.live

    def resume(self, process):
        if process.closed or not process.live: raise ipc.IpcError("cannot resume closed/terminated retained handle")
        process.suspended = False
        if process is self.worker:
            self.emit(self.channel.registry.ready())
            self.reply_by_sequence[0].eof = not self.missing_eof

    def emit(self, value):
        stream = self.reply_by_sequence[value["seq"]]
        if stream.eof or stream.closed: raise ipc.IpcError("reply writer used after permanent seal")
        stream.output.extend(ipc.encode_frame(value))

    def read_reply(self, stream, limit, deadline_ns):
        if self.on_read: self.on_read(self)
        if stream.closed: raise ipc.IpcError("private reply stream sealed during blocked read")
        if not stream.output and self.pending and not self.block_operation:
            self.finish()
        if self.raw_output_override is not None:
            raw, self.raw_output_override = self.raw_output_override, None
            return raw
        if not stream.output: return b"" if stream.eof else None
        count = min(limit, self.fragment)
        raw = bytes(stream.output[:count])
        del stream.output[:count]
        return raw

    def write(self, channel, raw, deadline_ns):
        if channel.closed: raise ipc.IpcError("write after private channel close")
        count = min(len(raw), self.fragment)
        for message in channel.decoder.feed(raw[:count]):
            self.messages.append(message)
            if message["kind"] == "register" and self.on_register:
                self.on_register(self)
            if channel.closed: raise ipc.IpcError("registration settled after terminal seal")
            reply = channel.registry.control(message)
            if message["kind"] == "register" and self.block_registration:
                continue
            self.emit(reply)
            channel.registry.acknowledgement_sent(reply)
            if message["kind"] == "register" and self.duplicate_ack: self.emit(reply)
            if message["kind"] == "begin":
                dispatch = channel.registry.dispatch(message["op"])
                self.external_starts += 1
                self.active.add(dispatch.operation_id)
                self.pending = dispatch.operation_id
            else:
                self.reply_by_sequence[message["seq"]].eof = not self.missing_eof
        return count

    def finish(self):
        if self.on_finish: self.on_finish(self)
        op = self.pending
        self.pending = None
        for child in self.processes[1:]:
            if not child.suspended: child.live = False
        for value in self.callbacks: self.emit(self.channel.registry.callback(op, value))
        self.active.discard(op)
        reply = self.channel.registry.complete(op, {"captured": True})
        self.emit(reply)
        if self.duplicate_result: self.emit(reply)
        stream = self.reply_by_sequence[reply["seq"]]
        stream.output.extend(self.trailing_result)
        stream.eof = not self.missing_eof

    def verify_operation_quiescent(self, op):
        if op in self.active or any(child.live for child in self.processes[1:]):
            raise ipc.WorkerQuiescenceError("fake worker operation is not quiescent")

    def diagnostic_output(self, process, limit): return b"x" * limit if self.diagnostic_flood else b""

    def spawn_child_suspended(self, worker, operation_id, image):
        child = Process(self.child_identity_override or self._identity(image, 901 + len(self.processes)),
                        self.child_parent_override or worker.identity)
        self.processes.append(child)
        if self.on_child_spawn: self.on_child_spawn(self)
        return child

    def parent_identity(self, child): return child.parent

    def terminate(self, process, expected):
        if self.on_terminate: self.on_terminate(self, process)
        if process.identity != expected: raise ipc.WorkerQuiescenceError("exact termination identity drift")
        process.killed, process.live = True, False
        if process is self.worker:
            self.active.clear()
            self.channel.registry.seal()
        if self.after_terminate: self.after_terminate(self, process)

    def join(self, process, expected, deadline_ns):
        if self.on_join: self.on_join(self, process)
        if process.identity != expected: raise ipc.WorkerQuiescenceError("exact join identity drift")
        process.joined = not process.live and not self.join_failure
        return process.joined

    def close_process(self, process, expected):
        if process.identity != expected or process.live or not process.joined:
            raise ipc.WorkerQuiescenceError("cannot close unjoined/unverified process")
        process.closed = True

    def close_channel(self, channel):
        if self.close_channel_failure: raise ipc.IpcError("private pipe close failed")
        channel.closed = True


class FramingTests(unittest.TestCase):
    def test_canonical_length_frame_survives_each_partial_boundary(self):
        value = {"a": [1, True, None], "unicode": "שלום"}
        framed = ipc.encode_frame(value)
        for split in range(1, len(framed)):
            with self.subTest(split=split):
                decoder = ipc.FrameDecoder()
                self.assertEqual(decoder.feed(framed[:split]), ())
                self.assertEqual(decoder.feed(framed[split:]), (value,))
                decoder.seal()

    def test_malformed_duplicate_key_and_noncanonical_json_are_rejected(self):
        values = [b'{"a":1,"a":2}', b'{"a":1} ', b'{ "a":1}', b'{"z":1,"a":2}', b'{"a":1.0}',
                  b'{"a":NaN}', b'{"a":-0}', b'{"a":"\\u0061"}', b'[]garbage', b'\xff', b'{',
                  b'{"a":9223372036854775808}', '{"a":"e\u0301"}'.encode()]
        for raw in values:
            with self.subTest(raw=raw):
                decoder = ipc.FrameDecoder()
                with self.assertRaises(ipc.IpcError): decoder.feed(len(raw).to_bytes(4, "big") + raw)
                self.assertTrue(decoder.sealed)

    def test_partial_oversize_zero_and_post_seal_frames_are_rejected(self):
        for raw in (b"\0\0\0\0", (ipc.MAX_FRAME + 1).to_bytes(4, "big")):
            with self.assertRaises(ipc.IpcError): ipc.FrameDecoder().feed(raw)
        decoder = ipc.FrameDecoder()
        decoder.feed(b"\0\0\0")
        with self.assertRaises(ipc.IpcError): decoder.seal()
        with self.assertRaises(ipc.IpcError): decoder.feed(b"x")
        with self.assertRaises(ipc.IpcError): ipc.FrameDecoder().feed(b"x" * (ipc.MAX_CHUNK + 1))

    def test_non_data_objects_float_topology_and_oversize_are_not_serializable(self):
        for value in (object(), b"pickle-like", 1.5, {1: "key"}, "x" * (ipc.MAX_FRAME + 1), 2 ** 70):
            with self.assertRaises(ipc.IpcError): ipc.encode_frame(value)
        value = None
        for _ in range(14): value = [value]
        with self.assertRaises(ipc.IpcError): ipc.encode_frame(value)

    def test_tiny_message_flood_is_bounded(self):
        with self.assertRaisesRegex(ipc.IpcError, "message count"):
            ipc.FrameDecoder().feed(ipc.encode_frame(None) * (ipc.MAX_MESSAGES + 1))


class WorkerTests(unittest.TestCase):
    def setUp(self):
        for guard in (patch.object(socket, "socket", side_effect=AssertionError("no network")),
                      patch.object(subprocess, "Popen", side_effect=AssertionError("no process launch"))):
            guard.start()
            self.addCleanup(guard.stop)
        self.fresh()

    def fresh(self, role="authority_worker", excluded=()):
        self.image, self.runtime = Image(role), FakeRuntime()
        self.worker = ipc.IsolatedWorker(self.image, self.runtime, SESSION, excluded=excluded)

    def deadline(self, span=1_000_000_000): return self.runtime.now_ns() + span
    def start(self): return self.worker.start(self.deadline())
    def permit(self, deadline=None):
        return runner.OperationStartPermit(deadline or self.deadline(), self.runtime.now_ns)

    def execute(self, permit=None, operation_id="op1", deadline=None):
        return self.worker.execute(permit or self.permit(), operation_id, "capture", {"request": 1}, deadline or self.deadline())

    def clean(self):
        self.assertEqual(self.worker.state, "CLOSED")
        self.assertFalse(self.worker.cleanup_obligations)
        self.assertFalse(self.runtime.active)
        self.assertTrue(all(p.closed and p.joined and not p.live for p in self.runtime.processes))
        self.assertTrue(all(stream.closed for stream in self.runtime.reply_streams))
        self.worker.assert_quiescent()

    def test_real_frozen_permit_registers_inside_worker_before_external_work(self):
        self.start()
        permit = self.permit()
        result = self.execute(permit)
        permit.require_exact_start(runner.ProviderQuiescenceFailure)
        self.assertEqual(result.value, {"captured": True})
        self.assertEqual([m["kind"] for m in self.runtime.messages], ["register", "begin"])
        record = self.runtime.channel.registry.operations["op1"]
        self.assertTrue(record["ack_sent"] and record["start_ack_sent"] and record["dispatched"])
        self.assertEqual(record["state"], "QUIESCENT")
        self.worker.assert_quiescent()
        self.worker.fail_stop_and_quiesce()
        self.clean()

    def test_frida_worker_uses_same_explicit_host_ownership_domain(self):
        self.fresh("frida_worker")
        self.start()
        self.execute()
        self.assertEqual(self.runtime.worker.identity.role, "frida_worker")
        self.worker.cancel_and_quiesce()
        self.clean()

    def test_no_default_launcher_or_missing_image_authority(self):
        for image, runtime in ((None, self.runtime), (self.image, None)):
            with self.assertRaises(ipc.IpcError): ipc.IsolatedWorker(image, runtime, SESSION)

    def test_terminal_seal_during_pending_launch_cannot_leave_a_late_retained_worker(self):
        unresolved = []
        def cancel_during_launch(runtime):
            try: self.worker.fail_stop_and_quiesce(timeout_ms=1)
            except ipc.WorkerQuiescenceError as error: unresolved.append(str(error))
        self.runtime.on_launch = cancel_during_launch
        with self.assertRaises(ipc.IpcError): self.start()
        self.assertIn("pending retained spawn", unresolved[0])
        self.assertTrue(self.runtime.worker.suspended)
        self.clean()

    def test_terminal_seal_during_pending_child_spawn_joins_late_child_before_return(self):
        self.start()
        ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        unresolved = []
        def cancel_during_spawn(runtime):
            try: self.worker.fail_stop_and_quiesce(timeout_ms=1)
            except ipc.WorkerQuiescenceError as error: unresolved.append(str(error))
        self.runtime.on_child_spawn = cancel_during_spawn
        with self.assertRaises(ipc.IpcError): self.worker.register_child(ticket, Image("operation_child"), self.deadline())
        self.assertIn("pending retained spawn", unresolved[0])
        self.assertTrue(self.runtime.processes[1].suspended)
        self.assertEqual(self.runtime.external_starts, 0)
        self.clean()

    def test_private_peer_image_and_containment_attestations_fail_closed(self):
        for flag in ("private_bad", "containment_bad", "image_bad"):
            with self.subTest(flag=flag):
                self.fresh()
                setattr(self.runtime, flag, True)
                with self.assertRaises(ipc.IpcError): self.start()
                self.assertEqual(self.runtime.external_starts, 0)
                setattr(self.runtime, flag, False)
                # Failed image attestation is intentionally not admitted for cleanup.
                if flag == "image_bad":
                    self.assertFalse(self.runtime.worker.killed)
                    self.assertTrue(self.worker.cleanup_obligations)
                else:
                    if flag == "containment_bad":
                        self.assertEqual(self.worker.state, "SEALED")
                        self.assertTrue(self.worker.cleanup_obligations)
                        self.worker.fail_stop_and_quiesce()
                    self.clean()

    def test_unregistered_live_child_survives_owned_joins_and_retains_cleanup_obligation(self):
        for detect_before_cleanup in (True, False):
            with self.subTest(detect_before_cleanup=detect_before_cleanup):
                self.fresh()
                self.start()
                foreign = Process(self.runtime._identity(Image("operation_child"), 777), suspended=False)
                self.runtime.unregistered_children.append(foreign)
                with self.assertRaises(ipc.WorkerQuiescenceError):
                    self.execute() if detect_before_cleanup else self.worker.fail_stop_and_quiesce()
                self.assertTrue(self.runtime.worker.killed and self.runtime.worker.joined)
                self.assertFalse(self.runtime.worker.closed)
                self.assertTrue(foreign.live)
                self.assertFalse(foreign.killed or foreign.joined or foreign.closed)
                self.assertEqual(self.worker.state, "SEALED")
                self.assertTrue(self.worker.cleanup_obligations)
                with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.assert_quiescent()
                with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.fail_stop_and_quiesce()
                # Independent evidence of absence, never a generic kill of the stranger.
                foreign.live = False
                self.worker.fail_stop_and_quiesce()
                self.clean()

    def test_child_attestation_crossing_deadline_or_seal_never_resumes(self):
        for phase in ("image", "containment"):
            for outcome in ("deadline", "terminal", "callback_seal"):
                with self.subTest(phase=phase, outcome=outcome):
                    self.fresh()
                    self.start()
                    deadline = self.deadline()
                    ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, deadline))
                    self.worker.register_child(ticket, Image("operation_child"), deadline)
                    child = self.runtime.processes[1]
                    def intervene(runtime, process=None):
                        if self.worker._operations.get("op1") != "STARTED": return
                        if phase == "image" and process is not child: return
                        runtime.on_attest_image = runtime.on_containment = None
                        if outcome == "deadline": runtime.clock = deadline
                        elif outcome == "terminal": self.worker.fail_stop_and_quiesce()
                        else: self.worker.seal_callbacks()
                    if phase == "image": self.runtime.on_attest_image = intervene
                    else: self.runtime.on_containment = intervene
                    with self.assertRaises(ipc.IpcError): self.worker.begin_and_wait(ticket, deadline)
                    self.assertTrue(child.suspended)
                    self.clean()

    def test_fresh_reply_binding_carries_exact_registration_ticket_for_every_rpc(self):
        self.start()
        ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        self.worker.register_child(ticket, Image("operation_child"), self.deadline())
        self.worker.begin_and_wait(ticket, self.deadline())
        bindings = [stream.binding for stream in self.runtime.reply_streams]
        self.assertEqual([b.sequence for b in bindings], [0, 1, 2, 3])
        self.assertEqual([b.registration_sequence for b in bindings], [None, 1, 1, 1])
        self.assertTrue(all(b.worker == self.runtime.worker.identity and b.session == SESSION for b in bindings))
        self.assertTrue(all(stream.closed and stream.eof and not stream.output for stream in self.runtime.reply_streams))
        self.worker.fail_stop_and_quiesce()
        self.clean()

    def test_reply_endpoint_creation_crossing_terminal_seal_is_closed_without_dispatch(self):
        self.start()
        unresolved = []
        def seal_during_open(runtime, stream):
            try: self.worker.fail_stop_and_quiesce(timeout_ms=1)
            except ipc.WorkerQuiescenceError as error: unresolved.append(str(error))
        self.runtime.on_open_reply = seal_during_open
        with self.assertRaises(ipc.IpcError): self.execute()
        self.assertIn("pending retained spawn", unresolved[0])
        self.assertEqual(self.runtime.external_starts, 0)
        self.clean()

    def test_post_result_child_join_cannot_publish_success_after_original_deadline(self):
        self.start()
        deadline = self.deadline()
        ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, deadline))
        self.worker.register_child(ticket, Image("operation_child"), deadline)
        def cross_deadline(runtime, process):
            runtime.on_join = None
            runtime.clock = deadline
        self.runtime.on_join = cross_deadline
        with self.assertRaisesRegex(ipc.IpcError, "deadline"): self.worker.begin_and_wait(ticket, deadline)
        self.clean()

    def test_swapped_replayed_wrong_peer_session_sequence_and_ticket_streams_fail_before_dispatch(self):
        variants = {
            "worker": lambda b: replace(b, worker=replace(b.worker, creation_ticks=1)),
            "session": lambda b: replace(b, session="b" * 64),
            "sequence": lambda b: replace(b, sequence=b.sequence + 1),
            "operation": lambda b: replace(b, operation_id="other"),
            "ticket": lambda b: replace(b, registration_sequence=999),
            "replay": None,
            "swap": None,
        }
        for variant, mutate in variants.items():
            with self.subTest(variant=variant):
                self.fresh()
                self.start()
                def substitute(runtime, stream):
                    if variant == "replay": stream.binding = runtime.reply_streams[0].binding
                    elif variant == "swap": runtime.reply_by_sequence[stream.binding.sequence] = runtime.reply_streams[0]
                    else: stream.binding = mutate(stream.binding)
                self.runtime.on_open_reply = substitute
                with self.assertRaises(ipc.IpcError): self.execute()
                self.assertEqual(self.runtime.external_starts, 0)
                self.assertEqual(self.runtime.messages, [])
                self.clean()

    def test_each_rpc_requires_real_eof_not_temporary_empty(self):
        for phase in ("ready", "register", "child", "result"):
            with self.subTest(phase=phase):
                self.fresh()
                if phase != "ready": self.start()
                if phase in {"child", "result"}:
                    ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
                self.runtime.missing_eof = True
                with self.assertRaisesRegex(ipc.IpcError, "deadline"):
                    if phase == "ready": self.worker.start(self.deadline(10_000_000))
                    elif phase == "register": self.execute(deadline=self.deadline(10_000_000))
                    elif phase == "child": self.worker.register_child(ticket, Image("operation_child"), self.deadline(10_000_000))
                    else: self.worker.begin_and_wait(ticket, self.deadline(10_000_000))
                self.assertEqual(self.runtime.external_starts, 1 if phase == "result" else 0)
                self.clean()

    def test_one_byte_fragmented_duplicate_and_partial_trailing_results_fail(self):
        for trailing in ("duplicate", b"\0", b"\0\0\0\x10{", ipc.encode_frame({"trailing": True})):
            with self.subTest(trailing=trailing):
                self.fresh()
                self.start()
                self.runtime.fragment = 1
                if trailing == "duplicate": self.runtime.duplicate_result = True
                else: self.runtime.trailing_result = trailing
                with self.assertRaisesRegex(ipc.IpcError, "trailing|unread|partial"): self.execute()
                self.clean()

    def test_blocked_registration_times_out_without_external_dispatch(self):
        self.start()
        self.runtime.block_registration = True
        deadline = self.deadline(10_000_000)
        with self.assertRaises(ipc.IpcError): self.execute(self.permit(deadline), deadline=deadline)
        self.assertEqual(self.runtime.external_starts, 0)
        self.clean()

    def test_expired_or_sealed_permit_never_registers_or_starts_work(self):
        for expired in (True, False):
            self.fresh()
            self.start()
            permit = self.permit()
            permit.expire() if expired else permit.seal()
            with self.assertRaises((runner.DeadlineExceeded, runner.ProviderQuiescenceFailure)):
                self.execute(permit)
            self.assertEqual(self.runtime.messages, [])
            self.clean()

    def test_registration_ack_after_permit_expiry_is_terminally_joined(self):
        self.start()
        permit = self.permit()
        self.runtime.on_register = lambda runtime: permit.expire()
        with self.assertRaises(runner.DeadlineExceeded): self.execute(permit)
        self.assertEqual(self.runtime.external_starts, 0)
        self.assertTrue(self.runtime.channel.registry.operations["op1"]["ack_sent"])
        self.clean()

    def test_blocked_claim_to_callback_interval_can_be_cancelled_from_other_thread(self):
        self.start()
        permit = self.permit()
        entered, released = threading.Event(), threading.Event()
        errors = []
        def block(runtime):
            entered.set()
            if not released.wait(2): raise AssertionError("test cancellation thread did not settle")
        self.runtime.on_register = block
        def cancel():
            try:
                if not entered.wait(2): raise AssertionError("registration did not begin")
                permit.expire()
                self.worker.fail_stop_and_quiesce()
            except BaseException as error: errors.append(error)
            finally: released.set()
        thread = threading.Thread(target=cancel)
        thread.start()
        with self.assertRaises(ipc.IpcError): self.execute(permit)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.runtime.external_starts, 0)
        self.clean()

    def test_duplicate_permit_registration_ticket_and_late_registration_are_denied(self):
        self.start()
        permit = self.permit()
        ticket = permit.start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        with self.assertRaises(ipc.IpcError): self.worker.register_operation("op1", "capture", {}, self.deadline())
        with self.assertRaises(ipc.IpcError): self.worker.begin_and_wait(replace(ticket, registration_sequence=999), self.deadline())
        self.worker.begin_and_wait(ticket, self.deadline())
        with self.assertRaises(ipc.IpcError): self.worker.begin_and_wait(ticket, self.deadline())
        with self.assertRaises(runner.ProviderQuiescenceFailure): self.execute(permit, "op2")
        with self.assertRaises(ipc.IpcError): self.worker.register_operation("late", "capture", {}, self.deadline())
        self.assertEqual(self.runtime.external_starts, 1)
        self.clean()

    def test_started_blocked_operation_returns_only_after_terminal_kill_and_join(self):
        self.start()
        self.runtime.block_operation = True
        deadline = self.deadline(10_000_000)
        with self.assertRaises(ipc.IpcError): self.execute(self.permit(deadline), deadline=deadline)
        self.assertEqual(self.runtime.external_starts, 1)
        self.assertTrue(self.runtime.worker.killed and self.runtime.worker.joined)
        self.clean()

    def test_worker_crash_is_joined_before_operation_failure_returns(self):
        self.start()
        self.runtime.block_operation = True
        def crash(runtime):
            if runtime.pending:
                runtime.worker.live = False
                runtime.active.clear()
        self.runtime.on_read = crash
        with self.assertRaises(ipc.IpcError): self.execute()
        self.clean()

    def test_partial_ipc_and_callbacks_return_only_after_worker_quiescence(self):
        self.start()
        self.runtime.fragment = 1
        self.runtime.callbacks = [{"event": 1}, {"event": 2}]
        result = self.execute()
        self.assertEqual(result.callbacks, ({"event": 1}, {"event": 2}))
        self.assertFalse(self.runtime.active)
        self.worker.fail_stop_and_quiesce()
        self.clean()

    def test_duplicate_registration_reply_and_duplicate_result_fail_stop(self):
        for flag in ("duplicate_ack", "duplicate_result"):
            self.fresh()
            self.start()
            setattr(self.runtime, flag, True)
            with self.assertRaises(ipc.IpcError): self.execute()
            self.clean()

    def test_callback_after_seal_and_callback_flood_are_never_delivered(self):
        for mode in ("seal", "flood"):
            self.fresh()
            self.start()
            self.runtime.callbacks = [{"late": 1}] if mode == "seal" else [{}] * (ipc.MAX_CALLBACKS + 1)
            if mode == "seal": self.runtime.on_finish = lambda runtime: self.worker.seal_callbacks()
            with self.assertRaises(ipc.IpcError): self.execute()
            self.clean()

    def test_late_reply_returned_by_a_read_after_terminal_seal_is_not_published(self):
        self.start()
        def cancel_before_read_returns(runtime):
            runtime.on_read = None
            self.worker.fail_stop_and_quiesce()
        self.runtime.on_read = cancel_before_read_returns
        with self.assertRaises(ipc.IpcError): self.execute()
        self.clean()

    def test_malformed_partial_oversize_and_output_flood_fail_stop(self):
        variants = [b"x" * (ipc.MAX_CHUNK + 1), (ipc.MAX_FRAME + 1).to_bytes(4, "big"),
                    (13).to_bytes(4, "big") + b'{"a":1,"a":2}']
        for raw in variants:
            self.fresh()
            self.start()
            self.runtime.raw_output_override = raw
            with self.assertRaises(ipc.IpcError): self.execute()
            self.clean()
        self.fresh()
        self.start()
        self.runtime.diagnostic_flood = self.runtime.block_operation = True
        with self.assertRaisesRegex(ipc.IpcError, "flood"): self.execute()
        self.clean()

    def test_operation_children_registered_inside_worker_before_resume_and_joined(self):
        self.start()
        permit = self.permit()
        ticket = permit.start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        self.worker.register_child(ticket, Image("operation_child"), self.deadline())
        child = self.runtime.processes[1]
        self.assertTrue(child.suspended)
        self.assertEqual(self.runtime.channel.registry.operations["op1"]["children"], [child.identity.wire()])
        self.worker.begin_and_wait(ticket, self.deadline())
        self.assertTrue(child.joined and child.closed and not child.live)
        self.worker.cancel_and_quiesce()
        self.clean()

    def test_terminal_fail_stop_kills_and_joins_registered_child_then_worker(self):
        self.start()
        ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        self.worker.register_child(ticket, Image("operation_child"), self.deadline())
        self.runtime.block_operation = True
        order = []
        self.runtime.on_terminate = lambda runtime, process: order.append(process.identity.role)
        with self.assertRaises(ipc.IpcError): self.worker.begin_and_wait(ticket, self.deadline(10_000_000))
        self.assertEqual(order, ["operation_child", "authority_worker"])
        self.clean()

    def test_pen_guardian_and_device_peer_identities_are_never_generic_cleanup_targets(self):
        for role in ipc.EXCLUDED_ROLES:
            with self.subTest(role=role):
                protected_image = Image(role)
                protected = ipc.ProcessIdentity(777, 777000, protected_image.image_sha256, protected_image.bootstrap_sha256, role)
                self.fresh(excluded=(protected,))
                self.runtime.worker_identity_override = protected
                with self.assertRaises(ipc.WorkerQuiescenceError): self.start()
                self.assertFalse(self.runtime.worker.killed)
                self.assertFalse(self.runtime.worker.joined)
                self.assertTrue(self.worker.cleanup_obligations)

    def test_excluded_identity_cannot_be_relabelled_as_operation_child(self):
        protected = ipc.ProcessIdentity(777, 777000, "b" * 64, "c" * 64, "pen_worker")
        self.fresh(excluded=(protected,))
        self.start()
        ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        self.runtime.child_identity_override = replace(protected, role="operation_child")
        with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.register_child(ticket, Image("operation_child"), self.deadline())
        self.assertFalse(self.runtime.processes[1].killed)
        self.assertTrue(self.worker.cleanup_obligations)

    def test_wrong_parent_child_escape_is_quarantined_not_killed(self):
        self.start()
        ticket = self.permit().start(lambda: self.worker.register_operation("op1", "capture", {}, self.deadline()))
        self.runtime.child_parent_override = replace(self.runtime.worker.identity, pid=777)
        with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.register_child(ticket, Image("operation_child"), self.deadline())
        self.assertTrue(self.runtime.worker.killed)
        self.assertFalse(self.runtime.processes[1].killed)
        self.assertTrue(self.worker.cleanup_obligations)
        with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.assert_quiescent()

    def test_pid_reuse_image_drift_and_join_failure_never_claim_quiescence(self):
        for mode in ("pid", "creation", "image", "join"):
            self.fresh()
            self.start()
            original = self.runtime.worker.identity
            if mode == "pid": self.runtime.worker.identity = replace(original, pid=777)
            elif mode == "creation": self.runtime.worker.identity = replace(original, creation_ticks=1)
            elif mode == "image": self.runtime.worker.identity = replace(original, image_sha256="f" * 64)
            else: self.runtime.join_failure = True
            with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.fail_stop_and_quiesce()
            self.assertTrue(self.worker.cleanup_obligations)
            with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.assert_quiescent()
            if mode != "join": self.assertFalse(self.runtime.worker.killed)
            self.runtime.worker.identity, self.runtime.join_failure = original, False
            self.worker.fail_stop_and_quiesce()
            self.clean()

    def test_exact_terminate_and_post_terminate_identity_are_rechecked(self):
        for phase in ("on_terminate", "after_terminate"):
            self.fresh()
            self.start()
            original = self.runtime.worker.identity
            setattr(self.runtime, phase, lambda runtime, process: setattr(process, "identity", replace(original, creation_ticks=999)))
            with self.assertRaises(ipc.WorkerQuiescenceError): self.worker.fail_stop_and_quiesce()
            self.assertFalse(self.runtime.worker.closed)
            setattr(self.runtime, phase, None)
            self.runtime.worker.identity = original
            self.worker.fail_stop_and_quiesce()
            self.clean()

    def test_worker_registry_denies_unacknowledged_duplicate_late_and_unquiescent_dispatch(self):
        registry = ipc.WorkerRegistry(SESSION, "authority_worker", frozenset({"capture"}), lambda: 100, lambda op: None)
        register = ipc.envelope(SESSION, 1, "register", "op", {"operation": "capture", "payload": {}, "deadline_ns": 200})
        ack = registry.control(register)
        with self.assertRaises(ipc.IpcError): registry.control(ipc.envelope(SESSION, 2, "begin", "op", {}))
        registry.acknowledgement_sent(ack)
        started = registry.control(ipc.envelope(SESSION, 3, "begin", "op", {}))
        with self.assertRaises(ipc.IpcError): registry.dispatch("op")
        registry.acknowledgement_sent(started)
        registry.dispatch("op")
        with self.assertRaises(ipc.IpcError): registry.dispatch("op")
        registry.verify_quiescent = lambda op: (_ for _ in ()).throw(ipc.WorkerQuiescenceError("still active"))
        with self.assertRaises(ipc.WorkerQuiescenceError): registry.complete("op", {})
        registry.seal()
        with self.assertRaises(ipc.IpcError): registry.callback("op", {})
        with self.assertRaises(ipc.IpcError): registry.acknowledgement_sent(ack)


if __name__ == "__main__": unittest.main()
