"""Synthetic tests for the observation-only no-pen semantic adapter.

All low-level entry points are in-memory fakes.  The suite patches network and
process creation to prove that the adapter has no ambient device route.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import copy
import hashlib
import hmac
import json
import socket
import struct
import subprocess
import threading
import unittest
from unittest.mock import patch

import native_page_android_authority as android
import native_page_graph_v2_runner as graph
import native_page_host_authority as host
import native_page_visual_no_pen_semantic as subject
import native_page_visual_session_harness as harness
import test_native_page_graph_v2_runner as graph_fakes


SESSION = "10000000-0000-4000-8000-000000000001"
BOOT = "20000000-0000-4000-8000-000000000002"
FIXTURE_URI = (
    "file:///storage/emulated/0/Download/"
    "NativeViewportVisualOnly-no-pen.pdf"
)
FIXTURE_PATH = (
    "/storage/emulated/0/Download/NativeViewportVisualOnly-no-pen.pdf"
)
FIXTURE_SHA = "2" * 64
HOST_TASK = 52
HOST_TOKEN = "host-token"
RECEIPT_KEY = b"S" * 32


def canonical(value, maximum=graph.MAX_AUTHORITY_BYTES):
    return graph.canonical_bytes(value, maximum)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


CLOCK_AUTHORITY_RAW = canonical({
    "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
    "schemaVersion": 1,
    "kind": "retained-provider-authority",
    "providerInstanceId": "a" * 64,
    "providerImageSha256": "b" * 64,
})
MONOTONIC_DOMAIN_RAW = canonical({
    "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
    "schemaVersion": 1,
    "kind": "monotonic-domain-identity",
    "domainId": "c" * 64,
    "providerInstanceId": "a" * 64,
    "unit": "nanoseconds",
})
CLOCK_AUTHORITY_SHA = sha(CLOCK_AUTHORITY_RAW)
MONOTONIC_DOMAIN_SHA = sha(MONOTONIC_DOMAIN_RAW)


class Clock:
    def __init__(self, now=1_000_000_000):
        self.now = now
        self.canonical_value = CLOCK_AUTHORITY_RAW
        self.domain_value = MONOTONIC_DOMAIN_RAW
        self.fail_verify = False
        self.stalled = False

    def verify(self):
        if self.fail_verify:
            raise RuntimeError("clock verify")

    def canonical_bytes(self):
        return self.canonical_value

    def monotonic_domain_identity(self):
        return self.domain_value

    def now_ns(self):
        return self.now

    def __call__(self):
        return self.now_ns()

    def advance(self, amount=1):
        if not self.stalled:
            self.now += amount
        return self.now


def make_plan():
    return subject.NoPenSemanticPlan(
        SESSION, harness.AUTHORIZED_SERIAL, FIXTURE_URI, FIXTURE_SHA,
        HOST_TASK, HOST_TOKEN, "/system/framework/framework.jar",
        "libart.so", "/apex/runtime/lib64/libart.so", 1_234_567,
        "1" * 64, CLOCK_AUTHORITY_SHA, MONOTONIC_DOMAIN_SHA, 1_000,
    )


def make_task(raw="a" * 64):
    return graph_fakes.task(raw)


def make_foreign(task):
    process = host.ProcessIdentity(
        task.pid, 9_000_001, task.uid, graph.PACKAGE_NAME)
    return host.ForeignIdentity(
        process, task.task_id, task.activity_token,
        android.stable_authority_sha256(task),
    )


def make_files(*, sha256=FIXTURE_SHA, uri=FIXTURE_URI, path=FIXTURE_PATH,
               mark=True):
    resolution = {
        "authority": "rtl-reader-file-uri-resolution-v1",
        "documentUri": uri,
        "resolvedPath": path,
        "evidenceSha256": "3" * 64,
    }
    return {
        "authority": graph.FILE_AUTHORITY,
        "verification": "external-before-and-after-exact",
        "originalPdf": {
            "present": True,
            "path": path,
            "size": "4096",
            "sha256": sha256,
            "stat": graph_fakes.stat(1),
            "documentUri": uri,
            "uriResolution": resolution,
        },
        "mark": ({
            "present": True,
            "path": path + ".mark",
            "size": "512",
            "sha256": "4" * 64,
            "stat": graph_fakes.stat(2),
        } if mark else {
            "present": False,
            "path": None,
            "size": None,
            "sha256": None,
            "stat": None,
        }),
    }


def stage_receipt(*, receipt_id, sequence, phase, previous, record_sha,
                  request, backend, key):
    body = {
        "authority": subject.STAGE_RECEIPT_AUTHORITY,
        "schemaVersion": 1,
        "receiptId": receipt_id,
        "sequence": sequence,
        "phase": phase,
        "previousReceiptSha256": previous,
        "recordSha256": record_sha,
        "requestSha256": request.sha256,
        "sampleId": request.sample_id,
        "observerSessionId": request.observer_session_id,
        "runNonce": request.run_nonce,
        "backendSha256": backend.sha256,
        "receiptKeyId": backend.receipt_key_id,
    }
    body["authenticator"] = hmac.new(
        key, canonical(body), hashlib.sha256).hexdigest()
    return body


class FakeBackend:
    def __init__(self, plan, clock, key=RECEIPT_KEY):
        self.plan = plan
        self.clock = clock
        self.key = key
        self.identity_value = subject.NoPenBackendIdentity(
            subject.BACKEND_AUTHORITY,
            "5" * 64,
            plan.serial,
            BOOT,
            "6" * 64,
            "7" * 64,
            4321,
            8_000_001,
            "8" * 64,
            "9" * 64,
            graph.EXPECTED_OBSERVER_SHA256,
            hashlib.sha256(key).hexdigest(),
            plan.clock_authority_sha256,
            plan.monotonic_domain_sha256,
            True, True, True, True, True, True, True, True, True, True,
            True,
            False, False, False, False, False, False, False, False,
        )
        self.canonical_value = self.identity_value.canonical_bytes()
        self.verify_count = 0
        self.capture_count = 0
        self.quiescent_count = 0
        self.fail_verify = False
        self.fail_capture = False
        self.fail_quiescent_at = None
        self.advance_quiescent_at = None
        self.quiescent_advance_ns = 0
        self.transport_updates = {}
        self.mutator = None
        self.raw_mutator = None
        self.wire_mutator = None
        self.reenter = None
        self.drift_after_capture = None
        self.reuse_capture_ids = False
        self.reuse_receipt_ids = False
        self.reuse_receipt_wire = None

    def verify(self):
        self.verify_count += 1
        if self.fail_verify:
            raise RuntimeError("backend verify")

    def canonical_bytes(self):
        return self.canonical_value

    def identity(self):
        return self.identity_value

    def assert_quiescent(self, deadline_ns):
        self.quiescent_count += 1
        if self.fail_quiescent_at == self.quiescent_count:
            raise RuntimeError("backend not quiescent")
        if self.clock() >= deadline_ns:
            raise RuntimeError("backend quiescence late")
        if self.advance_quiescent_at == self.quiescent_count:
            self.clock.advance(self.quiescent_advance_ns)

    def _external(self, phase_name, request, manifest, captured_ns,
                  capture_id):
        phase = next(item for item in
                     harness.BASE_PHASES + harness.ROTATION_PHASES
                     if item.placement.value == request.phase and
                     item.name == self.current_phase.name)
        applied = self.current_applied
        foreign = self.current_foreign
        return {
            "authority": subject.EXTERNAL_AUTHORITY,
            "schemaVersion": 1,
            "phase": phase_name,
            "captureId": capture_id,
            "sampleId": request.sample_id,
            "observerSessionId": request.observer_session_id,
            "runNonce": request.run_nonce,
            "requestSha256": request.sha256,
            "manifestSha256": manifest.sha256,
            "backendSha256": self.identity_value.sha256,
            "clockAuthoritySha256": request.clock_authority_sha256,
            "monotonicDomainSha256": request.monotonic_domain_sha256,
            "serial": self.plan.serial,
            "capturedNs": str(captured_ns),
            "taskAuthoritySha256": request.task_authority_sha256,
            "taskStableAuthoritySha256":
                request.task_stable_authority_sha256,
            "target": {
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
            },
            "files": copy.deepcopy(manifest.value["files"]),
            "host": {
                "authority": graph.HOST_AUTHORITY,
                "hostSessionId": self.plan.session_id,
                "stage": phase.placement.value,
                "displayId": applied.display_id,
                "defaultDisplayId": 0,
                "displayGeneration": applied.generation,
                "placementRequestGeneration": applied.sequence,
                "placementReadyGeneration": applied.sequence,
                "hostPackageName": host.HOST_PACKAGE,
                "hostApkSha256": host.APK_SHA256,
                "hostTaskId": self.plan.host_task_id,
                "hostActivityToken": self.plan.host_activity_token,
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
            },
            "observation": {
                "readOnly": True,
                "inputEventsGenerated": 0,
                "writerCalls": 0,
                "penOperations": 0,
                "penLeaseAcquisitions": 0,
                "penLeaseTouches": 0,
            },
        }

    def capture_no_pen(self, request, scope, deadline_ns):
        self.capture_count += 1
        if self.reenter is not None:
            self.reenter()
        if self.fail_capture:
            raise RuntimeError("capture failed")
        started = self.clock.advance()
        before_time = self.clock.advance()
        captured = self.clock.advance()
        after_time = self.clock.advance()
        finished = self.clock.advance()
        manifest = graph.load_canonical(
            scope.manifest_raw, graph.MAX_MANIFEST_BYTES)
        base = 1 if self.reuse_capture_ids else self.capture_count
        before_id = f"30000000-0000-4000-8000-{base * 2 - 1:012d}"
        after_id = f"30000000-0000-4000-8000-{base * 2:012d}"
        before = self._external(
            "before", request, manifest, before_time, before_id)
        after = self._external(
            "after", request, manifest, after_time, after_id)
        snapshot = graph_fakes.snapshot_value(manifest)
        transcript = {
            "authority": subject.TRANSCRIPT_AUTHORITY,
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
        values = {
            "manifest": copy.deepcopy(manifest.value),
            "before": before,
            "snapshot": snapshot,
            "after": after,
            "transcript": transcript,
        }
        if self.mutator is not None:
            self.mutator(values, request)
        raws = {
            name: canonical(value, graph.MAX_MESSAGE_BYTES)
            for name, value in values.items()
        }
        if self.raw_mutator is not None:
            self.raw_mutator(raws, request)
        receipt_base = 1 if self.reuse_receipt_ids else self.capture_count
        before_receipt = stage_receipt(
            receipt_id=f"40000000-0000-4000-8000-{receipt_base * 2 - 1:012d}",
            sequence=1, phase="before", previous=None,
            record_sha=sha(raws["before"]), request=request,
            backend=self.identity_value, key=self.key)
        before_receipt_sha = sha(canonical(before_receipt))
        after_receipt = stage_receipt(
            receipt_id=f"40000000-0000-4000-8000-{receipt_base * 2:012d}",
            sequence=2, phase="after", previous=before_receipt_sha,
            record_sha=sha(raws["after"]), request=request,
            backend=self.identity_value, key=self.key)
        receipt = {
            "authority": subject.RECEIPT_AUTHORITY,
            "schemaVersion": 1,
            "requestSha256": request.sha256,
            "backendSha256": self.identity_value.sha256,
            "observerAdmissionSha256": sha(canonical(
                subject.observer_admission(self.plan, self.identity_value))),
            "sampleId": request.sample_id,
            "observerSessionId": request.observer_session_id,
            "runNonce": request.run_nonce,
            "phase": request.phase,
            "ordinal": request.ordinal,
            "manifestSha256": sha(raws["manifest"]),
            "beforeSha256": sha(raws["before"]),
            "snapshotSha256": sha(raws["snapshot"]),
            "afterSha256": sha(raws["after"]),
            "transcriptSha256": sha(raws["transcript"]),
            "startedNs": str(started),
            "capturedNs": str(captured),
            "finishedNs": str(finished),
            "beforeReceipt": before_receipt,
            "afterReceipt": after_receipt,
            "observationOnly": True,
            "complete": True,
            "readOnly": True,
            "inputEventsGenerated": 0,
            "writerCalls": 0,
            "penOperations": 0,
            "penLeaseAcquisitions": 0,
            "penLeaseTouches": 0,
            "quiescentBeforeReturn": True,
        }
        receipt["authenticator"] = hmac.new(
            self.key, canonical(receipt), hashlib.sha256).hexdigest()
        receipt_raw = canonical(receipt)
        if self.reuse_receipt_wire is not None:
            receipt_raw = self.reuse_receipt_wire
        wire = subject.encode_no_pen_wire(
            raws["manifest"], raws["before"], raws["snapshot"],
            raws["after"], raws["transcript"], receipt_raw)
        if self.wire_mutator is not None:
            wire = self.wire_mutator(wire)
        if self.drift_after_capture is not None:
            self.drift_after_capture(self)
        updates = {
            "wire": wire,
            "started_ns": started,
            "captured_ns": captured,
            "finished_ns": finished,
            "stderr": b"",
            "exit_code": 0,
            "eof": True,
            "input_events_generated": 0,
            "writer_calls": 0,
            "pen_operations": 0,
            "pen_lease_acquisitions": 0,
            "pen_lease_touches": 0,
            "quiescent_before_return": True,
        }
        updates.update(self.transport_updates)
        self.clock.advance()
        return subject.NoPenBackendTransportResult(**updates)


class EqualitySpoofIdentity:
    """Hostile non-authority wrapper accepted by equality-only checks."""

    def __init__(self, retained):
        self.retained = retained

    def __eq__(self, _other):
        return True

    @property
    def sha256(self):
        return self.retained.sha256

    def canonical_bytes(self):
        return self.retained.canonical_bytes()

    def validate(self, _plan):
        return None


class NoPenSemanticAdapterTests(unittest.TestCase):
    def setUp(self):
        for guard in (
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(subprocess, "Popen",
                         side_effect=AssertionError("process launch")),
        ):
            guard.start()
            self.addCleanup(guard.stop)
        self.fresh()

    def fresh(self):
        self.clock = Clock()
        self.plan = make_plan()
        self.backend = FakeBackend(self.plan, self.clock)
        self.task = make_task()
        self.foreign = make_foreign(self.task)
        self.phase = harness.BASE_PHASES[0]
        self.applied = host.AppliedPlacement(
            SESSION, 9, 7, 12, self.phase.placement,
            self.phase.placement, self.phase.rect)
        self.files = make_files()
        self.adapter = self.make_adapter()
        self.bind_backend_context()

    def make_adapter(self):
        return subject.NoPenSemanticAdapter(
            self.plan, self.backend, RECEIPT_KEY, clock=self.clock)

    def bind_backend_context(self):
        self.backend.current_phase = self.phase
        self.backend.current_applied = self.applied
        self.backend.current_foreign = self.foreign

    def capture(self, *, phase=None, ordinal=1, foreign=None, applied=None,
                task=None, files=None, deadline=None):
        phase = self.phase if phase is None else phase
        applied = self.applied if applied is None else applied
        foreign = self.foreign if foreign is None else foreign
        task = self.task if task is None else task
        files = self.files if files is None else files
        self.backend.current_phase = phase
        self.backend.current_applied = applied
        self.backend.current_foreign = foreign
        return self.adapter.capture(
            phase, ordinal, foreign, applied, task, files,
            self.clock() + 5_000_000_000 if deadline is None else deadline)

    def assert_sealed(self):
        with self.assertRaisesRegex(subject.NoPenSemanticError, "sealed"):
            self.adapter.verify()

    def test_success_is_harness_compatible_and_five_way_no_pen(self):
        before_canonical = self.adapter.canonical_bytes()
        capture = self.capture()
        self.assertIs(type(capture), harness.SemanticCapture)
        self.assertEqual((capture.input_events_generated,
                          capture.writer_calls, capture.pen_operations),
                         (0, 0, 0))
        self.assertEqual(capture.result["authority"], graph.RUNNER_AUTHORITY)
        self.assertEqual(capture.result["stage"], "FULL")
        self.assertEqual(capture.result["beforeAuthoritySha256"],
                         sha(canonical(capture.external_record)))
        graph.validate_snapshot(capture.result["snapshot"], capture.manifest,
                                capture.external_record)
        transcript = subject.decode_no_pen_wire(capture.transcript)[4]
        decoded = graph.load_canonical(transcript, 262_144).value
        self.assertEqual([decoded[name] for name in
                          ("inputEventsGenerated", "writerCalls",
                           "penOperations", "penLeaseAcquisitions",
                           "penLeaseTouches")], [0, 0, 0, 0, 0])
        self.assertEqual(before_canonical, self.adapter.canonical_bytes())
        self.adapter.assert_quiescent(self.clock() + 1_000_000_000)
        self.assertEqual(self.backend.capture_count, 1)

    def test_two_independent_samples_are_semantically_equal_but_fresh(self):
        first = self.capture(ordinal=1)
        second = self.capture(ordinal=2)
        projection = lambda item: {
            name: item.result["snapshot"][name] for name in
            ("lifecycle", "document", "pageInfo", "presenter", "views",
             "layers")
        }
        self.assertEqual(projection(first), projection(second))
        self.assertNotEqual(first.sample_id, second.sample_id)
        self.assertNotEqual(first.result["runNonce"], second.result["runNonce"])
        self.assertNotEqual(
            first.result["snapshot"]["coordinator"]["observerSessionId"],
            second.result["snapshot"]["coordinator"]["observerSessionId"])
        self.assertNotEqual(first.adapter_receipt_sha256,
                            second.adapter_receipt_sha256)

    def test_internal_identities_are_fresh_full_256_bit_values(self):
        captures = (self.capture(ordinal=1), self.capture(ordinal=2))
        samples = [item.sample_id for item in captures]
        observers = [
            item.result["snapshot"]["coordinator"]["observerSessionId"]
            for item in captures
        ]
        nonces = [item.result["runNonce"] for item in captures]
        for value in samples:
            self.assertRegex(value, r"\Asemantic-sample:[0-9a-f]{64}\Z")
            self.assertEqual(len(bytes.fromhex(value.rsplit(":", 1)[1])), 32)
        for value in observers:
            self.assertRegex(value, r"\Ano-pen-observer:[0-9a-f]{64}\Z")
            self.assertEqual(len(bytes.fromhex(value.rsplit(":", 1)[1])), 32)
        for value in nonces:
            self.assertRegex(value, r"\A[0-9a-f]{64}\Z")
            self.assertEqual(len(bytes.fromhex(value)), 32)
        entropy_values = (
            [value.rsplit(":", 1)[1] for value in samples] +
            [value.rsplit(":", 1)[1] for value in observers] + nonces
        )
        self.assertEqual(len(set(entropy_values)), 6)

    def test_caller_identity_factories_are_not_an_adapter_surface(self):
        calls = []

        def side_effecting_factory():
            calls.append("called")
            return "0" * 64

        for keyword in ("sample_id_factory", "observer_session_factory",
                        "nonce_factory"):
            with self.subTest(keyword=keyword):
                with self.assertRaisesRegex(TypeError,
                                            "unexpected keyword argument"):
                    subject.NoPenSemanticAdapter(
                        self.plan, self.backend, RECEIPT_KEY,
                        clock=self.clock,
                        **{keyword: side_effecting_factory})
        self.assertEqual(calls, [])

    def test_entropy_collision_and_failure_seal_without_dispatch(self):
        cases = (
            ("collision", {"side_effect": [1, 1]},
             subject.NoPenSemanticError),
            ("exception", {"side_effect": OSError("entropy failed")},
             subject.NoPenSemanticUncertain),
        )
        for name, configuration, expected in cases:
            with self.subTest(name=name):
                self.fresh()
                with patch.object(subject.secrets.SystemRandom, "getrandbits",
                                  **configuration):
                    with self.assertRaises(expected):
                        self.capture()
                self.assertEqual(self.backend.capture_count, 0)
                self.assertEqual(self.backend.quiescent_count, 0)
                self.assert_sealed()
                with self.assertRaisesRegex(subject.NoPenSemanticError,
                                            "sealed"):
                    self.capture()
                self.assertEqual(self.backend.capture_count, 0)

    def test_admission_is_explicitly_blocked(self):
        status = subject.admission_status()
        self.assertFalse(status["admitted"])
        self.assertTrue(status["observationOnly"])
        self.assertTrue(status["noPenLease"])
        self.assertFalse(status["realFixedBackendImplemented"])
        self.assertGreaterEqual(len(status["blockers"]), 3)

    def test_backend_capability_flags_fail_closed_at_construction(self):
        fields = (
            "input_capability", "writer_capability",
            "pen_operation_capability", "pen_lease_acquisition_capability",
            "pen_lease_touch_capability", "accepts_general_commands",
            "accepts_caller_argv", "user_document_selection",
        )
        for name in fields:
            with self.subTest(name=name):
                backend = FakeBackend(self.plan, self.clock)
                backend.identity_value = replace(
                    backend.identity_value, **{name: True})
                backend.canonical_value = backend.identity_value.canonical_bytes()
                with self.assertRaises(subject.NoPenSemanticError):
                    subject.NoPenSemanticAdapter(
                        self.plan, backend, RECEIPT_KEY, clock=self.clock)

    def test_backend_required_guards_cannot_be_false_or_truthy_ints(self):
        for value in (False, 1):
            with self.subTest(value=value):
                backend = FakeBackend(self.plan, self.clock)
                backend.identity_value = replace(
                    backend.identity_value, fixed_capture_only=value)
                backend.canonical_value = backend.identity_value.canonical_bytes()
                with self.assertRaises(subject.NoPenSemanticError):
                    subject.NoPenSemanticAdapter(
                        self.plan, backend, RECEIPT_KEY, clock=self.clock)

    def test_receipt_key_and_backend_canonical_identity_are_bound(self):
        backend = FakeBackend(self.plan, self.clock)
        with self.assertRaisesRegex(subject.NoPenSemanticError,
                                    "receipt capability"):
            subject.NoPenSemanticAdapter(
                self.plan, backend, b"T" * 32, clock=self.clock)
        backend = FakeBackend(self.plan, self.clock)
        backend.canonical_value += b"x"
        with self.assertRaisesRegex(subject.NoPenSemanticError,
                                    "identity/canonical"):
            subject.NoPenSemanticAdapter(
                self.plan, backend, RECEIPT_KEY, clock=self.clock)

    def test_task_foreign_raw_and_stable_identity_are_strictly_bound(self):
        variants = (
            replace(self.task, raw_sha256="z" * 64),
            replace(self.task, pid=self.task.pid + 1),
            replace(self.task, now_visible=False),
            replace(self.task, width=self.task.width + 1),
            replace(self.task, activity_token="xyz"),
        )
        for index, task in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture(task=task)
                self.assertEqual(self.backend.capture_count, 0)

        foreign = replace(self.foreign, evidence_sha256="0" * 64)
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture(foreign=foreign)
        self.assertEqual(self.backend.capture_count, 0)

    def test_host_placement_phase_and_deadline_are_closed(self):
        variants = (
            replace(self.applied, session=SESSION[:-1] + "2"),
            replace(self.applied, sequence=0),
            replace(self.applied, effective=host.Placement.LEFT),
            replace(self.applied, rect=host.Rect(0, 0, 1, 1)),
        )
        for applied in variants:
            with self.subTest(applied=applied):
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture(applied=applied)
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture(ordinal=3)
        with self.assertRaisesRegex(subject.NoPenSemanticError, "deadline"):
            self.capture(deadline=self.clock() + 100_000_000)
        self.assertEqual(self.backend.capture_count, 0)

    def test_file_uri_hash_and_strict_topology_are_bound_before_dispatch(self):
        cases = (
            make_files(sha256="f" * 64),
            make_files(uri=FIXTURE_URI + "x"),
            {**make_files(), "unexpected": True},
        )
        for files in cases:
            with self.subTest(files=list(files)):
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture(files=files)
        self.assertEqual(self.backend.capture_count, 0)

    def test_external_task_host_file_and_target_mutations_fail_closed(self):
        mutations = (
            lambda values, _request: values["before"].update(
                taskAuthoritySha256="f" * 64),
            lambda values, _request: values["before"]["host"].update(
                measuredGlobalFrame=[0, 0, 1, 1]),
            lambda values, _request: values["before"]["files"]["originalPdf"].update(
                sha256="f" * 64),
            lambda values, _request: values["before"]["target"].update(
                pid=999),
            lambda values, _request: values["before"]["observation"].update(
                penLeaseTouches=1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.fresh()
                self.backend.mutator = mutation
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()

    def test_external_after_drift_and_reused_capture_ids_fail_closed(self):
        self.backend.mutator = lambda values, _request: (
            values["after"]["host"].update(activityFocused=False))
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

        self.fresh()
        self.capture()
        self.backend.reuse_capture_ids = True
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture(ordinal=2)
        self.assert_sealed()

    def test_graph_v2_snapshot_validation_rejects_every_major_binding(self):
        mutations = (
            lambda values, _request: values["snapshot"].update(
                observationOnly=False),
            lambda values, _request: values["snapshot"]["externalSession"].update(
                taskId=999),
            lambda values, _request: values["snapshot"]["attachment"].update(
                pid=999),
            lambda values, _request: values["snapshot"]["fileAuthority"][
                "originalPdf"].update(sha256="f" * 64),
            lambda values, _request: values["snapshot"]["document"].update(
                uri="file:///wrong.pdf"),
            lambda values, _request: values["snapshot"]["views"].pop(
                "contentView"),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.fresh()
                self.backend.mutator = mutation
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()

    def test_all_transport_operation_counters_and_policy_flags_must_be_zero(self):
        fields = (
            "input_events_generated", "writer_calls", "pen_operations",
            "pen_lease_acquisitions", "pen_lease_touches",
        )
        for name in fields:
            with self.subTest(name=name):
                self.fresh()
                self.backend.transport_updates[name] = 1
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()
        for name, value in (("stderr", b"warning"), ("exit_code", 1),
                            ("eof", False),
                            ("quiescent_before_return", False)):
            with self.subTest(name=name):
                self.fresh()
                self.backend.transport_updates[name] = value
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()

    def test_transcript_and_receipt_zero_counters_are_independently_required(self):
        for record, field in (("transcript", "writerCalls"),
                              ("before", "penOperations")):
            with self.subTest(record=record, field=field):
                self.fresh()
                if record == "transcript":
                    self.backend.mutator = lambda values, _request: (
                        values["transcript"].update(writerCalls=1))
                else:
                    self.backend.mutator = lambda values, _request: (
                        values["before"]["observation"].update(
                            penOperations=1))
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()

    def test_authenticated_receipt_tampering_fails_closed(self):
        def corrupt(wire):
            decoded = list(subject.decode_no_pen_wire(wire))
            receipt = bytearray(decoded[-1])
            receipt[-2] ^= 1
            decoded[-1] = bytes(receipt)
            return subject.encode_no_pen_wire(*decoded)

        self.backend.wire_mutator = corrupt
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

    def test_authenticated_receipt_binding_and_chain_fail_closed(self):
        def mutate_receipt(wire):
            decoded = list(subject.decode_no_pen_wire(wire))
            item = json.loads(decoded[-1])
            item["afterReceipt"]["previousReceiptSha256"] = "0" * 64
            after = dict(item["afterReceipt"])
            after.pop("authenticator")
            item["afterReceipt"]["authenticator"] = hmac.new(
                RECEIPT_KEY, canonical(after), hashlib.sha256).hexdigest()
            body = dict(item)
            body.pop("authenticator")
            item["authenticator"] = hmac.new(
                RECEIPT_KEY, canonical(body), hashlib.sha256).hexdigest()
            decoded[-1] = canonical(item)
            return subject.encode_no_pen_wire(*decoded)

        self.backend.wire_mutator = mutate_receipt
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

    def test_reused_capture_and_receipt_identities_are_rejected(self):
        self.capture(ordinal=1)
        self.backend.reuse_capture_ids = True
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture(ordinal=2)
        self.assert_sealed()

        self.fresh()
        self.capture(ordinal=1)
        self.backend.reuse_receipt_ids = True
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture(ordinal=2)
        self.assert_sealed()

    def test_wire_rejects_trailing_missing_reordered_digest_and_bad_magic(self):
        payloads = tuple(b"{}" for _ in subject.WIRE_MEMBERS)
        valid = subject.encode_no_pen_wire(*payloads)
        mutations = {
            "trailing": valid + b"x",
            "truncated": valid[:-1],
            "bad-magic": b"BADMAGIC" + valid[8:],
            "digest": valid[:15] + bytes([valid[15] ^ 1]) + valid[16:],
            "reordered": (valid[:8] + bytes([2]) + valid[9:]),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(subject.NoPenSemanticError):
                    subject.decode_no_pen_wire(raw)

    def test_wire_rejects_oversized_header_before_payload_allocation(self):
        tag, _label, maximum = subject.WIRE_MEMBERS[0]
        raw = (subject.WIRE_MAGIC +
               struct.pack(">BI32s", tag, maximum + 1, b"\0" * 32) +
               b"\0" + b"\0" * 32)
        with self.assertRaisesRegex(subject.NoPenSemanticError, "oversized"):
            subject.decode_no_pen_wire(raw)

    def test_canonical_json_rejects_duplicate_keys_trailing_and_nan(self):
        overrides = (
            b'{"a":1,"a":1}',
            b'{"a":1}x',
            b'{"a":NaN}',
        )
        for raw in overrides:
            with self.subTest(raw=raw):
                self.fresh()
                self.backend.raw_mutator = lambda raws, _request, raw=raw: (
                    raws.update(snapshot=raw))
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()

    def test_backend_identity_drift_before_and_after_dispatch_seals(self):
        self.backend.identity_value = replace(
            self.backend.identity_value, worker_start_ticks=8_000_002)
        self.backend.canonical_value = self.backend.identity_value.canonical_bytes()
        with self.assertRaises(subject.NoPenSemanticError):
            self.adapter.verify()
        self.assert_sealed()

        self.fresh()
        self.backend.drift_after_capture = lambda backend: setattr(
            backend, "fail_verify", True)
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

    def test_backend_failure_and_quiescence_uncertainty_are_permanent(self):
        self.backend.fail_capture = True
        with self.assertRaises(subject.NoPenSemanticUncertain):
            self.capture()
        self.assert_sealed()
        with self.assertRaises(subject.NoPenSemanticUncertain):
            self.adapter.assert_quiescent(self.clock() + 1_000_000_000)

        self.fresh()
        self.backend.fail_quiescent_at = 1
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()

    def test_deadline_transport_order_and_publication_are_fail_closed(self):
        cases = (
            {"finished_ns": self.clock() + 2_000_000_000},
            {"captured_ns": self.clock() - 1},
            {"started_ns": self.clock() + 10, "finished_ns": self.clock() + 5},
        )
        for updates in cases:
            with self.subTest(updates=updates):
                self.fresh()
                self.backend.transport_updates.update(updates)
                with self.assertRaises(subject.NoPenSemanticError):
                    self.capture()
                self.assert_sealed()

        self.fresh()
        self.backend.drift_after_capture = lambda backend: setattr(
            backend.clock, "now", self.clock() + 2_000_000_000)
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

    def test_monotonic_clock_regression_seals(self):
        self.capture()
        self.clock.now -= 100
        with self.assertRaises(subject.NoPenSemanticUncertain):
            self.adapter.assert_quiescent(self.clock() + 1_000_000_000)

    def test_retained_clock_is_bound_to_host_plan_and_backend(self):
        for field in ("clock_authority_sha256", "monotonic_domain_sha256"):
            with self.subTest(plan_field=field):
                plan = replace(self.plan, **{field: "d" * 64})
                backend = FakeBackend(plan, self.clock)
                with self.assertRaisesRegex(
                        subject.NoPenSemanticError,
                        "clock differs from HostAuthority plan"):
                    subject.NoPenSemanticAdapter(
                        plan, backend, RECEIPT_KEY, clock=self.clock)

        backend = FakeBackend(self.plan, self.clock)
        backend.identity_value = replace(
            backend.identity_value, monotonic_domain_sha256="d" * 64)
        backend.canonical_value = backend.identity_value.canonical_bytes()
        with self.assertRaisesRegex(subject.NoPenSemanticError,
                                    "monotonic authority"):
            subject.NoPenSemanticAdapter(
                self.plan, backend, RECEIPT_KEY, clock=self.clock)

    def test_monotonic_domain_identity_matches_plan_and_rejects_drift(self):
        self.assertEqual(self.adapter.monotonic_domain_identity(),
                         self.plan.monotonic_domain_sha256)
        self.clock.domain_value = canonical({
            "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
            "schemaVersion": 1,
            "kind": "monotonic-domain-identity",
            "domainId": "d" * 64,
            "providerInstanceId": "a" * 64,
            "unit": "nanoseconds",
        })
        with self.assertRaises(subject.NoPenSemanticError):
            self.adapter.monotonic_domain_identity()
        self.assert_sealed()

    def test_clock_authorities_are_strict_canonical_records_not_claim_flags(self):
        variants = (
            ("canonical_value", CLOCK_AUTHORITY_RAW + b"x"),
            ("canonical_value", canonical({
                "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
                "schemaVersion": 1,
                "kind": "retained-provider-authority",
                "providerInstanceId": "a" * 64,
                "providerImageSha256": "b" * 64,
                "sameAsHostAuthority": True,
            })),
            ("domain_value", canonical({
                "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
                "schemaVersion": 1,
                "kind": "monotonic-domain-identity",
                "domainId": "c" * 64,
                "providerInstanceId": "d" * 64,
                "unit": "nanoseconds",
            })),
            ("domain_value", b'{"authority":1,"authority":1}'),
        )
        for field, value in variants:
            with self.subTest(field=field, value=value[-20:]):
                clock = Clock()
                setattr(clock, field, value)
                with self.assertRaises(subject.NoPenSemanticError):
                    subject.NoPenSemanticAdapter(
                        self.plan, self.backend, RECEIPT_KEY, clock=clock)

    def test_clock_substitution_drift_and_verification_failure_seal(self):
        self.clock.canonical_value = canonical({
            "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
            "schemaVersion": 1,
            "kind": "retained-provider-authority",
            "providerInstanceId": "d" * 64,
            "providerImageSha256": "b" * 64,
        })
        with self.assertRaises(subject.NoPenSemanticError):
            self.adapter.verify()
        self.assert_sealed()

        self.fresh()
        self.backend.drift_after_capture = lambda _backend: setattr(
            self.clock, "domain_value", canonical({
                "authority": subject.MONOTONIC_CLOCK_AUTHORITY,
                "schemaVersion": 1,
                "kind": "monotonic-domain-identity",
                "domainId": "d" * 64,
                "providerInstanceId": "a" * 64,
                "unit": "nanoseconds",
            }))
        with self.assertRaises(subject.NoPenSemanticUncertain):
            self.capture()
        self.assert_sealed()

        self.fresh()
        self.clock.fail_verify = True
        with self.assertRaises(subject.NoPenSemanticUncertain):
            self.adapter.verify()
        self.assert_sealed()

    def test_stalled_clock_cannot_attest_an_external_capture(self):
        self.clock.stalled = True
        with self.assertRaisesRegex(subject.NoPenSemanticError,
                                    "incomplete, late, or not no-pen"):
            self.capture()
        self.assertEqual(self.backend.capture_count, 1)
        self.assert_sealed()

    def test_reentrant_capture_is_rejected_and_outer_capture_cannot_publish(self):
        attempted = []

        def reenter():
            with self.assertRaises(subject.NoPenSemanticUncertain):
                self.capture()
            attempted.append(True)

        self.backend.reenter = reenter
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assertEqual(attempted, [True])
        self.assertEqual(self.backend.capture_count, 1)
        self.assert_sealed()

    def test_strict_manifest_is_adapter_constructed_not_backend_selected(self):
        self.backend.mutator = lambda values, _request: (
            values["manifest"]["coordinator"].update(noRetry=False))
        with self.assertRaisesRegex(subject.NoPenSemanticError,
                                    "manifest differs"):
            self.capture()
        self.assert_sealed()

    def test_before_after_capture_time_brackets_are_enforced(self):
        self.backend.mutator = lambda values, _request: (
            values["before"].update(capturedNs="999999999999"))
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

    def test_receipt_transport_time_binding_is_enforced(self):
        self.backend.transport_updates["captured_ns"] = self.clock() + 2
        with self.assertRaises(subject.NoPenSemanticError):
            self.capture()
        self.assert_sealed()

    def test_quiescence_success_rechecks_backend_and_deadline(self):
        self.adapter.assert_quiescent(self.clock() + 1_000_000_000)
        self.assertEqual(self.backend.quiescent_count, 1)
        with self.assertRaises(subject.NoPenSemanticError):
            self.adapter.assert_quiescent(self.clock())

    def test_late_pre_capture_quiescence_never_dispatches_capture(self):
        self.backend.advance_quiescent_at = 1
        self.backend.quiescent_advance_ns = 1_000_000_000
        with self.assertRaisesRegex(subject.NoPenSemanticError,
                                    "pre-capture quiescence"):
            self.capture()
        self.assertEqual(self.backend.capture_count, 0)
        self.assert_sealed()

    def test_public_quiescence_rechecks_clock_after_backend_return(self):
        self.backend.advance_quiescent_at = 1
        self.backend.quiescent_advance_ns = 1_000_000_000
        deadline = self.clock() + 1_000_000_000
        with self.assertRaisesRegex(subject.NoPenSemanticUncertain,
                                    "quiescence is uncertain"):
            self.adapter.assert_quiescent(deadline)
        self.assertEqual(self.backend.capture_count, 0)
        self.assertEqual(self.backend.quiescent_count, 1)
        self.assert_sealed()

    def test_public_quiescence_rejects_equality_spoof_identity(self):
        retained = self.backend.identity_value
        self.backend.identity_value = EqualitySpoofIdentity(retained)
        self.backend.canonical_value = retained.canonical_bytes()
        with self.assertRaisesRegex(subject.NoPenSemanticUncertain,
                                    "quiescence is uncertain"):
            self.adapter.assert_quiescent(self.clock() + 1_000_000_000)
        self.assertEqual(self.backend.quiescent_count, 1)
        self.assertEqual(self.backend.capture_count, 0)
        self.assert_sealed()


if __name__ == "__main__":
    unittest.main()
