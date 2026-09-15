"""Deterministic fake-only S1b tests; no ADB, device, process, or network I/O."""
from __future__ import annotations

from dataclasses import replace
import inspect
import threading
import unittest

import native_page_private_adb_mutator as mut


SESSION = "a" * 64
ADB_SESSION = "b" * 64
WORKER_SESSION = "c" * 64
IMAGE_ID = "d" * 64
IMAGE_SHA = "e" * 64
BUNDLE_SHA = "f" * 64
WORKER_SHA = "1" * 64


class EqualString(str):
    """Value-equal string subtype that must never satisfy a wire contract."""


class EqualInteger(int):
    """Value-equal integer subtype that must never satisfy a wire contract."""


class FakeClock:
    def __init__(self):
        self.value = 1_000_000_000

    def now_ns(self):
        return self.value

    def advance(self, value=1_000_000):
        self.value += value


class FakeAdb:
    def __init__(self, binding):
        self.value = binding
        self.changed = False

    def binding(self):
        return replace(self.value, serial="DRIFT") if self.changed else self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise mut.DeviceFridaError("private ADB drift")


class FakeWorker:
    def __init__(self, binding):
        self.value = binding
        self.changed = False

    def binding(self):
        return replace(self.value, pid=999) if self.changed else self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise mut.DeviceFridaError("worker drift")


class FakeImage:
    def __init__(self, identity):
        self.value = identity
        self.changed = False

    def identity(self):
        return replace(self.value, sha256="0" * 64) if self.changed else self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise mut.DeviceFridaError("image drift")


class FakeBackend:
    """Stateful fixed-operation adapter with per-occurrence fault injection."""

    def __init__(self, clock, binding, policy, image):
        self.clock = clock
        self.value = binding
        self.policy = policy
        self.image = image
        self.changed = False
        self.calls = []
        self.counts = {}
        self.faults = {}
        self.quiescent_sequences = []
        self.file = None
        self.guardian = None
        self.server = None
        self.handshake = None
        self.guardian_active = False
        self.server_active = False

    def binding(self):
        return replace(self.value, serial="DRIFT") if self.changed else self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise mut.DeviceFridaError("backend drift")

    def assert_operation_quiescent(self, expected, sequence, deadline_ns):
        if expected != self.value:
            raise mut.DeviceFridaError("backend quiescence binding drift")
        if self.clock.now_ns() >= deadline_ns:
            raise mut.DeviceFridaError("backend quiescence deadline")
        self.quiescent_sequences.append(sequence)
        fault = self.faults.get(f"quiescence:{sequence}")
        if isinstance(fault, BaseException):
            raise fault

    def assert_all_quiescent(self, expected, deadline_ns):
        if (expected != self.value or self.clock.now_ns() >= deadline_ns or
                self.faults.get("all_quiescent")):
            raise mut.DeviceFridaError("backend operations are not quiescent")

    def _ack(self, request):
        return mut.MutationAck(
            mut.ACK_AUTHORITY, request.session_id, request.serial, request.sequence,
            request.operation, request.sha256(), request.issued_ns,
            self.clock.now_ns())

    def _return(self, name, request, receipt, *arguments):
        count = self.counts.get(name, 0) + 1
        self.counts[name] = count
        self.calls.append((name, request, arguments))
        self.clock.advance()
        receipt = replace(receipt, ack=replace(receipt.ack,
                                               produced_ns=self.clock.now_ns()))
        fault = self.faults.get(f"{name}:{count}", self.faults.get(name))
        if isinstance(fault, BaseException):
            raise fault
        if callable(fault):
            receipt = fault(receipt, request, self)
        return receipt

    def _file(self, path, mode):
        return mut.DeviceFileIdentity(path, self.image.sha256, self.image.size,
                                      2000, 2000, mode, 41, 73, 1, True, False,
                                      path, self.policy.staging_directory(),
                                      2000, 2000, 0o700, 41, 72, True, False, True)

    def _guardian(self, path, port):
        return mut.GuardianIdentity(
            mut.GUARDIAN_AUTHORITY, self.policy.session_id, self.policy.serial,
            301, 9001, 0, 0,
            ("rtl-reader-frida-guardian-v1", self.policy.session_id, path, str(port)),
            "2" * 64, True, ADB_SESSION, WORKER_SESSION)

    def _server(self, guardian, file, cmdline):
        return mut.ServerIdentity(
            mut.SERVER_AUTHORITY, self.policy.server_session_id(self.image),
            guardian.control_channel_id, 302, 9002, 0, 0, cmdline, file.path,
            file.sha256, file.device, file.inode, "127.0.0.1",
            self.policy.device_port)

    def sync_retained_image(self, request, image, path):
        self.file = self._file(path, 0o600)
        receipt = mut.SyncReceipt(self._ack(request), self.image.size, True, True, self.file)
        return self._return("sync_image", request, receipt, image, path)

    def inspect_staged_file(self, request, path):
        if self.file is None:
            raise mut.DeviceFridaError("file absent")
        return self._return("inspect_file", request,
                            mut.FileReceipt(self._ack(request), self.file), path)

    def create_root_guardian(self, request, path, device_port):
        self.guardian = self._guardian(path, device_port)
        self.guardian_active = True
        return self._return("create_guardian", request,
                            mut.GuardianReceipt(self._ack(request), self.guardian),
                            path, device_port)

    def start_exact_server(self, request, guardian, file, cmdline):
        self.file = replace(file, mode=0o700)
        self.server = self._server(guardian, self.file, cmdline)
        self.server_active = True
        return self._return("start_server", request,
                            mut.StartReceipt(self._ack(request), self.file, self.server),
                            guardian, file, cmdline)

    def handshake_exact_server(self, request, guardian, server):
        self.handshake = mut.HandshakeIdentity(
            mut.HANDSHAKE_AUTHORITY, self.policy.server_session_id(self.image), server.pid,
            server.start_ticks, self.image.version, self.image.protocol)
        return self._return("handshake", request,
                            mut.HandshakeReceipt(self._ack(request), self.handshake),
                            guardian, server)

    def observe_ready(self, request, guardian, server, file):
        observation = mut.ReadyObservation(
            self.file, self.guardian, self.server, self.handshake, True,
            self.guardian_active, self.guardian_active, self.server_active)
        return self._return("observe_ready", request,
                            mut.ObservationReceipt(self._ack(request), observation),
                            guardian, server, file)

    def stop_exact_server(self, request, guardian, server):
        self.server_active = False
        return self._return("stop_server", request,
                            mut.StopReceipt(self._ack(request), guardian, server,
                                            True, True, True, True, True), guardian, server)

    def unlink_exact_file(self, request, guardian, file):
        self.file = None
        return self._return("unlink_file", request,
                            mut.UnlinkReceipt(self._ack(request), file, True, True),
                            guardian, file)

    def unlink_unlaunched_file(self, request, file):
        self.file = None
        return self._return("unlink_unlaunched_file", request,
                            mut.UnlinkReceipt(self._ack(request), file, True, True), file)

    def stop_exact_guardian(self, request, guardian):
        self.guardian_active = False
        return self._return("stop_guardian", request,
                            mut.GuardianStopReceipt(self._ack(request), guardian,
                                                    True, True, True),
                            guardian)

    def prove_absent(self, request, path, server, guardian):
        proof = mut.AbsenceProof(
            mut.ABSENCE_AUTHORITY, self.policy.session_id, self.policy.serial, path,
            self.policy.staging_directory(),
            server.pid if server else None, server.start_ticks if server else None,
            guardian.pid if guardian else None,
            guardian.start_ticks if guardian else None,
            self.file is None, self.file is None, not self.server_active,
            not self.guardian_active, not self.server_active, True, True, True)
        return self._return("prove_absent", request,
                            mut.AbsenceReceipt(self._ack(request), proof),
                            path, server, guardian)


def fixture():
    clock = FakeClock()
    policy = mut.RunPolicy(SESSION, "SN078C10015092", 31337)
    adb_binding = mut.PrivateAdbBinding(
        mut.PRIVATE_ADB_AUTHORITY, policy.serial, "tcp:127.0.0.1:41337",
        101, 7001, BUNDLE_SHA, ADB_SESSION, True, True, True, False)
    worker_binding = mut.WorkerBinding(
        mut.WORKER_AUTHORITY, WORKER_SESSION, 201, 8001, WORKER_SHA, True, True)
    backend_binding = mut.BackendBinding(
        mut.BACKEND_AUTHORITY, policy.serial, ADB_SESSION,
        adb_binding.endpoint, adb_binding.server_pid, adb_binding.server_start_ticks,
        WORKER_SESSION, worker_binding.pid, worker_binding.start_ticks,
        worker_binding.image_sha256, True, True, False, True, True, True, True)
    image_identity = mut.FridaImageIdentity(
        mut.IMAGE_AUTHORITY, IMAGE_ID, IMAGE_SHA, 8_388_608,
        "17.2.17", "frida-core-17", "arm64-v8a", True)
    adb = FakeAdb(adb_binding)
    worker = FakeWorker(worker_binding)
    image = FakeImage(image_identity)
    backend = FakeBackend(clock, backend_binding, policy, image_identity)
    authority = mut.AuthenticatedDeviceFridaAuthority(
        policy=policy, private_adb=adb, worker=worker, image=image,
        backend=backend, clock=clock)
    return authority, backend, clock, adb, worker, image


def deadline(clock):
    return clock.now_ns() + mut.TARGET_TOTAL_BUDGET_NS


class DeviceFridaAuthorityTests(unittest.TestCase):
    def test_success_binds_exact_lifecycle_and_proves_absence(self):
        authority, backend, clock, *_ = fixture()
        lease = authority.start(deadline(clock))
        self.assertEqual(authority.state, "READY")
        self.assertEqual(lease.file.path,
                         f"{mut.STAGING_PREFIX}/{SESSION}/frida-server-{IMAGE_SHA[:16]}")
        self.assertEqual(lease.file.mode, 0o700)
        self.assertEqual(lease.server.executable_inode, lease.file.inode)
        self.assertEqual(lease.server.listen_port, 31337)
        self.assertNotEqual(lease.server.session_id, SESSION)
        self.assertEqual(lease.handshake.version, "17.2.17")
        self.assertEqual([x[0] for x in backend.calls], [
            "sync_image", "inspect_file", "create_guardian", "inspect_file",
            "start_server", "handshake", "observe_ready"])
        self.assertEqual(backend.quiescent_sequences, list(range(1, 8)))
        self.assertEqual(authority.verify_ready(deadline(clock)), lease)
        evidence = authority.teardown(deadline(clock))
        self.assertEqual(authority.state, "CLOSED")
        self.assertTrue(evidence.final_absence.file_absent)
        self.assertTrue(evidence.final_absence.server_absent)
        self.assertTrue(evidence.final_absence.guardian_absent)
        self.assertFalse(evidence.hardware_timing_proven)
        self.assertEqual([x[0] for x in backend.calls[-6:]], [
            "observe_ready", "stop_server", "inspect_file", "unlink_file",
            "stop_guardian", "prove_absent"])
        before = len(backend.calls)
        self.assertEqual(authority.teardown(deadline(clock)), evidence)
        self.assertEqual(len(backend.calls), before)
        authority.assert_quiescent(deadline(clock))
        authority.assert_quiescent(deadline(clock))
        self.assertEqual([x[0] for x in backend.calls[-2:]],
                         ["prove_absent", "prove_absent"])

    def test_public_authority_has_no_general_command_path_or_payload_surface(self):
        authority, *_ = fixture()
        public = {name for name, _ in inspect.getmembers(authority, callable)
                  if not name.startswith("_")}
        self.assertEqual(public,
                         {"assert_quiescent", "evidence", "start", "teardown",
                          "verify_ready"})
        for forbidden in ("run", "execute", "shell", "push", "kill", "unlink",
                          "command", "write"):
            self.assertNotIn(forbidden, public)

    def test_policy_rejects_default_shared_ports_paths_and_inexact_values(self):
        bad = [
            replace(mut.RunPolicy(SESSION, "SN", 31337), session_id="A" * 64),
            replace(mut.RunPolicy(SESSION, "SN", 31337), serial="bad serial"),
            replace(mut.RunPolicy(SESSION, "SN", 31337), device_port=27042),
            replace(mut.RunPolicy(SESSION, "SN", 31337), device_port=5037),
            replace(mut.RunPolicy(SESSION, "SN", 31337), device_port=29999),
            replace(mut.RunPolicy(SESSION, "SN", 31337), staging_uid=0),
            replace(mut.RunPolicy(SESSION, "SN", 31337), staged_mode=0o777),
            replace(mut.RunPolicy(SESSION, "SN", 31337), operation_budget_ns=True),
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(mut.DeviceFridaError):
                value.validate()

    def test_all_policy_and_binding_scalars_require_exact_builtin_types(self):
        authority, backend, _clock, adb, worker, image = fixture()
        policy = authority.policy
        policy_mutations = {
            "session_id": EqualString(policy.session_id),
            "serial": EqualString(policy.serial),
            "device_port": float(policy.device_port),
            "operation_budget_ns": EqualInteger(policy.operation_budget_ns),
            "total_budget_ns": float(policy.total_budget_ns),
            "staging_uid": EqualInteger(policy.staging_uid),
            "staging_gid": float(policy.staging_gid),
            "staged_mode": EqualInteger(policy.staged_mode),
            "running_mode": float(policy.running_mode),
        }
        for field, value in policy_mutations.items():
            with self.subTest(kind="policy", field=field), self.assertRaises(
                    mut.DeviceFridaError):
                replace(policy, **{field: value}).validate()

        adb_mutations = {
            "authority": EqualString(adb.value.authority),
            "serial": EqualString(adb.value.serial),
            "endpoint": EqualString(adb.value.endpoint),
            "server_pid": float(adb.value.server_pid),
            "server_start_ticks": EqualInteger(adb.value.server_start_ticks),
            "bundle_sha256": EqualString(adb.value.bundle_sha256),
            "session_id": EqualString(adb.value.session_id),
            "retained_server_handle": 1,
            "explicit_serial": 1,
            "private_socket": 1,
            "shared_server": 0,
        }
        for field, value in adb_mutations.items():
            with self.subTest(kind="adb", field=field), self.assertRaises(
                    mut.DeviceFridaError):
                replace(adb.value, **{field: value}).validate()

        worker_mutations = {
            "authority": EqualString(worker.value.authority),
            "session_id": EqualString(worker.value.session_id),
            "pid": float(worker.value.pid),
            "start_ticks": EqualInteger(worker.value.start_ticks),
            "image_sha256": EqualString(worker.value.image_sha256),
            "retained_process_handle": 1,
            "isolated": 1,
        }
        for field, value in worker_mutations.items():
            with self.subTest(kind="worker", field=field), self.assertRaises(
                    mut.DeviceFridaError):
                replace(worker.value, **{field: value}).validate()

        backend_mutations = {
            "authority": EqualString(backend.value.authority),
            "serial": EqualString(backend.value.serial),
            "private_adb_session_id": EqualString(backend.value.private_adb_session_id),
            "private_adb_endpoint": EqualString(backend.value.private_adb_endpoint),
            "private_adb_pid": float(backend.value.private_adb_pid),
            "private_adb_start_ticks": EqualInteger(
                backend.value.private_adb_start_ticks),
            "worker_session_id": EqualString(backend.value.worker_session_id),
            "worker_pid": float(backend.value.worker_pid),
            "worker_start_ticks": EqualInteger(backend.value.worker_start_ticks),
            "worker_image_sha256": EqualString(backend.value.worker_image_sha256),
            "private_socket": 1,
            "explicit_serial_every_operation": 1,
            "accepts_general_commands": 0,
            "retained_worker_handle": 1,
            "fresh_reply_channel_per_operation": 1,
            "late_ack_channel_sealed_before_return": 1,
            "failure_returns_after_operation_quiescence": 1,
        }
        for field, value in backend_mutations.items():
            with self.subTest(kind="backend", field=field), self.assertRaises(
                    mut.DeviceFridaError):
                replace(backend.value, **{field: value}).validate(adb.value, worker.value)

        image_mutations = {
            "authority": EqualString(image.value.authority),
            "retained_id": EqualString(image.value.retained_id),
            "sha256": EqualString(image.value.sha256),
            "size": float(image.value.size),
            "version": EqualString(image.value.version),
            "protocol": EqualString(image.value.protocol),
            "abi": EqualString(image.value.abi),
            "retained_bytes": 1,
        }
        for field, value in image_mutations.items():
            with self.subTest(kind="image", field=field), self.assertRaises(
                    mut.DeviceFridaError):
                replace(image.value, **{field: value}).validate()

    def test_constructor_rejects_ambient_or_drifting_bindings(self):
        authority, backend, clock, adb, worker, image = fixture()
        cases = [
            ("adb", replace(adb.value, endpoint="tcp:127.0.0.1:5037")),
            ("adb", replace(adb.value, shared_server=True)),
            ("adb", replace(adb.value, retained_server_handle=False)),
            ("worker", replace(worker.value, retained_process_handle=False)),
            ("backend", replace(backend.value, accepts_general_commands=True)),
            ("backend", replace(backend.value, explicit_serial_every_operation=False)),
            ("backend", replace(backend.value, private_adb_pid=102)),
            ("backend", replace(backend.value,
                                private_adb_endpoint="tcp:127.0.0.1:5037")),
            ("backend", replace(backend.value, worker_pid=202)),
            ("backend", replace(backend.value, worker_image_sha256="0" * 64)),
            ("backend", replace(backend.value, retained_worker_handle=False)),
            ("backend", replace(backend.value, fresh_reply_channel_per_operation=False)),
            ("backend", replace(backend.value,
                                late_ack_channel_sealed_before_return=False)),
            ("backend", replace(backend.value,
                                failure_returns_after_operation_quiescence=False)),
            ("image", replace(image.value, retained_bytes=False)),
            ("image", replace(image.value, abi="x86_64")),
        ]
        for target, value in cases:
            with self.subTest(target=target):
                _, b, c, a, w, i = fixture()
                if target == "adb": a.value = value
                elif target == "worker": w.value = value
                elif target == "backend": b.value = value
                else: i.value = value
                with self.assertRaises(mut.DeviceFridaError):
                    mut.AuthenticatedDeviceFridaAuthority(
                        policy=b.policy, private_adb=a, worker=w, image=i,
                        backend=b, clock=c)
        self.assertEqual(authority.state, "NEW")

    def test_sync_rejects_partial_or_substituted_file_and_seals(self):
        alterations = [
            lambda value: replace(value, transferred_bytes=value.transferred_bytes - 1),
            lambda value: replace(value, complete=False),
            lambda value: replace(value, directory_created_exclusively=False),
            lambda value: replace(value, file=replace(value.file, path="/data/local/tmp/evil")),
            lambda value: replace(value, file=replace(value.file, sha256="0" * 64)),
            lambda value: replace(value, file=replace(value.file, size=value.file.size - 1)),
            lambda value: replace(value, file=replace(value.file, uid=0)),
            lambda value: replace(value, file=replace(value.file, gid=0)),
            lambda value: replace(value, file=replace(value.file, mode=0o777)),
            lambda value: replace(value, file=replace(value.file, nlink=2)),
            lambda value: replace(value, file=replace(value.file, symlink=True)),
            lambda value: replace(value, file=replace(value.file, regular=False)),
            lambda value: replace(value, file=replace(value.file, resolved_path="/data/other")),
            lambda value: replace(value, file=replace(value.file, parent_symlink=True)),
            lambda value: replace(value, file=replace(value.file,
                                                       ancestors_symlink_free=False)),
        ]
        for alteration in alterations:
            with self.subTest(alteration=alteration):
                authority, backend, clock, *_ = fixture()
                backend.faults["sync_image"] = lambda receipt, _r, _b, f=alteration: f(receipt)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
                count = len(backend.calls)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.teardown(deadline(clock))
                self.assertEqual(len(backend.calls), count)

    def test_every_start_publication_edge_fails_closed(self):
        expected_states = {
            "sync_image": "CLEANUP_UNCERTAIN",
            "inspect_file:1": "FAILED_CLEAN",
            "create_guardian": "CLEANUP_UNCERTAIN",
            "inspect_file:2": "FAILED_CLEAN",
            "start_server": "CLEANUP_UNCERTAIN",
            "handshake": "FAILED_CLEAN",
            "observe_ready": "FAILED_CLEAN",
        }
        for operation, expected_state in expected_states.items():
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                backend.faults[operation] = mut.DeviceFridaError("injected edge failure")
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, expected_state)
                self.assertIsNone(authority.evidence().ready_lease)
                count = len(backend.calls)
                if expected_state == "FAILED_CLEAN":
                    self.assertIsNotNone(authority.evidence().final_absence)
                    authority.assert_quiescent(deadline(clock))
                    self.assertEqual(len(backend.calls), count + 1)
                else:
                    with self.assertRaises(mut.CleanupUncertain):
                        authority.assert_quiescent(deadline(clock))
                    self.assertEqual(len(backend.calls), count)

    def test_ack_rejects_stale_late_cross_session_and_substitution(self):
        faults = [
            lambda ack, request: replace(ack, sequence=request.sequence - 1),
            lambda ack, request: replace(ack, sequence=True),
            lambda ack, request: replace(ack, session_id="9" * 64),
            lambda ack, request: replace(ack, serial="OTHER"),
            lambda ack, request: replace(ack, operation="inspect_file"),
            lambda ack, request: replace(ack, request_sha256="0" * 64),
            lambda ack, request: replace(ack, issued_ns=request.issued_ns - 1),
            lambda ack, request: replace(ack, produced_ns=request.issued_ns - 1),
            lambda ack, request: replace(ack, produced_ns=request.deadline_ns),
        ]
        for fault in faults:
            with self.subTest(fault=fault):
                authority, backend, clock, *_ = fixture()
                backend.faults["sync_image"] = (
                    lambda receipt, request, _backend, f=fault:
                    replace(receipt, ack=f(receipt.ack, request)))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")

    def test_ack_and_sync_receipt_scalars_require_exact_builtin_types(self):
        ack_mutations = {
            "authority": lambda ack: EqualString(ack.authority),
            "session_id": lambda ack: EqualString(ack.session_id),
            "serial": lambda ack: EqualString(ack.serial),
            "sequence": lambda ack: float(ack.sequence),
            "operation": lambda ack: EqualString(ack.operation),
            "request_sha256": lambda ack: EqualString(ack.request_sha256),
            "issued_ns": lambda ack: EqualInteger(ack.issued_ns),
            "produced_ns": lambda ack: float(ack.produced_ns),
        }
        for field, convert in ack_mutations.items():
            with self.subTest(kind="ack", field=field):
                authority, backend, clock, *_ = fixture()
                backend.faults["sync_image"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, ack=replace(
                        receipt.ack, **{field: convert(receipt.ack)})))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

        receipt_mutations = {
            "transferred_bytes": lambda value: float(value),
            "complete": lambda _value: 1,
            "directory_created_exclusively": lambda _value: 1,
        }
        for field, convert in receipt_mutations.items():
            with self.subTest(kind="sync_receipt", field=field):
                authority, backend, clock, *_ = fixture()
                backend.faults["sync_image"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, **{field: convert(getattr(receipt, field))}))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

    def test_device_file_scalars_require_exact_builtin_types(self):
        mutations = {
            "path": lambda value: EqualString(value),
            "sha256": lambda value: EqualString(value),
            "size": lambda value: float(value),
            "uid": lambda value: EqualInteger(value),
            "gid": lambda value: float(value),
            "mode": lambda value: EqualInteger(value),
            "device": lambda value: float(value),
            "inode": lambda value: EqualInteger(value),
            "nlink": lambda value: float(value),
            "regular": lambda _value: 1,
            "symlink": lambda _value: 0,
            "resolved_path": lambda value: EqualString(value),
            "parent_path": lambda value: EqualString(value),
            "parent_uid": lambda value: float(value),
            "parent_gid": lambda value: EqualInteger(value),
            "parent_mode": lambda value: float(value),
            "parent_device": lambda value: EqualInteger(value),
            "parent_inode": lambda value: float(value),
            "parent_directory": lambda _value: 1,
            "parent_symlink": lambda _value: 0,
            "ancestors_symlink_free": lambda _value: 1,
        }
        for field, convert in mutations.items():
            with self.subTest(field=field):
                authority, backend, clock, *_ = fixture()
                backend.faults["sync_image"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, file=replace(
                        receipt.file, **{field: convert(getattr(receipt.file, field))})))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

    def test_unsealed_late_ack_channel_is_sticky_and_cannot_feed_next_call(self):
        authority, backend, clock, *_ = fixture()
        backend.faults["quiescence:1"] = mut.DeviceFridaError("late ACK channel open")
        with self.assertRaises(mut.DeviceFridaError):
            authority.start(deadline(clock))
        self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
        self.assertEqual([entry[0] for entry in backend.calls], ["sync_image"])
        before = len(backend.calls)
        with self.assertRaises(mut.DeviceFridaError):
            authority.start(deadline(clock))
        self.assertEqual(len(backend.calls), before)

    def test_file_replacement_and_hardlink_before_start_are_rejected(self):
        changes = [
            {"inode": 74}, {"device": 42}, {"nlink": 2}, {"symlink": True},
            {"sha256": "0" * 64}, {"mode": 0o700},
        ]
        for values in changes:
            with self.subTest(values=values):
                authority, backend, clock, *_ = fixture()
                def replace_file(receipt, _request, fake, values=values):
                    fake.file = replace(receipt.file, **values)
                    return replace(receipt, file=fake.file)
                backend.faults["inspect_file:2"] = replace_file
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")

    def test_chmod_start_retains_parent_identity_and_changes_only_file_mode(self):
        for field, value in (("parent_device", 42), ("parent_inode", 99)):
            with self.subTest(field=field):
                authority, backend, clock, *_ = fixture()

                def replace_parent(receipt, _request, _backend,
                                   field=field, value=value):
                    return replace(receipt, file=replace(
                        receipt.file, **{field: value}))

                backend.faults["start_server"] = replace_parent
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")

        authority, backend, clock, *_ = fixture()
        lease = authority.start(deadline(clock))
        start_call = next(call for call in backend.calls if call[0] == "start_server")
        staged_file = start_call[2][1]
        self.assertEqual(lease.file, replace(staged_file, mode=0o700))
        self.assertEqual(lease.file.parent_device, 41)
        self.assertEqual(lease.file.parent_inode, 72)
        self.assertEqual(lease.file.mode, 0o700)

    def test_guardian_must_be_exact_retained_root_control_channel(self):
        changes = [
            {"uid": 2000}, {"uid": False}, {"gid": 2000}, {"gid": False},
            {"session_id": "9" * 64},
            {"serial": "OTHER"}, {"pid": 0}, {"start_ticks": 0},
            {"control_channel_id": "z" * 64},
            {"retained_control_channel": False},
            {"private_adb_session_id": "9" * 64},
            {"worker_session_id": "9" * 64},
            {"cmdline": ("su", "-c", "anything")},
        ]
        for values in changes:
            with self.subTest(values=values):
                authority, backend, clock, *_ = fixture()
                backend.faults["create_guardian"] = (
                    lambda receipt, _request, _backend, values=values:
                    replace(receipt, guardian=replace(receipt.guardian, **values)))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

    def test_server_rejects_pid_path_hash_session_listener_or_file_reuse(self):
        changes = [
            {"uid": 2000}, {"uid": False}, {"gid": 2000}, {"gid": False},
            {"session_id": "9" * 64},
            {"pid": 301}, {"start_ticks": 0},
            {"guardian_control_channel_id": "9" * 64},
            {"executable_path": "/data/local/tmp/other"},
            {"executable_sha256": "0" * 64}, {"executable_inode": 74},
            {"listen_address": "0.0.0.0"}, {"listen_port": 27042},
            {"cmdline": ("frida-server",)},
        ]
        for values in changes:
            with self.subTest(values=values):
                authority, backend, clock, *_ = fixture()
                backend.faults["start_server"] = (
                    lambda receipt, _request, _backend, values=values:
                    replace(receipt, server=replace(receipt.server, **values)))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

    def test_handshake_rejects_version_protocol_pid_and_session_mismatch(self):
        changes = [
            {"version": "16.0.0"}, {"protocol": "frida-core-16"},
            {"server_pid": 999}, {"server_start_ticks": 999},
            {"session_id": "9" * 64},
        ]
        for values in changes:
            with self.subTest(values=values):
                authority, backend, clock, *_ = fixture()
                backend.faults["handshake"] = (
                    lambda receipt, _request, _backend, values=values:
                    replace(receipt, handshake=replace(receipt.handshake, **values)))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

    def test_guardian_server_handshake_and_observation_require_exact_scalar_types(self):
        guardian_mutations = {
            "authority": lambda value: EqualString(value),
            "session_id": lambda value: EqualString(value),
            "serial": lambda value: EqualString(value),
            "pid": lambda value: float(value),
            "start_ticks": lambda value: EqualInteger(value),
            "uid": lambda value: float(value),
            "gid": lambda value: EqualInteger(value),
            "cmdline": lambda value: tuple(EqualString(item) for item in value),
            "control_channel_id": lambda value: EqualString(value),
            "retained_control_channel": lambda _value: 1,
            "private_adb_session_id": lambda value: EqualString(value),
            "worker_session_id": lambda value: EqualString(value),
        }
        for field, convert in guardian_mutations.items():
            with self.subTest(kind="guardian", field=field):
                authority, backend, clock, *_ = fixture()
                backend.faults["create_guardian"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, guardian=replace(
                        receipt.guardian,
                        **{field: convert(getattr(receipt.guardian, field))})))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

        server_mutations = {
            "authority": lambda value: EqualString(value),
            "session_id": lambda value: EqualString(value),
            "guardian_control_channel_id": lambda value: EqualString(value),
            "pid": lambda value: float(value),
            "start_ticks": lambda value: EqualInteger(value),
            "uid": lambda value: float(value),
            "gid": lambda value: EqualInteger(value),
            "cmdline": lambda value: tuple(EqualString(item) for item in value),
            "executable_path": lambda value: EqualString(value),
            "executable_sha256": lambda value: EqualString(value),
            "executable_device": lambda value: float(value),
            "executable_inode": lambda value: EqualInteger(value),
            "listen_address": lambda value: EqualString(value),
            "listen_port": lambda value: float(value),
        }
        for field, convert in server_mutations.items():
            with self.subTest(kind="server", field=field):
                authority, backend, clock, *_ = fixture()
                backend.faults["start_server"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, server=replace(
                        receipt.server,
                        **{field: convert(getattr(receipt.server, field))})))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

        handshake_mutations = {
            "authority": lambda value: EqualString(value),
            "session_id": lambda value: EqualString(value),
            "server_pid": lambda value: float(value),
            "server_start_ticks": lambda value: EqualInteger(value),
            "version": lambda value: EqualString(value),
            "protocol": lambda value: EqualString(value),
        }
        for field, convert in handshake_mutations.items():
            with self.subTest(kind="handshake", field=field):
                authority, backend, clock, *_ = fixture()
                backend.faults["handshake"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, handshake=replace(
                        receipt.handshake,
                        **{field: convert(getattr(receipt.handshake, field))})))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))

        for field in ("listener_exclusive", "guardian_active",
                      "guardian_control_channel_active", "server_active"):
            with self.subTest(kind="observation", field=field):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults["observe_ready:2"] = (
                    lambda receipt, _request, _backend, field=field:
                    replace(receipt, observation=replace(
                        receipt.observation, **{field: 1})))
                with self.assertRaises(mut.DeviceFridaError):
                    authority.verify_ready(deadline(clock))

    def test_ready_observation_rejects_guardian_loss_pid_reuse_and_replacement(self):
        authority, backend, clock, *_ = fixture()
        authority.start(deadline(clock))
        variants = [
            lambda observation: replace(observation, guardian_active=False),
            lambda observation: replace(observation, guardian_control_channel_active=False),
            lambda observation: replace(observation, server_active=False),
            lambda observation: replace(observation, listener_exclusive=False),
            lambda observation: replace(
                observation, server=replace(observation.server, start_ticks=777)),
            lambda observation: replace(
                observation, file=replace(observation.file, inode=777)),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                a, b, c, *_ = fixture()
                a.start(deadline(c))
                b.faults["observe_ready:2"] = (
                    lambda receipt, _request, _backend, f=variant:
                    replace(receipt, observation=f(receipt.observation)))
                with self.assertRaises(mut.DeviceFridaError):
                    a.verify_ready(deadline(c))

    def test_every_cleanup_edge_is_sticky_and_never_retried(self):
        cleanup_edges = ("observe_ready:2", "stop_server", "inspect_file:3",
                         "unlink_file", "stop_guardian", "prove_absent")
        for operation in cleanup_edges:
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults[operation] = mut.DeviceFridaError("cleanup edge")
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
                self.assertTrue(authority.cleanup_obligations)
                count = len(backend.calls)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.teardown(deadline(clock))
                with self.assertRaises(mut.CleanupUncertain):
                    authority.assert_quiescent(deadline(clock))
                self.assertEqual(len(backend.calls), count)

    def test_every_startup_rollback_cleanup_edge_is_sticky(self):
        for operation in ("stop_server", "inspect_file:3", "unlink_file",
                          "stop_guardian", "prove_absent"):
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                backend.faults["handshake"] = mut.DeviceFridaError("admission failure")
                backend.faults[operation] = mut.DeviceFridaError("rollback edge")
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
                self.assertTrue(authority.cleanup_obligations)
                count = len(backend.calls)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.teardown(deadline(clock))
                self.assertEqual(len(backend.calls), count)

    def test_unlaunched_file_rollback_edges_are_fixed_and_sticky(self):
        for operation in ("inspect_file:2", "unlink_unlaunched_file", "prove_absent"):
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                backend.faults["inspect_file:1"] = mut.DeviceFridaError("admission failure")
                backend.faults[operation] = mut.DeviceFridaError("rollback edge")
                with self.assertRaises(mut.DeviceFridaError):
                    authority.start(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
                count = len(backend.calls)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.teardown(deadline(clock))
                self.assertEqual(len(backend.calls), count)

    def test_teardown_rejects_wrong_process_file_and_absence_proofs(self):
        faults = {
            "stop_server": lambda receipt, _r, _b: replace(receipt, joined_exact_server=False),
            "inspect_file:3": lambda receipt, _r, fake: replace(
                receipt, file=replace(receipt.file, inode=999)),
            "unlink_file": lambda receipt, _r, _b: replace(receipt, file_absent=False),
            "stop_guardian": lambda receipt, _r, _b: replace(receipt, joined_exact_guardian=False),
            "prove_absent": lambda receipt, _r, _b: replace(
                receipt, proof=replace(receipt.proof, path_not_replaced=False)),
        }
        for operation, fault in faults.items():
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults[operation] = fault
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")

    def test_absence_rejects_pid_reuse_path_replacement_and_ambiguous_presence(self):
        fields = ("file_absent", "directory_absent", "server_absent",
                  "guardian_absent", "listener_absent", "server_pid_not_reused",
                  "guardian_pid_not_reused", "path_not_replaced")
        for field in fields:
            with self.subTest(field=field):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults["prove_absent"] = (
                    lambda receipt, _r, _b, field=field:
                    replace(receipt, proof=replace(receipt.proof, **{field: False})))
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))

    def test_cleanup_receipts_and_absence_proof_require_exact_scalar_types(self):
        stop_mutations = {
            "guardian": lambda receipt: replace(
                receipt.guardian, pid=float(receipt.guardian.pid)),
            "server": lambda receipt: replace(
                receipt.server, listen_port=float(receipt.server.listen_port)),
            "signal_delivered_to_guardian": lambda _receipt: 1,
            "killed_exact_server": lambda _receipt: 1,
            "joined_exact_server": lambda _receipt: 1,
            "server_absent": lambda _receipt: 1,
            "listener_absent": lambda _receipt: 1,
        }
        for field, convert in stop_mutations.items():
            with self.subTest(kind="stop", field=field):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults["stop_server"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, **{field: convert(receipt)}))
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))

        unlink_mutations = {
            "file": lambda receipt: replace(
                receipt.file, parent_inode=float(receipt.file.parent_inode)),
            "file_absent": lambda _receipt: 1,
            "directory_absent": lambda _receipt: 1,
        }
        for field, convert in unlink_mutations.items():
            with self.subTest(kind="unlink", field=field):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults["unlink_file"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, **{field: convert(receipt)}))
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))

        guardian_stop_mutations = {
            "guardian": lambda receipt: replace(
                receipt.guardian, start_ticks=float(receipt.guardian.start_ticks)),
            "signal_delivered_to_guardian": lambda _receipt: 1,
            "joined_exact_guardian": lambda _receipt: 1,
            "guardian_absent": lambda _receipt: 1,
        }
        for field, convert in guardian_stop_mutations.items():
            with self.subTest(kind="guardian_stop", field=field):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults["stop_guardian"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, **{field: convert(receipt)}))
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))

        proof_mutations = {
            "authority": lambda value: EqualString(value),
            "session_id": lambda value: EqualString(value),
            "serial": lambda value: EqualString(value),
            "path": lambda value: EqualString(value),
            "directory_path": lambda value: EqualString(value),
            "server_pid": lambda value: float(value),
            "server_start_ticks": lambda value: EqualInteger(value),
            "guardian_pid": lambda value: float(value),
            "guardian_start_ticks": lambda value: EqualInteger(value),
            "file_absent": lambda _value: 1,
            "directory_absent": lambda _value: 1,
            "server_absent": lambda _value: 1,
            "guardian_absent": lambda _value: 1,
            "listener_absent": lambda _value: 1,
            "server_pid_not_reused": lambda _value: 1,
            "guardian_pid_not_reused": lambda _value: 1,
            "path_not_replaced": lambda _value: 1,
        }
        for field, convert in proof_mutations.items():
            with self.subTest(kind="absence", field=field):
                authority, backend, clock, *_ = fixture()
                authority.start(deadline(clock))
                backend.faults["prove_absent"] = (
                    lambda receipt, _request, _backend, field=field, convert=convert:
                    replace(receipt, proof=replace(
                        receipt.proof,
                        **{field: convert(getattr(receipt.proof, field))})))
                with self.assertRaises(mut.CleanupUncertain):
                    authority.teardown(deadline(clock))

    def test_dependency_serial_worker_image_and_backend_drift_are_rejected(self):
        for index in range(4):
            with self.subTest(index=index):
                authority, backend, clock, adb, worker, image = fixture()
                authority.start(deadline(clock))
                (adb, worker, image, backend)[index].changed = True
                before = len(backend.calls)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.verify_ready(deadline(clock))
                self.assertEqual(len(backend.calls), before)
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
                with self.assertRaises(mut.DeviceFridaError):
                    authority.teardown(deadline(clock))

    def test_equal_dependency_aliases_are_revalidated_on_every_operation(self):
        mutations = (
            lambda adb, _worker, _image, _backend: setattr(
                adb, "value", replace(adb.value, serial=EqualString(adb.value.serial))),
            lambda _adb, worker, _image, _backend: setattr(
                worker, "value", replace(
                    worker.value, start_ticks=EqualInteger(worker.value.start_ticks))),
            lambda _adb, _worker, image, _backend: setattr(
                image, "value", replace(
                    image.value, version=EqualString(image.value.version))),
            lambda _adb, _worker, _image, backend: setattr(
                backend, "value", replace(
                    backend.value, worker_pid=float(backend.value.worker_pid))),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                authority, backend, clock, adb, worker, image = fixture()
                authority.start(deadline(clock))
                mutate(adb, worker, image, backend)
                before = len(backend.calls)
                with self.assertRaises(mut.DeviceFridaError):
                    authority.verify_ready(deadline(clock))
                self.assertEqual(len(backend.calls), before)
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")

    def test_pre_sync_dependency_drift_fails_without_cleanup_obligation(self):
        authority, backend, clock, adb, *_ = fixture()
        adb.changed = True
        with self.assertRaises(mut.DeviceFridaError):
            authority.start(deadline(clock))
        self.assertEqual(authority.state, "FAILED")
        self.assertFalse(authority.cleanup_obligations)
        self.assertEqual(backend.calls, [])
        authority.assert_quiescent(deadline(clock))
        authority.teardown(deadline(clock))
        self.assertEqual(backend.calls, [])

    def test_deadlines_reject_expired_oversized_and_late_return(self):
        authority, backend, clock, *_ = fixture()
        for value in (clock.now_ns(), clock.now_ns() - 1,
                      clock.now_ns() + mut.TARGET_TOTAL_BUDGET_NS + 1):
            with self.subTest(value=value), self.assertRaises(mut.DeviceFridaError):
                authority.start(value)
        authority, backend, clock, *_ = fixture()
        def late(receipt, request, fake):
            fake.clock.value = request.deadline_ns
            return replace(receipt, ack=replace(receipt.ack,
                                                produced_ns=request.deadline_ns))
        backend.faults["sync_image"] = late
        with self.assertRaises(mut.DeviceFridaError):
            authority.start(deadline(clock))

    def test_regressing_clock_and_concurrent_entry_are_rejected(self):
        authority, _backend, clock, *_ = fixture()
        authority._last_now_ns = clock.now_ns()
        clock.value -= 1
        with self.assertRaises(mut.DeviceFridaError):
            authority.start(clock.now_ns() + mut.TARGET_TOTAL_BUDGET_NS)

        authority, _backend, _clock, *_ = fixture()
        errors = []
        authority._lock.acquire()
        try:
            thread = threading.Thread(
                target=lambda: self._capture_error(errors, authority.evidence))
            thread.start()
            thread.join(1)
            self.assertFalse(thread.is_alive())
        finally:
            authority._lock.release()
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], mut.DeviceFridaError)

    def test_same_thread_backend_callback_cannot_reenter_public_lifecycle(self):
        authority, backend, clock, *_ = fixture()
        lease = authority.start(deadline(clock))
        nested_errors = []
        callback_entered = threading.Event()

        def attempt_reentry(receipt, _request, _backend):
            callback_entered.set()
            self._capture_error(nested_errors,
                                lambda: authority.teardown(deadline(clock)))
            return receipt

        before_calls = len(backend.calls)
        before_sequence = authority.evidence().operation_count
        backend.faults["observe_ready:2"] = attempt_reentry
        self.assertEqual(authority.verify_ready(deadline(clock)), lease)
        self.assertTrue(callback_entered.is_set())
        self.assertEqual(len(nested_errors), 1)
        self.assertIsInstance(nested_errors[0], mut.DeviceFridaError)
        self.assertIn("reentrant", str(nested_errors[0]))
        self.assertEqual(authority.state, "READY")
        self.assertEqual([entry[0] for entry in backend.calls[before_calls:]],
                         ["observe_ready"])
        self.assertEqual(authority.evidence().operation_count,
                         before_sequence + 1)
        backend.faults.pop("observe_ready:2")
        authority.teardown(deadline(clock))

    def test_ack_is_rejected_if_callback_invalidates_request_generation(self):
        authority, backend, clock, *_ = fixture()

        def invalidate_request(receipt, _request, _backend):
            authority._state_generation += 1
            return receipt

        backend.faults["sync_image"] = invalidate_request
        with self.assertRaises(mut.DeviceFridaError):
            authority.start(deadline(clock))
        self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
        self.assertEqual([entry[0] for entry in backend.calls], ["sync_image"])

    @staticmethod
    def _capture_error(errors, function):
        try:
            function()
        except BaseException as error:
            errors.append(error)

    def test_target_timing_is_a_bound_not_an_offline_hardware_claim(self):
        authority, backend, clock, *_ = fixture()
        authority.start(deadline(clock))
        requests = [entry[1] for entry in backend.calls]
        self.assertTrue(requests)
        self.assertTrue(all(r.deadline_ns - r.issued_ns <=
                            mut.TARGET_CALL_BUDGET_NS for r in requests))
        self.assertFalse(mut.HARDWARE_TIMING_PROVEN_OFFLINE)
        self.assertFalse(authority.evidence().hardware_timing_proven)

    def test_mutation_requests_are_exactly_bound_to_serial_sessions_and_arguments(self):
        authority, backend, clock, *_ = fixture()
        authority.start(deadline(clock))
        requests = [entry[1] for entry in backend.calls]
        self.assertEqual([r.sequence for r in requests], list(range(1, 8)))
        for request in requests:
            self.assertEqual(request.authority, mut.AUTHORITY)
            self.assertEqual(request.session_id, SESSION)
            self.assertEqual(request.serial, "SN078C10015092")
            self.assertEqual(request.private_adb_session_id, ADB_SESSION)
            self.assertEqual(request.worker_session_id, WORKER_SESSION)
            self.assertRegex(request.private_adb_binding_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(request.worker_binding_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(request.backend_binding_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(request.image_identity_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(request.arguments_sha256, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
