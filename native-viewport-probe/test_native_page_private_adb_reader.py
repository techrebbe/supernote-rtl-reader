"""Deterministic fake-only S1c tests; no ADB, device, process, or network I/O."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import inspect
import json
import threading
import unittest
import unicodedata

import native_page_private_adb_mutator as mutator
import native_page_private_adb_reader as reader
import native_page_cleanup_ledger as cleanup_ledger
import native_page_windows_worker_runtime as worker_runtime


SESSION = "a" * 64
ADB_SESSION = "b" * 64
WORKER_SESSION = "c" * 64
ADB_SHA = "d" * 64
WORKER_SHA = "e" * 64
WORKER_SOURCE_SHA = "f" * 64
WORKER_IMAGE_PATH = r"C:\rtl-reader\authority-worker.exe"
READER_EPOCH = "6" * 64
READER_EPOCH_2 = "7" * 64
EPOCH_ISSUER = "8" * 64
PDF_SHA = "1" * 64
MARK_SHA = "2" * 64
BASE_SHA = "3" * 64
FRAMEWORK_SHA = "4" * 64
MODULE_SHA = "5" * 64
SERIAL = "SN078C10015092"


def canonical_digest(value):
    payload = json.dumps(
        asdict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def mapping_digest(value):
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class FakeClock:
    def __init__(self):
        self.value = 1_000_000_000

    def now_ns(self):
        return self.value

    def advance(self, amount=1_000_000):
        self.value += amount


class FakeAuthority:
    def __init__(self, value):
        self.value = value
        self.changed = False
        self.alias = None

    def binding(self):
        if self.alias is not None:
            return self.alias
        if self.changed:
            return replace(self.value, session_id="9" * 64)
        return self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise reader.DeviceReadError("retained authority drift")


class FakeWorkerRuntime:
    def __init__(self, value, process):
        self.value = value
        self.process = process
        self.changed = False
        self.alias = None
        self.binding_calls = 0

    def binding(self, process):
        self.binding_calls += 1
        if process is not self.process:
            raise reader.DeviceReadError("worker process handle substituted")
        if self.alias is not None:
            return self.alias
        if self.changed:
            return replace(self.value, session="9" * 64)
        return self.value


class FakeEpochAuthority:
    def __init__(self, plan, epoch_id=READER_EPOCH):
        self.value = reader.ReaderInstanceEpoch(
            reader.READER_EPOCH_AUTHORITY, epoch_id, EPOCH_ISSUER,
            plan.sha256(), plan.serial, 1, True, True)
        self.consumed = False
        self.changed = False
        self.verify_calls = 0

    def consume(self, plan_sha256, serial):
        if self.consumed or plan_sha256 != self.value.plan_sha256 or serial != self.value.serial:
            raise reader.DeviceReadError("reader epoch already consumed or rebound")
        self.consumed = True
        return self.value

    def verify(self, expected):
        self.verify_calls += 1
        if self.changed or not self.consumed or expected != self.value:
            raise reader.DeviceReadError("reader epoch authority drift")


def directory(path, inode, *, uid=2000, gid=2000, mode=0o700, device=41):
    return reader.DirectoryIdentity(path, uid, gid, mode, device, inode, True, False)


def file_identity(path, sha256, size, inode, *, uid=2000, gid=2000, mode=0o600,
                  device=41, nlink=1):
    parent_path = path.rsplit("/", 1)[0]
    return reader.FileIdentity(
        path, path, sha256, size, uid, gid, mode, device, inode, nlink, True, False,
        directory(parent_path, inode - 1, uid=uid, gid=gid, mode=0o700, device=device))


def make_plan(*, mark_present=False, pdf_path="/storage/emulated/0/Document/סידור test.pdf"):
    pdf = file_identity(pdf_path, PDF_SHA, 4096, 101)
    mark_path = pdf_path + ".mark"
    mark = file_identity(mark_path, MARK_SHA, 512, 103) if mark_present else None
    absent_parent = None if mark_present else pdf.parent
    base = file_identity(
        "/system/priv-app/SupernoteDocument/SupernoteDocument.apk", BASE_SHA,
        8_000_000, 201, uid=0, gid=0, mode=0o644, device=11)
    framework = file_identity(
        "/system/framework/framework.jar", FRAMEWORK_SHA, 20_000_000, 211,
        uid=0, gid=0, mode=0o644, device=11)
    module = file_identity(
        "/data/adb/modules/lsposed/module.apk", MODULE_SHA, 1_000_000, 221,
        uid=0, gid=0, mode=0o644, device=12)
    system_anchor = directory("/system", 10, uid=0, gid=0, mode=0o755, device=11)
    module_anchor = directory(
        "/data/adb/modules", 20, uid=0, gid=0, mode=0o755, device=12)
    staging_anchor = directory(
        reader.STAGING_PREFIX, 250, uid=2000, gid=2000, mode=0o700, device=42)
    device = reader.DeviceStatePlan(
        SERIAL, "device", True,
        "Ratta/Nomad/Nomad:15/AP3A/20260901:user/release-keys", "AP3A",
        "20260901", "Nomad", "Nomad", "Supernote Nomad", 35,
        "123e4567-e89b-42d3-a456-426614174000", "orange", False)
    target = reader.TargetProcessPlan(
        "com.supernote.document", "com.supernote.document", 1234, 987654,
        1000, 1000, ("com.supernote.document",), base.path)
    return reader.EvidencePlan(
        reader.PLAN_AUTHORITY, SESSION, SERIAL, device, target,
        reader.ExactFilePlan("original_pdf", "/storage/emulated/0/Document",
                             reader.canonical_file_uri(pdf.path), pdf, True),
        reader.NullableFilePlan("mark", "/storage/emulated/0/Document", mark_path,
                                reader.canonical_file_uri(mark_path), mark, absent_parent, True),
        (reader.ProtectedArtifactPlan(
             "framework", framework, system_anchor,
             (system_anchor, framework.parent)),
         reader.ProtectedArtifactPlan(
             "module_apk", module, module_anchor,
             (module_anchor, module.parent)),
         reader.ProtectedArtifactPlan(
             "target_base_apk", base, system_anchor,
             (system_anchor,
              directory("/system/priv-app", 190, uid=0, gid=0,
                        mode=0o755, device=11), base.parent))),
        staging_anchor,
        reader.DumpLimits(100_000, 100_000, 100_000))


class FakeBackend:
    def __init__(self, clock, binding, plan):
        self.clock = clock
        self.value = binding
        self.plan = plan
        self.changed = False
        self.alias = None
        self.calls = []
        self.counts = {}
        self.faults = {}
        self.receipts = {}
        self.quiescent = []
        self.quiescent_hook = None
        self.all_quiescent_hook = None
        self.protected_dispatches = []

    def binding(self):
        if self.alias is not None:
            return self.alias
        if self.changed:
            return replace(self.value, serial="OTHER")
        return self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise reader.DeviceReadError("backend drift")

    def assert_operation_quiescent(self, expected, operation_id, deadline_ns):
        if expected != self.value or self.clock.now_ns() >= deadline_ns:
            raise reader.DeviceReadError("operation is not quiescent")
        self.quiescent.append(operation_id)
        if self.quiescent_hook is not None:
            self.quiescent_hook(operation_id)
        fault = self.faults.get("quiescence:" + operation_id)
        if isinstance(fault, BaseException):
            raise fault

    def assert_all_quiescent(self, expected, deadline_ns):
        if expected != self.value or self.clock.now_ns() >= deadline_ns:
            raise reader.DeviceReadError("backend is not quiescent")
        if self.all_quiescent_hook is not None:
            self.all_quiescent_hook()

    def _ack(self, request):
        return reader.ReadAck(
            reader.ACK_AUTHORITY, request.session_id, request.serial, request.sequence,
            request.operation, request.operation_id, request.reader_epoch_id,
            request.sha256(), request.issued_ns,
            self.clock.now_ns())

    def _return(self, name, request, receipt, *args):
        count = self.counts.get(name, 0) + 1
        self.counts[name] = count
        self.calls.append((name, request, args))
        self.clock.advance()
        receipt = replace(receipt, ack=replace(receipt.ack,
                                               produced_ns=self.clock.now_ns()))
        fault = self.faults.get(f"{name}:{count}", self.faults.get(name))
        if isinstance(fault, BaseException):
            raise fault
        if callable(fault):
            receipt = fault(receipt, request, self)
        self.receipts[name] = receipt
        return receipt

    def _device(self, request):
        return reader.DeviceStateEvidence(
            canonical_digest(self.plan.device),
            request.operation_id,
            request.reader_epoch_id,
            self.plan.device, 2000, 2000)

    def _target(self, request):
        return reader.TargetProcessEvidence(
            canonical_digest(self.plan.target),
            request.operation_id, request.reader_epoch_id,
            self.plan.target, True, 2000, 2000)

    def _opened(self, plan, operation_id, reader_epoch_id):
        descriptor_id = mapping_digest({
            "authority": reader.AUTHORITY,
            "device": plan.expected.device,
            "inode": plan.expected.inode,
            "operationId": operation_id,
            "path": plan.expected.path,
            "purpose": plan.purpose,
        })
        return reader.OpenedFileEvidence(
            plan_sha256=canonical_digest(plan),
            operation_id=operation_id,
            reader_epoch_id=reader_epoch_id,
            uri=plan.uri,
            resolved_uri_path=plan.expected.path,
            uri_scheme="file",
            uri_resolution_exact=True,
            descriptor_id=descriptor_id,
            descriptor_read_only=True,
            descriptor_nofollow=True,
            descriptor_bound_to_stat=True,
            hash_from_descriptor=True,
            collector_uid=2000,
            collector_gid=2000,
            stat_before=plan.expected,
            stat_after=plan.expected,
            bytes_sha256=plan.expected.sha256,
            bytes_read=plan.expected.size)

    def read_device_state(self, request, plan):
        return self._return(request.operation, request,
                            reader.DeviceStateReceipt(self._ack(request), self._device(request)), plan)

    def read_target_process(self, request, plan):
        return self._return(request.operation, request,
                            reader.TargetProcessReceipt(self._ack(request), self._target(request)), plan)

    def read_original_pdf(self, request, plan):
        return self._return("original_pdf", request,
                            reader.OpenedFileReceipt(
                                self._ack(request), self._opened(
                                    plan, request.operation_id,
                                    request.reader_epoch_id)), plan)

    def read_nullable_mark(self, request, plan):
        plan_sha = canonical_digest(plan)
        if plan.expected is not None:
            value = reader.NullableFileEvidence(
                request.reader_epoch_id, True,
                self._opened(plan, request.operation_id,
                             request.reader_epoch_id), None)
        else:
            missing = reader.MissingFileEvidence(
                plan_sha256=plan_sha,
                operation_id=request.operation_id,
                reader_epoch_id=request.reader_epoch_id,
                path=plan.path,
                uri=plan.uri,
                resolved_uri_path=plan.path,
                uri_scheme="file",
                uri_resolution_exact=True,
                errno=2,
                parent_before=plan.absent_parent,
                parent_after=plan.absent_parent,
                collector_uid=2000,
                collector_gid=2000,
                nofollow_checked=True)
            value = reader.NullableFileEvidence(
                request.reader_epoch_id, False, None, missing)
        return self._return("nullable_mark", request,
                            reader.NullableFileReceipt(self._ack(request), value), plan)

    def _protected(self, request, plan, staging_path, dispatch_witness):
        preflight_fault = self.faults.get(plan.kind + ":preflight")
        if isinstance(preflight_fault, BaseException):
            raise preflight_fault
        dispatch_witness()
        self.protected_dispatches.append((plan.kind, request.operation_id, staging_path))
        plan_sha = canonical_digest(plan)
        suffix = 300 + tuple(reader.PROTECTED_KINDS).index(plan.kind) * 10
        root_session = hashlib.sha256(json.dumps({
            "authority": reader.PROTECTED_AUTHORITY,
            "kind": plan.kind,
            "operationId": request.operation_id,
            "planSession": SESSION,
            "privateAdbSession": ADB_SESSION,
            "readerEpoch": request.reader_epoch_id,
            "source": plan.expected.path,
            "staging": staging_path,
            "workerSession": WORKER_SESSION,
            "sourceAnchor": asdict(plan.source_anchor),
            "stagingAnchor": asdict(self.plan.staging_anchor),
        }, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        root_pid = 400 + suffix
        root_start = 9_000 + suffix
        root_control = hashlib.sha256(json.dumps({
            "authority": reader.PROTECTED_AUTHORITY,
            "pid": root_pid,
            "rootSession": root_session,
            "startTicks": root_start,
        }, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        source_relative = plan.expected.path[len(plan.source_anchor.path) + 1:]
        staging_relative = staging_path[len(self.plan.staging_anchor.path) + 1:]
        source_anchor_descriptor = mapping_digest({
            "authority": reader.PROTECTED_AUTHORITY,
            "device": plan.source_anchor.device,
            "inode": plan.source_anchor.inode,
            "path": plan.source_anchor.path,
            "role": "source-anchor",
            "rootSession": root_session,
        })
        staging_anchor_descriptor = mapping_digest({
            "authority": reader.PROTECTED_AUTHORITY,
            "device": self.plan.staging_anchor.device,
            "inode": self.plan.staging_anchor.inode,
            "path": self.plan.staging_anchor.path,
            "role": "staging-anchor",
            "rootSession": root_session,
        })
        source_descriptor = mapping_digest({
            "anchorDescriptor": source_anchor_descriptor,
            "authority": reader.PROTECTED_AUTHORITY,
            "device": plan.expected.device,
            "inode": plan.expected.inode,
            "path": plan.expected.path,
            "relativePath": source_relative,
            "role": "source",
            "rootSession": root_session,
        })
        staging_descriptor = mapping_digest({
            "anchorDescriptor": staging_anchor_descriptor,
            "authority": reader.PROTECTED_AUTHORITY,
            "device": 42,
            "inode": suffix,
            "path": staging_path,
            "relativePath": staging_relative,
            "role": "staging",
            "rootSession": root_session,
        })
        cleanup_descriptor = mapping_digest({
            "anchorDescriptor": staging_anchor_descriptor,
            "authority": reader.PROTECTED_AUTHORITY,
            "device": 42,
            "inode": suffix,
            "role": "cleanup",
            "rootSession": root_session,
            "stagingDescriptor": staging_descriptor,
        })
        staging_session = directory(
            reader.STAGING_PREFIX + "/" + SESSION, suffix - 2,
            uid=2000, gid=2000, mode=0o700, device=42)
        staging_parent = directory(
            staging_path.rsplit("/", 1)[0], suffix - 1,
            uid=2000, gid=2000, mode=0o700, device=42)
        source_path_authority = reader.AnchoredPathEvidence(
            anchor_before=plan.source_anchor,
            anchor_after=plan.source_anchor,
            ancestors_before=plan.source_ancestors,
            ancestors_after=plan.source_ancestors,
            anchor_descriptor_id=source_anchor_descriptor,
            anchor_descriptor_retained=True,
            relative_path=source_relative,
            resolved_path=plan.expected.path,
            resolve_beneath=True,
            resolve_no_symlinks=True,
            resolve_no_magiclinks=True,
            resolve_no_xdev=True,
            descriptor_bound_to_resolved_inode=True)
        staging_chain = (self.plan.staging_anchor, staging_session, staging_parent)
        staging_path_authority = reader.AnchoredPathEvidence(
            anchor_before=self.plan.staging_anchor,
            anchor_after=self.plan.staging_anchor,
            ancestors_before=staging_chain,
            ancestors_after=staging_chain,
            anchor_descriptor_id=staging_anchor_descriptor,
            anchor_descriptor_retained=True,
            relative_path=staging_relative,
            resolved_path=staging_path,
            resolve_beneath=True,
            resolve_no_symlinks=True,
            resolve_no_magiclinks=True,
            resolve_no_xdev=True,
            descriptor_bound_to_resolved_inode=True)
        value = reader.ProtectedReadEvidence(
            plan_sha256=plan_sha,
            operation_id=request.operation_id,
            reader_epoch_id=request.reader_epoch_id,
            source_before=plan.expected,
            source_after=plan.expected,
            source_descriptor_id=source_descriptor,
            source_descriptor_read_only=True,
            source_descriptor_nofollow=True,
            source_copy_bound_to_inode=True,
            source_path_authority=source_path_authority,
            staging_path=staging_path,
            staging_parent_before_read=staging_parent,
            staging_parent_after_read=staging_parent,
            staging_directory_created_exclusively=True,
            staging_device=42,
            staging_inode=suffix,
            staging_nlink=1,
            staging_uid=2000,
            staging_gid=2000,
            staging_mode=0o600,
            staging_sha256=plan.expected.sha256,
            staging_size=plan.expected.size,
            staging_regular=True,
            staging_symlink=False,
            descriptor_id=staging_descriptor,
            descriptor_read_only=True,
            descriptor_nofollow=True,
            descriptor_bound_to_staging_inode=True,
            staging_hash_from_descriptor=True,
            descriptor_collector_uid=2000,
            descriptor_collector_gid=2000,
            staging_path_authority=staging_path_authority,
            root_protocol=reader.PROTECTED_PROTOCOL,
            root_protocol_version=reader.PROTECTED_PROTOCOL_VERSION,
            root_session_id=root_session,
            root_guardian_pid=root_pid,
            root_guardian_start_ticks=root_start,
            root_guardian_uid=0,
            root_guardian_gid=0,
            root_control_id=root_control,
            root_cmdline=(reader.PROTECTED_PROTOCOL,
                          str(reader.PROTECTED_PROTOCOL_VERSION), SESSION,
                          request.reader_epoch_id, request.operation_id,
                          plan.kind, plan.source_anchor.path, source_relative,
                          self.plan.staging_anchor.path, staging_relative),
            private_adb_session_id=ADB_SESSION,
            worker_session_id=WORKER_SESSION,
            root_guardian_cleanup_armed=True,
            root_scope_protected_only=True,
            staging_file_absent=True,
            staging_inode_absent=True,
            staging_directory_absent=True,
            root_guardian_absent=True,
            root_guardian_pid_not_reused=True,
            root_control_closed=True,
            path_not_replaced=True,
            cleanup_anchor_descriptor_id=cleanup_descriptor,
            cleanup_handle_relative=True,
            cleanup_descriptor_bound_to_staging_inode=True)
        return self._return(plan.kind, request,
                            reader.ProtectedReadReceipt(self._ack(request), value),
                            plan, staging_path)

    def read_target_base_apk(self, request, plan, staging_path, dispatch_witness):
        return self._protected(request, plan, staging_path, dispatch_witness)

    def read_framework(self, request, plan, staging_path, dispatch_witness):
        return self._protected(request, plan, staging_path, dispatch_witness)

    def read_module_apk(self, request, plan, staging_path, dispatch_witness):
        return self._protected(request, plan, staging_path, dispatch_witness)

    def _dump(self, request, kind, maximum):
        raw = (kind.upper() + "\n").encode()
        source = {"activity": "dumpsys activity activities",
                  "window": "dumpsys window windows", "display": "dumpsys display"}[kind]
        value = reader.RawDumpEvidence(
            request.operation_id, request.reader_epoch_id, kind, source, raw,
            hashlib.sha256(raw).hexdigest(),
            len(raw), False, 2000, 2000)
        return self._return(kind + "_dump", request,
                            reader.DumpReceipt(self._ack(request), value), maximum)

    def read_activity_dump(self, request, maximum):
        return self._dump(request, "activity", maximum)

    def read_window_dump(self, request, maximum):
        return self._dump(request, "window", maximum)

    def read_display_dump(self, request, maximum):
        return self._dump(request, "display", maximum)


def fixture(*, mark_present=False, pdf_path="/storage/emulated/0/Document/סידור test.pdf",
            epoch_id=READER_EPOCH):
    plan = make_plan(mark_present=mark_present, pdf_path=pdf_path)
    clock = FakeClock()
    adb_binding = reader.PrivateAdbBinding(
        reader.PRIVATE_ADB_AUTHORITY, SERIAL, "tcp:127.0.0.1:41337", 101, 7001,
        ADB_SHA, ADB_SESSION, True, True, True, False)
    worker_binding = reader.WorkerBinding(
        201, 8001, WORKER_IMAGE_PATH, reader.WORKER_ROLE,
        reader.WORKER_FACTORY_ID, WORKER_SESSION, WORKER_SHA,
        WORKER_SOURCE_SHA, 301, 9001)
    backend_binding = reader.ReaderBackendBinding(
        authority=reader.BACKEND_AUTHORITY,
        serial=SERIAL,
        private_adb_session_id=ADB_SESSION,
        private_adb_endpoint=adb_binding.endpoint,
        private_adb_pid=adb_binding.server_pid,
        private_adb_start_ticks=adb_binding.server_start_ticks,
        private_adb_bundle_sha256=adb_binding.bundle_sha256,
        worker_session_id=WORKER_SESSION,
        worker_pid=worker_binding.pid,
        worker_creation_ticks=worker_binding.creation_ticks,
        worker_image_path=worker_binding.image_path,
        worker_image_sha256=WORKER_SHA,
        worker_source_sha256=WORKER_SOURCE_SHA,
        worker_parent_pid=worker_binding.parent_pid,
        worker_parent_creation_ticks=worker_binding.parent_creation_ticks,
        worker_role=reader.WORKER_ROLE,
        worker_factory_id=reader.WORKER_FACTORY_ID,
        ordinary_uid=2000,
        ordinary_gid=2000,
        private_socket=True,
        explicit_serial_every_operation=True,
        retained_worker_handle=True,
        fixed_operations_only=True,
        accepts_general_commands=False,
        fresh_reply_channel_per_operation=True,
        late_reply_channel_sealed=True,
        failure_returns_after_operation_quiescence=True,
        root_only_for_protected_reads=True,
        protected_cleanup_before_return=True,
        protected_dispatch_witness_required=True,
        protected_anchor_descriptor_retained=True,
        protected_handle_relative_nofollow=True,
        protected_descriptor_bound_cleanup=True)
    adb = FakeAuthority(adb_binding)
    worker_process = object()
    worker = FakeWorkerRuntime(worker_binding, worker_process)
    epoch_authority = FakeEpochAuthority(plan, epoch_id)
    backend = FakeBackend(clock, backend_binding, plan)
    authority = reader.AuthenticatedDeviceEvidenceReader(
        plan=plan, private_adb=adb, worker_runtime=worker,
        worker_process=worker_process, epoch_authority=epoch_authority,
        backend=backend, clock=clock,
        allow_unproven_epoch_authority_for_tests=True)
    return authority, backend, clock, adb, worker, plan, epoch_authority


def deadline(clock):
    return clock.now_ns() + reader.MAX_TOTAL_BUDGET_NS


class DeviceEvidenceReaderTests(unittest.TestCase):
    def test_success_collects_fixed_snapshot_and_closes(self):
        authority, backend, clock, _adb, worker, _plan, _epoch = fixture()
        snapshot = authority.collect(deadline(clock))
        self.assertEqual(authority.state, "READY")
        self.assertEqual(snapshot.authority, reader.SNAPSHOT_AUTHORITY)
        self.assertEqual(snapshot.target.value.package, "com.supernote.document")
        self.assertFalse(snapshot.mark.present)
        self.assertEqual(tuple(x.source_before.path for x in snapshot.protected),
                         tuple(x.expected.path for x in authority.plan.protected))
        self.assertEqual([x[0] for x in backend.calls], [
            "device_state_before", "target_process_before", "original_pdf",
            "nullable_mark", "framework", "module_apk", "target_base_apk",
            "activity_dump", "window_dump", "display_dump", "target_process_after",
            "device_state_after"])
        self.assertEqual(len(backend.quiescent), 12)
        self.assertEqual(worker.binding_calls, 27)
        self.assertFalse(snapshot.content_uri_supported)
        self.assertFalse(snapshot.real_runtime_backend_implemented)
        self.assertFalse(snapshot.real_reader_epoch_authority_implemented)
        self.assertFalse(snapshot.hardware_timing_proven)
        self.assertEqual(snapshot.reader_epoch.epoch_id, READER_EPOCH)
        self.assertTrue(snapshot.reader_epoch.one_shot_consumed)
        self.assertEqual(snapshot.unresolved_blockers, reader.UNRESOLVED_BLOCKERS)
        self.assertEqual(authority.close(deadline(clock)), snapshot)
        self.assertEqual(authority.state, "CLOSED")
        self.assertEqual(authority.close(deadline(clock)), snapshot)

    def test_verify_unchanged_recollects_every_exact_authority(self):
        authority, backend, clock, *_ = fixture(mark_present=True)
        first = authority.collect(deadline(clock))
        second = authority.verify_unchanged(deadline(clock))
        self.assertEqual(authority.state, "READY")
        self.assertTrue(second.mark.present)
        self.assertEqual(second.operation_count, first.operation_count + 12)
        self.assertEqual(backend.counts["target_base_apk"], 2)

    def test_public_surface_and_backend_protocol_have_no_general_shell(self):
        authority, *_ = fixture()
        public = {name for name, value in inspect.getmembers(authority, callable)
                  if not name.startswith("_")}
        self.assertEqual(public, {"close", "collect", "evidence", "verify_unchanged"})
        backend_public = {name for name, value in inspect.getmembers(FakeBackend, callable)
                          if not name.startswith("_")}
        for forbidden in ("run", "shell", "execute", "command", "search", "list_directory",
                          "push", "pull", "input", "launch", "page"):
            self.assertNotIn(forbidden, backend_public)

    def test_unicode_file_uri_is_exact_and_content_uri_is_explicitly_rejected(self):
        plan = make_plan()
        self.assertIn("%D7%A1", plan.original_pdf.uri)
        plan.validate()
        bad_uris = (
            "content://com.supernote/document/1",
            "file:///storage/emulated/0/Document/סידור test.pdf",
            plan.original_pdf.uri.replace("%D7", "%d7", 1),
            plan.original_pdf.uri.replace("/Document/", "%2FDocument%2F"),
            plan.original_pdf.uri + "#fragment",
        )
        for uri in bad_uris:
            with self.subTest(uri=uri):
                bad = replace(plan, original_pdf=replace(plan.original_pdf, uri=uri))
                with self.assertRaises(reader.DeviceReadError):
                    bad.validate()
        self.assertFalse(reader.CONTENT_URI_SUPPORTED)

    def test_path_policy_rejects_traversal_alias_nul_and_protected_escape(self):
        plan = make_plan()
        bad_paths = (
            "/storage/emulated/0/Document/../evil.pdf",
            "/storage/emulated/0//Document/a.pdf",
            "/storage/emulated/0/Document/a.pdf\x00x",
            "/sdcard/Document/a.pdf",
            "storage/emulated/0/Document/a.pdf",
        )
        for path in bad_paths:
            with self.subTest(path=path):
                identity = replace(plan.original_pdf.expected, path=path, resolved_path=path)
                altered = replace(plan, original_pdf=replace(
                    plan.original_pdf, uri="file://" + path, expected=identity))
                with self.assertRaises(reader.DeviceReadError):
                    altered.validate()
        protected = plan.protected[0]
        escaped = replace(protected, expected=replace(
            protected.expected, path="/data/local/tmp/framework.jar",
            resolved_path="/data/local/tmp/framework.jar",
            parent=replace(protected.expected.parent, path="/data/local/tmp")))
        with self.assertRaises(reader.DeviceReadError):
            replace(plan, protected=(escaped,) + plan.protected[1:]).validate()

    def test_protected_plan_preauthenticates_exact_anchor_and_ancestor_chain(self):
        plan = make_plan()
        protected = plan.protected[0]
        mutations = (
            replace(protected, source_anchor=replace(
                protected.source_anchor, path="/product")),
            replace(protected, source_anchor=replace(
                protected.source_anchor, symlink=True)),
            replace(protected, source_ancestors=protected.source_ancestors[:-1]),
            replace(protected, source_ancestors=(
                protected.source_ancestors[0],
                replace(protected.source_ancestors[-1], device=99))),
            replace(protected, source_ancestors=(
                protected.source_ancestors[0],
                replace(protected.source_ancestors[-1], path="/system/other"))),
        )
        for altered in mutations:
            with self.subTest(altered=altered):
                with self.assertRaises(reader.DeviceReadError):
                    replace(plan, protected=(altered,) + plan.protected[1:]).validate()
        for anchor in (
                replace(plan.staging_anchor, path="/data/local/tmp/other"),
                replace(plan.staging_anchor, symlink=True),
                replace(plan.staging_anchor, device=True),
                replace(plan.staging_anchor, mode=0o755)):
            with self.subTest(staging_anchor=anchor):
                with self.assertRaises(reader.DeviceReadError):
                    replace(plan, staging_anchor=anchor).validate()

    def test_nullable_mark_present_and_absent_are_both_exact(self):
        absent, _, clock, *_ = fixture()
        self.assertFalse(absent.collect(deadline(clock)).mark.present)
        present, _, clock, *_ = fixture(mark_present=True)
        value = present.collect(deadline(clock)).mark
        self.assertTrue(value.present)
        self.assertEqual(value.opened.bytes_sha256, MARK_SHA)

    def test_nullable_mark_rejects_unexpected_presence_shape(self):
        authority, backend, clock, *_ = fixture()
        backend.faults["nullable_mark"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=reader.NullableFileEvidence(READER_EPOCH, True, None, None))
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))

        authority, backend, clock, *_ = fixture(mark_present=True)
        backend.faults["nullable_mark"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=reader.NullableFileEvidence(READER_EPOCH, False, None, None))
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))

    def test_ordinary_pdf_descriptor_stat_hash_and_shell_identity_fail_closed(self):
        changes = (
            lambda x: replace(x, uri="content://com.supernote/document/1"),
            lambda x: replace(x, resolved_uri_path="/storage/emulated/0/Document/other.pdf"),
            lambda x: replace(x, uri_scheme="content"),
            lambda x: replace(x, uri_resolution_exact=False),
            lambda x: replace(x, operation_id="0" * 64),
            lambda x: replace(x, descriptor_id="0" * 64),
            lambda x: replace(x, descriptor_read_only=False),
            lambda x: replace(x, descriptor_nofollow=False),
            lambda x: replace(x, descriptor_bound_to_stat=False),
            lambda x: replace(x, hash_from_descriptor=False),
            lambda x: replace(x, collector_uid=0),
            lambda x: replace(x, bytes_sha256="0" * 64),
            lambda x: replace(x, bytes_read=x.bytes_read - 1),
            lambda x: replace(x, stat_after=replace(x.stat_after, inode=999)),
            lambda x: replace(x, stat_after=replace(x.stat_after, symlink=True)),
            lambda x: replace(x, stat_after=replace(x.stat_after, nlink=2)),
            lambda x: replace(x, stat_after=replace(x.stat_after, resolved_path="/other")),
        )
        for change in changes:
            with self.subTest(change=change):
                authority, backend, clock, *_ = fixture()
                backend.faults["original_pdf"] = lambda receipt, _r, _b, c=change: replace(
                    receipt, evidence=c(receipt.evidence))
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))
                self.assertEqual(authority.state, "FAILED")

    def test_missing_mark_requires_stable_parent_enoent_and_nofollow(self):
        changes = (
            lambda x: replace(x, uri="content://com.supernote/mark/1"),
            lambda x: replace(x, resolved_uri_path=x.path + ".other"),
            lambda x: replace(x, uri_scheme="content"),
            lambda x: replace(x, uri_resolution_exact=False),
            lambda x: replace(x, operation_id="0" * 64),
            lambda x: replace(x, errno=13),
            lambda x: replace(x, nofollow_checked=False),
            lambda x: replace(x, collector_uid=0),
            lambda x: replace(x, parent_after=replace(x.parent_after, inode=999)),
        )
        for change in changes:
            with self.subTest(change=change):
                authority, backend, clock, *_ = fixture()
                backend.faults["nullable_mark"] = lambda receipt, _r, _b, c=change: replace(
                    receipt, evidence=replace(receipt.evidence,
                                              missing=c(receipt.evidence.missing)))
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))

    def test_target_pid_start_cmdline_uid_and_base_apk_are_bound(self):
        changes = (
            {"pid": 999}, {"start_ticks": 1}, {"uid": 2000},
            {"cmdline": ("other",)}, {"base_apk_path": "/system/other.apk"},
        )
        for values in changes:
            with self.subTest(values=values):
                authority, backend, clock, *_ = fixture()
                backend.faults["target_process_before"] = (
                    lambda receipt, _r, _b, v=values: replace(
                        receipt, evidence=replace(
                            receipt.evidence, value=replace(receipt.evidence.value, **v))))
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))

    def test_before_after_device_and_process_revalidation_rejects_drift(self):
        for operation, field, value in (
                ("target_process_after", "start_ticks", 77),
                ("device_state_after", "boot_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")):
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                backend.faults[operation] = lambda receipt, _r, _b, f=field, v=value: replace(
                    receipt, evidence=replace(
                        receipt.evidence, value=replace(receipt.evidence.value, **{f: v})))
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))
                self.assertEqual(authority.state, "FAILED_CLEAN")

    def test_protected_read_proves_typed_root_scope_hash_inode_and_cleanup(self):
        authority, _, clock, *_ = fixture()
        protected = authority.collect(deadline(clock)).protected
        self.assertEqual(len(protected), 3)
        for value in protected:
            self.assertEqual((value.root_guardian_uid, value.root_guardian_gid), (0, 0))
            self.assertEqual((value.staging_uid, value.staging_gid, value.staging_mode),
                             (2000, 2000, 0o600))
            self.assertTrue(value.root_guardian_cleanup_armed)
            self.assertEqual(value.root_protocol, reader.PROTECTED_PROTOCOL)
            self.assertEqual(value.root_protocol_version,
                             reader.PROTECTED_PROTOCOL_VERSION)
            self.assertTrue(value.root_scope_protected_only)
            self.assertTrue(value.staging_file_absent)
            self.assertTrue(value.staging_directory_absent)
            self.assertTrue(value.root_guardian_absent)

    def test_every_protected_substitution_or_cleanup_gap_is_sticky(self):
        changes = (
            lambda x: replace(x, operation_id="0" * 64),
            lambda x: replace(x, source_after=replace(x.source_after, inode=999)),
            lambda x: replace(x, source_descriptor_id="0" * 64),
            lambda x: replace(x, source_descriptor_read_only=False),
            lambda x: replace(x, source_descriptor_nofollow=False),
            lambda x: replace(x, source_copy_bound_to_inode=False),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, anchor_after=replace(
                    x.source_path_authority.anchor_after,
                    inode=x.source_path_authority.anchor_after.inode + 1))),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, ancestors_after=(
                    x.source_path_authority.ancestors_after[0],
                    replace(x.source_path_authority.ancestors_after[-1], inode=999)))),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, anchor_descriptor_id="0" * 64)),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, anchor_descriptor_retained=False)),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, relative_path="../escape")),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, resolved_path="/system/other")),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, resolve_beneath=False)),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, resolve_no_symlinks=False)),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, resolve_no_magiclinks=False)),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, resolve_no_xdev=False)),
            lambda x: replace(x, source_path_authority=replace(
                x.source_path_authority, descriptor_bound_to_resolved_inode=False)),
            lambda x: replace(x, staging_path="/data/local/tmp/other"),
            lambda x: replace(
                x, staging_parent_after_read=replace(
                    x.staging_parent_after_read, inode=x.staging_parent_after_read.inode + 1)),
            lambda x: replace(
                x, staging_parent_before_read=replace(
                    x.staging_parent_before_read, mode=0o755)),
            lambda x: replace(x, staging_directory_created_exclusively=False),
            lambda x: replace(x, staging_sha256="0" * 64),
            lambda x: replace(x, staging_uid=0),
            lambda x: replace(x, staging_mode=0o700),
            lambda x: replace(x, staging_nlink=2),
            lambda x: replace(x, staging_symlink=True),
            lambda x: replace(x, descriptor_id="0" * 64),
            lambda x: replace(x, descriptor_read_only=False),
            lambda x: replace(x, descriptor_nofollow=False),
            lambda x: replace(x, descriptor_bound_to_staging_inode=False),
            lambda x: replace(x, staging_hash_from_descriptor=False),
            lambda x: replace(x, descriptor_collector_uid=0),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, anchor_after=replace(
                    x.staging_path_authority.anchor_after,
                    inode=x.staging_path_authority.anchor_after.inode + 1))),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, ancestors_after=(
                    x.staging_path_authority.ancestors_after[0],
                    x.staging_path_authority.ancestors_after[1],
                    replace(x.staging_path_authority.ancestors_after[-1], inode=999)))),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, anchor_descriptor_id="0" * 64)),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, anchor_descriptor_retained=False)),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, relative_path="../escape")),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, resolved_path="/data/local/tmp/other")),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, resolve_beneath=False)),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, resolve_no_symlinks=False)),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, resolve_no_magiclinks=False)),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, resolve_no_xdev=False)),
            lambda x: replace(x, staging_path_authority=replace(
                x.staging_path_authority, descriptor_bound_to_resolved_inode=False)),
            lambda x: replace(x, root_protocol="other"),
            lambda x: replace(x, root_protocol_version=True),
            lambda x: replace(x, root_session_id="0" * 64),
            lambda x: replace(x, root_control_id="0" * 64),
            lambda x: replace(x, root_cmdline=x.root_cmdline[:-1]),
            lambda x: replace(x, private_adb_session_id="0" * 64),
            lambda x: replace(x, worker_session_id="0" * 64),
            lambda x: replace(x, root_guardian_uid=2000),
            lambda x: replace(x, root_guardian_pid=True),
            lambda x: replace(x, root_guardian_cleanup_armed=False),
            lambda x: replace(x, root_scope_protected_only=False),
            lambda x: replace(x, staging_file_absent=False),
            lambda x: replace(x, staging_inode_absent=False),
            lambda x: replace(x, staging_directory_absent=False),
            lambda x: replace(x, root_guardian_absent=False),
            lambda x: replace(x, root_guardian_pid_not_reused=False),
            lambda x: replace(x, root_control_closed=False),
            lambda x: replace(x, path_not_replaced=False),
            lambda x: replace(x, cleanup_anchor_descriptor_id="0" * 64),
            lambda x: replace(x, cleanup_handle_relative=False),
            lambda x: replace(x, cleanup_descriptor_bound_to_staging_inode=False),
        )
        for change in changes:
            with self.subTest(change=change):
                authority, backend, clock, *_ = fixture()
                backend.faults["framework"] = lambda receipt, _r, _b, c=change: replace(
                    receipt, evidence=c(receipt.evidence))
                with self.assertRaises(reader.ReadCleanupUncertain):
                    authority.collect(deadline(clock))
                self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
                count = len(backend.calls)
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))
                with self.assertRaises(reader.ReadCleanupUncertain):
                    authority.close(deadline(clock))
                self.assertEqual(len(backend.calls), count)

    def test_protected_backend_exception_never_retries_or_broadens_cleanup(self):
        authority, backend, clock, *_ = fixture()
        backend.faults["framework"] = reader.DeviceReadError("root worker lost")
        with self.assertRaises(reader.ReadCleanupUncertain):
            authority.collect(deadline(clock))
        self.assertEqual([x[0] for x in backend.calls].count("framework"), 1)
        self.assertTrue(authority.cleanup_obligations)
        self.assertIn(reader.STAGING_PREFIX, authority.cleanup_obligations[0])
        self.assertIn("do not retry", authority.cleanup_obligations[0])

    def test_dump_kind_source_hash_shell_identity_and_bounds_are_exact(self):
        changes = (
            lambda x: replace(x, kind="window"),
            lambda x: replace(x, source="dumpsys activity"),
            lambda x: replace(x, sha256="0" * 64),
            lambda x: replace(x, byte_count=x.byte_count + 1),
            lambda x: replace(x, truncated=True),
            lambda x: replace(x, collector_uid=0),
            lambda x: replace(x, raw=b"A" * 100_001,
                              sha256=hashlib.sha256(b"A" * 100_001).hexdigest(),
                              byte_count=100_001),
        )
        for change in changes:
            with self.subTest(change=change):
                authority, backend, clock, *_ = fixture()
                backend.faults["activity_dump"] = lambda receipt, _r, _b, c=change: replace(
                    receipt, evidence=c(receipt.evidence))
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))

    def test_ack_substitution_replay_and_late_reply_fail_closed(self):
        faults = (
            lambda a, q: replace(a, authority="wrong"),
            lambda a, q: replace(a, sequence=q.sequence - 1),
            lambda a, q: replace(a, sequence=True),
            lambda a, q: replace(a, session_id="9" * 64),
            lambda a, q: replace(a, serial="OTHER"),
            lambda a, q: replace(a, operation="window_dump"),
            lambda a, q: replace(a, operation_id="0" * 64),
            lambda a, q: replace(a, request_sha256="0" * 64),
            lambda a, q: replace(a, issued_ns=float(q.issued_ns)),
            lambda a, q: replace(a, produced_ns=q.issued_ns - 1),
            lambda a, q: replace(a, produced_ns=q.deadline_ns),
        )
        for fault in faults:
            with self.subTest(fault=fault):
                authority, backend, clock, *_ = fixture()
                backend.faults["device_state_before"] = (
                    lambda receipt, request, _b, f=fault:
                    replace(receipt, ack=f(receipt.ack, request)))
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))
                self.assertEqual(authority.state, "FAILED")

    def test_deadline_clock_lock_reentry_and_post_terminal_use(self):
        authority, backend, clock, *_ = fixture()
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(clock.now_ns())
        authority, backend, clock, *_ = fixture()
        authority._last_now = clock.now_ns(); clock.value -= 1
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(clock.now_ns() + 1_000_000)

        authority, backend, clock, *_ = fixture()
        errors = []
        before_lock_attempt = clock.now_ns()
        authority._lock.acquire()
        try:
            thread = threading.Thread(target=lambda: self._capture(errors, authority.evidence))
            thread.start(); thread.join(1)
            self.assertFalse(thread.is_alive())
        finally:
            authority._lock.release()
        self.assertIsInstance(errors[0], reader.DeviceReadError)
        self.assertEqual(clock.now_ns(), before_lock_attempt)

        authority, backend, clock, *_ = fixture()
        nested = []
        def reenter(receipt, _request, _backend):
            self._capture(nested, authority.evidence)
            return receipt
        backend.faults["device_state_before"] = reenter
        authority.collect(deadline(clock))
        self.assertIsInstance(nested[0], reader.DeviceReadError)
        authority.close(deadline(clock))
        with self.assertRaises(reader.DeviceReadError):
            authority.verify_unchanged(deadline(clock))

    def test_dependencies_are_revalidated_before_and_after_each_operation(self):
        targets = ("epoch", "adb", "worker", "backend")
        for target in targets:
            with self.subTest(target=target):
                authority, backend, clock, adb, worker, _, epoch = fixture()
                {"epoch": epoch, "adb": adb, "worker": worker,
                 "backend": backend}[target].changed = True
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))
                self.assertEqual(backend.calls, [])

    def test_plan_and_wire_scalars_reject_bool_float_and_subclasses(self):
        plan = make_plan()
        class StringSubclass(str):
            pass
        for altered in (
                replace(plan, operation_budget_ns=True),
                replace(plan, total_budget_ns=float(plan.total_budget_ns)),
                replace(plan, authority=StringSubclass(plan.authority)),
                replace(plan, device=replace(plan.device, sdk_int=True)),
                replace(plan, target=replace(plan.target, pid=float(plan.target.pid))),
                replace(plan, original_pdf=replace(
                    plan.original_pdf, expected=replace(
                        plan.original_pdf.expected,
                        size=float(plan.original_pdf.expected.size)))),
                replace(plan, staging_anchor=replace(plan.staging_anchor, inode=True)),
                replace(plan, dumps=replace(plan.dumps, activity=True)),
        ):
            with self.subTest(altered=type(altered).__name__):
                with self.assertRaises(reader.DeviceReadError):
                    altered.validate()

    def test_plan_rejects_wrong_protected_order_duplicates_and_base_apk_disagreement(self):
        plan = make_plan()
        for protected in (
                tuple(reversed(plan.protected)),
                (plan.protected[0], plan.protected[0], plan.protected[2]),
                plan.protected[:-1],
        ):
            with self.subTest(protected=protected):
                with self.assertRaises(reader.DeviceReadError):
                    replace(plan, protected=protected).validate()
        target = replace(plan.target, base_apk_path="/system/priv-app/Other/Other.apk")
        with self.assertRaises(reader.DeviceReadError):
            replace(plan, target=target).validate()
        duplicate_source = replace(
            plan.protected[1], expected=plan.protected[0].expected)
        with self.assertRaises(reader.DeviceReadError):
            replace(plan, protected=(plan.protected[0], duplicate_source,
                                     plan.protected[2])).validate()

    def test_plan_freezes_authorized_device_fixed_target_and_operation_purposes(self):
        plan = make_plan()
        altered_plans = (
            replace(plan, device=replace(plan.device, adb_state="unauthorized")),
            replace(plan, device=replace(plan.device, adb_authorized=False)),
            replace(plan, target=replace(
                plan.target, package="com.example.other", process="com.example.other",
                cmdline=("com.example.other",))),
            replace(plan, original_pdf=replace(plan.original_pdf, purpose="other")),
            replace(plan, original_pdf=replace(
                plan.original_pdf, disposable_fixture=False)),
            replace(plan, mark=replace(plan.mark, purpose="other")),
            replace(plan, mark=replace(plan.mark, disposable_companion=False)),
            replace(plan, mark=replace(
                plan.mark,
                path=plan.original_pdf.expected.path + ".other",
                uri=reader.canonical_file_uri(
                    plan.original_pdf.expected.path + ".other"))),
        )
        for altered in altered_plans:
            with self.subTest(altered=altered):
                with self.assertRaises(reader.DeviceReadError):
                    altered.validate()

    def test_paths_reject_non_nfc_and_ordinary_hardlinks(self):
        plan = make_plan()
        nfd_path = unicodedata.normalize(
            "NFD", "/storage/emulated/0/Document/café.pdf")
        self.assertNotEqual(nfd_path, unicodedata.normalize("NFC", nfd_path))
        nfd_identity = replace(
            plan.original_pdf.expected, path=nfd_path, resolved_path=nfd_path)
        with self.assertRaises(reader.DeviceReadError):
            replace(plan, original_pdf=replace(
                plan.original_pdf, uri=reader.canonical_file_uri(
                    unicodedata.normalize("NFC", nfd_path)), expected=nfd_identity)).validate()
        hardlink = replace(plan.original_pdf.expected, nlink=2)
        with self.assertRaises(reader.DeviceReadError):
            replace(plan, original_pdf=replace(
                plan.original_pdf, expected=hardlink)).validate()
        wrong_parent_device = replace(
            plan.original_pdf.expected,
            parent=replace(plan.original_pdf.expected.parent, device=99))
        with self.assertRaises(reader.DeviceReadError):
            replace(plan, original_pdf=replace(
                plan.original_pdf, expected=wrong_parent_device)).validate()

    def test_file_uri_percent_and_fragment_characters_are_data_not_syntax(self):
        path = "/storage/emulated/0/Document/100% #סידור?.pdf"
        uri = reader.canonical_file_uri(path)
        self.assertIn("100%25%20%23", uri)
        self.assertIn("%3F.pdf", uri)
        self.assertNotIn("#", uri)
        make_plan(pdf_path=path).validate()

    def test_requests_and_evidence_are_fresh_and_bound_to_retained_authorities(self):
        authority, backend, clock, _adb, worker, _plan, _epoch = fixture(mark_present=True)
        snapshot = authority.collect(deadline(clock))
        requests = [entry[1] for entry in backend.calls]
        worker_digest = hashlib.sha256(worker.value.canonical_bytes()).hexdigest()
        self.assertEqual([value.sequence for value in requests], list(range(1, 13)))
        self.assertEqual(len({value.operation_id for value in requests}), 12)
        for request in requests:
            self.assertEqual(request.authority, reader.AUTHORITY)
            self.assertEqual(request.session_id, SESSION)
            self.assertEqual(request.serial, SERIAL)
            self.assertRegex(request.private_adb_binding_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(request.worker_binding_sha256, worker_digest)
            self.assertRegex(request.backend_binding_sha256, r"^[0-9a-f]{64}$")
            self.assertGreater(request.deadline_ns, request.issued_ns)
        by_operation = {value.operation: value for value in requests}
        self.assertEqual(snapshot.device.operation_id,
                         by_operation["device_state_before"].operation_id)
        self.assertEqual(snapshot.target.operation_id,
                         by_operation["target_process_before"].operation_id)
        self.assertEqual(snapshot.original_pdf.operation_id,
                         by_operation["original_pdf"].operation_id)
        self.assertEqual(snapshot.mark.opened.operation_id,
                         by_operation["nullable_mark"].operation_id)
        self.assertEqual(snapshot.activity.operation_id,
                         by_operation["activity_dump"].operation_id)
        self.assertEqual(snapshot.private_adb.session_id, ADB_SESSION)
        self.assertEqual(snapshot.worker.session, WORKER_SESSION)
        self.assertFalse(snapshot.private_adb.shared_server)

    def test_evidence_replay_across_verify_is_rejected(self):
        authority, backend, clock, *_ = fixture()
        first = authority.collect(deadline(clock))
        backend.faults["original_pdf:2"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=first.original_pdf)
        with self.assertRaises(reader.DeviceReadError):
            authority.verify_unchanged(deadline(clock))
        self.assertEqual(authority.state, "FAILED_CLEAN")
        for action in (authority.evidence,
                       lambda: authority.close(deadline(clock)),
                       authority.evidence,
                       lambda: authority.close(deadline(clock))):
            with self.assertRaises(reader.DeviceReadError):
                action()

    def test_cross_reader_replay_is_rejected_by_fresh_one_shot_epoch(self):
        first, first_backend, first_clock, *_ = fixture(epoch_id=READER_EPOCH)
        first.collect(deadline(first_clock))
        second, second_backend, second_clock, *_ = fixture(epoch_id=READER_EPOCH_2)
        second_backend.faults["device_state_before"] = (
            lambda _receipt, _request, _backend:
            first_backend.receipts["device_state_before"])
        with self.assertRaises(reader.DeviceReadError):
            second.collect(deadline(second_clock))
        self.assertEqual(second.state, "FAILED")
        self.assertNotEqual(
            first_backend.calls[0][1].operation_id,
            second_backend.calls[0][1].operation_id)
        self.assertNotEqual(
            first_backend.calls[0][1].reader_epoch_id,
            second_backend.calls[0][1].reader_epoch_id)

    def test_epoch_admission_is_retained_one_shot_and_production_is_blocked(self):
        authority, backend, clock, adb, worker, plan, epoch_authority = fixture()
        with self.assertRaises(reader.DeviceReadError):
            reader.AuthenticatedDeviceEvidenceReader(
                plan=plan, private_adb=adb, worker_runtime=worker,
                worker_process=worker.process, epoch_authority=epoch_authority,
                backend=backend, clock=clock,
                allow_unproven_epoch_authority_for_tests=True)
        self.assertEqual(backend.calls, [])

        fresh_plan = make_plan()
        fresh_epoch = FakeEpochAuthority(fresh_plan, READER_EPOCH_2)
        with self.assertRaises(reader.DeviceReadError):
            reader.AuthenticatedDeviceEvidenceReader(
                plan=fresh_plan, private_adb=adb, worker_runtime=worker,
                worker_process=worker.process, epoch_authority=fresh_epoch,
                backend=backend, clock=clock)
        self.assertFalse(fresh_epoch.consumed)
        self.assertFalse(reader.REAL_READER_EPOCH_AUTHORITY_IMPLEMENTED)

        for field, value in (
                ("epoch_id", SESSION),
                ("admission_sequence", True),
                ("one_shot_consumed", 1),
                ("retained_live_authority", 1),
                ("serial", "OTHER")):
            with self.subTest(epoch_field=field):
                bad_epoch = FakeEpochAuthority(plan, READER_EPOCH_2)
                bad_epoch.value = replace(bad_epoch.value, **{field: value})
                with self.assertRaises(reader.DeviceReadError):
                    reader.AuthenticatedDeviceEvidenceReader(
                        plan=plan, private_adb=adb, worker_runtime=worker,
                        worker_process=worker.process, epoch_authority=bad_epoch,
                        backend=backend, clock=clock,
                        allow_unproven_epoch_authority_for_tests=True)

    def test_epoch_drift_and_epoch_wire_substitution_fail_before_release(self):
        authority, backend, clock, *_rest, epoch_authority = fixture()
        epoch_authority.changed = True
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(backend.calls, [])

        authority, backend, clock, *_ = fixture()
        backend.faults["device_state_before"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=replace(receipt.evidence, reader_epoch_id=READER_EPOCH_2))
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(authority.state, "FAILED")

        authority, backend, clock, *_ = fixture()
        backend.faults["device_state_before"] = lambda receipt, _request, _backend: replace(
            receipt, ack=replace(receipt.ack, reader_epoch_id=READER_EPOCH_2))
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(authority.state, "FAILED")

    def test_protected_evidence_replay_is_sticky_and_never_retried(self):
        authority, backend, clock, *_ = fixture()
        first = authority.collect(deadline(clock))
        backend.faults["framework:2"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=first.protected[0])
        with self.assertRaises(reader.ReadCleanupUncertain):
            authority.verify_unchanged(deadline(clock))
        self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
        framework_calls = backend.counts["framework"]
        with self.assertRaises(reader.DeviceReadError):
            authority.verify_unchanged(deadline(clock))
        self.assertEqual(backend.counts["framework"], framework_calls)

    def test_wrong_receipt_and_backend_exception_still_require_quiescence(self):
        authority, backend, clock, *_ = fixture()
        backend.faults["original_pdf"] = lambda receipt, request, fake: (
            reader.DeviceStateReceipt(receipt.ack, fake._device(request)))
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(len(backend.quiescent), 3)
        self.assertEqual(authority.state, "FAILED")

        authority, backend, clock, *_ = fixture()
        backend.faults["original_pdf"] = reader.DeviceReadError("read worker failed")
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(len(backend.quiescent), 3)
        self.assertEqual([item[0] for item in backend.calls].count("original_pdf"), 1)

    def test_quiescence_uncertainty_is_sticky_and_seals_all_evidence(self):
        authority, backend, clock, *_ = fixture()
        backend.quiescent_hook = lambda _operation_id: (_ for _ in ()).throw(
            reader.DeviceReadError("late reply channel not sealed"))
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.collect(deadline(clock))
        self.assertEqual(authority.state, "QUIESCENCE_UNCERTAIN")
        self.assertIn("do not retry", authority.cleanup_obligations[0])
        count = len(backend.calls)
        for action in (authority.evidence,
                       lambda: authority.close(deadline(clock)),
                       lambda: authority.collect(deadline(clock)),
                       lambda: authority.verify_unchanged(deadline(clock))):
            with self.assertRaises(reader.DeviceReadError):
                action()
        self.assertEqual(len(backend.calls), count)

    def test_quiescence_failure_after_ready_cannot_return_old_snapshot(self):
        authority, backend, clock, *_ = fixture()
        authority.collect(deadline(clock))
        backend.quiescent_hook = lambda _operation_id: (_ for _ in ()).throw(
            reader.DeviceReadError("verification worker may still reply"))
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.verify_unchanged(deadline(clock))
        self.assertEqual(authority.state, "QUIESCENCE_UNCERTAIN")
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.evidence()
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.close(deadline(clock))

    def test_final_quiescence_failure_seals_previously_ready_snapshot(self):
        authority, backend, clock, *_ = fixture()
        authority.collect(deadline(clock))
        backend.all_quiescent_hook = lambda: (_ for _ in ()).throw(
            reader.DeviceReadError("worker shutdown not proven"))
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.close(deadline(clock))
        self.assertEqual(authority.state, "QUIESCENCE_UNCERTAIN")
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.evidence()
        with self.assertRaises(reader.QuiescenceUncertain):
            authority.close(deadline(clock))

    def test_protected_predispatch_failure_has_no_false_cleanup_obligation(self):
        authority, backend, clock, *_ = fixture()
        backend.faults["framework:preflight"] = reader.DeviceReadError(
            "fixed backend rejected before root dispatch")
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(authority.state, "FAILED")
        self.assertEqual(authority.cleanup_obligations, ())
        self.assertEqual(backend.protected_dispatches, [])
        self.assertNotIn("framework", backend.receipts)

    def test_protected_postdispatch_failure_is_cleanup_uncertain_and_one_shot(self):
        authority, backend, clock, *_ = fixture()
        backend.faults["framework"] = reader.DeviceReadError("root reply lost")
        with self.assertRaises(reader.ReadCleanupUncertain):
            authority.collect(deadline(clock))
        self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
        self.assertEqual(len(backend.protected_dispatches), 1)
        calls = len(backend.calls)
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(len(backend.calls), calls)

    def test_post_success_protected_reply_loss_seals_prior_snapshot(self):
        authority, backend, clock, *_ = fixture()
        authority.collect(deadline(clock))
        backend.faults["framework:2"] = reader.DeviceReadError(
            "protected reply channel lost after dispatch")
        with self.assertRaises(reader.ReadCleanupUncertain):
            authority.verify_unchanged(deadline(clock))
        self.assertEqual(authority.state, "CLEANUP_UNCERTAIN")
        calls = len(backend.calls)
        for action in (authority.evidence,
                       lambda: authority.close(deadline(clock)),
                       authority.evidence,
                       lambda: authority.close(deadline(clock))):
            with self.assertRaises(reader.ReadCleanupUncertain):
                action()
        self.assertEqual(len(backend.calls), calls)

    def test_post_success_ordinary_verify_failure_seals_prior_snapshot(self):
        authority, backend, clock, *_ = fixture()
        authority.collect(deadline(clock))
        backend.faults["original_pdf:2"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=replace(receipt.evidence, bytes_sha256="0" * 64))
        with self.assertRaises(reader.DeviceReadError):
            authority.verify_unchanged(deadline(clock))
        self.assertEqual(authority.state, "FAILED_CLEAN")
        calls = len(backend.calls)
        for action in (authority.evidence,
                       lambda: authority.close(deadline(clock)),
                       authority.evidence,
                       lambda: authority.close(deadline(clock)),
                       lambda: authority.verify_unchanged(deadline(clock))):
            with self.assertRaises(reader.DeviceReadError):
                action()
        self.assertEqual(len(backend.calls), calls)

    def test_dependency_drift_after_reply_fails_before_next_operation(self):
        authority, backend, clock, adb, *_ = fixture()
        def drift(receipt, _request, _backend):
            adb.changed = True
            return receipt
        backend.faults["device_state_before"] = drift
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(len(backend.quiescent), 1)
        self.assertEqual(authority.state, "FAILED")

    def test_authority_and_quiescence_checks_must_return_exact_none(self):
        authority, backend, clock, adb, *_ = fixture()
        adb.verify = lambda _expected: True
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(backend.calls, [])

        authority, backend, clock, *_ = fixture()
        backend.assert_operation_quiescent = lambda *_args: True
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(len(backend.calls), 1)

        authority, backend, clock, *_ = fixture()
        authority.collect(deadline(clock))
        backend.assert_all_quiescent = lambda *_args: True
        with self.assertRaises(reader.DeviceReadError):
            authority.close(deadline(clock))
        self.assertEqual(authority.state, "QUIESCENCE_UNCERTAIN")

    def test_same_thread_reentry_from_quiescence_is_rejected_without_deadlock(self):
        authority, backend, clock, *_ = fixture()
        nested = []
        backend.quiescent_hook = lambda _operation_id: self._capture(
            nested, authority.evidence)
        authority.collect(deadline(clock))
        self.assertEqual(len(nested), 12)
        self.assertTrue(all(isinstance(error, reader.DeviceReadError)
                            for error in nested))
        self.assertEqual(authority.state, "READY")

    def test_operation_timeout_never_retries(self):
        authority, backend, clock, *_ = fixture()
        def expire(receipt, request, _backend):
            clock.value = request.deadline_ns
            return receipt
        backend.faults["device_state_before"] = expire
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(authority.state, "QUIESCENCE_UNCERTAIN")

    def test_external_wire_types_are_exact_not_truthy(self):
        ordinary_cases = (
            ("device_state_before", lambda receipt: replace(
                receipt, evidence=replace(receipt.evidence, collector_uid=True))),
            ("target_process_before", lambda receipt: replace(
                receipt, evidence=replace(receipt.evidence, alive=1))),
            ("original_pdf", lambda receipt: replace(
                receipt, evidence=replace(receipt.evidence, uri_resolution_exact=1))),
            ("activity_dump", lambda receipt: replace(
                receipt, evidence=replace(receipt.evidence,
                                          raw=bytearray(receipt.evidence.raw)))),
        )
        for operation, change in ordinary_cases:
            with self.subTest(operation=operation):
                authority, backend, clock, *_ = fixture()
                backend.faults[operation] = lambda receipt, _request, _backend, c=change: c(receipt)
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))

        authority, backend, clock, *_ = fixture()
        backend.faults["framework"] = lambda receipt, _request, _backend: replace(
            receipt, evidence=replace(
                receipt.evidence, staging_directory_created_exclusively=1))
        with self.assertRaises(reader.ReadCleanupUncertain):
            authority.collect(deadline(clock))

    def test_close_failure_is_terminal_and_does_not_trigger_more_device_reads(self):
        authority, backend, clock, *_ = fixture()
        authority.collect(deadline(clock))
        count = len(backend.calls)
        backend.changed = True
        with self.assertRaises(reader.DeviceReadError):
            authority.close(deadline(clock))
        self.assertEqual(authority.state, "FAILED_CLEAN")
        self.assertEqual(len(backend.calls), count)
        with self.assertRaises(reader.DeviceReadError):
            authority.verify_unchanged(deadline(clock))
        for action in (authority.evidence,
                       lambda: authority.close(deadline(clock)),
                       authority.evidence,
                       lambda: authority.close(deadline(clock))):
            with self.assertRaises(reader.DeviceReadError):
                action()
        self.assertEqual(len(backend.calls), count)

    def test_runtime_content_and_hardware_timing_blockers_are_honest(self):
        self.assertFalse(reader.REAL_RUNTIME_BACKEND_IMPLEMENTED)
        self.assertFalse(reader.CONTENT_URI_SUPPORTED)
        self.assertFalse(reader.HARDWARE_TIMING_PROVEN)
        self.assertEqual(reader.TARGET_CALL_BUDGET_NS, 25_000_000)
        self.assertEqual(reader.TARGET_TOTAL_BUDGET_NS, 250_000_000)
        self.assertEqual(reader.TARGET_PACKAGE, "com.supernote.document")
        self.assertEqual(len(reader.UNRESOLVED_BLOCKERS), 4)

    def test_bindings_reject_ambient_unretained_or_general_command_authority(self):
        _, _, _, adb, worker, _, _epoch = fixture()
        adb_value = adb.value
        worker_value = worker.value
        for altered in (
                replace(adb_value, endpoint="tcp:127.0.0.1:5037"),
                replace(adb_value, retained_server_handle=False),
                replace(adb_value, explicit_serial=False),
                replace(adb_value, private_socket=False),
                replace(adb_value, shared_server=True),
                replace(adb_value, server_pid=True)):
            with self.subTest(binding="adb", altered=altered):
                with self.assertRaises(mutator.DeviceFridaError):
                    altered.validate()
        for field, value in (
                ("pid", True),
                ("creation_ticks", True),
                ("parent_pid", True),
                ("parent_creation_ticks", True),
                ("image_path", "relative.exe")):
            with self.subTest(binding="worker", field=field):
                with self.assertRaises((worker_runtime.RuntimeError,
                                        cleanup_ledger.AuthorityError)):
                    replace(worker_value, **{field: value})
        backend = fixture()[1].value
        for altered in (
                replace(backend, ordinary_uid=True),
                replace(backend, private_adb_bundle_sha256="0" * 64),
                replace(backend, worker_role="frida_worker"),
                replace(backend, worker_factory_id="frida_worker-v1"),
                replace(backend, worker_image_path=r"C:\rtl-reader\other.exe"),
                replace(backend, worker_source_sha256="0" * 64),
                replace(backend, worker_parent_pid=999),
                replace(backend, private_socket=False),
                replace(backend, explicit_serial_every_operation=False),
                replace(backend, retained_worker_handle=False),
                replace(backend, accepts_general_commands=True),
                replace(backend, fixed_operations_only=False),
                replace(backend, fresh_reply_channel_per_operation=False),
                replace(backend, late_reply_channel_sealed=False),
                replace(backend, failure_returns_after_operation_quiescence=False),
                replace(backend, root_only_for_protected_reads=False),
                replace(backend, protected_cleanup_before_return=False),
                replace(backend, protected_dispatch_witness_required=False),
                replace(backend, protected_anchor_descriptor_retained=False),
                replace(backend, protected_handle_relative_nofollow=False),
                replace(backend, protected_descriptor_bound_cleanup=False)):
            with self.subTest(binding="backend", altered=altered):
                with self.assertRaises(reader.DeviceReadError):
                    altered.validate(adb_value, worker_value)

    def test_exact_private_adb_is_reused_and_mutation_worker_is_rejected(self):
        self.assertIs(reader.PrivateAdbBinding, mutator.PrivateAdbBinding)
        authority, _, clock, *_ = fixture()
        self.assertEqual(authority.collect(deadline(clock)).private_adb.session_id,
                         ADB_SESSION)

        class PrivateAdbSubclass(mutator.PrivateAdbBinding):
            pass

        authority, backend, clock, adb, _, _, _epoch = fixture()
        adb.alias = PrivateAdbSubclass(**adb.value.__dict__)
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(backend.calls, [])

        _, backend, clock, adb, _, plan, _epoch = fixture()
        mutation_worker = mutator.WorkerBinding(
            mutator.WORKER_AUTHORITY, WORKER_SESSION, 201, 8001,
            WORKER_SHA, True, True)
        process = object()
        with self.assertRaises(reader.DeviceReadError):
            reader.AuthenticatedDeviceEvidenceReader(
                plan=plan, private_adb=adb,
                worker_runtime=FakeWorkerRuntime(mutation_worker, process),
                worker_process=process, epoch_authority=FakeEpochAuthority(plan),
                backend=backend, clock=clock,
                allow_unproven_epoch_authority_for_tests=True)

    def test_authority_worker_cannot_be_substituted_rebased_or_subclassed(self):
        self.assertIs(reader.WorkerBinding, worker_runtime.WorkerBinding)
        for alias in (
                replace(fixture()[4].value, role="frida_worker",
                        factory_id="frida_worker-v1"),
                replace(fixture()[4].value, session="8" * 64),
                replace(fixture()[4].value, parent_pid=302)):
            with self.subTest(alias=alias):
                authority, backend, clock, _, worker, _, _epoch = fixture()
                worker.alias = alias
                with self.assertRaises(reader.DeviceReadError):
                    authority.collect(deadline(clock))
                self.assertEqual(backend.calls, [])

        class WorkerSubclass(worker_runtime.WorkerBinding):
            pass

        authority, backend, clock, _, worker, _, _epoch = fixture()
        worker.alias = WorkerSubclass(**worker.value.__dict__)
        with self.assertRaises(reader.DeviceReadError):
            authority.collect(deadline(clock))
        self.assertEqual(backend.calls, [])

        _, backend, clock, adb, worker, plan, epoch_authority = fixture()
        with self.assertRaises(reader.DeviceReadError):
            reader.AuthenticatedDeviceEvidenceReader(
                plan=plan, private_adb=adb, worker_runtime=worker,
                worker_process=object(), epoch_authority=epoch_authority,
                backend=backend, clock=clock,
                allow_unproven_epoch_authority_for_tests=True)

    def test_constructor_rejects_worker_authority_race(self):
        plan = make_plan()
        clock = FakeClock()
        adb_binding = reader.PrivateAdbBinding(
            reader.PRIVATE_ADB_AUTHORITY, SERIAL, "tcp:127.0.0.1:41337", 101, 7001,
            ADB_SHA, ADB_SESSION, True, True, True, False)
        worker_binding = reader.WorkerBinding(
            201, 8001, WORKER_IMAGE_PATH, reader.WORKER_ROLE,
            reader.WORKER_FACTORY_ID, WORKER_SESSION, WORKER_SHA,
            WORKER_SOURCE_SHA, 301, 9001)
        backend_binding = reader.ReaderBackendBinding(
            authority=reader.BACKEND_AUTHORITY,
            serial=SERIAL,
            private_adb_session_id=ADB_SESSION,
            private_adb_endpoint=adb_binding.endpoint,
            private_adb_pid=adb_binding.server_pid,
            private_adb_start_ticks=adb_binding.server_start_ticks,
            private_adb_bundle_sha256=adb_binding.bundle_sha256,
            worker_session_id=WORKER_SESSION,
            worker_pid=worker_binding.pid,
            worker_creation_ticks=worker_binding.creation_ticks,
            worker_image_path=worker_binding.image_path,
            worker_image_sha256=WORKER_SHA,
            worker_source_sha256=WORKER_SOURCE_SHA,
            worker_parent_pid=worker_binding.parent_pid,
            worker_parent_creation_ticks=worker_binding.parent_creation_ticks,
            worker_role=reader.WORKER_ROLE,
            worker_factory_id=reader.WORKER_FACTORY_ID,
            ordinary_uid=2000,
            ordinary_gid=2000,
            private_socket=True,
            explicit_serial_every_operation=True,
            retained_worker_handle=True,
            fixed_operations_only=True,
            accepts_general_commands=False,
            fresh_reply_channel_per_operation=True,
            late_reply_channel_sealed=True,
            failure_returns_after_operation_quiescence=True,
            root_only_for_protected_reads=True,
            protected_cleanup_before_return=True,
            protected_dispatch_witness_required=True,
            protected_anchor_descriptor_retained=True,
            protected_handle_relative_nofollow=True,
            protected_descriptor_bound_cleanup=True)
        worker_process = object()
        class RacingWorker(FakeWorkerRuntime):
            def binding(self, process):
                value = super().binding(process)
                self.changed = True
                return value
        with self.assertRaises(reader.DeviceReadError):
            reader.AuthenticatedDeviceEvidenceReader(
                plan=plan, private_adb=FakeAuthority(adb_binding),
                worker_runtime=RacingWorker(worker_binding, worker_process),
                worker_process=worker_process,
                epoch_authority=FakeEpochAuthority(plan),
                backend=FakeBackend(clock, backend_binding, plan), clock=clock,
                allow_unproven_epoch_authority_for_tests=True)

    @staticmethod
    def _capture(errors, function):
        try:
            function()
        except BaseException as error:
            errors.append(error)


if __name__ == "__main__":
    unittest.main()
