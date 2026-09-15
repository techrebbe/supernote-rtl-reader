"""Fake crash/Win32 adversaries plus narrowly scoped Windows temporary files."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import json
import ntpath
import os
from pathlib import Path
import tempfile
import threading
import unittest

from native_page_cleanup_ledger import (
    AuthorityError, CleanupLedger, CorruptLedger, Observation, PersistenceError,
    RecoveryCheckpoint, ResourceIdentity, canonical_json,
)
from native_page_cleanup_store import (
    DurabilityUnavailable, FileIdentity, FileInfo, StorageError, StoreAuthority,
    Win32, WindowsCleanupStore, local_path,
)


RUN = r"C:\sandbox\run"
EXTERNAL = r"C:\authority\checkpoints"
CLOCK = "boot:11111111-1111-1111-1111-111111111111"
IDENTITY = ResourceIdentity("display", "fake-device", "7", "display-incarnation-1")


@dataclass
class Node:
    index: int
    directory: bool = False
    private: bool = True
    reparse: bool = False
    links: int = 1
    payload: bytes = b""
    synced: bytes | None = None


@dataclass
class Handle:
    node: Node
    path: str
    writable: bool = False
    deletable: bool = False
    exclusive: bool = False
    alive: bool = True
    deleted: bool = False


class FakeWin32:
    """Visibility, fsynced data, durable namespace, and Windows sharing are separate."""
    def __init__(self):
        self.nodes = {}
        self.durable = {}
        self.handles = []
        self.counter = 0
        self.log = []
        self.fault = None
        self.chunk = 101
        self.directory_flush_supported = True
        self.delete_calls = 0
        for path in ("C:\\", "C:\\sandbox", "C:\\authority"):
            self.nodes[path] = self.node(directory=True, private=False)
        self.durable = copy.deepcopy(self.nodes)

    def node(self, **kw):
        self.counter += 1
        return Node(self.counter, **kw)

    def boundary(self, operation, action):
        self.log.append(operation)
        edge = len(self.log)
        if self.fault == (edge, "before"):
            raise OSError(f"injected before {operation} at {edge}")
        result = action()
        if self.fault == (edge, "after"):
            raise OSError(f"injected after {operation} at {edge}")
        return result

    def clone(self):
        result = copy.deepcopy(self)
        result.handles, result.log, result.fault = [], [], None
        return result

    def crash(self):
        self.nodes = copy.deepcopy(self.durable)
        self.handles = []
        self.log = []
        self.fault = None

    def local_volume(self, path):
        return path.startswith("C:\\")

    def private(self, handle):
        self.validate(handle)
        return handle.node.private

    def mkdir(self, path):
        def action():
            if path in self.nodes or ntpath.dirname(path) not in self.nodes:
                raise FileExistsError(path)
            self.nodes[path] = self.node(directory=True)
        return self.boundary("mkdir", action)

    def open_directory(self, path, *, writable=False, attributes_only=False):
        return self._open(path, directory=True, writable=writable)

    def open_file(self, path, *, create=False, writable=False, exclusive=False, deletable=False):
        return self._open(path, create=create, writable=writable, exclusive=exclusive, deletable=deletable)

    def _open(self, path, *, directory=False, create=False, writable=False, exclusive=False, deletable=False):
        def action():
            if create:
                if path in self.nodes:
                    raise FileExistsError(path)
                self.nodes[path] = self.node()
            node = self.nodes[path]
            for other in self.handles:
                if other.alive and other.node is node and not directory:
                    if exclusive or other.exclusive or writable or deletable or other.writable or other.deletable:
                        raise PermissionError("Windows sharing violation")
            handle = Handle(node, path, writable, deletable, exclusive)
            self.handles.append(handle)
            return handle
        return self.boundary("open", action)

    def validate(self, handle):
        if not isinstance(handle, Handle) or not handle.alive:
            raise OSError("stale native handle")

    def info(self, handle):
        self.validate(handle)
        node = handle.node
        if self.nodes.get(handle.path) is not node:
            # A path replacement cannot silently change an existing handle.
            actual = next((path for path, value in self.nodes.items() if value is node), "C:\\lost")
        else:
            actual = handle.path
        return FileInfo(FileIdentity(17, node.index), actual, node.directory, node.reparse, node.links)

    def names(self, path):
        return [ntpath.basename(name) for name in self.nodes if ntpath.dirname(name) == path and name != path]

    def read(self, handle):
        self.validate(handle)
        return handle.node.payload

    def write(self, handle, payload):
        def action():
            self.validate(handle)
            if not handle.writable:
                raise PermissionError("read-only handle")
            chunk = payload[:self.chunk]
            handle.node.payload += chunk
            return len(chunk)
        return self.boundary("write", action)

    def flush(self, handle, *, directory=False):
        def action():
            self.validate(handle)
            if not handle.writable:
                raise PermissionError("FlushFileBuffers requires retained write access")
            if handle.node.directory != directory:
                raise OSError("flush file/directory role differs")
            if directory:
                if not self.directory_flush_supported:
                    raise DurabilityUnavailable("injected unsupported Windows directory FlushFileBuffers")
                # Namespace flush makes only individually file-flushed bytes durable.
                self.durable = {path: node for path, node in self.durable.items()
                                if ntpath.dirname(path) != handle.path or path == handle.path}
                for path, node in self.nodes.items():
                    if ntpath.dirname(path) == handle.path and path != handle.path:
                        stable = copy.deepcopy(node)
                        if not node.directory:
                            stable.payload = node.synced if node.synced is not None else b""
                        self.durable[path] = stable
            else:
                handle.node.synced = handle.node.payload
        return self.boundary("directory_flush" if directory else "file_flush", action)

    def rename(self, handle, directory, name):
        def action():
            self.validate(handle)
            self.validate(directory)
            if not handle.deletable:
                raise PermissionError("rename requires DELETE authority")
            destination = ntpath.join(directory.path, name)
            if destination in self.nodes:
                raise FileExistsError(destination)
            self.nodes[destination] = self.nodes.pop(handle.path)
            handle.path = destination
        return self.boundary("checkpoint_rename" if name.endswith("checkpoint.json") else "rename", action)

    def delete(self, handle):
        def action():
            self.validate(handle)
            if not handle.deletable:
                raise PermissionError("delete requires exact DELETE handle")
            self.delete_calls += 1
            handle.deleted = True
        return self.boundary("delete", action)

    def close(self, handle):
        def action():
            self.validate(handle)
            handle.alive = False
            if handle.deleted:
                if self.nodes.get(handle.path) is not handle.node:
                    raise AuthorityError("delete path no longer identifies retained file")
                del self.nodes[handle.path]
        return self.boundary("close", action)

    def unlink_attempt(self, path):
        node = self.nodes[path]
        if any(handle.alive and handle.node is node for handle in self.handles):
            raise PermissionError("retained handle denies DELETE sharing")
        del self.nodes[path]


def independent_chain(nodes, directory, checkpoint=False):
    """Independent test oracle: no production JSON decoder or state interpreter."""
    suffix = ".checkpoint.json" if checkpoint else ".json"
    entries = sorted((ntpath.basename(path), node.payload) for path, node in nodes.items()
                     if ntpath.dirname(path) == directory and ntpath.basename(path)[:20].isdigit()
                     and path.endswith(suffix))
    records, previous = [], "0" * 64
    for sequence, (name, payload) in enumerate(entries):
        assert name == f"{sequence:020d}" + suffix
        def pairs(items):
            result = {}
            for key, value in items:
                assert key not in result
                result[key] = value
            return result
        record = json.loads(payload.decode("ascii"), object_pairs_hook=pairs)
        encode = lambda data: (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        assert encode(record) == payload
        expected = record.pop("hash")
        assert hashlib.sha256(encode(record)).hexdigest() == expected
        assert type(record["sequence"]) is int and record["sequence"] == sequence
        assert record["previous_checkpoint_sha256" if checkpoint else "previous_hash"] == previous
        record["hash"] = expected
        records.append(record)
        previous = expected
    return records


def new_fake():
    api = FakeWin32()
    store = WindowsCleanupStore.create_new(RUN, EXTERNAL, api=api)
    ledger = CleanupLedger.create(store, lambda: 1, CLOCK, ledger_id="1" * 32)
    return api, store, ledger


class StoreTests(unittest.TestCase):
    def test_fake_directory_flush_enforces_write_access(self):
        api = FakeWin32()
        handle = api.open_directory("C:\\sandbox", attributes_only=True)
        before = copy.deepcopy(api.durable)
        with self.assertRaises(PermissionError):
            api.flush(handle, directory=True)
        self.assertEqual(api.durable, before)
        api.close(handle)

    def test_shared_ancestor_parent_access_is_precomputed_in_both_orders(self):
        for reversed_order in (False, True):
            api = FakeWin32()
            branch = "C:\\sandbox\\branch"
            api.nodes[branch] = api.node(directory=True, private=False)
            api.durable = copy.deepcopy(api.nodes)
            paths = [branch + "\\deep", "C:\\sandbox\\shallow"]
            if reversed_order:
                paths.reverse()
            store = WindowsCleanupStore.create_new(*paths, api=api)
            self.assertEqual({held.path for held in store._parents}, {branch, "C:\\sandbox"})
            for held in store._parents:
                self.assertTrue(held.handle.writable)
            self.assertFalse(next(held for held in store._ancestors if held.path == "C:\\").handle.writable)
            ledger = CleanupLedger.create(store, lambda: 1, CLOCK, ledger_id="1" * 32)
            authority, checkpoint = store.authority, store.load_checkpoint()
            store.close()
            api.crash()
            recovered = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=checkpoint, api=api)
            replay = CleanupLedger.recover(recovered, lambda: 1, CLOCK, checkpoint=recovered.load_checkpoint())
            self.assertEqual(replay.checkpoint, checkpoint)
            recovered.close()

    def test_distinct_paths_aliasing_an_ancestor_are_rejected_before_creation(self):
        api = FakeWin32()
        api.nodes["C:\\authority"] = api.nodes["C:\\sandbox"]
        before = copy.deepcopy(api.nodes)
        with self.assertRaisesRegex(AuthorityError, "alias"):
            WindowsCleanupStore.create_new(RUN, EXTERNAL, api=api)
        self.assertEqual(api.nodes, before)
        self.assertNotIn("mkdir", api.log)
        self.assertFalse(any(handle.alive for handle in api.handles))

    def test_golden_end_to_end_and_external_anchor(self):
        api, store, ledger = new_fake()
        resource = ledger.register(IDENTITY, "coordinator")
        present = [True]
        def mutate(authorization):
            ledger_records = independent_chain(api.durable, RUN)
            anchors = independent_chain(api.durable, EXTERNAL, True)
            self.assertEqual(ledger_records[-1]["event"], "cleanup_intent")
            self.assertEqual(anchors[-1]["record_sha256"], authorization.intent_record_sha256)
            self.assertEqual(anchors[-1]["sequence"], ledger_records[-1]["sequence"])
            present[0] = False
        self.assertTrue(ledger.attempt_cleanup(resource, "coordinator", deadline_ns=100,
            observe=lambda target: Observation(target, target if present[0] else None,
                "present" if present[0] else "absent", True, "a" * 64), mutate=mutate))
        self.assertTrue(ledger.finalize())
        anchor = store.load_checkpoint()
        authority = store.authority
        store.close()
        api.crash()
        recovered = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=anchor, api=api)
        replay = CleanupLedger.recover(recovered, lambda: 1, CLOCK, checkpoint=recovered.load_checkpoint())
        self.assertTrue(replay.successful)
        recovered.close()

    def test_duplicate_writer_and_reentrant_lease(self):
        api, store, ledger = new_fake()
        with self.assertRaises(PermissionError):
            WindowsCleanupStore.open_existing(store.authority, api=api)
        with store.exclusive():
            with self.assertRaises(AuthorityError):
                with store.exclusive():
                    pass
        store.close()

    def test_foreign_thread_cannot_borrow_active_lease_or_close_owner_handles(self):
        api, store, ledger = new_fake()
        barrier = threading.Barrier(2)
        outcomes = []
        with store.exclusive():
            name = ".pending-" + "f" * 32
            handle = store.create(name)
            payload = store.read("00000000000000000000.json")
            offset = 0
            while offset < len(payload):
                offset += store.write(handle, payload[offset:])
            store.fsync_file(handle)
            before_nodes, before_log = copy.deepcopy(api.nodes), list(api.log)
            operations = {
                "create": lambda: store.create(".pending-" + "e" * 32),
                "write": lambda: store.write(handle, b"x"),
                "file_flush": lambda: store.fsync_file(handle),
                "seal": lambda: store.close(handle),
                "rename": lambda: store.rename_no_replace(name, "00000000000000000001.json"),
                "directory_flush": store.fsync_directory,
                "read": lambda: store.read("00000000000000000000.json"),
                "names": store.names,
                "checkpoint": store.load_checkpoint,
                "discard": lambda: store.discard_temporary(name, hashlib.sha256(payload).hexdigest()),
                "dispose": store.close,
            }
            def probe():
                barrier.wait(timeout=5)
                for operation, action in operations.items():
                    try:
                        action()
                    except BaseException as error:
                        outcomes.append((operation, error))
                    else:
                        outcomes.append((operation, None))
            worker = threading.Thread(target=probe)
            worker.start()
            barrier.wait(timeout=5)
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(outcomes), len(operations))
            for operation, error in outcomes:
                self.assertIsInstance(error, AuthorityError, operation)
            self.assertEqual(api.nodes, before_nodes)
            self.assertEqual(api.log, before_log)
            self.assertFalse(handle.sealed)
            self.assertFalse(store._closed)
            store.close(handle)  # the exact owner still has usable authority
        store.close()

    def test_foreign_thread_cannot_exit_owner_lease_and_owner_can_still_exit(self):
        api, store, ledger = new_fake()
        lease = store.exclusive()
        lease.__enter__()
        before = list(api.log)
        failures = []
        def wrong_exit():
            try:
                lease.__exit__(None, None, None)
            except BaseException as error:
                failures.append(error)
        worker = threading.Thread(target=wrong_exit)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], AuthorityError)
        self.assertEqual(api.log, before)
        self.assertEqual(store.read("00000000000000000000.json"), api.nodes[ntpath.join(RUN, "00000000000000000000.json")].payload)
        lease.__exit__(None, None, None)
        store.close()

    def test_stale_context_and_write_handle_cannot_borrow_new_generation(self):
        api, store, ledger = new_fake()
        old_context = store.exclusive()
        with old_context:
            name = ".pending-" + "c" * 32
            handle = store.create(name)
            payload = store.read("00000000000000000000.json")
            offset = 0
            while offset < len(payload):
                offset += store.write(handle, payload[offset:])
            store.fsync_file(handle)
            old_identity = handle.write_lease
        with store.exclusive():
            self.assertIsNot(store._active_lease, old_identity)
            before_nodes, before_log = copy.deepcopy(api.nodes), list(api.log)
            for action in (lambda: store.write(handle, b"x"), lambda: store.fsync_file(handle),
                    lambda: store.close(handle), lambda: old_context.__exit__(None, None, None),
                    lambda: old_context.__enter__(), store.close):
                with self.assertRaises(AuthorityError):
                    action()
            handle.sealed = True  # even a sealed old generation cannot rename
            with self.assertRaises(AuthorityError):
                store.rename_no_replace(name, "00000000000000000001.json")
            self.assertEqual(api.nodes, before_nodes)
            self.assertEqual(api.log, before_log)
            # Reentrant acquisition fails without affecting the current owner.
            with self.assertRaises(AuthorityError):
                with store.exclusive():
                    pass
            store.read("00000000000000000000.json")
        store.close()

    def test_direct_calls_require_lease_and_handle_ownership(self):
        api, store, ledger = new_fake()
        for call in (store.names, lambda: store.read("00000000000000000000.json"),
                     lambda: store.create(".pending-" + "a" * 32), lambda: store.write(object(), b"x")):
            with self.assertRaises(AuthorityError):
                call()
        with store.exclusive():
            for name in ("../bad", ".pending-" + "A" * 32, "00000000000000000001.json", "a:b"):
                with self.assertRaises(AuthorityError):
                    store.create(name)
            with self.assertRaises(AuthorityError):
                store.write(object(), b"x")
        store.close()

    def test_no_replace_and_logical_close_retains_authority(self):
        api, store, ledger = new_fake()
        record_path = ntpath.join(RUN, "00000000000000000000.json")
        with self.assertRaises(PermissionError):
            api.unlink_attempt(record_path)
        with self.assertRaises(PermissionError):
            api.open_file(record_path, writable=True)
        with self.assertRaises(PermissionError):
            api.unlink_attempt(RUN)
        store.close()

    def test_nonempty_new_locations_are_never_reused(self):
        api, store, ledger = new_fake()
        store.close()
        before = copy.deepcopy(api.nodes)
        with self.assertRaises(FileExistsError):
            WindowsCleanupStore.create_new(RUN, EXTERNAL, api=api)
        self.assertEqual(before, api.nodes)

    def test_paths_and_disjoint_authority(self):
        for path in ("relative", "C:relative", r"\\server\share", r"\\?\C:\abc", "C:/a", r"C:\a\..\b",
                     "C:\\a ", "C:\\a.", r"C:\a:b", r"C:\NUL.txt", "C:\\a\\", "C:\\a\\\\b"):
            with self.subTest(path=path), self.assertRaises(AuthorityError):
                local_path(path)
        for external in (RUN, RUN + "\\nested", "C:\\sandbox"):
            with self.assertRaises(AuthorityError):
                WindowsCleanupStore.create_new(RUN, external, api=FakeWin32())

    def test_unsupported_directory_flush_never_reports_commit(self):
        api = FakeWin32()
        api.directory_flush_supported = False
        with self.assertRaises(DurabilityUnavailable):
            WindowsCleanupStore.create_new(RUN, EXTERNAL, api=api)
        self.assertEqual(api.delete_calls, 0)
        self.assertFalse(any(handle.alive for handle in api.handles))

    def test_directory_flush_failure_after_successful_rename_poisoned(self):
        api, store, ledger = new_fake()
        api.directory_flush_supported = False
        with self.assertRaises(PersistenceError):
            ledger.register(IDENTITY, "owner")
        with self.assertRaises(AuthorityError):
            store.load_checkpoint()
        with self.assertRaises(AuthorityError):
            ledger.checkpoint
        store.close()

    def test_missing_checkpoint_and_authority(self):
        for missing in ("00000000000000000000.checkpoint.json", "authority.json"):
            api, store, ledger = new_fake()
            authority = store.authority
            store.close()
            del api.nodes[ntpath.join(EXTERNAL, missing)]
            with self.assertRaises(CorruptLedger):
                WindowsCleanupStore.open_existing(authority, api=api)

    def test_ledger_suffix_rollback_detected_from_separate_checkpoint(self):
        api, store, ledger = new_fake()
        ledger.register(IDENTITY, "owner")
        authority = store.authority
        store.close()
        del api.nodes[ntpath.join(RUN, "00000000000000000001.json")]
        with self.assertRaises(CorruptLedger):
            WindowsCleanupStore.open_existing(authority, api=api)

    def test_checkpoint_suffix_rollback_detected_by_caller_minimum(self):
        api, store, ledger = new_fake()
        ledger.register(IDENTITY, "owner")
        authority, checkpoint = store.authority, store.load_checkpoint()
        store.close()
        del api.nodes[ntpath.join(EXTERNAL, "00000000000000000001.checkpoint.json")]
        with self.assertRaises(CorruptLedger):
            WindowsCleanupStore.open_existing(authority, minimum_checkpoint=checkpoint, api=api)

    def test_valid_extra_suffix_is_replayed_and_anchored(self):
        api, store, ledger = new_fake()
        checkpoint = store.load_checkpoint()
        ledger.register(IDENTITY, "owner")
        authority = store.authority
        store.close()
        del api.nodes[ntpath.join(EXTERNAL, "00000000000000000001.checkpoint.json")]
        recovered = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=checkpoint, api=api)
        self.assertEqual(recovered.load_checkpoint(), checkpoint)
        replay = CleanupLedger.recover(recovered, lambda: 1, CLOCK, checkpoint=checkpoint)
        self.assertEqual(replay.remaining, (IDENTITY.resource_id,))
        self.assertEqual(recovered.load_checkpoint().sequence, 1)
        self.assertEqual(independent_chain(api.durable, EXTERNAL, True)[-1]["record_sha256"], replay.checkpoint.record_sha256)
        recovered.close()

    def test_visible_checkpoint_is_flushed_before_exposure_after_reopen(self):
        api, store, ledger = new_fake()
        ledger.register(IDENTITY, "owner")
        authority = store.authority
        store.close()
        checkpoint_name = ntpath.join(EXTERNAL, "00000000000000000001.checkpoint.json")
        # Model interrupted external rename: visible valid anchor, not durable.
        del api.durable[checkpoint_name]
        self.assertIn(checkpoint_name, api.nodes)
        recovered = WindowsCleanupStore.open_existing(authority, api=api)
        latest = recovered.load_checkpoint()
        self.assertEqual(latest.sequence, 1)
        self.assertIn(checkpoint_name, api.durable)
        recovered.close()
        api.crash()
        reopened = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=latest, api=api)
        self.assertEqual(reopened.load_checkpoint(), latest)
        reopened.close()

    def test_failure_at_each_recovery_boundary_grants_no_ledger(self):
        baseline, store, ledger = new_fake()
        authority = store.authority
        store.close()
        golden = baseline.clone()
        recovered = WindowsCleanupStore.open_existing(authority, api=golden)
        boundaries = list(golden.log)
        recovered.close()
        for position, operation in enumerate(boundaries, 1):
            for side in ("before", "after"):
                api = baseline.clone()
                api.fault = (position, side)
                with self.subTest(position=position, operation=operation, side=side), self.assertRaises(OSError):
                    WindowsCleanupStore.open_existing(authority, api=api)
                self.assertEqual(api.delete_calls, 0)
                self.assertLessEqual(sum(handle.alive for handle in api.handles), int(operation == "open" and side == "after"))

    def test_identity_reparse_links_acl_and_path_drift(self):
        for target, kind in ((RUN, "reparse"), (RUN, "private"), (RUN, "replace"),
                             (EXTERNAL, "replace"), ("C:\\sandbox", "reparse"),
                             (ntpath.join(RUN, "00000000000000000000.json"), "links"),
                             (ntpath.join(RUN, "00000000000000000000.json"), "replace"),
                             (ntpath.join(EXTERNAL, "00000000000000000000.checkpoint.json"), "reparse")):
            with self.subTest(target=target, kind=kind):
                api, store, ledger = new_fake()
                if kind == "replace":
                    api.nodes[target] = api.node(directory=api.nodes[target].directory)
                elif kind == "links":
                    api.nodes[target].links = 2
                elif kind == "private":
                    api.nodes[target].private = False
                else:
                    api.nodes[target].reparse = True
                with self.assertRaises((AuthorityError, CorruptLedger)):
                    ledger.register(IDENTITY, "owner")
                self.assertEqual(api.delete_calls, 0)
                store.close()

    def test_reopen_rejects_directory_replacement_even_identical_bytes(self):
        api, store, ledger = new_fake()
        authority = store.authority
        store.close()
        api.nodes[RUN] = api.node(directory=True)
        with self.assertRaises(AuthorityError):
            WindowsCleanupStore.open_existing(authority, api=api)

    def test_file_symlink_and_directory_junction_are_rejected(self):
        for directory in (False, True):
            api, store, ledger = new_fake()
            authority = store.authority
            store.close()
            if directory:
                api.nodes[RUN].reparse = True
            else:
                api.nodes[ntpath.join(RUN, "00000000000000000000.json")].reparse = True
            with self.subTest(kind="junction" if directory else "symlink"), self.assertRaises(AuthorityError):
                WindowsCleanupStore.open_existing(authority, api=api)

    def test_ambiguous_case_inventory_and_two_conflicting_complete_temps(self):
        api, store, ledger = new_fake()
        authority = store.authority
        store.close()
        original_names = api.names
        api.names = lambda path: original_names(path) + (["AUTHORITY.JSON"] if path == EXTERNAL else [])
        with self.assertRaises(CorruptLedger):
            WindowsCleanupStore.open_existing(authority, api=api)
        api, store, ledger = new_fake()
        authority = store.authority
        ledger.register(IDENTITY, "owner")
        store.close()
        node = api.nodes.pop(ntpath.join(RUN, "00000000000000000001.json"))
        del api.nodes[ntpath.join(EXTERNAL, "00000000000000000001.checkpoint.json")]
        api.nodes[ntpath.join(RUN, ".pending-" + "a" * 32)] = node
        changed = json.loads(node.payload)
        changed["data"]["owner"] = "different-owner"
        del changed["hash"]
        changed["hash"] = hashlib.sha256(canonical_json(changed)).hexdigest()
        payload = canonical_json(changed)
        api.nodes[ntpath.join(RUN, ".pending-" + "b" * 32)] = api.node(payload=payload, synced=payload)
        with self.assertRaises(CorruptLedger):
            WindowsCleanupStore.open_existing(authority, api=api)

    def test_torn_pending_extra_files_and_duplicate_names_block_recovery(self):
        for directory, name, payload in ((RUN, ".pending-" + "a" * 32, b'{"torn":'),
                 (EXTERNAL, ".checkpoint-pending-" + "b" * 32, b'{"torn":'),
                 (RUN, "unexpected.txt", b""), (EXTERNAL, "extra.json", b"")):
            api, store, ledger = new_fake()
            authority = store.authority
            store.close()
            api.nodes[ntpath.join(directory, name)] = api.node(payload=payload)
            with self.assertRaises(CorruptLedger):
                WindowsCleanupStore.open_existing(authority, api=api)
            self.assertEqual(api.delete_calls, 0)

    def test_complete_pending_can_only_be_disposed_with_exact_digest(self):
        api, store, ledger = new_fake()
        authority = store.authority
        store.close()
        payload = api.nodes[ntpath.join(RUN, "00000000000000000000.json")].payload
        name = ".pending-" + "c" * 32
        api.nodes[ntpath.join(RUN, name)] = api.node(payload=payload, synced=payload)
        recovered = WindowsCleanupStore.open_existing(authority, api=api)
        with self.assertRaises(AuthorityError):
            recovered.discard_temporary(name, "0" * 64)
        with self.assertRaises(AuthorityError):
            recovered.discard_temporary("00000000000000000000.json", hashlib.sha256(payload).hexdigest())
        self.assertEqual(api.delete_calls, 0)
        recovered.discard_temporary(name, hashlib.sha256(payload).hexdigest())
        self.assertEqual(api.delete_calls, 1)
        self.assertNotIn(ntpath.join(RUN, name), api.nodes)
        recovered.close()

    def test_temporary_disposal_failure_and_replacement_never_deletes_uncertain_path(self):
        for kind in ("replacement", "hardlink", "torn"):
            api, store, ledger = new_fake()
            authority = store.authority
            store.close()
            payload = api.nodes[ntpath.join(RUN, "00000000000000000000.json")].payload
            name = ".pending-" + "c" * 32
            path = ntpath.join(RUN, name)
            api.nodes[path] = api.node(payload=payload, synced=payload)
            recovered = WindowsCleanupStore.open_existing(authority, api=api)
            if kind == "replacement":
                api.nodes[path] = api.node(payload=payload, synced=payload)
            elif kind == "hardlink":
                api.nodes[path].links = 2
            else:
                api.nodes[path].payload = b"torn"
            with self.assertRaises((AuthorityError, CorruptLedger)):
                recovered.discard_temporary(name, hashlib.sha256(payload).hexdigest())
            self.assertEqual(api.delete_calls, 0)
            recovered.close()
        # Every disposal mutation boundary poisons the instance when uncertain.
        for boundary in ("delete", "close", "directory_flush"):
            for side in ("before", "after"):
                api, store, ledger = new_fake()
                authority = store.authority
                store.close()
                payload = api.nodes[ntpath.join(RUN, "00000000000000000000.json")].payload
                name = ".pending-" + "d" * 32
                api.nodes[ntpath.join(RUN, name)] = api.node(payload=payload, synced=payload)
                recovered = WindowsCleanupStore.open_existing(authority, api=api)
                api.log = []
                api.fault = (("delete", "close", "directory_flush").index(boundary) + 1, side)
                with self.assertRaises(OSError):
                    recovered.discard_temporary(name, hashlib.sha256(payload).hexdigest())
                with self.assertRaises(AuthorityError):
                    recovered.load_checkpoint()
                api.fault = None
                try:
                    recovered.close()
                except StorageError:
                    pass  # after-close crash can leave a known stale retained token

    def test_stale_handle_and_bad_readback_fail_closed(self):
        api, store, ledger = new_fake()
        store._run_files["00000000000000000000.json"].handle.alive = False
        with self.assertRaises(OSError):
            ledger.register(IDENTITY, "owner")
        with self.assertRaises(StorageError):
            store.close()
        api, store, ledger = new_fake()
        original_flush = api.flush
        def damage(handle, *, directory=False):
            original_flush(handle, directory=directory)
            if not directory and ntpath.basename(handle.path).startswith(".pending-"):
                handle.node.payload += b"X"
        api.flush = damage
        with self.assertRaises(PersistenceError):
            ledger.register(IDENTITY, "owner")
        self.assertEqual(store._checkpoint_count, 1)
        store.close()

    def test_no_progress_and_write_type_are_not_success(self):
        for value in (0, True, -1, 999999):
            api, store, ledger = new_fake()
            api.write = lambda handle, payload: value
            with self.assertRaises(PersistenceError):
                ledger.register(IDENTITY, "owner")
            self.assertEqual(store._checkpoint_count, 1)
            store.close()

    def test_checkpoint_readback_corruption_cannot_acknowledge_ledger_commit(self):
        for boundary in ("file_flush", "checkpoint_rename"):
            api, store, ledger = new_fake()
            original = api.flush if boundary == "file_flush" else api.rename
            if boundary == "file_flush":
                def damage(handle, *, directory=False):
                    original(handle, directory=directory)
                    if not directory and ntpath.basename(handle.path).startswith(".checkpoint-pending-"):
                        handle.node.payload += b"X"
                api.flush = damage
            else:
                def damage(handle, directory, name):
                    original(handle, directory, name)
                    if name.endswith("checkpoint.json"):
                        handle.node.payload += b"X"
                api.rename = damage
            with self.assertRaises(PersistenceError):
                ledger.register(IDENTITY, "owner")
            with self.assertRaises(AuthorityError):
                store.load_checkpoint()
            self.assertEqual(len(independent_chain(api.durable, EXTERNAL, True)), 1)
            self.assertEqual(api.delete_calls, 0)
            store.close()

    def test_unflushed_unsealed_and_non_next_records_cannot_rename(self):
        api, store, ledger = new_fake()
        with store.exclusive():
            name = ".pending-" + "a" * 32
            held = store.create(name)
            with self.assertRaises(AuthorityError):
                store.close(held)
            with self.assertRaises(AuthorityError):
                store.rename_no_replace(name, "00000000000000000001.json")
            # A valid old record is still not the next append authority.
            payload = store.read("00000000000000000000.json")
            offset = 0
            while offset < len(payload):
                offset += store.write(held, payload[offset:])
            store.fsync_file(held)
            store.close(held)
            with self.assertRaises(AuthorityError):
                store.write(held, b"x")
            with self.assertRaises(CorruptLedger):
                store.rename_no_replace(name, "00000000000000000001.json")
            with self.assertRaises(AuthorityError):
                store.rename_no_replace(name, "00000000000000000000.json")
        store.close()

    def test_crash_faults_at_every_publication_and_checkpoint_boundary(self):
        baseline, store, ledger = new_fake()
        authority, minimum = store.authority, store.load_checkpoint()
        store.close()
        golden = baseline.clone()
        candidate = WindowsCleanupStore.open_existing(authority, api=golden)
        live = CleanupLedger.recover(candidate, lambda: 1, CLOCK, checkpoint=minimum)
        golden.log = []
        live.register(IDENTITY, "owner")
        boundaries = list(golden.log)
        self.assertTrue({"open", "write", "file_flush", "rename", "directory_flush", "checkpoint_rename"} <= set(boundaries))
        for position, operation in enumerate(boundaries, 1):
            for side in ("before", "after"):
                with self.subTest(position=position, operation=operation, side=side):
                    api = baseline.clone()
                    store = WindowsCleanupStore.open_existing(authority, api=api)
                    replay = CleanupLedger.recover(store, lambda: 1, CLOCK, checkpoint=minimum)
                    api.log = []
                    api.fault = (position, side)
                    with self.assertRaises((PersistenceError, OSError, AuthorityError)):
                        replay.register(IDENTITY, "owner")
                    api.crash()
                    records = independent_chain(api.durable, RUN)
                    checkpoints = independent_chain(api.durable, EXTERNAL, True)
                    self.assertLessEqual(len(checkpoints), len(records))
                    for anchor in checkpoints:
                        self.assertEqual(anchor["record_sha256"], records[anchor["sequence"]]["hash"])
                    try:
                        recovered = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=minimum, api=api)
                        latest = recovered.load_checkpoint()
                        resumed = CleanupLedger.recover(recovered, lambda: 1, CLOCK, checkpoint=latest)
                        self.assertEqual(resumed.remaining, (IDENTITY.resource_id,) if len(records) == 2 else ())
                        recovered.close()
                    except (CorruptLedger, AuthorityError):
                        # Torn/ambiguous pending files are deliberately retained and block recovery.
                        self.assertTrue(any("pending-" in name for name in api.nodes))
                    self.assertEqual(api.delete_calls, 0)
        print(f"S5b publication/checkpoint fault edges: {len(boundaries) * 2}")
        candidate.close()

    def test_whole_cleanup_crash_faults_never_mutate_without_external_intent(self):
        baseline, store, ledger = new_fake()
        resource = ledger.register(IDENTITY, "owner")
        authority, minimum = store.authority, store.load_checkpoint()
        store.close()
        def attempt(api, live, present, calls):
            def mutate(authorization):
                records = independent_chain(api.durable, RUN)
                anchors = independent_chain(api.durable, EXTERNAL, True)
                self.assertEqual(records[-1]["event"], "cleanup_intent")
                self.assertEqual(anchors[-1]["record_sha256"], authorization.intent_record_sha256)
                calls[0] += 1
                present[0] = False
            return live.attempt_cleanup(resource, "owner", deadline_ns=100,
                observe=lambda target: Observation(target, target if present[0] else None,
                    "present" if present[0] else "absent", True, "a" * 64), mutate=mutate)
        golden = baseline.clone()
        candidate = WindowsCleanupStore.open_existing(authority, api=golden)
        live = CleanupLedger.recover(candidate, lambda: 1, CLOCK, checkpoint=minimum)
        golden.log = []
        self.assertTrue(attempt(golden, live, [True], [0]))
        boundaries = list(golden.log)
        for position, operation in enumerate(boundaries, 1):
            for side in ("before", "after"):
                with self.subTest(position=position, operation=operation, side=side):
                    api = baseline.clone()
                    candidate = WindowsCleanupStore.open_existing(authority, api=api)
                    live = CleanupLedger.recover(candidate, lambda: 1, CLOCK, checkpoint=minimum)
                    present, calls = [True], [0]
                    api.log = []
                    api.fault = (position, side)
                    with self.assertRaises((PersistenceError, OSError, AuthorityError)):
                        attempt(api, live, present, calls)
                    api.crash()
                    records = independent_chain(api.durable, RUN)
                    anchors = independent_chain(api.durable, EXTERNAL, True)
                    self.assertLessEqual(len(anchors), len(records))
                    if calls[0]:
                        self.assertIn("cleanup_intent", [record["event"] for record in records])
                    try:
                        recovered = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=minimum, api=api)
                        resumed = CleanupLedger.recover(recovered, lambda: 1, CLOCK, checkpoint=recovered.load_checkpoint())
                    except (CorruptLedger, AuthorityError):
                        self.assertTrue(any("pending-" in name for name in api.nodes))
                    else:
                        terminal = bool(records[-1]["event"] == "cleanup_decision" and records[-1]["data"]["success"])
                        self.assertEqual(resumed.remaining == (), terminal)
                        # Only retry when no complete next-record temporary needs
                        # explicit disposal first; ambiguous paths stay untouched.
                        if not terminal and not any("pending-" in name for name in api.nodes):
                            self.assertTrue(attempt(api, resumed, present, calls))
                        self.assertLessEqual(calls[0], 1)
                        recovered.close()
                    self.assertEqual(api.delete_calls, 0)
        print(f"S5b whole-cleanup fault edges: {len(boundaries) * 2}")

    def test_failure_at_every_initialization_boundary_closes_known_handles(self):
        golden = FakeWin32()
        store = WindowsCleanupStore.create_new(RUN, EXTERNAL, api=golden)
        boundaries = list(golden.log)
        store.close()
        for position, operation in enumerate(boundaries, 1):
            for side in ("before", "after"):
                api = FakeWin32()
                api.fault = (position, side)
                with self.subTest(position=position, operation=operation, side=side), self.assertRaises(OSError):
                    WindowsCleanupStore.create_new(RUN, EXTERNAL, api=api)
                # An after-open shim exception models loss of delivery/crash: the
                # API-created but unreturned handle cannot be known to its caller.
                leaked = [handle for handle in api.handles if handle.alive]
                self.assertLessEqual(len(leaked), int(operation == "open" and side == "after"))
                self.assertEqual(api.delete_calls, 0)

    def test_checkpoint_canonical_types_duplicate_keys_and_hashes(self):
        for transform in (lambda value: value + b" ", lambda value: value.replace(b'"version":1', b'"version":true'),
                          lambda value: value.replace(b'"version":1', b'"version":1,"version":1'),
                          lambda value: value[:-1]):
            api, store, ledger = new_fake()
            authority = store.authority
            store.close()
            node = api.nodes[ntpath.join(EXTERNAL, "00000000000000000000.checkpoint.json")]
            node.payload = transform(node.payload)
            with self.assertRaises(CorruptLedger):
                WindowsCleanupStore.open_existing(authority, api=api)

    def test_primary_exception_preserved_when_disposal_also_fails(self):
        api, store, ledger = new_fake()
        original_close = api.close
        called = [False]
        def fail_once(handle):
            original_close(handle)
            if not called[0]:
                called[0] = True
                raise OSError("dispose failure")
        api.close = fail_once
        with self.assertRaisesRegex(RuntimeError, "primary") as failure:
            with store:
                raise RuntimeError("primary")
        self.assertTrue(failure.exception.__notes__)
        self.assertFalse(any(handle.alive for handle in api.handles))


@unittest.skipUnless(os.name == "nt", "concrete Win32 boundary requires Windows")
class NativeWindowsTests(unittest.TestCase):
    def test_real_shared_ancestor_parent_flush_in_both_argument_orders(self):
        api = Win32()
        for reverse in (False, True):
            with tempfile.TemporaryDirectory(prefix="s5b-parent-roles-") as temporary:
                root = local_path(str(Path(temporary).resolve()))
                branch = ntpath.join(root, "branch")
                api.mkdir(branch)
                paths = [ntpath.join(branch, "deep"), ntpath.join(root, "shallow")]
                if reverse:
                    paths.reverse()
                store = None
                try:
                    store = WindowsCleanupStore.create_new(*paths, api=api)
                    ledger = CleanupLedger.create(store, lambda: 1, CLOCK, ledger_id="3" * 32)
                    self.assertEqual(store.load_checkpoint(), ledger.checkpoint)
                    barrier, blocked = threading.Barrier(2), []
                    def foreign_create():
                        barrier.wait(timeout=5)
                        try:
                            store.create(".pending-" + "e" * 32)
                        except BaseException as error:
                            blocked.append(error)
                    with store.exclusive():
                        worker = threading.Thread(target=foreign_create)
                        worker.start()
                        barrier.wait(timeout=5)
                        worker.join(timeout=5)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(len(blocked), 1)
                        self.assertIsInstance(blocked[0], AuthorityError)
                        self.assertNotIn(".pending-" + "e" * 32, store.names())
                    self.assertTrue(ledger.finalize())
                    print(f"S5b shared-ancestor parent directory flush acknowledged, reversed={reverse}")
                except (OSError, AuthorityError) as error:
                    if os.environ.get("S5B_REQUIRE_NATIVE_SMOKE") == "1":
                        raise
                    print(f"S5b shared-ancestor native smoke unavailable (fail closed): {error}")
                finally:
                    if store is not None:
                        store.close()

    def test_real_private_create_file_flush_readback_and_no_replace(self):
        api = Win32()
        with tempfile.TemporaryDirectory(prefix="s5b-win32-") as temporary:
            root = local_path(str(Path(temporary).resolve()))
            directory = ntpath.join(root, "private")
            api.mkdir(directory)
            held_directory = api.open_directory(directory)
            source, destination = None, None
            try:
                self.assertTrue(api.private(held_directory))
                source = api.open_file(ntpath.join(directory, "source"), create=True, writable=True, deletable=True)
                self.assertTrue(api.private(source))
                self.assertEqual(api.write(source, b"exact bytes"), 11)
                api.flush(source)
                self.assertEqual(api.read(source), b"exact bytes")
                with self.assertRaises(OSError):
                    api.open_file(ntpath.join(directory, "source"), writable=True)
                with self.assertRaises(OSError):
                    os.unlink(ntpath.join(directory, "source"))
                with self.assertRaises(OSError):
                    os.rename(directory, directory + "-replaced")
                destination = api.open_file(ntpath.join(directory, "destination"), create=True, writable=True)
                api.close(destination)
                destination = None
                with self.assertRaises(OSError):
                    api.rename(source, held_directory, "destination")
                self.assertEqual(api.read(source), b"exact bytes")
                api.rename(source, held_directory, "published")
                self.assertTrue(api.info(source).path.endswith("\\published"))
            finally:
                if destination is not None:
                    api.close(destination)
                if source is not None:
                    api.close(source)
                api.close(held_directory)

    def test_real_directory_flush_reports_support_or_fails_closed(self):
        api = Win32()
        with tempfile.TemporaryDirectory(prefix="s5b-durability-") as temporary:
            root = local_path(str(Path(temporary).resolve()))
            store = None
            try:
                store = WindowsCleanupStore.create_new(ntpath.join(root, "run"), ntpath.join(root, "anchors"), api=api)
            except (OSError, AuthorityError) as error:
                if os.environ.get("S5B_REQUIRE_NATIVE_SMOKE") == "1":
                    raise
                # No fallback is acceptable when the concrete volume/API cannot
                # satisfy access, private ACL, or directory durability semantics.
                print(f"S5b concrete Windows store unavailable (fail closed): {type(error).__name__}: {error}")
                for note in getattr(error, "__notes__", []):
                    print(note)
            else:
                ledger = CleanupLedger.create(store, lambda: 1, CLOCK, ledger_id="2" * 32)
                self.assertEqual(store.load_checkpoint(), ledger.checkpoint)
                resource = ledger.register(IDENTITY, "owner")
                self.assertTrue(ledger.attempt_cleanup(resource, "owner", deadline_ns=100,
                    observe=lambda target: Observation(target, None, "absent", True, "a" * 64),
                    mutate=lambda authorization: self.fail("already-absent fake resource must not mutate")))
                self.assertTrue(ledger.finalize())
                authority, checkpoint = store.authority, store.load_checkpoint()
                with self.assertRaises(OSError):
                    WindowsCleanupStore.open_existing(authority, api=api)
                store.close()
                store = WindowsCleanupStore.open_existing(authority, minimum_checkpoint=checkpoint, api=api)
                recovered = CleanupLedger.recover(store, lambda: 1, CLOCK, checkpoint=store.load_checkpoint())
                self.assertTrue(recovered.successful)
                print("S5b concrete Windows directory FlushFileBuffers acknowledged; power-loss behavior not certified")
            finally:
                if store is not None:
                    store.close()

    def test_real_hardlink_information_and_reparse_rejection(self):
        api = Win32()
        with tempfile.TemporaryDirectory(prefix="s5b-topology-") as temporary:
            root = local_path(str(Path(temporary).resolve()))
            directory = ntpath.join(root, "private")
            api.mkdir(directory)
            path = ntpath.join(directory, "original")
            handle = api.open_file(path, create=True, writable=True)
            api.close(handle)
            os.link(path, ntpath.join(directory, "alias"))
            handle = api.open_file(path)
            try:
                self.assertEqual(api.info(handle).links, 2)
                store = WindowsCleanupStore(api)
                with self.assertRaises(AuthorityError):
                    store._retain(handle, path, False)
                handle = None
            finally:
                if handle is not None:
                    api.close(handle)


if __name__ == "__main__":
    unittest.main(verbosity=2)
