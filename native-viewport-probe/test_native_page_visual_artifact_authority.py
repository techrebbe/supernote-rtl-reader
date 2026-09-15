"""Deterministic crash, mutation, and Win32-boundary tests for artifacts."""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import ntpath
import os
from pathlib import Path
import threading
import unittest
from unittest import mock

import native_page_visual_artifact_authority as artifact
import native_page_visual_session_harness as harness


STORE = r"C:\evidence\visual-artifacts"
OTHER_STORE = r"C:\evidence\other-artifacts"
SOURCE = r"C:\reviewed\native_page_visual_artifact_authority.py"
SOURCE_RAW = b"reviewed immutable artifact adapter source\n"
PRODUCER = "a" * 64
REVIEWED_SOURCE_SHA256 = (
    "f3c2d51880ddc24ff1f058180088e3182683504b8ee69bd8926440096336f5d4")
REVIEWED_CANONICAL_PIN_SHA256 = (
    "2129b49ca6e4c13141600b63d58e1d67378c0954e2fb9a77d647b34b5d82cc91")


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


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


class FakeWin32:
    """Separates visibility, flushed bytes, durable names, and handles."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.durable: dict[str, Node] = {}
        self.handles: list[Handle] = []
        self.counter = 0
        self.log: list[str] = []
        self.fault: tuple[int, str] | None = None
        self.mutation: tuple[int, object] | None = None
        self.chunk = 73
        self.directory_flush_supported = True
        self.rename_calls = 0
        self.delete_calls = 0
        for path in ("C:\\", r"C:\evidence", r"C:\reviewed"):
            self.nodes[path] = self.node(directory=True, private=False)
        self.nodes[SOURCE] = self.node(
            payload=SOURCE_RAW, synced=SOURCE_RAW, private=False)
        self.durable = copy.deepcopy(self.nodes)

    def node(self, **values) -> Node:
        self.counter += 1
        return Node(self.counter, **values)

    def boundary(self, operation: str, action):
        self.log.append(operation)
        edge = len(self.log)
        if self.fault == (edge, "before"):
            raise OSError(f"injected before {operation} at {edge}")
        value = action()
        if self.mutation is not None and self.mutation[0] == edge:
            self.mutation[1](self, operation)
        if self.fault == (edge, "after"):
            raise OSError(f"injected after {operation} at {edge}")
        return value

    def clone(self):
        result = copy.deepcopy(self)
        result.handles, result.log = [], []
        result.fault, result.mutation = None, None
        return result

    def crash(self) -> None:
        self.nodes = copy.deepcopy(self.durable)
        self.handles = []
        self.log = []
        self.fault = None
        self.mutation = None

    def local_volume(self, path: str) -> bool:
        return path.startswith("C:\\")

    def private(self, handle: Handle) -> bool:
        self.validate(handle)
        return handle.node.private

    def mkdir(self, path: str) -> None:
        def action():
            if path in self.nodes or ntpath.dirname(path) not in self.nodes:
                raise FileExistsError(path)
            self.nodes[path] = self.node(directory=True)
        self.boundary("mkdir", action)

    def open_directory(self, path: str, *, writable: bool = False,
                       attributes_only: bool = False) -> Handle:
        del attributes_only
        return self._open(path, directory=True, writable=writable)

    def open_file(self, path: str, *, create: bool = False,
                  writable: bool = False, exclusive: bool = False,
                  deletable: bool = False) -> Handle:
        return self._open(path, create=create, writable=writable,
                          exclusive=exclusive, deletable=deletable)

    def _open(self, path: str, *, directory: bool = False,
              create: bool = False, writable: bool = False,
              exclusive: bool = False, deletable: bool = False) -> Handle:
        def action():
            if create:
                if path in self.nodes:
                    raise FileExistsError(path)
                if ntpath.dirname(path) not in self.nodes:
                    raise FileNotFoundError(path)
                self.nodes[path] = self.node()
            if path not in self.nodes:
                raise FileNotFoundError(path)
            node = self.nodes[path]
            if node.directory is not directory:
                raise OSError("file/directory role differs")
            for other in self.handles:
                if other.alive and other.node is node and not directory:
                    if (exclusive or other.exclusive or writable or deletable
                            or other.writable or other.deletable):
                        raise PermissionError("Windows sharing violation")
            handle = Handle(node, path, writable, deletable, exclusive)
            self.handles.append(handle)
            return handle
        return self.boundary("open", action)

    @staticmethod
    def validate(handle: Handle) -> None:
        if type(handle) is not Handle or not handle.alive:
            raise OSError("stale native handle")

    def info(self, handle: Handle) -> artifact.FileInfo:
        self.validate(handle)
        node = handle.node
        if self.nodes.get(handle.path) is node:
            actual = handle.path
        else:
            actual = next((path for path, item in self.nodes.items()
                           if item is node), r"C:\lost")
        return artifact.FileInfo(
            artifact.FileIdentity(29, node.index), actual, node.directory,
            node.reparse, node.links, len(node.payload))

    def names(self, path: str) -> list[str]:
        return [ntpath.basename(item) for item in self.nodes
                if item != path and ntpath.dirname(item) == path]

    def read(self, handle: Handle, maximum: int) -> bytes:
        self.validate(handle)
        if len(handle.node.payload) > maximum:
            raise artifact.ArtifactCorrupt("fake read exceeds bound")
        return handle.node.payload

    def write(self, handle: Handle, payload: bytes) -> int:
        def action():
            self.validate(handle)
            if not handle.writable:
                raise PermissionError("read-only handle")
            piece = payload[:self.chunk]
            handle.node.payload += piece
            return len(piece)
        return self.boundary("write", action)

    def flush(self, handle: Handle, *, directory: bool = False) -> None:
        def action():
            self.validate(handle)
            if not handle.writable:
                raise PermissionError("flush requires retained write access")
            if handle.node.directory is not directory:
                raise OSError("flush role differs")
            if not directory:
                handle.node.synced = handle.node.payload
                return
            if not self.directory_flush_supported:
                raise artifact.DurabilityUnavailable(
                    "fake directory flush unsupported")
            # Replace this directory's durable immediate-child namespace.  Only
            # bytes already acknowledged by a file flush become durable.
            for path in list(self.durable):
                if path != handle.path and ntpath.dirname(path) == handle.path:
                    del self.durable[path]
            for path, node in self.nodes.items():
                if path != handle.path and ntpath.dirname(path) == handle.path:
                    stable = copy.deepcopy(node)
                    if not node.directory:
                        stable.payload = (node.synced if node.synced is not None
                                          else b"")
                    self.durable[path] = stable
        self.boundary("directory_flush" if directory else "file_flush", action)

    def rename(self, handle: Handle, directory: Handle, name: str) -> None:
        def action():
            self.validate(handle)
            self.validate(directory)
            if not handle.deletable:
                raise PermissionError("rename requires DELETE authority")
            destination = ntpath.join(directory.path, name)
            if destination in self.nodes:
                raise FileExistsError(destination)
            if self.nodes.get(handle.path) is not handle.node:
                raise artifact.ArtifactAuthorityError(
                    "rename source path was replaced")
            self.nodes[destination] = self.nodes.pop(handle.path)
            handle.path = destination
            self.rename_calls += 1
        self.boundary("rename", action)

    def close(self, handle: Handle) -> None:
        def action():
            self.validate(handle)
            handle.alive = False
        self.boundary("close", action)


def new_store(path: str = STORE, *, api: FakeWin32 | None = None):
    api = FakeWin32() if api is None else api
    store = artifact.WindowsVisualArtifactAuthority.create_new(
        path, source_path=SOURCE, api=api)
    return api, store


def artifact_path(sequence: int = 0, path: str = STORE) -> str:
    return ntpath.join(path, f"{sequence:020d}.artifact")


def pending_path(token: str = "d" * 32, path: str = STORE) -> str:
    return ntpath.join(path, ".pending-" + token)


def rewrite_header(node: Node, **changes) -> None:
    payload = node.payload
    prefix = len(artifact.MAGIC) + 4
    size = int.from_bytes(payload[len(artifact.MAGIC):prefix], "big")
    header = json.loads(payload[prefix:prefix + size].decode("ascii"))
    header.update(changes)
    encoded = canonical(header)
    node.payload = (artifact.MAGIC + len(encoded).to_bytes(4, "big")
                    + encoded + payload[prefix + size:])
    node.synced = node.payload


class ContractAndGoldenTests(unittest.TestCase):
    def test_reviewed_production_source_and_canonical_pin_hashes_are_exact(self):
        source = Path(artifact.__file__).read_bytes()
        source_sha = hashlib.sha256(source).hexdigest()
        self.assertEqual(source_sha, REVIEWED_SOURCE_SHA256)
        pin = artifact.canonical_adapter_bytes(source_sha)
        self.assertEqual(hashlib.sha256(pin).hexdigest(),
                         REVIEWED_CANONICAL_PIN_SHA256)
        self.assertTrue(pin.endswith(b"\n"))

    def test_exact_harness_protocol_canonical_pin_and_golden_reopen(self):
        api, store = new_store()
        authority = store.authority
        expected_canonical = canonical({
            "artifactRefAuthority": harness.ARTIFACT_AUTHORITY,
            "authority": artifact.ADAPTER_AUTHORITY,
            "capabilities": [
                "private-single-store-identity",
                "retained-source-and-object-handles",
                "create-new-and-native-no-replace",
                "file-readback-and-directory-flush",
                "fail-closed-additive-recovery",
                "two-pass-quiescence",
            ],
            "maxArtifactBytes": 64 * 1024 * 1024,
            "maxArtifacts": 1024,
            "schemaVersion": 1,
            "sourceSha256": hashlib.sha256(SOURCE_RAW).hexdigest(),
            "supportedMediaTypes": [
                "application/json", "application/octet-stream", "image/png",
                "text/plain",
            ],
            "windowsNativeOnly": True,
        })
        self.assertEqual(store.canonical_bytes(), expected_canonical)
        self.assertEqual(store.adapter_pin_sha256,
                         hashlib.sha256(expected_canonical).hexdigest())

        raw = b"ActivityRecord taskId=17 displayId=3\n"
        reference = store.retain(
            "platform/prelaunch-activity.txt", raw, "text/plain", PRODUCER, 9)
        self.assertIs(type(reference), harness.ArtifactRef)
        self.assertEqual(reference, harness.ArtifactRef(
            "platform/prelaunch-activity.txt", "text/plain", len(raw),
            hashlib.sha256(raw).hexdigest(), PRODUCER,
            authority.store_identity_sha256, True))
        harness._validate_artifact_ref(
            reference, logical_name=reference.logical_name, raw=raw,
            producer_sha256=PRODUCER)
        store.verify_ref(reference)
        store.assert_quiescent()
        self.assertEqual(store.retained_refs(), (reference,))
        self.assertEqual(api.delete_calls, 0)
        self.assertEqual(api.nodes[artifact_path()].payload,
                         api.nodes[artifact_path()].synced)
        self.assertIn(artifact_path(), api.durable)
        store.close()

        reopened = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=api)
        self.assertEqual(reopened.authority, authority)
        self.assertEqual(reopened.store_identity_sha256,
                         reference.store_identity_sha256)
        self.assertEqual(reopened.canonical_bytes(), expected_canonical)
        self.assertEqual(reopened.retained_refs(), (reference,))
        reopened.verify_ref(reference)
        reopened.assert_quiescent()
        reopened.close()

    def test_publication_order_has_no_close_and_exposes_only_after_directory_flush(self):
        api, store = new_store()
        api.log = []
        reference = store.retain(
            "visual/00-LANDSCAPE_FULL_INITIAL.png", b"png-wire",
            "image/png", PRODUCER, 4)
        operations = api.log
        self.assertEqual(operations[0], "open")
        self.assertGreater(operations.count("write"), 1)
        self.assertLess(max(i for i, item in enumerate(operations)
                            if item == "write"),
                        operations.index("file_flush"))
        self.assertLess(operations.index("file_flush"),
                        operations.index("rename"))
        self.assertLess(operations.index("rename"),
                        operations.index("directory_flush"))
        self.assertEqual(operations[-1], "directory_flush")
        self.assertNotIn("close", operations)
        store.verify_ref(reference)
        store.close()

    def test_bound_accepts_full_frame_png_budget_and_raw_manager_wires(self):
        api, store = new_store()
        api.chunk = artifact.WRITE_CHUNK_BYTES
        # 1404x1872x4 plus modest PNG framing is far below the harness's 64 MiB
        # retained-wire cap; PNG structural validation remains in the harness.
        frame_sized = b"P" * (1404 * 1872 * 4 + 4096)
        png = store.retain(
            "visual/04-PORTRAIT_FULL.png", frame_sized, "image/png",
            PRODUCER, 10)
        am = store.retain(
            "platform/final-activity.txt", b"AM" * 4096, "text/plain",
            PRODUCER, 11)
        wm = store.retain(
            "platform/final-window.txt", b"WM" * 8192, "text/plain",
            PRODUCER, 12)
        self.assertLess(png.size, artifact.MAX_ARTIFACT_BYTES)
        self.assertEqual((am.size, wm.size), (8192, 16384))
        store.assert_quiescent()
        store.close()

    def test_argument_domains_and_logical_case_reuse_fail_before_mutation(self):
        api, store = new_store()
        bad_names = (
            "", "/visual/a.png", "visual/a.png/", "visual//a.png",
            ".", "..", "visual/../a.png", r"visual\a.png",
            "visual/a:stream", "visual/con", "visual/trailing.",
            "visual/\N{SNOWMAN}.png", "a" * 97 + "/x",
        )
        for name in bad_names:
            api.log = []
            with self.subTest(name=name), self.assertRaises(
                    artifact.ArtifactAuthorityError):
                store.retain(name, b"x", "text/plain", PRODUCER, 0)
            self.assertEqual(api.log, [])
        invalid_calls = (
            ("ok/a", b"", "text/plain", PRODUCER, 0),
            ("ok/b", bytearray(b"x"), "text/plain", PRODUCER, 0),
            ("ok/c", b"x", "text/html", PRODUCER, 0),
            ("ok/d", b"x", "text/plain", "A" * 64, 0),
            ("ok/e", b"x", "text/plain", PRODUCER, True),
            ("ok/f", b"x", "text/plain", PRODUCER, -1),
        )
        for values in invalid_calls:
            api.log = []
            with self.subTest(values=values), self.assertRaises(
                    artifact.ArtifactAuthorityError):
                store.retain(*values)
            self.assertEqual(api.log, [])
        oversized = b"x" * (artifact.MAX_ARTIFACT_BYTES + 1)
        with self.assertRaises(artifact.ArtifactAuthorityError):
            store.retain("ok/oversized", oversized, "text/plain", PRODUCER, 0)

        store.retain("Visual/Frame.PNG", b"one", "image/png", PRODUCER, 0)
        for replay in ("Visual/Frame.PNG", "visual/frame.png"):
            api.log = []
            with self.subTest(replay=replay), self.assertRaises(
                    artifact.ArtifactAuthorityError):
                store.retain(replay, b"two", "image/png", PRODUCER, 1)
            self.assertEqual(api.log, [])
        store.close()

    def test_store_authority_is_strict_and_store_creation_is_no_replace(self):
        api, store = new_store()
        authority = store.authority
        with self.assertRaises(artifact.ArtifactAuthorityError):
            artifact.ArtifactStoreAuthority(
                authority.path.lower(), authority.directory_identity,
                authority.store_nonce, authority.adapter_source_sha256)
        with self.assertRaises(artifact.ArtifactAuthorityError):
            artifact.ArtifactStoreAuthority(
                authority.path, authority.directory_identity, "g" * 32,
                authority.adapter_source_sha256)
        store.close()
        with self.assertRaises(FileExistsError):
            artifact.WindowsVisualArtifactAuthority.create_new(
                STORE, source_path=SOURCE, api=api)
        self.assertEqual(api.delete_calls, 0)


class CrashAndRecoveryTests(unittest.TestCase):
    def test_failure_before_and_after_every_store_initialization_boundary_exposes_nothing(self):
        golden_api = FakeWin32()
        golden = artifact.WindowsVisualArtifactAuthority.create_new(
            STORE, source_path=SOURCE, api=golden_api)
        boundaries = list(golden_api.log)
        golden.close()
        self.assertTrue({"mkdir", "open", "write", "file_flush", "rename",
                         "directory_flush"} <= set(boundaries))
        for position, operation in enumerate(boundaries, 1):
            for side in ("before", "after"):
                api = FakeWin32()
                api.fault = (position, side)
                with self.subTest(position=position, operation=operation,
                                  side=side), self.assertRaises(
                                      (OSError, artifact.ArtifactError)):
                    artifact.WindowsVisualArtifactAuthority.create_new(
                        STORE, source_path=SOURCE, api=api)
                # An exception injected after native open can withhold the new
                # handle from its caller.  Every handle actually delivered to
                # the authority is closed on initialization failure.
                leaked = [handle for handle in api.handles if handle.alive]
                self.assertLessEqual(
                    len(leaked), int(operation == "open" and side == "after"))
                self.assertEqual(api.delete_calls, 0)
        print(f"visual artifact initialization fault edges: {len(boundaries) * 2}")

    def test_mutation_after_every_store_control_publication_boundary_exposes_nothing(self):
        golden_api = FakeWin32()
        golden = artifact.WindowsVisualArtifactAuthority.create_new(
            STORE, source_path=SOURCE, api=golden_api)
        operations = list(golden_api.log)
        golden.close()
        first_file_flush = operations.index("file_flush")
        writer_open = max(index for index in range(first_file_flush)
                          if operations[index] == "open")
        rename = operations.index("rename")
        publication_directory_flush = operations.index(
            "directory_flush", rename)
        edges = range(writer_open + 1, publication_directory_flush + 2)

        def corrupt_control(api: FakeWin32, _operation: str) -> None:
            authority_paths = [
                path for path in api.nodes
                if ntpath.dirname(path) == STORE
                and (ntpath.basename(path).startswith(".authority-pending-")
                     or ntpath.basename(path) == "authority.json")]
            target = (authority_paths[0] if authority_paths
                      else ntpath.join(STORE, "writer.lock"))
            api.nodes[target].payload += b"!"

        for position in edges:
            api = FakeWin32()
            api.mutation = (position, corrupt_control)
            with self.subTest(position=position,
                              operation=operations[position - 1]), self.assertRaises(
                                  artifact.ArtifactError):
                artifact.WindowsVisualArtifactAuthority.create_new(
                    STORE, source_path=SOURCE, api=api)
            self.assertEqual(api.delete_calls, 0)
        print(f"visual artifact control publication mutation edges: {len(edges)}")

    def test_fault_before_and_after_every_publication_boundary_never_false_returns(self):
        base_api, base_store = new_store()
        authority = base_store.authority
        base_store.close()
        baseline = base_api.clone()

        golden_api = baseline.clone()
        golden = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=golden_api)
        golden_api.log = []
        golden.retain("files/before-provider.raw", b"raw-wire" * 20,
                      "application/octet-stream", PRODUCER, 1)
        boundaries = list(golden_api.log)
        golden.close()
        self.assertEqual(
            {"open", "write", "file_flush", "rename", "directory_flush"},
            set(boundaries))

        tested = 0
        for position, operation in enumerate(boundaries, 1):
            for side in ("before", "after"):
                with self.subTest(position=position, operation=operation,
                                  side=side):
                    api = baseline.clone()
                    candidate = artifact.WindowsVisualArtifactAuthority.open_existing(
                        authority, source_path=SOURCE, api=api)
                    api.log = []
                    api.fault = (position, side)
                    with self.assertRaises((OSError, artifact.ArtifactError)):
                        candidate.retain(
                            "files/before-provider.raw", b"raw-wire" * 20,
                            "application/octet-stream", PRODUCER, 1)
                    with self.assertRaises(artifact.ArtifactAuthorityError):
                        candidate.verify()
                    api.crash()
                    try:
                        recovered = artifact.WindowsVisualArtifactAuthority.open_existing(
                            authority, source_path=SOURCE, api=api)
                    except artifact.ArtifactError:
                        # A surviving torn/ambiguous pending object is retained;
                        # recovery performs no delete or replacement.
                        self.assertTrue(any(".pending-" in path
                                            for path in api.nodes))
                    else:
                        refs = recovered.retained_refs()
                        self.assertIn(len(refs), (0, 1))
                        if refs:
                            self.assertEqual(
                                refs[0].logical_name,
                                "files/before-provider.raw")
                        recovered.close()
                    self.assertEqual(api.delete_calls, 0)
                    tested += 1
        self.assertEqual(tested, len(boundaries) * 2)
        print(f"visual artifact publication fault edges: {tested}")

    def test_mutation_after_every_publication_boundary_is_detected_before_return(self):
        base_api, base_store = new_store()
        authority = base_store.authority
        base_store.close()
        baseline = base_api.clone()

        oracle_api = baseline.clone()
        oracle = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=oracle_api)
        oracle_api.log = []
        oracle.retain("semantic/00-result.json", b'{"ok":true}\n',
                      "application/json", PRODUCER, 2)
        boundaries = list(oracle_api.log)
        oracle.close()

        def corrupt_current(api: FakeWin32, _operation: str) -> None:
            targets = [path for path in api.nodes
                       if ntpath.dirname(path) == STORE
                       and (ntpath.basename(path).startswith(".pending-")
                            or ntpath.basename(path).endswith(".artifact"))]
            if targets:
                api.nodes[targets[-1]].payload += b"!"

        for position, operation in enumerate(boundaries, 1):
            with self.subTest(position=position, operation=operation):
                api = baseline.clone()
                candidate = artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=api)
                api.log = []
                api.mutation = (position, corrupt_current)
                with self.assertRaises(artifact.ArtifactError):
                    candidate.retain(
                        "semantic/00-result.json", b'{"ok":true}\n',
                        "application/json", PRODUCER, 2)
                with self.assertRaises(artifact.ArtifactAuthorityError):
                    candidate.retained_refs()
                self.assertEqual(api.delete_calls, 0)
                candidate.close()
        print(f"visual artifact publication mutation edges: {len(boundaries)}")

    def test_well_formed_binding_substitution_after_final_flush_is_rejected(self):
        api, store = new_store()
        authority = store.authority
        store.close()
        candidate = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=api)
        api.log = []

        def substitute_valid_container(target: FakeWin32, operation: str) -> None:
            self.assertEqual(operation, "directory_flush")
            paths = [path for path in target.nodes
                     if ntpath.dirname(path) == STORE
                     and ntpath.basename(path).endswith(".artifact")]
            self.assertEqual(len(paths), 1)
            node = target.nodes[paths[0]]
            prefix = len(artifact.MAGIC) + 4
            self.assertTrue(node.payload.startswith(artifact.MAGIC))
            header_size = int.from_bytes(
                node.payload[len(artifact.MAGIC):prefix], "big")
            header = json.loads(
                node.payload[prefix:prefix + header_size].decode("ascii"))
            raw = node.payload[prefix + header_size:]
            header["logicalName"] = "semantic/00-result.jsox"
            replacement = canonical(header)
            node.payload = (artifact.MAGIC
                            + len(replacement).to_bytes(4, "big")
                            + replacement + raw)

        # The last publication operation is the parent-directory durability
        # acknowledgement.  A syntactically valid substitution after it must
        # still be compared to the caller's original binding before exposure.
        oracle_api = api.clone()
        oracle = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=oracle_api)
        oracle_api.log = []
        oracle.retain("semantic/00-result.json", b'{"ok":true}\n',
                      "application/json", PRODUCER, 2)
        final_flush = len(oracle_api.log)
        self.assertEqual(oracle_api.log[-1], "directory_flush")
        oracle.close()

        api.mutation = (final_flush, substitute_valid_container)
        with self.assertRaisesRegex(
                artifact.ArtifactCorrupt,
                "durable artifact binding differs after directory flush"):
            candidate.retain("semantic/00-result.json", b'{"ok":true}\n',
                             "application/json", PRODUCER, 2)
        with self.assertRaises(artifact.ArtifactAuthorityError):
            candidate.retained_refs()
        self.assertEqual(api.delete_calls, 0)
        candidate.close()

    def test_complete_pending_is_only_additive_recovery_action(self):
        api, store = new_store()
        authority = store.authority
        reference = store.retain(
            "orientation/00-LANDSCAPE.txt", b"orientation-wire",
            "application/json", PRODUCER, 3)
        store.close()
        node = api.nodes.pop(artifact_path())
        pending = pending_path()
        api.nodes[pending] = node
        api.durable = copy.deepcopy(api.nodes)
        prior_renames = api.rename_calls

        recovered = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=api)
        self.assertEqual(recovered.retained_refs(), (reference,))
        self.assertIn(artifact_path(), api.nodes)
        self.assertNotIn(pending, api.nodes)
        self.assertIn(artifact_path(), api.durable)
        self.assertEqual(api.rename_calls, prior_renames + 1)
        self.assertEqual(api.delete_calls, 0)
        recovered.close()

    def test_faults_at_every_additive_recovery_publication_boundary_recover_again(self):
        api, store = new_store()
        authority = store.authority
        reference = store.retain(
            "orientation/00-LANDSCAPE.txt", b"orientation-wire",
            "application/json", PRODUCER, 3)
        store.close()
        api.nodes[pending_path()] = api.nodes.pop(artifact_path())
        api.durable = copy.deepcopy(api.nodes)
        baseline = api.clone()

        oracle_api = baseline.clone()
        oracle = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=oracle_api)
        recovery_edges = [
            (position, operation)
            for position, operation in enumerate(oracle_api.log, 1)
            if operation in ("file_flush", "rename", "directory_flush")
        ]
        oracle.close()
        self.assertEqual([operation for _, operation in recovery_edges],
                         ["file_flush", "rename", "directory_flush"])

        for position, operation in recovery_edges:
            for side in ("before", "after"):
                candidate_api = baseline.clone()
                candidate_api.fault = (position, side)
                with self.subTest(operation=operation, side=side), self.assertRaises(
                        (OSError, artifact.ArtifactError)):
                    artifact.WindowsVisualArtifactAuthority.open_existing(
                        authority, source_path=SOURCE, api=candidate_api)
                candidate_api.crash()
                recovered = artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=candidate_api)
                self.assertEqual(recovered.retained_refs(), (reference,))
                self.assertEqual(candidate_api.delete_calls, 0)
                recovered.close()
        print(f"visual artifact recovery fault edges: {len(recovery_edges) * 2}")

    def test_mutation_after_each_additive_recovery_boundary_blocks_exposure(self):
        api, store = new_store()
        authority = store.authority
        store.retain("files/recovery.json", b"{}\n", "application/json",
                     PRODUCER, 1)
        store.close()
        api.nodes[pending_path()] = api.nodes.pop(artifact_path())
        api.durable = copy.deepcopy(api.nodes)
        baseline = api.clone()

        oracle_api = baseline.clone()
        oracle = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=oracle_api)
        edges = [position for position, operation in enumerate(oracle_api.log, 1)
                 if operation in ("file_flush", "rename", "directory_flush")]
        oracle.close()

        def corrupt_object(target: FakeWin32, _operation: str) -> None:
            names = [path for path in target.nodes
                     if ntpath.dirname(path) == STORE
                     and (ntpath.basename(path).startswith(".pending-")
                          or ntpath.basename(path).endswith(".artifact"))]
            target.nodes[names[0]].payload += b"!"

        for position in edges:
            candidate_api = baseline.clone()
            candidate_api.mutation = (position, corrupt_object)
            with self.subTest(position=position), self.assertRaises(
                    artifact.ArtifactError):
                artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=candidate_api)
            self.assertEqual(candidate_api.delete_calls, 0)
        print(f"visual artifact recovery mutation edges: {len(edges)}")

    def test_well_formed_binding_substitution_after_every_recovery_boundary_is_rejected(self):
        api, store = new_store()
        authority = store.authority
        store.retain("files/recovery.json", b"{}\n", "application/json",
                     PRODUCER, 1)
        store.close()
        api.nodes[pending_path()] = api.nodes.pop(artifact_path())
        api.durable = copy.deepcopy(api.nodes)
        baseline = api.clone()

        oracle_api = baseline.clone()
        oracle = artifact.WindowsVisualArtifactAuthority.open_existing(
            authority, source_path=SOURCE, api=oracle_api)
        recovery_edges = [
            (position, operation)
            for position, operation in enumerate(oracle_api.log, 1)
            if operation in ("file_flush", "rename", "directory_flush")
        ]
        self.assertEqual([item[1] for item in recovery_edges],
                         ["file_flush", "rename", "directory_flush"])
        oracle.close()

        def substitute_valid_container(target: FakeWin32, operation: str) -> None:
            paths = [path for path in target.nodes
                     if ntpath.dirname(path) == STORE
                     and (ntpath.basename(path).startswith(".pending-")
                          or ntpath.basename(path).endswith(".artifact"))]
            self.assertEqual(len(paths), 1)
            rewrite_header(target.nodes[paths[0]],
                           logicalName="files/recoverx.json")

        for position, operation in recovery_edges:
            candidate_api = baseline.clone()
            candidate_api.mutation = (position, substitute_valid_container)
            with self.subTest(operation=operation), self.assertRaisesRegex(
                    artifact.ArtifactCorrupt,
                    "recovered artifact binding differs after"):
                artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=candidate_api)
            self.assertEqual(candidate_api.delete_calls, 0)

    def test_torn_duplicate_foreign_and_conflicting_pending_paths_are_untouched(self):
        cases = ("torn", "duplicate", "foreign", "already-published")
        for case in cases:
            api, store = new_store()
            authority = store.authority
            store.retain("files/before.json", b"{}\n", "application/json",
                         PRODUCER, 1)
            store.close()
            published = artifact_path()
            if case == "torn":
                node = copy.deepcopy(api.nodes.pop(published))
                node.payload = node.payload[:-3]
                node.synced = node.payload
                api.nodes[pending_path()] = node
            elif case == "duplicate":
                first = copy.deepcopy(api.nodes.pop(published))
                first.index = api.node().index
                second = copy.deepcopy(first)
                second.index = api.node().index
                api.nodes[pending_path("1" * 32)] = first
                api.nodes[pending_path("2" * 32)] = second
            elif case == "foreign":
                api.nodes[ntpath.join(STORE, "foreign.txt")] = api.node(
                    payload=b"foreign", synced=b"foreign")
            else:
                duplicate = copy.deepcopy(api.nodes[published])
                duplicate.index = api.node().index
                api.nodes[pending_path()] = duplicate
            api.durable = copy.deepcopy(api.nodes)
            snapshot = {path: (node.index, node.payload)
                        for path, node in api.nodes.items()}
            renames = api.rename_calls
            with self.subTest(case=case), self.assertRaises(
                    artifact.ArtifactError):
                artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=api)
            self.assertEqual(
                {path: (node.index, node.payload)
                 for path, node in api.nodes.items()}, snapshot)
            self.assertEqual(api.rename_calls, renames)
            self.assertEqual(api.delete_calls, 0)

    def test_case_ambiguous_recovered_logical_names_are_rejected(self):
        api, store = new_store()
        authority = store.authority
        store.retain("Visual/Frame.PNG", b"one", "image/png", PRODUCER, 1)
        store.retain("visual/other.png", b"two", "image/png", PRODUCER, 2)
        store.close()
        rewrite_header(api.nodes[artifact_path(1)],
                       logicalName="visual/frame.png")
        api.durable = copy.deepcopy(api.nodes)
        with self.assertRaises(artifact.ArtifactCorrupt):
            artifact.WindowsVisualArtifactAuthority.open_existing(
                authority, source_path=SOURCE, api=api)
        self.assertEqual(api.delete_calls, 0)

    def test_case_ambiguous_physical_inventory_is_rejected_without_mutation(self):
        api, store = new_store()
        authority = store.authority
        store.close()
        alias = ntpath.join(STORE, "AUTHORITY.JSON")
        duplicate = copy.deepcopy(api.nodes[ntpath.join(STORE, "authority.json")])
        duplicate.index = api.node().index
        api.nodes[alias] = duplicate
        api.durable = copy.deepcopy(api.nodes)
        snapshot = set(api.nodes)
        with self.assertRaises(artifact.ArtifactCorrupt):
            artifact.WindowsVisualArtifactAuthority.open_existing(
                authority, source_path=SOURCE, api=api)
        self.assertEqual(set(api.nodes), snapshot)
        self.assertEqual(api.rename_calls, 1)  # store authority publication only
        self.assertEqual(api.delete_calls, 0)


class IdentityMutationAndQuiescenceTests(unittest.TestCase):
    def test_split_store_identity_and_cross_store_refs_are_rejected(self):
        api = FakeWin32()
        first = artifact.WindowsVisualArtifactAuthority.create_new(
            STORE, source_path=SOURCE, api=api)
        second = artifact.WindowsVisualArtifactAuthority.create_new(
            OTHER_STORE, source_path=SOURCE, api=api)
        left = first.retain("files/a.json", b"a", "application/json",
                            PRODUCER, 0)
        right = second.retain("files/a.json", b"a", "application/json",
                              PRODUCER, 0)
        self.assertNotEqual(left.store_identity_sha256,
                            right.store_identity_sha256)
        with self.assertRaises(artifact.ArtifactAuthorityError):
            first.verify_ref(right)
        with self.assertRaises(artifact.ArtifactAuthorityError):
            second.verify_ref(left)
        first.close()
        second.close()

    def test_source_directory_file_link_reparse_acl_and_path_drift_fail_closed(self):
        mutations = (
            (SOURCE, "source-content"),
            (SOURCE, "reparse"),
            (SOURCE, "links"),
            (r"C:\evidence", "reparse"),
            (STORE, "reparse"),
            (STORE, "private"),
            (STORE, "replace-directory"),
            (ntpath.join(STORE, "writer.lock"), "links"),
            (ntpath.join(STORE, "authority.json"), "reparse"),
            (artifact_path(), "links"),
            (artifact_path(), "replace-file"),
        )
        for target, kind in mutations:
            api, store = new_store()
            store.retain("files/a.json", b"{}\n", "application/json",
                         PRODUCER, 0)
            if kind == "source-content":
                api.nodes[target].payload += b"changed"
            elif kind == "reparse":
                api.nodes[target].reparse = True
            elif kind == "links":
                api.nodes[target].links = 2
            elif kind == "private":
                api.nodes[target].private = False
            elif kind == "replace-directory":
                api.nodes[target] = api.node(directory=True)
            else:
                api.nodes[target] = api.node(
                    payload=api.nodes[target].payload,
                    synced=api.nodes[target].synced)
            with self.subTest(target=target, kind=kind), self.assertRaises(
                    artifact.ArtifactError):
                store.verify()
            with self.assertRaises(artifact.ArtifactAuthorityError):
                store.canonical_bytes()
            self.assertEqual(api.delete_calls, 0)
            try:
                store.close()
            except artifact.ArtifactError:
                pass

    def test_reopen_rejects_replacement_symlink_hardlink_and_private_drift(self):
        targets = (
            (STORE, "replace"),
            (STORE, "reparse"),
            (STORE, "private"),
            (SOURCE, "replace-source"),
            (SOURCE, "reparse"),
            (artifact_path(), "links"),
            (artifact_path(), "reparse"),
        )
        for target, kind in targets:
            api, store = new_store()
            authority = store.authority
            store.retain("files/a.json", b"{}\n", "application/json",
                         PRODUCER, 0)
            store.close()
            if kind == "replace":
                api.nodes[target] = api.node(directory=True)
            elif kind == "replace-source":
                api.nodes[target] = api.node(
                    payload=SOURCE_RAW, synced=SOURCE_RAW, private=False)
                # Same source bytes are a valid fresh retained source image;
                # the store directory identity, not source file ID, persists.
                reopened = artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=api)
                reopened.close()
                continue
            elif kind == "reparse":
                api.nodes[target].reparse = True
            elif kind == "private":
                api.nodes[target].private = False
            else:
                api.nodes[target].links = 2
            with self.subTest(target=target, kind=kind), self.assertRaises(
                    artifact.ArtifactError):
                artifact.WindowsVisualArtifactAuthority.open_existing(
                    authority, source_path=SOURCE, api=api)
            self.assertEqual(api.delete_calls, 0)

    def test_media_producer_size_and_content_are_bound_inside_object(self):
        changes = (
            {"mediaType": "application/octet-stream"},
            {"producerAuthoritySha256": "b" * 64},
            {"bytes": 1},
            {"sha256": "c" * 64},
            {"storeIdentitySha256": "d" * 64},
            {"capturedNs": "04"},
        )
        for change in changes:
            api, store = new_store()
            reference = store.retain(
                "files/a.json", b"payload", "application/json", PRODUCER, 4)
            rewrite_header(api.nodes[artifact_path()], **change)
            with self.subTest(change=change), self.assertRaises(
                    artifact.ArtifactError):
                store.verify_ref(reference)
            self.assertEqual(api.delete_calls, 0)
            store.close()

    def test_quiescence_is_two_pass_and_catches_post_flush_content_or_namespace_change(self):
        for kind in ("content", "namespace"):
            api, store = new_store()
            reference = store.retain(
                "visual/a.png", b"pixel-wire", "image/png", PRODUCER, 0)
            api.log = []

            def mutate(target: FakeWin32, operation: str) -> None:
                self.assertEqual(operation, "directory_flush")
                if kind == "content":
                    target.nodes[artifact_path()].payload += b"!"
                else:
                    target.nodes[ntpath.join(STORE, "foreign.bin")] = target.node(
                        payload=b"x", synced=b"x")

            api.mutation = (1, mutate)
            with self.subTest(kind=kind), self.assertRaises(
                    artifact.ArtifactError):
                store.assert_quiescent()
            with self.assertRaises(artifact.ArtifactAuthorityError):
                store.verify_ref(reference)
            self.assertEqual(api.delete_calls, 0)
            store.close()

    def test_writer_exclusion_reentrancy_and_closed_state(self):
        api, store = new_store()
        authority = store.authority
        with self.assertRaises(PermissionError):
            artifact.WindowsVisualArtifactAuthority.open_existing(
                authority, source_path=SOURCE, api=api)

        reentrant_errors = []

        def reenter(target: FakeWin32, _operation: str) -> None:
            try:
                store.verify()
            except BaseException as error:
                reentrant_errors.append(error)

        api.log = []
        api.mutation = (2, reenter)  # a write edge after the pending-file open
        store.retain("files/a.json", b"wire" * 30, "application/json",
                     PRODUCER, 0)
        self.assertTrue(reentrant_errors)
        self.assertIs(type(reentrant_errors[0]), artifact.ArtifactAuthorityError)
        store.close()
        store.close()
        for operation in (store.verify, store.canonical_bytes,
                          store.assert_quiescent, store.retained_refs):
            with self.subTest(operation=operation.__name__), self.assertRaises(
                    artifact.ArtifactAuthorityError):
                operation()

    def test_zero_progress_invalid_progress_and_unsupported_directory_flush(self):
        for count in (0, True, -1, artifact.WRITE_CHUNK_BYTES + 1):
            api, store = new_store()
            api.write = lambda _handle, _payload, value=count: value
            with self.subTest(count=count), self.assertRaises(
                    artifact.ArtifactError):
                store.retain("files/a.json", b"wire", "application/json",
                             PRODUCER, 0)
            self.assertEqual(api.delete_calls, 0)
            store.close()

        api = FakeWin32()
        api.directory_flush_supported = False
        with self.assertRaises(artifact.DurabilityUnavailable):
            artifact.WindowsVisualArtifactAuthority.create_new(
                STORE, source_path=SOURCE, api=api)
        self.assertEqual(api.delete_calls, 0)

    def test_native_boundary_has_no_non_windows_fallback(self):
        with mock.patch.object(artifact.os, "name", "posix"):
            with self.assertRaisesRegex(
                    artifact.ArtifactPersistenceError, "Windows native"):
                artifact.Win32()

    def test_noninjected_boundary_cannot_pin_an_unrelated_source_path(self):
        api = FakeWin32()
        with mock.patch.object(artifact, "Win32", return_value=api):
            with self.assertRaisesRegex(
                    artifact.ArtifactAuthorityError, "this module image"):
                artifact.WindowsVisualArtifactAuthority.create_new(
                    STORE, source_path=SOURCE)
        self.assertNotIn(STORE, api.nodes)

    @unittest.skipUnless(os.name == "nt", "Windows native binding check")
    def test_native_boundary_binds_required_symbols(self):
        api = artifact.Win32()
        self.assertTrue(api.sid.startswith("S-"))
        self.assertIn(api.sid, api.dacl)

    def test_concurrent_use_is_rejected_without_borrowing_owner_lock(self):
        api, store = new_store()
        entered = threading.Event()
        release = threading.Event()
        original_write = api.write

        def blocked_write(handle, payload):
            entered.set()
            if not release.wait(2):
                raise TimeoutError("test writer did not release")
            return original_write(handle, payload)

        api.write = blocked_write
        errors = []

        def owner():
            try:
                store.retain("files/a.json", b"wire", "application/json",
                             PRODUCER, 0)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=owner)
        thread.start()
        self.assertTrue(entered.wait(2))
        with self.assertRaises(artifact.ArtifactAuthorityError):
            store.verify()
        with self.assertRaises(artifact.ArtifactAuthorityError):
            store.close()
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
