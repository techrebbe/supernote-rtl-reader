"""Synthetic-only tests for the static PrivateADB complete-capture backend."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import native_page_host_authority as host
import native_page_private_adb as private
import native_page_private_adb_platform_backend as backend_module
import native_page_visual_platform_authority as platform
import native_page_visual_session_harness as harness
from test_native_page_private_adb import Bundle, Runtime, frame
from test_native_page_visual_platform_authority import (
    BOOT, DISPLAY, HOST_PROCESS, HOST_TASK, HOST_TOKEN, SESSION,
    make_bundle,
)


CAPTURE_ID = "00000000-0000-4000-8000-000000000501"


def facts_wire(*, serial: str = harness.AUTHORIZED_SERIAL,
               boot: str = BOOT,
               processes: tuple[host.ProcessIdentity, ...] = ()) -> bytes:
    if not processes:
        from test_native_page_visual_platform_authority import (
            HOST_PROCESS as default_host, STOCK_PROCESS,
        )
        processes = tuple(sorted((STOCK_PROCESS, default_host), key=lambda value: value.pid))
    package = host.PINNED_PACKAGE
    lines = [
        backend_module.PROCESS_FACTS_HEADER,
        "authority=" + backend_module.PROCESS_FACTS_AUTHORITY,
        "serial=" + serial,
        "bootId=" + boot,
        "policy readOnly=true mutationCount=0 userDocumentSelectionCount=0 "
        "scopePackages=" + ",".join(platform.RELEVANT_PACKAGES),
        f"package name={package.package} installedApkSha256={package.apk_sha256} "
        f"reviewedUnsignedApkSha256={package.reviewed_unsigned_apk_sha256} "
        f"dexSha256={package.dex_sha256} "
        f"signerCertSha256={package.signer_cert_sha256} "
        f"versionCode={package.version_code} versionName={package.version_name}",
    ]
    lines.extend(
        f"process pid={item.pid} startTicks={item.start_ticks} uid={item.uid} "
        f"package={item.package}"
        for item in processes
    )
    lines.append(f"END processCount={len(processes)} packageCount=1")
    return ("\n".join(lines) + "\n").encode("ascii")


def collector_wire(activity: bytes, window: bytes, process: bytes,
                   display: bytes, *, order=(1, 2, 3, 4),
                   terminal: bool = True, trailing: bytes = b"") -> bytes:
    payloads = {1: activity, 2: window, 3: process, 4: display}
    result = bytearray(backend_module.COLLECTOR_MAGIC)
    for tag in order:
        payload = payloads[tag]
        result.extend(struct.pack(">BI32s", tag, len(payload),
                                  hashlib.sha256(payload).digest()))
        result.extend(payload)
    if terminal:
        digest = hashlib.sha256(result).digest()
        result.append(backend_module.COLLECTOR_TERMINAL_TAG)
        result.extend(digest)
    result.extend(trailing)
    return bytes(result)


class PrivateAdbPlatformBackendTests(unittest.TestCase):
    def setUp(self):
        for guard in (
            patch.object(private, "WindowsRuntime",
                         side_effect=AssertionError("live runtime")),
            patch.object(private.socket, "socket",
                         side_effect=AssertionError("network")),
            patch.object(private.subprocess, "Popen",
                         side_effect=AssertionError("process")),
        ):
            guard.start()
            self.addCleanup(guard.stop)
        self.fresh()

    def fresh(self):
        self.bundle = Bundle()
        self.runtime = Runtime(self.bundle)
        self.server = private.PrivateAdbServer(
            self.bundle, harness.AUTHORIZED_SERIAL, Path("C:/private-platform"),
            runtime=self.runtime,
        )
        self.server.start_platform_capture()

    def clean(self):
        if self.server.state != "closed":
            self.server.close()
        self.assertEqual(self.server.state, "closed")
        self.assertFalse(self.server.cleanup_obligations)

    def valid_members(self):
        bundle, foreign = make_bundle()
        return (
            bundle.activity_manager_raw,
            bundle.window_manager_raw,
            facts_wire(),
            bundle.display_inventory_raw,
            foreign,
        )

    def load_shell(self, wire: bytes, *, exit_code: int = 0,
                   stderr: bytes = b"") -> None:
        frames = [b"OKAY"]
        if stderr:
            frames.append(frame(2, stderr))
        frames.extend((frame(1, wire), frame(3, bytes([exit_code]))))
        self.runtime.shell = frames

    def make_backend(self, *, capture_id=CAPTURE_ID):
        return backend_module.PrivateAdbPlatformBackend(
            self.server, boot_id=BOOT, generation=7,
            capture_id_factory=lambda: capture_id,
        )

    def test_fragmented_static_service_yields_visual_authority_bundle(self):
        expected_service = (
            "shell,v2,raw:exec /system/bin/native-page-platform-collector --wire-v1"
        )
        self.assertEqual(private.PLATFORM_CAPTURE_SERVICE, expected_service)
        self.assertEqual(private.PLATFORM_CAPTURE_SERVICE_SHA256,
                         hashlib.sha256(expected_service.encode("ascii")).hexdigest())
        activity, window, facts, display, foreign = self.valid_members()
        self.load_shell(collector_wire(activity, window, facts, display))
        self.runtime.fragment = 1
        backend = self.make_backend()
        authority = platform.VisualPlatformAuthority(
            backend, host_process=HOST_PROCESS, host_task_id=HOST_TASK,
            host_activity_token=HOST_TOKEN, session_id=SESSION,
        )
        before = backend.now_ns()
        value = authority.capture(
            "postlaunch-preack", foreign, DISPLAY,
            before + 1_000_000_000,
        )
        self.assertEqual(value.snapshot.am_sha256, hashlib.sha256(activity).hexdigest())
        self.assertEqual(len(self.runtime.connections), 1)
        self.assertEqual(
            self.runtime.connections[0].requests,
            [f"host:transport:{harness.AUTHORIZED_SERIAL}".encode("ascii"),
             private.PLATFORM_CAPTURE_SERVICE.encode("ascii")],
        )
        canonical = json.loads(backend.canonical_bytes())
        self.assertEqual(canonical["collectorService"],
                         private.PLATFORM_CAPTURE_SERVICE)
        self.assertEqual(canonical["collectorServiceSha256"],
                         private.PLATFORM_CAPTURE_SERVICE_SHA256)
        self.assertEqual(backend.identity().authority_sha256,
                         hashlib.sha256(backend.canonical_bytes()).hexdigest())
        transport = self.server.platform_transport_identity()
        self.assertEqual((transport.server_pid, transport.server_creation_time,
                          transport.server_image_path),
                         (900, 123000, "c:\\reviewed-adb\\adb.exe"))
        self.clean()

    def test_dedicated_platform_and_legacy_command_modes_cannot_mix(self):
        with self.assertRaisesRegex(private.PrivateAdbError,
                                    "frozen registry"):
            self.server.run("get_state", {}, self.runtime.now() + 1.0)
        self.assertEqual(len(self.runtime.connections), 0)
        self.clean()

        self.bundle = Bundle()
        self.runtime = Runtime(self.bundle)
        self.server = private.PrivateAdbServer(
            self.bundle, harness.AUTHORIZED_SERIAL, Path("C:/private-command"),
            runtime=self.runtime,
        ).start()
        with self.assertRaisesRegex(private.PrivateAdbError,
                                    "deadline/mode"):
            self.server.capture_platform_wire(self.runtime.now() + 1.0)
        self.assertEqual(len(self.runtime.connections), 0)
        self.clean()

    def test_transport_preserves_streams_and_rejects_exit_stderr_and_trailing(self):
        activity, window, facts, display, _ = self.valid_members()
        wire = collector_wire(activity, window, facts, display)
        cases = {
            "exit": [b"OKAY", frame(1, wire), frame(3, b"\x09")],
            "stderr": [b"OKAY", frame(2, b"diagnostic"),
                       frame(1, wire), frame(3, b"\0")],
            "trailing": [b"OKAY", frame(1, wire), frame(3, b"\0"),
                         frame(1, b"late")],
            "truncated": [b"OKAY", frame(1, wire)[:-3]],
            "missing-exit": [b"OKAY", frame(1, wire)],
        }
        for name, shell in cases.items():
            with self.subTest(name=name):
                if name != "exit":
                    self.fresh()
                self.runtime.shell = shell
                with self.assertRaises(private.PrivateAdbError):
                    self.server.capture_platform_wire(self.runtime.now() + .2)
                self.assertEqual(self.server.state, "closed")
                self.assertTrue(all(connection.closed
                                    for connection in self.runtime.connections))

    def test_transport_uses_one_connection_and_rejects_reentrancy(self):
        activity, window, facts, display, _ = self.valid_members()
        self.load_shell(collector_wire(activity, window, facts, display))
        attempted = []

        def reenter(runtime, connection):
            if attempted:
                return
            attempted.append(True)
            with self.assertRaisesRegex(private.PrivateAdbError,
                                        "concurrent or reentrant"):
                self.server.capture_platform_wire(runtime.now() + 1.0)

        self.runtime.on_receive = reenter
        result = self.server.capture_platform_wire(self.runtime.now() + 1.0)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, b"")
        self.assertTrue(result.eof)
        self.assertEqual(len(self.runtime.connections), 1)
        self.clean()

    def test_transport_bounds_stdout_stderr_and_frame_count_before_allocation(self):
        cases = {
            "stdout": [
                b"OKAY",
                b"\x01" + (private.MAX_PLATFORM_CAPTURE_BYTES + 1).to_bytes(4, "little"),
            ],
            "stderr": [
                b"OKAY",
                b"\x02" + (private.MAX_PLATFORM_STDERR_BYTES + 1).to_bytes(4, "little"),
            ],
            "aggregate": [
                b"OKAY", frame(2, b"x"),
                b"\x01" + private.MAX_PLATFORM_CAPTURE_BYTES.to_bytes(4, "little"),
            ],
            "frames": [b"OKAY"] + [frame(1, b"")]
            * private.MAX_PLATFORM_SHELL_FRAMES,
        }
        for index, (name, shell) in enumerate(cases.items()):
            with self.subTest(name=name):
                if index:
                    self.fresh()
                self.runtime.shell = shell
                with self.assertRaises(private.PrivateAdbError):
                    self.server.capture_platform_wire(self.runtime.now() + 1.0)
                self.assertLessEqual(max(self.runtime.read_limits), 4096)
                self.assertEqual(self.server.state, "closed")

    def test_transport_identity_drift_fails_and_never_releases_output(self):
        activity, window, facts, display, _ = self.valid_members()
        self.load_shell(collector_wire(activity, window, facts, display))
        process = self.runtime.processes[0]
        original = process.identity
        changed = False

        def drift(runtime, connection):
            nonlocal changed
            if not changed and connection.requests and connection.requests[-1] == \
                    private.PLATFORM_CAPTURE_SERVICE.encode("ascii"):
                changed = True
                process.identity = replace(original, creation_time=original.creation_time + 1)

        self.runtime.on_receive = drift
        with self.assertRaises(private.PrivateAdbError):
            self.server.capture_platform_wire(self.runtime.now() + 1.0)
        self.assertTrue(self.server.cleanup_obligations)
        process.identity = original
        self.server.close()
        self.clean()

    def test_collector_member_topology_digests_and_total_tail_fail_closed(self):
        activity, window, facts, display, _ = self.valid_members()
        valid = collector_wire(activity, window, facts, display)
        mutations = {
            "reordered": collector_wire(activity, window, facts, display,
                                         order=(2, 1, 3, 4)),
            "duplicate": collector_wire(activity, window, facts, display,
                                         order=(1, 2, 3, 3)),
            "missing": collector_wire(activity, window, facts, display,
                                       order=(1, 2, 3)),
            "trailing": valid + b"x",
            "aggregate": valid[:-1] + bytes([valid[-1] ^ 1]),
            "member-digest": (valid[:13] + bytes([valid[13] ^ 1]) + valid[14:]),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(backend_module.PrivateAdbPlatformBackendError):
                    backend_module.decode_collector_wire(raw)

    def test_collector_oversized_member_is_rejected_from_header_only(self):
        raw = (
            backend_module.COLLECTOR_MAGIC +
            struct.pack(">BI32s", 1, platform.MAX_ACTIVITY_BYTES + 1,
                        b"\0" * 32) +
            b"\0" + b"\0" * 32
        )
        with self.assertRaisesRegex(backend_module.PrivateAdbPlatformBackendError,
                                    "oversized"):
            backend_module.decode_collector_wire(raw)

    def test_backend_rejects_serial_boot_and_process_identity_drift(self):
        activity, window, _, display, _ = self.valid_members()
        from test_native_page_visual_platform_authority import (
            HOST_PROCESS as default_host, STOCK_PROCESS,
        )
        duplicate = (STOCK_PROCESS,
                     replace(default_host, pid=STOCK_PROCESS.pid))
        valid = facts_wire()
        cases = (
            facts_wire(serial="OTHER"),
            facts_wire(boot="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            facts_wire(processes=duplicate),
            valid.replace(b"readOnly=true", b"readOnly=false", 1),
            valid.replace(host.PINNED_PACKAGE.apk_sha256.encode("ascii"),
                          b"0" * 64, 1),
        )
        for index, facts in enumerate(cases):
            with self.subTest(index=index):
                if index:
                    self.fresh()
                self.load_shell(collector_wire(activity, window, facts, display))
                candidate = self.make_backend(capture_id=
                    f"00000000-0000-4000-8000-{600 + index:012d}")
                request = platform.CaptureRequest(
                    "postlaunch-preack", harness.AUTHORIZED_SERIAL, BOOT,
                    DISPLAY, "0" * 64,
                )
                with self.assertRaises(backend_module.PrivateAdbPlatformBackendError):
                    candidate.capture_complete(
                        request, candidate.now_ns() + 1_000_000_000)
                with self.assertRaisesRegex(
                        backend_module.PrivateAdbPlatformBackendError, "sealed"):
                    candidate.verify()

    def test_backend_rejects_request_borrowing_and_capture_id_replay(self):
        activity, window, facts, display, _ = self.valid_members()
        wire = collector_wire(activity, window, facts, display)
        self.load_shell(wire)
        candidate = self.make_backend()
        borrowed = platform.CaptureRequest(
            "postlaunch-preack", "OTHER", BOOT, DISPLAY, None)
        with self.assertRaises(backend_module.PrivateAdbPlatformBackendError):
            candidate.capture_complete(
                borrowed, candidate.now_ns() + 1_000_000_000)
        self.assertEqual(len(self.runtime.connections), 0)
        with self.assertRaisesRegex(backend_module.PrivateAdbPlatformBackendError,
                                    "sealed"):
            candidate.verify()

        self.fresh()
        self.load_shell(wire)
        candidate = self.make_backend()
        request = platform.CaptureRequest(
            "postlaunch-preack", harness.AUTHORIZED_SERIAL, BOOT,
            DISPLAY, None)
        candidate.capture_complete(
            request, candidate.now_ns() + 1_000_000_000)
        self.runtime.clock += .01
        self.load_shell(wire)
        with self.assertRaisesRegex(backend_module.PrivateAdbPlatformBackendError,
                                    "replayed"):
            candidate.capture_complete(
                request, candidate.now_ns() + 1_000_000_000)

    def test_backend_reentrancy_is_rejected_without_second_dispatch(self):
        activity, window, facts, display, _ = self.valid_members()
        self.load_shell(collector_wire(activity, window, facts, display))
        holder = {}
        attempted = []

        def capture_id():
            candidate = holder["backend"]
            request = platform.CaptureRequest(
                "postlaunch-preack", harness.AUTHORIZED_SERIAL, BOOT,
                DISPLAY, None)
            with self.assertRaisesRegex(
                    backend_module.PrivateAdbPlatformBackendError,
                    "concurrent or reentrant"):
                candidate.capture_complete(
                    request, self.runtime.now() * 1_000_000_000 + 1_000_000_000)
            attempted.append(True)
            return CAPTURE_ID

        candidate = backend_module.PrivateAdbPlatformBackend(
            self.server, boot_id=BOOT, generation=7,
            capture_id_factory=capture_id,
        )
        holder["backend"] = candidate
        request = platform.CaptureRequest(
            "postlaunch-preack", harness.AUTHORIZED_SERIAL, BOOT,
            DISPLAY, None)
        candidate.capture_complete(
            request, candidate.now_ns() + 1_000_000_000)
        self.assertEqual(attempted, [True])
        self.assertEqual(len(self.runtime.connections), 1)
        self.clean()


if __name__ == "__main__":
    unittest.main()
