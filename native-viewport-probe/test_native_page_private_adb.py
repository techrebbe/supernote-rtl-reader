"""Deterministic fake-only tests; no ADB, device, process, or network I/O."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import native_page_private_adb as private
from native_page_windows_tool_authority import FileAuthority, FileIdentity, FILENAMES, ToolAuthorityError

REAL_RUNTIME = private.WindowsRuntime


def frame(stream, raw):
    return bytes([stream]) + len(raw).to_bytes(4, "little") + raw


class Bundle:
    def __init__(self):
        self.directory = Path("C:/reviewed-adb")
        self.executable = "C:\\reviewed-adb\\adb.exe"
        self.changed = False
        self.images = {name: FileAuthority(name, "C:\\reviewed-adb\\" + name, 12,
                       hashlib.sha256(name.encode()).hexdigest(), FileIdentity(0, 7, n, 1, 12, 100, 200))
                       for n, name in enumerate(FILENAMES, 1)}

    def verify(self):
        if self.changed:
            raise ToolAuthorityError("fake bundle drift")

    def canonical_bytes(self):
        self.verify()
        return json.dumps({k: (v.path, v.sha256) for k, v in sorted(self.images.items())}).encode()

    def authorities(self):
        self.verify()
        return dict(self.images)


@dataclass
class Process:
    identity: private.ProcessIdentity
    modules: tuple[str, ...]
    status: int | None = None
    resumed: bool = False
    terminated: bool = False
    closed: bool = False
    flood: bool = False


@dataclass
class Connection:
    peer: private.ConnectionTuple
    owner: int
    received: list = field(default_factory=list)
    pending: bytearray = field(default_factory=bytearray)
    sent: bytearray = field(default_factory=bytearray)
    requests: list = field(default_factory=list)
    closed: bool = False


class Reservation:
    def __init__(self, runtime, port):
        self.runtime, self.port, self.released = runtime, port, False

    def release(self):
        self.released = True
        self.runtime.events.append("release")
        if self.runtime.race:
            self.runtime.rows = (self.runtime.race,)


class Runtime:
    def __init__(self, bundle):
        self.bundle, self.clock = bundle, 100.0
        self.events, self.processes, self.connections, self.spawns = [], [], [], []
        self.rows, self.race, self.reservation = (), None, None
        self.image, self.loaded_modules = None, None
        self.no_listener = self.keep_open = self.close_fails = False
        self.spawn_delay = self.connect_delay = 0.0
        self.fragment = 4096
        self.host = [b"OKAY0006device"]
        self.transport = [b"OKAY"]
        self.shell = [b"OKAY", frame(1, b"output"), frame(3, b"\0")]
        self.on_connect = self.after_connect = self.on_owner = self.on_send = None
        self.on_receive = self.on_terminate = self.after_terminate = self.on_close = None
        self.read_limits = []

    def now(self): return self.clock
    def windows_directory(self): return "C:\\Windows"

    def sleep(self, seconds):
        assert 0 < seconds <= private.POLL_SECONDS
        self.clock += seconds

    def reserve(self, port):
        self.reservation = Reservation(self, port or 41234)
        return self.reservation

    def listeners(self, port): return tuple(row for row in self.rows if row.port == port)

    def spawn_suspended(self, argv, environment, cwd):
        assert argv[-2:] == ("server", "nodaemon"), "CLI commands are prohibited"
        self.spawns.append((argv, dict(environment), cwd))
        process = Process(private.ProcessIdentity(900, 123000, self.image or self.bundle.executable),
                          self.loaded_modules or tuple(v.path for v in self.bundle.images.values()))
        self.processes.append(process)
        self.clock += self.spawn_delay
        return process

    def identity(self, process):
        assert not process.closed
        self.events.append("identity")
        return process.identity

    def modules(self, process):
        self.events.append("modules")
        return process.modules

    def resume(self, process):
        self.events.append("resume")
        process.resumed = True
        if not self.rows and not self.no_listener:
            self.rows = (private.Listener("127.0.0.1", 41234, 900),)

    def poll(self, process): return process.status

    def read(self, process, limit):
        self.read_limits.append(limit)
        return b"x" * limit if process.flood else b""

    def terminate(self, process, expected):
        if self.on_terminate: self.on_terminate(self, process)
        if process.identity != expected:
            raise private.PrivateAdbError("exact terminate identity drift")
        process.terminated, process.status = True, 137
        self.rows = tuple(row for row in self.rows if row.pid != expected.pid)
        if self.after_terminate: self.after_terminate(self, process)

    def close_process(self, process, expected):
        if self.on_close: self.on_close(self, process)
        if process.identity != expected or process.status is None:
            raise private.PrivateAdbError("exact close identity drift")
        process.closed = True

    def connect(self, port, deadline):
        if self.on_connect: self.on_connect(self)
        connection = Connection(private.ConnectionTuple("127.0.0.1", 52001, "127.0.0.1", port),
                                self.rows[0].pid if self.rows else 700)
        self.connections.append(connection)
        self.clock += self.connect_delay
        if self.after_connect: self.after_connect(self, connection)
        return connection

    def connection_tuple(self, connection):
        assert not connection.closed
        return connection.peer

    def peer_owner(self, connection):
        self.events.append("owner")
        if self.on_owner: self.on_owner(self, connection)
        return private.PeerOwner(connection.peer, connection.owner)

    def send(self, connection, raw, deadline):
        self.events.append("send")
        if self.on_send: self.on_send(self, connection)
        if self.processes[0].status is not None and connection.owner == 900:
            raise private.PrivateAdbError("original peer exited; no reconnect")
        count = min(len(raw), self.fragment)
        connection.sent.extend(raw[:count])
        connection.pending.extend(raw[:count])
        pending = connection.pending
        if len(pending) >= 4 and len(pending) >= int(pending[:4], 16) + 4:
            size = int(pending[:4], 16)
            service = bytes(pending[4:size + 4])
            del pending[:size + 4]
            connection.requests.append(service)
            if service.startswith(b"host-serial:"): connection.received.extend(self.host)
            elif service.startswith(b"host:transport:"): connection.received.extend(self.transport)
            elif service.startswith(b"shell,v2,raw:"): connection.received.extend(self.shell)
            else: raise AssertionError("unknown wire service")
        return count

    def receive(self, connection, limit, deadline):
        self.read_limits.append(limit)
        if self.on_receive: self.on_receive(self, connection)
        if not connection.received: return None if self.keep_open else b""
        chunk = connection.received.pop(0)
        if chunk is None: return None
        count = min(limit, self.fragment)
        if chunk[count:]: connection.received.insert(0, chunk[count:])
        return chunk[:count]

    def close_connection(self, connection):
        if self.close_fails: raise private.PrivateAdbError("exact socket close failed")
        connection.closed = True


class Kernel:
    """Pure memory simulation for the Windows launch/pipe adapter."""
    def __init__(self):
        self.attributes, self.closed, self.created = [], [], []
        self.reject_children = False

    def CreatePipe(self, read, write, security, size):
        read._obj.value, write._obj.value = 101, 102
        return 1

    def SetHandleInformation(self, handle, mask, flags): return 1
    def CreateFileW(self, path, *args): return 103

    def InitializeProcThreadAttributeList(self, buffer, count, flags, size):
        assert count == 2
        size._obj.value = 128
        return int(buffer is not None)

    def UpdateProcThreadAttribute(self, buffer, flags, attr, value, size, previous, returned):
        self.attributes.append((attr, tuple(value) if attr == 0x20002 else value._obj.value))
        return 0 if attr == 0x2000e and self.reject_children else 1

    def DeleteProcThreadAttributeList(self, buffer): pass

    def CreateProcessW(self, app, cmd, pa, ta, inherit, flags, env, cwd, startup, info):
        value = startup._obj.startup
        self.created.append((app, cmd.value, flags, "".join(env[:]), value.stdin,
                             value.stdout, value.stderr, value.show))
        info._obj.process, info._obj.thread, info._obj.pid = 201, 202, 203
        return 1

    def CloseHandle(self, handle):
        self.closed.append(handle.value if hasattr(handle, "value") else handle)
        return 1

    def PeekNamedPipe(self, handle, buffer, count, read, available, left):
        available._obj.value = 10000000
        return 1

    def ReadFile(self, handle, buffer, count, read, overlapped):
        ctypes.memmove(buffer, b"x" * count, count)
        read._obj.value = count
        return 1


class PrivateAdbTests(unittest.TestCase):
    def setUp(self):
        for guard in (patch.object(private, "WindowsRuntime", side_effect=AssertionError("live runtime")),
                      patch.object(private.socket, "socket", side_effect=AssertionError("network")),
                      patch.object(private.subprocess, "Popen", side_effect=AssertionError("process")),
                      patch.object(private.ctypes, "get_last_error", return_value=5, create=True)):
            guard.start()
            self.addCleanup(guard.stop)
        self.fresh()

    def fresh(self):
        self.bundle = Bundle()
        self.runtime = Runtime(self.bundle)
        self.server = private.PrivateAdbServer(self.bundle, "AUTHORIZED-123", Path("C:/private-run"),
                                                runtime=self.runtime)

    def start(self, specs=private.REFERENCE_COMMANDS): return self.server.start(specs)
    def run_command(self, command="get_state", args=None, seconds=1.0):
        return self.server.run(command, {} if args is None else args, self.runtime.now() + seconds)

    def clean(self):
        self.assertEqual(self.server.state, "closed")
        self.assertFalse(self.server.cleanup_obligations)
        self.assertTrue(all(p.closed for p in self.runtime.processes))
        self.assertTrue(all(c.closed for c in self.runtime.connections))
        if self.runtime.reservation: self.assertTrue(self.runtime.reservation.released)

    def test_retained_server_and_wire_serial_binding_without_cli_clients(self):
        self.start()
        self.assertEqual(self.runtime.spawns[0][0],
                         (self.bundle.executable, "-L", "tcp:127.0.0.1:41234", "server", "nodaemon"))
        self.assertEqual(self.run_command().output, b"device")
        self.assertEqual(self.runtime.connections[0].requests, [b"host-serial:AUTHORIZED-123:get-state"])
        for spec in private.REFERENCE_COMMANDS[1:]:
            self.run_command(spec.command_id)
            self.assertEqual(self.runtime.connections[-1].requests,
                             [b"host:transport:AUTHORIZED-123", ("shell,v2,raw:" + " ".join(spec.argv[1:])).encode()])
        self.assertEqual(len(self.runtime.spawns), 1)
        first = self.runtime.events.index("send")
        self.assertEqual(self.runtime.events[:first].count("owner"), 2)
        self.assertLess(self.runtime.events.index("release"), self.runtime.events.index("resume"))
        self.server.close()
        self.clean()

    def test_existing_listener_and_reservation_race_never_adopt_or_kill_foreign(self):
        foreign = private.Listener("127.0.0.1", 41234, 700)
        for existing in (True, False):
            with self.subTest(existing=existing):
                self.fresh()
                if existing:
                    self.server.requested_port, self.runtime.rows = 41234, (foreign,)
                else: self.runtime.race = foreign
                with self.assertRaises(private.PrivateAdbError): self.start()
                self.assertEqual(self.runtime.rows, (foreign,))
                self.clean()

    def test_precheck_to_connect_takeover_and_server_exit_send_zero_bytes(self):
        for exited in (False, True):
            with self.subTest(exited=exited):
                self.fresh()
                self.start()
                def takeover(runtime):
                    runtime.rows = (private.Listener("127.0.0.1", 41234, 700),)
                    if exited: runtime.processes[0].status = 1
                self.runtime.on_connect = takeover
                with self.assertRaises(private.PrivateAdbError): self.run_command()
                self.assertEqual(self.runtime.connections[0].owner, 700)
                self.assertEqual(self.runtime.connections[0].sent, b"")
                self.assertEqual(self.runtime.rows[0].pid, 700)
                self.clean()

    def test_exit_after_connect_or_after_admission_cannot_redirect_same_socket(self):
        for timing in ("after_connect", "on_send"):
            with self.subTest(timing=timing):
                self.fresh()
                self.start()
                def takeover(runtime, connection):
                    runtime.processes[0].status = 1
                    runtime.rows = (private.Listener("127.0.0.1", 41234, 700),)
                setattr(self.runtime, timing, takeover)
                with self.assertRaises(private.PrivateAdbError): self.run_command()
                self.assertEqual(len(self.runtime.connections), 1)
                self.assertEqual(self.runtime.connections[0].owner, 900)
                self.assertEqual(self.runtime.connections[0].sent, b"")
                self.clean()

    def test_new_listener_cannot_redirect_an_already_established_original_peer(self):
        self.start()
        def replace_listener(runtime, connection):
            runtime.rows = (private.Listener("127.0.0.1", 41234, 700),)
        self.runtime.after_connect = replace_listener
        with self.assertRaisesRegex(private.PrivateAdbError, "not exclusively owned"):
            self.run_command()
        self.assertEqual(len(self.runtime.connections), 1)
        self.assertEqual(self.runtime.connections[0].owner, 900)
        self.assertEqual(self.runtime.connections[0].requests, [b"host-serial:AUTHORIZED-123:get-state"])
        self.assertEqual(self.runtime.rows[0].pid, 700)
        self.clean()

    def test_peer_owner_bracket_pid_reuse_blocks_every_request_byte(self):
        self.start()
        process = self.runtime.processes[0]
        original = process.identity
        def drift(runtime, connection): process.identity = replace(original, creation_time=999999)
        self.runtime.on_owner = drift
        with self.assertRaisesRegex(private.PrivateAdbError, "cleanup incomplete"): self.run_command()
        self.assertEqual(self.runtime.connections[0].sent, b"")
        self.assertFalse(process.terminated)
        self.assertTrue(self.server.cleanup_obligations)
        process.identity = original
        self.server.close()
        self.clean()

    def test_second_owner_observation_and_tuple_drift_block_every_request_byte(self):
        for mode in ("owner", "tuple"):
            with self.subTest(mode=mode):
                self.fresh()
                self.start()
                count = 0
                def drift(runtime, connection):
                    nonlocal count
                    count += 1
                    if count == 2:
                        if mode == "owner": connection.owner = 700
                        else: connection.peer = replace(connection.peer, local_port=52002)
                self.runtime.on_owner = drift
                with self.assertRaises(private.PrivateAdbError): self.run_command()
                self.assertEqual(self.runtime.connections[0].sent, b"")
                self.clean()

    def test_wrong_connected_interface_or_port_is_rejected_before_bytes(self):
        for change in ({"peer_port": 5037}, {"peer_address": "192.0.2.1"}, {"local_address": "0.0.0.0"}):
            with self.subTest(change=change):
                self.fresh()
                self.start()
                def drift(runtime, connection): connection.peer = replace(connection.peer, **change)
                self.runtime.after_connect = drift
                with self.assertRaises(private.PrivateAdbError): self.run_command()
                self.assertEqual(self.runtime.connections[0].sent, b"")
                self.clean()

    def test_partial_sends_and_split_status_header_payload_and_exit(self):
        self.start()
        self.runtime.fragment = 1
        self.runtime.shell = [b"O", None, b"KAY", frame(1, b"out"), frame(2, b"err"), frame(3, b"\x07")]
        result = self.run_command("wm_size")
        self.assertEqual((result.output, result.returncode), (b"outerr", 7))
        self.assertEqual(len(self.runtime.connections), 1)
        self.server.close()
        self.clean()

    def test_final_write_exit_interleaving_and_exact_aggregate_cap(self):
        self.start((private.CommandSpec("wm_size", ("shell", "wm", "size"), 4),))
        self.runtime.shell = [b"OKAY", frame(1, b"ab"), None, frame(2, b"cd"), frame(3, b"\0")]
        self.assertEqual(self.run_command("wm_size").output, b"abcd")
        self.server.close()
        self.clean()

    def test_final_cap_plus_one_chunk_is_rejected_before_exit(self):
        self.start((private.CommandSpec("wm_size", ("shell", "wm", "size"), 4),))
        self.runtime.shell = [b"OKAY", frame(1, b"abcd"), None, frame(2, b"e"), frame(3, b"\0")]
        with self.assertRaisesRegex(private.PrivateAdbError, "aggregate shell output"): self.run_command("wm_size")
        self.clean()

    def test_malformed_partial_oversized_duplicate_missing_and_trailing_shell_frames(self):
        cases = {
            "oversize": [b"OKAY\x01\xff\xff\xff\xff"],
            "missing_exit": [b"OKAY", frame(1, b"output")],
            "duplicate_exit": [b"OKAY", frame(3, b"\0"), frame(3, b"\0")],
            "output_after_exit": [b"OKAY", frame(3, b"\0"), frame(1, b"late")],
            "long_exit": [b"OKAY", frame(3, b"\0\0\0\0")],
            "empty_exit": [b"OKAY", frame(3, b"")],
            "unknown_stream": [b"OKAY", frame(0, b"stdin")],
            "partial_header": [b"OKAY\x01\x04"],
            "partial_payload": [b"OKAY\x01\x04\0\0\0ab"],
            "fail": [b"FAIL0004oops"], "oversize_fail": [b"FAILffff"],
            "bad_hex": [b"FAILnope"], "bad_status": [b"WHAT"],
        }
        for name, wire in cases.items():
            with self.subTest(name=name):
                self.fresh()
                self.start()
                self.runtime.shell = wire
                with self.assertRaises(private.PrivateAdbError): self.run_command("wm_size")
                self.assertLessEqual(max(self.runtime.read_limits), 4096)
                self.clean()

    def test_missing_eof_and_missing_response_hit_bounded_deadline(self):
        for response in ([], [b"OKAY", frame(3, b"\0")]):
            with self.subTest(response=response):
                self.fresh()
                self.start()
                self.runtime.shell, self.runtime.keep_open = response, True
                with self.assertRaisesRegex(private.PrivateAdbError, "deadline"):
                    self.run_command("wm_size", seconds=0.1)
                self.clean()

    def test_excessive_empty_frames_are_bounded(self):
        self.start()
        self.runtime.shell = [b"OKAY" + frame(1, b"") * 4]
        with patch.object(private, "MAX_SHELL_FRAMES", 3):
            with self.assertRaisesRegex(private.PrivateAdbError, "frame count"): self.run_command("wm_size")
        self.clean()

    def test_transport_failure_sends_no_shell_request(self):
        self.start()
        self.runtime.transport = [b"FAIL0004oops"]
        with self.assertRaises(private.PrivateAdbError): self.run_command("wm_size")
        self.assertEqual(self.runtime.connections[0].requests, [b"host:transport:AUTHORIZED-123"])
        self.clean()

    def test_host_response_requires_bounded_hex_payload_and_eof(self):
        for wire in ([b"OKAYffff"], [b"OKAYnope"], [b"OKAY0006dev"], [b"OKAY0006deviceX"], [b"FAIL0004oops"]):
            with self.subTest(wire=wire):
                self.fresh()
                self.start()
                self.runtime.host = wire
                with self.assertRaises(private.PrivateAdbError): self.run_command()
                self.clean()

    def test_dynamic_and_mutating_specs_rejected_before_start(self):
        specs = [private.CommandSpec("get_state", ("get-state",), mutability="device_write"),
                 private.CommandSpec("get_state", ("get-state",), mutability="host_write"),
                 private.CommandSpec("custom", ("shell", "echo", "safe")),
                 private.CommandSpec("wm_size", ("shell", "wm", "size", "100x100")),
                 private.CommandSpec("wm_size", ("shell", "wm", private.ArgumentSlot("mode", "choice", choices=("size",)))),
                 private.CommandSpec("get_state", ("kill-server",))]
        for spec in specs:
            with self.subTest(spec=spec):
                with self.assertRaises(private.PrivateAdbError): self.server.start((spec,))
        self.assertEqual(self.runtime.spawns, [])

    def test_registry_and_arguments_remain_frozen(self):
        self.start()
        for command, args in (("unknown", {}), ("wm_size", {"size": "1x1"}), ("get_state", {"serial": "OTHER"}), ("get_state", [])):
            with self.assertRaises(private.PrivateAdbError): self.run_command(command, args)
        with self.assertRaises(TypeError): self.server._registry["other"] = private.REFERENCE_COMMANDS[0]
        self.assertEqual(self.runtime.connections, [])
        self.server.close()
        self.clean()

    def test_invalid_serial_port_and_deadline_fail_before_connection(self):
        for serial in ("", "-s", "A B", "A;id", "A\nB", "A:get-state", "127.0.0.1:5555", True, "A" * 129):
            with self.assertRaises(private.PrivateAdbError):
                private.PrivateAdbServer(self.bundle, serial, Path("C:/run"), runtime=self.runtime)
        with self.assertRaises(private.PrivateAdbError):
            private.PrivateAdbServer(self.bundle, "A", Path("C:/run"), runtime=self.runtime, port=5037)
        self.start()
        for deadline in (self.runtime.now(), self.runtime.now() + 61, float("inf"), float("nan"), True, "soon"):
            with self.assertRaises(private.PrivateAdbError): self.server.run("get_state", {}, deadline)
        self.assertEqual(self.runtime.connections, [])
        self.server.close()
        self.clean()

    def test_expired_connection_deadline_sends_zero_bytes(self):
        self.start()
        self.runtime.connect_delay = 1.0
        with self.assertRaisesRegex(private.PrivateAdbError, "deadline"): self.run_command(seconds=0.1)
        self.assertEqual(self.runtime.connections[0].sent, b"")
        self.clean()

    def test_hostile_environment_never_enters_private_server(self):
        hostile = {name: "evil" for name in ("PATH", "ADB_SERVER_SOCKET", "ANDROID_SERIAL", "ADB_VENDOR_KEYS",
                                             "ADB_TRACE", "LD_PRELOAD", "SystemRoot", "HOME", "COMSPEC", "PYTHONPATH")}
        with patch.dict(os.environ, hostile):
            self.start()
            self.run_command()
        environment = self.runtime.spawns[0][1]
        self.assertEqual(set(environment), {"SystemRoot", "WINDIR", "PATH", "HOME", "USERPROFILE",
                                           "ANDROID_USER_HOME", "TEMP", "TMP", "ADB_MDNS_AUTO_CONNECT"})
        self.assertNotIn("evil", repr(environment))
        self.server.close()
        self.clean()

    def test_missing_duplicate_and_substituted_loaded_dlls_are_rejected(self):
        api = self.bundle.images["AdbWinApi.dll"].path
        for changed in ((), (api, api), ("C:\\attacker\\AdbWinApi.dll",)):
            with self.subTest(changed=changed):
                self.fresh()
                self.runtime.loaded_modules = (self.bundle.executable, self.bundle.images["AdbWinUsbApi.dll"].path, *changed)
                with self.assertRaisesRegex(private.PrivateAdbError, "ADB DLL"): self.start()
                self.clean()

    def test_substituted_process_image_keeps_suspended_cleanup_obligation(self):
        self.runtime.image = "C:\\attacker\\adb.exe"
        with self.assertRaisesRegex(private.PrivateAdbError, "cleanup incomplete"): self.start()
        self.assertFalse(self.runtime.processes[0].resumed)
        self.assertFalse(self.runtime.processes[0].terminated)
        self.assertTrue(self.server.cleanup_obligations)

    def test_retained_exe_dll_digest_drift_is_rejected(self):
        self.start()
        original = dict(self.bundle.images)
        for name in FILENAMES:
            self.bundle.images[name] = replace(original[name], sha256="0" * 64)
            with self.assertRaisesRegex(private.PrivateAdbError, "authority changed"): self.server.verify()
            self.bundle.images = dict(original)
        self.server.close()
        self.clean()

    def test_bundle_drift_before_send_and_at_final_eof_never_releases_output(self):
        for before in (True, False):
            with self.subTest(before=before):
                self.fresh()
                self.start()
                def drift(runtime, connection):
                    if before or not connection.received: self.bundle.changed = True
                if before: self.runtime.after_connect = drift
                else: self.runtime.on_receive = drift
                with self.assertRaisesRegex(private.PrivateAdbError, "cleanup incomplete"): self.run_command()
                if before: self.assertEqual(self.runtime.connections[0].sent, b"")
                self.assertTrue(self.runtime.connections[0].closed)
                self.assertFalse(self.runtime.processes[0].terminated)
                self.bundle.changed = False
                self.server.close()
                self.clean()

    def test_server_output_flood_while_waiting_is_bounded(self):
        self.start()
        self.runtime.processes[0].flood = True
        self.runtime.host, self.runtime.keep_open = [], True
        with self.assertRaisesRegex(private.PrivateAdbError, "server output limit"): self.run_command(seconds=2)
        self.assertLessEqual(self.server._server_output, private.MAX_SERVER_OUTPUT + 1)
        self.clean()

    def test_startup_deadline_and_absent_listener_fail_closed(self):
        for delayed in (True, False):
            self.fresh()
            if delayed: self.runtime.spawn_delay = 1.0
            else: self.runtime.no_listener = True
            with self.assertRaisesRegex(private.PrivateAdbError, "startup deadline"): self.server.start(timeout=0.1)
            if delayed: self.assertFalse(self.runtime.processes[0].resumed)
            self.clean()

    def test_exact_cleanup_identity_checks_before_terminate_after_terminate_and_close(self):
        for phase in ("on_terminate", "after_terminate", "on_close"):
            with self.subTest(phase=phase):
                self.fresh()
                self.start()
                original = self.runtime.processes[0].identity
                def drift(runtime, process): process.identity = replace(original, creation_time=999999)
                setattr(self.runtime, phase, drift)
                with self.assertRaises(private.PrivateAdbError): self.server.close()
                self.assertFalse(self.runtime.processes[0].closed)
                self.assertTrue(self.server.cleanup_obligations)
                if phase == "on_terminate": self.assertFalse(self.runtime.processes[0].terminated)
                setattr(self.runtime, phase, None)
                self.runtime.processes[0].identity = original
                self.server.close()
                self.clean()

    def test_pid_and_image_identity_drift_never_kills_unverified_process(self):
        for change in ({"pid": 777}, {"image_path": "C:\\other\\adb.exe"}):
            self.fresh()
            self.start()
            original = self.runtime.processes[0].identity
            self.runtime.processes[0].identity = replace(original, **change)
            with self.assertRaises(private.PrivateAdbError): self.server.close()
            self.assertFalse(self.runtime.processes[0].terminated)
            self.runtime.processes[0].identity = original
            self.server.close()
            self.clean()

    def test_cleanup_timeout_and_stale_listener_keep_retained_handle(self):
        for mode in ("timeout", "listener"):
            self.fresh()
            self.start()
            def remain(runtime, process):
                if mode == "timeout": process.status = None
                else: runtime.rows = (private.Listener("127.0.0.1", 41234, 900),)
            self.runtime.after_terminate = remain
            with self.assertRaises(private.PrivateAdbError): self.server.close()
            self.assertFalse(self.runtime.processes[0].closed)
            self.assertTrue(self.server.cleanup_obligations)
            self.runtime.after_terminate, self.runtime.rows = None, ()
            self.server.close()
            self.clean()

    def test_failed_socket_close_is_recorded_and_retryable(self):
        self.start()
        self.runtime.close_fails = True
        with self.assertRaisesRegex(private.PrivateAdbError, "cleanup incomplete"): self.run_command()
        self.assertEqual(self.server.cleanup_obligations[0].role, "connection")
        self.assertTrue(self.runtime.processes[0].closed)
        self.runtime.close_fails = False
        self.server.close()
        self.server.close()
        self.clean()

    def test_windows_launch_adapter_restricts_handles_children_and_window(self):
        runtime = object.__new__(REAL_RUNTIME)
        runtime.k = Kernel()
        argv = ("C:\\reviewed tools\\adb.exe", "-L", "tcp:127.0.0.1:41234", "server", "nodaemon")
        process = runtime.spawn_suspended(argv, {"SystemRoot": "C:\\Windows"}, "C:\\reviewed tools")
        self.assertEqual(runtime.k.attributes, [(0x20002, (102, 103)), (0x2000e, 1)])
        app, command, flags, environment, stdin, stdout, stderr, show = runtime.k.created[0]
        self.assertEqual(app, argv[0])
        self.assertTrue(command.startswith('"C:\\reviewed tools\\adb.exe" '))
        self.assertEqual(flags, 0x4 | 0x8000000 | 0x80000 | 0x400)
        self.assertEqual((stdin, stdout, stderr, show), (103, 102, 102, 0))
        self.assertIn("SystemRoot=C:\\Windows\x00\x00", environment)
        self.assertEqual(runtime.k.closed, [102, 103])
        self.assertEqual((process.handle, process.thread, process.output), (201, 202, 101))

    def test_windows_unsupported_restriction_has_no_launch_fallback(self):
        runtime = object.__new__(REAL_RUNTIME)
        runtime.k = Kernel()
        runtime.k.reject_children = True
        with self.assertRaisesRegex(private.PrivateAdbError, "restrict child processes"):
            runtime.spawn_suspended(("C:\\tools\\adb.exe", "server", "nodaemon"), {}, "C:\\tools")
        self.assertEqual(runtime.k.created, [])
        self.assertCountEqual(runtime.k.closed, [101, 102, 103])

    def test_windows_pipe_allocation_is_bounded(self):
        runtime = object.__new__(REAL_RUNTIME)
        runtime.k = Kernel()
        self.assertEqual(runtime.read(private._WindowsProcess(201, 0, 101, 203), 17), b"x" * 17)

    def test_windows_peer_owner_matches_exact_established_server_side_four_tuple(self):
        runtime = object.__new__(REAL_RUNTIME)
        peer = private.ConnectionTuple("127.0.0.1", 52001, "127.0.0.1", 41234)
        runtime.connection_tuple = lambda connection: peer
        exact = private._TcpRow("127.0.0.1", 41234, "127.0.0.1", 52001, 900, 5)
        for rows in ((replace(exact, remote_port=52002),), (replace(exact, state=2),), (), (exact, exact)):
            runtime._tcp_rows = lambda table, rows=rows: rows
            with self.assertRaisesRegex(private.PrivateAdbError, "no unique owner"): runtime.peer_owner(object())
        runtime._tcp_rows = lambda table: (exact,)
        self.assertEqual(runtime.peer_owner(object()), private.PeerOwner(peer, 900))

    def test_windows_owner_table_adapter_decodes_both_endpoints_and_state(self):
        runtime = object.__new__(REAL_RUNTIME)
        class FakeIP:
            def GetExtendedTcpTable(self, buffer, size, ordered, family, table, reserved):
                if family == private.socket.AF_INET:
                    loopback = int.from_bytes(b"\x7f\0\0\x01", "little")
                    raw = struct.pack("<I6I", 1, 5, loopback, private.socket.htons(41234),
                                      loopback, private.socket.htons(52001), 900)
                else:
                    raw = struct.pack("<I", 0)
                size._obj.value = len(raw)
                if buffer is None: return 122
                ctypes.memmove(buffer, raw, len(raw))
                return 0
        runtime.ip = FakeIP()
        self.assertEqual(runtime._tcp_rows(4),
                         (private._TcpRow("127.0.0.1", 41234, "127.0.0.1", 52001, 900, 5),))

    def test_windows_connect_performs_only_handshake_and_uses_same_socket(self):
        runtime = object.__new__(REAL_RUNTIME)
        runtime.now = lambda: 100.0
        class FakeSocket:
            def __init__(self): self.events = []
            def settimeout(self, value): self.events.append(("timeout", value))
            def connect(self, value): self.events.append(("connect", value))
            def getsockname(self): return ("127.0.0.1", 52001)
            def getpeername(self): return ("127.0.0.1", 41234)
            def fileno(self): return 77
            def send(self, raw): self.events.append(("send", raw)); return len(raw)
            def recv(self, limit): self.events.append(("receive", limit)); return b"X"[:limit]
            def close(self): self.events.append(("close",))
        connection = FakeSocket()
        with patch.object(private.socket, "socket", return_value=connection):
            self.assertIs(runtime.connect(41234, 101.0), connection)
        self.assertEqual(connection.events, [("timeout", 1.0), ("connect", ("127.0.0.1", 41234))])
        self.assertEqual(runtime.connection_tuple(connection),
                         private.ConnectionTuple("127.0.0.1", 52001, "127.0.0.1", 41234))
        self.assertEqual(runtime.send(connection, b"request", 101.0), 7)
        self.assertEqual(runtime.receive(connection, 1, 101.0), b"X")
        runtime.close_connection(connection)
        self.assertEqual(connection.events[-1], ("close",))


if __name__ == "__main__":
    unittest.main()
