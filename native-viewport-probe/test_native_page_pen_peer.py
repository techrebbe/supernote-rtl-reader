"""Offline protocol-edge tests. No device, shell, network, or process cleanup."""
import unittest
import hashlib
import os
import re
from pathlib import Path
import select
import subprocess
import tempfile

from native_page_pen_peer import (
    BeforeAbsenceProof, CaptureLease, ClosureProof, FinalAbsenceProof, Lifecycle,
    PeerError, PenPeer, ProcessIdentity, StageSession,
)

STAGE = StageSession("a" * 64)
TOKEN = "b" * 64
BEFORE = BeforeAbsenceProof(STAGE, "c" * 64)
FINAL = FinalAbsenceProof(STAGE, TOKEN, "d" * 64)


def frozen_lease_terminal_fixture():
    """Independent wire oracle: hash the exact frozen lease, not broker source."""
    data = Path(__file__).with_name("native").joinpath("pen_input_lease.c").read_bytes()
    if hashlib.sha256(data).hexdigest() != "f45aa5daf9ab8126e66fdb60dc27da9402adc56157b8ee5849f1b069558ba9ef":
        raise AssertionError("Frozen lease source changed; fixture authority requires review")
    source = data.decode("utf-8")
    reasons = re.findall(r'case\s+PEN_INPUT_LEASE_END_RELEASE\s*:\s*return\s+"([a-z_]+)"\s*;', source)
    formats = [literal for literal in re.findall(r'"(PEN_INPUT_LEASE_RELEASED token=[^"\r\n]+)"', source)
               if "guardian_session=%s" in literal]
    if len(reasons) != 1 or len(formats) != 1:
        raise AssertionError("Ambiguous frozen public terminal formatter")
    terminal = bytes(formats[0], "ascii").decode("unicode_escape")
    return (reasons[0] + "\n" + terminal).encode("ascii")


class FakeTransport:
    peer_identity = ProcessIdentity(100, 1000)

    def __init__(self):
        self.commands = []
        self.retained = []
        self.mutate = lambda record: record
        self.now = 10000
        self.sequence = 0
        self.fail = False
        self.waits = 0
        self.closure = ClosureProof(self.peer_identity, 0, True, b"")

    def exchange(self, command):
        self.commands.append(command)
        if self.fail:
            raise OSError("Unavailable status")
        self.sequence += 1
        self.now += 1
        if command.startswith(b"ACQUIRE "):
            kind, proof, closed = "ACQUIRED", BEFORE.sha256, "false"
        elif command.startswith(b"CAPTURE "):
            kind, proof, closed = "CAPTURED", "0" * 64, "false"
        elif command.startswith(b"FINISH "):
            kind, proof, closed = "RELEASED", FINAL.sha256, "true"
        else:
            raise AssertionError(command)
        line = (
            f"PEN_PAGE_PEER {kind} stage_session={STAGE.value} sequence={self.sequence} "
            f"token={TOKEN} peer_pid=100 peer_starttime=1000 worker_pid=101 worker_starttime=1001 "
            f"guardian_pid=102 guardian_starttime=1002 guardian_session={'e' * 64} "
            f"deviceClockDomain=android-boottime-v1 deadline_boottime_ms=20000 "
            f"device_boottime_ms={self.now} proof_sha256={proof} "
            f"worker_closed={closed} guardian_closed={closed}\n"
        ).encode()
        return self.mutate(line)

    def wait_exact_peer_closed(self):
        self.waits += 1
        return self.closure

    def retain_quarantine(self, command):
        self.retained.append(command)


class PeerTests(unittest.TestCase):
    def fixture(self, acquired=False, captured=False):
        transport = FakeTransport()
        peer = PenPeer(transport, STAGE, TOKEN, 10000)
        if acquired or captured:
            peer.acquire(BEFORE)
        if captured:
            peer.capture_lease(STAGE)
        return peer, transport

    def assert_quarantined(self, peer, transport, operation):
        with self.assertRaises(PeerError):
            operation()
        self.assertEqual(peer.state, Lifecycle.QUARANTINED)
        self.assertIs(peer.transport, transport)
        self.assertTrue(transport.retained)
        self.assertTrue(all(c == f"QUARANTINE stage_session={STAGE.value}\n".encode()
                            for c in transport.retained))

    def test_success_exact_receipts_and_peer_closure(self):
        peer, transport = self.fixture()
        acquired = peer.acquire(BEFORE)
        self.assertIsInstance(acquired, CaptureLease)
        self.assertEqual(acquired.remaining_ms, 9999)
        capture = peer.capture_lease(STAGE)
        self.assertEqual(capture.remaining_ms, 9998)
        self.assertEqual(capture.binding, acquired.binding)
        self.assertEqual(peer.finish(FINAL), transport.closure)
        self.assertEqual(peer.state, Lifecycle.RELEASED)
        self.assertEqual(transport.waits, 1)
        self.assertFalse(transport.retained)
        self.assertFalse(hasattr(peer, "close"))
        self.assertFalse(hasattr(peer, "__del__"))

    @unittest.skipUnless(os.environ.get("NATIVE_PAGE_PEN_PEER_BINARY"), "Native fake-ELF integration not requested")
    def test_real_broker_launch_and_sealed_peer_handshake(self):
        binary = Path(os.environ["NATIVE_PAGE_PEN_PEER_BINARY"]).resolve(strict=True)
        fake_elf = Path(os.environ["NATIVE_PAGE_PEN_PEER_FAKE_ELF"]).resolve(strict=True)

        class OfflineProcessTransport:
            def __init__(self, process):
                self.process = process
                fields = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
                self.peer_identity = ProcessIdentity(process.pid, int(fields[19]))
                self.retained = False

            def exchange(self, command):
                assert os.write(self.process.stdin.fileno(), command) == len(command)
                # A test transport availability bound, never a lease-time sample.
                assert select.select([self.process.stdout], [], [], 3)[0], "broker status unavailable"
                return os.read(self.process.stdout.fileno(), 2048)

            def wait_exact_peer_closed(self):
                code = self.process.wait(timeout=3)
                trailing = self.process.stdout.read()
                return ClosureProof(self.peer_identity, code, True, trailing)

            def retain_quarantine(self, command):
                self.retained = True
                try:
                    os.write(self.process.stdin.fileno(), command)
                except OSError:
                    pass

        with tempfile.TemporaryDirectory(dir="build/native-page-pen-peer") as temp:
            authority = Path(temp, "authority").resolve()
            fixture = frozen_lease_terminal_fixture()
            authority.write_bytes(fixture)
            process = subprocess.Popen([
                str(binary), "--lease", str(fake_elf), "--lease-sha256", hashlib.sha256(fake_elf.read_bytes()).hexdigest(),
                "--authority", str(authority), "--authority-sha256", hashlib.sha256(fixture).hexdigest(),
                "--token", TOKEN, "--stage-session", STAGE.value, "--hold-ms", "2000",
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                transport = OfflineProcessTransport(process)
                peer = PenPeer(transport, STAGE, TOKEN, 2000)
                peer.acquire(BEFORE)
                self.assertGreater(peer.capture_lease(STAGE).remaining_ms, 0)
                peer.finish(FINAL)
                self.assertEqual(peer.state, Lifecycle.RELEASED)
                self.assertFalse(transport.retained)
                self.assertEqual(process.stderr.read(), b"")
            finally:
                # Test-only recovery targets only this Popen-owned fake broker;
                # fake worker/guardian expire themselves, with no evdev/grab.
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()
    def test_every_acquire_receipt_edge_fails_closed(self):
        mutations = [
            lambda r: b"", lambda r: r[:-1], lambda r: r + b"x", lambda r: r + r,
            lambda r: r.replace(b"\n", b"\r\n"), lambda r: r.replace(b"peer_pid=100", b"peer_pid=0100"),
            lambda r: r.replace(b"worker_pid=101", b"worker_pid=100"),
            lambda r: r.replace(b"guardian_pid=102", b"guardian_pid=1"),
            lambda r: r.replace(b"guardian_starttime=1002", b"guardian_starttime=0"),
            lambda r: r.replace(b"guardian_starttime=1002", b"guardian_starttime=18446744073709551616"),
            lambda r: r.replace(b"guardian_session=" + b"e" * 64, b"guardian_session=" + b"E" * 64),
            lambda r: r.replace(b"stage_session=" + b"a" * 64, b"stage_session=" + b"f" * 64),
            lambda r: r.replace(b"sequence=1", b"sequence=2"),
            lambda r: r.replace(b"android-boottime-v1", b"host-monotonic-v1"),
            lambda r: r.replace(b"device_boottime_ms=10001", b"device_boottime_ms=20000"),
            lambda r: r.replace(b"deadline_boottime_ms=20000", b"deadline_boottime_ms=999999"),
            lambda r: r.replace(b"worker_closed=false", b"worker_closed=true"),
            lambda r: r.replace(b"proof_sha256=" + b"c" * 64, b"proof_sha256=" + b"d" * 64),
            lambda r: r.replace(b" peer_pid=", b" unknown=bad peer_pid="),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(edge=index):
                peer, transport = self.fixture()
                transport.mutate = mutation
                self.assert_quarantined(peer, transport, lambda: peer.acquire(BEFORE))

    def test_suspend_and_backwards_clock(self):
        for now in (30000, 9000):
            peer, transport = self.fixture(acquired=True)
            transport.now = now
            self.assert_quarantined(peer, transport, lambda: peer.capture_lease(STAGE))

    def test_host_clock_not_an_input(self):
        peer, transport = self.fixture(acquired=True)
        with self.assertRaises(TypeError):
            peer.capture_lease(STAGE, host_monotonic_ms=10000)
        capture = peer.capture_lease(STAGE)
        self.assertEqual(capture.remaining_ms, 20000 - capture.device_boottime_ms)
        self.assertFalse(transport.retained)

    def test_binding_change_or_replay_at_capture(self):
        for old, new in ((b"worker_starttime=1001", b"worker_starttime=1003"),
                         (b"guardian_pid=102", b"guardian_pid=103"),
                         (b"deadline_boottime_ms=20000", b"deadline_boottime_ms=20001"),
                         (b"sequence=2", b"sequence=1")):
            peer, transport = self.fixture(acquired=True)
            transport.mutate = lambda r, old=old, new=new: r.replace(old, new)
            self.assert_quarantined(peer, transport, lambda: peer.capture_lease(STAGE))

    def test_status_hup_failed_release_or_trailing_terminal_unknown(self):
        for mutation in (lambda r: b"", lambda r: r.replace(b"RELEASED", b"FAILED"),
                         lambda r: r + r, lambda r: r[:-1],
                         lambda r: r.replace(b"worker_closed=true", b"worker_closed=false"),
                         lambda r: r.replace(b"guardian_closed=true", b"guardian_closed=false")):
            peer, transport = self.fixture(captured=True)
            transport.mutate = mutation
            self.assert_quarantined(peer, transport, lambda: peer.finish(FINAL))
            self.assertEqual(transport.waits, 0)

    def test_exact_peer_closure_required_after_released(self):
        closures = [ClosureProof(ProcessIdentity(100, 999), 0, True, b""),
                    ClosureProof(FakeTransport.peer_identity, 1, True, b""),
                    ClosureProof(FakeTransport.peer_identity, 0, False, b""),
                    ClosureProof(FakeTransport.peer_identity, 0, True, b"replay\n")]
        for closure in closures:
            peer, transport = self.fixture(captured=True)
            transport.closure = closure
            self.assert_quarantined(peer, transport, lambda: peer.finish(FINAL))

    def test_transport_peer_reconnect_during_wait_is_not_closure(self):
        for replace_closure in (False, True):
            peer, transport = self.fixture(captured=True)
            original = peer.binding.peer

            def swapped_wait():
                transport.peer_identity = ProcessIdentity(200, 2000)
                return ClosureProof(transport.peer_identity if replace_closure else original,
                                    0, True, b"")

            transport.wait_exact_peer_closed = swapped_wait
            self.assert_quarantined(peer, transport, lambda: peer.finish(FINAL))
            self.assertEqual(peer.binding.peer, original)

    def test_transport_identity_is_fixed_at_construction(self):
        peer, transport = self.fixture()
        transport.peer_identity = ProcessIdentity(200, 2000)
        self.assert_quarantined(peer, transport, lambda: peer.acquire(BEFORE))
        self.assertFalse(transport.commands)

    def test_invalid_lifecycle_absence_proof_or_session(self):
        cases = [lambda p: p.capture_lease(STAGE), lambda p: p.finish(FINAL),
                 lambda p: p.acquire(BeforeAbsenceProof(StageSession("f" * 64), "c" * 64)),
                 lambda p: p.acquire(True)]
        for operation in cases:
            peer, transport = self.fixture()
            self.assert_quarantined(peer, transport, lambda: operation(peer))
        peer, transport = self.fixture(captured=True)
        self.assert_quarantined(peer, transport,
                                lambda: peer.finish(FinalAbsenceProof(STAGE, "f" * 64, "d" * 64)))

    def test_transport_loss_retains_quarantine_at_every_edge(self):
        for stage in range(3):
            peer, transport = self.fixture(acquired=stage == 1, captured=stage == 2)
            transport.fail = True
            operation = (lambda: peer.acquire(BEFORE)) if stage == 0 else (
                (lambda: peer.capture_lease(STAGE)) if stage == 1 else lambda: peer.finish(FINAL))
            self.assert_quarantined(peer, transport, operation)
            self.assertEqual(transport.waits, 0)

    def test_repeated_acquire_quarantines_and_release_cannot_be_reused(self):
        peer, transport = self.fixture(acquired=True)
        self.assert_quarantined(peer, transport, lambda: peer.acquire(BEFORE))
        peer, transport = self.fixture(captured=True)
        peer.finish(FINAL)
        with self.assertRaises(PeerError):
            peer.capture_lease(STAGE)
        self.assertEqual(peer.state, Lifecycle.RELEASED)


if __name__ == "__main__":
    unittest.main()
