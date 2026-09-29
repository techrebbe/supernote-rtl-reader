"""Mock worker-pipe tests; no Frida import, ADB, or device access."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frida_worker as subject


class FakeOut:
    def __init__(self) -> None:
        self.lines: queue.Queue[bytes] = queue.Queue()

    def readline(self, _maximum: int) -> bytes:
        return self.lines.get(timeout=5)


class FakeIn:
    def __init__(self, process: "FakeProcess") -> None:
        self.process = process

    def write(self, raw: bytes) -> None:
        request = json.loads(raw)
        self.process.requests.append(request)
        if self.process.timeout_next:
            self.process.timeout_next = False
            return
        if self.process.bad_next:
            self.process.bad_next = False
            self.process.stdout.lines.put(b'{"wrong":true}\n')
            return
        op = request["op"]
        if op == "unload": value = {"unloaded": True}
        elif op == "detach": value = {"detached": True}
        elif op == "arm": value = {"ok": True, "phase": "ARMED"}
        elif op == "disarm": value = {"ok": True, "phase": "DISARMED"}
        else: value = {"phase": "ARMED"}
        frame = {"seq": request["seq"], "ok": True, "value": value}
        self.process.stdout.lines.put(subject._json_line(frame))

    def flush(self) -> None: pass


class FakeProcess:
    def __init__(self, args: list[str], **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs
        self.stdout = FakeOut()
        self.stdin = FakeIn(self)
        self.requests: list[dict] = []
        self.timeout_next = False
        self.bad_next = False
        self.killed = False
        self.returncode = None
        self.stdout.lines.put(subject._json_line({"event": "ready", "pid": int(args[3])}))

    def poll(self): return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.stdout.lines.put(b"")

    def wait(self, timeout: float) -> int:
        if self.returncode is None: self.returncode = 0
        return self.returncode


class WorkerTests(unittest.TestCase):
    def make(self):
        created = []
        def popen(args, **kwargs):
            process = FakeProcess(args, **kwargs)
            created.append(process)
            return process
        source = Path(__file__).with_name("layout_entry_observer.js")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        session = subject.WorkerSession(Path(sys.executable), source.parent,
                                        source, digest, 2468, popen=popen)
        return session, created[0]

    def test_bounded_lifecycle(self) -> None:
        session, process = self.make()
        self.assertEqual(session.hook.arm({"pid": 2468})["phase"], "ARMED")
        self.assertEqual(session.hook.snapshot()["phase"], "ARMED")
        self.assertEqual(session.hook.disarm()["phase"], "DISARMED")
        session.hook.unload()
        session.detach()
        self.assertEqual([request["op"] for request in process.requests],
                         ["arm", "snapshot", "disarm", "unload", "detach"])
        self.assertFalse(process.killed)
        self.assertTrue(all(request["seq"] == index
                            for index, request in enumerate(process.requests, 1)))

    def test_missing_reply_kills_only_worker(self) -> None:
        session, process = self.make()
        process.timeout_next = True
        with self.assertRaisesRegex(subject.WorkerError, "WORKER_TIMEOUT"):
            session.exchange("arm", {"pid": 2468}, timeout=0.01)
        self.assertTrue(process.killed)

    def test_malformed_reply_kills_worker(self) -> None:
        session, process = self.make()
        process.bad_next = True
        with self.assertRaisesRegex(subject.WorkerError, "WORKER_RESPONSE_INVALID"):
            session.hook.snapshot()
        self.assertTrue(process.killed)

    def test_bad_bundle_does_not_spawn(self) -> None:
        source = Path(__file__).with_name("layout_entry_observer.js")
        calls = []
        with self.assertRaisesRegex(subject.WorkerError, "WORKER_BUNDLE_INVALID"):
            subject.WorkerSession(Path(sys.executable), source.parent,
                                  source, "0" * 64, 2468,
                                  popen=lambda *a, **kw: calls.append((a, kw)))
        self.assertEqual(calls, [])

    def test_subprocess_exit_status_matches_clean_and_failed_child(self) -> None:
        # Exercise the actual __main__ footer without importing real Frida or
        # contacting its remote server. The fake module stays in this temp site.
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            (site / "frida.py").write_text(
                "class Script:\n"
                "    def on(self, *args): pass\n"
                "    def load(self): pass\n"
                "    def unload(self): pass\n"
                "class Session:\n"
                "    def create_script(self, source): return Script()\n"
                "    def detach(self): pass\n"
                "class Device:\n"
                "    def attach(self, pid): return Session()\n"
                "class Manager:\n"
                "    def add_remote_device(self, address): return Device()\n"
                "def get_device_manager(): return Manager()\n",
                encoding="utf-8")
            distribution = site / "frida-17.9.11.dist-info"
            distribution.mkdir()
            (distribution / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: frida\nVersion: 17.9.11\n",
                encoding="utf-8")
            bundle = site / "inert-bundle.js"
            bundle.write_text("// fake Frida never evaluates this bundle\n",
                              encoding="utf-8")
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            command = [sys.executable, "-B", str(Path(subject.__file__).resolve()),
                       "__worker", "2468", str(site), str(bundle), digest]

            def run(requests: list[dict]) -> tuple[int, list[dict], bytes]:
                payload = b"".join(subject._json_line(request)
                                   for request in requests)
                completed = subprocess.run(
                    command, input=payload, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=10, check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                frames = [json.loads(line) for line in completed.stdout.splitlines()]
                return completed.returncode, frames, completed.stderr

            status, frames, stderr = run([
                {"seq": 1, "op": "unload", "value": None},
                {"seq": 2, "op": "detach", "value": None},
            ])
            self.assertEqual(status, 0)
            self.assertEqual(frames, [
                {"event": "ready", "pid": 2468},
                {"seq": 1, "ok": True, "value": {"unloaded": True}},
                {"seq": 2, "ok": True, "value": {"detached": True}},
            ])
            self.assertEqual(stderr, b"")

            status, frames, stderr = run([
                {"seq": 1, "op": "invalid", "value": None},
            ])
            self.assertEqual(status, 2)
            self.assertEqual(frames, [
                {"event": "ready", "pid": 2468},
                {"seq": 1, "ok": False,
                 "value": {"code": "WORKER_OPERATION_FAILED"}},
            ])
            self.assertEqual(stderr, b"")


if __name__ == "__main__":
    unittest.main()
