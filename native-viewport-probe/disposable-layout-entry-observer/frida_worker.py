"""Killable, bounded Frida RPC worker for the synthetic emulator candidate.

Importing this module never imports Frida or accesses a device. The parent
process must arm the app-owned prearm watchdog before constructing a session.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any


FRIDA_VERSION = "17.9.11"
MAX_BUNDLE = 2_097_152
MAX_LINE = 65_536
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
PID_RE = re.compile(r"[1-9][0-9]{0,9}\Z")
OPS = frozenset({"arm", "snapshot", "disarm", "unload", "detach"})


class WorkerError(RuntimeError):
    """Only fixed protocol codes leave this boundary."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise WorkerError(code)


def _json_line(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    need(len(raw) <= MAX_LINE, "WORKER_FRAME_OVERSIZE")
    return raw


def _decode_line(raw: bytes) -> dict[str, Any]:
    need(type(raw) is bytes and 1 < len(raw) <= MAX_LINE and raw.endswith(b"\n") and
         raw.count(b"\n") == 1, "WORKER_FRAME_INVALID")
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise WorkerError("WORKER_FRAME_INVALID") from error
    need(type(value) is dict, "WORKER_FRAME_INVALID")
    return value


def _verified_bundle(path: Path, digest: str) -> bytes:
    need(type(digest) is str and SHA_RE.fullmatch(digest) is not None and
         path.is_file() and not path.is_symlink(), "WORKER_BUNDLE_INVALID")
    try: raw = path.read_bytes()
    except OSError as error: raise WorkerError("WORKER_BUNDLE_INVALID") from error
    need(0 < len(raw) <= MAX_BUNDLE and hashlib.sha256(raw).hexdigest() == digest,
         "WORKER_BUNDLE_INVALID")
    return raw


class WorkerHook:
    def __init__(self, owner: "WorkerSession") -> None:
        self.owner = owner

    def arm(self, config: dict[str, Any]) -> dict[str, Any]:
        return self.owner.exchange("arm", config, timeout=3.0)

    def snapshot(self) -> dict[str, Any]:
        return self.owner.exchange("snapshot", None, timeout=2.0)

    def disarm(self) -> dict[str, Any]:
        return self.owner.exchange("disarm", None, timeout=2.0)

    def unload(self) -> None:
        self.owner.exchange("unload", None, timeout=2.0)


class WorkerSession:
    """One child process; any timeout kills only this host worker.

    The app-owned watchdog/abort separately kills its exact app incarnation.
    Killing the worker alone never counts as a successful hook cleanup.
    """

    def __init__(self, python: Path, frida_site: Path, bundle: Path,
                 bundle_sha256: str, pid: int, *,
                 deadline_monotonic: float | None = None,
                 popen=subprocess.Popen) -> None:
        need(type(pid) is int and PID_RE.fullmatch(str(pid)) is not None and
             python.is_file() and frida_site.is_dir(), "WORKER_INPUT_INVALID")
        _verified_bundle(bundle, bundle_sha256)
        self.hook = WorkerHook(self)
        self._deadline = deadline_monotonic
        self._sequence = 0
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=4)
        self._closed = False
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            self._process = popen(
                [str(python), str(Path(__file__).resolve()), "__worker",
                 str(pid), str(frida_site), str(bundle), bundle_sha256],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, shell=False,
                creationflags=flags)
            need(self._process.stdin is not None and self._process.stdout is not None,
                 "WORKER_PIPE_INVALID")
            self._reader = threading.Thread(target=self._read, daemon=True)
            self._reader.start()
            ready = self._next(4.0)
            need(ready == {"event": "ready", "pid": pid}, "WORKER_READY_INVALID")
        except BaseException as error:
            self.kill_worker()
            raise WorkerError("WORKER_START_FAILED") from error

    def _read(self) -> None:
        try:
            assert self._process.stdout is not None
            while True:
                raw = self._process.stdout.readline(MAX_LINE + 1)
                if not raw:
                    self._queue.put_nowait(b"")
                    return
                try: self._queue.put_nowait(raw)
                except queue.Full: return
                if len(raw) > MAX_LINE: return
        except BaseException:
            try: self._queue.put_nowait(b"")
            except queue.Full: pass

    def _next(self, timeout: float) -> dict[str, Any]:
        need(0 < timeout <= 4.0, "WORKER_TIMEOUT_INVALID")
        if self._deadline is not None:
            timeout = min(timeout, self._deadline - time.monotonic() - 0.75)
            if timeout <= 0:
                self.kill_worker()
                raise WorkerError("WORKER_LEASE_EXPIRED")
        try: raw = self._queue.get(timeout=timeout)
        except queue.Empty as error:
            self.kill_worker()
            raise WorkerError("WORKER_TIMEOUT") from error
        if not raw:
            self.kill_worker()
            raise WorkerError("WORKER_EXITED")
        try: return _decode_line(raw)
        except WorkerError:
            self.kill_worker()
            raise

    def exchange(self, op: str, value: Any, *, timeout: float) -> dict[str, Any]:
        need(not self._closed and op in OPS, "WORKER_OPERATION_INVALID")
        if self._deadline is not None and time.monotonic() + 0.75 >= self._deadline:
            self.kill_worker()
            raise WorkerError("WORKER_LEASE_EXPIRED")
        self._sequence += 1
        seq = self._sequence
        request = _json_line({"seq": seq, "op": op, "value": value})
        try:
            assert self._process.stdin is not None
            self._process.stdin.write(request)
            self._process.stdin.flush()
        except BaseException as error:
            self.kill_worker()
            raise WorkerError("WORKER_SEND_FAILED") from error
        frame = self._next(timeout)
        if not (set(frame) == {"seq", "ok", "value"} and frame["seq"] == seq and
                frame["ok"] is True and type(frame["value"]) is dict):
            self.kill_worker()
            raise WorkerError("WORKER_RESPONSE_INVALID")
        return frame["value"]

    def detach(self) -> None:
        self.exchange("detach", None, timeout=2.0)
        self._closed = True
        try: self._process.wait(timeout=2.0)
        except BaseException as error:
            self.kill_worker()
            raise WorkerError("WORKER_EXIT_UNCERTAIN") from error
        need(self._process.returncode == 0, "WORKER_EXIT_UNCERTAIN")

    def kill_worker(self) -> None:
        self._closed = True
        process = getattr(self, "_process", None)
        if process is not None:
            try:
                if process.poll() is None: process.kill()
                process.wait(timeout=1.0)
            except BaseException: pass


def _child(pid: int, frida_site: Path, bundle: Path, digest: str) -> int:
    raw = _verified_bundle(bundle, digest)
    sys.path.insert(0, str(frida_site))
    try:
        import frida  # type: ignore[import-not-found]
        need(importlib.metadata.version("frida") == FRIDA_VERSION,
             "WORKER_FRIDA_VERSION_INVALID")
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        session = device.attach(pid)
        script = session.create_script(raw.decode("utf-8", "strict"))
        poisoned = [False]
        script.on("message", lambda _message, _data: poisoned.__setitem__(0, True))
        script.load()
    except BaseException:
        return 2
    sys.stdout.buffer.write(_json_line({"event": "ready", "pid": pid}))
    sys.stdout.buffer.flush()
    unloaded = detached = False
    for line in sys.stdin.buffer:
        request: dict[str, Any] | None = None
        try:
            request = _decode_line(line)
            need(set(request) == {"seq", "op", "value"} and
                 type(request["seq"]) is int and request["seq"] > 0 and
                 request["op"] in OPS and not poisoned[0],
                 "WORKER_REQUEST_INVALID")
            op, value = request["op"], request["value"]
            if op == "arm":
                need(type(value) is dict and not unloaded, "WORKER_REQUEST_INVALID")
                result = script.exports_sync.arm(value)
            elif op == "snapshot":
                need(value is None and not unloaded, "WORKER_REQUEST_INVALID")
                result = script.exports_sync.snapshot()
            elif op == "disarm":
                need(value is None and not unloaded, "WORKER_REQUEST_INVALID")
                result = script.exports_sync.disarm()
            elif op == "unload":
                need(value is None and not unloaded, "WORKER_REQUEST_INVALID")
                script.unload()
                unloaded = True
                result = {"unloaded": True}
            else:
                need(value is None and unloaded and not detached,
                     "WORKER_REQUEST_INVALID")
                session.detach()
                detached = True
                result = {"detached": True}
            need(type(result) is dict and not poisoned[0], "WORKER_RESULT_INVALID")
            reply = {"seq": request["seq"], "ok": True, "value": result}
        except BaseException:
            reply = {"seq": request.get("seq", -1) if request is not None else -1,
                     "ok": False, "value": {"code": "WORKER_OPERATION_FAILED"}}
        sys.stdout.buffer.write(_json_line(reply))
        sys.stdout.buffer.flush()
        if detached or reply["ok"] is False: break
    return 0 if detached else 2


if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        need(len(args) == 5 and args[0] == "__worker" and
             PID_RE.fullmatch(args[1]) is not None, "WORKER_INPUT_INVALID")
        status = _child(int(args[1]), Path(args[2]), Path(args[3]), args[4])
    except BaseException:
        status = 2
    raise SystemExit(status)
