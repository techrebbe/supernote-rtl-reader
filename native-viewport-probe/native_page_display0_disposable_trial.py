"""Alpha-only, one-use stock-reader identity trial on the fixed disposable PDF.

This is deliberately separate from the virtual-display admission runner. It may
briefly interrupt the native reader. A positive observation is *not* permission
to change a page, pen state, document, or annotation. No diagnostic raw dumps
are retained or printed. Run --preflight-only first; --run is explicit and
never retried automatically.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import time
from typing import Callable

import native_page_display0_one_shot as one_shot
import native_page_display0_bundle as bundle
import native_page_display0_stock_dialect as stock
import native_page_graph_v2_runner as graph


SERIAL = "SN078C10015092"
FINGERPRINT = graph.FIRMWARE_FINGERPRINT
PDF = "/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf"
URI = "file://" + PDF
PDF_SHA256 = "28b126627dd5966e8975ae1bf48385d65e1f8189e8aa32ddc0eab778904859c9"
SERVER = "/data/local/tmp/frida-server-17.9.11-android-arm64"
SERVER_SHA256 = "67896db6191bc65af8ddc218c26a00d9c06fb4456db6104d55aebd04a99ff731"
ADB = Path(r"C:\Users\mmkap\AppData\Local\Android\Sdk\platform-tools\adb.exe")
FRIDA_SITE = Path(__file__).resolve().parents[3] / "local-python" / "frida-17.9.11"
OBSERVER = Path(__file__).with_name("native_page_display0_identity_observer.js")
MAX_OUTPUT = 2_097_152
PORT = "tcp:27042"
PID_RE = re.compile(rb"[1-9][0-9]{0,6}\Z")
STAT_RE = re.compile(rb"[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-fA-F]+\Z")
CHILD_FAILURE_CODES = frozenset({
    "FRIDA_CHILD_INPUT_INVALID", "FRIDA_CHILD_HOST_SETUP_FAILED",
    "FRIDA_CHILD_CONNECT_FAILED", "FRIDA_CHILD_ATTACH_FAILED",
    "FRIDA_CHILD_SCRIPT_FAILED", "FRIDA_CHILD_LOAD_FAILED",
    "FRIDA_CHILD_WAIT_TIMEOUT", "FRIDA_CHILD_FRAME_REJECTED",
    "FRIDA_CHILD_OBSERVER_REJECTED", "FRIDA_CHILD_UNLOAD_FAILED",
    "FRIDA_CHILD_DETACH_FAILED", "FRIDA_CHILD_FAILED",
    "FRIDA_CHILD_BUNDLE_INVALID",
})


class TrialError(RuntimeError):
    """Only fixed, path-free diagnostic codes are exposed to the caller."""


@dataclass(frozen=True)
class Snapshot:
    pid: int
    start_ticks: str
    boot_id: str
    activity: bytes
    window: bytes
    pdf_stat: bytes


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise TrialError(code)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _start_ticks(stat_raw: bytes, pid: int) -> str:
    """Linux /proc/PID/stat field 22, after the final parenthesized comm."""
    _need(type(stat_raw) is bytes and 0 < len(stat_raw) < 8192, "PROCESS_STAT_INVALID")
    prefix = str(pid).encode("ascii") + b" ("
    _need(stat_raw.startswith(prefix), "PROCESS_PID_CHANGED")
    closing = stat_raw.rfind(b") ")
    _need(closing > len(prefix) and b"\n" not in stat_raw[:closing],
          "PROCESS_STAT_INVALID")
    fields = stat_raw[closing + 2:].strip().split()
    _need(len(fields) >= 20 and fields[0] in (b"R", b"S", b"D", b"I"),
          "PROCESS_STAT_INVALID")
    ticks = fields[19]
    _need(re.fullmatch(rb"[1-9][0-9]{0,19}", ticks) is not None,
          "PROCESS_STAT_INVALID")
    return ticks.decode("ascii")


class Backend:
    """The only live adapter. Commands are fixed; no caller-supplied shell text."""

    def adb(self, *args: str, timeout: float = 12.0) -> bytes:
        _need(ADB.is_file(), "ADB_UNAVAILABLE")
        try:
            result = subprocess.run([str(ADB), "-s", SERIAL, *args],
                                    capture_output=True, shell=False, timeout=timeout,
                                    check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TrialError("ADB_COMMAND_FAILED") from error
        _need(result.returncode == 0 and len(result.stdout) <= MAX_OUTPUT and
              len(result.stderr) <= 8192, "ADB_COMMAND_FAILED")
        return result.stdout

    def root(self, command: str, timeout: float = 12.0) -> bytes:
        # Every caller below supplies a literal command or validated PID/tick.
        _need(type(command) is str and command and len(command) <= 512 and
              all(0x20 <= ord(char) <= 0x7e for char in command),
              "ROOT_COMMAND_INVALID")
        # Single quoting is important: the outer Android shell must NOT
        # consume $! from the root shell's exact-server PID announcement.
        return self.adb("shell", "su -c " + shlex.quote(command), timeout=timeout)

    def child(self, pid: int, manifest: bytes, timeout: float) -> tuple[bytes, bytes]:
        encoded = base64.urlsafe_b64encode(manifest).decode("ascii")
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "__child", str(pid), encoded],
                capture_output=True, shell=False, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            # subprocess.run kills and waits for its exact child on timeout.
            raise TrialError("FRIDA_CHILD_TIMEOUT") from error
        except OSError as error:
            raise TrialError("FRIDA_CHILD_UNAVAILABLE") from error
        if result.returncode != 0:
            # Never relay arbitrary child stderr: Frida may include private
            # paths or exception details. Only our exact, fixed token travels.
            codes = {code.encode("ascii") + b"\n": code
                     for code in CHILD_FAILURE_CODES}
            if result.returncode == 2 and not result.stdout and result.stderr in codes:
                raise TrialError(codes[result.stderr])
            raise TrialError("FRIDA_CHILD_FAILED")
        _need(len(result.stdout) <= 8192 and not result.stderr, "FRIDA_CHILD_FAILED")
        try:
            frame_lines = result.stdout.splitlines()
            _need(len(frame_lines) == 2, "FRIDA_FRAME_COUNT")
            return tuple(base64.b64decode(line, validate=True)
                         for line in frame_lines)  # type: ignore[return-value]
        except (ValueError, TypeError) as error:
            raise TrialError("FRIDA_FRAME_INVALID") from error


def _forward_entries(backend: Backend) -> list[list[str]]:
    try:
        lines = backend.adb("forward", "--list").decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise TrialError("FRIDA_FORWARD_INVALID") from error
    entries = [line.split() for line in lines if line.strip()]
    _need(all(len(entry) == 3 for entry in entries), "FRIDA_FORWARD_INVALID")
    return entries


def _forward_absent(backend: Backend) -> None:
    _need(not any(entry[1] == PORT for entry in _forward_entries(backend)),
          "FRIDA_FORWARD_PRESENT")


def _owned_forward(backend: Backend) -> None:
    relevant = [entry for entry in _forward_entries(backend) if entry[1] == PORT]
    _need(relevant == [[SERIAL, PORT, PORT]], "FRIDA_FORWARD_CHANGED")


def _server_absent(backend: Backend) -> None:
    ps = backend.root("ps -A -o PID,ARGS")
    _need(b"frida-server" not in ps, "FRIDA_SERVER_PRESENT")
    listening = backend.root("ss -ltn")
    _need(not re.search(rb"(?:^|[\s:])27042(?:\s|$)", listening),
          "FRIDA_PORT_PRESENT")


def _file_stat(backend: Backend) -> bytes:
    raw = backend.adb("shell", "stat", "-c", "%d:%i:%s:%Y:%f", PDF).strip()
    _need(STAT_RE.fullmatch(raw) is not None, "PDF_STAT_INVALID")
    return raw


def _pdf_and_mark(backend: Backend) -> bytes:
    stat_raw = _file_stat(backend)
    digest_raw = backend.adb("shell", "sha256sum", PDF).strip()
    _need(digest_raw == (PDF_SHA256 + "  " + PDF).encode("ascii") or
          digest_raw == (PDF_SHA256 + " " + PDF).encode("ascii"),
          "DISPOSABLE_PDF_CHANGED")
    mark = backend.root("if [ -e " + PDF + ".mark ] || [ -L " + PDF +
                        ".mark ]; then echo PRESENT; else echo ABSENT; fi").strip()
    _need(mark == b"ABSENT", "DISPOSABLE_MARK_PRESENT")
    return stat_raw


def capture(backend: Backend) -> Snapshot:
    _need(backend.adb("get-state").strip() == b"device", "NOMAD_DISCONNECTED")
    _need(backend.adb("shell", "getprop", "ro.build.fingerprint").strip() ==
          FINGERPRINT.encode("ascii"), "FIRMWARE_CHANGED")
    pid_raw = backend.adb("shell", "pidof", "com.supernote.document").strip()
    _need(PID_RE.fullmatch(pid_raw) is not None, "DOCUMENT_PROCESS_AMBIGUOUS")
    pid = int(pid_raw)
    cmdline = backend.root("cat /proc/" + str(pid) + "/cmdline")
    process_name = b"com.supernote.document\x00"
    _need(cmdline.startswith(process_name) and
          all(byte == 0 for byte in cmdline[len(process_name):]),
          "DOCUMENT_PROCESS_CHANGED")
    ticks = _start_ticks(backend.root("cat /proc/" + str(pid) + "/stat"), pid)
    boot_id = backend.adb("shell", "cat", "/proc/sys/kernel/random/boot_id").strip()
    _need(re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                       boot_id) is not None, "BOOT_ID_INVALID")
    activity = backend.adb("shell", "dumpsys", "activity", "activities")
    window = backend.adb("shell", "dumpsys", "window", "windows")
    try:
        stock.validate_stock_dialect(activity, window, activity, window,
                                     expected_pid=pid)
    except stock.StockDialectError as error:
        raise TrialError("STOCK_READER_NOT_FOCUSED") from error
    pdf_stat = _pdf_and_mark(backend)
    _need(backend.adb("shell", "pidof", "com.supernote.document").strip() == pid_raw and
          _start_ticks(backend.root("cat /proc/" + str(pid) + "/stat"), pid) == ticks,
          "DOCUMENT_PROCESS_CHANGED")
    return Snapshot(pid, ticks, boot_id.decode("ascii"), activity, window, pdf_stat)


def _source_and_manifest(before: Snapshot) -> tuple[bytes, bytes]:
    source = OBSERVER.read_bytes()
    _need(_sha(source) == one_shot.OBSERVER_SHA256,
          "OBSERVER_SOURCE_CHANGED")
    value = {
        "schemaVersion": 1,
        "authority": one_shot.MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": "com.supernote.document", "processName": "com.supernote.document",
            "pid": before.pid, "startTimeTicks": before.start_ticks,
            "firmwareFingerprint": FINGERPRINT,
            "observerSha256": one_shot.OBSERVER_SHA256,
        },
        "expected": {"documentUri": URI, "markPath": None},
        "coordinator": {"maxJavaChooseWalks": 1, "retainedRootSamples": 2,
                        "hardDeadlineMs": 5000, "detachOnDeadline": True,
                        "abortOnAnyError": True, "noRetry": True},
    }
    manifest = graph.canonical_bytes(value, 4096)
    _need(all(0x20 <= byte <= 0x7e for byte in manifest), "MANIFEST_INVALID")
    return source, manifest


def _server_identity(backend: Backend, pid: int,
                     *, timeout: float = 12.0) -> str:
    cmdline = backend.root("cat /proc/" + str(pid) + "/cmdline", timeout=timeout)
    _need(cmdline.startswith(SERVER.encode("ascii") + b"\x00") and
          b"127.0.0.1:27042" in cmdline, "FRIDA_SERVER_IDENTITY_CHANGED")
    return _start_ticks(backend.root("cat /proc/" + str(pid) + "/stat",
                                     timeout=timeout), pid)


def _launch_server(backend: Backend) -> int:
    digest = backend.root("sha256sum " + SERVER).strip()
    _need(digest == (SERVER_SHA256 + "  " + SERVER).encode("ascii") or
          digest == (SERVER_SHA256 + " " + SERVER).encode("ascii"),
          "FRIDA_SERVER_IMAGE_CHANGED")
    # The server binary already exists on the approved device. This trial
    # creates no device file. If the PID cannot be captured, cleanup is
    # uncertain and the caller must not claim a pass.
    command = (SERVER + " --listen 127.0.0.1:27042 </dev/null >/dev/null 2>&1"
               " & echo $!")
    pid_raw = backend.root(command, timeout=8).strip()
    _need(PID_RE.fullmatch(pid_raw) is not None, "FRIDA_SERVER_PID_UNKNOWN")
    return int(pid_raw)


def _await_server_ready(backend: Backend, pid: int, ticks: str) -> None:
    """Bounded listener check; never retry or reattach to the reader."""
    deadline = time.monotonic() + 3.0
    for attempt in range(30):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        _need(_server_identity(backend, pid, timeout=min(1.0, remaining)) == ticks,
              "FRIDA_SERVER_IDENTITY_CHANGED")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        listening = backend.root("ss -ltn", timeout=min(1.0, remaining))
        if re.search(rb"(?:^|\s)127\.0\.0\.1:27042(?:\s|$)", listening):
            return
        if attempt < 29:
            time.sleep(0.1)
    raise TrialError("FRIDA_SERVER_READY_TIMEOUT")


def _stop_exact_server(backend: Backend, pid: int, ticks: str) -> None:
    # Never kill a PID whose incarnation differs. This is an alpha trial,
    # not a generalized process-management facility.
    try:
        actual = _server_identity(backend, pid)
    except TrialError:
        # A vanished PID is acceptable only if /proc confirms absence.
        absent = backend.root("if [ -e /proc/" + str(pid) +
                              " ]; then echo PRESENT; else echo ABSENT; fi").strip()
        _need(absent == b"ABSENT", "FRIDA_CLEANUP_UNCERTAIN")
        return
    _need(actual == ticks, "FRIDA_CLEANUP_UNCERTAIN")
    backend.root("kill -TERM " + str(pid))
    for _ in range(10):
        absent = backend.root("if [ -e /proc/" + str(pid) +
                              " ]; then echo PRESENT; else echo ABSENT; fi").strip()
        if absent == b"ABSENT":
            return
        time.sleep(0.1)
    _need(_server_identity(backend, pid) == ticks, "FRIDA_CLEANUP_UNCERTAIN")
    backend.root("kill -KILL " + str(pid))
    absent = backend.root("if [ -e /proc/" + str(pid) +
                          " ]; then echo PRESENT; else echo ABSENT; fi").strip()
    _need(absent == b"ABSENT", "FRIDA_CLEANUP_UNCERTAIN")


def _stable(before: Snapshot, after: Snapshot) -> None:
    _need((before.pid, before.start_ticks, before.boot_id, before.pdf_stat) ==
          (after.pid, after.start_ticks, after.boot_id, after.pdf_stat),
          "PRE_POST_IDENTITY_CHANGED")
    try:
        stock.validate_stock_dialect(before.activity, before.window,
                                     after.activity, after.window,
                                     expected_pid=before.pid)
    except stock.StockDialectError as error:
        raise TrialError("PRE_POST_READER_CHANGED") from error


def preflight(backend: Backend) -> Snapshot:
    _forward_absent(backend)
    _server_absent(backend)
    before = capture(backend)
    _source_and_manifest(before)
    return before


def run_trial(backend: Backend, *, announce: Callable[[str], None] = print) -> dict:
    """One attempt, one attach. Any uncertain cleanup prevents a positive result."""
    before = preflight(backend)
    _, manifest = _source_and_manifest(before)
    # This is deliberately before starting the server: a missing or changed
    # compiler, bridge package, or bundle must not touch the device process.
    try:
        bundle.build_verified_bundle()
    except bundle.BundleError as error:
        raise TrialError("BUNDLE_INVALID") from error
    server_pid: int | None = None
    server_ticks: str | None = None
    forwarded = False
    primary: TrialError | None = None
    cleanup_codes: list[str] = []
    frames: tuple[bytes, bytes] | None = None
    try:
        server_pid = _launch_server(backend)
        server_ticks = _server_identity(backend, server_pid)
        _await_server_ready(backend, server_pid, server_ticks)
        backend.adb("forward", "--no-rebind", PORT, PORT)
        forwarded = True
        _owned_forward(backend)
        frames = backend.child(before.pid, manifest, 8.0)
    except BaseException as error:
        primary = error if type(error) is TrialError else TrialError("TRIAL_RUNTIME_FAILED")
    finally:
        if forwarded:
            try:
                # A concurrent forward replacement is an uncertainty, never a
                # reason to remove someone else's mapping.
                _need([entry for entry in _forward_entries(backend)
                       if entry == [SERIAL, PORT, PORT]] == [[SERIAL, PORT, PORT]],
                      "FRIDA_FORWARD_CHANGED")
                backend.adb("forward", "--remove", PORT)
                _need([entry for entry in _forward_entries(backend)
                       if entry == [SERIAL, PORT, PORT]] == [],
                      "FRIDA_FORWARD_CLEANUP_UNCERTAIN")
            except (TrialError, UnicodeError):
                cleanup_codes.append("FRIDA_FORWARD_CLEANUP_UNCERTAIN")
        if server_pid is not None and server_ticks is not None:
            try:
                _stop_exact_server(backend, server_pid, server_ticks)
                _server_absent(backend)
            except TrialError:
                cleanup_codes.append("FRIDA_SERVER_CLEANUP_UNCERTAIN")
        elif server_pid is not None or primary is not None:
            # If startup failed before a reliable PID was returned, there may
            # be a server left behind; do not silently call that a pass.
            try:
                _server_absent(backend)
            except TrialError:
                cleanup_codes.append("FRIDA_SERVER_CLEANUP_UNCERTAIN")
        if not forwarded:
            try:
                _forward_absent(backend)
            except TrialError:
                cleanup_codes.append("FRIDA_FORWARD_CLEANUP_UNCERTAIN")
    post_error = False
    try:
        after = capture(backend)
        _stable(before, after)
    except BaseException:
        post_error = True
    if cleanup_codes:
        announce("cleanup_uncertain=" + ",".join(cleanup_codes))
        if post_error:
            announce("post_state_uncertain=true")
        raise TrialError("CLEANUP_UNCERTAIN")
    if post_error:
        raise TrialError("POST_STATE_UNCERTAIN")
    if primary is not None:
        raise primary
    _need(frames is not None, "FRIDA_NO_FRAMES")
    try:
        identity = one_shot.parse_identity_frames(
            frames, _sha(manifest), mark_required=False)
    except one_shot.OneShotError as error:
        raise TrialError("IDENTITY_OBSERVER_REJECTED") from error
    return {"trial": "alpha-disposable-only", "observerMatchedUri":
            identity["uriAgreementAndExpectedMatch"],
            "bundleSha256": bundle.BUNDLE_SHA256,
            "readerStable": True, "pdfUnchanged": True, "markAbsent": True,
            "serverRemoved": True, "forwardRemoved": True,
            "hardwareAdmission": False, "mutationAuthorized": False}


class _FrameCollector:
    """Fail-latched Frida callback stream, including late error/extra events."""

    def __init__(self):
        self.frames: list[bytes] = []
        self.failed = False
        self.complete = threading.Event()
        self._lock = threading.Lock()

    def on_message(self, message: dict, data: bytes | None) -> None:
        with self._lock:
            if self.failed:
                return
            if type(message) is not dict or message.get("type") != "send" or data is not None or len(self.frames) >= 2:
                self.failed = True
                self.complete.set()
                return
            try:
                raw = graph.canonical_bytes(message.get("payload"), one_shot.MAX_FRAME_BYTES)
            except graph.GraphRunnerError:
                self.failed = True
                self.complete.set()
                return
            self.frames.append(raw)
            if len(self.frames) == 2:
                self.complete.set()

    def checked_frames(self) -> tuple[bytes, bytes]:
        with self._lock:
            _need(not self.failed and len(self.frames) == 2, "FRIDA_CHILD_INCOMPLETE")
            return self.frames[0], self.frames[1]


def _child(pid: int, manifest: bytes) -> int:
    """Killable host child; output only two canonical, bounded observer frames."""
    _need(PID_RE.fullmatch(str(pid).encode("ascii")) is not None and
          len(manifest) <= 4096, "FRIDA_CHILD_INPUT_INVALID")
    value = graph.load_canonical(manifest, 4096).value
    _need(value["expected"] == {"documentUri": URI, "markPath": None} and
          value["attachment"]["pid"] == pid and
          value["attachment"]["firmwareFingerprint"] == FINGERPRINT,
          "FRIDA_CHILD_INPUT_INVALID")
    try:
        compiled = bundle.load_verified_bundle()
    except bundle.BundleError as error:
        raise TrialError("FRIDA_CHILD_BUNDLE_INVALID") from error
    try:
        sys.path.insert(0, str(FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        _need(importlib.metadata.version("frida") == "17.9.11" and
              callable(getattr(frida, "get_device_manager", None)),
              "FRIDA_CHILD_HOST_SETUP_FAILED")
    except BaseException as error:
        raise TrialError("FRIDA_CHILD_HOST_SETUP_FAILED") from error
    prefix = ("globalThis.NATIVE_PAGE_DISPLAY0_IDENTITY_MANIFEST_UTF8=" +
              json.dumps(list(manifest), separators=(",", ":")) + ";\n" +
              "globalThis.NATIVE_PAGE_DISPLAY0_IDENTITY_MANIFEST_SHA256=" +
              json.dumps(_sha(manifest)) + ";\n")
    collector = _FrameCollector()
    session = None
    script = None

    stage = "CONNECT"
    body_error: TrialError | None = None
    frames: tuple[bytes, bytes] | None = None
    try:
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        stage = "ATTACH"
        session = device.attach(pid)
        stage = "SCRIPT"
        script = session.create_script(prefix + compiled.decode("utf-8", "strict"))
        script.on("message", collector.on_message)
        stage = "LOAD"
        script.load()
        stage = "WAIT"
        if not collector.complete.wait(5.5):
            raise TrialError("FRIDA_CHILD_WAIT_TIMEOUT")
        stage = "FRAME"
        frames = collector.checked_frames()
        try:
            one_shot.parse_identity_frames(frames, _sha(manifest), mark_required=False)
        except one_shot.OneShotError as error:
            # The observer's explicit, path-free failure has a unique pair of
            # canonical frames. Any other malformed framing stays generic.
            try:
                first = graph.load_canonical(frames[0], one_shot.MAX_FRAME_BYTES).value
                second = graph.load_canonical(frames[1], one_shot.MAX_FRAME_BYTES).value
            except BaseException:
                first = second = None
            if first == {"event": "native_page_display0_identity_error",
                          "schemaVersion": 1, "code": "DISPLAY0_IDENTITY_REJECTED"} and \
                    second == {"event": "native_page_display0_identity_complete",
                               "success": False}:
                raise TrialError("FRIDA_CHILD_OBSERVER_REJECTED") from error
            raise TrialError("FRIDA_CHILD_FRAME_REJECTED") from error
    except BaseException as error:
        if type(error) is TrialError and str(error) in CHILD_FAILURE_CODES:
            body_error = error
        else:
            body_error = TrialError("FRIDA_CHILD_" + stage + "_FAILED"
                                    if stage in {"CONNECT", "ATTACH", "SCRIPT", "LOAD"}
                                    else "FRIDA_CHILD_FRAME_REJECTED")
    unload_failed = False
    detach_failed = False
    try:
        if script is not None:
            script.unload()
    except BaseException:
        unload_failed = True
    try:
        if session is not None:
            session.detach()
    except BaseException:
        detach_failed = True
    if detach_failed:
        raise TrialError("FRIDA_CHILD_DETACH_FAILED")
    if unload_failed:
        raise TrialError("FRIDA_CHILD_UNLOAD_FAILED")
    if body_error is not None:
        raise body_error
    # Unload/detach can deliver a final error or extra callback after the two
    # apparent success frames. Retire first, then inspect the latched stream.
    try:
        frames = collector.checked_frames()
    except TrialError as error:
        raise TrialError("FRIDA_CHILD_FRAME_REJECTED") from error
    for raw in frames:
        print(base64.b64encode(raw).decode("ascii"), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "__child":
        try:
            _need(len(args) == 3 and PID_RE.fullmatch(args[1].encode("ascii")) is not None,
                  "FRIDA_CHILD_INPUT_INVALID")
            manifest = base64.urlsafe_b64decode(args[2].encode("ascii"))
            return _child(int(args[1]), manifest)
        except BaseException as error:
            code = str(error) if type(error) is TrialError else "FRIDA_CHILD_FAILED"
            print(code if code in CHILD_FAILURE_CODES else "FRIDA_CHILD_FAILED",
                  file=sys.stderr)
            return 2  # No raw Frida exception or paths on stderr.
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--run", action="store_true")
    parsed = parser.parse_args(args)
    backend = Backend()
    try:
        if parsed.preflight_only:
            preflight(backend)
            try:
                bundle.build_verified_bundle()
            except bundle.BundleError as error:
                raise TrialError("BUNDLE_INVALID") from error
            print("preflight=PASS observation_not_run=true hardwareAdmission=false")
        else:
            print(json.dumps(run_trial(backend), sort_keys=True))
        return 0
    except BaseException as error:
        code = str(error) if type(error) is TrialError else "TRIAL_RUNTIME_FAILED"
        print("trial=REJECTED code=" + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
