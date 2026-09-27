"""One-attempt disposable stock-reader graph and crop-state observation.

This never launches or moves a task and never admits pen, ink, or a viewport.
The CLI must not be run against the device until the project coordination gate
authorizes a new bounded attachment. ``--preflight-only`` is read-only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
from typing import Any, Callable

import native_page_display0_disposable_trial as identity
import native_page_display0_graph_bundle as bundle
import native_page_display0_graph_contract as contract
import native_page_graph_v2_runner as canonical
import native_page_alpha_runner as alpha


OBSERVER = Path(__file__).with_name("native_page_display0_graph_observer.js")
PINNED_IMAGES = (
    ("/system_ext/app/SupernoteDocument/SupernoteDocument.apk", 138_486_560,
     "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482"),
    ("/system/framework/framework.jar", 30_186_065,
     "c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d"),
)
CHILD_BASE_CODES = frozenset({
    "GRAPH_CHILD_INPUT_INVALID", "GRAPH_CHILD_HOST_SETUP_FAILED",
    "GRAPH_CHILD_CONNECT_FAILED", "GRAPH_CHILD_ATTACH_FAILED",
    "GRAPH_CHILD_SCRIPT_FAILED", "GRAPH_CHILD_LOAD_FAILED",
    "GRAPH_CHILD_WAIT_TIMEOUT", "GRAPH_CHILD_FRAME_REJECTED",
    "GRAPH_CHILD_UNLOAD_FAILED", "GRAPH_CHILD_DETACH_FAILED",
    "GRAPH_CHILD_FAILED", "GRAPH_CHILD_BUNDLE_INVALID",
})
CHILD_OBSERVER_CODES = frozenset(
    "GRAPH_CHILD_OBSERVER_REJECTED_" + phase + "_" + reason
    for phase, reason in contract.OBSERVER_FAILURE_PAIRS)
CHILD_CODES = CHILD_BASE_CODES | CHILD_OBSERVER_CODES


class GraphTrialError(RuntimeError):
    """Only fixed, path-free diagnostic codes may escape to the CLI."""


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise GraphTrialError(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_and_manifest(before: identity.Snapshot) -> tuple[bytes, bytes]:
    """Bind one exact observer source to the existing fixed stock preflight."""
    try:
        _need(OBSERVER.is_file() and not OBSERVER.is_symlink(),
              "GRAPH_SOURCE_CHANGED")
        source = OBSERVER.read_bytes()
    except OSError as error:
        raise GraphTrialError("GRAPH_SOURCE_CHANGED") from error
    _need(0 < len(source) <= 65_536 and _sha(source) == bundle.SOURCE_SHA256,
          "GRAPH_SOURCE_CHANGED")
    value = {
        "schemaVersion": 2, "authority": contract.MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": "com.supernote.document",
            "processName": "com.supernote.document",
            "pid": before.pid, "startTimeTicks": before.start_ticks,
            "firmwareFingerprint": identity.FINGERPRINT,
            "observerSha256": bundle.SOURCE_SHA256,
        },
        "expected": {"documentUri": identity.URI, "markPath": None},
        "coordinator": {
            "maxJavaChooseWalks": 1, "retainedRootSamples": 2,
            "hardDeadlineMs": 5000, "detachOnDeadline": True,
            "abortOnAnyError": True, "noRetry": True,
        },
    }
    manifest = canonical.canonical_bytes(value, 4096)
    _need(all(0x20 <= byte <= 0x7e for byte in manifest),
          "GRAPH_MANIFEST_INVALID")
    return source, manifest


class GraphBackend(identity.Backend):
    """Reuses only the previously validated fixed-serial stock/device reads."""

    def child_graph(self, pid: int, manifest: bytes,
                    *, timeout: float = 8.0) -> tuple[bytes, bytes]:
        encoded = base64.urlsafe_b64encode(manifest).decode("ascii")
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "__child",
                 str(pid), encoded], capture_output=True, shell=False,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise GraphTrialError("GRAPH_CHILD_TIMEOUT") from error
        except OSError as error:
            raise GraphTrialError("GRAPH_CHILD_UNAVAILABLE") from error
        if result.returncode != 0:
            codes = {code.encode("ascii") + ending: code
                     for code in CHILD_CODES for ending in (b"\n", b"\r\n")}
            if result.returncode == 2 and not result.stdout and result.stderr in codes:
                raise GraphTrialError(codes[result.stderr])
            raise GraphTrialError("GRAPH_CHILD_FAILED")
        _need(not result.stderr and len(result.stdout) <= 24_576,
              "GRAPH_CHILD_FAILED")
        try:
            lines = result.stdout.splitlines()
            _need(len(lines) == 2, "GRAPH_CHILD_FRAME_COUNT")
            frames = tuple(base64.b64decode(line, validate=True) for line in lines)
            _need(all(0 < len(raw) <= contract.MAX_FRAME_BYTES for raw in frames),
                  "GRAPH_CHILD_FRAME_INVALID")
            return frames  # type: ignore[return-value]
        except (ValueError, TypeError) as error:
            raise GraphTrialError("GRAPH_CHILD_FRAME_INVALID") from error


def _pinned_images(backend: GraphBackend) -> None:
    """Admit the exact two binaries behind the direct-field map, without pull."""
    for path, size, digest in PINNED_IMAGES:
        stat = backend.adb("shell", "stat", "-c", "%s", path).strip()
        _need(stat == str(size).encode("ascii"), "GRAPH_PINNED_IMAGE_CHANGED")
        actual = backend.adb("shell", "sha256sum", path).strip()
        _need(actual in ((digest + "  " + path).encode("ascii"),
                         (digest + " " + path).encode("ascii")),
              "GRAPH_PINNED_IMAGE_CHANGED")


class FrameCollector:
    """Fail-latched callback stream, including a late frame during teardown."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self.failed = False
        self.complete = threading.Event()
        self._lock = threading.Lock()

    def on_message(self, message: dict, data: bytes | None) -> None:
        with self._lock:
            if self.failed:
                return
            if (type(message) is not dict or message.get("type") != "send" or
                    data is not None or len(self.frames) >= 2):
                self.failed = True
                self.complete.set()
                return
            try:
                raw = canonical.canonical_bytes(message.get("payload"),
                                                contract.MAX_FRAME_BYTES)
            except canonical.GraphRunnerError:
                self.failed = True
                self.complete.set()
                return
            self.frames.append(raw)
            if len(self.frames) == 2:
                self.complete.set()

    def checked_frames(self) -> tuple[bytes, bytes]:
        with self._lock:
            _need(not self.failed and len(self.frames) == 2,
                  "GRAPH_CHILD_INCOMPLETE")
            return self.frames[0], self.frames[1]


def child(pid: int, manifest: bytes) -> int:
    """Killable host child; emits only two bounded canonical observer frames."""
    _need(identity.PID_RE.fullmatch(str(pid).encode("ascii")) is not None and
          type(manifest) is bytes and 0 < len(manifest) <= 4096,
          "GRAPH_CHILD_INPUT_INVALID")
    try:
        value = canonical.load_canonical(manifest, 4096).value
        _need(type(value) is dict and
              value["expected"] == {"documentUri": identity.URI, "markPath": None} and
              value["attachment"]["pid"] == pid and
              value["attachment"]["firmwareFingerprint"] == identity.FINGERPRINT and
              value["attachment"]["observerSha256"] == bundle.SOURCE_SHA256 and
              value["authority"] == contract.MANIFEST_AUTHORITY,
              "GRAPH_CHILD_INPUT_INVALID")
        compiled = bundle.load_verified_bundle()
    except (KeyError, TypeError, canonical.GraphRunnerError,
            bundle.GraphBundleError) as error:
        raise GraphTrialError("GRAPH_CHILD_BUNDLE_INVALID") from error
    try:
        sys.path.insert(0, str(identity.FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        _need(importlib.metadata.version("frida") == "17.9.11" and
              callable(getattr(frida, "get_device_manager", None)),
              "GRAPH_CHILD_HOST_SETUP_FAILED")
    except BaseException as error:
        raise GraphTrialError("GRAPH_CHILD_HOST_SETUP_FAILED") from error
    prefix = (
        "globalThis.NATIVE_PAGE_DISPLAY0_GRAPH_MANIFEST_UTF8=" +
        json.dumps(list(manifest), separators=(",", ":")) + ";\n" +
        "globalThis.NATIVE_PAGE_DISPLAY0_GRAPH_MANIFEST_SHA256=" +
        json.dumps(_sha(manifest)) + ";\n")
    collector = FrameCollector()
    session = None
    script = None
    stage = "CONNECT"
    body_error: GraphTrialError | None = None
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
            raise GraphTrialError("GRAPH_CHILD_WAIT_TIMEOUT")
        stage = "FRAME"
        frames = collector.checked_frames()
        try:
            contract.parse_graph_frames(frames, _sha(manifest), mark_required=False)
        except contract.GraphContractError as error:
            try:
                phase, reason = contract.parse_graph_error_frames(frames)
            except contract.GraphContractError as parse_error:
                raise GraphTrialError("GRAPH_CHILD_FRAME_REJECTED") from parse_error
            raise GraphTrialError("GRAPH_CHILD_OBSERVER_REJECTED_" + phase +
                                  "_" + reason) from error
    except BaseException as error:
        if type(error) is GraphTrialError and str(error) in CHILD_CODES:
            body_error = error
        else:
            body_error = GraphTrialError(
                "GRAPH_CHILD_" + stage + "_FAILED"
                if stage in {"CONNECT", "ATTACH", "SCRIPT", "LOAD"}
                else "GRAPH_CHILD_FRAME_REJECTED")
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
        raise GraphTrialError("GRAPH_CHILD_DETACH_FAILED")
    if unload_failed:
        raise GraphTrialError("GRAPH_CHILD_UNLOAD_FAILED")
    if body_error is not None:
        if str(body_error) in CHILD_OBSERVER_CODES:
            try:
                collector.checked_frames()
            except GraphTrialError as error:
                raise GraphTrialError("GRAPH_CHILD_FRAME_REJECTED") from error
        raise body_error
    frames = collector.checked_frames()
    for raw in frames:
        print(base64.b64encode(raw).decode("ascii"), flush=True)
    return 0


def _landscape_orientation(backend: GraphBackend) -> int:
    """Bind physical display 0, not the reader's mutable configuration."""
    try:
        rotation = alpha._physical_orientation(
            backend.adb("shell", "dumpsys", "window", "displays"))
    except (alpha.AlphaError, identity.TrialError) as error:
        raise GraphTrialError("GRAPH_PHYSICAL_ORIENTATION_UNCERTAIN") from error
    _need(rotation in (1, 3), "GRAPH_NOT_LANDSCAPE")
    return rotation


def preflight(backend: GraphBackend) -> tuple[identity.Snapshot, int]:
    identity._forward_absent(backend)
    identity._server_absent(backend)
    before = identity.capture(backend)
    _pinned_images(backend)
    rotation = _landscape_orientation(backend)
    source_and_manifest(before)
    try:
        bundle.build_verified_bundle()
    except bundle.GraphBundleError as error:
        raise GraphTrialError("GRAPH_BUNDLE_INVALID") from error
    return before, rotation


def run_trial(backend: GraphBackend,
              *, announce: Callable[[str], None] = print) -> dict[str, Any]:
    """One bounded attach; a failed cleanup or changed PDF invalidates it."""
    before, rotation = preflight(backend)
    _, manifest = source_and_manifest(before)
    server_pid: int | None = None
    server_ticks: str | None = None
    forwarded = False
    primary: Exception | None = None
    cleanup_codes: list[str] = []
    frames: tuple[bytes, bytes] | None = None
    try:
        server_pid = identity._launch_server(backend)
        server_ticks = identity._server_identity(backend, server_pid)
        identity._await_server_ready(backend, server_pid, server_ticks)
        backend.adb("forward", "--no-rebind", identity.PORT, identity.PORT)
        forwarded = True
        identity._owned_forward(backend)
        frames = backend.child_graph(before.pid, manifest)
    except BaseException as error:
        primary = (error if type(error) in (GraphTrialError, identity.TrialError)
                   else GraphTrialError("GRAPH_TRIAL_RUNTIME_FAILED"))
    finally:
        if forwarded:
            try:
                _need([entry for entry in identity._forward_entries(backend)
                       if entry == [identity.SERIAL, identity.PORT, identity.PORT]] ==
                      [[identity.SERIAL, identity.PORT, identity.PORT]],
                      "GRAPH_FORWARD_CHANGED")
                backend.adb("forward", "--remove", identity.PORT)
                _need([entry for entry in identity._forward_entries(backend)
                       if entry == [identity.SERIAL, identity.PORT, identity.PORT]] == [],
                      "GRAPH_FORWARD_CLEANUP_UNCERTAIN")
            except (GraphTrialError, identity.TrialError):
                cleanup_codes.append("GRAPH_FORWARD_CLEANUP_UNCERTAIN")
        if server_pid is not None and server_ticks is not None:
            try:
                identity._stop_exact_server(backend, server_pid, server_ticks)
                identity._server_absent(backend)
            except identity.TrialError:
                cleanup_codes.append("GRAPH_SERVER_CLEANUP_UNCERTAIN")
        elif server_pid is not None or primary is not None:
            try:
                identity._server_absent(backend)
            except identity.TrialError:
                cleanup_codes.append("GRAPH_SERVER_CLEANUP_UNCERTAIN")
        if not forwarded:
            try:
                identity._forward_absent(backend)
            except identity.TrialError:
                cleanup_codes.append("GRAPH_FORWARD_CLEANUP_UNCERTAIN")
    post_error = False
    try:
        after = identity.capture(backend)
        identity._stable(before, after)
        _need(_landscape_orientation(backend) == rotation,
              "GRAPH_PHYSICAL_ORIENTATION_CHANGED")
        _pinned_images(backend)
    except BaseException:
        post_error = True
    if cleanup_codes:
        announce("cleanup_uncertain=" + ",".join(cleanup_codes))
        if post_error:
            announce("post_state_uncertain=true")
        raise GraphTrialError("GRAPH_CLEANUP_UNCERTAIN")
    if post_error:
        raise GraphTrialError("GRAPH_POST_STATE_UNCERTAIN")
    if primary is not None:
        raise GraphTrialError(str(primary)) from primary
    _need(frames is not None, "GRAPH_NO_FRAMES")
    try:
        record = contract.parse_graph_frames(frames, _sha(manifest),
                                             mark_required=False)
    except contract.GraphContractError as error:
        raise GraphTrialError("GRAPH_OBSERVER_REJECTED") from error
    return {"trial": "alpha-disposable-crop-graph-only",
            "record": record, "readerStable": True, "pdfUnchanged": True,
            "markAbsent": True, "serverRemoved": True, "forwardRemoved": True,
             "hardwareAdmission": False, "mutationAuthorized": False,
             "physicalRotation": rotation,
             "bundleSha256": bundle.BUNDLE_SHA256}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "__child":
        try:
            _need(len(args) == 3 and
                  identity.PID_RE.fullmatch(args[1].encode("ascii")) is not None,
                  "GRAPH_CHILD_INPUT_INVALID")
            manifest = base64.urlsafe_b64decode(args[2].encode("ascii"))
            return child(int(args[1]), manifest)
        except BaseException as error:
            code = str(error) if type(error) is GraphTrialError else "GRAPH_CHILD_FAILED"
            print(code if code in CHILD_CODES else "GRAPH_CHILD_FAILED",
                  file=sys.stderr)
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--run", action="store_true")
    parsed = parser.parse_args(args)
    backend = GraphBackend()
    try:
        if parsed.preflight_only:
            preflight(backend)
            print("preflight=PASS graph_observation_not_run=true hardwareAdmission=false")
        else:
            print(json.dumps(run_trial(backend), sort_keys=True))
        return 0
    except BaseException as error:
        code = str(error) if type(error) in (GraphTrialError, identity.TrialError) else \
            "GRAPH_TRIAL_RUNTIME_FAILED"
        print("trial=REJECTED code=" + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
