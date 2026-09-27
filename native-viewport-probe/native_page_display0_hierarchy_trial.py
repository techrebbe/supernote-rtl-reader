"""One-shot read-only hierarchy observation on the fixed disposable PDF.

Offline ``--build-only`` and ``--preflight-only`` are separate from ``--run``.
Do not run against the Nomad until the project hardware coordination gate
authorizes a bounded attachment. This proves no compositing or pen behavior.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import sys
import threading
from typing import Any, Callable

import native_page_display0_bundle as base_bundle
import native_page_display0_disposable_trial as identity
import native_page_display0_graph_trial as graph
import native_page_graph_v2_runner as canonical


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "native_page_display0_hierarchy_observer.js"
ENTRYPOINT = base_bundle.BUILD / "native_page_display0_hierarchy_entry.js"
BUNDLE = base_bundle.BUILD / "native_page_display0_hierarchy_bundle.js"
SOURCE_SHA256 = "cfbd4b185a7cc3044fcdb16a84bbe28e8bc0658f25e6c25054e82c341806ee32"
BUNDLE_SHA256 = "402fbdbb77057e81c68f2323916fa5d99b9740b3085d49f47e3accbad6b899d3"
MANIFEST_AUTHORITY = "rtl-reader-display0-hierarchy-manifest-v1"
RECORD_AUTHORITY = "rtl-reader-display0-hierarchy-observation-v1"
ERROR_PAIRS = frozenset({
    ("MANIFEST", "INVALID"), ("RUNTIME", "MISMATCH"),
    ("BRIDGE", "UNAVAILABLE"), ("JAVA_CHOOSE", "FAILED"),
    ("ACTIVITY", "NONE"), ("ACTIVITY", "MULTIPLE"),
    ("ACTIVITY", "LIMIT"), ("HIERARCHY", "MISMATCH"),
    ("CLEANUP", "FAILED"), ("DEADLINE", "EXPIRED"),
    ("OUTPUT", "OVERSIZE"),
})
CHILD_BASE_CODES = frozenset({
    "HIERARCHY_CHILD_INPUT_INVALID", "HIERARCHY_CHILD_HOST_SETUP_FAILED",
    "HIERARCHY_CHILD_CONNECT_FAILED", "HIERARCHY_CHILD_ATTACH_FAILED",
    "HIERARCHY_CHILD_SCRIPT_FAILED", "HIERARCHY_CHILD_LOAD_FAILED",
    "HIERARCHY_CHILD_WAIT_TIMEOUT", "HIERARCHY_CHILD_FRAME_REJECTED",
    "HIERARCHY_CHILD_UNLOAD_FAILED", "HIERARCHY_CHILD_DETACH_FAILED",
    "HIERARCHY_CHILD_FAILED", "HIERARCHY_CHILD_BUNDLE_INVALID",
})
CHILD_CODES = CHILD_BASE_CODES | frozenset(
    "HIERARCHY_CHILD_OBSERVER_REJECTED_" + phase + "_" + reason
    for phase, reason in ERROR_PAIRS)
MAX_FRAME = 16_384


class HierarchyError(RuntimeError):
    """Only path-free fixed diagnostic codes reach callers."""


def _need(ok: bool, code: str = "HIERARCHY_REJECTED") -> None:
    if not ok:
        raise HierarchyError(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source() -> bytes:
    try:
        _need(SOURCE.is_file() and not SOURCE.is_symlink(),
              "HIERARCHY_SOURCE_CHANGED")
        raw = SOURCE.read_bytes()
    except OSError as error:
        raise HierarchyError("HIERARCHY_SOURCE_CHANGED") from error
    _need(0 < len(raw) <= 65_536 and _sha(raw) == SOURCE_SHA256,
          "HIERARCHY_SOURCE_CHANGED")
    return raw


def _bundle(raw: bytes) -> bytes:
    _need(0 < len(raw) <= base_bundle.MAX_BUNDLE_BYTES and
          _sha(raw) == BUNDLE_SHA256, "HIERARCHY_BUNDLE_CHANGED")
    return raw


def build_bundle() -> bytes:
    """Compile only from the pinned source and dependency tree."""
    raw = _source()
    try:
        base_bundle.build_verified_bundle()
        base_bundle._atomic_bytes(ENTRYPOINT, base_bundle.IMPORT + raw)
        sys.path.insert(0, str(base_bundle.FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        _need(importlib.metadata.version("frida") == base_bundle.FRIDA_VERSION and
              callable(getattr(frida, "Compiler", None)),
              "HIERARCHY_COMPILER_CHANGED")
        built = frida.Compiler().build(
            str(ENTRYPOINT), project_root=str(base_bundle.BUILD),
            output_format="unescaped", bundle_format="iife", type_check="none",
            source_maps="omitted", compression="none", platform="gum")
        _need(type(built) is str, "HIERARCHY_COMPILER_FAILED")
        verified = _bundle(built.encode("utf-8", "strict"))
        base_bundle._atomic_bytes(BUNDLE, verified)
        return verified
    except HierarchyError:
        raise
    except base_bundle.BundleError as error:
        raise HierarchyError("HIERARCHY_DEPENDENCY_CHANGED") from error
    except BaseException as error:
        raise HierarchyError("HIERARCHY_COMPILER_FAILED") from error


def load_bundle() -> bytes:
    _source()
    try:
        base_bundle.check_inputs()
        _need(BUNDLE.is_file() and not BUNDLE.is_symlink(),
              "HIERARCHY_BUNDLE_MISSING")
        return _bundle(BUNDLE.read_bytes())
    except base_bundle.BundleError as error:
        raise HierarchyError("HIERARCHY_DEPENDENCY_CHANGED") from error
    except OSError as error:
        raise HierarchyError("HIERARCHY_BUNDLE_MISSING") from error


def manifest(before: identity.Snapshot) -> bytes:
    value = {
        "schemaVersion": 1, "authority": MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": "com.supernote.document",
            "processName": "com.supernote.document",
            "pid": before.pid,
            "startTimeTicks": before.start_ticks,
            "firmwareFingerprint": identity.FINGERPRINT,
            "observerSha256": SOURCE_SHA256,
        },
        "expected": {"documentUri": identity.URI, "markPath": None},
        "coordinator": {
            "maxJavaChooseWalks": 1, "retainedRootSamples": 2,
            "hardDeadlineMs": 5000, "detachOnDeadline": True,
            "abortOnAnyError": True, "noRetry": True,
        },
    }
    raw = canonical.canonical_bytes(value, 4096)
    _need(all(0x20 <= byte <= 0x7e for byte in raw),
          "HIERARCHY_MANIFEST_INVALID")
    return raw


def _dict(value: Any, names: set[str]) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == names)
    return value


def _int(value: Any, lo: int, hi: int) -> int:
    _need(type(value) is int and lo <= value <= hi)
    return value


def _box(value: Any, *, positive: bool = True) -> None:
    _need(type(value) is list and len(value) == 4)
    x0, y0, x1, y1 = [_int(item, -(2**31), 2**31 - 1) for item in value]
    _need((x1 > x0 and y1 > y0) if positive else
          (x1 >= x0 and y1 >= y0))


def _z(value: Any) -> None:
    _need(type(value) is str and re.fullmatch(r"0x[0-9a-f]{16}", value) is not None)
    number = struct.unpack(">d", bytes.fromhex(value[2:]))[0]
    _need(math.isfinite(number) and abs(number) <= 1_000_000_000)


def _frame(raw: bytes) -> dict[str, Any]:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME)
    try:
        value = canonical.load_canonical(raw, MAX_FRAME).value
        _need(type(value) is dict)
        return value
    except (canonical.GraphRunnerError, TypeError, ValueError) as error:
        raise HierarchyError("HIERARCHY_REJECTED") from error


def parse_frames(frames: tuple[bytes, bytes], manifest_sha: str) -> dict[str, Any]:
    _need(type(frames) is tuple and len(frames) == 2 and
          type(manifest_sha) is str and re.fullmatch(r"[0-9a-f]{64}", manifest_sha) is not None)
    first, end = [_frame(raw) for raw in frames]
    _dict(end, {"event", "success"})
    _need(end == {"event": "native_page_hierarchy_complete", "success": True})
    _dict(first, {"event", "schemaVersion", "authority", "manifestSha256",
                  "observationOnly", "hardwareAdmission", "heapWalks",
                  "retainedRootSamples", "uiThreadSamples", "hierarchyStable", "rootClass",
                  "rootId", "rootBounds", "childCount", "children",
                  "fieldIndex", "customDrawingOrder", "effectiveCompositingAdmitted",
                  "uriMatchedExpected", "lifecycleStable"})
    _need(first["event"] == "native_page_hierarchy" and
          _int(first["schemaVersion"], 1, 1) == 1 and
          first["authority"] == RECORD_AUTHORITY and
          first["manifestSha256"] == manifest_sha and
          first["observationOnly"] is True and first["hardwareAdmission"] is False and
          _int(first["heapWalks"], 1, 1) == 1 and
          _int(first["retainedRootSamples"], 2, 2) == 2 and
          first["uiThreadSamples"] is True and
          first["hierarchyStable"] is True and
          first["rootClass"] == "android.widget.FrameLayout" and
          first["effectiveCompositingAdmitted"] is False and
          first["uriMatchedExpected"] is True and first["lifecycleStable"] is True and
          type(first["customDrawingOrder"]) is bool)
    _int(first["rootId"], -1, 2**31 - 1)
    _box(first["rootBounds"])
    count = _int(first["childCount"], 4, 32)
    children = first["children"]
    _need(type(children) is list and len(children) == count)
    for i, child in enumerate(children):
        _dict(child, {"index", "id", "className", "bounds", "visibility",
                      "z", "parentIsRoot"})
        _need(_int(child["index"], i, i) == i and child["parentIsRoot"] is True)
        _int(child["id"], -1, 2**31 - 1)
        _need(type(child["className"]) is str and
              0 < len(child["className"]) <= 160 and
              all(0x20 <= ord(c) <= 0x7e for c in child["className"]))
        visibility = _int(child["visibility"], 0, 8)
        _need(visibility in (0, 4, 8))
        _box(child["bounds"], positive=visibility == 0)
        _z(child["z"])
    indices = _dict(first["fieldIndex"], {"pdf", "digest", "pen"})
    pdf, digest, pen = [_int(indices[name], 0, count - 1)
                        for name in ("pdf", "digest", "pen")]
    _need(pdf < digest < pen)
    for index, class_name in ((pdf, "com.supernote.document.utils.view.DocumentImageView"),
                              (digest, "com.supernote.document.utils.view.DigestImageView"),
                              (pen, "com.supernote.document.handwrite.HandWriteView")):
        _need(children[index]["className"] == class_name)
    return first


def parse_error_frames(frames: tuple[bytes, bytes]) -> tuple[str, str]:
    _need(type(frames) is tuple and len(frames) == 2)
    first, end = [_frame(raw) for raw in frames]
    _dict(first, {"event", "schemaVersion", "code", "phase", "reason"})
    _dict(end, {"event", "success"})
    pair = (first["phase"], first["reason"])
    _need(first["event"] == "native_page_hierarchy_error" and
          _int(first["schemaVersion"], 1, 1) == 1 and
          first["code"] == "HIERARCHY_REJECTED" and
          pair in ERROR_PAIRS and
          end == {"event": "native_page_hierarchy_complete", "success": False})
    return pair


class Collector:
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
                raw = canonical.canonical_bytes(message.get("payload"), MAX_FRAME)
            except canonical.GraphRunnerError:
                self.failed = True
                self.complete.set()
                return
            self.frames.append(raw)
            if len(self.frames) == 2:
                self.complete.set()

    def checked(self) -> tuple[bytes, bytes]:
        with self._lock:
            _need(not self.failed and len(self.frames) == 2,
                  "HIERARCHY_CHILD_FRAME_REJECTED")
            return self.frames[0], self.frames[1]


def child(pid: int, wire: bytes) -> int:
    _need(identity.PID_RE.fullmatch(str(pid).encode("ascii")) is not None and
          type(wire) is bytes and 0 < len(wire) <= 4096,
          "HIERARCHY_CHILD_INPUT_INVALID")
    try:
        value = canonical.load_canonical(wire, 4096).value
        _need(type(value) is dict and value["authority"] == MANIFEST_AUTHORITY and
              value["attachment"]["pid"] == pid and
              value["attachment"]["observerSha256"] == SOURCE_SHA256 and
              value["attachment"]["firmwareFingerprint"] == identity.FINGERPRINT and
              value["expected"] == {"documentUri": identity.URI, "markPath": None},
              "HIERARCHY_CHILD_INPUT_INVALID")
        compiled = load_bundle()
    except (KeyError, TypeError, canonical.GraphRunnerError, HierarchyError) as error:
        raise HierarchyError("HIERARCHY_CHILD_BUNDLE_INVALID") from error
    try:
        sys.path.insert(0, str(identity.FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        _need(importlib.metadata.version("frida") == "17.9.11" and
              callable(getattr(frida, "get_device_manager", None)),
              "HIERARCHY_CHILD_HOST_SETUP_FAILED")
    except BaseException as error:
        raise HierarchyError("HIERARCHY_CHILD_HOST_SETUP_FAILED") from error
    prefix = (
        "globalThis.NATIVE_PAGE_HIERARCHY_MANIFEST_UTF8=" +
        json.dumps(list(wire), separators=(",", ":")) + ";\n" +
        "globalThis.NATIVE_PAGE_HIERARCHY_MANIFEST_SHA256=" +
        json.dumps(_sha(wire)) + ";\n")
    collector = Collector()
    session = None
    script = None
    stage = "CONNECT"
    body_error: HierarchyError | None = None
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
            raise HierarchyError("HIERARCHY_CHILD_WAIT_TIMEOUT")
        stage = "FRAME"
        frames = collector.checked()
        try:
            parse_frames(frames, _sha(wire))
        except HierarchyError as error:
            try:
                phase, reason = parse_error_frames(frames)
            except HierarchyError:
                raise HierarchyError("HIERARCHY_CHILD_FRAME_REJECTED") from error
            raise HierarchyError("HIERARCHY_CHILD_OBSERVER_REJECTED_" +
                                 phase + "_" + reason) from error
    except BaseException as error:
        if type(error) is HierarchyError and str(error) in CHILD_CODES:
            body_error = error
        else:
            body_error = HierarchyError(
                "HIERARCHY_CHILD_" + stage + "_FAILED"
                if stage in {"CONNECT", "ATTACH", "SCRIPT", "LOAD"}
                else "HIERARCHY_CHILD_FRAME_REJECTED")
    unload_failed = detach_failed = False
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
        raise HierarchyError("HIERARCHY_CHILD_DETACH_FAILED")
    if unload_failed:
        raise HierarchyError("HIERARCHY_CHILD_UNLOAD_FAILED")
    if body_error is not None:
        raise body_error
    for raw in collector.checked():
        print(base64.b64encode(raw).decode("ascii"), flush=True)
    return 0


class Backend(graph.GraphBackend):
    def child_hierarchy(self, pid: int, wire: bytes) -> tuple[bytes, bytes]:
        encoded = base64.urlsafe_b64encode(wire).decode("ascii")
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "__child",
                 str(pid), encoded], capture_output=True, shell=False,
                timeout=8.0, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HierarchyError("HIERARCHY_CHILD_UNAVAILABLE") from error
        if result.returncode != 0:
            codes = {code.encode("ascii") + ending: code
                     for code in CHILD_CODES for ending in (b"\n", b"\r\n")}
            if result.returncode == 2 and not result.stdout and result.stderr in codes:
                raise HierarchyError(codes[result.stderr])
            raise HierarchyError("HIERARCHY_CHILD_FAILED")
        _need(not result.stderr and len(result.stdout) <= 40_000,
              "HIERARCHY_CHILD_FAILED")
        try:
            lines = result.stdout.splitlines()
            _need(len(lines) == 2, "HIERARCHY_CHILD_FRAME_REJECTED")
            frames = tuple(base64.b64decode(line, validate=True) for line in lines)
            _need(all(0 < len(raw) <= MAX_FRAME for raw in frames),
                  "HIERARCHY_CHILD_FRAME_REJECTED")
            return frames  # type: ignore[return-value]
        except (ValueError, TypeError) as error:
            raise HierarchyError("HIERARCHY_CHILD_FRAME_REJECTED") from error


def preflight(backend: Backend) -> tuple[identity.Snapshot, int]:
    identity._forward_absent(backend)
    identity._server_absent(backend)
    before = identity.capture(backend)
    graph._pinned_images(backend)
    rotation = graph._landscape_orientation(backend)
    manifest(before)
    build_bundle()
    return before, rotation


def run_trial(backend: Backend,
              *, announce: Callable[[str], None] = print) -> dict[str, Any]:
    before, rotation = preflight(backend)
    wire = manifest(before)
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
        frames = backend.child_hierarchy(before.pid, wire)
    except BaseException as error:
        primary = (error if type(error) in (HierarchyError, identity.TrialError)
                   else HierarchyError("HIERARCHY_TRIAL_RUNTIME_FAILED"))
    finally:
        if forwarded:
            try:
                _need([entry for entry in identity._forward_entries(backend)
                       if entry == [identity.SERIAL, identity.PORT, identity.PORT]] ==
                      [[identity.SERIAL, identity.PORT, identity.PORT]],
                      "HIERARCHY_FORWARD_CHANGED")
                backend.adb("forward", "--remove", identity.PORT)
                _need([entry for entry in identity._forward_entries(backend)
                       if entry == [identity.SERIAL, identity.PORT, identity.PORT]] == [],
                      "HIERARCHY_FORWARD_CLEANUP_UNCERTAIN")
            except (HierarchyError, identity.TrialError):
                cleanup_codes.append("HIERARCHY_FORWARD_CLEANUP_UNCERTAIN")
        if server_pid is not None and server_ticks is not None:
            try:
                identity._stop_exact_server(backend, server_pid, server_ticks)
                identity._server_absent(backend)
            except identity.TrialError:
                cleanup_codes.append("HIERARCHY_SERVER_CLEANUP_UNCERTAIN")
        elif server_pid is not None or primary is not None:
            try:
                identity._server_absent(backend)
            except identity.TrialError:
                cleanup_codes.append("HIERARCHY_SERVER_CLEANUP_UNCERTAIN")
        if not forwarded:
            try:
                identity._forward_absent(backend)
            except identity.TrialError:
                cleanup_codes.append("HIERARCHY_FORWARD_CLEANUP_UNCERTAIN")
    post_error = False
    try:
        after = identity.capture(backend)
        identity._stable(before, after)
        _need(graph._landscape_orientation(backend) == rotation,
              "HIERARCHY_PHYSICAL_ORIENTATION_CHANGED")
        graph._pinned_images(backend)
    except BaseException:
        post_error = True
    if cleanup_codes:
        announce("cleanup_uncertain=" + ",".join(cleanup_codes))
        if post_error:
            announce("post_state_uncertain=true")
        raise HierarchyError("HIERARCHY_CLEANUP_UNCERTAIN")
    if post_error:
        raise HierarchyError("HIERARCHY_POST_STATE_UNCERTAIN")
    if primary is not None:
        raise HierarchyError(str(primary)) from primary
    _need(frames is not None, "HIERARCHY_NO_FRAMES")
    record = parse_frames(frames, _sha(wire))
    return {"trial": "alpha-disposable-stock-hierarchy-only",
            "record": record, "readerStable": True, "pdfUnchanged": True,
            "markAbsent": True, "serverRemoved": True, "forwardRemoved": True,
            "hardwareAdmission": False, "mutationAuthorized": False,
            "physicalRotation": rotation, "bundleSha256": BUNDLE_SHA256}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "__child":
        try:
            _need(len(args) == 3 and
                  identity.PID_RE.fullmatch(args[1].encode("ascii")) is not None,
                  "HIERARCHY_CHILD_INPUT_INVALID")
            return child(int(args[1]), base64.urlsafe_b64decode(args[2]))
        except BaseException as error:
            code = str(error) if type(error) is HierarchyError else "HIERARCHY_CHILD_FAILED"
            print(code if code in CHILD_CODES else "HIERARCHY_CHILD_FAILED",
                  file=sys.stderr)
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--build-only", action="store_true")
    group.add_argument("--preflight-only", action="store_true")
    group.add_argument("--run", action="store_true")
    parsed = parser.parse_args(args)
    try:
        if parsed.build_only:
            build_bundle()
            print("build=PASS hierarchy_observation_not_run=true hardwareAdmission=false")
        elif parsed.preflight_only:
            preflight(Backend())
            print("preflight=PASS hierarchy_observation_not_run=true hardwareAdmission=false")
        else:
            print(json.dumps(run_trial(Backend()), sort_keys=True))
        return 0
    except BaseException as error:
        code = str(error) if type(error) in (HierarchyError, identity.TrialError,
                                             graph.GraphTrialError) else \
            "HIERARCHY_TRIAL_RUNTIME_FAILED"
        print("trial=REJECTED code=" + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
