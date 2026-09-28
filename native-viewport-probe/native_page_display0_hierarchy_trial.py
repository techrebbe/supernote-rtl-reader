"""One-shot read-only hierarchy and simple-case prediction on the disposable PDF.

Offline ``--build-only`` and ``--preflight-only`` are separate from ``--run``.
Do not run against the Nomad until the project hardware coordination gate
authorizes a bounded attachment. This observes no draw, pixels or pen behavior.
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
SOURCE_SHA256 = "8f1807c4acd75901f4ac1bb79d671e6005763ffea729b6491dddf86f85e5b1e0"
BUNDLE_SHA256 = "475e19b8e98448725dca4936922f875e4734b168ea4914245f6839642c75b24d"
MANIFEST_AUTHORITY = "rtl-reader-display0-hierarchy-manifest-v2"
RECORD_AUTHORITY = "rtl-reader-display0-hierarchy-observation-v2"
ROOT_ID = 0x7F09020F
CHILD_IDS = (0x7F090205, 0x7F090206, 0x7F090201,
             0x7F09021A, 0x7F090231, 0x7F0904F1,
             0x7F090225, 0x7F090725, 0x7F090200)
CHILD_CLASSES = (
    "com.supernote.document.utils.view.DocumentImageView",
    "com.supernote.document.utils.view.DigestImageView",
    "com.supernote.document.handwrite.HandWriteView",
    "android.widget.RelativeLayout", "android.widget.RelativeLayout",
    "android.widget.FrameLayout", "android.widget.RelativeLayout",
    "android.view.View", "android.widget.FrameLayout",
)
ERROR_PAIRS = frozenset({
    ("MANIFEST", "INVALID"), ("RUNTIME", "MISMATCH"),
    ("BRIDGE", "UNAVAILABLE"), ("JAVA_CHOOSE", "FAILED"),
    ("ACTIVITY", "NONE"), ("ACTIVITY", "MULTIPLE"),
    ("ACTIVITY", "LIMIT"), ("HIERARCHY", "MISMATCH"),
    ("CLEANUP", "FAILED"), ("DEADLINE", "EXPIRED"),
    ("OUTPUT", "OVERSIZE"),
})
HIERARCHY_STAGES = frozenset({
    "ACTIVITY_CLASS", "ACTIVITY_LIFECYCLE", "VM_CLASS", "PAGE_NUMBER", "URI_CLASS",
    "URI_VALUE", "ROOT_CLASS", "FIELD_PDF", "FIELD_DIGEST", "FIELD_PEN",
    "ROOT_CHILD_COUNT", "DRAW_ORDER", "CHILD_HANDLE", "CHILD_CLASS",
    "CHILD_PARENT", "CHILD_ID", "CHILD_VISIBILITY", "CHILD_BOUNDS",
    "CHILD_Z", "CHILD_ANIMATION", "CHILD_FIELD_IDENTITY", "FIELD_ORDER", "ROOT_ID",
    "ROOT_HARDWARE", "ROOT_DRAW_STATE",
    "ROOT_BOUNDS", "SECOND_SAMPLE_REFS", "SECOND_SAMPLE_VALUES",
})
CHILD_STAGES = frozenset(stage for stage in HIERARCHY_STAGES
                         if stage.startswith("CHILD_"))
CHILD_BASE_CODES = frozenset({
    "HIERARCHY_CHILD_INPUT_INVALID", "HIERARCHY_CHILD_HOST_SETUP_FAILED",
    "HIERARCHY_CHILD_CONNECT_FAILED", "HIERARCHY_CHILD_ATTACH_FAILED",
    "HIERARCHY_CHILD_SCRIPT_FAILED", "HIERARCHY_CHILD_LOAD_FAILED",
    "HIERARCHY_CHILD_WAIT_TIMEOUT", "HIERARCHY_CHILD_FRAME_REJECTED",
    "HIERARCHY_CHILD_UNLOAD_FAILED", "HIERARCHY_CHILD_DETACH_FAILED",
    "HIERARCHY_CHILD_FAILED", "HIERARCHY_CHILD_BUNDLE_INVALID",
})
ATTACH_ERROR_TYPES = (
    ("ProcessNotFoundError", "PROCESS_NOT_FOUND"),
    ("ProcessNotRespondingError", "PROCESS_NOT_RESPONDING"),
    ("PermissionDeniedError", "PERMISSION_DENIED"),
    ("TimedOutError", "TIMED_OUT"),
    ("TransportError", "TRANSPORT_ERROR"),
    ("ServerNotRunningError", "SERVER_NOT_RUNNING"),
    ("ProtocolError", "PROTOCOL_ERROR"),
    ("InvalidArgumentError", "INVALID_ARGUMENT"),
    ("InvalidOperationError", "INVALID_OPERATION"),
    ("NotSupportedError", "NOT_SUPPORTED"),
    ("OperationCancelledError", "OPERATION_CANCELLED"),
)
CHILD_CODES = CHILD_BASE_CODES | frozenset(
    "HIERARCHY_CHILD_OBSERVER_REJECTED_" + phase + "_" + reason
    for phase, reason in ERROR_PAIRS if phase != "HIERARCHY") | frozenset(
    "HIERARCHY_CHILD_OBSERVER_REJECTED_HIERARCHY_MISMATCH_S" +
    str(sample) + "_" + stage + ("_I" + str(index) if index >= 0 else "")
    for sample in (1, 2) for stage in HIERARCHY_STAGES
    for index in (range(32) if stage in CHILD_STAGES else (-1,))) | frozenset(
    "HIERARCHY_CHILD_ATTACH_" + reason for _, reason in ATTACH_ERROR_TYPES)
MAX_FRAME = 16_384


class HierarchyError(RuntimeError):
    """Only path-free fixed diagnostic codes reach callers."""


def _attach_error_code(error: BaseException, frida: Any) -> str:
    """Classify only exact Frida 17.9.11 attach errors; never inspect their text."""
    for class_name, reason in ATTACH_ERROR_TYPES:
        exception_type = getattr(frida, class_name, None)
        if type(exception_type) is type and type(error) is exception_type:
            return "HIERARCHY_CHILD_ATTACH_" + reason
    return "HIERARCHY_CHILD_ATTACH_FAILED"


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
        "schemaVersion": 2, "authority": MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": "com.supernote.document",
            "processName": "com.supernote.document",
            "pid": before.pid,
            "startTimeTicks": before.start_ticks,
            "firmwareFingerprint": identity.FINGERPRINT,
            "observerSha256": SOURCE_SHA256,
        },
        "expected": {"documentUri": identity.URI, "markPath": None,
                     "pageNumber": 1},
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


def _z(value: Any) -> float:
    _need(type(value) is str and re.fullmatch(r"0x[0-9a-f]{16}", value) is not None)
    number = struct.unpack(">d", bytes.fromhex(value[2:]))[0]
    _need(math.isfinite(number) and abs(number) <= 1_000_000_000)
    return number


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
                  "rootId", "rootBounds", "childCount", "children", "fieldIndex",
                  "customDrawingOrder", "rootHardwareAccelerated", "transientViewsPresent",
                  "transientIndicesPresent", "disappearingChildrenPresent",
                  "visibilityChangingChildrenPresent", "transitioningViewsPresent",
                  "rootOverlayPresent", "layoutAnimationPending", "visibleChildIndices",
                  "frameworkPredictedDirectChildOrder", "frameworkPredictionEligible",
                  "actualDrawObserved", "finalPixelsAdmitted",
                  "effectiveCompositingAdmitted", "uriMatchedExpected", "lifecycleStable"})
    _need(first["event"] == "native_page_hierarchy" and
          _int(first["schemaVersion"], 2, 2) == 2 and
          first["authority"] == RECORD_AUTHORITY and
          first["manifestSha256"] == manifest_sha and
          first["observationOnly"] is True and first["hardwareAdmission"] is False and
          _int(first["heapWalks"], 1, 1) == 1 and
          _int(first["retainedRootSamples"], 2, 2) == 2 and
          first["uiThreadSamples"] is True and
          first["hierarchyStable"] is True and
          first["rootClass"] == "android.widget.FrameLayout" and
          first["actualDrawObserved"] is False and
          first["finalPixelsAdmitted"] is False and
          first["effectiveCompositingAdmitted"] is False and
          first["uriMatchedExpected"] is True and first["lifecycleStable"] is True and
          all(type(first[name]) is bool for name in (
              "customDrawingOrder", "rootHardwareAccelerated", "transientViewsPresent",
              "transientIndicesPresent", "disappearingChildrenPresent",
              "visibilityChangingChildrenPresent", "transitioningViewsPresent",
              "rootOverlayPresent", "layoutAnimationPending",
              "frameworkPredictionEligible")))
    _need(first["transientViewsPresent"] is first["transientIndicesPresent"])
    _int(first["rootId"], ROOT_ID, ROOT_ID)
    _box(first["rootBounds"])
    count = _int(first["childCount"], len(CHILD_IDS), len(CHILD_IDS))
    children = first["children"]
    _need(type(children) is list and len(children) == count)
    z_values: list[float] = []
    for i, child in enumerate(children):
        _dict(child, {"index", "id", "className", "bounds", "visibility",
                      "z", "animationPresent", "parentIsRoot"})
        _need(_int(child["index"], i, i) == i and child["parentIsRoot"] is True)
        _int(child["id"], CHILD_IDS[i], CHILD_IDS[i])
        _need(child["className"] == CHILD_CLASSES[i] and
              type(child["animationPresent"]) is bool)
        visibility = _int(child["visibility"], 0, 8)
        _need(visibility in (0, 4, 8))
        _box(child["bounds"], positive=visibility == 0)
        z_values.append(_z(child["z"]))
    indices = _dict(first["fieldIndex"], {"pdf", "digest", "pen"})
    pdf, digest, pen = [_int(indices[name], 0, count - 1)
                        for name in ("pdf", "digest", "pen")]
    _need(pdf < digest < pen)
    for index, class_name in ((pdf, "com.supernote.document.utils.view.DocumentImageView"),
                              (digest, "com.supernote.document.utils.view.DigestImageView"),
                              (pen, "com.supernote.document.handwrite.HandWriteView")):
        _need(children[index]["className"] == class_name and
              children[index]["visibility"] == 0)
    visible = [child["index"] for child in children if child["visibility"] == 0]
    reported_visible = first["visibleChildIndices"]
    _need(type(reported_visible) is list and len(reported_visible) == len(visible))
    for actual, expected in zip(reported_visible, visible):
        _int(actual, expected, expected)
    eligible = (not first["customDrawingOrder"] and all(z == 0 for z in z_values)
                and not any(first[name] for name in (
                    "transientViewsPresent", "disappearingChildrenPresent",
                    "visibilityChangingChildrenPresent", "transitioningViewsPresent",
                    "rootOverlayPresent", "layoutAnimationPending"))
                and all(not child["animationPresent"] for child in children))
    _need(first["frameworkPredictionEligible"] is eligible)
    predicted = first["frameworkPredictedDirectChildOrder"]
    if eligible:
        _need(type(predicted) is list and len(predicted) == len(visible))
        for actual, expected in zip(predicted, visible):
            _int(actual, expected, expected)
    else:
        _need(predicted is None)
    return first


def parse_error_frames(frames: tuple[bytes, bytes]) -> tuple[str, str, str, int, int]:
    _need(type(frames) is tuple and len(frames) == 2)
    first, end = [_frame(raw) for raw in frames]
    _dict(first, {"event", "schemaVersion", "code", "phase", "reason",
                  "stage", "childIndex", "sampleOrdinal"})
    _dict(end, {"event", "success"})
    pair = (first["phase"], first["reason"])
    _need(first["event"] == "native_page_hierarchy_error" and
          _int(first["schemaVersion"], 2, 2) == 2 and
          first["code"] == "HIERARCHY_REJECTED" and
          pair in ERROR_PAIRS and
          end == {"event": "native_page_hierarchy_complete", "success": False})
    index = _int(first["childIndex"], -1, 31)
    sample = _int(first["sampleOrdinal"], 0, 2)
    stage = first["stage"]
    if pair[0] == "HIERARCHY":
        _need(type(stage) is str and stage in HIERARCHY_STAGES and
              sample in (1, 2) and
              ((0 <= index <= 31) if stage in CHILD_STAGES else index == -1))
    else:
        _need(stage == "NONE" and index == -1 and sample == 0)
    return pair[0], pair[1], stage, index, sample


def _observer_error_code(phase: str, reason: str, stage: str,
                         index: int, sample: int) -> str:
    code = "HIERARCHY_CHILD_OBSERVER_REJECTED_" + phase + "_" + reason
    if phase == "HIERARCHY":
        code += "_S" + str(sample) + "_" + stage
        if index >= 0:
            code += "_I" + str(index)
    _need(code in CHILD_CODES, "HIERARCHY_CHILD_FRAME_REJECTED")
    return code


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
              value["expected"] == {"documentUri": identity.URI, "markPath": None,
                                    "pageNumber": 1},
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
                phase, reason, stage, index, sample = parse_error_frames(frames)
            except HierarchyError:
                raise HierarchyError("HIERARCHY_CHILD_FRAME_REJECTED") from error
            raise HierarchyError(_observer_error_code(
                phase, reason, stage, index, sample)) from error
    except BaseException as error:
        if type(error) is HierarchyError and str(error) in CHILD_CODES:
            body_error = error
        elif stage == "ATTACH":
            body_error = HierarchyError(_attach_error_code(error, frida))
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
