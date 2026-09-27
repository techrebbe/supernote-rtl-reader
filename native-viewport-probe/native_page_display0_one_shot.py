"""Alpha-only, host-owned one-shot stock-reader identity observation contract.

This file deliberately has no ADB or Frida backend.  A future backend must put
the complete capture/attach/load/unload/detach sequence in one *killable host
process* with nonblocking IPC.  A Python thread, a Frida JavaScript timer, or a
provider's claim that it timed out is not a suitable retirement boundary.

The supplied captures, transport trace, and two JS frames are checked for
consistency, not authenticated as having come from the Nomad.  In particular,
even a successful result is neither a hardware admission nor permission to
mutate the native reader.  This contract does not reuse the virtual-display
v2 stage runner or its pen/host authorities.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import time
from typing import Any, Callable, Protocol

import native_page_display0_admission as admission
import native_page_display0_observation as observation
import native_page_display0_stock_dialect as stock
import native_page_graph_v2_runner as graph
from native_page_authority_provider import FileRead, ProcessRead


SCHEMA_VERSION = 1
MANIFEST_AUTHORITY = "rtl-reader-display0-identity-manifest-v1"
RECORD_AUTHORITY = "rtl-reader-display0-identity-observation-v1"
RUNNER_AUTHORITY = "rtl-reader-display0-one-shot-host-consistency-v1"
OBSERVER_SHA256 = "366d0ea9fd965fbb0e479e65f00498b5479a7cb5bcb4bb16c545c079ef44fcab"
DISPOSABLE_URI = (
    "file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf"
)
TRACE = ("attach", "load", "unload", "detach")
MIN_DEADLINE_MS = 250
MAX_DEADLINE_MS = 10_000
MAX_FRAME_BYTES = 4096


class OneShotError(RuntimeError):
    """Only a generic, path-free failure is exposed by the coordinator."""


class LiveBackendUnavailable(OneShotError):
    """There is not yet a reviewed killable ADB/Frida production backend."""


@dataclass(frozen=True)
class CaptureHalf:
    activity_raw: bytes
    window_raw: bytes
    process: ProcessRead
    pdf: FileRead
    mark: FileRead
    uri_resolution_raw: bytes


@dataclass(frozen=True)
class FinalEvidence:
    after: CaptureHalf
    frames: tuple[bytes, bytes]
    transport_trace: tuple[str, ...]


@dataclass(frozen=True)
class OneShotResult:
    raw: bytes
    sha256: str

    def value(self) -> dict[str, Any]:
        return graph.load_canonical(self.raw, graph.MAX_AUTHORITY_BYTES).value


class KillableWorker(Protocol):
    """Nonblocking IPC to one independently killable *host* worker process.

    Each operation must return promptly.  ``terminate`` must retire the host
    worker, not the Android reader.  These requirements cannot be established
    merely by implementing this Protocol; therefore no live factory is wired.
    """

    def launch(self, selection: admission.DisposableSelection) -> None: ...
    def poll_before(self) -> CaptureHalf | None: ...
    def submit(self, manifest_raw: bytes, observer_source: bytes) -> None: ...
    def poll_final(self) -> FinalEvidence | None: ...
    def terminate(self) -> None: ...
    def join(self, timeout_ns: int) -> bool: ...


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require(ok: bool) -> None:
    if not ok:
        raise OneShotError("stock observation rejected")


def _precheck(selection: admission.DisposableSelection,
              before: CaptureHalf) -> tuple[int, str, str]:
    _require(type(before) is CaptureHalf)
    admission._selection(selection)
    _require(selection.document_uri == DISPOSABLE_URI)
    pid, start, boot, _ = admission._process(before.process)
    stock.validate_stock_dialect(before.activity_raw, before.window_raw,
                                 before.activity_raw, before.window_raw,
                                 expected_pid=pid)
    admission._file(before.pdf, path=selection.pdf_path,
                    serial=selection.authorized_serial, required=True,
                    selected_size=selection.pdf_size,
                    selected_sha256=selection.pdf_sha256, label="PDF")
    admission._file(before.mark, path=selection.pdf_path + ".mark",
                    serial=selection.authorized_serial, required=False,
                    selected_size=selection.mark_size,
                    selected_sha256=selection.mark_sha256, label="mark")
    _require(before.pdf.identity.slot != before.mark.identity.slot)
    admission._uri_resolution(before.uri_resolution_raw, selection)
    return pid, start, boot


def _manifest(selection: admission.DisposableSelection,
              before: CaptureHalf, deadline_ms: int) -> bytes:
    pid, start, _ = _precheck(selection, before)
    value = {
        "schemaVersion": SCHEMA_VERSION,
        "authority": MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": "com.supernote.document",
            "processName": "com.supernote.document",
            "pid": pid,
            "startTimeTicks": start,
            "firmwareFingerprint": graph.FIRMWARE_FINGERPRINT,
            "observerSha256": OBSERVER_SHA256,
        },
        "expected": {
            "documentUri": selection.document_uri,
            "markPath": (selection.pdf_path + ".mark"
                         if selection.mark_sha256 is not None else None),
        },
        "coordinator": {
            "maxJavaChooseWalks": 1,
            "retainedRootSamples": 2,
            "hardDeadlineMs": deadline_ms,
            "detachOnDeadline": True,
            "abortOnAnyError": True,
            "noRetry": True,
        },
    }
    raw = graph.canonical_bytes(value, 4096)
    _require(all(0x20 <= byte <= 0x7e for byte in raw))
    return raw


def _frame(raw: bytes) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME_BYTES)
    return graph.load_canonical(raw, MAX_FRAME_BYTES).value


def parse_identity_frames(frames: tuple[bytes, bytes], manifest_sha256: str,
                          *, mark_required: bool) -> dict[str, Any]:
    """Accept only the two exact success frames of the new stock observer."""
    _require(type(frames) is tuple and len(frames) == 2)
    first, complete = (_frame(item) for item in frames)
    _require(type(first) is dict and set(first) == {
        "event", "schemaVersion", "authority", "manifestSha256",
        "observationOnly", "hardwareAdmission", "hostAssertionsOnly",
        "runtimePidMatched", "heapWalks", "retainedRootSamples", "lifecycle",
        "uriAgreementAndExpectedMatch", "markPathPresent",
        "markPathMatchedExpected",
    })
    lifecycle = first["lifecycle"]
    _require(type(lifecycle) is dict and set(lifecycle) ==
             {"resumed", "finished", "destroyed"} and
             lifecycle["resumed"] is True and lifecycle["finished"] is False and
             lifecycle["destroyed"] is False)
    _require(first["event"] == "native_page_display0_identity" and
             type(first["schemaVersion"]) is int and first["schemaVersion"] == 1 and
             first["authority"] == RECORD_AUTHORITY and
             first["manifestSha256"] == manifest_sha256 and
             first["observationOnly"] is True and
             first["hardwareAdmission"] is False and
             first["hostAssertionsOnly"] is True and
             first["runtimePidMatched"] is True and
             type(first["heapWalks"]) is int and first["heapWalks"] == 1 and
             type(first["retainedRootSamples"]) is int and
             first["retainedRootSamples"] == 2 and
             first["uriAgreementAndExpectedMatch"] is True and
             type(first["markPathPresent"]) is bool)
    _require(first["markPathMatchedExpected"] is (True if mark_required else None))
    if mark_required:
        _require(first["markPathPresent"] is True)
    _require(type(complete) is dict and set(complete) == {"event", "success"} and
             complete["event"] == "native_page_display0_identity_complete" and
             complete["success"] is True)
    return first


def _wait(poll: Callable[[], Any], deadline_ns: int,
          clock_ns: Callable[[], int], pause: Callable[[float], None]) -> Any:
    while True:
        _require(clock_ns() < deadline_ns)
        result = poll()
        _require(clock_ns() < deadline_ns)
        if result is not None:
            return result
        remaining_ns = deadline_ns - clock_ns()
        _require(remaining_ns > 0)
        pause(min(0.01, remaining_ns / 1_000_000_000))


def run_one_shot(selection: admission.DisposableSelection,
                 observer_source: bytes, worker: KillableWorker,
                 *, deadline_ms: int = 1000,
                 clock_ns: Callable[[], int] = time.monotonic_ns,
                 pause: Callable[[float], None] = time.sleep) -> OneShotResult:
    """Check one injected worker run; never admit hardware or reader mutation."""
    _require(type(deadline_ms) is int and MIN_DEADLINE_MS <= deadline_ms <= MAX_DEADLINE_MS)
    _require(type(observer_source) is bytes and
             _sha(observer_source) == OBSERVER_SHA256)
    _require(type(selection) is admission.DisposableSelection)
    try:
        admission._selection(selection)
    except admission.AdmissionError:
        raise OneShotError("stock observation rejected") from None
    _require(selection.document_uri == DISPOSABLE_URI)
    start_ns = clock_ns()
    _require(type(start_ns) is int and start_ns > 0)
    deadline_ns = start_ns + deadline_ms * 1_000_000
    launched = False
    answer: OneShotResult | None = None
    failed = False
    try:
        # All worker methods must be nonblocking.  A future live backend must
        # establish this with OS-backed IPC and a disposable process owner.
        launched = True
        worker.launch(selection)
        before = _wait(worker.poll_before, deadline_ns, clock_ns, pause)
        manifest_raw = _manifest(selection, before, deadline_ms)
        _require(clock_ns() < deadline_ns)
        worker.submit(manifest_raw, observer_source)
        _require(clock_ns() < deadline_ns)
        final = _wait(worker.poll_final, deadline_ns, clock_ns, pause)
        _require(type(final) is FinalEvidence and
                 type(final.transport_trace) is tuple and
                 final.transport_trace == TRACE)
        identity = parse_identity_frames(final.frames, _sha(manifest_raw),
                                         mark_required=selection.mark_sha256 is not None)
        capture = observation.ObservationCapture(
            before.activity_raw, before.window_raw,
            final.after.activity_raw, final.after.window_raw,
            before.process, final.after.process,
            before.pdf, final.after.pdf,
            before.mark, final.after.mark,
            before.uri_resolution_raw, final.after.uri_resolution_raw,
        )
        consistent = observation.validate_observation(selection, capture)
        _require(clock_ns() < deadline_ns)
        record = {
            "schemaVersion": SCHEMA_VERSION,
            "authority": RUNNER_AUTHORITY,
            "selectionSha256": _sha(graph.canonical_bytes(asdict(selection))),
            "manifestSha256": _sha(manifest_raw),
            "observerSourceSha256": OBSERVER_SHA256,
            "observationConsistencySha256": consistent.sha256,
            "identityFrameSha256": _sha(final.frames[0]),
            "identityObserverReportedUriAgreement": identity[
                "uriAgreementAndExpectedMatch"],
            "transportTraceClaimed": list(TRACE),
            "oneShotWorkerClaimConsistent": True,
            "rawCaptureProvenanceVerified": False,
            "workerIsolationVerified": False,
            "documentIdentityVerified": False,
            "hardwareAdmission": False,
            "mutationCommandsAuthorized": False,
        }
        raw = graph.canonical_bytes(record, graph.MAX_AUTHORITY_BYTES)
        answer = OneShotResult(raw, _sha(raw))
    except BaseException:
        failed = True
    finally:
        # The final result is published only after retirement.  A worker that
        # cannot be joined is an uncertain cleanup, even if its frames passed.
        if launched:
            try:
                worker.terminate()
            except BaseException:
                failed = True
            try:
                remaining = max(0, deadline_ns - clock_ns())
                _require(worker.join(remaining) is True)
                _require(clock_ns() <= deadline_ns)
            except BaseException:
                failed = True
    if failed or answer is None:
        raise OneShotError("stock observation rejected") from None
    return answer


def run_live(*_args: Any, **_kwargs: Any) -> OneShotResult:
    """Explicitly blocked: no reviewed process-isolated ADB/Frida adapter."""
    raise LiveBackendUnavailable("stock one-shot live backend is unavailable")
