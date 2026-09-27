"""Offline composition of *supplied* stock display-0 observation evidence.

This is a consistency check, not a capture mechanism or an attach permit.  In
particular, neither caller-supplied file bytes nor a graph-shaped message prove
their own provenance.  The frozen virtual-display v2 runner/manifest is not a
stock-reader authority and is deliberately not invoked here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from typing import Any

from native_page_authority_provider import FileRead, ProcessRead
import native_page_display0_admission as admission
import native_page_display0_stock_dialect as stock
import native_page_graph_v2_runner as graph


AUTHORITY = "rtl-reader-native-page-display0-observation-consistency-v1"
SCHEMA_VERSION = 1


class ObservationError(ValueError):
    """Supplied pre/post evidence is malformed, stale, or contradictory."""


@dataclass(frozen=True)
class ObservationCapture:
    before_activity_raw: bytes
    before_window_raw: bytes
    after_activity_raw: bytes
    after_window_raw: bytes
    before_process: ProcessRead
    after_process: ProcessRead
    before_pdf: FileRead
    after_pdf: FileRead
    before_mark: FileRead
    after_mark: FileRead
    before_uri_resolution_raw: bytes
    after_uri_resolution_raw: bytes
    candidate_graph_raw: bytes | None = None


@dataclass(frozen=True)
class ObservationResult:
    raw: bytes
    sha256: str

    def value(self) -> dict[str, Any]:
        return graph.load_canonical(self.raw, graph.MAX_AUTHORITY_BYTES).value


def _need(ok: bool, message: str) -> None:
    if not ok:
        raise ObservationError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _process_pair(capture: ObservationCapture, expected_pid: int) -> tuple[str, str]:
    before = admission._process(capture.before_process)
    after = admission._process(capture.after_process)
    _need(before[:3] == after[:3] and before[0] == expected_pid,
          "boot, process PID, or start time changed across observation")
    return before[1], before[2]


def _file_pair(selection: admission.DisposableSelection,
               capture: ObservationCapture, role: str) -> dict[str, Any]:
    is_pdf = role == "originalPdf"
    path = selection.pdf_path + ("" if is_pdf else ".mark")
    size = selection.pdf_size if is_pdf else selection.mark_size
    digest = selection.pdf_sha256 if is_pdf else selection.mark_sha256
    first = capture.before_pdf if is_pdf else capture.before_mark
    second = capture.after_pdf if is_pdf else capture.after_mark
    records = [admission._file(item, path=path, serial=selection.authorized_serial,
                               required=is_pdf, selected_size=size,
                               selected_sha256=digest, label=role)[0]
               for item in (first, second)]
    _need(records[0] == records[1], role + " inode/stat or contents changed")
    return records[0]


def _candidate_graph(raw: bytes | None, selection: admission.DisposableSelection,
                     *, pid: int, start: str, task_id: int) -> dict[str, Any]:
    if raw is None:
        return {"status": "absent", "sha256": None}
    _need(type(raw) is bytes, "candidate graph must be exact canonical bytes")
    value = graph.load_canonical(raw, graph.MAX_MESSAGE_BYTES).value
    _need(type(value) is dict and set(value) ==
          {"event", "schemaVersion", "authority", "manifestSha256", "observationOnly",
           "atomic", "attachment", "externalSession", "fileAuthority", "coordinator",
           "calibrationProfile", "lifecycle", "document", "pageInfo", "presenter",
           "views", "layers"}, "candidate graph top-level shape differs")
    _need(value["event"] == "native_page_graph_snapshot" and
          type(value["schemaVersion"]) is int and value["schemaVersion"] == 2 and
          value["authority"] == graph.SNAPSHOT_AUTHORITY and
          value["observationOnly"] is True and value["atomic"] is False,
          "candidate graph version or mode differs")
    attachment, session = value["attachment"], value["externalSession"]
    document, presenter, lifecycle = value["document"], value["presenter"], value["lifecycle"]
    _need(all(type(item) is dict for item in
              (attachment, session, document, presenter, lifecycle)),
          "candidate graph identity records differ")
    _need(attachment.get("packageName") == "com.supernote.document" and
          attachment.get("processName") == "com.supernote.document" and
          type(attachment.get("pid")) is int and attachment["pid"] == pid and
          attachment.get("processStartTimeTicks") == start and
          type(session.get("displayId")) is int and session["displayId"] == 0 and
          type(session.get("taskId")) is int and session["taskId"] == task_id and
          session.get("authorizedSerial") == selection.authorized_serial,
          "candidate graph targets another reader process, boot session, or display")
    expected_mark_path = selection.pdf_path + ".mark"
    # A reader may report its eventual .mark save path before that file exists.
    # No absent-file conclusion is drawn from this presenter property.
    allowed_mark_paths = ({expected_mark_path} if selection.mark_sha256 is not None
                          else {None, expected_mark_path})
    mark_path = presenter.get("markPath")
    _need(mark_path is None or type(mark_path) is str,
          "candidate graph mark path has an invalid type")
    _need(document.get("uri") == selection.document_uri and
          presenter.get("uri") == selection.document_uri and
          mark_path in allowed_mark_paths,
          "candidate graph describes another document or mark")
    _need(lifecycle == {"resumed": True, "finished": False,
                        "destroyed": False, "graphStable": True},
          "candidate graph lifecycle differs")
    # No manifest, trusted injected-source digest, Frida lifecycle, or retained
    # capture source is established by this comparison. Never call this a
    # validated v2 snapshot or an in-process document-identity witness.
    return {"status": "identity-shape-only-untrusted", "sha256": _sha(raw)}


def validate_observation(selection: admission.DisposableSelection,
                         capture: ObservationCapture) -> ObservationResult:
    """Compare detached pre/post evidence; never authorize attach or mutation."""
    try:
        admission._selection(selection)
        _need(type(capture) is ObservationCapture, "exact observation capture required")
        before_pid, start, boot = admission._process(capture.before_process)[:3]
        dialect = stock.validate_stock_dialect(
            capture.before_activity_raw, capture.before_window_raw,
            capture.after_activity_raw, capture.after_window_raw,
            expected_pid=before_pid)
        checked_start, checked_boot = _process_pair(capture, before_pid)
        _need(start == checked_start and boot == checked_boot,
              "stock process changed during observation")
        pdf = _file_pair(selection, capture, "originalPdf")
        mark = _file_pair(selection, capture, "mark")
        _need(capture.before_pdf.identity.slot != capture.before_mark.identity.slot and
              capture.after_pdf.identity.slot != capture.after_mark.identity.slot,
              "PDF and mark descriptor slots alias")
        for raw in (capture.before_uri_resolution_raw, capture.after_uri_resolution_raw):
            admission._uri_resolution(raw, selection)
        candidate = _candidate_graph(capture.candidate_graph_raw, selection,
                                     pid=before_pid, start=start,
                                     task_id=dialect.value()["taskId"])
    except (admission.AdmissionError, stock.StockDialectError,
            graph.GraphRunnerError) as error:
        raise ObservationError("stock observation evidence rejected") from error
    record = {
        "schemaVersion": SCHEMA_VERSION, "authority": AUTHORITY,
        "authorizedSerial": selection.authorized_serial,
        "observationSessionId": selection.observation_session_id,
        "selectionSha256": _sha(graph.canonical_bytes(asdict(selection))),
        "stockDialectSha256": dialect.sha256,
        "bootId": boot, "pid": before_pid, "processStartTimeTicks": start,
        "documentUri": selection.document_uri,
        "originalPdf": {"size": pdf["size"], "sha256": pdf["sha256"],
                        "stat": pdf["stat"]},
        "mark": {"present": mark["present"], "size": mark["size"],
                 "sha256": mark["sha256"], "stat": mark["stat"]},
        "candidateGraph": candidate,
        "prePostSuppliedEvidenceConsistent": True,
        "rawCaptureProvenanceVerified": False,
        "processStartTimeIndependentlyVerified": False,
        "fileReadProvenanceVerified": False,
        "uriResolutionIndependentlyVerified": False,
        "markAbsenceIndependentlyVerified": False,
        "stockGraphContractVerified": False,
        "graphSnapshotVerified": False,
        "documentIdentityVerified": False,
        "hardwareAdmission": False,
        "mutationCommandsAuthorized": False,
    }
    try:
        raw = graph.canonical_bytes(record, graph.MAX_AUTHORITY_BYTES)
    except graph.GraphRunnerError as error:
        raise ObservationError("observation result is not canonical") from error
    return ObservationResult(raw, _sha(raw))
