"""Host-only, phase-0 evidence check for an already-open stock reader on display 0.

This module performs no I/O, starts no process, and grants no Frida/hardware
admission. Its typed captures must eventually come from a separately reviewed,
retained read-only source. ActivityManager's resumed/visible record does not
prove WindowManager focus. A supplied URI-resolution digest does not prove
that a path resolves to the retained inode; a nonempty absence proof does not
prove that a .mark path is absent. Those limits remain explicit in the result.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
import stat
from typing import Any

import native_page_android_authority as android
from native_page_authority_provider import FileRead, ProcessRead
from native_page_cleanup_ledger import ResourceIdentity
import native_page_graph_v2_runner as graph


SCHEMA_VERSION = 1
SELECTION_AUTHORITY = "rtl-reader-native-page-display0-selection-v1"
ADMISSION_AUTHORITY = "rtl-reader-native-page-display0-pre-attach-v1"
MODE = "one-existing-document-observation"
AUTHORIZED_SERIAL = graph.AUTHORIZED_SERIAL
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_PROCESS_STAT_BYTES = 8192
MAX_URI_RESOLUTION_BYTES = 4096
FILE_URI = re.compile(
    r"file:///storage/emulated/0/Document/"
    r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.pdf\Z"
)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}\Z")


class AdmissionError(ValueError):
    """Phase-0 evidence is absent, malformed, or inconsistent."""


@dataclass(frozen=True)
class DisposableSelection:
    authority: str
    schema_version: int
    observation_session_id: str
    authorized_serial: str
    document_uri: str
    pdf_path: str
    pdf_size: int
    pdf_sha256: str
    mark_size: int | None
    mark_sha256: str | None
    disposable_attested: bool


@dataclass(frozen=True)
class PreAttachCapture:
    activity_raw: bytes
    process: ProcessRead
    pdf: FileRead
    mark: FileRead
    uri_resolution_raw: bytes


@dataclass(frozen=True)
class AdmissionResult:
    raw: bytes
    sha256: str

    def value(self) -> dict[str, Any]:
        return graph.load_canonical(self.raw, graph.MAX_AUTHORITY_BYTES).value


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionError(message)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _selection(value: DisposableSelection) -> None:
    _need(type(value) is DisposableSelection, "exact caller selection required")
    _need(type(value.schema_version) is int and value.schema_version == SCHEMA_VERSION and
          type(value.authority) is str and value.authority == SELECTION_AUTHORITY and
          type(value.authorized_serial) is str and value.authorized_serial == AUTHORIZED_SERIAL,
          "selection version or device differs")
    _need(type(value.observation_session_id) is str and
          TOKEN.fullmatch(value.observation_session_id) is not None,
          "observation session ID differs")
    _need(type(value.disposable_attested) is bool and value.disposable_attested,
          "caller must explicitly identify a disposable PDF")
    _need(type(value.document_uri) is str and FILE_URI.fullmatch(value.document_uri) is not None,
          "only an exact disposable file URI under Document is admitted")
    _need(type(value.pdf_path) is str and value.pdf_path == value.document_uri[7:],
          "selected PDF path and URI differ")
    _need(type(value.pdf_size) is int and 0 < value.pdf_size <= MAX_FILE_BYTES and
          type(value.pdf_sha256) is str and SHA256.fullmatch(value.pdf_sha256) is not None,
          "selected PDF size or digest differs")
    if value.mark_sha256 is None:
        _need(value.mark_size is None, "absent mark selection must be exactly nullable")
    else:
        _need(type(value.mark_sha256) is str and SHA256.fullmatch(value.mark_sha256) is not None and
              type(value.mark_size) is int and 0 < value.mark_size <= MAX_FILE_BYTES,
              "selected mark size or digest differs")


def _process(value: ProcessRead) -> tuple[int, str, str, dict[str, str]]:
    _need(type(value) is ProcessRead and type(value.stat_bytes) is bytes and
          type(value.cmdline_bytes) is bytes and type(value.boot_id) is str,
          "raw typed process evidence required")
    _need(0 < len(value.stat_bytes) <= MAX_PROCESS_STAT_BYTES and
          value.cmdline_bytes == android.PROCESS.encode("ascii") + b"\x00" and
          BOOT_ID.fullmatch(value.boot_id) is not None,
          "process stat, cmdline, or boot identity differs")
    try:
        text = value.stat_bytes.decode("ascii", "strict")
    except UnicodeError as error:
        raise AdmissionError("process stat is not ASCII") from error
    match = re.fullmatch(r"([1-9][0-9]*) \(([ -~]{1,256})\) ([RSDI]) ([!-~ ]+)\n", text)
    _need(match is not None, "process stat is malformed or not live")
    assert match is not None
    fields = match.group(4).split(" ")
    _need(len(fields) >= 19 and all(re.fullmatch(r"[!-~]+", field) is not None
                                   for field in fields) and
          DECIMAL.fullmatch(fields[18]) is not None,
          "process start time is missing or noncanonical")
    pid = int(match.group(1))
    _need(1 <= pid <= android.MAX_PID, "process PID is outside Android bounds")
    return pid, fields[18], value.boot_id, {
        "statSha256": _digest(value.stat_bytes),
        "cmdlineSha256": _digest(value.cmdline_bytes),
    }


def _stat(raw: bytes | None, label: str) -> dict[str, Any]:
    _need(type(raw) is bytes and 0 < len(raw) <= 2048, label + " fstat bytes required")
    try:
        loaded = graph.load_canonical(raw, 2048)
        graph._validate_stat(loaded.value, label)
    except graph.GraphRunnerError as error:
        raise AdmissionError(label + " fstat is not canonical") from error
    _need(stat.S_ISREG(int(loaded.value["mode"])), label + " is not a regular file")
    return loaded.value


def _file(value: FileRead, *, path: str, serial: str, required: bool,
          selected_size: int | None, selected_sha256: str | None,
          label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _need(type(value) is FileRead and type(value.identity) is ResourceIdentity and
          type(value.path) is str and value.path == path and type(value.present) is bool,
          label + " retained file capture differs")
    identity = value.identity
    _need(identity.kind == "file" and identity.namespace == serial,
          label + " descriptor identity differs")
    if not value.present:
        _need(not required and selected_size is None and selected_sha256 is None and
              value.contents is None and value.stat_before is None and value.stat_after is None and
              type(value.absence_proof) is bytes and 0 < len(value.absence_proof) <= 4096,
              label + " absence is not independently evidenced")
        return ({"present": False, "path": None, "size": None, "sha256": None, "stat": None},
                {"identity": identity.wire(), "absenceProofSha256": _digest(value.absence_proof)})
    _need(type(value.contents) is bytes and 0 < len(value.contents) <= MAX_FILE_BYTES and
          value.absence_proof is None and len(value.contents) == selected_size and
          _digest(value.contents) == selected_sha256,
          label + " bytes differ from exact caller selection")
    before = _stat(value.stat_before, label + " before")
    after = _stat(value.stat_after, label + " after")
    _need(before == after, label + " fstat changed during retained read")
    return ({"present": True, "path": path, "size": str(len(value.contents)),
             "sha256": _digest(value.contents), "stat": before},
            {"identity": identity.wire(), "beforeStatSha256": _digest(value.stat_before),
             "afterStatSha256": _digest(value.stat_after)})


def _uri_resolution(raw: bytes, selection: DisposableSelection) -> dict[str, Any]:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_URI_RESOLUTION_BYTES,
          "raw file URI resolution required")
    try:
        value = graph.load_canonical(raw, MAX_URI_RESOLUTION_BYTES).value
    except graph.GraphRunnerError as error:
        raise AdmissionError("URI resolution is not canonical") from error
    _need(type(value) is dict and set(value) ==
          {"authority", "documentUri", "resolvedPath", "evidenceSha256"} and
          value["authority"] == "rtl-reader-file-uri-resolution-v1" and
          value["documentUri"] == selection.document_uri and
          value["resolvedPath"] == selection.pdf_path and
          type(value["evidenceSha256"]) is str and
          SHA256.fullmatch(value["evidenceSha256"]) is not None,
          "file URI resolution differs from exact selection")
    return value


def validate_pre_attach(selection: DisposableSelection,
                        capture: PreAttachCapture) -> AdmissionResult:
    """Validate detached raw evidence; never authorize attach or stock mutation."""
    _selection(selection)
    _need(type(capture) is PreAttachCapture and type(capture.activity_raw) is bytes,
          "exact pre-attach capture required")
    pid, start_ticks, boot_id, process_hashes = _process(capture.process)
    try:
        task = android.parse_document_task_authority(capture.activity_raw,
                                                     expected_pid=pid, require_live=True)
    except android.AndroidAuthorityError as error:
        raise AdmissionError("one live stock DocumentActivity was not established") from error
    _need(task.display_id == 0 and task.package_name == android.PACKAGE and
          task.process_name == android.PROCESS and
          task.component in (android.SHORT_COMPONENT, android.FULL_COMPONENT),
          "stock DocumentActivity is not on display 0")
    pdf, pdf_evidence = _file(capture.pdf, path=selection.pdf_path,
                              serial=selection.authorized_serial, required=True,
                              selected_size=selection.pdf_size,
                              selected_sha256=selection.pdf_sha256, label="PDF")
    mark, mark_evidence = _file(capture.mark, path=selection.pdf_path + ".mark",
                                serial=selection.authorized_serial, required=False,
                                selected_size=selection.mark_size,
                                selected_sha256=selection.mark_sha256, label="mark")
    _need(capture.pdf.identity.slot != capture.mark.identity.slot,
          "PDF and mark descriptor slots alias")
    resolution = _uri_resolution(capture.uri_resolution_raw, selection)
    pdf["documentUri"] = selection.document_uri
    pdf["uriResolution"] = resolution
    selection_wire = graph.canonical_bytes(asdict(selection))
    record = {
        "schemaVersion": SCHEMA_VERSION,
        "authority": ADMISSION_AUTHORITY,
        "mode": MODE,
        "preAttachOnly": True,
        "hardwareAdmission": False,
        "focusVerified": False,
        "documentIdentityConfirmedByObserver": False,
        "uriResolutionIndependentlyVerified": False,
        "filePathIdentityVerified": False,
        "markAbsenceIndependentlyVerified": False,
        "disposableStatus": "caller-attested-only",
        "mutationCommandsAuthorized": False,
        "observationSessionId": selection.observation_session_id,
        "authorizedSerial": selection.authorized_serial,
        "selectionSha256": _digest(selection_wire),
        "target": {"pid": pid, "startTimeTicks": start_ticks, "bootId": boot_id,
                   "packageName": android.PACKAGE, "processName": android.PROCESS,
                   **process_hashes},
        "task": asdict(task),
        "taskAuthoritySha256": _digest(task.canonical_bytes()),
        "files": {"originalPdf": pdf, "mark": mark},
        "retainedFileEvidence": {"originalPdf": pdf_evidence, "mark": mark_evidence},
        "uriResolutionSha256": _digest(capture.uri_resolution_raw),
    }
    try:
        raw = graph.canonical_bytes(record, graph.MAX_AUTHORITY_BYTES)
    except graph.GraphRunnerError as error:
        raise AdmissionError("pre-attach record is not canonical") from error
    return AdmissionResult(raw, _digest(raw))
