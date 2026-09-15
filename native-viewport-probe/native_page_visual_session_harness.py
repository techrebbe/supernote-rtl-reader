"""Deterministic evidence binder for the visual-only native-page rerun.

This module deliberately has no ADB, Frida, shell, process, input, filesystem
path discovery, or device implementation.  It composes only injected retained
authorities and the already-reviewed HostAuthority/Android authority parsers.
The command-line entry point is status-only and remains hardware blocked.

The evidence log is an append-only hash chain stored by WindowsCleanupStore.
Every record is published no-replace, flushed, and bound by the store's
independent checkpoint directory before the next operation can begin.  The
terminal record is the immutable session manifest; there is no post-terminal
append path.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import argparse
import binascii
import hashlib
import json
import re
import sys
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid
import zlib

import native_page_android_authority as android
import native_page_cleanup_ledger as ledger
from native_page_cleanup_store import WindowsCleanupStore
import native_page_graph_v2_runner as graph
import native_page_host_authority as host


AUTHORITY = "rtl-reader-native-page-visual-session-harness-v1"
MANIFEST_AUTHORITY = "rtl-reader-native-page-visual-session-manifest-v1"
ARTIFACT_AUTHORITY = "rtl-reader-native-page-visual-artifact-ref-v1"
FILE_AUTHORITY = "rtl-reader-native-page-visual-file-evidence-v1"
SAVED_INK_AUTHORITY = "rtl-reader-native-page-saved-ink-evidence-v1"
ORIENTATION_AUTHORITY = "rtl-reader-physical-orientation-observation-v1"
VISUAL_CAPTURE_AUTHORITY = "rtl-reader-native-page-visual-capture-v1"
TASK_LAUNCH_UNCERTAINTY_AUTHORITY = (
    "rtl-reader-native-page-task-launch-uncertainty-v1")
AUTHORIZED_SERIAL = "SN078C10015092"
SHELL_UID = 2000
MAX_ADAPTER_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_FAILURE_CHARS = 1000
HEX = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
FIXTURE_URI = re.compile(
    r"file:///storage/emulated/0/Download/"
    r"NativeViewportVisualOnly-[A-Za-z0-9._-]{1,96}\.pdf\Z"
)

BLOCKERS = (
    "REVIEWED_COMPLETE_PLATFORM_INVENTORY_ADAPTER_REQUIRED",
    "REVIEWED_NO_PEN_SEMANTIC_SAMPLE_ADAPTER_REQUIRED",
    "REVIEWED_EXACT_FIXTURE_TASK_LAUNCH_TEARDOWN_ADAPTER_REQUIRED",
    "REVIEWED_PRE_ATTACH_DISPLAY_ABORT_AUTHORITY_REQUIRED",
    "REVIEWED_SHELL_UID_SAVEDINK_CAPTURE_ADAPTER_REQUIRED",
    "REVIEWED_IMMUTABLE_ARTIFACT_AUTHORITY_REQUIRED",
    "REVIEWED_READ_ONLY_VISUAL_CAPTURE_ADAPTER_REQUIRED",
    "INTEGRATED_HARDWARE_EXACT_HEAD_REVIEW_REQUIRED",
)


class HarnessError(RuntimeError):
    pass


class HarnessAdmissionBlocked(HarnessError):
    pass


class EvidenceRejected(HarnessError):
    pass


def _launch_foreign_wire(value: host.ForeignIdentity | None) -> dict[str, Any] | None:
    if value is None:
        return None
    _need(type(value) is host.ForeignIdentity,
          "uncertain launch retained identity has an inexact type")
    process = value.process
    _need(type(process) is host.ProcessIdentity and
          type(process.pid) is int and 1 <= process.pid <= android.MAX_PID and
          type(process.start_ticks) is int and process.start_ticks > 0 and
          type(process.uid) is int and process.uid == android.SYSTEM_UID and
          process.package == host.FOREIGN_PACKAGE and
          type(value.task_id) is int and value.task_id > 0 and
          type(value.activity_token) is str and
          re.fullmatch(r"[0-9a-f]+", value.activity_token) is not None and
          type(value.evidence_sha256) is str and
          HEX.fullmatch(value.evidence_sha256) is not None and
          value.component == host.FOREIGN_COMPONENT,
          "uncertain launch retained identity escaped the exact stock domain")
    return {
        **value.wire(),
        "activityToken": value.activity_token,
    }


class TaskLaunchOutcomeUncertain(EvidenceRejected):
    """Typed, immutable launch uncertainty crossing TaskAuthority boundaries.

    An optional identity is cleanup authority only after the harness re-pins
    the throwing adapter and validates the exact stock task/process domain.
    The bounded canonical evidence is constructed here rather than accepted
    as caller-controlled bytes.
    """

    side_effect_possible = True

    def __init__(self, message: str,
                 retained_foreign: host.ForeignIdentity | None = None,
                 *, reason_code: str = "LAUNCH_OUTCOME_UNCERTAIN"):
        _need(type(message) is str and 0 < len(message) <= MAX_FAILURE_CHARS,
              "uncertain launch message is absent or oversized")
        _token(reason_code, "uncertain launch reason")
        foreign_wire = _launch_foreign_wire(retained_foreign)
        evidence = graph.canonical_bytes({
            "authority": TASK_LAUNCH_UNCERTAINTY_AUTHORITY,
            "schemaVersion": 1,
            "reasonCode": reason_code,
            "message": message,
            "sideEffectPossible": True,
            "retainedForeign": foreign_wire,
        })
        _need(0 < len(evidence) <= MAX_ADAPTER_BYTES,
              "uncertain launch evidence is absent or oversized")
        HarnessError.__init__(self, message)
        object.__setattr__(self, "_retained_foreign", retained_foreign)
        object.__setattr__(self, "_evidence", evidence)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("task launch uncertainty evidence is immutable")
        object.__setattr__(self, name, value)

    @property
    def retained_foreign(self) -> host.ForeignIdentity | None:
        return self._retained_foreign

    @property
    def evidence(self) -> bytes:
        return self._evidence


class SessionFailed(HarnessError):
    def __init__(self, manifest: dict[str, Any]):
        super().__init__("visual session failed and exact cleanup completed")
        self.manifest = manifest


class SessionQuarantined(HarnessError):
    def __init__(self, terminal: dict[str, Any]):
        super().__init__("visual session has unresolved exact cleanup obligations")
        self.terminal = terminal


def admission_status() -> dict[str, Any]:
    return {
        "admitted": False,
        "diagnosticOnly": True,
        "visualOnly": True,
        "blockers": list(BLOCKERS),
        "noRetry": True,
        "forbidden": [
            "pen-or-touch-input",
            "pen-lease-or-event-device-operation",
            "writer-or-save-method",
            "user-document-selection",
            "boox-device",
            "ambient-adb-or-frida",
            "broad-task-or-process-cleanup",
        ],
    }


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceRejected(message)


def _sha(raw: bytes) -> str:
    _need(type(raw) is bytes, "digest input is not exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _sha(graph.canonical_bytes(value))


def _keys(value: Any, names: set[str], label: str) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == names,
          label + " topology differs")
    return value


def _hex(value: Any, label: str) -> str:
    _need(type(value) is str and HEX.fullmatch(value) is not None,
          label + " SHA-256 differs")
    return value


def _token(value: Any, label: str) -> str:
    _need(type(value) is str and TOKEN.fullmatch(value) is not None,
          label + " token differs")
    return value


def _bounded_record_data(value: Any, depth: int = 0,
                         count: list[int] | None = None) -> None:
    """Validate the nonnegative strict-JSON domain used by CleanupStore."""
    count = [0] if count is None else count
    count[0] += 1
    _need(depth <= 32 and count[0] <= 32768,
          "session record topology exceeds bound")
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int:
        _need(0 <= value <= 2**63 - 1, "session record integer is out of range")
        return
    if type(value) is list:
        for item in value:
            _bounded_record_data(item, depth + 1, count)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _bounded_record_data(item, depth + 1, count)
        return
    raise EvidenceRejected("session record contains a noncanonical value")


def _validate_png(raw: bytes, width: int, height: int) -> str:
    """Validate a complete non-interlaced PNG and its decoded row geometry."""
    _need(type(raw) is bytes and 33 <= len(raw) <= MAX_ARTIFACT_BYTES and
          raw.startswith(PNG_SIGNATURE),
          "visual capture is not a bounded PNG")
    offset = len(PNG_SIGNATURE)
    chunks: list[tuple[bytes, bytes]] = []
    while offset < len(raw):
        _need(offset + 12 <= len(raw), "visual PNG chunk header is truncated")
        size = int.from_bytes(raw[offset:offset + 4], "big")
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + size
        _need(size <= MAX_ARTIFACT_BYTES and end <= len(raw),
              "visual PNG chunk exceeds the retained wire")
        payload = raw[offset + 8:offset + 8 + size]
        checksum = int.from_bytes(raw[offset + 8 + size:end], "big")
        _need((binascii.crc32(kind + payload) & 0xffffffff) == checksum,
              "visual PNG chunk CRC differs")
        chunks.append((kind, payload))
        offset = end
        if kind == b"IEND":
            break
    _need(offset == len(raw) and chunks and chunks[0][0] == b"IHDR" and
          chunks[-1] == (b"IEND", b"") and
          sum(kind == b"IHDR" for kind, _ in chunks) == 1 and
          sum(kind == b"IEND" for kind, _ in chunks) == 1,
          "visual PNG structure differs")
    header = chunks[0][1]
    _need(len(header) == 13, "visual PNG IHDR differs")
    actual_width = int.from_bytes(header[0:4], "big")
    actual_height = int.from_bytes(header[4:8], "big")
    bit_depth, color_type, compression, filtering, interlace = header[8:13]
    legal_depths = {
        0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8},
        4: {8, 16}, 6: {8, 16},
    }
    _need((actual_width, actual_height) == (width, height) and
          color_type in legal_depths and
          bit_depth in legal_depths[color_type] and
          compression == 0 and filtering == 0 and interlace == 0,
          "visual PNG decoded geometry/format differs")
    kinds = [kind for kind, _ in chunks]
    _need(b"IDAT" in kinds and
          all(kind in (b"IHDR", b"PLTE", b"IDAT", b"IEND") or
              (kind[0] & 0x20) != 0 for kind in kinds),
          "visual PNG lacks pixels or has an unknown critical chunk")
    first_idat = kinds.index(b"IDAT")
    last_idat = len(kinds) - 1 - kinds[::-1].index(b"IDAT")
    _need(all(kind == b"IDAT" for kind in kinds[first_idat:last_idat + 1]),
          "visual PNG IDAT stream is not contiguous")
    if color_type == 3:
        _need(b"PLTE" in kinds[:first_idat],
              "indexed visual PNG lacks a preceding palette")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    row_bytes = (actual_width * channels * bit_depth + 7) // 8
    expected = actual_height * (row_bytes + 1)
    _need(expected <= MAX_ARTIFACT_BYTES,
          "visual PNG decoded pixels exceed the evidence bound")
    compressed = b"".join(payload for kind, payload in chunks
                           if kind == b"IDAT")
    try:
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(compressed, expected + 1)
        _need(len(pixels) <= expected and not decoder.unconsumed_tail,
              "visual PNG expands beyond its declared geometry")
        pixels += decoder.flush(expected + 1 - len(pixels))
    except zlib.error as error:
        raise EvidenceRejected("visual PNG pixel stream is invalid") from error
    _need(decoder.eof and not decoder.unused_data and
          len(pixels) == expected and
          all(pixels[row * (row_bytes + 1)] <= 4
              for row in range(actual_height)),
          "visual PNG decoded scanlines differ")
    return _sha(raw)


@dataclass(frozen=True)
class Phase:
    name: str
    placement: host.Placement
    physical: str
    width: int
    height: int
    rect: host.Rect

    def wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "placement": self.placement.value,
            "physical": self.physical,
            "width": self.width,
            "height": self.height,
            "rect": self.rect.wire(),
        }


BASE_PHASES = (
    Phase("LANDSCAPE_FULL_INITIAL", host.Placement.FULL, "LANDSCAPE",
          1872, 1404, host.Rect(409, 0, 1053, 1404)),
    Phase("LANDSCAPE_LEFT", host.Placement.LEFT, "LANDSCAPE",
          1872, 1404, host.Rect(0, 78, 936, 1248)),
    Phase("LANDSCAPE_RIGHT", host.Placement.RIGHT, "LANDSCAPE",
          1872, 1404, host.Rect(936, 78, 936, 1248)),
    Phase("LANDSCAPE_FULL_PLACEMENT_RETURN", host.Placement.FULL, "LANDSCAPE",
          1872, 1404, host.Rect(409, 0, 1053, 1404)),
)

ROTATION_PHASES = (
    Phase("PORTRAIT_FULL", host.Placement.FULL, "PORTRAIT",
          1404, 1872, host.Rect(0, 0, 1404, 1872)),
    Phase("LANDSCAPE_FULL_ROTATION_RETURN", host.Placement.FULL, "LANDSCAPE",
          1872, 1404, host.Rect(409, 0, 1053, 1404)),
)


@dataclass(frozen=True)
class SessionPlan:
    session_id: str
    fixture_uri: str
    fixture_sha256: str
    monotonic_domain_sha256: str
    absolute_deadline_ns: int
    include_physical_rotation: bool
    adapter_pins: Mapping[str, str]

    def __post_init__(self) -> None:
        try:
            canonical = str(uuid.UUID(self.session_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise EvidenceRejected("session ID is not a canonical UUID") from error
        _need(canonical == self.session_id, "session ID is not canonical")
        _need(type(self.fixture_uri) is str and
              FIXTURE_URI.fullmatch(self.fixture_uri) is not None and
              ".." not in self.fixture_uri,
              "only a disposable visual fixture in Download is admitted")
        _hex(self.fixture_sha256, "fixture")
        _hex(self.monotonic_domain_sha256, "monotonic clock domain")
        _need(type(self.absolute_deadline_ns) is int and
              0 < self.absolute_deadline_ns <= 2**63 - 1,
              "absolute deadline differs")
        _need(type(self.include_physical_rotation) is bool,
              "physical-rotation scope is not boolean")
        _need(self.include_physical_rotation is True,
              "portrait and landscape physical-rotation return are mandatory")
        expected = {"artifact", "platform", "semantic", "task", "file",
                    "orientation", "visual"}
        supplied_pins = self.adapter_pins
        _need(type(supplied_pins) is dict and
              set(supplied_pins) == expected,
              "complete exact adapter pin set required")
        for name, value in supplied_pins.items():
            _token(name, "adapter name")
            _hex(value, "adapter " + name)
        object.__setattr__(self, "adapter_pins", MappingProxyType(
            dict(sorted(supplied_pins.items()))))

    @property
    def phases(self) -> tuple[Phase, ...]:
        return BASE_PHASES + ROTATION_PHASES

    def wire(self) -> dict[str, Any]:
        return {
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "sessionId": self.session_id,
            "authorizedSerial": AUTHORIZED_SERIAL,
            "fixtureUri": self.fixture_uri,
            "fixtureSha256": self.fixture_sha256,
            "monotonicDomainSha256": self.monotonic_domain_sha256,
            "absoluteDeadlineNs": str(self.absolute_deadline_ns),
            "phases": [phase.wire() for phase in self.phases],
            "semanticSamplesPerPhase": 2,
            "inputOperationCount": 0,
            "writerOperationCount": 0,
            "retryAllowed": False,
            "adapterPins": dict(sorted(self.adapter_pins.items())),
        }

    @property
    def sha256(self) -> str:
        return _digest(self.wire())


@dataclass(frozen=True)
class ArtifactRef:
    logical_name: str
    media_type: str
    size: int
    sha256: str
    producer_authority_sha256: str
    store_identity_sha256: str
    immutable: bool

    def wire(self) -> dict[str, Any]:
        return {
            "authority": ARTIFACT_AUTHORITY,
            "logicalName": self.logical_name,
            "mediaType": self.media_type,
            "bytes": self.size,
            "sha256": self.sha256,
            "producerAuthoritySha256": self.producer_authority_sha256,
            "storeIdentitySha256": self.store_identity_sha256,
            "immutable": self.immutable,
        }


def _validate_artifact_ref(value: ArtifactRef, *, logical_name: str,
                           raw: bytes, producer_sha256: str) -> None:
    _need(type(value) is ArtifactRef, "artifact authority returned wrong type")
    _need(value.logical_name == logical_name and value.media_type and
          type(value.size) is int and value.size == len(raw) and
          0 < value.size <= MAX_ARTIFACT_BYTES and
          value.sha256 == _sha(raw) and
          value.producer_authority_sha256 == producer_sha256 and
          value.immutable is True,
          "artifact reference is not exact immutable content authority")
    _hex(value.sha256, "artifact")
    _hex(value.producer_authority_sha256, "artifact producer")
    _hex(value.store_identity_sha256, "artifact store")


def _validate_artifact_wire(value: Any) -> dict[str, Any]:
    item = _keys(value, {
        "authority", "logicalName", "mediaType", "bytes", "sha256",
        "producerAuthoritySha256", "storeIdentitySha256", "immutable",
    }, "artifact reference")
    _need(item["authority"] == ARTIFACT_AUTHORITY and
          type(item["logicalName"]) is str and
          0 < len(item["logicalName"]) <= 240 and
          type(item["mediaType"]) is str and
          0 < len(item["mediaType"]) <= 128 and
          type(item["bytes"]) is int and
          0 < item["bytes"] <= MAX_ARTIFACT_BYTES and
          item["immutable"] is True,
          "artifact wire authority differs")
    _hex(item["sha256"], "artifact wire")
    _hex(item["producerAuthoritySha256"], "artifact producer wire")
    _hex(item["storeIdentitySha256"], "artifact store wire")
    return item


@dataclass(frozen=True)
class DeviceFile:
    present: bool
    path: str | None
    size: int | None
    sha256: str | None
    device: int | None
    inode: int | None
    mode: int | None
    uid: int | None
    gid: int | None
    mtime_ns: int | None
    ctime_ns: int | None

    def wire(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "stat": None if not self.present else {
                "device": self.device,
                "inode": self.inode,
                "mode": self.mode,
                "uid": self.uid,
                "gid": self.gid,
                "mtimeNs": str(self.mtime_ns),
                "ctimeNs": str(self.ctime_ns),
            },
        }


def _validate_device_file(value: DeviceFile, *, expected_path: str,
                          required: bool) -> None:
    _need(type(value) is DeviceFile and type(value.present) is bool,
          "device file evidence type differs")
    _need(value.present or not required, "required PDF evidence is absent")
    scalar = (value.size, value.device, value.inode, value.mode, value.uid,
              value.gid, value.mtime_ns, value.ctime_ns)
    if value.present:
        _need(value.path == expected_path and
              all(type(item) is int and item >= 0 for item in scalar),
              "present device file stat/path authority differs")
        _need(type(value.size) is int and 0 < value.size <= 2**63 - 1,
              "present device file size differs")
        _hex(value.sha256, "device file")
    else:
        _need(value.path is None and value.sha256 is None and
              all(item is None for item in scalar),
              "absent device file must be an exact nullable record")


def _graph_stat(value: DeviceFile) -> dict[str, Any] | None:
    if not value.present:
        return None
    return {
        "device": str(value.device),
        "inode": str(value.inode),
        "mode": str(value.mode),
        "uid": value.uid,
        "gid": value.gid,
        "mtimeNs": str(value.mtime_ns),
        "ctimeNs": str(value.ctime_ns),
    }


@dataclass(frozen=True)
class SavedInkEvidence:
    state: str
    collector_uid: int
    collector_artifact_sha256: str
    source_mark_sha256: str | None
    canonical_sha256: str
    record_count: int
    raw: bytes

    def wire(self) -> dict[str, Any]:
        return {
            "authority": SAVED_INK_AUTHORITY,
            "state": self.state,
            "collectorUid": self.collector_uid,
            "collectorArtifactSha256": self.collector_artifact_sha256,
            "sourceMarkSha256": self.source_mark_sha256,
            "canonicalSha256": self.canonical_sha256,
            "recordCount": self.record_count,
        }


@dataclass(frozen=True)
class FileEvidenceCapture:
    captured_ns: int
    phase: str
    pdf: DeviceFile
    mark: DeviceFile
    saved_ink: SavedInkEvidence
    files_authority: dict[str, Any]
    raw: bytes


@dataclass(frozen=True)
class PlatformCapture:
    captured_ns: int
    snapshot: host.Snapshot
    activity_manager_raw: bytes
    window_manager_raw: bytes
    process_inventory_raw: bytes
    display_inventory_raw: bytes


@dataclass(frozen=True)
class OrientationObservation:
    captured_ns: int
    width: int
    height: int
    rotation: int
    source: str
    input_events_generated: int
    raw: bytes


@dataclass(frozen=True)
class VisualCapture:
    captured_ns: int
    width: int
    height: int
    task_id: int
    virtual_display_id: int
    placement_sequence: int
    png: bytes
    input_events_generated: int


@dataclass(frozen=True)
class SemanticCapture:
    sample_id: str
    adapter_receipt_sha256: str
    manifest: graph.LoadedJson
    external_record: dict[str, Any]
    result: dict[str, Any]
    transcript: bytes
    input_events_generated: int
    writer_calls: int
    pen_operations: int


@dataclass(frozen=True)
class LaunchReceipt:
    foreign: host.ForeignIdentity
    fixture_uri: str
    fixture_sha256: str
    launch_evidence: bytes
    broad_scope_used: bool
    process_kill_used: bool


@dataclass(frozen=True)
class TaskClosure:
    foreign: host.ForeignIdentity
    task_absent: bool
    stock_process_alive: bool
    closure_evidence: bytes
    broad_scope_used: bool
    process_kill_used: bool


class RetainedAdapter(Protocol):
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...


class ArtifactAuthority(RetainedAdapter, Protocol):
    def retain(self, logical_name: str, raw: bytes, media_type: str,
               producer_authority_sha256: str,
               captured_ns: int) -> ArtifactRef: ...
    def verify_ref(self, reference: ArtifactRef) -> None: ...
    def assert_quiescent(self) -> None: ...


class PlatformAuthority(RetainedAdapter, Protocol):
    def capture(self, label: str, foreign: host.ForeignIdentity | None,
                display_id: int | None, deadline_ns: int) -> PlatformCapture: ...


class SemanticAuthority(RetainedAdapter, Protocol):
    def monotonic_domain_identity(self) -> str: ...
    def capture(self, phase: Phase, ordinal: int,
                foreign: host.ForeignIdentity,
                applied: host.AppliedPlacement,
                task: android.DocumentTaskAuthority,
                files_authority: dict[str, Any], deadline_ns: int) -> SemanticCapture: ...
    def assert_quiescent(self, deadline_ns: int) -> None: ...


class TaskAuthority(RetainedAdapter, Protocol):
    def monotonic_domain_identity(self) -> str: ...
    def launch_fixture(self, serial: str, fixture_uri: str, fixture_sha256: str,
                       display_id: int, deadline_ns: int) -> LaunchReceipt: ...
    def destroy_exact_task(self, serial: str, foreign: host.ForeignIdentity,
                           deadline_ns: int) -> TaskClosure: ...
    def assert_quiescent(self, foreign: host.ForeignIdentity,
                         deadline_ns: int) -> None: ...


class FileAuthority(RetainedAdapter, Protocol):
    def capture(self, phase: str, serial: str, fixture_uri: str,
                deadline_ns: int) -> FileEvidenceCapture: ...


class OrientationAuthority(RetainedAdapter, Protocol):
    def await_observation(self, phase: Phase,
                          deadline_ns: int) -> OrientationObservation: ...


class VisualAuthority(RetainedAdapter, Protocol):
    def capture(self, phase: Phase, foreign: host.ForeignIdentity,
                applied: host.AppliedPlacement,
                deadline_ns: int) -> VisualCapture: ...


@dataclass(frozen=True)
class Adapters:
    artifact: ArtifactAuthority
    platform: PlatformAuthority
    semantic: SemanticAuthority
    task: TaskAuthority
    file: FileAuthority
    orientation: OrientationAuthority
    visual: VisualAuthority


EVENT_KEYS = {
    "opened": {"ledger_id", "authority", "schemaVersion", "plan",
               "admission"},
    "adapter_bound": {"name", "sha256"},
    "artifact_retained": {"reference"},
    "operation_intent": {"operation", "owner", "requestSha256",
                         "visualOnly"},
    "operation_result": {"operation", "intentSha256", "outcome",
                         "evidenceSha256"},
    "file_evidence": {"phase", "coreSha256", "artifact"},
    "platform_inventory": {"label", "capturedNs", "taskAuthoritySha256",
                           "inventorySha256", "counts", "artifacts"},
    "visual_capture": {"phaseIndex", "phase", "capturedNs", "width", "height",
                       "taskId", "virtualDisplayId", "placementSequence",
                       "pixelSha256", "artifact", "inputEventsGenerated"},
    "semantic_sample": {"phaseIndex", "phase", "ordinal", "sampleId",
                        "observerSessionId", "runNonce", "manifestSha256", "resultSha256",
                        "projectionSha256", "adapterReceiptSha256", "artifact",
                        "inputEventsGenerated", "writerCalls", "penOperations"},
    "phase_complete": {"phaseIndex", "phase", "applied", "sampleSha256",
                       "inventorySha256", "visualSha256"},
    "primary_failure": {"code", "message", "atRecordSha256"},
    "cleanup_started": {"primaryFailure", "headSha256"},
    "cleanup_step": {"stepIndex", "step", "status", "evidenceSha256",
                     "message"},
    "manifest": {"authority", "schemaVersion", "sessionId", "planSha256",
                 "status", "hardwareAdmission", "primaryFailure",
                 "journalHeadBeforeManifest", "recordCountBeforeManifest",
                 "phaseEvidence", "fileEvidence", "cleanup", "artifacts",
                 "provenance", "policy"},
    "quarantine": {"authority", "schemaVersion", "sessionId", "planSha256",
                   "reason", "primaryFailure", "cleanupFailures", "remaining",
                   "journalHeadBeforeTerminal", "recordCountBeforeTerminal",
                   "recoveryRequired", "retryAllowed", "journalFailure"},
}
TERMINAL_EVENTS = {"manifest", "quarantine"}


# Cleanup has three possible ownership shapes.  These are complete sequences,
# not a menu of optional steps: replay verification rejects omission,
# duplication, reordering, and invented cleanup names even for a quarantined
# run.  The two foreign-task variants distinguish a task acknowledged by the
# reviewed host from an exact task learned before that acknowledgement.
CLEANUP_SEQUENCES = (
    (
        "semantic_sampler_quiescent", "restore_full", "host_begin_close",
        "destroy_exact_foreign_task", "prove_exact_task_absent",
        "release_exact_host_display", "task_authority_quiescent",
        "host_authority_quiescent", "final_platform_inventory",
        "unchanged_pdf_mark_savedink", "all_adapters_still_pinned",
        "artifact_authority_quiescent",
    ),
    (
        "semantic_sampler_quiescent", "restore_full", "host_begin_close",
        "destroy_exact_foreign_task", "prove_pre_attach_display_empty",
        "release_pre_attach_empty_display", "task_authority_quiescent",
        "host_authority_quiescent", "final_platform_inventory",
        "unchanged_pdf_mark_savedink", "all_adapters_still_pinned",
        "artifact_authority_quiescent",
    ),
    (
        "semantic_sampler_quiescent", "prove_pre_attach_display_empty",
        "release_pre_attach_empty_display", "host_authority_quiescent",
        "final_platform_inventory", "unchanged_pdf_mark_savedink",
        "all_adapters_still_pinned", "artifact_authority_quiescent",
    ),
    (
        "semantic_sampler_quiescent", "host_authority_quiescent",
        "final_platform_inventory", "unchanged_pdf_mark_savedink",
        "all_adapters_still_pinned", "artifact_authority_quiescent",
    ),
)


def _main_operation_sequence(plan: SessionPlan) -> tuple[str, ...]:
    operations = [
        "capture_files_before",
        "host_admit_startable",
        "host_await_display",
        "capture_platform_prelaunch",
        "launch_exact_fixture_task",
        "capture_platform_postlaunch-preack",
        "host_attach_exact_foreign",
    ]
    for index, phase in enumerate(plan.phases):
        operations.extend((
            f"observe_orientation_{index:02d}",
            f"place_{index:02d}_{phase.placement.value.lower()}",
            f"capture_platform_phase-{index:02d}-sample-1-before",
            f"capture_semantic_{index:02d}_1",
            f"capture_platform_phase-{index:02d}-sample-1-after",
            f"capture_visual_{index:02d}",
            f"capture_platform_phase-{index:02d}-sample-2-before",
            f"capture_semantic_{index:02d}_2",
            f"capture_platform_phase-{index:02d}-sample-2-after",
        ))
    return tuple(operations)


CLEANUP_OPERATION_SEQUENCE = (
    "capture_platform_final-clean-inventory",
    "capture_files_after",
)


def _operation_owner(operation: str) -> str | None:
    if operation.startswith("capture_files_"):
        return "file"
    if operation.startswith("capture_platform_"):
        return "platform"
    if operation.startswith("capture_semantic_"):
        return "semantic"
    if operation.startswith("capture_visual_"):
        return "visual"
    if operation.startswith("observe_orientation_"):
        return "orientation"
    if operation == "launch_exact_fixture_task":
        return "task"
    if (operation.startswith("host_") or
            operation.startswith("place_")):
        return "host"
    return None


def _artifact_owner(logical_name: str) -> str | None:
    prefix = logical_name.split("/", 1)[0]
    return {
        "files": "file",
        "platform": "platform",
        "semantic": "semantic",
        "orientation": "orientation",
        "visual": "visual",
        "launch": "task",
        "cleanup": "task",
    }.get(prefix)


def _complete_artifact_names(plan: SessionPlan) -> tuple[str, ...]:
    names = [
        "files/before.json",
        "files/before-provider.raw",
        "files/before-saved-ink.json",
    ]

    def platform(label: str) -> None:
        names.extend(f"platform/{label}-{kind}.txt"
                     for kind in ("activity", "window", "process", "display"))

    platform("prelaunch")
    names.append("launch/exact-fixture-task.txt")
    platform("postlaunch-preack")
    for index, phase in enumerate(plan.phases):
        names.append(f"orientation/{index:02d}-{phase.name}.txt")
        for ordinal in (1, 2):
            platform(f"phase-{index:02d}-sample-{ordinal}-before")
            names.extend((
                f"semantic/{index:02d}-{phase.name}-{ordinal}.manifest.json",
                f"semantic/{index:02d}-{phase.name}-{ordinal}.stage-before.json",
                f"semantic/{index:02d}-{phase.name}-{ordinal}.json",
                f"semantic/{index:02d}-{phase.name}-{ordinal}.transcript",
            ))
            platform(f"phase-{index:02d}-sample-{ordinal}-after")
            if ordinal == 1:
                names.append(f"visual/{index:02d}-{phase.name}.png")
    names.append("cleanup/exact-task-closure.txt")
    platform("final-clean-inventory")
    names.extend((
        "files/after.json",
        "files/after-provider.raw",
        "files/after-saved-ink.json",
    ))
    return tuple(names)


class AppendOnlySessionLog:
    """Strict session semantics on the reviewed durable Windows store."""

    def __init__(self, store: WindowsCleanupStore, plan: SessionPlan):
        _need(type(store) is WindowsCleanupStore,
              "reviewed Windows cleanup store is required")
        _need(type(plan) is SessionPlan, "exact session plan required")
        self.store = store
        self.plan = plan
        # The reviewed cleanup store deliberately uses the ledger authority's
        # compact, lower-case 128-bit identity syntax.  Keep the user-visible
        # canonical UUID in every session/manifest field while binding the
        # durable store to the exact same 128 bits.
        self.ledger_id = uuid.UUID(plan.session_id).hex
        self.records: list[dict[str, Any]] = []
        self.usable = True
        with store.exclusive():
            _need(not store.names(), "session log store must be new and empty")
        self.append("opened", {
            "ledger_id": self.ledger_id,
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "plan": plan.wire(),
            "admission": admission_status(),
        }, ())

    @property
    def head(self) -> str:
        return self.records[-1]["hash"]

    @staticmethod
    def _validate_record(record: dict[str, Any]) -> None:
        event = record["event"]
        _need(type(event) is str and event in EVENT_KEYS,
              "unknown visual-session log event")
        _keys(record["data"], EVENT_KEYS[event], "event " + event)
        _need(record["remaining"] == sorted(set(record["remaining"])),
              "cleanup obligation list differs")
        _bounded_record_data(record["data"])
        if event == "opened":
            item = record["data"]
            plan = item["plan"]
            try:
                expected_ledger_id = uuid.UUID(plan["sessionId"]).hex
            except (KeyError, TypeError, ValueError, AttributeError) as error:
                raise EvidenceRejected(
                    "session opening plan identity differs") from error
            _need(record["sequence"] == 0 and record["remaining"] == [] and
                  item["authority"] == AUTHORITY and
                  item["schemaVersion"] == 1 and
                  item["ledger_id"] == expected_ledger_id and
                  item["admission"] == admission_status(),
                  "session opening differs")
        elif event == "adapter_bound":
            _token(record["data"]["name"], "adapter")
            _hex(record["data"]["sha256"], "adapter")
        elif event == "artifact_retained":
            _validate_artifact_wire(record["data"]["reference"])
        elif event == "operation_intent":
            _token(record["data"]["operation"], "operation")
            _token(record["data"]["owner"], "operation owner")
            _hex(record["data"]["requestSha256"], "operation request")
            _need(record["data"]["visualOnly"] is True,
                  "operation is not visual-only")
        elif event == "operation_result":
            _token(record["data"]["operation"], "operation")
            _hex(record["data"]["intentSha256"], "operation intent")
            _hex(record["data"]["evidenceSha256"], "operation evidence")
            _need(record["data"]["outcome"] in ("SUCCESS", "ERROR"),
                  "operation outcome differs")
        elif event == "platform_inventory":
            item = record["data"]
            _token(item["label"], "platform inventory")
            _need(type(item["capturedNs"]) is int and
                  0 <= item["capturedNs"] <= 2**63 - 1,
                  "platform inventory capture time differs")
            _need(item["taskAuthoritySha256"] is None or
                  (type(item["taskAuthoritySha256"]) is str and
                   HEX.fullmatch(item["taskAuthoritySha256"]) is not None),
                  "platform task authority SHA-256 differs")
            _hex(item["inventorySha256"], "platform inventory")
            counts = _keys(item["counts"], {
                "processes", "activities", "windows", "displays",
                "publicDisplays",
            }, "platform inventory counts")
            _need(all(type(value) is int and 0 <= value <= host.MAX_CAPTURE_ROWS
                      for value in counts.values()),
                  "platform inventory count differs")
            artifacts = _keys(item["artifacts"], {
                "activity", "window", "process", "display",
            }, "platform inventory artifacts")
            for reference in artifacts.values():
                _validate_artifact_wire(reference)
        elif event == "semantic_sample":
            item = record["data"]
            _need(type(item["phaseIndex"]) is int and
                  item["phaseIndex"] >= 0 and
                  item["ordinal"] in (1, 2),
                  "semantic sample scalar authority differs")
            _token(item["phase"], "semantic phase")
            _token(item["sampleId"], "semantic sample")
            _token(item["observerSessionId"], "semantic observer session")
            _hex(item["runNonce"], "semantic run nonce")
            for name in ("manifestSha256", "resultSha256",
                         "projectionSha256", "adapterReceiptSha256"):
                _hex(item[name], "semantic " + name)
            artifacts = _keys(item["artifact"], {
                "manifest", "external", "result", "transcript",
            }, "semantic artifacts")
            for reference in artifacts.values():
                _validate_artifact_wire(reference)
            _need(artifacts["manifest"]["sha256"] ==
                  item["manifestSha256"] and
                  artifacts["result"]["sha256"] == item["resultSha256"],
                  "semantic record differs from retained result artifacts")
            _need(item["inputEventsGenerated"] == 0 and
                  item["writerCalls"] == 0 and
                  item["penOperations"] == 0,
                  "semantic evidence contains an input/writer/pen operation")
        elif event == "file_evidence":
            item = record["data"]
            _need(item["phase"] in ("before", "after"),
                  "file evidence phase differs")
            _hex(item["coreSha256"], "file evidence core")
            artifacts = _keys(item["artifact"], {
                "file", "provider", "savedInk",
            }, "file evidence artifacts")
            for reference in artifacts.values():
                _validate_artifact_wire(reference)
        elif event == "visual_capture":
            item = record["data"]
            _need(type(item["phaseIndex"]) is int and item["phaseIndex"] >= 0 and
                  type(item["capturedNs"]) is int and item["capturedNs"] >= 0 and
                  type(item["width"]) is int and item["width"] > 0 and
                  type(item["height"]) is int and item["height"] > 0 and
                  type(item["taskId"]) is int and item["taskId"] > 0 and
                  type(item["virtualDisplayId"]) is int and
                  item["virtualDisplayId"] > 0 and
                  type(item["placementSequence"]) is int and
                  item["placementSequence"] > 0 and
                  item["inputEventsGenerated"] == 0,
                  "visual capture scalar authority differs")
            _hex(item["pixelSha256"], "visual capture")
            artifact = _validate_artifact_wire(item["artifact"])
            _need(artifact["sha256"] == item["pixelSha256"],
                  "visual capture differs from retained PNG")
        elif event == "phase_complete":
            item = record["data"]
            _need(type(item["phaseIndex"]) is int and
                  item["phaseIndex"] >= 0,
                  "phase completion index differs")
            _token(item["phase"], "phase completion")
            _need(type(item["sampleSha256"]) is list and
                  len(item["sampleSha256"]) == 2 and
                  type(item["inventorySha256"]) is list and
                  len(item["inventorySha256"]) == 4,
                  "phase completion evidence cardinality differs")
            for digest in item["sampleSha256"] + item["inventorySha256"]:
                _hex(digest, "phase completion evidence")
            _hex(item["visualSha256"], "phase completion visual")
        elif event == "cleanup_step":
            item = record["data"]
            _need(type(item["stepIndex"]) is int and
                  item["stepIndex"] >= 0 and
                  item["status"] in ("SUCCESS", "FAILED") and
                  ((item["status"] == "SUCCESS" and item["message"] is None) or
                   (item["status"] == "FAILED" and
                    type(item["message"]) is str and item["message"])),
                  "cleanup step scalar authority differs")
            _token(item["step"], "cleanup step")
            _hex(item["evidenceSha256"], "cleanup evidence")
        elif event in TERMINAL_EVENTS:
            expected_authority = (MANIFEST_AUTHORITY
                                  if event == "manifest" else AUTHORITY)
            _need(record["data"]["authority"] == expected_authority,
                  "terminal authority differs")

    def _read(self) -> list[dict[str, Any]]:
        names = self.store.names()
        published = sorted(name for name in names
                           if re.fullmatch(r"[0-9]{20}\.json", name))
        _need(all(name in published or
                  re.fullmatch(r"\.pending-[0-9a-f]{32}", name)
                  for name in names), "unknown session log file")
        _need(published == [f"{index:020d}.json"
                            for index in range(len(published))],
              "session log has a publication gap")
        result: list[dict[str, Any]] = []
        previous = ledger.ZERO_HASH
        terminal = False
        for index, name in enumerate(published):
            record = ledger.decode_record(self.store.read(name))
            _need(not terminal, "session log contains a post-terminal record")
            _need(record["sequence"] == index and
                  record["previous_hash"] == previous,
                  "session log hash chain differs")
            self._validate_record(record)
            self._validate_transition(result, record["event"], record["data"])
            result.append(record)
            previous = record["hash"]
            terminal = record["event"] in TERMINAL_EVENTS
        return result

    @staticmethod
    def _validate_transition(records: Sequence[dict[str, Any]], event: str,
                             data: dict[str, Any]) -> None:
        """Reject structurally valid records in an impossible session order."""
        pending_operation: str | None = None
        for record in records:
            if record["event"] == "operation_intent":
                _need(pending_operation is None,
                      "operation intent overlaps a prior operation")
                pending_operation = record["data"]["operation"]
            elif record["event"] == "operation_result":
                _need(pending_operation == record["data"]["operation"],
                      "operation result order differs")
                pending_operation = None
        if event == "operation_intent":
            _need(pending_operation is None,
                  "operation intent overlaps a prior operation")
        elif event == "operation_result":
            _need(pending_operation == data["operation"],
                  "operation result order differs")

        cleanup_open = any(record["event"] == "cleanup_started"
                           for record in records)
        if event == "cleanup_started":
            _need(not cleanup_open and pending_operation is None,
                  "cleanup start was replayed")
        if cleanup_open and event in {
                "semantic_sample", "visual_capture", "phase_complete"}:
            raise EvidenceRejected(
                "phase evidence cannot be published after cleanup starts")

        completed = [record["data"]["phaseIndex"] for record in records
                     if record["event"] == "phase_complete"]
        _need(completed == list(range(len(completed))),
              "phase completion sequence differs")
        if event == "platform_inventory":
            label = data["label"]
            prior_labels = [record["data"]["label"] for record in records
                            if record["event"] == "platform_inventory"]
            _need(label not in prior_labels,
                  "platform inventory label was replayed")
            if label == "prelaunch":
                _need(not cleanup_open and not prior_labels and not completed,
                      "prelaunch inventory order differs")
            elif label == "postlaunch-preack":
                _need(not cleanup_open and prior_labels == ["prelaunch"] and
                      not completed,
                      "postlaunch inventory order differs")
            elif label == "final-clean-inventory":
                _need(cleanup_open,
                      "final platform inventory precedes cleanup")
            else:
                match = re.fullmatch(
                    r"phase-([0-9]{2})-sample-([12])-(before|after)",
                    label)
                _need(match is not None and not cleanup_open,
                      "platform inventory label differs")
                index = int(match.group(1))
                ordinal = int(match.group(2))
                side = match.group(3)
                _need(index == len(completed),
                      "platform inventory is not for the next open phase")
                selected_samples = [
                    record["data"] for record in records
                    if record["event"] == "semantic_sample" and
                    record["data"]["phaseIndex"] == index
                ]
                selected_visuals = [
                    record["data"] for record in records
                    if record["event"] == "visual_capture" and
                    record["data"]["phaseIndex"] == index
                ]
                expected_state = {
                    (1, "before"): ([], 0),
                    (1, "after"): ([1], 0),
                    (2, "before"): ([1], 1),
                    (2, "after"): ([1, 2], 1),
                }[(ordinal, side)]
                _need(([item["ordinal"] for item in selected_samples],
                       len(selected_visuals)) == expected_state,
                      "platform inventory/sample bracket order differs")
        if event in {"semantic_sample", "visual_capture", "phase_complete"}:
            index = data["phaseIndex"]
            _need(index == len(completed),
                  "phase evidence is not for the next open phase")
            selected_samples = [
                record["data"] for record in records
                if record["event"] == "semantic_sample" and
                record["data"]["phaseIndex"] == index
            ]
            selected_visuals = [
                record["data"] for record in records
                if record["event"] == "visual_capture" and
                record["data"]["phaseIndex"] == index
            ]
            if event == "semantic_sample":
                expected_ordinal = len(selected_samples) + 1
                _need(expected_ordinal <= 2 and
                      data["ordinal"] == expected_ordinal and
                      len(selected_visuals) == (0 if expected_ordinal == 1
                                                else 1),
                      "semantic sample order differs")
                expected_label = (
                    f"phase-{index:02d}-sample-{expected_ordinal}-before")
                _need(any(record["event"] == "platform_inventory" and
                          record["data"]["label"] == expected_label
                          for record in records),
                      "semantic sample lacks its before inventory")
            elif event == "visual_capture":
                _need([item["ordinal"] for item in selected_samples] == [1] and
                      not selected_visuals and
                      any(record["event"] == "platform_inventory" and
                          record["data"]["label"] ==
                          f"phase-{index:02d}-sample-1-after"
                          for record in records),
                      "visual capture is not between the two semantic samples")
            else:
                _need([item["ordinal"] for item in selected_samples] == [1, 2]
                      and len(selected_visuals) == 1 and
                      any(record["event"] == "platform_inventory" and
                          record["data"]["label"] ==
                          f"phase-{index:02d}-sample-2-after"
                          for record in records),
                      "phase completed before its exact evidence set")

        if event == "cleanup_step":
            _need(cleanup_open,
                  "cleanup step precedes cleanup start")
            steps = [record["data"]["step"] for record in records
                     if record["event"] == "cleanup_step"] + [data["step"]]
            _need(data["stepIndex"] == len(steps) - 1 and
                  any(tuple(steps) == sequence[:len(steps)]
                      for sequence in CLEANUP_SEQUENCES),
                  "cleanup step sequence differs")

    def append(self, event: str, data: dict[str, Any],
               remaining: Sequence[str]) -> str:
        _need(self.usable, "uncertain session publisher is sealed")
        _need(not self.records or self.records[-1]["event"] not in TERMINAL_EVENTS,
              "terminal session record forbids later publication")
        handle = None
        try:
            with self.store.exclusive():
                actual = self._read()
                _need(len(actual) == len(self.records) and
                      all(left["hash"] == right["hash"]
                          for left, right in zip(actual, self.records)),
                      "session log instance is stale")
                record = {
                    "version": 1,
                    "sequence": len(self.records),
                    "previous_hash": self.head if self.records else ledger.ZERO_HASH,
                    "event": event,
                    "data": data,
                    "remaining": sorted(set(remaining)),
                }
                self._validate_record(record)
                self._validate_transition(self.records, event, data)
                unsigned = dict(record)
                record["hash"] = _sha(ledger.canonical_json(unsigned))
                raw = ledger.canonical_json(record)
                _need(len(raw) <= ledger.MAX_RECORD_BYTES,
                      "session record exceeds durable store bound")
                temporary = ".pending-" + record["hash"][:32]
                handle = self.store.create(temporary)
                offset = 0
                while offset < len(raw):
                    count = self.store.write(handle, raw[offset:])
                    _need(type(count) is int and 0 < count <= len(raw) - offset,
                          "session record write made no exact progress")
                    offset += count
                self.store.fsync_file(handle)
                self.store.close(handle)
                handle = None
                self.store.rename_no_replace(
                    temporary, f"{len(self.records):020d}.json")
                self.store.fsync_directory()
            checkpoint = self.store.load_checkpoint()
            _need(checkpoint.sequence == len(self.records) and
                  checkpoint.record_sha256 == record["hash"] and
                  checkpoint.ledger_id == self.ledger_id,
                  "external checkpoint does not bind exact session tail")
            self.records.append(record)
            return record["hash"]
        except BaseException:
            self.usable = False
            if handle is not None:
                try:
                    self.store.close(handle)
                except BaseException:
                    pass
            raise

    def verify(self) -> dict[str, Any]:
        with self.store.exclusive():
            records = self._read()
        _need(records and records[0]["data"]["plan"] == self.plan.wire() and
              records[0]["data"]["ledger_id"] == self.ledger_id and
              records[0]["data"]["admission"] == admission_status(),
              "session log belongs to another plan")
        checkpoint = self.store.load_checkpoint()
        _need(checkpoint.sequence == len(records) - 1 and
              checkpoint.record_sha256 == records[-1]["hash"] and
              checkpoint.ledger_id == self.ledger_id,
              "session log checkpoint differs")
        intents: dict[str, str] = {}
        results: dict[str, str] = {}
        intent_rows: list[tuple[int, str]] = []
        result_rows: list[tuple[int, str]] = []
        bindings: dict[str, str] = {}
        samples: dict[int, list[dict[str, Any]]] = {}
        visuals: dict[int, list[dict[str, Any]]] = {}
        phase_rows: list[dict[str, Any]] = []
        artifact_rows: list[dict[str, Any]] = []
        cleanup_rows: list[dict[str, Any]] = []
        cleanup_started: list[tuple[int, dict[str, Any], str]] = []
        file_rows: dict[str, str] = {}
        inventories: dict[str, str] = {}
        primary_rows: list[dict[str, Any]] = []
        sample_ids: set[str] = set()
        observer_ids: set[str] = set()
        nonces: set[str] = set()
        semantic_receipts: set[str] = set()
        platform_times: list[int] = []
        visual_times: list[int] = []
        input_operation_count = 0
        writer_operation_count = 0
        pen_operation_count = 0
        referenced_artifacts: list[tuple[dict[str, Any], str]] = []
        for record in records:
            event, data = record["event"], record["data"]
            if event == "adapter_bound":
                _need(data["name"] not in bindings,
                      "adapter authority was rebound")
                bindings[data["name"]] = data["sha256"]
            elif event == "artifact_retained":
                reference = _validate_artifact_wire(data["reference"])
                _need(reference["logicalName"] not in {
                    item["logicalName"] for item in artifact_rows},
                    "artifact logical name was reused")
                owner = _artifact_owner(reference["logicalName"])
                _need(owner is not None and
                      reference["producerAuthoritySha256"] ==
                      self.plan.adapter_pins[owner],
                      "artifact producer differs from its retained adapter pin")
                artifact_rows.append(reference)
            elif event == "operation_intent":
                _need(data["operation"] not in intents,
                      "operation intent was replayed")
                owner = _operation_owner(data["operation"])
                _need(owner is not None and data["owner"] == owner,
                      "operation owner differs from the fixed session plan")
                intents[data["operation"]] = record["hash"]
                intent_rows.append((record["sequence"], data["operation"]))
            elif event == "operation_result":
                _need(data["operation"] in intents and
                      data["operation"] not in results and
                      data["intentSha256"] == intents[data["operation"]],
                      "operation result is orphaned/replayed")
                results[data["operation"]] = data["outcome"]
                result_rows.append((record["sequence"], data["operation"]))
            elif event == "platform_inventory":
                _need(data["label"] not in inventories,
                      "platform inventory label was replayed")
                _need(data["capturedNs"] <= self.plan.absolute_deadline_ns and
                      (not platform_times or
                       data["capturedNs"] >= platform_times[-1]),
                      "platform inventory capture time moved backwards or past deadline")
                platform_times.append(data["capturedNs"])
                inventories[data["label"]] = data["inventorySha256"]
                referenced_artifacts.extend(
                    (reference, "platform")
                    for reference in data["artifacts"].values())
            elif event == "semantic_sample":
                index = data["phaseIndex"]
                _need(type(index) is int and 0 <= index < len(self.plan.phases) and
                      data["phase"] == self.plan.phases[index].name and
                      data["ordinal"] in (1, 2),
                      "semantic sample phase binding differs")
                _need(data["sampleId"] not in sample_ids and
                      data["observerSessionId"] not in observer_ids and
                      data["runNonce"] not in nonces and
                      data["adapterReceiptSha256"] not in semantic_receipts,
                      "semantic sample independence identity was reused")
                sample_ids.add(data["sampleId"])
                observer_ids.add(data["observerSessionId"])
                nonces.add(data["runNonce"])
                semantic_receipts.add(data["adapterReceiptSha256"])
                input_operation_count += data["inputEventsGenerated"]
                writer_operation_count += data["writerCalls"]
                pen_operation_count += data["penOperations"]
                samples.setdefault(index, []).append(data)
                referenced_artifacts.extend(
                    (reference, "semantic")
                    for reference in data["artifact"].values())
            elif event == "visual_capture":
                index = data["phaseIndex"]
                _need(type(index) is int and 0 <= index < len(self.plan.phases) and
                      data["phase"] == self.plan.phases[index].name,
                      "visual capture phase binding differs")
                _need(data["capturedNs"] <= self.plan.absolute_deadline_ns and
                      (not visual_times or
                       data["capturedNs"] >= visual_times[-1]),
                      "visual capture time moved backwards or past deadline")
                visual_times.append(data["capturedNs"])
                input_operation_count += data["inputEventsGenerated"]
                visuals.setdefault(index, []).append(data)
                referenced_artifacts.append((data["artifact"], "visual"))
            elif event == "phase_complete":
                index = data["phaseIndex"]
                selected = samples.get(index, [])
                selected_visual = visuals.get(index, [])
                _need([item["ordinal"] for item in selected] == [1, 2],
                      "phase completion lacks exactly two ordered samples")
                _need(len(selected_visual) == 1 and
                      data["sampleSha256"] == [
                          item["projectionSha256"] for item in selected] and
                      data["visualSha256"] ==
                      selected_visual[0]["pixelSha256"],
                      "phase completion evidence differs from sample records")
                expected_inventory = [
                    inventories.get(
                        f"phase-{index:02d}-sample-{ordinal}-{side}")
                    for ordinal in (1, 2) for side in ("before", "after")]
                phase = self.plan.phases[index]
                applied = data["applied"]
                _need(None not in expected_inventory and
                      data["inventorySha256"] == expected_inventory and
                      applied == {
                          "session": self.plan.session_id,
                          "generation": 1,
                          "displayId": selected_visual[0]["virtualDisplayId"],
                          "sequence": selected_visual[0]["placementSequence"],
                          "requested": phase.placement.value,
                          "effective": phase.placement.value,
                          "rect": phase.rect.wire(),
                      },
                      "phase completion placement/inventory binding differs")
                phase_rows.append(data)
            elif event == "file_evidence":
                _need(data["phase"] in ("before", "after") and
                      data["phase"] not in file_rows,
                      "file evidence phase was replayed")
                file_rows[data["phase"]] = data["coreSha256"]
                referenced_artifacts.extend(
                    (reference, "file")
                    for reference in data["artifact"].values())
            elif event == "primary_failure":
                primary_rows.append(data)
            elif event == "cleanup_started":
                cleanup_started.append(
                    (record["sequence"], data, record["previous_hash"]))
            elif event == "cleanup_step":
                _need(data["stepIndex"] == len(cleanup_rows),
                      "cleanup step order differs")
                cleanup_rows.append(data)
        _need(set(intents) == set(results),
              "terminal session contains an unresolved operation intent")
        _need(bindings == self.plan.adapter_pins,
              "terminal session lacks the exact adapter binding set")
        artifact_index = {item["logicalName"]: item for item in artifact_rows}
        _need(all(artifact_index.get(item["logicalName"]) == item and
                  _artifact_owner(item["logicalName"]) == owner and
                  item["producerAuthoritySha256"] ==
                  self.plan.adapter_pins[owner]
                  for item, owner in referenced_artifacts),
              "evidence record refers to an unretained artifact")
        terminal = records[-1]
        _need(terminal["event"] in TERMINAL_EVENTS,
              "session log has no terminal record")
        expected_primary = primary_rows[0] if primary_rows else None
        cleanup_names = tuple(row["step"] for row in cleanup_rows)
        _need(len(primary_rows) <= 1 and len(cleanup_started) == 1 and
              cleanup_started[0][1]["primaryFailure"] == expected_primary and
              cleanup_started[0][1]["headSha256"] ==
              cleanup_started[0][2] and
              cleanup_names in CLEANUP_SEQUENCES,
              "terminal session cleanup prefix/order differs")
        cleanup_start_sequence = cleanup_started[0][0]
        main_operations = tuple(operation for sequence, operation in intent_rows
                                if sequence < cleanup_start_sequence)
        cleanup_operations = tuple(
            operation for sequence, operation in intent_rows
            if sequence > cleanup_start_sequence)
        expected_main_operations = _main_operation_sequence(self.plan)
        _need(main_operations ==
              expected_main_operations[:len(main_operations)] and
              cleanup_operations == CLEANUP_OPERATION_SEQUENCE and
              tuple(operation for _, operation in result_rows) ==
              tuple(operation for _, operation in intent_rows) and
              all(intent_sequence < result_sequence
                  for (intent_sequence, intent_operation),
                      (result_sequence, result_operation)
                  in zip(intent_rows, result_rows)
                  if intent_operation == result_operation),
              "operation sequence differs from the fixed session plan")
        if terminal["event"] == "manifest":
            manifest = terminal["data"]
            _need(manifest["authority"] == MANIFEST_AUTHORITY and
                  manifest["schemaVersion"] == 1 and
                  manifest["sessionId"] == self.plan.session_id and
                  artifact_rows,
                  "terminal manifest identity/evidence differs")
            provenance = _keys(manifest["provenance"], {
                "harnessAuthority", "hostApkSha256", "hostUnsignedApkSha256",
                "hostDexSha256", "hostSignerCertSha256",
                "androidTaskAuthority", "semanticSnapshotAuthority",
                "journalStoreId", "journalLedgerId",
                "artifactStoreIdentitySha256", "adapterPins",
            }, "terminal manifest provenance")
            policy = _keys(manifest["policy"], {
                "visualOnly", "inputOperationCount", "writerOperationCount",
                "penOperationCount", "booxAddressed", "userDocumentTouched",
                "retryAllowed", "physicalRotationRequested",
                "physicalRotationCaptured", "hardwareAdmissionBlockers",
            }, "terminal manifest policy")
            phase_completions = [item["phaseIndex"] for item in phase_rows]
            expected_prefix = list(range(len(phase_rows)))
            _need(phase_completions == expected_prefix,
                  "terminal manifest phase sequence is not a contiguous prefix")
            if manifest["status"] == "VISUAL_EVIDENCE_COMPLETE_DIAGNOSTIC":
                complete_cleanup = [
                    "semantic_sampler_quiescent", "restore_full",
                    "host_begin_close", "destroy_exact_foreign_task",
                    "prove_exact_task_absent", "release_exact_host_display",
                    "task_authority_quiescent", "host_authority_quiescent",
                    "final_platform_inventory", "unchanged_pdf_mark_savedink",
                    "all_adapters_still_pinned",
                    "artifact_authority_quiescent",
                ]
                complete_inventories = ["prelaunch", "postlaunch-preack"]
                for index in range(len(self.plan.phases)):
                    complete_inventories.extend(
                        f"phase-{index:02d}-sample-{ordinal}-{side}"
                        for ordinal in (1, 2)
                        for side in ("before", "after"))
                complete_inventories.append("final-clean-inventory")
                _need(phase_completions == list(range(len(self.plan.phases))) and
                      not primary_rows and
                      main_operations == expected_main_operations and
                      list(inventories) == complete_inventories and
                      tuple(item["logicalName"] for item in artifact_rows) ==
                      _complete_artifact_names(self.plan) and
                      [row["step"] for row in cleanup_rows] == complete_cleanup and
                      all(record["data"]["outcome"] == "SUCCESS"
                          for record in records
                          if record["event"] == "operation_result"),
                      "complete terminal manifest lacks the full phase sequence")
            else:
                _need(manifest["status"] == "FAILED_CLEAN" and
                      manifest["primaryFailure"] is not None,
                      "non-complete clean manifest classification differs")
            essential_cleanup = {
                "semantic_sampler_quiescent", "host_authority_quiescent",
                "final_platform_inventory", "unchanged_pdf_mark_savedink",
                "all_adapters_still_pinned", "artifact_authority_quiescent",
            }
            _need(len(primary_rows) <= 1 and len(cleanup_started) == 1 and
                  cleanup_started[0][1]["primaryFailure"] == expected_primary and
                  cleanup_started[0][1]["headSha256"] ==
                  cleanup_started[0][2] and
                  all(row["status"] == "SUCCESS" for row in cleanup_rows) and
                  essential_cleanup.issubset({row["step"]
                                              for row in cleanup_rows}) and
                  manifest["primaryFailure"] == expected_primary and
                  manifest["planSha256"] == self.plan.sha256 and
                  manifest["hardwareAdmission"] is False and
                  manifest["phaseEvidence"] == phase_rows and
                  manifest["cleanup"] == cleanup_rows and
                  manifest["artifacts"] == artifact_rows and
                  set(file_rows) == {"before", "after"} and
                  manifest["fileEvidence"] == {
                      "beforeSha256": file_rows["before"],
                      "afterSha256": file_rows["after"],
                      "unchanged": True,
                  } and file_rows["before"] == file_rows["after"] and
                  provenance["adapterPins"] ==
                  dict(sorted(self.plan.adapter_pins.items())) and
                  provenance["harnessAuthority"] == AUTHORITY and
                  provenance["hostApkSha256"] == host.APK_SHA256 and
                  provenance["hostUnsignedApkSha256"] ==
                  host.REVIEWED_UNSIGNED_APK_SHA256 and
                  provenance["hostDexSha256"] == host.DEX_SHA256 and
                  provenance["hostSignerCertSha256"] ==
                  host.SIGNER_CERT_SHA256 and
                  provenance["androidTaskAuthority"] == android.AUTHORITY and
                  provenance["semanticSnapshotAuthority"] ==
                  graph.SNAPSHOT_AUTHORITY and
                  provenance["journalStoreId"] ==
                  self.store.authority.store_id and
                  provenance["journalLedgerId"] == self.ledger_id and
                  provenance["artifactStoreIdentitySha256"] ==
                  artifact_rows[0]["storeIdentitySha256"] and
                  all(item["storeIdentitySha256"] ==
                      artifact_rows[0]["storeIdentitySha256"]
                      for item in artifact_rows) and
                  policy["visualOnly"] is True and
                  policy["inputOperationCount"] ==
                  input_operation_count == 0 and
                  policy["writerOperationCount"] ==
                  writer_operation_count == 0 and
                  policy["penOperationCount"] ==
                  pen_operation_count == 0 and
                  policy["booxAddressed"] is False and
                  policy["userDocumentTouched"] is False and
                  policy["retryAllowed"] is False and
                  policy["physicalRotationRequested"] is
                  self.plan.include_physical_rotation and
                  policy["physicalRotationCaptured"] is
                  all(any(row["phase"] == phase.name for row in phase_rows)
                      for phase in ROTATION_PHASES) and
                  policy["hardwareAdmissionBlockers"] ==
                  list(BLOCKERS),
                  "terminal manifest differs from journal evidence")
            _need(manifest["recordCountBeforeManifest"] == len(records) - 1 and
                  manifest["journalHeadBeforeManifest"] ==
                  records[-2]["hash"] and not terminal["remaining"],
                  "terminal manifest is not bound to the exact clean prefix")
        else:
            quarantine = terminal["data"]
            _need(quarantine["authority"] == AUTHORITY and
                  quarantine["schemaVersion"] == 1 and
                  quarantine["sessionId"] == self.plan.session_id and
                  quarantine["planSha256"] == self.plan.sha256 and
                  quarantine["primaryFailure"] ==
                  (primary_rows[0] if primary_rows else None) and
                  quarantine["cleanupFailures"] == [
                      item for item in cleanup_rows
                      if item["status"] != "SUCCESS"] and
                  quarantine["remaining"] == terminal["remaining"] and
                  quarantine["recoveryRequired"] is True and
                  quarantine["retryAllowed"] is False,
                  "quarantine differs from journal evidence")
            _need(quarantine["recordCountBeforeTerminal"] == len(records) - 1 and
                  quarantine["journalHeadBeforeTerminal"] ==
                  records[-2]["hash"],
                  "quarantine terminal is not bound to the exact prefix")
        return terminal["data"]


def _adapter_bytes(value: RetainedAdapter) -> bytes:
    _need(value is not None, "retained adapter is absent")
    value.verify()
    raw = value.canonical_bytes()
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_ADAPTER_BYTES,
          "adapter canonical authority is absent or oversized")
    value.verify()
    return raw


def _snapshot_inventory(snapshot: host.Snapshot) -> dict[str, Any]:
    _need(type(snapshot) is host.Snapshot and snapshot.complete is True,
          "platform snapshot is not complete typed host authority")
    processes = [asdict(item) for item in snapshot.processes]
    activities = [asdict(item) for item in snapshot.activities]
    windows = [asdict(item) for item in snapshot.windows]
    displays = [asdict(item) for item in snapshot.displays]
    for row in displays:
        row["flags"] = sorted(row["flags"])
        if row["owner"] is not None:
            row["owner"] = dict(row["owner"])
    for row in windows:
        if row["surface_frame"] is not None:
            row["surface_frame"] = dict(row["surface_frame"])
        row["frame"] = dict(row["frame"])
        if row["buffer"] is not None:
            row["buffer"] = list(row["buffer"])
    _need(len({row["pid"] for row in processes}) == len(processes),
          "process inventory contains a duplicate PID")
    _need(len({row["display_id"] for row in displays}) == len(displays),
          "display inventory contains a duplicate ID")
    return {
        "package": asdict(snapshot.package),
        "processes": processes,
        "activities": activities,
        "windows": windows,
        "displays": displays,
        "publicDisplayIds": sorted(row["display_id"] for row in displays
                                   if "PUBLIC" in row["flags"]),
    }


class VisualSessionHarness:
    """One-shot visual evidence transaction over retained injected authorities."""

    def __init__(self, plan: SessionPlan, host_authority: host.HostAuthority,
                 adapters: Adapters, log: AppendOnlySessionLog):
        _need(type(plan) is SessionPlan and type(host_authority) is host.HostAuthority and
              type(adapters) is Adapters and type(log) is AppendOnlySessionLog,
              "exact reviewed harness composition required")
        _need(host_authority.session == plan.session_id,
              "host session and evidence session differ")
        _need(log.plan == plan, "session log plan differs")
        self.plan = plan
        self.host = host_authority
        self._retained_host_authority = host_authority
        self._retained_host_providers = host_authority.providers
        self._retained_host_process_authority = host_authority.retained
        self.adapters = adapters
        self._retained_adapters_container = adapters
        self._retained_adapters: dict[str, RetainedAdapter] = {}
        self.log = log
        self.remaining: set[str] = {
            "artifact_store", "semantic_sampler", "host_session"}
        self._used = False
        self._foreign: host.ForeignIdentity | None = None
        self._host_attach_attempted = False
        self._host_attached = False
        self._file_before: FileEvidenceCapture | None = None
        self._file_after: FileEvidenceCapture | None = None
        self._artifacts: list[ArtifactRef] = []
        self._phase_evidence: list[dict[str, Any]] = []
        self._cleanup: list[dict[str, Any]] = []
        self._primary: dict[str, Any] | None = None
        self._journal_failure: dict[str, Any] | None = None
        self._last_applied: host.AppliedPlacement | None = None
        self._global_projection: str | None = None
        self._seen_sample_ids: set[str] = set()
        self._seen_observer_sessions: set[str] = set()
        self._seen_nonces: set[str] = set()
        self._seen_semantic_receipts: set[str] = set()
        self._adapter_raw: dict[str, bytes] = {}
        self._last_platform_captured_ns: int | None = None
        self._artifact_store_identity: str | None = None
        self._artifact_identity_failure: str | None = None
        host_clock_identity = getattr(
            self._retained_host_providers,
            "monotonic_domain_identity", None)
        _need(callable(host_clock_identity),
              "retained host provider lacks monotonic clock identity")
        host_domain = host_clock_identity()
        _need(self.host is self._retained_host_authority and
              self._retained_host_authority.providers is
              self._retained_host_providers and
              self._retained_host_authority.retained is
              self._retained_host_process_authority,
              "retained host/provider object changed during construction")
        _hex(host_domain, "retained host monotonic clock domain")
        _need(host_domain == self.plan.monotonic_domain_sha256,
              "host provider and session-plan monotonic domains differ")
        self._host_clock_domain = host_domain
        for item in fields(Adapters):
            name = item.name
            adapter = getattr(adapters, name)
            self._retained_adapters[name] = adapter
            raw = _adapter_bytes(adapter)
            _need(self.adapters is self._retained_adapters_container and
                  getattr(self._retained_adapters_container, name) is adapter,
                  "retained adapter object changed during construction: " + name)
            digest = _sha(raw)
            _need(digest == plan.adapter_pins[name],
                  "adapter pin differs: " + name)
            self._adapter_raw[name] = raw
            if name in {"task", "semantic"}:
                adapter_domain = adapter.monotonic_domain_identity()
                _need(self.adapters is self._retained_adapters_container and
                      getattr(self._retained_adapters_container, name) is adapter,
                      "retained adapter object changed during construction: " + name)
                _hex(adapter_domain, name + " adapter monotonic clock domain")
                _need(adapter_domain == self._host_clock_domain,
                      name + " adapter and host monotonic domains differ")
            self.log.append("adapter_bound", {"name": name, "sha256": digest},
                            self.remaining)

    def _verify_host_binding(self) -> host.HostAuthority:
        """Prove exact construction-time host and provider object ownership."""
        authority = self._retained_host_authority
        providers = self._retained_host_providers
        _need(self.host is authority,
              "retained host authority object was substituted")
        _need(authority.providers is providers,
              "retained host provider object was substituted")
        _need(authority.retained is self._retained_host_process_authority,
              "retained host process authority object was substituted")
        domain_method = getattr(providers, "monotonic_domain_identity", None)
        _need(callable(domain_method),
              "retained host provider lacks monotonic clock identity")
        domain = domain_method()
        _need(self.host is authority and authority.providers is providers and
              authority.retained is self._retained_host_process_authority,
              "retained host/provider object changed during verification")
        _hex(domain, "retained host monotonic clock domain")
        _need(domain == self._host_clock_domain,
              "retained host monotonic clock domain changed")
        return authority

    def _host_call(self, function: Callable[[host.HostAuthority], Any]) -> Any:
        authority = self._verify_host_binding()
        try:
            result = function(authority)
        except BaseException as error:
            try:
                self._verify_host_binding()
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._verify_host_binding()
        return result

    def _host_provider_call(self, function: Callable[[Any], Any]) -> Any:
        providers = self._verify_host_binding().providers
        try:
            result = function(providers)
        except BaseException as error:
            try:
                self._verify_host_binding()
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._verify_host_binding()
        return result

    def _host_process_authority_call(
            self, function: Callable[[Any], Any]) -> Any:
        retained = self._verify_host_binding().retained
        try:
            result = function(retained)
        except BaseException as error:
            try:
                self._verify_host_binding()
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._verify_host_binding()
        return result

    def _trusted_capture_start(self) -> int:
        """Read the retained host provider's authenticated monotonic domain."""
        self._host_process_authority_call(
            lambda retained: retained.verify())
        authority = self._verify_host_binding()
        _need(self._host_process_authority_call(
                  lambda retained: retained.identity()) == authority.process,
              "retained host identity changed before evidence capture")
        value = self._host_provider_call(lambda providers: providers.now_ns())
        _need(type(value) is int and
              0 <= value < self.plan.absolute_deadline_ns,
              "trusted evidence capture clock is expired or invalid")
        return value

    def _trusted_capture_finish(self, started_ns: int,
                                captured_ns: int) -> None:
        self._host_process_authority_call(
            lambda retained: retained.verify())
        authority = self._verify_host_binding()
        _need(self._host_process_authority_call(
                  lambda retained: retained.identity()) == authority.process,
              "retained host identity changed during evidence capture")
        finished_ns = self._host_provider_call(
            lambda providers: providers.now_ns())
        _need(type(finished_ns) is int and
              started_ns <= captured_ns <= finished_ns <
              self.plan.absolute_deadline_ns,
              "evidence capture timestamp is outside its trusted host bracket")

    def _adapter_object(self, name: str) -> RetainedAdapter:
        _need(name in self._retained_adapters,
              "unknown retained adapter name")
        _need(self.adapters is self._retained_adapters_container,
              "retained adapters container was substituted")
        adapter = self._retained_adapters[name]
        _need(getattr(self._retained_adapters_container, name) is adapter,
              "retained adapter object was substituted: " + name)
        return adapter

    def _verify_adapter(self, name: str) -> RetainedAdapter:
        adapter = self._adapter_object(name)
        _need(_adapter_bytes(adapter) == self._adapter_raw[name],
              "retained adapter authority changed: " + name)
        _need(self._adapter_object(name) is adapter,
              "retained adapter object changed during verification: " + name)
        if name in {"task", "semantic"}:
            domain = adapter.monotonic_domain_identity()
            _need(self._adapter_object(name) is adapter,
                  "retained adapter object changed during verification: " + name)
            _hex(domain, name + " adapter monotonic clock domain")
            _need(domain == self._host_clock_domain,
                  name + " adapter monotonic clock domain changed")
        return adapter

    def _adapter_call(self, name: str,
                      function: Callable[[Any], Any]) -> Any:
        adapter = self._verify_adapter(name)
        try:
            result = function(adapter)
        except BaseException as error:
            try:
                self._verify_adapter(name)
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._verify_adapter(name)
        return result

    def _retain(self, logical_name: str, raw: bytes, media_type: str,
                producer: str, captured_ns: int) -> ArtifactRef:
        _need(type(raw) is bytes and 0 < len(raw) <= MAX_ARTIFACT_BYTES,
              "evidence artifact is empty or oversized")
        reference = self._adapter_call(
            "artifact", lambda adapter: adapter.retain(
                logical_name, raw, media_type,
                self.plan.adapter_pins[producer], captured_ns))
        self._adapter_call(
            "artifact", lambda adapter: adapter.verify_ref(reference))
        _validate_artifact_ref(
            reference, logical_name=logical_name, raw=raw,
            producer_sha256=self.plan.adapter_pins[producer])
        if self._artifact_store_identity is None:
            self._artifact_store_identity = reference.store_identity_sha256
        elif reference.store_identity_sha256 != self._artifact_store_identity:
            # The adapter may already have published this object.  Retain its
            # reference for quiescence checks, but never describe the session
            # as clean or pretend that two stores form one immutable bundle.
            self._artifact_identity_failure = (
                "artifact authority returned more than one store identity")
            self._artifacts.append(reference)
            self.remaining.add("artifact_store")
            raise EvidenceRejected(self._artifact_identity_failure)
        self._artifacts.append(reference)
        self.log.append("artifact_retained", {"reference": reference.wire()},
                        self.remaining)
        return reference

    def _operation(self, operation: str, owner: str, request: Any,
                   action: Callable[[], Any], summary: Callable[[Any], Any]) -> Any:
        _token(operation, "operation")
        request_sha = _digest(request)
        intent = self.log.append("operation_intent", {
            "operation": operation,
            "owner": owner,
            "requestSha256": request_sha,
            "visualOnly": True,
        }, self.remaining)
        try:
            result = action()
            evidence_sha = _digest(summary(result))
            outcome = "SUCCESS"
        except BaseException as error:
            evidence_sha = _digest({"type": type(error).__name__,
                                    "message": str(error)[:MAX_FAILURE_CHARS]})
            outcome = "ERROR"
            self.log.append("operation_result", {
                "operation": operation,
                "intentSha256": intent,
                "outcome": outcome,
                "evidenceSha256": evidence_sha,
            }, self.remaining)
            raise
        self.log.append("operation_result", {
            "operation": operation,
            "intentSha256": intent,
            "outcome": outcome,
            "evidenceSha256": evidence_sha,
        }, self.remaining)
        return result

    def _cleanup_append(self, event: str, data: dict[str, Any]) -> bool:
        """Never let lost evidence publication suppress safety cleanup.

        A journal fault makes a clean terminal claim impossible.  Cleanup still
        runs in its fixed order and the in-memory quarantine retains the first
        publication error; no replacement store or retry is attempted.
        """
        if self._journal_failure is not None or not self.log.usable:
            if self._journal_failure is None:
                self._journal_failure = {
                    "code": "SESSION_LOG_UNUSABLE",
                    "message": "durable session log was sealed after publication uncertainty",
                    "headSha256": self.log.head,
                }
            self.remaining.add("session_log")
            return False
        try:
            self.log.append(event, data, self.remaining)
            return True
        except BaseException as error:
            self._journal_failure = {
                "code": type(error).__name__,
                "message": str(error)[:MAX_FAILURE_CHARS],
                "headSha256": self.log.head,
            }
            self.remaining.add("session_log")
            return False

    def _file_capture(self, phase: str) -> FileEvidenceCapture:
        _need(phase in ("before", "after"), "file capture phase differs")

        def capture() -> FileEvidenceCapture:
            started_ns = self._trusted_capture_start()
            selected = self._adapter_call(
                "file", lambda adapter: adapter.capture(
                    phase, AUTHORIZED_SERIAL, self.plan.fixture_uri,
                    self.plan.absolute_deadline_ns))
            _need(type(selected) is FileEvidenceCapture and
                  selected.phase == phase and
                  type(selected.captured_ns) is int and
                  selected.captured_ns >= 0 and
                  type(selected.raw) is bytes and selected.raw,
                  "file capture envelope differs")
            self._trusted_capture_finish(started_ns, selected.captured_ns)
            return selected

        value = self._operation(
            "capture_files_" + phase, "file",
            {"phase": phase, "serial": AUTHORIZED_SERIAL,
             "fixtureUri": self.plan.fixture_uri},
            capture,
            lambda selected: {
                "phase": selected.phase,
                "capturedNs": str(selected.captured_ns),
                "providerRawSha256": _sha(selected.raw),
            })
        path = self.plan.fixture_uri[len("file://"):]
        _validate_device_file(value.pdf, expected_path=path, required=True)
        _validate_device_file(value.mark, expected_path=path + ".mark",
                              required=False)
        _need(value.pdf.sha256 == self.plan.fixture_sha256,
              "captured PDF differs from the admitted fixture digest")
        ink = value.saved_ink
        _need(type(ink) is SavedInkEvidence and ink.collector_uid == SHELL_UID and
              type(ink.raw) is bytes and ink.raw and
              type(ink.record_count) is int and ink.record_count >= 0,
              "SavedInk evidence must come from exact shell UID authority")
        _hex(ink.collector_artifact_sha256, "SavedInk collector artifact")
        _hex(ink.canonical_sha256, "SavedInk canonical evidence")
        _need(ink.canonical_sha256 == _sha(ink.raw),
              "SavedInk canonical digest differs from retained bytes")
        expected_state = "PRESENT" if value.mark.present else "MARK_ABSENT"
        _need(ink.state == expected_state and
              ink.source_mark_sha256 == value.mark.sha256,
              "SavedInk nullable mark/source authority differs")
        ink_loaded = graph.load_canonical(ink.raw, MAX_ARTIFACT_BYTES)
        ink_record = _keys(ink_loaded.value, {
            "authority", "schemaVersion", "state", "sourceMarkSha256",
            "records",
        }, "SavedInk canonical record")
        _need(ink_record["authority"] == SAVED_INK_AUTHORITY and
              ink_record["schemaVersion"] == 1 and
              ink_record["state"] == ink.state and
              ink_record["sourceMarkSha256"] == ink.source_mark_sha256 and
              type(ink_record["records"]) is list and
              len(ink_record["records"]) == ink.record_count,
              "SavedInk typed evidence differs from canonical retained bytes")
        files = value.files_authority
        _keys(files, {"authority", "verification", "originalPdf", "mark"},
              "graph file authority")
        _need(files["authority"] == graph.FILE_AUTHORITY and
              files["verification"] == "external-before-and-after-exact",
              "graph file authority identity differs")
        pdf, mark = files["originalPdf"], files["mark"]
        _keys(pdf, {"present", "path", "size", "sha256", "stat",
                    "documentUri", "uriResolution"},
              "graph original PDF authority")
        _keys(mark, {"present", "path", "size", "sha256", "stat"},
              "graph mark authority")
        resolution = _keys(pdf["uriResolution"], {
            "authority", "documentUri", "resolvedPath", "evidenceSha256",
        }, "graph fixture URI resolution")
        _need(pdf["present"] is True and pdf["path"] == value.pdf.path and
              pdf["sha256"] == value.pdf.sha256 and
              pdf["size"] == str(value.pdf.size) and
              pdf["stat"] == _graph_stat(value.pdf) and
              pdf["documentUri"] == self.plan.fixture_uri and
              resolution["authority"] == "rtl-reader-file-uri-resolution-v1" and
              resolution["documentUri"] == self.plan.fixture_uri and
              resolution["resolvedPath"] == value.pdf.path,
              "PDF graph/file evidence differs")
        _hex(resolution["evidenceSha256"], "fixture URI resolution")
        _need(mark["present"] == value.mark.present and
              mark["path"] == value.mark.path and
              mark["sha256"] == value.mark.sha256 and
              mark["stat"] == _graph_stat(value.mark) and
              mark["size"] == (str(value.mark.size)
                               if value.mark.present else None),
              "mark graph/file evidence differs")
        raw = graph.canonical_bytes({
            "authority": FILE_AUTHORITY,
            "phase": phase,
            "capturedNs": str(value.captured_ns),
            "pdf": value.pdf.wire(),
            "mark": value.mark.wire(),
            "savedInk": ink.wire(),
            "filesAuthority": files,
            "providerRawSha256": _sha(value.raw),
        })
        reference = self._retain("files/" + phase + ".json", raw,
                                 "application/json", "file", value.captured_ns)
        provider_ref = self._retain(
            "files/" + phase + "-provider.raw", value.raw,
            "application/octet-stream", "file", value.captured_ns)
        ink_ref = self._retain("files/" + phase + "-saved-ink.json", ink.raw,
                               "application/json", "file", value.captured_ns)
        core = self._file_core(value)
        self.log.append("file_evidence", {
            "phase": phase,
            "coreSha256": _digest(core),
            "artifact": {"file": reference.wire(),
                         "provider": provider_ref.wire(),
                         "savedInk": ink_ref.wire()},
        }, self.remaining)
        return value

    @staticmethod
    def _file_core(value: FileEvidenceCapture) -> dict[str, Any]:
        return {
            "pdf": value.pdf.wire(),
            "mark": value.mark.wire(),
            "savedInk": value.saved_ink.wire(),
            "filesAuthority": value.files_authority,
        }

    def _platform_capture(self, label: str,
                          foreign: host.ForeignIdentity | None,
                          display_id: int | None) -> tuple[PlatformCapture,
                                                          android.DocumentTaskAuthority | None,
                                                          str]:
        _token(label, "platform capture")

        def capture() -> PlatformCapture:
            started_ns = self._trusted_capture_start()
            selected = self._adapter_call(
                "platform", lambda adapter: adapter.capture(
                    label, foreign, display_id,
                    self.plan.absolute_deadline_ns))
            _need(type(selected) is PlatformCapture and
                  type(selected.captured_ns) is int and
                  selected.captured_ns >= 0 and
                  type(selected.snapshot) is host.Snapshot and
                  selected.snapshot.captured_ns == selected.captured_ns and
                  all(type(raw) is bytes and raw for raw in (
                      selected.activity_manager_raw,
                      selected.window_manager_raw,
                      selected.process_inventory_raw,
                      selected.display_inventory_raw)),
                  "platform capture envelope differs")
            self._trusted_capture_finish(started_ns, selected.captured_ns)
            return selected

        value = self._operation(
            "capture_platform_" + label, "platform",
            {"label": label,
             "foreign": None if foreign is None else foreign.wire(),
             "displayId": display_id},
            capture,
            lambda selected: {
                "capturedNs": str(selected.captured_ns),
                "activitySha256": _sha(selected.activity_manager_raw),
                "windowSha256": _sha(selected.window_manager_raw),
                "processSha256": _sha(selected.process_inventory_raw),
                "displaySha256": _sha(selected.display_inventory_raw),
            })
        _need(self._last_platform_captured_ns is None or
              value.captured_ns >= self._last_platform_captured_ns,
              "platform capture timestamp moved backwards")
        self._last_platform_captured_ns = value.captured_ns
        raw_items = (
            ("activity", value.activity_manager_raw, value.snapshot.am_sha256),
            ("window", value.window_manager_raw, value.snapshot.window_sha256),
            ("process", value.process_inventory_raw, value.snapshot.process_sha256),
            ("display", value.display_inventory_raw, value.snapshot.display_sha256),
        )
        references: dict[str, Any] = {}
        for kind, raw, expected in raw_items:
            _need(_sha(raw) == expected,
                  kind + " raw evidence digest differs from typed snapshot")
            references[kind] = self._retain(
                "platform/" + label + "-" + kind + ".txt", raw,
                "text/plain", "platform", value.captured_ns).wire()
        inventory = _snapshot_inventory(value.snapshot)
        task: android.DocumentTaskAuthority | None = None
        document_activities = [item for item in value.snapshot.activities
                               if item.component == host.FOREIGN_COMPONENT]
        document_windows = [item for item in value.snapshot.windows
                            if (item.process.package == host.FOREIGN_PACKAGE
                                if foreign is None else
                                item.activity_token == foreign.activity_token)]
        if foreign is None:
            _need(not document_activities and not document_windows,
                  "absence inventory contains a DocumentActivity")
        else:
            task = android.parse_document_task_authority(
                value.activity_manager_raw, expected_pid=foreign.process.pid)
            _need(task.task_id == foreign.task_id and
                  task.activity_token == foreign.activity_token and
                  task.display_id == display_id and task.pid == foreign.process.pid and
                  task.uid == foreign.process.uid and
                  task.package_name == foreign.process.package,
                  "strict ActivityManager authority differs from retained foreign task")
            _need(android.stable_authority_sha256(task) ==
                  foreign.evidence_sha256,
                  "foreign identity is not bound to stable ActivityManager "
                  "task authority")
            _need(len(document_activities) == 1 and
                  document_activities[0].task_id == foreign.task_id and
                  document_activities[0].process == foreign.process and
                  document_activities[0].display_id == display_id and
                  document_activities[0].resumed and
                  document_activities[0].visible,
                  "typed task inventory differs from strict ActivityManager authority")
            _need(len(document_windows) == 1 and
                  document_windows[0].task_id == foreign.task_id and
                  document_windows[0].display_id == display_id and
                  document_windows[0].visible,
                  "typed window inventory differs from retained foreign task")
            _need(sum(item == foreign.process for item in value.snapshot.processes) == 1,
                  "exact foreign process inventory is absent or ambiguous")
            _need(sum(item.display_id == display_id for item in
                      value.snapshot.displays) == 1 and
                  display_id in inventory["publicDisplayIds"],
                  "exact public virtual display inventory differs")
        if display_id is not None:
            owned = [item for item in value.snapshot.displays
                     if item.display_id == display_id or
                     item.owner == self._retained_host_authority.process]
            _need(len(owned) == 1 and
                  owned[0].display_id == display_id and
                  owned[0].owner == self._retained_host_authority.process and
                  owned[0].name ==
                  f"NativePageVisualOnly-{self.plan.session_id}-1" and
                  owned[0].flags == host.FLAGS and
                  (owned[0].width, owned[0].height, owned[0].density) ==
                  (1404, 1872, graph.VIRTUAL_DISPLAY_DENSITY_DPI),
                  "platform inventory virtual-display authority differs")
        inventory_sha = _digest(inventory)
        task_sha = None if task is None else _sha(task.canonical_bytes())
        self.log.append("platform_inventory", {
            "label": label,
            "capturedNs": value.captured_ns,
            "taskAuthoritySha256": task_sha,
            "inventorySha256": inventory_sha,
            "counts": {
                "processes": len(inventory["processes"]),
                "activities": len(inventory["activities"]),
                "windows": len(inventory["windows"]),
                "displays": len(inventory["displays"]),
                "publicDisplays": len(inventory["publicDisplayIds"]),
            },
            "artifacts": references,
        }, self.remaining)
        return value, task, inventory_sha

    def _orientation(self, phase: Phase, index: int) -> OrientationObservation:
        def observe() -> OrientationObservation:
            started_ns = self._trusted_capture_start()
            selected = self._adapter_call(
                "orientation", lambda adapter: adapter.await_observation(
                    phase, self.plan.absolute_deadline_ns))
            _need(type(selected) is OrientationObservation and
                  type(selected.raw) is bytes and selected.raw,
                  "orientation capture envelope differs")
            self._trusted_capture_finish(started_ns, selected.captured_ns)
            return selected

        value = self._operation(
            f"observe_orientation_{index:02d}", "orientation",
            {"phase": phase.wire()}, observe,
            lambda selected: {
                "capturedNs": str(selected.captured_ns),
                "rawSha256": _sha(selected.raw),
            })
        allowed_rotations = ((0, 2) if phase.physical == "PORTRAIT"
                             else (1, 3))
        _need(type(value) is OrientationObservation and
              (value.width, value.height) == (phase.width, phase.height) and
              value.source == "physical-user-rotation-observation-only" and
              value.input_events_generated == 0 and
              type(value.captured_ns) is int and value.captured_ns >= 0 and
              type(value.rotation) is int and
              value.rotation in allowed_rotations,
              "physical orientation observation differs or generated input")
        loaded = graph.load_canonical(value.raw, graph.MAX_AUTHORITY_BYTES)
        _need(loaded.value == {
            "authority": ORIENTATION_AUTHORITY,
            "schemaVersion": 1,
            "capturedNs": str(value.captured_ns),
            "phase": phase.name,
            "width": value.width,
            "height": value.height,
            "rotation": value.rotation,
            "source": value.source,
            "inputEventsGenerated": 0,
        }, "orientation raw/typed authority differs")
        self._retain(f"orientation/{index:02d}-{phase.name}.txt", value.raw,
                     "application/json", "orientation", value.captured_ns)
        return value

    def _visual(self, phase: Phase, index: int,
                applied: host.AppliedPlacement) -> str:
        _need(self._foreign is not None,
              "visual capture lacks retained foreign authority")

        def capture() -> VisualCapture:
            started_ns = self._trusted_capture_start()
            selected = self._adapter_call(
                "visual", lambda adapter: adapter.capture(
                    phase, self._foreign, applied,
                    self.plan.absolute_deadline_ns))
            _need(type(selected) is VisualCapture and
                  type(selected.png) is bytes and selected.png,
                  "visual capture envelope differs")
            self._trusted_capture_finish(started_ns, selected.captured_ns)
            return selected

        value = self._operation(
            f"capture_visual_{index:02d}", "visual",
            {"phase": phase.wire(), "foreign": self._foreign.wire(),
             "placementSequence": applied.sequence},
            capture,
            lambda selected: {
                "capturedNs": str(selected.captured_ns),
                "pixelSha256": _sha(selected.png),
            })
        _need(type(value.captured_ns) is int and value.captured_ns >= 0 and
              (value.width, value.height) == (phase.width, phase.height) and
              value.task_id == self._foreign.task_id and
              value.virtual_display_id == applied.display_id and
              value.placement_sequence == applied.sequence and
              value.input_events_generated == 0,
              "visual capture task/display/placement authority differs")
        pixel_sha = _validate_png(value.png, value.width, value.height)
        reference = self._retain(
            f"visual/{index:02d}-{phase.name}.png", value.png,
            "image/png", "visual", value.captured_ns)
        self.log.append("visual_capture", {
            "phaseIndex": index,
            "phase": phase.name,
            "capturedNs": value.captured_ns,
            "width": value.width,
            "height": value.height,
            "taskId": value.task_id,
            "virtualDisplayId": value.virtual_display_id,
            "placementSequence": value.placement_sequence,
            "pixelSha256": pixel_sha,
            "artifact": reference.wire(),
            "inputEventsGenerated": 0,
        }, self.remaining)
        return pixel_sha

    def _semantic(self, phase: Phase, phase_index: int, ordinal: int,
                  applied: host.AppliedPlacement,
                  task: android.DocumentTaskAuthority) -> tuple[str, str, str]:
        _need(self._file_before is not None and self._foreign is not None,
              "semantic sample lacks file/foreign authority")

        def capture() -> SemanticCapture:
            selected = self._adapter_call(
                "semantic", lambda adapter: adapter.capture(
                    phase, ordinal, self._foreign, applied, task,
                    self._file_before.files_authority,
                    self.plan.absolute_deadline_ns))
            _need(type(selected) is SemanticCapture and
                  type(selected.transcript) is bytes and selected.transcript,
                  "semantic capture envelope differs")
            return selected

        value = self._operation(
            f"capture_semantic_{phase_index:02d}_{ordinal}", "semantic",
            {"phase": phase.wire(), "ordinal": ordinal,
             "foreign": self._foreign.wire(),
             "placementSequence": applied.sequence,
             "taskAuthoritySha256": _sha(task.canonical_bytes()),
             "fileAuthoritySha256": _digest(
                 self._file_before.files_authority)},
            capture,
            lambda selected: {
                "sampleId": selected.sample_id,
                "adapterReceiptSha256": selected.adapter_receipt_sha256,
                "transcriptSha256": _sha(selected.transcript),
            })
        _need(type(value) is SemanticCapture and
              value.input_events_generated == 0 and value.writer_calls == 0 and
              value.pen_operations == 0,
              "semantic sampler reached input, pen, or writer methods")
        _token(value.sample_id, "semantic sample")
        _hex(value.adapter_receipt_sha256, "semantic adapter receipt")
        _need(type(value.manifest) is graph.LoadedJson,
              "semantic manifest wrapper differs")
        manifest = graph.load_canonical(value.manifest.raw,
                                        graph.MAX_MANIFEST_BYTES)
        _need(manifest.sha256 == value.manifest.sha256,
              "semantic manifest changed after adapter validation")
        result = value.result
        _keys(result, {"schemaVersion", "authority", "stage", "manifestSha256",
                       "observerSha256", "runNonce", "providerAdmissionSha256",
                       "fridaAdmissionSha256", "beforeAuthoritySha256",
                       "afterAuthoritySha256", "beforeReceiptSha256",
                       "afterReceiptSha256", "toolBundleSha256", "snapshot"},
              "semantic runner result")
        _need(result["schemaVersion"] == 2 and
              result["authority"] == graph.RUNNER_AUTHORITY and
              result["stage"] == phase.placement.value and
              result["manifestSha256"] == manifest.sha256,
              "semantic runner result binding differs")
        for name, item in result.items():
            if name.endswith("Sha256"):
                _hex(item, "semantic " + name)
        _hex(result["runNonce"], "semantic run nonce")
        _need(type(value.external_record) is dict,
              "semantic external authority record differs")
        external_raw = graph.canonical_bytes(value.external_record)
        _need(result["beforeAuthoritySha256"] == _sha(external_raw) and
              value.external_record.get("taskAuthoritySha256") ==
              _sha(task.canonical_bytes()),
              "semantic result is not bound to the supplied external authority")
        host_record = value.external_record.get("host")
        _need(type(host_record) is dict and
              host_record.get("authority") == graph.HOST_AUTHORITY and
              host_record.get("hostSessionId") == self.plan.session_id and
              host_record.get("stage") == phase.placement.value and
              host_record.get("displayId") == applied.display_id and
              host_record.get("displayGeneration") == applied.generation and
              host_record.get("placementRequestGeneration") == applied.sequence and
              host_record.get("placementReadyGeneration") == applied.sequence and
              host_record.get("hostPackageName") == host.HOST_PACKAGE and
              host_record.get("hostApkSha256") == host.APK_SHA256 and
              host_record.get("hostTaskId") ==
              self._retained_host_authority.host_task_id and
              host_record.get("hostActivityToken") ==
              self._retained_host_authority.host_token and
              host_record.get("requestedFrame") == phase.rect.wire() and
              host_record.get("measuredGlobalFrame") == phase.rect.wire(),
              "semantic host record differs from retained placement authority")
        snapshot = graph.validate_snapshot(result["snapshot"], manifest,
                                           value.external_record)
        external = snapshot["externalSession"]
        _need(external == {
            "authority": graph.EXTERNAL_SESSION_AUTHORITY,
            "source": "external-coordinator",
            "authorizedSerial": AUTHORIZED_SERIAL,
            "taskId": self._foreign.task_id,
            "displayId": applied.display_id,
            "hostSessionId": self.plan.session_id,
            "displayGeneration": applied.generation,
        }, "semantic snapshot external session differs")
        _need(snapshot["fileAuthority"] == self._file_before.files_authority and
              snapshot["attachment"]["pid"] == self._foreign.process.pid and
              snapshot["attachment"]["processStartTimeTicks"] ==
              str(self._foreign.process.start_ticks),
              "semantic snapshot file/process authority differs")
        observer_session = snapshot["coordinator"]["observerSessionId"]
        _need(value.sample_id not in self._seen_sample_ids and
              observer_session not in self._seen_observer_sessions and
              result["runNonce"] not in self._seen_nonces and
              value.adapter_receipt_sha256 not in
              self._seen_semantic_receipts,
              "semantic sample identity was reused within the session")
        self._seen_sample_ids.add(value.sample_id)
        self._seen_observer_sessions.add(observer_session)
        self._seen_nonces.add(result["runNonce"])
        self._seen_semantic_receipts.add(value.adapter_receipt_sha256)
        projection = {name: snapshot[name] for name in
                      ("lifecycle", "document", "pageInfo", "presenter",
                       "views", "layers")}
        projection_sha = _digest(projection)
        result_raw = graph.canonical_bytes(result)
        manifest_ref = self._retain(
            f"semantic/{phase_index:02d}-{phase.name}-{ordinal}.manifest.json",
            manifest.raw, "application/json", "semantic", 0)
        external_ref = self._retain(
            f"semantic/{phase_index:02d}-{phase.name}-{ordinal}.stage-before.json",
            external_raw, "application/json", "semantic", 0)
        reference = self._retain(
            f"semantic/{phase_index:02d}-{phase.name}-{ordinal}.json",
            result_raw, "application/json", "semantic", 0)
        transcript = self._retain(
            f"semantic/{phase_index:02d}-{phase.name}-{ordinal}.transcript",
            value.transcript, "application/octet-stream", "semantic", 0)
        self.log.append("semantic_sample", {
            "phaseIndex": phase_index,
            "phase": phase.name,
            "ordinal": ordinal,
            "sampleId": value.sample_id,
            "observerSessionId": observer_session,
            "runNonce": result["runNonce"],
            "manifestSha256": manifest.sha256,
            "resultSha256": _sha(result_raw),
            "projectionSha256": projection_sha,
            "adapterReceiptSha256": value.adapter_receipt_sha256,
            "artifact": {"manifest": manifest_ref.wire(),
                         "external": external_ref.wire(),
                         "result": reference.wire(),
                         "transcript": transcript.wire()},
            "inputEventsGenerated": 0,
            "writerCalls": 0,
            "penOperations": 0,
        }, self.remaining)
        return projection_sha, observer_session, result["runNonce"]

    def _phase(self, phase: Phase, index: int) -> None:
        orientation = self._orientation(phase, index)
        applied = self._operation(
            f"place_{index:02d}_{phase.placement.value.lower()}", "host",
            {"phase": phase.wire(), "orientationSha256": _sha(orientation.raw)},
            lambda: self._host_call(
                lambda authority: authority.place(
                    phase.placement, self.plan.absolute_deadline_ns)),
            lambda value: {
                "session": value.session, "generation": value.generation,
                "displayId": value.display_id, "sequence": value.sequence,
                "requested": value.requested.value,
                "effective": value.effective.value, "rect": value.rect.wire(),
            })
        _need(type(applied) is host.AppliedPlacement and
              applied.session == self.plan.session_id and
              applied.generation == self._retained_host_authority.generation and
              applied.display_id == self._retained_host_authority.display_id and
              applied.requested is phase.placement and
              applied.effective is phase.placement and
              applied.rect == phase.rect,
              "host placement acknowledgement differs from exact phase")
        self._last_applied = applied
        projections: list[str] = []
        observers: list[str] = []
        nonces: list[str] = []
        inventories: list[str] = []
        visual_sha: str | None = None
        for ordinal in (1, 2):
            before, task_before, before_sha = self._platform_capture(
                f"phase-{index:02d}-sample-{ordinal}-before",
                self._foreign, applied.display_id)
            _need(task_before is not None,
                  "semantic sample lacks strict task authority")
            projection, observer, nonce = self._semantic(
                phase, index, ordinal, applied, task_before)
            after, task_after, after_sha = self._platform_capture(
                f"phase-{index:02d}-sample-{ordinal}-after",
                self._foreign, applied.display_id)
            _need(task_after is not None and
                  android.stable_authority(task_before, task_after),
                  "ActivityManager semantic identity changed during sample")
            _need(_snapshot_inventory(before.snapshot) ==
                  _snapshot_inventory(after.snapshot),
                  "task/process/public-display inventory changed during sample")
            if ordinal == 1:
                # The retained pixels sit between the two independent semantic
                # samples and their independent before/after inventories.
                visual_sha = self._visual(phase, index, applied)
            projections.append(projection)
            observers.append(observer)
            nonces.append(nonce)
            inventories.extend((before_sha, after_sha))
        _need(len(set(observers)) == 2 and len(set(nonces)) == 2,
              "two semantic samples are not independently session/challenge bound")
        _need(projections[0] == projections[1],
              "independent semantic samples disagree within phase")
        _need(visual_sha is not None,
              "phase lacks an independently retained visual capture")
        if self._global_projection is None:
            self._global_projection = projections[0]
        _need(self._global_projection == projections[0],
              "native page/model/presenter semantics changed between phases")
        evidence = {
            "phaseIndex": index,
            "phase": phase.name,
            "applied": {
                "session": applied.session,
                "generation": applied.generation,
                "displayId": applied.display_id,
                "sequence": applied.sequence,
                "requested": applied.requested.value,
                "effective": applied.effective.value,
                "rect": applied.rect.wire(),
            },
            "sampleSha256": projections,
            "inventorySha256": inventories,
            "visualSha256": visual_sha,
        }
        self.log.append("phase_complete", evidence, self.remaining)
        self._phase_evidence.append(evidence)

    def _cleanup_step(self, index: int, name: str,
                      action: Callable[[], Any],
                      success: Callable[[Any], Any]) -> bool:
        try:
            value = action()
            evidence = _digest(success(value))
            status, message = "SUCCESS", None
            ok = True
        except BaseException as error:
            evidence = _digest({"type": type(error).__name__,
                                "message": str(error)[:MAX_FAILURE_CHARS]})
            status = "FAILED"
            message = type(error).__name__ + ": " + str(error)[:MAX_FAILURE_CHARS]
            ok = False
        row = {"stepIndex": index, "step": name, "status": status,
               "evidenceSha256": evidence, "message": message}
        self._cleanup.append(row)
        self._cleanup_append("cleanup_step", row)
        return ok

    def _semantic_quiescent(self) -> None:
        self._adapter_call(
            "semantic", lambda adapter: adapter.assert_quiescent(
                self.plan.absolute_deadline_ns))

    def _task_quiescent(self, foreign: host.ForeignIdentity) -> None:
        self._adapter_call(
            "task", lambda adapter: adapter.assert_quiescent(
                foreign, self.plan.absolute_deadline_ns))

    def _artifacts_quiescent(self) -> None:
        for reference in self._artifacts:
            self._adapter_call(
                "artifact", lambda adapter, selected=reference:
                    adapter.verify_ref(selected))
            _validate_artifact_wire(reference.wire())
        self._adapter_call(
            "artifact", lambda adapter: adapter.assert_quiescent())
        _need(self._artifact_identity_failure is None and
              self._artifact_store_identity is not None and
              len({reference.store_identity_sha256
                   for reference in self._artifacts}) == 1,
              self._artifact_identity_failure or
              "artifact bundle lacks one immutable store identity")

    def _all_adapters_pinned(self) -> None:
        for item in fields(Adapters):
            self._verify_adapter(item.name)

    def _cleanup_session(self) -> None:
        retired_foreign = self._foreign
        retired_display_id = self._retained_host_authority.display_id
        healthy_pre_attach = self._retained_host_authority.failure is None

        def prove_pre_attach() -> host.TaskAbsence:
            _need("foreign_task_creation" not in self.remaining,
                  "unknown task-creation side effects cannot authorize empty-display abort")
            if self._foreign is not None:
                # A known task must be gone globally, not merely have migrated
                # off the owned display, before the healthy empty route applies.
                self._task_quiescent(self._foreign)
            return self._host_call(
                lambda authority: authority.prove_pre_attach_empty(
                    self.plan.absolute_deadline_ns)
                if healthy_pre_attach else authority.prove_empty(
                    self.plan.absolute_deadline_ns))

        def release_pre_attach(proof: host.TaskAbsence) -> None:
            if healthy_pre_attach:
                self._host_call(
                    lambda authority: authority.abort_pre_attach_empty(
                        proof, self.plan.absolute_deadline_ns))
            else:
                self._host_call(
                    lambda authority: authority.ack_empty(
                        proof, self.plan.absolute_deadline_ns))

        def begin_close() -> dict[str, Any]:
            if self._host_attached:
                self._host_call(
                    lambda authority: authority.begin_close(
                        self.plan.absolute_deadline_ns))
                return {"state": self._retained_host_authority.state}
            _need(not self._host_attach_attempted,
                  "host attach was attempted but acknowledgement is uncertain or failed")
            return {"notApplicable": True,
                    "reason": "host attach was never attempted"}

        self._cleanup_append("cleanup_started", {
            "primaryFailure": self._primary,
            "headSha256": self.log.head,
        })
        step = 0
        if self._cleanup_step(
                step, "semantic_sampler_quiescent",
                self._semantic_quiescent, lambda _: {"quiescent": True}):
            self.remaining.discard("semantic_sampler")
        step += 1
        if self._foreign is not None:
            if (self._last_applied is not None and
                    self._last_applied.requested is not host.Placement.FULL):
                self._cleanup_step(
                    step, "restore_full",
                    lambda: self._host_call(
                        lambda authority: authority.place(
                            host.Placement.FULL,
                            self.plan.absolute_deadline_ns)),
                    lambda value: {
                        "session": value.session,
                        "generation": value.generation,
                        "displayId": value.display_id,
                        "sequence": value.sequence,
                        "requested": value.requested.value,
                        "effective": value.effective.value,
                        "rect": value.rect.wire(),
                    })
            else:
                self._cleanup_step(step, "restore_full", lambda: None,
                                   lambda _: {"alreadyFull": True})
            step += 1
            self._cleanup_step(
                step, "host_begin_close", begin_close, lambda value: value)
            step += 1
            box: list[TaskClosure] = []

            def destroy() -> TaskClosure:
                value = self._adapter_call(
                    "task", lambda adapter: adapter.destroy_exact_task(
                        AUTHORIZED_SERIAL, self._foreign,
                        self.plan.absolute_deadline_ns))
                _need(type(value) is TaskClosure and
                      value.foreign == self._foreign and value.task_absent is True and
                      value.stock_process_alive is True and
                      value.broad_scope_used is False and
                      value.process_kill_used is False and
                      type(value.closure_evidence) is bytes and
                      value.closure_evidence,
                      "task cleanup was not exact-task-only")
                # Retain the validated closure before returning.  `box` keeps
                # the exact result if publication then fails; the independent
                # host absence proof below must still be attempted.
                box.append(value)
                self._retain("cleanup/exact-task-closure.txt",
                             value.closure_evidence, "text/plain", "task", 0)
                return value

            self._cleanup_step(
                step, "destroy_exact_foreign_task", destroy,
                lambda value: {
                    "task": value.foreign.task_id,
                    "pid": value.foreign.process.pid,
                    "stockProcessAlive": value.stock_process_alive,
                })
            step += 1
            proof_box: list[host.TaskAbsence] = []
            proof_ok = self._cleanup_step(
                step, ("prove_exact_task_absent" if self._host_attached
                       else "prove_pre_attach_display_empty"),
                lambda: proof_box.append(
                    self._host_call(
                        lambda authority: authority.prove_task_absent(
                            self.plan.absolute_deadline_ns))
                    if self._host_attached else
                    prove_pre_attach()
                ) or proof_box[0],
                lambda value: asdict(value))
            step += 1
            if proof_ok:
                released = self._cleanup_step(
                    step, ("release_exact_host_display" if self._host_attached
                           else "release_pre_attach_empty_display"),
                    lambda: (self._host_call(
                        lambda authority: authority.ack_destroyed(
                            proof_box[0], self.plan.absolute_deadline_ns))
                        if self._host_attached else release_pre_attach(proof_box[0])),
                    lambda _: {"state": self._retained_host_authority.state})
                if released:
                    self.remaining.discard("foreign_task")
                    self.remaining.discard("virtual_display")
            else:
                self._cleanup_step(
                    step, ("release_exact_host_display" if self._host_attached
                           else "release_pre_attach_empty_display"),
                                   lambda: (_ for _ in ()).throw(
                                       EvidenceRejected("absence proof unavailable")),
                                   lambda _: {})
            step += 1
            if self._cleanup_step(
                    step, "task_authority_quiescent",
                    lambda: self._task_quiescent(self._foreign),
                    lambda _: {"quiescent": True}):
                if "foreign_task" not in self.remaining:
                    self._foreign = None
            step += 1
        elif retired_display_id is not None:
            # Coordinator errors use the distinct healthy abort. Host failures
            # keep their original failed-empty route; unknown effects cannot
            # substitute for exact absence authority in either route.
            proof_box: list[host.TaskAbsence] = []
            proof_ok = self._cleanup_step(
                step, "prove_pre_attach_display_empty",
                lambda: proof_box.append(prove_pre_attach()) or proof_box[0],
                lambda value: asdict(value))
            step += 1
            if proof_ok:
                released = self._cleanup_step(
                    step, "release_pre_attach_empty_display",
                    lambda: release_pre_attach(proof_box[0]),
                    lambda _: {"state": self._retained_host_authority.state})
                if released:
                    self.remaining.discard("virtual_display")
            else:
                self._cleanup_step(
                    step, "release_pre_attach_empty_display",
                    lambda: (_ for _ in ()).throw(
                        EvidenceRejected("pre-attach empty proof unavailable")),
                    lambda _: {})
            step += 1
        if self._cleanup_step(
                step, "host_authority_quiescent",
                lambda: self._host_call(
                    lambda authority: authority.assert_quiescent(
                        self.plan.absolute_deadline_ns)),
                lambda _: {"state": self._retained_host_authority.state,
                           "obligations": list(
                               self._retained_host_authority.cleanup_obligations)}):
            self.remaining.discard("host_session")
            self.remaining.discard("virtual_display")
        step += 1
        try:
            final_capture, _, _ = self._platform_capture(
                "final-clean-inventory", None, None)
            snapshot = final_capture.snapshot
            _need(retired_display_id is None or
                  not any(item.display_id == retired_display_id or
                          item.owner == self._retained_host_authority.process
                          for item in snapshot.displays),
                  "final inventory retains the created public display")
            _need(not any(item.task_id ==
                          self._retained_host_authority.host_task_id or
                          item.token == self._retained_host_authority.host_token
                          for item in snapshot.activities) and
                  not any(item.task_id ==
                          self._retained_host_authority.host_task_id or
                          item.activity_token ==
                          self._retained_host_authority.host_token
                          for item in snapshot.windows),
                  "final inventory retains the exact host task/window")
            if retired_foreign is not None:
                _need(not any(item.task_id == retired_foreign.task_id or
                              item.token == retired_foreign.activity_token
                              for item in snapshot.activities) and
                      not any(item.task_id == retired_foreign.task_id or
                              item.activity_token == retired_foreign.activity_token
                              for item in snapshot.windows) and
                      sum(item == retired_foreign.process
                          for item in snapshot.processes) == 1,
                      "final inventory lacks exact task absence/stock-process liveness")
            final_inventory_error: BaseException | None = None
        except BaseException as error:
            final_inventory_error = error
        self._cleanup_step(
            step, "final_platform_inventory",
            (lambda: None) if final_inventory_error is None else
            (lambda: (_ for _ in ()).throw(final_inventory_error)),
            lambda _: {"noDocumentActivity": True})
        step += 1
        try:
            self._file_after = self._file_capture("after")
            _need(self._file_before is not None and
                  self._file_core(self._file_before) ==
                  self._file_core(self._file_after),
                  "PDF/mark/SavedInk evidence changed")
            file_error: BaseException | None = None
        except BaseException as error:
            file_error = error
        self._cleanup_step(
            step, "unchanged_pdf_mark_savedink",
            (lambda: None) if file_error is None else
            (lambda: (_ for _ in ()).throw(file_error)),
            lambda _: {"unchanged": True})
        step += 1
        if self._cleanup_step(
                step, "all_adapters_still_pinned",
                self._all_adapters_pinned,
                lambda _: {"adapterCount": len(fields(Adapters))}):
            pass
        step += 1
        if self._cleanup_step(
                step, "artifact_authority_quiescent",
                self._artifacts_quiescent,
                lambda _: {"artifacts": len(self._artifacts)}):
            self.remaining.discard("artifact_store")

    def _terminal(self) -> dict[str, Any]:
        artifact_store_ids = {
            item.store_identity_sha256 for item in self._artifacts}
        if (self._artifact_identity_failure is not None or
                len(artifact_store_ids) != 1):
            # Terminal construction is itself fail-closed.  A missing or split
            # store identity selects quarantine; it must never escape as an
            # unclassified exception before the terminal decision.
            self.remaining.add("artifact_store")
        cleanup_failures = [row for row in self._cleanup
                            if row["status"] != "SUCCESS"]
        if self.remaining or cleanup_failures:
            terminal = {
                "authority": AUTHORITY,
                "schemaVersion": 1,
                "sessionId": self.plan.session_id,
                "planSha256": self.plan.sha256,
                "reason": "exact cleanup or evidence postcondition unresolved",
                "primaryFailure": self._primary,
                "cleanupFailures": cleanup_failures,
                "remaining": sorted(self.remaining),
                "journalHeadBeforeTerminal": self.log.head,
                "recordCountBeforeTerminal": len(self.log.records),
                "recoveryRequired": True,
                "retryAllowed": False,
                "journalFailure": self._journal_failure,
            }
            if self._journal_failure is None and self.log.usable:
                try:
                    self.log.append("quarantine", terminal, self.remaining)
                    self.log.verify()
                except BaseException as error:
                    self._journal_failure = {
                        "code": type(error).__name__,
                        "message": str(error)[:MAX_FAILURE_CHARS],
                        "headSha256": self.log.head,
                    }
                    self.remaining.add("session_log")
                    terminal["journalFailure"] = self._journal_failure
                    terminal["remaining"] = sorted(self.remaining)
            raise SessionQuarantined(terminal)
        _need(self._file_before is not None and self._file_after is not None,
              "terminal manifest lacks before/after file evidence")
        manifest = {
            "authority": MANIFEST_AUTHORITY,
            "schemaVersion": 1,
            "sessionId": self.plan.session_id,
            "planSha256": self.plan.sha256,
            "status": ("VISUAL_EVIDENCE_COMPLETE_DIAGNOSTIC"
                       if self._primary is None else "FAILED_CLEAN"),
            "hardwareAdmission": False,
            "primaryFailure": self._primary,
            "journalHeadBeforeManifest": self.log.head,
            "recordCountBeforeManifest": len(self.log.records),
            "phaseEvidence": self._phase_evidence,
            "fileEvidence": {
                "beforeSha256": _digest(self._file_core(self._file_before)),
                "afterSha256": _digest(self._file_core(self._file_after)),
                "unchanged": True,
            },
            "cleanup": self._cleanup,
            "artifacts": [item.wire() for item in self._artifacts],
            "provenance": {
                "harnessAuthority": AUTHORITY,
                "hostApkSha256": host.APK_SHA256,
                "hostUnsignedApkSha256": host.REVIEWED_UNSIGNED_APK_SHA256,
                "hostDexSha256": host.DEX_SHA256,
                "hostSignerCertSha256": host.SIGNER_CERT_SHA256,
                "androidTaskAuthority": android.AUTHORITY,
                "semanticSnapshotAuthority": graph.SNAPSHOT_AUTHORITY,
                "journalStoreId": self.log.store.authority.store_id,
                "journalLedgerId": self.log.ledger_id,
                "artifactStoreIdentitySha256": next(iter(artifact_store_ids)),
                "adapterPins": dict(sorted(self.plan.adapter_pins.items())),
            },
            "policy": {
                "visualOnly": True,
                "inputOperationCount": 0,
                "writerOperationCount": 0,
                "penOperationCount": 0,
                "booxAddressed": False,
                "userDocumentTouched": False,
                "retryAllowed": False,
                "physicalRotationRequested": self.plan.include_physical_rotation,
                "physicalRotationCaptured": all(
                    any(row["phase"] == phase.name
                        for row in self._phase_evidence)
                    for phase in ROTATION_PHASES),
                "hardwareAdmissionBlockers": list(BLOCKERS),
            },
        }
        try:
            self.log.append("manifest", manifest, ())
            self.log.verify()
        except BaseException as error:
            self._journal_failure = {
                "code": type(error).__name__,
                "message": str(error)[:MAX_FAILURE_CHARS],
                "headSha256": self.log.head,
            }
            self.remaining.add("session_log")
            terminal = {
                "authority": AUTHORITY,
                "schemaVersion": 1,
                "sessionId": self.plan.session_id,
                "planSha256": self.plan.sha256,
                "reason": "terminal manifest publication or verification failed",
                "primaryFailure": self._primary,
                "cleanupFailures": cleanup_failures,
                "remaining": sorted(self.remaining),
                "journalHeadBeforeTerminal": self.log.head,
                "recordCountBeforeTerminal": len(self.log.records),
                "recoveryRequired": True,
                "retryAllowed": False,
                "journalFailure": self._journal_failure,
            }
            raise SessionQuarantined(terminal) from error
        if self._primary is not None:
            raise SessionFailed(manifest)
        return manifest

    def run(self) -> dict[str, Any]:
        _need(not self._used, "visual session is one-shot and cannot retry")
        self._used = True
        try:
            self._file_before = self._file_capture("before")
            self._operation(
                "host_admit_startable", "host",
                {"sessionId": self.plan.session_id},
                lambda: self._host_call(
                    lambda authority: authority.admit_startable(
                        self.plan.absolute_deadline_ns)),
                lambda _: {"state": self._retained_host_authority.state})
            # Allocation can become real before the bounded readiness call
            # returns, so retain the exact obligation before dispatch.
            self.remaining.add("virtual_display")
            display_id = self._operation(
                "host_await_display", "host",
                {"sessionId": self.plan.session_id},
                lambda: self._host_call(
                    lambda authority: authority.await_display_ready(
                        self.plan.absolute_deadline_ns)),
                lambda value: {"displayId": value,
                               "generation":
                               self._retained_host_authority.generation})
            self._platform_capture("prelaunch", None, display_id)

            def launch() -> LaunchReceipt:
                try:
                    value = self._adapter_call(
                        "task", lambda adapter: adapter.launch_fixture(
                            AUTHORIZED_SERIAL, self.plan.fixture_uri,
                            self.plan.fixture_sha256, display_id,
                            self.plan.absolute_deadline_ns))
                except TaskLaunchOutcomeUncertain as error:
                    # The throwing adapter is the sole possible source of an
                    # exact cleanup identity.  Re-pin it *after* the throw,
                    # validate the base-class-owned immutable evidence and
                    # stock identity domain, and take cleanup ownership before
                    # publishing either an artifact or an operation result.
                    self._verify_adapter("task")
                    foreign = TaskLaunchOutcomeUncertain.retained_foreign.fget(
                        error)
                    evidence = TaskLaunchOutcomeUncertain.evidence.fget(error)
                    _need(type(evidence) is bytes and
                          0 < len(evidence) <= MAX_ADAPTER_BYTES,
                          "uncertain task launch evidence is absent or oversized")
                    foreign_wire = _launch_foreign_wire(foreign)
                    uncertainty = _keys(
                        graph.load_canonical(
                            evidence, MAX_ADAPTER_BYTES).value,
                        {"authority", "schemaVersion", "reasonCode", "message",
                         "sideEffectPossible", "retainedForeign"},
                        "uncertain task launch evidence")
                    _need(uncertainty["authority"] ==
                          TASK_LAUNCH_UNCERTAINTY_AUTHORITY and
                          uncertainty["schemaVersion"] == 1 and
                          uncertainty["sideEffectPossible"] is True and
                          uncertainty["message"] == str(error) and
                          uncertainty["retainedForeign"] == foreign_wire,
                          "uncertain task launch evidence binding differs")
                    _token(uncertainty["reasonCode"],
                           "uncertain task launch reason")
                    if foreign is not None:
                        self._foreign = foreign
                        self.remaining.discard("foreign_task_creation")
                        self.remaining.add("foreign_task")
                    self._retain("launch/exact-fixture-task.txt", evidence,
                                 "application/json", "task", 0)
                    raise
                self._verify_adapter("task")
                _need(type(value) is LaunchReceipt and
                      value.fixture_uri == self.plan.fixture_uri and
                      value.fixture_sha256 == self.plan.fixture_sha256 and
                      value.broad_scope_used is False and
                      value.process_kill_used is False and
                      type(value.foreign) is host.ForeignIdentity and
                      value.foreign.process.package == host.FOREIGN_PACKAGE and
                      value.foreign.process.uid == android.SYSTEM_UID,
                      "fixture launch did not return exact retained task authority")
                # Cleanup ownership must precede artifact/result publication:
                # the exact task already exists if either durable write fails.
                self._foreign = value.foreign
                self.remaining.discard("foreign_task_creation")
                self.remaining.add("foreign_task")
                self._retain("launch/exact-fixture-task.txt",
                             value.launch_evidence, "text/plain", "task", 0)
                return value

            # A throwing launcher can leave a task-creation uncertainty but
            # cannot provide an identity that would authorize broad cleanup.
            self.remaining.add("foreign_task_creation")
            launched = self._operation(
                "launch_exact_fixture_task", "task",
                {"serial": AUTHORIZED_SERIAL,
                 "fixtureUri": self.plan.fixture_uri,
                 "fixtureSha256": self.plan.fixture_sha256,
                 "displayId": display_id},
                launch,
                lambda value: value.foreign.wire())
            _need(self._foreign == launched.foreign,
                  "retained launch cleanup identity differs")
            _, attached_task, _ = self._platform_capture(
                "postlaunch-preack", self._foreign, display_id)
            _need(attached_task is not None,
                  "launch lacks strict live task authority")

            def attach() -> None:
                self._host_attach_attempted = True
                self._host_call(
                    lambda authority: authority.attach_ack(
                        self._foreign, self.plan.absolute_deadline_ns))
                # Like the task identity, acknowledged host ownership is a
                # cleanup fact before its result record is published.
                self._host_attached = True

            self._operation(
                "host_attach_exact_foreign", "host",
                {"foreign": self._foreign.wire()},
                attach,
                lambda _: {"state": self._retained_host_authority.state})
            for index, phase in enumerate(self.plan.phases):
                self._phase(phase, index)
        except BaseException as error:
            self._primary = {
                "code": type(error).__name__,
                "message": str(error)[:MAX_FAILURE_CHARS],
                "atRecordSha256": self.log.head,
            }
            try:
                self.log.append("primary_failure", self._primary,
                                self.remaining)
            except BaseException as journal_error:
                self._journal_failure = {
                    "code": type(journal_error).__name__,
                    "message": str(journal_error)[:MAX_FAILURE_CHARS],
                    "headSha256": self.log.head,
                }
                self.remaining.add("session_log")
        self._cleanup_session()
        return self._terminal()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Visual-only native-page session evidence harness (hardware blocked)")
    parser.add_argument("--status", action="store_true",
                        help="print the fail-closed hardware admission status")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.status:
        raise HarnessAdmissionBlocked(
            "no device route exists; use --status and supply independently reviewed adapters in code")
    sys.stdout.buffer.write(graph.canonical_bytes(admission_status()) + b"\n")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessAdmissionBlocked as error:
        sys.stderr.write(str(error) + "\n")
        raise SystemExit(2)
