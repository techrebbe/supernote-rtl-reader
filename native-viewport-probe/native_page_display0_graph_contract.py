"""Strict host parser for the read-only stock-display graph calibration.

The parsed record is raw diagnostic evidence only. In particular, neither the
page-number base nor the meaning of either MuPDF matrix is established here.
This contract does not admit a virtual-display viewport or any pen operation.
"""
from __future__ import annotations

import math
import re
import struct
from typing import Any

import native_page_graph_v2_runner as canonical


SCHEMA_VERSION = 1
MANIFEST_AUTHORITY = "rtl-reader-display0-graph-manifest-v1"
RECORD_AUTHORITY = "rtl-reader-display0-graph-observation-v1"
MAX_FRAME_BYTES = 8192
OBSERVER_FAILURE_PAIRS = frozenset({
    ("MANIFEST", "INVALID"), ("RUNTIME", "MISMATCH"),
    ("BRIDGE", "UNAVAILABLE"), ("JAVA_CHOOSE", "FAILED"),
    ("ACTIVITY", "NONE"), ("ACTIVITY", "MULTIPLE"),
    ("ACTIVITY", "LIMIT"), ("GRAPH", "MISMATCH"),
    ("URI", "SUBTYPE"), ("URI", "WRAPPER"), ("URI", "MISMATCH"),
    ("CLEANUP", "FAILED"), ("DEADLINE", "EXPIRED"),
    ("OUTPUT", "OVERSIZE"),
})
VIEW_NAMES = frozenset({
    "handWriteView", "documentImage", "digestImage", "contentView",
    "documentLayout",
})
MAX_DIMENSION = 32768
MAX_FLOAT_ABS = 1_000_000_000


class GraphContractError(RuntimeError):
    """Only one generic rejection is exposed to ordinary callers."""


def _need(ok: bool) -> None:
    if not ok:
        raise GraphContractError("display-0 graph rejected")


def _keys(value: Any, expected: set[str] | frozenset[str]) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == set(expected))
    return value


def _int(value: Any, lower: int, upper: int) -> int:
    _need(type(value) is int and lower <= value <= upper)
    return value


def _bool(value: Any) -> bool:
    _need(type(value) is bool)
    return value


def _binary64(value: Any) -> float:
    _need(type(value) is str and
          re.fullmatch(r"0x[0-9a-f]{16}", value) is not None)
    number = struct.unpack(">d", bytes.fromhex(value[2:]))[0]
    _need(math.isfinite(number) and abs(number) <= MAX_FLOAT_ABS)
    return number


def _floats(value: Any, count: int, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    _need(type(value) is list and len(value) == count)
    for item in value:
        _binary64(item)


def _bitmap(value: Any) -> None:
    item = _keys(value, {"present", "dimensions"})
    present = _bool(item["present"])
    dimensions = item["dimensions"]
    if not present:
        _need(dimensions is None)
        return
    _need(type(dimensions) is list and len(dimensions) == 2)
    for dimension in dimensions:
        _int(dimension, 1, MAX_DIMENSION)


def _view(value: Any) -> None:
    item = _keys(value, {"present", "bounds", "windowAttachCount", "attached"})
    present = _bool(item["present"])
    if not present:
        _need(item["bounds"] is None and item["windowAttachCount"] is None and
              item["attached"] is None)
        return
    bounds = item["bounds"]
    _need(type(bounds) is list and len(bounds) == 4)
    for coordinate in bounds:
        _int(coordinate, -2147483648, 2147483647)
    _need(bounds[2] > bounds[0] and bounds[3] > bounds[1])
    _int(item["windowAttachCount"], 0, 2147483647)
    _bool(item["attached"])


def _frame(raw: bytes) -> dict[str, Any]:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME_BYTES)
    try:
        value = canonical.load_canonical(raw, MAX_FRAME_BYTES).value
    except canonical.GraphRunnerError as error:
        raise GraphContractError("display-0 graph rejected") from error
    _need(type(value) is dict)
    return value


def parse_graph_frames(frames: tuple[bytes, bytes], manifest_sha256: str,
                       *, mark_required: bool) -> dict[str, Any]:
    """Accept exactly one calibrated raw graph and its success terminator."""
    _need(type(frames) is tuple and len(frames) == 2 and
          type(manifest_sha256) is str and
          re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is not None and
          type(mark_required) is bool)
    first, complete = (_frame(raw) for raw in frames)
    expected = {
        "event", "schemaVersion", "authority", "manifestSha256",
        "observationOnly", "hardwareAdmission", "semanticCalibration",
        "hostAssertionsOnly", "runtimePidMatched", "heapWalks",
        "retainedRootSamples", "graphStable", "lifecycle",
        "uriAgreementAndExpectedMatch", "markPathPresent",
        "markPathMatchedExpected", "rawPageTuple", "pageInfo", "presenter",
        "views",
    }
    _keys(first, expected)
    _need(first["event"] == "native_page_display0_graph" and
          _int(first["schemaVersion"], 1, 1) == SCHEMA_VERSION and
          first["authority"] == RECORD_AUTHORITY and
          first["manifestSha256"] == manifest_sha256 and
          first["observationOnly"] is True and
          first["hardwareAdmission"] is False and
          first["semanticCalibration"] is False and
          first["hostAssertionsOnly"] is True and
          first["runtimePidMatched"] is True and
          _int(first["heapWalks"], 1, 1) == 1 and
          _int(first["retainedRootSamples"], 2, 2) == 2 and
          first["graphStable"] is True and
          first["uriAgreementAndExpectedMatch"] is True)
    lifecycle = _keys(first["lifecycle"], {"resumed", "finished", "destroyed"})
    _need(lifecycle == {"resumed": True, "finished": False,
                        "destroyed": False})
    _need(_bool(first["markPathPresent"]) is mark_required)
    _need(first["markPathMatchedExpected"] is
          (True if mark_required else None))

    pages = first["rawPageTuple"]
    _need(type(pages) is list and len(pages) == 4)
    for number in pages:
        _int(number, 0, 10_000_000)
    _need(pages[1] >= 1)

    page = _keys(first["pageInfo"], {
        "ctm", "revertCtm", "offset", "scale", "trimmingRect", "bitmaps",
    })
    _floats(page["ctm"], 6, nullable=True)
    _floats(page["revertCtm"], 6, nullable=True)
    _floats(page["trimmingRect"], 4, nullable=True)
    _binary64(page["scale"])
    offset = page["offset"]
    _need(type(offset) is list and len(offset) == 2)
    for number in offset:
        _int(number, -2147483648, 2147483647)
    bitmaps = _keys(page["bitmaps"], {"origin", "display", "digest"})
    for bitmap in bitmaps.values():
        _bitmap(bitmap)

    presenter = _keys(first["presenter"], {"rawRotationCode", "bitmap"})
    _int(presenter["rawRotationCode"], -2147483648, 2147483647)
    _bitmap(presenter["bitmap"])
    views = _keys(first["views"], VIEW_NAMES)
    for view in views.values():
        _view(view)

    _keys(complete, {"event", "success"})
    _need(complete == {"event": "native_page_display0_graph_complete",
                        "success": True})
    return first


def parse_graph_error_frames(frames: tuple[bytes, bytes]) -> tuple[str, str]:
    """A fixed, path-free observer rejection is diagnostic, never authority."""
    _need(type(frames) is tuple and len(frames) == 2)
    first, complete = (_frame(raw) for raw in frames)
    _keys(first, {"event", "schemaVersion", "code", "phase", "reason"})
    _need(first["event"] == "native_page_display0_graph_error" and
          _int(first["schemaVersion"], 1, 1) == SCHEMA_VERSION and
          first["code"] == "DISPLAY0_GRAPH_REJECTED" and
          type(first["phase"]) is str and type(first["reason"]) is str and
          (first["phase"], first["reason"]) in OBSERVER_FAILURE_PAIRS)
    _keys(complete, {"event", "success"})
    _need(complete == {"event": "native_page_display0_graph_complete",
                        "success": False})
    return first["phase"], first["reason"]
