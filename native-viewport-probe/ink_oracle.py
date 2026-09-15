"""Offline native-ink evidence comparisons, NOT a .mark parser or sync format.

Never normalize native coordinates or guess a tolerance. Unknown fields in each
trail are retained in equality. A difference is evidence to investigate, not
automatic proof that a native operation was incorrect (e.g. compaction may
renumber records). Only a separately validated collector can supply evidence.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import struct
from pathlib import Path

import inspect_loader_dependencies as evidence_files


class EvidenceError(ValueError):
    pass


# Exact counterpart of SavedInkReader's encoded-tree contract.  The file-size
# limit includes the envelope; these structural limits apply to the serialized
# `trails` value and are enforced independently of semantic field checks.
MAX_CAPTURE_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 16
MAX_VALUES = 2000000
MAX_STRING_BYTES = 65536
MAX_LIST_ITEMS = 200000
EVIDENCE_SCHEMA = "native-viewport-ink-evidence-v2"
SOURCE_SHA256_AUTHORITY = "external-assertion-v1"
COLLECTOR_FRAME_PREFIX = b"NATIVE_VIEWPORT_INK_EVIDENCE "
MAX_COLLECTOR_FRAME_BYTES = len(COLLECTOR_FRAME_PREFIX) + MAX_CAPTURE_BYTES + 1


# Exact top-level fields of the pinned JniTrailContainer. Reference-valued
# fields may legitimately be null in native records. The two object fields and
# m_hierarchy are explicitly opaque canonical trees; all other field grammars
# are pinned below.
NATIVE_INTS = frozenset("""flag_penup flag_special font_height font_width layer_num
m_after_shift_angle m_before_shift_angle m_copy m_draw_version m_emr_point_axis
m_group_nest m_group_num m_mupdf_chapter m_mupdf_offset_x m_mupdf_offset_y
m_mupdf_position m_redraw_height m_redraw_width m_rotate_angle m_thickness
m_trail_father m_trail_num_in_page m_trail_status m_trail_type max_x max_y
page_num pen_color pen_type pre_num process_mod rec_mod recogn_trail_type
trail_num walcom_emr_type""".split())
NATIVE_BOOLS = frozenset("""m_filter_flag m_group_end m_recogn_flag
m_render_flag""".split())
NATIVE_STRINGS = frozenset("""m_custom_string m_link_image_string m_link_info
m_userData write_app_name""".split())
NATIVE_LISTS = frozenset("""angles disable_area_list erase_line_trail_num flag_draw
m_contours_src m_control_nums m_hierarchy m_mark_pen_d_fill_dir m_points
pressures recogn_points timestamp""".split())
NATIVE_RECTS = frozenset("m_after_shift_rect m_before_shift_rect refresh_rect".split())
NATIVE_OBJECTS = frozenset(("geometry_info", "rrd"))
OPAQUE_NATIVE_LISTS = frozenset(("m_hierarchy",))
OPAQUE_NATIVE_OBJECTS = NATIVE_OBJECTS
NATIVE_FIELDS = (NATIVE_INTS | NATIVE_BOOLS | NATIVE_STRINGS | NATIVE_LISTS
                 | NATIVE_RECTS | NATIVE_OBJECTS | {"m_factor_resize"})


def _reject_decimal(_):
    raise EvidenceError("native floating-point values require exact binary wrappers")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


class _BoundedJsonParser:
    """Small exact JSON decoder whose limits precede container materialization."""
    def __init__(self, text):
        self.text = text
        self.at = 0
        self.nodes = 0
        self.trail_nodes = 0

    def parse(self):
        try:
            value = self.value(0)
            self.space()
            if self.at != len(self.text):
                raise EvidenceError("trailing JSON data")
            return value
        except (MemoryError, RecursionError) as error:
            raise EvidenceError("native JSON exceeds bounded decoder resources") from error

    def space(self):
        while self.at < len(self.text) and self.text[self.at] in " \t\r\n":
            self.at += 1

    def value(self, depth, trail_depth=None):
        self.space()
        # The semantic `trails` root is exactly one level below the envelope.
        if depth > MAX_DEPTH + 1:
            raise EvidenceError("native JSON exceeds decode depth")
        self.nodes += 1
        # Root object plus eight non-trail envelope values are the only nine
        # nodes outside the semantic tree.
        if trail_depth is not None:
            if trail_depth > MAX_DEPTH:
                raise EvidenceError("native JSON exceeds trail decode depth")
            self.trail_nodes += 1
            if self.trail_nodes > MAX_VALUES:
                raise EvidenceError("native JSON exceeds trail decode node limit")
        if self.nodes > MAX_VALUES + 9:
            raise EvidenceError("native JSON exceeds decode node limit")
        if self.at >= len(self.text):
            raise EvidenceError("truncated JSON value")
        token = self.text[self.at]
        if token == '"':
            return self.string()
        if token == "{":
            return self.object(depth, trail_depth)
        if token == "[":
            return self.array(depth, trail_depth)
        for literal, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(literal, self.at):
                self.at += len(literal)
                return value
        if token == "-" or "0" <= token <= "9":
            return self.integer()
        raise EvidenceError("unsupported JSON token")

    def string(self):
        self.at += 1
        result = []
        encoded = 0
        escapes = {'"':'"', "\\":"\\", "/":"/", "b":"\b", "f":"\f",
                   "n":"\n", "r":"\r", "t":"\t"}
        while self.at < len(self.text):
            character = self.text[self.at]
            self.at += 1
            if character == '"':
                return "".join(result)
            if ord(character) < 0x20:
                raise EvidenceError("unescaped JSON control character")
            if character == "\\":
                if self.at >= len(self.text):
                    raise EvidenceError("truncated JSON escape")
                escape = self.text[self.at]
                self.at += 1
                if escape in escapes:
                    character = escapes[escape]
                elif escape == "u":
                    if self.at + 4 > len(self.text) or not re.fullmatch(
                            "[0-9a-fA-F]{4}", self.text[self.at:self.at+4]):
                        raise EvidenceError("invalid JSON unicode escape")
                    code = int(self.text[self.at:self.at+4], 16)
                    self.at += 4
                    if 0xD800 <= code <= 0xDBFF:
                        if (self.at + 6 > len(self.text) or self.text[self.at:self.at+2] != "\\u" or
                                not re.fullmatch("[0-9a-fA-F]{4}", self.text[self.at+2:self.at+6])):
                            raise EvidenceError("unpaired JSON surrogate")
                        low = int(self.text[self.at+2:self.at+6], 16)
                        if not 0xDC00 <= low <= 0xDFFF:
                            raise EvidenceError("unpaired JSON surrogate")
                        self.at += 6
                        character = chr(0x10000 + ((code-0xD800)<<10) + low-0xDC00)
                    elif 0xDC00 <= code <= 0xDFFF:
                        raise EvidenceError("unpaired JSON surrogate")
                    else:
                        character = chr(code)
                else:
                    raise EvidenceError("invalid JSON escape")
            elif 0xD800 <= ord(character) <= 0xDFFF:
                raise EvidenceError("unpaired JSON surrogate")
            encoded += len(character.encode("utf-8"))
            if encoded > MAX_STRING_BYTES:
                raise EvidenceError("oversized decoded JSON string")
            result.append(character)
        raise EvidenceError("unterminated JSON string")

    def integer(self):
        start = self.at
        if self.text[self.at] == "-":
            self.at += 1
            if self.at >= len(self.text):
                raise EvidenceError("truncated JSON integer")
        if self.text[self.at] == "0":
            self.at += 1
            if (self.at < len(self.text) and
                    "0" <= self.text[self.at] <= "9"):
                raise EvidenceError("leading-zero JSON integer")
        elif "1" <= self.text[self.at] <= "9":
            while (self.at < len(self.text) and
                   "0" <= self.text[self.at] <= "9"):
                self.at += 1
        else:
            raise EvidenceError("invalid JSON integer")
        if self.at < len(self.text) and self.text[self.at] in ".eE":
            raise EvidenceError("native floating-point values require exact binary wrappers")
        token = self.text[start:self.at]
        if len(token) > 11:
            raise EvidenceError("bare native integer exceeds signed-32-bit producer contract")
        value = int(token)
        if not -2**31 <= value <= 2**31 - 1:
            raise EvidenceError("bare native integer exceeds signed-32-bit producer contract")
        return value

    def array(self, depth, trail_depth):
        self.at += 1
        result = []
        self.space()
        if self.at < len(self.text) and self.text[self.at] == "]":
            self.at += 1
            return result
        while True:
            if len(result) >= MAX_LIST_ITEMS:
                raise EvidenceError("oversized decoded JSON array")
            result.append(self.value(
                depth + 1, None if trail_depth is None else trail_depth + 1))
            self.space()
            if self.at >= len(self.text):
                raise EvidenceError("truncated JSON array")
            delimiter = self.text[self.at]
            self.at += 1
            if delimiter == "]":
                return result
            if delimiter != ",":
                raise EvidenceError("invalid JSON array delimiter")

    def object(self, depth, trail_depth):
        self.at += 1
        result = {}
        self.space()
        if self.at < len(self.text) and self.text[self.at] == "}":
            self.at += 1
            return result
        while True:
            self.space()
            if self.at >= len(self.text) or self.text[self.at] != '"':
                raise EvidenceError("JSON object key required")
            key = self.string()
            if key in result:
                raise EvidenceError("duplicate JSON field: " + key)
            self.space()
            if self.at >= len(self.text) or self.text[self.at] != ":":
                raise EvidenceError("JSON object colon required")
            self.at += 1
            child_trail_depth = (0 if depth == 0 and trail_depth is None and key == "trails"
                                 else None if trail_depth is None else trail_depth + 1)
            result[key] = self.value(depth + 1, child_trail_depth)
            self.space()
            if self.at >= len(self.text):
                raise EvidenceError("truncated JSON object")
            delimiter = self.text[self.at]
            self.at += 1
            if delimiter == "}":
                return result
            if delimiter != ",":
                raise EvidenceError("invalid JSON object delimiter")


def _parse_bounded_json(text):
    return _BoundedJsonParser(text).parse()


class _CanonicalWriter:
    """Independent implementation of the frozen v2 compact UTF-8 wire."""
    def __init__(self, limit, materialize):
        if type(limit) is not int or limit < 0:
            raise EvidenceError("invalid canonical JSON byte limit")
        self.limit = limit
        self.parts = [] if materialize else None
        self.bytes = 0
        self.visiting = set()

    def reserve(self, count):
        if type(count) is not int or count < 0 or self.bytes > self.limit - count:
            raise EvidenceError("canonical JSON exceeds byte bound")
        self.bytes += count

    def ascii(self, value):
        if type(value) is not str or any(ord(character) > 0x7f for character in value):
            raise EvidenceError("internal non-ASCII canonical token")
        self.reserve(len(value))
        if self.parts is not None:
            self.parts.append(value)

    def raw(self, value):
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise EvidenceError("invalid native string encoding") from error
        self.reserve(len(encoded))
        if self.parts is not None:
            self.parts.append(value)

    def string(self, value):
        if type(value) is not str:
            raise EvidenceError("canonical JSON string required")
        self.ascii('"')
        short = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t",
                 "\n": "\\n", "\f": "\\f", "\r": "\\r"}
        for character in value:
            code = ord(character)
            if character in short:
                self.ascii(short[character])
            elif code <= 0x1f:
                self.ascii(f"\\u{code:04x}")
            else:
                self.raw(character)
        self.ascii('"')

    @staticmethod
    def key_order(value):
        try:
            return value.encode("utf-16-be", errors="strict")
        except UnicodeEncodeError as error:
            raise EvidenceError("invalid native object key") from error

    def write(self, value):
        kind = type(value)
        if value is None:
            self.ascii("null")
        elif kind is bool:
            self.ascii("true" if value else "false")
        elif kind is int:
            if not -2**31 <= value <= 2**31 - 1:
                raise EvidenceError("bare native integer exceeds signed-32-bit producer contract")
            self.ascii(str(value))
        elif kind is str:
            self.string(value)
        elif kind is list:
            identity = id(value)
            if identity in self.visiting:
                raise EvidenceError("cyclic canonical JSON value")
            self.visiting.add(identity)
            try:
                self.ascii("[")
                for index, child in enumerate(value):
                    if index:
                        self.ascii(",")
                    self.write(child)
                self.ascii("]")
            finally:
                self.visiting.remove(identity)
        elif kind is dict:
            identity = id(value)
            if identity in self.visiting:
                raise EvidenceError("cyclic canonical JSON value")
            keys = list(value)
            for key in keys:
                if type(key) is not str:
                    raise EvidenceError("invalid native object key")
                try:
                    key_bytes = len(key.encode("utf-8", errors="strict"))
                except UnicodeEncodeError as error:
                    raise EvidenceError("invalid native object key") from error
                if key_bytes > MAX_STRING_BYTES:
                    raise EvidenceError("invalid native object key")
            keys.sort(key=self.key_order)
            self.visiting.add(identity)
            try:
                self.ascii("{")
                for index, key in enumerate(keys):
                    if index:
                        self.ascii(",")
                    self.string(key)
                    self.ascii(":")
                    self.write(value[key])
                self.ascii("}")
            finally:
                self.visiting.remove(identity)
        elif kind is float:
            _reject_decimal(value)
        else:
            raise EvidenceError("non-JSON native value")

    def result(self):
        if self.parts is None:
            raise EvidenceError("count-only canonical writer has no text")
        return "".join(self.parts)


def canonical_json(value, limit=MAX_CAPTURE_BYTES):
    writer = _CanonicalWriter(limit, True)
    writer.write(value)
    result = writer.result()
    if len(result.encode("utf-8", errors="strict")) != writer.bytes:
        raise EvidenceError("canonical JSON byte accounting mismatch")
    return result


def _canonical_json_bytes(value, limit=MAX_CAPTURE_BYTES):
    writer = _CanonicalWriter(limit, False)
    writer.write(value)
    return writer.bytes


def _canonical_string_bytes(value, limit=MAX_CAPTURE_BYTES):
    writer = _CanonicalWriter(limit, False)
    writer.string(value)
    return writer.bytes


class _EncodingBudget:
    """Per-root authority matching SavedInkReader.EncodingBudget exactly."""
    def __init__(self):
        self.values = 0
        self.encoded_bytes = 0

    def reserve_value(self):
        if self.values >= MAX_VALUES:
            raise EvidenceError("native data exceeds structural bound")
        self.values += 1

def _validate_encoded_tree(value):
    budget = _EncodingBudget()
    _validate_encoded_value(value, 0, budget)
    budget.encoded_bytes = _canonical_json_bytes(value, MAX_CAPTURE_BYTES)
    return (budget.values, budget.encoded_bytes)


def _validate_encoded_value(value, depth, budget):
    budget.reserve_value()
    if depth > MAX_DEPTH:
        raise EvidenceError("native data exceeds structural bound")
    kind = type(value)
    if kind not in (type(None), bool, int, str, dict, list):
        if kind is float:
            _reject_decimal(value)
        raise EvidenceError("non-JSON native value")
    if kind is int:
        if not -2**31 <= value <= 2**31 - 1:
            raise EvidenceError("bare native integer exceeds signed-32-bit producer contract")
    elif kind is float:
        # Even finite JSON decimals can already have rounded or underflowed
        # before comparison. The collector never emits unwrapped floats.
        _reject_decimal(value)
    elif kind is str:
        try:
            string_bytes = len(value.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as error:
            raise EvidenceError("invalid native string encoding") from error
        if string_bytes > MAX_STRING_BYTES:
            raise EvidenceError("oversized native string")
    elif kind is dict:
        if "binary32" in value or "binary64" in value:
            tag = "binary32" if "binary32" in value else "binary64"
            width, fmt = (8, ">f") if tag == "binary32" else (16, ">d")
            if set(value) != {tag} or type(value[tag]) is not str or not re.fullmatch(
                    "[0-9a-f]{" + str(width) + "}", value[tag]):
                raise EvidenceError("invalid native floating-point bit wrapper")
            if not math.isfinite(struct.unpack(fmt, bytes.fromhex(value[tag]))[0]):
                raise EvidenceError("non-finite native floating-point bits")
        for key, child in value.items():
            try:
                key_bytes = len(key.encode("utf-8", errors="strict")) if type(key) is str else -1
            except UnicodeEncodeError as error:
                raise EvidenceError("invalid native object key") from error
            if type(key) is not str or key_bytes > MAX_STRING_BYTES:
                raise EvidenceError("invalid native object key")
            _validate_encoded_value(child, depth + 1, budget)
    elif kind is list:
        if len(value) > MAX_LIST_ITEMS:
            raise EvidenceError("oversized native array")
        for child in value:
            _validate_encoded_value(child, depth + 1, budget)


def _envelope_encoded_bytes(capture, trails_bytes):
    """Canonical envelope size; trails_bytes is independently cross-checked."""
    if trails_bytes != _canonical_json_bytes(capture["trails"], MAX_CAPTURE_BYTES):
        raise EvidenceError("canonical trail byte accounting mismatch")
    return _canonical_json_bytes(capture, MAX_CAPTURE_BYTES)


def _require_expected_source(capture, expected_source_sha256):
    if (type(expected_source_sha256) is not str or
            not re.fullmatch("[0-9a-f]{64}", expected_source_sha256)):
        raise EvidenceError("trusted outer verifier must supply expected source SHA-256")
    if capture["sourceSha256"] != expected_source_sha256:
        raise EvidenceError("externally asserted source SHA-256 does not match verifier authority")


def _decode_canonical_capture(raw, expected_source_sha256):
    if type(raw) is not bytes or len(raw) > MAX_CAPTURE_BYTES:
        raise EvidenceError("capture exceeds diagnostic size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        capture = _parse_bounded_json(text)
    except (ValueError, UnicodeError) as error:
        raise EvidenceError(str(error)) from error
    validate(capture)
    _require_expected_source(capture, expected_source_sha256)
    expected_wire = canonical_json(capture, MAX_CAPTURE_BYTES)
    if raw != expected_wire.encode("utf-8"):
        raise EvidenceError("capture is not the canonical v2 JSON wire")
    return capture


def read(path, expected_source_sha256):
    try:
        raw = evidence_files.read_bounded(Path(path), MAX_CAPTURE_BYTES)
    except evidence_files.InventoryError as error:
        raise EvidenceError(str(error)) from error
    return _decode_canonical_capture(raw, expected_source_sha256)


def parse_collector_frame(raw, expected_source_sha256):
    """Admit exactly one complete SavedInkReader stdout record.

    The producer checks PrintStream's sticky error state. This independent
    parser closes the other side of the publication boundary: a truncated,
    concatenated, prefixed, suffixed, or CRLF-rewritten capture is never
    mistaken for evidence.
    """
    if type(raw) is not bytes or len(raw) > MAX_COLLECTOR_FRAME_BYTES:
        raise EvidenceError("collector frame exceeds diagnostic size limit")
    if not raw.startswith(COLLECTOR_FRAME_PREFIX) or not raw.endswith(b"\n"):
        raise EvidenceError("collector frame is incomplete or has wrong prefix")
    payload = raw[len(COLLECTOR_FRAME_PREFIX):-1]
    if not payload or b"\n" in payload or b"\r" in payload:
        raise EvidenceError("collector output is not exactly one framed record")
    return _decode_canonical_capture(payload, expected_source_sha256)


def read_collector_frame(path, expected_source_sha256):
    try:
        raw = evidence_files.read_bounded(Path(path), MAX_COLLECTOR_FRAME_BYTES)
    except evidence_files.InventoryError as error:
        raise EvidenceError(str(error)) from error
    return parse_collector_frame(raw, expected_source_sha256)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate(capture):
    required = {"schema", "sourceSha256", "markSha256Before", "markSha256After",
                "nativePage", "complete", "readMethod", "sourceSha256Authority",
                "trails"}
    if type(capture) is not dict or set(capture) != required:
        raise EvidenceError("unknown or missing capture envelope field")
    if capture["schema"] != EVIDENCE_SCHEMA:
        raise EvidenceError("unknown diagnostic schema")
    if capture["sourceSha256Authority"] != SOURCE_SHA256_AUTHORITY:
        raise EvidenceError("source SHA-256 is not explicitly an external assertion")
    if capture["complete"] is not True or capture["readMethod"] != "getFilePageTrails":
        raise EvidenceError("requires complete saved-page capture, not live pending input")
    for key in ("sourceSha256", "markSha256Before", "markSha256After"):
        if type(capture[key]) is not str or not re.fullmatch("[0-9a-f]{64}", capture[key]):
            raise EvidenceError(f"invalid {key}")
    if capture["markSha256Before"] != capture["markSha256After"]:
        raise EvidenceError("mark changed during capture")
    page = capture["nativePage"]
    if not _integer(page, 1, 2**31 - 1):
        raise EvidenceError("native page is explicitly one-based")
    trails = capture["trails"]
    if type(trails) is not list or len(trails) > 4096:
        raise EvidenceError("invalid trail list")
    trail_state = _validate_encoded_tree(trails)
    _envelope_encoded_bytes(capture, trail_state[1])
    keys = set()
    for trail in trails:
        if type(trail) is not dict:
            raise EvidenceError("invalid native record")
        if set(trail) != NATIVE_FIELDS:
            raise EvidenceError("unknown or incomplete native record field inventory")
        for key in NATIVE_INTS:
            if key not in trail or not _integer(trail[key], -2**31, 2**31-1):
                raise EvidenceError(f"missing/inexact native integer {key}")
        for key in NATIVE_BOOLS:
            if type(trail[key]) is not bool:
                raise EvidenceError(f"invalid native boolean {key}")
        for key in NATIVE_STRINGS:
            if trail[key] is not None and type(trail[key]) is not str:
                raise EvidenceError(f"invalid native string {key}")
        for key in NATIVE_LISTS:
            if trail[key] is not None and type(trail[key]) is not list:
                raise EvidenceError(f"invalid native list {key}")
        for key in NATIVE_RECTS:
            rect = trail[key]
            if rect is not None and (type(rect) is not list or len(rect) != 4 or not all(
                    _integer(v, -2**31, 2**31-1) for v in rect)):
                raise EvidenceError(f"invalid native rectangle {key}")
        for key in NATIVE_OBJECTS:
            if trail[key] is not None and type(trail[key]) is not dict:
                raise EvidenceError(f"invalid native object {key}")
        if type(trail["m_factor_resize"]) is not dict or set(trail["m_factor_resize"]) != {"binary64"}:
            raise EvidenceError("native resize factor requires binary64 bits")
        if trail["page_num"] != page:
            raise EvidenceError("wrong-page trail")
        identity = trail_key(trail)
        if identity in keys:
            raise EvidenceError("ambiguous duplicate native trail identity")
        keys.add(identity)
        # No invented alignment between different native arrays. The collector
        # preserves all of them; sample-count conventions require hardware proof.
        for key in ("m_points", "pressures", "angles", "flag_draw", "timestamp"):
            if key not in trail or type(trail[key]) is not list or len(trail[key]) > 200000:
                raise EvidenceError(f"missing/invalid native sample array {key}")
        for point in trail["m_points"]:
            if type(point) is not list or len(point) != 2 or not all(
                    _integer(v, -2**31, 2**31-1) for v in point):
                raise EvidenceError("invalid native point")
        if not all(_integer(v, -32768, 32767) for v in trail["pressures"]):
            raise EvidenceError("invalid native pressure")
        if not all(type(v) is bool for v in trail["flag_draw"]):
            raise EvidenceError("invalid native draw flag")
        for angle in trail["angles"]:
            if type(angle) is not dict or set(angle) != {"x", "y"} or not all(
                    _integer(v, -32768, 32767) for v in angle.values()):
                raise EvidenceError("invalid native angle")
        for timestamp in trail["timestamp"]:
            if not _lossless_long(timestamp):
                raise EvidenceError("invalid lossless native timestamp")
        _validate_flag_rect_list(trail["disable_area_list"])
        _validate_int_list(trail["erase_line_trail_num"], -2**31, 2**31-1,
                           "erase_line_trail_num")
        _validate_pointf_contours(trail["m_contours_src"])
        _validate_int_list(trail["m_control_nums"], -2**31, 2**31-1,
                           "m_control_nums")
        _validate_pointf_list(trail["m_mark_pen_d_fill_dir"],
                              "m_mark_pen_d_fill_dir")
        _validate_recogn_data_list(trail["recogn_points"])


def _optional_list(value, label):
    if value is None:
        return None
    if type(value) is not list:
        raise EvidenceError(f"invalid native list {label}")
    return value


def _validate_int_list(value, low, high, label):
    values = _optional_list(value, label)
    if values is not None and not all(_integer(item, low, high) for item in values):
        raise EvidenceError(f"invalid native integer list {label}")


def _lossless_long(value):
    return (type(value) is str and
            re.fullmatch("0|-?[1-9][0-9]{0,18}", value) is not None and
            -2**63 <= int(value) <= 2**63 - 1)


def _binary32(value):
    if (type(value) is not dict or set(value) != {"binary32"} or
            type(value["binary32"]) is not str or
            re.fullmatch("[0-9a-f]{8}", value["binary32"]) is None):
        return False
    return math.isfinite(struct.unpack(">f", bytes.fromhex(value["binary32"]))[0])


def _pointf(value):
    return (type(value) is list and len(value) == 2 and
            all(_binary32(coordinate) for coordinate in value))


def _validate_pointf_list(value, label):
    values = _optional_list(value, label)
    if values is not None and not all(_pointf(point) for point in values):
        raise EvidenceError(f"invalid native PointF list {label}")


def _validate_pointf_contours(value):
    contours = _optional_list(value, "m_contours_src")
    if contours is not None:
        for contour in contours:
            if type(contour) is not list or not all(_pointf(point) for point in contour):
                raise EvidenceError("invalid native PointF contour list m_contours_src")


def _validate_flag_rect_list(value):
    values = _optional_list(value, "disable_area_list")
    fields = {"coorOrigin", "flag", "height", "width", "x", "y"}
    if values is not None and not all(
            type(rect) is dict and set(rect) == fields and
            all(_integer(item, -2**31, 2**31 - 1) for item in rect.values())
            for rect in values):
        raise EvidenceError("invalid native JniFlagRect list disable_area_list")


def _validate_recogn_data_list(value):
    values = _optional_list(value, "recogn_points")
    fields = {"Flag", "X", "Y", "timestamp"}
    if values is not None and not all(
            type(item) is dict and set(item) == fields and
            all(_integer(item[field], -2**31, 2**31 - 1)
                for field in ("Flag", "X", "Y")) and
            _lossless_long(item["timestamp"])
            for item in values):
        raise EvidenceError("invalid native JniRecognData list recogn_points")


def trail_key(trail):
    """Diagnostic record identity only; not a promised stable annotation UUID."""
    return tuple(trail[k] for k in ("page_num", "layer_num", "trail_num", "m_trail_num_in_page"))


def compare(before, after, expected_source_sha256):
    validate(before)
    validate(after)
    _require_expected_source(before, expected_source_sha256)
    _require_expected_source(after, expected_source_sha256)
    if (before["sourceSha256"], before["nativePage"]) != (after["sourceSha256"], after["nativePage"]):
        raise EvidenceError("different document/page authority")
    left = {trail_key(t): t for t in before["trails"]}
    right = {trail_key(t): t for t in after["trails"]}
    changed = {}
    for identity in sorted(left.keys() & right.keys()):
        fields = []
        for key in sorted(left[identity].keys() | right[identity].keys()):
            # The frozen canonical wire preserves exact JSON producer types.
            if key not in left[identity] or key not in right[identity] or canonical_json(
                    left[identity].get(key)) != canonical_json(right[identity].get(key)):
                fields.append(key)
        if fields:
            changed[str(identity)] = fields
    return {"added": sorted(right.keys() - left.keys()), "removed": sorted(left.keys() - right.keys()),
            "changed": changed, "unchanged": len(left.keys() & right.keys()) - len(changed)}


def java_golden_trail():
    """Independent expected wire for every field in GoldenTrailRecord."""
    expected = {
        "flag_penup": 101, "flag_special": 102, "font_height": 103,
        "font_width": 104, "layer_num": 7, "m_after_shift_angle": 106,
        "m_before_shift_angle": 107, "m_copy": 108, "m_draw_version": 109,
        "m_emr_point_axis": 110, "m_group_nest": 111, "m_group_num": 112,
        "m_mupdf_chapter": 113, "m_mupdf_offset_x": -114,
        "m_mupdf_offset_y": -115, "m_mupdf_position": 116,
        "m_redraw_height": 117, "m_redraw_width": 118,
        "m_rotate_angle": 119, "m_thickness": 300, "m_trail_father": -121,
        "m_trail_num_in_page": 19, "m_trail_status": 123,
        "m_trail_type": 124, "max_x": 125, "max_y": 126, "page_num": 1,
        "pen_color": 157, "pen_type": 10, "pre_num": 130,
        "process_mod": 131, "rec_mod": 132, "recogn_trail_type": 133,
        "trail_num": 17, "walcom_emr_type": 135,
        "m_filter_flag": True, "m_group_end": False,
        "m_recogn_flag": True, "m_render_flag": False,
        "m_custom_string": "custom-golden",
        "m_link_image_string": "image-golden",
        "m_link_info": "link-golden",
        "m_userData": ('slash=/ close=</ quote=" backslash=\\'
                       ' controls=\u0000\b\t\n\u000b\f\r\u001f del=\u007f c1=\u0085'
                       ' separators=\u2028\u2029 hebrew=\u05e9\u05dc\u05d5\u05dd'
                       ' combining=e\u0301 emoji=\U0001f600'),
        "write_app_name": "writer-golden",
        "angles": [{"x": 11, "y": -12}, {"x": 13, "y": -14}],
        "disable_area_list": [{"coorOrigin": -206, "flag": 205,
                               "height": -2147483648, "width": 2147483647,
                               "x": 201, "y": -202}],
        "erase_line_trail_num": [205, 206],
        "flag_draw": [True, False, True],
        "m_contours_src": [[[{"binary32": "80000000"},
                              {"binary32": "3fc00000"}],
                             [{"binary32": "00000001"},
                              {"binary32": "ff7fffff"}]]],
        "m_control_nums": [-2147483648, 2147483647],
        "m_hierarchy": ["hierarchy-golden"],
        "m_mark_pen_d_fill_dir": [[{"binary32": "80000000"},
                                    {"binary32": "00000000"}],
                                   [{"binary32": "3fc00000"},
                                    {"binary32": "c0100000"}]],
        "m_points": [[939, 388], [1078, 401]],
        "pressures": [100, 200],
        "recogn_points": [{"Flag": -211, "X": -2147483648,
                            "Y": 2147483647,
                            "timestamp": "-9223372036854775808"},
                           {"Flag": 214, "X": 212, "Y": -213,
                            "timestamp": "9223372036854775807"}],
        "timestamp": ["1788700000000", "1788700000010"],
        "m_after_shift_rect": [301, 302, 303, 304],
        "m_before_shift_rect": [305, 306, 307, 308],
        "refresh_rect": [309, 310, 311, 312],
        "geometry_info": {"code": 401, "label": "geometry-golden"},
        "rrd": {"code": 402, "label": "rrd-golden"},
        "m_factor_resize": {"binary64": "8000000000000000"},
    }
    if set(expected) != NATIVE_FIELDS:
        raise EvidenceError("Java golden expectation field inventory is incomplete")
    return expected


def validate_java_golden(capture):
    """Prove every native field traversed the real Java encoder losslessly."""
    validate(capture)
    if len(capture["trails"]) != 1:
        raise EvidenceError("Java golden requires exactly one encoded trail")
    trail = capture["trails"][0]
    expected = java_golden_trail()
    if set(trail) != set(expected):
        raise EvidenceError("Java golden trail field inventory changed")
    for key in sorted(expected):
        actual_wire = canonical_json(trail[key])
        expected_wire = canonical_json(expected[key])
        if actual_wire != expected_wire:
            raise EvidenceError(f"Java golden production-encoder field changed: {key}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, nargs="?")
    parser.add_argument("after", type=Path, nargs="?")
    parser.add_argument("--framed-before", type=Path)
    parser.add_argument("--framed-after", type=Path)
    parser.add_argument("--expect", required=True, choices=("unchanged", "one-addition"))
    parser.add_argument("--expect-java-golden", action="store_true")
    parser.add_argument("--expected-source-sha256")
    args = parser.parse_args()
    try:
        expected_source = args.expected_source_sha256
        if expected_source is None and args.expect_java_golden:
            expected_source = "a" * 64
        if expected_source is None:
            raise EvidenceError(
                "trusted outer verifier must supply --expected-source-sha256")
        raw_any = args.before is not None or args.after is not None
        raw_complete = args.before is not None and args.after is not None
        framed_any = (args.framed_before is not None or
                      args.framed_after is not None)
        framed_complete = (args.framed_before is not None and
                           args.framed_after is not None)
        if (raw_any != raw_complete or framed_any != framed_complete or
                raw_complete == framed_complete):
            raise EvidenceError(
                "supply exactly one complete raw or framed before/after pair")
        if framed_complete:
            before = read_collector_frame(args.framed_before, expected_source)
            after = read_collector_frame(args.framed_after, expected_source)
        else:
            before = read(args.before, expected_source)
            after = read(args.after, expected_source)
        if args.expect_java_golden:
            validate_java_golden(before)
            validate_java_golden(after)
        diff = compare(before, after, expected_source)
        ok = not diff["removed"] and not diff["changed"] and len(diff["added"]) == (
            1 if args.expect == "one-addition" else 0)
        print(json.dumps({"status": "PASS" if ok else "DIFFERENT", "comparison": diff,
                          "scope": "captured native records; collector validity is a separate gate"}))
        return 0 if ok else 1
    except EvidenceError as error:
        print(json.dumps({"status": "INVALID_EVIDENCE", "reason": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
