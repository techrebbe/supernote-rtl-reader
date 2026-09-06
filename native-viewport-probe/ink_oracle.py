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


class EvidenceError(ValueError):
    pass


# Required top-level fields of the pinned JniTrailContainer. Extra fields remain
# visible in comparisons, but omission of an existing field is never complete
# evidence. Reference-valued fields may legitimately be null in native records.
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


def _finite(value):
    if isinstance(value, float):
        # Even finite JSON decimals can already have rounded or underflowed
        # before comparison. The collector never emits unwrapped floats.
        _reject_decimal(value)
    if isinstance(value, dict):
        if "binary32" in value or "binary64" in value:
            tag = "binary32" if "binary32" in value else "binary64"
            width, fmt = (8, ">f") if tag == "binary32" else (16, ">d")
            if set(value) != {tag} or type(value[tag]) is not str or not re.fullmatch(
                    "[0-9a-f]{" + str(width) + "}", value[tag]):
                raise EvidenceError("invalid native floating-point bit wrapper")
            if not math.isfinite(struct.unpack(fmt, bytes.fromhex(value[tag]))[0]):
                raise EvidenceError("non-finite native floating-point bits")
        for child in value.values():
            _finite(child)
    elif isinstance(value, list):
        for child in value:
            _finite(child)


def read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise EvidenceError("capture exceeds diagnostic size limit")
    try:
        capture = json.loads(raw, object_pairs_hook=_object,
                             parse_float=_reject_decimal, parse_constant=_reject_decimal)
    except (ValueError, UnicodeError) as error:
        raise EvidenceError(str(error)) from error
    validate(capture)
    return capture


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate(capture):
    required = {"schema", "sourceSha256", "markSha256Before", "markSha256After",
                "nativePage", "complete", "readMethod", "trails"}
    if type(capture) is not dict or set(capture) != required:
        raise EvidenceError("unknown or missing capture envelope field")
    _finite(capture)
    if capture["schema"] != "native-viewport-ink-evidence-v1":
        raise EvidenceError("unknown diagnostic schema")
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
    keys = set()
    for trail in trails:
        if type(trail) is not dict:
            raise EvidenceError("invalid native record")
        if not NATIVE_FIELDS <= trail.keys():
            raise EvidenceError("incomplete native record field inventory")
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
            if type(timestamp) is not str or not re.fullmatch("0|-?[1-9][0-9]{0,18}", timestamp) or not (
                    -2**63 <= int(timestamp) <= 2**63-1):
                raise EvidenceError("invalid lossless native timestamp")


def trail_key(trail):
    """Diagnostic record identity only; not a promised stable annotation UUID."""
    return tuple(trail[k] for k in ("page_num", "layer_num", "trail_num", "m_trail_num_in_page"))


def compare(before, after):
    validate(before)
    validate(after)
    if (before["sourceSha256"], before["nativePage"]) != (after["sourceSha256"], after["nativePage"]):
        raise EvidenceError("different document/page authority")
    left = {trail_key(t): t for t in before["trails"]}
    right = {trail_key(t): t for t in after["trails"]}
    changed = {}
    for identity in sorted(left.keys() & right.keys()):
        fields = []
        for key in sorted(left[identity].keys() | right[identity].keys()):
            # JSON encoding preserves int/float and signed-zero distinctions.
            if key not in left[identity] or key not in right[identity] or json.dumps(
                    left[identity].get(key), sort_keys=True, allow_nan=False) != json.dumps(
                    right[identity].get(key), sort_keys=True, allow_nan=False):
                fields.append(key)
        if fields:
            changed[str(identity)] = fields
    return {"added": sorted(right.keys() - left.keys()), "removed": sorted(left.keys() - right.keys()),
            "changed": changed, "unchanged": len(left.keys() & right.keys()) - len(changed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--expect", required=True, choices=("unchanged", "one-addition"))
    args = parser.parse_args()
    try:
        diff = compare(read(args.before), read(args.after))
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
