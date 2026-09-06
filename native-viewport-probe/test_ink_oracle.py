import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ink_oracle import (EvidenceError, compare, read, validate, NATIVE_FIELDS,
                        NATIVE_INTS, NATIVE_BOOLS, NATIVE_STRINGS, NATIVE_LISTS,
                        NATIVE_RECTS, NATIVE_OBJECTS)


def record(n=1):
    trail = {key: 0 for key in NATIVE_INTS}
    trail.update({key: False for key in NATIVE_BOOLS})
    trail.update({key: "" for key in NATIVE_STRINGS})
    trail.update({key: [] for key in NATIVE_LISTS})
    trail.update({key: [0, 0, 1, 1] for key in NATIVE_RECTS})
    trail.update({key: None for key in NATIVE_OBJECTS})
    trail.update({"page_num": 1, "layer_num": 0, "trail_num": n, "m_trail_num_in_page": n,
            "m_thickness": 300, "pen_type": 10, "pen_color": 157, "m_trail_status": 0,
            "m_points": [[939, 388], [1078, 401]], "pressures": [100, 200],
            "angles": [{"x": 0, "y": 0}, {"x": 0, "y": 1}], "flag_draw": [True, True],
            "timestamp": ["1788700000000", "1788700000010"], "m_userData": "",
            "m_factor_resize": {"binary64": "3ff0000000000000"}, "m_after_shift_rect": [0, 0, 1, 1]})
    return trail


def capture():
    return {"schema": "native-viewport-ink-evidence-v1", "sourceSha256": "a"*64,
            "markSha256Before": "b"*64, "markSha256After": "b"*64,
            "nativePage": 1, "complete": True, "readMethod": "getFilePageTrails", "trails": [record()]}


class OracleTests(unittest.TestCase):
    def test_unchanged_and_reordered(self):
        a = capture(); a["trails"].append(record(2))
        b = copy.deepcopy(a); b["trails"].reverse()
        self.assertEqual(compare(a, b), {"added": [], "removed": [], "changed": {}, "unchanged": 2})

    def test_addition_preserves_prior(self):
        a = capture(); b = copy.deepcopy(a); b["trails"].append(record(2))
        self.assertEqual(compare(a, b)["added"], [(1, 0, 2, 2)])
        b["trails"][0]["m_points"][0][0] += 1
        self.assertTrue(compare(a, b)["changed"])

    def test_each_prior_failure_is_visible(self):
        changes = {"m_points": [[939, 313], [1078, 326]], "m_thickness": 225,
                   "pressures": [99, 200], "m_after_shift_rect": [0, 0, 9, 9],
                   "m_factor_resize": {"binary64": "3fe8000000000000"}, "flag_draw": [False, True],
                   "timestamp": ["1788700000001", "1788700000010"], "m_userData": "different"}
        for field, value in changes.items():
            with self.subTest(field=field):
                a = capture(); b = copy.deepcopy(a); b["trails"][0][field] = value
                self.assertEqual(list(compare(a, b)["changed"].values()), [[field]])

    def test_disappeared_and_duplicate(self):
        a = capture(); b = copy.deepcopy(a); b["trails"] = []
        self.assertEqual(compare(a, b)["removed"], [(1, 0, 1, 1)])
        a["trails"].append(record())
        with self.assertRaises(EvidenceError): validate(a)

    def test_wrong_authority_or_incomplete(self):
        for field, value in (("sourceSha256", "c"*64), ("nativePage", 2)):
            a = capture(); b = copy.deepcopy(a); b[field] = value
            with self.assertRaises(EvidenceError): compare(a, b)
        for field, value in (("complete", False), ("complete", 1), ("nativePage", True),
                             ("markSha256After", "c"*64), ("readMethod", "getTrailContainer")):
            a = capture(); a[field] = value
            with self.assertRaises(EvidenceError): validate(a)

    def test_unknown_native_fields_are_not_ignored(self):
        a = capture(); b = copy.deepcopy(a); b["trails"][0]["new_native_field"] = 7
        self.assertEqual(list(compare(a, b)["changed"].values()), [["new_native_field"]])

    def test_signed_zero_and_types(self):
        a = capture(); a["trails"][0]["m_factor_resize"] = {"binary64": "0000000000000000"}
        b = copy.deepcopy(a); b["trails"][0]["m_factor_resize"] = {"binary64": "8000000000000000"}
        self.assertTrue(compare(a, b)["changed"])
        for value in (0.0, -0.0, 1.0, float("nan"), float("inf"), float("-inf")):
            b["trails"][0]["m_factor_resize"] = value
            with self.assertRaises(EvidenceError): validate(b)
        b = capture(); b["trails"][0]["m_points"][0][0] = True
        with self.assertRaises(EvidenceError): validate(b)

    def test_every_native_field_is_required(self):
        for field in NATIVE_FIELDS:
            with self.subTest(field=field):
                a = capture(); del a["trails"][0][field]
                with self.assertRaises(EvidenceError): compare(a, copy.deepcopy(a))

    def test_native_field_types(self):
        for field, value in (("m_userData", {}), ("m_render_flag", 1),
                             ("m_factor_resize", {"binary32": "3f800000"}),
                             ("m_after_shift_rect", [0, 0, 1]), ("geometry_info", []),
                             ("m_control_nums", {}), ("m_rotate_angle", True)):
            with self.subTest(field=field):
                a = capture(); a["trails"][0][field] = value
                with self.assertRaises(EvidenceError): validate(a)

    def test_lossy_decimal_json_is_rejected_before_rounding(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.json"
            a = capture(); a["trails"][0]["extra_float"] = "TOKEN"
            for literal in ("1.0000000000000001", "1e-400", "0.0", "-0.0", "NaN", "Infinity"):
                with self.subTest(literal=literal):
                    path.write_text(json.dumps(a).replace('"TOKEN"', literal))
                    with self.assertRaises(EvidenceError): read(path)

    def test_size_limit_bounds_the_read_itself(self):
        limit = 32 * 1024 * 1024
        with patch("ink_oracle.Path.open") as opened:
            stream = opened.return_value.__enter__.return_value
            stream.read.return_value = b"x" * (limit + 1)
            with self.assertRaises(EvidenceError): read("oversized-capture.json")
            opened.assert_called_once_with("rb")
            stream.read.assert_called_once_with(limit + 1)

    def test_json_duplicate_keys_and_truncated(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.json"
            for raw in ('{"schema":1,"schema":2}', '{"schema":'):
                path.write_text(raw)
                with self.assertRaises(EvidenceError): read(path)
            path.write_text(json.dumps(capture()))
            self.assertEqual(read(path), capture())

    def test_actual_collector_numeric_encoding(self):
        a = capture(); a["trails"][0]["m_factor_resize"] = {"binary64": "0000000000000000"}
        b = copy.deepcopy(a); b["trails"][0]["m_factor_resize"] = {"binary64": "8000000000000000"}
        self.assertTrue(compare(a, b)["changed"])
        for value in ({"binary32": "7fc00000"}, {"binary64": "7ff0000000000000"},
                      {"binary32": "00"}, {"binary64": "0000000000000000", "ignored": 1}):
            b["trails"][0]["m_factor_resize"] = value
            with self.assertRaises(EvidenceError): validate(b)
        for value in ([1], ["9223372036854775808"], ["-0"], ["00"]):
            b = capture(); b["trails"][0]["timestamp"] = value
            with self.assertRaises(EvidenceError): validate(b)
        b = capture(); b["trails"][0]["angles"] = [{"x": True, "y": 0}]
        with self.assertRaises(EvidenceError): validate(b)


if __name__ == "__main__": unittest.main()
