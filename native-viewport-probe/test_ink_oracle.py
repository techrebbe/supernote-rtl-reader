import copy
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import ink_oracle as oracle
from ink_oracle import (EvidenceError, compare, read, validate, NATIVE_FIELDS,
                        NATIVE_INTS, NATIVE_BOOLS, NATIVE_STRINGS, NATIVE_LISTS,
                        NATIVE_RECTS, NATIVE_OBJECTS)


EXPECTED_SOURCE = "a" * 64
GOLDEN_SHA256 = "20a179534dfce744b9be97e8e40c1ab07ef19e1c1ddb618ed38f58002e648158"


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
    return {"schema": oracle.EVIDENCE_SCHEMA, "sourceSha256": EXPECTED_SOURCE,
            "sourceSha256Authority": oracle.SOURCE_SHA256_AUTHORITY,
            "markSha256Before": "b"*64, "markSha256After": "b"*64,
            "nativePage": 1, "complete": True, "readMethod": "getFilePageTrails", "trails": [record()]}


def invoke_main(arguments):
    output = io.StringIO()
    with patch.object(sys, "argv", ["ink_oracle.py", *arguments]), \
            contextlib.redirect_stdout(output):
        code = oracle.main()
    return code, json.loads(output.getvalue())


class OracleTests(unittest.TestCase):
    def test_java_golden_contract_preserves_utf8_and_exact_fields(self):
        golden = capture()
        golden["trails"] = [oracle.java_golden_trail()]
        oracle.validate_java_golden(golden)
        payload = oracle.canonical_json(golden).encode("utf-8")
        self.assertEqual(hashlib.sha256(payload).hexdigest(), GOLDEN_SHA256)
        broken = copy.deepcopy(golden)
        broken["trails"][0]["m_userData"] = broken["trails"][0]["m_userData"].replace(
            "\U0001f600", "?")
        with self.assertRaisesRegex(EvidenceError, "m_userData"):
            oracle.validate_java_golden(broken)
        additions = {
            "m_points": [0, 0], "pressures": 0,
            "angles": {"x": 0, "y": 0}, "flag_draw": False,
            "timestamp": "0",
        }
        for field, expected in oracle.java_golden_trail().items():
            with self.subTest(field=field):
                broken = copy.deepcopy(golden)
                if field == "m_factor_resize":
                    replacement = {"binary64": "0000000000000000"}
                elif type(expected) is bool:
                    replacement = not expected
                elif type(expected) is int:
                    replacement = expected + 1
                elif type(expected) is str:
                    replacement = expected + "!"
                elif type(expected) is list:
                    replacement = expected + [additions.get(field)]
                elif type(expected) is dict:
                    replacement = {**expected, "goldenMutation": 1}
                else:
                    self.fail(f"unhandled golden mutation type for {field}")
                broken["trails"][0][field] = replacement
                with self.assertRaises(EvidenceError):
                    oracle.validate_java_golden(broken)

    def test_unchanged_and_reordered(self):
        a = capture(); a["trails"].append(record(2))
        b = copy.deepcopy(a); b["trails"].reverse()
        self.assertEqual(compare(a, b, EXPECTED_SOURCE),
                         {"added": [], "removed": [], "changed": {}, "unchanged": 2})

    def test_addition_preserves_prior(self):
        a = capture(); b = copy.deepcopy(a); b["trails"].append(record(2))
        self.assertEqual(compare(a, b, EXPECTED_SOURCE)["added"], [(1, 0, 2, 2)])
        b["trails"][0]["m_points"][0][0] += 1
        self.assertTrue(compare(a, b, EXPECTED_SOURCE)["changed"])

    def test_each_prior_failure_is_visible(self):
        changes = {"m_points": [[939, 313], [1078, 326]], "m_thickness": 225,
                   "pressures": [99, 200], "m_after_shift_rect": [0, 0, 9, 9],
                   "m_factor_resize": {"binary64": "3fe8000000000000"}, "flag_draw": [False, True],
                   "timestamp": ["1788700000001", "1788700000010"], "m_userData": "different"}
        for field, value in changes.items():
            with self.subTest(field=field):
                a = capture(); b = copy.deepcopy(a); b["trails"][0][field] = value
                self.assertEqual(list(compare(a, b, EXPECTED_SOURCE)["changed"].values()), [[field]])

    def test_disappeared_and_duplicate(self):
        a = capture(); b = copy.deepcopy(a); b["trails"] = []
        self.assertEqual(compare(a, b, EXPECTED_SOURCE)["removed"], [(1, 0, 1, 1)])
        a["trails"].append(record())
        with self.assertRaises(EvidenceError): validate(a)

    def test_wrong_authority_or_incomplete(self):
        for field, value in (("sourceSha256", "c"*64), ("nativePage", 2)):
            a = capture(); b = copy.deepcopy(a); b[field] = value
            with self.assertRaises(EvidenceError): compare(a, b, EXPECTED_SOURCE)
        with self.assertRaisesRegex(EvidenceError, "trusted outer verifier"):
            compare(capture(), capture(), None)
        with self.assertRaisesRegex(EvidenceError, "verifier authority"):
            compare(capture(), capture(), "c" * 64)
        for field, value in (("complete", False), ("complete", 1), ("nativePage", True),
                             ("markSha256After", "c"*64), ("readMethod", "getTrailContainer")):
            a = capture(); a[field] = value
            with self.assertRaises(EvidenceError): validate(a)

    def test_unknown_native_fields_fail_closed(self):
        a = capture(); b = copy.deepcopy(a); b["trails"][0]["new_native_field"] = 7
        with self.assertRaisesRegex(EvidenceError, "field inventory"):
            compare(a, b, EXPECTED_SOURCE)

    def test_signed_zero_and_types(self):
        a = capture(); a["trails"][0]["m_factor_resize"] = {"binary64": "0000000000000000"}
        b = copy.deepcopy(a); b["trails"][0]["m_factor_resize"] = {"binary64": "8000000000000000"}
        self.assertTrue(compare(a, b, EXPECTED_SOURCE)["changed"])
        for value in (0.0, -0.0, 1.0, float("nan"), float("inf"), float("-inf")):
            b["trails"][0]["m_factor_resize"] = value
            with self.assertRaises(EvidenceError): validate(b)
        b = capture(); b["trails"][0]["m_points"][0][0] = True
        with self.assertRaises(EvidenceError): validate(b)
        a=capture(); b=copy.deepcopy(a)
        a["trails"][0]["geometry_info"]={"value":True}
        b["trails"][0]["geometry_info"]={"value":1}
        self.assertTrue(compare(a, b, EXPECTED_SOURCE)["changed"])

    def test_reserved_numeric_wrapper_object_keys_are_unambiguous(self):
        # Evidence-v2 assigns singleton binary32/binary64 objects exclusively
        # to exact numeric values. The Java producer separately rejects an
        # ordinary reflected object with either field name.
        for tag, bits in (("binary32", "3f800000"),
                          ("binary64", "3ff0000000000000")):
            with self.subTest(tag=tag):
                a = capture()
                a["trails"][0]["geometry_info"] = {tag: bits}
                validate(a)
                a["trails"][0]["geometry_info"] = {tag: "ordinary-native-field"}
                with self.assertRaisesRegex(EvidenceError, "floating-point"):
                    validate(a)

    def test_every_native_field_is_required(self):
        for field in NATIVE_FIELDS:
            with self.subTest(field=field):
                a = capture(); del a["trails"][0][field]
                with self.assertRaises(EvidenceError):
                    compare(a, copy.deepcopy(a), EXPECTED_SOURCE)

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
            a = capture(); a["trails"][0]["m_rotate_angle"] = "TOKEN"
            for literal in ("1.0000000000000001", "1e-400", "0.0", "-0.0", "NaN", "Infinity"):
                with self.subTest(literal=literal):
                    path.write_text(oracle.canonical_json(a).replace('"TOKEN"', literal))
                    with self.assertRaises(EvidenceError): read(path, EXPECTED_SOURCE)

    def test_size_limit_bounds_the_read_itself(self):
        with patch.object(oracle.evidence_files,"read_bounded",
                          side_effect=oracle.evidence_files.InventoryError(
                              "evidence size budget/mismatch")) as opened:
            with self.assertRaises(EvidenceError): read("oversized-capture.json", EXPECTED_SOURCE)
            opened.assert_called_once_with(Path("oversized-capture.json"),
                                           oracle.MAX_CAPTURE_BYTES)

    def test_decode_limits_precede_container_materialization(self):
        envelope = capture()
        envelope["trails"] = []
        with patch.object(oracle,"MAX_VALUES",1):
            parsed=oracle._parse_bounded_json(json.dumps(envelope,separators=(",",":")))
            self.assertEqual(parsed["trails"],[])
            envelope["trails"]=[0]
            with self.assertRaisesRegex(EvidenceError,"decode node limit"):
                oracle._parse_bounded_json(json.dumps(envelope,separators=(",",":")))
        envelope=capture(); envelope["trails"]=[[[]]]
        with patch.object(oracle,"MAX_DEPTH",1), \
             self.assertRaisesRegex(EvidenceError,"decode depth"):
            oracle._parse_bounded_json(json.dumps(envelope,separators=(",",":")))

    def test_trail_decode_node_limit_is_exact_and_envelope_order_independent(self):
        base = capture()
        ordered_fields = list(base.items())
        without_trails = [(key, value) for key, value in ordered_fields
                          if key != "trails"]
        # Exercise first/middle/last positions; decode limits cannot depend on
        # pre-canonical input object order.
        for insertion in (0, 3, 4, len(without_trails)):
            with patch.object(oracle, "MAX_VALUES", 3):
                accepted = without_trails[:]
                accepted.insert(insertion, ("trails", [0, 1]))
                parsed = oracle._parse_bounded_json(json.dumps(
                    dict(accepted), separators=(",", ":")))
                self.assertEqual(parsed["trails"], [0, 1])

                rejected = without_trails[:]
                rejected.insert(insertion, ("trails", [0, 1, 2]))
                with self.assertRaisesRegex(EvidenceError,
                                             "trail decode node limit"):
                    oracle._parse_bounded_json(json.dumps(
                        dict(rejected), separators=(",", ":")))

    def test_collector_source_contract_and_oracle_share_structural_and_byte_limits(self):
        # This is deliberately a source-shape guard. SavedInkReader.collect()
        # requires Android plus the pinned firmware and is a separate Nomad gate.
        source=(Path(__file__).parent / "java/com/techrebbe/supernote/viewportprobe/SavedInkReader.java").read_text()
        for declaration in ("MAX_CAPTURE_BYTES = 32 * 1024 * 1024",
                            "MAX_DEPTH = 16", "MAX_VALUES = 2000000",
                            "MAX_STRING_BYTES = 65536", "MAX_LIST_ITEMS = 200000"):
            self.assertIn(declaration,source)
        self.assertIn("strictUtf8Bytes(payload, MAX_CAPTURE_BYTES)",source)
        self.assertIn("canonicalJson(result, MAX_CAPTURE_BYTES)", source)
        self.assertNotIn("org.json", source)
        for invariant in ("OsConstants.O_NOFOLLOW", "OsConstants.O_NONBLOCK",
                          "O_DIRECTORY = 0x4000", "Os.memfd_create", "F_ADD_SEALS", "F_GET_SEALS",
                          "REQUIRED_SEALS", "copyAndHash(source, sealed",
                          'INPUT_ROOT_PATH =\n        "/data/local/native-viewport-ink-reader-input"',
                          "SNAPSHOT_DIRECTORY_PERMISSIONS = 0550",
                          "SNAPSHOT_FILE_PERMISSIONS = 0440",
                          "admittedSnapshotBasename(copy.getName())",
                          "verifyInputDirectory(parent, parentIdentity)",
                          "verifyInputAuthority(parent, parentIdentity",
                          "class FirmwareAuthority", "MAX_FIRMWARE_FILE_BYTES",
                          "requireDefinedBy(constants, loader)",
                          "requireDefinedBy(type, loader)",
                          "identity.st_size, MAX_FIRMWARE_FILE_BYTES",
                          "opened.st_nlink", "opened.st_uid", "opened.st_gid",
                          "sourceSha256Authority", "external-assertion-v1",
                          "class CanonicalWriter", "class CloseStack",
                          "requireShellProcessIdentity(Os.getuid(), Os.getgid())",
                          "encodeNativeRecordList(", "publishEvidenceFrame(System.out",
                          "native object field collides with reserved numeric wrapper"):
            self.assertIn(invariant, source)
        collect_start = source.index("private static CanonicalObject collect")
        shell_gate = source.index("requireShellProcessIdentity(Os.getuid(), Os.getgid())",
                                  collect_start)
        argument_gate = source.index("if (args.length != 6", collect_start)
        first_file = source.index("new File(args[2])", collect_start)
        first_firmware = source.index("FirmwareAuthority.open()", collect_start)
        first_native_loader = source.index("new DexClassLoader", collect_start)
        self.assertLess(shell_gate, argument_gate)
        self.assertLess(shell_gate, first_file)
        self.assertLess(shell_gate, first_firmware)
        self.assertLess(shell_gate, first_native_loader)
        self.assertLess(source.index("copyAndHash(source, sealed"),
                        source.index("fetchPagesOfMark"))
        collect_source = source[collect_start:source.index(
            "static CanonicalObject evidenceEnvelope", collect_start)]
        self.assertNotIn("descriptorPath", collect_source)
        self.assertIn('.invoke(note, path);', collect_source)
        self.assertIn('.invoke(note, path, page);', collect_source)
        self.assertGreaterEqual(collect_source.count(
            "verifyInputAuthority(parent, parentIdentity"), 3)
        first_authority = collect_source.index(
            "verifyInputAuthority(parent, parentIdentity")
        inventory = collect_source.index("fetchPagesOfMark")
        between_authority = collect_source.index(
            "verifyInputAuthority(parent, parentIdentity", first_authority + 1)
        trails = collect_source.index("getFilePageTrails")
        final_authority = collect_source.index(
            "verifyInputAuthority(parent, parentIdentity", between_authority + 1)
        self.assertLess(first_authority, inventory)
        self.assertLess(inventory, between_authority)
        self.assertLess(between_authority, trails)
        self.assertLess(trails, final_authority)
        free_common = collect_source.index('getMethod("freeCommon")')
        self.assertLess(trails, free_common)
        self.assertLess(free_common, final_authority)
        self.assertIn("FileDescriptor finalNamed = Os.open(path", collect_source)
        self.assertIn("StructStat finalNameStat = Os.lstat(path)", collect_source)
        self.assertIn("StructStat finalAnchoredStat = Os.lstat(anchoredPath)",
                      collect_source)
        self.assertIn('DocumentConstants\", false, loader', source)
        self.assertIn('SuperNoteNote\", false, loader', source)
        self.assertNotIn('Class.forName("com.example.libsupernote.SuperNoteNote", true', source)
        self.assertLess(source.index("firmware.verify();"),
                        source.index("new DexClassLoader"))
        self.assertLess(source.index("result.verify();"), source.index("cleanup.disarm();"))
        self.assertLess(source.index("disposable mark must be a direct child"),
                        source.index("FirmwareAuthority firmware = FirmwareAuthority.open();"))
        self.assertLess(source.index("requireDefinedBy(constants, loader)"),
                        source.index('getMethod("getDeviceType")'))
        self.assertLess(source.index("requireDefinedBy(type, loader)"),
                        source.index('getMethod("createSuperNoteNote")'))
        self.assertIn("new EncodingBudget()", source)
        self.assertNotIn("private static int values;", source)
        self.assertNotIn("private static long encodedBytes;", source)
        self.assertNotIn("GoldenTrailRecord", source)
        harness=(Path(__file__).parent /
                 "test/java/com/techrebbe/supernote/viewportprobe/SavedInkBudgetTest.java").read_text()
        self.assertIn("SavedInkReader.encodeTree", harness)
        self.assertIn("StandardOpenOption.CREATE_NEW", harness)
        self.assertNotIn("System.out.println(result.toString())", harness)
        self.assertNotIn('payload + "\\n"', harness)
        golden_source=(Path(__file__).parent /
                       "java/com/example/libsupernote/GoldenTrailRecord.java").read_text()
        for field in NATIVE_FIELDS:
            self.assertIn(field, golden_source)
        self.assertIn("class Binary32CollisionObject", golden_source)
        self.assertIn("class Binary64CollisionObject", golden_source)

        too_deep=capture(); nested={}; too_deep["trails"][0]["geometry_info"]=nested
        for _ in range(oracle.MAX_DEPTH+1): nested=nested.setdefault("x",{})
        with self.assertRaises(EvidenceError): validate(too_deep)
        too_long=capture(); too_long["trails"][0]["m_custom_string"]="xxx"
        with patch.object(oracle,"MAX_STRING_BYTES",2),self.assertRaises(EvidenceError):
            validate(too_long)
        too_many=capture(); too_many["trails"][0]["m_hierarchy"]=[0,1,2]
        with patch.object(oracle,"MAX_LIST_ITEMS",2),self.assertRaises(EvidenceError):
            validate(too_many)
        too_many_nodes=capture(); too_many_nodes["trails"][0]["m_hierarchy"]=[0,1,2]
        with patch.object(oracle,"MAX_VALUES",3),self.assertRaises(EvidenceError):
            validate(too_many_nodes)

        with patch.object(oracle,"MAX_CAPTURE_BYTES",64),self.assertRaises(EvidenceError):
            validate(capture())

        exact=capture(); value=None
        for _ in range(14): value={"x":value}
        exact["trails"][0]["geometry_info"]=value
        validate(exact)
        exact["trails"][0]["geometry_info"]={"x":value}
        with self.assertRaises(EvidenceError): validate(exact)

        nodes=oracle._validate_encoded_tree(capture()["trails"])[0]
        with patch.object(oracle,"MAX_VALUES",nodes): validate(capture())
        with patch.object(oracle,"MAX_VALUES",nodes-1),self.assertRaises(EvidenceError):
            validate(capture())

    def test_structural_budget_is_fresh_for_every_validation_root(self):
        trails = capture()["trails"]
        expected = oracle._validate_encoded_tree(trails)
        poisoned = oracle._EncodingBudget()
        poisoned.values = oracle.MAX_VALUES
        poisoned.encoded_bytes = oracle.MAX_CAPTURE_BYTES
        self.assertEqual(oracle._validate_encoded_tree(trails), expected)
        nodes = expected[0]
        with patch.object(oracle, "MAX_VALUES", nodes - 1):
            with self.assertRaises(EvidenceError):
                oracle._validate_encoded_tree(trails)
        self.assertEqual(oracle._validate_encoded_tree(trails), expected)

    def test_only_exact_java_producer_json_types_are_admitted(self):
        for value in ((1, 2), b"bytes", bytearray(b"bytes"), {1, 2}, 2**100, -(2**100)):
            with self.subTest(value=type(value).__name__):
                evidence=capture(); evidence["trails"][0]["geometry_info"] = value
                with self.assertRaises(EvidenceError): validate(evidence)
        evidence = capture(); evidence["trails"][0]["extra"] = 1
        with self.assertRaisesRegex(EvidenceError, "field inventory"):
            validate(evidence)

    def test_frozen_canonical_wire_vectors(self):
        vectors = (
            ("/", '"/"'), ("</", '"</"'), ('"', '"\\\""'),
            ("\\", '"\\\\"'), ("\b\t\n\f\r", '"\\b\\t\\n\\f\\r"'),
            ("\u0000\u000b\u001f", '"\\u0000\\u000b\\u001f"'),
            ("\u007f\u0085", '"\u007f\u0085"'),
            ("\u2028\u2029", '"\u2028\u2029"'),
            ("\u05e9\u05dc\u05d5\u05dd e\u0301 \U0001f600",
             '"\u05e9\u05dc\u05d5\u05dd e\u0301 \U0001f600"'),
        )
        for value, expected in vectors:
            with self.subTest(value=repr(value)):
                self.assertEqual(oracle.canonical_json(value), expected)
                self.assertEqual(oracle._canonical_string_bytes(value),
                                 len(expected.encode("utf-8")))
        for invalid in ("\ud800", "\udc00"):
            with self.assertRaises(EvidenceError):
                oracle.canonical_json(invalid)

        first = {"\ue000": 3, "z": 1, "\U0001f600": 2}
        second = {"\U0001f600": 2, "\ue000": 3, "z": 1}
        expected = '{"z":1,"\U0001f600":2,"\ue000":3}'
        self.assertEqual(oracle.canonical_json(first), expected)
        self.assertEqual(oracle.canonical_json(second), expected)
        self.assertEqual(oracle.canonical_json([2, 1]), "[2,1]")

    def test_canonical_wire_exact_capture_cap(self):
        exactly_at_cap = "x" * (oracle.MAX_CAPTURE_BYTES - 2)
        self.assertEqual(oracle._canonical_json_bytes(exactly_at_cap),
                         oracle.MAX_CAPTURE_BYTES)
        with self.assertRaises(EvidenceError):
            oracle._canonical_json_bytes(exactly_at_cap,
                                         oracle.MAX_CAPTURE_BYTES - 1)

    def test_read_requires_outer_source_authority_and_exact_wire(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.json"
            exact = oracle.canonical_json(capture())
            path.write_text(exact, encoding="utf-8")
            self.assertEqual(read(path, EXPECTED_SOURCE), capture())
            for asserted in (None, "c" * 64, "not-a-sha"):
                with self.subTest(asserted=asserted), self.assertRaises(EvidenceError):
                    read(path, asserted)

            reordered = json.dumps(capture(), ensure_ascii=False, separators=(",", ":"))
            mutations = [" " + exact, exact + "\n", reordered]
            slash_capture = capture(); slash_capture["trails"][0]["m_userData"] = "/"
            slash_wire = oracle.canonical_json(slash_capture)
            mutations.append(slash_wire.replace(':"/"', ':"\\/"'))
            unicode_capture = capture()
            unicode_capture["trails"][0]["m_userData"] = "\u2028\U0001f600"
            unicode_wire = oracle.canonical_json(unicode_capture)
            mutations.append(unicode_wire.replace("\u2028", "\\u2028"))
            mutations.append(unicode_wire.replace("\U0001f600", "\\ud83d\\ude00"))
            mutations.append(exact.replace("native-viewport", "\\u006eative-viewport", 1))
            for mutated in mutations:
                with self.subTest(prefix=repr(mutated[:30])):
                    path.write_text(mutated, encoding="utf-8")
                    with self.assertRaisesRegex(EvidenceError, "canonical"):
                        read(path, EXPECTED_SOURCE)

    def test_collector_stdout_frame_is_single_complete_and_bounded(self):
        payload = oracle.canonical_json(capture()).encode("utf-8")
        frame = oracle.COLLECTOR_FRAME_PREFIX + payload + b"\n"
        self.assertEqual(oracle.parse_collector_frame(frame, EXPECTED_SOURCE),
                         capture())
        mutations = (
            payload,
            frame[:-1],
            frame[:-2] + b"\n",
            b"x" + frame,
            b"native_viewport_ink_evidence " + payload + b"\n",
            oracle.COLLECTOR_FRAME_PREFIX + b" " + payload + b"\n",
            oracle.COLLECTOR_FRAME_PREFIX[:-1] + payload + b"\n",
            frame[:-1] + b"\r\n",
            frame[:-1] + b"\r",
            frame + frame,
            frame + b"trailing",
            b"\xef\xbb\xbf" + frame,
            oracle.COLLECTOR_FRAME_PREFIX + b"\xef\xbb\xbf" + payload + b"\n",
            oracle.COLLECTOR_FRAME_PREFIX + payload[:-2] + b"\xff}\n",
            (oracle.COLLECTOR_FRAME_PREFIX + b'{"complete":true,' +
             payload[1:] + b"\n"),
            oracle.COLLECTOR_FRAME_PREFIX + b"{ " + payload[1:] + b"\n",
            oracle.COLLECTOR_FRAME_PREFIX + b"\n",
        )
        for mutated in mutations:
            with self.subTest(prefix=repr(mutated[:40])), \
                    self.assertRaises(EvidenceError):
                oracle.parse_collector_frame(mutated, EXPECTED_SOURCE)
        with patch.object(oracle, "MAX_COLLECTOR_FRAME_BYTES", len(frame) - 1), \
                self.assertRaisesRegex(EvidenceError, "size limit"):
            oracle.parse_collector_frame(frame, EXPECTED_SOURCE)

    def test_collector_stdout_file_reader_uses_framed_bound(self):
        with patch.object(oracle.evidence_files, "read_bounded",
                          return_value=(oracle.COLLECTOR_FRAME_PREFIX
                                        + oracle.canonical_json(capture()).encode("utf-8")
                                        + b"\n")) as opened:
            self.assertEqual(oracle.read_collector_frame("collector.log", EXPECTED_SOURCE),
                             capture())
            opened.assert_called_once_with(Path("collector.log"),
                                           oracle.MAX_COLLECTOR_FRAME_BYTES)

        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            payload = oracle.canonical_json(capture()).encode("utf-8")
            raw_before = parent / "before.json"
            raw_after = parent / "after.json"
            framed_before = parent / "before.frame"
            framed_after = parent / "after.frame"
            raw_before.write_bytes(payload)
            raw_after.write_bytes(payload)
            frame = oracle.COLLECTOR_FRAME_PREFIX + payload + b"\n"
            framed_before.write_bytes(frame)
            framed_after.write_bytes(frame)
            common = ["--expect", "unchanged", "--expected-source-sha256",
                      EXPECTED_SOURCE]

            raw_code, raw_result = invoke_main(
                [str(raw_before), str(raw_after), *common])
            self.assertEqual((raw_code, raw_result["status"]), (0, "PASS"))
            framed_code, framed_result = invoke_main([
                "--framed-before", str(framed_before),
                "--framed-after", str(framed_after), *common])
            self.assertEqual(
                (framed_code, framed_result["status"]), (0, "PASS"))

            invalid_modes = (
                [],
                [str(raw_before)],
                ["--framed-before", str(framed_before)],
                [str(raw_before), str(raw_after),
                 "--framed-before", str(framed_before),
                 "--framed-after", str(framed_after)],
                [str(raw_before), "--framed-after", str(framed_after)],
                [str(raw_before), str(raw_after),
                 "--framed-before", str(framed_before)],
            )
            for mode in invalid_modes:
                with self.subTest(mode=mode):
                    code, result = invoke_main([*mode, *common])
                    self.assertEqual((code, result["status"]),
                                     (2, "INVALID_EVIDENCE"))
                    self.assertIn("exactly one complete", result["reason"])

            mismatch_code, mismatch = invoke_main([
                "--framed-before", str(framed_before),
                "--framed-after", str(framed_after), "--expect", "unchanged",
                "--expected-source-sha256", "c" * 64])
            self.assertEqual((mismatch_code, mismatch["status"]),
                             (2, "INVALID_EVIDENCE"))
            self.assertIn("does not match", mismatch["reason"])

    def test_pinned_native_list_grammars_and_declared_opaque_fields(self):
        self.assertEqual(oracle.OPAQUE_NATIVE_LISTS, {"m_hierarchy"})
        self.assertEqual(oracle.OPAQUE_NATIVE_OBJECTS, {"geometry_info", "rrd"})
        evidence = capture()
        trail = evidence["trails"][0]
        trail["disable_area_list"] = [{
            "coorOrigin": -2147483648, "flag": 2147483647,
            "height": -3, "width": 4, "x": -5, "y": 6,
        }]
        trail["m_contours_src"] = [[
            [{"binary32": "80000000"}, {"binary32": "00000000"}],
            [{"binary32": "00000001"}, {"binary32": "ff7fffff"}],
        ]]
        trail["m_control_nums"] = [-2147483648, 2147483647]
        trail["m_mark_pen_d_fill_dir"] = [
            [{"binary32": "80000000"}, {"binary32": "3fc00000"}],
        ]
        trail["recogn_points"] = [{
            "Flag": -2147483648, "X": 2147483647, "Y": -7,
            "timestamp": "-9223372036854775808",
        }, {
            "Flag": 8, "X": -9, "Y": 10,
            "timestamp": "9223372036854775807",
        }]
        validate(evidence)

        invalid = (
            ("disable_area_list", [[1, 2, 3, 4]]),
            ("disable_area_list", [{"coorOrigin": 0, "flag": 0,
                                    "height": 0, "width": 0, "x": 0}]),
            ("disable_area_list", [{"coorOrigin": 0, "flag": 0,
                                    "height": 0, "width": 0, "x": 0,
                                    "y": True}]),
            ("erase_line_trail_num", [True]),
            ("m_contours_src", [[{"binary32": "3f800000"},
                                   {"binary32": "40000000"}]]),
            ("m_contours_src", [[[{"binary32": "3f800000"},
                                    {"binary64": "4000000000000000"}]]]),
            ("m_contours_src", [[[{"binary32": "7f800000"},
                                    {"binary32": "00000000"}]]]),
            ("m_control_nums", [2147483648]),
            ("m_control_nums", [True]),
            ("m_mark_pen_d_fill_dir", [False]),
            ("m_mark_pen_d_fill_dir", [[{"binary32": "80000000"},
                                         {"binary32": "00000000",
                                          "extra": 0}]]),
            ("recogn_points", [[211, 212]]),
            ("recogn_points", [{"flag": 1, "X": 2, "Y": 3,
                                "timestamp": "4"}]),
            ("recogn_points", [{"Flag": 1, "X": 2, "Y": 3,
                                "timestamp": 4}]),
            ("recogn_points", [{"Flag": 1, "X": 2, "Y": 3,
                                "timestamp": "-0"}]),
        )
        for field, value in invalid:
            with self.subTest(field=field):
                evidence = capture(); evidence["trails"][0][field] = value
                with self.assertRaises(EvidenceError):
                    validate(evidence)

    def test_nested_pointf_signed_zero_and_recogn_timestamp_are_observable(self):
        negative = capture()
        negative["trails"][0]["m_mark_pen_d_fill_dir"] = [[
            {"binary32": "80000000"}, {"binary32": "00000000"}]]
        positive = copy.deepcopy(negative)
        positive["trails"][0]["m_mark_pen_d_fill_dir"][0][0]["binary32"] = "00000000"
        self.assertEqual(
            list(compare(negative, positive, EXPECTED_SOURCE)["changed"].values()),
            [["m_mark_pen_d_fill_dir"]])

        for timestamp in ("-9223372036854775809", "9223372036854775808", "00"):
            with self.subTest(timestamp=timestamp):
                evidence = capture()
                evidence["trails"][0]["recogn_points"] = [{
                    "Flag": 1, "X": 2, "Y": 3, "timestamp": timestamp}]
                with self.assertRaises(EvidenceError):
                    validate(evidence)

    def test_each_pinned_nested_record_field_fails_closed(self):
        flag_rect = {"coorOrigin": 1, "flag": 2, "height": 3,
                     "width": 4, "x": 5, "y": 6}
        for field in flag_rect:
            with self.subTest(record="JniFlagRect", field=field):
                evidence = capture()
                mutated = dict(flag_rect)
                del mutated[field]
                evidence["trails"][0]["disable_area_list"] = [mutated]
                with self.assertRaises(EvidenceError):
                    validate(evidence)
        for value in (True, 2147483648, -2147483649):
            with self.subTest(record="JniFlagRect", mutation=value):
                evidence = capture()
                mutated = dict(flag_rect)
                mutated["x"] = value
                evidence["trails"][0]["disable_area_list"] = [mutated]
                with self.assertRaises(EvidenceError):
                    validate(evidence)
        evidence = capture()
        evidence["trails"][0]["disable_area_list"] = [
            {**flag_rect, "right": 7}]
        with self.assertRaises(EvidenceError):
            validate(evidence)

        recogn = {"Flag": 1, "X": 2, "Y": 3, "timestamp": "4"}
        for field in recogn:
            with self.subTest(record="JniRecognData", field=field):
                evidence = capture()
                mutated = dict(recogn)
                del mutated[field]
                evidence["trails"][0]["recogn_points"] = [mutated]
                with self.assertRaises(EvidenceError):
                    validate(evidence)
        for field in ("Flag", "X", "Y"):
            for value in (True, 2147483648, -2147483649):
                with self.subTest(record="JniRecognData", field=field,
                                  mutation=value):
                    evidence = capture()
                    mutated = dict(recogn)
                    mutated[field] = value
                    evidence["trails"][0]["recogn_points"] = [mutated]
                    with self.assertRaises(EvidenceError):
                        validate(evidence)
        evidence = capture()
        evidence["trails"][0]["recogn_points"] = [
            {**recogn, "flag": recogn["Flag"]}]
        with self.assertRaises(EvidenceError):
            validate(evidence)

    def test_capture_wire_is_strict_utf8_not_json_autodetected_utf16(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"capture.json"
            path.write_bytes(json.dumps(capture()).encode("utf-16"))
            with self.assertRaises(EvidenceError): read(path, EXPECTED_SOURCE)

    def test_json_duplicate_keys_and_truncated(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.json"
            for raw in ('{"schema":1,"schema":2}',
                        '{"schema":1,"\\u0073chema":2}', '{"schema":'):
                path.write_text(raw)
                with self.assertRaises(EvidenceError): read(path, EXPECTED_SOURCE)
            path.write_text(oracle.canonical_json(capture()))
            self.assertEqual(read(path, EXPECTED_SOURCE), capture())

    def test_json_numbers_reject_every_non_ascii_digit_position(self):
        # JSON's number grammar is ASCII-only.  ``str.isdigit`` admits many
        # Unicode Nd characters, so exercise the first digit, continuation
        # digit, negative continuation, and leading-zero boundaries.
        non_ascii_digits = (
            "\u0661", "\u06f1", "\u0967", "\uff11", "\U0001d7d9")
        for digit in non_ascii_digits:
            for encoded in (digit, "1" + digit, "-1" + digit,
                            "0" + digit, "[1," + digit + "]",
                            '{"value":1' + digit + "}"):
                with self.subTest(digit=digit, encoded=encoded), \
                     self.assertRaises(EvidenceError):
                    oracle._parse_bounded_json(encoded)

    def test_streaming_decoder_rejects_depth_and_decoded_string_before_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"capture.json"
            path.write_text("["*1000 + "]"*1000)
            with self.assertRaises(EvidenceError): read(path, EXPECTED_SOURCE)
            with patch.object(oracle,"MAX_STRING_BYTES",4):
                path.write_text('"\\u0061\\u0062\\u0063\\u0064\\u0065"')
                with self.assertRaises(EvidenceError): read(path, EXPECTED_SOURCE)
                self.assertEqual(oracle._parse_bounded_json('"\u05e9\u05e9"'), "\u05e9\u05e9")
                self.assertEqual(oracle._parse_bounded_json('"\U0001f600"'), "\U0001f600")
                with self.assertRaises(EvidenceError):
                    oracle._parse_bounded_json('"\u05e9\u05e9\u05e9"')
                with self.assertRaises(EvidenceError):
                    oracle._parse_bounded_json('"\U0001f600\U0001f600"')
            path.write_text('{"x":true,"x":1}')
            with self.assertRaises(EvidenceError): read(path, EXPECTED_SOURCE)

    def test_actual_collector_numeric_encoding(self):
        a = capture(); a["trails"][0]["m_factor_resize"] = {"binary64": "0000000000000000"}
        b = copy.deepcopy(a); b["trails"][0]["m_factor_resize"] = {"binary64": "8000000000000000"}
        self.assertTrue(compare(a, b, EXPECTED_SOURCE)["changed"])
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
