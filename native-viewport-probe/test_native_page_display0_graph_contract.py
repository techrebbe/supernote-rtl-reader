"""Adversarial host parser coverage for the raw graph calibration record."""
from __future__ import annotations

import copy
import json
import unittest

import native_page_display0_graph_contract as contract
import native_page_graph_v2_runner as canonical


DIGEST = "a" * 64
ZERO = "0x0000000000000000"
ONE = "0x3ff0000000000000"
EMPTY_BITMAP = {"present": False, "dimensions": None}
EMPTY_VIEW = {"present": False, "bounds": None,
              "windowAttachCount": None, "attached": None}


def success() -> dict:
    return {
        "event": "native_page_display0_graph", "schemaVersion": 1,
        "authority": contract.RECORD_AUTHORITY, "manifestSha256": DIGEST,
        "observationOnly": True, "hardwareAdmission": False,
        "semanticCalibration": False, "hostAssertionsOnly": True,
        "runtimePidMatched": True, "heapWalks": 1,
        "retainedRootSamples": 2, "graphStable": True,
        "lifecycle": {"resumed": True, "finished": False,
                      "destroyed": False},
        "uriAgreementAndExpectedMatch": True,
        "markPathPresent": False, "markPathMatchedExpected": None,
        "rawPageTuple": [0, 2, 0, 0],
        "pageInfo": {
            "ctm": [ONE, ZERO, ZERO, ONE, ZERO, ZERO],
            "revertCtm": [ONE, ZERO, ZERO, ONE, ZERO, ZERO],
            "offset": [0, 0], "scale": ONE, "trimmingRect": None,
            "bitmaps": {"origin": copy.deepcopy(EMPTY_BITMAP),
                        "display": {"present": True, "dimensions": [1404, 1872]},
                        "digest": copy.deepcopy(EMPTY_BITMAP)},
        },
        "presenter": {"rawRotationCode": 0,
                      "bitmap": copy.deepcopy(EMPTY_BITMAP)},
        "views": {name: copy.deepcopy(EMPTY_VIEW)
                  for name in contract.VIEW_NAMES},
    }


def frames(value: dict) -> tuple[bytes, bytes]:
    return (canonical.canonical_bytes(value, contract.MAX_FRAME_BYTES),
            canonical.canonical_bytes(
                {"event": "native_page_display0_graph_complete",
                 "success": True}, contract.MAX_FRAME_BYTES))


class GraphContractTests(unittest.TestCase):
    def test_valid_raw_calibration_is_not_admission(self) -> None:
        value = contract.parse_graph_frames(frames(success()), DIGEST,
                                            mark_required=False)
        self.assertIs(value["semanticCalibration"], False)
        self.assertIs(value["hardwareAdmission"], False)

    def test_mark_required_path_is_not_serialized(self) -> None:
        value = success()
        value["markPathPresent"] = True
        value["markPathMatchedExpected"] = True
        parsed = contract.parse_graph_frames(frames(value), DIGEST,
                                             mark_required=True)
        self.assertNotIn(".pdf.mark", json.dumps(parsed))

    def test_absent_mark_file_may_still_have_presenter_path(self) -> None:
        value = success()
        value["markPathPresent"] = True
        parsed = contract.parse_graph_frames(frames(value), DIGEST,
                                             mark_required=False)
        self.assertIs(parsed["markPathPresent"], True)
        self.assertIsNone(parsed["markPathMatchedExpected"])

    def test_mark_path_presence_never_substitutes_for_expected_match(self) -> None:
        for mark_required, present, matched in (
            (False, False, True), (False, True, True),
            (False, False, False), (False, True, False),
            (True, False, True), (True, True, None),
        ):
            with self.subTest(mark_required=mark_required,
                              present=present, matched=matched):
                value = success()
                value["markPathPresent"] = present
                value["markPathMatchedExpected"] = matched
                with self.assertRaises(contract.GraphContractError):
                    contract.parse_graph_frames(frames(value), DIGEST,
                                                mark_required=mark_required)

    def test_required_top_level_flags_are_exact(self) -> None:
        for key, changed in (("hardwareAdmission", True),
                             ("semanticCalibration", True),
                             ("graphStable", False),
                             ("runtimePidMatched", False),
                             ("retainedRootSamples", 1),
                             ("heapWalks", 2),
                             ("observationOnly", False)):
            with self.subTest(key=key):
                value = success()
                value[key] = changed
                with self.assertRaises(contract.GraphContractError):
                    contract.parse_graph_frames(frames(value), DIGEST,
                                                mark_required=False)

    def test_unknown_and_missing_fields_reject(self) -> None:
        value = success()
        value["surprise"] = 1
        with self.assertRaises(contract.GraphContractError):
            contract.parse_graph_frames(frames(value), DIGEST,
                                        mark_required=False)
        value = success()
        del value["views"]
        with self.assertRaises(contract.GraphContractError):
            contract.parse_graph_frames(frames(value), DIGEST,
                                        mark_required=False)

    def test_malformed_binary64_and_nonfinite_reject(self) -> None:
        for invalid in ("0x7ff8000000000000", "0x7ff0000000000000",
                        "0x3FF0000000000000", "0xzz00000000000000",
                        "0x7fefffffffffffff"):
            with self.subTest(invalid=invalid):
                value = success()
                value["pageInfo"]["scale"] = invalid
                with self.assertRaises(contract.GraphContractError):
                    contract.parse_graph_frames(frames(value), DIGEST,
                                                mark_required=False)

    def test_bitmap_and_view_nullable_shape(self) -> None:
        for mutate in (
            lambda v: v["pageInfo"]["bitmaps"]["origin"].update(dimensions=[1, 1]),
            lambda v: v["pageInfo"]["bitmaps"]["display"].update(dimensions=None),
            lambda v: v["views"]["handWriteView"].update(attached=False),
            lambda v: v["views"]["documentLayout"].update(
                present=True, bounds=[0, 0, 0, 0]),
        ):
            value = success()
            mutate(value)
            with self.assertRaises(contract.GraphContractError):
                contract.parse_graph_frames(frames(value), DIGEST,
                                            mark_required=False)

    def test_noncanonical_and_extra_terminal_reject(self) -> None:
        first, terminal = frames(success())
        with self.assertRaises(contract.GraphContractError):
            contract.parse_graph_frames((first + b" ", terminal), DIGEST,
                                        mark_required=False)
        with self.assertRaises(contract.GraphContractError):
            contract.parse_graph_frames((first, terminal, terminal), DIGEST,
                                        mark_required=False)  # type: ignore[arg-type]

    def test_error_frames_only_accept_fixed_diagnostic(self) -> None:
        error = {"event": "native_page_display0_graph_error",
                 "schemaVersion": 1, "code": "DISPLAY0_GRAPH_REJECTED",
                 "phase": "URI", "reason": "WRAPPER"}
        complete = {"event": "native_page_display0_graph_complete",
                    "success": False}
        raw = tuple(canonical.canonical_bytes(item, contract.MAX_FRAME_BYTES)
                    for item in (error, complete))
        self.assertEqual(contract.parse_graph_error_frames(raw),
                         ("URI", "WRAPPER"))
        error["reason"] = "private path here"
        bad = (canonical.canonical_bytes(error, contract.MAX_FRAME_BYTES), raw[1])
        with self.assertRaises(contract.GraphContractError):
            contract.parse_graph_error_frames(bad)


if __name__ == "__main__":
    unittest.main()
