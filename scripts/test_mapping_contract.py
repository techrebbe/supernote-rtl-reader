#!/usr/bin/env python3
"""Deterministic tests for the InkBridge/Virtual Spread wire boundary."""

from __future__ import annotations

import copy
import json
import math
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from virtual_spread.mapping_contract import (  # noqa: E402
    MappingContractError,
    canonical_mapping_bytes,
    canonical_mapping_record,
    canonical_view_bytes,
    document_id,
    mapping_authority_sha256,
    normalized_to_spread,
    output_basename,
    spread_to_normalized,
    view_id,
)


FIXTURE = (
    ROOT / "virtual_spread" / "fixtures" / "page-143-contract-v1.json"
)


class MappingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def identity(self) -> dict[str, object]:
        fixture = self.fixture
        return {
            "source_sha256": fixture["sourceSha256"],
            "mapping_authority_sha256": fixture["mappingAuthoritySha256"],
            "direction": fixture["direction"],
            "cover_separate": fixture["coverSeparate"],
            "spread_width": fixture["spreadSize"][0],
            "spread_height": fixture["spreadSize"][1],
            "gutter": fixture["gutter"],
            "manifest_schema": fixture["manifestSchema"],
            "generator_version": fixture["generatorVersion"],
        }

    def test_page_143_golden_bytes_and_identities(self) -> None:
        fixture = self.fixture
        self.assertEqual(
            canonical_mapping_bytes(fixture["mappings"]).decode("ascii"),
            fixture["canonicalMapping"],
        )
        self.assertEqual(
            mapping_authority_sha256(fixture["mappings"]),
            fixture["mappingAuthoritySha256"],
        )
        identity = self.identity()
        self.assertEqual(
            canonical_view_bytes(**identity).decode("ascii"),
            fixture["canonicalView"],
        )
        self.assertEqual(
            document_id(fixture["sourceSha256"]), fixture["documentId"]
        )
        self.assertEqual(view_id(**identity), fixture["viewId"])
        self.assertEqual(
            output_basename(**identity),
            fixture["outputBasename"],
        )

    def test_page_143_point_and_stroke_round_trips(self) -> None:
        fixture = self.fixture
        mapping = fixture["mappings"][fixture["page143MappingIndex"]]
        tolerance = fixture["tolerance"]
        vectors = list(fixture["pointRoundTrips"])
        stroke = fixture["strokeRoundTrip"]
        vectors.extend({
            "normalized": normalized,
            "spread": spread,
            "normalizedAfterInverse": restored,
        } for normalized, spread, restored in zip(
            stroke["normalized"],
            stroke["spread"],
            stroke["normalizedAfterInverse"],
        ))
        for vector in vectors:
            with self.subTest(point=vector["normalized"]):
                spread = normalized_to_spread(mapping, *vector["normalized"])
                restored = spread_to_normalized(mapping, *spread)
                for actual, expected in zip(spread, vector["spread"]):
                    self.assertAlmostEqual(actual, expected, delta=tolerance)
                for actual, expected in zip(
                    restored, vector["normalizedAfterInverse"]
                ):
                    self.assertAlmostEqual(actual, expected, delta=tolerance)

    def test_every_authenticated_mapping_field_changes_or_rejects(self) -> None:
        fixture = self.fixture
        original = fixture["mappings"]
        original_digest = mapping_authority_sha256(original)
        cases: dict[str, object] = {
            "sourcePageIndex": 3,
            "virtualPageIndex": 2,
            "side": "right",
            "sourceRotation": 180,
            "sourceBox": [19.0, 36.0, 594.0, 756.0],
            "normalizedSourceBox": [37.0, 18.0, 756.0, 594.0],
            "slot": [1.0, 0.0, 432.0, 648.0],
            "destination": [1.0, 151.2, 432.0, 496.8],
            "scale": 0.5,
            "transform": [0.0, -0.6, 0.6, 0.0, -21.6, 507.6],
        }
        for field, replacement in cases.items():
            with self.subTest(field=field):
                mutated = copy.deepcopy(original)
                mutated[2][field] = replacement
                try:
                    digest = mapping_authority_sha256(mutated)
                except MappingContractError:
                    continue
                self.assertNotEqual(digest, original_digest)

    def test_mapping_records_reject_ambiguous_types_and_fields(self) -> None:
        mapping = copy.deepcopy(self.fixture["mappings"][0])
        invalid_cases = (
            ("sourcePageIndex", True),
            ("virtualPageIndex", 0.0),
            ("sourceRotation", 45),
            ("scale", float("nan")),
            ("sourceBox", [0.0, 1.0]),
            ("side", "LEFT"),
        )
        for field, value in invalid_cases:
            with self.subTest(field=field, value=value):
                mutated = copy.deepcopy(mapping)
                mutated[field] = value
                with self.assertRaises(MappingContractError):
                    canonical_mapping_record(mutated)
        mapping["untrustedInverse"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
        with self.assertRaises(MappingContractError):
            canonical_mapping_record(mapping)

    def test_mapping_sequence_must_be_complete_and_ordered(self) -> None:
        mappings = self.fixture["mappings"]
        for invalid in (
            list(reversed(mappings)),
            mappings[1:],
            [mappings[0], mappings[0], mappings[2]],
            [],
        ):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(MappingContractError):
                    canonical_mapping_bytes(invalid)

    def test_each_view_input_changes_or_rejects_identity(self) -> None:
        identity = self.identity()
        original = view_id(**identity)
        cases: dict[str, object] = {
            "source_sha256": "f" * 64,
            "mapping_authority_sha256": "e" * 64,
            "direction": "ltr",
            "cover_separate": False,
            "spread_width": 865.0,
            "spread_height": 649.0,
            "gutter": 1.0,
            "manifest_schema": "techrebbe.supernote.virtual-spread/v4",
            "generator_version": (
                "techrebbe.supernote.virtual-spread-generator/v2"
            ),
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                mutated = dict(identity)
                mutated[field] = value
                try:
                    changed = view_id(**mutated)
                except MappingContractError:
                    continue
                self.assertNotEqual(changed, original)
        uppercase = self.identity()
        uppercase["source_sha256"] = uppercase["source_sha256"].upper()
        with self.assertRaises(MappingContractError):
            view_id(**uppercase)

    def test_singular_transform_is_rejected_on_inverse(self) -> None:
        mapping = copy.deepcopy(self.fixture["mappings"][2])
        mapping["transform"] = [1.0, 2.0, 2.0, 4.0, 0.0, 0.0]
        with self.assertRaisesRegex(MappingContractError, "Singular"):
            spread_to_normalized(mapping, 1.0, 1.0)

    def test_inverse_rejects_points_outside_mapped_destination(self) -> None:
        mapping = self.fixture["mappings"][self.fixture["page143MappingIndex"]]
        midpoint_y = (
            mapping["destination"][1] + mapping["destination"][3]
        ) / 2
        with self.assertRaisesRegex(MappingContractError, "outside"):
            spread_to_normalized(
                mapping, mapping["destination"][0] - 1.0, midpoint_y
            )

    def test_inverse_clamps_only_edge_roundoff(self) -> None:
        mapping = self.fixture["mappings"][self.fixture["page143MappingIndex"]]
        midpoint_y = (
            mapping["destination"][1] + mapping["destination"][3]
        ) / 2
        normalized = spread_to_normalized(
            mapping,
            mapping["destination"][0] - 1.0e-13,
            midpoint_y,
        )
        self.assertEqual(0.0, normalized[0])
        self.assertAlmostEqual(0.5, normalized[1], delta=1.0e-12)

    def test_ill_conditioned_transform_fails_round_trip(self) -> None:
        mapping = copy.deepcopy(self.fixture["mappings"][2])
        mapping["sourceBox"] = [0.0, 0.0, 1.0, 1.0]
        mapping["normalizedSourceBox"] = [0.0, 0.0, 1.0, 1.0]
        mapping["sourceRotation"] = 0
        mapping["transform"] = [
            1.0, 1.0, 1.0, 1.0000000000000002, 0.0, 0.0
        ]
        with self.assertRaisesRegex(MappingContractError, "round trip"):
            normalized_to_spread(mapping, 0.25, 0.75)

    def test_signed_zero_mapping_and_view_vectors(self) -> None:
        vector = self.fixture["signedZeroVectors"]
        mappings = copy.deepcopy(self.fixture["mappings"])
        mutation = vector["mappingMutation"]
        mapping = mappings[mutation["mappingIndex"]]
        mapping[mutation["field"]][mutation["elementIndex"]] = -0.0
        self.assertEqual(
            mutation["canonicalRecord"], canonical_mapping_record(mapping)
        )
        self.assertEqual(
            mutation["mappingAuthoritySha256"],
            mapping_authority_sha256(mappings),
        )

        identity = self.identity()
        identity["gutter"] = -0.0
        view = vector["viewMutation"]
        self.assertEqual(
            view["canonicalView"],
            canonical_view_bytes(**identity).decode(),
        )
        self.assertEqual(view["viewId"], view_id(**identity))
        self.assertIn("8000000000000000", view["canonicalView"])

    def test_nonfinite_view_geometry_is_rejected(self) -> None:
        for value in (math.inf, -math.inf, math.nan, True, "864"):
            with self.subTest(value=value):
                identity = self.identity()
                identity["spread_width"] = value
                with self.assertRaises(MappingContractError):
                    canonical_view_bytes(**identity)


if __name__ == "__main__":
    unittest.main()
