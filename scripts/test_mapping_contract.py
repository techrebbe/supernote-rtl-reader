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
    JAVA_INT32_MAX,
    MappingContractError,
    NAVIGATION_GENERATOR_FORMAT_VERSION,
    NAVIGATION_MANIFEST_SCHEMA,
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

    def simple_mapping(self, rotation: int) -> dict[str, object]:
        source_box = [0.0, 0.0, 100.0, 200.0]
        if rotation == 0:
            normalized_box = source_box
            destination = [54.0, 0.0, 378.0, 648.0]
            scale = 3.24
            transform = [3.24, 0.0, 0.0, 3.24, 54.0, 0.0]
        elif rotation == 90:
            normalized_box = [0.0, 0.0, 200.0, 100.0]
            destination = [0.0, 216.0, 432.0, 432.0]
            scale = 2.16
            transform = [0.0, -2.16, 2.16, 0.0, 0.0, 432.0]
        elif rotation == 180:
            normalized_box = source_box
            destination = [54.0, 0.0, 378.0, 648.0]
            scale = 3.24
            transform = [-3.24, 0.0, 0.0, -3.24, 378.0, 648.0]
        elif rotation == 270:
            normalized_box = [0.0, 0.0, 200.0, 100.0]
            destination = [0.0, 216.0, 432.0, 432.0]
            scale = 2.16
            transform = [0.0, 2.16, -2.16, 0.0, 432.0, 216.0]
        else:
            raise AssertionError(f"unsupported test rotation: {rotation}")
        return {
            "sourcePageIndex": 0,
            "virtualPageIndex": 0,
            "side": "left",
            "sourceRotation": rotation,
            "sourceBox": source_box,
            "normalizedSourceBox": normalized_box,
            "slot": [0.0, 0.0, 432.0, 648.0],
            "destination": destination,
            "scale": scale,
            "transform": transform,
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

    def test_navigation_view_identity_cross_language_vector(self) -> None:
        identity = {
            "source_sha256": "0123456789abcdef" * 4,
            "mapping_authority_sha256":
                "646b905c12266774882e0c4d7ebbbca77b2f386f432979ebcbfcda1d9ace268a",
            "direction": "rtl",
            "cover_separate": True,
            "spread_width": 864.0,
            "spread_height": 648.0,
            "gutter": 0.0,
            "manifest_schema": NAVIGATION_MANIFEST_SCHEMA,
            "generator_version": NAVIGATION_GENERATOR_FORMAT_VERSION,
            "navigation_authority_sha256":
                "7fbaa18d9b6c14ac6e1d5ea3062dccdb82c4092de9b56150676d19cc9695c172",
            "remove_adjacent_page_links": True,
        }
        self.assertEqual(
            view_id(**identity),
            "inkbridge-view-v1-"
            "9c6d77c84ef97e7f73aa40156a78ef7248b3ce1bca39d71eb2cda5341b040d2f",
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

    def test_singular_transform_is_rejected_semantically(self) -> None:
        mapping = copy.deepcopy(self.fixture["mappings"][2])
        mapping["transform"] = [1.0, 2.0, 2.0, 4.0, 0.0, 0.0]
        with self.assertRaisesRegex(MappingContractError, "Transform"):
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

    def test_all_exact_quarter_turn_geometries_are_accepted(self) -> None:
        for rotation in (0, 90, 180, 270):
            with self.subTest(rotation=rotation):
                mapping = self.simple_mapping(rotation)
                canonical_mapping_record(mapping)
                spread = normalized_to_spread(mapping, 0.25, 0.75)
                restored = spread_to_normalized(mapping, *spread)
                self.assertAlmostEqual(0.25, restored[0], delta=1.0e-12)
                self.assertAlmostEqual(0.75, restored[1], delta=1.0e-12)

    def test_semantic_geometry_rejects_non_generator_mappings(self) -> None:
        valid = self.simple_mapping(0)
        mutations = {
            "reflection": {
                "transform": [-3.24, 0.0, 0.0, 3.24, 378.0, 0.0]
            },
            "wrong rotation": {"sourceRotation": 180},
            "non-generator fit": {
                "destination": [66.0, 24.0, 366.0, 624.0],
                "scale": 3.0,
                "transform": [3.0, 0.0, 0.0, 3.0, 66.0, 24.0],
            },
            "off-center destination": {
                "destination": [55.0, 0.0, 379.0, 648.0],
                "transform": [3.24, 0.0, 0.0, 3.24, 55.0, 0.0],
            },
        }
        for label, mutation in mutations.items():
            with self.subTest(case=label):
                mapping = copy.deepcopy(valid)
                mapping.update(mutation)
                with self.assertRaises(MappingContractError):
                    canonical_mapping_record(mapping)

    def test_quarter_turn_coefficients_are_exact_binary64(self) -> None:
        mapping = self.simple_mapping(90)
        mapping["transform"][0] = 1.0e-15
        with self.assertRaisesRegex(MappingContractError, "Transform"):
            canonical_mapping_record(mapping)

    def test_tiny_scale_reflection_is_rejected(self) -> None:
        half_width = (864.0 - 863.999) / 2.0
        scale = half_width / 14400.0
        bottom = (648.0 - half_width) / 2.0
        mapping = {
            "sourcePageIndex": 0,
            "virtualPageIndex": 0,
            "side": "left",
            "sourceRotation": 0,
            "sourceBox": [0.0, 0.0, 14400.0, 14400.0],
            "normalizedSourceBox": [0.0, 0.0, 14400.0, 14400.0],
            "slot": [0.0, 0.0, half_width, 648.0],
            "destination": [0.0, bottom, half_width, bottom + half_width],
            "scale": scale,
            "transform": [-scale, 0.0, 0.0, scale, half_width, bottom],
        }
        with self.assertRaisesRegex(MappingContractError, "Transform"):
            canonical_mapping_record(mapping)

    def test_far_offset_mapping_is_rejected_as_numerically_unstable(
        self,
    ) -> None:
        mapping = self.simple_mapping(0)
        offset = float(2 ** 40)
        mapping["sourceBox"] = [
            offset,
            offset,
            offset + 100.0,
            offset + 200.0,
        ]
        mapping["normalizedSourceBox"] = list(mapping["sourceBox"])
        mapping["transform"] = [
            3.24,
            0.0,
            0.0,
            3.24,
            54.0 - 3.24 * offset,
            -3.24 * offset,
        ]
        with self.assertRaisesRegex(MappingContractError, "unstable"):
            normalized_to_spread(mapping, 0.25, 0.75)

    def test_mapping_indices_are_bounded_by_java_int32(self) -> None:
        mapping = self.simple_mapping(0)
        mapping["sourcePageIndex"] = JAVA_INT32_MAX
        mapping["virtualPageIndex"] = JAVA_INT32_MAX
        canonical_mapping_record(mapping)
        for field in ("sourcePageIndex", "virtualPageIndex"):
            with self.subTest(field=field):
                overflow = copy.deepcopy(mapping)
                overflow[field] = JAVA_INT32_MAX + 1
                with self.assertRaises(MappingContractError):
                    canonical_mapping_record(overflow)

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
