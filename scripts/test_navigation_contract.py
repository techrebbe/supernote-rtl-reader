#!/usr/bin/env python3
"""Golden and mutation tests for authenticated bookmark navigation."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from virtual_spread.navigation_contract import (  # noqa: E402
    NavigationContractError,
    canonical_navigation_bytes,
    navigation_authority_sha256,
)


OUTLINES = [
    {
        "outlineIndex": 0,
        "parentOutlineIndex": None,
        "title": "שער ראשון",
        "isOpen": True,
        "bold": True,
        "italic": False,
        "color": [0.0, 0.0, -0.0],
        "destination": None,
    },
    {
        "outlineIndex": 1,
        "parentOutlineIndex": 0,
        "title": "תפילת שחרית",
        "isOpen": True,
        "bold": False,
        "italic": False,
        "color": [0.0, 0.0, 0.0],
        "destination": {
            "sourcePageIndex": 142,
            "virtualPageIndex": 71,
            "side": "right",
            "targetView": "fit-source-page",
            "mode": "/FitR",
            "operands": [432.0, 0.0, 864.0, 648.0],
        },
    },
]
AUTHORITY_KWARGS = {
    "remove_adjacent_page_links": True,
    "removed_adjacent_page_link_count": 3,
    "retained_link_count": 7,
}


class NavigationContractTest(unittest.TestCase):
    def test_golden_vector(self) -> None:
        canonical = canonical_navigation_bytes(OUTLINES, **AUTHORITY_KWARGS)
        self.assertTrue(canonical.endswith(b"\n"))
        self.assertIn(b"8000000000000000", canonical)
        self.assertEqual(
            navigation_authority_sha256(OUTLINES, **AUTHORITY_KWARGS),
            "7fbaa18d9b6c14ac6e1d5ea3062dccdb82c4092de9b56150676d19cc9695c172",
        )

    def test_every_authoritative_field_is_authenticated(self) -> None:
        baseline = navigation_authority_sha256(
            OUTLINES, **AUTHORITY_KWARGS
        )
        mutations = (
            (0, "title", "different"),
            (0, "isOpen", False),
            (0, "bold", False),
            (1, "italic", True),
            (1, "parentOutlineIndex", None),
        )
        for index, field, value in mutations:
            with self.subTest(index=index, field=field):
                changed = copy.deepcopy(OUTLINES)
                changed[index][field] = value
                self.assertNotEqual(
                    baseline,
                    navigation_authority_sha256(
                        changed, **AUTHORITY_KWARGS
                    ),
                )
        changed = copy.deepcopy(OUTLINES)
        changed[0]["color"][0] = 0.25
        self.assertNotEqual(
            baseline,
            navigation_authority_sha256(changed, **AUTHORITY_KWARGS),
        )
        changed = copy.deepcopy(OUTLINES)
        changed[1]["destination"]["sourcePageIndex"] = 143
        self.assertNotEqual(
            baseline,
            navigation_authority_sha256(changed, **AUTHORITY_KWARGS),
        )
        changed = copy.deepcopy(OUTLINES)
        changed[1]["destination"]["virtualPageIndex"] = 72
        self.assertNotEqual(
            baseline,
            navigation_authority_sha256(changed, **AUTHORITY_KWARGS),
        )
        changed = copy.deepcopy(OUTLINES)
        changed[1]["destination"]["side"] = "left"
        self.assertNotEqual(
            baseline,
            navigation_authority_sha256(changed, **AUTHORITY_KWARGS),
        )
        changed = copy.deepcopy(OUTLINES)
        changed[1]["destination"]["targetView"] = "preserve"
        with self.assertRaises(NavigationContractError):
            navigation_authority_sha256(changed, **AUTHORITY_KWARGS)
        changed = copy.deepcopy(OUTLINES)
        changed[1]["destination"]["operands"][0] += 1.0
        self.assertNotEqual(
            baseline,
            navigation_authority_sha256(changed, **AUTHORITY_KWARGS),
        )

        for field, value in (
            ("remove_adjacent_page_links", False),
            ("removed_adjacent_page_link_count", 4),
            ("retained_link_count", 8),
        ):
            with self.subTest(field=field):
                changed_options = dict(AUTHORITY_KWARGS)
                changed_options[field] = value
                if field == "remove_adjacent_page_links":
                    changed_options["removed_adjacent_page_link_count"] = 0
                self.assertNotEqual(
                    baseline,
                    navigation_authority_sha256(
                        OUTLINES, **changed_options
                    ),
                )

    def test_unknown_fields_and_invalid_parent_fail_closed(self) -> None:
        unknown = copy.deepcopy(OUTLINES)
        unknown[0]["unexpected"] = True
        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(unknown, **AUTHORITY_KWARGS)
        invalid_parent = copy.deepcopy(OUTLINES)
        invalid_parent[1]["parentOutlineIndex"] = 1
        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(invalid_parent, **AUTHORITY_KWARGS)

        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(
                OUTLINES,
                remove_adjacent_page_links=False,
                removed_adjacent_page_link_count=1,
                retained_link_count=7,
            )

        invalid_color = copy.deepcopy(OUTLINES)
        invalid_color[0]["color"][0] = 1.1
        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(
                invalid_color, **AUTHORITY_KWARGS
            )

        invalid_index = copy.deepcopy(OUTLINES)
        invalid_index[1]["outlineIndex"] = 2
        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(
                invalid_index, **AUTHORITY_KWARGS
            )

        invalid_mode = copy.deepcopy(OUTLINES)
        invalid_mode[1]["destination"]["mode"] = "/Fit"
        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(
                invalid_mode, **AUTHORITY_KWARGS
            )

        invalid_title = copy.deepcopy(OUTLINES)
        invalid_title[0]["title"] = "bad\ud800"
        with self.assertRaises(NavigationContractError):
            canonical_navigation_bytes(
                invalid_title, **AUTHORITY_KWARGS
            )


if __name__ == "__main__":
    unittest.main()
