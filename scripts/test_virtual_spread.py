#!/usr/bin/env python3
"""Deterministic tests for the virtual-spread PDF generator."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "virtual_spread"))

from generate_virtual_spread import build_pairs, build_virtual_spread  # noqa: E402


PAGE_SIZES = [
    (432, 576),
    (300, 600),
    (600, 300),
    (420, 420),
    (200, 700),
    (700, 200),
    (432, 576),
]


def create_odd_page_fixture(path: Path) -> None:
    pdf = canvas.Canvas(str(path), pagesize=PAGE_SIZES[0])
    for index, (width, height) in enumerate(PAGE_SIZES):
        pdf.setPageSize((width, height))
        name = f"source-{index + 1}"
        pdf.bookmarkPage(name)
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(20, height - 35, f"ODD SOURCE PAGE {index + 1}")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(20, height - 55, f"SIZE {width} x {height}")
        pdf.rect(10, 10, width - 20, height - 20)
        if index == 1:
            pdf.drawString(20, 30, "LINK TO PAGE 6")
            pdf.linkRect("", "source-6", (15, 15, min(width - 15, 180), 48))
            pdf.drawString(20, 75, "LINK TO PAGE 7")
            pdf.linkRect("", "source-7", (15, 55, min(width - 15, 180), 93))
        if index == 5:
            pdf.drawString(20, 30, "LINK TO PAGE 2")
            pdf.linkRect("", "source-2", (15, 15, min(width - 15, 180), 48))
        if index == 6:
            pdf.drawString(20, 30, "LINK TO PAGE 3")
            pdf.linkRect("", "source-3", (15, 15, min(width - 15, 180), 48))
        pdf.showPage()
    pdf.save()


def destination_page_index(reader: PdfReader, annotation: object) -> int:
    destination = annotation.get_object()["/Dest"]
    target = destination[0]
    for index, page in enumerate(reader.pages):
        if page.indirect_reference == target:
            return index
    raise AssertionError("Destination page reference was not found")


class VirtualSpreadTests(unittest.TestCase):
    def test_rtl_cover_pairing(self) -> None:
        self.assertEqual(
            build_pairs(7, "rtl", True),
            [(None, 0), (2, 1), (4, 3), (6, 5)],
        )

    def test_ltr_pairing_without_cover(self) -> None:
        self.assertEqual(
            build_pairs(5, "ltr", False),
            [(0, 1), (2, 3), (4, None)],
        )

    def test_odd_pages_text_and_links_survive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "odd-source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            manifest = build_virtual_spread(
                source,
                output,
                manifest_path,
                direction="rtl",
                cover_separate=True,
            )

            self.assertEqual(manifest["output"]["pageCount"], 4)
            self.assertEqual(len(manifest["sourcePages"]), 7)
            self.assertEqual(len(manifest["links"]), 4)
            self.assertEqual(
                [link["sourceSide"] for link in manifest["links"]],
                ["right", "right", "right", "left"],
            )
            self.assertEqual(
                json.loads(manifest_path.read_text(encoding="utf-8"))["schema"],
                "techrebbe.supernote.virtual-spread/v1",
            )

            reader = PdfReader(str(output), strict=True)
            self.assertEqual(len(reader.pages), 4)
            for page in reader.pages:
                self.assertAlmostEqual(float(page.mediabox.width), 864.0)
                self.assertAlmostEqual(float(page.mediabox.height), 648.0)

            first_text = reader.pages[0].extract_text() or ""
            second_text = reader.pages[1].extract_text() or ""
            self.assertIn("ODD SOURCE PAGE 1", first_text)
            self.assertIn("ODD SOURCE PAGE 2", second_text)
            self.assertIn("ODD SOURCE PAGE 3", second_text)

            source_two_annotations = reader.pages[1]["/Annots"]
            source_six_annotations = reader.pages[3]["/Annots"]
            self.assertEqual(len(source_two_annotations), 2)
            self.assertEqual(len(source_six_annotations), 2)
            expected_links = (
                (source_two_annotations[0], 3, "/Right", 1),
                (source_two_annotations[1], 3, "/Left", 1),
                (source_six_annotations[0], 1, "/Right", 5),
                (source_six_annotations[1], 1, "/Left", 6),
            )
            for annotation, target_page, target_side, source_page in expected_links:
                self.assertEqual(
                    destination_page_index(reader, annotation),
                    target_page,
                )
                self.assertEqual(
                    annotation.get_object()["/SNTargetSide"],
                    target_side,
                )
                self.assertEqual(
                    annotation.get_object()["/SNSourcePage"],
                    source_page,
                )

            for mapping in manifest["sourcePages"]:
                left, bottom, right, top = mapping["destination"]
                slot_left, slot_bottom, slot_right, slot_top = mapping["slot"]
                self.assertGreater(right, left)
                self.assertGreater(top, bottom)
                self.assertGreaterEqual(left, slot_left - 0.001)
                self.assertGreaterEqual(bottom, slot_bottom - 0.001)
                self.assertLessEqual(right, slot_right + 0.001)
                self.assertLessEqual(top, slot_top + 0.001)


if __name__ == "__main__":
    unittest.main(verbosity=2)
