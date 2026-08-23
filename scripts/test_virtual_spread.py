#!/usr/bin/env python3
"""Deterministic tests for the virtual-spread PDF generator."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "virtual_spread"))

from generate_virtual_spread import (  # noqa: E402
    VirtualSpreadError,
    _publish_pair,
    build_pairs,
    build_virtual_spread,
)


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


def create_rotated_link_fixture(path: Path) -> None:
    unrotated = path.with_name("unrotated.pdf")
    pdf = canvas.Canvas(str(unrotated), pagesize=(200, 100))
    pdf.bookmarkPage("first")
    pdf.drawString(10, 70, "ROTATED LINK SOURCE")
    pdf.linkRect("", "second", (10, 20, 60, 40))
    pdf.showPage()
    pdf.setPageSize((200, 100))
    pdf.bookmarkPage("second")
    pdf.drawString(10, 70, "LINK TARGET")
    pdf.showPage()
    pdf.save()

    source = PdfReader(str(unrotated), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    writer.pages[0].rotate(90)
    with path.open("wb") as stream:
        writer.write(stream)
    unrotated.unlink()


def transform_rect(rect: object, transform: list[float]) -> list[float]:
    x0, y0, x1, y1 = [float(value) for value in rect]
    a, b, c, d, e, f = transform
    points = [
        (a * x + c * y + e, b * x + d * y + f)
        for x, y in ((x0, y0), (x0, y1), (x1, y0), (x1, y1))
    ]
    return [
        min(point[0] for point in points),
        min(point[1] for point in points),
        max(point[0] for point in points),
        max(point[1] for point in points),
    ]


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

            self.assertIs(manifest["coverSeparate"], True)
            self.assertEqual(manifest["output"]["pageCount"], 4)
            self.assertEqual(len(manifest["sourcePages"]), 7)
            self.assertEqual(
                [
                    (
                        None if spread["left"] is None else
                            spread["left"]["sourcePageIndex"],
                        None if spread["right"] is None else
                            spread["right"]["sourcePageIndex"],
                    )
                    for spread in manifest["spreads"]
                ],
                [(None, 0), (2, 1), (4, 3), (6, 5)],
            )
            self.assertEqual(
                [
                    (mapping["virtualPageIndex"], mapping["side"])
                    for mapping in manifest["sourcePages"]
                ],
                [
                    (0, "right"),
                    (1, "right"), (1, "left"),
                    (2, "right"), (2, "left"),
                    (3, "right"), (3, "left"),
                ],
            )
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

    def test_output_and_manifest_paths_must_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            collision = root / "collision.pdf"
            create_odd_page_fixture(source)

            with self.assertRaisesRegex(VirtualSpreadError, "must be distinct"):
                build_virtual_spread(
                    source,
                    collision,
                    collision,
                    force=True,
                )
            self.assertFalse(collision.exists())

    def test_non_finite_spread_geometry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            create_odd_page_fixture(source)
            cases = (
                {"spread_width": float("nan")},
                {"spread_height": float("inf")},
                {"gutter": float("nan")},
            )
            for index, values in enumerate(cases):
                with self.subTest(values=values):
                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "dimensions and gutter",
                    ):
                        build_virtual_spread(
                            source,
                            root / f"spread-{index}.pdf",
                            root / f"spread-{index}.pdf.json",
                            **values,
                        )

    def test_rotated_page_link_uses_source_to_spread_transform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "rotated-source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_rotated_link_fixture(source)
            source_reader = PdfReader(str(source), strict=True)
            source_rect = source_reader.pages[0]["/Annots"][0].get_object()[
                "/Rect"
            ]

            manifest = build_virtual_spread(
                source,
                output,
                manifest_path,
                direction="rtl",
                cover_separate=False,
            )
            mapping = manifest["sourcePages"][0]
            transform = mapping["transform"]
            self.assertNotAlmostEqual(transform[1], 0.0)
            self.assertNotAlmostEqual(transform[2], 0.0)

            output_reader = PdfReader(str(output), strict=True)
            output_rect = [
                float(value)
                for value in output_reader.pages[0]["/Annots"][0]
                .get_object()["/Rect"]
            ]
            expected_rect = transform_rect(source_rect, transform)
            for actual, expected in zip(output_rect, expected_rect):
                self.assertAlmostEqual(actual, expected, places=4)

            left, bottom, right, top = mapping["destination"]
            self.assertGreaterEqual(output_rect[0], left - 0.001)
            self.assertGreaterEqual(output_rect[1], bottom - 0.001)
            self.assertLessEqual(output_rect[2], right + 0.001)
            self.assertLessEqual(output_rect[3], top + 0.001)

    def test_pair_publication_rolls_back_after_second_replace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            temporary_output = root / ".spread.pdf.new"
            temporary_manifest = root / ".spread.pdf.json.new"
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            temporary_output.write_bytes(b"new-pdf")
            temporary_manifest.write_bytes(b"new-manifest")

            real_replace = os.replace

            def fail_output_publication(source: object, target: object) -> None:
                if (
                    Path(source) == temporary_output
                    and Path(target) == output
                ):
                    raise OSError("simulated output publication failure")
                real_replace(source, target)

            with mock.patch(
                "generate_virtual_spread.os.replace",
                side_effect=fail_output_publication,
            ):
                with self.assertRaisesRegex(
                    OSError,
                    "simulated output publication failure",
                ):
                    _publish_pair(
                        temporary_output,
                        output,
                        temporary_manifest,
                        manifest,
                    )

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(temporary_output.exists())
            self.assertFalse(temporary_manifest.exists())
            self.assertEqual(
                list(root.glob("*.bak")),
                [],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
