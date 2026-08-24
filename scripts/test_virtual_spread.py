#!/usr/bin/env python3
"""Deterministic tests for the virtual-spread PDF generator."""

from __future__ import annotations

import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    BooleanObject,
    DictionaryObject,
    FloatObject,
    IndirectObject,
    NameObject,
    NumberObject,
    NullObject,
    TextStringObject,
)
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "virtual_spread"))

from generate_virtual_spread import (  # noqa: E402
    LAYOUT_AUTHORITY_MARKER,
    LINK_AUTHORITY_MARKER,
    MAX_MANIFEST_BYTES,
    MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH,
    SourceIdentity,
    VirtualSpreadError,
    _canonical_layout,
    _durable_replace,
    _identity,
    _layout_authority_sha256,
    _link_authority_sha256,
    _link_annotation_flags,
    _publish_pair,
    _require_unaliased_output_path,
    _publication_artifacts,
    _publication_lock,
    _transform_rect,
    _publication_lock_path,
    _prepare_publication_transaction,
    _recover_pair_publication,
    _sha256_open_file,
    _windows_move_flags,
    _write_json,
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


def add_outline_entry(path: Path) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    writer.add_outline_item("Chapter 2", 1)
    with path.open("wb") as stream:
        writer.write(stream)

    persisted = PdfReader(str(path), strict=True)
    catalog = persisted.trailer["/Root"]
    if "/Outlines" not in catalog:
        raise AssertionError("fixture document outline was not persisted")
    if not persisted.outline:
        raise AssertionError("fixture document outline is empty")


def add_document_open_action(path: Path) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    writer._root_object[NameObject("/OpenAction")] = ArrayObject(
        [writer.pages[1].indirect_reference, NameObject("/Fit")]
    )
    with path.open("wb") as stream:
        writer.write(stream)

    persisted = PdfReader(str(path), strict=True)
    catalog = persisted.trailer["/Root"]
    if "/OpenAction" not in catalog:
        raise AssertionError("fixture document open action was not persisted")
    open_action = catalog["/OpenAction"]
    if not isinstance(open_action, ArrayObject) or len(open_action) != 2:
        raise AssertionError("fixture document open action is malformed")


def make_annotation_array_indirect(path: Path, page_index: int) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation_array = annotations.get_object()
    writer.pages[page_index][NameObject("/Annots")] = writer._add_object(
        annotation_array
    )
    with path.open("wb") as stream:
        writer.write(stream)

    persisted = PdfReader(str(path), strict=True)
    persisted_annotations = persisted.pages[page_index].raw_get(
        "/Annots"
    )
    if not isinstance(persisted_annotations, IndirectObject):
        raise AssertionError("fixture annotation array is not indirect")


def make_link_destination_indirect(
    path: Path,
    page_index: int,
    annotation_index: int,
) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation_array = annotations.get_object()
    annotation = annotation_array[annotation_index].get_object()
    destination = annotation.get("/Dest")
    if destination is None:
        raise AssertionError("fixture link has no direct destination")
    annotation[NameObject("/Dest")] = writer._add_object(
        destination.get_object()
    )
    with path.open("wb") as stream:
        writer.write(stream)

    persisted = PdfReader(str(path), strict=True)
    persisted_annotations = persisted.pages[page_index]["/Annots"].get_object()
    persisted_destination = persisted_annotations[
        annotation_index
    ].get_object().raw_get("/Dest")
    if not isinstance(persisted_destination, IndirectObject):
        raise AssertionError("fixture link destination is not indirect")


def set_link_destination_mode(
    path: Path,
    source_page_index: int,
    annotation_index: int,
    target_page_index: int,
    mode: str,
    arguments: tuple[float | None, ...],
) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[source_page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation = annotations.get_object()[annotation_index].get_object()
    target_reference = writer.pages[target_page_index].indirect_reference
    if target_reference is None:
        raise AssertionError("fixture target page has no indirect reference")
    destination_arguments = [
        NullObject() if value is None else FloatObject(value)
        for value in arguments
    ]
    annotation.pop("/A", None)
    annotation[NameObject("/Dest")] = ArrayObject(
        [target_reference, NameObject(mode), *destination_arguments]
    )
    with path.open("wb") as stream:
        writer.write(stream)


def set_raw_link_destination(
    path: Path,
    source_page_index: int,
    annotation_index: int,
    target_page_index: int,
    mode: object,
    arguments: tuple[object, ...],
) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[source_page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation = annotations.get_object()[annotation_index].get_object()
    target_reference = writer.pages[target_page_index].indirect_reference
    if target_reference is None:
        raise AssertionError("fixture target page has no indirect reference")
    annotation.pop("/A", None)
    annotation[NameObject("/Dest")] = ArrayObject(
        [target_reference, mode, *arguments]
    )
    with path.open("wb") as stream:
        writer.write(stream)


def set_link_quad_points(
    path: Path,
    source_page_index: int,
    annotation_index: int,
    points: tuple[object, ...],
) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[source_page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation = annotations.get_object()[annotation_index].get_object()
    annotation[NameObject("/QuadPoints")] = ArrayObject(points)
    with path.open("wb") as stream:
        writer.write(stream)


def set_link_annotation_value(
    path: Path,
    source_page_index: int,
    annotation_index: int,
    key: str,
    value: object,
) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[source_page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation = annotations.get_object()[annotation_index].get_object()
    annotation[NameObject(key)] = value
    with path.open("wb") as stream:
        writer.write(stream)


def set_link_action(
    path: Path,
    source_page_index: int,
    annotation_index: int,
    action: DictionaryObject,
) -> None:
    source = PdfReader(str(path), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(source)
    annotations = writer.pages[source_page_index].get("/Annots")
    if annotations is None:
        raise AssertionError("fixture page has no annotations")
    annotation = annotations.get_object()[annotation_index].get_object()
    annotation.pop("/Dest", None)
    annotation[NameObject("/A")] = action
    with path.open("wb") as stream:
        writer.write(stream)


def output_annotation_for_source(
    output: Path,
    manifest: dict[str, object],
    source_page_index: int,
) -> DictionaryObject:
    reader = PdfReader(str(output), strict=True)
    mapping = manifest["sourcePages"][source_page_index]
    annotations = reader.pages[mapping["virtualPageIndex"]]["/Annots"]
    return next(
        item.get_object()
        for item in annotations.get_object()
        if int(item.get_object()["/SNSourcePage"]) == source_page_index
    )


def transform_point(
    x: float, y: float, transform: list[float]
) -> tuple[float, float]:
    a, b, c, d, e, f = transform
    return (a * x + c * y + e, b * x + d * y + f)


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

    def test_ltr_generation_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Unsupported virtual-spread direction: ltr",
            ):
                build_virtual_spread(
                    source, output, manifest_path, direction="ltr"
                )

            with self.assertRaisesRegex(VirtualSpreadError, "direction: ltr"):
                build_pairs(5, "ltr", False)
            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())
            self.assertFalse(_publication_lock_path(output).exists())

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

    def test_document_outlines_fail_closed_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "outlined-source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            add_outline_entry(source)
            source_bytes = source.read_bytes()
            output.write_bytes(b"existing-output")
            manifest_path.write_bytes(b"existing-manifest")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Document outlines are not supported",
            ):
                build_virtual_spread(
                    source,
                    output,
                    manifest_path,
                    force=True,
                )

            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertEqual(output.read_bytes(), b"existing-output")
            self.assertEqual(
                manifest_path.read_bytes(), b"existing-manifest"
            )

    def test_document_open_action_fails_closed_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "open-action-source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            add_document_open_action(source)
            source_bytes = source.read_bytes()
            output.write_bytes(b"existing-output")
            manifest_path.write_bytes(b"existing-manifest")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Document open actions are not supported",
            ):
                build_virtual_spread(
                    source,
                    output,
                    manifest_path,
                    force=True,
                )

            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertEqual(output.read_bytes(), b"existing-output")
            self.assertEqual(
                manifest_path.read_bytes(), b"existing-manifest"
            )

    def test_pdf_authorities_are_embedded_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
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

            authority = _link_authority_sha256(manifest["links"])
            self.assertEqual(
                manifest["output"]["linkAuthoritySha256"],
                authority,
            )
            metadata = PdfReader(str(output), strict=True).metadata
            self.assertEqual(
                metadata["/SNVirtualSpreadLinksSHA256"],
                authority,
            )
            layout_record = _canonical_layout(
                "rtl", True, 7, 4, 864.0, 648.0, 0.0
            )
            self.assertEqual(
                layout_record,
                "v1|layout|rtl|1|7|4|408b000000000000|"
                "4084400000000000|0000000000000000",
            )
            layout_authority = _layout_authority_sha256(
                "rtl", True, 7, 4, 864.0, 648.0, 0.0
            )
            self.assertEqual(
                layout_authority,
                "53d5b0b6c97118392220518325c8ee23f1a81d04bf430e01c893d88c490a4307",
            )
            self.assertEqual(
                manifest["output"]["layoutAuthoritySha256"],
                layout_authority,
            )
            self.assertEqual(
                metadata["/SNVirtualSpreadLayoutSHA256"],
                layout_authority,
            )
            # Seven source pages produce four spreads with either cover mode.
            # The layout digest must still distinguish their different parity.
            self.assertEqual(manifest["output"]["pageCount"], 4)
            self.assertNotEqual(
                _layout_authority_sha256(
                    "rtl", False, 7, 4, 864.0, 648.0, 0.0
                ),
                layout_authority,
            )
            with output.open("rb") as stream:
                stream.seek(max(0, output.stat().st_size - 4096))
                tail = stream.read()
            layout_marker = (
                LAYOUT_AUTHORITY_MARKER
                + layout_authority.encode("ascii")
                + b"\n"
            )
            link_marker = (
                LINK_AUTHORITY_MARKER + authority.encode("ascii") + b"\n"
            )
            self.assertEqual(tail.count(layout_marker), 1)
            self.assertEqual(tail.count(link_marker), 1)
            self.assertEqual(
                tail.index(layout_marker) + len(layout_marker),
                tail.index(link_marker),
            )
            self.assertEqual(
                tail.index(link_marker) + len(link_marker),
                tail.rindex(b"startxref"),
            )

            tampered_links = json.loads(json.dumps(manifest["links"]))
            tampered_links[0]["targetSourcePage"] = 6
            tampered_links[0]["targetSide"] = "left"
            self.assertEqual(tampered_links[0]["targetOutputPage"], 3)
            self.assertNotEqual(
                _link_authority_sha256(tampered_links),
                authority,
            )
            self.assertNotEqual(_link_authority_sha256([]), authority)

    def test_windows_namespace_changes_always_request_write_through(self) -> None:
        self.assertEqual(
            _windows_move_flags(False),
            MOVEFILE_WRITE_THROUGH,
        )
        self.assertEqual(
            _windows_move_flags(True),
            MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING,
        )

    def test_source_change_before_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)

            def write_then_mutate(
                path: Path,
                value: dict[str, object],
                ownership_guard: object = None,
            ) -> None:
                _write_json(path, value, ownership_guard)
                source.write_bytes(source.read_bytes() + b"\n% changed\n")

            with mock.patch(
                "generate_virtual_spread._write_json",
                side_effect=write_then_mutate,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "changed before publication",
                ):
                    build_virtual_spread(source, output, manifest_path)

            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                sorted([
                    "source.pdf",
                    _publication_lock_path(output).name,
                ]),
            )

    def test_source_change_during_snapshot_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            stable = _identity(source.stat())
            changed = SourceIdentity(
                device=stable.device,
                inode=stable.inode,
                size=stable.size,
                modified_ns=stable.modified_ns,
                changed_ns=stable.changed_ns + 1,
            )

            with mock.patch(
                "generate_virtual_spread._identity",
                side_effect=(stable, stable, changed, changed),
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "changed while snapshotting",
                ):
                    build_virtual_spread(source, output, manifest_path)

            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                sorted([
                    "source.pdf",
                    _publication_lock_path(output).name,
                ]),
            )

    def test_content_change_during_snapshot_is_rejected_with_stable_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            stable = _identity(source.stat())
            real_hash = _sha256_open_file
            changed = False

            def mutate_then_hash(stream: object) -> str:
                nonlocal changed
                if not changed:
                    contents = bytearray(source.read_bytes())
                    contents[len(contents) // 2] ^= 1
                    source.write_bytes(contents)
                    changed = True
                return real_hash(stream)  # type: ignore[arg-type]

            with mock.patch(
                "generate_virtual_spread._identity",
                return_value=stable,
            ), mock.patch(
                "generate_virtual_spread._sha256_open_file",
                side_effect=mutate_then_hash,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "content changed while snapshotting",
                ):
                    build_virtual_spread(source, output, manifest_path)

            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                sorted([
                    "source.pdf",
                    _publication_lock_path(output).name,
                ]),
            )

    def test_content_change_before_publication_is_rejected_with_stable_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            stable = _identity(source.stat())
            changed_contents = bytearray(source.read_bytes())
            changed_contents[len(changed_contents) // 2] ^= 1

            def write_then_mutate(
                path: Path,
                value: dict[str, object],
                ownership_guard: object = None,
            ) -> None:
                _write_json(path, value, ownership_guard)
                source.write_bytes(changed_contents)

            with mock.patch(
                "generate_virtual_spread._identity",
                return_value=stable,
            ), mock.patch(
                "generate_virtual_spread._write_json",
                side_effect=write_then_mutate,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "content changed before publication",
                ):
                    build_virtual_spread(source, output, manifest_path)

            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                sorted([
                    "source.pdf",
                    _publication_lock_path(output).name,
                ]),
            )

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

    def test_source_reserved_artifact_collisions_fail_before_locking(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(9):
                with self.subTest(index=index):
                    case_root = root / str(index)
                    case_root.mkdir()
                    output = case_root / "spread.pdf"
                    manifest_path = case_root / "spread.pdf.json"
                    marker, output_backup, manifest_backup = (
                        _publication_artifacts(output)
                    )
                    removable = (
                        marker,
                        output_backup,
                        manifest_backup,
                    )
                    reserved = (
                        *removable,
                        *(
                            path.with_name(path.name + ".retired")
                            for path in (
                                *removable,
                                output,
                                manifest_path,
                            )
                        ),
                        _publication_lock_path(output),
                    )
                    source = reserved[index]
                    create_odd_page_fixture(source)
                    source_bytes = source.read_bytes()

                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "reserved virtual-spread publication artifact",
                    ):
                        build_virtual_spread(
                            source,
                            output,
                            manifest_path,
                            force=True,
                        )

                    self.assertEqual(source.read_bytes(), source_bytes)
                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())
                    for artifact in reserved:
                        if artifact != source:
                            self.assertFalse(artifact.exists())

    def test_indirect_annotation_array_is_dereferenced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            make_annotation_array_indirect(source, 1)

            manifest = build_virtual_spread(
                source,
                output,
                manifest_path,
                direction="rtl",
                cover_separate=True,
            )

            self.assertEqual(len(manifest["links"]), 4)
            persisted_source = PdfReader(str(source), strict=True)
            self.assertIsInstance(
                persisted_source.pages[1].raw_get("/Annots"),
                IndirectObject,
            )
            output_reader = PdfReader(str(output), strict=True)
            self.assertEqual(
                len(output_reader.pages[1]["/Annots"].get_object()),
                2,
            )

    def test_indirect_link_destination_is_dereferenced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            make_link_destination_indirect(source, 1, 0)

            persisted_source = PdfReader(str(source), strict=True)
            persisted_annotation = (
                persisted_source.pages[1]["/Annots"].get_object()[0]
                .get_object()
            )
            self.assertIsInstance(
                persisted_annotation.raw_get("/Dest"),
                IndirectObject,
            )

            manifest = build_virtual_spread(
                source,
                output,
                manifest_path,
                direction="rtl",
                cover_separate=True,
            )

            self.assertEqual(len(manifest["links"]), 4)
            output_reader = PdfReader(str(output), strict=True)
            first_link = output_reader.pages[1]["/Annots"].get_object()[0]
            self.assertEqual(
                destination_page_index(output_reader, first_link),
                3,
            )

    def test_internal_destination_modes_are_preserved_and_transformed(
        self,
    ) -> None:
        cases = (
            ("/Fit", ()),
            ("/FitB", ()),
            ("/XYZ", (30.0, 160.0, 1.25)),
            ("/FitH", (160.0,)),
            ("/FitBH", (160.0,)),
            ("/FitV", (30.0,)),
            ("/FitBV", (30.0,)),
            ("/FitR", (10.0, 20.0, 100.0, 160.0)),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (mode, arguments) in enumerate(cases):
                with self.subTest(mode=mode):
                    source = root / f"source-{index}.pdf"
                    output = root / f"spread-{index}.pdf"
                    manifest_path = root / f"spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_link_destination_mode(
                        source,
                        source_page_index=1,
                        annotation_index=0,
                        target_page_index=5,
                        mode=mode,
                        arguments=arguments,
                    )

                    manifest = build_virtual_spread(
                        source,
                        output,
                        manifest_path,
                        direction="rtl",
                        cover_separate=True,
                    )
                    reader = PdfReader(str(output), strict=True)
                    source_mapping = manifest["sourcePages"][1]
                    target_mapping = manifest["sourcePages"][5]
                    annotation = reader.pages[
                        source_mapping["virtualPageIndex"]
                    ]["/Annots"].get_object()[0].get_object()
                    destination = annotation["/Dest"]

                    self.assertEqual(str(destination[1]), mode)
                    self.assertEqual(
                        destination_page_index(reader, annotation),
                        target_mapping["virtualPageIndex"],
                    )
                    transform = target_mapping["transform"]
                    if mode in {"/Fit", "/FitB"}:
                        self.assertEqual(len(destination), 2)
                    elif mode == "/XYZ":
                        expected_left, expected_top = transform_point(
                            arguments[0], arguments[1], transform
                        )
                        self.assertAlmostEqual(
                            float(destination[2]), expected_left, places=4
                        )
                        self.assertAlmostEqual(
                            float(destination[3]), expected_top, places=4
                        )
                        self.assertAlmostEqual(
                            float(destination[4]), arguments[2], places=4
                        )
                    elif mode in {"/FitH", "/FitBH"}:
                        _, expected_top = transform_point(
                            0.0, arguments[0], transform
                        )
                        self.assertAlmostEqual(
                            float(destination[2]), expected_top, places=4
                        )
                    elif mode in {"/FitV", "/FitBV"}:
                        expected_left, _ = transform_point(
                            arguments[0], 0.0, transform
                        )
                        self.assertAlmostEqual(
                            float(destination[2]), expected_left, places=4
                        )
                    elif mode == "/FitR":
                        expected_rectangle = transform_rect(
                            arguments, transform
                        )
                        for actual, expected in zip(
                            destination[2:6], expected_rectangle
                        ):
                            self.assertAlmostEqual(
                                float(actual), expected, places=4
                            )

    def test_null_destination_coordinates_survive_matching_transform(
        self,
    ) -> None:
        cases = (
            ("/XYZ", (None, 160.0, 1.25), 2),
            ("/XYZ", (30.0, None, 1.25), 3),
            ("/FitH", (None,), 2),
            ("/FitBH", (None,), 2),
            ("/FitV", (None,), 2),
            ("/FitBV", (None,), 2),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (mode, arguments, null_index) in enumerate(cases):
                with self.subTest(mode=mode, arguments=arguments):
                    source = root / f"matching-source-{index}.pdf"
                    output = root / f"matching-spread-{index}.pdf"
                    manifest_path = root / f"matching-spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_link_destination_mode(
                        source,
                        source_page_index=1,
                        annotation_index=0,
                        target_page_index=1,
                        mode=mode,
                        arguments=arguments,
                    )

                    manifest = build_virtual_spread(
                        source,
                        output,
                        manifest_path,
                        direction="rtl",
                        cover_separate=True,
                    )
                    reader = PdfReader(str(output), strict=True)
                    source_mapping = manifest["sourcePages"][1]
                    annotation = reader.pages[
                        source_mapping["virtualPageIndex"]
                    ]["/Annots"].get_object()[0].get_object()
                    destination = annotation["/Dest"]

                    self.assertEqual(str(destination[1]), mode)
                    self.assertIsInstance(destination[null_index], NullObject)

    def test_null_destination_coordinates_reject_different_transforms(
        self,
    ) -> None:
        cases = (
            ("/XYZ", (None, 160.0, 1.25)),
            ("/XYZ", (30.0, None, 1.25)),
            ("/FitH", (None,)),
            ("/FitBH", (None,)),
            ("/FitV", (None,)),
            ("/FitBV", (None,)),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (mode, arguments) in enumerate(cases):
                with self.subTest(mode=mode, arguments=arguments):
                    source = root / f"different-source-{index}.pdf"
                    output = root / f"different-spread-{index}.pdf"
                    manifest_path = root / f"different-spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_link_destination_mode(
                        source,
                        source_page_index=1,
                        annotation_index=0,
                        target_page_index=5,
                        mode=mode,
                        arguments=arguments,
                    )

                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "Cannot preserve null",
                    ):
                        build_virtual_spread(
                            source,
                            output,
                            manifest_path,
                            direction="rtl",
                            cover_separate=True,
                        )

                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_destination_operands_require_pdf_name_and_numbers(self) -> None:
        cases = (
            (
                TextStringObject("/Fit"),
                (),
                "Invalid internal destination mode object",
            ),
            (
                NameObject("/XYZ"),
                (
                    TextStringObject("30"),
                    FloatObject(160.0),
                    FloatObject(1.25),
                ),
                "Invalid internal destination /XYZ left",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (mode, arguments, message) in enumerate(cases):
                with self.subTest(mode=mode):
                    source = root / f"operand-source-{index}.pdf"
                    output = root / f"operand-spread-{index}.pdf"
                    manifest_path = root / f"operand-spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_raw_link_destination(
                        source,
                        source_page_index=1,
                        annotation_index=0,
                        target_page_index=5,
                        mode=mode,
                        arguments=arguments,
                    )

                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        message,
                    ):
                        build_virtual_spread(
                            source,
                            output,
                            manifest_path,
                            direction="rtl",
                            cover_separate=True,
                        )

                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_link_quad_points_are_preserved_and_transformed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "quadpoints-source.pdf"
            output = root / "quadpoints-spread.pdf"
            manifest_path = root / "quadpoints-spread.pdf.json"
            create_odd_page_fixture(source)
            coordinates = (
                15.0,
                48.0,
                80.0,
                48.0,
                15.0,
                30.0,
                80.0,
                30.0,
                100.0,
                48.0,
                165.0,
                48.0,
                100.0,
                30.0,
                165.0,
                30.0,
            )
            set_link_quad_points(
                source,
                source_page_index=1,
                annotation_index=0,
                points=tuple(FloatObject(value) for value in coordinates),
            )

            manifest = build_virtual_spread(
                source,
                output,
                manifest_path,
                direction="rtl",
                cover_separate=True,
            )
            reader = PdfReader(str(output), strict=True)
            source_mapping = manifest["sourcePages"][1]
            annotation = reader.pages[
                source_mapping["virtualPageIndex"]
            ]["/Annots"].get_object()[0].get_object()
            actual = annotation["/QuadPoints"]
            expected: list[float] = []
            for index in range(0, len(coordinates), 2):
                expected.extend(
                    transform_point(
                        coordinates[index],
                        coordinates[index + 1],
                        source_mapping["transform"],
                    )
                )

            self.assertEqual(len(actual), len(expected))
            for actual_coordinate, expected_coordinate in zip(
                actual, expected
            ):
                self.assertAlmostEqual(
                    float(actual_coordinate), expected_coordinate, places=4
                )

    def test_malformed_link_quad_points_fail_closed(self) -> None:
        cases = (
            tuple(FloatObject(value) for value in range(6)),
            (
                TextStringObject("15"),
                *(FloatObject(value) for value in range(1, 8)),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, points in enumerate(cases):
                with self.subTest(index=index):
                    source = root / f"bad-quadpoints-source-{index}.pdf"
                    output = root / f"bad-quadpoints-spread-{index}.pdf"
                    manifest_path = (
                        root / f"bad-quadpoints-spread-{index}.pdf.json"
                    )
                    create_odd_page_fixture(source)
                    set_link_quad_points(source, 1, 0, points)

                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "/QuadPoints",
                    ):
                        build_virtual_spread(
                            source,
                            output,
                            manifest_path,
                            direction="rtl",
                            cover_separate=True,
                        )

                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_link_annotation_flags_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flags-source.pdf"
            output = root / "flags-spread.pdf"
            manifest_path = root / "flags-spread.pdf.json"
            create_odd_page_fixture(source)
            set_link_annotation_value(
                source,
                source_page_index=1,
                annotation_index=0,
                key="/F",
                value=NumberObject(34),
            )

            manifest = build_virtual_spread(
                source,
                output,
                manifest_path,
                direction="rtl",
                cover_separate=True,
            )
            reader = PdfReader(str(output), strict=True)
            mapping = manifest["sourcePages"][1]
            annotations = reader.pages[
                mapping["virtualPageIndex"]
            ]["/Annots"].get_object()
            copied = next(
                item.get_object()
                for item in annotations
                if int(item.get_object()["/SNSourcePage"]) == 1
            )
            self.assertIsInstance(copied.raw_get("/F"), NumberObject)
            self.assertEqual(int(copied["/F"]), 34)

    def test_malformed_link_annotation_flags_fail_closed(self) -> None:
        malformed_type = DictionaryObject(
            {NameObject("/F"): FloatObject(2.0)}
        )
        with self.assertRaisesRegex(
            VirtualSpreadError,
            "Invalid link annotation /F flags",
        ):
            _link_annotation_flags(malformed_type)

        cases = (
            TextStringObject("2"),
            NumberObject(-1),
            NumberObject(0x0400),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, flags in enumerate(cases):
                with self.subTest(flags=flags):
                    source = root / f"bad-flags-source-{index}.pdf"
                    output = root / f"bad-flags-spread-{index}.pdf"
                    manifest_path = root / f"bad-flags-spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_link_annotation_value(
                        source,
                        source_page_index=1,
                        annotation_index=0,
                        key="/F",
                        value=flags,
                    )

                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "link annotation /F flags",
                    ):
                        build_virtual_spread(
                            source,
                            output,
                            manifest_path,
                            direction="rtl",
                            cover_separate=True,
                        )

                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_link_rect_requires_finite_pdf_numbers(self) -> None:
        invalid_rectangles = (
            ArrayObject(
                [
                    TextStringObject("15"),
                    FloatObject(15.0),
                    FloatObject(180.0),
                    FloatObject(48.0),
                ]
            ),
            ArrayObject(
                [
                    FloatObject(float("nan")),
                    FloatObject(15.0),
                    FloatObject(180.0),
                    FloatObject(48.0),
                ]
            ),
            ArrayObject(
                [
                    FloatObject(180.0),
                    FloatObject(15.0),
                    FloatObject(15.0),
                    FloatObject(48.0),
                ]
            ),
        )
        identity = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
        for rectangle in invalid_rectangles:
            with self.subTest(rectangle=rectangle):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "link annotation /Rect",
                ):
                    _transform_rect(rectangle, identity)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bad-rect-source.pdf"
            output = root / "bad-rect-spread.pdf"
            manifest_path = root / "bad-rect-spread.pdf.json"
            create_odd_page_fixture(source)
            set_link_annotation_value(
                source,
                source_page_index=1,
                annotation_index=0,
                key="/Rect",
                value=invalid_rectangles[0],
            )

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "link annotation /Rect coordinate",
            ):
                build_virtual_spread(
                    source,
                    output,
                    manifest_path,
                    direction="rtl",
                    cover_separate=True,
                )

            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())

    def test_visible_link_border_and_highlight_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "border-source.pdf"
            output = root / "border-spread.pdf"
            manifest_path = root / "border-spread.pdf.json"
            create_odd_page_fixture(source)
            set_link_annotation_value(
                source, 1, 0, "/Border", ArrayObject([
                    FloatObject(2.0),
                    FloatObject(3.0),
                    FloatObject(4.0),
                    ArrayObject([FloatObject(5.0), FloatObject(2.0)]),
                ])
            )
            set_link_annotation_value(
                source, 1, 0, "/BS", DictionaryObject({
                    NameObject("/Type"): NameObject("/Border"),
                    NameObject("/W"): FloatObject(2.0),
                    NameObject("/S"): NameObject("/D"),
                    NameObject("/D"): ArrayObject([
                        FloatObject(3.0), FloatObject(1.0)
                    ]),
                })
            )
            set_link_annotation_value(
                source, 1, 0, "/C", ArrayObject([
                    FloatObject(0.1),
                    FloatObject(0.2),
                    FloatObject(0.3),
                ])
            )
            set_link_annotation_value(
                source, 1, 0, "/H", NameObject("/O")
            )

            manifest = build_virtual_spread(
                source, output, manifest_path, direction="rtl"
            )
            copied = output_annotation_for_source(output, manifest, 1)
            transform = manifest["sourcePages"][1]["transform"]
            a, b, c, d = transform[:4]
            scale = math.hypot(a, b)
            expected_border = [
                abs(a) * 2.0 + abs(c) * 3.0,
                abs(b) * 2.0 + abs(d) * 3.0,
                4.0 * scale,
            ]
            for actual, expected in zip(
                copied["/Border"][:3], expected_border
            ):
                self.assertAlmostEqual(float(actual), expected, places=4)
            for actual, expected in zip(
                copied["/Border"][3], (5.0 * scale, 2.0 * scale)
            ):
                self.assertAlmostEqual(float(actual), expected, places=4)
            self.assertEqual(copied["/H"], "/O")
            self.assertEqual(
                [round(float(value), 4) for value in copied["/C"]],
                [0.1, 0.2, 0.3],
            )
            border_style = copied["/BS"]
            self.assertEqual(border_style["/S"], "/D")
            self.assertAlmostEqual(
                float(border_style["/W"]), 2.0 * scale, places=4
            )
            for actual, expected in zip(
                border_style["/D"], (3.0 * scale, 1.0 * scale)
            ):
                self.assertAlmostEqual(float(actual), expected, places=4)

    def test_malformed_link_border_or_highlight_fails_closed(self) -> None:
        cases = (
            (
                "/Border",
                ArrayObject([
                    TextStringObject("0"),
                    NumberObject(0),
                    NumberObject(1),
                ]),
                "/Border value",
            ),
            ("/H", TextStringObject("/N"), "annotation /H"),
            ("/H", NameObject("/X"), "annotation /H"),
            (
                "/BS",
                DictionaryObject({NameObject("/Foo"): NumberObject(1)}),
                "Unsupported link annotation /BS entries",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (key, value, message) in enumerate(cases):
                with self.subTest(key=key, value=value):
                    source = root / f"bad-border-source-{index}.pdf"
                    output = root / f"bad-border-spread-{index}.pdf"
                    manifest_path = root / f"bad-border-spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_link_annotation_value(source, 1, 0, key, value)
                    with self.assertRaisesRegex(
                        VirtualSpreadError, message
                    ):
                        build_virtual_spread(
                            source, output, manifest_path, direction="rtl"
                        )
                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_uri_action_is_map_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "uri-source.pdf"
            output = root / "uri-spread.pdf"
            manifest_path = root / "uri-spread.pdf.json"
            create_odd_page_fixture(source)
            set_link_action(
                source,
                1,
                0,
                DictionaryObject({
                    NameObject("/Type"): NameObject("/Action"),
                    NameObject("/S"): NameObject("/URI"),
                    NameObject("/URI"): TextStringObject(
                        "https://example.test/map"
                    ),
                    NameObject("/IsMap"): BooleanObject(True),
                }),
            )

            manifest = build_virtual_spread(
                source, output, manifest_path, direction="rtl"
            )
            copied = output_annotation_for_source(output, manifest, 1)
            action = copied["/A"]
            self.assertEqual(action["/S"], "/URI")
            self.assertEqual(
                action["/URI"], "https://example.test/map"
            )
            self.assertIsInstance(action.raw_get("/IsMap"), BooleanObject)
            self.assertIs(action["/IsMap"].value, True)
            uri_link = next(
                link for link in manifest["links"]
                if link["kind"] == "uri"
            )
            self.assertEqual(
                uri_link["uri"], "https://example.test/map"
            )

    def test_uri_action_operands_and_chains_fail_closed(self) -> None:
        base = {
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://example.test"),
        }
        actions = (
            (
                DictionaryObject({
                    NameObject("/S"): NameObject("/URI"),
                    NameObject("/URI"): NumberObject(7),
                }),
                "Invalid URI link /URI string",
            ),
            (
                DictionaryObject({
                    **base,
                    NameObject("/IsMap"): NumberObject(1),
                }),
                "Invalid URI link /IsMap boolean",
            ),
            (
                DictionaryObject({
                    **base,
                    NameObject("/Next"): DictionaryObject({
                        NameObject("/S"): NameObject("/URI"),
                        NameObject("/URI"): TextStringObject(
                            "https://example.test/next"
                        ),
                    }),
                }),
                "Chained link /Next actions are unsupported",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (action, message) in enumerate(actions):
                with self.subTest(index=index):
                    source = root / f"bad-uri-source-{index}.pdf"
                    output = root / f"bad-uri-spread-{index}.pdf"
                    manifest_path = root / f"bad-uri-spread-{index}.pdf.json"
                    create_odd_page_fixture(source)
                    set_link_action(source, 1, 0, action)
                    with self.assertRaisesRegex(
                        VirtualSpreadError, message
                    ):
                        build_virtual_spread(
                            source, output, manifest_path, direction="rtl"
                        )
                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_unsupported_link_semantics_fail_closed(self) -> None:
        cases = (
            ("/AP", DictionaryObject()),
            ("/AS", NameObject("/On")),
            ("/OC", NameObject("/Layer")),
            ("/AA", DictionaryObject()),
            ("/PA", DictionaryObject()),
            ("/StructParent", NumberObject(0)),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (key, value) in enumerate(cases):
                with self.subTest(key=key):
                    source = root / f"unsupported-link-source-{index}.pdf"
                    output = root / f"unsupported-link-spread-{index}.pdf"
                    manifest_path = (
                        root / f"unsupported-link-spread-{index}.pdf.json"
                    )
                    create_odd_page_fixture(source)
                    set_link_annotation_value(source, 1, 0, key, value)
                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "Unsupported link annotation entries",
                    ):
                        build_virtual_spread(
                            source, output, manifest_path, direction="rtl"
                        )
                    self.assertFalse(output.exists())
                    self.assertFalse(manifest_path.exists())

    def test_unsupported_internal_destination_mode_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest_path = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            set_link_destination_mode(
                source,
                source_page_index=1,
                annotation_index=0,
                target_page_index=5,
                mode="/FitWindow",
                arguments=(),
            )

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Unsupported internal destination mode: /FitWindow",
            ):
                build_virtual_spread(
                    source,
                    output,
                    manifest_path,
                    direction="rtl",
                    cover_separate=True,
                )

            self.assertFalse(output.exists())
            self.assertFalse(manifest_path.exists())

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

    def test_publication_ownership_is_keyed_only_by_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "nested" / ".." / "spread.pdf"
            canonical = root / "spread.pdf"

            self.assertEqual(
                _publication_artifacts(output),
                _publication_artifacts(canonical),
            )
            marker, output_backup, manifest_backup = (
                _publication_artifacts(canonical)
            )
            self.assertEqual(marker.parent, root)
            self.assertEqual(output_backup.parent, root)
            self.assertEqual(manifest_backup.parent, root)
            self.assertEqual(
                _publication_lock_path(output),
                _publication_lock_path(canonical),
            )

    def test_custom_manifest_path_is_rejected_before_lock_or_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            runtime_manifest = root / "spread.pdf.json"
            custom_manifest = root / "custom.json"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            runtime_manifest.write_bytes(b"old-runtime-manifest")
            custom_manifest.write_bytes(b"old-custom-manifest")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Manifest path must be the runtime sibling",
            ):
                build_virtual_spread(
                    source,
                    output,
                    custom_manifest,
                    force=True,
                )

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(
                runtime_manifest.read_bytes(), b"old-runtime-manifest"
            )
            self.assertEqual(
                custom_manifest.read_bytes(), b"old-custom-manifest"
            )
            self.assertFalse(_publication_lock_path(output).exists())

    def test_output_filesystem_alias_is_rejected_before_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lexical = root / "alias.pdf"
            resolved = root / "target.pdf"

            class AliasedPath:
                def __fspath__(self) -> str:
                    return str(lexical)

                def resolve(self) -> Path:
                    return resolved

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "must not contain symlinks or filesystem aliases",
            ):
                _require_unaliased_output_path(
                    AliasedPath(),  # type: ignore[arg-type]
                )

            self.assertFalse(lexical.exists())
            self.assertFalse(resolved.exists())
            self.assertFalse(_publication_lock_path(lexical).exists())

    def test_output_alias_is_rechecked_after_publication_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            lexical_output = output.absolute()

            with mock.patch(
                "generate_virtual_spread._require_unaliased_output_path",
                side_effect=(
                    lexical_output,
                    VirtualSpreadError("simulated output alias race"),
                ),
            ) as alias_guard:
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "simulated output alias race",
                ):
                    build_virtual_spread(
                        source,
                        output,
                        manifest,
                        force=True,
                    )

            self.assertEqual(alias_guard.call_count, 2)
            self.assertFalse(output.exists())
            self.assertFalse(manifest.exists())
            self.assertTrue(_publication_lock_path(output).is_file())

    def test_publication_lock_symlink_never_touches_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            victim = root / "victim.bin"
            create_odd_page_fixture(source)
            victim.write_bytes(b"victim")
            lock_path = _publication_lock_path(output)
            try:
                lock_path.symlink_to(victim)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Publication lock must be a regular file",
            ):
                build_virtual_spread(
                    source,
                    output,
                    manifest,
                    force=True,
                )

            self.assertEqual(victim.read_bytes(), b"victim")
            self.assertTrue(lock_path.is_symlink())
            self.assertFalse(output.exists())
            self.assertFalse(manifest.exists())

    @unittest.skipIf(
        os.name == "nt",
        "Windows does not allow an open lock pathname to be unlinked",
    )
    def test_publication_lock_replacement_is_detected_while_held(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            lock_path = _publication_lock_path(output)

            with _publication_lock(output) as ownership_guard:
                lock_path.unlink()
                lock_path.write_bytes(b"replacement-lock")
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "Publication lock must remain one regular, unaliased file",
                ):
                    ownership_guard()

            self.assertEqual(lock_path.read_bytes(), b"replacement-lock")
            self.assertFalse(output.exists())

    @unittest.skipIf(
        os.name == "nt",
        "Windows does not allow an open lock pathname to be unlinked",
    )
    def test_replaced_lock_path_does_not_admit_second_publisher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            lock_path = _publication_lock_path(output)

            with _publication_lock(output):
                lock_path.unlink()
                lock_path.write_bytes(b"replacement-lock")
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "Publication is already active",
                ):
                    with _publication_lock(output):
                        self.fail(
                            "replacement lock admitted a second publisher"
                        )

            self.assertEqual(lock_path.read_bytes(), b"replacement-lock")
            self.assertFalse(output.exists())

    @unittest.skipIf(
        os.name == "nt",
        "Windows does not allow an open publication tree to be exchanged",
    )
    def test_parent_exchange_cannot_redirect_locked_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "active"
            detached = root / "detached"
            active.mkdir()
            output = active / "spread.pdf"
            staged = active / ".spread.pdf.new"
            output.write_bytes(b"old-output")
            staged.write_bytes(b"old-staged")
            real_replace = os.replace
            exchanged = False

            with _publication_lock(output) as ownership_guard:
                def exchange_then_replace(
                    source: object,
                    target: object,
                    *args: object,
                    **kwargs: object,
                ) -> None:
                    nonlocal exchanged
                    if not exchanged:
                        active.rename(detached)
                        active.mkdir()
                        (active / "spread.pdf").write_bytes(
                            b"replacement-output"
                        )
                        (active / ".spread.pdf.new").write_bytes(
                            b"replacement-staged"
                        )
                        with _publication_lock(output):
                            pass
                        exchanged = True
                    real_replace(source, target, *args, **kwargs)

                with mock.patch(
                    "generate_virtual_spread.os.replace",
                    side_effect=exchange_then_replace,
                ):
                    _durable_replace(
                        staged,
                        output,
                        ownership_guard=ownership_guard,
                    )

            self.assertTrue(exchanged)
            self.assertEqual(
                (active / "spread.pdf").read_bytes(),
                b"replacement-output",
            )
            self.assertEqual(
                (active / ".spread.pdf.new").read_bytes(),
                b"replacement-staged",
            )
            self.assertEqual(
                (detached / "spread.pdf").read_bytes(),
                b"old-staged",
            )
            self.assertFalse((detached / ".spread.pdf.new").exists())

    @unittest.skipIf(
        os.name == "nt",
        "Windows does not allow an open publication tree to be exchanged",
    )
    def test_parent_exchange_cannot_redirect_staged_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "active"
            detached = root / "detached"
            active.mkdir()
            output = active / "spread.pdf"
            staged = active / ".spread.pdf.manifest.tmp"
            staged.write_bytes(b"old-staged")
            real_open = os.open
            exchanged = False

            with _publication_lock(output) as ownership_guard:
                directory_descriptor = getattr(
                    ownership_guard, "directory_descriptor"
                )

                def exchange_then_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal exchanged
                    if (
                        not exchanged
                        and dir_fd == directory_descriptor
                        and os.fspath(path) == staged.name
                    ):
                        active.rename(detached)
                        active.mkdir()
                        (active / staged.name).write_bytes(
                            b"replacement-staged"
                        )
                        exchanged = True
                    if dir_fd is None:
                        return real_open(path, flags, mode)
                    return real_open(
                        path,
                        flags,
                        mode,
                        dir_fd=dir_fd,
                    )

                with mock.patch(
                    "generate_virtual_spread.os.open",
                    side_effect=exchange_then_open,
                ):
                    _write_json(
                        staged,
                        {"owner": "detached"},
                        ownership_guard,
                    )

            self.assertTrue(exchanged)
            self.assertEqual(
                (active / staged.name).read_bytes(),
                b"replacement-staged",
            )
            self.assertEqual(
                json.loads((detached / staged.name).read_text("utf-8")),
                {"owner": "detached"},
            )

    def test_force_rejects_directory_publication_targets(self) -> None:
        for directory_target in ("output", "manifest"):
            with self.subTest(directory_target=directory_target):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "source.pdf"
                    output = root / "spread.pdf"
                    manifest = root / "spread.pdf.json"
                    create_odd_page_fixture(source)

                    if directory_target == "output":
                        blocked = output
                        preserved_file = manifest
                        preserved_bytes = b"old-manifest"
                    else:
                        blocked = manifest
                        preserved_file = output
                        preserved_bytes = b"old-pdf"
                    blocked.mkdir()
                    sentinel = blocked / "keep.txt"
                    sentinel.write_bytes(b"keep")
                    preserved_file.write_bytes(preserved_bytes)

                    with self.assertRaisesRegex(
                        VirtualSpreadError,
                        "must be a regular file",
                    ):
                        build_virtual_spread(
                            source,
                            output,
                            manifest,
                            force=True,
                        )

                    self.assertTrue(blocked.is_dir())
                    self.assertEqual(sentinel.read_bytes(), b"keep")
                    self.assertEqual(
                        preserved_file.read_bytes(),
                        preserved_bytes,
                    )
                    self.assertFalse(
                        _publication_lock_path(output).exists()
                    )
                    self.assertFalse(any(root.glob("*.publish.json")))
                    self.assertFalse(any(root.glob("*.bak")))
                    self.assertFalse(any(root.glob("*.retired")))

    def test_concurrent_backup_directory_is_never_replaced(self) -> None:
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
            real_prepare = _prepare_publication_transaction
            created_backup: Path | None = None

            def prepare_then_race(
                staged_output: Path,
                final_output: Path,
                staged_manifest: Path,
                final_manifest: Path,
                ownership_guard: object = None,
            ) -> dict[str, object]:
                nonlocal created_backup
                transaction = real_prepare(
                    staged_output,
                    final_output,
                    staged_manifest,
                    final_manifest,
                    ownership_guard,
                )
                created_backup = Path(transaction["outputBackupPath"])
                created_backup.mkdir()
                (created_backup / "keep.txt").write_bytes(b"keep")
                return transaction

            with mock.patch(
                "generate_virtual_spread._prepare_publication_transaction",
                side_effect=prepare_then_race,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "rollback was incomplete: Output backup must be a regular file",
                ):
                    _publish_pair(
                        temporary_output,
                        output,
                        temporary_manifest,
                        manifest,
                    )

            self.assertIsNotNone(created_backup)
            assert created_backup is not None
            self.assertTrue(created_backup.is_dir())
            self.assertEqual(
                (created_backup / "keep.txt").read_bytes(),
                b"keep",
            )
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")

    def test_first_publication_rechecks_state_after_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            temporary_output = root / ".spread.pdf.new"
            temporary_manifest = root / ".spread.pdf.json.new"
            create_odd_page_fixture(source)
            temporary_output.write_bytes(b"new-pdf")
            temporary_manifest.write_bytes(b"new-manifest")

            transaction = _prepare_publication_transaction(
                temporary_output,
                output,
                temporary_manifest,
                manifest,
            )
            marker = Path(transaction["markerPath"])
            _durable_replace(temporary_manifest, manifest)

            generated = build_virtual_spread(source, output, manifest)

            self.assertEqual(generated["output"]["path"], str(output))
            self.assertTrue(output.is_file())
            self.assertTrue(manifest.is_file())
            self.assertFalse(marker.exists())
            self.assertFalse(any(root.glob("*.bak")))

    def test_staged_directory_is_rejected_before_backup_moves(self) -> None:
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
            real_prepare = _prepare_publication_transaction

            def prepare_then_replace_stage(
                staged_output: Path,
                final_output: Path,
                staged_manifest: Path,
                final_manifest: Path,
                ownership_guard: object = None,
            ) -> dict[str, object]:
                transaction = real_prepare(
                    staged_output,
                    final_output,
                    staged_manifest,
                    final_manifest,
                    ownership_guard,
                )
                staged_manifest.unlink()
                staged_manifest.mkdir()
                (staged_manifest / "keep.txt").write_bytes(b"keep")
                return transaction

            with mock.patch(
                "generate_virtual_spread._prepare_publication_transaction",
                side_effect=prepare_then_replace_stage,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "Staged manifest must be a regular file",
                ):
                    _publish_pair(
                        temporary_output,
                        output,
                        temporary_manifest,
                        manifest,
                    )

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(temporary_manifest.is_dir())
            self.assertEqual(
                (temporary_manifest / "keep.txt").read_bytes(),
                b"keep",
            )
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_published_hash_mismatch_restores_existing_pair(self) -> None:
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
            real_replace = _durable_replace
            replaced_stage = False

            def replace_with_tamper(
                source: object,
                target: object,
                *,
                replace_existing: bool = True,
                ownership_guard: object = None,
            ) -> None:
                nonlocal replaced_stage
                if (
                    not replaced_stage
                    and Path(source) == temporary_manifest
                    and Path(target) == manifest
                ):
                    temporary_manifest.write_bytes(b"tampered-manifest")
                    replaced_stage = True
                real_replace(
                    Path(source),
                    Path(target),
                    replace_existing=replace_existing,
                    ownership_guard=ownership_guard,
                )

            with mock.patch(
                "generate_virtual_spread._durable_replace",
                side_effect=replace_with_tamper,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "Published manifest SHA-256 mismatch",
                ):
                    _publish_pair(
                        temporary_output,
                        output,
                        temporary_manifest,
                        manifest,
                    )

            self.assertTrue(replaced_stage)
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(temporary_output.is_file())
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_live_publication_lock_blocks_recovery_by_second_generator(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            temporary_output = root / ".spread.pdf.new"
            temporary_manifest = root / ".spread.pdf.json.new"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            temporary_output.write_bytes(b"new-pdf")
            temporary_manifest.write_bytes(b"new-manifest")
            transaction = _prepare_publication_transaction(
                temporary_output,
                output,
                temporary_manifest,
                manifest,
            )
            marker = Path(transaction["markerPath"])
            marker_before = marker.read_bytes()

            with _publication_lock(output):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "Publication is already active",
                ):
                    build_virtual_spread(
                        source,
                        output,
                        manifest,
                        force=True,
                    )
                self.assertEqual(marker.read_bytes(), marker_before)
                self.assertEqual(output.read_bytes(), b"old-pdf")
                self.assertEqual(manifest.read_bytes(), b"old-manifest")

            self.assertEqual(
                _recover_pair_publication(output, manifest),
                "rolled_back",
            )
            self.assertFalse(marker.exists())

    def test_oversized_manifest_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")

            def write_oversized(
                path: Path,
                value: object,
                ownership_guard: object = None,
            ) -> None:
                del value
                _write_json(
                    path,
                    {"padding": "x" * MAX_MANIFEST_BYTES},
                    ownership_guard,
                )

            with mock.patch(
                "generate_virtual_spread._write_json",
                side_effect=write_oversized,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "exceeds the runtime limit",
                ):
                    build_virtual_spread(
                        source, output, manifest, force=True
                    )

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_staged_manifest_swap_to_oversized_is_rejected_at_publication_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            real_prepare = _prepare_publication_transaction
            swapped = False

            def swap_then_prepare(
                temporary_output: Path,
                output_path: Path,
                temporary_manifest: Path,
                manifest_path: Path,
                ownership_guard: object = None,
                expected_output_identity: object = None,
                expected_output_hash: str | None = None,
                expected_manifest_identity: object = None,
                expected_manifest_hash: str | None = None,
            ) -> dict[str, object]:
                nonlocal swapped
                temporary_manifest.unlink()
                temporary_manifest.write_bytes(b"x" * (MAX_MANIFEST_BYTES + 1))
                swapped = True
                return real_prepare(
                    temporary_output,
                    output_path,
                    temporary_manifest,
                    manifest_path,
                    ownership_guard,
                    expected_output_identity=expected_output_identity,
                    expected_output_hash=expected_output_hash,
                    expected_manifest_identity=expected_manifest_identity,
                    expected_manifest_hash=expected_manifest_hash,
                )

            with mock.patch(
                "generate_virtual_spread._prepare_publication_transaction",
                side_effect=swap_then_prepare,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "exceeds the runtime limit",
                ):
                    build_virtual_spread(source, output, manifest, force=True)

            self.assertTrue(swapped)
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_same_content_staged_manifest_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            real_prepare = _prepare_publication_transaction
            swapped = False

            def swap_then_prepare(
                temporary_output: Path,
                output_path: Path,
                temporary_manifest: Path,
                manifest_path: Path,
                ownership_guard: object = None,
                expected_output_identity: object = None,
                expected_output_hash: str | None = None,
                expected_manifest_identity: object = None,
                expected_manifest_hash: str | None = None,
            ) -> dict[str, object]:
                nonlocal swapped
                replacement = temporary_manifest.with_name(
                    temporary_manifest.name + ".replacement"
                )
                replacement.write_bytes(temporary_manifest.read_bytes())
                os.replace(replacement, temporary_manifest)
                swapped = True
                return real_prepare(
                    temporary_output,
                    output_path,
                    temporary_manifest,
                    manifest_path,
                    ownership_guard,
                    expected_output_identity=expected_output_identity,
                    expected_output_hash=expected_output_hash,
                    expected_manifest_identity=expected_manifest_identity,
                    expected_manifest_hash=expected_manifest_hash,
                )

            with mock.patch(
                "generate_virtual_spread._prepare_publication_transaction",
                side_effect=swap_then_prepare,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "identity changed before publication",
                ):
                    build_virtual_spread(source, output, manifest, force=True)

            self.assertTrue(swapped)
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_staged_output_swap_is_rejected_at_publication_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            real_prepare = _prepare_publication_transaction
            swapped = False

            def swap_then_prepare(
                temporary_output: Path,
                output_path: Path,
                temporary_manifest: Path,
                manifest_path: Path,
                ownership_guard: object = None,
                expected_output_identity: object = None,
                expected_output_hash: str | None = None,
                expected_manifest_identity: object = None,
                expected_manifest_hash: str | None = None,
            ) -> dict[str, object]:
                nonlocal swapped
                replacement = temporary_output.with_name(
                    temporary_output.name + ".replacement"
                )
                replacement.write_bytes(b"replacement-pdf")
                os.replace(replacement, temporary_output)
                swapped = True
                return real_prepare(
                    temporary_output,
                    output_path,
                    temporary_manifest,
                    manifest_path,
                    ownership_guard,
                    expected_output_identity=expected_output_identity,
                    expected_output_hash=expected_output_hash,
                    expected_manifest_identity=expected_manifest_identity,
                    expected_manifest_hash=expected_manifest_hash,
                )

            with mock.patch(
                "generate_virtual_spread._prepare_publication_transaction",
                side_effect=swap_then_prepare,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "Staged output SHA-256 mismatch",
                ):
                    build_virtual_spread(source, output, manifest, force=True)

            self.assertTrue(swapped)
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_same_content_staged_output_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            real_prepare = _prepare_publication_transaction
            swapped = False

            def swap_then_prepare(
                temporary_output: Path,
                output_path: Path,
                temporary_manifest: Path,
                manifest_path: Path,
                ownership_guard: object = None,
                expected_output_identity: object = None,
                expected_output_hash: str | None = None,
                expected_manifest_identity: object = None,
                expected_manifest_hash: str | None = None,
            ) -> dict[str, object]:
                nonlocal swapped
                replacement = temporary_output.with_name(
                    temporary_output.name + ".replacement"
                )
                replacement.write_bytes(temporary_output.read_bytes())
                os.replace(replacement, temporary_output)
                swapped = True
                return real_prepare(
                    temporary_output,
                    output_path,
                    temporary_manifest,
                    manifest_path,
                    ownership_guard,
                    expected_output_identity=expected_output_identity,
                    expected_output_hash=expected_output_hash,
                    expected_manifest_identity=expected_manifest_identity,
                    expected_manifest_hash=expected_manifest_hash,
                )

            with mock.patch(
                "generate_virtual_spread._prepare_publication_transaction",
                side_effect=swap_then_prepare,
            ):
                with self.assertRaisesRegex(
                    VirtualSpreadError,
                    "identity changed before publication",
                ):
                    build_virtual_spread(source, output, manifest, force=True)

            self.assertTrue(swapped)
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertFalse(any(root.glob("*.bak")))
            self.assertFalse(any(root.glob("*.publish.json")))

    def test_obsolete_marker_without_backups_is_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            marker.write_text(
                json.dumps(
                    {
                        "schema": (
                            "techrebbe.supernote."
                            "virtual-spread-publication/v1"
                        ),
                        "outputPath": str(output),
                        "manifestPath": str(manifest),
                        "outputBackupPath": str(output_backup),
                        "manifestBackupPath": str(manifest_backup),
                        "hadOutput": True,
                        "hadManifest": True,
                        "newOutputSha256": "0" * 64,
                        "newManifestSha256": "1" * 64,
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                _recover_pair_publication(output, manifest),
                "discarded",
            )
            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertFalse(marker.exists())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

    def test_legacy_marker_with_duplicate_keys_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            record = {
                "schema": (
                    "techrebbe.supernote."
                    "virtual-spread-publication/v1"
                ),
                "outputPath": str(output),
                "manifestPath": str(manifest),
                "outputBackupPath": str(output_backup),
                "manifestBackupPath": str(manifest_backup),
                "hadOutput": True,
                "hadManifest": True,
                "newOutputSha256": "0" * 64,
                "newManifestSha256": "1" * 64,
            }
            marker_text = json.dumps(record).replace(
                '"hadOutput": true',
                '"hadOutput": false, "hadOutput": true',
                1,
            )
            self.assertEqual(marker_text.count('"hadOutput"'), 2)
            marker.write_text(marker_text, encoding="utf-8")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Cannot recover ambiguous virtual-spread publication marker",
            ):
                _recover_pair_publication(output, manifest)

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(marker.is_file())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

    def test_legacy_marker_with_unknown_fields_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            marker.write_text(
                json.dumps(
                    {
                        "schema": (
                            "techrebbe.supernote."
                            "virtual-spread-publication/v1"
                        ),
                        "outputPath": str(output),
                        "manifestPath": str(manifest),
                        "outputBackupPath": str(output_backup),
                        "manifestBackupPath": str(manifest_backup),
                        "hadOutput": True,
                        "hadManifest": True,
                        "newOutputSha256": "0" * 64,
                        "newManifestSha256": "1" * 64,
                        "unexpectedRecoveryHint": "discard-marker",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Cannot recover ambiguous virtual-spread publication marker",
            ):
                _recover_pair_publication(output, manifest)

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(marker.is_file())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

    def test_obsolete_marker_with_backup_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            marker.write_text(
                json.dumps(
                    {
                        "schema": (
                            "techrebbe.supernote."
                            "virtual-spread-publication/v1"
                        ),
                        "outputPath": str(output),
                        "manifestPath": str(manifest),
                        "outputBackupPath": str(output_backup),
                        "manifestBackupPath": str(manifest_backup),
                        "hadOutput": True,
                        "hadManifest": True,
                        "newOutputSha256": "0" * 64,
                        "newManifestSha256": "1" * 64,
                    }
                ),
                encoding="utf-8",
            )
            output_backup.write_bytes(b"recovery-evidence")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Cannot recover obsolete virtual-spread publication marker",
            ):
                _recover_pair_publication(output, manifest)

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(marker.is_file())
            self.assertEqual(
                output_backup.read_bytes(),
                b"recovery-evidence",
            )
            self.assertFalse(manifest_backup.exists())

    def test_obsolete_new_pair_partial_sidecar_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            manifest.write_bytes(b"published-sidecar")
            with manifest.open("rb") as stream:
                manifest_hash = _sha256_open_file(stream)
            marker.write_text(
                json.dumps(
                    {
                        "schema": (
                            "techrebbe.supernote."
                            "virtual-spread-publication/v1"
                        ),
                        "outputPath": str(output),
                        "manifestPath": str(manifest),
                        "outputBackupPath": str(output_backup),
                        "manifestBackupPath": str(manifest_backup),
                        "hadOutput": False,
                        "hadManifest": False,
                        "newOutputSha256": "0" * 64,
                        "newManifestSha256": manifest_hash,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Cannot recover obsolete virtual-spread publication marker",
            ):
                _recover_pair_publication(output, manifest)

            self.assertFalse(output.exists())
            self.assertEqual(manifest.read_bytes(), b"published-sidecar")
            self.assertTrue(marker.is_file())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

    def test_obsolete_new_pair_complete_publication_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            output.write_bytes(b"published-output")
            manifest.write_bytes(b"published-sidecar")
            with output.open("rb") as stream:
                output_hash = _sha256_open_file(stream)
            with manifest.open("rb") as stream:
                manifest_hash = _sha256_open_file(stream)
            marker.write_text(
                json.dumps(
                    {
                        "schema": (
                            "techrebbe.supernote."
                            "virtual-spread-publication/v1"
                        ),
                        "outputPath": str(output),
                        "manifestPath": str(manifest),
                        "outputBackupPath": str(output_backup),
                        "manifestBackupPath": str(manifest_backup),
                        "hadOutput": False,
                        "hadManifest": False,
                        "newOutputSha256": output_hash,
                        "newManifestSha256": manifest_hash,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Cannot recover obsolete virtual-spread publication marker",
            ):
                _recover_pair_publication(output, manifest)

            self.assertEqual(output.read_bytes(), b"published-output")
            self.assertEqual(manifest.read_bytes(), b"published-sidecar")
            self.assertTrue(marker.is_file())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

    def test_invalid_marker_with_canonical_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            marker, output_backup, manifest_backup = _publication_artifacts(
                output
            )
            manifest.write_bytes(b"unclassified-canonical-artifact")
            marker.write_text(
                json.dumps(
                    {
                        "schema": "unsupported-publication-schema",
                        "outputPath": str(output),
                        "manifestPath": str(manifest),
                        "outputBackupPath": str(output_backup),
                        "manifestBackupPath": str(manifest_backup),
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Cannot recover invalid virtual-spread publication marker",
            ):
                _recover_pair_publication(output, manifest)

            self.assertFalse(output.exists())
            self.assertEqual(
                manifest.read_bytes(),
                b"unclassified-canonical-artifact",
            )
            self.assertTrue(marker.is_file())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

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

            real_replace = _durable_replace

            def fail_output_publication(
                source: object,
                target: object,
                *,
                replace_existing: bool = True,
                ownership_guard: object = None,
            ) -> None:
                if (
                    Path(source) == temporary_output
                    and Path(target) == output
                ):
                    raise OSError("simulated output publication failure")
                real_replace(
                    Path(source),
                    Path(target),
                    replace_existing=replace_existing,
                    ownership_guard=ownership_guard,
                )

            with mock.patch(
                "generate_virtual_spread._durable_replace",
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
    def test_next_run_recovers_interrupted_partial_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.pdf"
            output = root / "spread.pdf"
            manifest = root / "spread.pdf.json"
            temporary_output = root / ".spread.pdf.new"
            temporary_manifest = root / ".spread.pdf.json.new"
            create_odd_page_fixture(source)
            output.write_bytes(b"old-pdf")
            manifest.write_bytes(b"old-manifest")
            temporary_output.write_bytes(b"new-pdf")
            temporary_manifest.write_bytes(b"new-manifest")

            transaction = _prepare_publication_transaction(
                temporary_output,
                output,
                temporary_manifest,
                manifest,
            )
            output_backup = Path(transaction["outputBackupPath"])
            manifest_backup = Path(transaction["manifestBackupPath"])
            marker = Path(transaction["markerPath"])
            _durable_replace(output, output_backup)
            _durable_replace(manifest, manifest_backup)
            _durable_replace(temporary_manifest, manifest)

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Output already exists",
            ):
                build_virtual_spread(source, output, manifest)

            self.assertEqual(output.read_bytes(), b"old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(temporary_output.exists())
            self.assertFalse(temporary_manifest.exists())
            self.assertFalse(marker.exists())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())

    def test_recovery_rejects_tampered_backup_without_restoring_it(self) -> None:
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

            transaction = _prepare_publication_transaction(
                temporary_output,
                output,
                temporary_manifest,
                manifest,
            )
            output_backup = Path(transaction["outputBackupPath"])
            marker = Path(transaction["markerPath"])
            _durable_replace(output, output_backup)
            output_backup.write_bytes(b"tampered-old-pdf")

            with self.assertRaisesRegex(
                VirtualSpreadError,
                "Output backup SHA-256 mismatch",
            ):
                _recover_pair_publication(output, manifest)

            self.assertFalse(output.exists())
            self.assertEqual(output_backup.read_bytes(), b"tampered-old-pdf")
            self.assertEqual(manifest.read_bytes(), b"old-manifest")
            self.assertTrue(marker.is_file())

    def test_recovery_finishes_cleanup_after_complete_publication(self) -> None:
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

            transaction = _prepare_publication_transaction(
                temporary_output,
                output,
                temporary_manifest,
                manifest,
            )
            output_backup = Path(transaction["outputBackupPath"])
            manifest_backup = Path(transaction["manifestBackupPath"])
            marker = Path(transaction["markerPath"])
            _durable_replace(output, output_backup)
            _durable_replace(manifest, manifest_backup)
            _durable_replace(temporary_manifest, manifest)
            _durable_replace(temporary_output, output)

            self.assertEqual(
                _recover_pair_publication(output, manifest),
                "committed",
            )
            self.assertEqual(output.read_bytes(), b"new-pdf")
            self.assertEqual(manifest.read_bytes(), b"new-manifest")
            self.assertFalse(marker.exists())
            self.assertFalse(output_backup.exists())
            self.assertFalse(manifest_backup.exists())



if __name__ == "__main__":
    unittest.main(verbosity=2)
