#!/usr/bin/env python3
"""Build the normative InkBridge/Virtual Spread page-143 artifact bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, NumberObject, RectangleObject
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "virtual_spread"))

from generate_virtual_spread import (  # noqa: E402
    LAYOUT_AUTHORITY_MARKER,
    LINK_AUTHORITY_MARKER,
    MAPPING_AUTHORITY_MARKER,
    SOURCE_AUTHORITY_MARKER,
    VIEW_AUTHORITY_MARKER,
    build_virtual_spread,
)
from mapping_contract import (  # noqa: E402
    GENERATOR_FORMAT_VERSION,
    MANIFEST_SCHEMA,
    NORMALIZED_EDGE_TOLERANCE,
    ROUND_TRIP_TOLERANCE,
    normalized_to_spread,
    spread_to_normalized,
)


FIXTURE_DIR = ROOT / "virtual_spread" / "fixtures" / "page-143-v1"
SOURCE_NAME = "page-143-source-v1.pdf"
OUTPUT_ARTIFACT_NAME = "page-143-virtual-spread-v1.pdf"
SIDECAR_ARTIFACT_NAME = "page-143-virtual-spread-v1.pdf.json"
DESCRIPTOR_NAME = "page-143-artifacts-v1.json"
TAIL_NAME = "page-143-pdf-tail-authorities-v1.txt"
NATIVE_VIEWPORT_NAME = "page-143-native-viewport-v1.json"
README_NAME = "README.md"
# Exact v0.0.26 hardware measurement from the Nomad native reader for
# zero-based Virtual Spread page 1. This is deliberately not reconstructed
# from page aspect ratio; the nonzero translation and unequal scales are the
# native PageInfo CTM/offset evidence InkBridge needs.
NOMAD_PAGE143_SPREAD_TO_NATIVE = (
    2.164006674264231,
    0.0,
    0.0,
    -2.1636211394924048,
    0.999465811965812,
    1402.0264983910781,
)
SYNTHETIC_GOLDEN = (
    ROOT / "virtual_spread" / "fixtures" / "page-143-contract-v1.json"
)
WIRE_CONTRACT = ROOT / "virtual_spread" / "MAPPING_WIRE_CONTRACT.md"
REPRESENTATION_CONTRACT = (
    ROOT / "virtual_spread" / "INKBRIDGE_REPRESENTATION_CONTRACT.md"
)
V025_MERGE_COMMIT = "025d870bd73f1133664aa37b8443feb7ce10d12d"

MAPPING_FIELDS = (
    "sourcePageIndex",
    "virtualPageIndex",
    "side",
    "sourceRotation",
    "sourceBox",
    "normalizedSourceBox",
    "slot",
    "destination",
    "scale",
    "transform",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_text_bytes(path: Path) -> bytes:
    """Return repository text with platform line endings normalized to LF."""
    return (
        path.read_text(encoding="utf-8")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .encode("utf-8")
    )


def sha256_canonical_text(path: Path) -> str:
    return sha256_bytes(canonical_text_bytes(path))


def create_source_pdf(path: Path) -> None:
    """Create a deterministic three-page, rotated Letter-size source PDF."""
    raw = io.BytesIO()
    pdf = canvas.Canvas(
        raw,
        pagesize=(612.0, 792.0),
        pageCompression=0,
        invariant=1,
        pdfVersion=(1, 4),
    )
    pdf.setTitle("InkBridge Virtual Spread page-143 fixture v1")
    pdf.setAuthor("techrebbe")
    pdf.setSubject("Normative cross-project transform fixture")
    pdf.setCreator("build_page_143_artifacts.py")
    labels = (
        "SYNTHETIC SOURCE PAGE 1",
        "SYNTHETIC SOURCE PAGE 2",
        "SYNTHETIC SOURCE PAGE 143",
    )
    for index, label in enumerate(labels):
        # Draw in the page's eventual displayed coordinate system. The source
        # page is stored as portrait Letter with /Rotate 90; this counter-
        # transform keeps the fixture labels upright in ordinary PDF viewers.
        pdf.saveState()
        pdf.translate(612.0, 0.0)
        pdf.rotate(90.0)
        pdf.setLineWidth(1.0)
        pdf.rect(36.0, 18.0, 720.0, 576.0)
        pdf.setFont("Helvetica-Bold", 22)
        pdf.drawString(72.0, 548.0, label)
        pdf.setFont("Helvetica", 12)
        pdf.drawString(
            72.0,
            524.0,
            f"sourcePageIndex={index}; CropBox=[18,36,594,756]; Rotate=90",
        )
        pdf.drawString(72.0, 500.0, "Displayed coordinates: top-left origin")
        pdf.line(72.0, 462.0, 720.0, 462.0)
        pdf.line(72.0, 462.0, 72.0, 92.0)
        pdf.setFont("Helvetica", 10)
        pdf.drawString(80.0, 447.0, "normalized x ->")
        pdf.saveState()
        pdf.translate(90.0, 432.0)
        pdf.rotate(-90.0)
        pdf.drawString(0.0, 0.0, "normalized y ->")
        pdf.restoreState()
        if index == 2:
            pdf.setFont("Helvetica-Bold", 16)
            pdf.drawString(250.0, 320.0, "PAGE-143 INK GOLDEN AREA")
            pdf.rect(220.0, 170.0, 360.0, 120.0)
        pdf.restoreState()
        pdf.showPage()
    pdf.save()

    reader = PdfReader(io.BytesIO(raw.getvalue()), strict=True)
    writer = PdfWriter()
    writer.clone_document_from_reader(reader)
    for page in writer.pages:
        page[NameObject("/CropBox")] = RectangleObject(
            (18.0, 36.0, 594.0, 756.0)
        )
        page[NameObject("/Rotate")] = NumberObject(90)
    with path.open("wb") as stream:
        writer.write(stream)


def authority_tail(pdf_bytes: bytes) -> tuple[bytes, int, int]:
    startxref = pdf_bytes.rfind(b"startxref")
    if startxref < 0:
        raise AssertionError("Generated PDF has no final startxref")
    authority_start = pdf_bytes.rfind(SOURCE_AUTHORITY_MARKER, 0, startxref)
    if authority_start < 0:
        raise AssertionError("Generated PDF has no source authority marker")
    tail = pdf_bytes[authority_start:]
    required = (
        SOURCE_AUTHORITY_MARKER,
        LAYOUT_AUTHORITY_MARKER,
        LINK_AUTHORITY_MARKER,
        MAPPING_AUTHORITY_MARKER,
        VIEW_AUTHORITY_MARKER,
    )
    for marker in required:
        if tail.count(marker) != 1:
            raise AssertionError(f"Invalid authority marker count: {marker!r}")
    expected_order = [tail.index(marker) for marker in required]
    if expected_order != sorted(expected_order):
        raise AssertionError("PDF authority markers are out of order")
    return tail, authority_start, startxref


def normalized_sidecar(manifest: dict[str, Any]) -> bytes:
    """Remove host paths while preserving every authenticated field."""
    portable = json.loads(json.dumps(manifest))
    portable["source"]["path"] = portable["source"]["name"]
    portable["output"]["path"] = portable["output"]["cacheBasename"]
    portable["output"]["name"] = portable["output"]["cacheBasename"]
    return (
        json.dumps(portable, indent=2, sort_keys=True, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def mapping_projection(item: dict[str, Any]) -> dict[str, Any]:
    return {field: item[field] for field in MAPPING_FIELDS}


def build_bundle(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / SOURCE_NAME
    create_source_pdf(source)

    probe = directory / "page-143-probe.pdf"
    probe_manifest = Path(str(probe) + ".json")
    first = build_virtual_spread(
        source,
        probe,
        probe_manifest,
        direction="rtl",
        cover_separate=True,
        spread_width=864.0,
        spread_height=648.0,
        gutter=0.0,
    )
    cache_basename = first["output"]["cacheBasename"]
    cache_output = directory / cache_basename
    cache_sidecar = Path(str(cache_output) + ".json")
    manifest = build_virtual_spread(
        source,
        cache_output,
        cache_sidecar,
        direction="rtl",
        cover_separate=True,
        spread_width=864.0,
        spread_height=648.0,
        gutter=0.0,
    )
    cache_sidecar.write_bytes(normalized_sidecar(manifest))

    # The production cache basename is deliberately long because it carries the
    # document and view identities. Tracking that name inside the repository,
    # however, prevents checkout with Git for Windows' default MAX_PATH policy.
    # Preserve the exact generated bytes under short artifact names; the
    # authenticated cache basename remains in the sidecar and descriptor and is
    # materialized by the generator for verification above.
    output = directory / OUTPUT_ARTIFACT_NAME
    sidecar = directory / SIDECAR_ARTIFACT_NAME
    cache_output.replace(output)
    cache_sidecar.replace(sidecar)

    golden = json.loads(SYNTHETIC_GOLDEN.read_text(encoding="utf-8"))
    mappings = [mapping_projection(item) for item in manifest["sourcePages"]]
    if mappings != golden["mappings"]:
        raise AssertionError("Generated mappings differ from frozen golden")
    if (
        manifest["output"]["mappingAuthoritySha256"]
        != golden["mappingAuthoritySha256"]
    ):
        raise AssertionError("Generated mapping authority differs from golden")

    page_143 = mappings[golden["page143MappingIndex"]]
    point_vectors: list[dict[str, list[float]]] = []
    normalized_points = ([0.0, 0.0], [0.25, 0.5], [1.0, 1.0])
    for normalized in normalized_points:
        spread = list(normalized_to_spread(page_143, *normalized))
        restored = list(spread_to_normalized(page_143, *spread))
        point_vectors.append({
            "normalized": normalized,
            "spread": spread,
            "normalizedAfterInverse": restored,
        })
    stroke_normalized = [[0.1, 0.2], [0.5, 0.5], [0.9, 0.8]]
    stroke_spread = [
        list(normalized_to_spread(page_143, *point))
        for point in stroke_normalized
    ]
    stroke_restored = [
        list(spread_to_normalized(page_143, *point))
        for point in stroke_spread
    ]

    output_bytes = output.read_bytes()
    tail, authority_offset, startxref_offset = authority_tail(output_bytes)
    tail_path = directory / TAIL_NAME
    tail_path.write_bytes(tail)
    sidecar_bytes = sidecar.read_bytes()
    descriptor = {
        "schema": "techrebbe.supernote.virtual-spread-artifacts/v1",
        "contract": {
            "v025MergeCommit": V025_MERGE_COMMIT,
            "manifestSchema": MANIFEST_SCHEMA,
            "generatorVersion": GENERATOR_FORMAT_VERSION,
            "textHashCanonicalization": (
                "UTF-8 bytes after CRLF and CR are normalized to LF; "
                "no other normalization"
            ),
            "wireContract": {
                "path": "../../MAPPING_WIRE_CONTRACT.md",
                "sha256": sha256_canonical_text(WIRE_CONTRACT),
            },
            "representationContract": {
                "path": "../../INKBRIDGE_REPRESENTATION_CONTRACT.md",
                "sha256": sha256_canonical_text(REPRESENTATION_CONTRACT),
            },
            "syntheticGolden": {
                "path": "../page-143-contract-v1.json",
                "sha256": sha256_canonical_text(SYNTHETIC_GOLDEN),
            },
        },
        "indexBase": 0,
        "page143SourcePageIndex": 2,
        "source": {
            "filename": source.name,
            "sha256": sha256_file(source),
            "size": source.stat().st_size,
            "pageCount": 3,
            "cropBox": [18.0, 36.0, 594.0, 756.0],
            "rotation": 90,
        },
        "output": {
            "artifactFilename": output.name,
            "sha256": sha256_file(output),
            "size": output.stat().st_size,
            "pageCount": manifest["output"]["pageCount"],
            "sidecarArtifactFilename": sidecar.name,
            "sidecarSha256": sha256_bytes(sidecar_bytes),
            "sidecarSize": len(sidecar_bytes),
            "documentId": manifest["source"]["documentId"],
            "mappingAuthoritySha256": manifest["output"][
                "mappingAuthoritySha256"
            ],
            "viewId": manifest["output"]["viewId"],
            "cacheBasename": manifest["output"]["cacheBasename"],
        },
        "pdfTailAuthorityEvidence": {
            "filename": tail_path.name,
            "sha256": sha256_bytes(tail),
            "authorityBlockOffset": authority_offset,
            "startxrefOffset": startxref_offset,
            "immediatelyBeforeStartxref": True,
            "sourceSha256": manifest["source"]["sha256"],
            "layoutAuthoritySha256": manifest["output"][
                "layoutAuthoritySha256"
            ],
            "linkAuthoritySha256": manifest["output"][
                "linkAuthoritySha256"
            ],
            "mappingAuthoritySha256": manifest["output"][
                "mappingAuthoritySha256"
            ],
            "viewSha256": manifest["output"]["viewId"].removeprefix(
                "inkbridge-view-v1-"
            ),
        },
        "page143Mapping": page_143,
        "pointRoundTrips": point_vectors,
        "strokeRoundTrip": {
            "normalized": stroke_normalized,
            "spread": stroke_spread,
            "normalizedAfterInverse": stroke_restored,
        },
        "verifierRules": {
            "coordinateSystem": {
                "space": "displayed-cropbox-normalized",
                "origin": "top-left",
                "xAxis": "right",
                "yAxis": "down",
                "bounds": [0.0, 1.0],
            },
            "normalizedEdgeTolerance": NORMALIZED_EDGE_TOLERANCE,
            "roundTripTolerance": ROUND_TRIP_TOLERANCE,
            "canonicalFloatEncoding": (
                "lowercase hexadecimal of the exact big-endian IEEE-754 "
                "binary64 bits; signed zero is preserved"
            ),
            "authoritativeTransform": "forward source-to-spread only",
            "inverse": "derived locally and rejected if singular or unstable",
            "quarterTurns": (
                "rotation is exactly 0, 90, 180, or 270 and zero CTM "
                "coefficients are exact binary64 zero"
            ),
            "orientation": "forward CTM determinant must be positive",
            "numericStability": (
                "forward/inverse probes must remain finite and round-trip "
                "within 1e-12; far-offset unstable mappings fail closed"
            ),
            "androidVerifierIncludesTinyScaleOrientationFix": True,
            "androidVerifierIncludesFarOffsetStabilityFix": True,
        },
        "cache": {
            "locationTemplate": (
                "/storage/emulated/0/.inkbridge/virtual-spread/v1/"
                "<document-id>/<view-id>/<cache-basename>"
            ),
            "nativeReaderCanOpen": True,
            "hiddenFromSupernoteDocumentsLibrary": True,
            "nomediaRecommendedForGenericAndroidMediaIndexes": True,
            "activation": (
                "publish the PDF and exact .json sibling under cacheBasename; "
                "the Android verifier recomputes sidecar, PDF-tail, mapping, "
                "view, output-hash, and open-MuPDF authorities before activation"
            ),
        },
        "diagnosticPathNormalization": (
            "source.path and output.path are non-authoritative diagnostics "
            "normalized to filenames in the distributed sidecar"
        ),
    }
    descriptor_path = directory / DESCRIPTOR_NAME
    descriptor_path.write_text(
        json.dumps(descriptor, indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    native_viewport_path = directory / NATIVE_VIEWPORT_NAME
    native_viewport_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "authority": "rtl-reader-native-viewport-v1",
                "documentId": descriptor["output"]["documentId"],
                "viewId": descriptor["output"]["viewId"],
                "virtualPageIndex": 1,
                "nativePageSize": [1872, 1404],
                "spreadToNative": list(
                    NOMAD_PAGE143_SPREAD_TO_NATIVE
                ),
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    readme_path = directory / README_NAME
    readme_path.write_text(
        "# Page-143 Virtual Spread fixture v1\n\n"
        "This directory is the normative byte-level handoff from RTL Reader "
        "v0.0.25 to InkBridge. `page-143-source-v1.pdf` contains three physical "
        "pages; zero-based source page index 2 is the synthetic page-143 stand-in.\n\n"
        "The generated PDF and schema-v3 sidecar are tracked under short "
        "artifact names so a default Windows Git checkout remains portable. "
        "Their bytes are unchanged from the production pair; the descriptor "
        "and sidecar retain the exact authenticated cache basename that must "
        "be materialized for cache activation. "
        "`page-143-artifacts-v1.json` records stable hashes, mapping/view "
        "identities, the page-143 forward mapping, derived inverse round trips, "
        "verifier rules, and the hardware-proven cache assumptions. "
        "`page-143-pdf-tail-authorities-v1.txt` is the exact generated PDF tail "
        "beginning with the five authenticated authority markers immediately "
        "before `startxref`.\n\n"
        "`page-143-native-viewport-v1.json` is the exact seven-field native "
        "viewport descriptor measured by v0.0.26 for zero-based Virtual Spread "
        "page 1 on the Nomad's 1872-by-1404 persistent page canvas. It preserves "
        "the native PageInfo fit and translation rather than inferring them from "
        "page aspect ratio. It is a cross-project "
        "golden vector, not runtime authority: production InkBridge must still "
        "obtain a fresh matching descriptor from the v0.0.26 companion provider "
        "and validate it against `PluginFileAPI.getPageSize` and the active "
        "schema-v3 evidence.\n\n"
        "Contract and synthetic-golden text hashes use UTF-8 bytes with CRLF "
        "and CR normalized to LF and no other normalization. "
        "Only the forward source-to-spread transform is authoritative. InkBridge "
        "must derive and validate the inverse. The sidecar's diagnostic `path` "
        "fields are normalized to filenames so the fixture carries no host path; "
        "they are not mapping, view, cache, or activation authority.\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "source": source,
        "output": output,
        "sidecar": sidecar,
        "descriptor": descriptor_path,
        "tail": tail_path,
        "native_viewport": native_viewport_path,
        "readme": readme_path,
    }


def check_bundle() -> None:
    with tempfile.TemporaryDirectory(prefix="page-143-artifacts-") as root:
        generated = build_bundle(Path(root))
        for label, path in generated.items():
            expected = FIXTURE_DIR / path.name
            if not expected.is_file():
                raise AssertionError(f"Missing committed {label}: {expected}")
            if path.read_bytes() != expected.read_bytes():
                raise AssertionError(f"Committed {label} is not reproducible")


def write_bundle() -> None:
    with tempfile.TemporaryDirectory(prefix="page-143-artifacts-") as root:
        generated = build_bundle(Path(root))
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        expected_names = {path.name for path in generated.values()}
        for existing in FIXTURE_DIR.iterdir():
            if existing.is_file() and existing.name not in expected_names:
                existing.unlink()
        for path in generated.values():
            shutil.copyfile(path, FIXTURE_DIR / path.name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the committed fixture bundle",
    )
    args = parser.parse_args()
    if args.write:
        write_bundle()
    else:
        check_bundle()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
