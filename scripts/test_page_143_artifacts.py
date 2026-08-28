#!/usr/bin/env python3
"""Verify the committed page-143 cross-project artifact bundle."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from pypdf import PdfReader

from build_page_143_artifacts import (
    DESCRIPTOR_NAME,
    FIXTURE_DIR,
    MAPPING_FIELDS,
    REPRESENTATION_CONTRACT,
    SOURCE_NAME,
    SYNTHETIC_GOLDEN,
    V025_MERGE_COMMIT,
    WIRE_CONTRACT,
    authority_tail,
    check_bundle,
    sha256_bytes,
    sha256_canonical_text,
    sha256_file,
)
from mapping_contract import normalized_to_spread, spread_to_normalized


def strict_json(path: Path) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON value {value!r} in {path}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_constant,
        object_pairs_hook=unique_object,
    )
    if not isinstance(value, dict):
        raise AssertionError(f"Expected JSON object in {path}")
    return value


def assert_close(actual: float, expected: float, tolerance: float) -> None:
    if not math.isfinite(actual) or abs(actual - expected) > tolerance:
        raise AssertionError(
            f"Expected {expected!r} +/- {tolerance!r}, got {actual!r}"
        )


def verify_bundle_semantics() -> None:
    descriptor = strict_json(FIXTURE_DIR / DESCRIPTOR_NAME)
    source_path = FIXTURE_DIR / SOURCE_NAME
    output_path = FIXTURE_DIR / descriptor["output"]["artifactFilename"]
    sidecar_path = FIXTURE_DIR / descriptor["output"][
        "sidecarArtifactFilename"
    ]
    tail_path = FIXTURE_DIR / descriptor["pdfTailAuthorityEvidence"][
        "filename"
    ]
    sidecar = strict_json(sidecar_path)
    golden = strict_json(SYNTHETIC_GOLDEN)

    assert descriptor["schema"] == (
        "techrebbe.supernote.virtual-spread-artifacts/v1"
    )
    assert descriptor["contract"]["v025MergeCommit"] == V025_MERGE_COMMIT
    assert descriptor["contract"]["textHashCanonicalization"] == (
        "UTF-8 bytes after CRLF and CR are normalized to LF; "
        "no other normalization"
    )
    assert descriptor["indexBase"] == 0
    assert descriptor["page143SourcePageIndex"] == 2
    assert descriptor["contract"]["wireContract"]["sha256"] == (
        sha256_canonical_text(WIRE_CONTRACT)
    )
    assert descriptor["contract"]["representationContract"]["sha256"] == (
        sha256_canonical_text(REPRESENTATION_CONTRACT)
    )
    assert descriptor["contract"]["syntheticGolden"]["sha256"] == (
        sha256_canonical_text(SYNTHETIC_GOLDEN)
    )

    source = descriptor["source"]
    output = descriptor["output"]
    assert source["filename"] == source_path.name
    assert source["sha256"] == sha256_file(source_path)
    assert source["size"] == source_path.stat().st_size
    assert output["sha256"] == sha256_file(output_path)
    assert output["size"] == output_path.stat().st_size
    assert output["sidecarSha256"] == sha256_file(sidecar_path)
    assert output["sidecarSize"] == sidecar_path.stat().st_size

    source_pdf = PdfReader(source_path, strict=True)
    output_pdf = PdfReader(output_path, strict=True)
    assert len(source_pdf.pages) == source["pageCount"] == 3
    assert len(output_pdf.pages) == output["pageCount"] == 2
    for page in source_pdf.pages:
        assert [float(value) for value in page.cropbox] == source["cropBox"]
        assert int(page.get("/Rotate", 0)) == source["rotation"]
    for page in output_pdf.pages:
        assert [float(value) for value in page.mediabox] == [
            0.0,
            0.0,
            864.0,
            648.0,
        ]

    assert sidecar["schema"] == descriptor["contract"]["manifestSchema"]
    assert sidecar["generatorVersion"] == descriptor["contract"][
        "generatorVersion"
    ]
    assert sidecar["direction"] == "rtl"
    assert sidecar["coverSeparate"] is True
    assert sidecar["source"]["path"] == source_path.name
    assert sidecar["source"]["name"] == source_path.name
    assert sidecar["source"]["sha256"] == source["sha256"]
    assert sidecar["source"]["documentId"] == output["documentId"]
    assert sidecar["output"]["path"] == output["cacheBasename"]
    assert sidecar["output"]["name"] == output["cacheBasename"]
    assert sidecar["output"]["cacheBasename"] == output["cacheBasename"]
    assert sidecar["output"]["sha256"] == output["sha256"]
    assert sidecar["output"]["size"] == output["size"]
    assert sidecar["output"]["viewId"] == output["viewId"]
    assert sidecar["output"]["mappingAuthoritySha256"] == output[
        "mappingAuthoritySha256"
    ]
    assert output["cacheBasename"] == (
        f'{output["documentId"]}.{output["viewId"]}.virtual-spread.pdf'
    )
    assert output_path.name == "page-143-virtual-spread-v1.pdf"
    assert sidecar_path.name == "page-143-virtual-spread-v1.pdf.json"

    serialized_sidecar = sidecar_path.read_text(encoding="utf-8")
    assert '"inverse"' not in serialized_sidecar
    assert ":\\" not in serialized_sidecar
    assert "/Users/" not in serialized_sidecar
    assert "/home/" not in serialized_sidecar

    page_143_items = [
        item
        for item in sidecar["sourcePages"]
        if item["sourcePageIndex"] == descriptor["page143SourcePageIndex"]
    ]
    assert len(page_143_items) == 1
    page_143 = page_143_items[0]
    projection = {field: page_143[field] for field in MAPPING_FIELDS}
    assert projection == descriptor["page143Mapping"]
    assert projection == golden["mappings"][golden["page143MappingIndex"]]
    assert output["mappingAuthoritySha256"] == golden[
        "mappingAuthoritySha256"
    ]

    tolerance = descriptor["verifierRules"]["roundTripTolerance"]
    for vector in descriptor["pointRoundTrips"]:
        spread = normalized_to_spread(page_143, *vector["normalized"])
        restored = spread_to_normalized(page_143, *spread)
        for actual, expected in zip(spread, vector["spread"], strict=True):
            assert_close(actual, expected, tolerance)
        for actual, expected in zip(
            restored, vector["normalizedAfterInverse"], strict=True
        ):
            assert_close(actual, expected, tolerance)
    stroke = descriptor["strokeRoundTrip"]
    for normalized, expected_spread, expected_restored in zip(
        stroke["normalized"],
        stroke["spread"],
        stroke["normalizedAfterInverse"],
        strict=True,
    ):
        spread = normalized_to_spread(page_143, *normalized)
        restored = spread_to_normalized(page_143, *spread)
        for actual, expected in zip(spread, expected_spread, strict=True):
            assert_close(actual, expected, tolerance)
        for actual, expected in zip(
            restored, expected_restored, strict=True
        ):
            assert_close(actual, expected, tolerance)

    rules = descriptor["verifierRules"]
    assert rules["authoritativeTransform"] == (
        "forward source-to-spread only"
    )
    assert rules["androidVerifierIncludesTinyScaleOrientationFix"] is True
    assert rules["androidVerifierIncludesFarOffsetStabilityFix"] is True

    pdf_bytes = output_path.read_bytes()
    tail, authority_offset, startxref_offset = authority_tail(pdf_bytes)
    evidence = descriptor["pdfTailAuthorityEvidence"]
    assert tail == tail_path.read_bytes()
    assert evidence["sha256"] == sha256_bytes(tail)
    assert evidence["authorityBlockOffset"] == authority_offset
    assert evidence["startxrefOffset"] == startxref_offset
    assert evidence["immediatelyBeforeStartxref"] is True
    expected_markers = (
        f'%SNVirtualSpreadSourceSHA256:{source["sha256"]}\n'
        f'%SNVirtualSpreadLayoutSHA256:'
        f'{sidecar["output"]["layoutAuthoritySha256"]}\n'
        f'%SNVirtualSpreadLinksSHA256:'
        f'{sidecar["output"]["linkAuthoritySha256"]}\n'
        f'%SNVirtualSpreadMappingSHA256:'
        f'{output["mappingAuthoritySha256"]}\n'
        f'%SNVirtualSpreadViewSHA256:'
        f'{output["viewId"].removeprefix("inkbridge-view-v1-")}\n'
    ).encode("ascii")
    assert tail.startswith(expected_markers + b"startxref\n")

    cache = descriptor["cache"]
    assert cache["nativeReaderCanOpen"] is True
    assert cache["hiddenFromSupernoteDocumentsLibrary"] is True
    assert "<document-id>/<view-id>/<cache-basename>" in cache[
        "locationTemplate"
    ]


if __name__ == "__main__":
    check_bundle()
    verify_bundle_semantics()
    print("Page-143 cross-project artifacts: PASS")
