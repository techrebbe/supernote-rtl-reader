"""Frozen cross-language mapping and view-identity contract."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Mapping, Sequence
from typing import Any


MANIFEST_SCHEMA = "techrebbe.supernote.virtual-spread/v3"
MAPPING_AUTHORITY_DOMAIN = "techrebbe.supernote.virtual-spread-mapping/v1"
VIEW_IDENTITY_DOMAIN = "techrebbe.supernote.virtual-spread-view/v1"
GENERATOR_FORMAT_VERSION = (
    "techrebbe.supernote.virtual-spread-generator/v1"
)
DOCUMENT_ID_PREFIX = "inkbridge-doc-v1-"
VIEW_ID_PREFIX = "inkbridge-view-v1-"

_AUTHORITATIVE_MAPPING_FIELDS = frozenset({
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
})
_DISPLAY_ONLY_MAPPING_FIELDS = frozenset({
    "sourcePageNumber",
    "virtualPageNumber",
})
_ARRAY_LENGTHS = {
    "sourceBox": 4,
    "normalizedSourceBox": 4,
    "slot": 4,
    "destination": 4,
    "transform": 6,
}


class MappingContractError(ValueError):
    """Raised when data is not representable by the frozen wire contract."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MappingContractError(f"Invalid {label}")
    return value


def _require_index(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise MappingContractError(f"Invalid {label}")
    return value


def _require_finite(value: Any, label: str) -> float:
    if type(value) not in (int, float):
        raise MappingContractError(f"Invalid {label}")
    result = float(value)
    if not math.isfinite(result):
        raise MappingContractError(f"Invalid {label}")
    return result


def _float_bits(value: Any, label: str) -> str:
    return struct.pack(">d", _require_finite(value, label)).hex()


def _number_array(mapping: Mapping[str, Any], field: str) -> list[float]:
    raw = mapping.get(field)
    expected = _ARRAY_LENGTHS[field]
    if not isinstance(raw, list) or len(raw) != expected:
        raise MappingContractError(f"Invalid {field}")
    return [
        _require_finite(value, f"{field}[{index}]")
        for index, value in enumerate(raw)
    ]


def _validated_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(mapping, Mapping):
        raise MappingContractError("Invalid mapping record")
    keys = frozenset(mapping.keys())
    if not _AUTHORITATIVE_MAPPING_FIELDS.issubset(keys) or not keys.issubset(
        _AUTHORITATIVE_MAPPING_FIELDS | _DISPLAY_ONLY_MAPPING_FIELDS
    ):
        raise MappingContractError("Invalid mapping field set")
    source_index = _require_index(
        mapping.get("sourcePageIndex"), "sourcePageIndex"
    )
    virtual_index = _require_index(
        mapping.get("virtualPageIndex"), "virtualPageIndex"
    )
    side = mapping.get("side")
    if side not in ("left", "right"):
        raise MappingContractError("Invalid side")
    rotation = mapping.get("sourceRotation")
    if type(rotation) is not int or rotation not in (0, 90, 180, 270):
        raise MappingContractError("Invalid sourceRotation")
    if "sourcePageNumber" in mapping and (
        type(mapping["sourcePageNumber"]) is not int
        or mapping["sourcePageNumber"] != source_index + 1
    ):
        raise MappingContractError("Invalid sourcePageNumber")
    if "virtualPageNumber" in mapping and (
        type(mapping["virtualPageNumber"]) is not int
        or mapping["virtualPageNumber"] != virtual_index + 1
    ):
        raise MappingContractError("Invalid virtualPageNumber")
    values = {
        field: _number_array(mapping, field) for field in _ARRAY_LENGTHS
    }
    scale = _require_finite(mapping.get("scale"), "scale")
    if scale <= 0.0:
        raise MappingContractError("Invalid scale")
    return {
        "sourcePageIndex": source_index,
        "virtualPageIndex": virtual_index,
        "side": side,
        "sourceRotation": rotation,
        **values,
        "scale": scale,
    }


def canonical_mapping_record(mapping: Mapping[str, Any]) -> str:
    """Return one exact LF-free mapping record."""
    item = _validated_mapping(mapping)
    numeric_values = [
        *item["sourceBox"],
        *item["normalizedSourceBox"],
        *item["slot"],
        *item["destination"],
        item["scale"],
        *item["transform"],
    ]
    return "|".join([
        "page",
        str(item["sourcePageIndex"]),
        str(item["virtualPageIndex"]),
        item["side"],
        str(item["sourceRotation"]),
        *(
            _float_bits(value, f"mapping number {index}")
            for index, value in enumerate(numeric_values)
        ),
    ])


def canonical_mapping_bytes(
    mappings: Sequence[Mapping[str, Any]],
) -> bytes:
    if not isinstance(mappings, (list, tuple)) or not mappings:
        raise MappingContractError("Mappings must be a nonempty sequence")
    records: list[str] = []
    for expected_index, mapping in enumerate(mappings):
        item = _validated_mapping(mapping)
        if item["sourcePageIndex"] != expected_index:
            raise MappingContractError(
                "Mappings must be complete and ordered by sourcePageIndex"
            )
        records.append(canonical_mapping_record(mapping))
    canonical = MAPPING_AUTHORITY_DOMAIN + "\n" + "\n".join(records) + "\n"
    return canonical.encode("ascii")


def mapping_authority_sha256(
    mappings: Sequence[Mapping[str, Any]],
) -> str:
    return _sha256_hex(canonical_mapping_bytes(mappings))


def canonical_view_bytes(
    *,
    source_sha256: str,
    mapping_authority_sha256: str,
    direction: str,
    cover_separate: bool,
    spread_width: Any,
    spread_height: Any,
    gutter: Any,
    manifest_schema: str = MANIFEST_SCHEMA,
    generator_version: str = GENERATOR_FORMAT_VERSION,
) -> bytes:
    source_hash = _require_sha256(source_sha256, "source SHA-256")
    mapping_hash = _require_sha256(
        mapping_authority_sha256, "mapping authority SHA-256"
    )
    if manifest_schema != MANIFEST_SCHEMA:
        raise MappingContractError("Invalid manifest schema")
    if generator_version != GENERATOR_FORMAT_VERSION:
        raise MappingContractError("Invalid generator version")
    if direction != "rtl":
        raise MappingContractError("Invalid direction")
    if type(cover_separate) is not bool:
        raise MappingContractError("Invalid cover parity")
    spread = "|".join((
        _float_bits(spread_width, "spread width"),
        _float_bits(spread_height, "spread height"),
        _float_bits(gutter, "gutter"),
    ))
    return (
        VIEW_IDENTITY_DOMAIN
        + "\nsource|"
        + source_hash
        + "\nschema|"
        + manifest_schema
        + "\ngenerator|"
        + generator_version
        + "\ndirection|"
        + direction
        + "\ncover|"
        + ("1" if cover_separate else "0")
        + "\nspread|"
        + spread
        + "\nmapping|"
        + mapping_hash
        + "\n"
    ).encode("ascii")


def document_id(source_sha256: str) -> str:
    return DOCUMENT_ID_PREFIX + _require_sha256(
        source_sha256, "source SHA-256"
    )


def view_id(**identity: Any) -> str:
    return VIEW_ID_PREFIX + _sha256_hex(canonical_view_bytes(**identity))


def output_basename(**identity: Any) -> str:
    source_sha256 = identity.get("source_sha256")
    return (
        document_id(source_sha256)
        + "."
        + view_id(**identity)
        + ".virtual-spread.pdf"
    )


def normalized_to_source(
    mapping: Mapping[str, Any], u: Any, v: Any
) -> tuple[float, float]:
    item = _validated_mapping(mapping)
    normalized_x = _require_finite(u, "normalized x")
    normalized_y = _require_finite(v, "normalized y")
    if not (0.0 <= normalized_x <= 1.0 and 0.0 <= normalized_y <= 1.0):
        raise MappingContractError("Normalized point is outside [0,1]")
    left, bottom, right, top = item["sourceBox"]
    width = right - left
    height = top - bottom
    if width <= 0.0 or height <= 0.0:
        raise MappingContractError("Invalid sourceBox")
    rotation = item["sourceRotation"]
    if rotation == 0:
        return left + normalized_x * width, top - normalized_y * height
    if rotation == 90:
        return left + normalized_y * width, bottom + normalized_x * height
    if rotation == 180:
        return right - normalized_x * width, bottom + normalized_y * height
    return right - normalized_y * width, top - normalized_x * height


def source_to_normalized(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    item = _validated_mapping(mapping)
    source_x = _require_finite(x, "source x")
    source_y = _require_finite(y, "source y")
    left, bottom, right, top = item["sourceBox"]
    width = right - left
    height = top - bottom
    if width <= 0.0 or height <= 0.0:
        raise MappingContractError("Invalid sourceBox")
    rotation = item["sourceRotation"]
    if rotation == 0:
        return (source_x - left) / width, (top - source_y) / height
    if rotation == 90:
        return (source_y - bottom) / height, (source_x - left) / width
    if rotation == 180:
        return (right - source_x) / width, (source_y - bottom) / height
    return (top - source_y) / height, (right - source_x) / width


def source_to_spread(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    item = _validated_mapping(mapping)
    source_x = _require_finite(x, "source x")
    source_y = _require_finite(y, "source y")
    a, b, c, d, e, f = item["transform"]
    spread_x = a * source_x + c * source_y + e
    spread_y = b * source_x + d * source_y + f
    if not math.isfinite(spread_x) or not math.isfinite(spread_y):
        raise MappingContractError("Non-finite forward transform result")
    return spread_x, spread_y


def spread_to_source(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    item = _validated_mapping(mapping)
    spread_x = _require_finite(x, "spread x")
    spread_y = _require_finite(y, "spread y")
    a, b, c, d, e, f = item["transform"]
    determinant = a * d - b * c
    if not math.isfinite(determinant) or determinant == 0.0:
        raise MappingContractError("Singular forward transform")
    delta_x = spread_x - e
    delta_y = spread_y - f
    source_x = (d * delta_x - c * delta_y) / determinant
    source_y = (-b * delta_x + a * delta_y) / determinant
    if not math.isfinite(source_x) or not math.isfinite(source_y):
        raise MappingContractError("Non-finite inverse transform result")
    return source_x, source_y


def normalized_to_spread(
    mapping: Mapping[str, Any], u: Any, v: Any
) -> tuple[float, float]:
    return source_to_spread(mapping, *normalized_to_source(mapping, u, v))


def spread_to_normalized(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    return source_to_normalized(mapping, *spread_to_source(mapping, x, y))
