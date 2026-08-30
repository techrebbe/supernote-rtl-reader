"""Frozen cross-language mapping and view-identity contract."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Mapping, Sequence
from typing import Any


MANIFEST_SCHEMA = "techrebbe.supernote.virtual-spread/v3"
NAVIGATION_MANIFEST_SCHEMA = "techrebbe.supernote.virtual-spread/v4"
MAPPING_AUTHORITY_DOMAIN = "techrebbe.supernote.virtual-spread-mapping/v1"
VIEW_IDENTITY_DOMAIN = "techrebbe.supernote.virtual-spread-view/v1"
GENERATOR_FORMAT_VERSION = (
    "techrebbe.supernote.virtual-spread-generator/v1"
)
NAVIGATION_GENERATOR_FORMAT_VERSION = (
    "techrebbe.supernote.virtual-spread-generator/v2"
)
NAVIGATION_VIEW_IDENTITY_DOMAIN = (
    "techrebbe.supernote.virtual-spread-view/v2"
)
DOCUMENT_ID_PREFIX = "inkbridge-doc-v1-"
VIEW_ID_PREFIX = "inkbridge-view-v1-"
NORMALIZED_EDGE_TOLERANCE = 1.0e-12
ROUND_TRIP_TOLERANCE = 1.0e-12
GEOMETRY_RELATIVE_TOLERANCE = 1.0e-7
JAVA_INT32_MAX = 2_147_483_647

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
    if (
        type(value) is not int
        or value < 0
        or value > JAVA_INT32_MAX
    ):
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


def _nearly_equal(left: float, right: float) -> bool:
    if not math.isfinite(left) or not math.isfinite(right):
        return False
    magnitude = max(1.0, abs(left), abs(right))
    return abs(left - right) <= GEOMETRY_RELATIVE_TOLERANCE * magnitude


def _require_positive_rectangle(values: list[float], label: str) -> None:
    left, bottom, right, top = values
    if left >= right or bottom >= top:
        raise MappingContractError(f"Invalid {label}")


def _rectangle_nearly_equals(
    actual: list[float], expected: tuple[float, float, float, float]
) -> bool:
    return all(
        _nearly_equal(actual_value, expected_value)
        for actual_value, expected_value in zip(actual, expected)
    )


def _raw_normalized_to_source(
    item: Mapping[str, Any], normalized_x: float, normalized_y: float
) -> tuple[float, float]:
    left, bottom, right, top = item["sourceBox"]
    width = right - left
    height = top - bottom
    rotation = item["sourceRotation"]
    if rotation == 0:
        return left + normalized_x * width, top - normalized_y * height
    if rotation == 90:
        return left + normalized_y * width, bottom + normalized_x * height
    if rotation == 180:
        return right - normalized_x * width, bottom + normalized_y * height
    return right - normalized_y * width, top - normalized_x * height


def _raw_source_to_normalized(
    item: Mapping[str, Any], source_x: float, source_y: float
) -> tuple[float, float]:
    left, bottom, right, top = item["sourceBox"]
    width = right - left
    height = top - bottom
    rotation = item["sourceRotation"]
    if rotation == 0:
        return (source_x - left) / width, (top - source_y) / height
    if rotation == 90:
        return (source_y - bottom) / height, (source_x - left) / width
    if rotation == 180:
        return (right - source_x) / width, (source_y - bottom) / height
    return (top - source_y) / height, (right - source_x) / width


def _raw_source_to_spread(
    item: Mapping[str, Any], source_x: float, source_y: float
) -> tuple[float, float]:
    a, b, c, d, e, f = item["transform"]
    return (
        a * source_x + c * source_y + e,
        b * source_x + d * source_y + f,
    )


def _raw_spread_to_source(
    item: Mapping[str, Any], spread_x: float, spread_y: float
) -> tuple[float, float]:
    a, b, c, d, e, f = item["transform"]
    determinant = a * d - b * c
    delta_x = spread_x - e
    delta_y = spread_y - f
    return (
        (d * delta_x - c * delta_y) / determinant,
        (-b * delta_x + a * delta_y) / determinant,
    )


def _require_numerically_stable_transform(item: Mapping[str, Any]) -> None:
    destination = item["destination"]
    destination_width = destination[2] - destination[0]
    destination_height = destination[3] - destination[1]
    probes = (
        (0.0, 0.0),
        (0.25, 0.5),
        (0.5, 0.5),
        (0.75, 0.25),
        (1.0, 1.0),
    )
    for normalized_x, normalized_y in probes:
        source = _raw_normalized_to_source(
            item, normalized_x, normalized_y
        )
        spread = _raw_source_to_spread(item, *source)
        expected_spread = (
            destination[0] + normalized_x * destination_width,
            destination[3] - normalized_y * destination_height,
        )
        restored_source = _raw_spread_to_source(item, *spread)
        restored_normalized = _raw_source_to_normalized(
            item, *restored_source
        )
        if (
            any(
                not math.isfinite(value)
                for value in (*spread, *restored_source)
            )
            or any(
                abs(actual - expected) > ROUND_TRIP_TOLERANCE
                for actual, expected in zip(spread, expected_spread)
            )
            or any(
                abs(actual - expected) > ROUND_TRIP_TOLERANCE
                for actual, expected in zip(
                    restored_normalized, (normalized_x, normalized_y)
                )
            )
        ):
            raise MappingContractError(
                "Mapping transform is numerically unstable"
            )


def _require_semantic_geometry(item: Mapping[str, Any]) -> None:
    source_box = item["sourceBox"]
    normalized_box = item["normalizedSourceBox"]
    slot = item["slot"]
    destination = item["destination"]
    for values, label in (
        (source_box, "sourceBox"),
        (normalized_box, "normalizedSourceBox"),
        (slot, "slot"),
        (destination, "destination"),
    ):
        _require_positive_rectangle(values, label)
    if (
        destination[0] < slot[0] - GEOMETRY_RELATIVE_TOLERANCE
        or destination[1] < slot[1] - GEOMETRY_RELATIVE_TOLERANCE
        or destination[2] > slot[2] + GEOMETRY_RELATIVE_TOLERANCE
        or destination[3] > slot[3] + GEOMETRY_RELATIVE_TOLERANCE
    ):
        raise MappingContractError("Destination is outside slot")

    source_width = source_box[2] - source_box[0]
    source_height = source_box[3] - source_box[1]
    normalized_width = normalized_box[2] - normalized_box[0]
    normalized_height = normalized_box[3] - normalized_box[1]
    quarter_turn = item["sourceRotation"] in (90, 270)
    if not _nearly_equal(
        normalized_width,
        source_height if quarter_turn else source_width,
    ) or not _nearly_equal(
        normalized_height,
        source_width if quarter_turn else source_height,
    ):
        raise MappingContractError(
            "normalizedSourceBox disagrees with source rotation"
        )

    slot_width = slot[2] - slot[0]
    slot_height = slot[3] - slot[1]
    expected_scale = min(
        slot_width / normalized_width,
        slot_height / normalized_height,
    )
    expected_width = normalized_width * expected_scale
    expected_height = normalized_height * expected_scale
    expected_left = slot[0] + (slot_width - expected_width) / 2.0
    expected_bottom = slot[1] + (slot_height - expected_height) / 2.0
    expected_destination = (
        expected_left,
        expected_bottom,
        expected_left + expected_width,
        expected_bottom + expected_height,
    )
    if not _nearly_equal(item["scale"], expected_scale):
        raise MappingContractError("Invalid generator scale")
    if not _rectangle_nearly_equals(destination, expected_destination):
        raise MappingContractError("Destination is not generator-centered")

    scale = item["scale"]
    rotation = item["sourceRotation"]
    a, b, c, d, _, _ = item["transform"]
    expected_linear = {
        0: (scale, 0.0, 0.0, scale),
        90: (0.0, -scale, scale, 0.0),
        180: (-scale, 0.0, 0.0, -scale),
        270: (0.0, scale, -scale, 0.0),
    }[rotation]
    determinant = a * d - b * c
    if (
        not math.isfinite(determinant)
        or determinant <= 0.0
        or any(
            struct.pack(">d", actual) != struct.pack(">d", expected)
            for actual, expected in zip((a, b, c, d), expected_linear)
        )
    ):
        raise MappingContractError(
            "Transform disagrees with source rotation and scale"
        )

    corners = (
        (source_box[0], source_box[1]),
        (source_box[2], source_box[1]),
        (source_box[2], source_box[3]),
        (source_box[0], source_box[3]),
    )
    transformed = [
        _raw_source_to_spread(item, *point) for point in corners
    ]
    if any(
        not math.isfinite(value)
        for point in transformed
        for value in point
    ):
        raise MappingContractError("Non-finite transform result")
    transformed_rectangle = (
        min(point[0] for point in transformed),
        min(point[1] for point in transformed),
        max(point[0] for point in transformed),
        max(point[1] for point in transformed),
    )
    if not _rectangle_nearly_equals(destination, transformed_rectangle):
        raise MappingContractError(
            "Transform does not map sourceBox to destination"
        )
    _require_numerically_stable_transform(item)


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
    item = {
        "sourcePageIndex": source_index,
        "virtualPageIndex": virtual_index,
        "side": side,
        "sourceRotation": rotation,
        **values,
        "scale": scale,
    }
    _require_semantic_geometry(item)
    return item


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
    navigation_authority_sha256: str | None = None,
    remove_adjacent_page_links: bool = False,
) -> bytes:
    source_hash = _require_sha256(source_sha256, "source SHA-256")
    mapping_hash = _require_sha256(
        mapping_authority_sha256, "mapping authority SHA-256"
    )
    legacy = (
        manifest_schema == MANIFEST_SCHEMA
        and generator_version == GENERATOR_FORMAT_VERSION
    )
    navigation = (
        manifest_schema == NAVIGATION_MANIFEST_SCHEMA
        and generator_version == NAVIGATION_GENERATOR_FORMAT_VERSION
    )
    if not (legacy or navigation):
        raise MappingContractError("Invalid manifest/generator version pair")
    if direction != "rtl":
        raise MappingContractError("Invalid direction")
    if type(cover_separate) is not bool:
        raise MappingContractError("Invalid cover parity")
    spread = "|".join((
        _float_bits(spread_width, "spread width"),
        _float_bits(spread_height, "spread height"),
        _float_bits(gutter, "gutter"),
    ))
    if type(remove_adjacent_page_links) is not bool:
        raise MappingContractError("Invalid adjacent-link policy")
    if legacy:
        if navigation_authority_sha256 is not None:
            raise MappingContractError(
                "Legacy view identity cannot include navigation authority"
            )
        if remove_adjacent_page_links:
            raise MappingContractError(
                "Legacy view identity cannot filter adjacent-page links"
            )
        domain = VIEW_IDENTITY_DOMAIN
        navigation_suffix = ""
    else:
        navigation_hash = _require_sha256(
            navigation_authority_sha256,
            "navigation authority SHA-256",
        )
        domain = NAVIGATION_VIEW_IDENTITY_DOMAIN
        navigation_suffix = (
            "\nnavigation|"
            + navigation_hash
            + "\nremove-adjacent-page-links|"
            + ("1" if remove_adjacent_page_links else "0")
        )
    return (
        domain
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
        + navigation_suffix
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
    return _raw_normalized_to_source(item, normalized_x, normalized_y)


def source_to_normalized(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    item = _validated_mapping(mapping)
    source_x = _require_finite(x, "source x")
    source_y = _require_finite(y, "source y")
    result = _raw_source_to_normalized(item, source_x, source_y)
    bounded = []
    for label, value in zip(("x", "y"), result):
        if (
            value < -NORMALIZED_EDGE_TOLERANCE
            or value > 1.0 + NORMALIZED_EDGE_TOLERANCE
        ):
            raise MappingContractError(
                f"Normalized {label} is outside [0,1]"
            )
        bounded.append(min(1.0, max(0.0, value)))
    return bounded[0], bounded[1]


def source_to_spread(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    item = _validated_mapping(mapping)
    source_x = _require_finite(x, "source x")
    source_y = _require_finite(y, "source y")
    spread_x, spread_y = _raw_source_to_spread(item, source_x, source_y)
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
    source_x, source_y = _raw_spread_to_source(item, spread_x, spread_y)
    if not math.isfinite(source_x) or not math.isfinite(source_y):
        raise MappingContractError("Non-finite inverse transform result")
    return source_x, source_y


def normalized_to_spread(
    mapping: Mapping[str, Any], u: Any, v: Any
) -> tuple[float, float]:
    normalized_x = _require_finite(u, "normalized x")
    normalized_y = _require_finite(v, "normalized y")
    spread = source_to_spread(
        mapping,
        *normalized_to_source(mapping, normalized_x, normalized_y),
    )
    restored = source_to_normalized(
        mapping, *spread_to_source(mapping, *spread)
    )
    if any(
        abs(actual - expected) > ROUND_TRIP_TOLERANCE
        for actual, expected in zip(
            restored, (normalized_x, normalized_y)
        )
    ):
        raise MappingContractError(
            "Forward/inverse round trip exceeds tolerance"
        )
    return spread


def spread_to_normalized(
    mapping: Mapping[str, Any], x: Any, y: Any
) -> tuple[float, float]:
    spread_x = _require_finite(x, "spread x")
    spread_y = _require_finite(y, "spread y")
    normalized = source_to_normalized(
        mapping, *spread_to_source(mapping, spread_x, spread_y)
    )
    restored = source_to_spread(
        mapping, *normalized_to_source(mapping, *normalized)
    )
    if any(
        abs(actual - expected) > ROUND_TRIP_TOLERANCE
        for actual, expected in zip(restored, (spread_x, spread_y))
    ):
        raise MappingContractError(
            "Inverse/forward round trip exceeds tolerance"
        )
    return normalized
