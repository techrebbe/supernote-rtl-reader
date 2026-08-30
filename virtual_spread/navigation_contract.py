"""Versioned bookmark authority for Virtual Spread navigation."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Mapping, Sequence
from typing import Any


NAVIGATION_AUTHORITY_DOMAIN = (
    "techrebbe.supernote.virtual-spread-navigation/v1"
)
_SIDES = frozenset({"left", "right"})
_TARGET_VIEWS = frozenset({"fit-source-page"})
_DESTINATION_MODES = frozenset({"/FitR"})


class NavigationContractError(ValueError):
    """Raised when bookmark authority cannot be canonicalized safely."""


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value > 2_147_483_647:
        raise NavigationContractError(f"Invalid {label}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise NavigationContractError(f"Invalid {label}")
    return value


def _float_bits(value: Any, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NavigationContractError(f"Invalid {label}")
    number = float(value)
    if not math.isfinite(number):
        raise NavigationContractError(f"Invalid {label}")
    return struct.pack(">d", number).hex()


def _title_hash(value: Any) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise NavigationContractError("Invalid bookmark title")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise NavigationContractError("Invalid bookmark title") from error
    return hashlib.sha256(encoded).hexdigest()


def canonical_navigation_bytes(
    outlines: Sequence[Mapping[str, Any]],
    *,
    remove_adjacent_page_links: bool,
    removed_adjacent_page_link_count: int,
    retained_link_count: int,
) -> bytes:
    remove = _boolean(
        remove_adjacent_page_links, "adjacent-page-link filter state"
    )
    removed = _integer(
        removed_adjacent_page_link_count, "removed adjacent-page-link count"
    )
    retained = _integer(retained_link_count, "retained link count")
    if not remove and removed != 0:
        raise NavigationContractError(
            "Removed adjacent-page links require the filter"
        )
    records = [
        NAVIGATION_AUTHORITY_DOMAIN,
        "config|{}|{}|{}".format(
            1 if remove else 0,
            removed,
            retained,
        ),
    ]
    for expected_index, outline in enumerate(outlines):
        if not isinstance(outline, Mapping):
            raise NavigationContractError("Invalid bookmark record")
        expected_keys = {
            "outlineIndex", "parentOutlineIndex", "title", "isOpen",
            "bold", "italic", "color", "destination",
        }
        if set(outline) != expected_keys:
            raise NavigationContractError("Invalid bookmark record fields")
        index = _integer(outline["outlineIndex"], "bookmark index")
        if index != expected_index:
            raise NavigationContractError("Bookmarks are not in canonical order")
        parent = outline["parentOutlineIndex"]
        if parent is None:
            parent_field = "-"
        else:
            parent_index = _integer(parent, "bookmark parent index")
            if parent_index >= index:
                raise NavigationContractError("Invalid bookmark parent index")
            parent_field = str(parent_index)
        color = outline["color"]
        if not isinstance(color, Sequence) or isinstance(color, (str, bytes)):
            raise NavigationContractError("Invalid bookmark color")
        if len(color) != 3:
            raise NavigationContractError("Invalid bookmark color")
        canonical_color = []
        for component in color:
            bits = _float_bits(component, "bookmark color")
            number = float(component)
            if not 0.0 <= number <= 1.0:
                raise NavigationContractError("Invalid bookmark color")
            canonical_color.append(bits)
        common = [
            "outline", str(index), parent_field,
            "1" if _boolean(outline["isOpen"], "bookmark open state") else "0",
            "1" if _boolean(outline["bold"], "bookmark bold state") else "0",
            "1" if _boolean(outline["italic"], "bookmark italic state") else "0",
            *canonical_color,
            _title_hash(outline["title"]),
        ]
        destination = outline["destination"]
        if destination is None:
            records.append("|".join((*common, "-")))
            continue
        if not isinstance(destination, Mapping):
            raise NavigationContractError("Invalid bookmark destination")
        expected_destination_keys = {
            "sourcePageIndex", "virtualPageIndex", "side", "targetView",
            "mode", "operands",
        }
        if set(destination) != expected_destination_keys:
            raise NavigationContractError(
                "Invalid bookmark destination fields"
            )
        side = destination["side"]
        target_view = destination["targetView"]
        mode = destination["mode"]
        if side not in _SIDES:
            raise NavigationContractError("Invalid bookmark destination side")
        if target_view not in _TARGET_VIEWS:
            raise NavigationContractError("Invalid bookmark target view")
        if mode not in _DESTINATION_MODES:
            raise NavigationContractError("Invalid bookmark destination mode")
        operands = destination["operands"]
        if not isinstance(operands, Sequence) or isinstance(
            operands, (str, bytes)
        ):
            raise NavigationContractError("Invalid bookmark operands")
        if mode == "/FitR" and (
            len(operands) != 4 or any(value is None for value in operands)
        ):
            raise NavigationContractError("Invalid bookmark operands")
        canonical_operands = []
        for operand in operands:
            canonical_operands.append(
                "null" if operand is None
                else _float_bits(operand, "bookmark destination operand")
            )
        records.append("|".join((
            *common,
            str(_integer(destination["sourcePageIndex"], "source page index")),
            str(_integer(destination["virtualPageIndex"], "virtual page index")),
            side,
            target_view,
            mode,
            str(len(canonical_operands)),
            *canonical_operands,
        )))
    return ("\n".join(records) + "\n").encode("ascii")


def navigation_authority_sha256(
    outlines: Sequence[Mapping[str, Any]],
    *,
    remove_adjacent_page_links: bool,
    removed_adjacent_page_link_count: int,
    retained_link_count: int,
) -> str:
    return hashlib.sha256(canonical_navigation_bytes(
        outlines,
        remove_adjacent_page_links=remove_adjacent_page_links,
        removed_adjacent_page_link_count=removed_adjacent_page_link_count,
        retained_link_count=retained_link_count,
    )).hexdigest()
