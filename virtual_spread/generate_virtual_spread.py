#!/usr/bin/env python3
"""Create a native-reader PDF whose pages are deterministic two-page spreads."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import secrets
import stat
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Iterator

from pypdf import PdfReader, PdfWriter, Transformation
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    FloatObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)


SCHEMA = "techrebbe.supernote.virtual-spread/v1"
LINK_AUTHORITY_MARKER = b"%SNVirtualSpreadLinksSHA256:"
LAYOUT_AUTHORITY_MARKER = b"%SNVirtualSpreadLayoutSHA256:"
PUBLICATION_SCHEMA = "techrebbe.supernote.virtual-spread-publication/v2"
MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_WRITE_THROUGH = 0x00000008
WINDOWS_ALREADY_EXISTS = {80, 183}
MAX_MANIFEST_BYTES = 8 * 1024 * 1024

PublicationOwnershipGuard = Callable[[], None]


class VirtualSpreadError(RuntimeError):
    """Raised when a source document cannot be transformed without data loss."""


@dataclass(frozen=True)
class Slot:
    side: str
    left: float
    bottom: float
    width: float
    height: float


@dataclass(frozen=True)
class SourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def _sha256_open_file(stream: BinaryIO) -> str:
    """Hash one complete view of an already-open file."""
    digest = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(stat_result: os.stat_result) -> SourceIdentity:
    return SourceIdentity(
        device=int(stat_result.st_dev),
        inode=int(stat_result.st_ino),
        size=int(stat_result.st_size),
        modified_ns=int(stat_result.st_mtime_ns),
        changed_ns=int(stat_result.st_ctime_ns),
    )


def _same_open_file(
    path_identity: SourceIdentity,
    open_identity: SourceIdentity,
) -> bool:
    return (
        path_identity.device == open_identity.device
        and path_identity.inode == open_identity.inode
        and path_identity.size == open_identity.size
        and path_identity.modified_ns == open_identity.modified_ns
    )


def _snapshot_source(
    source_path: Path,
    snapshot_stream: BinaryIO,
) -> tuple[SourceIdentity, str]:
    digest = hashlib.sha256()
    try:
        path_before = _identity(source_path.stat())
        snapshot_stream.seek(0)
        snapshot_stream.truncate()
        with source_path.open("rb") as source:
            opened_before = _identity(os.fstat(source.fileno()))
            if not _same_open_file(path_before, opened_before):
                raise VirtualSpreadError(
                    "Source PDF changed before snapshot creation"
                )
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                snapshot_stream.write(chunk)
                digest.update(chunk)
            snapshot_stream.flush()
            os.fsync(snapshot_stream.fileno())
            verified_source_hash = _sha256_open_file(source)
            opened_after = _identity(os.fstat(source.fileno()))
        path_after = _identity(source_path.stat())
    except OSError as error:
        raise VirtualSpreadError(
            f"Cannot create a stable source snapshot: {source_path}"
        ) from error
    if (
        opened_before != opened_after
        or path_before != path_after
    ):
        raise VirtualSpreadError("Source PDF changed while snapshotting")
    snapshot_hash = digest.hexdigest()
    if verified_source_hash != snapshot_hash:
        raise VirtualSpreadError("Source PDF content changed while snapshotting")
    snapshot_stream.seek(0)
    return path_before, snapshot_hash


def _require_source_snapshot(
    source_path: Path,
    expected: SourceIdentity,
    expected_hash: str,
) -> None:
    try:
        path_before = _identity(source_path.stat())
        with source_path.open("rb") as source:
            opened_before = _identity(os.fstat(source.fileno()))
            if not _same_open_file(path_before, opened_before):
                raise VirtualSpreadError(
                    "Source PDF changed before publication"
                )
            current_hash = _sha256_open_file(source)
            opened_after = _identity(os.fstat(source.fileno()))
        path_after = _identity(source_path.stat())
    except OSError as error:
        raise VirtualSpreadError(
            "Source PDF disappeared before publication"
        ) from error
    if (
        path_before != expected
        or path_after != expected
        or opened_before != opened_after
        or not _same_open_file(path_after, opened_after)
    ):
        raise VirtualSpreadError("Source PDF changed before publication")
    if current_hash != expected_hash:
        raise VirtualSpreadError("Source PDF content changed before publication")


def _float_bits(value: Any) -> str:
    return struct.pack(">d", float(value)).hex()


def _canonical_link(link: dict[str, Any]) -> str:
    kind = str(link["kind"])
    fields = [
        "v1",
        kind,
        str(int(link["sourcePage"])),
        str(link["sourceSide"]),
        str(int(link["outputPage"])),
        *(_float_bits(value) for value in link["rect"]),
    ]
    if kind == "internal":
        fields.extend(
            [
                str(int(link["targetSourcePage"])),
                str(int(link["targetOutputPage"])),
                str(link["targetSide"]),
            ]
        )
    elif kind == "uri":
        fields.append(
            hashlib.sha256(str(link["uri"]).encode("utf-8")).hexdigest()
        )
    else:
        raise VirtualSpreadError(f"Unsupported link kind: {kind}")
    return "|".join(fields)


def _link_authority_sha256(links: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for link in links:
        digest.update(_canonical_link(link).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _canonical_layout(
    direction: str,
    cover_separate: bool,
    source_page_count: int,
    output_page_count: int,
    spread_width: float,
    spread_height: float,
    gutter: float,
) -> str:
    return "|".join(
        [
            "v1",
            "layout",
            direction,
            "1" if cover_separate else "0",
            str(source_page_count),
            str(output_page_count),
            _float_bits(spread_width),
            _float_bits(spread_height),
            _float_bits(gutter),
        ]
    )


def _layout_authority_sha256(
    direction: str,
    cover_separate: bool,
    source_page_count: int,
    output_page_count: int,
    spread_width: float,
    spread_height: float,
    gutter: float,
) -> str:
    record = _canonical_layout(
        direction,
        cover_separate,
        source_page_count,
        output_page_count,
        spread_width,
        spread_height,
        gutter,
    )
    return hashlib.sha256((record + "\n").encode("utf-8")).hexdigest()


def _bind_pdf_authorities(
    path: Path,
    layout_authority_sha256: str,
    link_authority_sha256: str,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    for label, value in (
        ("layout", layout_authority_sha256),
        ("link", link_authority_sha256),
    ):
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise VirtualSpreadError(f"Invalid {label} authority digest")
    marker = (
        LAYOUT_AUTHORITY_MARKER
        + layout_authority_sha256.encode("ascii")
        + b"\n"
        + LINK_AUTHORITY_MARKER
        + link_authority_sha256.encode("ascii")
        + b"\n"
    )
    flags = os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = _publication_open_file(path, flags, ownership_guard)
    with os.fdopen(descriptor, "r+b", buffering=0) as stream:
        stream.seek(0, os.SEEK_END)
        length = stream.tell()
        tail_start = max(0, length - 4096)
        stream.seek(tail_start)
        tail = stream.read()
        startxref = tail.rfind(b"startxref")
        if startxref < 0:
            raise VirtualSpreadError("Written PDF has no final startxref")
        authority_tail = tail[startxref:]
        if (
            LAYOUT_AUTHORITY_MARKER in authority_tail
            or LINK_AUTHORITY_MARKER in authority_tail
        ):
            raise VirtualSpreadError("Written PDF has an invalid authority marker")
        stream.seek(tail_start + startxref)
        stream.write(marker)
        stream.write(tail[startxref:])
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def build_pairs(
    page_count: int,
    direction: str,
    cover_separate: bool,
) -> list[tuple[int | None, int | None]]:
    """Return display-order (left, right) source page indices."""
    if page_count < 1:
        raise VirtualSpreadError("The source PDF has no pages")
    if direction not in {"rtl", "ltr"}:
        raise VirtualSpreadError(f"Unsupported direction: {direction}")

    pairs: list[tuple[int | None, int | None]] = []
    next_page = 0
    if cover_separate:
        if direction == "rtl":
            pairs.append((None, 0))
        else:
            pairs.append((0, None))
        next_page = 1

    while next_page < page_count:
        first = next_page
        second = next_page + 1 if next_page + 1 < page_count else None
        if direction == "rtl":
            pairs.append((second, first))
        else:
            pairs.append((first, second))
        next_page += 2
    return pairs


def _page_ref_key(value: Any) -> tuple[int, int] | None:
    if isinstance(value, IndirectObject):
        return (value.idnum, value.generation)
    reference = getattr(value, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return (reference.idnum, reference.generation)
    return None


def _normalization_transform(page: Any) -> Transformation:
    rotation = int(page.get("/Rotate", 0) or 0) % 360
    if rotation not in {0, 90, 180, 270}:
        raise VirtualSpreadError(
            f"Unsupported source page rotation: {rotation}"
        )
    if rotation == 0:
        return Transformation()
    box = page.mediabox
    transform = (
        Transformation()
        .translate(
            -float(box.left + box.width / 2),
            -float(box.bottom + box.height / 2),
        )
        .rotate(-rotation)
    )
    lower = transform.apply_on(box.lower_left)
    upper = transform.apply_on(box.upper_right)
    return transform.translate(
        -min(lower[0], upper[0]),
        -min(lower[1], upper[1]),
    )


def _normalized_page(source_page: Any) -> tuple[Any, Transformation]:
    # Assign the clone to a writer before replacing its content stream. pypdf
    # 7 removes support for mutating detached PageObject clones.
    page = PdfWriter().add_page(source_page)
    # merge_transformed_page also merges /Annots. Links are copied separately
    # after every source-to-spread mapping is known, so the content clone must
    # not carry stale source destinations into the output page.
    page.pop("/Annots", None)
    rotation = int(page.get("/Rotate", 0) or 0) % 360
    normalization = _normalization_transform(page)
    if rotation:
        page.transfer_rotation_to_content()
    return page, normalization


def _layout_for_page(
    page: Any,
    slot: Slot,
    source_transform: Transformation,
) -> dict[str, Any]:
    box = page.cropbox
    source_left = float(box.left)
    source_bottom = float(box.bottom)
    source_width = float(box.width)
    source_height = float(box.height)
    if source_width <= 0 or source_height <= 0:
        raise VirtualSpreadError(
            f"Invalid source page box: {source_width} x {source_height}"
        )
    scale = min(slot.width / source_width, slot.height / source_height)
    placed_width = source_width * scale
    placed_height = source_height * scale
    translate_x = (
        slot.left
        + (slot.width - placed_width) / 2.0
        - source_left * scale
    )
    translate_y = (
        slot.bottom
        + (slot.height - placed_height) / 2.0
        - source_bottom * scale
    )
    content_transform = Transformation(
        ctm=(scale, 0.0, 0.0, scale, translate_x, translate_y)
    )
    source_to_spread = source_transform.transform(content_transform)
    destination = [
        slot.left + (slot.width - placed_width) / 2.0,
        slot.bottom + (slot.height - placed_height) / 2.0,
        slot.left + (slot.width + placed_width) / 2.0,
        slot.bottom + (slot.height + placed_height) / 2.0,
    ]
    return {
        "side": slot.side,
        "normalizedSourceBox": [
            source_left,
            source_bottom,
            source_left + source_width,
            source_bottom + source_height,
        ],
        "slot": [
            slot.left,
            slot.bottom,
            slot.left + slot.width,
            slot.bottom + slot.height,
        ],
        "destination": destination,
        "scale": scale,
        "transform": list(source_to_spread.ctm),
        "contentTransform": list(content_transform.ctm),
    }


def _transform_rect(rect: Iterable[Any], transform: list[float]) -> ArrayObject:
    values = [float(value) for value in rect]
    if len(values) != 4:
        raise VirtualSpreadError(f"Invalid annotation rectangle: {values}")
    x1, y1, x2, y2 = values
    a, b, c, d, e, f = transform
    points = [
        (a * x + c * y + e, b * x + d * y + f)
        for x, y in ((x1, y1), (x1, y2), (x2, y1), (x2, y2))
    ]
    return ArrayObject(
        [
            FloatObject(min(point[0] for point in points)),
            FloatObject(min(point[1] for point in points)),
            FloatObject(max(point[0] for point in points)),
            FloatObject(max(point[1] for point in points)),
        ]
    )


def _destination_source_page(
    reader: PdfReader,
    destination: Any,
    page_ref_to_index: dict[tuple[int, int], int],
) -> int | None:
    if isinstance(destination, IndirectObject):
        destination = destination.get_object()
    if isinstance(destination, (str, TextStringObject, NameObject)):
        names = [str(destination), str(destination).lstrip("/")]
        named = reader.named_destinations
        for name in names:
            if name in named:
                return reader.get_destination_page_number(named[name])
        return None
    if isinstance(destination, (list, ArrayObject)) and destination:
        return page_ref_to_index.get(_page_ref_key(destination[0]))
    return None


def _attach_annotation(
    writer: PdfWriter,
    output_page_index: int,
    annotation: DictionaryObject,
) -> None:
    """Attach an already-normalized annotation without rewriting its destination."""
    output_page = writer.pages[output_page_index]
    page_reference = output_page.indirect_reference
    if page_reference is None:
        raise VirtualSpreadError("Output page has no indirect reference")

    annotation[NameObject("/P")] = page_reference
    annotation_reference = writer._add_object(annotation)
    annotations = output_page.get("/Annots")
    if annotations is None:
        annotation_array = ArrayObject()
        output_page[NameObject("/Annots")] = annotation_array
    else:
        annotation_array = annotations.get_object()
        if not isinstance(annotation_array, ArrayObject):
            raise VirtualSpreadError("Output page /Annots is not an array")
    annotation_array.append(annotation_reference)


def _copy_link_annotation(
    *,
    reader: PdfReader,
    writer: PdfWriter,
    annotation: Any,
    output_page_index: int,
    source_page_index: int,
    source_mapping: dict[int, dict[str, Any]],
    page_ref_to_index: dict[tuple[int, int], int],
) -> dict[str, Any]:
    original = annotation.get_object()
    mapping = source_mapping[source_page_index]
    copied = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): _transform_rect(
                original["/Rect"], mapping["transform"]
            ),
            NameObject("/Border"): ArrayObject(
                [NumberObject(0), NumberObject(0), NumberObject(0)]
            ),
            NameObject("/SNSourcePage"): NumberObject(source_page_index),
        }
    )
    if "/Contents" in original:
        copied[NameObject("/Contents")] = TextStringObject(
            str(original["/Contents"])
        )

    destination = original.get("/Dest")
    action = original.get("/A")
    action_object = action.get_object() if action is not None else None
    if destination is None and action_object is not None:
        if action_object.get("/S") == "/GoTo":
            destination = action_object.get("/D")
        elif action_object.get("/S") == "/URI":
            uri = action_object.get("/URI")
            if uri is None:
                raise VirtualSpreadError("URI link has no /URI value")
            copied[NameObject("/A")] = DictionaryObject(
                {
                    NameObject("/S"): NameObject("/URI"),
                    NameObject("/URI"): TextStringObject(str(uri)),
                }
            )
            _attach_annotation(writer, output_page_index, copied)
            return {
                "sourcePage": source_page_index,
                "sourceSide": source_mapping[source_page_index]["side"],
                "outputPage": output_page_index,
                "kind": "uri",
                "uri": str(uri),
                "rect": [float(value) for value in copied["/Rect"]],
            }
        else:
            raise VirtualSpreadError(
                f"Unsupported link action: {action_object.get('/S')}"
            )

    if destination is None:
        raise VirtualSpreadError("Link annotation has neither /Dest nor /A")
    target_source_page = _destination_source_page(
        reader, destination, page_ref_to_index
    )
    if target_source_page is None or target_source_page not in source_mapping:
        raise VirtualSpreadError(
            f"Cannot resolve internal link on source page {source_page_index + 1}"
        )
    target = source_mapping[target_source_page]
    target_output_page = int(target["virtualPageIndex"])
    target_reference = writer.pages[target_output_page].indirect_reference
    if target_reference is None:
        raise VirtualSpreadError("Output page has no indirect reference")
    copied[NameObject("/Dest")] = ArrayObject(
        [target_reference, NameObject("/Fit")]
    )
    copied[NameObject("/SNTargetSourcePage")] = NumberObject(
        target_source_page
    )
    copied[NameObject("/SNTargetSide")] = NameObject(
        "/Left" if target["side"] == "left" else "/Right"
    )
    _attach_annotation(writer, output_page_index, copied)
    return {
        "sourcePage": source_page_index,
        "sourceSide": source_mapping[source_page_index]["side"],
        "outputPage": output_page_index,
        "kind": "internal",
        "targetSourcePage": target_source_page,
        "targetOutputPage": target_output_page,
        "targetSide": target["side"],
        "rect": [float(value) for value in copied["/Rect"]],
    }


def _write_json(
    path: Path,
    value: dict[str, Any],
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    flags = os.O_WRONLY | os.O_TRUNC
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = _publication_open_file(path, flags, ownership_guard)
    with os.fdopen(
        descriptor,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _temporary_neighbor(
    path: Path,
    suffix: str,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> Path:
    path = _lexical_absolute(path)
    namespace = _publication_namespace(ownership_guard)
    if namespace is not None and namespace.directory_descriptor is not None:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        for _ in range(128):
            candidate = path.with_name(
                f".{path.name}.{secrets.token_hex(16)}{suffix}"
            )
            try:
                descriptor = namespace.open_file(candidate, flags, 0o600)
            except FileExistsError:
                continue
            os.close(descriptor)
            namespace.fsync()
            return candidate
        raise VirtualSpreadError(
            f"Cannot allocate a staged publication file: {path}"
        )
    _validate_publication_ownership(ownership_guard)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=path.parent
    )
    os.close(descriptor)
    return Path(name)


def _publish_pair(
    temporary_output: Path,
    output_path: Path,
    temporary_manifest: Path,
    manifest_path: Path,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    """Publish a matching pair with durable recovery across process death."""
    transaction = _prepare_publication_transaction(
        temporary_output,
        output_path,
        temporary_manifest,
        manifest_path,
        ownership_guard,
    )
    try:
        expected_output_hash = transaction["newOutputSha256"]
        expected_manifest_hash = transaction["newManifestSha256"]
        _require_publication_file_hash(
            temporary_output,
            expected_output_hash,
            "Staged output",
            ownership_guard,
        )
        _require_publication_file_hash(
            temporary_manifest,
            expected_manifest_hash,
            "Staged manifest",
            ownership_guard,
        )
        entries = (
            (
                output_path,
                Path(transaction["outputBackupPath"]),
                transaction["hadOutput"],
                transaction["oldOutputSha256"],
                "Existing output",
                "Output backup",
            ),
            (
                manifest_path,
                Path(transaction["manifestBackupPath"]),
                transaction["hadManifest"],
                transaction["oldManifestSha256"],
                "Existing manifest",
                "Manifest backup",
            ),
        )
        for (
            final_path,
            backup,
            had_final,
            old_hash,
            final_label,
            backup_label,
        ) in entries:
            backup_exists = _require_regular_publication_target(
                backup,
                backup_label,
                ownership_guard,
            )
            if backup_exists:
                raise VirtualSpreadError(
                    f"Publication backup appeared concurrently: {backup}"
                )
            exists_now = _require_regular_publication_target(
                final_path,
                final_label,
                ownership_guard,
            )
            if had_final:
                if not exists_now:
                    raise VirtualSpreadError(
                        f"Publication target disappeared: {final_path}"
                    )
                assert isinstance(old_hash, str)
                _require_publication_file_hash(
                    final_path,
                    old_hash,
                    final_label,
                    ownership_guard,
                )
                _validate_publication_ownership(ownership_guard)
                _durable_replace(
                    final_path,
                    backup,
                    replace_existing=False,
                    ownership_guard=ownership_guard,
                )
                _require_publication_file_hash(
                    backup,
                    old_hash,
                    backup_label,
                    ownership_guard,
                )
            elif exists_now:
                raise VirtualSpreadError(
                    f"Publication target appeared concurrently: {final_path}"
                )

        # Publish the sidecar first. Until the PDF appears, the module fails
        # closed; once the PDF is published, its persisted hash matches.
        _require_publication_file_hash(
            temporary_manifest,
            expected_manifest_hash,
            "Staged manifest",
            ownership_guard,
        )
        _validate_publication_ownership(ownership_guard)
        _durable_replace(
            temporary_manifest,
            manifest_path,
            ownership_guard=ownership_guard,
        )
        _require_publication_file_hash(
            manifest_path,
            expected_manifest_hash,
            "Published manifest",
            ownership_guard,
        )
        _require_publication_file_hash(
            temporary_output,
            expected_output_hash,
            "Staged output",
            ownership_guard,
        )
        _validate_publication_ownership(ownership_guard)
        _durable_replace(
            temporary_output,
            output_path,
            ownership_guard=ownership_guard,
        )
        _require_publication_file_hash(
            manifest_path,
            expected_manifest_hash,
            "Published manifest",
            ownership_guard,
        )
        _require_publication_file_hash(
            output_path,
            expected_output_hash,
            "Published output",
            ownership_guard,
        )
        _finish_publication_transaction(transaction, ownership_guard)
    except BaseException as publication_error:
        try:
            recovery = _recover_pair_publication(
                output_path, manifest_path, ownership_guard
            )
        except BaseException as recovery_error:
            raise VirtualSpreadError(
                "Virtual-spread publication failed and rollback was incomplete: "
                + str(recovery_error)
            ) from publication_error
        if recovery == "committed":
            return
        raise


def _lexical_absolute(path: Path) -> Path:
    """Normalize dot segments without following filesystem aliases."""
    return Path(os.path.abspath(os.fspath(path)))


def _require_unaliased_output_path(output_path: Path) -> Path:
    """Reject output aliases whose runtime sidecar path would be ambiguous."""
    lexical = _lexical_absolute(output_path)
    resolved = output_path.resolve()
    if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
        raise VirtualSpreadError(
            "Output PDF path must not contain symlinks or filesystem aliases: "
            f"{lexical} resolves to {resolved}"
        )
    return lexical


def _runtime_manifest_path(output_path: Path) -> Path:
    """Return the only sidecar path probed by the Android runtime."""
    output_path = _lexical_absolute(output_path)
    return Path(str(output_path) + ".json")


def _require_runtime_manifest_path(
    output_path: Path,
    manifest_path: Path,
) -> Path:
    expected = _runtime_manifest_path(output_path)
    actual = _lexical_absolute(manifest_path)
    if os.path.normcase(str(actual)) != os.path.normcase(str(expected)):
        raise VirtualSpreadError(
            "Manifest path must be the runtime sibling "
            f"{expected}; got {actual}"
        )
    resolved = actual.resolve()
    if os.path.normcase(str(actual)) != os.path.normcase(str(resolved)):
        raise VirtualSpreadError(
            "Manifest path must not contain symlinks or filesystem aliases: "
            f"{actual} resolves to {resolved}"
        )
    return actual


def _require_regular_publication_target(
    path: Path,
    label: str,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> bool:
    """Return entry existence, rejecting anything other than a regular file."""
    path = _lexical_absolute(path)
    try:
        namespace = _publication_namespace(ownership_guard)
        entry = (
            namespace.lstat(path) if namespace is not None else path.lstat()
        )
    except FileNotFoundError:
        return False
    except OSError as error:
        raise VirtualSpreadError(f"Cannot inspect {label}: {path}") from error
    if not stat.S_ISREG(entry.st_mode):
        raise VirtualSpreadError(
            f"{label} must be a regular file when it exists: {path}"
        )
    return True


def _require_regular_publication_targets(
    output_path: Path,
    manifest_path: Path,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> tuple[bool, bool]:
    return (
        _require_regular_publication_target(
            output_path, "Output PDF", ownership_guard
        ),
        _require_regular_publication_target(
            manifest_path,
            "Manifest",
            ownership_guard,
        ),
    )


def _require_publication_file_hash(
    path: Path,
    expected_hash: str,
    label: str,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    if not _require_regular_publication_target(
        path, label, ownership_guard
    ):
        raise VirtualSpreadError(f"{label} disappeared: {path}")
    try:
        actual_hash = _publication_sha256(path, ownership_guard)
    except OSError as error:
        raise VirtualSpreadError(f"Cannot hash {label}: {path}") from error
    if actual_hash != expected_hash:
        raise VirtualSpreadError(
            f"{label} SHA-256 mismatch: expected {expected_hash}, "
            f"got {actual_hash}"
        )


def _publication_artifacts(
    output_path: Path,
) -> tuple[Path, Path, Path]:
    output_path = _lexical_absolute(output_path)
    manifest_path = _runtime_manifest_path(output_path)
    # The manifest is now derived rather than caller-controlled. Retaining the
    # earlier canonical pair bytes keeps interrupted canonical transactions
    # discoverable across this hardening update while ownership remains solely
    # a function of the output PDF.
    key_material = (
        os.path.normcase(str(output_path))
        + "\0"
        + os.path.normcase(str(manifest_path))
    ).encode("utf-8")
    key = hashlib.sha256(key_material).hexdigest()[:24]
    marker = output_path.parent / f".virtual-spread-{key}.publish.json"
    output_backup = output_path.parent / (
        f".virtual-spread-{key}.output.bak"
    )
    manifest_backup = output_path.parent / (
        f".virtual-spread-{key}.manifest.bak"
    )
    return marker, output_backup, manifest_backup


def _publication_lock_path(output_path: Path) -> Path:
    marker, _, _ = _publication_artifacts(output_path)
    return marker.with_name(marker.name + ".lock")


def _require_open_lock_identity(
    lock_path: Path,
    descriptor: int,
    directory_descriptor: int | None = None,
) -> None:
    try:
        path_entry = (
            lock_path.lstat()
            if directory_descriptor is None
            else os.stat(
                lock_path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        )
        opened_entry = os.fstat(descriptor)
    except OSError as error:
        raise VirtualSpreadError(
            f"Cannot verify publication lock: {lock_path}"
        ) from error
    if (
        not stat.S_ISREG(path_entry.st_mode)
        or not stat.S_ISREG(opened_entry.st_mode)
        or path_entry.st_dev != opened_entry.st_dev
        or path_entry.st_ino != opened_entry.st_ino
    ):
        raise VirtualSpreadError(
            "Publication lock must remain one regular, unaliased file: "
            f"{lock_path}"
        )


def _require_open_directory_identity(
    directory_path: Path,
    descriptor: int,
) -> None:
    try:
        path_entry = directory_path.lstat()
        opened_entry = os.fstat(descriptor)
    except OSError as error:
        raise VirtualSpreadError(
            "Cannot verify publication lock directory: "
            f"{directory_path}"
        ) from error
    if (
        not stat.S_ISDIR(path_entry.st_mode)
        or not stat.S_ISDIR(opened_entry.st_mode)
        or path_entry.st_dev != opened_entry.st_dev
        or path_entry.st_ino != opened_entry.st_ino
    ):
        raise VirtualSpreadError(
            "Publication lock directory must remain one unaliased directory: "
            f"{directory_path}"
        )


def _acquire_publication_directory_lock(
    lock_path: Path,
    output_path: Path,
) -> int | None:
    """Hold one stable POSIX namespace owner while a pair is published."""
    if os.name == "nt":
        return None

    import fcntl

    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path.parent, flags)
    except OSError as error:
        raise VirtualSpreadError(
            "Cannot open publication lock directory safely: "
            f"{lock_path.parent}"
        ) from error
    try:
        _require_open_directory_identity(lock_path.parent, descriptor)
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as error:
            raise VirtualSpreadError(
                f"Publication is already active: {output_path}"
            ) from error
        _require_open_directory_identity(lock_path.parent, descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _release_publication_directory_lock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    import fcntl

    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
    finally:
        os.close(descriptor)


@dataclass
class _PublicationNamespace:
    """Bind all POSIX publication I/O to one locked directory handle."""

    directory_path: Path
    directory_descriptor: int | None
    lock_path: Path
    lock_descriptor: int

    def __call__(self) -> None:
        if self.directory_descriptor is not None:
            _require_open_directory_identity(
                self.directory_path,
                self.directory_descriptor,
            )
        _require_open_lock_identity(
            self.lock_path,
            self.lock_descriptor,
            self.directory_descriptor,
        )

    def _member_name(self, path: Path) -> str:
        lexical = _lexical_absolute(path)
        if os.path.normcase(str(lexical.parent)) != os.path.normcase(
            str(self.directory_path)
        ):
            raise VirtualSpreadError(
                "Publication artifact escaped the locked directory: "
                f"{lexical}"
            )
        return lexical.name

    def lstat(self, path: Path) -> os.stat_result:
        self()
        if self.directory_descriptor is None:
            return _lexical_absolute(path).lstat()
        return os.stat(
            self._member_name(path),
            dir_fd=self.directory_descriptor,
            follow_symlinks=False,
        )

    def open_file(self, path: Path, flags: int, mode: int = 0o666) -> int:
        self()
        if self.directory_descriptor is None:
            return os.open(_lexical_absolute(path), flags, mode)
        return os.open(
            self._member_name(path),
            flags,
            mode,
            dir_fd=self.directory_descriptor,
        )

    def fsync(self) -> None:
        if self.directory_descriptor is not None:
            os.fsync(self.directory_descriptor)

    def replace(
        self,
        source: Path,
        target: Path,
        *,
        replace_existing: bool,
    ) -> None:
        self()
        if self.directory_descriptor is None:
            _windows_move_file_ex(
                source,
                target,
                _windows_move_flags(replace_existing),
            )
            return
        source_name = self._member_name(source)
        target_name = self._member_name(target)
        if replace_existing:
            os.replace(
                source_name,
                target_name,
                src_dir_fd=self.directory_descriptor,
                dst_dir_fd=self.directory_descriptor,
            )
            self.fsync()
            return
        os.link(
            source_name,
            target_name,
            src_dir_fd=self.directory_descriptor,
            dst_dir_fd=self.directory_descriptor,
            follow_symlinks=False,
        )
        self.fsync()
        os.unlink(source_name, dir_fd=self.directory_descriptor)
        self.fsync()

    def unlink(self, path: Path, *, missing_ok: bool) -> None:
        self()
        try:
            if self.directory_descriptor is None:
                _lexical_absolute(path).unlink()
            else:
                os.unlink(
                    self._member_name(path),
                    dir_fd=self.directory_descriptor,
                )
        except FileNotFoundError:
            if not missing_ok:
                raise
            return
        self.fsync()


def _publication_namespace(
    ownership_guard: PublicationOwnershipGuard | None,
) -> _PublicationNamespace | None:
    return (
        ownership_guard
        if isinstance(ownership_guard, _PublicationNamespace)
        else None
    )


def _publication_open_file(
    path: Path,
    flags: int,
    ownership_guard: PublicationOwnershipGuard | None,
    mode: int = 0o666,
) -> int:
    namespace = _publication_namespace(ownership_guard)
    if namespace is not None:
        return namespace.open_file(path, flags, mode)
    _validate_publication_ownership(ownership_guard)
    return os.open(_lexical_absolute(path), flags, mode)


def _publication_sha256(
    path: Path,
    ownership_guard: PublicationOwnershipGuard | None,
) -> str:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = _publication_open_file(path, flags, ownership_guard)
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        return _sha256_open_file(stream)


def _publication_file_size(
    path: Path,
    ownership_guard: PublicationOwnershipGuard | None,
) -> int:
    namespace = _publication_namespace(ownership_guard)
    if namespace is not None:
        return int(namespace.lstat(path).st_size)
    _validate_publication_ownership(ownership_guard)
    return int(_lexical_absolute(path).stat().st_size)


def _publication_unlink(
    path: Path,
    ownership_guard: PublicationOwnershipGuard | None,
    *,
    missing_ok: bool,
) -> None:
    namespace = _publication_namespace(ownership_guard)
    if namespace is not None:
        namespace.unlink(path, missing_ok=missing_ok)
        return
    _validate_publication_ownership(ownership_guard)
    _lexical_absolute(path).unlink(missing_ok=missing_ok)


def _open_publication_lock(
    lock_path: Path,
    directory_descriptor: int | None,
) -> BinaryIO:
    if directory_descriptor is None:
        _require_regular_publication_target(lock_path, "Publication lock")
    else:
        try:
            lock_entry = os.stat(
                lock_path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            lock_entry = None
        except OSError as error:
            raise VirtualSpreadError(
                f"Cannot inspect Publication lock: {lock_path}"
            ) from error
        if lock_entry is not None and not stat.S_ISREG(lock_entry.st_mode):
            raise VirtualSpreadError(
                "Publication lock must be a regular file when it exists: "
                f"{lock_path}"
            )
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        if directory_descriptor is None:
            descriptor = os.open(lock_path, flags, 0o600)
        else:
            descriptor = os.open(
                lock_path.name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
    except OSError as error:
        raise VirtualSpreadError(
            f"Cannot open publication lock safely: {lock_path}"
        ) from error
    try:
        _require_open_lock_identity(
            lock_path, descriptor, directory_descriptor
        )
        return os.fdopen(descriptor, "r+b", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _publication_lock(
    output_path: Path,
) -> Iterator[PublicationOwnershipGuard]:
    """Serialize every publisher and recovery owner for one output PDF."""
    lock_path = _publication_lock_path(output_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    directory_descriptor = _acquire_publication_directory_lock(
        lock_path,
        output_path,
    )
    try:
        stream = _open_publication_lock(
            lock_path, directory_descriptor
        )
        acquired = False
        try:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
                os.fsync(stream.fileno())
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(
                        stream.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
            except OSError as error:
                raise VirtualSpreadError(
                    f"Publication is already active: {output_path}"
                ) from error
            ownership = _PublicationNamespace(
                directory_path=lock_path.parent,
                directory_descriptor=directory_descriptor,
                lock_path=lock_path,
                lock_descriptor=stream.fileno(),
            )
            ownership()
            acquired = True

            yield ownership
        finally:
            if acquired:
                stream.seek(0)
                try:
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    # Closing the descriptor below releases an OS-owned lock even
                    # if an explicit unlock reports a late platform error.
                    pass
            stream.close()
    finally:
        _release_publication_directory_lock(directory_descriptor)


def _validate_publication_ownership(
    ownership_guard: PublicationOwnershipGuard | None,
) -> None:
    if ownership_guard is not None:
        ownership_guard()


def _windows_move_flags(replace_existing: bool) -> int:
    flags = MOVEFILE_WRITE_THROUGH
    if replace_existing:
        flags |= MOVEFILE_REPLACE_EXISTING
    return flags


def _windows_move_file_ex(source: Path, target: Path, flags: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file_ex = kernel32.MoveFileExW
    move_file_ex.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    move_file_ex.restype = ctypes.c_int
    if move_file_ex(str(source), str(target), flags):
        return
    error_code = ctypes.get_last_error()
    if not (flags & MOVEFILE_REPLACE_EXISTING) and error_code in WINDOWS_ALREADY_EXISTS:
        raise FileExistsError(
            error_code,
            f"Publication target already exists: {target}",
            str(target),
        )
    raise ctypes.WinError(error_code)


def _durable_replace(
    source: Path,
    target: Path,
    *,
    replace_existing: bool = True,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    source = Path(source)
    target = Path(target)
    namespace = _publication_namespace(ownership_guard)
    if namespace is not None:
        namespace.replace(
            source, target, replace_existing=replace_existing
        )
        return
    _validate_publication_ownership(ownership_guard)
    if os.name == "nt":
        _windows_move_file_ex(
            source,
            target,
            _windows_move_flags(replace_existing),
        )
        return
    if not replace_existing and target.exists():
        raise FileExistsError(
            f"Publication target already exists: {target}"
        )
    os.replace(source, target)
    _fsync_parent_directories(source, target)


def _fsync_parent_directories(*paths: Path) -> None:
    if os.name == "nt":
        # Every publication namespace change on Windows goes through
        # MoveFileExW(MOVEFILE_WRITE_THROUGH). Directory handles cannot be
        # opened portably by Python's os.open implementation.
        return
    directories = sorted(
        {path.resolve().parent for path in paths},
        key=lambda path: str(path),
    )
    for directory in directories:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(directory, flags)
        except OSError:
            raise
        try:
            os.fsync(descriptor)
        except OSError:
            raise
        finally:
            os.close(descriptor)


def _durably_remove(
    path: Path,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    retired = path.with_name(path.name + ".retired")
    try:
        _durable_replace(
            path,
            retired,
            ownership_guard=ownership_guard,
        )
    except FileNotFoundError:
        return
    namespace = _publication_namespace(ownership_guard)
    if namespace is not None:
        namespace.unlink(retired, missing_ok=True)
    else:
        _validate_publication_ownership(ownership_guard)
        retired.unlink(missing_ok=True)
        _fsync_parent_directories(retired)


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _file_matches_sha256(
    path: Path,
    expected_hash: str,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> bool:
    try:
        return (
            _require_regular_publication_target(
                path, "Publication target", ownership_guard
            )
            and _publication_sha256(path, ownership_guard) == expected_hash
        )
    except OSError:
        return False


def _write_publication_marker(
    marker_path: Path,
    transaction: dict[str, Any],
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    _validate_publication_ownership(ownership_guard)
    namespace = _publication_namespace(ownership_guard)
    if namespace is None:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        staged_marker = _temporary_neighbor(
            marker_path,
            ".publish-marker.tmp",
            ownership_guard,
        )
        try:
            _write_json(staged_marker, transaction, ownership_guard)
            try:
                _validate_publication_ownership(ownership_guard)
                _durable_replace(
                    staged_marker,
                    marker_path,
                    replace_existing=False,
                    ownership_guard=ownership_guard,
                )
            except FileExistsError as error:
                raise VirtualSpreadError(
                    f"Publication is already in progress: {marker_path}"
                ) from error
        finally:
            _publication_unlink(
                staged_marker,
                ownership_guard,
                missing_ok=True,
            )
        return

    marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    marker_flags |= getattr(os, "O_NOINHERIT", 0)
    marker_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        _validate_publication_ownership(ownership_guard)
        descriptor = _publication_open_file(
            marker_path,
            marker_flags,
            ownership_guard,
            0o600,
        )
    except FileExistsError as error:
        raise VirtualSpreadError(
            f"Publication is already in progress: {marker_path}"
        ) from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(
                transaction,
                stream,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            _publication_unlink(
                marker_path,
                ownership_guard,
                missing_ok=True,
            )
        except VirtualSpreadError:
            pass
        raise
    _validate_publication_ownership(ownership_guard)
    if namespace is not None:
        namespace.fsync()
    else:
        _fsync_parent_directories(marker_path)


def _validated_publication_transaction(
    marker_path: Path,
    output_path: Path,
    manifest_path: Path,
    output_backup: Path,
    manifest_backup: Path,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> dict[str, Any]:
    marker_flags = os.O_RDONLY
    marker_flags |= getattr(os, "O_BINARY", 0)
    marker_flags |= getattr(os, "O_NOINHERIT", 0)
    marker_flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = _publication_open_file(
        marker_path, marker_flags, ownership_guard
    )
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        transaction = json.load(stream)
    expected = {
        "schema": PUBLICATION_SCHEMA,
        "outputPath": str(_lexical_absolute(output_path)),
        "manifestPath": str(_lexical_absolute(manifest_path)),
        "outputBackupPath": str(_lexical_absolute(output_backup)),
        "manifestBackupPath": str(_lexical_absolute(manifest_backup)),
    }
    if not isinstance(transaction, dict) or any(
        transaction.get(key) != value for key, value in expected.items()
    ):
        raise VirtualSpreadError("Invalid virtual-spread publication marker")
    for key in ("hadOutput", "hadManifest"):
        if type(transaction.get(key)) is not bool:
            raise VirtualSpreadError("Invalid virtual-spread publication marker")
    for key in ("newOutputSha256", "newManifestSha256"):
        if not _valid_sha256(transaction.get(key)):
            raise VirtualSpreadError("Invalid virtual-spread publication marker")
    for had_key, old_hash_key in (
        ("hadOutput", "oldOutputSha256"),
        ("hadManifest", "oldManifestSha256"),
    ):
        old_hash = transaction.get(old_hash_key)
        if transaction[had_key]:
            if not _valid_sha256(old_hash):
                raise VirtualSpreadError(
                    "Invalid virtual-spread publication marker"
                )
        elif old_hash is not None:
            raise VirtualSpreadError(
                "Invalid virtual-spread publication marker"
            )
    return transaction


def _finish_publication_transaction(
    transaction: dict[str, Any],
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> None:
    marker_path = Path(transaction["markerPath"])
    output_backup = Path(transaction["outputBackupPath"])
    manifest_backup = Path(transaction["manifestBackupPath"])
    artifacts = (
        (output_backup, "Output backup"),
        (manifest_backup, "Manifest backup"),
        (marker_path, "Publication marker"),
    )
    for path, label in artifacts:
        _require_regular_publication_target(
            path, label, ownership_guard
        )
    for path, _ in artifacts:
        _durably_remove(path, ownership_guard)


def _recover_pair_publication(
    output_path: Path,
    manifest_path: Path,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> str | None:
    output_path = _require_unaliased_output_path(output_path)
    manifest_path = _require_runtime_manifest_path(
        output_path,
        manifest_path,
    )
    _require_regular_publication_targets(
        output_path, manifest_path, ownership_guard
    )
    marker_path, output_backup, manifest_backup = _publication_artifacts(
        output_path,
    )
    marker_exists = _require_regular_publication_target(
        marker_path,
        "Publication marker",
        ownership_guard,
    )
    output_backup_exists = _require_regular_publication_target(
        output_backup,
        "Output backup",
        ownership_guard,
    )
    manifest_backup_exists = _require_regular_publication_target(
        manifest_backup,
        "Manifest backup",
        ownership_guard,
    )
    if not marker_exists:
        if output_backup_exists or manifest_backup_exists:
            raise VirtualSpreadError(
                "Orphaned virtual-spread publication backup requires recovery"
            )
        return None
    try:
        transaction = _validated_publication_transaction(
            marker_path,
            output_path,
            manifest_path,
            output_backup,
            manifest_backup,
            ownership_guard,
        )
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        current_output_backup_exists = _require_regular_publication_target(
            output_backup,
            "Output backup",
            ownership_guard,
        )
        current_manifest_backup_exists = _require_regular_publication_target(
            manifest_backup,
            "Manifest backup",
            ownership_guard,
        )
        if not current_output_backup_exists and not current_manifest_backup_exists:
            marker_still_exists = _require_regular_publication_target(
                marker_path,
                "Publication marker",
                ownership_guard,
            )
            if marker_still_exists:
                _durably_remove(marker_path, ownership_guard)
            return "discarded"
        raise VirtualSpreadError(
            "Cannot recover invalid virtual-spread publication marker"
        ) from error
    transaction["markerPath"] = str(marker_path)
    output_is_new = _file_matches_sha256(
        output_path,
        transaction["newOutputSha256"],
        ownership_guard,
    )
    manifest_is_new = _file_matches_sha256(
        manifest_path,
        transaction["newManifestSha256"],
        ownership_guard,
    )
    if output_is_new and manifest_is_new:
        _finish_publication_transaction(transaction, ownership_guard)
        return "committed"

    errors: list[str] = []
    entries = (
        (
            output_path,
            output_backup,
            transaction["hadOutput"],
            transaction["newOutputSha256"],
            transaction["oldOutputSha256"],
            "Output backup",
        ),
        (
            manifest_path,
            manifest_backup,
            transaction["hadManifest"],
            transaction["newManifestSha256"],
            transaction["oldManifestSha256"],
            "Manifest backup",
        ),
    )
    for final_path, backup, had_final, new_hash, old_hash, backup_label in entries:
        try:
            backup_exists = _require_regular_publication_target(
                backup,
                backup_label,
                ownership_guard,
            )
            final_exists = _require_regular_publication_target(
                final_path,
                "Publication target",
                ownership_guard,
            )
            if backup_exists:
                if not had_final:
                    raise VirtualSpreadError(
                        f"Unexpected backup without an original: {backup}"
                    )
                assert isinstance(old_hash, str)
                _require_publication_file_hash(
                    backup,
                    old_hash,
                    backup_label,
                    ownership_guard,
                )
                _validate_publication_ownership(ownership_guard)
                _durable_replace(
                    backup,
                    final_path,
                    ownership_guard=ownership_guard,
                )
                _require_publication_file_hash(
                    final_path,
                    old_hash,
                    "Restored publication target",
                    ownership_guard,
                )
            elif had_final:
                if not final_exists:
                    raise VirtualSpreadError(
                        f"Missing original and backup: {final_path}"
                    )
                assert isinstance(old_hash, str)
                _require_publication_file_hash(
                    final_path,
                    old_hash,
                    "Original publication target",
                    ownership_guard,
                )
            elif final_exists:
                if not _file_matches_sha256(
                    final_path, new_hash, ownership_guard
                ):
                    raise VirtualSpreadError(
                        f"Unexpected publication target: {final_path}"
                    )
                _durably_remove(final_path, ownership_guard)
        except BaseException as error:
            errors.append(f"{final_path}: {error}")
    if errors:
        raise VirtualSpreadError(
            "Virtual-spread recovery was incomplete: " + "; ".join(errors)
        )
    _finish_publication_transaction(transaction, ownership_guard)
    return "rolled_back"


def _prepare_publication_transaction(
    temporary_output: Path,
    output_path: Path,
    temporary_manifest: Path,
    manifest_path: Path,
    ownership_guard: PublicationOwnershipGuard | None = None,
) -> dict[str, Any]:
    output_path = _require_unaliased_output_path(output_path)
    manifest_path = _require_runtime_manifest_path(
        output_path,
        manifest_path,
    )
    _recover_pair_publication(output_path, manifest_path, ownership_guard)
    had_output, had_manifest = _require_regular_publication_targets(
        output_path,
        manifest_path,
        ownership_guard,
    )
    marker_path, output_backup, manifest_backup = _publication_artifacts(
        output_path,
    )
    old_output_hash = (
        _publication_sha256(output_path, ownership_guard)
        if had_output
        else None
    )
    old_manifest_hash = (
        _publication_sha256(manifest_path, ownership_guard)
        if had_manifest
        else None
    )
    _validate_publication_ownership(ownership_guard)
    transaction: dict[str, Any] = {
        "schema": PUBLICATION_SCHEMA,
        "markerPath": str(marker_path),
        "outputPath": str(output_path),
        "manifestPath": str(manifest_path),
        "outputBackupPath": str(output_backup),
        "manifestBackupPath": str(manifest_backup),
        "hadOutput": had_output,
        "hadManifest": had_manifest,
        "oldOutputSha256": old_output_hash,
        "oldManifestSha256": old_manifest_hash,
        "newOutputSha256": _publication_sha256(temporary_output, ownership_guard),
        "newManifestSha256": _publication_sha256(temporary_manifest, ownership_guard),
    }
    marker_record = dict(transaction)
    marker_record.pop("markerPath")
    _write_publication_marker(marker_path, marker_record, ownership_guard)
    return transaction


def _build_virtual_spread_from_snapshot(
    source_path: Path,
    source_snapshot: BinaryIO,
    source_identity: SourceIdentity,
    source_hash: str,
    output_path: Path,
    manifest_path: Path,
    *,
    ownership_guard: PublicationOwnershipGuard | None = None,
    direction: str = "rtl",
    cover_separate: bool = True,
    spread_width: float = 864.0,
    spread_height: float = 648.0,
    gutter: float = 0.0,
    force: bool = False,
) -> dict[str, Any]:
    source_path = source_path.resolve()
    output_path = _require_unaliased_output_path(output_path)
    manifest_path = _require_runtime_manifest_path(
        output_path,
        manifest_path,
    )
    output_exists, manifest_exists = _require_regular_publication_targets(
        output_path,
        manifest_path,
        ownership_guard,
    )
    if not source_path.is_file():
        raise VirtualSpreadError(f"Source PDF does not exist: {source_path}")
    if len({source_path, output_path, manifest_path}) != 3:
        raise VirtualSpreadError(
            "Source PDF, output PDF, and manifest paths must be distinct"
        )
    if not force and (output_exists or manifest_exists):
        raise VirtualSpreadError("Output already exists; pass --force to replace it")
    if not all(math.isfinite(value) for value in (
        spread_width, spread_height, gutter
    )) or spread_width <= 0 or spread_height <= 0 or gutter < 0:
        raise VirtualSpreadError("Spread dimensions and gutter must be valid")
    slot_width = (spread_width - gutter) / 2.0
    if slot_width <= 0:
        raise VirtualSpreadError("Gutter consumes the complete spread width")

    reader = PdfReader(source_snapshot, strict=True)
    if reader.is_encrypted:
        raise VirtualSpreadError("Encrypted PDFs are not supported by this prototype")
    pairs = build_pairs(len(reader.pages), direction, cover_separate)
    normalized_pages = [_normalized_page(page) for page in reader.pages]
    left_slot = Slot("left", 0.0, 0.0, slot_width, spread_height)
    right_slot = Slot(
        "right", slot_width + gutter, 0.0, slot_width, spread_height
    )

    writer = PdfWriter()
    source_mapping: dict[int, dict[str, Any]] = {}
    spread_records: list[dict[str, Any]] = []
    for virtual_page_index, (left_source, right_source) in enumerate(pairs):
        output_page = writer.add_blank_page(spread_width, spread_height)
        record: dict[str, Any] = {
            "virtualPageIndex": virtual_page_index,
            "virtualPageNumber": virtual_page_index + 1,
            "left": None,
            "right": None,
        }
        for source_page_index, slot in (
            (left_source, left_slot),
            (right_source, right_slot),
        ):
            if source_page_index is None:
                continue
            page, source_transform = normalized_pages[source_page_index]
            layout = _layout_for_page(page, slot, source_transform)
            original_box = reader.pages[source_page_index].cropbox
            layout["sourceBox"] = [
                float(original_box.left),
                float(original_box.bottom),
                float(original_box.right),
                float(original_box.top),
            ]
            output_page.merge_transformed_page(
                page,
                Transformation(ctm=tuple(layout["contentTransform"])),
                over=True,
                expand=False,
            )
            layout.pop("contentTransform")
            mapping = {
                **layout,
                "sourcePageIndex": source_page_index,
                "sourcePageNumber": source_page_index + 1,
                "virtualPageIndex": virtual_page_index,
                "virtualPageNumber": virtual_page_index + 1,
            }
            source_mapping[source_page_index] = mapping
            record[slot.side] = mapping
        spread_records.append(record)

    page_ref_to_index = {
        key: index
        for index, page in enumerate(reader.pages)
        if (key := _page_ref_key(page)) is not None
    }
    links: list[dict[str, Any]] = []
    for source_page_index, source_page in enumerate(reader.pages):
        output_page_index = int(
            source_mapping[source_page_index]["virtualPageIndex"]
        )
        annotations = source_page.get("/Annots")
        if annotations is None:
            continue
        annotation_array = annotations.get_object()
        if not isinstance(annotation_array, ArrayObject):
            raise VirtualSpreadError(
                "Source page /Annots is not an array; "
                f"source page {source_page_index + 1}"
            )
        for annotation in annotation_array:
            annotation_object = annotation.get_object()
            if annotation_object.get("/Subtype") != "/Link":
                raise VirtualSpreadError(
                    "Only /Link annotations are supported by this prototype; "
                    f"source page {source_page_index + 1} contains "
                    f"{annotation_object.get('/Subtype')}"
                )
            links.append(
                _copy_link_annotation(
                    reader=reader,
                    writer=writer,
                    annotation=annotation,
                    output_page_index=output_page_index,
                    source_page_index=source_page_index,
                    source_mapping=source_mapping,
                    page_ref_to_index=page_ref_to_index,
                )
            )

    link_authority_hash = _link_authority_sha256(links)
    layout_authority_hash = _layout_authority_sha256(
        direction,
        cover_separate,
        len(reader.pages),
        len(pairs),
        spread_width,
        spread_height,
        gutter,
    )
    metadata = {
        key: str(value)
        for key, value in (reader.metadata or {}).items()
        if value is not None
    }
    metadata.update(
        {
            "/SNVirtualSpreadSchema": SCHEMA,
            "/SNVirtualSpreadSource": source_path.name,
            "/SNVirtualSpreadSourceSHA256": source_hash,
            "/SNVirtualSpreadLayoutSHA256": layout_authority_hash,
            "/SNVirtualSpreadLinksSHA256": link_authority_hash,
        }
    )
    writer.add_metadata(metadata)

    temporary_output = _temporary_neighbor(
        output_path, ".tmp", ownership_guard
    )
    temporary_manifest: Path | None = None
    try:
        output_flags = os.O_WRONLY | os.O_TRUNC
        output_flags |= getattr(os, "O_BINARY", 0)
        output_flags |= getattr(os, "O_NOINHERIT", 0)
        output_flags |= getattr(os, "O_NOFOLLOW", 0)
        output_descriptor = _publication_open_file(
            temporary_output, output_flags, ownership_guard
        )
        with os.fdopen(output_descriptor, "wb", buffering=0) as stream:
            writer.write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        _bind_pdf_authorities(
            temporary_output,
            layout_authority_hash,
            link_authority_hash,
            ownership_guard,
        )
        verification_flags = os.O_RDONLY
        verification_flags |= getattr(os, "O_BINARY", 0)
        verification_flags |= getattr(os, "O_NOINHERIT", 0)
        verification_flags |= getattr(os, "O_NOFOLLOW", 0)
        verification_descriptor = _publication_open_file(
            temporary_output, verification_flags, ownership_guard
        )
        with os.fdopen(
            verification_descriptor, "rb", buffering=0
        ) as verification_stream:
            verification = PdfReader(verification_stream, strict=True)
            if len(verification.pages) != len(pairs):
                raise VirtualSpreadError(
                    "Written PDF failed page-count verification"
                )
            for page in verification.pages:
                if abs(float(page.mediabox.width) - spread_width) > 0.01 or abs(
                    float(page.mediabox.height) - spread_height
                ) > 0.01:
                    raise VirtualSpreadError(
                        "Written PDF has inconsistent page geometry"
                    )

        manifest: dict[str, Any] = {
            "schema": SCHEMA,
            "source": {
                "name": source_path.name,
                "path": str(source_path),
                "size": source_identity.size,
                "sha256": source_hash,
                "pageCount": len(reader.pages),
            },
            "output": {
                "name": output_path.name,
                "path": str(output_path),
                "size": _publication_file_size(
                    temporary_output, ownership_guard
                ),
                "sha256": _publication_sha256(
                    temporary_output, ownership_guard
                ),
                "pageCount": len(pairs),
                "spreadSize": [spread_width, spread_height],
                "gutter": gutter,
                "layoutAuthoritySha256": layout_authority_hash,
                "linkAuthoritySha256": link_authority_hash,
            },
            "direction": direction,
            "coverSeparate": cover_separate,
            "spreads": spread_records,
            "sourcePages": [
                source_mapping[index] for index in range(len(reader.pages))
            ],
            "links": links,
        }
        temporary_manifest = _temporary_neighbor(
            manifest_path,
            ".tmp",
            ownership_guard,
        )
        _write_json(temporary_manifest, manifest, ownership_guard)
        temporary_manifest_size = _publication_file_size(
            temporary_manifest, ownership_guard
        )
        if temporary_manifest_size > MAX_MANIFEST_BYTES:
            raise VirtualSpreadError(
                "Generated manifest exceeds the runtime limit of "
                f"{MAX_MANIFEST_BYTES} bytes"
            )
        _require_source_snapshot(
            source_path,
            source_identity,
            source_hash,
        )
        _publish_pair(
            temporary_output,
            output_path,
            temporary_manifest,
            manifest_path,
            ownership_guard,
        )
        return manifest
    finally:
        _publication_unlink(
            temporary_output,
            ownership_guard,
            missing_ok=True,
        )
        if temporary_manifest is not None:
            _publication_unlink(
                temporary_manifest,
                ownership_guard,
                missing_ok=True,
            )


def _build_virtual_spread_locked(
    source_path: Path,
    output_path: Path,
    manifest_path: Path,
    *,
    ownership_guard: PublicationOwnershipGuard | None = None,
    direction: str = "rtl",
    cover_separate: bool = True,
    spread_width: float = 864.0,
    spread_height: float = 648.0,
    gutter: float = 0.0,
    force: bool = False,
) -> dict[str, Any]:
    source_path = source_path.resolve()
    output_path = _require_unaliased_output_path(output_path)
    manifest_path = _require_runtime_manifest_path(
        output_path,
        manifest_path,
    )
    if len({source_path, output_path, manifest_path}) != 3:
        raise VirtualSpreadError(
            "Source PDF, output PDF, and manifest paths must be distinct"
        )
    _recover_pair_publication(output_path, manifest_path, ownership_guard)
    output_exists, manifest_exists = _require_regular_publication_targets(
        output_path,
        manifest_path,
        ownership_guard,
    )
    if not source_path.is_file():
        raise VirtualSpreadError(f"Source PDF does not exist: {source_path}")
    if not force and (output_exists or manifest_exists):
        raise VirtualSpreadError("Output already exists; pass --force to replace it")
    if not all(math.isfinite(value) for value in (
        spread_width, spread_height, gutter
    )) or spread_width <= 0 or spread_height <= 0 or gutter < 0:
        raise VirtualSpreadError("Spread dimensions and gutter must be valid")
    if (spread_width - gutter) / 2.0 <= 0:
        raise VirtualSpreadError("Gutter consumes the complete spread width")

    with tempfile.TemporaryFile(
        mode="w+b",
        prefix="virtual-spread-source-",
        suffix=".pdf",
    ) as source_snapshot:
        source_identity, source_hash = _snapshot_source(
            source_path,
            source_snapshot,
        )
        return _build_virtual_spread_from_snapshot(
            source_path,
            source_snapshot,
            source_identity,
            source_hash,
            output_path,
            manifest_path,
            direction=direction,
            ownership_guard=ownership_guard,
            cover_separate=cover_separate,
            spread_width=spread_width,
            spread_height=spread_height,
            gutter=gutter,
            force=force,
        )


def build_virtual_spread(
    source_path: Path,
    output_path: Path,
    manifest_path: Path,
    *,
    direction: str = "rtl",
    cover_separate: bool = True,
    spread_width: float = 864.0,
    spread_height: float = 648.0,
    gutter: float = 0.0,
    force: bool = False,
) -> dict[str, Any]:
    resolved_source = source_path.resolve()
    lexical_output = _require_unaliased_output_path(output_path)
    lexical_manifest = _lexical_absolute(manifest_path)
    if len({resolved_source, lexical_output, lexical_manifest}) != 3:
        raise VirtualSpreadError(
            "Source PDF, output PDF, and manifest paths must be distinct"
        )
    lexical_manifest = _require_runtime_manifest_path(
        lexical_output,
        lexical_manifest,
    )
    _require_regular_publication_targets(lexical_output, lexical_manifest)
    with _publication_lock(lexical_output) as ownership_guard:
        return _build_virtual_spread_locked(
            resolved_source,
            lexical_output,
            lexical_manifest,
            direction=direction,
            ownership_guard=ownership_guard,
            cover_separate=cover_separate,
            spread_width=spread_width,
            spread_height=spread_height,
            gutter=gutter,
            force=force,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="optional explicit <output>.json path; other paths are rejected",
    )
    parser.add_argument("--direction", choices=("rtl", "ltr"), default="rtl")
    parser.add_argument(
        "--cover-separate",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--spread-width", type=float, default=864.0)
    parser.add_argument("--spread-height", type=float, default=648.0)
    parser.add_argument("--gutter", type=float, default=0.0)
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    manifest_path = args.manifest or args.output.with_suffix(
        args.output.suffix + ".json"
    )
    manifest = build_virtual_spread(
        args.source,
        args.output,
        manifest_path,
        direction=args.direction,
        cover_separate=args.cover_separate,
        spread_width=args.spread_width,
        spread_height=args.spread_height,
        gutter=args.gutter,
        force=args.force,
    )
    print(f"Virtual spread PDF: {manifest['output']['path']}")
    print(f"Mapping manifest:   {_lexical_absolute(manifest_path)}")
    print(f"Source pages:       {manifest['source']['pageCount']}")
    print(f"Virtual spreads:    {manifest['output']['pageCount']}")
    print(f"Output SHA-256:      {manifest['output']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
