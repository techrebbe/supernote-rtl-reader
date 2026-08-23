#!/usr/bin/env python3
"""Create a native-reader PDF whose pages are deterministic two-page spreads."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

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
PUBLICATION_SCHEMA = "techrebbe.supernote.virtual-spread-publication/v1"
MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_WRITE_THROUGH = 0x00000008
WINDOWS_ALREADY_EXISTS = {80, 183}
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


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
    snapshot_path: Path,
) -> tuple[SourceIdentity, str]:
    digest = hashlib.sha256()
    try:
        path_before = _identity(source_path.stat())
        with source_path.open("rb") as source, snapshot_path.open("wb") as target:
            opened_before = _identity(os.fstat(source.fileno()))
            if not _same_open_file(path_before, opened_before):
                raise VirtualSpreadError(
                    "Source PDF changed before snapshot creation"
                )
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                target.write(chunk)
                digest.update(chunk)
            target.flush()
            os.fsync(target.fileno())
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
    with path.open("r+b") as stream:
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


def _write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _temporary_neighbor(path: Path, suffix: str) -> Path:
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
) -> None:
    """Publish a matching pair with durable recovery across process death."""
    transaction = _prepare_publication_transaction(
        temporary_output,
        output_path,
        temporary_manifest,
        manifest_path,
    )
    try:
        entries = (
            (
                output_path,
                Path(transaction["outputBackupPath"]),
                transaction["hadOutput"],
            ),
            (
                manifest_path,
                Path(transaction["manifestBackupPath"]),
                transaction["hadManifest"],
            ),
        )
        for final_path, backup, had_final in entries:
            if had_final:
                _durable_replace(final_path, backup)
            elif final_path.exists():
                raise VirtualSpreadError(
                    f"Publication target appeared concurrently: {final_path}"
                )

        # Publish the sidecar first. Until the PDF appears, the module fails
        # closed; once the PDF is published, its persisted hash matches.
        _durable_replace(temporary_manifest, manifest_path)
        _durable_replace(temporary_output, output_path)
        _finish_publication_transaction(transaction)
    except BaseException as publication_error:
        try:
            recovery = _recover_pair_publication(output_path, manifest_path)
        except BaseException as recovery_error:
            raise VirtualSpreadError(
                "Virtual-spread publication failed and rollback was incomplete: "
                + str(recovery_error)
            ) from publication_error
        if recovery == "committed":
            return
        raise


def _runtime_manifest_path(output_path: Path) -> Path:
    """Return the only sidecar path probed by the Android runtime."""
    output_path = output_path.resolve()
    return Path(str(output_path) + ".json")


def _require_runtime_manifest_path(
    output_path: Path,
    manifest_path: Path,
) -> Path:
    expected = _runtime_manifest_path(output_path)
    actual = manifest_path.resolve()
    if os.path.normcase(str(actual)) != os.path.normcase(str(expected)):
        raise VirtualSpreadError(
            "Manifest path must be the runtime sibling "
            f"{expected}; got {actual}"
        )
    return expected


def _publication_artifacts(
    output_path: Path,
) -> tuple[Path, Path, Path]:
    output_path = output_path.resolve()
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


@contextmanager
def _publication_lock(
    output_path: Path,
) -> Iterator[None]:
    """Serialize every publisher and recovery owner for one output PDF."""
    lock_path = _publication_lock_path(output_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    stream = lock_path.open("a+b")
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
        acquired = True
        yield
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
) -> None:
    source = Path(source)
    target = Path(target)
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


def _durably_remove(path: Path) -> None:
    retired = path.with_name(path.name + ".retired")
    try:
        _durable_replace(path, retired)
    except FileNotFoundError:
        return
    retired.unlink(missing_ok=True)
    _fsync_parent_directories(retired)


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _file_matches_sha256(path: Path, expected_hash: str) -> bool:
    try:
        return path.is_file() and sha256_file(path) == expected_hash
    except OSError:
        return False


def _write_publication_marker(
    marker_path: Path,
    transaction: dict[str, Any],
) -> None:
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        staged_marker = _temporary_neighbor(marker_path, ".publish-marker.tmp")
        try:
            _write_json(staged_marker, transaction)
            try:
                _durable_replace(
                    staged_marker,
                    marker_path,
                    replace_existing=False,
                )
            except FileExistsError as error:
                raise VirtualSpreadError(
                    f"Publication is already in progress: {marker_path}"
                ) from error
        finally:
            staged_marker.unlink(missing_ok=True)
        return

    try:
        descriptor = os.open(
            marker_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
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
        marker_path.unlink(missing_ok=True)
        raise
    _fsync_parent_directories(marker_path)


def _validated_publication_transaction(
    marker_path: Path,
    output_path: Path,
    manifest_path: Path,
    output_backup: Path,
    manifest_backup: Path,
) -> dict[str, Any]:
    with marker_path.open("r", encoding="utf-8") as stream:
        transaction = json.load(stream)
    expected = {
        "schema": PUBLICATION_SCHEMA,
        "outputPath": str(output_path.resolve()),
        "manifestPath": str(manifest_path.resolve()),
        "outputBackupPath": str(output_backup.resolve()),
        "manifestBackupPath": str(manifest_backup.resolve()),
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
    return transaction


def _finish_publication_transaction(transaction: dict[str, Any]) -> None:
    marker_path = Path(transaction["markerPath"])
    output_backup = Path(transaction["outputBackupPath"])
    manifest_backup = Path(transaction["manifestBackupPath"])
    _durably_remove(output_backup)
    _durably_remove(manifest_backup)
    _durably_remove(marker_path)


def _recover_pair_publication(
    output_path: Path,
    manifest_path: Path,
) -> str | None:
    output_path = output_path.resolve()
    manifest_path = manifest_path.resolve()
    _require_runtime_manifest_path(output_path, manifest_path)
    marker_path, output_backup, manifest_backup = _publication_artifacts(
        output_path,
    )
    if not marker_path.exists():
        if output_backup.exists() or manifest_backup.exists():
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
        )
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        if not output_backup.exists() and not manifest_backup.exists():
            _durably_remove(marker_path)
            return "discarded"
        raise VirtualSpreadError(
            "Cannot recover invalid virtual-spread publication marker"
        ) from error
    transaction["markerPath"] = str(marker_path)
    output_is_new = _file_matches_sha256(
        output_path,
        transaction["newOutputSha256"],
    )
    manifest_is_new = _file_matches_sha256(
        manifest_path,
        transaction["newManifestSha256"],
    )
    if output_is_new and manifest_is_new:
        _finish_publication_transaction(transaction)
        return "committed"

    errors: list[str] = []
    entries = (
        (
            output_path,
            output_backup,
            transaction["hadOutput"],
            transaction["newOutputSha256"],
        ),
        (
            manifest_path,
            manifest_backup,
            transaction["hadManifest"],
            transaction["newManifestSha256"],
        ),
    )
    for final_path, backup, had_final, new_hash in entries:
        try:
            if backup.exists():
                _durable_replace(backup, final_path)
            elif had_final:
                if not final_path.exists():
                    raise VirtualSpreadError(
                        f"Missing original and backup: {final_path}"
                    )
            elif final_path.exists():
                if not _file_matches_sha256(final_path, new_hash):
                    raise VirtualSpreadError(
                        f"Unexpected publication target: {final_path}"
                    )
                _durably_remove(final_path)
        except BaseException as error:
            errors.append(f"{final_path}: {error}")
    if errors:
        raise VirtualSpreadError(
            "Virtual-spread recovery was incomplete: " + "; ".join(errors)
        )
    _finish_publication_transaction(transaction)
    return "rolled_back"


def _prepare_publication_transaction(
    temporary_output: Path,
    output_path: Path,
    temporary_manifest: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    output_path = output_path.resolve()
    manifest_path = manifest_path.resolve()
    _require_runtime_manifest_path(output_path, manifest_path)
    _recover_pair_publication(output_path, manifest_path)
    marker_path, output_backup, manifest_backup = _publication_artifacts(
        output_path,
    )
    transaction: dict[str, Any] = {
        "schema": PUBLICATION_SCHEMA,
        "markerPath": str(marker_path),
        "outputPath": str(output_path),
        "manifestPath": str(manifest_path),
        "outputBackupPath": str(output_backup),
        "manifestBackupPath": str(manifest_backup),
        "hadOutput": output_path.exists(),
        "hadManifest": manifest_path.exists(),
        "newOutputSha256": sha256_file(temporary_output),
        "newManifestSha256": sha256_file(temporary_manifest),
    }
    marker_record = dict(transaction)
    marker_record.pop("markerPath")
    _write_publication_marker(marker_path, marker_record)
    return transaction


def _build_virtual_spread_from_snapshot(
    source_path: Path,
    source_snapshot: Path,
    source_identity: SourceIdentity,
    source_hash: str,
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
    source_path = source_path.resolve()
    output_path = output_path.resolve()
    manifest_path = manifest_path.resolve()
    if not source_path.is_file():
        raise VirtualSpreadError(f"Source PDF does not exist: {source_path}")
    if len({source_path, output_path, manifest_path}) != 3:
        raise VirtualSpreadError(
            "Source PDF, output PDF, and manifest paths must be distinct"
        )
    if not force and (output_path.exists() or manifest_path.exists()):
        raise VirtualSpreadError("Output already exists; pass --force to replace it")
    if not all(math.isfinite(value) for value in (
        spread_width, spread_height, gutter
    )) or spread_width <= 0 or spread_height <= 0 or gutter < 0:
        raise VirtualSpreadError("Spread dimensions and gutter must be valid")
    slot_width = (spread_width - gutter) / 2.0
    if slot_width <= 0:
        raise VirtualSpreadError("Gutter consumes the complete spread width")

    reader = PdfReader(str(source_snapshot), strict=True)
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

    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = _temporary_neighbor(output_path, ".tmp")
    temporary_manifest: Path | None = None
    try:
        with temporary_output.open("wb") as stream:
            writer.write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        _bind_pdf_authorities(
            temporary_output,
            layout_authority_hash,
            link_authority_hash,
        )
        verification = PdfReader(str(temporary_output), strict=True)
        if len(verification.pages) != len(pairs):
            raise VirtualSpreadError("Written PDF failed page-count verification")
        for page in verification.pages:
            if abs(float(page.mediabox.width) - spread_width) > 0.01 or abs(
                float(page.mediabox.height) - spread_height
            ) > 0.01:
                raise VirtualSpreadError("Written PDF has inconsistent page geometry")

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
                "size": temporary_output.stat().st_size,
                "sha256": sha256_file(temporary_output),
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
        temporary_manifest = _temporary_neighbor(manifest_path, ".tmp")
        _write_json(temporary_manifest, manifest)
        if temporary_manifest.stat().st_size > MAX_MANIFEST_BYTES:
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
        )
        return manifest
    finally:
        temporary_output.unlink(missing_ok=True)
        if temporary_manifest is not None:
            temporary_manifest.unlink(missing_ok=True)


def _build_virtual_spread_locked(
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
    source_path = source_path.resolve()
    output_path = output_path.resolve()
    manifest_path = manifest_path.resolve()
    if len({source_path, output_path, manifest_path}) != 3:
        raise VirtualSpreadError(
            "Source PDF, output PDF, and manifest paths must be distinct"
        )
    _recover_pair_publication(output_path, manifest_path)
    if not source_path.is_file():
        raise VirtualSpreadError(f"Source PDF does not exist: {source_path}")
    if not force and (output_path.exists() or manifest_path.exists()):
        raise VirtualSpreadError("Output already exists; pass --force to replace it")
    if not all(math.isfinite(value) for value in (
        spread_width, spread_height, gutter
    )) or spread_width <= 0 or spread_height <= 0 or gutter < 0:
        raise VirtualSpreadError("Spread dimensions and gutter must be valid")
    if (spread_width - gutter) / 2.0 <= 0:
        raise VirtualSpreadError("Gutter consumes the complete spread width")

    source_snapshot = _temporary_neighbor(output_path, ".source.tmp")
    try:
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
            cover_separate=cover_separate,
            spread_width=spread_width,
            spread_height=spread_height,
            gutter=gutter,
            force=force,
        )
    finally:
        source_snapshot.unlink(missing_ok=True)


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
    resolved_output = output_path.resolve()
    resolved_manifest = manifest_path.resolve()
    if len({resolved_source, resolved_output, resolved_manifest}) != 3:
        raise VirtualSpreadError(
            "Source PDF, output PDF, and manifest paths must be distinct"
        )
    _require_runtime_manifest_path(resolved_output, resolved_manifest)
    with _publication_lock(resolved_output):
        return _build_virtual_spread_locked(
            resolved_source,
            resolved_output,
            resolved_manifest,
            direction=direction,
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
    print(f"Mapping manifest:   {manifest_path.resolve()}")
    print(f"Source pages:       {manifest['source']['pageCount']}")
    print(f"Virtual spreads:    {manifest['output']['pageCount']}")
    print(f"Output SHA-256:      {manifest['output']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
