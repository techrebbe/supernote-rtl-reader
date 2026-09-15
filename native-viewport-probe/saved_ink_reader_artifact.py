"""Build and verify the deterministic SavedInkReader device DEX JAR.

This module never runs the collector and never reads a ``.mark`` file.  It is
only the host-side artifact authority for the separately reviewed Java source.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tempfile
import zipfile
import zlib


ARTIFACT_SCHEMA = "native-viewport-saved-ink-device-artifact-v1"
PROVENANCE_SCHEMA = "native-viewport-saved-ink-build-provenance-v1"
COLLECTOR_SCHEMA = "native-viewport-ink-evidence-v2"
FRAME_PREFIX = "NATIVE_VIEWPORT_INK_EVIDENCE "
MAIN_CLASS = "com.techrebbe.supernote.viewportprobe.SavedInkReader"
SOURCE_LOGICAL_PATH = (
    "java/com/techrebbe/supernote/viewportprobe/SavedInkReader.java"
)
SOURCE_SHA256 = "67b4991fdeb6ed385665487af02add44e15be54c7f54b441d5a797d38f9ee148"
COMPILE_SDK = 35
MIN_API = 30
BUILD_TOOLS_VERSION = "35.0.0"
EXPECTED_DEX_STRING_COUNT = 486
EXPECTED_DEX_STRING_SHA256 = (
    "ad0e1cfff35b9d31bb1c84f56258617789d0f86984c537fffc06f14e55542d81"
)
CANONICAL_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
CANONICAL_EXTERNAL_ATTR = 0o600 << 16
MAX_SOURCE_BYTES = 128 * 1024
MAX_CLASS_BYTES = 256 * 1024
MAX_DEX_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_AUTHORITY_BYTES = 128 * 1024

PINNED_FILES = {
    "jdkRelease": (1306,
        "00d3211a59bc9f2577f93962e9210de8578c49fd2625022cb38606817d3a71f9"),
    "jdkModules": (125748850,
        "81f0e1bb87cd303ddcce2b216e27da416bd20799d9a9811ea1b070123cefff0f"),
    "javac": (23664,
        "ff58ff79e356c4f62e0fdf67af6f71dcc7b8fb63edb5156d3eb064342e2a56a5"),
    "java": (54384,
        "9da06bd6c880c0c8d1a63e3716f8ef7996f146c41e6d339e4eafc93df28392f9"),
    "androidJar": (27092450,
        "4566663c3876e022b4fa4ced8c8697c4ab1688267f090114fd92d027b32e619b"),
    "d8Launcher": (3156,
        "ccc279cdc020fc20cb7889d829b9dc36a462ce4fca8ac713088f6be100b714d0"),
    "d8Jar": (16614740,
        "305622ad00535684534eb8f742cbf5e628a9abc09d8ea4d39d1babb95bf0cee5"),
    "python": (107312,
        "b7a12c3af0b4db44191eec14ea095eba731b7328917f570806183093d19ddca2"),
}
PINNED_JDK_BIN_TREE = {
    "files": 124,
    "bytes": 48473176,
    "sha256": "6e3c13be7a014d64463a7672b7b9b7f01659c67ef7d6f974fea7ed5ab43f6ad5",
}

_CLASS_NAMES = (
    "SavedInkReader",
    "SavedInkReader$CanonicalArray",
    "SavedInkReader$CanonicalObject",
    "SavedInkReader$CanonicalWriter",
    "SavedInkReader$CloseAction",
    "SavedInkReader$CloseStack",
    "SavedInkReader$EncodingBudget",
    "SavedInkReader$FileIdentity",
    "SavedInkReader$FirmwareAuthority",
    "SavedInkReader$FirmwareAuthority$1",
    "SavedInkReader$FirmwareAuthority$2",
    "SavedInkReader$FirmwareAuthority$3",
    "SavedInkReader$FirmwareAuthority$4",
    "SavedInkReader$FirmwareAuthority$5",
)
CLASS_PREFIX = "com/techrebbe/supernote/viewportprobe/"
EXPECTED_CLASS_PATHS = tuple(CLASS_PREFIX + name + ".class" for name in _CLASS_NAMES)
EXPECTED_CLASS_DESCRIPTORS = frozenset(
    "L" + CLASS_PREFIX + name + ";" for name in _CLASS_NAMES
)
EXPECTED_JAR_ENTRIES = (
    "META-INF/MANIFEST.MF",
    "META-INF/native-viewport-saved-ink-reader.json",
    "classes.dex",
)
MANIFEST = b"Manifest-Version: 1.0\r\n\r\n"
BUILD_RECIPE = {
    "classJar": "canonical ZIP_STORED exact-class allowlist",
    "d8": ["--no-desugaring", "--min-api", "30", "--lib", "<androidJar>",
           "--output", "<dexDirectory>", "<classJar>"],
    "environment": {
        "cleared": ["CLASSPATH", "D8_OPTS", "JAVACMD", "JAVA_OPTS",
                    "JAVA_TOOL_OPTIONS", "JDK_JAVAC_OPTIONS",
                    "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"],
        "javaHome": "<pinnedJdk>",
    },
    "javac": ["-encoding", "UTF-8", "--release", "8", "-classpath",
              "<androidJar>", "-d", "<classesDirectory>", "<source>"],
    "jar": "canonical ZIP_STORED exact-entry allowlist",
}
REQUIRED_DEX_STRINGS = frozenset({
    COLLECTOR_SCHEMA,
    FRAME_PREFIX,
    "NATIVE_VIEWPORT_INK_FAILED ",
    "/data/local/tmp/native-viewport-ink-reader/",
    "/data/local/native-viewport-ink-reader-input",
    "/system_ext/app/SupernoteDocument/SupernoteDocument.apk",
    "/system_ext/app/SupernoteDocument/lib/arm64",
    "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482",
    "898129ad25fe90734f2b9760786c846864f3622ebd82c25c5a3ce82ca4174919",
    "b7af795b72076e1996aa88dee3db32feecc25b89da01e9c96db8a86696c9bff4",
    "com.example.libsupernote.JniTrailContainer",
    "com.example.libsupernote.SuperNoteNote",
    "com.ratta.supernote.documentlib.constants.DocumentConstants",
    "createSuperNoteNote",
    "fetchPagesOfMark",
    "getFilePageTrails",
    "markInitProcess",
    "freeCommon",
})


class ArtifactError(ValueError):
    pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(value: os.stat_result) -> tuple[int, ...]:
    fields = (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_nlink,
              value.st_size, value.st_mtime_ns,
              getattr(value, "st_file_attributes", 0))
    if os.name == "posix":
        fields += (value.st_ctime_ns,)
    return fields


def _object_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_size,
            value.st_mtime_ns, getattr(value, "st_file_attributes", 0))


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode),
            getattr(value, "st_file_attributes", 0))


def _read_regular(path: Path, limit: int) -> bytes:
    path = Path(path).absolute()
    descriptor = None
    try:
        named = os.lstat(path)
        if (not stat.S_ISREG(named.st_mode) or named.st_size < 1 or
                named.st_size > limit or
                getattr(named, "st_file_attributes", 0) & 0x400):
            raise ArtifactError(f"not one bounded regular file: {path.name}")
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
        descriptor = os.open(path, flags)
        os.set_inheritable(descriptor, False)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                _identity(opened) != _identity(named)):
            raise ArtifactError(f"file identity changed before read: {path.name}")
        chunks = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if (len(raw) != opened.st_size or
                _identity(os.fstat(descriptor)) != _identity(opened) or
                _identity(os.lstat(path)) != _identity(opened)):
            raise ArtifactError(f"file identity changed during read: {path.name}")
        return raw
    except OSError as error:
        raise ArtifactError(f"cannot read {path.name}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _canonical_source(raw: bytes) -> bytes:
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        raise ArtifactError("source contains a Unicode line separator")
    if b"\r" in raw:
        if (raw.count(b"\r") != raw.count(b"\r\n") or
                raw.count(b"\n") != raw.count(b"\r\n")):
            raise ArtifactError("source has mixed or bare-CR newlines")
        raw = raw.replace(b"\r\n", b"\n")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ArtifactError("source is not strict UTF-8") from error
    return raw


def _file_record(path: Path, logical: str, limit: int,
                 expected: tuple[int, str] | None = None,
                 canonical_source: bool = False) -> dict[str, object]:
    raw = _read_regular(path, limit)
    if canonical_source:
        raw = _canonical_source(raw)
    record = {"path": logical, "bytes": len(raw), "sha256": _sha256(raw)}
    if expected is not None and (record["bytes"], record["sha256"]) != expected:
        raise ArtifactError(f"pinned input changed: {logical}")
    return record


def _tree_record(root: Path) -> dict[str, object]:
    root = Path(root).absolute()
    try:
        root_info = os.lstat(root)
    except OSError as error:
        raise ArtifactError("JDK bin tree is unavailable") from error
    if (not stat.S_ISDIR(root_info.st_mode) or
            getattr(root_info, "st_file_attributes", 0) & 0x400):
        raise ArtifactError("JDK bin tree is not an ordinary directory")
    paths = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            info = os.lstat(current_path / name)
            if (not stat.S_ISDIR(info.st_mode) or
                    getattr(info, "st_file_attributes", 0) & 0x400):
                raise ArtifactError("JDK bin tree contains a redirected directory")
        for name in filenames:
            paths.append(current_path / name)
    paths.sort(key=lambda item: item.relative_to(root).as_posix())
    records = []
    total = 0
    for path in paths:
        relative = path.relative_to(root).as_posix()
        raw = _read_regular(path, 64 * 1024 * 1024)
        total += len(raw)
        encoded = relative.encode("utf-8")
        records.append(len(encoded).to_bytes(4, "big") + encoded +
                       len(raw).to_bytes(8, "big") + hashlib.sha256(raw).digest())
    result = {"files": len(paths), "bytes": total,
              "sha256": _sha256(b"".join(records))}
    if result != PINNED_JDK_BIN_TREE:
        raise ArtifactError("pinned JDK bin tree changed")
    return result


def _class_records(classes: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    classes = Path(classes).absolute()
    actual = []
    for path in classes.rglob("*"):
        if path.is_file():
            actual.append(path.relative_to(classes).as_posix())
    actual.sort()
    if tuple(actual) != tuple(sorted(EXPECTED_CLASS_PATHS)):
        raise ArtifactError("compiled class inventory differs from exact allowlist")
    records = []
    payloads = {}
    for logical in actual:
        raw = _read_regular(classes.joinpath(*PurePosixPath(logical).parts),
                            MAX_CLASS_BYTES)
        payloads[logical] = raw
        records.append({"path": logical, "bytes": len(raw), "sha256": _sha256(raw)})
    return records, payloads


def _ordinary_directory(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as error:
        raise ArtifactError(f"output directory is unavailable: {path.name}") from error
    if (not stat.S_ISDIR(value.st_mode) or
            getattr(value, "st_file_attributes", 0) & 0x400):
        raise ArtifactError("output directory is not an ordinary directory")
    return value


def _publish_staged_no_replace(temporary: Path, output: Path, limit: int) -> None:
    """Publish a same-directory staged file without ever replacing a name.

    A generic link/publication error deliberately retains the uniquely named
    staged file as recovery evidence.  A known destination collision removes
    only our staged file and never touches the competing destination.
    """
    temporary = Path(temporary).absolute()
    output = Path(output).absolute()
    if temporary.parent != output.parent:
        raise ArtifactError("staged publication crossed directories")
    parent_before = _ordinary_directory(output.parent)
    staged_before = os.lstat(temporary)
    if not stat.S_ISREG(staged_before.st_mode) or staged_before.st_nlink != 1:
        raise ArtifactError("publication stage is not a regular file")
    staged_raw = _read_regular(temporary, limit)
    try:
        os.link(temporary, output)
    except FileExistsError as error:
        try:
            os.unlink(temporary)
        except OSError as cleanup_error:
            raise ArtifactError(
                "destination collision; staged cleanup requires review: " +
                temporary.name) from cleanup_error
        raise ArtifactError(f"refusing to replace existing output: {output.name}") from error
    except OSError as error:
        raise ArtifactError(
            "atomic no-replace publication failed; retained staged evidence: " +
            temporary.name) from error

    try:
        parent_after = os.lstat(output.parent)
        staged_after = os.lstat(temporary)
        published = os.lstat(output)
        if (_directory_identity(parent_before) != _directory_identity(parent_after) or
                _object_identity(staged_before) != _object_identity(staged_after) or
                _object_identity(staged_after) != _object_identity(published) or
                staged_after.st_nlink != 2 or published.st_nlink != 2 or
                _read_regular(output, limit) != staged_raw):
            raise ArtifactError(
                "published identity is uncertain; retained staged evidence: " +
                temporary.name)
    except OSError as error:
        raise ArtifactError(
            "published identity cannot be confirmed; retained staged evidence: " +
            temporary.name) from error
    try:
        os.unlink(temporary)
    except OSError as error:
        raise ArtifactError(
            "publication succeeded but staged cleanup requires review: " +
            temporary.name) from error
    final = os.lstat(output)
    if (_object_identity(final) != _object_identity(published) or
            final.st_nlink != 1 or _read_regular(output, limit) != staged_raw):
        raise ArtifactError("published output changed after staged cleanup")


def _publish_bytes_no_replace(path: Path, raw: bytes, limit: int) -> None:
    path = Path(path).absolute()
    if not raw or len(raw) > limit:
        raise ArtifactError("publication payload is outside its byte bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    _ordinary_directory(path.parent)
    descriptor, temporary_text = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_text)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ArtifactError("staged publication write made no progress")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    os.close(descriptor)
    _publish_staged_no_replace(temporary, path, limit)


def _canonical_zip_bytes(entries: dict[str, bytes]) -> bytes:
    for name in entries:
        parsed = PurePosixPath(name)
        if (not name or name.startswith("/") or "\\" in name or "\0" in name or
                any(part in ("", ".", "..") for part in parsed.parts)):
            raise ArtifactError("unsafe archive member")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED,
                             allowZip64=False) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, CANONICAL_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = CANONICAL_EXTERNAL_ATTR
            info.flag_bits = 0
            archive.writestr(info, entries[name])
    return stream.getvalue()


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    raw = _canonical_zip_bytes(entries)
    _publish_bytes_no_replace(Path(path), raw, MAX_ARTIFACT_BYTES)


def write_class_jar(classes: Path, output: Path) -> None:
    _, payloads = _class_records(classes)
    _write_zip(output, payloads)


def _u16(raw: bytes, at: int) -> int:
    if at < 0 or at + 2 > len(raw):
        raise ArtifactError("DEX 16-bit read outside file")
    return struct.unpack_from("<H", raw, at)[0]


def _u32(raw: bytes, at: int) -> int:
    if at < 0 or at + 4 > len(raw):
        raise ArtifactError("DEX 32-bit read outside file")
    return struct.unpack_from("<I", raw, at)[0]


def _uleb(raw: bytes, at: int) -> tuple[int, int]:
    result = 0
    for shift in range(0, 35, 7):
        if at >= len(raw):
            raise ArtifactError("truncated DEX ULEB128")
        value = raw[at]
        at += 1
        result |= (value & 0x7f) << shift
        if not value & 0x80:
            if shift == 28 and value & 0xf0:
                raise ArtifactError("oversized DEX ULEB128")
            return result, at
    raise ArtifactError("oversized DEX ULEB128")


def _mutf8(raw: bytes, at: int) -> tuple[str, int]:
    units, at = _uleb(raw, at)
    values = []
    while True:
        if at >= len(raw):
            raise ArtifactError("unterminated DEX string")
        first = raw[at]
        at += 1
        if first == 0:
            break
        if first < 0x80:
            values.append(first)
        elif first & 0xe0 == 0xc0:
            if at >= len(raw) or raw[at] & 0xc0 != 0x80:
                raise ArtifactError("invalid DEX MUTF-8")
            value = ((first & 0x1f) << 6) | (raw[at] & 0x3f)
            at += 1
            if value != 0 and value < 0x80:
                raise ArtifactError("noncanonical DEX MUTF-8")
            values.append(value)
        elif first & 0xf0 == 0xe0:
            if (at + 1 >= len(raw) or raw[at] & 0xc0 != 0x80 or
                    raw[at + 1] & 0xc0 != 0x80):
                raise ArtifactError("invalid DEX MUTF-8")
            value = (((first & 0x0f) << 12) |
                     ((raw[at] & 0x3f) << 6) |
                     (raw[at + 1] & 0x3f))
            at += 2
            if value < 0x800:
                raise ArtifactError("noncanonical DEX MUTF-8")
            values.append(value)
        else:
            raise ArtifactError("invalid DEX MUTF-8 lead byte")
    if len(values) != units:
        raise ArtifactError("DEX MUTF-8 UTF-16 length mismatch")
    result = []
    index = 0
    while index < len(values):
        value = values[index]
        if 0xd800 <= value <= 0xdbff and index + 1 < len(values):
            following = values[index + 1]
            if 0xdc00 <= following <= 0xdfff:
                result.append(chr(0x10000 + ((value - 0xd800) << 10) + following - 0xdc00))
                index += 2
                continue
        result.append(chr(value))
        index += 1
    return "".join(result), at


def _section(raw: bytes, size: int, offset: int, item_size: int, label: str) -> None:
    if size == 0:
        if offset != 0:
            raise ArtifactError(f"empty DEX {label} has nonzero offset")
        return
    if offset < 0x70 or item_size <= 0 or size > (len(raw) - offset) // item_size:
        raise ArtifactError(f"DEX {label} is outside file")


def _type_list(raw: bytes, at: int, types: list[str]) -> tuple[str, ...]:
    if at == 0:
        return ()
    count = _u32(raw, at)
    if count > (len(raw) - at - 4) // 2:
        raise ArtifactError("DEX type list outside file")
    result = []
    for index in range(count):
        type_index = _u16(raw, at + 4 + index * 2)
        if type_index >= len(types):
            raise ArtifactError("DEX type list index outside table")
        result.append(types[type_index])
    return tuple(result)


def _skip_encoded_fields(raw: bytes, at: int, count: int) -> int:
    field_index = 0
    for _ in range(count):
        difference, at = _uleb(raw, at)
        field_index += difference
        _, at = _uleb(raw, at)
    return at


def _encoded_methods(raw: bytes, at: int, count: int) -> tuple[list[tuple[int, int, int]], int]:
    method_index = 0
    result = []
    for _ in range(count):
        difference, at = _uleb(raw, at)
        method_index += difference
        access, at = _uleb(raw, at)
        code, at = _uleb(raw, at)
        result.append((method_index, access, code))
    return result, at


def verify_dex(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not 0x70 <= len(raw) <= MAX_DEX_BYTES:
        raise ArtifactError("DEX size is outside bound")
    if re.fullmatch(b"dex\\n0(?:35|37|38|39|40|41)\\x00", raw[:8]) is None:
        raise ArtifactError("unsupported DEX magic/version")
    if _u32(raw, 32) != len(raw) or _u32(raw, 36) != 0x70 or _u32(raw, 40) != 0x12345678:
        raise ArtifactError("invalid DEX header authority")
    if raw[12:32] != hashlib.sha1(raw[32:]).digest():
        raise ArtifactError("DEX SHA-1 signature mismatch")
    if _u32(raw, 8) != zlib.adler32(raw[12:]) & 0xffffffff:
        raise ArtifactError("DEX Adler-32 checksum mismatch")

    string_count, string_off = _u32(raw, 56), _u32(raw, 60)
    type_count, type_off = _u32(raw, 64), _u32(raw, 68)
    proto_count, proto_off = _u32(raw, 72), _u32(raw, 76)
    field_count, field_off = _u32(raw, 80), _u32(raw, 84)
    method_count, method_off = _u32(raw, 88), _u32(raw, 92)
    class_count, class_off = _u32(raw, 96), _u32(raw, 100)
    for size, offset, width, label in (
        (string_count, string_off, 4, "string table"),
        (type_count, type_off, 4, "type table"),
        (proto_count, proto_off, 12, "prototype table"),
        (field_count, field_off, 8, "field table"),
        (method_count, method_off, 8, "method table"),
        (class_count, class_off, 32, "class table"),
    ):
        _section(raw, size, offset, width, label)
    if not 0 < string_count <= 10000 or not 0 < type_count <= 5000:
        raise ArtifactError("DEX identifier counts exceed bound")

    strings = []
    for index in range(string_count):
        string_offset = _u32(raw, string_off + index * 4)
        if string_offset < 0x70 or string_offset >= len(raw):
            raise ArtifactError("DEX string data offset outside file")
        value, _ = _mutf8(raw, string_offset)
        strings.append(value)
    types = []
    for index in range(type_count):
        string_index = _u32(raw, type_off + index * 4)
        if string_index >= len(strings):
            raise ArtifactError("DEX type string index outside table")
        types.append(strings[string_index])
    methods = []
    for index in range(method_count):
        at = method_off + index * 8
        class_index, proto_index, name_index = _u16(raw, at), _u16(raw, at + 2), _u32(raw, at + 4)
        if class_index >= len(types) or proto_index >= proto_count or name_index >= len(strings):
            raise ArtifactError("DEX method identifier outside table")
        methods.append((types[class_index], proto_index, strings[name_index]))
    class_data = {}
    descriptors = []
    for index in range(class_count):
        at = class_off + index * 32
        class_index, data_offset = _u32(raw, at), _u32(raw, at + 24)
        if class_index >= len(types) or data_offset >= len(raw):
            raise ArtifactError("DEX class definition outside table")
        descriptor = types[class_index]
        if descriptor in class_data:
            raise ArtifactError("duplicate DEX class definition")
        class_data[descriptor] = data_offset
        descriptors.append(descriptor)
    if frozenset(descriptors) != EXPECTED_CLASS_DESCRIPTORS or len(descriptors) != 14:
        raise ArtifactError("DEX class definitions differ from exact collector allowlist")
    string_set = frozenset(strings)
    encoded_strings = []
    for value in strings:
        encoded = value.encode("utf-8")
        encoded_strings.append(len(encoded).to_bytes(4, "big") + encoded)
    string_authority = {
        "count": len(strings),
        "sha256": _sha256(b"".join(encoded_strings)),
    }
    if string_authority != {
            "count": EXPECTED_DEX_STRING_COUNT,
            "sha256": EXPECTED_DEX_STRING_SHA256}:
        raise ArtifactError("DEX exact string-table authority changed")
    missing = REQUIRED_DEX_STRINGS - string_set
    if missing:
        raise ArtifactError("DEX lacks required collector string: " + min(missing))
    if "native-viewport-ink-evidence-v1" in string_set:
        raise ArtifactError("stale schema-v1 collector DEX is forbidden")

    main_descriptor = "L" + MAIN_CLASS.replace(".", "/") + ";"
    entrypoints = []
    for class_descriptor in sorted(EXPECTED_CLASS_DESCRIPTORS):
        data_offset = class_data[class_descriptor]
        if data_offset == 0:
            continue
        at = data_offset
        static_fields, at = _uleb(raw, at)
        instance_fields, at = _uleb(raw, at)
        direct_count, at = _uleb(raw, at)
        virtual_count, at = _uleb(raw, at)
        if max(static_fields, instance_fields, direct_count, virtual_count) > 10000:
            raise ArtifactError("DEX class data counts exceed bound")
        at = _skip_encoded_fields(raw, at, static_fields)
        at = _skip_encoded_fields(raw, at, instance_fields)
        direct, at = _encoded_methods(raw, at, direct_count)
        virtual, at = _encoded_methods(raw, at, virtual_count)
        for kind, encoded in (("direct", direct), ("virtual", virtual)):
            for method_index, access, code_offset in encoded:
                if method_index >= len(methods):
                    raise ArtifactError("DEX encoded method index outside table")
                declaring, prototype, name = methods[method_index]
                if declaring != class_descriptor:
                    raise ArtifactError("DEX encoded method belongs to another class")
                if name != "main":
                    continue
                proto_at = proto_off + prototype * 12
                return_type = _u32(raw, proto_at + 4)
                parameters = _u32(raw, proto_at + 8)
                if return_type >= len(types):
                    raise ArtifactError("DEX main return type outside table")
                signature = (_type_list(raw, parameters, types), types[return_type])
                entrypoints.append(
                    (declaring, kind, access, code_offset, signature))
    expected_signature = (("[Ljava/lang/String;",), "V")
    expected_entrypoint = (main_descriptor, "direct")
    if (len(entrypoints) != 1 or entrypoints[0][:2] != expected_entrypoint or
            entrypoints[0][2] & 0x9 != 0x9 or
            entrypoints[0][2] & (0x100 | 0x400) != 0 or
            entrypoints[0][3] == 0 or entrypoints[0][4] != expected_signature):
        raise ArtifactError("DEX entrypoint inventory is not exactly one public static main(String[])")

    map_offset = _u32(raw, 52)
    if map_offset < 0x70 or map_offset + 4 > len(raw):
        raise ArtifactError("DEX map is outside file")
    map_count = _u32(raw, map_offset)
    if not 1 <= map_count <= 128 or map_count > (len(raw) - map_offset - 4) // 12:
        raise ArtifactError("DEX map count is outside bound")
    map_types, map_offsets = set(), []
    for index in range(map_count):
        at = map_offset + 4 + index * 12
        item_type, item_count, item_offset = _u16(raw, at), _u32(raw, at + 4), _u32(raw, at + 8)
        if item_type in map_types or item_count == 0 or item_offset >= len(raw):
            raise ArtifactError("invalid DEX map entry")
        map_types.add(item_type)
        map_offsets.append(item_offset)
    if map_types & {0x0007, 0x0008}:
        raise ArtifactError("DEX dynamic invocation bootstrap is forbidden")
    if map_offsets != sorted(map_offsets) or 0x1000 not in map_types:
        raise ArtifactError("DEX map ordering/authority is invalid")
    return {"bytes": len(raw), "sha256": _sha256(raw),
            "classDescriptors": sorted(descriptors), "dexVersion": raw[4:7].decode("ascii"),
            "stringTable": string_authority}


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError("duplicate JSON authority field")
        result[key] = value
    return result


def _reject_json_float(_):
    raise ArtifactError("floating-point JSON values are forbidden")


def _reject_json_constant(_):
    raise ArtifactError("nonfinite JSON values are forbidden")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def _read_zip(path: Path) -> tuple[bytes, dict[str, bytes]]:
    raw = _read_regular(path, MAX_ARTIFACT_BYTES)
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            if archive.testzip() is not None:
                raise ArtifactError("artifact ZIP CRC failed")
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if tuple(names) != EXPECTED_JAR_ENTRIES or len(names) != len(set(names)):
                raise ArtifactError("artifact JAR inventory/order differs from exact allowlist")
            payloads = {}
            for info in infos:
                parsed = PurePosixPath(info.filename)
                if (info.is_dir() or info.date_time != CANONICAL_TIMESTAMP or
                        info.compress_type != zipfile.ZIP_STORED or
                        info.create_system != 0 or
                        info.external_attr != CANONICAL_EXTERNAL_ATTR or
                        info.flag_bits != 0 or info.file_size > MAX_DEX_BYTES or
                        any(part in ("", ".", "..") for part in parsed.parts)):
                    raise ArtifactError("artifact JAR member metadata is not canonical")
                payloads[info.filename] = archive.read(info)
    except (OSError, zipfile.BadZipFile) as error:
        raise ArtifactError("artifact is not a valid bounded ZIP") from error
    if raw != _canonical_zip_bytes(payloads):
        raise ArtifactError("artifact JAR wire bytes are not canonical")
    return raw, payloads


def _tool_authority(args) -> dict[str, object]:
    values = {
        "jdkRelease": (Path(args.jdk_release), "jdk/release", 4096),
        "jdkModules": (Path(args.jdk_modules), "jdk/lib/modules", 256 * 1024 * 1024),
        "javac": (Path(args.javac), "jdk/bin/javac.exe", 1024 * 1024),
        "java": (Path(args.java), "jdk/bin/java.exe", 1024 * 1024),
        "androidJar": (Path(args.android_jar), "android/platforms/android-35/android.jar", 64 * 1024 * 1024),
        "d8Launcher": (Path(args.d8_launcher), "android/build-tools/35.0.0/d8.bat", 64 * 1024),
        "d8Jar": (Path(args.d8_jar), "android/build-tools/35.0.0/lib/d8.jar", 64 * 1024 * 1024),
        "python": (Path(args.python), "python/python.exe", 1024 * 1024),
    }
    result = {}
    for key in sorted(values):
        path, logical, limit = values[key]
        result[key] = _file_record(path, logical, limit, PINNED_FILES[key])
    result["jdkBinTree"] = _tree_record(Path(args.jdk_bin))
    return result


def package_artifact(args) -> dict[str, object]:
    source = _file_record(Path(args.source), SOURCE_LOGICAL_PATH,
                           MAX_SOURCE_BYTES, (48933, SOURCE_SHA256), True)
    classes, _ = _class_records(Path(args.classes))
    dex_raw = _read_regular(Path(args.dex), MAX_DEX_BYTES)
    dex = verify_dex(dex_raw)
    packager = _file_record(Path(__file__), "saved_ink_reader_artifact.py",
                            1024 * 1024, canonical_source=True)
    authority = {
        "artifactSchema": ARTIFACT_SCHEMA,
        "buildRecipe": BUILD_RECIPE,
        "buildToolsVersion": BUILD_TOOLS_VERSION,
        "classes": classes,
        "collectorSchema": COLLECTOR_SCHEMA,
        "compileSdk": COMPILE_SDK,
        "dex": dex,
        "framePrefix": FRAME_PREFIX,
        "mainClass": MAIN_CLASS,
        "minApi": MIN_API,
        "packager": packager,
        "source": source,
        "tools": _tool_authority(args),
    }
    authority_raw = _canonical_json(authority)
    if len(authority_raw) > MAX_AUTHORITY_BYTES:
        raise ArtifactError("artifact authority exceeds bound")
    _write_zip(Path(args.output), {
        EXPECTED_JAR_ENTRIES[0]: MANIFEST,
        EXPECTED_JAR_ENTRIES[1]: authority_raw,
        EXPECTED_JAR_ENTRIES[2]: dex_raw,
    })
    return verify_artifact(Path(args.output))


def _validate_hash_record(value, path: str, expected=None) -> None:
    if (type(value) is not dict or set(value) != {"path", "bytes", "sha256"} or
            value["path"] != path or type(value["bytes"]) is not int or
            value["bytes"] <= 0 or type(value["sha256"]) is not str or
            re.fullmatch("[0-9a-f]{64}", value["sha256"]) is None):
        raise ArtifactError("invalid artifact authority hash record: " + path)
    if expected is not None and (value["bytes"], value["sha256"]) != expected:
        raise ArtifactError("artifact authority disagrees with pinned input: " + path)


def verify_artifact(path: Path) -> dict[str, object]:
    raw, payloads = _read_zip(path)
    if payloads[EXPECTED_JAR_ENTRIES[0]] != MANIFEST:
        raise ArtifactError("artifact manifest bytes changed")
    authority_raw = payloads[EXPECTED_JAR_ENTRIES[1]]
    if len(authority_raw) > MAX_AUTHORITY_BYTES:
        raise ArtifactError("artifact authority exceeds bound")
    try:
        authority = json.loads(
            authority_raw.decode("ascii"), object_pairs_hook=_strict_object,
            parse_float=_reject_json_float, parse_constant=_reject_json_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactError("invalid artifact authority JSON") from error
    if authority_raw != _canonical_json(authority):
        raise ArtifactError("artifact authority is not canonical JSON")
    required = {"artifactSchema", "buildRecipe", "buildToolsVersion", "classes",
                "collectorSchema", "compileSdk", "dex", "framePrefix", "mainClass",
                "minApi", "packager", "source", "tools"}
    if type(authority) is not dict or set(authority) != required:
        raise ArtifactError("artifact authority fields differ from exact contract")
    scalars = {
        "artifactSchema": ARTIFACT_SCHEMA, "buildToolsVersion": BUILD_TOOLS_VERSION,
        "collectorSchema": COLLECTOR_SCHEMA, "compileSdk": COMPILE_SDK,
        "framePrefix": FRAME_PREFIX, "mainClass": MAIN_CLASS, "minApi": MIN_API,
    }
    if any(authority[key] != value for key, value in scalars.items()):
        raise ArtifactError("artifact authority scalar changed")
    if authority["buildRecipe"] != BUILD_RECIPE:
        raise ArtifactError("artifact build recipe changed")
    _validate_hash_record(authority["source"], SOURCE_LOGICAL_PATH,
                           (48933, SOURCE_SHA256))
    current_packager = _file_record(
        Path(__file__), "saved_ink_reader_artifact.py", 1024 * 1024,
        canonical_source=True)
    _validate_hash_record(authority["packager"], "saved_ink_reader_artifact.py")
    if authority["packager"] != current_packager:
        raise ArtifactError("artifact was not produced by this exact reviewed packager")
    tools = authority["tools"]
    if type(tools) is not dict or set(tools) != set(PINNED_FILES) | {"jdkBinTree"}:
        raise ArtifactError("artifact tool authority inventory changed")
    logical = {
        "jdkRelease": "jdk/release", "jdkModules": "jdk/lib/modules",
        "javac": "jdk/bin/javac.exe", "java": "jdk/bin/java.exe",
        "androidJar": "android/platforms/android-35/android.jar",
        "d8Launcher": "android/build-tools/35.0.0/d8.bat",
        "d8Jar": "android/build-tools/35.0.0/lib/d8.jar",
        "python": "python/python.exe",
    }
    for key in PINNED_FILES:
        _validate_hash_record(tools[key], logical[key], PINNED_FILES[key])
    if tools["jdkBinTree"] != PINNED_JDK_BIN_TREE:
        raise ArtifactError("artifact JDK tree authority changed")
    classes = authority["classes"]
    if type(classes) is not list or len(classes) != len(EXPECTED_CLASS_PATHS):
        raise ArtifactError("artifact class authority count changed")
    for record, expected_path in zip(classes, sorted(EXPECTED_CLASS_PATHS)):
        _validate_hash_record(record, expected_path)
    dex = verify_dex(payloads[EXPECTED_JAR_ENTRIES[2]])
    if authority["dex"] != dex:
        raise ArtifactError("artifact DEX differs from embedded authority")
    return {"bytes": len(raw), "sha256": _sha256(raw),
            "authoritySha256": _sha256(authority_raw), "dex": dex,
            "entries": list(EXPECTED_JAR_ENTRIES)}


def verify_final_artifact(path: Path, artifact_sha256: str, dex_sha256: str,
                          authority_sha256: str) -> dict[str, object]:
    expected = (artifact_sha256, dex_sha256, authority_sha256)
    if any(type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None
           for value in expected):
        raise ArtifactError("final artifact authority pins are not canonical SHA-256")
    result = verify_artifact(path)
    actual = (result["sha256"], result["dex"]["sha256"],
              result["authoritySha256"])
    if actual != expected:
        raise ArtifactError("artifact differs from the exact reviewed final authority")
    return result


def _reviewed_source_records(build_script: Path, tests: Path) -> dict[str, object]:
    return {
        "buildScript": _file_record(build_script, "build-saved-ink-reader.ps1",
                                    256 * 1024, canonical_source=True),
        "packager": _file_record(Path(__file__), "saved_ink_reader_artifact.py",
                                 1024 * 1024, canonical_source=True),
        "tests": _file_record(tests, "test_saved_ink_reader_artifact.py",
                              512 * 1024, canonical_source=True),
    }


def _require_distinct_build_outputs(artifact: Path, repeat: Path) -> None:
    try:
        first, second = os.lstat(artifact), os.lstat(repeat)
    except OSError as error:
        raise ArtifactError("clean-build output is unavailable") from error
    if (not stat.S_ISREG(first.st_mode) or not stat.S_ISREG(second.st_mode) or
            _identity(first) == _identity(second)):
        raise ArtifactError("clean builds must be distinct regular file identities")


def write_provenance(artifact: Path, repeat: Path, output: Path,
                     build_script: Path, tests: Path) -> dict[str, object]:
    _require_distinct_build_outputs(artifact, repeat)
    first, second = verify_artifact(artifact), verify_artifact(repeat)
    first_raw = _read_regular(artifact, MAX_ARTIFACT_BYTES)
    second_raw = _read_regular(repeat, MAX_ARTIFACT_BYTES)
    if first_raw != second_raw or first != second:
        raise ArtifactError("two clean SavedInk device builds are not byte-identical")
    value = {
        "artifact": {"basename": Path(artifact).name, "bytes": first["bytes"],
                     "sha256": first["sha256"]},
        "artifactAuthoritySha256": first["authoritySha256"],
        "dex": {"bytes": first["dex"]["bytes"], "sha256": first["dex"]["sha256"]},
        "provenanceSchema": PROVENANCE_SCHEMA,
        "reviewedSources": _reviewed_source_records(build_script, tests),
        "repeatArtifact": {"basename": Path(repeat).name, "bytes": second["bytes"],
                           "sha256": second["sha256"]},
        "twoCleanBuildsByteIdentical": True,
    }
    output = Path(output).absolute()
    _publish_bytes_no_replace(output, _canonical_json(value) + b"\n",
                              MAX_AUTHORITY_BYTES)
    return value


def verify_provenance(artifact: Path, repeat: Path, provenance: Path,
                      build_script: Path, tests: Path) -> dict[str, object]:
    _require_distinct_build_outputs(artifact, repeat)
    raw = _read_regular(provenance, MAX_AUTHORITY_BYTES)
    if not raw.endswith(b"\n") or b"\r" in raw or raw.count(b"\n") != 1:
        raise ArtifactError("provenance is not one LF-terminated record")
    try:
        value = json.loads(
            raw[:-1].decode("ascii"), object_pairs_hook=_strict_object,
            parse_float=_reject_json_float, parse_constant=_reject_json_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactError("invalid provenance JSON") from error
    if raw[:-1] != _canonical_json(value):
        raise ArtifactError("provenance is not canonical JSON")
    expected_keys = {"artifact", "artifactAuthoritySha256", "dex", "provenanceSchema",
                     "reviewedSources", "repeatArtifact", "twoCleanBuildsByteIdentical"}
    if (type(value) is not dict or set(value) != expected_keys or
            value["provenanceSchema"] != PROVENANCE_SCHEMA or
            value["twoCleanBuildsByteIdentical"] is not True):
        raise ArtifactError("provenance fields differ from exact contract")
    first, second = verify_artifact(artifact), verify_artifact(repeat)
    expected = {
        "artifact": {"basename": Path(artifact).name, "bytes": first["bytes"],
                     "sha256": first["sha256"]},
        "artifactAuthoritySha256": first["authoritySha256"],
        "dex": {"bytes": first["dex"]["bytes"], "sha256": first["dex"]["sha256"]},
        "provenanceSchema": PROVENANCE_SCHEMA,
        "reviewedSources": _reviewed_source_records(build_script, tests),
        "repeatArtifact": {"basename": Path(repeat).name, "bytes": second["bytes"],
                           "sha256": second["sha256"]},
        "twoCleanBuildsByteIdentical": True,
    }
    if value != expected or _read_regular(artifact, MAX_ARTIFACT_BYTES) != \
            _read_regular(repeat, MAX_ARTIFACT_BYTES):
        raise ArtifactError("provenance does not bind two identical artifacts")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    class_jar = commands.add_parser("class-jar")
    class_jar.add_argument("--classes", required=True)
    class_jar.add_argument("--output", required=True)
    package = commands.add_parser("package")
    for option in ("source", "classes", "dex", "output", "jdk-release",
                   "jdk-modules", "jdk-bin", "javac", "java", "android-jar",
                   "d8-launcher", "d8-jar", "python"):
        package.add_argument("--" + option, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--artifact", required=True)
    verify_final = commands.add_parser("verify-final")
    verify_final.add_argument("--artifact", required=True)
    verify_final.add_argument("--expected-artifact-sha256", required=True)
    verify_final.add_argument("--expected-dex-sha256", required=True)
    verify_final.add_argument("--expected-authority-sha256", required=True)
    publish = commands.add_parser("publish-copy")
    publish.add_argument("--source", required=True)
    publish.add_argument("--output", required=True)
    provenance = commands.add_parser("provenance")
    provenance.add_argument("--artifact", required=True)
    provenance.add_argument("--repeat", required=True)
    provenance.add_argument("--output", required=True)
    provenance.add_argument("--build-script", required=True)
    provenance.add_argument("--tests", required=True)
    verify_prov = commands.add_parser("verify-provenance")
    verify_prov.add_argument("--artifact", required=True)
    verify_prov.add_argument("--repeat", required=True)
    verify_prov.add_argument("--provenance", required=True)
    verify_prov.add_argument("--build-script", required=True)
    verify_prov.add_argument("--tests", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "class-jar":
            write_class_jar(Path(args.classes), Path(args.output))
            result = {"status": "CLASS_JAR_CREATED", "sha256": _sha256(
                _read_regular(Path(args.output), MAX_ARTIFACT_BYTES))}
        elif args.command == "package":
            result = {"status": "ARTIFACT_CREATED", **package_artifact(args)}
        elif args.command == "verify":
            result = {"status": "ARTIFACT_VERIFIED", **verify_artifact(Path(args.artifact))}
        elif args.command == "verify-final":
            result = {"status": "FINAL_ARTIFACT_VERIFIED", **verify_final_artifact(
                Path(args.artifact), args.expected_artifact_sha256,
                args.expected_dex_sha256, args.expected_authority_sha256)}
        elif args.command == "publish-copy":
            copied = _read_regular(Path(args.source), MAX_ARTIFACT_BYTES)
            _publish_bytes_no_replace(Path(args.output), copied, MAX_ARTIFACT_BYTES)
            result = {"status": "COPY_PUBLISHED", "bytes": len(copied),
                      "sha256": _sha256(copied)}
        elif args.command == "provenance":
            result = {"status": "PROVENANCE_CREATED", **write_provenance(
                Path(args.artifact), Path(args.repeat), Path(args.output),
                Path(args.build_script), Path(args.tests))}
        else:
            result = {"status": "PROVENANCE_VERIFIED", **verify_provenance(
                Path(args.artifact), Path(args.repeat), Path(args.provenance),
                Path(args.build_script), Path(args.tests))}
        print(_canonical_json(result).decode("ascii"))
        return 0
    except (ArtifactError, OSError, OverflowError, ValueError) as error:
        print(_canonical_json({"status": "INVALID_ARTIFACT", "reason": str(error)}).decode("ascii"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
