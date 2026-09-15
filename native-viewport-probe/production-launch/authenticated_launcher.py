"""Authenticated entry point for the probe's production Python CLIs.

This file is never executed by pathname directly.  The reviewed PowerShell
launcher first captures these exact bytes from a regular no-follow file in a
fresh ``python -I -S -E -s -c`` process.  This second stage then captures every
local source reachable by the selected command before importing any of them.

The standard library and CPython executable remain part of the documented host
trust boundary.  Project modules do not: they are loaded only from the retained,
SHA-pinned byte snapshots below.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.abc
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import types


FAIL_CLOSED = 126
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_CAPTURED_OUTPUT = 64 * 1024 * 1024
CONCRETE_PATH_TYPE = type(Path("."))
MUTATING_ARTIFACT_COMMANDS = frozenset({
    "class-jar", "package", "publish-copy", "provenance",
})
SAVED_INK_CLASS_JAR_SHA256 = (
    "214afe65b35f446705d207c8d90493bd1bf2370403e7723461bb7e73db8f7656"
)
SAVED_INK_ARTIFACT_SHA256 = (
    "fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2"
)
SAVED_INK_AUTHORITY_SHA256 = (
    "c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c"
)
SAVED_INK_DEX_SHA256 = (
    "ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097"
)
SAVED_INK_DEX_STRING_SHA256 = (
    "ad0e1cfff35b9d31bb1c84f56258617789d0f86984c537fffc06f14e55542d81"
)
SAVED_INK_CLASS_DESCRIPTORS = (
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$CanonicalArray;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$CanonicalObject;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$CanonicalWriter;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$CloseAction;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$CloseStack;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$EncodingBudget;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FileIdentity;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FirmwareAuthority$1;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FirmwareAuthority$2;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FirmwareAuthority$3;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FirmwareAuthority$4;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FirmwareAuthority$5;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader$FirmwareAuthority;",
    "Lcom/techrebbe/supernote/viewportprobe/SavedInkReader;",
)
SAVED_INK_ENTRIES = (
    "META-INF/MANIFEST.MF",
    "META-INF/native-viewport-saved-ink-reader.json",
    "classes.dex",
)

# These are canonical-LF authorities.  Uniform LF and CRLF checkouts are
# equivalent; mixed/bare-CR/Unicode line separators fail.  Any semantic source
# update still requires an explicit reviewed launcher-authority update.
SOURCE_SHA256 = {
    "bounded_command_runner.py":
        "b5b643c035114b503952ccf45363d07dbcc3c6f31b119ae3c9c95f719a61d288",
    "ink_oracle.py":
        "13ebdf78fa90896256e177e768b89bd06b8cbddfb15c8b44a2aa7e89499ac99f",
    "inspect_loader_bindings.py":
        "01799d3d3d5dbc2e15be885331d74a32cb81572529d6a7873239e746e277c592",
    "inspect_loader_dependencies.py":
        "462eb4af835684e2df840f40b0e9a10f2043c94c553bd6a887cc2e664cf53ee9",
    "pinned_elftools_gate.py":
        "ff7021874c16321f71b4309e131d78061d0d71c4cd6d14743574fc4eb229cd2f",
    "saved_ink_reader_artifact.py":
        "53b68403b9d517a123f32c02a25abc48077cc83d0b9a1617ddaac222d2d1c29c",
    "test_display_host_scope.py":
        "1c341101d3a1b90eaf0bc0e4df61696b4b7c1e435f1530a74360ad63dbeb9b8d",
    "test_saved_ink_reader_artifact.py":
        "7e51b717d5fe2ac3b534af90d2529095429e4aedfd6c6d13a424bd5674062d15",
}

MODE_SOURCES = {
    "display-inspect": (
        "bounded_command_runner.py",
        "inspect_loader_bindings.py",
        "inspect_loader_dependencies.py",
        "pinned_elftools_gate.py",
        "test_display_host_scope.py",
    ),
    "display-verify": (
        "bounded_command_runner.py",
        "inspect_loader_bindings.py",
        "inspect_loader_dependencies.py",
        "pinned_elftools_gate.py",
        "test_display_host_scope.py",
    ),
    "ink-oracle": (
        "bounded_command_runner.py",
        "ink_oracle.py",
        "inspect_loader_dependencies.py",
        "pinned_elftools_gate.py",
    ),
    "saved-ink-artifact": (
        "saved_ink_reader_artifact.py",
    ),
    "saved-ink-artifact-tests": (
        "saved_ink_reader_artifact.py",
        "test_saved_ink_reader_artifact.py",
    ),
}

TARGET_MODULE = {
    "display-inspect": "test_display_host_scope",
    "display-verify": "test_display_host_scope",
    "ink-oracle": "ink_oracle",
    "saved-ink-artifact": "saved_ink_reader_artifact",
    "saved-ink-artifact-tests": "test_saved_ink_reader_artifact",
}


class LaunchError(RuntimeError):
    pass


class PublicationUncertain(LaunchError):
    """The inspector may have committed authority; retry is prohibited."""


def _canonical_source(raw):
    if type(raw) is not bytes or any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        raise LaunchError("authenticated source encoding changed")
    if b"\r" not in raw:
        return raw
    if (raw.count(b"\r") != raw.count(b"\r\n") or
            raw.count(b"\n") != raw.count(b"\r\n")):
        raise LaunchError("authenticated source has mixed newlines")
    return raw.replace(b"\r\n", b"\n")


def _identity(value):
    fields = (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        getattr(value, "st_uid", 0),
        getattr(value, "st_gid", 0),
        getattr(value, "st_rdev", 0),
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_file_attributes", 0),
    )
    # Merely opening a file through the Windows CRT can change ctime.  POSIX
    # ctime remains an important same-inode mutation/ABA witness.
    if os.name == "posix":
        fields += (
            getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
        )
    return fields


def _read_descriptor(descriptor, size):
    if type(size) is not int or size < 1 or size > MAX_SOURCE_BYTES:
        raise LaunchError("invalid authenticated source size")
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks = []
        remaining = size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as error:
        raise LaunchError("authenticated source read failed") from error
    raw = b"".join(chunks)
    if len(raw) != size:
        raise LaunchError("authenticated source size changed")
    return raw


class _RetainedSource:
    """One exact named regular source retained through terminal reporting."""

    def __init__(self, root, name, expected):
        if (type(root) is not CONCRETE_PATH_TYPE or type(name) is not str or
                name not in SOURCE_SHA256 or SOURCE_SHA256[name] != expected or
                "/" in name or "\\" in name or name in ("", ".", "..")):
            raise LaunchError("invalid authenticated source authority")
        self.path = root / name
        self.expected = expected
        self.descriptor = None
        self.opened = None
        self.file_bytes = None
        self.raw = None

    def open(self):
        try:
            named = os.lstat(self.path)
            if (not stat.S_ISREG(named.st_mode) or
                    getattr(named, "st_file_attributes", 0) & 0x400):
                raise LaunchError("authenticated source is not a regular file")
            flags = (
                os.O_RDONLY |
                getattr(os, "O_CLOEXEC", 0) |
                getattr(os, "O_NONBLOCK", 0) |
                getattr(os, "O_NOFOLLOW", 0) |
                getattr(os, "O_BINARY", 0) |
                getattr(os, "O_NOINHERIT", 0)
            )
            self.descriptor = os.open(self.path, flags)
            os.set_inheritable(self.descriptor, False)
            if os.get_inheritable(self.descriptor):
                raise LaunchError("authenticated source descriptor is inheritable")
            self.opened = os.fstat(self.descriptor)
            if (not stat.S_ISREG(self.opened.st_mode) or
                    getattr(self.opened, "st_file_attributes", 0) & 0x400 or
                    _identity(self.opened) != _identity(named)):
                raise LaunchError("authenticated source name changed while opening")
            self.file_bytes = _read_descriptor(
                self.descriptor, self.opened.st_size)
            self.raw = _canonical_source(self.file_bytes)
            if (hashlib.sha256(self.raw).hexdigest() != self.expected or
                    _identity(os.fstat(self.descriptor)) != _identity(self.opened) or
                    _identity(os.lstat(self.path)) != _identity(self.opened)):
                raise LaunchError("authenticated source differs from reviewed bytes")
            return self
        except LaunchError:
            self.close()
            raise
        except (OSError, OverflowError, TypeError, ValueError) as error:
            self.close()
            raise LaunchError("authenticated source is unavailable") from error

    def verify(self):
        if self.descriptor is None or self.opened is None or self.raw is None:
            raise LaunchError("authenticated source authority is not retained")
        try:
            opened = os.fstat(self.descriptor)
            named = os.lstat(self.path)
            current = _read_descriptor(self.descriptor, self.opened.st_size)
        except (OSError, OverflowError, TypeError, ValueError) as error:
            raise LaunchError("authenticated source revalidation failed") from error
        if (_identity(opened) != _identity(self.opened) or
                _identity(named) != _identity(self.opened) or
                current != self.file_bytes or
                hashlib.sha256(_canonical_source(current)).hexdigest() !=
                self.expected):
            raise LaunchError("authenticated source changed during command")

    def close(self):
        descriptor, self.descriptor = self.descriptor, None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                raise LaunchError("authenticated source close failed") from error


class _CapturedLoader(importlib.abc.Loader):
    def __init__(self, path, raw, authority_sha256):
        self.source = path
        self.raw = raw
        self.authority_sha256 = authority_sha256

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__cached__ = None
        code = compile(self.raw, str(self.source), "exec", dont_inherit=True)
        exec(code, module.__dict__, module.__dict__)


class _CapturedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, sources, authority_sha256, closed_names):
        self.sources = sources
        self.authority_sha256 = authority_sha256
        self.closed_names = frozenset(closed_names)

    def find_spec(self, fullname, path=None, target=None):
        captured = self.sources.get(fullname)
        if captured is None:
            if fullname in self.closed_names:
                raise ModuleNotFoundError(
                    "module is outside authenticated production sources: " + fullname)
            return None
        source, raw = captured
        loader = _CapturedLoader(source, raw, self.authority_sha256)
        return importlib.util.spec_from_file_location(fullname, source, loader=loader)


class _BoundedText(io.TextIOBase):
    def __init__(self, limit):
        self.limit = limit
        self.parts = []
        self.size = 0

    @property
    def encoding(self):
        return "utf-8"

    def writable(self):
        return True

    def write(self, value):
        if type(value) is not str:
            raise TypeError("text output required")
        encoded = value.encode("utf-8")
        if self.size + len(encoded) > self.limit:
            raise LaunchError("production command output exceeds bound")
        self.parts.append(value)
        self.size += len(encoded)
        return len(value)

    def flush(self):
        return None

    def value(self):
        return "".join(self.parts)


def _aggregate_authority(retained):
    records = []
    for source in retained:
        name = source.path.name.encode("utf-8")
        records.append(
            len(name).to_bytes(4, "big") + name +
            len(source.raw).to_bytes(8, "big") +
            hashlib.sha256(source.raw).digest()
        )
    return hashlib.sha256(b"".join(records)).hexdigest()


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LaunchError("duplicate authenticated command result field")
        result[key] = value
    return result


def _reject_terminal_float(_):
    raise LaunchError("floating-point authenticated command results are forbidden")


def _reject_terminal_constant(_):
    raise LaunchError("non-finite authenticated command results are forbidden")


def _is_sha256(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _valid_ink_identity_list(value):
    return (type(value) is list and all(
        type(identity) is list and len(identity) == 4 and
        all(type(part) is int for part in identity)
        for identity in value))


def _valid_ink_comparison(value):
    if (type(value) is not dict or
            set(value) != {"added", "removed", "changed", "unchanged"} or
            not _valid_ink_identity_list(value["added"]) or
            not _valid_ink_identity_list(value["removed"]) or
            type(value["changed"]) is not dict or
            type(value["unchanged"]) is not int or value["unchanged"] < 0):
        return False
    return all(
        type(identity) is str and
        re.fullmatch(r"\(-?\d+, -?\d+, -?\d+, -?\d+\)", identity) is not None and
        type(fields) is list and all(type(field) is str for field in fields)
        for identity, fields in value["changed"].items())


def _valid_dex_result(value):
    return (
        type(value) is dict and
        set(value) == {"bytes", "classDescriptors", "dexVersion", "sha256",
                       "stringTable"} and
        type(value["bytes"]) is int and value["bytes"] == 31108 and
        type(value["classDescriptors"]) is list and
        tuple(value["classDescriptors"]) == SAVED_INK_CLASS_DESCRIPTORS and
        value["dexVersion"] == "039" and
        value["sha256"] == SAVED_INK_DEX_SHA256 and
        type(value["stringTable"]) is dict and
        set(value["stringTable"]) == {"count", "sha256"} and
        type(value["stringTable"]["count"]) is int and
        value["stringTable"]["count"] == 486 and
        value["stringTable"]["sha256"] == SAVED_INK_DEX_STRING_SHA256)


def _valid_hash_record(value, expected_path=None, expected_sha256=None):
    return (
        type(value) is dict and set(value) == {"bytes", "path", "sha256"} and
        type(value["bytes"]) is int and value["bytes"] > 0 and
        type(value["path"]) is str and
        (expected_path is None or value["path"] == expected_path) and
        _is_sha256(value["sha256"]) and
        (expected_sha256 is None or value["sha256"] == expected_sha256))


def _valid_artifact_result(value, status):
    return (
        type(value) is dict and
        set(value) == {"status", "authoritySha256", "bytes", "dex", "entries",
                       "sha256"} and
        value["status"] == status and
        value["authoritySha256"] == SAVED_INK_AUTHORITY_SHA256 and
        type(value["bytes"]) is int and value["bytes"] == 37578 and
        _valid_dex_result(value["dex"]) and
        type(value["entries"]) is list and
        tuple(value["entries"]) == SAVED_INK_ENTRIES and
        value["sha256"] == SAVED_INK_ARTIFACT_SHA256)


def _valid_artifact_reference(value):
    return (
        type(value) is dict and set(value) == {"basename", "bytes", "sha256"} and
        type(value["basename"]) is str and value["basename"].endswith(".jar") and
        value["basename"] not in ("", ".", "..") and
        "/" not in value["basename"] and "\\" not in value["basename"] and
        type(value["bytes"]) is int and value["bytes"] == 37578 and
        value["sha256"] == SAVED_INK_ARTIFACT_SHA256)


def _valid_provenance_result(value, status):
    if (type(value) is not dict or set(value) != {
            "status", "artifact", "artifactAuthoritySha256", "dex",
            "provenanceSchema", "repeatArtifact", "reviewedSources",
            "twoCleanBuildsByteIdentical"} or value["status"] != status or
            not _valid_artifact_reference(value["artifact"]) or
            not _valid_artifact_reference(value["repeatArtifact"]) or
            value["artifactAuthoritySha256"] != SAVED_INK_AUTHORITY_SHA256 or
            type(value["dex"]) is not dict or
            set(value["dex"]) != {"bytes", "sha256"} or
            type(value["dex"]["bytes"]) is not int or
            value["dex"]["bytes"] != 31108 or
            value["dex"]["sha256"] != SAVED_INK_DEX_SHA256 or
            value["provenanceSchema"] !=
            "native-viewport-saved-ink-build-provenance-v1" or
            value["twoCleanBuildsByteIdentical"] is not True):
        return False
    sources = value["reviewedSources"]
    if type(sources) is not dict or set(sources) != {
            "buildScript", "packager", "tests"}:
        return False
    return (
        _valid_hash_record(sources["buildScript"], "build-saved-ink-reader.ps1") and
        _valid_hash_record(
            sources["packager"], "saved_ink_reader_artifact.py",
            SOURCE_SHA256["saved_ink_reader_artifact.py"]) and
        _valid_hash_record(
            sources["tests"], "test_saved_ink_reader_artifact.py",
            SOURCE_SHA256["test_saved_ink_reader_artifact.py"]))


def _validate_ink_output(output, code):
    if (not output.endswith("\n") or output.count("\n") != 1 or
            "\r" in output):
        raise LaunchError("ink oracle emitted an invalid terminal record")
    try:
        value = json.loads(
            output[:-1], object_pairs_hook=_strict_object,
            parse_float=_reject_terminal_float,
            parse_constant=_reject_terminal_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LaunchError("ink oracle emitted invalid JSON") from error
    expected_status = {0: "PASS", 1: "DIFFERENT", 2: "INVALID_EVIDENCE"}.get(code)
    if (type(value) is not dict or expected_status is None or
            value.get("status") != expected_status):
        raise LaunchError("ink oracle result disagrees with process status")
    if expected_status == "INVALID_EVIDENCE":
        if set(value) != {"status", "reason"} or type(value["reason"]) is not str:
            raise LaunchError("invalid ink-oracle rejection record")
    else:
        if (set(value) != {"status", "comparison", "scope"} or
                not _valid_ink_comparison(value["comparison"]) or
                value["scope"] !=
                "captured native records; collector validity is a separate gate"):
            raise LaunchError("invalid ink-oracle comparison record")


def _validate_artifact_output(output, code, command):
    if (not output.endswith("\n") or output.count("\n") != 1 or
            "\r" in output):
        raise LaunchError("artifact tool emitted an invalid terminal record")
    try:
        value = json.loads(
            output[:-1], object_pairs_hook=_strict_object,
            parse_float=_reject_terminal_float,
            parse_constant=_reject_terminal_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LaunchError("artifact tool emitted invalid JSON") from error
    canonical = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"))
    expected_status = {
        "class-jar": "CLASS_JAR_CREATED",
        "package": "ARTIFACT_CREATED",
        "verify": "ARTIFACT_VERIFIED",
        "verify-final": "FINAL_ARTIFACT_VERIFIED",
        "publish-copy": "COPY_PUBLISHED",
        "provenance": "PROVENANCE_CREATED",
        "verify-provenance": "PROVENANCE_VERIFIED",
    }
    if (type(value) is not dict or command not in expected_status or
            canonical != output[:-1] or code not in (0, 2)):
        raise LaunchError("artifact result disagrees with process status")
    if code == 2:
        if (value.get("status") != "INVALID_ARTIFACT" or
                set(value) != {"status", "reason"} or
                type(value["reason"]) is not str):
            raise LaunchError("artifact result disagrees with process status")
        return
    status = expected_status[command]
    if command == "class-jar":
        valid = (set(value) == {"status", "sha256"} and
                 value["status"] == status and
                 value["sha256"] == SAVED_INK_CLASS_JAR_SHA256)
    elif command in ("package", "verify", "verify-final"):
        valid = _valid_artifact_result(value, status)
    elif command == "publish-copy":
        valid = (set(value) == {"status", "bytes", "sha256"} and
                 value["status"] == status and type(value["bytes"]) is int and
                 0 <= value["bytes"] <= 4 * 1024 * 1024 and
                 _is_sha256(value["sha256"]))
    else:
        valid = _valid_provenance_result(value, status)
    if not valid:
        raise LaunchError("artifact result disagrees with process status")


def _validate_artifact_test_output(output, code):
    expected = {
        0: "SAVED_INK_READER_ARTIFACT_TESTS_PASS tests=12\n",
        1: "SAVED_INK_READER_ARTIFACT_TESTS_FAILED tests=12\n",
    }.get(code)
    if expected is None or output != expected:
        raise LaunchError("artifact test result disagrees with process status")


def _validate_success_output(mode, output, code, errors, arguments=()):
    if (mode.startswith("display-") and code == 2 and not output and
            errors == "PACKAGED_PUBLICATION_REVIEW_REQUIRED\n"):
        return
    if errors:
        raise LaunchError("authenticated command unexpectedly wrote stderr")
    if mode == "display-inspect":
        if code != 0 or output != "PACKAGED_PERMISSION_SURFACES_EMPTY\n":
            raise LaunchError("display inspector terminal result is not exact")
    elif mode == "display-verify":
        if (code != 0 or re.fullmatch(
                r"PACKAGED_APK_AUTHORITY_VERIFIED sha256=[0-9a-f]{64}\n",
                output) is None):
            raise LaunchError("display verifier terminal result is not exact")
    elif mode == "ink-oracle":
        _validate_ink_output(output, code)
    elif mode == "saved-ink-artifact":
        _validate_artifact_output(
            output, code, arguments[0] if arguments else None)
    else:
        _validate_artifact_test_output(output, code)


def _neutralize_terminal(attribute):
    stream = getattr(sys, attribute, None)
    descriptor = None
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        pass
    if type(descriptor) is int and descriptor >= 0:
        null_descriptor = None
        try:
            null_descriptor = os.open(
                os.devnull, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
            if null_descriptor != descriptor:
                os.dup2(null_descriptor, descriptor)
        except OSError:
            pass
        finally:
            if null_descriptor is not None and null_descriptor != descriptor:
                try:
                    os.close(null_descriptor)
                except OSError:
                    pass
    try:
        setattr(sys, attribute, io.StringIO())
    except BaseException:
        pass


def _invoke(mode, root, arguments):
    expected_names = MODE_SOURCES.get(mode)
    if (expected_names is None or type(root) is not CONCRETE_PATH_TYPE or
            type(expected_names) is not tuple or not expected_names or
            len(expected_names) != len(set(expected_names)) or
            tuple(sorted(expected_names)) != expected_names):
        raise LaunchError("invalid authenticated production mode")
    try:
        root = root.absolute()
        root_info = os.lstat(root)
    except (OSError, TypeError, ValueError) as error:
        raise LaunchError("production source root is unavailable") from error
    if (not stat.S_ISDIR(root_info.st_mode) or
            getattr(root_info, "st_file_attributes", 0) & 0x400):
        raise LaunchError("production source root is not a regular directory")

    retained = []
    finder = None
    target = None
    output = _BoundedText(MAX_CAPTURED_OUTPUT)
    errors = _BoundedText(1024 * 1024)
    code = FAIL_CLOSED
    committed = False
    try:
        for name in expected_names:
            retained.append(_RetainedSource(root, name, SOURCE_SHA256[name]).open())
        if _identity(os.lstat(root)) != _identity(root_info):
            raise LaunchError("production source root changed during capture")
        sources = {
            item.path.stem: (item.path, item.raw)
            for item in retained
            if item.path.name not in ("bounded_command_runner.py",
                                      "pinned_elftools_gate.py")
        }
        closed_names = {Path(name).stem for name in SOURCE_SHA256}
        if any(name in sys.modules for name in closed_names):
            raise LaunchError("a production project module was imported before capture")
        authority = _aggregate_authority(retained)
        finder = _CapturedFinder(sources, authority, closed_names)
        sys.meta_path.insert(0, finder)
        target_name = TARGET_MODULE[mode]
        target = importlib.util.module_from_spec(
            finder.find_spec(target_name))
        sys.modules[target_name] = target
        target.__spec__.loader.exec_module(target)
        loader = target.__spec__.loader
        if (type(loader) is not _CapturedLoader or
                loader.authority_sha256 != authority or
                loader.raw is not sources[target_name][1]):
            raise LaunchError("target escaped authenticated production sources")
        old_argv = sys.argv
        try:
            if mode == "display-inspect":
                sys.argv = [str(sources[target_name][0]), "--inspect-package", *arguments]
            elif mode == "display-verify":
                sys.argv = [str(sources[target_name][0]), "--verify-package", *arguments]
            else:
                sys.argv = [str(sources[target_name][0]), *arguments]
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                if mode.startswith("display-"):
                    target._run_requested_mode()
                    code = 0
                    committed = mode == "display-inspect"
                else:
                    if (mode == "saved-ink-artifact" and arguments and
                            arguments[0] in MUTATING_ARTIFACT_COMMANDS):
                        # A no-replace output may be committed anywhere inside
                        # the target call.  Treat all later uncertainty as
                        # non-retryable from the start of such a command.
                        committed = True
                    result = target.main()
                    code = result if type(result) is int else FAIL_CLOSED
        except BaseException as error:
            publication_type = getattr(
                getattr(target, "publication", None),
                "PublicationReviewRequired", None)
            if (mode.startswith("display-") and
                    isinstance(publication_type, type) and
                    isinstance(error, publication_type)):
                errors.write("PACKAGED_PUBLICATION_REVIEW_REQUIRED\n")
                code = 2
                committed = True
            elif isinstance(error, SystemExit):
                code = error.code if type(error.code) is int else FAIL_CLOSED
            else:
                raise LaunchError("authenticated production command failed") from error
        finally:
            sys.argv = old_argv

        try:
            for item in retained:
                item.verify()
            if _identity(os.lstat(root)) != _identity(root_info):
                raise LaunchError("production source root changed during command")
            _validate_success_output(
                mode, output.value(), code, errors.value(), arguments)
            # No terminal result is released until every retained project
            # source descriptor has closed successfully and the captured import
            # authority has been removed.  A post-publication cleanup failure
            # therefore produces review-required status without a stray PASS.
            for item in reversed(retained):
                item.close()
            retained.clear()
            if finder is not None and finder in sys.meta_path:
                sys.meta_path.remove(finder)
            finder = None
            if target is not None:
                sys.modules.pop(TARGET_MODULE[mode], None)
            target = None
            terminal_output = output.value()
            terminal_errors = errors.value()
            if terminal_output:
                sys.stdout.write(terminal_output)
                sys.stdout.flush()
            if terminal_errors:
                sys.stderr.write(terminal_errors)
                sys.stderr.flush()
        except BaseException as error:
            if committed:
                raise PublicationUncertain(
                    "packaged evidence committed before launcher uncertainty") from error
            raise
        return code
    finally:
        if finder is not None and finder in sys.meta_path:
            sys.meta_path.remove(finder)
        if target is not None:
            sys.modules.pop(TARGET_MODULE[mode], None)
        close_error = None
        for item in reversed(retained):
            try:
                item.close()
            except LaunchError as error:
                close_error = close_error or error
        pending = sys.exc_info()[1]
        if close_error is not None and (pending is None or committed):
            if committed:
                raise PublicationUncertain(
                    "packaged evidence committed before source cleanup uncertainty"
                ) from (pending or close_error)
            raise close_error


def main():
    if len(sys.argv) < 3:
        return FAIL_CLOSED
    mode = sys.argv[1]
    try:
        return _invoke(mode, Path(sys.argv[2]), sys.argv[3:])
    except PublicationUncertain:
        _neutralize_terminal("stdout")
        try:
            sys.stderr.write("PACKAGED_PUBLICATION_REVIEW_REQUIRED\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            _neutralize_terminal("stderr")
        return 2
    except (LaunchError, OSError, OverflowError, TypeError, ValueError):
        _neutralize_terminal("stdout")
        try:
            sys.stderr.write("AUTHENTICATED_PRODUCTION_LAUNCH_FAILED\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            _neutralize_terminal("stderr")
        return FAIL_CLOSED


if __name__ == "__main__":
    raise SystemExit(main())
