"""Fail-closed Windows authority for immutable visual-session artifacts.

The visual session harness needs to retain large raw AM/WM wires and full-size
PNG captures without turning a path name into authority.  This module therefore
uses one dedicated private directory, a caller-retained directory identity, an
exclusive writer handle, and a retained handle for every object.  Publication
is CREATE_NEW, complete write, file flush, retained-handle readback, native
handle-relative no-replace rename, second readback, and directory flush.  An
ArtifactRef is not returned before all of those boundaries have succeeded.

Recovery never deletes or replaces a path.  It may promote exactly one complete,
canonical next-sequence pending object with a no-replace rename; torn, duplicate,
out-of-sequence, case-ambiguous, or foreign entries stop recovery unchanged.
The concrete adapter is Windows-only and deliberately has no portable fallback.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import ntpath
import os
import re
import secrets
import threading
from typing import Any

from native_page_visual_session_harness import (
    ARTIFACT_AUTHORITY as HARNESS_ARTIFACT_AUTHORITY,
    MAX_ARTIFACT_BYTES as HARNESS_MAX_ARTIFACT_BYTES,
    ArtifactRef,
    EvidenceRejected,
)


ADAPTER_AUTHORITY = "rtl-reader-native-page-visual-artifact-authority-v1"
STORE_AUTHORITY = "rtl-reader-native-page-visual-artifact-store-v1"
OBJECT_AUTHORITY = "rtl-reader-native-page-visual-artifact-object-v1"
SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CONTAINER_BYTES = MAX_ARTIFACT_BYTES + 16 * 1024
MAX_HEADER_BYTES = 8 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_ARTIFACTS = 1024
WRITE_CHUNK_BYTES = 1024 * 1024
MAGIC = b"NPVA-OBJECT-V1\n"
SUPPORTED_MEDIA_TYPES = (
    "application/json",
    "application/octet-stream",
    "image/png",
    "text/plain",
)

_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_PUBLISHED = re.compile(r"[0-9]{20}\.artifact\Z")
_PENDING = re.compile(r"\.pending-[0-9a-f]{32}\Z")
_AUTHORITY_PENDING = re.compile(r"\.authority-pending-[0-9a-f]{32}\Z")
_LOGICAL_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_RESERVED = re.compile(
    r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?\Z"
)


class ArtifactError(EvidenceRejected):
    """Base class for rejected artifact authority operations."""


class ArtifactAuthorityError(ArtifactError):
    """The caller or retained identity lacks exact authority."""


class ArtifactCorrupt(ArtifactError):
    """Stored bytes, topology, or namespace are ambiguous/corrupt."""


class ArtifactPersistenceError(ArtifactError):
    """A native persistence operation did not prove success."""


class DurabilityUnavailable(ArtifactPersistenceError):
    """The filesystem cannot acknowledge a directory namespace flush."""


def _sha(payload: bytes) -> str:
    if type(payload) is not bytes:
        raise ArtifactAuthorityError("SHA-256 input is not exact bytes")
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ArtifactAuthorityError("authority value is not canonical JSON") from error


def _strict_json(payload: bytes, *, maximum: int) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ArtifactCorrupt("duplicate authority key")
            result[key] = value
        return result

    try:
        if type(payload) is not bytes or not 0 < len(payload) <= maximum:
            raise ArtifactCorrupt("authority JSON size/type differs")
        value = json.loads(payload.decode("ascii"), object_pairs_hook=pairs)
        if type(value) is not dict or _canonical_json(value) != payload:
            raise ArtifactCorrupt("authority JSON is not exact canonical bytes")
        return value
    except ArtifactError:
        raise
    except (ValueError, TypeError, UnicodeError) as error:
        raise ArtifactCorrupt("authority JSON cannot be decoded") from error


def local_path(value: str) -> str:
    """Accept one unambiguous short DOS path on a fixed local drive."""
    if (type(value) is not str or not value.isascii() or len(value) > 240
            or any(ord(char) < 32 for char in value)
            or re.match(r"^[A-Za-z]:\\", value) is None):
        raise ArtifactAuthorityError(
            "artifact storage requires an explicit short local drive path")
    if "/" in value or "\0" in value or value.startswith("\\"):
        raise ArtifactAuthorityError("artifact path is noncanonical")
    parts = value[3:].split("\\") if len(value) > 3 else []
    for part in parts:
        if (not part or part in (".", "..") or part[-1:] in (" ", ".")
                or any(char in part for char in ':*?"<>|')
                or _RESERVED.fullmatch(part) is not None):
            raise ArtifactAuthorityError("ambiguous Windows path component")
    return value[0].upper() + value[1:]


def _same_path(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()


def _logical_name(value: object) -> str:
    if (type(value) is not str or not value.isascii()
            or not 0 < len(value) <= 240 or "\\" in value
            or value.startswith("/") or value.endswith("/")):
        raise ArtifactAuthorityError("artifact logical name is not bounded ASCII")
    parts = value.split("/")
    if any(_LOGICAL_COMPONENT.fullmatch(part) is None
           or part in (".", "..") or part[-1:] in (" ", ".")
           or _RESERVED.fullmatch(part) is not None for part in parts):
        raise ArtifactAuthorityError("artifact logical name is ambiguous or traverses")
    return value


def _media_type(value: object) -> str:
    if type(value) is not str or value not in SUPPORTED_MEDIA_TYPES:
        raise ArtifactAuthorityError("artifact media type is not admitted")
    return value


def _digest64(value: object, label: str) -> str:
    if type(value) is not str or _HEX_64.fullmatch(value) is None:
        raise ArtifactAuthorityError(label + " is not exact lowercase SHA-256")
    return value


def _captured_ns(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ArtifactAuthorityError("artifact capture time is not an exact integer")
    return value


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    index: int

    def __post_init__(self) -> None:
        if (type(self.volume) is not int or not 0 <= self.volume <= 2**32 - 1
                or type(self.index) is not int or not 0 < self.index <= 2**64 - 1):
            raise ArtifactAuthorityError("invalid native file identity")

    def wire(self) -> dict[str, Any]:
        return {"volume": self.volume, "index": f"{self.index:016x}"}


@dataclass(frozen=True)
class FileInfo:
    identity: FileIdentity
    path: str
    directory: bool
    reparse: bool
    links: int
    size: int


@dataclass(frozen=True)
class ArtifactStoreAuthority:
    path: str
    directory_identity: FileIdentity
    store_nonce: str
    adapter_source_sha256: str

    def __post_init__(self) -> None:
        canonical = local_path(self.path)
        if canonical != self.path:
            raise ArtifactAuthorityError("store authority path is not canonical")
        if type(self.directory_identity) is not FileIdentity:
            raise ArtifactAuthorityError("store directory identity is absent")
        if type(self.store_nonce) is not str or _HEX_32.fullmatch(self.store_nonce) is None:
            raise ArtifactAuthorityError("store nonce differs")
        _digest64(self.adapter_source_sha256, "adapter source digest")

    def wire(self) -> dict[str, Any]:
        return {
            "adapterSourceSha256": self.adapter_source_sha256,
            "authority": STORE_AUTHORITY,
            "directoryIdentity": self.directory_identity.wire(),
            "path": self.path,
            "schemaVersion": SCHEMA_VERSION,
            "storeNonce": self.store_nonce,
        }

    @property
    def store_identity_sha256(self) -> str:
        return _sha(_canonical_json(self.wire()))


def canonical_adapter_bytes(source_sha256: str) -> bytes:
    """Return the exact harness pin bytes for one retained source image."""
    _digest64(source_sha256, "adapter source digest")
    return _canonical_json({
        "artifactRefAuthority": HARNESS_ARTIFACT_AUTHORITY,
        "authority": ADAPTER_AUTHORITY,
        "capabilities": [
            "private-single-store-identity",
            "retained-source-and-object-handles",
            "create-new-and-native-no-replace",
            "file-readback-and-directory-flush",
            "fail-closed-additive-recovery",
            "two-pass-quiescence",
        ],
        "maxArtifactBytes": MAX_ARTIFACT_BYTES,
        "maxArtifacts": MAX_ARTIFACTS,
        "schemaVersion": SCHEMA_VERSION,
        "sourceSha256": source_sha256,
        "supportedMediaTypes": list(SUPPORTED_MEDIA_TYPES),
        "windowsNativeOnly": True,
    })


def _adapter_source_path(value: str | None, *, injected_api: bool) -> str:
    reviewed = local_path(ntpath.abspath(__file__))
    if not injected_api:
        if value is not None and local_path(value) != reviewed:
            raise ArtifactAuthorityError(
                "production adapter source path must be this module image")
        return reviewed
    return local_path(reviewed if value is None else value)


class Win32:
    """Small injectable native boundary; no shell, PATH lookup, or fallback."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise ArtifactPersistenceError(
                "Windows native artifact authority is unavailable")
        try:
            self.k = ctypes.WinDLL("kernel32", use_last_error=True)
            self.a = ctypes.WinDLL("advapi32", use_last_error=True)
            self.n = ctypes.WinDLL("ntdll", use_last_error=True)
        except (AttributeError, OSError) as error:
            raise ArtifactPersistenceError(
                "required Windows native libraries are unavailable") from error

        def bind(dll, name, result, args):
            try:
                function = getattr(dll, name)
            except AttributeError as error:
                raise ArtifactPersistenceError(
                    "required Windows native operation is unavailable: " + name) from error
            function.restype, function.argtypes = result, args
            return function

        pointer = ctypes.c_void_p
        self._create = bind(self.k, "CreateFileW", w.HANDLE,
                            [w.LPCWSTR, w.DWORD, w.DWORD, pointer, w.DWORD,
                             w.DWORD, w.HANDLE])
        self._mkdir = bind(self.k, "CreateDirectoryW", w.BOOL,
                           [w.LPCWSTR, pointer])
        self._close = bind(self.k, "CloseHandle", w.BOOL, [w.HANDLE])
        self._flush = bind(self.k, "FlushFileBuffers", w.BOOL, [w.HANDLE])
        self._read = bind(self.k, "ReadFile", w.BOOL,
                          [w.HANDLE, pointer, w.DWORD, pointer, pointer])
        self._write = bind(self.k, "WriteFile", w.BOOL,
                           [w.HANDLE, pointer, w.DWORD, pointer, pointer])
        self._seek = bind(self.k, "SetFilePointerEx", w.BOOL,
                          [w.HANDLE, ctypes.c_longlong, pointer, w.DWORD])
        self._info = bind(self.k, "GetFileInformationByHandle", w.BOOL,
                          [w.HANDLE, pointer])
        self._path = bind(self.k, "GetFinalPathNameByHandleW", w.DWORD,
                          [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD])
        self._nt_set = bind(self.n, "NtSetInformationFile", w.LONG,
                            [w.HANDLE, pointer, pointer, w.ULONG, ctypes.c_int])
        self._nt_error = bind(self.n, "RtlNtStatusToDosError", w.ULONG,
                              [w.LONG])
        self._drive = bind(self.k, "GetDriveTypeW", w.UINT, [w.LPCWSTR])
        self._free = bind(self.k, "LocalFree", pointer, [pointer])
        self._process = bind(self.k, "GetCurrentProcess", w.HANDLE, [])
        self._token = bind(self.a, "OpenProcessToken", w.BOOL,
                           [w.HANDLE, w.DWORD, pointer])
        self._token_info = bind(self.a, "GetTokenInformation", w.BOOL,
                                [w.HANDLE, ctypes.c_int, pointer, w.DWORD,
                                 pointer])
        self._sid_text = bind(self.a, "ConvertSidToStringSidW", w.BOOL,
                              [pointer, pointer])
        self._sddl = bind(
            self.a, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            w.BOOL, [w.LPCWSTR, w.DWORD, pointer, pointer])
        self._security = bind(self.a, "GetSecurityInfo", w.DWORD,
                              [w.HANDLE, ctypes.c_int, w.DWORD, pointer, pointer,
                               pointer, pointer, pointer])
        self._security_text = bind(
            self.a, "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            w.BOOL, [pointer, w.DWORD, w.DWORD, pointer, pointer])

        token = w.HANDLE()
        self._check(self._token(self._process(), 8, ctypes.byref(token)))
        try:
            size = w.DWORD()
            self._token_info(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            self._check(self._token_info(
                token, 1, buffer, size, ctypes.byref(size)))
            self.sid = self._sid_string(
                ctypes.c_void_p.from_buffer(buffer).value)
        finally:
            self.close(token)
        self.dacl = f"D:P(A;;FA;;;SY)(A;;FA;;;{self.sid})"

    @staticmethod
    def _check(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def _sid_string(self, sid):
        output = w.LPWSTR()
        self._check(self._sid_text(sid, ctypes.byref(output)))
        try:
            return output.value
        finally:
            self._free(output)

    @contextmanager
    def _attributes(self):
        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("length", w.DWORD),
                ("descriptor", ctypes.c_void_p),
                ("inherit", w.BOOL),
            ]

        descriptor = ctypes.c_void_p()
        self._check(self._sddl(
            self.dacl, 1, ctypes.byref(descriptor), None))
        try:
            value = SECURITY_ATTRIBUTES(
                ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
            yield ctypes.byref(value)
        finally:
            self._free(descriptor)

    def private(self, handle) -> bool:
        owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        status = self._security(
            handle, 1, 5, ctypes.byref(owner), None, None, None,
            ctypes.byref(descriptor))
        if status:
            raise ctypes.WinError(status)
        output = w.LPWSTR()
        try:
            self._check(self._security_text(
                descriptor, 1, 4, ctypes.byref(output), None))
            return self._sid_string(owner) == self.sid and output.value == self.dacl
        finally:
            if output:
                self._free(output)
            self._free(descriptor)

    def local_volume(self, path: str) -> bool:
        return self._drive(path[:3]) == 3

    def mkdir(self, path: str) -> None:
        with self._attributes() as attributes:
            self._check(self._mkdir(path, attributes))

    def open_directory(self, path: str, *, writable: bool = False,
                       attributes_only: bool = False):
        access = 0xC0000000 if writable else (0x80 if attributes_only else 0x20080)
        return self._open(path, access, 3, 3, 0x02200000)

    def open_file(self, path: str, *, create: bool = False,
                  writable: bool = False, exclusive: bool = False,
                  deletable: bool = False):
        access = (0x80000000 | (0x40000000 if writable else 0)
                  | (0x10000 if deletable else 0))
        share = 0 if exclusive else 1
        return self._open(path, access, share, 1 if create else 3, 0x00200080)

    def _open(self, path, access, share, disposition, flags):
        with self._attributes() as attributes:
            handle = self._create(
                path, access, share, attributes, disposition, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            error = ctypes.WinError(ctypes.get_last_error())
            error.add_note(f"CreateFileW path={path!r}, access=0x{access:08x}")
            raise error
        return handle

    def info(self, handle) -> FileInfo:
        class INFO(ctypes.Structure):
            _fields_ = [
                ("attributes", w.DWORD), ("created", w.FILETIME),
                ("accessed", w.FILETIME), ("written", w.FILETIME),
                ("volume", w.DWORD), ("size_hi", w.DWORD),
                ("size_lo", w.DWORD), ("links", w.DWORD),
                ("index_hi", w.DWORD), ("index_lo", w.DWORD),
            ]

        value = INFO()
        self._check(self._info(handle, ctypes.byref(value)))
        path = ctypes.create_unicode_buffer(32768)
        length = self._path(handle, path, len(path), 0)
        if not 0 < length < len(path) or not path.value.startswith("\\\\?\\"):
            raise ArtifactAuthorityError("native handle has no exact DOS path")
        return FileInfo(
            FileIdentity(value.volume, (value.index_hi << 32) | value.index_lo),
            path.value[4:], bool(value.attributes & 16),
            bool(value.attributes & 1024), value.links,
            (value.size_hi << 32) | value.size_lo,
        )

    def names(self, path: str) -> list[str]:
        return os.listdir(path)

    def read(self, handle, maximum: int) -> bytes:
        if type(maximum) is not int or maximum < 0:
            raise ArtifactAuthorityError("native read bound differs")
        self._check(self._seek(handle, 0, None, 0))
        result = bytearray()
        while True:
            request = min(WRITE_CHUNK_BYTES, maximum + 1 - len(result))
            if request <= 0:
                raise ArtifactCorrupt("native file exceeds retained read bound")
            buffer, count = ctypes.create_string_buffer(request), w.DWORD()
            self._check(self._read(
                handle, buffer, request, ctypes.byref(count), None))
            if not count.value:
                return bytes(result)
            result.extend(buffer.raw[:count.value])
            if len(result) > maximum:
                raise ArtifactCorrupt("native file exceeds retained read bound")

    def write(self, handle, payload: bytes) -> int:
        if type(payload) is not bytes or not payload:
            raise ArtifactAuthorityError("native write payload differs")
        self._check(self._seek(handle, 0, None, 2))
        buffer, count = ctypes.create_string_buffer(payload), w.DWORD()
        self._check(self._write(
            handle, buffer, len(payload), ctypes.byref(count), None))
        return count.value

    def flush(self, handle, *, directory: bool = False) -> None:
        if not self._flush(handle):
            error = ctypes.WinError(ctypes.get_last_error())
            if directory:
                raise DurabilityUnavailable(
                    "Windows directory FlushFileBuffers unavailable") from error
            raise error

    def rename(self, handle, directory, name: str) -> None:
        class RENAME(ctypes.Structure):
            _fields_ = [
                ("replace", w.BOOL), ("root", w.HANDLE),
                ("length", w.DWORD), ("name", w.WCHAR * (len(name) + 1)),
            ]

        value = RENAME(False, directory, len(name.encode("utf-16-le")), name)

        class IO_STATUS_BLOCK(ctypes.Structure):
            _fields_ = [
                ("status", ctypes.c_void_p),
                ("information", ctypes.c_size_t),
            ]

        status_block = IO_STATUS_BLOCK()
        status = self._nt_set(
            handle, ctypes.byref(status_block), ctypes.byref(value),
            RENAME.name.offset + value.length, 10)
        if status != 0:
            raise ctypes.WinError(self._nt_error(status))

    def close(self, handle) -> None:
        self._check(self._close(handle))


@dataclass
class _Held:
    handle: object
    path: str
    identity: FileIdentity
    directory: bool
    private: bool
    writable: bool = False


@dataclass(frozen=True)
class _StoredArtifact:
    physical_name: str
    held: _Held
    reference: ArtifactRef
    captured_ns: int


class WindowsVisualArtifactAuthority:
    """Concrete retained implementation of the harness ArtifactAuthority."""

    def __init__(self, api=None) -> None:
        if MAX_ARTIFACT_BYTES != HARNESS_MAX_ARTIFACT_BYTES:
            raise ArtifactAuthorityError("artifact bound differs from harness")
        self.api = api if api is not None else Win32()
        self._all: list[_Held] = []
        self._ancestors: list[_Held] = []
        self._files: dict[str, _Held] = {}
        self._published: list[_StoredArtifact] = []
        self._refs_by_name: dict[str, _StoredArtifact] = {}
        self._logical_case: dict[str, str] = {}
        self._mutex = threading.Lock()
        self._closed = False
        self._poisoned = False
        self._authority: ArtifactStoreAuthority | None = None
        self._canonical: bytes | None = None
        self._source_bytes: bytes | None = None

    @classmethod
    def create_new(cls, path: str, *, source_path: str | None = None,
                   api=None):
        result = cls(api)
        try:
            store_path = local_path(path)
            source = _adapter_source_path(
                source_path, injected_api=api is not None)
            result._prepare(store_path, source, create=True)
            result._authority = ArtifactStoreAuthority(
                result.root.path, result.root.identity, secrets.token_hex(16),
                result._source_sha256)
            result._canonical = canonical_adapter_bytes(result._source_sha256)
            result._lock_writer(create=True)
            result._publish_authority()
            result.api.flush(result.root.handle, directory=True)
            result.api.flush(result.parent.handle, directory=True)
            result._verify_base()
            return result
        except BaseException as error:
            result._close_after_error(error)
            raise

    @classmethod
    def open_existing(cls, authority: ArtifactStoreAuthority, *,
                      source_path: str | None = None, api=None):
        if type(authority) is not ArtifactStoreAuthority:
            raise ArtifactAuthorityError(
                "reopening requires exact external store authority")
        result = cls(api)
        try:
            source = _adapter_source_path(
                source_path, injected_api=api is not None)
            result._prepare(authority.path, source, create=False)
            if result.root.identity != authority.directory_identity:
                raise ArtifactAuthorityError("artifact store directory identity drift")
            if result._source_sha256 != authority.adapter_source_sha256:
                raise ArtifactAuthorityError("adapter source bytes differ")
            result._authority = authority
            result._canonical = canonical_adapter_bytes(result._source_sha256)
            result._lock_writer(create=False)
            result._open_inventory()
            result._load_existing_and_recover()
            result._verify_base()
            result._verify_all_published()
            return result
        except BaseException as error:
            result._close_after_error(error)
            raise

    @property
    def authority(self) -> ArtifactStoreAuthority:
        if self._authority is None:
            raise ArtifactAuthorityError("artifact store authority is absent")
        return self._authority

    @property
    def store_identity_sha256(self) -> str:
        return self.authority.store_identity_sha256

    @property
    def adapter_pin_sha256(self) -> str:
        canonical = self.canonical_bytes()
        return _sha(canonical)

    def _prepare(self, path: str, source_path: str, *, create: bool) -> None:
        path, source_path = local_path(path), local_path(source_path)
        if len(path) <= 3 or len(source_path) <= 3:
            raise ArtifactAuthorityError("root/source path lacks dedicated authority")
        if (_same_path(path, source_path)
                or source_path.casefold().startswith(path.casefold() + "\\")):
            raise ArtifactAuthorityError("adapter source cannot be inside artifact store")
        if not self.api.local_volume(path) or not self.api.local_volume(source_path):
            raise ArtifactAuthorityError("artifact authority requires fixed local volumes")

        parent_path = ntpath.dirname(path)
        components = [path[:3]]
        for component in parent_path[3:].split("\\"):
            if component:
                components.append(ntpath.join(components[-1], component))
        identities: dict[FileIdentity, str] = {}
        for component in components:
            held = self._retain(
                self.api.open_directory(
                    component, writable=create and _same_path(component, parent_path),
                    attributes_only=not (create and _same_path(component, parent_path))),
                component, True, private=False,
                writable=create and _same_path(component, parent_path))
            if held.identity in identities and not _same_path(
                    identities[held.identity], component):
                raise ArtifactAuthorityError(
                    "distinct ancestor paths alias one directory")
            identities[held.identity] = component
            self._ancestors.append(held)
        self.parent = self._ancestors[-1]
        if create:
            self.api.mkdir(path)
        self.root = self._retain(
            self.api.open_directory(path, writable=True), path, True,
            private=True, writable=True)
        if self.root.identity in identities:
            raise ArtifactAuthorityError("artifact store aliases an ancestor")

        self.source = self._retain(
            self.api.open_file(source_path), source_path, False,
            private=False, writable=False)
        if self.source.identity == self.root.identity:
            raise ArtifactAuthorityError("adapter source aliases artifact directory")
        source_raw = self._read_held(self.source, MAX_SOURCE_BYTES)
        if not source_raw:
            raise ArtifactAuthorityError("adapter source bytes are empty")
        self._source_bytes = source_raw
        self._source_sha256 = _sha(source_raw)

    def _retain(self, handle, path: str, directory: bool, *, private: bool,
                writable: bool) -> _Held:
        try:
            info = self.api.info(handle)
            held = _Held(handle, path, info.identity, directory, private, writable)
            self._check(held)
            self._all.append(held)
            return held
        except BaseException:
            self.api.close(handle)
            raise

    def _check(self, held: _Held) -> FileInfo:
        if type(held) is not _Held:
            raise ArtifactAuthorityError("retained handle token differs")
        info = self.api.info(held.handle)
        if (type(info) is not FileInfo or info.identity != held.identity
                or info.directory is not held.directory or info.reparse
                or not _same_path(info.path, held.path)
                or (not held.directory and info.links != 1)
                or (held.private and not self.api.private(held.handle))
                or type(info.size) is not int or info.size < 0):
            raise ArtifactAuthorityError(
                "retained file/directory authority differs")
        return info

    def _read_held(self, held: _Held, maximum: int) -> bytes:
        before = self._check(held)
        raw = self.api.read(held.handle, maximum)
        after = self._check(held)
        if (type(raw) is not bytes or before.identity != after.identity
                or before.size != after.size or len(raw) != after.size
                or len(raw) > maximum):
            raise ArtifactCorrupt("retained-handle readback differs")
        return raw

    def _lock_writer(self, *, create: bool) -> None:
        path = ntpath.join(self.root.path, "writer.lock")
        self.writer = self._retain(
            self.api.open_file(path, create=create, writable=True,
                               exclusive=True),
            path, False, private=True, writable=True)
        if self._read_held(self.writer, 0) != b"":
            raise ArtifactCorrupt("exclusive writer file is not empty")
        if create:
            self.api.flush(self.writer.handle)
            if self._read_held(self.writer, 0) != b"":
                raise ArtifactCorrupt("flushed writer file differs")

    def _new_pending_name(self, prefix: str) -> str:
        nonce = secrets.token_hex(16)
        if type(nonce) is not str or _HEX_32.fullmatch(nonce) is None:
            raise ArtifactAuthorityError("temporary nonce source differs")
        return prefix + nonce

    def _write_all(self, held: _Held, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            piece = payload[offset:offset + WRITE_CHUNK_BYTES]
            count = self.api.write(held.handle, piece)
            if type(count) is not int or not 0 < count <= len(piece):
                raise ArtifactPersistenceError(
                    "artifact write made no/invalid progress")
            offset += count

    def _publish_authority(self) -> None:
        payload = _canonical_json(self.authority.wire())
        temporary = self._new_pending_name(".authority-pending-")
        path = ntpath.join(self.root.path, temporary)
        held = self._retain(
            self.api.open_file(path, create=True, writable=True,
                               exclusive=True, deletable=True),
            path, False, private=True, writable=True)
        self._files[temporary] = held
        self._write_all(held, payload)
        self.api.flush(held.handle)
        if self._read_held(held, MAX_HEADER_BYTES) != payload:
            raise ArtifactCorrupt("authority file readback differs")
        self.api.rename(held.handle, self.root.handle, "authority.json")
        held.path = ntpath.join(self.root.path, "authority.json")
        self._files["authority.json"] = self._files.pop(temporary)
        self._check(held)
        if self._read_held(held, MAX_HEADER_BYTES) != payload:
            raise ArtifactCorrupt("renamed authority readback differs")
        self.api.flush(self.root.handle, directory=True)

    def _inventory_names(self) -> tuple[str, ...]:
        self._check(self.root)
        names = self.api.names(self.root.path)
        self._check(self.root)
        if (type(names) is not list or any(type(name) is not str for name in names)
                or len(names) != len({name.casefold() for name in names})
                or len(names) > MAX_ARTIFACTS + 4):
            raise ArtifactCorrupt("artifact directory inventory is ambiguous")
        return tuple(sorted(names))

    @staticmethod
    def _allowed_name(name: str) -> bool:
        return bool(name in ("writer.lock", "authority.json")
                    or _PUBLISHED.fullmatch(name)
                    or _PENDING.fullmatch(name)
                    or _AUTHORITY_PENDING.fullmatch(name))

    def _open_inventory(self) -> None:
        names = self._inventory_names()
        if "writer.lock" not in names or "authority.json" not in names:
            raise ArtifactCorrupt("artifact store authority files are missing")
        for name in names:
            if not self._allowed_name(name):
                raise ArtifactCorrupt("unexpected artifact store entry")
            if name == "writer.lock":
                continue
            if _AUTHORITY_PENDING.fullmatch(name):
                raise ArtifactCorrupt("uncertain authority publication is retained")
            path = ntpath.join(self.root.path, name)
            pending = _PENDING.fullmatch(name) is not None
            self._files[name] = self._retain(
                self.api.open_file(path, writable=pending, exclusive=pending,
                                   deletable=pending),
                path, False, private=True, writable=pending)

    def _authority_payload(self) -> bytes:
        if "authority.json" not in self._files:
            raise ArtifactCorrupt("artifact authority record is absent")
        return self._read_held(self._files["authority.json"], MAX_HEADER_BYTES)

    def _validate_authority_payload(self) -> None:
        payload = self._authority_payload()
        value = _strict_json(payload, maximum=MAX_HEADER_BYTES)
        if value != self.authority.wire() or payload != _canonical_json(
                self.authority.wire()):
            raise ArtifactCorrupt("artifact store authority record differs")

    def _encode_container(self, *, sequence: int, logical_name: str, raw: bytes,
                          media_type: str, producer: str,
                          captured_ns: int) -> bytes:
        header = _canonical_json({
            "authority": OBJECT_AUTHORITY,
            "bytes": len(raw),
            "capturedNs": str(captured_ns),
            "logicalName": logical_name,
            "mediaType": media_type,
            "producerAuthoritySha256": producer,
            "schemaVersion": SCHEMA_VERSION,
            "sequence": sequence,
            "sha256": _sha(raw),
            "storeIdentitySha256": self.store_identity_sha256,
        })
        if not 0 < len(header) <= MAX_HEADER_BYTES:
            raise ArtifactAuthorityError("artifact header exceeds bound")
        payload = MAGIC + len(header).to_bytes(4, "big") + header + raw
        if len(payload) > MAX_CONTAINER_BYTES:
            raise ArtifactAuthorityError("artifact container exceeds bound")
        return payload

    def _decode_container(self, held: _Held, *, expected_sequence: int
                          ) -> tuple[dict[str, Any], bytes]:
        payload = self._read_held(held, MAX_CONTAINER_BYTES)
        prefix = len(MAGIC) + 4
        if len(payload) < prefix or not payload.startswith(MAGIC):
            raise ArtifactCorrupt("artifact object magic/truncation differs")
        header_size = int.from_bytes(payload[len(MAGIC):prefix], "big")
        if not 0 < header_size <= MAX_HEADER_BYTES or prefix + header_size > len(payload):
            raise ArtifactCorrupt("artifact object header bound differs")
        header_raw = payload[prefix:prefix + header_size]
        raw = payload[prefix + header_size:]
        header = _strict_json(header_raw, maximum=MAX_HEADER_BYTES)
        expected_keys = {
            "authority", "bytes", "capturedNs", "logicalName", "mediaType",
            "producerAuthoritySha256", "schemaVersion", "sequence", "sha256",
            "storeIdentitySha256",
        }
        if set(header) != expected_keys:
            raise ArtifactCorrupt("artifact object topology differs")
        if (header["authority"] != OBJECT_AUTHORITY
                or type(header["schemaVersion"]) is not int
                or header["schemaVersion"] != SCHEMA_VERSION
                or type(header["sequence"]) is not int
                or header["sequence"] != expected_sequence
                or type(header["bytes"]) is not int
                or not 0 < header["bytes"] <= MAX_ARTIFACT_BYTES
                or header["bytes"] != len(raw)
                or header["storeIdentitySha256"] != self.store_identity_sha256):
            raise ArtifactCorrupt("artifact object authority/size/sequence differs")
        try:
            logical = _logical_name(header["logicalName"])
            media = _media_type(header["mediaType"])
            producer = _digest64(
                header["producerAuthoritySha256"], "artifact producer digest")
            digest = _digest64(header["sha256"], "artifact content digest")
            captured_text = header["capturedNs"]
            if (type(captured_text) is not str
                    or re.fullmatch(r"0|[1-9][0-9]{0,18}", captured_text) is None):
                raise ArtifactAuthorityError("artifact capturedNs differs")
            captured = _captured_ns(int(captured_text))
        except ArtifactAuthorityError as error:
            raise ArtifactCorrupt(str(error)) from error
        if digest != _sha(raw):
            raise ArtifactCorrupt("artifact retained content digest differs")
        header["logicalName"], header["mediaType"] = logical, media
        header["producerAuthoritySha256"] = producer
        header["capturedNsValue"] = captured
        return header, raw

    def _stored(self, name: str, held: _Held, sequence: int) -> _StoredArtifact:
        header, _ = self._decode_container(held, expected_sequence=sequence)
        reference = ArtifactRef(
            header["logicalName"], header["mediaType"], header["bytes"],
            header["sha256"], header["producerAuthoritySha256"],
            header["storeIdentitySha256"], True)
        return _StoredArtifact(
            name, held, reference, header["capturedNsValue"])

    def _add_published(self, stored: _StoredArtifact) -> None:
        expected = f"{len(self._published):020d}.artifact"
        folded = stored.reference.logical_name.casefold()
        if (stored.physical_name != expected
                or folded in self._logical_case
                or stored.reference.logical_name in self._refs_by_name):
            raise ArtifactCorrupt("artifact sequence/logical-name reuse differs")
        self._published.append(stored)
        self._refs_by_name[stored.reference.logical_name] = stored
        self._logical_case[folded] = stored.reference.logical_name

    def _load_existing_and_recover(self) -> None:
        self._validate_authority_payload()
        published_names = sorted(name for name in self._files
                                 if _PUBLISHED.fullmatch(name))
        expected = [f"{sequence:020d}.artifact"
                    for sequence in range(len(published_names))]
        if published_names != expected or len(published_names) > MAX_ARTIFACTS:
            raise ArtifactCorrupt("published artifact sequence differs")
        for sequence, name in enumerate(published_names):
            self._add_published(self._stored(name, self._files[name], sequence))

        pending = sorted(name for name in self._files if _PENDING.fullmatch(name))
        if len(pending) > 1:
            raise ArtifactCorrupt("multiple uncertain artifact publications")
        if pending:
            if len(self._published) >= MAX_ARTIFACTS:
                raise ArtifactCorrupt("artifact count exceeds bound")
            name = pending[0]
            sequence = len(self._published)
            candidate = self._stored(name, self._files[name], sequence)
            expected_reference = candidate.reference
            expected_captured_ns = candidate.captured_ns
            if candidate.reference.logical_name.casefold() in self._logical_case:
                raise ArtifactCorrupt("pending artifact reuses a logical name")
            destination = f"{sequence:020d}.artifact"
            if destination in self._files:
                raise ArtifactCorrupt("pending artifact destination is occupied")
            held = self._files[name]
            # Recovery does not assume that surviving bytes imply the original
            # pre-crash file flush completed.  Re-acknowledge the fully verified
            # pending bytes before its only permitted namespace mutation.
            self.api.flush(held.handle)
            candidate = self._stored(name, held, sequence)
            if (candidate.reference != expected_reference
                    or candidate.captured_ns != expected_captured_ns):
                raise ArtifactCorrupt(
                    "recovered artifact binding differs after file flush")
            self.api.rename(held.handle, self.root.handle, destination)
            held.path = ntpath.join(self.root.path, destination)
            self._files[destination] = self._files.pop(name)
            self._check(held)
            candidate = self._stored(destination, held, sequence)
            if (candidate.reference != expected_reference
                    or candidate.captured_ns != expected_captured_ns):
                raise ArtifactCorrupt(
                    "recovered artifact binding differs after rename")
            self.api.flush(self.root.handle, directory=True)
            candidate = self._stored(destination, held, sequence)
            if (candidate.reference != expected_reference
                    or candidate.captured_ns != expected_captured_ns):
                raise ArtifactCorrupt(
                    "recovered artifact binding differs after directory flush")
            self._add_published(candidate)
        else:
            # A crash after rename but before its acknowledgement can leave a
            # complete surviving namespace.  Acknowledge it before exposure.
            self.api.flush(self.root.handle, directory=True)

    def _verify_source(self) -> None:
        if self._source_bytes is None:
            raise ArtifactAuthorityError("adapter source pin is absent")
        raw = self._read_held(self.source, MAX_SOURCE_BYTES)
        if raw != self._source_bytes or _sha(raw) != self.authority.adapter_source_sha256:
            raise ArtifactAuthorityError("retained adapter source changed")
        if self._canonical != canonical_adapter_bytes(_sha(raw)):
            raise ArtifactAuthorityError("adapter canonical pin bytes changed")

    def _verify_base(self) -> tuple[str, ...]:
        if self._closed or self._poisoned:
            raise ArtifactAuthorityError("closed/uncertain artifact store")
        for held in self._ancestors + [self.root, self.source, self.writer]:
            self._check(held)
        for held in self._files.values():
            self._check(held)
        self._verify_source()
        self._validate_authority_payload()
        if self.authority.store_identity_sha256 != self.store_identity_sha256:
            raise ArtifactAuthorityError("artifact store identity changed")
        if self._read_held(self.writer, 0) != b"":
            raise ArtifactCorrupt("writer lease content changed")
        names = self._inventory_names()
        expected = set(self._files) | {"writer.lock"}
        if set(names) != expected or any(not self._allowed_name(name) for name in names):
            raise ArtifactCorrupt("artifact namespace changed outside authority")
        if any(_PENDING.fullmatch(name) or _AUTHORITY_PENDING.fullmatch(name)
               for name in names):
            raise ArtifactCorrupt("artifact namespace contains uncertain publication")
        if len(self._published) != len(self._refs_by_name):
            raise ArtifactCorrupt("artifact reference index differs")
        return names

    @contextmanager
    def _exclusive(self):
        if not self._mutex.acquire(blocking=False):
            raise ArtifactAuthorityError("concurrent/reentrant artifact authority use")
        try:
            if self._closed or self._poisoned:
                raise ArtifactAuthorityError("closed/uncertain artifact store")
            yield
        finally:
            self._mutex.release()

    def verify(self) -> None:
        with self._exclusive():
            try:
                self._verify_base()
            except BaseException:
                self._poisoned = True
                raise

    def canonical_bytes(self) -> bytes:
        with self._exclusive():
            try:
                self._verify_base()
                if type(self._canonical) is not bytes or not self._canonical:
                    raise ArtifactAuthorityError("adapter canonical bytes are absent")
                return self._canonical
            except BaseException:
                self._poisoned = True
                raise

    def retain(self, logical_name: str, raw: bytes, media_type: str,
               producer_authority_sha256: str,
               captured_ns: int) -> ArtifactRef:
        logical = _logical_name(logical_name)
        media = _media_type(media_type)
        producer = _digest64(
            producer_authority_sha256, "artifact producer digest")
        captured = _captured_ns(captured_ns)
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ARTIFACT_BYTES:
            raise ArtifactAuthorityError("artifact bytes are empty, inexact, or oversized")

        with self._exclusive():
            try:
                self._verify_base()
            except BaseException:
                self._poisoned = True
                raise
            folded = logical.casefold()
            if folded in self._logical_case:
                raise ArtifactAuthorityError(
                    "artifact logical name was already used or is case-ambiguous")
            if len(self._published) >= MAX_ARTIFACTS:
                raise ArtifactAuthorityError("artifact count exceeds bound")
            sequence = len(self._published)
            expected_reference = ArtifactRef(
                logical, media, len(raw), _sha(raw), producer,
                self.store_identity_sha256, True)
            container = self._encode_container(
                sequence=sequence, logical_name=logical, raw=raw,
                media_type=media, producer=producer, captured_ns=captured)
            temporary = self._new_pending_name(".pending-")
            path = ntpath.join(self.root.path, temporary)
            mutated = True
            try:
                held = self._retain(
                    self.api.open_file(path, create=True, writable=True,
                                       exclusive=True, deletable=True),
                    path, False, private=True, writable=True)
                self._files[temporary] = held
                self._write_all(held, container)
                self.api.flush(held.handle)
                if self._read_held(held, MAX_CONTAINER_BYTES) != container:
                    raise ArtifactCorrupt("flushed artifact readback differs")
                # Decode from the retained handle before namespace mutation so
                # metadata, length, and raw digest are all publication authority.
                self._stored(temporary, held, sequence)
                destination = f"{sequence:020d}.artifact"
                if destination in self._files:
                    raise ArtifactCorrupt("artifact destination unexpectedly exists")
                self.api.rename(held.handle, self.root.handle, destination)
                held.path = ntpath.join(self.root.path, destination)
                self._files[destination] = self._files.pop(temporary)
                self._check(held)
                stored = self._stored(destination, held, sequence)
                if (stored.reference != expected_reference
                        or stored.captured_ns != captured):
                    raise ArtifactCorrupt("published artifact binding differs")
                self.api.flush(self.root.handle, directory=True)
                # This final retained readback and inventory check happens after
                # the namespace durability acknowledgement and before exposure.
                stored = self._stored(destination, held, sequence)
                if (stored.reference != expected_reference
                        or stored.captured_ns != captured):
                    raise ArtifactCorrupt(
                        "durable artifact binding differs after directory flush")
                names = self._inventory_names()
                if (set(names) != set(self._files) | {"writer.lock"}
                        or temporary in names or destination not in names):
                    raise ArtifactCorrupt("durable artifact namespace differs")
                self._add_published(stored)
                mutated = False
                return stored.reference
            except BaseException:
                if mutated:
                    self._poisoned = True
                raise

    def _verify_stored(self, stored: _StoredArtifact,
                       expected: ArtifactRef) -> None:
        sequence = self._published.index(stored)
        actual = self._stored(stored.physical_name, stored.held, sequence)
        if actual.reference != expected or actual.captured_ns != stored.captured_ns:
            raise ArtifactCorrupt("artifact reference/readback changed")

    def _verify_all_published(self) -> None:
        for stored in self._published:
            self._verify_stored(stored, stored.reference)

    def verify_ref(self, reference: ArtifactRef) -> None:
        if type(reference) is not ArtifactRef:
            raise ArtifactAuthorityError("artifact reference type differs")
        _logical_name(reference.logical_name)
        _media_type(reference.media_type)
        _digest64(reference.sha256, "artifact digest")
        _digest64(reference.producer_authority_sha256, "artifact producer digest")
        _digest64(reference.store_identity_sha256, "artifact store digest")
        if (type(reference.size) is not int
                or not 0 < reference.size <= MAX_ARTIFACT_BYTES
                or reference.immutable is not True
                or reference.store_identity_sha256 != self.store_identity_sha256):
            raise ArtifactAuthorityError("artifact reference authority differs")
        with self._exclusive():
            stored = self._refs_by_name.get(reference.logical_name)
            if stored is None or stored.reference != reference:
                raise ArtifactAuthorityError(
                    "artifact reference is not retained by this store")
            try:
                self._verify_base()
                self._verify_stored(stored, reference)
            except BaseException:
                self._poisoned = True
                raise

    def retained_refs(self) -> tuple[ArtifactRef, ...]:
        """Return recovery-discovered references in immutable sequence order."""
        with self._exclusive():
            try:
                self._verify_base()
                self._verify_all_published()
                return tuple(item.reference for item in self._published)
            except BaseException:
                self._poisoned = True
                raise

    def assert_quiescent(self) -> None:
        with self._exclusive():
            try:
                first_names = self._verify_base()
                first_refs = tuple(item.reference for item in self._published)
                for stored in self._published:
                    self._verify_stored(stored, stored.reference)
                self.api.flush(self.root.handle, directory=True)
                second_names = self._verify_base()
                for stored in self._published:
                    self._verify_stored(stored, stored.reference)
                if (first_names != second_names
                        or first_refs != tuple(item.reference
                                               for item in self._published)):
                    raise ArtifactCorrupt("artifact store did not remain quiescent")
            except BaseException:
                self._poisoned = True
                raise

    def close(self) -> None:
        if not self._mutex.acquire(blocking=False):
            raise ArtifactAuthorityError(
                "cannot close artifact authority during active operation")
        try:
            if self._closed:
                return
            self._closed = True
            errors = []
            for held in reversed(self._all):
                try:
                    self.api.close(held.handle)
                except Exception as error:
                    errors.append(error)
            self._all.clear()
            if errors:
                raise ArtifactPersistenceError(
                    "retained artifact handle disposal failed", errors)
        finally:
            self._mutex.release()

    def _close_after_error(self, primary: BaseException) -> None:
        try:
            self.close()
        except Exception as error:
            if hasattr(primary, "add_note"):
                primary.add_note(
                    "retained artifact handle cleanup also failed: " + str(error))

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if value is not None:
            self._close_after_error(value)
        else:
            self.close()


__all__ = [
    "ADAPTER_AUTHORITY", "ArtifactAuthorityError", "ArtifactCorrupt",
    "ArtifactError", "ArtifactPersistenceError", "ArtifactStoreAuthority",
    "DurabilityUnavailable", "FileIdentity", "FileInfo", "MAX_ARTIFACT_BYTES",
    "MAX_ARTIFACTS", "SUPPORTED_MEDIA_TYPES", "Win32",
    "WindowsVisualArtifactAuthority", "canonical_adapter_bytes", "local_path",
]
