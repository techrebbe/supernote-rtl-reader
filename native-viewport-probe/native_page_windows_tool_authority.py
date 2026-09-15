"""Retained Windows byte/identity authority for the exact ADB client bundle.

The three adjacent files are opened with read-only sharing before any command
may be executed.  Their retained handles deny writes, renames, and deletion for
the lifetime of the authority.  This closes the hash-one-path/execute-another
gap in a later production coordinator; this module itself runs no command.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


AUTHORITY = "rtl-reader-windows-adb-bundle-authority-v1"
FILENAMES = ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")
MAX_FILE_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class ToolAuthorityError(RuntimeError):
    """The named tool bundle cannot remain the exact reviewed byte authority."""


@dataclass(frozen=True)
class FileIdentity:
    attributes: int
    volume_serial: int
    file_index: int
    link_count: int
    size: int
    creation_time: int
    last_write_time: int


@dataclass(frozen=True)
class FileAuthority:
    basename: str
    path: str
    size: int
    sha256: str
    identity: FileIdentity


if os.name == "nt":
    class _FILETIME(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation", _FILETIME),
            ("access", _FILETIME),
            ("write", _FILETIME),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("link_count", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]


    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                             wintypes.HANDLE]
    _CreateFileW.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL
    _GetFileInformationByHandle = _kernel32.GetFileInformationByHandle
    _GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)]
    _GetFileInformationByHandle.restype = wintypes.BOOL
    _GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                           wintypes.DWORD, wintypes.DWORD]
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _SetFilePointerEx = _kernel32.SetFilePointerEx
    _SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                  ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    _SetFilePointerEx.restype = wintypes.BOOL
    _ReadFile = _kernel32.ReadFile
    _ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    _ReadFile.restype = wintypes.BOOL


GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_BEGIN = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _windows_error(label: str) -> ToolAuthorityError:
    code = ctypes.get_last_error()
    return ToolAuthorityError(f"{label} failed with Windows error {code}")


def _time(value: Any) -> int:
    return (int(value.high) << 32) | int(value.low)


def _info(handle: int) -> FileIdentity:
    if os.name != "nt":
        raise ToolAuthorityError("Windows handle authority is unavailable")
    value = _BY_HANDLE_FILE_INFORMATION()
    if not _GetFileInformationByHandle(handle, ctypes.byref(value)):
        raise _windows_error("GetFileInformationByHandle")
    return FileIdentity(
        int(value.attributes), int(value.volume_serial),
        (int(value.index_high) << 32) | int(value.index_low),
        int(value.link_count),
        (int(value.size_high) << 32) | int(value.size_low),
        _time(value.creation), _time(value.write))


def _final_path(handle: int) -> str:
    required = _GetFinalPathNameByHandleW(handle, None, 0, 0)
    if not required or required > 32768:
        raise _windows_error("GetFinalPathNameByHandleW size")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = _GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise _windows_error("GetFinalPathNameByHandleW")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.abspath(value))


def _read_exact(handle: int, size: int) -> bytes:
    if not 0 < size <= MAX_FILE_BYTES:
        raise ToolAuthorityError("tool file size is outside the admitted bound")
    new_position = ctypes.c_longlong()
    if not _SetFilePointerEx(handle, 0, ctypes.byref(new_position), FILE_BEGIN):
        raise _windows_error("SetFilePointerEx")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        count = min(65536, remaining)
        buffer = ctypes.create_string_buffer(count)
        read = wintypes.DWORD()
        if not _ReadFile(handle, buffer, count, ctypes.byref(read), None):
            raise _windows_error("ReadFile")
        if read.value == 0:
            raise ToolAuthorityError("tool file ended before its retained size")
        chunks.append(buffer.raw[:read.value])
        remaining -= read.value
    probe = ctypes.create_string_buffer(1)
    read = wintypes.DWORD()
    if (not _ReadFile(handle, probe, 1, ctypes.byref(read), None) or
            read.value != 0):
        raise ToolAuthorityError("tool file differs from its retained size")
    raw = b"".join(chunks)
    if len(raw) != size:
        raise ToolAuthorityError("tool file capture size differs")
    return raw


class _RetainedHandle:
    def __init__(self, path: Path, *, directory: bool):
        self.path = Path(path)
        self.directory = directory
        self.handle: int | None = None
        self.opened: FileIdentity | None = None
        self.raw: bytes | None = None
        self.sha256: str | None = None

    def open(self) -> "_RetainedHandle":
        if os.name != "nt" or self.handle is not None:
            raise ToolAuthorityError("invalid Windows handle lifecycle")
        absolute = os.path.abspath(str(self.path))
        flags = FILE_FLAG_OPEN_REPARSE_POINT
        desired = 0 if self.directory else GENERIC_READ
        flags |= FILE_FLAG_BACKUP_SEMANTICS if self.directory else FILE_FLAG_SEQUENTIAL_SCAN
        handle = _CreateFileW(absolute, desired, FILE_SHARE_READ, None,
                              OPEN_EXISTING, flags, None)
        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise _windows_error("CreateFileW")
        self.handle = int(handle)
        try:
            opened = _info(self.handle)
            expected_directory = bool(opened.attributes & FILE_ATTRIBUTE_DIRECTORY)
            invalid_link_count = (opened.link_count < 1 if self.directory else
                                  opened.link_count != 1)
            if (bool(opened.attributes & FILE_ATTRIBUTE_REPARSE_POINT) or
                    expected_directory != self.directory or invalid_link_count or
                    _final_path(self.handle) != os.path.normcase(absolute)):
                raise ToolAuthorityError("tool path is not one direct retained file")
            self.opened = opened
            if not self.directory:
                self.raw = _read_exact(self.handle, opened.size)
                self.sha256 = hashlib.sha256(self.raw).hexdigest()
            self.verify()
            return self
        except BaseException:
            self.close()
            raise

    def verify(self) -> None:
        if self.handle is None or self.opened is None:
            raise ToolAuthorityError("tool handle is not retained")
        if (_info(self.handle) != self.opened or
                _final_path(self.handle) !=
                os.path.normcase(os.path.abspath(str(self.path)))):
            raise ToolAuthorityError("retained tool identity changed")
        if not self.directory:
            assert self.raw is not None and self.sha256 is not None
            current = _read_exact(self.handle, self.opened.size)
            if current != self.raw or hashlib.sha256(current).hexdigest() != self.sha256:
                raise ToolAuthorityError("retained tool bytes changed")

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle is not None and not _CloseHandle(handle):
            raise _windows_error("CloseHandle")


class LockedAdbBundle:
    """Exact adjacent ADB bundle retained against write/delete replacement."""

    def __init__(self, directory: Path,
                 expected_sha256: dict[str, str]):
        try:
            self.directory = Path(os.path.abspath(os.fspath(directory)))
        except (OSError, TypeError, ValueError) as error:
            raise ToolAuthorityError("ADB bundle directory is invalid") from error
        if type(expected_sha256) is not dict:
            raise ToolAuthorityError("expected tool digest map is invalid")
        self.expected = dict(expected_sha256)
        if (set(self.expected) != set(FILENAMES) or
                any(type(name) is not str or type(value) is not str or
                    SHA256_RE.fullmatch(value) is None
                    for name, value in self.expected.items())):
            raise ToolAuthorityError("expected tool digest map is invalid")
        self._directory: _RetainedHandle | None = None
        self._files: list[_RetainedHandle] = []
        self._closed = False

    def open(self) -> "LockedAdbBundle":
        if self._closed or self._directory is not None or self._files:
            raise ToolAuthorityError("ADB bundle lifecycle is invalid")
        try:
            self._directory = _RetainedHandle(self.directory, directory=True).open()
            for basename in FILENAMES:
                retained = _RetainedHandle(self.directory / basename,
                                           directory=False).open()
                self._files.append(retained)
                if retained.sha256 != self.expected[basename]:
                    raise ToolAuthorityError("tool digest differs from reviewed authority")
            self.verify()
            return self
        except BaseException:
            self.close()
            raise

    @property
    def executable(self) -> str:
        if not self._files:
            raise ToolAuthorityError("ADB bundle is not open")
        return str((self.directory / FILENAMES[0]).resolve(strict=True))

    def authorities(self) -> dict[str, FileAuthority]:
        self.verify()
        values: dict[str, FileAuthority] = {}
        for retained in self._files:
            assert retained.opened is not None and retained.sha256 is not None
            basename = retained.path.name
            values[basename] = FileAuthority(
                basename, os.path.abspath(str(retained.path)),
                retained.opened.size, retained.sha256, retained.opened)
        return values

    def canonical_bytes(self) -> bytes:
        values = {
            "authority": AUTHORITY,
            "files": {name: asdict(value)
                      for name, value in self.authorities().items()},
        }
        return json.dumps(values, ensure_ascii=False, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self) -> None:
        if self._closed or self._directory is None or len(self._files) != len(FILENAMES):
            raise ToolAuthorityError("ADB bundle is not completely retained")
        self._directory.verify()
        for retained in self._files:
            retained.verify()

    def close(self) -> None:
        errors: list[BaseException] = []
        for retained in reversed(self._files):
            try:
                retained.close()
            except BaseException as error:
                errors.append(error)
        self._files = []
        if self._directory is not None:
            try:
                self._directory.close()
            except BaseException as error:
                errors.append(error)
            self._directory = None
        self._closed = True
        if errors:
            raise ToolAuthorityError("one or more retained tool handles failed to close")

    def __enter__(self) -> "LockedAdbBundle":
        return self.open()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
