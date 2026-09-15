"""Read-only Nomad dependency inventory. NEVER authorizes native loading.

Only existing proc metadata and mapped system-library files are read. Collected
ELFs stay in an exclusive local build directory; do not publish/upload them.
Multiple mapped candidates for a SONAME are recorded as unresolved, not guessed.
"""
from __future__ import annotations

import argparse
import builtins
import contextlib
import errno
import hashlib
import io
import json
import os
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import time
import types
from collections import deque
from pathlib import Path, PurePosixPath

SERIAL = "SN078C10015092"
FINGERPRINT = "Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys"
ROOT_LIBRARY = "/system_ext/app/drawPath/lib/arm64/librecgnition.so"
ROOT_SHA256 = "3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2"
MAX_FILES = 256
MAX_MAPPED_LIBRARIES = 1024
MAX_MAP_RECORDS = 16384
MAX_RAW_MAP_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_PROGRAM_HEADERS = 128
MAX_SECTION_HEADERS = 4096
MAX_SECTION_NAME_TABLE_BYTES = 1024 * 1024
MAX_SECTION_NAME_BYTES = 256
MAX_DYNAMIC_ENTRIES = 4096
MAX_DYNAMIC_STRING_BYTES = 16 * 1024 * 1024
MAX_DEPENDENCIES = 512
MAX_DEPENDENCY_NAME_BYTES = 512
MAX_DEPENDENCY_NAME_BYTES_TOTAL = 64 * 1024
MAX_DEPENDENCY_EDGES = 8192
MAX_BOUNDED_COMMAND_SPEC = 1024 * 1024
PAGE_SIZE = 4096
NAME = re.compile(r"[A-Za-z0-9_+@.\-]+\.so\Z")
PATH = re.compile(r"/(?:system/lib64|system_ext/app/drawPath/lib/arm64|apex/[A-Za-z0-9_.@\-]+/lib64(?:/bionic)?)/[A-Za-z0-9_+@.\-]+\.so\Z")
MAP = re.compile(r"([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) ([0-9a-f]+:[0-9a-f]+) ([0-9]+)(?: +(.*))?\Z")
AUTHENTICATED_GATE_MODULE = "_rtl_reader_authenticated_elftools_gate"
AUTHENTICATED_GATE_SOURCE_ATTR = "_rtl_reader_authenticated_gate_source"
PINNED_GATE_SHA256 = "ff7021874c16321f71b4309e131d78061d0d71c4cd6d14743574fc4eb229cd2f"
MAX_PINNED_GATE_BYTES = 64 * 1024
PINNED_RUNNER_SHA256 = "b5b643c035114b503952ccf45363d07dbcc3c6f31b119ae3c9c95f719a61d288"
MAX_PINNED_RUNNER_BYTES = 128 * 1024
_LOCAL_GATE_AUTHORITY = None
_LOCAL_GATE_METHOD = None
_LOCAL_GATE_SOURCE = None
_OUTER_GATE_AUTHORITY = None
_OUTER_GATE_METHOD = None
_OUTER_GATE_SOURCE = None
_OUTER_GATE_LOADER = None
_OUTER_GATE_FINDER = None
_OUTER_COLLECTOR_SOURCE = None
RUNNER_BOOTSTRAP = (
    "import hashlib,sys,types\n"
    "r=sys.stdin.buffer\n"
    "def exact(n):\n"
    " b=bytearray()\n"
    " while len(b)<n:\n"
    "  c=r.read(n-len(b))\n"
    "  if not c: raise SystemExit(126)\n"
    "  b.extend(c)\n"
    " return bytes(b)\n"
    "n=int.from_bytes(exact(8),'big')\n"
    "if n<1 or n>int(sys.argv[2]): raise SystemExit(126)\n"
    "s=exact(n)\n"
    "if hashlib.sha256(s).hexdigest()!=sys.argv[1]: raise SystemExit(126)\n"
    "m=types.ModuleType('__main__')\n"
    "m.__file__='<authenticated-bounded-command-runner>'\n"
    "m.__package__=''\n"
    "sys.modules['__main__']=m\n"
    "exec(compile(s,m.__file__,'exec',dont_inherit=True),m.__dict__,m.__dict__)\n"
)


class InventoryError(ValueError):
    pass


class InventoryCommittedRelocatedError(RuntimeError):
    """Terminal authority exists, but not at the requested path: never retry."""
    pass


_GATE_MODULE_METADATA = frozenset({
    "__builtins__", "__cached__", "__file__", "__loader__", "__name__",
    "__package__", "__spec__", AUTHENTICATED_GATE_SOURCE_ATTR,
})
_GATE_CLASS_METADATA = frozenset({
    "__dict__", "__module__", "__weakref__", "_abc_impl",
})
_GATE_ATOM_TYPES = (str, bytes, int, float, bool, type(None))
_CONCRETE_PATH_TYPE = type(Path())


def _same_gate_value(actual, reference, actual_globals, reference_globals,
                     visited):
    """Compare executable gate state with the module compiled from pinned bytes."""
    pair = (id(actual), id(reference))
    if pair in visited:
        return True
    visited.add(pair)
    if type(actual) is not type(reference):
        return False
    if type(reference) in _GATE_ATOM_TYPES:
        return actual == reference
    if type(reference) in (tuple, list):
        return (len(actual) == len(reference) and all(
            _same_gate_value(left, right, actual_globals, reference_globals,
                             visited)
            for left, right in zip(actual, reference)))
    if type(reference) in (set, frozenset):
        if (len(actual) != len(reference) or
                any(type(item) not in _GATE_ATOM_TYPES for item in actual) or
                any(type(item) not in _GATE_ATOM_TYPES for item in reference)):
            return False
        unmatched = list(actual)
        for expected_item in reference:
            for index, actual_item in enumerate(unmatched):
                if (type(actual_item) is type(expected_item) and
                        actual_item == expected_item):
                    unmatched.pop(index)
                    break
            else:
                return False
        return not unmatched
    if type(reference) is dict:
        if (len(actual) != len(reference) or
                any(type(key) not in _GATE_ATOM_TYPES for key in actual) or
                any(type(key) not in _GATE_ATOM_TYPES for key in reference)):
            return False
        for reference_key, reference_value in reference.items():
            matching_keys = [
                key for key in actual
                if type(key) is type(reference_key) and key == reference_key
            ]
            if (len(matching_keys) != 1 or not _same_gate_value(
                    actual[matching_keys[0]], reference_value, actual_globals,
                    reference_globals, visited)):
                return False
        return True
    if type(reference) is types.FunctionType:
        return (actual.__globals__ is actual_globals and
                reference.__globals__ is reference_globals and
                actual.__builtins__ is builtins.__dict__ and
                reference.__builtins__ is builtins.__dict__ and
                actual.__name__ == reference.__name__ and
                actual.__qualname__ == reference.__qualname__ and
                actual.__closure__ is None and reference.__closure__ is None and
                actual.__code__ == reference.__code__ and
                _same_gate_value(actual.__dict__, reference.__dict__,
                                 actual_globals, reference_globals, visited) and
                _same_gate_value(actual.__defaults__, reference.__defaults__,
                                 actual_globals, reference_globals, visited) and
                _same_gate_value(actual.__kwdefaults__, reference.__kwdefaults__,
                                 actual_globals, reference_globals, visited) and
                _same_gate_value(actual.__annotations__, reference.__annotations__,
                                 actual_globals, reference_globals, visited))
    if type(reference) is staticmethod:
        return _same_gate_value(
            actual.__func__, reference.__func__, actual_globals,
            reference_globals, visited)
    if type(reference) is classmethod:
        return _same_gate_value(
            actual.__func__, reference.__func__, actual_globals,
            reference_globals, visited)
    if isinstance(reference, type) and reference.__module__ == reference_globals[
            "__name__"]:
        if (actual.__name__ != reference.__name__ or
                actual.__qualname__ != reference.__qualname__ or
                actual.__bases__ != reference.__bases__):
            return False
        actual_members = {
            key: value for key, value in vars(actual).items()
            if key not in _GATE_CLASS_METADATA
        }
        reference_members = {
            key: value for key, value in vars(reference).items()
            if key not in _GATE_CLASS_METADATA
        }
        return _same_gate_value(
            actual_members, reference_members, actual_globals,
            reference_globals, visited)
    return actual is reference


def _gate_matches_captured_source(gate, raw: bytes, expected: Path) -> bool:
    """Bind the reused gate's complete executable namespace to captured bytes."""
    reference = types.ModuleType("_rtl_reader_pinned_gate_reference")
    reference.__file__ = str(expected)
    reference.__package__ = ""
    try:
        exec(compile(raw, str(expected), "exec", dont_inherit=True),
             reference.__dict__)
        if (type(gate) is not types.ModuleType or
                gate.__dict__.get("__builtins__") is not builtins.__dict__ or
                reference.__dict__.get("__builtins__") is not
                builtins.__dict__):
            return False
        actual_values = {
            key: value for key, value in gate.__dict__.items()
            if key not in _GATE_MODULE_METADATA
        }
        reference_values = {
            key: value for key, value in reference.__dict__.items()
            if key not in _GATE_MODULE_METADATA
        }
        return _same_gate_value(
            actual_values, reference_values, gate.__dict__,
            reference.__dict__, set())
    except BaseException:
        return False


def authenticate_elftools(root: Path):
    """Enter or revalidate the reviewed in-memory pyelftools authority."""
    global _LOCAL_GATE_AUTHORITY, _LOCAL_GATE_METHOD, _LOCAL_GATE_SOURCE
    global _OUTER_GATE_AUTHORITY, _OUTER_GATE_METHOD, _OUTER_GATE_SOURCE
    global _OUTER_GATE_LOADER, _OUTER_GATE_FINDER, _OUTER_COLLECTOR_SOURCE
    if type(root) is not _CONCRETE_PATH_TYPE:
        raise InventoryError(
            "authenticated pyelftools root must be an inert concrete path")
    expected = Path(__file__).absolute().with_name(
        "pinned_elftools_gate.py")
    raw = read_bounded(expected, MAX_PINNED_GATE_BYTES)
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        raise InventoryError("authenticated pyelftools gate source newlines changed")
    if b"\r" in raw:
        if (raw.count(b"\r") != raw.count(b"\r\n") or
                raw.count(b"\n") != raw.count(b"\r\n")):
            raise InventoryError("authenticated pyelftools gate source newlines changed")
        raw = raw.replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != PINNED_GATE_SHA256:
        raise InventoryError("authenticated pyelftools gate source changed")
    gate = sys.modules.get(AUTHENTICATED_GATE_MODULE)
    if gate is not None and type(gate) is not types.ModuleType:
        raise InventoryError(
            "authenticated pyelftools gate provenance is unavailable")
    local_authority = False
    outer_candidate = None
    if gate is None:
        loader = getattr(getattr(
            sys.modules.get(__name__), "__spec__", None), "loader", None)
        if (getattr(loader, "gate_authority", None) is not None or
                getattr(loader, "gate_source", None) is not None or
                getattr(loader, "gate_method", None) is not None):
            raise InventoryError(
                "authenticated top-level gate authority disappeared")
        if _LOCAL_GATE_AUTHORITY is not None:
            raise InventoryError(
                "authenticated local gate authority disappeared")
        gate = types.ModuleType(AUTHENTICATED_GATE_MODULE)
        gate.__file__ = str(expected)
        gate.__package__ = ""
        sys.modules[AUTHENTICATED_GATE_MODULE] = gate
        try:
            exec(compile(raw, str(expected), "exec", dont_inherit=True),
                 gate.__dict__)
        except BaseException:
            if sys.modules.get(AUTHENTICATED_GATE_MODULE) is gate:
                sys.modules.pop(AUTHENTICATED_GATE_MODULE, None)
            raise
        if sys.modules.get(AUTHENTICATED_GATE_MODULE) is not gate:
            raise InventoryError(
                "authenticated local gate authority was replaced")
        source = gate.__dict__.get("__file__")
        if type(source) is not str or source != str(expected):
            if sys.modules.get(AUTHENTICATED_GATE_MODULE) is gate:
                sys.modules.pop(AUTHENTICATED_GATE_MODULE, None)
            raise InventoryError(
                "authenticated pyelftools gate source is unavailable")
        if not _gate_matches_captured_source(gate, raw, expected):
            if sys.modules.get(AUTHENTICATED_GATE_MODULE) is gate:
                sys.modules.pop(AUTHENTICATED_GATE_MODULE, None)
            raise InventoryError(
                "authenticated local gate source authority changed")
        local_authority = True
    elif _LOCAL_GATE_AUTHORITY is not None:
        if gate is not _LOCAL_GATE_AUTHORITY:
            raise InventoryError(
                "authenticated local gate authority was replaced")
        source = gate.__dict__.get("__file__")
        if (type(source) is not str or source != str(expected) or
                _LOCAL_GATE_SOURCE != raw or
                not _gate_matches_captured_source(gate, raw, expected)):
            raise InventoryError(
                "authenticated local gate source authority changed")
        local_authority = True
    elif _OUTER_GATE_AUTHORITY is not None:
        current = sys.modules.get(__name__)
        loader = getattr(getattr(current, "__spec__", None), "loader", None)
        source = gate.__dict__.get("__file__")
        gate_name = gate.__dict__.get("__name__")
        if (type(source) is not str or source != str(expected) or
                type(gate_name) is not str or gate_name != "__main__" or
                gate is not _OUTER_GATE_AUTHORITY or
                gate is not sys.modules.get("__main__") or
                loader is not _OUTER_GATE_LOADER or
                getattr(gate, "authenticate_elftools", None) is not
                _OUTER_GATE_METHOD or
                getattr(gate, AUTHENTICATED_GATE_SOURCE_ATTR, None) is not
                _OUTER_GATE_SOURCE or
                _OUTER_GATE_SOURCE != raw or
                _OUTER_GATE_FINDER not in sys.meta_path or
                getattr(_OUTER_GATE_FINDER, "sources", {}).get(__name__) is not
                _OUTER_COLLECTOR_SOURCE or
                getattr(loader, "gate_authority", None) is not gate or
                getattr(loader, "gate_source", None) is not _OUTER_GATE_SOURCE or
                getattr(loader, "gate_method", None) is not _OUTER_GATE_METHOD or
                getattr(loader, "source", None) is not
                _OUTER_COLLECTOR_SOURCE[0] or
                getattr(loader, "raw", None) is not
                _OUTER_COLLECTOR_SOURCE[1] or
                not _gate_matches_captured_source(gate, raw, expected)):
            raise InventoryError(
                "authenticated outer gate authority was replaced")
    else:
        current = sys.modules.get(__name__)
        loader = getattr(getattr(current, "__spec__", None), "loader", None)
        gate_loader_type = getattr(gate, "_PinnedSourceLoader", None)
        gate_finder_type = getattr(gate, "_PinnedSourceFinder", None)
        gate_method = getattr(gate, "authenticate_elftools", None)
        launch_source = getattr(
            gate, AUTHENTICATED_GATE_SOURCE_ATTR, None)
        source = gate.__dict__.get("__file__")
        gate_name = gate.__dict__.get("__name__")
        loader_exec = (None if not isinstance(gate_loader_type, type) else
                       gate_loader_type.__dict__.get("exec_module"))
        finder_find = (None if not isinstance(gate_finder_type, type) else
                       gate_finder_type.__dict__.get("find_spec"))
        matching_finders = []
        if isinstance(gate_finder_type, type):
            for finder in sys.meta_path:
                if type(finder) is not gate_finder_type:
                    continue
                captured = getattr(finder, "sources", {}).get(__name__)
                if (captured is not None and len(captured) == 3 and
                        captured[2] is False):
                    matching_finders.append((finder, captured))
        if (type(source) is not str or source != str(expected) or
                type(gate_name) is not str or gate_name != "__main__" or
                gate is not sys.modules.get("__main__") or
                not isinstance(gate_loader_type, type) or
                not isinstance(gate_finder_type, type) or
                type(loader) is not gate_loader_type or
                type(loader_exec) is not types.FunctionType or
                loader_exec.__globals__ is not gate.__dict__ or
                type(finder_find) is not types.FunctionType or
                finder_find.__globals__ is not gate.__dict__ or
                getattr(loader, "gate_authority", None) is not gate or
                getattr(loader, "gate_source", None) is not launch_source or
                getattr(loader, "gate_method", None) is not gate_method or
                type(launch_source) is not bytes or launch_source != raw or
                len(matching_finders) != 1 or
                matching_finders[0][0].gate_authority is not gate or
                matching_finders[0][0].gate_source is not launch_source or
                matching_finders[0][0].gate_method is not gate_method or
                getattr(loader, "authority_sha256", None) !=
                matching_finders[0][0].authority_sha256 or
                getattr(loader, "source", None) is not matching_finders[0][1][0] or
                getattr(loader, "raw", None) is not matching_finders[0][1][1] or
                not _gate_matches_captured_source(gate, raw, expected)):
            raise InventoryError(
                "authenticated pyelftools gate provenance is unavailable")
        outer_candidate = (gate, gate_method, launch_source, loader,
                           matching_finders[0][0], matching_finders[0][1])
    method = getattr(gate, "authenticate_elftools", None)
    if (type(method) is not types.FunctionType or
            method.__globals__ is not gate.__dict__):
        raise InventoryError("authenticated pyelftools gate protocol is unavailable")
    if local_authority:
        if _LOCAL_GATE_AUTHORITY is None:
            _LOCAL_GATE_AUTHORITY = gate
            _LOCAL_GATE_METHOD = method
            _LOCAL_GATE_SOURCE = raw
        elif method is not _LOCAL_GATE_METHOD:
            raise InventoryError(
                "authenticated local gate protocol was replaced")
    elif _OUTER_GATE_AUTHORITY is None:
        if (outer_candidate is None or
                sys.modules.get(AUTHENTICATED_GATE_MODULE) is not gate):
            raise InventoryError(
                "authenticated outer gate authority was replaced")
        (_OUTER_GATE_AUTHORITY, _OUTER_GATE_METHOD, _OUTER_GATE_SOURCE,
         _OUTER_GATE_LOADER, _OUTER_GATE_FINDER,
         _OUTER_COLLECTOR_SOURCE) = outer_candidate
    if sys.modules.get(AUTHENTICATED_GATE_MODULE) is not gate:
        raise InventoryError("authenticated pyelftools gate authority was replaced")
    result = method(root)
    if sys.modules.get(AUTHENTICATED_GATE_MODULE) is not gate:
        raise InventoryError("authenticated pyelftools gate authority was replaced")
    return result


def _authenticated_runner_source():
    """Capture the reviewed worker through one stable regular-file descriptor."""
    expected = Path(__file__).absolute().with_name(
        "bounded_command_runner.py")
    raw = read_bounded(expected, MAX_PINNED_RUNNER_BYTES)
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        raise InventoryError("authenticated bounded-command runner newlines changed")
    if b"\r" in raw:
        if (raw.count(b"\r") != raw.count(b"\r\n") or
                raw.count(b"\n") != raw.count(b"\r\n")):
            raise InventoryError("authenticated bounded-command runner newlines changed")
        raw = raw.replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != PINNED_RUNNER_SHA256:
        raise InventoryError("authenticated bounded-command runner changed")
    return raw


def _read_opened_bounded(stream, opened, limit, expected_size=None, budget=None):
    """Read one already-authenticated regular descriptor with a +1 sentinel."""
    if (type(limit) is not int or limit <= 0 or not 0 < opened.st_size <= limit or
            (expected_size is not None and
             (type(expected_size) is not int or opened.st_size != expected_size))):
        raise InventoryError("evidence size budget/mismatch")
    if budget is not None:
        budget.reserve_bytes(opened.st_size + 1)
    data = stream.read(opened.st_size + 1)
    after = os.fstat(stream.fileno())
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)
    if len(data) != opened.st_size or fields(opened) != fields(after):
        raise InventoryError("evidence changed during bounded read")
    return data


def _stable_stat_identity(value):
    """Stable authority fields; atime is intentionally excluded after reads."""
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_rdev, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate JSON key")
        result[key] = value
    return result


def exact_equal(left, right):
    """JSON equality without Python's bool/int aliasing."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            exact_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(
            exact_equal(a, b) for a, b in zip(left, right))
    return left == right


def load_strict_json(raw: bytes):
    try:
        return json.loads(
            raw,
            object_pairs_hook=strict_json_object,
            parse_float=lambda value: (_ for _ in ()).throw(
                InventoryError("floating JSON numbers are not allowed")),
            parse_constant=lambda value: (_ for _ in ()).throw(
                InventoryError("non-finite JSON number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("invalid inventory JSON") from exc


class EvidenceDirectory:
    """One retained, component-walked directory authority for local evidence."""
    def __init__(self, path: Path, allow_child_mutation=False):
        if type(allow_child_mutation) is not bool:
            raise InventoryError("invalid evidence-directory access mode")
        self.path = Path(path).absolute()
        self.allow_child_mutation = allow_child_mutation
        self.directory = None
        self._kernel = None
        self._ntdll = None
        self._HandleInfo = None
        self._windows_chain = []

    def __enter__(self):
        if os.name == "posix":
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | nofollow
            parts = self.path.parts
            descriptor = os.open(parts[0] if self.path.is_absolute() else ".", flags)
            try:
                for part in (parts[1:] if self.path.is_absolute() else parts):
                    if part in ("", ".", ".."):
                        raise InventoryError("unsafe evidence directory component")
                    child = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                self.directory = descriptor
                return self
            except BaseException:
                os.close(descriptor)
                raise
        if os.name == "nt":
            self._open_windows_directory()
            return self
        raise InventoryError("unsupported local evidence platform")

    def __exit__(self, *_):
        if self.directory is None:
            return
        if os.name == "nt":
            errors = []
            handles, self._windows_chain = self._windows_chain, []
            self.directory = None
            for handle in reversed(handles):
                if not self._kernel.CloseHandle(handle):
                    errors.append(InventoryError(
                        "could not close evidence directory authority"))
            if errors:
                raise errors[0]
        else:
            os.close(self.directory)
            self.directory = None

    def _open_windows_directory(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        class FileTime(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]
        class HandleInfo(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("created", FileTime),
                        ("accessed", FileTime), ("written", FileTime),
                        ("volume", wintypes.DWORD), ("sizeHigh", wintypes.DWORD),
                        ("sizeLow", wintypes.DWORD), ("links", wintypes.DWORD),
                        ("indexHigh", wintypes.DWORD), ("indexLow", wintypes.DWORD)]
        class UnicodeString(ctypes.Structure):
            _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                        ("Buffer", wintypes.LPWSTR)]
        class ObjectAttributes(ctypes.Structure):
            _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                        ("ObjectName", ctypes.POINTER(UnicodeString)),
                        ("Attributes", wintypes.ULONG), ("SecurityDescriptor", ctypes.c_void_p),
                        ("SecurityQualityOfService", ctypes.c_void_p)]
        class IoStatusBlock(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        ntdll.NtCreateFile.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
            ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatusBlock), ctypes.c_void_p,
            wintypes.ULONG, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
            ctypes.c_void_p, wintypes.ULONG]
        ntdll.NtCreateFile.restype = wintypes.LONG

        self._kernel, self._ntdll, self._HandleInfo = kernel, ntdll, HandleInfo
        self._UnicodeString, self._ObjectAttributes, self._IoStatusBlock = (
            UnicodeString, ObjectAttributes, IoStatusBlock)
        parts = self.path.parts
        if not self.path.is_absolute() or not parts or not re.fullmatch(r"[A-Za-z]:\\", parts[0]):
            raise InventoryError("Windows evidence directory must be drive-absolute")
        if any(":" in part for part in parts[1:]):
            raise InventoryError("Windows evidence directory contains an alternate stream")
        invalid = wintypes.HANDLE(-1).value
        # Retain the exact leaf with delete sharing denied.  Some ordinary
        # user-profile ancestors cannot be reopened with a restrictive share
        # mask (and walking them therefore rejects valid evidence paths).  The
        # no-reparse leaf plus its handle-resolved final path is the authority.
        desired = 0x001000c5 if self.allow_child_mutation else 0x00100081
        handle = kernel.CreateFileW(str(self.path), desired, 3, None, 3,
                                    0x02000000 | 0x00200000, None)
        if handle == invalid or not handle:
            raise InventoryError("could not open evidence directory authority")
        try:
            self._win_identity(handle, True)
            if self._win_final_path(handle) != self.path:
                raise InventoryError("evidence directory resolved through another path")
            self._windows_chain = [handle]
            self.directory = handle
        except BaseException:
            kernel.CloseHandle(handle)
            raise

    def _win_final_path(self, handle):
        import ctypes
        from ctypes import wintypes
        self._kernel.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        self._kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        needed = self._kernel.GetFinalPathNameByHandleW(handle, None, 0, 0)
        if not needed:
            raise InventoryError("could not resolve evidence directory authority")
        buffer = ctypes.create_unicode_buffer(needed + 1)
        written = self._kernel.GetFinalPathNameByHandleW(
            handle, buffer, len(buffer), 0)
        if not written or written >= len(buffer):
            raise InventoryError("could not resolve evidence directory authority")
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return Path(value).absolute()

    def _win_identity(self, handle, directory):
        import ctypes
        info = self._HandleInfo()
        if not self._kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise InventoryError("could not authenticate evidence handle")
        if info.attributes & 0x400 or directory != bool(info.attributes & 0x10):
            raise InventoryError("nonregular or reparse evidence path")
        return (info.attributes, info.created.high, info.created.low,
                info.volume, info.sizeHigh, info.sizeLow, info.links,
                info.indexHigh, info.indexLow, info.written.high, info.written.low)

    def _win_relative_open(self, parent, name, directory):
        import ctypes
        from ctypes import wintypes
        if (not name or name in (".", "..") or "\\" in name or "/" in name or
                ":" in name or "\0" in name):
            raise InventoryError("invalid evidence child name")
        buffer = ctypes.create_unicode_buffer(name)
        string = self._UnicodeString(len(name) * 2, (len(name) + 1) * 2,
                                     ctypes.cast(buffer, wintypes.LPWSTR))
        attrs = self._ObjectAttributes(ctypes.sizeof(self._ObjectAttributes), parent,
            ctypes.pointer(string), 0x40, None, None)
        status = self._IoStatusBlock()
        result = wintypes.HANDLE()
        options = 0x00200000 | 0x4000 | 0x20 | (0x1 if directory else 0x40)
        desired = 0x001000a0 if directory else 0x00100081
        share = 7 if directory else 1
        code = self._ntdll.NtCreateFile(ctypes.byref(result), desired,
            ctypes.byref(attrs), ctypes.byref(status), None, 0, share, 1,
            options, None, 0)
        if code < 0 or not result.value:
            raise InventoryError(f"could not open parent-relative evidence child {name!r} ({code & 0xffffffff:08x})")
        try:
            self._win_identity(result, directory)
            return result
        except BaseException:
            self._kernel.CloseHandle(result)
            raise

    def create_child_directory(self, name: str):
        """Create and return one retained direct-child directory, no replace."""
        if (type(name) is not str or not name or name in (".", "..") or
                "/" in name or "\\" in name or "\0" in name or
                (os.name == "nt" and ":" in name)):
            raise InventoryError("invalid evidence generation name")
        child = EvidenceDirectory(self.path / name)
        if os.name == "posix":
            os.mkdir(name, 0o700, dir_fd=self.directory)
            flags = (os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
            descriptor = os.open(name, flags, dir_fd=self.directory)
            try:
                created = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                opened = os.fstat(descriptor)
                if (not stat.S_ISDIR(opened.st_mode) or
                        _stable_stat_identity(created) != _stable_stat_identity(opened)):
                    raise InventoryError("created evidence generation changed")
                os.fsync(self.directory)
                child.directory = descriptor
                return child
            except BaseException:
                os.close(descriptor)
                raise
        if os.name != "nt":
            raise InventoryError("unsupported evidence generation platform")
        import ctypes
        from ctypes import wintypes
        buffer = ctypes.create_unicode_buffer(name)
        string = self._UnicodeString(len(name) * 2, (len(name) + 1) * 2,
                                     ctypes.cast(buffer, wintypes.LPWSTR))
        attrs = self._ObjectAttributes(ctypes.sizeof(self._ObjectAttributes),
            self.directory, ctypes.pointer(string), 0x40, None, None)
        status = self._IoStatusBlock()
        result = wintypes.HANDLE()
        # FILE_CREATE + FILE_DIRECTORY_FILE + OPEN_REPARSE_POINT.  The retained
        # handle itself performs the final directory rename, so Windows requires
        # delete sharing even though every transition is reauthenticated.
        code = self._ntdll.NtCreateFile(ctypes.byref(result), 0x001100a0,
            ctypes.byref(attrs), ctypes.byref(status), None, 0x10, 7, 2,
            0x00200000 | 0x4000 | 0x20 | 0x1, None, 0)
        if code < 0 or not result.value:
            if (code & 0xffffffff) == 0xC0000035:
                raise FileExistsError(name)
            raise InventoryError(
                f"could not create retained evidence generation ({code & 0xffffffff:08x})")
        try:
            self._win_identity(result, True)
            child._kernel, child._ntdll, child._HandleInfo = (
                self._kernel, self._ntdll, self._HandleInfo)
            child._UnicodeString, child._ObjectAttributes, child._IoStatusBlock = (
                self._UnicodeString, self._ObjectAttributes, self._IoStatusBlock)
            child._windows_chain = [result]
            child.directory = result
            if child._win_final_path(result) != child.path:
                raise InventoryError("created evidence generation resolved elsewhere")
            return child
        except BaseException:
            self._kernel.CloseHandle(result)
            raise

    @contextlib.contextmanager
    def open_regular(self, name: str, final_bytes=None):
        if (type(name) is not str or not name or name in (".", "..") or
                "/" in name or "\\" in name or "\0" in name or
                (os.name == "nt" and ":" in name)):
            raise InventoryError("invalid evidence filename")
        descriptor = None
        opened_identity = None
        native_handle = None
        if os.name == "posix":
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(name, flags, dir_fd=self.directory)
            except OSError as error:
                raise InventoryError("could not open regular evidence file") from error
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                os.close(descriptor)
                raise InventoryError("nonregular evidence file")
            opened_identity = _stable_stat_identity(opened)
        else:
            import msvcrt
            handle = self._win_relative_open(self.directory, name, False)
            opened_identity = self._win_identity(handle, False)
            native_handle = handle
            try:
                descriptor = msvcrt.open_osfhandle(handle.value, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                self._kernel.CloseHandle(handle)
                raise
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                descriptor = None
                opened = os.fstat(stream.fileno())
                yield stream, opened
                expected = None if final_bytes is None else final_bytes.get("data")
                if final_bytes is not None and type(expected) is not bytes:
                    raise InventoryError("missing final evidence byte witness")
                if os.name == "posix":
                    retained_identity = _stable_stat_identity(os.fstat(stream.fileno()))
                else:
                    retained_identity = self._win_identity(native_handle, False)
                if retained_identity != opened_identity:
                    raise InventoryError("retained evidence changed during read")
                if expected is not None:
                    position = stream.tell()
                    stream.seek(0)
                    retained_bytes = stream.read(len(expected) + 1)
                    stream.seek(position)
                    if retained_bytes != expected:
                        raise InventoryError("retained evidence bytes changed during read")
                    if os.name == "posix":
                        retained_after = _stable_stat_identity(os.fstat(stream.fileno()))
                    else:
                        retained_after = self._win_identity(native_handle, False)
                    if retained_after != opened_identity:
                        raise InventoryError("retained evidence changed during final read")
                if os.name == "posix":
                    try:
                        check = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK |
                                        getattr(os, "O_NOFOLLOW", 0), dir_fd=self.directory)
                    except OSError as error:
                        raise InventoryError("could not reauthenticate evidence name") from error
                    try:
                        checked = os.fstat(check)
                        if _stable_stat_identity(checked) != opened_identity:
                            raise InventoryError("evidence name replaced during read")
                        if expected is not None and os.pread(
                                check, len(expected) + 1, 0) != expected:
                            raise InventoryError("evidence name bytes changed during read")
                        if _stable_stat_identity(os.fstat(check)) != opened_identity:
                            raise InventoryError("evidence name changed during final read")
                    finally:
                        os.close(check)
                else:
                    check = self._win_relative_open(self.directory, name, False)
                    try:
                        if self._win_identity(check, False) != opened_identity:
                            raise InventoryError("evidence name replaced during read")
                        if expected is not None:
                            import msvcrt
                            checked_descriptor = msvcrt.open_osfhandle(
                                check.value, os.O_RDONLY | os.O_BINARY)
                            check = None
                            with os.fdopen(checked_descriptor, "rb", closefd=True) as checked_stream:
                                if checked_stream.read(len(expected) + 1) != expected:
                                    raise InventoryError("evidence name bytes changed during read")
                                checked_handle = msvcrt.get_osfhandle(checked_stream.fileno())
                                if self._win_identity(checked_handle, False) != opened_identity:
                                    raise InventoryError("evidence name changed during final read")
                    finally:
                        if check is not None and not self._kernel.CloseHandle(check):
                            raise InventoryError("could not close evidence name check")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def read(self, name: str, limit=MAX_FILE_BYTES, expected_size=None, budget=None) -> bytes:
        final_bytes = {}
        with self.open_regular(name, final_bytes) as (stream, opened):
            data = _read_opened_bounded(stream, opened, limit, expected_size, budget)
            final_bytes["data"] = data
            return data


@contextlib.contextmanager
def _open_regular_nofollow(path: Path):
    path = Path(path).absolute()
    with EvidenceDirectory(path.parent) as authority:
        with authority.open_regular(path.name) as opened:
            yield opened


def read_bounded(path: Path, limit=MAX_FILE_BYTES, expected_size=None,
                 budget=None) -> bytes:
    """Descriptor-first bounded read; debit bytes before materialization."""
    path = Path(path).absolute()
    with EvidenceDirectory(path.parent) as authority:
        return authority.read(path.name, limit, expected_size, budget)


def _descriptor_sha256(descriptor, expected_size):
    if type(expected_size) is not int or not 0 < expected_size <= MAX_FILE_BYTES:
        raise InventoryError("invalid staged evidence size")
    digest = hashlib.sha256()
    total = 0
    while total < expected_size:
        chunk = os.pread(descriptor, min(65536, expected_size - total), total)
        if not chunk:
            raise InventoryError("staged evidence shrank")
        digest.update(chunk)
        total += len(chunk)
    if os.pread(descriptor, 1, expected_size):
        raise InventoryError("staged evidence grew")
    return digest.hexdigest()


class _InventoryStage:
    """One retained anonymous/private stage for a future direct-child name."""
    def __init__(self, output, authority, payload_sha256, size,
                 descriptor=None, windows_handle=None, temporary_name=None):
        self.output = Path(output).absolute()
        self.authority = authority
        self.sha256 = payload_sha256
        self.size = size
        self.descriptor = descriptor
        self.windows_handle = windows_handle
        self.temporary_name = temporary_name
        self.committed = False

    def close(self, publication_committed=False):
        errors = []
        if self.windows_handle is not None:
            handle, self.windows_handle = self.windows_handle, None
            if not self.committed:
                import ctypes
                from ctypes import wintypes
                kernel = self.authority._kernel
                kernel.SetFileInformationByHandle.argtypes = [
                    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
                kernel.SetFileInformationByHandle.restype = wintypes.BOOL
                class Disposition(ctypes.Structure):
                    _fields_ = [("DeleteFile", wintypes.BOOL)]
                disposition = Disposition(True)
                if not kernel.SetFileInformationByHandle(
                        handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                    errors.append(InventoryError("could not retire private evidence stage"))
            if not self.authority._kernel.CloseHandle(handle):
                errors.append(InventoryError("could not close retained evidence stage"))
        if self.descriptor is not None:
            descriptor, self.descriptor = self.descriptor, None
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(error)
        if errors and not publication_committed:
            raise errors[0]


def _windows_stage_write(authority, handle, payload):
    import ctypes
    from ctypes import wintypes
    kernel = authority._kernel
    kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.WriteFile.restype = wintypes.BOOL
    at = 0
    while at < len(payload):
        chunk = payload[at:at + 65536]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not kernel.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
            raise OSError(ctypes.get_last_error(), "could not write private evidence stage")
        if written.value != len(chunk):
            raise InventoryError("short private evidence-stage write")
        at += written.value
    kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel.FlushFileBuffers.restype = wintypes.BOOL
    if not kernel.FlushFileBuffers(handle):
        raise OSError(ctypes.get_last_error(), "could not flush private evidence stage")


def _windows_stage_sha256(authority, handle, expected_size):
    import ctypes
    from ctypes import wintypes
    if type(expected_size) is not int or not 0 < expected_size <= MAX_FILE_BYTES:
        raise InventoryError("invalid Windows evidence-stage size")
    kernel = authority._kernel
    kernel.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    kernel.GetFileSizeEx.restype = wintypes.BOOL
    kernel.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                        ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    kernel.SetFilePointerEx.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.ReadFile.restype = wintypes.BOOL
    size = ctypes.c_longlong()
    if not kernel.GetFileSizeEx(handle, ctypes.byref(size)) or size.value != expected_size:
        raise InventoryError("retained Windows evidence-stage size changed")
    position = ctypes.c_longlong()
    if not kernel.SetFilePointerEx(handle, 0, ctypes.byref(position), 0):
        raise OSError(ctypes.get_last_error(), "could not rewind retained evidence stage")
    digest = hashlib.sha256()
    total = 0
    remaining = expected_size + 1
    while remaining:
        amount = min(65536, remaining)
        buffer = ctypes.create_string_buffer(amount)
        count = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, amount, ctypes.byref(count), None):
            raise OSError(ctypes.get_last_error(), "could not read retained evidence stage")
        if not count.value:
            break
        digest.update(buffer.raw[:count.value])
        total += count.value
        remaining -= count.value
    if total != expected_size:
        raise InventoryError("retained Windows evidence-stage content changed")
    return digest.hexdigest()


def _stage_inventory_bytes(authority, output, payload):
    """Stage nonempty bounded bytes without exposing their final child name."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_FILE_BYTES:
        raise InventoryError("invalid staged inventory payload")
    output = Path(output).absolute()
    name = output.name
    if (name in ("", ".", "..") or "/" in name or "\\" in name or "\0" in name or
            (os.name == "nt" and ":" in name) or output.parent != authority.path):
        raise InventoryError("invalid staged inventory output")
    digest = hashlib.sha256(payload).hexdigest()
    if os.name == "posix":
        anonymous = getattr(os, "O_TMPFILE", 0)
        if not anonymous:
            raise InventoryError("anonymous inventory staging is unavailable")
        descriptor = os.open(".", os.O_RDWR | os.O_CLOEXEC | anonymous,
                             0o600, dir_fd=authority.directory)
        try:
            at = 0
            while at < len(payload):
                written = os.write(descriptor, payload[at:at + 65536])
                if written <= 0:
                    raise InventoryError("short inventory-stage write")
                at += written
            os.fsync(descriptor)
            os.fchmod(descriptor, stat.S_IRUSR)
            readonly = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC)
            opened, reopened = os.fstat(descriptor), os.fstat(readonly)
            if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                    (reopened.st_dev, reopened.st_ino, reopened.st_size)):
                os.close(readonly)
                raise InventoryError("inventory stage changed during read-only reopen")
            os.close(descriptor)
            descriptor = readonly
            if _descriptor_sha256(descriptor, len(payload)) != digest:
                raise InventoryError("inventory-stage bytes changed")
            return _InventoryStage(output, authority, digest, len(payload),
                                   descriptor=descriptor)
        except BaseException:
            os.close(descriptor)
            raise
    if os.name != "nt":
        raise InventoryError("unsupported inventory-publication platform")
    import ctypes
    from ctypes import wintypes
    handle = None
    temporary_name = None
    for _ in range(64):
        candidate = ".inventory-" + secrets.token_hex(16) + ".tmp"
        buffer = ctypes.create_unicode_buffer(candidate)
        string = authority._UnicodeString(
            len(candidate) * 2, (len(candidate) + 1) * 2,
            ctypes.cast(buffer, wintypes.LPWSTR))
        attrs = authority._ObjectAttributes(
            ctypes.sizeof(authority._ObjectAttributes), authority.directory,
            ctypes.pointer(string), 0x40, None, None)
        status = authority._IoStatusBlock()
        created = wintypes.HANDLE()
        # Retain the private file from creation through its no-replace rename.
        # RootDirectory is the already authenticated generation directory, so
        # ancestor rename/recreation cannot redirect this stage.
        code = authority._ntdll.NtCreateFile(
            ctypes.byref(created), 0x00110183, ctypes.byref(attrs),
            ctypes.byref(status), None, 0x80, 0x1, 2,
            0x00200000 | 0x40 | 0x20, None, 0)
        if code >= 0 and created.value:
            handle, temporary_name = created, candidate
            break
        # STATUS_OBJECT_NAME_COLLISION / STATUS_OBJECT_NAME_EXISTS.
        if (code & 0xffffffff) not in (0xC0000035, 0x40000000):
            raise InventoryError(
                f"could not create private Windows evidence stage ({code & 0xffffffff:08x})")
    if handle is None:
        raise InventoryError("could not allocate private Windows evidence stage")
    stage = _InventoryStage(output, authority, digest, len(payload),
                            windows_handle=handle, temporary_name=temporary_name)
    try:
        _windows_stage_write(authority, handle, payload)
        if (authority._win_final_path(handle) != authority.path / temporary_name or
                _windows_stage_sha256(authority, handle, len(payload)) != digest):
            raise InventoryError("private Windows evidence-stage authority changed")
        return stage
    except BaseException:
        stage.close()
        raise


def _posix_link_inventory_stage(descriptor, directory, name):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_int]
    linkat.restype = ctypes.c_int
    if linkat(descriptor, b"", directory, os.fsencode(name), 0x1000) == 0:
        return
    error = ctypes.get_errno()
    if error not in (errno.EPERM, errno.ENOENT, errno.EINVAL,
                     getattr(errno, "EOPNOTSUPP", errno.EINVAL)):
        raise OSError(error, "anonymous inventory publication failed")
    if linkat(-100, os.fsencode(f"/proc/self/fd/{descriptor}"), directory,
              os.fsencode(name), 0x400) != 0:
        raise OSError(ctypes.get_errno(), "anonymous inventory publication failed")


def _commit_inventory_stage(stage):
    if not isinstance(stage, _InventoryStage) or stage.committed:
        raise InventoryError("invalid inventory publication stage")
    authority = stage.authority
    if os.name == "posix":
        opened = os.fstat(stage.descriptor)
        if (_descriptor_sha256(stage.descriptor, stage.size) != stage.sha256 or
                not stat.S_ISREG(opened.st_mode)):
            raise InventoryError("retained inventory stage changed before commit")
        _posix_link_inventory_stage(stage.descriptor, authority.directory,
                                    stage.output.name)
        linked = os.stat(stage.output.name, dir_fd=authority.directory,
                         follow_symlinks=False)
        if ((linked.st_dev, linked.st_ino, linked.st_size) !=
                (opened.st_dev, opened.st_ino, opened.st_size)):
            raise InventoryError("published inventory differs from retained stage")
        os.fsync(authority.directory)
    elif os.name == "nt":
        import ctypes
        from ctypes import wintypes
        if (_windows_stage_sha256(authority, stage.windows_handle, stage.size) !=
                stage.sha256):
            raise InventoryError("retained Windows inventory stage changed before commit")
        class RenameInfo(ctypes.Structure):
            _fields_ = [("ReplaceIfExists", ctypes.c_ubyte),
                        ("RootDirectory", wintypes.HANDLE),
                        ("FileNameLength", wintypes.DWORD),
                        ("FileName", wintypes.WCHAR * 1)]
        class IoStatusBlock(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p),
                        ("Information", ctypes.c_size_t)]
        encoded = stage.output.name.encode("utf-16-le")
        storage = ctypes.create_string_buffer(max(
            ctypes.sizeof(RenameInfo), RenameInfo.FileName.offset + len(encoded)))
        info = ctypes.cast(storage, ctypes.POINTER(RenameInfo)).contents
        info.ReplaceIfExists = 0
        info.RootDirectory = authority.directory
        info.FileNameLength = len(encoded)
        ctypes.memmove(ctypes.addressof(storage) + RenameInfo.FileName.offset,
                       encoded, len(encoded))
        ntdll = authority._ntdll
        ntdll.NtSetInformationFile.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(IoStatusBlock), ctypes.c_void_p,
            wintypes.ULONG, ctypes.c_int]
        ntdll.NtSetInformationFile.restype = wintypes.LONG
        status = IoStatusBlock()
        code = ntdll.NtSetInformationFile(stage.windows_handle,
            ctypes.byref(status), storage, len(storage), 10)
        if code < 0:
            raise InventoryError(
                f"no-replace Windows inventory commit failed ({code & 0xffffffff:08x})")
        authority._kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        authority._kernel.FlushFileBuffers.restype = wintypes.BOOL
        if not authority._kernel.FlushFileBuffers(stage.windows_handle):
            raise OSError(ctypes.get_last_error(), "could not flush committed evidence")
        if (authority._win_final_path(stage.windows_handle) != stage.output or
                _windows_stage_sha256(authority, stage.windows_handle, stage.size) !=
                stage.sha256):
            raise InventoryError("committed Windows evidence authority changed")
    else:
        raise InventoryError("unsupported inventory-publication platform")
    stage.committed = True


def _verify_inventory_stage(stage):
    if not isinstance(stage, _InventoryStage) or not stage.committed:
        raise InventoryError("invalid committed inventory stage")
    authority = stage.authority
    if os.name == "posix":
        retained = os.fstat(stage.descriptor)
        named_descriptor = os.open(stage.output.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=authority.directory)
        try:
            named = os.fstat(named_descriptor)
            if ((retained.st_dev, retained.st_ino, retained.st_size) !=
                    (named.st_dev, named.st_ino, named.st_size) or
                    _descriptor_sha256(stage.descriptor, stage.size) != stage.sha256 or
                    _descriptor_sha256(named_descriptor, stage.size) != stage.sha256):
                raise InventoryError("committed inventory evidence changed")
        finally:
            os.close(named_descriptor)
    elif os.name == "nt":
        if (authority._win_final_path(stage.windows_handle) != stage.output or
                _windows_stage_sha256(authority, stage.windows_handle, stage.size) !=
                stage.sha256):
            raise InventoryError("committed Windows inventory evidence changed")
    else:
        raise InventoryError("unsupported inventory-publication platform")


def _verify_inventory_generation_files(directory, stages):
    """Reauthenticate all exact named bytes through the retained directory."""
    for staged in stages:
        if os.name == "nt":
            # The retained stage handle was opened with FILE_SHARE_READ only;
            # it therefore prevents both replacement and new writers.  Opening
            # a second named handle would conflict with the retained handle's
            # still-present WRITE_DATA access.  Authenticate the retained
            # name/bytes directly instead.
            if (directory._win_final_path(staged.windows_handle) != staged.output or
                    _windows_stage_sha256(directory, staged.windows_handle,
                                          staged.size) != staged.sha256):
                raise InventoryError("activated inventory artifact changed")
        else:
            payload = directory.read(staged.output.name, staged.size, staged.size)
            if hashlib.sha256(payload).hexdigest() != staged.sha256:
                raise InventoryError("activated inventory artifact changed")


def _verify_terminal_inventory_stage(stage):
    """Authenticate an unpublished terminal stage by its retained authority."""
    if not isinstance(stage, _InventoryStage) or stage.committed:
        raise InventoryError("invalid unpublished terminal inventory stage")
    authority = stage.authority
    if os.name == "posix":
        opened = os.fstat(stage.descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 0 or
                _descriptor_sha256(stage.descriptor, stage.size) != stage.sha256):
            raise InventoryError("unpublished terminal inventory stage changed")
        os.fsync(stage.descriptor)
        return
    if os.name == "nt":
        if (type(stage.temporary_name) is not str or
                authority._win_final_path(stage.windows_handle) !=
                authority.path / stage.temporary_name or
                _windows_stage_sha256(authority, stage.windows_handle,
                                      stage.size) != stage.sha256):
            raise InventoryError("private Windows terminal inventory stage changed")
        return
    raise InventoryError("unsupported terminal inventory platform")


def _verify_evidence_directory_name(authority):
    """Bind a retained directory back to its originally requested name."""
    if not isinstance(authority, EvidenceDirectory) or authority.directory is None:
        raise InventoryError("invalid evidence directory authority")
    if os.name == "posix":
        retained = os.fstat(authority.directory)
        with EvidenceDirectory(authority.path) as rebound:
            current = os.fstat(rebound.directory)
            if (_stable_stat_identity(retained) !=
                    _stable_stat_identity(current)):
                raise InventoryError("evidence directory name was replaced")
        return
    if os.name == "nt":
        if authority._win_final_path(authority.directory) != authority.path:
            raise InventoryError("Windows evidence directory name was replaced")
        return
    raise InventoryError("unsupported evidence-directory platform")


def _activate_inventory_generation(parent, directory, private_name, final_name):
    """Expose one empty retained generation directory, never replacing a name."""
    if (not isinstance(parent, EvidenceDirectory) or
            not isinstance(directory, EvidenceDirectory) or
            type(private_name) is not str or type(final_name) is not str):
        raise InventoryError("invalid inventory generation activation")
    for name in (private_name, final_name):
        if (not name or name in (".", "..") or "/" in name or "\\" in name or
                "\0" in name or (os.name == "nt" and ":" in name)):
            raise InventoryError("invalid inventory generation activation name")
    _verify_evidence_directory_name(parent)
    if os.name == "posix":
        import ctypes
        private = os.stat(private_name, dir_fd=parent.directory,
                          follow_symlinks=False)
        retained = os.fstat(directory.directory)
        if (not stat.S_ISDIR(private.st_mode) or
                _stable_stat_identity(private) !=
                _stable_stat_identity(retained)):
            raise InventoryError("private inventory generation changed")
        # This directory is deliberately empty and has no semantic authority.
        # Publishing it before creating children avoids relying on platforms
        # being able to rename a directory containing retained child handles.
        os.fsync(parent.directory)
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError as error:
            raise InventoryError("no-replace generation activation is unavailable") from error
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        if renameat2(parent.directory, os.fsencode(private_name),
                     parent.directory, os.fsencode(final_name), 1) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "no-replace inventory generation activation failed")
        # No semantic authority exists yet, so failure to durably record this
        # empty-directory name is an ordinary prepublication failure.
        os.fsync(parent.directory)
        return
    if os.name != "nt":
        raise InventoryError("unsupported inventory-generation platform")
    import ctypes
    from ctypes import wintypes

    if directory._win_final_path(directory.directory) != parent.path / private_name:
        raise InventoryError("private Windows inventory generation resolved elsewhere")
    rebound = parent._win_relative_open(parent.directory, private_name, True)
    try:
        if (parent._win_identity(rebound, True) !=
                directory._win_identity(directory.directory, True)):
            raise InventoryError("private Windows inventory generation changed")
    finally:
        if not parent._kernel.CloseHandle(rebound):
            raise InventoryError("could not close private generation check")

    class RenameInfo(ctypes.Structure):
        _fields_ = [("ReplaceIfExists", ctypes.c_ubyte),
                    ("RootDirectory", wintypes.HANDLE),
                    ("FileNameLength", wintypes.DWORD),
                    ("FileName", wintypes.WCHAR * 1)]

    encoded = final_name.encode("utf-16-le")
    storage = ctypes.create_string_buffer(max(
        ctypes.sizeof(RenameInfo), RenameInfo.FileName.offset + len(encoded)))
    info = ctypes.cast(storage, ctypes.POINTER(RenameInfo)).contents
    info.ReplaceIfExists = 0
    info.RootDirectory = parent.directory
    info.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(storage) + RenameInfo.FileName.offset,
                   encoded, len(encoded))
    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p),
                    ("Information", ctypes.c_size_t)]

    # The generation is still empty, so the ordinary descriptor-relative
    # no-replace rename does not depend on child-handle rename semantics.
    ntdll = parent._ntdll
    ntdll.NtSetInformationFile.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(IoStatusBlock), ctypes.c_void_p,
        wintypes.ULONG, ctypes.c_int]
    ntdll.NtSetInformationFile.restype = wintypes.LONG
    status = IoStatusBlock()
    code = ntdll.NtSetInformationFile(directory.directory,
        ctypes.byref(status), storage, len(storage), 10)
    if code < 0:
        raise InventoryError(
            f"no-replace Windows inventory generation activation failed ({code & 0xffffffff:08x})")


def _retire_empty_inventory_generation(parent, directory, private_name):
    """Remove our still-private empty directory after activation failure."""
    if (not isinstance(parent, EvidenceDirectory) or
            not isinstance(directory, EvidenceDirectory) or
            type(private_name) is not str):
        raise InventoryError("invalid private inventory generation cleanup")
    if os.name == "posix":
        retained = os.fstat(directory.directory)
        named = os.stat(private_name, dir_fd=parent.directory,
                        follow_symlinks=False)
        if (_stable_stat_identity(retained) != _stable_stat_identity(named) or
                not stat.S_ISDIR(named.st_mode)):
            raise InventoryError("private inventory generation changed before cleanup")
        os.rmdir(private_name, dir_fd=parent.directory)
        return
    if os.name != "nt":
        raise InventoryError("unsupported inventory-generation platform")
    import ctypes
    from ctypes import wintypes
    if directory._win_final_path(directory.directory) != parent.path / private_name:
        raise InventoryError("private Windows generation changed before cleanup")
    kernel = directory._kernel
    kernel.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL

    class Disposition(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    disposition = Disposition(True)
    if not kernel.SetFileInformationByHandle(
            directory.directory, 4, ctypes.byref(disposition),
            ctypes.sizeof(disposition)):
        raise OSError(ctypes.get_last_error(),
                      "could not retire empty private inventory generation")


def _inventory_artifact_authority(report):
    """Return the exact non-authority artifact set authenticated by a report."""
    validate_inventory_v4(report)
    raw_size = report["completeRawMapsBytes"]
    raw_digest = report["completeRawMapsSha256"]
    expected = {
        "maps-before.txt": (raw_size, raw_digest),
        "maps-after.txt": (raw_size, raw_digest),
    }
    for metadata in report["libraries"].values():
        name = metadata["localFile"]
        if name in expected:
            raise InventoryError("duplicate authenticated inventory artifact")
        expected[name] = (metadata["bytes"], metadata["sha256"])
    return expected


def _verify_inventory_artifact_set(report, stages):
    """Bind every staged data byte, and no others, to the terminal report."""
    expected = _inventory_artifact_authority(report)
    actual = {}
    for stage in stages:
        if (not isinstance(stage, _InventoryStage) or
                stage.output.name in actual):
            raise InventoryError("invalid or duplicate staged inventory artifact")
        if os.name == "posix":
            retained_digest = _descriptor_sha256(stage.descriptor, stage.size)
        elif os.name == "nt":
            retained_digest = _windows_stage_sha256(
                stage.authority, stage.windows_handle, stage.size)
        else:
            raise InventoryError("unsupported inventory-publication platform")
        if retained_digest != stage.sha256:
            raise InventoryError("staged inventory artifact changed")
        actual[stage.output.name] = (stage.size, stage.sha256)
    if actual != expected:
        raise InventoryError("staged artifacts differ from inventory authority")


def _publish_terminal_inventory(stage):
    """Publish the exact retained stage as inventory.json in one terminal syscall.

    The caller must complete every potentially failing verification and flush
    before entering this function.  Once the no-replace rename succeeds there
    is deliberately no stat, hash, flush, or path operation that can turn a
    semantically committed generation into a reported retryable failure.
    """
    if (not isinstance(stage, _InventoryStage) or stage.committed or
            stage.output.name != "inventory.json"):
        raise InventoryError("invalid terminal inventory stage")
    authority = stage.authority
    if os.name == "posix":
        # O_TMPFILE has no mutable private pathname: this link publishes the
        # exact retained inode and fails if inventory.json already exists.
        _posix_link_inventory_stage(
            stage.descriptor, authority.directory, "inventory.json")
        # The link is the logical commit. A best-effort directory fsync can
        # improve power-loss durability, but must never turn a visible, valid
        # authority into a retryable reported failure. A lost directory update
        # after power failure simply leaves no inventory.json and consumers
        # continue to fail closed.
        try:
            os.fsync(authority.directory)
        except OSError:
            pass
        return
    if os.name != "nt":
        raise InventoryError("unsupported terminal inventory platform")
    import ctypes
    from ctypes import wintypes

    class RenameInfo(ctypes.Structure):
        _fields_ = [("ReplaceIfExists", ctypes.c_ubyte),
                    ("RootDirectory", wintypes.HANDLE),
                    ("FileNameLength", wintypes.DWORD),
                    ("FileName", wintypes.WCHAR * 1)]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p),
                    ("Information", ctypes.c_size_t)]

    encoded = "inventory.json".encode("utf-16-le")
    storage = ctypes.create_string_buffer(max(
        ctypes.sizeof(RenameInfo), RenameInfo.FileName.offset + len(encoded)))
    info = ctypes.cast(storage, ctypes.POINTER(RenameInfo)).contents
    info.ReplaceIfExists = 0
    info.RootDirectory = authority.directory
    info.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(storage) + RenameInfo.FileName.offset,
                   encoded, len(encoded))
    ntdll = authority._ntdll
    ntdll.NtSetInformationFile.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(IoStatusBlock), ctypes.c_void_p,
        wintypes.ULONG, ctypes.c_int]
    ntdll.NtSetInformationFile.restype = wintypes.LONG
    status = IoStatusBlock()
    code = ntdll.NtSetInformationFile(stage.windows_handle,
        ctypes.byref(status), storage, len(storage), 10)
    if code < 0:
        raise InventoryError(
            f"no-replace terminal inventory publication failed ({code & 0xffffffff:08x})")


class InventoryGeneration:
    """Multi-file generation whose inventory.json is the final authority."""
    def __init__(self, output):
        self.output = Path(output).absolute()
        self.parent = None
        self.directory = None
        self.private_name = None
        self.stages = []
        self.names = set()
        self.activated = False
        self.committed = False

    def __enter__(self):
        final_name = self.output.name
        if (final_name in ("", ".", "..") or "/" in final_name or
                "\\" in final_name or "\0" in final_name or
                (os.name == "nt" and ":" in final_name)):
            raise InventoryError("invalid inventory generation path")
        self.parent = EvidenceDirectory(self.output.parent, allow_child_mutation=True)
        self.parent.__enter__()
        try:
            for _ in range(64):
                candidate = ".inventory-generation-" + secrets.token_hex(16) + ".tmp"
                try:
                    self.directory = self.parent.create_child_directory(candidate)
                    self.private_name = candidate
                    break
                except FileExistsError:
                    continue
            if self.directory is None:
                raise InventoryError("could not allocate private inventory generation")
            _activate_inventory_generation(
                self.parent, self.directory, self.private_name, final_name)
            self.directory.path = self.output
            self.activated = True
            _verify_evidence_directory_name(self.parent)
            _verify_evidence_directory_name(self.directory)
            return self
        except BaseException as primary:
            cleanup_errors = []
            if self.directory is not None:
                if not self.activated:
                    try:
                        _retire_empty_inventory_generation(
                            self.parent, self.directory, self.private_name)
                    except BaseException as error:
                        cleanup_errors.append(error)
                try:
                    self.directory.__exit__(None, None, None)
                except BaseException as error:
                    cleanup_errors.append(error)
                self.directory = None
            try:
                self.parent.__exit__(None, None, None)
            except BaseException as error:
                cleanup_errors.append(error)
            self.parent = None
            for error in cleanup_errors:
                primary.add_note("inventory-generation cleanup: " + repr(error))
            raise

    def stage(self, name, payload):
        if (self.committed or type(name) is not str or
                name == "inventory.json" or name.startswith(".inventory-") or
                name in self.names):
            raise InventoryError("invalid or duplicate inventory data artifact")
        staged = _stage_inventory_bytes(
            self.directory, self.directory.path / name, payload)
        self.stages.append(staged)
        self.names.add(name)

    def finalize(self, report):
        if self.committed or type(report) is not dict:
            raise InventoryError("invalid inventory authority commit")
        _verify_inventory_artifact_set(report, self.stages)
        payload = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("ascii")
        authority_stage = _stage_inventory_bytes(
            self.directory, self.directory.path / "inventory.json", payload)
        self.stages.append(authority_stage)
        # Data names may become visible first, but no consumer authority exists
        # until the complete, validated inventory is the terminal commit.
        for staged in self.stages[:-1]:
            _commit_inventory_stage(staged)
        for staged in self.stages[:-1]:
            _verify_inventory_stage(staged)
        _verify_inventory_generation_files(self.directory, self.stages[:-1])
        _verify_terminal_inventory_stage(authority_stage)
        _verify_evidence_directory_name(self.parent)
        _verify_evidence_directory_name(self.directory)
        _publish_terminal_inventory(authority_stage)
        authority_stage.committed = True
        self.committed = True
        # POSIX cannot prevent the owning user from renaming a directory
        # between the precommit rebind and linkat. Distinguish that rare race
        # from every retryable precommit failure: exact authority already
        # exists through our retained directory and must not be duplicated by
        # an automatic retry.
        try:
            _verify_evidence_directory_name(self.parent)
            _verify_evidence_directory_name(self.directory)
        except BaseException as error:
            raise InventoryCommittedRelocatedError(
                "inventory authority committed outside the requested path; "
                "do not retry automatically") from error

    def __exit__(self, exc_type, exc, traceback):
        errors = []
        for staged in reversed(self.stages):
            try:
                staged.close(self.committed)
            except Exception as error:
                errors.append(error)
        self.stages = []
        if self.directory is not None:
            try:
                self.directory.__exit__(None, None, None)
            except Exception as error:
                errors.append(error)
            self.directory = None
        if self.parent is not None:
            try:
                self.parent.__exit__(None, None, None)
            except Exception as error:
                errors.append(error)
            self.parent = None
        # A durable terminal inventory must never be reported as a retryable
        # failure merely because handle cleanup or stdout later failed.
        if errors and not self.committed and exc is None:
            raise errors[0]


def _remaining_millis(deadline: float) -> int:
    remaining = max(0.0, deadline - time.monotonic())
    return min(0xFFFFFFFF, int(remaining * 1000 + 0.999999))


def _popen_before_deadline(command, hard_deadline: float, **kwargs):
    """Create no outer supervisor after its original hard deadline."""
    if time.monotonic() >= hard_deadline:
        raise InventoryError("bounded command timed out before supervisor creation")
    # Keep Popen immediately adjacent to the final pre-creation deadline gate.
    return subprocess.Popen(command, **kwargs)


def _posix_retire_outer_supervision(process, hard_deadline: float) -> bool:
    """Best-effort retirement after an untrusted supervisor result.

    The worker is the retained leader of a fresh session/process group.  A
    non-clean or malformed result cannot be trusted as proof that the worker
    retired every same-group descendant, so kill that exact group even when
    ``communicate`` has already reaped the leader.  A deliberately daemonized
    descendant which creates a different session is outside this unprivileged
    POSIX boundary.
    """
    group_retired = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException:
        group_retired = False

    # communicate() normally already reaped this exact Popen child.  Retain a
    # small cleanup grace for its exceptional paths; failure is reported to the
    # primary exception as a note and must never replace that primary failure.
    remaining = max(0.0, hard_deadline - time.monotonic())
    try:
        process.wait(timeout=max(0.001, min(0.25, remaining + 0.05)))
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException:
            group_retired = False
        try:
            process.wait(timeout=0.25)
        except BaseException:
            return False
    return group_retired and process.returncode is not None


def _windows_exact_process_retired(process, kernel) -> bool:
    if kernel.WaitForSingleObject(int(process._handle), 0) != 0:
        return False
    try:
        process.wait(timeout=0)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return True


def _windows_retire_unassigned_process(process, kernel,
                                       hard_deadline: float) -> bool:
    """Retry termination and require proof from the exact retained handle."""
    while True:
        waited = kernel.WaitForSingleObject(int(process._handle), 0)
        if waited == 0:
            return _windows_exact_process_retired(process, kernel)
        if waited != 258:  # WAIT_TIMEOUT
            return False
        try:
            kernel.TerminateProcess(int(process._handle), 91)
        except BaseException:
            # A raised termination API is not success, but a concurrent natural
            # exit may still be accepted only when the retained exact handle
            # independently proves it below.
            pass
        remaining_ms = _remaining_millis(hard_deadline)
        if remaining_ms == 0:
            return _windows_exact_process_retired(process, kernel)
        waited = kernel.WaitForSingleObject(
            int(process._handle), min(remaining_ms, 10))
        if waited == 0:
            return _windows_exact_process_retired(process, kernel)
        if waited != 258:
            return False


def _windows_supervise_worker(worker_command, hard_deadline: float,
                              worker_input: bytes, decode_result, *, kernel,
                              ntdll, limits_factory, accounting_factory,
                              pointer, size_of, spawn=None):
    """Run the disposable worker inside one authenticated kill-on-close Job.

    The injected API seam is intentionally private.  Production supplies the
    exact ctypes bindings below; host regressions can fault each boundary
    without launching or mutating a device process.
    """
    if spawn is None:
        spawn = _popen_before_deadline
    process = None
    job = None
    payload = b""
    assignment_confirmed = False
    preassignment_retired = False
    try:
        job = kernel.CreateJobObjectW(None, None)
        info = limits_factory()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        if not job or not kernel.SetInformationJobObject(
                job, 9, pointer(info), size_of(info)):
            raise InventoryError("could not establish bounded Windows process job")
        process = spawn(
            worker_command, hard_deadline,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004)
        if process is None:
            raise InventoryError("bounded command timed out before supervisor creation")
        try:
            assigned = bool(kernel.AssignProcessToJobObject(
                job, int(process._handle)))
        except BaseException as assignment_error:
            try:
                preassignment_retired = _windows_retire_unassigned_process(
                    process, kernel, hard_deadline)
            except BaseException as cleanup_error:
                failure = InventoryError(
                    "unassigned Windows supervisor cleanup uncertain")
                if hasattr(failure, "add_note"):
                    failure.add_note("assignment failure: " + repr(assignment_error))
                    failure.add_note("retirement failure: " + repr(cleanup_error))
                raise failure from assignment_error
            if not preassignment_retired:
                raise InventoryError(
                    "unassigned Windows supervisor cleanup uncertain") from assignment_error
            raise
        if not assigned:
            if not _windows_retire_unassigned_process(
                    process, kernel, hard_deadline):
                raise InventoryError("unassigned Windows supervisor cleanup uncertain")
            preassignment_retired = True
            raise InventoryError("could not assign bounded Windows process job")
        assignment_confirmed = True
        if time.monotonic() >= hard_deadline:
            raise InventoryError("bounded command timed out before resume")
        if ntdll.NtResumeProcess(int(process._handle)) != 0:
            raise InventoryError("could not resume bounded Windows process")
        try:
            payload, _ = process.communicate(
                input=worker_input,
                timeout=max(0.001, hard_deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            raise InventoryError("bounded command timed out")
        if time.monotonic() >= hard_deadline:
            raise InventoryError("bounded command timed out")
        return decode_result(payload, process.returncode)
    finally:
        # Cleanup failures remain terminal even if the worker produced a valid
        # result.  Closing a configured Job is a fallback kill action, not proof
        # that its complete process tree retired, so retain the failure verdict.
        cleanup_error = None
        job_verified = False
        if job and process is not None and not assignment_confirmed:
            # The worker is still suspended and therefore childless. Retire
            # its exact handle before releasing a Job whose assignment call
            # may itself have faulted after changing kernel state.
            if not preassignment_retired:
                try:
                    preassignment_retired = _windows_retire_unassigned_process(
                        process, kernel, hard_deadline)
                except BaseException:
                    preassignment_retired = False
            if not preassignment_retired:
                cleanup_error = InventoryError(
                    "unassigned Windows supervisor cleanup uncertain")
            try:
                closed = bool(kernel.CloseHandle(job))
            except BaseException:
                closed = False
            if not closed:
                cleanup_error = InventoryError(
                    "could not close bounded Windows process job")
            job = None
        elif job:
            try:
                try:
                    terminated = bool(kernel.TerminateJobObject(job, 91))
                except BaseException:
                    terminated = False
                if terminated:
                    accounting = accounting_factory()
                    while True:
                        try:
                            queried = bool(kernel.QueryInformationJobObject(
                                job, 1, pointer(accounting), size_of(accounting), None))
                        except BaseException:
                            queried = False
                        if not queried:
                            cleanup_error = InventoryError(
                                "could not authenticate bounded Windows job retirement")
                            break
                        if accounting.ActiveProcesses == 0:
                            job_verified = True
                            break
                        if time.monotonic() >= hard_deadline:
                            cleanup_error = InventoryError(
                                "bounded Windows process tree cleanup timed out")
                            break
                        time.sleep(0.005)
                else:
                    cleanup_error = InventoryError(
                        "could not terminate bounded Windows process job")

                if not job_verified:
                    try:
                        closed = bool(kernel.CloseHandle(job))
                    except BaseException:
                        closed = False
                    if not closed:
                        cleanup_error = InventoryError(
                            "could not close bounded Windows process job")
                    else:
                        job = None
                if process is not None:
                    try:
                        waited = kernel.WaitForSingleObject(
                            int(process._handle), _remaining_millis(hard_deadline))
                        process_retired = (waited == 0 and
                            _windows_exact_process_retired(process, kernel))
                    except BaseException:
                        process_retired = False
                    if not process_retired:
                        cleanup_error = InventoryError(
                            "bounded Windows supervisor did not retire")
            finally:
                if job:
                    try:
                        closed = bool(kernel.CloseHandle(job))
                    except BaseException:
                        closed = False
                    if not closed:
                        cleanup_error = InventoryError(
                            "could not close bounded Windows process job")
                    job = None
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        cleanup_error = InventoryError(
                            "could not close bounded Windows supervisor pipe")
        if cleanup_error is not None:
            raise cleanup_error


def bounded_command(command, limit, timeout=30):
    """Run via a disposable, childless supervisor with a distinct status wire."""
    if (type(limit) is not int or limit<=0 or not 0<timeout<=60 or
            type(command) not in (list, tuple) or not command or
            len(command) > MAX_BOUNDED_COMMAND_SPEC//3 or
            any(type(part) is not str or "\0" in part for part in command)):
        raise InventoryError("invalid command budget")
    # Bound both the number of empty arguments and total unescaped input before
    # json.dumps can create an expanded wire.  The exact UTF-8 wire is then
    # checked against the worker's matching MAX_SPEC contract.
    command_characters = 0
    for part in command:
        command_characters += len(part)
        if command_characters > MAX_BOUNDED_COMMAND_SPEC:
            raise InventoryError("bounded command specification exceeds budget")
    hard_deadline = time.monotonic() + timeout
    runner_source = _authenticated_runner_source()
    worker_command = [sys.executable, "-I", "-S", "-E", "-s", "-c",
                      RUNNER_BOOTSTRAP, PINNED_RUNNER_SHA256,
                      str(MAX_PINNED_RUNNER_BYTES)]
    specification = json.dumps({"command": list(command), "limit": limit,
        "deadlineNs": int(hard_deadline * 1_000_000_000)},
        separators=(",", ":")).encode("utf-8") + b"\n"
    if len(specification) > MAX_BOUNDED_COMMAND_SPEC:
        raise InventoryError("bounded command specification exceeds budget")
    magic = b"BCR1"
    worker_input = (len(runner_source).to_bytes(8, "big") + runner_source +
                    specification)

    def result(payload, returncode):
        if (returncode != 0 or len(payload) < 13 or payload[:4] != magic or
                payload[4] not in range(6)):
            raise InventoryError("bounded command supervisor failed")
        size = struct.unpack_from("<Q", payload, 5)[0]
        if size > limit or len(payload) != 13 + size:
            raise InventoryError("invalid bounded command result")
        if payload[4] == 1:
            raise InventoryError("bounded command failed")
        if payload[4] == 2:
            raise InventoryError("bounded command timed out")
        if payload[4] == 3:
            raise InventoryError("command output budget exceeded")
        if payload[4] == 4:
            raise InventoryError("bounded command cleanup failed")
        if payload[4] == 5:
            raise InventoryError("bounded command cleanup could not be authenticated")
        return payload[13:]

    if os.name == "posix":
        if not sys.platform.startswith("linux"):
            raise InventoryError("unsupported bounded command platform")
        process = _popen_before_deadline(
            worker_command, hard_deadline,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
        try:
            try:
                payload, _ = process.communicate(worker_input,
                    timeout=max(0.001, hard_deadline-time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise InventoryError("bounded command timed out") from exc
            return result(payload, process.returncode)
        except BaseException as primary:
            retired = _posix_retire_outer_supervision(process, hard_deadline)
            if not retired and hasattr(primary, "add_note"):
                primary.add_note(
                    "outer bounded-command supervisor retirement could not be authenticated")
            raise

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits),
                        ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                         ("PeakJobMemoryUsed", ctypes.c_size_t)]

        class BasicAccounting(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_longlong),
                        ("TotalKernelTime", ctypes.c_longlong),
                        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                        ("TotalPageFaultCount", wintypes.DWORD),
                        ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD),
                        ("TotalTerminatedProcesses", wintypes.DWORD)]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                     ctypes.c_void_p, wintypes.DWORD,
                                                     ctypes.c_void_p]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = wintypes.LONG
        return _windows_supervise_worker(
            worker_command, hard_deadline, worker_input, result,
            kernel=kernel, ntdll=ntdll, limits_factory=ExtendedLimits,
            accounting_factory=BasicAccounting, pointer=ctypes.byref,
            size_of=ctypes.sizeof)

    raise InventoryError("unsupported bounded command platform")


def mapped_file_identity(header, mappings, limit=MAX_FILE_BYTES):
    """stat decimal Linux dev_t must match maps' hexadecimal major:minor."""
    if type(limit) is not int or not 0 < limit <= MAX_FILE_BYTES:
        raise InventoryError("invalid mapped-file byte allowance")
    if not re.fullmatch(rb"[0-9]+:[0-9]+:[0-9]+:[0-9a-fA-F]+:[0-9]+:[0-9]+",header):
        raise InventoryError("invalid mapped descriptor stat")
    dev,inode,size,mode,mtime,ctime=header.decode().split(":")
    dev,inode,size=int(dev),int(inode),int(size)
    major=((dev>>8)&0xfff)|((dev>>32)&~0xfff)
    minor=(dev&0xff)|((dev>>12)&~0xff)
    identities={(m["device"],m["inode"]) for m in mappings}
    if len(identities) != 1:
        raise InventoryError("inconsistent mapped descriptor authority")
    mapped_device, mapped_inode = next(iter(identities))
    mapped_numbers = tuple(int(x, 16) for x in mapped_device.split(":"))
    if mapped_numbers != (major,minor) or mapped_inode != inode or inode<=0 or not stat.S_ISREG(int(mode,16)) or not 0<size<=limit:
        raise InventoryError("descriptor differs from mapped file identity/size")
    # Preserve the exact /proc/maps spelling (for example fd:04).  The numeric
    # stat comparison above authenticates it without inventing a second wire
    # representation that cannot round-trip into inventory-v4.
    return {"device":mapped_device,"inode":inode,"bytes":size,
            "mtime":int(mtime),"ctime":int(ctime),"authority":"proc-map-files-open-descriptor-v1"}


def mapped_capture_command(pid, mappings, limit=MAX_FILE_BYTES):
    if type(pid) is not int or not 1<pid<4194304 or not mappings:
        raise InventoryError("invalid mapped capture process")
    if type(limit) is not int or not 0 < limit <= MAX_FILE_BYTES:
        raise InventoryError("invalid mapped capture allowance")
    mapping=mappings[0]
    start,end=mapping["start"],mapping["end"]
    if type(start) is not int or type(end) is not int or not 0<start<end<(1<<56):
        raise InventoryError("invalid mapped capture range")
    # Open the exact mapped inode through the process, not an adb namespace
    # pathname. Keep that descriptor across both stat records and the data read.
    blocks = limit // 65536 + 1
    return (f"su -c 'exec 9</proc/{pid}/map_files/{start:x}-{end:x} || exit 61; "
            "size=$(stat -L -c %s /proc/self/fd/9) || exit 62; "
            f"[ \"$size\" -gt 0 ] && [ \"$size\" -le {limit} ] || exit 65; "
            "stat -L -c %d:%i:%s:%f:%Y:%Z /proc/self/fd/9 || exit 62; "
            f"dd if=/proc/self/fd/9 bs=65536 count={blocks} 2>/dev/null || exit 63; "
            "stat -L -c %d:%i:%s:%f:%Y:%Z /proc/self/fd/9 || exit 64'")


def parse_mapped_capture(payload, mappings, limit=MAX_FILE_BYTES):
    header,separator,rest=payload.partition(b"\n")
    if not separator or len(header)>256: raise InventoryError("missing descriptor header")
    identity=mapped_file_identity(header,mappings,limit)
    size=identity["bytes"]
    if len(rest)!=size+len(header)+1 or rest[size:]!=header+b"\n":
        raise InventoryError("mapped descriptor changed or transfer size mismatch")
    return rest[:size],identity


def process_identity(stat: str, expected_pid: int) -> tuple[int, int]:
    # comm can contain spaces or parentheses. Fields after final ')' start at 3.
    head, sep, tail = stat.strip().rpartition(")")
    if not sep or not head.startswith(str(expected_pid) + " ("):
        raise InventoryError("process stat identity mismatch")
    fields = tail.split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise InventoryError("malformed process start time")
    return expected_pid, int(fields[19])


def require_drawpath_cmdline(value: bytes) -> bytes:
    if type(value) is not bytes or value != b"com.ratta.drawpath\0":
        raise InventoryError("native process command line is not exact")
    return value


def complete_map_digest(raw: bytes) -> str:
    """Authenticate the exact bounded `/proc/<pid>/maps` byte sequence."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RAW_MAP_BYTES or not raw.endswith(b"\n"):
        raise InventoryError("invalid complete process-map capture")
    if (any(byte < 0x20 and byte != 0x0a for byte in raw) or
            any(token in raw for token in (
                b"\xef\xbb\xbf", b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9"))):
        raise InventoryError("process maps are not exact LF-only UTF-8")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise InventoryError("process maps are not strict UTF-8") from error
    lines = text[:-1].split("\n")
    if not 0 < len(lines) <= MAX_MAP_RECORDS:
        raise InventoryError("invalid complete process-map grammar")
    previous_end = 0
    for line in lines:
        match = MAP.fullmatch(line)
        if match is None or len(line.encode("utf-8")) > 4096:
            raise InventoryError("invalid complete process-map grammar")
        start, end = int(match.group(1), 16), int(match.group(2), 16)
        if start >= end or start < previous_end:
            raise InventoryError("unordered or overlapping complete process maps")
        previous_end = end
    return hashlib.sha256(raw).hexdigest()


def mapped_libraries(text: str) -> dict[str, list[dict]]:
    if type(text) is not str or len(text.encode("utf-8")) > 4 * 1024 * 1024:
        raise InventoryError("maps input budget exceeded")
    result: dict[str, list[dict]] = {}
    records = 0
    for line_number, line in enumerate(io.StringIO(text), 1):
        if line_number > MAX_MAP_RECORDS or len(line) > 4096:
            raise InventoryError("maps record budget exceeded")
        line = line.rstrip("\r\n")
        match = MAP.fullmatch(line)
        if not match:
            raise InventoryError("malformed maps record")
        start, end, perms, offset, dev, inode, path = match.groups()
        if int(start, 16) >= int(end, 16):
            raise InventoryError("invalid mapping extent")
        if not path or not path.endswith(".so") or not PATH.fullmatch(path):
            continue
        parts = path.split("/")
        if any(part in (".", "..") for part in parts):
            raise InventoryError("noncanonical library path")
        if path not in result and len(result) >= MAX_MAPPED_LIBRARIES:
            raise InventoryError("mapped library budget exceeded")
        records += 1
        if records > MAX_MAP_RECORDS:
            raise InventoryError("mapped library record budget exceeded")
        result.setdefault(path, []).append({
            "start": int(start, 16), "end": int(end, 16), "permissions": perms,
            "offset": int(offset, 16), "device": dev, "inode": int(inode),
        })
    for path, records in result.items():
        if len({(r["device"], r["inode"]) for r in records}) != 1:
            raise InventoryError("inconsistent mapped file identity: " + path)
    return result


def validate_mapping_set(value) -> dict[str, list[dict]]:
    """Strictly validate the complete filtered map set loaded from evidence."""
    if type(value) is not dict or len(value) > MAX_MAPPED_LIBRARIES:
        raise InventoryError("invalid filtered mapping set")
    total = 0
    normalized = {}
    occupied = []
    for path, records in value.items():
        if type(path) is not str or not PATH.fullmatch(path) or type(records) is not list or not records:
            raise InventoryError("invalid filtered mapping path/records")
        if any(part in (".", "..") for part in path.split("/")):
            raise InventoryError("noncanonical filtered mapping path")
        clean = []
        identities = set()
        previous_end = -1
        for record in records:
            total += 1
            if total > MAX_MAP_RECORDS or type(record) is not dict or set(record) != {
                    "start", "end", "permissions", "offset", "device", "inode"}:
                raise InventoryError("invalid filtered mapping record")
            start, end, offset, inode = (record[k] for k in ("start", "end", "offset", "inode"))
            permissions, device = record["permissions"], record["device"]
            if (any(type(x) is not int for x in (start, end, offset, inode)) or
                    not 0 < start < end < (1 << 56) or start % PAGE_SIZE or end % PAGE_SIZE or
                    offset < 0 or offset % PAGE_SIZE or inode <= 0 or
                    type(permissions) is not str or not re.fullmatch(r"[r-][w-][x-][ps]", permissions) or
                    type(device) is not str or not re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", device) or
                    start < previous_end):
                raise InventoryError("invalid filtered mapping fields/order")
            previous_end = end
            identities.add((device, inode))
            clean.append(dict(record))
            occupied.append((start, end, path))
        if len(identities) != 1:
            raise InventoryError("inconsistent filtered mapping identity")
        normalized[path] = clean
    occupied.sort()
    if any(end > next_start for (_, end, _), (next_start, _, _) in zip(occupied, occupied[1:])):
        raise InventoryError("overlapping filtered process mappings")
    return normalized


def mapping_set_digest(maps) -> str:
    normalized = validate_mapping_set(maps)
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


INVENTORY_NOTES = "Candidate closure only, not ELF binding/namespace or safe-initializer proof."


def validate_inventory_v4(value, budget=None) -> dict:
    """Validate the one exact inventory wire schema shared by all consumers."""
    top = {"schema", "firmware", "serial", "process", "filteredMappings",
           "filteredMapSetSha256", "completeRawMapsSha256",
           "completeRawMapsBytes", "nativeStartAllowed", "bindingAuthority",
           "libraries", "edges", "notes"}
    if type(value) is not dict or set(value) != top:
        raise InventoryError("invalid inventory v4 fields")
    if (value["schema"] != "native-loader-inventory-v4" or
            value["serial"] != SERIAL or value["firmware"] != FINGERPRINT or
            value["nativeStartAllowed"] is not False or
            value["bindingAuthority"] is not False or value["notes"] != INVENTORY_NOTES):
        raise InventoryError("wrong inventory v4 identity or authority")
    process = value["process"]
    if (type(process) is not dict or set(process) != {"pid", "startTime"} or
            type(process["pid"]) is not int or not 1 < process["pid"] < 4194304 or
            type(process["startTime"]) is not int or process["startTime"] <= 0):
        raise InventoryError("invalid inventory process identity")
    maps = validate_mapping_set(value["filteredMappings"])
    if budget is not None:
        budget.step(sum(len(records) for records in maps.values()) + len(maps))
    digest = mapping_set_digest(maps)
    if value["filteredMapSetSha256"] != digest:
        raise InventoryError("filtered mapping authority digest mismatch")
    raw_digest, raw_bytes = (value["completeRawMapsSha256"],
                             value["completeRawMapsBytes"])
    if (type(raw_digest) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", raw_digest) or
            type(raw_bytes) is not int or
            not 0 < raw_bytes <= MAX_RAW_MAP_BYTES):
        raise InventoryError("invalid complete raw-map authority")
    libraries = value["libraries"]
    library_fields = {"sha256", "bytes", "soname", "needed", "initArrayEntries",
                      "initFunctions", "mappings", "localFile", "mappedFileIdentity"}
    identity_fields = {"device", "inode", "bytes", "mtime", "ctime", "authority"}
    if type(libraries) is not dict or not 0 < len(libraries) <= MAX_FILES or ROOT_LIBRARY not in libraries:
        raise InventoryError("invalid inventory library set")
    total_bytes = 0
    local_files = set()
    for path, metadata in libraries.items():
        if budget is not None:
            budget.step()
        if path not in maps or type(metadata) is not dict or set(metadata) != library_fields:
            raise InventoryError("library outside mapping authority or invalid fields")
        if not exact_equal(metadata["mappings"], maps[path]):
            raise InventoryError("library mappings differ from complete mapping authority")
        sha256, byte_count, soname = (metadata[k] for k in ("sha256", "bytes", "soname"))
        if (type(sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", sha256) or
                type(byte_count) is not int or not 0 < byte_count <= MAX_FILE_BYTES or
                (soname is not None and (type(soname) is not str or not NAME.fullmatch(soname)))):
            raise InventoryError("invalid inventory library metadata")
        total_bytes += byte_count
        if total_bytes > MAX_TOTAL_BYTES:
            raise InventoryError("inventory dependency byte budget exceeded")
        needed = metadata["needed"]
        if type(needed) is not list or len(needed) > MAX_DEPENDENCIES:
            raise InventoryError("invalid inventory dependency list")
        name_bytes = 0
        for name in needed:
            if type(name) is not str or not NAME.fullmatch(name) or len(name.encode("utf-8")) > MAX_DEPENDENCY_NAME_BYTES:
                raise InventoryError("invalid inventory dependency name")
            name_bytes += len(name.encode("utf-8"))
            if name_bytes > MAX_DEPENDENCY_NAME_BYTES_TOTAL:
                raise InventoryError("inventory dependency-name budget exceeded")
        init_entries, init_functions = metadata["initArrayEntries"], metadata["initFunctions"]
        if (type(init_entries) is not int or not 0 <= init_entries <= MAX_FILE_BYTES // 8 or
                type(init_functions) is not list or len(init_functions) > MAX_DYNAMIC_ENTRIES or
                any(type(item) is not int or not 0 <= item < (1 << 64) for item in init_functions)):
            raise InventoryError("invalid inventory initializer metadata")
        filename = metadata["localFile"]
        if type(filename) is not str or not re.fullmatch(r"[0-9a-f]{16}\.so", filename) or filename in local_files:
            raise InventoryError("invalid or duplicate local evidence filename")
        local_files.add(filename)
        identity = metadata["mappedFileIdentity"]
        if type(identity) is not dict or set(identity) != identity_fields:
            raise InventoryError("invalid mapped descriptor identity fields")
        if (identity["authority"] != "proc-map-files-open-descriptor-v1" or
                type(identity["bytes"]) is not int or identity["bytes"] != byte_count or
                type(identity["inode"]) is not int or
                identity["inode"] <= 0 or type(identity["device"]) is not str or
                not re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", identity["device"]) or
                type(identity["mtime"]) is not int or identity["mtime"] < 0 or
                type(identity["ctime"]) is not int or identity["ctime"] < 0 or
                any((record["device"], record["inode"]) !=
                    (identity["device"], identity["inode"]) for record in maps[path])):
            raise InventoryError("inventory lacks exact mapped descriptor authority")
    edges = value["edges"]
    if type(edges) is not list or len(edges) > MAX_DEPENDENCY_EDGES:
        raise InventoryError("invalid dependency edge set")
    expected_pairs = []
    for path, metadata in libraries.items():
        for name in metadata["needed"]:
            if budget is not None:
                budget.step()
            expected_pairs.append((path, name))
            if len(expected_pairs) > MAX_DEPENDENCY_EDGES:
                raise InventoryError("dependency edge budget exceeded")
    expected_pairs.sort()
    actual_pairs = []
    candidate_index = dependency_candidate_index(maps, budget)
    for edge in edges:
        if budget is not None:
            budget.step()
        if type(edge) is not dict or set(edge) != {"requester", "needed", "candidates", "resolution"}:
            raise InventoryError("invalid dependency edge fields")
        requester, needed, candidates = edge["requester"], edge["needed"], edge["candidates"]
        if requester not in libraries or type(needed) is not str or type(candidates) is not list:
            raise InventoryError("invalid dependency edge authority")
        expected_candidates = dependency_candidates(needed, maps, candidate_index, budget)
        resolution = ("unresolved_multiple" if len(expected_candidates) > 1 else
                      "missing" if not expected_candidates else "unique_mapped_candidate")
        if (not exact_equal(candidates, expected_candidates) or
                type(edge["resolution"]) is not str or edge["resolution"] != resolution):
            raise InventoryError("dependency edge differs from mapping authority")
        actual_pairs.append((requester, needed))
    if sorted(actual_pairs) != expected_pairs:
        raise InventoryError("dependency edges do not cover exact requested set")
    reachable = {ROOT_LIBRARY}
    pending = deque([ROOT_LIBRARY])
    while pending:
        requester = pending.popleft()
        for needed in libraries[requester]["needed"]:
            if budget is not None:
                budget.step()
            for candidate in dependency_candidates(needed, maps, candidate_index, budget):
                if candidate not in libraries:
                    raise InventoryError("root-reachable candidate missing from inventory libraries")
                if candidate not in reachable:
                    reachable.add(candidate)
                    pending.append(candidate)
    if reachable != set(libraries):
        raise InventoryError("inventory libraries differ from root-reachable candidate closure")
    return value


def preflight_elf_header(data: bytes) -> None:
    """Reject adversarial header counts before pyelftools materializes objects."""
    if not data or len(data) > MAX_FILE_BYTES or len(data) < 64:
        raise InventoryError("invalid ELF file size")
    try:
        (ident, _, machine, _, _, phoff, shoff, _, ehsize, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    except struct.error as exc:
        raise InventoryError("truncated ELF header") from exc
    if (ident[:7] != b"\x7fELF\x02\x01\x01" or machine != 183 or ehsize != 64 or
            phentsize != 56 or not 0 < phnum <= MAX_PROGRAM_HEADERS or
            shnum > MAX_SECTION_HEADERS or phoff + phnum * phentsize > len(data) or
            (shnum == 0 and shoff != 0) or
            (shnum and (shentsize != 64 or shoff + shnum * shentsize > len(data))) or
            (shnum and shstrndx >= shnum) or phnum == 0xffff or shnum == 0xffff or
            shstrndx == 0xffff):
        raise InventoryError("unsupported or over-budget ELF header")
    raw_sections = []
    for index in range(shnum):
        section = shoff + index * shentsize
        raw_sections.append(struct.unpack_from("<IIQQQQIIQQ", data, section))
        sh_type = struct.unpack_from("<I", data, section + 4)[0]
        sh_size = struct.unpack_from("<Q", data, section + 32)[0]
        sh_entsize = struct.unpack_from("<Q", data, section + 56)[0]
        if sh_type == 4 and (sh_entsize != 24 or sh_size % 24):
            raise InventoryError("invalid raw SHT_RELA entry size")
    # pyelftools resolves every section name while iterating sections. Bound and
    # validate that unauthenticated work before constructing ELFFile so repeated
    # offsets cannot trigger repeated scans of a giant unterminated string.
    if shnum:
        if shstrndx == 0:
            if any(section[0] != 0 for section in raw_sections):
                raise InventoryError("section names present without a name table")
        else:
            string_header = raw_sections[shstrndx]
            string_offset, string_size = string_header[4], string_header[5]
            if (string_header[1] != 3 or not 0 < string_size <= MAX_SECTION_NAME_TABLE_BYTES or
                    string_offset + string_size > len(data)):
                raise InventoryError("invalid or over-budget section-name table")
            names = data[string_offset:string_offset + string_size]
            if not names or names[0] != 0:
                raise InventoryError("invalid section-name table prefix")
            checked = set()
            for section in raw_sections:
                name_offset = section[0]
                if name_offset in checked:
                    continue
                checked.add(name_offset)
                if name_offset >= len(names):
                    raise InventoryError("section name outside bounded table")
                end = names.find(b"\0", name_offset,
                                 min(len(names), name_offset + MAX_SECTION_NAME_BYTES + 1))
                if end < 0:
                    raise InventoryError("unterminated or over-budget section name")
                try:
                    names[name_offset:end].decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise InventoryError("invalid section-name encoding") from exc


def _page_floor(value: int) -> int:
    return value & -PAGE_SIZE


def _page_ceil(value: int) -> int:
    return (value + PAGE_SIZE - 1) & -PAGE_SIZE


def runtime_file_offset(address, size, loads):
    """Return the effective runtime file offset after ordered page mappings.

    PT_LOAD mappings are page rounded and applied in program-header order. A
    later nominally disjoint segment can therefore replace an earlier page.
    BSS tails/anonymous pages are modeled as zero backing and are never accepted
    as file authority.
    """
    if any(type(x) is not int for x in (address, size)) or min(address, size) < 0 or size == 0 or address + size >= (1 << 64):
        raise InventoryError("invalid runtime table extent")
    if type(loads) is not list or not 0 < len(loads) <= MAX_PROGRAM_HEADERS:
        raise InventoryError("invalid runtime load set")
    end = address + size
    operations = []
    cuts = {address, end}
    for load in loads:
        new_operations = []
        vaddr, offset, filesz, memsz = (int(load[k]) for k in
                                        ("p_vaddr", "p_offset", "p_filesz", "p_memsz"))
        flags = int(load["p_flags"])
        readable = bool(flags & 4)
        writable = bool(flags & 2)
        file_start, file_end = _page_floor(vaddr), _page_ceil(vaddr + filesz)
        # Bionic includes the in-page prefix implied by p_offset/p_vaddr even
        # when p_filesz is zero.  Only an aligned zero-file segment has no file
        # mapping at all.
        if file_end > file_start:
            new_operations.append((file_start, file_end, "file", _page_floor(offset), readable))
        # Bionic zeroes the remainder of a writable segment's final file page
        # even when p_filesz == p_memsz.  This is independent from allocation
        # of later anonymous BSS pages.  Read-only tails retain file authority.
        if writable and vaddr + filesz < file_end:
            new_operations.append((vaddr + filesz, file_end, "zero", None, False))
        if filesz < memsz:
            anonymous_end = _page_ceil(vaddr + memsz)
            if file_end < anonymous_end:
                new_operations.append((file_end, anonymous_end, "zero", None, False))
        operations.extend(new_operations)
        for start, stop, *_ in new_operations:
            if address < start < end:
                cuts.add(start)
            if address < stop < end:
                cuts.add(stop)
    first_offset = None
    expected_offset = None
    points = sorted(cuts)
    for fragment_start, fragment_end in zip(points, points[1:]):
        state = None
        for start, stop, kind, file_page, readable in operations:
            if start <= fragment_start < stop:
                state = (kind, None if file_page is None else
                         file_page + fragment_start - start, readable)
        if state is None or state[0] != "file" or not state[2]:
            raise InventoryError("runtime table lacks effective readable file backing")
        offset = state[1]
        if expected_offset is not None and offset != expected_offset:
            raise InventoryError("runtime table has discontinuous effective file backing")
        if first_offset is None:
            first_offset = offset
        expected_offset = offset + fragment_end - fragment_start
    return first_offset


def dynamic_entries(elf, budget=None):
    """Validate the runtime-address authority before parsing any dynamic tag.

    Do not use DynamicSegment.iter_tags: that resolves strings through optional
    section links and can scan past PT_DYNAMIC searching for a terminator.
    """
    stream=elf.stream
    saved=stream.tell()
    length=stream.seek(0,2)
    stream.seek(saved)
    if not 0<length<=MAX_FILE_BYTES or elf.elfclass!=64 or not elf.little_endian or elf["e_machine"]!="EM_AARCH64":
        raise InventoryError("unsupported dynamic image")
    if not 0 < elf.num_segments() <= MAX_PROGRAM_HEADERS:
        raise InventoryError("program segment budget exceeded")
    segment_count = elf.num_segments()
    if budget is not None:
        budget.step(segment_count)
    segments=list(elf.iter_segments())
    loads=[s for s in segments if s["p_type"]=="PT_LOAD"]
    seen_loads = set()
    for load in loads:
        offset,address,size,memory,align=(load[k] for k in ("p_offset","p_vaddr","p_filesz","p_memsz","p_align"))
        load_identity = (int(offset), int(address), int(size), int(memory), int(load["p_flags"]), int(align))
        if load_identity in seen_loads:
            raise InventoryError("duplicate file-backed program segment")
        seen_loads.add(load_identity)
        if min(offset,address,size,memory,align)<0 or size>memory or offset+size>length or address+memory>=(1<<64) or (
                align>1 and (align&(align-1) or address%align!=offset%align)) or address%PAGE_SIZE!=offset%PAGE_SIZE:
            raise InventoryError("invalid file-backed program segment")
    dynamics=[s for s in segments if s["p_type"]=="PT_DYNAMIC"]
    if len(dynamics)!=1: raise InventoryError("expected one dynamic segment")
    dynamic=dynamics[0]
    address,offset,size=dynamic["p_vaddr"],dynamic["p_offset"],dynamic["p_filesz"]
    if size<=0 or size//16>MAX_DYNAMIC_ENTRIES or size%16 or offset%8 or address%8 or dynamic["p_memsz"]!=size:
        raise InventoryError("invalid dynamic extent")
    if budget is not None:
        budget.reserve_bytes(size)
    if runtime_file_offset(address,size,loads)!=offset:
        raise InventoryError("dynamic segment file correspondence mismatch")
    stream.seek(offset)
    data=stream.read(size)
    if len(data)!=size: raise InventoryError("truncated dynamic segment")
    entries=[]
    for i in range(0,size,16):
        if budget is not None:
            budget.step()
        entry=elf.structs.Elf_Dyn.parse(data[i:i+16])
        entries.append(entry)
        if entry.d_tag=="DT_NULL": return entries,loads
    raise InventoryError("dynamic terminator outside declared extent")


def dynamic_strings(elf,entries,loads):
    tables=[int(e.d_val) for e in entries if e.d_tag=="DT_STRTAB"]
    sizes=[int(e.d_val) for e in entries if e.d_tag=="DT_STRSZ"]
    if len(tables)!=1 or len(sizes)!=1 or not 0<sizes[0]<=MAX_DYNAMIC_STRING_BYTES:
        raise InventoryError("ambiguous dynamic string table")
    offset=runtime_file_offset(tables[0],sizes[0],loads)
    elf.stream.seek(offset)
    data=elf.stream.read(sizes[0])
    if len(data)!=sizes[0]: raise InventoryError("truncated dynamic strings")
    return data


def bounded_string(data,offset,limit=MAX_DEPENDENCY_NAME_BYTES):
    if not 0<=offset<len(data): raise InventoryError("dynamic name offset outside string table")
    end=data.find(b"\0",offset,min(len(data),offset+limit+1))
    if end<0: raise InventoryError("unterminated or over-budget dynamic name")
    return data[offset:end].decode("utf-8",errors="strict")


def elf_metadata(data: bytes) -> dict:
    from elftools.elf.elffile import ELFFile
    preflight_elf_header(data)
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_DYN":
        raise InventoryError("expected AArch64 little-endian shared library")
    entries,loads=dynamic_entries(elf)
    strings=dynamic_strings(elf,entries,loads)
    needed, sonames, sizes, init_functions = [], [], [], []
    names = {}
    total_name_bytes = 0
    for tag in entries:
        kind = tag.d_tag
        if kind == "DT_NEEDED":
            if len(needed) >= MAX_DEPENDENCIES:
                raise InventoryError("dependency count budget exceeded")
            name_offset = int(tag.d_val)
            if name_offset not in names:
                names[name_offset] = bounded_string(strings, name_offset)
            name = names[name_offset]
            total_name_bytes += len(name.encode("utf-8"))
            if total_name_bytes > MAX_DEPENDENCY_NAME_BYTES_TOTAL:
                raise InventoryError("dependency name budget exceeded")
            if not NAME.fullmatch(name):
                raise InventoryError("unsupported dependency name")
            needed.append(name)
        elif kind == "DT_SONAME":
            sonames.append(bounded_string(strings,int(tag.d_val)))
        elif kind == "DT_INIT_ARRAYSZ":
            sizes.append(int(tag.d_val))
        elif kind == "DT_INIT":
            init_functions.append(int(tag.d_ptr))
    if len(sonames) > 1 or any(not NAME.fullmatch(x) for x in sonames):
        raise InventoryError("invalid SONAME")
    if len(sizes) > 1 or (sizes and (sizes[0] % 8 or sizes[0] > len(data))):
        raise InventoryError("invalid initializer array size")
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "soname": sonames[0] if sonames else None, "needed": needed,
            "initArrayEntries": sizes[0] // 8 if sizes else 0,
            "initFunctions": init_functions}


def dependency_candidate_index(maps, budget=None):
    if type(maps) is not dict:
        raise InventoryError("invalid dependency mapping authority")
    result = {}
    for path in maps:
        if budget is not None:
            budget.step()
        result.setdefault(PurePosixPath(path).name, []).append(path)
    for paths in result.values():
        paths.sort()
    return result


def dependency_candidates(name: str, maps: dict[str, list[dict]], index=None,
                          budget=None) -> list[str]:
    if type(name) is not str or len(name.encode("utf-8")) > MAX_DEPENDENCY_NAME_BYTES or not NAME.fullmatch(name):
        raise InventoryError("unsupported dependency name")
    if budget is not None:
        budget.step()
    if index is None:
        index = dependency_candidate_index(maps, budget)
    if type(index) is not dict:
        raise InventoryError("invalid dependency candidate index")
    return list(index.get(name, ()))


def collect_graph(maps: dict, read_library, publish_library=None) -> tuple[dict, list[dict]]:
    if ROOT_LIBRARY not in maps:
        raise InventoryError("pinned DrawPath library is not mapped")
    pending, libraries, edges, total = deque([ROOT_LIBRARY]), {}, [], 0
    queued = {ROOT_LIBRARY}
    while pending:
        path = pending.popleft()
        queued.discard(path)
        if path in libraries:
            continue
        if len(libraries) >= MAX_FILES:
            raise InventoryError("dependency file budget exceeded")
        remaining = MAX_TOTAL_BYTES - total
        capture = read_library(path, remaining)
        if type(capture) is not tuple or len(capture) != 2:
            raise InventoryError("library reader did not return metadata and bounded payload")
        metadata, payload = capture
        if type(metadata) is not dict:
            raise InventoryError("invalid library metadata")
        if type(metadata["bytes"]) is not int or not 0 < metadata["bytes"] <= MAX_FILE_BYTES:
            raise InventoryError("invalid library byte count")
        if metadata["bytes"] > remaining:
            raise InventoryError("dependency byte budget exceeded before capture admission")
        if type(payload) is not bytes or len(payload) != metadata["bytes"]:
            raise InventoryError("captured library payload size mismatch")
        total += metadata["bytes"]
        if total > MAX_TOTAL_BYTES:
            raise InventoryError("dependency byte budget exceeded")
        if path == ROOT_LIBRARY and metadata["sha256"] != ROOT_SHA256:
            raise InventoryError("root library digest differs from pinned firmware")
        libraries[path] = {**metadata, "mappings": maps[path]}
        needed = metadata["needed"]
        if type(needed) is not list or len(needed) > MAX_DEPENDENCIES:
            raise InventoryError("invalid dependency list")
        for name in needed:
            if len(edges) >= MAX_DEPENDENCY_EDGES:
                raise InventoryError("dependency edge budget exceeded")
            candidates = dependency_candidates(name, maps)
            edges.append({"requester": path, "needed": name, "candidates": candidates,
                          "resolution": "unresolved_multiple" if len(candidates) > 1 else
                          "missing" if not candidates else "unique_mapped_candidate"})
            for candidate in candidates:
                if candidate not in libraries and candidate not in queued:
                    pending.append(candidate)
                    queued.add(candidate)
        if publish_library is not None:
            publish_library(path, metadata, payload)
    # Even a unique mapped candidate does not prove the actual relocation target.
    return libraries, edges


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--python-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Establish the authenticated, source-only parser before reading the device
    # or creating artifacts. Never delegate this import to the ambient path.
    authenticate_elftools(args.python_path)
    adb = str(args.adb.resolve(strict=True))

    def run(*command: str, timeout=30) -> bytes:
        return bounded_command([adb,"-s",SERIAL,*command],4*1024*1024,timeout)

    fingerprint = run("shell", "getprop", "ro.build.fingerprint").decode().strip()
    if fingerprint != FINGERPRINT:
        raise InventoryError("wrong firmware or device")
    pid_text = run("shell", "pidof", "com.ratta.drawpath").decode().strip()
    if not pid_text.isdecimal() or not 1 < int(pid_text) < 4194304:
        raise InventoryError("expected exactly one native pen process")
    pid = int(pid_text)

    def snapshot() -> tuple[tuple, dict, bytes, str]:
        first = process_identity(run("exec-out", f"su -c 'cat /proc/{pid}/stat'").decode(), pid)
        require_drawpath_cmdline(
            run("exec-out", f"su -c 'cat /proc/{pid}/cmdline'"))
        raw = run("exec-out", f"su -c 'cat /proc/{pid}/maps'")
        # Authenticate the complete byte wire, including excluded rows, before
        # any Unicode decoding or filtered-library projection.
        raw_digest = complete_map_digest(raw)
        text = raw.decode("utf-8", errors="strict")
        last = process_identity(run("exec-out", f"su -c 'cat /proc/{pid}/stat'").decode(), pid)
        if first != last:
            raise InventoryError("native process changed during capture")
        return first, mapped_libraries(text), raw, raw_digest

    before, maps, raw, raw_digest = snapshot()
    maps = validate_mapping_set(maps)
    maps_digest = mapping_set_digest(maps)
    with InventoryGeneration(args.output) as generation:
        generation.stage("maps-before.txt", raw)

        def read_library(path: str, remaining: int) -> tuple[dict, bytes]:
            if not PATH.fullmatch(path):
                raise InventoryError("path outside allowed system-library roots")
            if type(remaining) is not int or remaining <= 0:
                raise InventoryError("dependency byte allowance exhausted")
            basename = PurePosixPath(path).name
            # Short artifact basename: adb on Windows cannot reliably create long
            # paths. The complete remote path/digest remain in the JSON inventory.
            filename = hashlib.sha256(path.encode()).hexdigest()[:16] + ".so"
            if filename in generation.names:
                raise InventoryError("local evidence filename collision")
            allowance = min(MAX_FILE_BYTES, remaining)
            command=[adb,"-s",SERIAL,"exec-out",mapped_capture_command(pid,maps[path],allowance)]
            data,identity=parse_mapped_capture(
                bounded_command(command,allowance+512,60),maps[path],allowance)
            again,identity_again=parse_mapped_capture(
                bounded_command(command,allowance+512,60),maps[path],allowance)
            if data!=again or identity!=identity_again:
                raise InventoryError("mapped library changed across bounded captures")
            metadata = elf_metadata(data)
            return ({**metadata, "localFile": filename,"mappedFileIdentity":identity}, data)

        def publish_library(path: str, metadata: dict, data: bytes) -> None:
            if len(data) != metadata["bytes"]:
                raise InventoryError("local evidence publication mismatch")
            generation.stage(metadata["localFile"], data)
            print("READ", PurePosixPath(path).name, metadata["bytes"], flush=True)

        libraries, edges = collect_graph(maps, read_library, publish_library)
        after, after_maps, after_raw, after_raw_digest = snapshot()
        after_maps = validate_mapping_set(after_maps)
        if (after != before or after_raw != raw or after_raw_digest != raw_digest or
                after_maps != maps or mapping_set_digest(after_maps) != maps_digest):
            raise InventoryError("process or complete raw/filtered mapping set changed")
        generation.stage("maps-after.txt", after_raw)
        report = {"schema": "native-loader-inventory-v4", "firmware": fingerprint,
                  "serial": SERIAL, "process": {"pid": pid, "startTime": before[1]},
                  "filteredMappings": maps, "filteredMapSetSha256": maps_digest,
                  "completeRawMapsSha256": raw_digest,
                  "completeRawMapsBytes": len(raw),
                  "nativeStartAllowed": False, "bindingAuthority": False,
                  "libraries": libraries, "edges": edges,
                  "notes": INVENTORY_NOTES}
        validate_inventory_v4(report)
        generation.finalize(report)
    unresolved = [e for e in edges if e["resolution"] != "unique_mapped_candidate"]
    _report_terminal_success(
        f"INVENTORY_COMPLETE libraries={len(libraries)} edges={len(edges)} "
        f"unresolved={len(unresolved)} native_start_allowed=false")
    return 0


def _report_committed_relocated(error) -> int:
    """Preserve the nonretryable exit classification even if stderr is broken."""
    try:
        print("INVENTORY_COMMITTED_RELOCATED_NONRETRYABLE", str(error),
              file=sys.stderr)
    except (OSError, ValueError):
        pass
    return 2


def _neutralize_failed_stdout(stream):
    """Prevent shutdown from retrying a failed buffered terminal report.

    A successful terminal authority commit must remain process success even if
    the diagnostic stdout reader disappears. Redirect the original descriptor
    first so any bytes still buffered by the wrapper can be discarded safely,
    then replace ``sys.stdout`` so interpreter finalization cannot retry the
    broken stream.
    """
    descriptor = None
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        pass
    if type(descriptor) is int and descriptor >= 0:
        devnull = None
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            if devnull != descriptor:
                os.dup2(devnull, descriptor)
            try:
                stream.flush()
            except (OSError, ValueError):
                pass
        except OSError:
            pass
        finally:
            # If the failed wrapper named a descriptor that was already
            # closed, os.open may reclaim that exact number. It is then the
            # replacement descriptor and must remain open through shutdown.
            if devnull is not None and devnull != descriptor:
                try:
                    os.close(devnull)
                except OSError:
                    pass
    if sys.stdout is stream:
        # Clear the failing wrapper before allocating its replacement. Even
        # descriptor/resource exhaustion must not leave it installed for
        # CPython's final flush.
        sys.stdout = None
        try:
            sys.stdout = open(os.devnull, "w", encoding="utf-8", newline="\n")
        except (OSError, ValueError):
            pass


def _report_terminal_success(message):
    """Flush one terminal diagnostic without weakening a committed authority."""
    stream = sys.stdout
    try:
        print(message, file=stream)
        stream.flush()
    except (OSError, ValueError):
        _neutralize_failed_stdout(stream)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryCommittedRelocatedError as exc:
        raise SystemExit(_report_committed_relocated(exc))
    except (InventoryError, OSError, subprocess.SubprocessError, UnicodeError, ImportError) as exc:
        print("INVENTORY_FAILED", str(exc), file=sys.stderr)
        raise SystemExit(1)
