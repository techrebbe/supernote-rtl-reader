"""Windows-local storage for native_page_cleanup_ledger (no resource cleanup).

This adapter is deliberately strict, not a portable os.replace/fsync fallback.
It requires local drive paths, a private ACL, retained non-delete-shared handles,
single-link ordinary files, handle-relative no-replace rename, file read-back,
and successful FlushFileBuffers on BOTH dedicated directory handles. Windows
filesystems commonly reject directory FlushFileBuffers. Such a volume is NOT
supported: creation/publication fails closed. Even a successful flush is only
the OS/filesystem durability acknowledgement, not proof against lying hardware,
power loss outside its guarantees, or a privileged kernel/storage adversary.

Each ledger directory commit also publishes a hash-linked checkpoint in a
separate, caller-selected private authority directory BEFORE returning. Keep
StoreAuthority outside both directories; it pins their file identities across
restarts. The checkpoint directory is trusted external authority, not a second
untrusted copy of the ledger. Optionally retain the latest RecoveryCheckpoint
elsewhere too, to detect rollback of that authority itself. Valid extra ledger
suffixes are retained and anchored during ledger recovery, never truncated.

No implicit deletion occurs on error or recovery. Torn pending files, unknown
entries, missing checkpoints, and identity drift block recovery. Complete,
canonical pending files are retained. Explicit temporary disposal requires an
exact retained identity and content digest and deletes by handle, never by path.
Production use still requires review/testing of the concrete target filesystem.
Every active lease is bound to its exact thread and generation. Temporary write
handles cannot be reused in a later lease; whole-store disposal is excluded while
any lease is active. These are API concurrency boundaries, not a sandbox against
code that can overwrite this Python object's internals or call its Win32 API.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes as w
import hashlib
import ntpath
import os
import re
import secrets
import threading

from native_page_cleanup_ledger import (
    AuthorityError, CorruptLedger, RecoveryCheckpoint, MAX_RECORD_BYTES,
    MAX_RECORDS, ZERO_HASH, canonical_json, decode_record,
)


class StorageError(OSError):
    pass


class DurabilityUnavailable(StorageError):
    pass


def local_path(value: str) -> str:
    if (type(value) is not str or not value.isascii() or len(value) > 240
            or any(ord(char) < 32 for char in value) or not re.match(r"^[A-Za-z]:\\", value)):
        raise AuthorityError("storage requires an explicit short local drive path")
    if "/" in value or "\0" in value or value.startswith("\\"):
        raise AuthorityError("noncanonical local path")
    parts = value[3:].split("\\") if len(value) > 3 else []
    for part in parts:
        if (not part or part in (".", "..") or part[-1:] in (" ", ".")
                or any(char in part for char in ':*?"<>|')
                or re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)):
            raise AuthorityError("ambiguous Windows path component")
    return value[0].upper() + value[1:]


def _same_path(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_json(payload: bytes) -> dict:
    import json
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise CorruptLedger("duplicate authority key")
            result[key] = value
        return result
    try:
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_RECORD_BYTES:
            raise CorruptLedger("authority record size/type")
        result = json.loads(payload.decode("ascii"), object_pairs_hook=pairs)
        if type(result) is not dict or canonical_json(result) != payload:
            raise CorruptLedger("noncanonical authority JSON")
        return result
    except (ValueError, TypeError, UnicodeError, AuthorityError) as error:
        raise CorruptLedger(str(error)) from error


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    index: int

    def wire(self):
        return {"volume": self.volume, "index": f"{self.index:016x}"}


@dataclass(frozen=True)
class FileInfo:
    identity: FileIdentity
    path: str
    directory: bool
    reparse: bool
    links: int


@dataclass(frozen=True)
class StoreAuthority:
    run_path: str
    checkpoint_path: str
    run_identity: FileIdentity
    checkpoint_identity: FileIdentity
    store_id: str

    def __post_init__(self):
        local_path(self.run_path)
        local_path(self.checkpoint_path)
        if (type(self.run_identity) is not FileIdentity or type(self.checkpoint_identity) is not FileIdentity
                or type(self.store_id) is not str or re.fullmatch(r"[0-9a-f]{32}", self.store_id) is None):
            raise AuthorityError("incomplete externally held store authority")
        for identity in (self.run_identity, self.checkpoint_identity):
            if (type(identity.volume) is not int or not 0 <= identity.volume <= 2**32 - 1
                    or type(identity.index) is not int or not 0 < identity.index <= 2**64 - 1):
                raise AuthorityError("invalid directory identity")

    def wire(self):
        return dict(version=1, run_path=self.run_path, checkpoint_path=self.checkpoint_path,
                    run_identity=self.run_identity.wire(), checkpoint_identity=self.checkpoint_identity.wire(),
                    store_id=self.store_id)


class Win32:
    """Small injectable Win32 boundary. No shell, PATH lookup, or helper process."""
    def __init__(self):
        if os.name != "nt":
            raise StorageError("Windows storage adapter cannot run on this platform")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a = ctypes.WinDLL("advapi32", use_last_error=True)
        self.n = ctypes.WinDLL("ntdll", use_last_error=True)
        def bind(dll, name, result, args):
            function = getattr(dll, name)
            function.restype, function.argtypes = result, args
            return function
        P = ctypes.c_void_p
        self._create = bind(self.k, "CreateFileW", w.HANDLE, [w.LPCWSTR, w.DWORD, w.DWORD, P, w.DWORD, w.DWORD, w.HANDLE])
        self._mkdir = bind(self.k, "CreateDirectoryW", w.BOOL, [w.LPCWSTR, P])
        self._close = bind(self.k, "CloseHandle", w.BOOL, [w.HANDLE])
        self._flush = bind(self.k, "FlushFileBuffers", w.BOOL, [w.HANDLE])
        self._read = bind(self.k, "ReadFile", w.BOOL, [w.HANDLE, P, w.DWORD, P, P])
        self._write = bind(self.k, "WriteFile", w.BOOL, [w.HANDLE, P, w.DWORD, P, P])
        self._seek = bind(self.k, "SetFilePointerEx", w.BOOL, [w.HANDLE, ctypes.c_longlong, P, w.DWORD])
        self._info = bind(self.k, "GetFileInformationByHandle", w.BOOL, [w.HANDLE, P])
        self._path = bind(self.k, "GetFinalPathNameByHandleW", w.DWORD, [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD])
        self._set = bind(self.k, "SetFileInformationByHandle", w.BOOL, [w.HANDLE, ctypes.c_int, P, w.DWORD])
        self._nt_set = bind(self.n, "NtSetInformationFile", w.LONG, [w.HANDLE, P, P, w.ULONG, ctypes.c_int])
        self._nt_error = bind(self.n, "RtlNtStatusToDosError", w.ULONG, [w.LONG])
        self._drive = bind(self.k, "GetDriveTypeW", w.UINT, [w.LPCWSTR])
        self._free = bind(self.k, "LocalFree", P, [P])
        self._process = bind(self.k, "GetCurrentProcess", w.HANDLE, [])
        self._token = bind(self.a, "OpenProcessToken", w.BOOL, [w.HANDLE, w.DWORD, P])
        self._token_info = bind(self.a, "GetTokenInformation", w.BOOL, [w.HANDLE, ctypes.c_int, P, w.DWORD, P])
        self._sid_text = bind(self.a, "ConvertSidToStringSidW", w.BOOL, [P, P])
        self._sddl = bind(self.a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL, [w.LPCWSTR, w.DWORD, P, P])
        self._security = bind(self.a, "GetSecurityInfo", w.DWORD, [w.HANDLE, ctypes.c_int, w.DWORD, P, P, P, P, P])
        self._security_text = bind(self.a, "ConvertSecurityDescriptorToStringSecurityDescriptorW", w.BOOL, [P, w.DWORD, w.DWORD, P, P])
        token = w.HANDLE()
        self._check(self._token(self._process(), 8, ctypes.byref(token)))
        try:
            size = w.DWORD()
            self._token_info(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            self._check(self._token_info(token, 1, buffer, size, ctypes.byref(size)))
            self.sid = self._sid_string(ctypes.c_void_p.from_buffer(buffer).value)
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
            _fields_ = [("length", w.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]
        descriptor = ctypes.c_void_p()
        self._check(self._sddl(self.dacl, 1, ctypes.byref(descriptor), None))
        try:
            value = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
            yield ctypes.byref(value)
        finally:
            self._free(descriptor)

    def private(self, handle):
        owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        status = self._security(handle, 1, 5, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
        if status:
            raise ctypes.WinError(status)
        output = w.LPWSTR()
        try:
            self._check(self._security_text(descriptor, 1, 4, ctypes.byref(output), None))
            return self._sid_string(owner) == self.sid and output.value == self.dacl
        finally:
            if output:
                self._free(output)
            self._free(descriptor)

    def local_volume(self, path):
        # Removable, network, optical and unknown drive types are excluded.
        return self._drive(path[:3]) == 3

    def mkdir(self, path):
        with self._attributes() as attributes:
            self._check(self._mkdir(path, attributes))

    def open_directory(self, path, *, writable=False, attributes_only=False):
        access = 0xC0000000 if writable else (0x80 if attributes_only else 0x20080)
        return self._open(path, access, 3, 3, 0x02200000)

    def open_file(self, path, *, create=False, writable=False, exclusive=False, deletable=False):
        access = 0x80000000 | (0x40000000 if writable else 0) | (0x10000 if deletable else 0)
        return self._open(path, access, 0 if exclusive else 1, 1 if create else 3, 0x00200080)

    def _open(self, path, access, share, disposition, flags):
        with self._attributes() as attributes:
            handle = self._create(path, access, share, attributes, disposition, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            error = ctypes.WinError(ctypes.get_last_error())
            error.add_note(f"CreateFileW path={path!r}, access=0x{access:08x}")
            raise error
        return handle

    def info(self, handle):
        class INFO(ctypes.Structure):
            _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                        ("written", w.FILETIME), ("volume", w.DWORD), ("size_hi", w.DWORD),
                        ("size_lo", w.DWORD), ("links", w.DWORD), ("index_hi", w.DWORD), ("index_lo", w.DWORD)]
        value = INFO()
        self._check(self._info(handle, ctypes.byref(value)))
        path = ctypes.create_unicode_buffer(32768)
        length = self._path(handle, path, len(path), 0)
        if not 0 < length < len(path) or not path.value.startswith("\\\\?\\"):
            raise AuthorityError("handle has no exact DOS final path")
        return FileInfo(FileIdentity(value.volume, (value.index_hi << 32) | value.index_lo),
                        path.value[4:], bool(value.attributes & 16), bool(value.attributes & 1024), value.links)

    def names(self, path):
        return os.listdir(path)

    def read(self, handle):
        self._check(self._seek(handle, 0, None, 0))
        result = bytearray()
        while len(result) <= MAX_RECORD_BYTES:
            buffer, count = ctypes.create_string_buffer(4096), w.DWORD()
            self._check(self._read(handle, buffer, len(buffer), ctypes.byref(count), None))
            if not count.value:
                return bytes(result)
            result.extend(buffer.raw[:count.value])
        raise CorruptLedger("file exceeds record budget")

    def write(self, handle, payload):
        self._check(self._seek(handle, 0, None, 2))
        buffer, count = ctypes.create_string_buffer(payload), w.DWORD()
        self._check(self._write(handle, buffer, len(payload), ctypes.byref(count), None))
        return count.value

    def flush(self, handle, *, directory=False):
        if not self._flush(handle):
            error = ctypes.WinError(ctypes.get_last_error())
            if directory:
                raise DurabilityUnavailable(f"Windows directory FlushFileBuffers unavailable: {error}") from error
            raise error

    def rename(self, handle, directory, name):
        class RENAME(ctypes.Structure):
            _fields_ = [("replace", w.BOOL), ("root", w.HANDLE), ("length", w.DWORD),
                        ("name", w.WCHAR * (len(name) + 1))]
        value = RENAME(False, directory, len(name.encode("utf-16-le")), name)
        class IO_STATUS_BLOCK(ctypes.Structure):
            _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]
        status_block = IO_STATUS_BLOCK()
        # Win32 FILE_RENAME_INFO reserves RootDirectory. The native information
        # class supports the retained root handle; do not degrade to path rename.
        status = self._nt_set(handle, ctypes.byref(status_block), ctypes.byref(value),
                              RENAME.name.offset + value.length, 10)
        if status != 0:
            raise ctypes.WinError(self._nt_error(status))

    def delete(self, handle):
        value = w.BOOL(True)
        self._check(self._set(handle, 4, ctypes.byref(value), ctypes.sizeof(value)))

    def close(self, handle):
        self._check(self._close(handle))


@dataclass
class _Held:
    handle: object
    path: str
    identity: FileIdentity
    directory: bool
    private: bool = True
    payload: bytearray = field(default_factory=bytearray)
    synced: bool = False
    sealed: bool = False
    write_lease: object | None = None


@dataclass(frozen=True)
class _LeaseIdentity:
    owner_thread: int
    generation: int


class _ExclusiveLease:
    """A one-use context whose exit cannot release another thread/generation."""
    def __init__(self, store):
        self._store = store
        self._used = False
        self._identity = None

    def __enter__(self):
        if self._used:
            raise AuthorityError("exclusive lease context is stale/already used")
        self._used = True
        self._identity = self._store._enter_lease()
        return None

    def __exit__(self, kind, value, traceback):
        self._store._leave_lease(self._identity)


class WindowsCleanupStore:
    RECORD = re.compile(r"[0-9]{20}\.json\Z")
    PENDING = re.compile(r"\.pending-[0-9a-f]{32}\Z")
    CHECKPOINT = re.compile(r"[0-9]{20}\.checkpoint\.json\Z")
    CHECKPOINT_PENDING = re.compile(r"\.checkpoint-pending-[0-9a-f]{32}\Z")

    def __init__(self, api=None):
        self.api = api if api is not None else Win32()
        self._all = []
        self._run_files, self._authority_files = {}, {}
        self._mutex = threading.Lock()
        self._lease_local = threading.local()
        self._lease_generation = 0
        self._active_lease = None
        self._closed = False
        self._poisoned = False
        self.authority = None

    @classmethod
    def create_new(cls, run_path, checkpoint_path, *, api=None):
        result = cls(api)
        try:
            result._prepare_paths(run_path, checkpoint_path, create=True)
            result.authority = StoreAuthority(result.run.path, result.external.path,
                result.run.identity, result.external.identity, secrets.token_hex(16))
            result._lock_file(create=True)
            result._publish_external("authority.json", canonical_json(result.authority.wire()))
            result.api.flush(result.run.handle, directory=True)
            # New directory names themselves must be acknowledged by parents.
            for parent in result._parents:
                result.api.flush(parent.handle, directory=True)
            return result
        except BaseException as error:
            result._close_after_error(error)
            raise

    @classmethod
    def open_existing(cls, authority, *, minimum_checkpoint=None, api=None):
        if type(authority) is not StoreAuthority:
            raise AuthorityError("reopening requires external directory identities")
        result = cls(api)
        try:
            result._prepare_paths(authority.run_path, authority.checkpoint_path, create=False)
            if (result.run.identity != authority.run_identity or result.external.identity != authority.checkpoint_identity):
                raise AuthorityError("store directory identity drift")
            result.authority = authority
            result._lock_file(create=False)
            result._scan()
            result._load_checkpoints(require=True, minimum=minimum_checkpoint)
            # A prior process may have died after either rename but before its
            # namespace acknowledgement. Promote surviving valid namespaces
            # before exposing their checkpoint as durable external authority.
            result.api.flush(result.run.handle, directory=True)
            result.api.flush(result.external.handle, directory=True)
            return result
        except BaseException as error:
            result._close_after_error(error)
            raise

    def _prepare_paths(self, run_path, checkpoint_path, *, create):
        run_path, checkpoint_path = local_path(run_path), local_path(checkpoint_path)
        paths = [run_path.casefold(), checkpoint_path.casefold()]
        if (len(run_path) <= 3 or len(checkpoint_path) <= 3 or paths[0] == paths[1]
                or paths[0].startswith(paths[1] + "\\") or paths[1].startswith(paths[0] + "\\")):
            raise AuthorityError("ledger and external authority require disjoint dedicated directories")
        # Merge every role before opening anything: one directory can first be
        # encountered as a traversal ancestor and later as a directory we must
        # flush. Retained access must not depend on argument/traversal order.
        roles = {}
        parent_keys = []
        for path in (run_path, checkpoint_path):
            if not self.api.local_volume(path):
                raise AuthorityError("storage is not a fixed local volume")
            parent_path = ntpath.dirname(path)
            components = [path[:3]]
            for component in parent_path[3:].split("\\"):
                if component:
                    components.append(ntpath.join(components[-1], component))
            for component in components:
                key = component.casefold()
                role = roles.setdefault(key, {"path": component, "flush_parent": False})
                role["flush_parent"] |= create and _same_path(component, parent_path)
            parent_keys.append(parent_path.casefold())
        ancestors, identities = {}, {}
        for key, role in roles.items():
            held = self._retain(self.api.open_directory(role["path"],
                writable=role["flush_parent"], attributes_only=True), role["path"], True, private=False)
            if held.identity in identities and identities[held.identity] != key:
                raise AuthorityError("distinct ancestor paths alias one directory identity")
            identities[held.identity] = key
            ancestors[key] = held
        self._parents = [ancestors[key] for key in dict.fromkeys(parent_keys)]
        self._ancestors = list(ancestors.values())
        if create:
            self.api.mkdir(run_path)
            self.api.mkdir(checkpoint_path)
        self.run = self._retain(self.api.open_directory(run_path, writable=True), run_path, True)
        self.external = self._retain(self.api.open_directory(checkpoint_path, writable=True), checkpoint_path, True)
        if (self.run.identity == self.external.identity or self.run.identity in identities
                or self.external.identity in identities):
            raise AuthorityError("dedicated storage paths alias each other/an ancestor")

    def _retain(self, handle, path, directory, *, private=True):
        try:
            info = self.api.info(handle)
            held = _Held(handle, path, info.identity, directory, private)
            self._check(held)
            self._all.append(held)
            return held
        except BaseException:
            self.api.close(handle)
            raise

    def _check(self, held):
        info = self.api.info(held.handle)
        if (info.identity != held.identity or info.directory != held.directory or info.reparse
                or not _same_path(info.path, held.path) or (not held.directory and info.links != 1)
                or (held.private and not self.api.private(held.handle))):
            raise AuthorityError("retained file/directory authority differs")

    def _validate_directories(self):
        if self._closed or self._poisoned:
            raise AuthorityError("closed/uncertain store must be reopened")
        for held in self._ancestors + [self.run, self.external, self._writer]:
            self._check(held)

    def _lock_file(self, *, create):
        path = ntpath.join(self.external.path, "writer.lock")
        self._writer = self._retain(self.api.open_file(path, create=create, writable=True, exclusive=True), path, False)
        if self.api.read(self._writer.handle) != b"":
            raise CorruptLedger("writer lease file is not empty")
        if create:
            self.api.flush(self._writer.handle)

    def exclusive(self):
        return _ExclusiveLease(self)

    def _enter_lease(self):
        if not self._mutex.acquire(blocking=False):
            raise AuthorityError("concurrent/reentrant cleanup writer")
        self._lease_generation += 1
        identity = _LeaseIdentity(threading.get_ident(), self._lease_generation)
        self._active_lease = identity
        self._lease_local.identity = identity
        try:
            self._validate_directories()
            self._scan()
            return identity
        except BaseException:
            self._leave_lease(identity)
            raise

    def _leave_lease(self, identity):
        if identity is None or identity is not self._active_lease:
            raise AuthorityError("stale exclusive lease generation")
        self._require_lease(validate=False)
        self._active_lease = None
        self._lease_local.identity = None
        self._mutex.release()

    def _require_lease(self, *, validate=True):
        identity = self._active_lease
        if (identity is None or identity.owner_thread != threading.get_ident()
                or getattr(self._lease_local, "identity", None) is not identity):
            raise AuthorityError("storage operation requires this thread's active exact lease")
        if validate:
            self._validate_directories()

    def _inventory(self, directory, mapping, allowed):
        names = self.api.names(directory.path)
        if (type(names) is not list or any(type(name) is not str for name in names)
                or len(names) != len(set(name.casefold() for name in names)) or len(names) > MAX_RECORDS * 3):
            raise CorruptLedger("ambiguous directory inventory")
        for name in names:
            if not allowed(name):
                raise CorruptLedger("unexpected storage directory entry")
            if name == "writer.lock":
                continue
            if name not in mapping:
                path = ntpath.join(directory.path, name)
                mapping[name] = self._retain(self.api.open_file(path,
                    deletable=bool(self.PENDING.fullmatch(name) or self.CHECKPOINT_PENDING.fullmatch(name))), path, False)
                mapping[name].sealed = True
            self._check(mapping[name])
        if set(mapping) - set(names):
            raise CorruptLedger("retained directory entry disappeared")
        return sorted(names)

    def _scan(self):
        run = self._inventory(self.run, self._run_files, lambda name: self.RECORD.fullmatch(name) or self.PENDING.fullmatch(name))
        external = self._inventory(self.external, self._authority_files, lambda name:
            name in ("writer.lock", "authority.json") or self.CHECKPOINT.fullmatch(name) or self.CHECKPOINT_PENDING.fullmatch(name))
        published = [name for name in run if self.RECORD.fullmatch(name)]
        if published != [f"{sequence:020d}.json" for sequence in range(len(published))] or len(published) > MAX_RECORDS:
            raise CorruptLedger("ledger file sequence differs")
        records, previous = [], ZERO_HASH
        for name in published:
            record = decode_record(self._read_held(self._run_files[name]))
            if record["sequence"] != len(records) or record["previous_hash"] != previous:
                raise CorruptLedger("ledger content sequence/hash differs")
            records.append(record)
            previous = record["hash"]
        pending_by_sequence = {}
        for name in run:
            if self.PENDING.fullmatch(name):
                record = decode_record(self._read_held(self._run_files[name]))
                sequence = record["sequence"]
                if (sequence > len(records) or (sequence < len(records) and record != records[sequence])
                        or (sequence == len(records) and record["previous_hash"] != previous)
                        or (sequence in pending_by_sequence and pending_by_sequence[sequence] != record)):
                    raise CorruptLedger("ambiguous pending ledger record")
                pending_by_sequence[sequence] = record
        if "authority.json" not in external or self._read_held(self._authority_files["authority.json"]) != canonical_json(self.authority.wire()):
            raise CorruptLedger("external authority record differs/missing")
        self._records = records
        self._load_checkpoints(require=False)
        return run

    def _read_held(self, held):
        self._check(held)
        result = self.api.read(held.handle)
        self._check(held)
        if type(result) is not bytes or len(result) > MAX_RECORD_BYTES:
            raise CorruptLedger("invalid exact file read-back")
        return result

    def names(self):
        self._require_lease()
        return self._scan()

    def read(self, name):
        self._require_lease()
        if type(name) is not str or name not in self._run_files:
            raise AuthorityError("read lacks retained exact file authority")
        return self._read_held(self._run_files[name])

    def create(self, name):
        self._require_lease()
        if type(name) is not str or not self.PENDING.fullmatch(name) or name in self._run_files:
            raise AuthorityError("temporary name is not new/exact")
        path = ntpath.join(self.run.path, name)
        held = self._retain(self.api.open_file(path, create=True, writable=True, deletable=True), path, False)
        held.write_lease = self._active_lease
        self._run_files[name] = held
        return held

    def _writable(self, held):
        self._require_lease()
        if (type(held) is not _Held or not any(item is held for item in self._run_files.values())
                or held.sealed or held.write_lease is not self._active_lease):
            raise AuthorityError("write handle is stale/sealed/not owned")
        self._check(held)

    def write(self, handle, payload):
        self._writable(handle)
        if type(payload) is not bytes or not payload or len(handle.payload) + len(payload) > MAX_RECORD_BYTES:
            raise AuthorityError("invalid write payload")
        count = self.api.write(handle.handle, payload)
        if type(count) is not int or not 0 < count <= len(payload):
            raise StorageError("write returned no/invalid progress")
        handle.payload.extend(payload[:count])
        handle.synced = False
        return count

    def fsync_file(self, handle):
        self._writable(handle)
        self.api.flush(handle.handle)
        if self._read_held(handle) != bytes(handle.payload):
            raise CorruptLedger("flushed temporary read-back differs")
        decode_record(bytes(handle.payload))
        handle.synced = True

    def close(self, handle=None):
        if handle is not None:
            # Ledger close is a logical sealing boundary. The native handle is
            # retained through rename and until store disposal to deny swapping.
            self._writable(handle)
            if not handle.synced:
                raise AuthorityError("cannot seal an unflushed temporary")
            handle.sealed = True
            return
        # Whole-store disposal is allowed outside a lease only. A foreign thread
        # (or reentrant callback) must never close the owner's retained handles.
        if not self._mutex.acquire(blocking=False):
            raise AuthorityError("cannot dispose a store with an active lease")
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
                raise StorageError("retained handle disposal failed", errors)
        finally:
            self._mutex.release()

    def rename_no_replace(self, source, destination):
        self._require_lease()
        if (type(source) is not str or not self.PENDING.fullmatch(source)
                or type(destination) is not str or not self.RECORD.fullmatch(destination)
                or source not in self._run_files or destination in self._run_files):
            raise AuthorityError("rename lacks exact unpublished source/destination")
        held = self._run_files[source]
        if held.write_lease is not self._active_lease or not held.sealed or not held.synced:
            raise AuthorityError("rename requires flushed sealed content")
        self._check(held)
        payload = self._read_held(held)
        if payload != bytes(held.payload):
            raise CorruptLedger("temporary changed after file flush")
        record = decode_record(payload)
        if (destination != f"{len(self._records):020d}.json" or record["sequence"] != len(self._records)
                or record["previous_hash"] != (self._records[-1]["hash"] if self._records else ZERO_HASH)):
            raise CorruptLedger("rename record is not the exact next sequence")
        self.api.rename(held.handle, self.run.handle, destination)
        held.path = ntpath.join(self.run.path, destination)
        self._run_files[destination] = self._run_files.pop(source)
        self._check(held)
        if self._read_held(held) != payload:
            raise CorruptLedger("renamed record read-back differs")

    def _checkpoint_wire(self, record, previous):
        value = dict(version=1, store_id=self.authority.store_id, ledger_id=self._records[0]["data"]["ledger_id"],
            sequence=record["sequence"], record_sha256=record["hash"], previous_checkpoint_sha256=previous)
        value["hash"] = _sha(canonical_json(value))
        return value

    def _load_checkpoints(self, *, require, minimum=None):
        names = sorted(name for name in self._authority_files if self.CHECKPOINT.fullmatch(name))
        if names != [f"{sequence:020d}.checkpoint.json" for sequence in range(len(names))] or len(names) > len(self._records):
            raise CorruptLedger("checkpoint sequence is missing/ahead of ledger")
        previous = ZERO_HASH
        for sequence, name in enumerate(names):
            expected = self._checkpoint_wire(self._records[sequence], previous)
            if self._read_held(self._authority_files[name]) != canonical_json(expected):
                raise CorruptLedger("external checkpoint differs from ledger prefix")
            previous = expected["hash"]
        for name, held in self._authority_files.items():
            if self.CHECKPOINT_PENDING.fullmatch(name):
                pending = _strict_json(self._read_held(held))
                sequence = pending.get("sequence")
                if type(sequence) is not int or not 0 <= sequence < len(self._records) or sequence > len(names):
                    raise CorruptLedger("ambiguous pending checkpoint")
                predecessor = ZERO_HASH if sequence == 0 else _strict_json(
                    self._read_held(self._authority_files[f"{sequence - 1:020d}.checkpoint.json"]))["hash"]
                if pending != self._checkpoint_wire(self._records[sequence], predecessor):
                    raise CorruptLedger("pending checkpoint content differs")
        if require and not names:
            raise CorruptLedger("trusted external checkpoint is missing")
        self._checkpoint_count, self._checkpoint_head = len(names), previous
        if minimum is not None:
            if (type(minimum) is not RecoveryCheckpoint or minimum.sequence >= len(names)
                    or minimum.ledger_id != self._records[0]["data"]["ledger_id"]
                    or minimum.record_sha256 != self._records[minimum.sequence]["hash"]):
                raise CorruptLedger("externally retained checkpoint prefix is missing/changed")

    def _publish_external(self, name, payload):
        temporary = ".checkpoint-pending-" + secrets.token_hex(16)
        path = ntpath.join(self.external.path, temporary)
        held = self._retain(self.api.open_file(path, create=True, writable=True, deletable=True), path, False)
        self._authority_files[temporary] = held
        offset = 0
        while offset < len(payload):
            count = self.api.write(held.handle, payload[offset:])
            if type(count) is not int or not 0 < count <= len(payload) - offset:
                raise StorageError("checkpoint write made no/invalid progress")
            offset += count
        self.api.flush(held.handle)
        if self._read_held(held) != payload:
            raise CorruptLedger("checkpoint read-back differs")
        self.api.rename(held.handle, self.external.handle, name)
        held.path = ntpath.join(self.external.path, name)
        self._authority_files[name] = self._authority_files.pop(temporary)
        self._check(held)
        if self._read_held(held) != payload:
            raise CorruptLedger("published checkpoint read-back differs")
        self.api.flush(self.external.handle, directory=True)

    def fsync_directory(self):
        self._require_lease()
        try:
            self.api.flush(self.run.handle, directory=True)
            self._scan()
            for record in self._records[self._checkpoint_count:]:
                value = self._checkpoint_wire(record, self._checkpoint_head)
                self._publish_external(f"{record['sequence']:020d}.checkpoint.json", canonical_json(value))
                self._checkpoint_head = value["hash"]
                self._checkpoint_count += 1
            self.api.flush(self.external.handle, directory=True)
        except BaseException:
            self._poisoned = True
            raise

    def load_checkpoint(self):
        with self.exclusive():
            self._load_checkpoints(require=True)
            record = self._records[self._checkpoint_count - 1]
            return RecoveryCheckpoint(self._records[0]["data"]["ledger_id"], record["sequence"], record["hash"])

    def discard_temporary(self, name, expected_sha256):
        """Explicit narrow cleanup only; never remove a torn/unknown/published file."""
        with self.exclusive():
            if (type(name) is not str or not self.PENDING.fullmatch(name) or name not in self._run_files
                    or type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
                raise AuthorityError("temporary cleanup lacks exact file/content authority")
            held = self._run_files[name]
            payload = self._read_held(held)
            decode_record(payload)
            if _sha(payload) != expected_sha256:
                raise AuthorityError("temporary cleanup digest differs")
            try:
                self.api.delete(held.handle)
                self.api.close(held.handle)
                self._all.remove(held)
                del self._run_files[name]
                self.api.flush(self.run.handle, directory=True)
            except BaseException:
                self._poisoned = True
                raise

    def _close_after_error(self, primary):
        try:
            self.close()
        except Exception as error:
            primary.add_note(f"retained-handle cleanup also failed: {error}")

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if value is not None:
            self._close_after_error(value)
        else:
            self.close()
