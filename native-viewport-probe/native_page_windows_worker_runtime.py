"""S2b retained Windows worker Runtime; no hardware admission or default backend.

Only authority_worker/frida_worker are allowed. A retained kill-on-close job with
ActiveProcessLimit=1 forbids all descendants. Python/Windows native startup is
platform trusted (not protection against an administrator/kernel adversary).
All declared runtime files are retained and hash-pinned; project code uses a
closed loader, never sys.path. Native pipe cancellation must be observed before
its buffer/handle is released. Local tests cannot certify 25/250ms hardware
budgets. The S6/S7 child capability backends remain separately reviewed blockers.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
import ctypes
from ctypes import wintypes as w
import hashlib
import hmac
import ntpath
import os
import re
import secrets
import threading
import time
from types import MappingProxyType
import native_page_isolated_ipc as ipc
from native_page_cleanup_store import Win32 as FileWin32, local_path

class RuntimeError(ipc.IpcError): pass

FACTORIES = MappingProxyType({"authority_worker": "authority_worker-v1", "frida_worker": "frida_worker-v1"})
MAX_BOOTSTRAP = 2 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
DOMAIN = "native-page-s2b-private-reply-v1"
SPAWN_FLAGS = 0x4 | 0x80000 | 0x400 | 0x8  # suspended, extended, Unicode, detached
MODULE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")
def require(ok, message):
    if not ok: raise RuntimeError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def detached(value): return ipc.decode_json(ipc.canonical_json(value))
def decode_reply_frames(raw):
    """Decode one retained transport accumulation without mutable decoder aliases."""
    require(type(raw) is bytes, "reply transport bytes")
    frames, offset = [], 0
    while len(raw) - offset >= 4:
        size = int.from_bytes(raw[offset:offset + 4], "big")
        require(1 <= size <= ipc.MAX_FRAME, "reply frame length")
        if len(raw) - offset < size + 4: break
        frames.append(ipc.decode_json(raw[offset + 4:offset + 4 + size]))
        require(len(frames) <= ipc.MAX_MESSAGES, "reply frame count")
        offset += size + 4
    remainder = raw[offset:]
    require(len(remainder) <= ipc.MAX_FRAME + 4, "reply frame accumulation")
    return tuple(frames), remainder
def binding_wire(binding):
    require(type(binding) is ipc.ReplyBinding and type(binding.worker) is ipc.ProcessIdentity, "exact reply binding")
    worker = binding.worker
    require(type(worker.pid) is int and worker.pid > 0 and type(worker.creation_ticks) is int and worker.creation_ticks > 0
            and worker.role in FACTORIES and type(worker.image_sha256) is str and ipc.HEX.fullmatch(worker.image_sha256)
            and type(worker.bootstrap_sha256) is str and ipc.HEX.fullmatch(worker.bootstrap_sha256), "exact worker binding")
    require(type(binding.sequence) is int and 0 <= binding.sequence < 2**31 and type(binding.session) is str
            and ipc.HEX.fullmatch(binding.session), "reply sequence/session")
    require(binding.operation_id is None or (type(binding.operation_id) is str and ipc.NAME.fullmatch(binding.operation_id)), "reply operation")
    require(binding.registration_sequence is None or (type(binding.registration_sequence) is int
            and 0 < binding.registration_sequence < 2**31), "registration sequence")
    return dict(worker=worker.wire(), session=binding.session, sequence=binding.sequence,
                operation_id=binding.operation_id, registration_sequence=binding.registration_sequence)

# Fixed code; manifest is data held no-write/no-delete before CreateProcessW.
# The Python pre--c encodings/native initialization is in the pinned-platform
# bootstrap trust boundary. No circular claim to authenticate this source file.
BOOTSTRAP = r'''import sys
from _frozen_importlib import BuiltinImporter, FrozenImporter, ModuleSpec
from _frozen_importlib_external import ExtensionFileLoader
raw=open(sys.argv[1],'rb').read(2097153)
if len(raw)>2097152: raise RuntimeError('bootstrap size')
head,config=raw.split(b'\n--CONFIG--\n',1)
lines=head.decode('ascii').splitlines()
if lines.pop(0)!='S2B1': raise RuntimeError('bootstrap version')
table={}
for line in lines:
 n,path,digest,kind=line.split('\t')
 if n in table or kind not in ('source','package','extension'): raise RuntimeError('module topology')
 table[n]=(path,digest,kind)
class Closed:
 def find_spec(self,name,path=None,target=None):
  if name not in table:
   if BuiltinImporter.find_spec(name) or FrozenImporter.find_spec(name): return None
   raise ModuleNotFoundError('unreviewed module: '+name)
  p,d,k=table[name]
  if k=='extension': return ModuleSpec(name,ExtensionFileLoader(name,p),origin=p)
  return ModuleSpec(name,self,origin=p,is_package=k=='package')
 def create_module(self,spec): return None
 def exec_module(self,module):
  p,d,k=table[module.__name__]
  source=open(p,'rb').read(134217729)
  if len(source)>134217728: raise RuntimeError('source size')
  if 'hashlib' in sys.modules and hasattr(sys.modules['hashlib'],'sha256'):
   if sys.modules['hashlib'].sha256(source).hexdigest()!=d: raise RuntimeError('source digest')
  module.__file__=p
  if k=='package': module.__path__=[]
  exec(compile(source,p,'exec',dont_inherit=True),module.__dict__)
sys.path=[]
sys.path_hooks=[]
sys.path_importer_cache.clear()
sys.meta_path=[BuiltinImporter,FrozenImporter,Closed()]
import hashlib
if hashlib.sha256(raw).hexdigest()!=sys.argv[2]: raise RuntimeError('bootstrap digest')
for path,digest,kind in table.values():
 if hashlib.sha256(open(path,'rb').read(134217729)).hexdigest()!=digest: raise RuntimeError('module digest')
import json
import native_page_worker_entry
native_page_worker_entry.main(json.loads(config))
'''

@dataclass(frozen=True)
class SourcePin:
    path: str
    sha256: str
    module: str | None = None
    kind: str = "data"
    def __post_init__(self):
        local_path(self.path)
        require(type(self.sha256) is str and ipc.HEX.fullmatch(self.sha256), "source digest")
        require(type(self.kind) is str and self.kind in ("data", "source", "package", "extension"), "source kind")
        require((self.module is None and self.kind == "data") or (type(self.module) is str
                and MODULE.fullmatch(self.module) and self.kind != "data"), "source module")
    def wire(self): return dict(path=self.path, sha256=self.sha256, module=self.module, kind=self.kind)

@dataclass(frozen=True)
class Capability:
    """Reviewed native capability: verifier must attest identity AND access."""
    name: str
    handle: object
    identity: bytes
    verify: object

class Lifecycle(Enum):
    NEW = "NEW"
    LAUNCHING = "LAUNCHING"
    SUSPENDED = "SUSPENDED"
    RESUMED = "RESUMED"
    READY = "READY"
    SEALED = "SEALED"
    POISONED = "POISONED"
    CLOSED = "CLOSED"

@dataclass(frozen=True)
class _RuntimeAuthority:
    api: object
    run_path: str
    clock: object
    start_guard: object
    owner: int
    deadline_ns: int

@dataclass(frozen=True, eq=False)
class PipeHandle:
    """An adapter-owned endpoint generation, never a bare native handle."""
    value: int
    owner: object

@dataclass(frozen=True, eq=False)
class _PipeCloseReceipt:
    endpoint: PipeHandle
    native: int
    authority: object
    generation: object

class _HandleKind(Enum):
    GENERIC = "generic"
    PIPE = "pipe"
    PROCESS = "process"
    REMOTE = "remote"

@dataclass(frozen=True)
class _HandleObligation:
    handle: object
    kind: _HandleKind

@dataclass(frozen=True, eq=False)
class _Acquisition:
    handle: object
    kind: _HandleKind
    identity: object = None

class _AcquisitionBook:
    """Unpublished native handles survive constructor and cleanup failures.

    Tokens are generations, not numeric handles. A failed acquisition seals
    further acquisition until exact recovery. Published owners remain able to
    terminate/join; they cannot claim quiescence while this book is nonempty.
    """
    def _init_acquisitions(self):
        self.__acquisitions = {}
        self.__acquisition_failed = False
        self.__acquisition_deadline = None
        self.__acquisition_clock = None
        self.__acquisition_owner = None
        self.__acquisition_lock = threading.RLock()
        self.__acquisition_processes = {}
        self.__acquisition_identity_lost = False
    def bind_acquisition_deadline(self, owner, deadline, clock):
        with self.__acquisition_lock:
            require(self.__acquisition_owner is None, "adapter already bound to a runtime")
            self.assert_acquisitions_clear()
            self.__acquisition_owner, self.__acquisition_deadline, self.__acquisition_clock = owner, deadline, clock
    @property
    def acquisition_obligations(self):
        with self.__acquisition_lock: return tuple(self.__acquisitions)
    def assert_acquisitions_clear(self):
        with self.__acquisition_lock:
            require(not self.__acquisitions and not self.__acquisition_failed and not self.__acquisition_identity_lost,
                    "unpublished native acquisition obligations remain")
    def _track_acquisition(self, handle, kind=_HandleKind.GENERIC, identity=None):
        with self.__acquisition_lock:
            require(not any(t.handle == handle and t.kind is kind for t in self.__acquisitions),
                    "duplicate live acquisition generation")
            token = _Acquisition(handle, kind, identity)
            self.__acquisitions[token] = (handle, kind, identity)
            return token
    def _acquisition_exact(self, token):
        expected = self.__acquisitions.get(token)
        require(type(token) is _Acquisition and expected is not None
                and token.handle is expected[0] and token.kind is expected[1] and token.identity is expected[2],
                "stale/substituted acquisition generation")
    def _publish_acquisition(self, token):
        with self.__acquisition_lock:
            self._acquisition_exact(token); del self.__acquisitions[token]
            self.__acquisition_processes.pop(token,None)
    def _close_acquisition(self, token, deadline=None, clock=None):
        with self.__acquisition_lock:
            self._acquisition_exact(token)
            self._raw_close_acquisition(token, deadline, clock)
            del self.__acquisitions[token]
            self.__acquisition_processes.pop(token,None)
    def _acquired_identity(self, exact):
        if not exact:
            self.__acquisition_identity_lost = True
            raise RuntimeError("acquired native identity drift seals recovery")
    def _bind_acquired_process(self, token, native):
        self._acquisition_exact(token)
        pid,path=token.identity
        self._acquired_identity(type(native) is tuple and len(native)==3 and type(native[0]) is int
            and type(native[1]) is int and native[1]>0 and type(native[2]) is str
            and native[0]==pid and native[2].casefold()==path.casefold()
            and (token not in self.__acquisition_processes or self.__acquisition_processes[token]==native))
        self.__acquisition_processes[token]=native
    def _acquisition_close_guard(self, handle):
        require(not any(t.handle == handle for t in self.__acquisitions),
                "unpublished acquisition requires exact recovery")
    @contextmanager
    def _acquiring(self):
        # Hold through publication: two callers cannot consume each other's
        # provisional records, even when a nested helper acquires duplicates.
        with self.__acquisition_lock:
            require(not self.__acquisition_failed and not self.__acquisition_identity_lost,
                    "adapter acquisition uncertainty is sticky")
            before = set(self.__acquisitions)
            try: yield
            except BaseException as primary:
                failed = False
                for token in reversed(tuple(t for t in self.__acquisitions if t not in before)):
                    try: self._close_acquisition(token, self.__acquisition_deadline, self.__acquisition_clock)
                    except BaseException: failed = True
                if failed:
                    self.__acquisition_failed = True
                    raise ipc.WorkerQuiescenceError("constructor cleanup retains exact acquisition obligations") from primary
                if not self.__acquisitions and not self.__acquisition_identity_lost: self.__acquisition_failed = False
                raise
    def retain_failed_handles(self, handles):
        with self.__acquisition_lock:
            for handle in handles: self._track_acquisition(handle)
            self.__acquisition_failed = True
    def recover_acquisitions(self, deadline, clock, *, owner=None):
        with self.__acquisition_lock:
            require(self.__acquisition_failed and self.__acquisitions, "no acquisition recovery/replayed recovery")
            require(not self.__acquisition_identity_lost, "acquisition identity uncertainty is permanently sealed")
            if self.__acquisition_owner is not None:
                require(owner is self.__acquisition_owner and deadline == self.__acquisition_deadline,
                        "acquisition recovery owner/deadline substitution")
                clock = self.__acquisition_clock
            require(callable(clock) and type(deadline) is int and clock() < deadline, "acquisition recovery deadline")
            failed = False
            for token in reversed(tuple(self.__acquisitions)):
                try:
                    require(clock() < deadline, "acquisition recovery deadline exhausted")
                    self._close_acquisition(token, deadline, clock)
                except BaseException: failed = True
            require(not failed and not self.__acquisitions, "acquisition recovery remains uncertain")
            self.__acquisition_failed = False

@dataclass(frozen=True)
class WorkerBinding:
    """S2b-only binding; deliberately not S1b's mutation WorkerBinding.

    Obtain from runtime.binding() while the exact native process/job/source
    handles remain retained. Serialized identity alone is never live authority.
    """
    pid: int
    creation_ticks: int
    image_path: str
    role: str
    factory_id: str
    session: str
    image_sha256: str
    source_sha256: str
    parent_pid: int
    parent_creation_ticks: int
    def __post_init__(self):
        require(all(type(v) is int and 0 < v < 2**63 for v in
                    (self.pid, self.creation_ticks, self.parent_pid, self.parent_creation_ticks)), "worker binding integer identity")
        local_path(self.image_path)
        require(type(self.role) is str and self.role in FACTORIES and type(self.factory_id) is str
                and self.factory_id == FACTORIES[self.role], "worker binding role/factory")
        require(all(type(v) is str and ipc.HEX.fullmatch(v) for v in
                    (self.session, self.image_sha256, self.source_sha256)), "worker binding digests")
    def canonical_bytes(self):
        self.__post_init__()
        return ipc.canonical_json(dict(version=1, pid=self.pid, creation_ticks=self.creation_ticks,
            image_path=self.image_path, role=self.role, factory_id=self.factory_id, session=self.session,
            image_sha256=self.image_sha256, source_sha256=self.source_sha256,
            parent_pid=self.parent_pid, parent_creation_ticks=self.parent_creation_ticks))

class _ImagePhase(Enum):
    LIVE = "LIVE"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"

class _ImageHandleKind(Enum):
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"

@dataclass(frozen=True, eq=False)
class _ImageHandleObligation:
    handle: object
    kind: _ImageHandleKind
    subject: object
    expected: object
    generation: object

@dataclass(frozen=True, eq=False)
class _ImageHandleCloseReceipt:
    handle: object
    kind: _ImageHandleKind
    generation: object
    authority: object

@dataclass(frozen=True)
class _ImageState:
    generation: int = 0
    phase: _ImagePhase = _ImagePhase.LIVE

class WorkerImage:
    def __init__(self, role, executable, sources, *, runtime_roots, backend_sha256,
                 configuration, capabilities=(), api=None):
        require(type(role) is str and role in FACTORIES and type(executable) is SourcePin
                and executable.module is None, "closed worker role/executable")
        require(type(sources) is tuple and 0 < len(sources) <= 4096 and all(type(p) is SourcePin for p in sources), "closed source pins")
        require(type(runtime_roots) is tuple and runtime_roots and type(backend_sha256) is str
                and ipc.HEX.fullmatch(backend_sha256), "reviewed runtime/backend authority")
        require(type(capabilities) is tuple and len(capabilities) <= 16, "capability limit")
        self.__api = api if api is not None else Win32()
        self.__retained_api = self.__api
        self.role, self.executable, self.sources = role, executable, sources
        self.runtime_roots = tuple(local_path(p) for p in runtime_roots)
        require(ntpath.dirname(executable.path).casefold() in {p.casefold() for p in self.runtime_roots},
                "the executable directory must be a complete retained runtime root")
        self.backend_sha256, self.configuration = backend_sha256, detached(configuration)
        self.capabilities = capabilities
        # Immutable obligation generations and per-handle typed receipts are the
        # cleanup authority. Public/legacy collection aliases are never trusted.
        self.__obligations = self.__obligation_values = ()
        self.__receipts = self.__receipt_values = ()
        self.__close_authority = object()
        self.__state = _ImageState()
        self.__state_values = (0, _ImagePhase.LIVE)
        self.__runtime_owner = None
        self.__mutex = self.__retained_mutex = threading.Lock()
        paths = [p.path.casefold() for p in (executable, *sources)]
        require(len(paths) == len(set(paths)), "duplicate source path")
        modules = [p.module for p in sources if p.module is not None]
        require(len(modules) == len(set(modules)) and {"native_page_worker_entry", "native_page_isolated_ipc"} <= set(modules), "closed entry/IPC modules")
        names, cap_handles, cap_ids = set(), set(), set()
        for cap in capabilities:
            require(type(cap) is Capability and type(cap.name) is str and ipc.NAME.fullmatch(cap.name)
                    and cap.name not in names and type(cap.identity) is bytes and cap.identity and callable(cap.verify)
                    and cap.handle not in cap_handles and cap.identity not in cap_ids, "capability authority/alias")
            names.add(cap.name); cap_handles.add(cap.handle); cap_ids.add(cap.identity)
        try:
            for pin in (executable, *sources):
                self._ancestors(pin.path)
                handle = self.api.open_file(pin.path)
                index = self._append_image_handle(handle, _ImageHandleKind.FILE, pin)
                self._complete_image_handle(index, self.api.info(handle))
            self._raw = self._wire()
            self._bootstrap_sha = sha(self._raw)
            self.verify()
        except BaseException:
            try: self.close()
            except BaseException:
                self.api.retain_failed_handles([obligation.handle for obligation, receipt
                    in zip(self.__obligations, self.__receipts) if receipt is None])
                raise
            raise
    @property
    def api(self): return self.__api
    @property
    def closed(self):
        with self._image_lease():
            self._image_state_exact(); self._image_obligations_exact()
            return self.__state.phase is _ImagePhase.CLOSED
    @contextmanager
    def _image_lease(self):
        lock = self.__mutex
        require(lock is self.__retained_mutex and type(lock) is type(threading.Lock()),
                "retained image lock changed")
        require(lock.acquire(blocking=False), "image reentry/concurrent use")
        try:
            require(self.__mutex is lock and self.__retained_mutex is lock,
                    "retained image lock changed")
            yield
        finally: lock.release()
    def _check_api(self):
        require(self.__api is self.__retained_api, "retained image API substitution")
    def _wire(self):
        # Large runtime inventories are hashed as canonical individual records;
        # the outer authority stays within S2's 64KiB canonical-byte contract.
        return ipc.canonical_json(dict(version=1, role=self.role, factory=FACTORIES[self.role],
            executable=self.executable.wire(), source_count=len(self.sources),
            sources_sha256=sha(b"\n".join(ipc.canonical_json(p.wire()) for p in self.sources)),
            runtime_roots=list(self.runtime_roots), backend_sha256=self.backend_sha256, configuration=self.configuration,
            capabilities=[dict(name=c.name, identity=c.identity.hex()) for c in self.capabilities],
            loader_sha256=sha(BOOTSTRAP.encode("utf-8"))))
    @staticmethod
    def _obligation_wire(obligation):
        return (obligation.handle, obligation.kind, obligation.subject,
                obligation.expected, obligation.generation)
    def _image_state_exact(self):
        state = self.__state
        require(type(state) is _ImageState
                and (state.generation, state.phase) == self.__state_values
                and type(state.generation) is int and state.generation >= 0
                and type(state.phase) is _ImagePhase,
                "retained image lifecycle changed")
        return state
    def _image_obligations_exact(self):
        require(type(self.__obligations) is tuple and type(self.__obligation_values) is tuple
                and len(self.__obligations) == len(self.__obligation_values)
                and type(self.__receipts) is tuple and type(self.__receipt_values) is tuple
                and len(self.__receipts) == len(self.__receipt_values) == len(self.__obligations),
                "retained image obligation topology changed")
        for obligation, values, receipt, expected_receipt in zip(
                self.__obligations, self.__obligation_values,
                self.__receipts, self.__receipt_values):
            require(type(obligation) is _ImageHandleObligation
                    and self._obligation_wire(obligation) == values
                    and type(obligation.kind) is _ImageHandleKind
                    and receipt is expected_receipt,
                    "retained image handle obligation changed")
            if receipt is not None:
                require(type(receipt) is _ImageHandleCloseReceipt
                        and receipt.handle == obligation.handle
                        and type(receipt.handle) is type(obligation.handle)
                        and receipt.kind is obligation.kind
                        and receipt.generation is obligation.generation
                        and receipt.authority is self.__close_authority,
                        "retained image handle close receipt changed")
    def _append_image_handle(self, handle, kind, subject):
        require(type(kind) is _ImageHandleKind, "retained image handle kind")
        obligation = _ImageHandleObligation(handle, kind, subject, None, object())
        self.__obligations = (*self.__obligations, obligation)
        self.__obligation_values = (*self.__obligation_values, self._obligation_wire(obligation))
        self.__receipts = (*self.__receipts, None)
        self.__receipt_values = (*self.__receipt_values, None)
        return len(self.__obligations) - 1
    def _complete_image_handle(self, index, expected):
        require(type(index) is int and 0 <= index < len(self.__obligations),
                "retained image handle index")
        obligation = self.__obligations[index]
        require(obligation.expected is None and self.__receipts[index] is None,
                "retained image handle already completed")
        completed = _ImageHandleObligation(obligation.handle, obligation.kind,
            obligation.subject, expected, obligation.generation)
        obligations = list(self.__obligations); obligations[index] = completed
        values = list(self.__obligation_values); values[index] = self._obligation_wire(completed)
        self.__obligations, self.__obligation_values = tuple(obligations), tuple(values)
    def _image_transition(self, phase):
        state = self._image_state_exact()
        require(type(phase) is _ImagePhase, "retained image lifecycle transition")
        updated = _ImageState(state.generation + 1, phase)
        self.__state, self.__state_values = updated, (updated.generation, updated.phase)
    def _publish_image_close(self, index):
        self._image_state_exact(); self._image_obligations_exact()
        obligation = self.__obligations[index]
        require(self.__receipts[index] is None, "duplicate image handle close")
        receipt = _ImageHandleCloseReceipt(obligation.handle, obligation.kind,
            obligation.generation, self.__close_authority)
        receipts = list(self.__receipts); receipts[index] = receipt
        values = list(self.__receipt_values); values[index] = receipt
        self.__receipts, self.__receipt_values = tuple(receipts), tuple(values)
    def _ancestors(self, path):
        parent, chain = ntpath.dirname(path), []
        retained = {obligation.subject.casefold() for obligation in self.__obligations
                    if obligation.kind is _ImageHandleKind.DIRECTORY}
        while parent and parent.casefold() not in retained:
            chain.append(parent)
            if parent == ntpath.dirname(parent): break
            parent = ntpath.dirname(parent)
        for path in reversed(chain):
            handle = self.api.open_directory(path, attributes_only=True)
            index = self._append_image_handle(handle, _ImageHandleKind.DIRECTORY, path)
            self._complete_image_handle(index, self.api.info(handle))
    def verify(self):
        with self._image_lease():
            self._check_api()
            state = self._image_state_exact(); self._image_obligations_exact()
            require(state.phase is _ImagePhase.LIVE and not any(self.__receipts)
                    and all(obligation.expected is not None for obligation in self.__obligations)
                    and self._wire() == self._raw,
                    "source authority changed/closed")
            files = tuple(obligation for obligation in self.__obligations
                          if obligation.kind is _ImageHandleKind.FILE)
            require(files and self.executable == files[0].subject
                    and self.sources == tuple(obligation.subject for obligation in files[1:]),
                    "source handle authority changed")
            identities = set()
            for obligation in self.__obligations:
                info = self.api.info(obligation.handle)
                require(info == obligation.expected, "retained image handle identity drift")
                if obligation.kind is _ImageHandleKind.DIRECTORY:
                    path = obligation.subject
                    require(info.directory and not info.reparse and info.path.casefold() == path.casefold(),
                            "directory identity/reparse drift")
                else:
                    pin = obligation.subject
                    require(not info.directory and not info.reparse and info.links == 1
                            and info.path.casefold() == pin.path.casefold() and info.identity not in identities,
                            "source identity/link drift")
                    identities.add(info.identity)
                    require(sha(self.api.read_all(obligation.handle, MAX_FILE)) == pin.sha256,
                            "source bytes changed")
            for root in self.runtime_roots:
                require(root.casefold() in {obligation.subject.casefold() for obligation in self.__obligations
                        if obligation.kind is _ImageHandleKind.DIRECTORY}, "runtime root not retained")
                expected = {obligation.subject.path.casefold() for obligation in files
                    if obligation.subject.path.casefold().startswith(root.casefold().rstrip("\\") + "\\")}
                require(self.api.inventory(root) == expected, "runtime closure missing/extra/reparse files")
            for cap in self.capabilities: require(cap.verify(cap.handle) == cap.identity, "capability identity/access drift")
    def canonical_bytes(self):
        self.verify(); return self._raw
    def _acquire(self, owner):
        with self._image_lease():
            self._image_state_exact(); self._image_obligations_exact()
            require(self.__runtime_owner is None and self.__state.phase is _ImagePhase.LIVE,
                    "image already retained by a worker")
            self.__runtime_owner = owner
    def _release(self, owner):
        with self._image_lease():
            require(self.__runtime_owner is owner, "image lease owner drift")
            self.__runtime_owner = None
    def close(self):
        with self._image_lease():
            self._check_api()
            state = self._image_state_exact(); self._image_obligations_exact()
            if state.phase is _ImagePhase.CLOSED:
                require(all(type(receipt) is _ImageHandleCloseReceipt for receipt in self.__receipts),
                        "closed image retains native handles")
                return
            require(self.__runtime_owner is None, "source locks cannot close before worker quiescence")
            if state.phase is _ImagePhase.LIVE: self._image_transition(_ImagePhase.CLOSING)
            else: require(state.phase is _ImagePhase.CLOSING, "invalid image close state")
            for index in reversed(range(len(self.__obligations))):
                if self.__receipts[index] is None:
                    self.api.close(self.__obligations[index].handle)
                    self._publish_image_close(index)
            self._image_obligations_exact()
            require(all(type(receipt) is _ImageHandleCloseReceipt for receipt in self.__receipts),
                    "image close obligations remain")
            self._image_transition(_ImagePhase.CLOSED)

@dataclass(frozen=True)
class _ProcessDeadline:
    initial_ns: int
    absolute_ns: int
    generation: int

@dataclass
class _ProcessState:
    suspended: bool = True
    resumed: bool = False
    closed: bool = False
    joined: bool = False
    deadline: _ProcessDeadline | None = None

@dataclass(frozen=True)
class _Process:
    handle: object
    thread: object
    job: object
    native: tuple
    image: WorkerImage
    session: str
    parent: tuple
    parent_handle: object
    _state: _ProcessState = field(default_factory=_ProcessState, compare=False, repr=False)
    @property
    def suspended(self): return self._state.suspended
    @property
    def resumed(self): return self._state.resumed
    @property
    def closed(self): return self._state.closed
    @property
    def joined(self): return self._state.joined
    @property
    def deadline_ns(self): return self._state.deadline.absolute_ns

class _ChannelPhase(Enum):
    LIVE = "LIVE"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"

@dataclass(frozen=True)
class _ChannelState:
    generation: int = 0
    phase: _ChannelPhase = _ChannelPhase.LIVE
    next_sequence: int = 0
    close_receipt: _PipeCloseReceipt | None = None

@dataclass(frozen=True, slots=True)
class _Channel:
    handle: object
    process: _Process
    key: bytes

class _ReplyPhase(Enum):
    OPEN = "OPEN"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"

@dataclass(frozen=True)
class _ReplyState:
    generation: int = 0
    partial: bytes = b""
    pending: bytes = b""
    ordinal: int = 0
    terminal: bool = False
    eof: bool = False
    published: bool = False
    ready_raw: bytes = b""
    phase: _ReplyPhase = _ReplyPhase.OPEN
    close_receipt: _PipeCloseReceipt | None = None
    eof_receipt: object = None
    publish_ready: bool = False

@dataclass(frozen=True, eq=False)
class _AuthenticatedReplyEof:
    stream: object
    binding_raw: bytes
    nonce: str
    ordinal: int
    ready_sha256: str

@dataclass(frozen=True, slots=True)
class _Reply:
    handle: object
    channel: _Channel
    binding_raw: bytes
    nonce: str
    remote_writer: int
    @property
    def binding(self):
        value = ipc.decode_json(self.binding_raw)
        return ipc.ReplyBinding(ipc.ProcessIdentity(**value["worker"]), value["session"], value["sequence"],
                                value["operation_id"], value["registration_sequence"])

@dataclass(frozen=True)
class _ClosedProcessHandle:
    process: _Process
    name: str
    handle: object
    authority: tuple

class WindowsWorkerRuntime:
    """One owner-thread worker; cleanup alone permits cross-thread calls.

    start_guard is a retained out-of-band non-replayable launch permit verifier.
    S8 supplies an absolute launch deadline at construction. S2's initial
    open_reply_stream may tighten, never extend it. Neither
    evidence nor worker IPC grants launch authority. The caller owns WorkerImage
    until exact runtime quiescence; source locks are not released prematurely.
    """
    def __init__(self, private_run_path, *, launch_deadline_ns, start_guard, api=None, clock_ns=time.monotonic_ns):
        require(callable(start_guard) and callable(clock_ns), "trusted start guard/clock")
        self.__authority = _RuntimeAuthority(api if api is not None else Win32(),
            local_path(private_run_path), clock_ns, start_guard, threading.get_ident(), launch_deadline_ns)
        self.__retained_authority = self.__authority
        self.__authority_values = (self.__authority.api, self.__authority.run_path, clock_ns, start_guard,
                                  self.__authority.owner, launch_deadline_ns)
        self._mutex = threading.Lock()
        self.__lifecycle = Lifecycle.NEW
        self.process = self.channel = self.reply = None
        self._files, self._dirs, self.__launch_obligations = [], [], []
        self.__failed_process = self.__failed_identity = self.__failed_job = None
        self.__process_state = self.__deadline_authority = None
        self.__deadline_values = None
        self.__channel_authority = self.__channel_state = self.__channel_state_values = None
        self.__reply_authority = self.__reply_state = self.__reply_state_values = None
        self.__close_receipts, self.__closing_authority = {}, None
        self.__reply_setup_obligations = []
        self._used = self._sealed = False
        self._last_clock = -1
        self.__launch_uncertain = False
        self.__ready_authenticated = None
        self.__recovery_identity_lost = False
        self._deadline(launch_deadline_ns)
        self.api.bind_acquisition_deadline(self, launch_deadline_ns, self._clock_ns)
    @property
    def launch_deadline_ns(self): return self.__authority.deadline_ns
    @property
    def api(self): return self.__authority.api
    @property
    def run_path(self): return self.__authority.run_path
    @property
    def clock(self): return self.__authority.clock
    @property
    def start_guard(self): return self.__authority.start_guard
    @property
    def owner(self): return self.__authority.owner
    @property
    def lifecycle(self): return self.__lifecycle
    @property
    def _launch_uncertain(self): return self.__launch_uncertain
    @property
    def _launch_obligations(self): return tuple(self.__launch_obligations)
    @property
    def _failed_process(self): return self.__failed_process
    @property
    def _failed_identity(self): return self.__failed_identity
    @property
    def _failed_job(self): return self.__failed_job
    def _authority(self):
        a, original = self.__authority, self.__authority_values
        require(a is self.__retained_authority and type(a) is _RuntimeAuthority
                and a.api is original[0] and type(a.run_path) is str and a.run_path == original[1]
                and a.clock is original[2] and a.start_guard is original[3]
                and type(a.owner) is int and a.owner == original[4]
                and type(a.deadline_ns) is int and a.deadline_ns == original[5]
                and type(self.__lifecycle) is Lifecycle, "retained constructor authority changed")
    @contextmanager
    def _lease(self, cleanup=False, *, recovery=False, diagnostic=False):
        self._authority()
        require(cleanup or threading.get_ident() == self.owner, "foreign runtime owner thread")
        require(self._mutex.acquire(blocking=False), "runtime reentry/concurrent use")
        try:
            self._authority()
            require(not (self._launch_uncertain or self.lifecycle is Lifecycle.POISONED)
                    or recovery or diagnostic, "poisoned launch permits exact recovery only")
            yield
        finally: self._mutex.release()
    def now_ns(self):
        self._authority()
        if self._launch_uncertain:
            raise ipc.WorkerQuiescenceError("unpublished failed launch requires exact recovery; S2 cannot claim quiescence")
        return self._clock_ns()
    def _clock_ns(self):
        self._authority()
        value = self.clock()
        require(type(value) is int and 0 <= value < 2**63 and value >= self._last_clock, "trusted monotonic clock")
        self._last_clock = value; return value
    def _deadline(self, deadline):
        now = self.now_ns()
        require(type(deadline) is int and now < deadline <= now + ipc.MAX_SECONDS_NS, "absolute worker deadline exhausted/invalid")
    def sleep_ns(self, ns):
        with self._lease():
            require(type(ns) is int and 0 < ns <= ipc.POLL_NS, "bounded poll delay"); self.api.sleep_ns(ns)
    def _exact(self, process):
        self._authority()
        require(process is self.process and type(process) is _Process and not process.closed, "stale/foreign process")
        values = (process, process.handle, process.thread, process.job, process.native, process.image,
                  process.session, process.parent, process.parent_handle)
        expected = self._process_authority
        require(all(type(a) is type(b) and (a is b if i in (0, 5) else a == b)
                    for i, (a, b) in enumerate(zip(values, expected))), "retained process objects changed")
        require(process._state is self.__process_state and process._state.deadline is self.__deadline_authority
                and type(self.__deadline_authority) is _ProcessDeadline
                and all(type(v) is int for v in (self.__deadline_authority.initial_ns,
                    self.__deadline_authority.absolute_ns,self.__deadline_authority.generation))
                and (self.__deadline_authority.initial_ns,self.__deadline_authority.absolute_ns,
                    self.__deadline_authority.generation)==self.__deadline_values
                and type(process.deadline_ns) is int and process.deadline_ns <= self.launch_deadline_ns,
                "retained process deadline/state changed")
        if not self._closed_handle("handle"):
            require(self.api.process_identity(process.handle) == process.native, "process PID/creation/image drift")
        if not self._closed_handle("parent_handle"):
            require(self.api.process_identity(process.parent_handle) == process.parent, "parent PID/creation/image drift")
        return ipc.ProcessIdentity(process.native[0], process.native[1], process.image.executable.sha256, process.image._bootstrap_sha, process.image.role)
    def _closed_handle(self, name):
        receipt = self.__close_receipts.get(name)
        if receipt is None: return False
        require(type(receipt) is _ClosedProcessHandle and receipt.process is self.process
                and receipt.name == name and receipt.handle == getattr(self.process, name)
                and receipt.authority is self._process_authority and self.__closing_authority is self._process_authority
                and self.process.joined and self._sealed
                and self.__channel_state is not None
                and self.__channel_state.phase is _ChannelPhase.CLOSED,
                "closed handle receipt authority changed")
        return True
    def _tighten_process_deadline(self, process, deadline):
        self._exact(process)
        require(type(deadline) is int and self.lifecycle is Lifecycle.SUSPENDED
                and deadline <= process.deadline_ns, "process deadline cannot restore/rebase")
        self._deadline(deadline)
        previous = self.__deadline_authority
        tightened = _ProcessDeadline(previous.initial_ns, deadline, previous.generation + 1)
        self.__process_state.deadline = tightened
        self.__deadline_authority = tightened
        self.__deadline_values = (tightened.initial_ns,tightened.absolute_ns,tightened.generation)
    def _containment(self, process, dead=False):
        self._exact(process)
        if self._closed_handle("job"):
            require(dead and process.joined, "closed job cannot prove live containment")
            return
        require(self.api.in_job(process.handle, process.job), "worker escaped retained job")
        limits, pids = self.api.job_state(process.job)
        require(limits == (0x2008, 1), "job kill-on-close/active-process policy drift")
        require(pids == (() if dead else (process.native[0],)), "unknown descendant/job quiescence")
    def _source(self, process):
        self._authority()
        process.image.verify()
        require(process.native[2].casefold() == process.image.executable.path.casefold(), "spawn image substituted")
        self._authority()
    def _live_authority(self, process):
        self.api.assert_acquisitions_clear()
        require(not self.__reply_setup_obligations, "unpublished reply setup obligations")
        self._channel_exact(self.channel)
        self._exact(process)
        require(not self.__close_receipts, "partially closed process is not live authority")
        require(self.api.alive(process.handle) and self.api.alive(process.parent_handle), "live worker/parent required")
        self._source(process); self._containment(process); self._exact(process)
        require(self.api.alive(process.handle) and self.api.alive(process.parent_handle), "worker/parent exited during authority check")
        self._authority()
    def _seal(self):
        self._sealed = True
        if self.lifecycle not in (Lifecycle.POISONED, Lifecycle.CLOSED):
            self.__lifecycle = Lifecycle.SEALED
    def launch_suspended(self, image, session):
        with self._lease():
            self._deadline(self.launch_deadline_ns)
            require(self.lifecycle is Lifecycle.NEW and not self._used
                    and type(image) is WorkerImage and image.api is self.api and type(session) is str
                    and ipc.HEX.fullmatch(session), "one exact retained launch")
            self._used = True; self.__lifecycle = Lifecycle.LAUNCHING
            image.verify(); image._acquire(self)
            self._launch_image = image
            handle = thread = job = parent_handle = control = None
            children = []
            try:
                # Pin every cwd ancestor against rename/junction replacement.
                parent, chain = ntpath.dirname(self.run_path), []
                while parent:
                    chain.append(parent)
                    if parent == ntpath.dirname(parent): break
                    parent = ntpath.dirname(parent)
                for path in reversed(chain):
                    self._deadline(self.launch_deadline_ns)
                    held = self.api.open_directory(path, attributes_only=True)
                    self._dirs.append((held, None))
                    self._dirs[-1] = (held, self.api.info(held))
                    require(self._dirs[-1][1].directory and not self._dirs[-1][1].reparse, "cwd ancestor reparse")
                self._deadline(self.launch_deadline_ns); self.api.mkdir(self.run_path)
                self._deadline(self.launch_deadline_ns)
                directory = self.api.open_directory(self.run_path)
                self._dirs.append((directory, None))
                self._dirs[-1] = (directory, self.api.info(directory))
                require(self.api.private_directory(directory), "private cwd ACL")
                self._deadline(self.launch_deadline_ns); parent_handle = self.api.retain_current_process()
                parent = self.api.process_identity(parent_handle)
                self._deadline(self.launch_deadline_ns)
                parent_child = self.api.inheritable_copy(parent_handle); children.append(parent_child)
                self._deadline(self.launch_deadline_ns)
                control, child_control = self.api.pipe_pair(parent_reads=False); children.append(child_control)
                key, caps = secrets.token_bytes(32), []
                for cap in image.capabilities:
                    self._deadline(self.launch_deadline_ns)
                    require(cap.verify(cap.handle) == cap.identity, "bootstrap capability drift")
                    child = self.api.inheritable_copy(cap.handle); children.append(child)
                    caps.append(dict(name=cap.name, handle=child, identity=cap.identity.hex()))
                descriptor = dict(version=1, factory=FACTORIES[image.role], role=image.role, session=session,
                    image_sha256=image.executable.sha256, bootstrap_sha256=image._bootstrap_sha, backend_sha256=image.backend_sha256,
                    configuration=image.configuration, capabilities=caps, control_handle=child_control, parent_handle=parent_child,
                    parent=dict(pid=parent[0], creation_ticks=parent[1], image_path=parent[2]), key=key.hex())
                rows = ["S2B1", *["\t".join((p.module, p.path, p.sha256, p.kind)) for p in image.sources if p.module]]
                raw = "\n".join(rows).encode("ascii") + b"\n--CONFIG--\n" + ipc.canonical_json(descriptor)
                require(len(raw) <= MAX_BOOTSTRAP, "bootstrap size")
                path = ntpath.join(self.run_path, "bootstrap.manifest")
                self._deadline(self.launch_deadline_ns); locked = self.api.create_sealed_file(path, raw)
                self._files.append((locked, sha(raw), None))
                self._files[-1] = (locked, sha(raw), self.api.info(locked))
                self._deadline(self.launch_deadline_ns); job = self.api.create_job()
                environment = {"SystemRoot": self.api.system_root(), "WINDIR": self.api.system_root()}
                argv = (image.executable.path, "-I", "-S", "-E", "-B", "-s", "-P", "-X", "utf8", "-c", BOOTSTRAP, path, sha(raw))
                self._deadline(self.launch_deadline_ns)
                handle, thread = self.api.create_suspended(image.executable.path, argv, environment, self.run_path, tuple(children))
                native = self.api.process_identity(handle)
                self.process = _Process(handle, thread, job, native, image, session, parent, parent_handle)
                self.__process_state = self.process._state
                self.__deadline_authority = _ProcessDeadline(self.launch_deadline_ns, self.launch_deadline_ns, 0)
                self.__deadline_values = (self.launch_deadline_ns,self.launch_deadline_ns,0)
                self.__process_state.deadline = self.__deadline_authority
                self._process_authority = (self.process, handle, thread, job, native, image, session, parent, parent_handle)
                self.channel = _Channel(control, self.process, key)
                self.__channel_authority = (self.channel, control, self.process, key)
                self.__channel_state = _ChannelState()
                self.__channel_state_values = (0, _ChannelPhase.LIVE, 0, None)
                self._deadline(self.launch_deadline_ns); self._exact(self.process); self._source(self.process)
                self._deadline(self.launch_deadline_ns); self.api.assign_job(job, handle); self._containment(self.process)
                while children: self.api.close(children[-1]); children.pop()
                self._deadline(self.launch_deadline_ns)
                self.__lifecycle = Lifecycle.SUSPENDED
                return ipc.WorkerLaunch(self.process, self.channel)
            except BaseException as primary:
                self._seal()
                # Preserve all uncertain handles for explicit abort retry. No
                # closing a live unassigned process and forgetting its identity.
                self.__launch_obligations = [_HandleObligation(h, _HandleKind.PIPE if h is control else _HandleKind.GENERIC)
                    for h in [*children, control, thread, job, parent_handle] if h is not None]
                self.__failed_process = handle
                self.__failed_identity = self._process_authority[4] if self.process is not None else None
                self.__failed_job = job
                try: self._abort_launch(self.launch_deadline_ns)
                except BaseException as cleanup:
                    self.__launch_uncertain = True
                    self.__lifecycle = Lifecycle.POISONED
                    raise ipc.WorkerQuiescenceError("failed launch retains native cleanup obligations") from cleanup
                raise primary
    def _abort_launch(self, deadline):
        self._authority()
        require(type(deadline) is int and deadline == self.launch_deadline_ns
                and self._clock_ns() < deadline, "failed-launch recovery deadline exhausted/rebased")
        self._recover_adapter()
        process = self._failed_process
        if process is not None:
            if self._failed_identity is None: self.__failed_identity = self.api.process_identity(process)
            if self.api.process_identity(process) != self._failed_identity:
                self.__recovery_identity_lost = True
                raise RuntimeError("failed-spawn identity uncertain; recovery authority sealed")
            if self.api.alive(process): self.api.terminate_process(process)
            require(self.api.wait_process(process, deadline, self._clock_ns), "failed-spawn join")
            require(not self.api.alive(process), "failed-spawn remained live after join")
            if self._failed_job is not None:
                while True:
                    limits, pids = self.api.job_state(self._failed_job)
                    require(limits == (0x2008, 1) and pids in ((), (self._failed_identity[0],)),
                            "failed-spawn job authority uncertain")
                    if not pids: break
                    require(self._clock_ns() < deadline, "failed-spawn job accounting deadline")
                    self.api.sleep_ns(min(ipc.POLL_NS, deadline - self._clock_ns()))
            if self.api.process_identity(process) != self._failed_identity:
                self.__recovery_identity_lost = True
                raise RuntimeError("failed-spawn final identity uncertain; recovery authority sealed")
            self.api.close(process); self.__failed_process = None
        while self._launch_obligations:
            require(self._clock_ns() < deadline, "failed-launch obligation deadline")
            obligation = self._launch_obligations[-1]
            require(type(obligation) is _HandleObligation, "failed-launch obligation type")
            if obligation.kind is _HandleKind.PIPE: self.api.close_pipe(obligation.handle)
            else: self.api.close(obligation.handle)
            self.__launch_obligations.pop()
        self._close_bootstrap(deadline); self.process = self.channel = None
        self.api.assert_acquisitions_clear()
        require(self._clock_ns() < deadline, "failed-launch final recovery deadline")
        if self._launch_image is not None:
            self._launch_image._release(self); self._launch_image = None
        self.__launch_uncertain = False
        self.__lifecycle = Lifecycle.CLOSED
    def abort_failed_launch(self, deadline_ns):
        with self._lease(cleanup=True, recovery=True):
            require(self._launch_uncertain and self._sealed and hasattr(self, "_failed_process")
                    and not self.__recovery_identity_lost, "no unresolved failed launch/replayed or sealed recovery")
            self._abort_launch(deadline_ns)
    def identity(self, process):
        with self._lease(cleanup=True): return self._exact(process)
    def binding(self, process):
        with self._lease():
            require(self.lifecycle is Lifecycle.READY and not self._sealed and not self._launch_uncertain
                    and self.__ready_authenticated is not None
                    and process is self.process and process.resumed and not process.suspended
                    and not process.joined and self.channel is not None
                    and self.__channel_state is not None
                    and self.__channel_state.phase is _ChannelPhase.LIVE,
                    "worker binding requires guarded resume and published authenticated ready")
            self._live_authority(process)
            identity = self._exact(process)
            result = WorkerBinding(identity.pid, identity.creation_ticks, process.native[2], identity.role,
                FACTORIES[identity.role], process.session, identity.image_sha256, identity.bootstrap_sha256,
                process.parent[0], process.parent[1])
            self._live_authority(process)
            require(self.lifecycle is Lifecycle.READY and not self._sealed, "worker sealed during binding publication")
            return result
    def attest_image(self, process, image):
        with self._lease(cleanup=True):
            self._exact(process); require(image is process.image, "image authority substitution"); self._source(process)
    def attest_private_channel(self, channel, peer):
        with self._lease():
            self._channel_exact(channel)
            require(peer == self._exact(channel.process), "private control binding")
    def _channel_exact(self, channel, *, closed=False):
        expected = self.__channel_authority
        require(type(channel) is _Channel and expected is not None and channel is self.channel is expected[0]
                and channel.handle is expected[1] and channel.process is expected[2]
                and type(channel.key) is bytes and channel.key == expected[3], "retained control-channel identity changed")
        state = self.__channel_state
        require(type(state) is _ChannelState
                and (state.generation, state.phase, state.next_sequence, state.close_receipt)
                    == self.__channel_state_values
                and type(state.generation) is int and state.generation >= 0
                and type(state.phase) is _ChannelPhase
                and type(state.next_sequence) is int and 0 <= state.next_sequence < 2**31,
                "retained control-channel state changed")
        self._exact(channel.process)
        if closed:
            require(state.phase is _ChannelPhase.CLOSED and type(state.close_receipt) is _PipeCloseReceipt,
                    "control channel lacks authenticated close receipt")
            self.api.attest_pipe_closed(channel.handle, state.close_receipt)
        else:
            require(state.phase is _ChannelPhase.LIVE and state.close_receipt is None,
                    "control channel is not live")
            self.api.attest_pipe(channel.handle)
    def _channel_closing_exact(self, channel):
        expected = self.__channel_authority
        require(type(channel) is _Channel and expected is not None and channel is self.channel is expected[0]
                and channel.handle is expected[1] and channel.process is expected[2]
                and type(channel.key) is bytes and channel.key == expected[3],
                "retained closing-channel identity changed")
        state = self.__channel_state
        require(type(state) is _ChannelState
                and (state.generation, state.phase, state.next_sequence, state.close_receipt)
                    == self.__channel_state_values
                and state.phase is _ChannelPhase.CLOSING and state.close_receipt is None,
                "retained closing-channel state changed")
        self._exact(channel.process)
    def _channel_transition(self, channel, *, phase=None, next_sequence=None, close_receipt=None):
        state = self.__channel_state
        expected = self.__channel_authority
        require(type(channel) is _Channel and expected is not None
                and channel is self.channel is expected[0]
                and channel.handle is expected[1] and channel.process is expected[2]
                and type(channel.key) is bytes and channel.key == expected[3]
                and type(state) is _ChannelState
                and (state.generation, state.phase, state.next_sequence, state.close_receipt)
                    == self.__channel_state_values,
                "channel transition authority")
        updated = _ChannelState(state.generation + 1, state.phase if phase is None else phase,
            state.next_sequence if next_sequence is None else next_sequence,
            state.close_receipt if close_receipt is None else close_receipt)
        self.__channel_state = updated
        self.__channel_state_values = (updated.generation, updated.phase, updated.next_sequence, updated.close_receipt)
    def attest_containment(self, process, registered_children):
        with self._lease():
            require(registered_children == (), "descendants prohibited"); self._containment(process)
    def attest_containment_quiescent(self, process, registered_children):
        with self._lease(cleanup=True):
            self._exact(process)
            require(registered_children == (), "descendants prohibited")
            require(self._closed_handle("handle") or not self.api.alive(process.handle),
                    "worker still live")
            self._containment(process, dead=True)
            self.api.assert_acquisitions_clear()
            require(self.__channel_state is not None
                    and self.__channel_state.phase is _ChannelPhase.CLOSED
                    and self.reply is None and not self.__reply_setup_obligations,
                    "channels not quiescent")
            self._channel_exact(self.channel, closed=True)
    def open_reply_stream(self, control_channel, binding, deadline_ns):
        with self._lease():
            self._deadline(deadline_ns); wire = binding_wire(binding)
            self._channel_exact(control_channel)
            channel_state = self.__channel_state
            require(not self._sealed and control_channel is self.channel
                    and channel_state is not None and channel_state.phase is _ChannelPhase.LIVE
                    and self.reply is None
                    and binding.worker == self._exact(control_channel.process) and binding.session == self.process.session
                    and binding.sequence == channel_state.next_sequence, "fresh reply binding/sequence")
            require((binding.sequence == 0 and self.lifecycle is Lifecycle.SUSPENDED)
                    or (binding.sequence > 0 and self.lifecycle is Lifecycle.READY), "reply lifecycle authority")
            if binding.sequence == 0:
                deadline_ns = min(deadline_ns, self.process.deadline_ns)
                self._tighten_process_deadline(self.process, deadline_ns)
            parent = child = None
            try:
                parent, child = self.api.pipe_pair(parent_reads=True)
                self.__reply_setup_obligations = [_HandleObligation(parent, _HandleKind.PIPE),
                    _HandleObligation(child, _HandleKind.GENERIC)]
                remote = self.api.transfer_to_child(child, self.process.handle)
                self.reply = _Reply(parent, control_channel, ipc.canonical_json(wire), secrets.token_hex(32), remote)
                self.__reply_state = _ReplyState()
                self.__reply_state_values = self._reply_state_wire(self.__reply_state)
                self.__reply_authority = (self.reply, parent, control_channel, self.reply.binding_raw,
                                          self.reply.nonce, remote, self.__reply_state)
                # The reply owns its parent endpoint before closing the local
                # writer. Repeated writer-close failure cannot lose either.
                del self.__reply_setup_obligations[0]
                self.api.close(child); self.__reply_setup_obligations.pop(); child = None
                message = dict(s2b=1, binding=wire, nonce=self.reply.nonce, writer=remote)
                message["mac"] = hmac.new(control_channel.key, ipc.canonical_json(message), hashlib.sha256).hexdigest()
                self.api.write_pipe(control_channel.handle, ipc.encode_frame(message), deadline_ns, self.now_ns)
                self._channel_transition(control_channel, next_sequence=channel_state.next_sequence + 1)
                self._deadline(deadline_ns); self._reply_transition(published=True); return self.reply
            except BaseException:
                self._seal()
                self._close_reply_setup()
                raise
    def _close_reply_setup(self):
        failed = False
        for obligation in reversed(tuple(self.__reply_setup_obligations)):
            try:
                require(self._clock_ns() < self.launch_deadline_ns, "reply setup cleanup deadline")
                if obligation.kind is _HandleKind.PIPE: self.api.close_pipe(obligation.handle)
                else: self.api.close(obligation.handle)
                self.__reply_setup_obligations.remove(obligation)
            except BaseException: failed = True
        require(not failed, "reply setup cleanup retains exact handles")
    def _recover_adapter(self):
        if self.api.acquisition_obligations:
            self.api.recover_acquisitions(self.launch_deadline_ns, self._clock_ns, owner=self)
        self.api.assert_acquisitions_clear()
    @staticmethod
    def _reply_state_wire(state):
        return (state.generation, state.partial, state.pending, state.ordinal, state.terminal,
            state.eof, state.published, state.ready_raw, state.phase, state.close_receipt,
            state.eof_receipt, state.publish_ready)
    def _reply_state_exact(self):
        state = self.__reply_state
        require(type(state) is _ReplyState and self._reply_state_wire(state) == self.__reply_state_values
                and type(state.generation) is int and state.generation >= 0
                and type(state.partial) is bytes and len(state.partial) <= ipc.MAX_FRAME + 4
                and type(state.pending) is bytes and len(state.pending) <= ipc.MAX_CHUNK * ipc.MAX_MESSAGES
                and type(state.ordinal) is int and state.ordinal >= 0
                and type(state.terminal) is bool and type(state.eof) is bool
                and type(state.published) is bool and type(state.ready_raw) is bytes
                and len(state.ready_raw) <= ipc.MAX_FRAME and type(state.phase) is _ReplyPhase
                and type(state.publish_ready) is bool
                and (not state.terminal or state.ordinal > 0)
                and (not state.eof or (state.terminal and state.partial == b""
                    and type(state.eof_receipt) is _AuthenticatedReplyEof
                    and state.eof_receipt.stream is self.reply
                    and state.eof_receipt.binding_raw == self.reply.binding_raw
                    and state.eof_receipt.nonce == self.reply.nonce
                    and state.eof_receipt.ordinal == state.ordinal
                    and state.eof_receipt.ready_sha256 == sha(state.ready_raw)))
                and (state.eof or state.eof_receipt is None)
                and (state.phase is not _ReplyPhase.OPEN or state.close_receipt is None)
                and (state.phase is not _ReplyPhase.CLOSED
                    or type(state.close_receipt) is _PipeCloseReceipt),
                "retained reply state changed")
        return state
    def _reply_transition(self, **changes):
        state = self._reply_state_exact()
        expected, stream = self.__reply_authority, self.reply
        require(expected is not None and type(stream) is _Reply and stream is expected[0]
                and stream.handle is expected[1] and stream.channel is expected[2]
                and type(stream.binding_raw) is bytes and stream.binding_raw == expected[3]
                and type(stream.nonce) is str and stream.nonce == expected[4]
                and type(stream.remote_writer) is int and stream.remote_writer == expected[5]
                and state is expected[6], "reply transition authority changed")
        updated = replace(state, generation=state.generation + 1, **changes)
        self.__reply_state = updated
        self.__reply_state_values = self._reply_state_wire(updated)
        if self.__reply_authority is not None:
            self.__reply_authority = (*self.__reply_authority[:6], updated)
        return updated
    def _reply_exact(self, stream, binding, *, closing=False):
        expected = self.__reply_authority
        state = self._reply_state_exact()
        require(stream is self.reply and type(stream) is _Reply and expected is not None and stream is expected[0]
                and stream.handle is expected[1] and stream.channel is expected[2]
                and type(stream.binding_raw) is bytes and stream.binding_raw == expected[3]
                and type(stream.nonce) is str and stream.nonce == expected[4]
                and type(stream.remote_writer) is int and stream.remote_writer == expected[5]
                and state is expected[6]
                and state.phase is (_ReplyPhase.CLOSING if closing else _ReplyPhase.OPEN)
                and ipc.canonical_json(binding_wire(binding)) == expected[3]
                and binding.worker == self._exact(stream.channel.process), "stale/substituted reply")
        self._channel_exact(stream.channel)
        if closing:
            require(state.close_receipt is None, "closing reply already has a receipt")
        else:
            require(state.close_receipt is None, "open reply has a close receipt")
            self.api.attest_pipe(stream.handle)
    def attest_reply_stream(self, stream, binding):
        with self._lease(): self._reply_exact(stream, binding)
    def read_reply(self, stream, limit, deadline_ns):
        try:
            return self._read_reply(stream, limit, deadline_ns)
        except BaseException:
            # A failed reply cannot continue to advertise live/public authority.
            # Failed-launch poison is never downgraded by a public operation.
            if (threading.get_ident() == self.owner and not self._mutex.locked()
                    and self.lifecycle is not Lifecycle.POISONED):
                self._seal()
            raise
    def _read_reply(self, stream, limit, deadline_ns):
        with self._lease():
            self._deadline(deadline_ns)
            require(type(limit) is int and 0 < limit <= ipc.MAX_CHUNK, "reply read limit")
            self._reply_exact(stream, stream.binding)
            state = self._reply_state_exact()
            if state.pending:
                raw = state.pending[:limit]
                self._reply_transition(pending=state.pending[len(raw):])
                return raw
            require(not state.eof, "read after terminal EOF")
            chunk = self.api.read_pipe(stream.handle, ipc.MAX_CHUNK, deadline_ns, self.now_ns)
            self._deadline(deadline_ns)
            if chunk is None: return None
            require(type(chunk) is bytes and len(chunk) <= ipc.MAX_CHUNK,
                    "reply transport returned invalid bytes")
            if chunk == b"":
                require(state.partial == b"" and state.terminal and state.ordinal > 0,
                        "EOF without complete authenticated terminal")
                if stream.binding.sequence == 0:
                    require(state.ready_raw, "worker ready payload missing")
                    ready = ipc.FrameDecoder()
                    messages = ready.feed(state.ready_raw); ready.seal()
                    expected = ipc.envelope(stream.binding.session, 0, "ready", None, {"role": self.process.image.role})
                    require(len(messages) == 1 and ipc.canonical_json(messages[0]) == ipc.canonical_json(expected),
                            "exact authenticated worker ready required")
                receipt = _AuthenticatedReplyEof(stream, stream.binding_raw, stream.nonce,
                    state.ordinal, sha(state.ready_raw))
                self._reply_transition(eof=True, eof_receipt=receipt)
                if stream.binding.sequence == 0: self.__ready_authenticated = receipt
                return b""
            frames, partial = decode_reply_frames(state.partial + chunk)
            pending, ordinal = state.pending, state.ordinal
            terminal, ready_raw = state.terminal, state.ready_raw
            for packet in frames:
                require(not terminal and type(packet) is dict and set(packet) ==
                        {"domain", "binding", "nonce", "ordinal", "payload", "terminal", "mac"}, "reply schema/late output")
                mac = packet.pop("mac")
                require(type(mac) is str and hmac.compare_digest(mac, hmac.new(stream.channel.key, ipc.canonical_json(packet), hashlib.sha256).hexdigest()), "reply authentication")
                require(packet["domain"] == DOMAIN and ipc.canonical_json(packet["binding"]) == ipc.canonical_json(binding_wire(stream.binding))
                        and packet["nonce"] == stream.nonce and type(packet["ordinal"]) is int and packet["ordinal"] == ordinal
                        and type(packet["terminal"]) is bool and type(packet["payload"]) is str
                        and re.fullmatch(r"(?:[0-9a-f]{2})*", packet["payload"]), "reply replay/binding/type")
                payload = bytes.fromhex(packet["payload"])
                require(len(payload) <= ipc.MAX_CHUNK and (not packet["terminal"] or payload == b""), "reply size/terminal data")
                ordinal += 1
                require(ordinal <= ipc.MAX_MESSAGES * (ipc.MAX_FRAME // ipc.MAX_CHUNK + 2), "reply flood")
                pending += payload; terminal = packet["terminal"]
                if stream.binding.sequence == 0:
                    ready_raw += payload
                    require(len(ready_raw) <= ipc.MAX_FRAME, "ready publication size")
            require(len(pending) <= ipc.MAX_CHUNK * ipc.MAX_MESSAGES,
                    "reply authenticated output accumulation")
            raw = pending[:limit]
            self._reply_transition(partial=partial, pending=pending[len(raw):], ordinal=ordinal,
                                   terminal=terminal, ready_raw=ready_raw)
            return raw if raw else None
    def close_reply_stream(self, stream, binding):
        with self._lease(cleanup=True):
            state = self._reply_state_exact()
            if state is not None and state.phase is _ReplyPhase.OPEN:
                self._reply_exact(stream, binding)
                publish = binding.sequence == 0 and state.eof and not self._sealed
                if publish:
                    receipt = state.eof_receipt
                    require(type(receipt) is _AuthenticatedReplyEof and receipt is self.__ready_authenticated
                            and receipt.stream is stream and receipt.binding_raw == stream.binding_raw
                            and receipt.nonce == stream.nonce and receipt.ordinal == state.ordinal
                            and receipt.ready_sha256 == sha(bytes(state.ready_raw)),
                            "ready publication lacks retained authenticated EOF")
                    require(self.lifecycle is Lifecycle.RESUMED and self.process.resumed and not self.process.suspended,
                            "ready publication before guarded resume")
                    self._live_authority(self.process); self._deadline(self.process.deadline_ns)
                if not state.eof: self._seal()
                state = self._reply_transition(publish_ready=publish, phase=_ReplyPhase.CLOSING)
            else:
                self._reply_exact(stream, binding, closing=True)
                state = self._reply_state_exact()
            try: receipt = self.api.close_pipe(stream.handle)
            except BaseException:
                self._seal(); raise
            self.api.attest_pipe_closed(stream.handle, receipt)
            state = self._reply_transition(close_receipt=receipt, phase=_ReplyPhase.CLOSED)
            publish = state.publish_ready
            self.reply = None; self.__reply_authority = None
            self.__reply_state = self.__reply_state_values = None
            if publish:
                try:
                    self._live_authority(self.process); self._deadline(self.process.deadline_ns)
                    self.__lifecycle = Lifecycle.READY
                except BaseException:
                    self._seal(); raise
    def is_suspended(self, process):
        with self._lease():
            self._exact(process)
            if self._closed_handle("thread"): return False
            return process.suspended and not process.resumed and self.api.thread_suspended(process.thread)
    def resume(self, process):
        with self._lease():
            self._exact(process)
            require(self.lifecycle is Lifecycle.SUSPENDED and not self._sealed
                    and process.suspended and not process.resumed and self.reply is not None, "resume state")
            try:
                self._deadline(process.deadline_ns)
                self.start_guard(process.image, process.session, process.deadline_ns)
                self._source(process)
                for handle, digest, info in self._files:
                    require(self.api.info(handle) == info and sha(self.api.read_all(handle, MAX_BOOTSTRAP)) == digest, "bootstrap file drift")
                for handle, info in self._dirs: require(self.api.info(handle) == info, "cwd identity drift")
                self._exact(process); self._containment(process); self._deadline(process.deadline_ns)
                require(self.api.resume_thread(process.thread) == 1, "suspend count drift")
                process._state.suspended, process._state.resumed = False, True
                self.__lifecycle = Lifecycle.RESUMED
            except BaseException:
                self._seal(); raise
    def alive(self, process):
        with self._lease(cleanup=True):
            self._exact(process); return False if self._closed_handle("handle") else self.api.alive(process.handle)
    def write(self, channel, raw, deadline_ns):
        with self._lease():
            self._deadline(deadline_ns)
            require(not self._sealed and channel is self.channel
                    and self.__channel_state is not None
                    and self.__channel_state.phase is _ChannelPhase.LIVE
                    and self.reply is not None
                    and type(raw) is bytes and 0 < len(raw) <= ipc.MAX_CHUNK, "control authority/limit")
            self._channel_exact(channel); self._reply_exact(self.reply, self.reply.binding)
            try:
                self._exact(channel.process); self.api.write_pipe(channel.handle, raw, deadline_ns, self.now_ns)
                self._deadline(deadline_ns); return len(raw)
            except BaseException:
                self._seal(); raise
    def diagnostic_output(self, process, limit):
        with self._lease(diagnostic=True):
            if self.lifecycle is Lifecycle.POISONED:
                require(process is self.process and type(limit) is int and limit > 0, "diagnostic identity/limit")
                return b""  # Nonmutating; never a quiescence/authority claim.
            self._exact(process); require(type(limit) is int and limit > 0, "diagnostic limit")
            return b""  # No stdio inherited; diagnostics intentionally unavailable.
    def spawn_child_suspended(self, worker, operation_id, image): raise RuntimeError("operation_child prohibited by two-role/job policy")
    def parent_identity(self, child): raise RuntimeError("operation_child prohibited")
    def terminate(self, process, expected):
        with self._lease(cleanup=True):
            require(self._exact(process) == expected, "termination identity uncertain")
            self._seal()
            if self._closed_handle("job"): return
            self.api.terminate_job(process.job)
    def join(self, process, expected, deadline_ns):
        with self._lease(cleanup=True):
            require(self._exact(process) == expected, "join identity uncertain"); self._deadline(deadline_ns)
            if self._closed_handle("handle"): return True
            joined = self.api.wait_process(process.handle, deadline_ns, self.now_ns)
            if joined:
                require(not self.api.alive(process.handle), "signaled process remains alive")
                # A process can signal before Windows removes its final job
                # accounting entry. Wait under the SAME deadline; only that
                # exact exiting PID is tolerated, never an unknown descendant.
                while True:
                    self._exact(process)
                    if self._closed_handle("job"): break
                    limits, pids = self.api.job_state(process.job)
                    require(limits == (0x2008, 1) and pids in ((), (process.native[0],)),
                            f"join job authority drift: limits={limits}, pids={pids}, expected={process.native[0]}")
                    if not pids: break
                    if self.now_ns() >= deadline_ns: return False
                    self.api.sleep_ns(min(ipc.POLL_NS, deadline_ns - self.now_ns()))
                self._containment(process, dead=True); process._state.joined = True
                self._recover_adapter(); self._close_reply_setup()
            return joined
    def close_process(self, process, expected):
        with self._lease(cleanup=True):
            require(self._exact(process) == expected and process.joined
                    and (self._closed_handle("handle") or not self.api.alive(process.handle)), "close before exact join")
            self._containment(process, dead=True)
            require(self.__channel_state is not None
                    and self.__channel_state.phase is _ChannelPhase.CLOSED
                    and self.reply is None, "close before channel quiescence")
            self._channel_exact(self.channel, closed=True)
            self._recover_adapter(); self._close_reply_setup()
            if self.__closing_authority is None: self.__closing_authority = self._process_authority
            self._close_bootstrap()
            for name in ("thread", "parent_handle", "job", "handle"):
                value = getattr(process, name)
                if not self._closed_handle(name):
                    self.api.close(value)
                    self.__close_receipts[name] = _ClosedProcessHandle(process, name, value, self._process_authority)
            process.image._release(self); self._launch_image = None
            process._state.closed = self._sealed = True
            self.__lifecycle = Lifecycle.CLOSED
    def _close_bootstrap(self, deadline=None):
        for obligations in (self._files, self._dirs):
            while obligations:
                if deadline is not None: require(self._clock_ns() < deadline, "bootstrap close deadline")
                self.api.close(obligations[-1][0]); obligations.pop()
        # Private bootstrap artifacts are retained, not implicitly deleted.
    def close_channel(self, channel):
        with self._lease(cleanup=True):
            state = self.__channel_state
            if state is not None and state.phase is _ChannelPhase.LIVE:
                self._channel_exact(channel)
                self._close_reply_setup()
                if self.reply is not None:
                    reply_state = self._reply_state_exact()
                    require(not reply_state.published,
                            "published reply must be closed before its channel")
                    if reply_state.phase is _ReplyPhase.OPEN:
                        self._reply_exact(self.reply, self.reply.binding)
                        reply_state = self._reply_transition(phase=_ReplyPhase.CLOSING)
                    else:
                        self._reply_exact(self.reply, self.reply.binding, closing=True)
                    receipt = self.api.close_pipe(self.reply.handle)
                    self.api.attest_pipe_closed(self.reply.handle, receipt)
                    self._reply_transition(close_receipt=receipt, phase=_ReplyPhase.CLOSED)
                    self.reply = None; self.__reply_authority = None
                    self.__reply_state = self.__reply_state_values = None
                self._seal()
                self._channel_transition(channel, phase=_ChannelPhase.CLOSING)
            else:
                self._channel_closing_exact(channel)
                require(self.reply is None and not self.__reply_setup_obligations,
                        "closing channel retains reply obligations")
            receipt = self.api.close_pipe(channel.handle)
            self.api.attest_pipe_closed(channel.handle, receipt)
            self._channel_transition(channel, phase=_ChannelPhase.CLOSED, close_receipt=receipt)
Runtime = WindowsWorkerRuntime

class _BasicLimits(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", w.DWORD),
        ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t), ("active", w.DWORD),
        ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
class _JobLimits(ctypes.Structure):
    _fields_ = [("basic", _BasicLimits), ("io", ctypes.c_ulonglong * 6), ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
class _Overlapped(ctypes.Structure):
    _fields_ = [("internal", ctypes.c_size_t), ("internal_high", ctypes.c_size_t),
               ("offset", w.DWORD), ("offset_high", w.DWORD), ("event", w.HANDLE)]
def _quote(value):
    require(type(value) is str and "\0" not in value, "argv type/NUL")
    result, slashes = '"', 0
    for char in value:
        if char == "\\": slashes += 1
        elif char == '"': result += "\\" * (slashes * 2 + 1) + char; slashes = 0
        else: result += "\\" * slashes + char; slashes = 0
    return result + "\\" * (slashes * 2) + '"'

class Win32(_AcquisitionBook, FileWin32):
    """Concrete Win32 boundary; no shell, helper process or PATH lookup."""
    def __init__(self):
        self._init_acquisitions()
        self._pipe_lock = threading.RLock()
        self.__pipe_owner = object()
        self.__pipe_receipt_authority = object()
        self.__closed_pipes, self.__closed_pipe_values = {}, {}
        self._pending, self._pipes = {}, {}
        super().__init__()
        P = ctypes.c_void_p
        def bind(name, result, args):
            fun = getattr(self.k, name); fun.restype, fun.argtypes = result, args; return fun
        self._dup = bind("DuplicateHandle", w.BOOL, [w.HANDLE,w.HANDLE,w.HANDLE,P,w.DWORD,w.BOOL,w.DWORD])
        self._pid = bind("GetProcessId", w.DWORD, [w.HANDLE])
        self._exit_code = bind("GetExitCodeProcess", w.BOOL, [w.HANDLE,P])
        self._times = bind("GetProcessTimes", w.BOOL, [w.HANDLE,P,P,P,P])
        self._image = bind("QueryFullProcessImageNameW", w.BOOL, [w.HANDLE,w.DWORD,w.LPWSTR,P])
        self._job_new = bind("CreateJobObjectW", w.HANDLE, [P,w.LPCWSTR])
        self._job_set = bind("SetInformationJobObject", w.BOOL, [w.HANDLE,ctypes.c_int,P,w.DWORD])
        self._job_get = bind("QueryInformationJobObject", w.BOOL, [w.HANDLE,ctypes.c_int,P,w.DWORD,P])
        self._assign = bind("AssignProcessToJobObject", w.BOOL, [w.HANDLE,w.HANDLE])
        self._in_job = bind("IsProcessInJob", w.BOOL, [w.HANDLE,w.HANDLE,P])
        self._kill_job = bind("TerminateJobObject", w.BOOL, [w.HANDLE,w.UINT])
        self._kill = bind("TerminateProcess", w.BOOL, [w.HANDLE,w.UINT])
        self._wait = bind("WaitForSingleObject", w.DWORD, [w.HANDLE,w.DWORD])
        self._resume = bind("ResumeThread", w.DWORD, [w.HANDLE])
        self._suspend_query = self.n.NtQueryInformationThread
        self._suspend_query.restype,self._suspend_query.argtypes = w.LONG,[w.HANDLE,ctypes.c_int,P,w.ULONG,P]
        self._attr_init = bind("InitializeProcThreadAttributeList",w.BOOL,[P,w.DWORD,w.DWORD,P])
        self._attr_set = bind("UpdateProcThreadAttribute",w.BOOL,[P,w.DWORD,ctypes.c_size_t,P,ctypes.c_size_t,P,P])
        self._attr_free = bind("DeleteProcThreadAttributeList",None,[P])
        self._spawn = bind("CreateProcessW",w.BOOL,[w.LPCWSTR,w.LPWSTR,P,P,w.BOOL,w.DWORD,P,w.LPCWSTR,P,P])
        self._pipe = bind("CreateNamedPipeW",w.HANDLE,[w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,P])
        self._connect = bind("ConnectNamedPipe",w.BOOL,[w.HANDLE,P])
        self._peek = bind("PeekNamedPipe",w.BOOL,[w.HANDLE,P,w.DWORD,P,P,P])
        self._event = bind("CreateEventW",w.HANDLE,[P,w.BOOL,w.BOOL,w.LPCWSTR])
        self._overlapped = bind("GetOverlappedResult",w.BOOL,[w.HANDLE,P,P,w.BOOL])
        self._cancel = bind("CancelIoEx",w.BOOL,[w.HANDLE,P])
        self._type = bind("GetFileType",w.DWORD,[w.HANDLE])
        self._system = bind("GetWindowsDirectoryW",w.UINT,[w.LPWSTR,w.UINT])
        self._process_images = {}
    def read_all(self,handle,limit):
        self._check(self._seek(handle,0,None,0)); raw=bytearray()
        while len(raw)<=limit:
            buffer,count=ctypes.create_string_buffer(min(65536,limit+1-len(raw))),w.DWORD()
            self._check(self._read(handle,buffer,len(buffer),ctypes.byref(count),None))
            if not count.value: return bytes(raw)
            raw.extend(buffer.raw[:count.value])
        raise RuntimeError("retained file size exceeded")
    def inventory(self,root):
        result=set()
        for current,dirs,files in os.walk(root,followlinks=False):
            for name in [*dirs,*files]:
                require(not os.lstat(ntpath.join(current,name)).st_file_attributes & 0x400,"runtime reparse entry")
            result.update(ntpath.join(current,name).casefold() for name in files)
        return result
    def private_directory(self,handle):
        info=self.info(handle); return info.directory and not info.reparse and self.private(handle)
    def _open(self,path,access,share,disposition,flags):
        with self._acquiring():
            with self._attributes() as attributes:
                handle=self._create(path,access,share,attributes,disposition,flags,None)
                require(handle not in (None,ctypes.c_void_p(-1).value), "retained file/directory open")
                token=self._track_acquisition(handle)
            self._publish_acquisition(token); return handle
    def create_sealed_file(self,path,raw):
        with self._acquiring():
            handle=self.open_file(path,create=True,writable=True)
            original=self._track_acquisition(handle)
            require(self.write(handle,raw)==len(raw),"short bootstrap write"); self.flush(handle)
            require(self.read_all(handle,MAX_BOOTSTRAP)==raw,"bootstrap read-back")
            result=self._duplicate(handle,self._process(),access=0x80000000)
            duplicate=self._track_acquisition(result)
            self._close_acquisition(original)
            self._publish_acquisition(duplicate); return result
    def system_root(self):
        buffer=ctypes.create_unicode_buffer(32768)
        require(0<self._system(buffer,len(buffer))<len(buffer),"Windows root unavailable"); return local_path(buffer.value)
    def _duplicate(self,handle,target,*,inheritable=False,access=None):
        with self._acquiring():
            result=w.HANDLE()
            native = None if target == self._process() else self.process_identity(target)
            done=self._dup(self._process(),handle,target,ctypes.byref(result),access or 0,inheritable,2 if access is None else 0)
            token = None
            if result.value:
                token=self._track_acquisition(result.value, _HandleKind.GENERIC if native is None else _HandleKind.REMOTE,
                                              None if native is None else (target,native))
            self._check(done); require(token is not None,"duplicate handle result missing")
            self._publish_acquisition(token); return result.value
    def inheritable_copy(self,handle): return self._duplicate(handle,self._process(),inheritable=True)
    def retain_current_process(self): return self._duplicate(self._process(),self._process(),access=0x101000)
    def transfer_to_child(self,handle,process): return self._duplicate(handle,process,inheritable=False)
    def process_identity(self,handle):
        times=[w.FILETIME() for _ in range(4)]; self._check(self._times(handle,*[ctypes.byref(t) for t in times]))
        buffer,length=ctypes.create_unicode_buffer(32768),w.DWORD(32768)
        pid=self._pid(handle); require(pid>0,"process PID unavailable")
        created=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
        if self._image(handle,0,buffer,ctypes.byref(length)):
            value=(pid,created,local_path(buffer.value))
            require(handle not in self._process_images or self._process_images[handle]==value,"native process identity changed")
            self._process_images[handle]=value
            return value
        # Windows can discard image-name data when a suspended/just-resumed
        # process is terminated. Preserve only a path authenticated on THIS
        # still-open handle, with freshly identical PID+creation and signaled
        # process. No cache lookup by PID and no reopening a dead process.
        prior=self._process_images.get(handle)
        require(prior is not None and prior[:2]==(pid,created) and self._wait(handle,0)==0,
                "process image unavailable without retained exited identity")
        return prior
    def close(self,handle):
        with self._pipe_lock:
            require(type(handle) is not PipeHandle, "registered pipe requires typed close")
            native = handle.value if type(handle) is w.HANDLE else handle
            require(type(native) is int and native > 0
                    and native not in self._pipes and native not in self._pending,
                    "registered/pending pipe requires typed close")
            self._acquisition_close_guard(native)
            super().close(native)
            getattr(self,"_process_images",{}).pop(native,None)
    def _raw_close_acquisition(self, token, deadline, clock):
        if token.kind is _HandleKind.PROCESS:
            require(callable(clock) and type(deadline) is int and clock()<deadline,
                    "unpublished process requires original bounded recovery")
            native=self.process_identity(token.handle)
            self._bind_acquired_process(token,native)
            if self.alive(token.handle): self.terminate_process(token.handle)
            require(self.wait_process(token.handle,deadline,clock) and not self.alive(token.handle),
                    "unpublished process join")
            self._bind_acquired_process(token,self.process_identity(token.handle))
        elif token.kind is _HandleKind.REMOTE:
            process,native=token.identity
            self._acquired_identity(self.process_identity(process)==native)
            require(not self.alive(process),"remote writer remains owned until exact process exit")
            return  # Windows has closed the exact dead process's handle table.
        else: require(token.kind is _HandleKind.GENERIC, "unexpected acquisition kind")
        FileWin32.close(self,token.handle)
        getattr(self,"_process_images",{}).pop(token.handle,None)
    def create_job(self):
        with self._acquiring():
            with self._attributes() as attributes:
                job=self._job_new(attributes,None)
                self._check(job); token=self._track_acquisition(job)
            limits=_JobLimits(); limits.basic.flags=0x2008; limits.basic.active=1
            self._check(self._job_set(job,9,ctypes.byref(limits),ctypes.sizeof(limits)))
            self._publish_acquisition(token); return job
    def job_state(self,job):
        limits=_JobLimits(); self._check(self._job_get(job,9,ctypes.byref(limits),ctypes.sizeof(limits),None))
        class PIDS(ctypes.Structure): _fields_=[("assigned",w.DWORD),("count",w.DWORD),("pids",ctypes.c_size_t*2)]
        pids=PIDS(); returned=w.DWORD()
        self._check(self._job_get(job,3,ctypes.byref(pids),ctypes.sizeof(pids),ctypes.byref(returned)))
        self._last_job_query=dict(handle=job,assigned=pids.assigned,count=pids.count,size=ctypes.sizeof(pids),
            offset=PIDS.pids.offset,returned=returned.value,raw=bytes(pids).hex())
        require(pids.assigned==pids.count and pids.count<=1,"job descendant count")
        return (limits.basic.flags,limits.basic.active),tuple(pids.pids[:pids.count])
    def assign_job(self,job,process): self._check(self._assign(job,process))
    def in_job(self,process,job):
        value=w.BOOL(); self._check(self._in_job(process,job,ctypes.byref(value))); return bool(value.value)
    def terminate_job(self,job): self._check(self._kill_job(job,0xE2B))
    def terminate_process(self,process): self._check(self._kill(process,0xE2B))
    def alive(self,process):
        result=self._wait(process,0); require(result in (0,258),"retained process wait failure"); return result==258
    def exit_code(self,process):
        require(not self.alive(process),"exit code requires retained signaled process")
        value=w.DWORD(); self._check(self._exit_code(process,ctypes.byref(value))); return value.value
    def wait_process(self,process,deadline,clock):
        while clock()<deadline:
            if not self.alive(process): return True
            self._wait(process,min(1,max(0,(deadline-clock())//1_000_000)))
        return not self.alive(process)
    def resume_thread(self,thread): return self._resume(thread)
    def thread_suspended(self,thread):
        count=w.ULONG(); status=self._suspend_query(thread,35,ctypes.byref(count),ctypes.sizeof(count),None)
        require(status==0,"thread suspend count unavailable"); return count.value==1
    def sleep_ns(self,ns): time.sleep(ns/1_000_000_000)
    def create_suspended(self,executable,argv,environment,cwd,handles):
        with self._acquiring():
            return self._create_suspended(executable,argv,environment,cwd,handles)
    def _create_suspended(self,executable,argv,environment,cwd,handles):
        require(len(handles)==len(set(handles)) and handles,"inheritance allowlist")
        class START(ctypes.Structure):
            _fields_=[("cb",w.DWORD),("reserved",w.LPWSTR),("desktop",w.LPWSTR),("title",w.LPWSTR),
                ("x",w.DWORD),("y",w.DWORD),("xs",w.DWORD),("ys",w.DWORD),("xc",w.DWORD),("yc",w.DWORD),
                ("fill",w.DWORD),("flags",w.DWORD),("show",w.WORD),("reserved2",w.WORD),("bytes",ctypes.c_void_p),
                ("stdin",w.HANDLE),("stdout",w.HANDLE),("stderr",w.HANDLE)]
        class EX(ctypes.Structure): _fields_=[("start",START),("attributes",ctypes.c_void_p)]
        class PI(ctypes.Structure): _fields_=[("process",w.HANDLE),("thread",w.HANDLE),("pid",w.DWORD),("tid",w.DWORD)]
        size=ctypes.c_size_t(); self._attr_init(None,1,0,ctypes.byref(size)); attributes=ctypes.create_string_buffer(size.value)
        self._check(self._attr_init(attributes,1,0,ctypes.byref(size)))
        try:
            allow=(w.HANDLE*len(handles))(*handles)
            self._check(self._attr_set(attributes,0,0x20002,allow,ctypes.sizeof(allow),None,None))
            startup,result=EX(),PI(); startup.start.cb=ctypes.sizeof(startup); startup.start.flags=0x101; startup.start.show=0
            startup.attributes=ctypes.cast(attributes,ctypes.c_void_p)
            command=ctypes.create_unicode_buffer(" ".join(_quote(v) for v in argv)); require(len(command)<32767,"Windows argv limit")
            block=ctypes.create_unicode_buffer("\0".join(f"{n}={v}" for n,v in sorted(environment.items()))+"\0\0")
            # DETACHED_PROCESS is essential: CREATE_NO_WINDOW still creates a
            # headless conhost on Windows and can leave it in the job after the
            # primary process exits. No console/std handles are needed here.
            done=self._spawn(executable,command,None,None,True,SPAWN_FLAGS,
                             block,cwd,ctypes.byref(startup),ctypes.byref(result))
            thread_token=self._track_acquisition(result.thread) if result.thread else None
            process_token=self._track_acquisition(result.process,_HandleKind.PROCESS,
                                                  (result.pid,executable)) if result.process else None
            self._check(done)
            require(thread_token is not None and process_token is not None,"incomplete native spawn handles")
            self._bind_acquired_process(process_token,self.process_identity(result.process))
        finally: self._attr_free(attributes)
        self._publish_acquisition(process_token); self._publish_acquisition(thread_token)
        return result.process,result.thread
    def pipe_pair(self,*,parent_reads):
        with self._acquiring(): return self._pipe_pair(parent_reads=parent_reads)
    def _pipe_pair(self,*,parent_reads):
        name="\\\\.\\pipe\\native-page-s2b-"+secrets.token_hex(24)
        with self._attributes() as attributes:
            parent=self._pipe(name,(1 if parent_reads else 2)|0x40000000|0x80000,8,1,65536,65536,0,attributes)
            require(parent not in (None,ctypes.c_void_p(-1).value),"private pipe creation")
            parent_token=self._track_acquisition(parent)
        with self._attributes() as attributes:
            attributes._obj.inherit=True
            child=self._create(name,0x40000000 if parent_reads else 0x80000000,0,attributes,3,0,None)
            require(child not in (None,ctypes.c_void_p(-1).value),"private pipe client")
            child_token=self._track_acquisition(child)
        if not self._connect(parent,None): require(ctypes.get_last_error()==535,"private pipe connect")
        with self._pipe_lock:
            require(parent not in self._pipes and parent not in self._pending, "live pipe numeric handle reuse")
            endpoint = PipeHandle(parent, self.__pipe_owner)
            self._pipes[parent] = endpoint
            self._publish_acquisition(parent_token); self._publish_acquisition(child_token)
            return endpoint,child
    def attest_pipe(self,handle):
        with self._pipe_lock:
            require(type(handle) is PipeHandle and handle.owner is self.__pipe_owner
                    and self._pipes.get(handle.value) is handle and self._type(handle.value)==3,
                    "retained private pipe generation/authority")
    def attest_pipe_closed(self, handle, receipt):
        with self._pipe_lock:
            expected = self.__closed_pipe_values.get(handle)
            require(type(handle) is PipeHandle and type(receipt) is _PipeCloseReceipt
                    and receipt.endpoint is handle and receipt.native == handle.value
                    and receipt.authority is self.__pipe_receipt_authority
                    and self.__closed_pipes.get(handle) is receipt
                    and expected is not None and expected[0] is receipt
                    and expected[1] is handle and expected[2] == receipt.native
                    and expected[3] is receipt.authority
                    and expected[4] is receipt.generation
                    and self._pipes.get(handle.value) is not handle
                    and (handle.value not in self._pending or self._pending[handle.value][0] is not handle),
                    "retained private pipe close receipt")
    def _io(self,handle,payload,limit,deadline,clock):
        self.attest_pipe(handle)
        native = handle.value
        require(native not in self._pending,"pending pipe operation")
        with self._acquiring():
            event=self._event(None,True,False,None)
            require(event not in (None,0), "private I/O event creation")
            token=self._track_acquisition(event)
            overlap=_Overlapped(); overlap.event=event
            buffer=ctypes.create_string_buffer(payload if payload is not None else limit); count=w.DWORD()
            operation=self._write if payload is not None else self._read
            # Own event, buffer and OVERLAPPED before the native call. Even an
            # adapter exception after issuing I/O cannot lose pending storage.
            self._pending[native]=(handle,overlap,buffer,event)
            self._publish_acquisition(token)
        done=operation(native,buffer,len(payload) if payload is not None else limit,ctypes.byref(count),ctypes.byref(overlap))
        if not done and ctypes.get_last_error()!=997:
            error=ctypes.get_last_error(); self.close(event); self._pending.pop(native)
            if error==109 and payload is None: return b""
            raise ctypes.WinError(error)
        try:
            while not done and clock()<deadline:
                result=self._wait(event,0); require(result in (0,258),"overlapped event failure")
                if result==0:
                    self._check(self._overlapped(native,ctypes.byref(overlap),ctypes.byref(count),False)); done=True; break
                time.sleep(0)
            if not done:
                self._cancel(native,ctypes.byref(overlap)); raise RuntimeError("private pipe operation deadline")
            require(payload is None or count.value==len(payload),"short control write")
            return count.value if payload is not None else buffer.raw[:count.value]
        finally:
            if done:
                self.close(event); self._pending.pop(native)
    def write_pipe(self,handle,raw,deadline,clock):
        with self._pipe_lock:
            self.attest_pipe(handle); return self._io(handle,raw,None,deadline,clock)
    def read_pipe(self,handle,limit,deadline,clock):
        with self._pipe_lock:
            self.attest_pipe(handle); count=w.DWORD()
            if not self._peek(handle.value,None,0,None,ctypes.byref(count),None):
                if ctypes.get_last_error()==109: return b""
                raise ctypes.WinError(ctypes.get_last_error())
            if not count.value: return None
            return self._io(handle,None,min(limit,count.value),deadline,clock)
    def close_pipe(self,handle):
        with self._pipe_lock:
            prior = self.__closed_pipes.get(handle)
            if prior is not None:
                self.attest_pipe_closed(handle, prior)
                return prior
            self.attest_pipe(handle)
            native = handle.value
            if native in self._pending:
                owner,overlap,buffer,event=self._pending[native]
                require(owner is handle, "pending I/O belongs to another pipe generation")
                self._cancel(native,ctypes.byref(overlap))
                require(self._wait(event,0)==0,"canceled I/O not yet quiescent")
                count=w.DWORD()
                if not self._overlapped(native,ctypes.byref(overlap),ctypes.byref(count),False):
                    require(ctypes.get_last_error() in (995,109), "canceled I/O completion uncertain")
                self.close(event); self._pending.pop(native)
            # Retire the exact registry generation only after observed I/O
            # quiescence and a successful native close. Failure retains it.
            super().close(native)
            require(self._pipes.get(native) is handle, "pipe registry changed during close")
            del self._pipes[native]
            generation = object()
            receipt = _PipeCloseReceipt(handle, native, self.__pipe_receipt_authority, generation)
            self.__closed_pipes[handle] = receipt
            self.__closed_pipe_values[handle] = (receipt, handle, native,
                self.__pipe_receipt_authority, generation)
            self.attest_pipe_closed(handle, receipt)
            return receipt
