"""Closed S2b worker-side transport and versioned role/capability contract.

main intentionally has no installed backend. Reviewed S6/S7 adapters must inject
RoleBackend objects through an authenticated embedded registry, never an IPC
module name, import path, serialized Python object, or command. Factory IDs below
are protocol identifiers only. Until that review, a concrete child exits closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes as w
import hashlib
import hmac
import re
import threading
import time
from types import MappingProxyType

import native_page_isolated_ipc as ipc


DOMAIN = "native-page-s2b-private-reply-v1"
EXIT_BACKEND_UNAVAILABLE = 78

class BackendUnavailable(ipc.IpcError):
    pass
_ROLE_OPERATIONS = MappingProxyType({
    "authority_worker-v1": ("authority_worker", frozenset({"authority_admission", "authority_capture"})),
    "frida_worker-v1": ("frida_worker", frozenset({"frida_admission", "frida_attach", "frida_load",
        "frida_seal", "frida_unload", "frida_detach", "frida_teardown"})),
})
ROLE_OPERATIONS = _ROLE_OPERATIONS


def require(value, message):
    if not value: raise ipc.IpcError(message)


def copy(value): return ipc.decode_json(ipc.canonical_json(value))


@dataclass(frozen=True)
class RoleBackend:
    """Installed by reviewed bootstrap code, never selected by import path.

    open(descriptor, native) independently verifies retained capabilities and
    returns an engine exposing dispatch(op,payload,absolute_deadline_ns),
    verify_quiescent(operation_id), and seal(). No backend exists by default.
    """
    factory_id: str
    implementation_sha256: str
    open: object


def validate_descriptor(value, _roles=_ROLE_OPERATIONS):
    value = copy(value)
    require(type(value) is dict and set(value) == {"version", "factory", "role", "session", "image_sha256",
        "bootstrap_sha256", "backend_sha256", "configuration", "capabilities", "control_handle",
        "parent_handle", "parent", "key"}, "closed bootstrap descriptor schema")
    require(type(value["version"]) is int and value["version"] == 1 and type(value["factory"]) is str
            and value["factory"] in _roles and value["role"] == _roles[value["factory"]][0], "bootstrap role/version")
    for name in ("session", "image_sha256", "bootstrap_sha256", "backend_sha256", "key"):
        require(type(value[name]) is str and ipc.HEX.fullmatch(value[name]), "bootstrap digest/key")
    for name in ("control_handle", "parent_handle"):
        require(type(value[name]) is int and 0 < value[name] < 2**63, "bootstrap native handle")
    parent = value["parent"]
    require(type(parent) is dict and set(parent) == {"pid", "creation_ticks", "image_path"}
            and type(parent["pid"]) is int and parent["pid"] > 0 and type(parent["creation_ticks"]) is int
            and parent["creation_ticks"] > 0 and type(parent["image_path"]) is str and parent["image_path"], "parent identity")
    require(type(value["configuration"]) is dict and type(value["capabilities"]) is list and len(value["capabilities"]) <= 16, "bootstrap capability/configuration types")
    names, handles = set(), {value["control_handle"], value["parent_handle"]}
    require(len(handles) == 2, "aliased bootstrap handles")
    for cap in value["capabilities"]:
        require(type(cap) is dict and set(cap) == {"name", "handle", "identity"} and type(cap["name"]) is str
                and ipc.NAME.fullmatch(cap["name"]) and cap["name"] not in names and type(cap["handle"]) is int
                and 0 < cap["handle"] < 2**63 and cap["handle"] not in handles and type(cap["identity"]) is str
                and re.fullmatch(r"(?:[0-9a-f]{2})+", cap["identity"]), "capability identity/alias")
        names.add(cap["name"]); handles.add(cap["handle"])
    return value


class Entry:
    def __init__(self, descriptor, native, registry, _roles=_ROLE_OPERATIONS):
        self.descriptor = validate_descriptor(descriptor)
        require(type(registry) is tuple and len(registry) <= 2, "closed embedded registry")
        factories = {}
        for backend in registry:
            require(type(backend) is RoleBackend and type(backend.factory_id) is str and backend.factory_id in _roles
                    and backend.factory_id not in factories and type(backend.implementation_sha256) is str
                    and ipc.HEX.fullmatch(backend.implementation_sha256) and callable(backend.open), "reviewed role factory")
            factories[backend.factory_id] = backend
        factories = MappingProxyType(factories)
        d = self.descriptor
        # Capture immutable policy BEFORE entering any backend code. Rebinding
        # the exported map cannot replace this retained per-entry authority.
        self.__operations = _roles[d["factory"]][1]
        require(type(self.__operations) is frozenset, "immutable operation authority")
        if d["factory"] not in factories:
            raise BackendUnavailable("S6/S7 reviewed child capability backend unavailable")
        backend = factories[d["factory"]]
        require(backend.implementation_sha256 == d["backend_sha256"], "backend implementation pin")
        self.native, self.owner = native, threading.get_ident()
        self.key, self.sequence = bytes.fromhex(d["key"]), 0
        self.nonces, self.writers = set(), set()
        self.closed, self.busy = False, False
        self._decoder, self._messages = ipc.FrameDecoder(), []
        self.native.attest_bootstrap(d)
        self.engine = backend.open(copy(d), native)
        require(all(callable(getattr(self.engine, name, None)) for name in ("dispatch", "verify_quiescent", "seal")), "closed backend contract")
        self.__registry = ipc.WorkerRegistry(d["session"], d["role"], self.__operations,
                                          native.now_ns, self.engine.verify_quiescent)
    @property
    def registry(self): return self.__registry
    @property
    def allowed_operations(self): return self.__operations
    def _registry_authority(self):
        require(self.registry.allowed is self.__operations
                and self.registry.session == self.descriptor["session"]
                and self.registry.role == self.descriptor["role"], "retained registry authority changed")

    def _next(self):
        while not self._messages:
            raw = self.native.read_control(self.descriptor["control_handle"], ipc.MAX_CHUNK)
            require(type(raw) is bytes and raw, "control EOF before complete request")
            self._messages.extend(self._decoder.feed(raw))
        return self._messages.pop(0)

    def _header(self, value):
        require(type(value) is dict and set(value) == {"s2b", "binding", "nonce", "writer", "mac"}
                and type(value["s2b"]) is int and value["s2b"] == 1, "private header schema")
        body = {name: item for name, item in value.items() if name != "mac"}
        require(type(value["mac"]) is str and hmac.compare_digest(value["mac"],
                hmac.new(self.key, ipc.canonical_json(body), hashlib.sha256).hexdigest()), "private header authentication")
        require(type(value["nonce"]) is str and ipc.HEX.fullmatch(value["nonce"]) and value["nonce"] not in self.nonces
                and type(value["writer"]) is int and 0 < value["writer"] < 2**63, "private header nonce/writer")
        # Native handle numbers may be legitimately recycled after exact close;
        # freshness is the authenticated nonce+sequence, not a numeric ban.
        binding = value["binding"]
        require(type(binding) is dict and set(binding) == {"worker", "session", "sequence", "operation_id", "registration_sequence"}
                and binding["session"] == self.descriptor["session"] and type(binding["sequence"]) is int
                and binding["sequence"] == self.sequence, "header binding/sequence")
        worker = binding["worker"]
        actual = self.native.self_identity()
        require(type(worker) is dict and set(worker) == {"pid", "creation_ticks", "image_sha256", "bootstrap_sha256", "role"}
                and type(worker["pid"]) is int and type(worker["creation_ticks"]) is int
                and worker == dict(pid=actual[0], creation_ticks=actual[1], image_sha256=self.descriptor["image_sha256"],
                                   bootstrap_sha256=self.descriptor["bootstrap_sha256"], role=self.descriptor["role"]), "child process binding")
        require(binding["operation_id"] is None or (type(binding["operation_id"]) is str and ipc.NAME.fullmatch(binding["operation_id"])), "operation binding")
        require(binding["registration_sequence"] is None or (type(binding["registration_sequence"]) is int
                and 0 < binding["registration_sequence"] <= self.sequence), "registration binding")
        if self.sequence == 0:
            require(binding["operation_id"] is None and binding["registration_sequence"] is None, "ready scope")
        self.native.attest_writer(value["writer"])
        self.native.attest_bootstrap(self.descriptor)
        self.nonces.add(value["nonce"])
        require(len(self.nonces) <= ipc.MAX_OPERATIONS * 2 + 1, "RPC count limit")
        return value

    def serve_one(self):
        require(not self.closed and not self.busy and threading.get_ident() == self.owner, "entry reentry/thread/terminal state")
        self.busy = True
        header = None
        try:
            self._registry_authority()
            header = self._header(self._next())
            ordinal = 0
            def packet(payload, terminal=False):
                nonlocal ordinal
                value = dict(domain=DOMAIN, binding=header["binding"], nonce=header["nonce"], ordinal=ordinal,
                             payload=payload.hex(), terminal=terminal)
                value["mac"] = hmac.new(self.key, ipc.canonical_json(value), hashlib.sha256).hexdigest()
                self.native.write_reply(header["writer"], ipc.encode_frame(value))
                ordinal += 1
            def reply(value):
                raw = ipc.encode_frame(value)
                for offset in range(0, len(raw), ipc.MAX_CHUNK): packet(raw[offset:offset + ipc.MAX_CHUNK])
            if self.sequence == 0:
                reply(self.registry.ready())
            else:
                request = self._next()
                require(request.get("seq") == self.sequence and request.get("op") == header["binding"]["operation_id"], "control/reply cross binding")
                if request.get("kind") == "register":
                    require(header["binding"]["registration_sequence"] == self.sequence, "registration header scope")
                    require(type(request.get("body")) is dict
                            and type(request["body"].get("operation")) is str
                            and request["body"]["operation"] in self.__operations, "closed role operation")
                else:
                    record = self.registry.operations.get(request.get("op"))
                    require(record is not None and header["binding"]["registration_sequence"] == record["sequence"], "begin registration scope")
                acknowledgement = self.registry.control(request)
                reply(acknowledgement)
                self.registry.acknowledgement_sent(acknowledgement)
                if acknowledgement["kind"] == "started":
                    dispatch = self.registry.dispatch(acknowledgement["op"])
                    self._registry_authority()
                    require(dispatch.operation in self.__operations, "dispatch operation authority changed")
                    deadline = self.registry.operations[dispatch.operation_id]["deadline_ns"]
                    result = self.engine.dispatch(dispatch.operation, copy(dispatch.payload), deadline)
                    require(self.native.now_ns() < deadline, "late worker backend output")
                    self.native.attest_bootstrap(self.descriptor)
                    reply(self.registry.complete(dispatch.operation_id, copy(result)))
            packet(b"", True)
            self.native.close_writer(header["writer"])
            header = None
            self.sequence += 1
        except BaseException:
            self.closed = True
            self.registry.seal()
            self.engine.seal()
            if header is not None: self.native.close_writer(header["writer"])
            raise
        finally: self.busy = False


class Native:
    """Child-only synchronous bounded-frame pipe I/O; parent contains hangs."""
    def __init__(self):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        def bind(name, result, args):
            fun = getattr(self.k, name); fun.restype, fun.argtypes = result, args
            return fun
        P = ctypes.c_void_p
        self.read = bind("ReadFile", w.BOOL, [w.HANDLE, P, w.DWORD, P, P])
        self.write = bind("WriteFile", w.BOOL, [w.HANDLE, P, w.DWORD, P, P])
        self.close = bind("CloseHandle", w.BOOL, [w.HANDLE])
        self.pid = bind("GetProcessId", w.DWORD, [w.HANDLE])
        self.times = bind("GetProcessTimes", w.BOOL, [w.HANDLE, P, P, P, P])
        self.image = bind("QueryFullProcessImageNameW", w.BOOL, [w.HANDLE, w.DWORD, w.LPWSTR, P])
        self.current = bind("GetCurrentProcess", w.HANDLE, [])
        self.wait = bind("WaitForSingleObject", w.DWORD, [w.HANDLE, w.DWORD])
        self.kind = bind("GetFileType", w.DWORD, [w.HANDLE])

    def now_ns(self): return time.monotonic_ns()
    def identity(self, handle):
        times = [w.FILETIME() for _ in range(4)]
        require(self.times(handle, *[ctypes.byref(value) for value in times]), "child identity clock")
        buffer, count = ctypes.create_unicode_buffer(32768), w.DWORD(32768)
        require(self.image(handle, 0, buffer, ctypes.byref(count)), "child image path")
        return self.pid(handle), (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime, buffer.value
    def self_identity(self): return self.identity(self.current())
    def attest_bootstrap(self, descriptor):
        parent = self.identity(descriptor["parent_handle"])
        require(dict(pid=parent[0], creation_ticks=parent[1], image_path=parent[2]) == descriptor["parent"]
                and self.wait(descriptor["parent_handle"], 0) == 258, "parent process identity/liveness")
        require(self.kind(descriptor["control_handle"]) == 3, "child control handle type")
    def attest_writer(self, handle): require(self.kind(handle) == 3, "child reply handle type")
    def read_control(self, handle, limit):
        buffer, count = ctypes.create_string_buffer(limit), w.DWORD()
        require(self.read(handle, buffer, limit, ctypes.byref(count), None), "child control read")
        return buffer.raw[:count.value]
    def write_reply(self, handle, raw):
        buffer, count = ctypes.create_string_buffer(raw), w.DWORD()
        require(self.write(handle, buffer, len(raw), ctypes.byref(count), None) and count.value == len(raw), "child reply write")
    def close_writer(self, handle): require(self.close(handle), "child reply close")


def main(descriptor):
    # No dynamic discovery/import fallback. A later reviewed integration embeds
    # exactly the two RoleBackend factories here; evidence/config cannot do so.
    try:
        entry = Entry(descriptor, Native(), ())
    except BackendUnavailable:
        # A distinct refusal exit, NEVER a successful ready/admission response.
        # Useful to distinguish an audited loader reaching its explicit blocker
        # from a broken interpreter/loader in scoped local smoke tests.
        raise SystemExit(EXIT_BACKEND_UNAVAILABLE)
    while not entry.closed: entry.serve_one()
