"""S8 diagnostic composition, not hardware admission or a production launcher.

The injected ports are retained, authenticated adapters, NOT RPC text returned by
an untrusted device. S1c/S2b and the root launch/reopen bridge remain separately
reviewed dependencies. There is deliberately no default transport, process
factory, shell, clock, file opener, or ambient adb/frida fallback here.

Two separate S5b stores hold the S8 event journal and S5 ownership ledger. Intent
is durable before dispatch. An interrupted run is never resumed: recovery is a
read-only classification retaining exact identities and unresolved intent scopes.
The S8 journal uses the S5 record envelope, but its event semantics are its own;
it must not be passed to CleanupLedger.recover.

Injected calls, especially S4's legacy transport, must provide their own bounded
join/EOF lifetime. S8 rejects late synchronous returns but cannot forcibly bound
an arbitrary callable. No such timing assumption is promoted to hardware proof.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
import hashlib
import json
import re
import threading
import types
from typing import Callable, Protocol

import native_page_coordinator_contracts as c
import native_page_cleanup_ledger as ledger
from native_page_cleanup_store import WindowsCleanupStore, StoreAuthority, FileIdentity
import native_page_graph_v2_runner as runner
import native_page_pen_peer as pen


AUTHORITY = "rtl-reader-native-page-visual-coordinator-v1"
RECEIPT_AUTHORITY = "rtl-reader-native-page-visual-port-receipt-v1"
BLOCKERS = c.ADMISSION_BLOCKERS + (
    "REVIEWED_READONLY_S1C_ADAPTER_REQUIRED", "REVIEWED_WINDOWS_S2B_RUNTIME_REQUIRED",
    "REVIEWED_CAUSAL_LAUNCH_AND_ORDINARY_REOPEN_BRIDGE_REQUIRED",
    "RETAINED_CROSS_OWNER_PREDISPATCH_PROOFS_REQUIRED",
    "REVIEWED_S6_STAGE_EPOCH_PREATTACH_OWNER_EXCLUSION_REQUIRED",
    "REQUESTED_PAGE_TO_RAW_GRAPH_INDEX_HARDWARE_CALIBRATION_REQUIRED",
    "IMMUTABLE_OS_HANDLE_DISPATCH_AUTHORITY_REQUIRED",
    "REVIEWED_INDEPENDENT_DURABLE_STAGE_CREATION_OWNER_REQUIRED",
)


class CoordinatorError(RuntimeError): pass
class RetainedQuarantine(CoordinatorError): pass
class AdmissionBlocked(CoordinatorError): pass
class TerminalDecisionUncertain(RetainedQuarantine): pass


def admission_status():
    return dict(admitted=False, diagnosticOnly=True, blockers=list(BLOCKERS),
                cleanupTotalMs=250, cleanupPerCallMs=25, hardwareTimingProven=False,
                ambientFallback=False)


def _need(ok, message):
    if not ok: raise CoordinatorError(message)


def _same(actual, expected, message="exact binding differs"):
    _need(c.canonical_bytes(actual) == c.canonical_bytes(expected), message)


def _verified_none(result):
    _need(result is None, "lifecycle verifier returned non-None evidence")


def _copy(value): return c.load_canonical(c.canonical_bytes(value))
def _sha(raw): return hashlib.sha256(raw).hexdigest()
def _binding_wire(binding):
    _need(type(binding) is c.ResourceBinding,"exact inventory binding required")
    return dict(role=binding.role,owner=binding.owner,identity=binding.identity.wire())


def _ordered_bindings(value, roles):
    _need(type(value) is list and len(value)==len(roles),"complete ordered creation bindings required")
    result=[]
    for item,role in zip(value,roles):
        c._keys(item,"role owner identity")
        binding=c.ResourceBinding(item["role"],item["owner"],c.ResourceIdentity.parse(item["identity"]))
        _need(binding.role==role,"creation binding role/order differs")
        result.append(binding)
    c.validate_resource_bindings(tuple(result))
    return tuple(result)


def _port_creation(operation, request, body, plan):
    """The authenticated result, not a later observation, names acquisitions.

    No receipt grants task disposal before the separate causal-attach model
    proof. This authority only preserves exact pending identities on loss.
    """
    if operation==Operation.HOST_START.value:
        c._keys(request,"host hostSessionId canvas")
        _same(request,dict(host=plan["host"],hostSessionId=plan["hostSessionId"],canvas=plan["canvas"]))
        c._keys(body,"display evidenceSha256 ownerInventory")
        c._display(body["display"],plan);c._sha(body["evidenceSha256"])
        expected=(c.ResourceBinding("host_session","host_authority",c.ResourceIdentity(
            "host_session",c.AUTHORIZED_SERIAL,plan["hostSessionId"],plan["runSessionId"])),
            c.ResourceBinding("virtual_display","host_authority",c.ResourceIdentity.parse(body["display"]["identity"])))
        owner="host"
    elif operation==Operation.ATTACH.value:
        c._keys(body,"foreign launchCommandSha256 causalLaunchProofSha256 hostAttachAckSha256 documentTasks "
            "documentActivities displayZeroDocumentTasks displayZeroDocumentActivities prelaunchAbsenceSha256 ownerInventory")
        c._keys(request,"commandId component display beforeAbsenceSha256 prelaunchAbsenceSha256 documentTasks documentActivities fixtureSha256 commandSha256")
        _same(request["component"],c.COMPONENT);c._display(request["display"],plan)
        c._foreign(body["foreign"],request["display"])
        _same(body["launchCommandSha256"],request["commandSha256"])
        _same(body["prelaunchAbsenceSha256"],request["prelaunchAbsenceSha256"])
        for key in ("causalLaunchProofSha256","hostAttachAckSha256"):c._sha(body[key])
        _same(body["documentTasks"],[body["foreign"]["identity"]])
        _same(body["documentActivities"],[body["foreign"]["activityToken"]])
        _same(body["displayZeroDocumentTasks"],[]);_same(body["displayZeroDocumentActivities"],[])
        expected=(c.ResourceBinding("foreign_task","root_supervisor",c.ResourceIdentity.parse(body["foreign"]["identity"])),)
        owner="supervisor"
    else:return None
    _ordered_bindings(body["ownerInventory"],tuple(binding.role for binding in expected))
    _same(body["ownerInventory"],[_binding_wire(binding) for binding in expected],
          "creator result differs from its exact complete acquisition batch")
    return dict(owner=owner,bindings=[_binding_wire(binding) for binding in expected])


def _anchor(original):
    """Retain identity and independent primitive values, never user equality.

    Dispatch checks traverse only exact builtins and explicitly listed transport
    dataclasses. They invoke no canonical_bytes, equality, repr or user iterator.
    Detached views are reconstructed from private immutable scalar tuples.
    """
    classes = (Selection, StageContext, PredispatchView, ResourceClosure, c.RunContract, c.ResourceIdentity,
        c.ResourceBinding, runner.StageBinding, runner.CanonicalAuthority, runner.LoadedJson,
        runner.TrustedPins, runner.DocumentTaskAuthority, pen.ProcessIdentity, pen.StageSession,
        pen.LeaseBinding, StoreAuthority, FileIdentity)
    nodes = []
    def build(value, depth=0):
        _need(depth < 64, "retained identity nesting exceeds bound")
        kind = type(value)
        if any(kind is exact for exact in (str, int, bool, bytes, type(None))):
            def check(live): _need(type(live) is kind and live == value, "retained scalar changed")
            tag = kind.__name__
            scalar = value.hex() if kind is bytes else str(value) if kind is int else value
            return lambda:value, check, [tag, scalar]
        _need(any(kind is exact for exact in (dict, list, tuple)+classes), "unsupported retained identity type")
        if kind is dict:
            _need(all(type(key) is str for key in value), "retained dictionary keys must be exact strings")
            names = tuple(dict.keys(value)); children = tuple(build(dict.__getitem__(value,key),depth+1) for key in names)
            get = lambda live,name:dict.__getitem__(live,name)
        elif kind in (list, tuple):
            names = tuple(range(len(value))); children = tuple(build(value[n],depth+1) for n in names)
            get = lambda live,name:kind.__getitem__(live,name)
        else:
            names = tuple(field.name for field in fields(kind))
            children = tuple(build(object.__getattribute__(value,name),depth+1) for name in names)
            get = object.__getattribute__
        expected = tuple((get(value,name),type(get(value,name))) for name in names)
        nodes.append((value,kind,names,expected,get))
        def check(live):
            _need(type(live) is kind and live is value, "retained nested object replaced")
            if kind is dict:
                _need(len(live) == len(names) and all(type(k) is str for k in live) and
                      tuple(dict.keys(live)) == names, "retained dictionary shape changed")
            elif kind in (list, tuple): _need(len(live) == len(names), "retained sequence shape changed")
            for name, child in zip(names, children): child[1](get(live,name))
        def view():
            values = [child[0]() for child in children]
            if kind is dict: return dict(zip(names,values))
            if kind in (list,tuple): return kind(values)
            return kind(**dict(zip(names,values)))
        shape = [kind.__module__+"."+kind.__name__, [[str(name), child[2]] for name,child in zip(names,children)]]
        return view, check, shape
    view, check, shape = build(original)
    # Internal tagged canonical codec accommodates observer/manifest byte blobs
    # larger than S0's public per-string limit. Only the exact builtins produced
    # above enter this encoder; no user serialization hooks are used.
    raw = json.dumps(["s8-private-anchor-v1",shape],sort_keys=True,separators=(",",":"),
                     ensure_ascii=True,allow_nan=False).encode("ascii")
    root_kind = type(original)
    def exact_check():
        # Flat traversal avoids a Python closure call for every primitive on
        # every verifier edge. Accessors only receive construction-validated
        # exact builtins/trusted dataclasses; no user iterator/equality runs.
        for owner,kind,names,expected,get in nodes:
            if type(owner) is not kind:
                raise CoordinatorError("retained nested type changed")
            if kind is dict:
                if len(owner)!=len(names) or not all(type(k) is str for k in owner) or tuple(dict.keys(owner))!=names:
                    raise CoordinatorError("retained dictionary shape changed")
            elif kind is list or kind is tuple:
                if len(owner)!=len(names):raise CoordinatorError("retained sequence shape changed")
            for name,(prior,exact) in zip(names,expected):
                live=get(owner,name)
                if type(live) is not exact:
                    raise CoordinatorError("retained scalar type changed")
                if exact is str or exact is int or exact is bool or exact is bytes or exact is type(None):
                    if live!=prior:raise CoordinatorError("retained scalar changed")
                elif live is not prior:
                    raise CoordinatorError("retained nested object replaced")
        if not nodes and type(original) is not root_kind:
            raise CoordinatorError("retained root type changed")
    return view, exact_check, raw


def _method_slot(owner, name):
    """Static lookup and binding: no user __getattribute__/descriptor call."""
    kind = type(owner)
    _need(type.__getattribute__(kind,"__getattribute__") is object.__getattribute__,
          "dynamic retained owner lookup is unsupported")
    data=None
    for base in type.__getattribute__(kind,"__mro__"):
        members=type.__getattribute__(base,"__dict__")
        if "__dict__" in members:
            descriptor=members["__dict__"]
            _need(type(descriptor) is types.GetSetDescriptorType,"dynamic retained dictionary is unsupported")
            data=descriptor.__get__(owner,kind)
            break
    if type(data) is dict and name in data:
        value = dict.__getitem__(data,name)
        _need(type(value) is types.FunctionType or type(value) is types.MethodType, "unattestable retained callable")
        return value, value, False
    for base in type.__getattribute__(kind,"__mro__"):
        members = type.__getattribute__(base,"__dict__")
        if name in members:
            value = members[name]
            _need(type(value) is types.FunctionType, "retained method must be a plain function")
            return value, types.MethodType(value,owner), True
    raise CoordinatorError("retained method unavailable: "+name)


def _resource_slot(owner):
    """Construction-time, callback-free resource identity authority.

    A binding() callback is consistency evidence only. The reviewed adapter
    must retain the exact ResourceBinding in a declared plain instance slot.
    Properties, descriptors, computed values and missing slots are rejected.
    """
    kind=type(owner); hierarchy=type.__getattribute__(kind,"__mro__")
    def member(name):
        for base in hierarchy:
            members=type.__getattribute__(base,"__dict__")
            if name in members:return members[name]
        raise CoordinatorError("resource lacks static identity slot")
    name=member("BINDING_SLOT")
    _need(type(name) is str and re.fullmatch(r"[a-z][a-z0-9_]*",name) is not None,
          "resource identity slot name differs")
    descriptor=member("__dict__")
    _need(type(descriptor) is types.GetSetDescriptorType,"resource dictionary must be a plain native descriptor")
    data=descriptor.__get__(owner,kind)
    _need(type(data) is dict and name in data,"resource identity slot is unavailable")
    binding=dict.__getitem__(data,name)
    _need(type(binding) is c.ResourceBinding,"resource slot lacks exact binding")
    _,binding_check,_=_anchor(binding)
    def check():
        _need(type(owner) is kind and type.__getattribute__(kind,"__mro__") is hierarchy and
              member("BINDING_SLOT") is name and member("__dict__") is descriptor,
              "resource slot definition replaced")
        current=descriptor.__get__(owner,kind)
        _need(current is data and name in current and dict.__getitem__(current,name) is binding,
              "static resource binding replaced")
        binding_check()
    return binding,check


def _inventory_slot(owner):
    """Read the complete owner inventory without calling its producer.

    Creation may replace this tuple only inside a coordinator-admitted pending
    creation transaction. The final dispatch fence compares the exact last
    admitted tuple; retained_resources() is evidence, not the inventory root.
    """
    kind=type(owner); hierarchy=type.__getattribute__(kind,"__mro__")
    maps=tuple(type.__getattribute__(base,"__dict__") for base in hierarchy)
    def member(name):
        for mapping in maps:
            if name in mapping:return mapping[name]
        raise CoordinatorError("owner lacks static complete inventory slot")
    name=member("RESOURCE_INVENTORY_SLOT")
    _need(type(name) is str and re.fullmatch(r"[a-z][a-z0-9_]*",name) is not None,
          "owner inventory slot name differs")
    descriptor=member("__dict__")
    _need(type(descriptor) is types.GetSetDescriptorType,"owner inventory dictionary is not native")
    data=descriptor.__get__(owner,kind)
    def read():
        _need(type(owner) is kind and type.__getattribute__(kind,"__mro__") is hierarchy and
              member("RESOURCE_INVENTORY_SLOT") is name and member("__dict__") is descriptor and
              descriptor.__get__(owner,kind) is data and type(data) is dict and name in data,
              "owner inventory slot replaced")
        result=dict.__getitem__(data,name)
        _need(type(result) is tuple and len(result)<=128,"complete retained inventory must be an exact bounded tuple")
        return result
    read()
    return read


def _method_anchor(owner,name):
    """Resolve once; subsequent exact checks use native dictionaries only."""
    slot,call,bound=_method_slot(owner,name)
    kind=type(owner); hierarchy=type.__getattribute__(kind,"__mro__")
    maps=tuple(type.__getattribute__(base,"__dict__") for base in hierarchy)
    dictionary_at=next((n for n,mapping in enumerate(maps) if "__dict__" in mapping),None)
    descriptor=None if dictionary_at is None else maps[dictionary_at]["__dict__"]
    data=None if descriptor is None else descriptor.__get__(owner,kind)
    declaration=next((n for n,mapping in enumerate(maps) if name in mapping),None) if bound else None
    function=call.__func__ if type(call) is types.MethodType else call
    code=function.__code__; absent=object()
    def check():
        _need(type(owner) is kind and type.__getattribute__(kind,"__mro__") is hierarchy and
              type.__getattribute__(kind,"__getattribute__") is object.__getattribute__ and
              function.__code__ is code,"retained callable owner/code replaced")
        if descriptor is not None:
            _need(all("__dict__" not in mapping for mapping in maps[:dictionary_at]) and
                  maps[dictionary_at].get("__dict__") is descriptor and descriptor.__get__(owner,kind) is data,
                  "retained native dictionary replaced")
        if bound:
            _need((data is None or dict.get(data,name,absent) is absent) and
                  all(name not in mapping for mapping in maps[:declaration]) and maps[declaration].get(name) is slot,
                  "retained class callable replaced")
        else:_need(type(data) is dict and dict.get(data,name,absent) is slot,"retained instance callable replaced")
    return call,check


def _store_pair(journal_store, ownership_store):
    # No store method is called until all exact input types/identities pass.
    _need(type(journal_store) is WindowsCleanupStore and type(ownership_store) is WindowsCleanupStore and
          journal_store is not ownership_store, "distinct exact S5b stores required")
    left, right = journal_store.authority, ownership_store.authority
    left_api, right_api = journal_store.api, ownership_store.api
    _need(type(left) is StoreAuthority and type(right) is StoreAuthority and left is not right,
          "distinct exact store authorities required")
    lv, lc, _ = _anchor(left); rv, rc, _ = _anchor(right)
    a, b = lv(), rv(); StoreAuthority.__post_init__(a); StoreAuthority.__post_init__(b)
    slots = [(x.volume,x.index) for x in (a.run_identity,a.checkpoint_identity,b.run_identity,b.checkpoint_identity)]
    _need(len(set(slots)) == 4 and len({a.run_path,a.checkpoint_path,b.run_path,b.checkpoint_path}) == 4 and
          a.store_id != b.store_id, "store authorities alias")
    def check():
        _need(journal_store.authority is left and ownership_store.authority is right and
              journal_store.api is left_api and ownership_store.api is right_api, "retained store authority replaced")
        lc(); rc()
    return check


def encode_evidence(value):
    """Versioned, type-preserving JSON codec inside an unsigned S5 envelope.

    Integer tokens use S0's exact signed decimal grammar; strings retain JSON
    quotes, so neither numeric-looking strings nor boolean aliases are coerced.
    The decoded value, not this transport representation, defines equivalence.
    """
    raw = c.canonical_bytes(value)
    text = raw.decode("utf-8")
    return dict(codec="s0-canonical-json-text", version=1, sha256=_sha(raw),
                canonicalParts=[text[i:i + 4096] for i in range(0, len(text), 4096)])


def decode_evidence(value):
    c._keys(value, "codec version sha256 canonicalParts")
    _same(value["codec"], "s0-canonical-json-text"); _same(value["version"], 1)
    c._sha(value["sha256"])
    parts = value["canonicalParts"]
    _need(type(parts) is list and 1 <= len(parts) <= 32 and
          all(type(part) is str and 0 < len(part) <= 4096 for part in parts), "evidence encoding differs")
    raw = "".join(parts).encode("utf-8")
    _same(_sha(raw), value["sha256"])
    decoded = c.load_canonical(raw)
    _same(encode_evidence(decoded), value, "noncanonical evidence chunking")
    return decoded


class Operation(Enum):
    PREFLIGHT = "preflight"
    PRELAUNCH = "prelaunch_absence"
    EXACT_TASK = "exact_foreign_task"
    FINAL_ABSENCE = "final_absence"
    REACQUIRE = "independent_pen_reacquire"
    UNCHANGED = "verify_unchanged"
    CLOSE_PRIVATE_ADB = "close_exact_private_adb_server"
    HOST_START = "host_start_display"
    PLACE = "host_place"
    RESTORE = "host_restore_full_and_begin_close"
    TASK_ABSENT = "host_prove_task_absent"
    RELEASE_DISPLAY = "host_ack_absent_release_display"
    LAUNCH = "root_causal_launch"
    ATTACH = "root_prove_causal_attach"
    DESTROY_TASK = "root_destroy_exact_task"
    REOPEN = "ordinary_stock_reopen"


ROLES = {
    "reader": frozenset((Operation.PREFLIGHT, Operation.PRELAUNCH, Operation.EXACT_TASK,
                          Operation.FINAL_ABSENCE, Operation.REACQUIRE, Operation.UNCHANGED, Operation.CLOSE_PRIVATE_ADB)),
    "host": frozenset((Operation.HOST_START, Operation.PLACE, Operation.RESTORE,
                        Operation.TASK_ABSENT, Operation.RELEASE_DISPLAY)),
    "supervisor": frozenset((Operation.LAUNCH, Operation.ATTACH, Operation.DESTROY_TASK)),
    "reopen": frozenset((Operation.REOPEN,)),
}


class RetainedPort(Protocol):
    """Fixed operations only; deadline includes RPC, EOF, and exact worker join.

    Reader adapts S1/S1c; host adapts S3; supervisor adapts reviewed root launch
    ownership. Reopen is a separately retained, independently pinned port. No port may
    kill pen processes, the stock process, or an unproven task. Receipt envelope
    authenticity comes from retained S1/S2 authority, never its digest alone.
    stage_evidence reads the retained identity, including after exact owner exit;
    it never reacquires a PID/path or starts a replacement. Its context retains
    the original stage deadline; deadline_ns bounds this read, not a new launch.
    """
    RESOURCE_INVENTORY_SLOT: str
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def perform(self, operation: Operation, request: bytes, deadline_ns: int) -> bytes: ...
    def retained_resources(self) -> tuple["RetainedResource", ...]: ...
    def stage_evidence(self, context: "StageContext", deadline_ns: int) -> bytes: ...


@dataclass(frozen=True)
class ResourceClosure:
    binding: c.ResourceBinding
    request_sha256: str
    observed_ns: int
    absent: bool
    joined: bool
    channels_closed: bool
    evidence_sha256: str


class RetainedResource(Protocol):
    """The owning adapter retains the real handle; a declaration is not ownership.

    verify/binding remain available on an exited retained handle. prove_absent
    observes that exact handle plus owner-specific channel/file absence, never a
    PID lookup or a coordinator-supplied success digest. No cleanup method exists.
    """
    BINDING_SLOT: str
    def verify(self) -> None: ...
    def binding(self) -> c.ResourceBinding: ...
    def prove_absent(self, request: bytes, deadline_ns: int) -> ResourceClosure: ...


@dataclass(frozen=True)
class Selection:
    """Reviewed allowlist entry, not arbitrary user shell/URI text."""
    document_uri: str
    page_index: int

    def __post_init__(self):
        _need(type(self.document_uri) is str and re.fullmatch(
            r"file:///storage/emulated/0/Document/[A-Za-z0-9_/-]+\.pdf", self.document_uri) is not None
            and ".." not in self.document_uri and "//" not in self.document_uri[7:], "allowlisted PDF URI required")
        _need(type(self.page_index) is int and 0 <= self.page_index < 10_000_000, "allowlisted page required")

    def wire(self): return dict(documentUri=self.document_uri, pageIndex=self.page_index)


@dataclass(frozen=True)
class StageContext:
    contract: c.RunContract
    stage_index: int
    binding: runner.StageBinding
    foreign_raw: bytes
    placement_raw: bytes
    run_nonce: str
    previous_stage_closures_raw: bytes
    forbidden_owners_raw: bytes
    selection_raw: bytes
    causal_raw: bytes


def stage_epoch(context):
    """Closed v1 transition: only stage workers and the torn-down Frida epoch.

    Shared ADB/observer/pen/target/host/file authorities NEVER rotate here.
    This is not permission to resurrect a prior PID/start or reuse its staging.
    """
    stage = context.contract.value["stages"][context.stage_index]
    token = c.digest(dict(authority="rtl-reader-frida-stage-epoch-v1", runSessionId=context.contract.value["runSessionId"],
        stageIndex=context.stage_index, commandId=stage["commandId"], runNonce=context.run_nonce))
    return dict(authority="rtl-reader-frida-stage-epoch-v1", epoch=token,
        providerSessionId="stage-provider:" + token, serverSessionId="stage-server:" + token,
        controlId="stage-control:" + token, stagingPath="/data/local/tmp/rtl-reader-frida-" + token,
        predecessorClosures=c.load_canonical(context.previous_stage_closures_raw))


def context_sha256(context):
    return c.digest(dict(contractSha256=context.contract.sha256, stageIndex=context.stage_index,
        deadlineNs=str(context.binding.absolute_deadline_ns), runNonce=context.run_nonce,
        foreign=c.load_canonical(context.foreign_raw), placement=c.load_canonical(context.placement_raw),
        epoch=stage_epoch(context), forbiddenOwners=c.load_canonical(context.forbidden_owners_raw),
        selection=c.load_canonical(context.selection_raw), causal=c.load_canonical(context.causal_raw)))


def stage_creation_window(context, recovery_owner_sha256):
    c._sha(recovery_owner_sha256)
    value=dict(authority="rtl-reader-stage-creation-window-v1",schemaVersion=1,
        runSessionId=context.contract.value["runSessionId"],contractSha256=context.contract.sha256,
        stageIndex=context.stage_index,runNonce=context.run_nonce,contextSha256=context_sha256(context),
        absoluteDeadlineNs=str(context.binding.absolute_deadline_ns),recoveryOwnerSha256=recovery_owner_sha256,
        expectedBatches=[dict(owner="stage_authority",roles=["authority_worker"]),
                         dict(owner="stage_frida",roles=["frida_worker","root_frida_server"])])
    return dict(value,transactionId=c.digest(value))


def _creation_window(value, plan):
    c._keys(value,"authority schemaVersion runSessionId contractSha256 stageIndex runNonce contextSha256 "
        "absoluteDeadlineNs recoveryOwnerSha256 expectedBatches transactionId")
    _same(value["authority"],"rtl-reader-stage-creation-window-v1");_same(value["schemaVersion"],1)
    _same(value["runSessionId"],plan["runSessionId"]);_same(value["contractSha256"],c.digest(plan))
    c._int(value["stageIndex"],0,3)
    for key in ("runNonce","contextSha256","recoveryOwnerSha256","transactionId"):c._sha(value[key])
    _need(c._decimal(value["absoluteDeadlineNs"])<=int(plan["absoluteRunDeadlineNs"]),"creation deadline exceeds original run")
    _same(value["expectedBatches"],[dict(owner="stage_authority",roles=["authority_worker"]),
        dict(owner="stage_frida",roles=["frida_worker","root_frida_server"])])
    _same(value["transactionId"],c.digest({key:item for key,item in value.items() if key!="transactionId"}))


def _materialized_receipt(value, window):
    c._keys(value,"authority schemaVersion transactionId windowSha256 recoveryOwnerSha256 contextSha256 "
        "absoluteDeadlineNs acquisitionState ownerSequence batches")
    _same(value["authority"],"rtl-reader-stage-owner-materialization-v1");_same(value["schemaVersion"],1)
    for key in ("transactionId","recoveryOwnerSha256","contextSha256","absoluteDeadlineNs"):_same(value[key],window[key])
    _same(value["windowSha256"],c.digest(window))
    _same(value["acquisitionState"],"acquired-retained-unexposed")
    _same(value["ownerSequence"],window["stageIndex"]+1)
    _need(type(value["batches"]) is list and len(value["batches"])==2,"complete materialization owner batches required")
    bindings=[]
    for batch,expected in zip(value["batches"],window["expectedBatches"]):
        c._keys(batch,"owner bindings");_same(batch["owner"],expected["owner"])
        bindings.extend(_ordered_bindings(batch["bindings"],expected["roles"]))
    c.validate_resource_bindings(tuple(bindings))
    return tuple(bindings)


def selection_authority(context, manifest_sha256):
    """S8 authority, not a field added to the closed frozen-v2 manifest.

    Requested page is zero-based. Raw graph page indices remain calibration
    observations and are never asserted equal to this requested index.
    """
    selection = c.load_canonical(context.selection_raw)
    c._keys(selection,"documentUri pageIndex"); Selection(selection["documentUri"],selection["pageIndex"])
    c._sha(manifest_sha256)
    stage = context.contract.value["stages"][context.stage_index]
    return dict(authority="rtl-reader-native-page-stage-selection-v1", schemaVersion=1,
        runSessionId=context.contract.value["runSessionId"], contractSha256=context.contract.sha256,
        documentUri=selection["documentUri"], requestedPageIndex=selection["pageIndex"],
        stageIndex=context.stage_index, stage=stage["stage"], contextSha256=context_sha256(context),
        manifestSha256=manifest_sha256, causalLaunchAttach=c.load_canonical(context.causal_raw))


@dataclass(frozen=True)
class PredispatchView:
    context_sha256: str
    deadline_ns: int
    record: runner.CanonicalAuthority
    task: runner.DocumentTaskAuthority


@dataclass(frozen=True)
class StageBundle:
    """S7 AuthorityProvider and S6 FridaProvider over exact S2 worker factories.

    The reviewed factory constructs a new manifest/Configuration for this exact
    context. Provisionally injected runtime IDs are authority_worker-v1 and
    frida_worker-v1; arbitrary executable/module names are not accepted here.
    The selected providers additionally implement predispatch, verify_retained,
    and retained_resources. These methods inspect already-retained authority;
    they MUST NOT admit/capture/attach/load or start a replacement process. The
    Frida adapter applies the context's forbidden-owner set immediately after
    its exact stage-epoch start and before any attach. Current production S6
    does not supply that capability: execute remains explicitly blocked.
    """
    manifest: runner.LoadedJson
    observer_source: str
    observer_sha256: str
    tool_bundle: runner.LockedToolBundle
    authority_provider: runner.AuthorityProvider
    frida_provider: runner.FridaProvider
    trusted_pins: runner.TrustedPins
    resources: tuple[c.ResourceBinding, ...]
    # Narrow provisional seam. Both selected providers must expose retained
    # resources and an authenticated pre-dispatch record, without admission/RPC.
    worker_transitions_raw: bytes


class StageFactory(Protocol):
    """Pure selection facade; all creation is delegated to StageCreationOwner.

    A factory is not a process owner and cannot attest acquisitions. A reviewed
    production implementation must lack any creation route outside that owner's
    pre-armed lifetime. Arbitrary Python injected code is not such a boundary.
    """
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def prepare(self, context: StageContext, deadline_ns: int) -> StageBundle: ...


class StageCreationOwner(Protocol):
    """Independent pinned acquisition authority, never factory-authored truth.

    open_window arms an independently durable/kill-on-owner-loss lifetime for
    every expected role before materialization. The owner, not the factory,
    creates and retains the exact resources. It authenticates its acquired,
    unexposed receipt and publishes it through the one-shot capability before
    exposing handles. A lost coordinator leaves this owner responsible; window
    loss cannot be treated as successful cleanup. Existing adapters lack this
    reviewed OS-backed interface and are not production-admitted.
    """
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def open_window(self, window: bytes, publish: Callable[[bytes], str], deadline_ns: int) -> bytes: ...
    def authenticate_materialization(self, window: bytes, receipt: bytes, deadline_ns: int) -> None: ...
    def materialize(self, context: StageContext, deadline_ns: int) -> StageBundle: ...


@dataclass(frozen=True)
class Dependencies:
    reader: RetainedPort
    host: RetainedPort
    supervisor: RetainedPort
    reopen: RetainedPort
    stages: StageFactory
    pen_peer: pen.PenPeer
    clock: Callable[[], c.HostInstant]
    nonce: Callable[[], str]
    private_adb_resource: c.ResourceBinding
    # Diagnostic test seam only. The hardware entry is blocked even when the
    # genuine frozen function is injected; a callable cannot grant admission.
    run_stage: Callable = runner.run_one_stage
    creation_owner: StageCreationOwner | None = None
    creation_owner_sha256: str | None = None


PORT_METHODS = ("verify", "canonical_bytes", "perform", "retained_resources", "stage_evidence")
AUTHORITY_METHODS = ("admission", "capture", "cancel_and_quiesce", "assert_quiescent",
    "fail_stop_and_quiesce", "predispatch", "verify_retained", "retained_resources")
FRIDA_METHODS = ("admission", "attach", "teardown", "assert_quiescent", "predispatch", "verify_retained", "retained_resources")
SESSION_METHODS = ("load", "seal_callbacks", "unload", "detach", "assert_quiescent")


class _Endpoint:
    """Coordinator-created dispatch facade; never resolves methods on the peer."""
    def __init__(self, owner, invoke, names): self._owner, self._invoke, self._names = owner, invoke, names
    def __getattr__(self, name):
        _need(name in self._names, "unretained endpoint operation")
        return lambda *args, **kwargs:self._invoke(self._owner,name,*args,**kwargs)


class _CapturedAuthority:
    """Retain exact authenticated captures without bypassing runner validation."""
    def __init__(self, target, fence, validate, cleanup):
        self.target, self.captures, self.fence, self.validate = target, [], fence, validate
        self.cleanup = cleanup
        self.sealed = False
    def admission(self, timeout_ms, start_permit):
        _need(not self.sealed, "mismatched capture permanently sealed provider admission")
        return _guarded(self.fence, lambda:self.target.admission(timeout_ms, start_permit))
    def capture(self, request, timeout_ms, start_permit):
        _need(not self.sealed, "mismatched capture permanently sealed provider capture")
        try:
            self.fence()
            result = _guarded(self.fence, lambda:self.target.capture(request, timeout_ms, start_permit))
            retained = runner._snapshot_stage_capture(result)
            # This check precedes publication to the frozen runner. Its before
            # capture therefore cannot authorize attach/load for another owner,
            # even when a producer rebuilt the raw task digest or policy pin.
            self.fence(); self.validate(retained)
            self.captures.append(retained)
            return retained
        except BaseException:
            self.sealed = True
            raise
    def cancel_and_quiesce(self, timeout_ms):
        return self.cleanup(self.target.cancel_and_quiesce, timeout_ms)
    def assert_quiescent(self, timeout_ms):
        return self.cleanup(self.target.assert_quiescent, timeout_ms)
    def fail_stop_and_quiesce(self, timeout_ms):
        return self.cleanup(self.target.fail_stop_and_quiesce, timeout_ms)


def _guarded(fence, operation):
    """The same immutable ownership fence surrounds success AND failure."""
    fence()
    try: return operation()
    finally: fence()


class _FencedSession:
    def __init__(self, target, fence, can_start, cleanup):
        self.target, self.fence, self.can_start, self.cleanup = target, fence, can_start, cleanup
    def load(self, source, on_message, timeout_ms, start_permit):
        self.can_start()
        return _verified_none(_guarded(self.fence, lambda:self.target.load(source, on_message, timeout_ms, start_permit)))
    def seal_callbacks(self, timeout_ms):
        return self.cleanup(self.target.seal_callbacks, timeout_ms)
    def unload(self, timeout_ms):
        return self.cleanup(self.target.unload, timeout_ms)
    def detach(self, timeout_ms):
        return self.cleanup(self.target.detach, timeout_ms)
    def assert_quiescent(self, timeout_ms):
        return self.cleanup(self.target.assert_quiescent, timeout_ms)


class _FencedFrida:
    def __init__(self, target, fence, can_start, cleanup, wrap_session=lambda x:x):
        self.target, self.fence, self.can_start, self.cleanup = target, fence, can_start, cleanup
        self.wrap_session = wrap_session
    def admission(self, timeout_ms, start_permit):
        self.can_start(); return _guarded(self.fence, lambda:self.target.admission(timeout_ms, start_permit))
    def attach(self, serial, pid, timeout_ms, start_permit):
        self.can_start()
        target = _guarded(self.fence, lambda:self.target.attach(serial, pid, timeout_ms, start_permit))
        return _FencedSession(self.wrap_session(target), self.fence, self.can_start, self.cleanup)
    def teardown(self, timeout_ms):
        return self.cleanup(self.target.teardown, timeout_ms)
    def assert_quiescent(self, timeout_ms):
        return self.cleanup(self.target.assert_quiescent, timeout_ms)


class _PenResource:
    """Adapt authenticated S4 closure, not arbitrary captured absence flags."""
    BINDING_SLOT = "value"
    def __init__(self, coordinator, binding): self.coordinator, self.value = coordinator, binding
    def binding(self): return self.value
    def verify(self):
        co = self.coordinator
        co._verify_pen_identity()
    def prove_absent(self, request, deadline_ns):
        self.verify(); co = self.coordinator
        proof = co._pen_closure
        peer = co._endpoint("pen_peer")
        _need(type(proof) is pen.ClosureProof and proof.peer == peer.binding.peer and
              proof.exit_code == 0 and type(proof.exit_code) is int and proof.output_eof is True and
              proof.trailing_output == b"" and peer.state is pen.Lifecycle.RELEASED,
              "S4 exact worker/guardian/peer release and EOF missing")
        return ResourceClosure(self.value, _sha(request), co._live(deadline_ns), True, True, True,
                               c.digest(dict(binding=co._pen_binding, peerExit=0, eof=True)))


class EventJournal:
    """Append-only S8 semantics on real S5b deny-write/delete retained stores."""
    def __init__(self, store, contract, selection, *, recover=False):
        _need(type(store) is WindowsCleanupStore, "reviewed S5b store required")
        self.store, self.contract, self.selection = store, contract, selection
        self.records, self.usable = [], True
        if recover:
            checkpoint = store.load_checkpoint()
            with store.exclusive(): self.records = self._read()
            _need(self.records and checkpoint.sequence == len(self.records) - 1 and
                  checkpoint.record_sha256 == self.records[-1]["hash"], "journal checkpoint must bind exact tail")
            _same(self.records[0]["data"], self._opening(), "journal belongs to another plan")
        else:
            with store.exclusive(): _need(not store.names(), "journal must be new")
            self.append("s8_opened", self._opening(), ())

    def _opening(self):
        return dict(ledger_id=self.contract.value["runSessionId"][:32], authority=AUTHORITY,
                    contract=self.contract.value, selection=self.selection.wire())

    def _read(self, *, validate=True):
        names = self.store.names()
        _need(type(names) is list and len(names) == len(set(names)), "journal inventory differs")
        published = sorted(name for name in names if re.fullmatch(r"[0-9]{20}\.json", name))
        _need(all(name in published or re.fullmatch(r"\.pending-[0-9a-f]{32}", name) for name in names), "unknown journal file")
        _need(published == [f"{i:020d}.json" for i in range(len(published))], "journal gap")
        records, previous, terminal = [], ledger.ZERO_HASH, False
        for i, name in enumerate(published):
            record = ledger.decode_record(self.store.read(name))
            _need(not terminal, "journal contains a post-terminal publication")
            _need(record["sequence"] == i and record["previous_hash"] == previous, "journal replay/hash link")
            if validate: self._validate(record)
            records.append(record); previous = record["hash"]
            terminal = record["event"] in ("s8_finished", "s8_quarantine")
        return records

    @staticmethod
    def _validate(record):
        schemas = {
            "s8_opened": "ledger_id authority contract selection",
            "s8_intent": "operation deadlineNs request", "s8_result": "operation intentSha256 receipt",
            "s8_pen": "operation binding sequence deviceBoottimeMs",
            "s8_owned": "role key owner identity checkpoint inventoryRecordSha256", "s8_stage": "stageIndex evidence",
            "s8_owner_closed": "key owner identity requestSha256 observedNs evidenceSha256 absent joined channelsClosed",
            "s8_stage_admitted": "stageIndex evidence",
            "s8_cleanup_proof": "stepIndex details",
            "s8_model": "authority schemaVersion contractSha256 runSessionId sequence previousEventSha256 observedHostNs kind body",
            "s8_finished": "authority schemaVersion runSessionId contractSha256 status admission stageEvidenceSha256 selection stageSelectionSha256 ownershipCheckpoint eventHeadSha256 remaining files noRetry",
            "s8_quarantine": "reason retained pendingOperations pendingInventoryBatches recoveryRequired",
            "s8_inventory_batch": "owner bindings inventorySha256 ownershipComplete sourceRecordSha256",
            "s8_creation_window": "window prepareIntentSha256",
            "s8_creation_materialized": "windowRecordSha256 receipt",
            "s8_inventory_retired": "sourceRecordSha256 keys checkpoint",
        }
        event, data = record["event"], record["data"]
        _need(type(event) is str and event in schemas, "unknown journal event")
        c._keys(data, schemas[event])
        _need(record["remaining"] == sorted(set(record["remaining"])), "journal obligation list differs")
        for value in record["remaining"]: c._sha(value)
        if event == "s8_opened":
            _same(data["authority"], AUTHORITY)
            _need(record["sequence"] == 0, "duplicate journal opening")
            c.RunContract(c.canonical_bytes(data["contract"]))
        elif event == "s8_intent":
            _need(type(data["operation"]) is str and data["operation"], "operation identity required")
            c._decimal(data["deadlineNs"])
            _need(type(data["request"]) is dict, "typed intent scope required")
        elif event == "s8_result":
            c._sha(data["intentSha256"])
            c._keys(data["receipt"], "authority requestSha256 runSessionId commandId observedHostNs body")
        elif event == "s8_owned":
            c.ResourceBinding(data["role"], data["owner"], c.ResourceIdentity.parse(data["identity"]))
            c._keys(data["checkpoint"], "ledgerId sequence sha256")
            c._sha(data["checkpoint"]["sha256"]); c._int(data["checkpoint"]["sequence"])
            if data["inventoryRecordSha256"] is not None:c._sha(data["inventoryRecordSha256"])
        elif event == "s8_creation_window":
            c._sha(data["prepareIntentSha256"]);c._sha(data["window"]["transactionId"])
        elif event == "s8_creation_materialized":
            c._sha(data["windowRecordSha256"]);c._sha(data["receipt"]["transactionId"])
        elif event == "s8_inventory_retired":
            c._sha(data["sourceRecordSha256"])
            _need(type(data["keys"]) is list,"exact retired inventory keys required")
            c._keys(data["checkpoint"],"ledgerId sequence sha256")
            c._int(data["checkpoint"]["sequence"]);c._sha(data["checkpoint"]["sha256"])
        elif event == "s8_owner_closed":
            c.ResourceIdentity.parse(data["identity"]); c._sha(data["requestSha256"]); c._sha(data["evidenceSha256"])
            c._decimal(data["observedNs"])
            for key in ("absent", "joined", "channelsClosed"): _same(data[key], True)
        elif event in ("s8_stage", "s8_stage_admitted"):
            c._int(data["stageIndex"], 0, 3); decode_evidence(data["evidence"])
        elif event == "s8_cleanup_proof": c._int(data["stepIndex"], 0, 7)
        elif event == "s8_quarantine":
            _same(data["recoveryRequired"], True)
            _need(type(data["reason"]) is str and data["reason"] and type(data["retained"]) is list and
                  type(data["pendingOperations"]) is list, "quarantine classification differs")
            for identity in data["retained"]: c.ResourceIdentity.parse(identity)
            _need(type(data["pendingInventoryBatches"]) is list,"exact pending inventories required")
            for batch in data["pendingInventoryBatches"]:
                c._keys(batch,"owner bindings unresolvedHandleCount state ownershipComplete")
                _need(type(batch["owner"]) is str and batch["owner"] in
                      ("reader","host","supervisor","reopen","stage_authority","stage_frida") and
                      batch["state"] in ("creation_pending","rejected_unresolved") and batch["ownershipComplete"] is False,
                      "pending inventory owner/classification differs")
                c._int(batch["unresolvedHandleCount"],0,128)
                _need(type(batch["bindings"]) is list,"pending inventory bindings differ")
                for binding in batch["bindings"]:
                    c._keys(binding,"role owner identity")
                    c.ResourceBinding(binding["role"],binding["owner"],c.ResourceIdentity.parse(binding["identity"]))
        elif event == "s8_inventory_batch":
            _need(type(data["owner"]) is str and type(data["bindings"]) is list and data["ownershipComplete"] is False,
                  "pending inventory batch differs")
            for binding in data["bindings"]:
                c._keys(binding,"role owner identity")
                c.ResourceBinding(binding["role"],binding["owner"],c.ResourceIdentity.parse(binding["identity"]))
            _same(data["inventorySha256"],c.digest(data["bindings"]))
            if data["sourceRecordSha256"] is not None:c._sha(data["sourceRecordSha256"])
        elif event == "s8_finished":
            _same(data["authority"], AUTHORITY); _same(data["schemaVersion"], 1)
            _same(data["status"], "CLEAN"); _same(data["remaining"], []); _same(data["noRetry"], True)
            _same(data["admission"], admission_status())

    @property
    def head(self): return self.records[-1]["hash"]

    def append(self, event, data, remaining):
        _need(self.usable, "uncertain journal is sealed")
        _need(not self.records or self.records[-1]["event"] not in ("s8_finished", "s8_quarantine"),
              "persisted terminal decision forbids later publication")
        handle = None
        try:
            with self.store.exclusive():
                # Every prefix record was semantically validated on admission.
                # Re-read and authenticate each exact record/hash, without
                # redundantly decoding every embedded native graph again.
                actual = self._read(validate=False)
                _need(len(actual) == len(self.records) and all(a["hash"] == b["hash"]
                      for a, b in zip(actual, self.records)), "journal instance is stale")
                record = dict(version=1, sequence=len(self.records), previous_hash=self.head if self.records else ledger.ZERO_HASH,
                              event=event, data=_copy(data), remaining=sorted(remaining))
                self._validate(record)
                record["hash"] = _sha(ledger.canonical_json(record))
                raw = ledger.canonical_json(record)
                _need(len(raw) <= ledger.MAX_RECORD_BYTES, "journal record exceeds durable bound")
                temporary = ".pending-" + record["hash"][:32]
                handle = self.store.create(temporary)
                offset = 0
                while offset < len(raw):
                    count = self.store.write(handle, raw[offset:])
                    _need(type(count) is int and 0 < count <= len(raw) - offset, "journal write made no exact progress")
                    offset += count
                self.store.fsync_file(handle); self.store.close(handle); handle = None
                self.store.rename_no_replace(temporary, f"{len(self.records):020d}.json")
                self.store.fsync_directory()
            checkpoint = self.store.load_checkpoint()
            _need(checkpoint.record_sha256 == record["hash"] and checkpoint.sequence == len(self.records), "journal checkpoint differs")
            self.records.append(record)
            return record["hash"]
        except BaseException:
            self.usable = False
            if handle is not None:
                try: self.store.close(handle)
                except BaseException: pass
            raise


def _ownership_prefix(read, checkpoint):
    """Bind every S8 registration link to the independently recovered S5 chain."""
    records=[]; previous=ledger.ZERO_HASH
    for sequence in range(checkpoint.sequence+1):
        record=ledger.decode_record(read(f"{sequence:020d}.json"))
        _need(record["sequence"]==sequence and record["previous_hash"]==previous,
              "ownership prefix sequence/hash differs")
        records.append(record);previous=record["hash"]
    _need(previous==checkpoint.record_sha256 and records[0]["data"]["ledger_id"]==checkpoint.ledger_id,
          "ownership prefix does not reach its independent checkpoint")
    return records


PENDING_INVENTORY_KEYS = (
    "owner state bindings unresolvedHandleCount ownershipComplete cleanupAuthority "
    "sourceRecordSha256 inventoryRecordSha256 ownershipRecordSha256 ownershipIdentity "
    "joinStatus expectedRoles expectedBatches reportedEvidenceSha256"
)
PENDING_INVENTORY_STATES = frozenset(("creation_result_missing","creation_window_unmaterialized",
    "creation_result_pending","materialized_pending","batch_registration_pending",
    "registered_pending_closure","stage_retirement_pending","ledger_registration_unlinked",
    "rejected_inventory_unresolved"))


def _pending_inventory(owner,state,bindings,*,unresolved=0,source=None,inventory=None,
                       ownership=None,identity=None,join="not_applicable",roles=(),expected=(),reported=None):
    """Uniform read-only recovery codec, never a cleanup authorization.

    owner is the retained port/creation-owner scope, except the ledger-unlinked
    arm where it is the exact S5 owner. bindings contains only authenticated S8
    role bindings. Unknown handles are counted separately and never inferred.
    The three hash fields have distinct S8-source/S8-batch/S5-record domains.
    Unused fields are exact null/empty values, not optional or extensible keys.
    """
    return dict(owner=owner,state=state,bindings=bindings,unresolvedHandleCount=unresolved,
        ownershipComplete=state in ("registered_pending_closure","stage_retirement_pending"),cleanupAuthority=False,
        sourceRecordSha256=source,inventoryRecordSha256=inventory,ownershipRecordSha256=ownership,
        ownershipIdentity=identity,joinStatus=join,expectedRoles=list(roles),expectedBatches=list(expected),
        reportedEvidenceSha256=reported)


def _pending_inventory_context(records,ownership_records):
    # Only already-authenticated replay records enter this context. In
    # particular, rejected observations are never join candidates. A binding
    # repeated as an already-owned member of a later complete host inventory
    # is not a second registration origin.
    s8={record["hash"]:record for record in records}
    s5={record["hash"]:record for record in ownership_records}
    candidates=[];owned=set()
    for record in records:
        if record["event"]=="s8_owned":
            data=record["data"]
            owned.add(c.canonical_bytes(dict(role=data["role"],owner=data["owner"],identity=data["identity"])))
        elif record["event"]=="s8_inventory_batch":
            for binding in record["data"]["bindings"]:
                if c.canonical_bytes(binding) not in owned:candidates.append((record,binding))
    return s8,s5,tuple(candidates)


def _pending_registration_join(owner,identity,candidates):
    matches=[(record,binding) for record,binding in candidates
             if binding["owner"]==owner and binding["identity"]==identity]
    if len(matches)!=1:return ("absent" if not matches else "ambiguous"),None,None,[]
    record,binding=matches[0]
    return "unique",record["data"]["sourceRecordSha256"],record["hash"],[binding]


def _validate_pending_inventory(value,context):
    """Exact discriminated validation, including reference-domain resolution."""
    c._keys(value,PENDING_INVENTORY_KEYS)
    state=value["state"];_need(type(state) is str and state in PENDING_INVENTORY_STATES,"unknown pending inventory state")
    _need(type(value["owner"]) is str and value["owner"],"pending owner required")
    _need(type(value["bindings"]) is list,"pending bindings must be an exact list")
    bindings=[]
    for item in value["bindings"]:
        c._keys(item,"role owner identity")
        bindings.append(c.ResourceBinding(item["role"],item["owner"],c.ResourceIdentity.parse(item["identity"])))
    c.validate_resource_bindings(tuple(bindings))
    c._int(value["unresolvedHandleCount"],0,1024)
    _need(value["cleanupAuthority"] is False,"recovery report cannot authorize cleanup")
    _need(type(value["ownershipComplete"]) is bool and
          value["ownershipComplete"]==(state in ("registered_pending_closure","stage_retirement_pending")),
          "pending ownership completeness differs")
    s8,s5,candidates=context
    source=value["sourceRecordSha256"];inventory=value["inventoryRecordSha256"];ownership=value["ownershipRecordSha256"]
    for reference,domain,other in ((source,s8,s5),(inventory,s8,s5),(ownership,s5,s8)):
        if reference is not None:
            c._sha(reference);_need(reference in domain and reference not in other,"pending reference has wrong record domain")
    if inventory is not None:_need(s8[inventory]["event"]=="s8_inventory_batch","pending inventory reference is not a batch")
    _need(type(value["expectedRoles"]) is list and type(value["expectedBatches"]) is list,"pending expectations must be exact lists")
    if state=="ledger_registration_unlinked":
        _need(ownership is not None and s5[ownership]["event"]=="registered","unlinked registration lacks exact S5 record")
        actual=s5[ownership]["data"]
        _same(value["owner"],actual["owner"]);_same(value["ownershipIdentity"],actual["identity"])
        c.ResourceIdentity.parse(value["ownershipIdentity"])
        join,joined_source,joined_inventory,joined_bindings=_pending_registration_join(actual["owner"],actual["identity"],candidates)
        _same(value["joinStatus"],join);_same(source,joined_source);_same(inventory,joined_inventory)
        _same(value["bindings"],joined_bindings)
        _same(value["unresolvedHandleCount"],0 if join=="unique" else 1)
    else:
        _need(ownership is None and value["ownershipIdentity"] is None and value["joinStatus"]=="not_applicable",
              "non-registration arm contains S5/join fields")
    if state=="creation_result_missing":
        _need(source is not None and s8[source]["event"]=="s8_intent" and inventory is None,"missing-result source differs")
        operation=s8[source]["data"]["operation"]
        expected={Operation.HOST_START.value:("host",["virtual_display"]),Operation.ATTACH.value:("supervisor",["foreign_task"]),
                  Operation.LAUNCH.value:("supervisor",["foreign_task"])}
        _need(operation in expected,"missing-result operation differs")
        owner,roles=expected[operation];_same(value["owner"],owner);_same(value["expectedRoles"],roles)
        _same(value["bindings"],[]);_same(value["unresolvedHandleCount"],len(roles))
    elif state=="creation_window_unmaterialized":
        _need(source is not None and s8[source]["event"]=="s8_creation_window" and inventory is None,"window source differs")
        expected=s8[source]["data"]["window"]["expectedBatches"]
        _same(value["owner"],"stage_creation_owner");_same(value["expectedBatches"],expected)
        _same(value["bindings"],[]);_same(value["unresolvedHandleCount"],sum(len(batch["roles"]) for batch in expected))
    elif state in ("creation_result_pending","materialized_pending","batch_registration_pending","registered_pending_closure","stage_retirement_pending"):
        _same(value["unresolvedHandleCount"],0)
        if source is None:
            _need(state=="batch_registration_pending" and inventory is not None and
                  s8[inventory]["data"]["sourceRecordSha256"] is None,"baseline pending batch differs")
            expected=[s8[inventory]["data"]]
        else:
            _need(inventory is None,"aggregate source cannot name one selected batch")
            record=s8[source]
            if record["event"]=="s8_result":
                _need(state in ("creation_result_pending","batch_registration_pending","registered_pending_closure"),"result state differs")
                operation=record["data"]["operation"]
                _need(operation in (Operation.HOST_START.value,Operation.ATTACH.value),"not a creation result")
                expected=[dict(owner="host" if operation==Operation.HOST_START.value else "supervisor",
                               bindings=record["data"]["receipt"]["body"]["ownerInventory"])]
            else:
                _need(record["event"]=="s8_creation_materialized" and state!="creation_result_pending","materialization source/state differs")
                expected=record["data"]["receipt"]["batches"]
        _same(value["owner"],expected[0]["owner"] if len(expected)==1 else "stage_creation_owner")
        _same(value["bindings"],[binding for batch in expected for binding in batch["bindings"]])
    elif state=="rejected_inventory_unresolved":
        _same(value["owner"],"coordinator");_same(value["bindings"],[])
        _need(source is None and inventory is None,"rejected evidence cannot claim an identity/source")
        c._sha(value["reportedEvidenceSha256"])
    if state!="creation_result_missing":_same(value["expectedRoles"],[])
    if state!="creation_window_unmaterialized":_same(value["expectedBatches"],[])
    if state!="rejected_inventory_unresolved":_need(value["reportedEvidenceSha256"] is None,"wrong-state rejected evidence")


def _replay_creations(records, plan, ownership_records, checkpoint):
    """Closed creation/registration/retirement protocol; no recovery mutations.

    Creation receipts preserve exact acquisition obligations before registration.
    A window without its independent owner's receipt preserves only the expected
    roles: it never guesses identities or grants per-resource cleanup authority.
    """
    intents={}; results=set(); sources={}; windows={}; batches={}; owned={}; closed={}
    baseline=[]; linked=set(); admitted_slots={}; stage_sources=[]
    baseline_spec=(("supervisor",()),("reopen",()),("reader",("private_adb_server",)),("host",("host_session",)))
    def point(value):
        c._keys(value,"ledgerId sequence sha256")
        _need(type(value["sequence"]) is int and 0<=value["sequence"]<len(ownership_records),
              "ownership checkpoint sequence unavailable")
        _same(value["ledgerId"],checkpoint.ledger_id)
        record=ownership_records[value["sequence"]]
        _same(value["sha256"],record["hash"])
        return record
    def binding_id(binding):return ledger.ResourceIdentity.parse(binding["identity"]).resource_id
    def remember(binding):
        identity=c.ResourceIdentity.parse(binding["identity"])
        slot=(identity.kind,identity.namespace,identity.key)
        old=admitted_slots.get(slot)
        _need(old is None or c.canonical_bytes(old)==c.canonical_bytes(binding),"creation retained slot reused/cross-owned")
        admitted_slots[slot]=binding
    def source(record_hash,expected,kind,stage=None):
        _need(record_hash not in sources,"creation source replay")
        for batch in expected:
            for binding in batch["bindings"]:remember(binding)
        sources[record_hash]=dict(expected=expected,published=[],kind=kind,stage=stage,retired=False)
    def successful(binding,through):
        key=binding_id(binding)
        return any(r["event"]=="cleanup_decision" and r["data"]["resource"]==key and
                   r["data"]["owner"]==binding["owner"] and r["data"]["success"] is True
                   for r in ownership_records[:through+1])
    for record in records:
        event,data,record_hash=record["event"],record["data"],record["hash"]
        if event=="s8_intent":
            _need(data["operation"] not in intents,"creation operation replay")
            intents[data["operation"]]=record
        elif event=="s8_result":
            operation=data["operation"]
            _need(operation in intents and operation not in results,"orphan/replayed creation result")
            intent=intents[operation];_same(data["intentSha256"],intent["hash"])
            receipt=data["receipt"]
            _same(receipt["authority"],RECEIPT_AUTHORITY)
            _same(receipt["requestSha256"],c.digest(intent["data"]["request"]))
            _same(receipt["commandId"],operation);_same(receipt["runSessionId"],plan["runSessionId"])
            creation=_port_creation(operation,intent["data"]["request"]["request"],receipt["body"],plan)
            if creation is not None:source(record_hash,[creation],"creation_result_pending")
            results.add(operation)
        elif event=="s8_creation_window":
            window=data["window"];_creation_window(window,plan)
            stage=window["stageIndex"]
            _need(stage==len(windows) and (stage==0 or (len(stage_sources)==stage and sources[stage_sources[-1]]["retired"])),
                  "creation window reordered/before predecessor retirement")
            intent=intents.get(f"prepare_stage_{stage}")
            _need(intent is not None,"creation window lacks pre-call intent")
            _same(data["prepareIntentSha256"],intent["hash"])
            _same(window["absoluteDeadlineNs"],intent["data"]["deadlineNs"])
            _same(window["contextSha256"],intent["data"]["request"]["contextSha256"])
            _need(all(item["window"]["transactionId"]!=window["transactionId"] for item in windows.values()),"creation window replay")
            windows[record_hash]=dict(window=window,source=None)
        elif event=="s8_creation_materialized":
            window_entry=windows.get(data["windowRecordSha256"])
            _need(window_entry is not None and window_entry["source"] is None,"orphan/replayed materialization")
            _materialized_receipt(data["receipt"],window_entry["window"])
            source(record_hash,data["receipt"]["batches"],"materialized_pending",window_entry["window"]["stageIndex"])
            window_entry["source"]=record_hash;stage_sources.append(record_hash)
        elif event=="s8_inventory_batch":
            source_hash=data["sourceRecordSha256"]
            if source_hash is None:
                _need(len(baseline)<len(baseline_spec),"unrequested baseline inventory")
                owner,roles=baseline_spec[len(baseline)]
                _same(data["owner"],owner);_ordered_bindings(data["bindings"],roles)
                if owner=="host":
                    _same(data["bindings"],[dict(role="host_session",owner="host_authority",identity=c.ResourceIdentity(
                        "host_session",c.AUTHORIZED_SERIAL,plan["hostSessionId"],plan["runSessionId"]).wire())])
                for binding in data["bindings"]:remember(binding)
                baseline.append(record_hash)
            else:
                item=sources.get(source_hash)
                _need(item is not None and len(item["published"])<len(item["expected"]),"orphan/replayed inventory batch")
                expected=item["expected"][len(item["published"])]
                _same(dict(owner=data["owner"],bindings=data["bindings"]),expected,"creation inventory order/owner/bindings differ")
                item["published"].append(record_hash)
            required=[]
            for binding in data["bindings"]:
                old=next((value for value in owned.values() if value["binding"]==binding),None)
                if old is None:required.append(binding)
                else:_need(source_hash is not None and binding["role"]=="host_session","inventory resurrects an old binding")
            batches[record_hash]=dict(data=data,required=required,registered=[])
        elif event=="s8_owned":
            binding=dict(role=data["role"],owner=data["owner"],identity=data["identity"])
            _need(data["key"] not in owned,"ownership key replay")
            batch_hash=data["inventoryRecordSha256"]
            if data["owner"]=="pen_peer":
                _need(batch_hash is None and data["key"]==data["role"],"pen registration source differs")
                remember(binding)
            else:
                batch=batches.get(batch_hash)
                _need(batch is not None and len(batch["registered"])<len(batch["required"]),"orphan/replayed batch registration")
                _same(binding,batch["required"][len(batch["registered"])] ,"batch ownership registration reordered/copied")
                source_hash=batch["data"]["sourceRecordSha256"]
                stage=None if source_hash is None else sources[source_hash]["stage"]
                _same(data["key"],data["role"] if stage is None else f'{data["role"]}:{stage}')
                batch["registered"].append(data["key"])
            registration=point(data["checkpoint"])
            _need(registration["event"]=="registered" and registration["hash"] not in linked,
                  "S8 ownership link does not name a unique S5 registration")
            _same(registration["data"],dict(identity=data["identity"],owner=data["owner"],postcondition="absent",baseline_sha256=None))
            linked.add(registration["hash"]);owned[data["key"]]=dict(binding=binding,batch=batch_hash)
        elif event=="s8_owner_closed":
            item=owned.get(data["key"])
            _need(item is not None and data["key"] not in closed,"orphan/replayed closure")
            _same(data["owner"],item["binding"]["owner"]);_same(data["identity"],item["binding"]["identity"])
            closed[data["key"]]=True
        elif event=="s8_inventory_retired":
            item=sources.get(data["sourceRecordSha256"])
            _need(item is not None and item["stage"] is not None and not item["retired"],"orphan/replayed inventory retirement")
            _need(len(item["published"])==len(item["expected"]),"retirement before complete batch publication")
            expected=[f'{binding["role"]}:{item["stage"]}' for batch in item["expected"] for binding in batch["bindings"]]
            _same(data["keys"],expected);limit=point(data["checkpoint"])["sequence"]
            for key in expected:
                _need(key in owned and key in closed and successful(owned[key]["binding"],limit),"retirement before exact registered closure")
            item["retired"]=True
    pending=[]
    if Operation.LAUNCH.value in intents and Operation.ATTACH.value not in intents:
        pending.append(_pending_inventory("supervisor","creation_result_missing",[],source=intents[Operation.LAUNCH.value]["hash"],
                                          roles=("foreign_task",),unresolved=1))
    for operation,roles in ((Operation.HOST_START.value,["virtual_display"]),(Operation.ATTACH.value,["foreign_task"])):
        if operation in intents and operation not in results:
            pending.append(_pending_inventory("host" if operation==Operation.HOST_START.value else "supervisor",
                "creation_result_missing",[],source=intents[operation]["hash"],roles=roles,unresolved=len(roles)))
    for record_hash,item in windows.items():
        if item["source"] is None:
            expected=item["window"]["expectedBatches"]
            pending.append(_pending_inventory("stage_creation_owner","creation_window_unmaterialized",[],source=record_hash,
                expected=expected,unresolved=sum(len(batch["roles"]) for batch in expected)))
    for record_hash,item in sources.items():
        if item["retired"]:continue
        bindings=[binding for batch in item["expected"] for binding in batch["bindings"]]
        if len(item["published"])<len(item["expected"]):state=item["kind"]
        elif any(len(batches[value]["registered"])<len(batches[value]["required"]) for value in item["published"]):state="batch_registration_pending"
        elif any(not any(value["binding"]==binding and key in closed and successful(binding,checkpoint.sequence)
                        for key,value in owned.items()) for binding in bindings):state="registered_pending_closure"
        elif item["stage"] is not None:state="stage_retirement_pending"
        else:continue
        pending.append(_pending_inventory(item["expected"][0]["owner"] if len(item["expected"])==1 else "stage_creation_owner",
                                          state,bindings,source=record_hash))
    for record_hash in baseline:
        batch=batches[record_hash]
        if len(batch["registered"])<len(batch["required"]):
            pending.append(_pending_inventory(batch["data"]["owner"],"batch_registration_pending",batch["required"],inventory=record_hash))
    pending_context=_pending_inventory_context(records,ownership_records)
    for record in ownership_records:
        if record["event"]=="registered" and record["hash"] not in linked:
            data=record["data"]
            join,source,inventory,bindings=_pending_registration_join(data["owner"],data["identity"],pending_context[2])
            pending.append(_pending_inventory(data["owner"],"ledger_registration_unlinked",bindings,source=source,inventory=inventory,
                ownership=record["hash"],identity=data["identity"],join=join,unresolved=0 if join=="unique" else 1))
    for item in pending:_validate_pending_inventory(item,pending_context)
    complete=not pending and len(windows)==4 and len(baseline)==4 and all(
        key in closed and successful(value["binding"],checkpoint.sequence) for key,value in owned.items())
    return dict(complete=complete,pending=pending)


class VisualCoordinator:
    def __init__(self, contract, selection, dependencies, journal_store, ownership_store, port_pins,
                 *, stage_timeout_ms=1000):
        _need(type(contract) is c.RunContract and type(selection) is Selection and
              type(dependencies) is Dependencies, "exact immutable plan/dependencies required")
        _need(type(dependencies.pen_peer) is pen.PenPeer and
              dependencies.pen_peer.stage_session == pen.StageSession(contract.value["runSessionId"]),
              "exact shared-session S4 peer required")
        _need(type(dependencies.private_adb_resource) is c.ResourceBinding and
              dependencies.private_adb_resource.role == "private_adb_server" and
              dependencies.private_adb_resource.identity.namespace.startswith("windows-host/"),
              "exact retained S1 private-server ownership required")
        _need(type(ownership_store) is WindowsCleanupStore and ownership_store is not journal_store,
              "separate S5b ownership store required")
        _need(type(port_pins) is dict and set(port_pins) == {"reader", "host", "supervisor", "reopen", "stages"}, "exact retained port pins required")
        c._sha(dependencies.creation_owner_sha256)
        _need(dependencies.creation_owner is not None and dependencies.creation_owner is not dependencies.stages,
              "independently pinned stage creation owner required")
        _need(dependencies.reopen is not dependencies.supervisor, "ordinary reopen must have separate retained authority")
        for value in port_pins.values(): c._sha(value)
        c._int(stage_timeout_ms, c.MIN_DEADLINE_MS, c.MAX_DEADLINE_MS)
        store_check = _store_pair(journal_store, ownership_store)
        contract_view, contract_check, _ = _anchor(contract)
        selection_view, selection_check, _ = _anchor(selection)
        contract_raw, contract_hash = contract.raw, contract.sha256
        c.RunContract(contract_raw); Selection(selection.document_uri,selection.page_index)
        pin_view, pin_check, _ = _anchor(port_pins)
        self.contract, self.plan, self.selection, self.deps = contract, contract.value, selection, dependencies
        self.pins, self.stage_timeout_ms = _copy(port_pins), stage_timeout_ms
        plan_mirror, pin_mirror = self.plan, self.pins
        _, plan_check, _ = _anchor(plan_mirror); _, pin_mirror_check, _ = _anchor(pin_mirror)
        # The bytes were validated once above; a fresh builtin JSON value is
        # detached without repeatedly revalidating the immutable schema.
        self._plan = lambda:json.loads(contract_raw)
        self._contract_view, self._selection_view, self._pin_view = contract_view, selection_view, pin_view
        self._contract_hash = lambda:contract_hash
        roots = {f.name:object.__getattribute__(dependencies,f.name) for f in fields(Dependencies)}
        root_names = tuple(roots)
        pen_owner, transport = roots["pen_peer"], roots["pen_peer"].transport
        pen_values = (pen_owner.stage_session, pen_owner.token, pen_owner.hold_ms, transport.peer_identity)
        pen_value_guards = tuple(_anchor(value)[1] for value in pen_values)
        _, adb_check, _ = _anchor(roots["private_adb_resource"])
        guards, fast_guards, retained_methods, binding_returns, resource_slots = [], [], {}, {}, {}
        inventories, inventory_claims, rejected_inventories = {}, {}, []
        inventory_sources={}
        retired_inventory_handles=set()
        inventory_pending = {}
        def inventory_owner_name(owner):
            for role in ("reader","host","supervisor","reopen"):
                if owner is roots[role]:return role
            names=retained_methods.get(id(owner),(None,{}))[1]
            return "stage_authority" if "capture" in names else "stage_frida"
        def reject_inventory(owner,current):
            for prior in rejected_inventories:
                if prior[0] is owner and prior[1] is current:return prior
            bindings=[];unknown=0
            for handle in current:
                try:
                    binding,_=_resource_slot(handle)
                    bindings.append(_binding_wire(_anchor(binding)[0]()))
                except BaseException:unknown+=1
            observation=(owner,current,c.canonical_bytes(bindings),unknown)
            rejected_inventories.append(observation)
            return observation
        dispatch_lock=threading.RLock()
        total, last_stage_bound, owned, event_journal = None, None, None, None
        forbidden_pids = set()
        def basic():
            _need(self.deps is dependencies and type(self.deps) is Dependencies, "construction dependencies replaced")
            for name in root_names:
                _need(object.__getattribute__(dependencies,name) is roots[name], "construction endpoint replaced: "+name)
            _need(self.contract is contract and self.selection is selection and self.plan is plan_mirror and self.pins is pin_mirror,
                  "construction plan/selection/pin mirror replaced")
            contract_check(); selection_check(); plan_check(); pin_check(); pin_mirror_check(); adb_check(); store_check()
            _need(self.stage_timeout_ms == stage_timeout_ms and type(self.stage_timeout_ms) is int, "stage budget changed")
            _need(pen_owner.transport is transport and pen_owner.stage_session is pen_values[0] and
                  transport.peer_identity is pen_values[3] and type(pen_owner.token) is str and pen_owner.token == pen_values[1] and
                  type(pen_owner.hold_ms) is int and pen_owner.hold_ms == pen_values[2], "construction pen scope replaced")
            for check in pen_value_guards: check()
            if owned is not None:
                _need(self.ownership is owned and self._ownership_store is ownership_store and self._journal is event_journal,
                      "construction ledger/store replaced")
            if total is not None:
                _need(type(self._cleanup_deadline) is int and type(self._cleanup_original_deadline) is int and
                      self._cleanup_deadline == total and self._cleanup_original_deadline == total, "cleanup total deadline rebased")
            elif owned is not None:
                _need(self._cleanup_deadline is None and self._cleanup_original_deadline is None, "cleanup total not admitted")
        def retain(owner, names):
            basic()
            entry = retained_methods.setdefault(id(owner),(owner,{}))
            _need(entry[0] is owner, "retained owner ID reused")
            for name in names:
                if name in entry[1]: continue
                call,check=_method_anchor(owner,name)
                entry[1][name] = (call, check); guards.append(check)
        def root_check():
            basic()
            for check in fast_guards: check()
            for check in guards: check()
            basic()
        def retain_resource(owner):
            prior=resource_slots.get(id(owner))
            if prior is not None:
                _need(prior[0] is owner,"resource owner ID reused");prior[2]();return
            # No owner verifier/binding callback precedes this static admission.
            binding,check=_resource_slot(owner)
            resource_slots[id(owner)]=(owner,binding,check)
            binding_returns[id(owner)]=(binding,check)
            fast_guards.append(check)
            retain(owner,("verify","binding","prove_absent"))
        def retain_inventory(owner):
            entry=inventories.get(id(owner))
            if entry is not None:
                _need(entry[0] is owner,"inventory owner ID reused");return entry
            read=_inventory_slot(owner)
            entry=[owner,read,read(),(),False,b"[]",None]
            inventories[id(owner)]=entry
            def check():
                current=read()
                if id(owner) in inventory_pending and current is not entry[2]:reject_inventory(owner,current)
                if id(owner) not in inventory_pending:
                    if current is not entry[2]:
                        reject_inventory(owner,current)
                        raise CoordinatorError("complete owner inventory replaced outside creation")
                for handle,binding,binding_check in entry[3]:binding_check()
            fast_guards.append(check)
            return entry
        def inspect_inventory(owner, additions=()):
            entry=retain_inventory(owner)
            if not entry[4] and id(owner) not in inventory_pending:
                begin_inventory_creation(owner,None)
            original=entry[1]()
            # Keep a failed observation reachable. It confers no disposal
            # authority, and cannot be forgotten when its producer mutates.
            observation=reject_inventory(owner,original)
            _need(type(additions) is tuple,"exact inventory declaration batch required")
            expected={binding.role:binding for _,binding,_ in entry[3]}
            declared_roles=set()
            for binding in additions:
                _need(type(binding) is c.ResourceBinding and binding.role not in declared_roles,
                      "inventory declaration repeats a role")
                declared_roles.add(binding.role)
                _need(binding.role not in expected or binding==expected[binding.role],
                      "inventory declaration changes an existing binding")
                expected[binding.role]=binding
            _need(len(original)==len(expected),"owner inventory is not set-complete")
            selected=[];seen_handles=set();seen_roles=set()
            for handle in original:
                _need(id(handle) not in seen_handles,"duplicate retained inventory handle")
                seen_handles.add(id(handle))
                binding,check=_resource_slot(handle)
                _need(binding.role in expected and binding.role not in seen_roles,
                      "extra or duplicate retained inventory role")
                seen_roles.add(binding.role)
                _need(binding==expected[binding.role],"complete inventory binding differs")
                claim=inventory_claims.get(id(handle))
                _need(id(handle) not in retired_inventory_handles and
                      (claim is None or (claim[0] is handle and claim[1] is owner)),
                      "retained inventory handle is claimed by another port owner")
                for prior_handle,prior_binding,_ in entry[3]:
                    if prior_binding.role==binding.role:
                        _need(handle is prior_handle and binding is prior_binding,
                              "registered live inventory handle was omitted or replaced")
                selected.append((handle,binding,check))
            _need(seen_roles==set(expected),"registered inventory handle is missing")
            # The callback must return the exact static tuple, not a selected
            # subset, a copy, or an alternate list assembled after inspection.
            _need(invoke(owner,"retained_resources") is original and entry[1]() is original,
                  "inventory producer differs from its static complete tuple")
            for handle,binding,check in selected:
                check();retain_resource(handle)
                _verified_none(invoke(handle,"verify"))
                _need(invoke(handle,"binding") is binding,"inventory binding producer differs")
            _need(entry[1]() is original,"inventory changed during its last verifier")
            for _,_,check in selected:check()
            root_check()
            if not entry[4] or len(selected)!=len(entry[3]):
                bindings=[_binding_wire(binding) for _,binding,_ in selected]
                source=inventory_sources.get(id(owner))
                if source is not None:
                    _need(c.canonical_bytes(dict(owner=inventory_owner_name(owner),bindings=bindings))==source[1],
                          "live inventory differs from authenticated ordered creation batch")
                entry[6]=self._record("s8_inventory_batch",dict(owner=inventory_owner_name(owner),bindings=bindings,
                    inventorySha256=c.digest(bindings),ownershipComplete=False,
                    sourceRecordSha256=None if source is None else source[0]))
                root_check()
                _need(entry[1]() is original,"inventory changed during pending publication")
                for _,_,check in selected:check()
                entry[5]=c.canonical_bytes(bindings)
            entry[2],entry[3],entry[4]=original,tuple(selected),True
            for handle,_,_ in selected:inventory_claims[id(handle)]=(handle,owner)
            for number,prior in enumerate(rejected_inventories):
                if prior is observation:
                    del rejected_inventories[number];break
            if not selected:end_inventory_creation(owner)
            return tuple(handle for handle,_,_ in selected)
        def observe_inventory(owner, additions=()):
            try:
                _need(not self._authority_sealed,"rejected owner inventory is permanently sealed")
                return inspect_inventory(owner,additions)
            except BaseException:
                self._authority_sealed=True
                raise
        def begin_inventory_creation(owner, operation):
            entry=retain_inventory(owner)
            _need((entry[4] or operation is None) and id(owner) not in inventory_pending and
                  (not inventory_pending or (operation is None and all(item[1] is None for item in inventory_pending.values()))),
                  "owner creation transaction overlaps or lacks baseline")
            _need(entry[1]() is entry[2],"creation cannot rebase an already replaced inventory")
            inventory_pending[id(owner)]=[owner,operation,False]
        def end_inventory_creation(owner):
            _need(id(owner) in inventory_pending,"owner creation transaction is absent")
            entry=inventories[id(owner)]
            _need(entry[1]() is entry[2],"creation inventory was not admitted")
            for handle,binding,_ in entry[3]:
                _need(any(live is handle and self._identities[key]==binding
                          for key,live in self._resource_handles.items()),"creation batch remains unregistered")
            inventory_pending.pop(id(owner));root_check()
        def check_inventories():
            for key,entry in tuple(inventories.items()):
                if entry[4] and key not in inventory_pending:
                    _need(invoke(entry[0],"retained_resources") is entry[2] and entry[1]() is entry[2],
                          "complete owner inventory evidence drift")
        self._observe_inventory=observe_inventory
        self._begin_inventory_creation,self._end_inventory_creation=begin_inventory_creation,end_inventory_creation
        self._check_inventories=check_inventories
        self._inventory_rejections=lambda:tuple(rejected_inventories)
        self._retained_inventory_handles=lambda:tuple(handle for entry in inventories.values() for handle,_,_ in entry[3])
        def inventory_source(owner,source,expected):
            c._sha(source);c._keys(expected,"owner bindings")
            _same(expected["owner"],inventory_owner_name(owner))
            _need(id(owner) not in inventory_sources,"creation source owner replay")
            inventory_sources[id(owner)]=(source,c.canonical_bytes(expected))
        self._install_inventory_source=inventory_source
        self._inventory_registration_record=lambda handle:inventories[id(inventory_claims[id(handle)][1])][6]
        def pending_inventory_evidence():
            pending=[dict(owner=inventory_owner_name(entry[0]),bindings=json.loads(entry[5]),
                          unresolvedHandleCount=0,state="creation_pending",ownershipComplete=False)
                     for key,entry in inventories.items() if key in inventory_pending]
            pending.extend(dict(owner=inventory_owner_name(owner),bindings=json.loads(raw),
                unresolvedHandleCount=unknown,state="rejected_unresolved",ownershipComplete=False)
                for owner,_,raw,unknown in rejected_inventories)
            return pending
        self._pending_inventory_evidence=pending_inventory_evidence
        def claimed_handle(handle,binding):
            claim=inventory_claims.get(id(handle))
            _need(claim is not None and claim[0] is handle,"resource was not admitted in a complete owner inventory")
            source={"private_adb":"reader","host_authority":"host","root_supervisor":"supervisor"}.get(binding.owner)
            if source is not None:_need(claim[1] is roots[source],"resource is claimed by the wrong retained port")
        self._claimed_handle=claimed_handle
        def finish_inventory_registration(handle):
            claim=inventory_claims.get(id(handle))
            if claim is None:return
            owner=claim[1];entry=inventories[id(owner)]
            if id(owner) in inventory_pending and all(
                any(live is retained and self._identities[key]==binding
                    for key,live in self._resource_handles.items()) for retained,binding,_ in entry[3]):
                end_inventory_creation(owner)
        self._finish_inventory_registration=finish_inventory_registration
        def invoke(owner,name,*args,**kwargs):
            entry = retained_methods.get(id(owner))
            _need(entry is not None and entry[0] is owner and name in entry[1], "unretained dispatch")
            operation, callable_check = entry[1][name]
            pending=None
            if inventory_pending and name in ("perform","prepare","admission","capture","attach","load","finish",
                    "teardown","unload","detach","seal_callbacks","cancel_and_quiesce","fail_stop_and_quiesce",
                    "assert_quiescent","prove_absent","attempt_cleanup"):
                pending=inventory_pending.get(id(owner))
                _need(pending is not None and pending[1] is not None and not pending[2] and name=="perform" and args and args[0] is pending[1],
                      "pending creation batch forbids later lifecycle dispatch")
            callable_check()
            # Cooperative arbitration only: foreign Python writes need not
            # obey this lock. Real adapters must consume immutable retained OS
            # handles/adapter-local authority, never caller-owned mirrors.
            # Keep blocking RPC outside the lock so exact watchdog teardown
            # cannot deadlock behind an in-flight operation.
            with dispatch_lock:
                if name in ("verify","binding","canonical_bytes","stage_evidence","verify_retained",
                            "predispatch","retained_resources","load_checkpoint"):
                    # These fixed interfaces provide proofs only. Recheck all
                    # exact identity slots after each proof; the complete
                    # callable inventory is checked by the final fence and
                    # again before every actual lifecycle/read/cleanup call.
                    basic()
                    for check in fast_guards:check()
                    callable_check()
                else:root_check()
                if pending is not None:
                    _need(not pending[2],"pending creation operation replay")
                    pending[2]=True
                dispatched=operation
            try:
                result = dispatched(*args,**kwargs)
                if name == "binding":
                    _need(type(result) is c.ResourceBinding, "exact retained binding return required")
                    prior = binding_returns.get(id(owner))
                    if prior is None:
                        _, check, _ = _anchor(result)
                        binding_returns[id(owner)] = (result,check)
                    else:
                        _need(result is prior[0], "retained binding object replaced")
                        prior[1]()
                return result
            finally:
                basic()
                for check in fast_guards: check()
                callable_check()
        def endpoint(name): return roots[name]
        def install_total(bound):
            nonlocal total
            _need(total is None and type(bound) is int, "cleanup total is one-shot")
            total = bound; self._cleanup_deadline = self._cleanup_original_deadline = bound
        def cleanup_total(): root_check(); return total
        def stage_bound(bound=None):
            nonlocal last_stage_bound
            if bound is not None:
                _need(type(bound) is int, "stage absolute bound type")
                last_stage_bound = bound
            return last_stage_bound
        self._root_check, self._endpoint, self._invoke, self._retain_methods = root_check, endpoint, invoke, retain
        self._retain_resource = retain_resource
        # Identity anchors are cheap exact-type/scalar checks and run after
        # EVERY fallible external verifier/evidence call, not merely at the
        # next lifecycle transition. Static callable inventory is also checked
        # at each full fence; the selected callable is checked at dispatch.
        self._add_guard = fast_guards.append
        self._add_fast_guard = fast_guards.append
        self._install_cleanup_total, self._cleanup_total, self._stage_bound = install_total, cleanup_total, stage_bound
        def stage_scope(): return (len(guards),len(fast_guards),frozenset(retained_methods))
        def retire_scope(scope):
            root_check()
            ordinary,identities,prior_methods=scope
            for key,entry in inventories.items():
                if key not in prior_methods:
                    _need(key not in inventory_pending and all(any(
                        retained is live and owned_key in self._completed_resources
                        for owned_key,live in self._resource_handles.items()) for retained,_,_ in entry[3]),
                        "pending owner inventory cannot retire without exact whole-inventory closure")
            del guards[ordinary:]; del fast_guards[identities:]
            for key in tuple(retained_methods):
                if key not in prior_methods:
                    retained_methods.pop(key);binding_returns.pop(key,None);resource_slots.pop(key,None)
                    retired_inventory=inventories.pop(key,None)
                    if retired_inventory is not None:
                        for handle,_,_ in retired_inventory[3]:
                            inventory_claims.pop(id(handle),None);retired_inventory_handles.add(id(handle))
                        inventory_sources.pop(key,None)
        self._stage_scope, self._retire_scope = stage_scope, retire_scope
        def forbid(identity):
            value = c.ResourceIdentity.parse(identity)
            if value.kind == "process": forbidden_pids.add(value.key)
        self._forbid_process = forbid
        self._server_excluded = lambda pid:type(pid) is int and str(pid) not in forbidden_pids
        for role in ("reader","host","supervisor","reopen"):
            retain(roots[role],PORT_METHODS);retain_inventory(roots[role])
        retain(roots["stages"],("verify","canonical_bytes","prepare"))
        retain(roots["creation_owner"],("verify","canonical_bytes","open_window","authenticate_materialization","materialize"))
        retain(pen_owner,("acquire","capture_lease","finish","quarantine"))
        retain(transport,("exchange","wait_exact_peer_closed","retain_quarantine"))
        for name in ("clock","nonce","run_stage"):
            value = roots[name]
            _need(type(value) is types.FunctionType or type(value) is types.MethodType, "exact construction callable required")
            function = value.__func__ if type(value) is types.MethodType else value
            code = function.__code__
            guards.append(lambda function=function,code=code:_need(function.__code__ is code,"construction callable code changed"))
        self.model, self._last_ns = c.CoordinatorModel(contract_view()), int(self.plan["createdHostNs"])
        self._lock, self._used, self._quarantined = threading.Lock(), False, False
        self._attempted, self._nonces, self._receipts = set(), set(), {}
        self._call_sequence = 0
        self._identities, self._completed_resources = {}, set()
        self._resource_handles, self._closure_proofs = {}, {}
        self._shared_stage_identity = None
        self._active_stage_context = None
        self._retained_context = self._retained_views = None
        self._authority_sealed = False
        self._retained_sources = {role:getattr(dependencies, role) for role in port_pins}
        self._retained_pen = dependencies.pen_peer
        self._retained_private_adb_resource = dependencies.private_adb_resource
        self._retained_pen_transport = dependencies.pen_peer.transport
        self._initial_pen_identity = (dependencies.pen_peer.stage_session, dependencies.pen_peer.token,
            dependencies.pen_peer.hold_ms, dependencies.pen_peer.transport.peer_identity)
        self._terminal_attempted, self._terminal_result = False, None
        self._pen_closure = None
        self._pen_binding = self._display = self._foreign = self._stock = self._absence = None
        self._bundles, self._stage_results, self._events = [], [], []
        self._cleanup_deadline, self._stage_deadline = None, None
        self._cleanup_original_deadline = None
        self._device_ms, self._pen_sequence = 0, 0
        self._journal = EventJournal(journal_store, contract_view(), selection_view())
        self.ownership = ledger.CleanupLedger.create(ownership_store, self._ns, self.plan["hostClockId"],
                                                    ledger_id=self.plan["runSessionId"][32:])
        self._ownership_store = ownership_store
        owned, event_journal = self.ownership, self._journal
        journal_contract, journal_selection = event_journal.contract, event_journal.selection
        _, journal_contract_check, _ = _anchor(journal_contract)
        _, journal_selection_check, _ = _anchor(journal_selection)
        ledger_clock, ledger_clock_id = owned._clock, owned._clock_id
        def ledger_roots_check():
            _need(event_journal.store is journal_store and event_journal.contract is journal_contract and
                  event_journal.selection is journal_selection and owned._store is ownership_store and
                  owned._clock is ledger_clock and type(owned._clock_id) is str and owned._clock_id == ledger_clock_id,
                  "retained ledger/store/clock authority replaced")
            journal_contract_check(); journal_selection_check()
        fast_guards.append(ledger_roots_check)
        self._original_journal = lambda:event_journal
        self._original_owned = lambda:owned
        retain(owned,("register","attempt_cleanup","finalize","primary_failure"))
        for retained_store in (journal_store,ownership_store):
            retain(retained_store,("exclusive","names","read","create","write","fsync_file","close",
                "rename_no_replace","fsync_directory","load_checkpoint"))
        retain(event_journal,("append",))
        journal_append, journal_append_check = retained_methods[id(event_journal)][1]["append"]
        def append_record(event,data,remaining):
            journal_append_check()
            return journal_append(event,data,remaining)
        self._append_record = append_record
        root_check()

    def _proxy(self, owner, names):
        self._retain_methods(owner,names)
        return _Endpoint(owner,self._invoke,names)

    def _freeze_bundle(self, bundle):
        _need(type(bundle) is StageBundle, "typed stage factory result required")
        names = ("manifest","observer_source","observer_sha256","trusted_pins","resources","worker_transitions_raw")
        payload = {name:object.__getattribute__(bundle,name) for name in names}
        view, check, _ = _anchor(payload)
        refs = (bundle.tool_bundle,bundle.authority_provider,bundle.frida_provider)
        def original_check():
            _need(type(bundle) is StageBundle, "stage bundle type changed")
            for name,value in payload.items():
                _need(object.__getattribute__(bundle,name) is value, "stage bundle field replaced")
            _need(bundle.tool_bundle is refs[0] and bundle.authority_provider is refs[1] and bundle.frida_provider is refs[2],
                  "stage bundle owner replaced")
            check()
        self._add_guard(original_check)
        self._retain_methods(refs[1],AUTHORITY_METHODS); self._retain_methods(refs[2],FRIDA_METHODS)
        self._retain_methods(refs[0],("verify","canonical_bytes"))
        result = StageBundle(tool_bundle=refs[0],authority_provider=refs[1],frida_provider=refs[2],**view())
        # Runner arguments get detached objects, also anchored before exposure.
        _, detached_check, _ = _anchor(result.trusted_pins); self._add_guard(detached_check)
        return result

    def execute(self):
        raise AdmissionBlocked("; ".join(BLOCKERS))

    @property
    def phase(self):
        if self._terminal_attempted and self._terminal_result is None: return "TERMINAL_DECISION_UNCERTAIN"
        return "QUARANTINED" if self._quarantined else self.model.phase

    def _ns(self):
        self._root_check()
        now = self._endpoint("clock")()
        self._root_check()
        _need(type(now) is c.HostInstant and type(now.clock_id) is str and now.clock_id == self._plan()["hostClockId"] and
              type(now.nanoseconds) is int and
              now.nanoseconds >= self._last_ns, "trusted host clock drift")
        self._last_ns = now.nanoseconds
        return now.nanoseconds

    def _live(self, deadline):
        _need(type(deadline) is int, "exact absolute deadline required")
        now = self._ns()
        _need(now < deadline, "absolute deadline exhausted")
        return now

    def _nonce(self):
        self._root_check()
        nonce = self._endpoint("nonce")(); c._sha(nonce)
        self._root_check()
        _need(nonce not in self._nonces, "nonce replay")
        self._nonces.add(nonce)
        return nonce

    def _verify(self, role):
        source = self._endpoint(role)
        _need(source is self._retained_sources[role], "retained port object was replaced")
        _need(self._invoke(source,"verify") is None, "retained " + role + " verification did not authenticate")
        raw = self._invoke(source,"canonical_bytes")
        _need(type(raw) is bytes and _sha(raw) == self._pin_view()[role], "retained " + role + " authority drift")

    def _verify_creation_owner(self):
        owner=self._endpoint("creation_owner")
        _verified_none(self._invoke(owner,"verify"))
        raw=self._invoke(owner,"canonical_bytes")
        _need(type(raw) is bytes and _sha(raw)==self._endpoint("creation_owner_sha256"),
              "independent creation owner authority drift")

    def _verify_pen_identity(self):
        peer = self._endpoint("pen_peer")
        _need(peer is self._retained_pen and peer.transport is self._retained_pen_transport,
              "retained pen owner/transport replaced")
        _need((peer.stage_session, peer.token, peer.hold_ms, peer.transport.peer_identity) == self._initial_pen_identity,
              "retained pen scope drift")
        if self._pen_binding is not None:
            _same(self._lease_wire(peer.binding), self._pen_binding, "retained pen binding drift")

    @staticmethod
    def _identity_views(views):
        # Placement is the sole authorized host transition. Retained task/raw
        # evidence may have a new observation hash; its semantic identity may not.
        result = _copy(views)
        for name in ("stage", "requestedFrame", "measuredGlobalFrame", "placementRequestGeneration", "placementReadyGeneration"):
            result["host"]["host"].pop(name, None)
        result["supervisor"]["task"].pop("raw_sha256", None)
        for role in ("reader","supervisor"): result[role].pop("selectionAuthoritySha256",None)
        return result

    def _retained_fence(self, deadline=None, *, exact_views=None):
        """All owners, not just the callee. Failure permanently seals dispatch.

        Exited handles remain retained and identity-checkable; an absence flag
        never replaces the owning handle. This is a provisional authenticated
        adapter seam, not a claim that current production ports implement it.
        """
        _need(not self._authority_sealed and not self._quarantined, "retained authority fence is sealed")
        try:
            self._root_check()
            _need(type(self._endpoint("private_adb_resource")) is c.ResourceBinding and
                  self._endpoint("private_adb_resource") == self._retained_private_adb_resource,
                  "private ADB retained configuration drift")
            if self._cleanup_deadline is not None:
                _need(type(self._cleanup_deadline) is int and self._cleanup_deadline == self._cleanup_original_deadline,
                      "cleanup total deadline rebased")
            for role in self._pin_view(): self._verify(role)
            self._verify_creation_owner()
            self._check_inventories()
            self._verify_pen_identity()
            def handles():
                for key, handle in self._resource_handles.items():
                    if key in self._completed_resources and ":" in key: continue
                    _verified_none(self._invoke(handle,"verify"))
                    binding = self._invoke(handle,"binding")
                    _need(type(binding) is c.ResourceBinding and binding == self._identities[key],
                          "retained resource identity drift: " + key)
            if self._retained_context is not None:
                bound = int(self._plan()["absoluteRunDeadlineNs"]) if deadline is None else deadline
                views = {}
                for role in ("reader", "host", "supervisor", "reopen"):
                    views[role] = c.load_canonical(self._invoke(self._endpoint(role),"stage_evidence",self._retained_context,bound))
                _same(self._identity_views(views), self._retained_views, "retained non-stage authority drift")
                if exact_views is not None: _same(views,exact_views,"retained stage owner drift")
            # A fallible verifier may itself have side effects. Nothing is
            # published/dispatched until all retained handles are checked again.
            handles(); self._verify_pen_identity()
            self._root_check()
            if deadline is not None: self._live(deadline)
            # The trusted clock is itself a fallible callback. This final
            # static graph fence MUST follow it and invokes no owner callbacks.
            self._root_check()
        except BaseException:
            self._authority_sealed = True
            raise

    def _record(self, event, data):
        return self._append_record(event,data,self._original_owned().remaining)

    def _event(self, kind, body, *, observed=None):
        now = self._ns() if observed is None else observed
        sequence, previous = self.model.event_head
        value = dict(authority=c.EVENT_AUTHORITY, schemaVersion=1, contractSha256=self._contract_hash(),
                     runSessionId=self._plan()["runSessionId"], sequence=sequence + 1,
                     previousEventSha256=previous, observedHostNs=str(now), kind=kind, body=body)
        raw = c.canonical_bytes(value)
        # Validate using the real S0 model before durable publication. If this
        # publication fails, no further operation runs; recovery replays only
        # the durable prefix and classifies the outstanding intent as unknown.
        self.model.apply(raw, c.HostInstant(self._plan()["hostClockId"], now))
        self._record("s8_model", value); self._events.append(value)

    def _intent(self, label, request, deadline):
        _need(not self._quarantined and label not in self._attempted, "one-shot operation is fenced/replayed")
        self._live(deadline); self._attempted.add(label)
        result = self._record("s8_intent", dict(operation=label, deadlineNs=str(deadline), request=request))
        self._live(deadline)
        return result

    def _call(self, role, operation, request, label=None, *, deadline=None):
        _need(type(operation) is Operation and operation in ROLES[role], "operation is not owned by retained port")
        if self._cleanup_deadline is not None:
            issued, deadline = self._cleanup_call_window(deadline)
        else:
            deadline = self._operation_deadline() if deadline is None else deadline
            issued = self._live(deadline)
        label = operation.value if label is None else label
        self._retained_fence(deadline)
        self._call_sequence += 1
        envelope = dict(runSessionId=self._plan()["runSessionId"], operation=operation.value,
                        commandId=label, sequence=self._call_sequence, challenge=self._nonce(), issuedHostNs=str(issued),
                        previousReceiptSha256=self._receipts.get(role), request=request)
        intent = self._intent(label, envelope, deadline)
        raw = _guarded(lambda:self._retained_fence(deadline),
            lambda:self._invoke(self._endpoint(role),"perform",operation,c.canonical_bytes(envelope),deadline))
        now = self._live(deadline)
        value = c.load_canonical(raw)
        c._keys(value, "authority requestSha256 runSessionId commandId observedHostNs body")
        _same(value["authority"], RECEIPT_AUTHORITY)
        _same(value["requestSha256"], _sha(c.canonical_bytes(envelope)))
        _same(value["runSessionId"], self._plan()["runSessionId"])
        _same(value["commandId"], label)
        _need(type(value["observedHostNs"]) is str and c._decimal(value["observedHostNs"]) <= now and
              int(value["observedHostNs"]) >= issued,
              "port receipt time differs")
        _need(type(value["body"]) is dict, "typed port body required")
        creation=_port_creation(operation.value,request,value["body"],self._plan())
        result_record=self._record("s8_result", dict(operation=label, intentSha256=intent, receipt=value))
        if creation is not None:self._install_inventory_source(self._endpoint(role),result_record,creation)
        self._receipts[role] = _sha(raw)
        self._live(deadline)
        return value["body"]

    def _operation_deadline(self):
        if self._cleanup_total() is not None:
            return self._cleanup_call_window()[1]
        return int(self._plan()["absoluteRunDeadlineNs"])

    def _cleanup_call_window(self, parent=None):
        """One trusted issuance read, one immutable absolute per-call bound.

        No rounded timeout or later proof/clock read rebases this bound. Equality
        is expired, and an explicit parent can only narrow the original budget.
        """
        total = self._cleanup_total()
        if total is not None:
            if parent is None: parent = total
            _need(type(parent) is int and parent <= total,
                  "cleanup parent deadline rebased")
        _need(type(parent) is int, "exact cleanup parent deadline required")
        issued = self._ns()
        bound = min(parent, issued + c.CLEANUP_STEP_TIMEOUT_MS * 1_000_000)
        _need(issued < bound, "cleanup deadline exhausted")
        return issued, bound

    def _register(self, role, identity, *, key=None, handle=None):
        key = role if key is None else key
        _need(key not in self._identities, "resource ownership key replay")
        binding = c.ResourceBinding(role, c.RESOURCE_OWNERS[role][1], c.ResourceIdentity.parse(identity))
        if handle is None:
            if binding.owner == "pen_peer": handle = _PenResource(self, binding)
            else:
                source = {"private_adb": "reader", "host_authority": "host", "root_supervisor": "supervisor"}.get(binding.owner)
                _need(source is not None, "resource registration needs its retained owner handle")
                handle = self._owner_handle(self._endpoint(source), role, identity)
        if binding.owner!="pen_peer":self._claimed_handle(handle,binding)
        c.validate_resource_bindings(tuple(self._identities.values()) + (binding,))
        if handle is not None:
            self._retain_resource(handle)
            _need(self._invoke(handle,"verify") is None and type(self._invoke(handle,"binding")) is c.ResourceBinding,
                  "owner has no retained exact resource")
            reported = self._invoke(handle,"binding")
            _, reported_check, _ = _anchor(reported)
            _same(reported.identity.wire(), identity, "retained owner/resource identity mismatch")
            _need(reported == binding, "retained resource owner differs")
            def resource_check(handle=handle,reported=reported,check=reported_check,key=key,binding=binding):
                _need(self._resource_handles[key] is handle and self._identities[key] is binding, "retained resource slot replaced")
                check()
            self._resource_handles[key] = handle
        self._invoke(self.ownership,"register",ledger.ResourceIdentity.parse(identity),binding.owner)
        self._identities[key] = binding
        _, binding_check, _ = _anchor(binding)
        self._add_fast_guard(binding_check); self._add_fast_guard(resource_check)
        self._forbid_process(binding.identity.wire())
        self._record("s8_owned", dict(role=role, key=key, owner=binding.owner, identity=identity,
            checkpoint=self._ownership_checkpoint(),inventoryRecordSha256=None if binding.owner=="pen_peer" else self._inventory_registration_record(handle)))
        self._finish_inventory_registration(handle)

    def _ownership_checkpoint(self):
        point = self._invoke(self._ownership_store,"load_checkpoint")
        _need(point == self.ownership.checkpoint, "ownership external checkpoint differs")
        return dict(ledgerId=point.ledger_id, sequence=point.sequence, sha256=point.record_sha256)

    def _owner_handle(self, owner, role, identity):
        binding=c.ResourceBinding(role,c.RESOURCE_OWNERS[role][1],c.ResourceIdentity.parse(identity))
        handles=self._observe_inventory(owner,(binding,))
        return next(handle for handle in handles if _resource_slot(handle)[0].role==role)

    def _settle_resources(self, roles, *, deadline=None):
        parent = self._cleanup_total() if deadline is None else deadline
        for role in roles:
            if role not in self._identities: continue
            binding = self._identities[role]
            identity = ledger.ResourceIdentity.parse(binding.identity.wire())
            _need(role in self._resource_handles, "absence has no retained owning authority")
            handle = self._resource_handles[role]
            issued, deadline = self._cleanup_call_window(parent)
            self._retained_fence(deadline)
            request = c.canonical_bytes(dict(runSessionId=self._plan()["runSessionId"], resource=binding.identity.wire(),
                owner=binding.owner, challenge=self._nonce(), issuedNs=str(issued), deadlineNs=str(deadline)))
            proof = _guarded(lambda:self._retained_fence(deadline), lambda:self._invoke(handle,"prove_absent",request,deadline))
            now = self._live(deadline)
            _need(type(proof) is ResourceClosure, "exact owner closure required")
            _anchor(proof)[1]()
            _need(type(proof) is ResourceClosure and type(proof.binding) is c.ResourceBinding and proof.binding == binding,
                  "absence receipt does not bind the retained owner")
            _same(proof.request_sha256, _sha(request)); c._sha(proof.evidence_sha256)
            _need(type(proof.observed_ns) is int and issued <= proof.observed_ns <= now and
                  proof.absent is True and proof.joined is True and proof.channels_closed is True,
                  "exact absence/join/channel closure is unproven")
            _need(self._invoke(handle,"verify") is None and self._invoke(handle,"binding") == binding, "closure owner was substituted")
            evidence = c.digest(dict(requestSha256=proof.request_sha256, evidenceSha256=proof.evidence_sha256,
                identity=binding.identity.wire(), owner=binding.owner, observedNs=str(proof.observed_ns)))
            self._record("s8_owner_closed", dict(key=role, owner=binding.owner, identity=binding.identity.wire(),
                requestSha256=proof.request_sha256, observedNs=str(proof.observed_ns), evidenceSha256=proof.evidence_sha256,
                absent=True, joined=True, channelsClosed=True))
            self._retained_fence(deadline)
            result = self._invoke(self.ownership,"attempt_cleanup",identity.resource_id,binding.owner,
                deadline_ns=deadline,
                observe=lambda exact: ledger.Observation(exact, None, "absent", True, evidence),
                mutate=lambda _: (_ for _ in ()).throw(CoordinatorError("generic cleanup forbidden")))
            self._retained_fence(deadline)
            _need(result, "S5 absence decision failed")
            self._completed_resources.add(role)
            self._closure_proofs[role] = evidence

    def _lease_wire(self, b):
        _need(type(b) is pen.LeaseBinding, "typed retained S4 binding required")
        wire = dict(observerSessionId=b.stage_session.value, leaseToken=b.token,
            peer=self._pen_process(b.peer), worker=self._pen_process(b.worker), guardian=self._pen_process(b.guardian),
            guardianSession=b.guardian_session, deviceClockDomain=b.device_clock_domain,
            absoluteDeviceBoottimeExpiryMs=str(b.deadline_boottime_ms))
        c._pen(wire, self._plan())
        return wire

    def _lease(self, capture):
        _need(type(capture) is pen.CaptureLease and type(capture.binding) is pen.LeaseBinding, "typed S4 lease required")
        b = capture.binding
        _need(type(capture.sequence) is int and capture.sequence > self._pen_sequence, "pen receipt replay")
        _need(type(capture.device_boottime_ms) is int and capture.device_boottime_ms >= self._device_ms,
              "device BOOTTIME drift")
        _need(capture.remaining_ms == c.remaining_device_ms(c.DeviceBoottime(b.deadline_boottime_ms),
              c.DeviceBoottime(capture.device_boottime_ms)), "cross-clock pen lease misuse")
        wire = self._lease_wire(b)
        if self._pen_binding is not None: _same(wire, self._pen_binding, "pen ownership changed")
        self._pen_sequence, self._device_ms = capture.sequence, capture.device_boottime_ms
        return wire

    def _pen_process(self, identity):
        _need(type(identity) is pen.ProcessIdentity, "exact pen process required")
        return c.ResourceIdentity("process", c.AUTHORIZED_SERIAL, str(identity.pid),
                                  self._boot + ":" + str(identity.starttime)).wire()

    def _pen_capture(self, label, *, acquire=False):
        deadline = self._operation_deadline()
        self._intent(label, {"observerSessionId": self._plan()["runSessionId"], "leaseToken": self._endpoint("pen_peer").token,
                             "peer": self._pen_process(self._endpoint("pen_peer").transport.peer_identity)}, deadline)
        operation = (lambda:self._invoke(self._endpoint("pen_peer"),"acquire",pen.BeforeAbsenceProof(
            pen.StageSession(self._plan()["runSessionId"]), self._before_sha))) if acquire else (
            lambda:self._invoke(self._endpoint("pen_peer"),"capture_lease",pen.StageSession(self._plan()["runSessionId"])))
        capture = _guarded(lambda:self._retained_fence(deadline), operation)
        self._live(deadline)
        wire = self._lease(capture)
        self._record("s8_pen", dict(operation=label, binding=wire, sequence=capture.sequence,
                                     deviceBoottimeMs=str(capture.device_boottime_ms)))
        return wire

    def run_diagnostic(self):
        _need(self._lock.acquire(blocking=False), "concurrent run rejected")
        try:
            _need(not self._used, "run cannot retry")
            self._used = True
            try:
                self._run()
                return self._finish_result()
            except BaseException as error:
                if self._terminal_result is not None: return self._terminal_result
                if self._terminal_attempted:
                    if self._journal.records[-1]["event"] == "s8_finished":
                        self._terminal_result = c.canonical_bytes(self._journal.records[-1]["data"])
                        return self._terminal_result
                    raise TerminalDecisionUncertain("terminal publication must be resolved from its exact durable checkpoint") from error
                self._quarantine(error)
                raise RetainedQuarantine(str(error)) from error
        finally: self._lock.release()

    def _run(self):
        # Initial complete inventories are closed by contract. A live resource
        # outside these batches is not an implicit future creation permission.
        self._observe_inventory(self._endpoint("supervisor"))
        self._observe_inventory(self._endpoint("reopen"))
        self._register("private_adb_server", self._endpoint("private_adb_resource").identity.wire())
        self._register("host_session", c.ResourceIdentity("host_session", c.AUTHORIZED_SERIAL,
            self._plan()["hostSessionId"], self._plan()["runSessionId"]).wire())
        for role in self._pin_view(): self._verify(role)
        before = self._call("reader", Operation.PREFLIGHT,
            dict(target=self._plan()["target"], fixtures=self._plan()["fixtures"], selection=self._selection_view().wire(),
                 allDisplays=True, noDocumentTaskOrActivity=True, stockProcessMayLive=True))
        c._keys(before, "target bootId selection prechecked")
        _same(before["target"], self._plan()["target"]); _same(before["selection"], self._selection_view().wire())
        c._match(before["bootId"], c._BOOT, "authenticated device boot required")
        self._boot = before["bootId"]
        self._event("prechecked", before["prechecked"])
        self._stock = before["prechecked"]["stockProcess"]
        if self._stock is not None:
            _same(self._stock["identity"]["incarnation"].split(":")[0], self._boot)
            self._forbid_process(self._stock["identity"])
        self._before_sha = before["prechecked"]["evidenceSha256"]
        if self._stock is not None:
            _need(self._endpoint("pen_peer").transport.peer_identity.pid != int(self._stock["identity"]["key"]),
                  "peer aliases stock process before acquisition")
        # Retain known scope BEFORE acquisition. Worker/guardian identities are
        # learned from the authenticated READY; a crash in between leaves this
        # exact peer/token scope durably owned, never a PID-search permission.
        self._register("device_peer", self._pen_process(self._endpoint("pen_peer").transport.peer_identity))
        self._register("pen_lease", c.ResourceIdentity("pen_lease", c.AUTHORIZED_SERIAL,
            self._endpoint("pen_peer").token, self._plan()["runSessionId"]).wire())
        self._pen_binding = self._pen_capture("pen_acquire", acquire=True)
        _, pen_binding_check, _ = _anchor(self._endpoint("pen_peer").binding)
        self._add_fast_guard(pen_binding_check)
        _same(self._pen_binding["peer"], self._identities["device_peer"].identity.wire())
        for role, key in (("pen_worker", "worker"), ("pen_guardian", "guardian")):
            self._register(role, self._pen_binding[key])
        self._event("pen_acquired", dict(beforeAbsenceSha256=self._before_sha, penBinding=self._pen_binding,
                                         deviceBoottimeMs=str(self._device_ms)))
        self._begin_inventory_creation(self._endpoint("host"),Operation.HOST_START)
        display = self._call("host", Operation.HOST_START, dict(host=self._plan()["host"],
                    hostSessionId=self._plan()["hostSessionId"], canvas=self._plan()["canvas"]))
        c._keys(display,"display evidenceSha256 ownerInventory")
        declared=display.pop("ownerInventory")
        _same(declared,[_binding_wire(self._identities["host_session"]),
            _binding_wire(c.ResourceBinding("virtual_display","host_authority",c.ResourceIdentity.parse(display["display"]["identity"])))],
            "host result does not authenticate its complete next inventory")
        self._event("display_ready", display); self._display = display["display"]
        self._register("virtual_display", self._display["identity"])
        absent = self._call("reader", Operation.PRELAUNCH, dict(display=self._display, allDisplays=True))
        c._keys(absent, "documentTasks documentActivities evidenceSha256")
        _same(absent["documentTasks"], []); _same(absent["documentActivities"], []); c._sha(absent["evidenceSha256"])
        launch = dict(commandId="launch_foreign_document", component=c.COMPONENT, display=self._display,
            beforeAbsenceSha256=self._before_sha, prelaunchAbsenceSha256=absent["evidenceSha256"],
            documentTasks=[], documentActivities=[], fixtureSha256=self._plan()["fixtures"]["pdf"]["sha256"])
        command = dict(component=c.COMPONENT, selection=self._selection_view().wire(), display=self._display,
                       nonExportedRootRoute=True, noWriterMutation=True, prelaunchAbsenceSha256=absent["evidenceSha256"])
        launch["commandSha256"] = c.digest(command)
        # The launch intent is part of the S0 state before any root launch. It
        # still confers NO task disposal authority until foreign_attached.
        self._event("foreign_launch_recorded", launch)
        launched = self._call("supervisor", Operation.LAUNCH, command)
        _same(launched, {"launchCommandSha256": launch["commandSha256"]})
        self._begin_inventory_creation(self._endpoint("supervisor"),Operation.ATTACH)
        attached = self._call("supervisor", Operation.ATTACH, launch)
        declared=attached.pop("ownerInventory")
        _same(declared,[_binding_wire(c.ResourceBinding("foreign_task","root_supervisor",
            c.ResourceIdentity.parse(attached["foreign"]["identity"])))],
            "attach result does not authenticate its complete next inventory")
        candidate = attached["foreign"]["process"]["identity"]
        for role in ("pen_worker", "pen_guardian", "device_peer"):
            exact = self._identities[role].identity
            _need((candidate["namespace"], candidate["key"]) != (exact.namespace, exact.key),
                  "causally attached target aliases retained pen owner")
        self._event("foreign_attached", attached)
        self._foreign = attached["foreign"]; self._stock = self._foreign["process"]
        self._causal_raw = c.canonical_bytes(dict(launch=launch,command=command,attached=attached))
        causal_raw = self._causal_raw
        self._add_guard(lambda:_need(type(self._causal_raw) is bytes and self._causal_raw == causal_raw,
                                    "authenticated causal launch evidence replaced"))
        _, foreign_check, _ = _anchor(self._foreign)
        self._add_guard(foreign_check); self._forbid_process(self._stock["identity"])
        self._register("foreign_task", self._foreign["identity"])
        for index in range(4): self._stage(index)
        self._cleanup()

    def _stage(self, index):
        scope = self._stage_scope()
        stage = self._plan()["stages"][index]
        placed = self._call("host", Operation.PLACE, dict(stage=stage, foreign=self._foreign, canvas=self._plan()["canvas"]), stage["commandId"])
        c._keys(placed, "stage foreign evidenceSha256")
        _same(placed["stage"], stage); _same(placed["foreign"], self._foreign); c._sha(placed["evidenceSha256"])
        self._pen_capture("pen_before_" + str(index))
        issued = self._ns()
        absolute = min(issued + self.stage_timeout_ms * 1_000_000, int(self._plan()["absoluteRunDeadlineNs"]))
        self._stage_deadline = absolute
        self._stage_bound(absolute)
        binding = runner.StageBinding(c.AUTHORIZED_SERIAL, int(self._foreign["process"]["identity"]["key"]),
            self._foreign["process"]["identity"]["incarnation"].split(":")[1], self._plan()["runSessionId"],
            self.stage_timeout_ms, absolute, stage["stage"])
        nonce = self._nonce()
        previous = {} if index == 0 else {role: self._closure_proofs[role + ":" + str(index - 1)]
            for role in ("authority_worker", "frida_worker", "root_frida_server")}
        forbidden = [b.identity.wire() for b in self._identities.values() if b.identity.kind == "process"]
        forbidden.append(self._stock["identity"])
        context = StageContext(self._contract_view(), index, binding, c.canonical_bytes(self._foreign), c.canonical_bytes(placed), nonce,
            c.canonical_bytes(previous), c.canonical_bytes(forbidden),
            c.canonical_bytes(self._selection_view().wire()), self._causal_raw)
        context_view, context_check, context_raw = _anchor(context)
        context_digest = _sha(context_raw)
        self._add_guard(context_check)
        # Independent scalars precede the first factory call, including its
        # exception/finally edge; no post-factory hash can authenticate mutation.
        scalar_tuple = (index,nonce,absolute,stage["stage"],tuple(stage["rect"]),
                        context.previous_stage_closures_raw,context.forbidden_owners_raw)
        self._verify("stages")
        prepare_intent=self._intent("prepare_stage_" + str(index),
            dict(stage=stage,nonce=nonce,contextSha256=context_sha256(context)),absolute)
        window=stage_creation_window(context,self._endpoint("creation_owner_sha256"))
        window_raw=c.canonical_bytes(window)
        window_record=self._record("s8_creation_window",dict(window=window,prepareIntentSha256=prepare_intent))
        creator=self._endpoint("creation_owner");published=[None];publication_used=[False]
        def publish_materialization(raw):
            _need(not publication_used[0] and type(raw) is bytes,"materialization publication replay/type")
            publication_used[0]=True
            self._retained_fence(absolute);context_check()
            # Only the independently retained acquisition owner can
            # authenticate these identities. Factory-authored claims, early
            # claims and prior-window receipts cannot satisfy this method.
            _verified_none(self._invoke(creator,"authenticate_materialization",window_raw,raw,absolute))
            self._retained_fence(absolute);context_check()
            receipt=c.load_canonical(raw)
            actual=_materialized_receipt(receipt,window)
            c.validate_resource_bindings(tuple(self._identities.values())+actual)
            server=actual[-1].identity
            _need(self._server_excluded(int(server.key)) and all(server.key!=item.identity.key for item in actual[:-1]),
                  "materialization aliases a forbidden retained process")
            record=self._record("s8_creation_materialized",dict(windowRecordSha256=window_record,receipt=receipt))
            published[0]=(raw,record)
            self._retained_fence(absolute);context_check()
            return record
        opened=self._invoke(creator,"open_window",window_raw,publish_materialization,absolute)
        _same(c.load_canonical(opened),dict(authority="rtl-reader-stage-creation-owner-window-v1",
            transactionId=window["transactionId"],windowSha256=c.digest(window),
            recoveryOwnerSha256=window["recoveryOwnerSha256"],
            lifetime="independent-durable-owner-v1",state="armed-unmaterialized"))
        self._retained_fence(absolute)
        bundle = _guarded(lambda:self._retained_fence(absolute), lambda:self._invoke(self._endpoint("stages"),"prepare",context,absolute))
        _need(published[0] is not None,"factory exposed resources without owner-side durable publication")
        materialization=c.load_canonical(published[0][0]);materialization_record=published[0][1]
        context_check(); _same(_sha(context_raw),context_digest)
        context = context_view(); binding = context.binding
        _need((context.stage_index,context.run_nonce,context.binding.absolute_deadline_ns,
            context.contract.value["stages"][index]["stage"],tuple(context.contract.value["stages"][index]["rect"]),
            context.previous_stage_closures_raw,context.forbidden_owners_raw) == scalar_tuple, "original stage scalar authority differs")
        _, detached_context_check, _ = _anchor(context); self._add_guard(detached_context_check)
        self._bundles.append(bundle)
        bundle = self._freeze_bundle(bundle)
        c.validate_resource_bindings(bundle.resources)
        _same([item.role for item in bundle.resources], ["authority_worker", "frida_worker"])
        transitions=c.load_canonical(bundle.worker_transitions_raw)
        c._keys(transitions,"authority_worker frida_worker root_frida_server")
        server_binding=c.ResourceBinding("root_frida_server","mutating_private_adb",
            c.ResourceIdentity.parse(transitions["root_frida_server"]["current"]))
        _need(server_binding.identity.namespace==c.AUTHORIZED_SERIAL and
              server_binding.identity.incarnation.split(":")[0]==self._boot and
              self._server_excluded(int(server_binding.identity.key)) and
              all(server_binding.identity.key!=item.identity.key for item in bundle.resources),
              "declared Frida inventory aliases a retained authority")
        c.validate_resource_bindings(tuple(self._identities.values())+bundle.resources+(server_binding,))
        _same(materialization["batches"],[dict(owner="stage_authority",bindings=[_binding_wire(bundle.resources[0])]),
            dict(owner="stage_frida",bindings=[_binding_wire(bundle.resources[1]),_binding_wire(server_binding)])],
            "factory bundle differs from independent owner acquisition")
        self._install_inventory_source(bundle.authority_provider,materialization_record,materialization["batches"][0])
        self._install_inventory_source(bundle.frida_provider,materialization_record,materialization["batches"][1])
        self._begin_inventory_creation(bundle.authority_provider,None)
        self._begin_inventory_creation(bundle.frida_provider,None)
        authority_handles=self._observe_inventory(bundle.authority_provider,(bundle.resources[0],))
        frida_handles=self._observe_inventory(bundle.frida_provider,(bundle.resources[1],server_binding))
        for item in bundle.resources:
            _need(item.identity.namespace == self._endpoint("private_adb_resource").identity.namespace and
                  item.identity.incarnation.split(":")[0] == self._endpoint("private_adb_resource").identity.incarnation.split(":")[0],
                  "isolated worker is not in retained host boot namespace")
            selected_handles=authority_handles if item.role=="authority_worker" else frida_handles
            handle=next(handle for handle in selected_handles if _resource_slot(handle)[0].role==item.role)
            self._register(item.role, item.identity.wire(), key=item.role + ":" + str(index), handle=handle)
        server_handle=next(handle for handle in frida_handles if _resource_slot(handle)[0].role=="root_frida_server")
        self._register("root_frida_server",server_binding.identity.wire(),key="root_frida_server:"+str(index),handle=server_handle)
        self._verify("stages"); self._live(absolute)
        manifest = runner.load_canonical(bundle.manifest.raw, runner.MAX_MANIFEST_BYTES)
        _, manifest_check, _ = _anchor(manifest); self._add_guard(manifest_check)
        _same(bundle.manifest.sha256, manifest.sha256)
        runner.validate_manifest(manifest, binding, bundle.observer_sha256)
        _same(manifest.value["externalSession"], dict(authority=runner.EXTERNAL_SESSION_AUTHORITY,
            authorizedSerial=c.AUTHORIZED_SERIAL, taskId=self._foreign["taskId"], displayId=self._display["displayId"],
            hostSessionId=self._display["hostSessionId"], displayGeneration=self._display["generation"]))
        _same(manifest.value["expected"]["documentUri"], self._selection_view().document_uri)
        files = manifest.value["files"]
        pdf, mark = files["originalPdf"], files["mark"]
        baseline_pdf, baseline_mark = self._plan()["fixtures"]["pdf"], self._plan()["fixtures"]["mark"]
        _same(pdf["sha256"], baseline_pdf["sha256"]); _same(pdf["size"], str(baseline_pdf["size"]))
        _same("file://" + pdf["path"], self._selection_view().document_uri)
        _same(c.digest(pdf["uriResolution"]), self._plan()["fixtures"]["uriResolutionSha256"])
        _same(mark["present"], baseline_mark is not None)
        if baseline_mark is not None:
            _same(mark["sha256"], baseline_mark["sha256"]); _same(mark["size"], str(baseline_mark["size"]))
            _same(mark["path"], pdf["path"] + ".mark")
        _need(all(value["result"]["manifestSha256"] != manifest.sha256 for value in self._stage_results), "per-stage manifest replay")
        predispatch, stage_selection = self._reconcile_stage(context, bundle, manifest)
        self._pen_capture("pen_prepared_" + str(index))
        issued = self._live(absolute)
        start = dict(stage=stage, window=dict(clockId=self._plan()["hostClockId"], issuedNs=str(issued),
            absoluteNs=str(absolute), hardDeadlineMs=self.stage_timeout_ms, noRetry=True), runNonce=nonce,
            manifestSha256=manifest.sha256, placementAckSha256=placed["evidenceSha256"],
            penBinding=self._pen_binding, deviceBoottimeMs=str(self._device_ms), foreign=self._foreign)
        # Sample after preparation. The absolute bound is NOT extended by work
        # done while preparing its immutable manifest.
        self._event("capture_started", start, observed=issued)
        self._intent("run_stage_" + str(index), dict(stage=stage, manifestSha256=manifest.sha256, runNonce=nonce), absolute)
        fence = lambda deadline=None:self._stage_fence(context, bundle, predispatch, deadline=deadline)
        def validate_capture(cap):
            _same(runner.stage_policy_sha256(runner._authority(cap.record).value),
                  runner.stage_policy_sha256(runner._authority(predispatch.record).value),
                  "captured retained identity differs before runner publication")
            _need(runner._document_task_semantics_equal(cap.task, predispatch.task),
                  "captured task/activity differs before runner publication")
        cleanup = lambda operation, timeout:self._stage_cleanup_call(fence, absolute, operation, timeout)
        authority_endpoint = self._proxy(bundle.authority_provider,AUTHORITY_METHODS)
        frida_endpoint = self._proxy(bundle.frida_provider,FRIDA_METHODS)
        captured = _CapturedAuthority(authority_endpoint, fence, validate_capture, cleanup)
        fenced_frida = _FencedFrida(frida_endpoint, fence,
            lambda:_need(not captured.sealed, "capture mismatch permanently sealed Frida admission/attach/load"), cleanup,
            lambda target:self._proxy(target,SESSION_METHODS))
        result = _guarded(fence, lambda:self._endpoint("run_stage")(manifest=manifest, observer_source=bundle.observer_source,
            observer_sha256=bundle.observer_sha256, binding=binding, tool_bundle=bundle.tool_bundle,
            authority_provider=captured, frida_provider=fenced_frida,
            trusted_pins=bundle.trusted_pins, ambient_environment={}, clock_ns=self._ns, nonce_factory=lambda: nonce))
        self._live(absolute)
        c._keys(result, "schemaVersion authority stage manifestSha256 observerSha256 runNonce providerAdmissionSha256 "
                "fridaAdmissionSha256 beforeAuthoritySha256 afterAuthoritySha256 beforeReceiptSha256 afterReceiptSha256 toolBundleSha256 snapshot")
        for key in result:
            if key.endswith("Sha256"): c._sha(result[key])
        _same(result["schemaVersion"], 2); _same(result["authority"], runner.RUNNER_AUTHORITY)
        _same(result["stage"], stage["stage"]); _same(result["manifestSha256"], manifest.sha256)
        _same(result["runNonce"], nonce); _same(result["observerSha256"], c.EXPECTED_OBSERVER_SHA256)
        _need(len(captured.captures) == 2, "runner lacks exactly two retained captures")
        before_capture, after_capture = captured.captures
        before_record = runner._authority(before_capture.record)
        after_record = runner._authority(after_capture.record)
        before_receipt = runner._authority(before_capture.receipt)
        after_receipt = runner._authority(after_capture.receipt)
        _same(result["beforeAuthoritySha256"], before_record.sha256)
        _same(result["afterAuthoritySha256"], after_record.sha256)
        _same(result["beforeReceiptSha256"], before_receipt.sha256)
        _same(result["afterReceiptSha256"], after_receipt.sha256)
        for value in (before_record.value, after_record.value):
            _same(runner.stage_policy_sha256(value), runner.stage_policy_sha256(runner._authority(predispatch.record).value),
                  "capture drifted from retained pre-dispatch owners")
            _same(value["host"]["requestedFrame"], stage["rect"])
            _same(value["host"]["measuredGlobalFrame"], stage["rect"])
            _same(value["host"]["hostPackageName"], c.HOST_PACKAGE)
            _same(value["penLease"]["leaseId"], self._pen_binding["leaseToken"])
            _same(value["penLease"]["helperPid"], int(self._pen_binding["worker"]["key"]))
            _same(value["penLease"]["helperStartTimeTicks"], self._pen_binding["worker"]["incarnation"].split(":")[1])
        for cap in captured.captures:
            _need(runner._document_task_semantics_equal(cap.task, predispatch.task), "captured task/activity differs from causal owner")
        runner.validate_snapshot(result["snapshot"], manifest, before_record.value)
        graph = {name: result["snapshot"][name] for name in ("document", "pageInfo", "presenter", "views", "layers", "lifecycle")}
        graph_sha = c.digest(graph)
        if self._stage_results: _same(graph_sha, self._stage_results[0]["graphSha256"], "native graph/page/writer state changed between placements")
        # Actual S7 and S6 expose the frozen methods. Close each stage authority
        # worker; runner already sealed/unloaded/detached/tore down Frida.
        for label, operation in (("authority_stop", authority_endpoint.fail_stop_and_quiesce),
                                 ("authority_quiet", authority_endpoint.assert_quiescent),
                                 ("frida_quiet", frida_endpoint.assert_quiescent)):
            issued, deadline = self._cleanup_call_window(absolute + 250_000_000)
            self._intent(label + "_" + str(index), {"stageIndex": index}, deadline)
            fence(deadline)
            remaining_ms = (deadline - self._live(deadline)) // 1_000_000
            _need(remaining_ms > 0, "cleanup lacks a representable non-rebased timeout")
            try: result_none = operation(remaining_ms)
            finally: fence(deadline); self._live(deadline)
            _verified_none(result_none)
            self._live(deadline)
        self._settle_resources(tuple(role + ":" + str(index) for role in
            ("authority_worker", "frida_worker", "root_frida_server")),
            deadline=absolute + 250_000_000)
        self._active_stage_context = None
        self._pen_capture("pen_after_" + str(index))
        evidence = dict(stage=stage, result=result, graphSha256=graph_sha, stageSelection=stage_selection,
            beforeAuthority=before_record.value, afterAuthority=after_record.value,
            beforeReceipt=before_receipt.value, afterReceipt=after_receipt.value)
        # S5's envelope integer domain is unsigned; native graph coordinates
        # legitimately include negatives. Retain lossless canonical JSON text
        # in bounded chunks, not coerced numbers or a digest-only substitute.
        record = self._record("s8_stage", dict(stageIndex=index, evidence=encode_evidence(evidence)))
        self._stage_results.append(_copy(evidence))
        # Before/after authority equivalence and receipt linking are already
        # authenticated by frozen run_one_stage; retain its result as authority.
        invariant = c.digest(dict(foreign=self._foreign, fixtures=self._plan()["fixtures"], graphSha256=graph_sha))
        self._event("capture_completed", dict(stage=stage, runNonce=nonce, manifestSha256=manifest.sha256,
            beforeSequence=1, afterSequence=2, beforeReceiptSha256=result["beforeReceiptSha256"],
            afterPreviousReceiptSha256=result["beforeReceiptSha256"], afterReceiptSha256=result["afterReceiptSha256"],
            beforeInvariantSha256=invariant, afterInvariantSha256=invariant, beforeGraphSha256=graph_sha,
            afterGraphSha256=graph_sha, quiescenceSha256=c.digest({role:self._closure_proofs[role+":"+str(index)]
                for role in ("authority_worker", "frida_worker", "root_frida_server")}),
            retainedAuthoritySha256=c.digest(self._pin_view()), stageLedgerRecordSha256=record,
            durableCheckpointSha256=self._journal.head, penBinding=self._pen_binding,
            deviceBoottimeMs=str(self._device_ms), foreign=self._foreign))
        # Exact provider teardown plus joined/absent owner receipts end this
        # stage's authority. Keep detached canonical evidence and predecessor
        # identities, not caller-owned completed graphs in later hot fences.
        stage_keys=tuple(role+":"+str(index) for role in
            ("authority_worker","frida_worker","root_frida_server"))
        _need(all(key in self._completed_resources and key in self._closure_proofs for key in stage_keys),
              "stage cannot retire live cleanup authority")
        retained_context=_anchor(context)[0]()
        retired=tuple((key,_anchor(self._identities[key])[0]()) for key in stage_keys)
        self._record("s8_inventory_retired",dict(sourceRecordSha256=materialization_record,
            keys=list(stage_keys),checkpoint=self._ownership_checkpoint()))
        self._retire_scope(scope)
        for key,binding in retired:
            self._identities[key]=binding
            self._add_fast_guard(_anchor(binding)[1])
        self._retained_context=retained_context
        # Evidence reads after this stage still bind the last exact placement;
        # this detached context is not a reusable stage/provider capability.
        self._add_fast_guard(_anchor(retained_context)[1])

    def _reconcile_stage(self, context, bundle, manifest):
        """No provider admission, capture, attach or load precedes this gate.

        Each port supplies its own retained view. The factory cannot declare
        what another owner holds, and a stage-policy digest is not such proof.
        """
        deadline, index = context.binding.absolute_deadline_ns, context.stage_index
        views = {}
        for role in ("reader", "host", "supervisor", "reopen"):
            views[role] = c.load_canonical(_guarded(lambda:self._retained_fence(deadline),
                lambda:self._invoke(self._endpoint(role),"stage_evidence",context,deadline)))
            self._verify(role); self._live(deadline)
        pre = _guarded(lambda:self._retained_fence(deadline), lambda:self._invoke(bundle.authority_provider,"predispatch",context,deadline))
        _need(type(pre) is PredispatchView and type(pre.task) is runner.DocumentTaskAuthority,
              "selected provider cannot prove retained pre-dispatch authority")
        pre_view, pre_check, _ = _anchor(pre); self._add_guard(pre_check)
        pre = pre_view()
        _same(pre.context_sha256, context_sha256(context))
        _need(type(pre.deadline_ns) is int and pre.deadline_ns == deadline, "provider launch deadline rebased")
        record = runner._authority(pre.record).value
        _same(record["manifestSha256"], manifest.sha256)
        _same(runner.stage_policy_sha256(record), bundle.trusted_pins.stage_policy_sha256)
        _same(record["files"], manifest.value["files"], "manifest descriptor identity differs")
        selection = selection_authority(context,manifest.sha256)
        _same(selection["documentUri"],self._selection_view().document_uri)
        _same(selection["requestedPageIndex"],self._selection_view().page_index)
        selection_raw = c.canonical_bytes(selection); selection_hash = _sha(selection_raw)
        c._keys(views["reader"], "privateAdbServer target firmware files fixtures observerSha256 selectionAuthoritySha256")
        _same(views["reader"]["selectionAuthoritySha256"],selection_hash)
        for name in ("privateAdbServer", "target", "firmware", "files"):
            _same(record[name], views["reader"][name], "reader/selected provider " + name + " identity mismatch")
        _same(views["reader"]["fixtures"], self._plan()["fixtures"])
        _same(views["reader"]["observerSha256"], bundle.observer_sha256)
        _same(_sha(bundle.observer_source.encode("utf-8")), c.EXPECTED_OBSERVER_SHA256)
        adb = record["privateAdbServer"]
        retained_adb = self._identities["private_adb_server"].identity
        _same(str(adb["pid"]), retained_adb.key)
        _same(adb["processCreationFileTime"], retained_adb.incarnation.split(":", 1)[1])
        _same(record["target"]["pid"], int(self._foreign["process"]["identity"]["key"]))
        _same(record["target"]["startTimeTicks"], self._foreign["process"]["identity"]["incarnation"].split(":", 1)[1])
        c._keys(views["supervisor"], "foreign task selectionAuthoritySha256")
        _same(views["supervisor"]["selectionAuthoritySha256"],selection_hash)
        _same(views["supervisor"]["foreign"], self._foreign)
        task = c.load_canonical(pre.task.canonical_bytes())
        _same(task, views["supervisor"]["task"], "captured activity differs from causal launch/attach owner")
        _same(pre.task.activity_token, self._foreign["activityToken"])
        _same(pre.task.task_id, self._foreign["taskId"])
        _same(pre.task.pid, record["target"]["pid"])
        _same(record["taskAuthoritySha256"], _sha(pre.task.canonical_bytes()))
        c._keys(views["host"], "host display hostSessionId")
        _same(views["host"]["display"], self._display)
        _same(views["host"]["hostSessionId"], self._plan()["hostSessionId"])
        _same(record["host"], views["host"]["host"], "host owner APK/task/activity/placement differs")
        _same(record["host"]["hostPackageName"], c.HOST_PACKAGE)
        _same(record["host"]["hostSessionId"], self._display["hostSessionId"])
        _same(record["host"]["displayId"], self._display["displayId"])
        _same(record["host"]["displayGeneration"], self._display["generation"])
        _same(record["host"]["requestedFrame"], self._plan()["stages"][index]["rect"])
        _same(record["host"]["measuredGlobalFrame"], self._plan()["stages"][index]["rect"])
        _same(views["reopen"], {"ordinaryRouteAuthoritySha256": self._pin_view()["reopen"]})
        lease = record["penLease"]
        _same(lease["leaseId"], self._pen_binding["leaseToken"])
        _same(lease["helperPid"], int(self._pen_binding["worker"]["key"]))
        _same(lease["helperStartTimeTicks"], self._pen_binding["worker"]["incarnation"].split(":", 1)[1])
        _same(lease["holderSessionId"], self._plan()["runSessionId"])
        _same(lease["deviceClockDomain"], "android-boottime-v1")
        selected = c.load_canonical(_guarded(lambda:self._retained_fence(deadline),
            lambda:self._invoke(bundle.frida_provider,"predispatch",context,deadline)))
        c._keys(selected, "contextSha256 deadlineNs frida epoch forbiddenOwnersSha256 exclusionAppliedBeforeAttach")
        _same(selected["contextSha256"], context_sha256(context)); _same(selected["deadlineNs"], str(deadline))
        _same(selected["epoch"], stage_epoch(context))
        _same(selected["forbiddenOwnersSha256"], _sha(context.forbidden_owners_raw))
        _same(selected["exclusionAppliedBeforeAttach"], True)
        _same(selected["frida"], record["frida"], "selected Frida owner differs from captured server")
        epoch = stage_epoch(context); frida = record["frida"]
        admitted_server=self._identities["root_frida_server:"+str(index)].identity
        _same(str(frida["serverPid"]),admitted_server.key,"Frida differs from admitted complete inventory")
        for field in ("providerSessionId", "serverSessionId"):
            _same(frida[field], epoch[field], "Frida stage epoch is not deterministically bound")
        _same(record["providerSessionId"], epoch["providerSessionId"])
        _same(frida["serverPath"], epoch["stagingPath"])
        _same(frida["serverCmdline"], epoch["stagingPath"])
        server = c.ResourceIdentity("process", c.AUTHORIZED_SERIAL, str(frida["serverPid"]),
            self._boot + ":" + frida["serverStartTimeTicks"])
        for forbidden in c.load_canonical(context.forbidden_owners_raw):
            _need((server.kind, server.namespace, server.key) !=
                  (forbidden["kind"], forbidden["namespace"], forbidden["key"]),
                  "Frida aliases stock/pen/previous server owner before attach")
        _same(server.wire(),admitted_server.wire(),"Frida server differs from admitted complete inventory")
        transitions = c.load_canonical(bundle.worker_transitions_raw)
        expected_transitions = {}
        for role in ("authority_worker", "frida_worker", "root_frida_server"):
            current = self._identities[role + ":" + str(index)].identity.wire()
            prior = None if index == 0 else self._identities[role + ":" + str(index - 1)].identity.wire()
            expected_transitions[role] = dict(previous=prior, current=current,
                predecessorClosure=None if index == 0 else self._closure_proofs[role + ":" + str(index - 1)],
                epoch=epoch["epoch"], contextSha256=context_sha256(context), retainedSuccessorOpen=True)
        _same(transitions, expected_transitions, "stage predecessor-close/successor-open authority differs")
        # Only placement fields and the explicitly versioned stage epoch vary.
        static_host = dict(record["host"])
        for name in ("stage", "requestedFrame", "measuredGlobalFrame", "placementRequestGeneration", "placementReadyGeneration"):
            static_host.pop(name, None)
        static_task = dict(task); static_task.pop("raw_sha256", None)
        static_frida = dict(frida)
        for name in ("providerSessionId", "serverSessionId", "serverPath", "serverCmdline", "serverPid", "serverStartTimeTicks"):
            static_frida.pop(name, None)
        shared = dict(reader=self._identity_views(views)["reader"], host=static_host, task=static_task, fridaRuntime=static_frida,
            observerSha256=bundle.observer_sha256, routePins=self._pin_view(), foreign=self._foreign, pen=self._pen_binding)
        if self._shared_stage_identity is None: self._shared_stage_identity = _copy(shared)
        else: _same(shared, self._shared_stage_identity, "shared visual-run identity changed across stages")
        self._verify("stages"); self._live(deadline)
        self._record("s8_stage_admitted", dict(stageIndex=index, evidence=encode_evidence(dict(
            contextSha256=context_sha256(context), owners=views, record=record, task=task,
            transitions=transitions, selectedFrida=selected, stageSelection=c.load_canonical(selection_raw)))))
        self._live(deadline)
        self._admitted_views = _copy(views)
        self._active_stage_context = context
        self._retained_context = context
        self._retained_views = self._identity_views(views)
        self._retained_fence(deadline)
        return pre, c.load_canonical(selection_raw)

    def _stage_cleanup_call(self, fence, absolute, operation, timeout_ms):
        _need(type(absolute) is int, "exact original stage deadline required")
        _need(type(timeout_ms) is int and timeout_ms > 0, "exact cleanup timeout required")
        issued, deadline = self._cleanup_call_window(absolute + 250_000_000)
        deadline = min(deadline, issued + timeout_ms * 1_000_000)
        def bounded_fence():
            fence(deadline); self._live(deadline)
        bounded_fence()
        remaining_ms = (deadline - self._live(deadline)) // 1_000_000
        _need(remaining_ms > 0, "cleanup has no non-rebased millisecond budget")
        # The frozen methods accept a relative integer, not an absolute value.
        # Floor the remaining time immediately at dispatch and retain/recheck
        # the original absolute bound here; never round up or restart it.
        try: result = operation(remaining_ms)
        finally: bounded_fence()
        return _verified_none(result)

    def _stage_fence(self, context, bundle, pre, *, deadline=None):
        try: self._stage_fence_checks(context, bundle, pre, deadline)
        except BaseException:
            self._authority_sealed = True
            raise

    def _stage_fence_checks(self, context, bundle, pre, deadline):
        # Retained-handle checks remain available after exit and never launch,
        # attach or observe through a replacement process. Failure retains all
        # obligations; even cleanup does not get permission to retarget.
        _need(self._active_stage_context is context and not self._quarantined,
              "provider lifecycle request belongs to an inactive stage")
        bound = context.binding.absolute_deadline_ns if deadline is None else deadline
        _need(type(bound) is int and bound <= context.binding.absolute_deadline_ns + 250_000_000,
              "stage identity-read deadline rebased")
        self._retained_fence(bound,exact_views=self._admitted_views)
        _need(self._invoke(bundle.authority_provider,"verify_retained",context) is None and
              self._invoke(bundle.frida_provider,"verify_retained",context) is None, "selected provider retention proof unavailable")
        self._root_check(); self._live(bound)

    def _cleanup_event(self, index, details, intent, completion):
        step, owner = c.CLEANUP_STEPS[index]
        self._event("cleanup_step", dict(stepIndex=index, stepId=step, owner=owner, evidenceSha256=c.digest(details),
            intentRecordSha256=intent, completionRecordSha256=completion,
            durableCheckpointSha256=self._journal.head, attempt=1, details=details))

    def _cleanup(self):
        self._install_cleanup_total(min(self._ns() + 250_000_000, self._stage_bound() + 250_000_000))
        self._live(self._cleanup_deadline)
        self._event("begin_cleanup", dict(primaryFailure=False, evidenceSha256=self._journal.head))
        for index, (step, owner) in enumerate(c.CLEANUP_STEPS):
            intent = self._intent("cleanup_" + step, {"owner": owner}, self._operation_deadline())
            if index == 0:
                _need(all(role+":"+str(stage) in self._completed_resources for stage in range(4)
                          for role in ("authority_worker", "frida_worker", "root_frida_server")),
                      "stage owner closures are incomplete")
                details = dict(callbacksSealed=True, unloaded=True, detached=True, isolatedWorkersClosed=True)
            elif index == 1:
                present = self._call("reader", Operation.EXACT_TASK, {"foreign": self._foreign})
                _same(present, {"status": "present", "foreign": self._foreign})
                details = self._call("host", Operation.RESTORE, {"foreign": self._foreign, "placement": "FULL"})
            elif index == 2:
                destroyed = self._call("supervisor", Operation.DESTROY_TASK,
                    dict(foreign=self._foreign, display=self._display, disposableAfterAttachOnly=True))
                _same(destroyed, {"foreign": self._foreign, "exactTaskAbsent": True})
                details = self._call("host", Operation.TASK_ABSENT, dict(foreign=self._foreign, display=self._display))
                # S0 validates exact task/display absence before disposal is
                # recorded; a port success boolean alone does not release pen.
            elif index == 3:
                details = self._call("host", Operation.RELEASE_DISPLAY, dict(display=self._display, foreign=self._foreign))
            elif index == 4:
                details = self._call("reader", Operation.FINAL_ABSENCE, dict(stockProcess=self._stock, display=self._display,
                    foreign=self._foreign, allDisplays=True, penStillHeld=True))
            elif index == 5:
                final = pen.FinalAbsenceProof(pen.StageSession(self._plan()["runSessionId"]),
                    self._pen_binding["leaseToken"], self._absence)
                deadline = self._operation_deadline()
                self._intent("pen_finish", dict(finalAbsenceSha256=self._absence), deadline)
                closure = _guarded(lambda:self._retained_fence(deadline), lambda:self._invoke(self._endpoint("pen_peer"),"finish",final))
                self._live(deadline)
                _need(type(closure) is pen.ClosureProof and closure.peer == self._endpoint("pen_peer").binding.peer and
                    type(closure.exit_code) is int and closure.exit_code == 0 and closure.output_eof is True and
                    closure.trailing_output == b"" and self._endpoint("pen_peer").state is pen.Lifecycle.RELEASED, "authenticated pen closure missing")
                self._pen_closure = closure
                reacquired = self._call("reader", Operation.REACQUIRE, dict(penBinding=self._pen_binding, finalAbsenceSha256=self._absence))
                _same(reacquired, {"independentDeviceReacquireProven": True, "testGrabClosed": True, "penBinding": self._pen_binding})
                details = dict(penBinding=self._pen_binding, authenticatedReleased=True, sealedControlAndPhaseBeforeRelease=True,
                               workerGuardianPeerClosed=True, independentDeviceReacquireProven=True)
            elif index == 6:
                _need(self._absence is not None and self._endpoint("pen_peer").state is pen.Lifecycle.RELEASED, "stock reopen lacks pen/foreign closure")
                details = self._call("reopen", Operation.REOPEN, dict(component=c.COMPONENT, displayId=0,
                    selection=self._selection_view().wire(), ordinaryRouteOnly=True, untouchedStockProcess=self._stock,
                    ordinaryRouteAuthoritySha256=self._pin_view()["reopen"],
                    stageSelectionSha256=[c.digest(value["stageSelection"]) for value in self._stage_results]))
                _same(details["ordinaryRouteAuthoritySha256"], self._pin_view()["reopen"], "ordinary route authority substitution")
            else:
                details = self._call("reader", Operation.UNCHANGED, dict(fixtures=self._plan()["fixtures"], selection=self._selection_view().wire()))
            completion = self._record("s8_cleanup_proof", dict(stepIndex=index, details=details))
            self._cleanup_event(index, details, intent, completion)
            if index == 2: self._settle_resources(("foreign_task",))
            if index == 3: self._settle_resources(("virtual_display", "host_session"))
            if index == 4: self._absence = c.digest(details)
            if index == 5: self._settle_resources(("device_peer", "pen_worker", "pen_guardian", "pen_lease"))
            self._live(self._cleanup_deadline)
        # S1 remains available for pen reacquisition, ordinary reopen and the
        # final read-only file capture. Its own server is closed only afterward;
        # this fixed operation cannot name another PID or any pen/stock owner.
        private = self._endpoint("private_adb_resource").identity.wire()
        closed = self._call("reader", Operation.CLOSE_PRIVATE_ADB, {"identity": private})
        _same(closed, {"identity": private, "exactServerAbsent": True, "clientsClosed": True, "listenerAbsent": True})
        self._settle_resources(("private_adb_server",))

    def _finish_result(self):
        _need(self.model.phase == "CLEAN" and not self.ownership.remaining, "result lacks exact cleanup")
        bound = self._cleanup_total()
        self._retained_fence(bound)
        _need(self._invoke(self.ownership,"finalize") is True, "ownership ledger did not finalize cleanly")
        self._retained_fence(bound)
        checkpoint = self._ownership_checkpoint()
        self._retained_fence(bound)
        external=ledger.RecoveryCheckpoint(checkpoint["ledgerId"],checkpoint["sequence"],checkpoint["sha256"])
        with self._invoke(self._ownership_store,"exclusive"):
            prefix=_ownership_prefix(lambda name:self._invoke(self._ownership_store,"read",name),external)
        self._retained_fence(bound)
        creation_state=_replay_creations(self._journal.records,self._plan(),prefix,external)
        _need(creation_state["complete"],"terminal decision has unresolved creation/registration obligations")
        self._retained_fence(bound)
        result = dict(authority=AUTHORITY, schemaVersion=1, runSessionId=self._plan()["runSessionId"],
            contractSha256=self._contract_hash(), status="CLEAN", admission=admission_status(),
            stageEvidenceSha256=[c.digest(value) for value in self._stage_results],
            selection=self._selection_view().wire(), stageSelectionSha256=[c.digest(value["stageSelection"]) for value in self._stage_results],
            ownershipCheckpoint=checkpoint, eventHeadSha256=self.model.event_head[1],
            remaining=[], files=self._plan()["fixtures"], noRetry=True)
        raw = c.canonical_bytes(result)
        # The persisted terminal decision is the linearization point. Complete
        # all clock/serialization/authority work first; never retroactively
        # overwrite a committed decision because a later observation is late.
        self._retained_fence(bound)
        self._live(bound)
        self._terminal_attempted = True
        self._record("s8_finished", result)
        self._terminal_result = raw
        return raw

    def _quarantine(self, error):
        if self._terminal_attempted or self._terminal_result is not None: return
        self._quarantined = True
        reason = type(error).__name__ + ": " + str(error)[:1000]
        # No cleanup, retry, ordinary reopen, worker kill or broad PID search.
        # A durable earlier intent is the fallback if publication itself failed.
        try:
            self._verify_pen_identity()
            if self._retained_pen.state not in (pen.Lifecycle.NEW, pen.Lifecycle.RELEASED):
                self._invoke(self._retained_pen,"quarantine",reason)
        except BaseException:
            # Keep the original peer/transport retained; a substituted scope
            # cannot receive even a quarantine command on another owner's behalf.
            pass
        try: self._invoke(self._original_owned(),"primary_failure",reason)
        except BaseException: pass
        try: self._record("s8_quarantine", dict(reason=reason, retained=[b.identity.wire() for b in self._identities.values()],
            pendingOperations=sorted(self._attempted),pendingInventoryBatches=self._pending_inventory_evidence(),recoveryRequired=True))
        except BaseException: pass

    @staticmethod
    def recover(contract, selection, journal_store, ownership_store, clock):
        """Read/replay only. No port is accepted, so recovery cannot mutate/kill.

        Even a completed diagnostic record is evidence, not permission to run
        again. Pending publication/operation intent requires reviewed recovery.
        """
        _need(type(contract) is c.RunContract and type(selection) is Selection and
              (type(clock) is types.FunctionType or type(clock) is types.MethodType), "exact recovery inputs required")
        cv, cc, _ = _anchor(contract); sv, sc, _ = _anchor(selection)
        original_contract, original_selection = contract, selection
        contract, selection = cv(), sv()
        c.RunContract(contract.raw); Selection(selection.document_uri,selection.page_index)
        store_check = _store_pair(journal_store,ownership_store)
        function = clock.__func__ if type(clock) is types.MethodType else clock
        code = function.__code__
        now = clock()
        _need(type(now) is c.HostInstant and type(now.clock_id) is str and type(now.nanoseconds) is int and
              now.clock_id == contract.value["hostClockId"] and now.nanoseconds >= int(contract.value["createdHostNs"]),
              "recovery clock identity differs")
        fixed_ns = now.nanoseconds
        def recovery_check():
            cc(); sc(); store_check()
            _need(type(original_contract) is c.RunContract and type(original_selection) is Selection and
                  function.__code__ is code, "recovery input replaced during store access")
        recovery_check()
        journal = EventJournal(journal_store, contract, selection, recover=True)
        recovery_check()
        checkpoint = ownership_store.load_checkpoint()
        recovery_check()
        owned = ledger.CleanupLedger.recover(ownership_store, lambda:fixed_ns,
                                             contract.value["hostClockId"], checkpoint=checkpoint)
        recovery_check()
        with ownership_store.exclusive():prefix=_ownership_prefix(ownership_store.read,checkpoint)
        recovery_check()
        creation_state=_replay_creations(journal.records,contract.value,prefix,checkpoint)
        model = c.CoordinatorModel(contract)
        intents, completed, stages, admitted, terminal, retained = {}, set(), [], [], None, []
        inventory_batches=[]
        allowed = {"s8_opened", "s8_intent", "s8_result", "s8_pen", "s8_owned", "s8_owner_closed", "s8_model", "s8_stage", "s8_stage_admitted", "s8_cleanup_proof", "s8_finished", "s8_quarantine","s8_inventory_batch", "s8_creation_window", "s8_creation_materialized", "s8_inventory_retired"}
        for record in journal.records:
            event, data = record["event"], record["data"]
            _need(event in allowed and terminal is None, "unknown/post-terminal journal event")
            if event == "s8_intent":
                c._keys(data, "operation deadlineNs request")
                _need(data["operation"] not in intents, "replayed durable operation")
                intents[data["operation"]] = record
            elif event == "s8_result":
                c._keys(data, "operation intentSha256 receipt")
                _need(data["operation"] in intents and data["operation"] not in completed, "orphan/replayed result")
                intent = intents[data["operation"]]
                _same(data["intentSha256"], intent["hash"])
                _same(data["receipt"]["requestSha256"], c.digest(intent["data"]["request"]))
                _same(data["receipt"]["commandId"], data["operation"])
                _same(data["receipt"]["runSessionId"], contract.value["runSessionId"])
                completed.add(data["operation"])
            elif event == "s8_owned": retained.append(data)
            elif event == "s8_model":
                model.apply(c.canonical_bytes(data), c.HostInstant(contract.value["hostClockId"], int(data["observedHostNs"])))
            elif event == "s8_stage_admitted":
                _same(data["stageIndex"], len(admitted))
                _need(len(admitted) == len(stages), "new stage admitted before predecessor completed")
                admitted.append(decode_evidence(data["evidence"]))
                selected = admitted[-1]["stageSelection"]
                c._keys(selected,"authority schemaVersion runSessionId contractSha256 documentUri requestedPageIndex stageIndex stage contextSha256 manifestSha256 causalLaunchAttach")
                causal = selected["causalLaunchAttach"]
                c._keys(causal,"launch command attached")
                launch_intent = intents[Operation.LAUNCH.value]["data"]["request"]["request"]
                attach_intent = intents[Operation.ATTACH.value]["data"]["request"]["request"]
                _same(causal["command"],launch_intent); _same(causal["launch"],attach_intent)
                attachment = next(r["data"]["receipt"]["body"] for r in journal.records
                    if r["event"] == "s8_result" and r["data"]["operation"] == Operation.ATTACH.value)
                attachment=_copy(attachment)
                inventory=attachment.pop("ownerInventory")
                _same(inventory,[_binding_wire(c.ResourceBinding("foreign_task","root_supervisor",
                    c.ResourceIdentity.parse(attachment["foreign"]["identity"])))])
                _same(causal["attached"],attachment)
                _same(selected["authority"],"rtl-reader-native-page-stage-selection-v1")
                _same(selected["schemaVersion"],1); _same(selected["runSessionId"],contract.value["runSessionId"])
                _same(selected["contractSha256"],contract.sha256)
                _same(selected["documentUri"],selection.document_uri); _same(selected["requestedPageIndex"],selection.page_index)
                _same(selected["stageIndex"],len(stages)); _same(selected["stage"],contract.value["stages"][len(stages)]["stage"])
                _same(selected["contextSha256"],admitted[-1]["contextSha256"])
                _same(selected["manifestSha256"],admitted[-1]["record"]["manifestSha256"])
                for role in ("reader","supervisor"):
                    _same(admitted[-1]["owners"][role]["selectionAuthoritySha256"],c.digest(selected))
            elif event == "s8_stage":
                c._keys(data, "stageIndex evidence")
                _same(data["stageIndex"], len(stages))
                value = decode_evidence(data["evidence"])
                _need(len(admitted) == len(stages) + 1, "stage lacks durable pre-dispatch owner proof")
                _same(runner.stage_policy_sha256(value["beforeAuthority"]),
                      runner.stage_policy_sha256(admitted[-1]["record"]))
                _same(runner.stage_policy_sha256(value["afterAuthority"]),
                      runner.stage_policy_sha256(admitted[-1]["record"]))
                _same(value["stage"], contract.value["stages"][len(stages)])
                _same(value["stageSelection"],admitted[-1]["stageSelection"])
                stages.append(value)
            elif event in ("s8_finished", "s8_quarantine"):
                terminal = event
                if event=="s8_quarantine":inventory_batches.extend(data["pendingInventoryBatches"])
        clean = terminal == "s8_finished" and model.phase == "CLEAN" and owned.successful and len(stages) == 4 and creation_state["complete"]
        _need(terminal!="s8_finished" or clean,"terminal decision contradicts unresolved creation/ownership state")
        if clean:
            final = journal.records[-1]["data"]
            _same(final["contractSha256"], contract.sha256); _same(final["runSessionId"], contract.value["runSessionId"])
            _same(final["files"], contract.value["fixtures"]); _same(final["eventHeadSha256"], model.event_head[1])
            _same(final["selection"],selection.wire())
            _same(final["stageSelectionSha256"],[c.digest(value["stageSelection"]) for value in stages])
            _same(journal.records[-1]["data"]["stageEvidenceSha256"], [c.digest(value) for value in stages])
            _same(journal.records[-1]["data"]["ownershipCheckpoint"],
                dict(ledgerId=checkpoint.ledger_id, sequence=checkpoint.sequence, sha256=checkpoint.record_sha256))
        recovery_check()
        # Rejected observations are not acquisition authorities and cannot
        # replace a source's exact bindings. Preserve the existing pending
        # report contract with an explicitly identity-free unresolved marker;
        # keep the possibly contradictory observations in a separate field.
        pending_creation=list(creation_state["pending"])
        if inventory_batches:
            pending_creation.append(_pending_inventory("coordinator","rejected_inventory_unresolved",[],
                unresolved=sum(len(batch["bindings"])+batch["unresolvedHandleCount"] for batch in inventory_batches),
                reported=c.digest(inventory_batches)))
        pending_context=_pending_inventory_context(journal.records,prefix)
        for item in pending_creation:_validate_pending_inventory(item,pending_context)
        return c.canonical_bytes(dict(authority=AUTHORITY, runSessionId=contract.value["runSessionId"],
            contractSha256=contract.sha256, selection=selection.wire(),
            stageSelectionSha256=[c.digest(value["stageSelection"]) for value in stages],
            status="CLEAN_EVIDENCE_ONLY" if clean else "RETAINED_QUARANTINE", resumeAllowed=False,
            recoveryRequired=not clean, remaining=list(owned.remaining), journalHeadSha256=journal.head,
            pendingInventoryBatches=[] if clean else pending_creation,
            rejectedInventoryEvidence=[] if clean else inventory_batches,
            retainedIdentities=retained, attemptedOperations=sorted(intents), admission=admission_status()))
