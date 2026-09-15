import copy
import hashlib
import hmac
import inspect
import json
import pickle
import sys
import threading
import unittest
import weakref
from dataclasses import FrozenInstanceError, replace

import native_page_worker_capability_ipc as ipc


SESSION_KEY = b"k" * 32
RAW_TRACEBACK_SLOT = BaseException.__dict__["__traceback__"]
RAW_CONTEXT_SLOT = BaseException.__dict__["__context__"]
RAW_CAUSE_SLOT = BaseException.__dict__["__cause__"]
RAW_GROUP_EXCEPTIONS_SLOT = BaseExceptionGroup.__dict__["exceptions"]
STACK_STEAL_ATTEMPTS = []


def digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class FakeClock:
    def __init__(self):
        self.value = 1_000_000_000

    def now_ns(self):
        return self.value

    def advance(self, amount=1_000_000):
        self.value += amount


class FakeCrypto:
    def __init__(self):
        self.challenge_counter = 0
        self.hmac_error = None
        self.hmac_hook = None
        self.sha_hook = None

    def challenge(self, size):
        if type(size) is not int or size != 32:
            raise ipc.CapabilityIpcError("wrong challenge size")
        self.challenge_counter += 1
        return self.challenge_counter.to_bytes(32, "big")

    def sha256(self, payload):
        if self.sha_hook is not None:
            self.sha_hook()
        return hashlib.sha256(payload).digest()

    def hmac_sha256(self, key, payload):
        if self.hmac_hook is not None:
            self.hmac_hook(payload)
        if self.hmac_error is not None:
            raise self.hmac_error
        return hmac.new(key, payload, hashlib.sha256).digest()

    def compare_digest(self, left, right):
        return hmac.compare_digest(left, right)


_EPOCH_COUNTER_LOCK = threading.Lock()
_EPOCH_COUNTER = 0


class FakeEpochAdmission:
    def __init__(self, factory_id, role, session_id, owner_object_id, label):
        global _EPOCH_COUNTER
        with _EPOCH_COUNTER_LOCK:
            _EPOCH_COUNTER += 1
            ordinal = _EPOCH_COUNTER
        self.value = ipc.SessionEpochBinding(
            ipc.SESSION_EPOCH_AUTHORITY,
            digest(f"epoch:{label}:{ordinal}"),
            digest(f"admission:{label}:{ordinal}"),
            session_id, factory_id, role, owner_object_id, True, True)
        self.used = set()
        self.active = set()
        self.revoked = set()

    def binding(self):
        return self.value

    def admit(self, expected, side):
        if expected is not self.value or side not in {"parent", "child"} or side in self.used:
            raise ipc.CapabilityIpcError("session epoch admission replayed or substituted")
        self.used.add(side)
        self.active.add(side)

    def verify_admitted(self, expected, side):
        if expected is not self.value or side not in self.active:
            raise ipc.CapabilityIpcError("session epoch is not admitted")

    def revoke(self, expected, side):
        if expected is not self.value or side not in self.used:
            raise ipc.CapabilityIpcError("session epoch revoke is substituted")
        self.active.discard(side)
        self.revoked.add(side)

    def verify_revoked(self, expected, side):
        if expected is not self.value or side not in self.revoked or side in self.active:
            raise ipc.CapabilityIpcError("session epoch revocation is not proven")


def identity(capability_id, numeric, kind, rights=("read",)):
    return ipc.HandleIdentity(
        ipc.HANDLE_AUTHORITY, capability_id, numeric,
        digest(f"object:{capability_id}:{numeric}"), 701, 9001, kind,
        tuple(sorted(rights)), True, True)


class FakeHandleAuthority:
    def __init__(self):
        self.values = {}
        self.calls = []
        self.identity_error = None
        self.identity_errors = {}

    def retain(self, handle, expected):
        self.values[id(handle)] = expected

    def identity(self, retained_handle):
        self.calls.append(retained_handle)
        targeted_error = self.identity_errors.get(id(retained_handle))
        if targeted_error is not None:
            raise targeted_error
        if self.identity_error is not None:
            raise self.identity_error
        if id(retained_handle) not in self.values:
            raise ipc.CapabilityIpcError("unretained handle")
        return self.values[id(retained_handle)]

    def stale(self, handle):
        old = self.values[id(handle)]
        self.values[id(handle)] = replace(
            old, object_id=digest("reused:" + old.object_id))


class SharedTransport:
    def __init__(self, binding, events):
        self.binding_value = binding
        self.events = events
        self.changed = False
        self.parent_to_child = []
        self.child_to_parent = []
        self.history = []
        self.revoked = False
        self.revocations = []
        self.sealed = set()
        self.send_counts = {"parent": 0, "child": 0}
        self.receive_counts = {"parent": 0, "child": 0}
        self.fail_send = set()
        self.fail_receive = set()
        self.fail_seal = False
        self.fail_send_seal_verify = False
        self.fail_revoke = False
        self.fail_quiescent = False
        self.send_hooks = {}
        self.receive_hooks = {}
        self.quiescent_hook = None
        self.post_quiescent_hook = None
        self.verify_hook = None
        self.quiescent_requests = []
        self.send_error = None


class FakeTransport:
    def __init__(self, shared, side):
        self.shared = shared
        self.side = side

    def binding(self):
        if self.shared.changed:
            return replace(self.shared.binding_value, channel_id=digest("changed channel"))
        return self.shared.binding_value

    def verify(self, expected):
        if self.shared.verify_hook is not None:
            self.shared.verify_hook()
        if self.shared.changed or expected != self.shared.binding_value:
            raise ipc.CapabilityIpcError("transport identity drift")

    def send(self, packet, deadline_ns):
        self.shared.send_counts[self.side] += 1
        index = self.shared.send_counts[self.side]
        if self.shared.send_error is not None:
            raise self.shared.send_error
        if self.shared.revoked or (self.side, index) in self.shared.fail_send:
            raise ipc.CapabilityIpcError("transport send killed")
        hook = self.shared.send_hooks.get((self.side, index))
        if hook is not None:
            hook()
        if self.shared.revoked:
            raise ipc.CapabilityIpcError("transport revoked during send")
        self.shared.history.append((self.side, packet, deadline_ns))
        self.shared.events.append(self.side + "_send")
        target = (self.shared.parent_to_child if self.side == "parent"
                  else self.shared.child_to_parent)
        target.append(packet)

    def receive(self, deadline_ns):
        self.shared.receive_counts[self.side] += 1
        index = self.shared.receive_counts[self.side]
        if (self.side, index) in self.shared.fail_receive:
            raise ipc.CapabilityIpcError("transport receive killed")
        hook = self.shared.receive_hooks.get((self.side, index))
        if hook is not None:
            hook()
        if self.shared.revoked:
            return None
        source = (self.shared.child_to_parent if self.side == "parent"
                  else self.shared.parent_to_child)
        return source.pop(0) if source else None

    def seal_send(self, request_id, deadline_ns):
        if self.shared.fail_seal or self.shared.revoked:
            raise ipc.CapabilityIpcError("send endpoint seal failed")
        self.shared.sealed.add(request_id)

    def verify_send_sealed(self, request_id):
        if self.shared.fail_send_seal_verify or request_id not in self.shared.sealed:
            raise ipc.CapabilityIpcError("send endpoint not sealed")

    def revoke(self, request_id, deadline_ns):
        self.shared.revocations.append((request_id, deadline_ns))
        if self.shared.fail_revoke:
            raise ipc.CapabilityIpcError("transport revoke failed")
        self.shared.revoked = True
        self.shared.parent_to_child.clear()
        self.shared.child_to_parent.clear()
        if request_id is not None:
            self.shared.sealed.add(request_id)

    def verify_quiescent(self, request_id, challenge):
        self.shared.quiescent_requests.append((self.side, request_id))
        if self.shared.quiescent_hook is not None:
            self.shared.quiescent_hook(challenge)
        if self.shared.fail_quiescent or self.shared.changed:
            raise ipc.CapabilityIpcError("transport quiescence unavailable")
        if self.shared.revoked:
            pass
        elif request_id is None:
            if self.shared.parent_to_child or self.shared.child_to_parent:
                raise ipc.CapabilityIpcError("transport queues are not empty")
        elif request_id not in self.shared.sealed or self.shared.child_to_parent:
            raise ipc.CapabilityIpcError("operation endpoint is not sealed and drained")
        if self.shared.post_quiescent_hook is not None:
            self.shared.post_quiescent_hook(challenge)
        return ipc.make_quiescence_receipt(challenge, "transport")


class FakeOperationOwner:
    def __init__(self, capability, owner_handle, clock, crypto, events):
        self.value = ipc.make_operation_owner_binding(capability, crypto)
        self.owner_handle = owner_handle
        self.clock = clock
        self.events = events
        self.alias = None
        self.changed = False
        self.active = None
        self.completed = set()
        self.revoked = set()
        self.fail_admit = False
        self.fail_settle = False
        self.fail_revoke = False
        self.fail_quiescent = False
        self.settle_hook = None
        self.quiescent_hook = None
        self.post_quiescent_hook = None
        self.quiescent_requests = []

    def binding(self, retained_owner):
        if retained_owner is not self.owner_handle:
            raise ipc.CapabilityIpcError("operation owner handle substituted")
        if self.alias is not None:
            return self.alias
        if self.changed:
            return replace(self.value, session_id=digest("changed owner session"))
        return self.value

    def verify(self, expected):
        if self.changed or expected != self.value:
            raise ipc.CapabilityIpcError("operation owner binding drift")

    def admit(self, retained_owner, expected, lease):
        if (retained_owner is not self.owner_handle or expected != self.value or
                type(lease) is not ipc.OperationLease or self.active is not None or
                self.clock.now_ns() >= lease.deadline_ns or self.fail_admit):
            raise ipc.CapabilityIpcError("operation owner admission failed")
        self.active = lease
        self.events.append("owner_admit")

    def settle(self, retained_owner, expected, lease):
        if self.settle_hook is not None:
            self.settle_hook()
        if (retained_owner is not self.owner_handle or expected != self.value or
                type(lease) is not ipc.OperationLease or lease is not self.active or
                self.clock.now_ns() >= lease.deadline_ns or self.fail_settle):
            raise ipc.CapabilityIpcError("operation owner settlement failed")
        self.active = None
        self.completed.add(lease.request_id)
        self.events.append("owner_settle")

    def revoke(self, retained_owner, expected, request_id, deadline_ns):
        if (retained_owner is not self.owner_handle or expected != self.value or
                self.fail_revoke):
            raise ipc.CapabilityIpcError("operation owner revoke failed")
        if self.active is not None and request_id not in {None, self.active.request_id}:
            raise ipc.CapabilityIpcError("wrong outstanding operation revoke")
        if request_id is not None:
            self.revoked.add(request_id)
        self.active = None
        self.events.append("owner_revoke")

    def verify_quiescent(self, retained_owner, expected, request_id, challenge):
        self.quiescent_requests.append(request_id)
        if self.quiescent_hook is not None:
            self.quiescent_hook(challenge)
        if (retained_owner is not self.owner_handle or expected != self.value or
                self.changed or self.fail_quiescent or self.active is not None):
            raise ipc.CapabilityIpcError("operation owner is not quiescent")
        if (request_id is not None and
                request_id not in self.completed and request_id not in self.revoked):
            raise ipc.CapabilityIpcError("unknown operation owner terminal record")
        if self.post_quiescent_hook is not None:
            self.post_quiescent_hook(challenge)
        return ipc.make_quiescence_receipt(challenge, "operation_owner")

class FakeDrain:
    def __init__(self, events):
        self.calls = []
        self.events = events
        self.fail = False
        self.hook = None
        self.post_quiescent_hook = None
        self.held_error = None

    def verify_drained(self, expected, challenge):
        self.calls.append(expected)
        self.events.append("callback_drain")
        if self.hook is not None:
            self.hook(challenge)
        if self.held_error is not None:
            raise self.held_error
        if self.fail:
            raise ipc.CapabilityIpcError("callback producers remain live")
        if self.post_quiescent_hook is not None:
            self.post_quiescent_hook(challenge)
        return ipc.make_quiescence_receipt(challenge, "callback_drain")


def raw_fixture(factory_id=ipc.FRIDA_FACTORY_ID, session_label="session"):
    clock = FakeClock()
    crypto = FakeCrypto()
    handles = FakeHandleAuthority()
    owner_handle = object()
    owner_identity = identity("parent_owner", 20, "owner", ("query", "terminate"))
    handles.retain(owner_handle, owner_identity)

    endpoint_ids = ("child_receive", "child_send", "parent_receive", "parent_send")
    endpoints = tuple(identity(
        name, 10 + index, "transport",
        ("read",) if name.endswith("receive") else ("write",))
                      for index, name in enumerate(endpoint_ids))
    transport_binding = ipc.TransportBinding(
        ipc.TRANSPORT_AUTHORITY, digest("channel:" + session_label), endpoints,
        True, True, True, True, False)
    policy = ipc.factory_policy(factory_id)
    session_id = digest(session_label)
    epoch_admission = FakeEpochAdmission(
        factory_id, policy.role, session_id, owner_identity.object_id, session_label)
    retained = []
    for index, resource_id in enumerate(policy.resource_ids):
        handle = object()
        resource_identity = identity(resource_id, 30 + index, "resource", ("query", "read"))
        handles.retain(handle, resource_identity)
        retained.append(ipc.RetainedCapability(resource_identity, handle))
    retained = tuple(retained)
    absolute_deadline = clock.value + 10_000_000_000
    binding = ipc.make_capability_binding(
        factory_id=factory_id, session_id=session_id,
        session_epoch=epoch_admission.value,
        absolute_deadline_ns=absolute_deadline,
        key_id=hashlib.sha256(SESSION_KEY).hexdigest(), owner=owner_identity,
        resources=tuple(item.identity for item in retained),
        transport=transport_binding, crypto=crypto)
    events = []
    shared = SharedTransport(transport_binding, events)
    parent_transport = FakeTransport(shared, "parent")
    child_transport = FakeTransport(shared, "child")
    drain = FakeDrain(events)
    operation_owner = FakeOperationOwner(
        binding, owner_handle, clock, crypto, events)
    return {
        "clock": clock, "crypto": crypto, "handles": handles,
        "owner_handle": owner_handle, "owner_identity": owner_identity,
        "retained": retained, "binding": binding, "shared": shared,
        "parent_transport": parent_transport, "child_transport": child_transport,
        "drain": drain, "operation_owner": operation_owner,
        "epoch_admission": epoch_admission, "policy": policy, "events": events,
    }


def fixture(factory_id=ipc.FRIDA_FACTORY_ID, session_label="session"):
    values = raw_fixture(factory_id, session_label)
    common = dict(
        binding=values["binding"], resources=values["retained"],
        owner_handle=values["owner_handle"],
        handle_authority=values["handles"], clock=values["clock"],
        crypto=values["crypto"], session_key=SESSION_KEY,
        epoch_admission=values["epoch_admission"],
        allow_unproven_transport_for_tests=True)
    values["parent"] = ipc.ParentCapabilitySession(
        transport=values["parent_transport"],
        operation_owner=values["operation_owner"], **common)
    values["child"] = ipc.ChildCapabilitySession(
        transport=values["child_transport"], callback_drain=values["drain"], **common)
    return values


def operation_deadline(values):
    return values["clock"].value + 1_000_000_000


def first_operation(values):
    return values["policy"].operations[0].operation_id


def install_resource_identity_error(values, error, capability_id):
    retained = next(
        item for item in values["retained"]
        if item.identity.capability_id == capability_id)
    values["handles"].identity_errors[id(retained.handle)] = error


def finish(values, callbacks=(), result=None):
    if result is None:
        result = {"ok": True}
    lease = values["parent"].begin(
        first_operation(values), {}, operation_deadline(values))
    operation = values["child"].receive_request()
    for payload in callbacks:
        operation.emit_callback("native_page_event.v1", payload)
    operation.seal_callbacks()
    operation.publish_result(result)
    outcome = values["parent"].settle(lease)
    return lease, operation, outcome


def resign(packet, key, crypto, mutate):
    value = ipc.decode_canonical_json(packet.frame[4:])
    mutate(value["header"])
    unsigned = b"rtl-reader-worker-capability-ipc-v1\x00" + ipc.canonical_json(value["header"])
    value["mac"] = crypto.hmac_sha256(key, unsigned).hex()
    raw = ipc.canonical_json(value)
    return ipc.WirePacket(len(raw).to_bytes(4, "big") + raw, packet.payload)


def resign_payload(packet, payload, key, crypto):
    envelope = ipc.decode_canonical_json(packet.frame[4:])
    envelope["header"]["payload_bytes"] = len(payload)
    envelope["header"]["payload_sha256"] = crypto.sha256(payload).hex()
    unsigned = (b"rtl-reader-worker-capability-ipc-v1\x00" +
                ipc.canonical_json(envelope["header"]))
    envelope["mac"] = crypto.hmac_sha256(key, unsigned).hex()
    raw = ipc.canonical_json(envelope)
    return ipc.WirePacket(len(raw).to_bytes(4, "big") + raw, payload)


class FakePacketTransportAuthorityV2:
    """Deterministic contract fake; its profile is never production-admissible."""

    def __init__(self, attestation, crypto, events):
        self.value = attestation
        self.crypto = crypto
        self.events = events
        self.sent_eof = set()
        self.sealed = set()
        self.drained = set()
        self.closed = set()
        self.fail_component = None
        self.wrong_admission = False
        self.wrong_generation_component = None
        self.component_hook = None

    def attestation(self):
        return self.value

    def _admission(self, binding):
        return ipc.make_admission_receipt_v2(
            binding, "transport", "channel", self.value.profile,
            digest("v2 transport admission"), self.crypto)

    def admit(self, binding):
        self.events.append("transport_admit")
        receipt = self._admission(binding)
        return replace(receipt, generation=1) if self.wrong_admission else receipt

    def _receipt(self, request, component, subject):
        if self.fail_component == component:
            raise ipc.CapabilityIpcError("injected v2 closure failure")
        receipt = ipc.make_closure_component_receipt_v2(
            request, component, subject,
            digest(f"v2:{component}:{subject}"), self.crypto)
        if self.wrong_generation_component == component:
            receipt = replace(receipt, generation=receipt.generation + 1)
        self.events.append(component + ":" + subject)
        if self.component_hook is not None:
            self.component_hook(component, subject)
        return receipt

    def send_authenticated_eof(self, request, direction):
        if direction in self.sent_eof:
            raise ipc.CapabilityIpcError("duplicate v2 EOF")
        self.sent_eof.add(direction)
        return self._receipt(request, "authenticated_eof", direction)

    def seal_direction(self, request, direction):
        if direction not in self.sent_eof or direction in self.sealed:
            raise ipc.CapabilityIpcError("v2 direction seal is out of order")
        self.sealed.add(direction)
        return self._receipt(request, "direction_sealed", direction)

    def verify_direction_drained(self, request, direction):
        if direction not in self.sealed or direction in self.drained:
            raise ipc.CapabilityIpcError("v2 direction drain is out of order")
        self.drained.add(direction)
        return self._receipt(request, "direction_drained", direction)

    def close_endpoint(self, request, endpoint_id):
        if self.drained != {"child_to_parent", "parent_to_child"}:
            raise ipc.CapabilityIpcError("v2 endpoint closed before bidirectional drain")
        if endpoint_id in self.closed:
            raise ipc.CapabilityIpcError("duplicate v2 endpoint close")
        self.closed.add(endpoint_id)
        return self._receipt(request, "endpoint_closed", endpoint_id)


class FakeSessionEpochAuthorityV2:
    def __init__(self, attestation, crypto, events):
        self.value = attestation
        self.crypto = crypto
        self.events = events
        self.admitted = set()
        self.revoked = set()
        self.fail_admit_side = None

    def attestation(self):
        return self.value

    def admit_side(self, binding, side):
        if side == self.fail_admit_side:
            raise ipc.CapabilityIpcError("injected v2 epoch admission failure")
        if side in self.admitted or side not in {"child", "parent"}:
            raise ipc.CapabilityIpcError("v2 epoch side replayed")
        self.admitted.add(side)
        self.events.append("epoch_admit:" + side)
        return ipc.make_admission_receipt_v2(
            binding, "epoch", side, self.value.profile,
            digest("v2 epoch admission:" + side), self.crypto)

    def revoke_side(self, request, side):
        if side not in self.admitted or side in self.revoked:
            raise ipc.CapabilityIpcError("v2 epoch side cannot be revoked")
        self.revoked.add(side)
        self.events.append("epoch_revoked:" + side)
        return ipc.make_closure_component_receipt_v2(
            request, "epoch_revoked", side,
            digest("v2 epoch revoked:" + side), self.crypto)


class FakeSessionLifecycleAuthorityV2:
    def __init__(self, crypto, events):
        self.crypto = crypto
        self.events = events
        self.owner_closed = False

    def admit(self, binding):
        self.events.append("lifecycle_admit")
        return ipc.make_admission_receipt_v2(
            binding, "lifecycle", "session", ipc.SESSION_LIFECYCLE_PROFILE_V2,
            digest("v2 lifecycle admission"), self.crypto)

    def verify_zero_operations(self, request, subject):
        if subject != "session":
            raise ipc.CapabilityIpcError("wrong v2 operation-zero subject")
        self.events.append("operations_zero:session")
        return ipc.make_closure_component_receipt_v2(
            request, "operations_zero", "session",
            digest("v2 zero operations"), self.crypto)

    def verify_zero_callbacks(self, request, subject):
        if subject != "session":
            raise ipc.CapabilityIpcError("wrong v2 callback-zero subject")
        self.events.append("callbacks_zero:session")
        return ipc.make_closure_component_receipt_v2(
            request, "callbacks_zero", "session",
            digest("v2 zero callbacks"), self.crypto)

    def close_owner(self, request, subject):
        if subject != "parent_owner" or self.owner_closed:
            raise ipc.CapabilityIpcError("duplicate v2 owner close")
        self.owner_closed = True
        self.events.append("owner_closed:parent_owner")
        return ipc.make_closure_component_receipt_v2(
            request, "owner_closed", "parent_owner",
            digest("v2 owner closed"), self.crypto)


def raw_fixture_v2(session_label="v2 session"):
    clock = FakeClock()
    crypto = FakeCrypto()
    events = []
    owner = identity("parent_owner", 120, "owner", ("query", "terminate"))
    policy = ipc.factory_policy(ipc.FRIDA_FACTORY_ID)
    resources = tuple(identity(
        resource_id, 130 + index, "resource", policy.resource_rights[index])
                      for index, resource_id in enumerate(policy.resource_ids))
    endpoints = tuple(identity(
        endpoint_id, 140 + index, "transport",
        ("read",) if endpoint_id.endswith("receive") else ("write",))
                      for index, endpoint_id in enumerate(
                          ("child_receive", "child_send",
                           "parent_receive", "parent_send")))
    session_id = digest(session_label)
    epoch_id = digest(session_label + ":epoch")
    transport_attestation = ipc.TransportAttestationV2(
        ipc.TRANSPORT_ATTESTATION_AUTHORITY_V2,
        ipc.CONTRACT_FAKE_TRANSPORT_PROFILE_V2,
        digest(session_label + ":transport-attestation"), session_id,
        epoch_id, ipc.FRIDA_FACTORY_ID, ipc.FRIDA_ROLE, owner.object_id,
        digest(session_label + ":channel"), endpoints)
    epoch_attestation = ipc.EpochAttestationV2(
        ipc.EPOCH_ATTESTATION_AUTHORITY_V2,
        ipc.CONTRACT_FAKE_EPOCH_PROFILE_V2,
        digest(session_label + ":epoch-attestation"), epoch_id,
        digest(session_label + ":admission"), session_id,
        ipc.FRIDA_FACTORY_ID, ipc.FRIDA_ROLE, owner.object_id)
    effect_deadline_ns = clock.value + 1_000_000_000
    closure_deadline_ns = clock.value + 3_000_000_000
    binding = ipc.make_capability_binding_body_v2(
        factory_id=ipc.FRIDA_FACTORY_ID, session_id=session_id,
        effect_deadline_ns=effect_deadline_ns,
        closure_deadline_ns=closure_deadline_ns,
        key_id=hashlib.sha256(SESSION_KEY).hexdigest(), owner=owner,
        resources=resources, transport_attestation=transport_attestation,
        epoch_attestation=epoch_attestation, crypto=crypto)
    transport = FakePacketTransportAuthorityV2(
        transport_attestation, crypto, events)
    epoch = FakeSessionEpochAuthorityV2(epoch_attestation, crypto, events)
    lifecycle = FakeSessionLifecycleAuthorityV2(crypto, events)
    acquired = ipc.AcquiredAuthorityV2(
        ipc.ACQUIRED_AUTHORITY_V2, digest(session_label + ":acquisition"),
        ipc.capability_binding_sha256_v2(binding, crypto), transport, epoch,
        lifecycle, clock, crypto, SESSION_KEY)
    return {
        "clock": clock, "crypto": crypto, "events": events,
        "binding": binding, "transport": transport, "epoch": epoch,
        "lifecycle": lifecycle, "acquired": acquired,
    }


def fixture_v2(session_label="v2 session"):
    values = raw_fixture_v2(session_label)
    values["session"] = ipc._construct_contract_capability_session_v2(
        binding=values["binding"], acquired_authority=values["acquired"])
    return values


def verified_v2_outcome(values, lease, result_value, callback_values,
                        generation):
    crypto = values["crypto"]
    binding = values["binding"]
    callbacks = []
    packets = []
    for ordinal, callback_value in enumerate(callback_values, 1):
        payload = ipc.DetachedPayloadV2.from_value(
            lease, "callback", callback_value, ipc.MAX_PAYLOAD_BYTES,
            crypto, ordinal)
        callback = ipc.CallbackRecordV2(
            lease, ordinal, "native_page_event.v2", payload)
        callbacks.append(callback)
        packets.append(ipc.make_wire_packet_v2(
            binding=binding, lease=lease, message_sequence=ordinal,
            kind="callback", body={"event": callback.event,
                                    "ordinal": ordinal},
            payload=payload, key=SESSION_KEY, crypto=crypto))
    next_message = len(callbacks) + 1
    packets.append(ipc.make_wire_packet_v2(
        binding=binding, lease=lease, message_sequence=next_message,
        kind="barrier", body={"callback_count": len(callbacks)},
        payload=None, key=SESSION_KEY, crypto=crypto))
    challenge = ipc.make_quiescence_challenge_v2(
        lease, generation, "operation.settle", ("callback_drain",),
        digest("settlement nonce:" + lease.request_id), crypto)
    receipt = ipc.make_quiescence_receipt_v2(
        challenge, "callback_drain",
        digest("settlement drain:" + lease.request_id), crypto)
    result = ipc.DetachedPayloadV2.from_value(
        lease, "result", result_value, ipc.MAX_PAYLOAD_BYTES, crypto)
    packets.append(ipc.make_wire_packet_v2(
        binding=binding, lease=lease, message_sequence=next_message + 1,
        kind="reply", body={
            "callback_drain_challenge_id": challenge.challenge_id,
            "callback_drain_receipt_sha256": receipt.receipt_sha256,
            "status": "ok",
        }, payload=result, key=SESSION_KEY, crypto=crypto))
    packets.append(ipc.make_wire_packet_v2(
        binding=binding, lease=lease, message_sequence=next_message + 2,
        kind="eof", body={}, payload=None, key=SESSION_KEY, crypto=crypto))
    outcome = ipc.make_operation_outcome_v2(
        binding, lease, tuple(packets), challenge, receipt,
        SESSION_KEY, crypto)
    return outcome, tuple(callbacks)


def complete_v2_operation(values, operation_id, purpose, result_value,
                          callback_values=()):
    lease = ipc.make_operation_lease_v2(
        values["binding"], operation_id, purpose,
        digest("challenge:" + operation_id), values["crypto"])
    request = values["session"].begin_operation(lease, {})
    outcome, callbacks = verified_v2_outcome(
        values, lease, result_value, callback_values,
        values["session"].generation)
    for callback in callbacks:
        values["session"].note_callback(callback)
    values["session"].complete_operation(outcome)
    return lease, request, outcome


class StackStealingDescriptor:
    """A data descriptor that would capture scrubber locals if dispatched."""

    def __init__(self, label):
        self.label = label

    def _steal(self, operation):
        frame = inspect.currentframe()
        cursor = None if frame is None else frame.f_back
        stolen = []
        while cursor is not None and len(stolen) < 32:
            stolen.append((cursor.f_code.co_name, dict(cursor.f_locals)))
            cursor = cursor.f_back
        STACK_STEAL_ATTEMPTS.append((self.label, operation, tuple(stolen)))
        raise AssertionError("hostile exception data descriptor executed")

    def __get__(self, _instance, _owner):
        return self._steal("get")

    def __set__(self, _instance, _value):
        return self._steal("set")


class HostileProviderError(RuntimeError):
    """Provider error with stack-stealing exception-slot descriptors."""

    __traceback__ = StackStealingDescriptor("error traceback")
    __context__ = StackStealingDescriptor("error context")
    __cause__ = StackStealingDescriptor("error cause")

    def __str__(self):
        raise AssertionError("provider error was formatted")

    def __repr__(self):
        raise AssertionError("provider error was represented")

    def __hash__(self):
        raise AssertionError("provider error was hashed")

    def __eq__(self, _other):
        raise AssertionError("provider error was compared")



class HostileProviderGroup(ExceptionGroup):
    __traceback__ = StackStealingDescriptor("group traceback")
    __context__ = StackStealingDescriptor("group context")
    __cause__ = StackStealingDescriptor("group cause")
    exceptions = StackStealingDescriptor("group children")


def provider_exception_graph(label):
    hostile = HostileProviderError(label)
    nested_leaf = LookupError(label + " nested leaf")
    nested = HostileProviderGroup(label + " nested", [nested_leaf])
    sibling = ValueError(label + " sibling")
    top = HostileProviderGroup(label + " top", [hostile, nested, sibling])
    cause = OSError(label + " cause")
    context = ArithmeticError(label + " context")
    nodes = (top, hostile, nested, nested_leaf, sibling, cause, context)

    # Give every node a real provider-owned traceback before linking the graph.
    for node in nodes:
        try:
            raise node
        except BaseException:
            pass
    # Explicit cause/context cycles and nested groups challenge recursive,
    # identity-only scrubbing.  Base operations bypass HostileProviderError's
    # deliberately dangerous hooks.
    RAW_CAUSE_SLOT.__set__(top, cause)
    RAW_CONTEXT_SLOT.__set__(top, context)
    RAW_CONTEXT_SLOT.__set__(cause, top)
    RAW_CAUSE_SLOT.__set__(context, hostile)
    RAW_CONTEXT_SLOT.__set__(hostile, nested)
    RAW_CAUSE_SLOT.__set__(nested_leaf, top)
    return top, nodes


def provider_exception_graph_is_scrubbed(test, nodes):
    for node in nodes:
        test.assertIsNone(RAW_TRACEBACK_SLOT.__get__(node, BaseException))
        test.assertIsNone(RAW_CONTEXT_SLOT.__get__(node, BaseException))
        test.assertIsNone(RAW_CAUSE_SLOT.__get__(node, BaseException))
        if isinstance(node, BaseExceptionGroup):
            children = RAW_GROUP_EXCEPTIONS_SLOT.__get__(
                node, BaseExceptionGroup)
            test.assertIs(type(children), tuple)


def exact_container_contains(value, identities, forbidden_strings, seen=None):
    """Identity-only recursive search through exact built-in containers."""

    if seen is None:
        seen = set()
    if any(value is item for item in identities):
        return True
    if type(value) is str:
        return value in forbidden_strings
    value_id = id(value)
    if value_id in seen:
        return False
    seen.add(value_id)
    if type(value) is dict:
        return any(
            exact_container_contains(item, identities, forbidden_strings, seen)
            for pair in value.items() for item in pair)
    if type(value) in {tuple, list, set, frozenset}:
        return any(
            exact_container_contains(item, identities, forbidden_strings, seen)
            for item in value)
    return False


class CapabilityIpcTests(unittest.TestCase):
    def test_000_v2_closed_purpose_tables_and_immutable_deadlines(self):
        values = raw_fixture_v2("v2 closed tables")
        binding = values["binding"]
        frida = ipc.factory_operation_table_v2(ipc.FRIDA_FACTORY_ID)
        authority = ipc.factory_operation_table_v2(ipc.AUTHORITY_FACTORY_ID)

        self.assertEqual(
            tuple((item.sequence, item.operation_id, item.operation_purpose,
                   item.phase, item.prerequisite_purpose)
                  for item in frida.operations),
            ((1, ipc.FRIDA_CAPTURE_OPERATION_V2,
              ipc.FRIDA_CAPTURE_PURPOSE_V2, "effect", None),
             (2, ipc.FRIDA_CLEANUP_OPERATION_V2,
              ipc.FRIDA_CLEANUP_PURPOSE_V2, "closure",
              ipc.FRIDA_CAPTURE_PURPOSE_V2)))
        self.assertEqual(len(authority.operations), 10)
        self.assertEqual(
            tuple(item.sequence for item in authority.operations),
            tuple(range(1, 11)))
        self.assertIs(ipc.FACTORY_OPERATION_TABLES_V2[ipc.FRIDA_FACTORY_ID], frida)
        with self.assertRaises(TypeError):
            ipc.FACTORY_OPERATION_TABLES_V2["generic"] = frida
        with self.assertRaises(ipc.CapabilityIpcError):
            frida.operation(ipc.FRIDA_CAPTURE_OPERATION_V2,
                            ipc.FRIDA_CLEANUP_PURPOSE_V2)
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.factory_operation_table_v2("generic_worker-v2")

        self.assertLess(binding.effect_deadline_ns,
                        binding.closure_deadline_ns)
        with self.assertRaises(FrozenInstanceError):
            binding.effect_deadline_ns += 1
        with self.assertRaises(FrozenInstanceError):
            binding.transport_attestation.profile = (
                ipc.PRODUCTION_TRANSPORT_PROFILE_V2)
        self.assertNotIn("real_transport", binding.wire())
        self.assertNotIn("allow_unproven_transport_for_tests",
                         inspect.signature(
                             ipc.construct_production_capability_session_v2
                         ).parameters)

    def test_001_v2_lease_payload_packet_outcome_and_quiescence_bind_authority(self):
        values = raw_fixture_v2("v2 bindings")
        binding = values["binding"]
        crypto = values["crypto"]
        lease = ipc.make_operation_lease_v2(
            binding, ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, digest("v2 binding challenge"), crypto)
        request = ipc.DetachedPayloadV2.from_value(
            lease, "request", {}, ipc.MAX_PAYLOAD_BYTES, crypto)
        packet = ipc.make_wire_packet_v2(
            binding=binding, lease=lease, message_sequence=0, kind="request",
            body={}, payload=request, key=SESSION_KEY, crypto=crypto)
        header, raw = ipc.open_wire_packet_v2(
            packet, binding=binding, lease=lease, message_sequence=0,
            key=SESSION_KEY, crypto=crypto)
        self.assertEqual(raw, request.canonical)
        self.assertEqual(header["operation_purpose"], lease.operation_purpose)
        self.assertEqual(header["effect_deadline_ns"], lease.effect_deadline_ns)
        self.assertEqual(header["closure_deadline_ns"], lease.closure_deadline_ns)

        outcome, _callbacks = verified_v2_outcome(
            values, lease, {"captured": True}, (), 1)
        outcome.validate(binding, SESSION_KEY, crypto)
        challenge = ipc.make_quiescence_challenge_v2(
            lease, 1, "operation.settle", ("callback_drain", "transport"),
            digest("v2 quiescence nonce"), crypto)
        receipt = ipc.make_quiescence_receipt_v2(
            challenge, "transport", digest("v2 transport evidence"), crypto)
        receipt.validate(challenge, "transport", crypto)

        for substituted in (
                replace(lease, closure_deadline_ns=lease.closure_deadline_ns + 1),
                replace(lease, operation_purpose=ipc.FRIDA_CLEANUP_PURPOSE_V2)):
            with self.assertRaises(ipc.CapabilityIpcError):
                substituted.validate(binding, crypto)
        with self.assertRaises(ipc.CapabilityIpcError):
            replace(request, effect_deadline_ns=request.effect_deadline_ns + 1).validate(
                lease, ipc.MAX_PAYLOAD_BYTES, crypto)
        with self.assertRaises(ipc.CapabilityIpcError):
            replace(outcome, operation_purpose=ipc.FRIDA_CLEANUP_PURPOSE_V2).validate(
                binding, SESSION_KEY, crypto)
        with self.assertRaises(ipc.CapabilityIpcError):
            replace(challenge,
                    closure_deadline_ns=challenge.closure_deadline_ns + 1).validate(
                        lease, crypto)

        envelope = ipc.decode_canonical_json(packet.frame[4:])
        envelope["header"]["operation_purpose"] = ipc.FRIDA_CLEANUP_PURPOSE_V2
        forged_raw = ipc.canonical_json(envelope)
        forged = ipc.WirePacketV2(
            len(forged_raw).to_bytes(4, "big") + forged_raw, packet.payload)
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.open_wire_packet_v2(
                forged, binding=binding, lease=lease, message_sequence=0,
                key=SESSION_KEY, crypto=crypto)

    def test_002_v2_cleanup_expiry_preserves_slot_checkpoint_and_deadlines(self):
        values = raw_fixture_v2("v2 expiry")
        lease = ipc.make_operation_lease_v2(
            values["binding"], ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, digest("v2 expiry challenge"),
            values["crypto"])
        checkpoint = digest("v2 existing checkpoint")
        receipt = ipc.make_cleanup_expiry_receipt_v2(
            lease, lease.effect_deadline_ns, 2, checkpoint,
            SESSION_KEY, values["crypto"])
        receipt.validate(lease, SESSION_KEY, values["crypto"])
        self.assertEqual(receipt.original_reserved_slot, 2)
        self.assertEqual(receipt.checkpoint_sha256, checkpoint)
        self.assertLess(receipt.observed_at_ns, receipt.closure_deadline_ns)

        for changed in (
                replace(receipt, original_reserved_slot=0),
                replace(receipt, original_reserved_slot=7),
                replace(receipt, checkpoint_sha256=None),
                replace(receipt, observed_at_ns=lease.closure_deadline_ns),
                replace(receipt, effect_deadline_ns=lease.effect_deadline_ns + 1)):
            with self.assertRaises(ipc.CapabilityIpcError):
                changed.validate(lease, SESSION_KEY, values["crypto"])

    def test_003_v2_production_admission_rejects_fakes_and_retains_phase_one(self):
        values = raw_fixture_v2("v2 production reject")
        acquired = values["acquired"]
        result = ipc.construct_production_capability_session_v2(
            binding=values["binding"], acquired_authority=acquired)
        result.validate()
        self.assertEqual(result.status, "failed_authority_retained")
        self.assertIs(result.acquired_authority, acquired)
        self.assertIsNone(result.session)
        self.assertEqual(result.failure_code, "production_admission_failed")
        self.assertEqual(values["events"], [])
        with self.assertRaises(ipc.CapabilityIpcError):
            result.require_session()
        with self.assertRaises(FrozenInstanceError):
            result.acquired_authority = None
        malformed_acquired = replace(acquired, binding_sha256="not-a-digest")
        malformed_result = ipc.construct_production_capability_session_v2(
            binding=values["binding"], acquired_authority=malformed_acquired)
        malformed_result.validate()
        self.assertEqual(malformed_result.status, "failed_authority_retained")
        self.assertIs(malformed_result.acquired_authority, malformed_acquired)
        contract_values = fixture_v2("v2 direct construction seal")
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.CapabilitySessionV2(
                binding=contract_values["binding"],
                acquired=contract_values["acquired"],
                admission_receipts=contract_values["session"]._admission_receipts,
                admission_profile=ipc.CONTRACT_FAKE_TRANSPORT_PROFILE_V2,
                _construction_authority=object())
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.CapabilitySessionV2(
                binding=contract_values["binding"],
                acquired=contract_values["acquired"],
                admission_receipts=contract_values["session"]._admission_receipts,
                admission_profile=ipc.CONTRACT_FAKE_TRANSPORT_PROFILE_V2,
                _construction_authority=ipc._V2_PRODUCTION_SESSION_CONSTRUCTION)
        forged_commit = ipc.CapabilityConstructionResultV2(
            ipc.CONSTRUCTION_RESULT_AUTHORITY_V2,
            contract_values["acquired"].binding_sha256, "committed",
            contract_values["acquired"], contract_values["session"], None)
        with self.assertRaises(ipc.CapabilityIpcError):
            forged_commit.validate()

        sequential = raw_fixture_v2("v2 sequential admission validation")
        sequential["transport"].wrong_admission = True
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc._construct_contract_capability_session_v2(
                binding=sequential["binding"],
                acquired_authority=sequential["acquired"])
        self.assertEqual(sequential["events"], ["transport_admit"])
        self.assertEqual(sequential["epoch"].admitted, set())
        self.assertFalse(sequential["lifecycle"].owner_closed)
        self.assertFalse(ipc.REAL_V2_TRANSPORT_AUTHORITY_IMPLEMENTED)
        self.assertFalse(ipc.REAL_V2_EPOCH_AUTHORITY_IMPLEMENTED)
        self.assertTrue(ipc.V2_UNRESOLVED_BLOCKERS)

    def test_004_v2_open_idle_is_not_closure_and_seq2_cleanup_is_mandatory(self):
        values = fixture_v2("v2 successful closure")
        session = values["session"]
        binding = values["binding"]
        idle = session.verify_operation_idle()
        self.assertEqual(session.state, "OPEN")
        self.assertFalse(idle.terminal)
        self.assertEqual(idle.epoch_admitted_sides, ("child", "parent"))
        self.assertEqual(idle.open_endpoints,
                         ("child_receive", "child_send",
                          "parent_receive", "parent_send"))
        self.assertNotIsInstance(idle, ipc.SuccessfulSessionClosureReceiptV2)
        with self.assertRaises(ipc.CapabilityIpcError):
            session.close_successfully()

        capture_lease, _request, capture = complete_v2_operation(
            values, ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, {"pixels": 42},
            ({"page": 1},))
        self.assertEqual(capture_lease.sequence, 1)
        self.assertEqual(len(capture.callbacks), 1)
        self.assertEqual(session.state, "OPEN")
        self.assertFalse(session.verify_operation_idle().terminal)
        with self.assertRaises(ipc.CapabilityIpcError):
            session.close_successfully()

        values["clock"].value = binding.effect_deadline_ns + 1
        cleanup_lease, _request, cleanup = complete_v2_operation(
            values, ipc.FRIDA_CLEANUP_OPERATION_V2,
            ipc.FRIDA_CLEANUP_PURPOSE_V2, {"clean": True})
        self.assertEqual(cleanup_lease.sequence, 2)
        self.assertTrue(cleanup.cleanup_completed)
        self.assertGreater(values["clock"].value, binding.effect_deadline_ns)
        self.assertLess(values["clock"].value, binding.closure_deadline_ns)

        closure = session.close_successfully()
        closure.validate(binding,
                         ipc.make_session_closure_request_v2(
                             binding, closure.generation, SESSION_KEY,
                             values["crypto"]),
                         SESSION_KEY, values["crypto"])
        self.assertEqual(session.state, "CLOSED")
        self.assertIs(session.successful_closure_receipt, closure)
        self.assertEqual(closure.active_operations, 0)
        self.assertEqual(closure.live_callbacks, 0)
        self.assertEqual(closure.sealed_directions,
                         ("child_to_parent", "parent_to_child"))
        self.assertEqual(closure.authenticated_eof_drained_directions,
                         ("child_to_parent", "parent_to_child"))
        self.assertEqual(closure.revoked_epoch_sides, ("child", "parent"))
        self.assertEqual(len(closure.component_receipts), 15)
        self.assertEqual(values["transport"].closed,
                         {"child_receive", "child_send",
                          "parent_receive", "parent_send"})
        self.assertEqual(values["epoch"].revoked, {"child", "parent"})
        self.assertTrue(values["lifecycle"].owner_closed)
        with self.assertRaises(ipc.CapabilityIpcError):
            session.verify_operation_idle()
        with self.assertRaises(ipc.CapabilityIpcError):
            replace(closure, authentication_tag="0" * 64).validate(
                binding,
                ipc.make_session_closure_request_v2(
                    binding, closure.generation, SESSION_KEY, values["crypto"]),
                SESSION_KEY, values["crypto"])

    def test_005_v2_cleanup_cannot_skip_capture_and_bad_closure_is_uncertain(self):
        values = fixture_v2("v2 cleanup ordering")
        cleanup = ipc.make_operation_lease_v2(
            values["binding"], ipc.FRIDA_CLEANUP_OPERATION_V2,
            ipc.FRIDA_CLEANUP_PURPOSE_V2, digest("v2 early cleanup"),
            values["crypto"])
        with self.assertRaises(ipc.CapabilityIpcError):
            values["session"].begin_operation(cleanup, {})
        self.assertEqual(values["session"].state, "OPEN")

        complete_v2_operation(
            values, ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, {"captured": True})
        complete_v2_operation(
            values, ipc.FRIDA_CLEANUP_OPERATION_V2,
            ipc.FRIDA_CLEANUP_PURPOSE_V2, {"clean": True})
        values["transport"].wrong_generation_component = "direction_drained"
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["session"].close_successfully()
        self.assertEqual(values["session"].state, "CLOSURE_UNCERTAIN")
        self.assertIsNone(values["session"].successful_closure_receipt)

    def test_006_v2_each_closure_effect_is_deadline_fenced_and_retained(self):
        values = fixture_v2("v2 per effect closure deadline")
        complete_v2_operation(
            values, ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, {"captured": True})
        complete_v2_operation(
            values, ipc.FRIDA_CLEANUP_OPERATION_V2,
            ipc.FRIDA_CLEANUP_PURPOSE_V2, {"clean": True})

        def expire_after_first_effect(component, subject):
            if component == "authenticated_eof" and subject == "child_to_parent":
                values["clock"].value = values["binding"].closure_deadline_ns

        values["transport"].component_hook = expire_after_first_effect
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["session"].close_successfully()
        self.assertEqual(values["session"].state, "CLOSURE_UNCERTAIN")
        self.assertEqual(len(values["session"].partial_closure_receipts), 1)
        partial = values["session"].partial_closure_receipts[0]
        self.assertEqual(
            (partial.component, partial.subject),
            ("authenticated_eof", "child_to_parent"))
        self.assertEqual(values["transport"].sent_eof, {"child_to_parent"})
        self.assertEqual(values["transport"].sealed, set())
        self.assertEqual(values["epoch"].revoked, set())
        self.assertEqual(values["transport"].closed, set())

        publication = fixture_v2("v2 final closure publication fence")
        complete_v2_operation(
            publication, ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, {"captured": True})
        complete_v2_operation(
            publication, ipc.FRIDA_CLEANUP_OPERATION_V2,
            ipc.FRIDA_CLEANUP_PURPOSE_V2, {"clean": True})

        def expire_during_final_auth(payload):
            if payload.startswith(
                    b"rtl-reader-successful-session-closure-auth-v2\x00"):
                publication["clock"].value = (
                    publication["binding"].closure_deadline_ns)

        publication["crypto"].hmac_hook = expire_during_final_auth
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            publication["session"].close_successfully()
        self.assertEqual(publication["session"].state, "CLOSURE_UNCERTAIN")
        self.assertEqual(
            len(publication["session"].partial_closure_receipts), 15)
        self.assertIsNone(publication["session"].successful_closure_receipt)

    def test_007_v2_outcome_requires_transcript_and_session_entry_is_serialized(self):
        values = raw_fixture_v2("v2 transcript tamper")
        lease = ipc.make_operation_lease_v2(
            values["binding"], ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, digest("v2 transcript challenge"),
            values["crypto"])
        outcome, _callbacks = verified_v2_outcome(
            values, lease, {"captured": True}, (), 1)
        evidence = outcome.settlement_evidence
        transcript = list(evidence.transcript)
        transcript[-3] = ipc.make_wire_packet_v2(
            binding=values["binding"], lease=lease, message_sequence=1,
            kind="barrier", body={"callback_count": 1}, payload=None,
            key=SESSION_KEY, crypto=values["crypto"])
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.make_operation_outcome_v2(
                values["binding"], lease, tuple(transcript),
                evidence.callback_drain_challenge,
                evidence.callback_drain_receipt, SESSION_KEY, values["crypto"])
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.make_operation_outcome_v2(
                values["binding"], lease, evidence.transcript[:-1],
                evidence.callback_drain_challenge,
                evidence.callback_drain_receipt, SESSION_KEY, values["crypto"])

        exact_callbacks = fixture_v2("v2 exact callback stream")
        callback_lease = ipc.make_operation_lease_v2(
            exact_callbacks["binding"], ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, digest("v2 exact callback challenge"),
            exact_callbacks["crypto"])
        exact_callbacks["session"].begin_operation(callback_lease, {})
        callback_outcome, _ = verified_v2_outcome(
            exact_callbacks, callback_lease, {"captured": True},
            ({"expected": True},), exact_callbacks["session"].generation)
        substituted_payload = ipc.DetachedPayloadV2.from_value(
            callback_lease, "callback", {"substituted": True},
            ipc.MAX_PAYLOAD_BYTES, exact_callbacks["crypto"], 1)
        exact_callbacks["session"].note_callback(ipc.CallbackRecordV2(
            callback_lease, 1, "native_page_event.v2", substituted_payload))
        with self.assertRaises(ipc.CapabilityIpcError):
            exact_callbacks["session"].complete_operation(callback_outcome)
        self.assertEqual(exact_callbacks["session"].state, "ACTIVE")

        late = fixture_v2("v2 late capture settlement")
        late_lease = ipc.make_operation_lease_v2(
            late["binding"], ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, digest("v2 late outcome challenge"),
            late["crypto"])
        late["session"].begin_operation(late_lease, {})
        late_outcome, _ = verified_v2_outcome(
            late, late_lease, {"captured": True}, (),
            late["session"].generation)
        late["clock"].value = late["binding"].effect_deadline_ns
        with self.assertRaises(ipc.CapabilityIpcError):
            late["session"].complete_operation(late_outcome)
        self.assertEqual(late["session"].state, "ACTIVE")

        values = fixture_v2("v2 serialized entry")
        lease = ipc.make_operation_lease_v2(
            values["binding"], ipc.FRIDA_CAPTURE_OPERATION_V2,
            ipc.FRIDA_CAPTURE_PURPOSE_V2, digest("v2 serialized challenge"),
            values["crypto"])
        entered = threading.Event()
        release = threading.Event()
        errors = []
        blocked_once = {"value": False}

        def block_first_digest():
            if not blocked_once["value"]:
                blocked_once["value"] = True
                entered.set()
                if not release.wait(2):
                    raise ipc.CapabilityIpcError("v2 serialized test timed out")

        values["crypto"].sha_hook = block_first_digest

        def begin():
            try:
                values["session"].begin_operation(lease, {})
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=begin)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaises(ipc.CapabilityIpcError):
                values["session"].verify_operation_idle()
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(values["session"].state, "ACTIVE")

    def test_successful_fixed_operations_are_detached_bounded_and_reusable(self):
        values = fixture()
        lease, operation, outcome = finish(
            values, callbacks=({"page": 1}, {"page": 2}), result={"complete": True})
        self.assertEqual(values["parent"].state, "OPEN")
        self.assertEqual(values["child"].state, "OPEN")
        self.assertEqual(outcome.authority, ipc.OUTCOME_AUTHORITY)
        self.assertEqual(outcome.lease, lease)
        self.assertEqual(outcome.result.decode(), {"complete": True})
        self.assertEqual([item.payload.decode() for item in outcome.callbacks],
                         [{"page": 1}, {"page": 2}])
        self.assertTrue(outcome.barrier_verified)
        self.assertTrue(outcome.eof_verified)
        # Exact terminal retirement removes the sensitive operation root; a
        # backend-retained stale handle cannot inspect or reactivate it.
        with self.assertRaises(ipc.CapabilityIpcError):
            _ = operation.callbacks_sealed
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.decode_request()
        with self.assertRaises(ipc.CapabilityIpcError):
            _ = operation.required_resource_ids
        for name in ("lease", "policy", "request", "resources", "callback_sink",
                     "_child", "_key", "_transport", "_owner_handle"):
            with self.subTest(opaque_operation_field=name):
                self.assertFalse(hasattr(operation, name))
        for _side, packet, _deadline in values["shared"].history:
            self.assertIs(type(packet.frame), bytes)
            self.assertIs(type(packet.payload), bytes)
            envelope = ipc.decode_canonical_json(packet.frame[4:])
            self.assertNotIn("payload", envelope)
            self.assertNotIn("payload", envelope["header"])
            self.assertEqual(envelope["header"]["payload_bytes"], len(packet.payload))

        second, _, second_outcome = finish(values, result={"round": 2})
        self.assertEqual(second.sequence, lease.sequence + 1)
        self.assertNotEqual(second.challenge, lease.challenge)
        self.assertNotEqual(second.request_id, lease.request_id)
        self.assertEqual(second_outcome.result.decode(), {"round": 2})

        authority_values = fixture(ipc.AUTHORITY_FACTORY_ID, "authority session")
        _, authority_operation, authority_outcome = finish(
            authority_values, result={"device": "bound"})
        with self.assertRaises(ipc.CapabilityIpcError):
            _ = authority_operation.callback_count
        self.assertEqual(authority_outcome.callbacks, ())

        events = values["events"]
        self.assertLess(events.index("owner_admit"), events.index("parent_send"))
        self.assertLess(events.index("callback_drain"), events.index("owner_settle"))
        self.assertLess(events.index("child_send"), events.index("owner_settle"))

    def test_real_transport_blocker_is_explicit_and_production_admission_fails(self):
        values = raw_fixture()
        common = dict(
            binding=values["binding"], resources=values["retained"],
            owner_handle=values["owner_handle"], handle_authority=values["handles"],
            clock=values["clock"], crypto=values["crypto"], session_key=SESSION_KEY,
            epoch_admission=values["epoch_admission"])
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(
                transport=values["parent_transport"],
                operation_owner=values["operation_owner"], **common)
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ChildCapabilitySession(
                transport=values["child_transport"], callback_drain=values["drain"],
                **common)
        self.assertFalse(ipc.REAL_TRANSPORT_IMPLEMENTED)
        self.assertFalse(ipc.REAL_EPOCH_ADMISSION_IMPLEMENTED)
        self.assertFalse(values["binding"].real_transport)
        self.assertEqual(len(ipc.UNRESOLVED_BLOCKERS), 2)

        original_status = ipc.REAL_TRANSPORT_IMPLEMENTED
        try:
            ipc.REAL_TRANSPORT_IMPLEMENTED = True
            with self.assertRaises(ipc.CapabilityIpcError):
                ipc.ParentCapabilitySession(
                    transport=values["parent_transport"],
                    operation_owner=values["operation_owner"], **common)
        finally:
            ipc.REAL_TRANSPORT_IMPLEMENTED = original_status

    def test_json_is_strict_canonical_and_rejects_duplicate_nan_and_loose_types(self):
        self.assertEqual(ipc.canonical_json({"b": 2, "a": [True, None]}),
                         b'{"a":[true,null],"b":2}')
        self.assertEqual(ipc.decode_canonical_json(b'{"a":1}'), {"a": 1})
        bad_values = (
            1.0, bytearray(b"x"), (1,), {1: "x"}, {"x": 2**64},
            {"x": "e\u0301"}, {"x": "\ud800"}, {"x": object()},
        )
        for value in bad_values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ipc.CapabilityIpcError):
                    ipc.canonical_json(value)
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{ "a":1}', b'{"x":-0}',
                    b'{"x":1.0}', b'null\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(ipc.CapabilityIpcError):
                    ipc.decode_canonical_json(raw)

        class IntSubclass(int):
            pass
        class DictSubclass(dict):
            pass
        for value in (IntSubclass(1), DictSubclass()):
            with self.assertRaises(ipc.CapabilityIpcError):
                ipc.canonical_json(value)

    def test_factory_table_is_immutable_closed_and_has_no_generic_surface(self):
        with self.assertRaises(TypeError):
            ipc.FACTORY_POLICIES["evil-v1"] = ipc.factory_policy(ipc.FRIDA_FACTORY_ID)
        with self.assertRaises(FrozenInstanceError):
            ipc.factory_policy(ipc.FRIDA_FACTORY_ID).operations[0].max_callbacks = 999
        operation = ipc.factory_policy(ipc.FRIDA_FACTORY_ID).operations[0]
        with self.assertRaises(ipc.CapabilityIpcError):
            replace(operation, max_result_bytes=ipc.MAX_PAYLOAD_BYTES + 1).validate()
        with self.assertRaises(ipc.CapabilityIpcError):
            replace(ipc.factory_policy(ipc.FRIDA_FACTORY_ID),
                    operations=(operation, operation)).validate()
        values = fixture()
        with self.assertRaises(FrozenInstanceError):
            values["binding"].session_id = digest("mutated")
        bad_binding = replace(values["binding"], operation_table_sha256="0" * 64)
        with self.assertRaises(ipc.CapabilityIpcError):
            bad_binding.validate(values["crypto"])
        sends = len(values["shared"].history)
        for operation_id in ("shell", "execute", "dynamic.operation.v1"):
            with self.assertRaises(ipc.CapabilityIpcError):
                values["parent"].begin(operation_id, {}, operation_deadline(values))
        for payload in ({"command": "id"}, {"path": "/tmp/x"}, {"argv": []},
                        {"imports": ["os"]}):
            with self.assertRaises(ipc.CapabilityIpcError):
                values["parent"].begin(first_operation(values), payload,
                                       operation_deadline(values))
        self.assertEqual(len(values["shared"].history), sends)
        public = {
            name for name, member in inspect.getmembers(ipc.ParentCapabilitySession, callable)
            if not name.startswith("_")}
        self.assertEqual(public, {"begin", "cancel", "settle", "verify_quiescent"})
        child_public = {
            name for name, member in inspect.getmembers(ipc.ChildCapabilitySession, callable)
            if not name.startswith("_")}
        operation_public = {
            name for name, member in inspect.getmembers(ipc.ChildOperation, callable)
            if not name.startswith("_")}
        self.assertEqual(child_public, {"receive_request", "verify_quiescent"})
        self.assertFalse(hasattr(ipc, "AuthenticatedCallbackSink"))
        self.assertEqual(operation_public,
                         {"decode_request", "emit_callback", "publish_result",
                          "seal_callbacks"})
        self.assertFalse(public & {"register", "command", "shell", "execute", "path",
                                   "argv", "import_module"})

        exported_view = ipc.FACTORY_POLICIES
        try:
            ipc.FACTORY_POLICIES = {"evil-v1": "dynamic"}
            lease, _, outcome = finish(values, result={"registry": "still frozen"})
            self.assertEqual(lease.operation_id, "frida.collect_native_page.v1")
            self.assertEqual(outcome.result.decode(), {"registry": "still frozen"})
        finally:
            ipc.FACTORY_POLICIES = exported_view

    def test_missing_extra_reordered_duplicate_and_aliased_handles_fail(self):
        values = raw_fixture(ipc.AUTHORITY_FACTORY_ID)
        binding = values["binding"]
        kwargs = dict(
            factory_id=binding.factory_id, session_id=binding.session_id,
            session_epoch=binding.session_epoch,
            absolute_deadline_ns=binding.absolute_deadline_ns, key_id=binding.key_id,
            owner=binding.owner, transport=binding.transport, crypto=values["crypto"])
        bad_resource_sets = (
            binding.resources[:-1],
            binding.resources + (identity("unexpected", 99, "resource"),),
            tuple(reversed(binding.resources)),
            (binding.resources[0], replace(
                binding.resources[1], numeric_value=binding.resources[0].numeric_value),
             binding.resources[2]),
            (binding.resources[0], replace(
                binding.resources[1], object_id=binding.resources[0].object_id),
             binding.resources[2]),
            (replace(binding.resources[0], rights=("query", "read", "write")),
             binding.resources[1], binding.resources[2]),
        )
        for resources in bad_resource_sets:
            with self.subTest(resources=tuple(item.capability_id for item in resources)):
                with self.assertRaises(ipc.CapabilityIpcError):
                    ipc.make_capability_binding(resources=resources, **kwargs)

        aliased_endpoint = replace(
            binding.transport,
            endpoints=(binding.transport.endpoints[0], replace(
                binding.transport.endpoints[1],
                numeric_value=binding.transport.endpoints[0].numeric_value),
                *binding.transport.endpoints[2:]))
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.make_capability_binding(resources=binding.resources,
                                        transport=aliased_endpoint,
                                        **{key: value for key, value in kwargs.items()
                                           if key != "transport"})

        first = values["retained"][0]
        aliased_retained = (first, replace(values["retained"][1], handle=first.handle),
                            values["retained"][2])
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(
                binding=binding, resources=aliased_retained,
                owner_handle=values["owner_handle"], handle_authority=values["handles"],
                operation_owner=values["operation_owner"],
                epoch_admission=values["epoch_admission"],
                transport=values["parent_transport"], clock=values["clock"],
                crypto=values["crypto"], session_key=SESSION_KEY,
                allow_unproven_transport_for_tests=True)

    def _prepared_result(self, callbacks=()):
        values = fixture()
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        for payload in callbacks:
            operation.emit_callback("native_page_event.v1", payload)
        operation.seal_callbacks()
        operation.publish_result({"ok": True})
        return values, lease, operation

    def _assert_parent_packet_rejected(self, change):
        values, lease, _ = self._prepared_result()
        change(values)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertIn(values["parent"].state, {"REVOKED", "QUIESCENCE_UNCERTAIN"})
        self.assertNotEqual(values["parent"].state, "OUTSTANDING")

    def test_partial_forged_detached_missing_and_extra_frames_fail_closed(self):
        def partial(values):
            packet = values["shared"].child_to_parent[0]
            values["shared"].child_to_parent[0] = ipc.WirePacket(
                packet.frame[:-1], packet.payload)

        def forged(values):
            packet = values["shared"].child_to_parent[0]
            envelope = ipc.decode_canonical_json(packet.frame[4:])
            envelope["header"]["body"]["callback_count"] = 7
            raw = ipc.canonical_json(envelope)  # retain the old MAC intentionally
            values["shared"].child_to_parent[0] = ipc.WirePacket(
                len(raw).to_bytes(4, "big") + raw, packet.payload)

        def detached(values):
            packet = values["shared"].child_to_parent[1]
            values["shared"].child_to_parent[1] = ipc.WirePacket(
                packet.frame, packet.payload + b"x")

        def missing(values):
            packet = values["shared"].child_to_parent[0]
            values["shared"].child_to_parent[0] = resign(
                packet, SESSION_KEY, values["crypto"],
                lambda header: header.pop("owner_object_id"))

        def extra(values):
            packet = values["shared"].child_to_parent[0]
            values["shared"].child_to_parent[0] = resign(
                packet, SESSION_KEY, values["crypto"],
                lambda header: header.__setitem__("extra", 1))

        def loose_scalar(values):
            packet = values["shared"].child_to_parent[0]
            values["shared"].child_to_parent[0] = resign(
                packet, SESSION_KEY, values["crypto"],
                lambda header: header.__setitem__("sequence", True))

        def authenticated_bad_payload(values):
            packet = values["shared"].child_to_parent[1]
            values["shared"].child_to_parent[1] = resign_payload(
                packet, b'{"a":1,"a":2}', SESSION_KEY, values["crypto"])

        for attack in (partial, forged, detached, missing, extra, loose_scalar,
                       authenticated_bad_payload):
            with self.subTest(attack=attack.__name__):
                self._assert_parent_packet_rejected(attack)

    def test_reply_replay_reorder_and_result_before_barrier_are_rejected(self):
        def replay(values):
            packet = values["shared"].child_to_parent[0]
            values["shared"].child_to_parent.insert(1, packet)

        def reorder(values):
            queue = values["shared"].child_to_parent
            queue[0], queue[1] = queue[1], queue[0]

        for attack, callbacks in ((replay, ({"event": 1},)), (reorder, ())):
            with self.subTest(attack=attack.__name__):
                values, lease, _ = self._prepared_result(callbacks)
                attack(values)
                with self.assertRaises(ipc.CapabilityIpcError):
                    values["parent"].settle(lease)
                self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture()
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.publish_result({"too": "early"})
        self.assertEqual(values["child"].state, "REVOKED")
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)

    def test_cross_session_cross_operation_and_callback_after_barrier_fail(self):
        for field, value in (("session_id", digest("other session")),
                             ("operation_id", "frida.other_operation.v1"),
                             ("request_id", digest("other request")),
                             ("owner_object_id", digest("other owner"))):
            with self.subTest(field=field):
                values, lease, _ = self._prepared_result(({"event": 1},))
                packet = values["shared"].child_to_parent[0]
                values["shared"].child_to_parent[0] = resign(
                    packet, SESSION_KEY, values["crypto"],
                    lambda header, f=field, v=value: header.__setitem__(f, v))
                with self.assertRaises(ipc.CapabilityIpcError):
                    values["parent"].settle(lease)
                self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture()
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        operation.seal_callbacks()
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {"late": True})
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="stale callback capability")
        _, operation, _ = finish(values)
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {"stale": True})
        self.assertEqual(values["child"].state, "OPEN")

    def test_zero_callback_policy_overflow_and_drain_failure_revoke(self):
        authority = fixture(ipc.AUTHORITY_FACTORY_ID)
        lease = authority["parent"].begin(
            first_operation(authority), {}, operation_deadline(authority))
        operation = authority["child"].receive_request()
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {})
        self.assertEqual(authority["child"].state, "REVOKED")

        values = fixture()
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        for index in range(values["policy"].operations[0].max_callbacks):
            operation.emit_callback("native_page_event.v1", {"index": index})
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {"overflow": True})
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture()
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["drain"].fail = True
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.seal_callbacks()
        with self.assertRaises(ipc.CapabilityIpcError):
            _ = operation.callbacks_sealed
        self.assertEqual(values["child"].state, "QUIESCENCE_UNCERTAIN")
        self.assertTrue(any("callback producers" in item
                            for item in values["child"].cleanup_obligations))

    def test_request_replay_reorder_and_repeated_challenge_revoke_child_or_parent(self):
        values = fixture()
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        request = values["shared"].parent_to_child[0]
        operation = values["child"].receive_request()
        operation.seal_callbacks()
        operation.publish_result({"ok": True})
        values["parent"].settle(lease)
        values["shared"].parent_to_child.append(request)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].receive_request()
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="reordered")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        packet = values["shared"].parent_to_child[0]
        values["shared"].parent_to_child[0] = resign(
            packet, SESSION_KEY, values["crypto"],
            lambda header: header.__setitem__("sequence", 2))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].receive_request()
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="request id derivation")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        packet = values["shared"].parent_to_child[0]
        values["shared"].parent_to_child[0] = resign(
            packet, SESSION_KEY, values["crypto"],
            lambda header: header.__setitem__("request_id", digest("forged request")))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].receive_request()
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="challenge")
        finish(values)
        values["crypto"].challenge_counter = 0
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertEqual(values["parent"].state, "REVOKED")

    def test_deadline_is_absolute_and_cannot_be_rebased(self):
        values = fixture()
        deadline = operation_deadline(values)
        lease = values["parent"].begin(first_operation(values), {}, deadline)
        operation = values["child"].receive_request()
        operation.seal_callbacks()
        operation.publish_result({"ok": True})
        values["clock"].value = deadline
        replacement = replace(lease, deadline_ns=deadline + 1_000_000_000)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(replacement)
        self.assertEqual(values["parent"].state, "OUTSTANDING")
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")
        self.assertEqual(values["shared"].revocations[-1][1], deadline)

        values = fixture(session_label="invalid later cleanup deadline")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        request = values["shared"].parent_to_child[0]
        values["shared"].parent_to_child[0] = resign(
            request, SESSION_KEY, values["crypto"],
            lambda header: header.__setitem__(
                "deadline_ns", values["binding"].absolute_deadline_ns + 1))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].receive_request()
        self.assertEqual(
            values["shared"].revocations[-1][1],
            values["binding"].absolute_deadline_ns)

        values = fixture(session_label="bool deadline")
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(first_operation(values), {}, True)
        self.assertEqual(values["shared"].history, [])

        values, lease, _ = self._prepared_result()
        values["shared"].receive_hooks[("parent", 1)] = lambda: setattr(
            values["clock"], "value", lease.deadline_ns)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture(session_label="late child send")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["shared"].send_hooks[("child", 1)] = lambda: setattr(
            values["clock"], "value", lease.deadline_ns)
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {})
        self.assertEqual(values["child"].state, "REVOKED")

    def test_unexpected_eof_at_every_result_boundary_revokes(self):
        for boundary in ("no_child", "accepted", "callback", "barrier", "reply"):
            with self.subTest(boundary=boundary):
                values = fixture(session_label="eof " + boundary)
                lease = values["parent"].begin(
                    first_operation(values), {}, operation_deadline(values))
                if boundary != "no_child":
                    operation = values["child"].receive_request()
                    if boundary == "callback":
                        operation.emit_callback("native_page_event.v1", {"x": 1})
                    elif boundary == "barrier":
                        operation.seal_callbacks()
                    elif boundary == "reply":
                        operation.seal_callbacks()
                        operation.publish_result({"ok": True})
                        values["shared"].child_to_parent.pop()  # remove authenticated EOF
                with self.assertRaises(ipc.CapabilityIpcError):
                    values["parent"].settle(lease)
                self.assertEqual(values["parent"].state, "REVOKED")

    def test_transport_kill_at_each_send_receive_and_seal_boundary_revokes(self):
        values = fixture(session_label="parent send")
        values["shared"].fail_send.add(("parent", 1))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture(session_label="child receive")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        values["shared"].fail_receive.add(("child", 1))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].receive_request()
        self.assertEqual(values["child"].state, "REVOKED")

        for index, phase in ((1, "barrier"), (2, "reply"), (3, "eof")):
            with self.subTest(child_send=phase):
                values = fixture(session_label="child send " + phase)
                values["parent"].begin(
                    first_operation(values), {}, operation_deadline(values))
                operation = values["child"].receive_request()
                values["shared"].fail_send.add(("child", index))
                if phase == "barrier":
                    action = operation.seal_callbacks
                else:
                    operation.seal_callbacks()
                    action = lambda: operation.publish_result({"ok": True})
                with self.assertRaises(ipc.CapabilityIpcError):
                    action()
                self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="callback send")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["shared"].fail_send.add(("child", 1))
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {})
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="seal")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        operation.seal_callbacks()
        values["shared"].fail_seal = True
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.publish_result({"ok": True})
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="seal verification")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        operation.seal_callbacks()
        values["shared"].fail_send_seal_verify = True
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.publish_result({"ok": True})
        self.assertEqual(values["child"].state, "REVOKED")

        values, lease, _ = self._prepared_result()
        values["shared"].fail_receive.add(("parent", 1))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")

    def test_stale_numeric_identity_is_rejected_at_constructor_and_each_attestation(self):
        values = raw_fixture(session_label="constructor stale")
        values["handles"].stale(values["retained"][0].handle)
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(
                binding=values["binding"], resources=values["retained"],
                owner_handle=values["owner_handle"], handle_authority=values["handles"],
                operation_owner=values["operation_owner"],
                epoch_admission=values["epoch_admission"],
                transport=values["parent_transport"], clock=values["clock"],
                crypto=values["crypto"], session_key=SESSION_KEY,
                allow_unproven_transport_for_tests=True)

        values = fixture(session_label="begin stale")
        values["handles"].stale(values["retained"][0].handle)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture(session_label="receive stale")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        values["handles"].stale(values["retained"][0].handle)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].receive_request()
        self.assertEqual(values["child"].state, "REVOKED")

        values = fixture(session_label="callback stale")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["handles"].stale(values["retained"][0].handle)
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {})
        self.assertEqual(values["child"].state, "REVOKED")

        values, lease, _ = self._prepared_result()
        values["handles"].stale(values["owner_handle"])
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture(session_label="post request send stale")
        values["shared"].send_hooks[("parent", 1)] = lambda: values["handles"].stale(
            values["owner_handle"])
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture(session_label="post callback send stale")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["shared"].send_hooks[("child", 1)] = lambda: values["handles"].stale(
            values["retained"][0].handle)
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {})
        self.assertEqual(values["child"].state, "REVOKED")

    def test_parent_retained_owner_cancel_and_exact_lease_are_terminal(self):
        first = fixture(session_label="first owner")
        second = fixture(session_label="second owner")
        first_lease = first["parent"].begin(
            first_operation(first), {}, operation_deadline(first))
        second_lease = second["parent"].begin(
            first_operation(second), {}, operation_deadline(second))
        with self.assertRaises(ipc.CapabilityIpcError):
            first["parent"].settle(second_lease)
        self.assertEqual(first["parent"].state, "OUTSTANDING")
        copied = replace(first_lease)
        with self.assertRaises(ipc.CapabilityIpcError):
            first["parent"].cancel(copied)
        self.assertEqual(first["parent"].state, "OUTSTANDING")
        self.assertIsNone(first["parent"].cancel(first_lease))
        self.assertEqual(first["parent"].state, "REVOKED")
        self.assertIsNone(first["parent"].verify_quiescent())
        terminal_packets = [packet for side, packet, _ in first["shared"].history
                            if side == "parent"]
        self.assertGreaterEqual(len(terminal_packets), 2)
        terminal_header, terminal_payload = ipc._open_packet(
            terminal_packets[-1], key=SESSION_KEY, crypto=first["crypto"])
        self.assertEqual(terminal_header["kind"], "terminal")
        self.assertEqual(terminal_header["body"], {"reason": "cancelled"})
        self.assertEqual(terminal_payload, b"")

        second["parent"].cancel(second_lease)

    def test_owner_substitution_admission_stale_lease_and_settlement_fail_closed(self):
        values = raw_fixture(session_label="owner substitution")
        values["operation_owner"].alias = replace(
            values["operation_owner"].value, owner_object_id=digest("substitute owner"))
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(
                binding=values["binding"], resources=values["retained"],
                owner_handle=values["owner_handle"], handle_authority=values["handles"],
                operation_owner=values["operation_owner"],
                epoch_admission=values["epoch_admission"],
                transport=values["parent_transport"], clock=values["clock"],
                crypto=values["crypto"], session_key=SESSION_KEY,
                allow_unproven_transport_for_tests=True)

        values = fixture(session_label="owner admission")
        values["operation_owner"].fail_admit = True
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertEqual(values["parent"].state, "REVOKED")
        self.assertEqual(values["shared"].history, [])

        values, lease, _ = self._prepared_result()
        values["operation_owner"].active = replace(lease)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")
        self.assertIn(lease.request_id, values["operation_owner"].revoked)

        values, lease, _ = self._prepared_result()
        values["operation_owner"].fail_settle = True
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")
        self.assertIn(lease.request_id, values["operation_owner"].revoked)

        values, lease, _ = self._prepared_result()
        values["operation_owner"].settle_hook = lambda: setattr(
            values["clock"], "value", lease.deadline_ns)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")
        self.assertEqual(values["shared"].revocations[-1][1], lease.deadline_ns)

    def test_owner_revoke_or_quiescence_failure_is_sticky_uncertainty(self):
        values = fixture(session_label="owner revoke failure")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        values["operation_owner"].fail_revoke = True
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "QUIESCENCE_UNCERTAIN")
        self.assertTrue(any("owner revocation" in item
                            for item in values["parent"].cleanup_obligations))
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["parent"].verify_quiescent()
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))

        values, lease, _ = self._prepared_result()
        values["operation_owner"].fail_quiescent = True
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "QUIESCENCE_UNCERTAIN")
        self.assertTrue(values["parent"].cleanup_obligations)

        values = fixture(session_label="transport revoke failure")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        values["shared"].fail_revoke = True
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "QUIESCENCE_UNCERTAIN")
        self.assertTrue(any("transport revocation" in item
                            for item in values["parent"].cleanup_obligations))

    def test_signed_eof_requires_exact_seal_and_no_trailing_frames(self):
        values, lease, _ = self._prepared_result()
        values["shared"].child_to_parent.append(values["shared"].child_to_parent[0])
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")

        values, lease, _ = self._prepared_result()
        values["shared"].sealed.clear()
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")

        values = fixture(session_label="uncertain")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        values["shared"].fail_quiescent = True
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "QUIESCENCE_UNCERTAIN")
        self.assertTrue(values["parent"].cleanup_obligations)

    def test_verify_quiescent_is_nonmutating_and_rejects_active_sessions(self):
        values = fixture()
        before = (values["parent"].state, values["parent"].cleanup_obligations,
                  values["operation_owner"].active,
                  tuple(values["shared"].parent_to_child),
                  tuple(values["shared"].child_to_parent))
        self.assertIsNone(values["parent"].verify_quiescent())
        after = (values["parent"].state, values["parent"].cleanup_obligations,
                 values["operation_owner"].active,
                 tuple(values["shared"].parent_to_child),
                 tuple(values["shared"].child_to_parent))
        self.assertEqual(after, before)
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["parent"].verify_quiescent()
        operation = values["child"].receive_request()
        with self.assertRaises(ipc.CapabilityQuiescenceError):
            values["child"].verify_quiescent()
        operation.seal_callbacks()
        operation.publish_result({"ok": True})
        values["parent"].settle(lease)
        self.assertIsNone(values["parent"].verify_quiescent())
        self.assertIsNone(values["child"].verify_quiescent())

    def test_type_confusion_reentry_and_concurrency_are_rejected(self):
        class DictSubclass(dict):
            pass
        class PacketSubclass(ipc.WirePacket):
            pass
        values = fixture()
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), DictSubclass(), operation_deadline(values))

        values, lease, _ = self._prepared_result()
        first = values["shared"].child_to_parent[0]
        values["shared"].child_to_parent[0] = PacketSubclass(first.frame, first.payload)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)

        values, lease, _ = self._prepared_result()
        nested = []
        values["shared"].receive_hooks[("parent", 1)] = lambda: self._capture(
            nested, values["parent"].verify_quiescent)
        outcome = values["parent"].settle(lease)
        self.assertTrue(outcome.eof_verified)
        self.assertEqual(len(nested), 1)
        self.assertIn("reentrant", str(nested[0]))

        values, lease, _ = self._prepared_result()
        concurrent = []
        def concurrent_probe():
            thread = threading.Thread(
                target=lambda: self._capture(concurrent, values["parent"].verify_quiescent))
            thread.start()
            thread.join()
        values["shared"].receive_hooks[("parent", 1)] = concurrent_probe
        values["parent"].settle(lease)
        self.assertEqual(len(concurrent), 1)
        self.assertIn("concurrent", str(concurrent[0]))

        values = fixture(session_label="callback reentry")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["shared"].send_hooks[("child", 1)] = lambda: operation.emit_callback(
            "native_page_event.v1", {"nested": True})
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.emit_callback("native_page_event.v1", {"outer": True})
        self.assertEqual(values["child"].state, "REVOKED")

    def test_private_authority_storage_and_dynamic_replay_views_are_read_only(self):
        values = fixture(session_label="private storage")
        self.assertFalse(hasattr(values["parent"], "__dict__"))
        self.assertFalse(hasattr(values["child"], "__dict__"))
        policy = values["policy"]
        expanded_operation = replace(
            policy.operations[0], callback_events=("extra_event.v1",) +
            policy.operations[0].callback_events)
        expanded_policy = replace(policy, operations=(expanded_operation,))
        with self.assertRaises(ipc.CapabilityIpcError):
            expanded_policy.validate()

        replacements = {
            "binding": replace(values["binding"]),
            "_policy": expanded_policy,
            "_resources": (),
            "_owner_handle": object(),
            "_handles": FakeHandleAuthority(),
            "_transport": values["child_transport"],
            "_clock": FakeClock(),
            "_crypto": FakeCrypto(),
            "_key": b"z" * 32,
            "_entry_lock": threading.Lock(),
            "_operation_owner": object(),
            "_operation_owner_binding": replace(values["operation_owner"].value),
            "_sequence": 0,
            "_challenges": set(),
            "_outstanding": None,
        }
        for name, replacement_value in replacements.items():
            with self.subTest(parent_field=name):
                with self.assertRaises(AttributeError):
                    setattr(values["parent"], name, replacement_value)
        child_replacements = dict(replacements)
        child_replacements.update({"_callback_drain": FakeDrain([]), "_active": None})
        for name, replacement_value in child_replacements.items():
            with self.subTest(child_field=name):
                with self.assertRaises(AttributeError):
                    setattr(values["child"], name, replacement_value)
        self.assertFalse(hasattr(values["parent"], "_challenges"))

        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        self.assertFalse(hasattr(operation, "__dict__"))
        self.assertTrue(weakref.getweakrefs(operation))
        self.assertTrue(all(reference.__callback__ is None
                            for reference in weakref.getweakrefs(operation)))
        for target, name, replacement_value in (
                (operation, "_child", object()),
                (operation, "_lease", object()),
                (operation, "_policy", expanded_operation),
                (operation, "_resources", ()),
                (operation, "_generation", 0),
                (operation, "_drain", FakeDrain([])),
                (operation, "_binding", object()),
                (operation, "_count", 0),
                (operation, "_sealed", False)):
            with self.subTest(operation_field=name):
                with self.assertRaises(AttributeError):
                    setattr(target, name, replacement_value)
        operation.seal_callbacks()
        operation.publish_result({"private": True})
        outcome = values["parent"].settle(lease)
        self.assertEqual(outcome.result.decode(), {"private": True})

    def test_retained_provider_method_substitution_and_forged_key_fail_closed(self):
        attacks = (
            ("clock", lambda values: setattr(values["clock"], "now_ns", lambda: 0)),
            ("crypto compare", lambda values: setattr(
                values["crypto"], "compare_digest", lambda _left, _right: True)),
            ("handles", lambda values: setattr(
                values["handles"], "identity", lambda _handle: values["owner_identity"])),
            ("transport", lambda values: setattr(
                values["child_transport"], "receive", lambda _deadline: None)),
            ("epoch", lambda values: setattr(
                values["epoch_admission"], "verify_admitted",
                lambda _binding, _side: None)),
            ("drain", lambda values: setattr(
                values["drain"], "verify_drained",
                lambda _binding, _challenge: None)),
        )
        for label, attack in attacks:
            with self.subTest(authority=label):
                values = fixture(session_label="method substitution " + label)
                values["parent"].begin(
                    first_operation(values), {}, operation_deadline(values))
                if label == "drain":
                    operation = values["child"].receive_request()
                    attack(values)
                    with self.assertRaises(ipc.CapabilityIpcError):
                        operation.seal_callbacks()
                    with self.assertRaises(ipc.CapabilityIpcError):
                        _ = operation.callbacks_sealed
                else:
                    attack(values)
                    with self.assertRaises(ipc.CapabilityIpcError):
                        values["child"].receive_request()
                self.assertIn(values["child"].state,
                              {"REVOKED", "QUIESCENCE_UNCERTAIN"})

        values = fixture(session_label="operation owner method substitution")
        values["operation_owner"].verify = lambda _expected: None
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertIn(values["parent"].state, {"REVOKED", "QUIESCENCE_UNCERTAIN"})

        values, lease, _operation = self._prepared_result()
        with self.assertRaises(AttributeError):
            values["parent"]._key = b"forged" * 6
        packet = values["shared"].child_to_parent[0]
        values["shared"].child_to_parent[0] = resign(
            packet, b"x" * 32, values["crypto"], lambda _header: None)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertEqual(values["parent"].state, "REVOKED")

    def test_epoch_is_one_shot_bound_everywhere_and_cross_instance_replay_fails(self):
        values = raw_fixture(session_label="one shot epoch")
        common = dict(
            binding=values["binding"], resources=values["retained"],
            owner_handle=values["owner_handle"], handle_authority=values["handles"],
            operation_owner=values["operation_owner"],
            transport=values["parent_transport"], clock=values["clock"],
            crypto=values["crypto"], session_key=SESSION_KEY,
            epoch_admission=values["epoch_admission"],
            allow_unproven_transport_for_tests=True)
        parent = ipc.ParentCapabilitySession(**common)
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(**common)
        cloned_admission = FakeEpochAdmission(
            values["binding"].factory_id, values["binding"].role,
            values["binding"].session_id, values["binding"].owner.object_id,
            "cloned epoch authority")
        cloned_admission.value = values["binding"].session_epoch
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(
                **{**common, "epoch_admission": cloned_admission})
        with self.assertRaises(AttributeError):
            parent._sequence = 0
        with self.assertRaises(AttributeError):
            parent._challenges = set()

        replay_source = fixture(session_label="epoch replay source")
        replay_target = fixture(session_label="epoch replay target")
        source_lease = replay_source["parent"].begin(
            first_operation(replay_source), {}, operation_deadline(replay_source))
        source_packet = replay_source["shared"].parent_to_child.pop(0)
        source_header = ipc.decode_canonical_json(source_packet.frame[4:])["header"]
        self.assertEqual(source_lease.session_epoch,
                         replay_source["binding"].session_epoch.epoch_id)
        self.assertEqual(source_header["session_epoch"], source_lease.session_epoch)
        self.assertIn(source_lease.session_epoch,
                      ipc.canonical_json(replay_source["binding"].wire()).decode())
        replay_target["shared"].parent_to_child.append(source_packet)
        with self.assertRaises(ipc.CapabilityIpcError):
            replay_target["child"].receive_request()
        self.assertEqual(replay_target["child"].state, "REVOKED")
        replay_source["parent"].cancel(source_lease)

    def test_stale_callback_racing_next_receive_cannot_reopen_generation(self):
        values = fixture(session_label="stale callback generation race")
        _first_lease, stale_operation, _outcome = finish(values)
        second_lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        stale_errors = []

        def stale_during_receive():
            thread = threading.Thread(target=lambda: self._capture(
                stale_errors, lambda: stale_operation.emit_callback(
                    "native_page_event.v1", {"stale": True})))
            thread.start()
            thread.join()

        values["shared"].receive_hooks[("child", 2)] = stale_during_receive
        current_operation = values["child"].receive_request()
        self.assertEqual(len(stale_errors), 1)
        self.assertEqual(
            str(stale_errors[0]),
            "child operation failed inside the retained capability boundary "
            "(capability)")
        self.assertEqual(values["child"].state, "ACTIVE")
        current_operation.seal_callbacks()
        current_operation.publish_result({"current": True})
        self.assertEqual(
            values["parent"].settle(second_lease).result.decode(),
            {"current": True})

        values = fixture(session_label="result concurrency")
        values["parent"].begin(first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        operation.seal_callbacks()
        concurrent_result = []
        def result_probe():
            thread = threading.Thread(target=lambda: self._capture(
                concurrent_result, lambda: operation.publish_result({"nested": True})))
            thread.start()
            thread.join()
        values["shared"].send_hooks[("child", 2)] = result_probe
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.publish_result({"outer": True})
        self.assertEqual(len(concurrent_result), 1)
        self.assertEqual(
            str(concurrent_result[0]),
            "child operation failed inside the retained capability boundary "
            "(capability)")
        self.assertEqual(values["child"].state, "REVOKED")

    def test_private_roots_cannot_be_copied_replaced_or_reset_for_replay(self):
        values = fixture(session_label="closure private roots")
        # The supported object-capability boundary exposes neither the private
        # registry nor a root-returning method.  Arbitrary same-process module
        # introspection is deliberately outside this Python prototype boundary.
        self.assertNotIn("_LOOKUP_PRIVATE_AUTHORITY", ipc.__all__)
        self.assertNotIn("_session_authority", ipc.__all__)
        for session in (values["parent"], values["child"]):
            self.assertTrue(weakref.getweakrefs(session))
            self.assertTrue(all(reference.__callback__ is None
                                for reference in weakref.getweakrefs(session)))
            self.assertFalse(hasattr(session, "_authority_capsule"))
            self.assertFalse(hasattr(session, "_session_authority"))
            self.assertFalse(hasattr(session, "_LOOKUP_PRIVATE_AUTHORITY"))
            with self.assertRaises(AttributeError):
                object.__setattr__(session, "_SessionBase__authority", object())
            with self.assertRaises(ipc.CapabilityIpcError):
                copy.copy(session)
            with self.assertRaises(ipc.CapabilityIpcError):
                copy.deepcopy(session)

        _lease, operation, _outcome = finish(values)
        for capability in (operation,):
            self.assertFalse(hasattr(capability, "_authority_capsule"))
            with self.assertRaises(ipc.CapabilityIpcError):
                copy.copy(capability)
            with self.assertRaises(ipc.CapabilityIpcError):
                copy.deepcopy(capability)

        # Rewinding only the caller-retained challenge provider cannot recreate
        # an accepted packet because sequence/nonces are closure-held append-only state.
        values["crypto"].challenge_counter = 0
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].begin(
                first_operation(values), {}, operation_deadline(values))
        self.assertIn(values["parent"].state, {"REVOKED", "QUIESCENCE_UNCERTAIN"})

    def test_ambiguous_epoch_admission_is_revoked_or_reports_uncertainty(self):
        values = raw_fixture(session_label="partial epoch admission")
        admission = values["epoch_admission"]

        def partial_admit(expected, side):
            admission.used.add(side)
            admission.active.add(side)
            raise ipc.CapabilityIpcError("epoch admission reply lost")

        admission.admit = partial_admit
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ParentCapabilitySession(
                binding=values["binding"], resources=values["retained"],
                owner_handle=values["owner_handle"],
                handle_authority=values["handles"],
                operation_owner=values["operation_owner"],
                transport=values["parent_transport"],
                epoch_admission=admission, clock=values["clock"],
                crypto=values["crypto"], session_key=SESSION_KEY,
                allow_unproven_transport_for_tests=True)
        self.assertNotIn("parent", admission.active)
        self.assertIn("parent", admission.revoked)

        values = raw_fixture(session_label="uncertain epoch admission cleanup")
        admission = values["epoch_admission"]

        def failed_verify(_expected, _side):
            raise ipc.CapabilityIpcError("epoch admission cannot be verified")

        def failed_revoke(_expected, _side):
            raise ipc.CapabilityIpcError("epoch revocation reply lost")

        admission.verify_admitted = failed_verify
        admission.revoke = failed_revoke
        with self.assertRaises(ipc.CapabilityQuiescenceError) as caught:
            ipc.ParentCapabilitySession(
                binding=values["binding"], resources=values["retained"],
                owner_handle=values["owner_handle"],
                handle_authority=values["handles"],
                operation_owner=values["operation_owner"],
                transport=values["parent_transport"],
                epoch_admission=admission, clock=values["clock"],
                crypto=values["crypto"], session_key=SESSION_KEY,
                allow_unproven_transport_for_tests=True)
        self.assertIn("quiescence is not proven", str(caught.exception))
        self.assertIn("parent", admission.active)

    def test_quiescence_uses_exact_terminal_receipt_and_rechecks_final_drift(self):
        values = fixture(session_label="exact revoked receipt")
        first_lease, _operation, _outcome = finish(values)
        second_lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        values["parent"].cancel(second_lease)
        values["operation_owner"].quiescent_requests.clear()
        values["shared"].quiescent_requests.clear()
        self.assertIsNone(values["parent"].verify_quiescent())
        self.assertEqual(values["operation_owner"].quiescent_requests,
                         [second_lease.request_id])
        self.assertIn(("parent", second_lease.request_id),
                      values["shared"].quiescent_requests)
        self.assertNotEqual(first_lease.request_id, second_lease.request_id)

        values = fixture(session_label="exact child revoked receipt")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.publish_result({"before": "barrier"})
        values["shared"].quiescent_requests.clear()
        self.assertIsNone(values["child"].verify_quiescent())
        self.assertIn(("child", lease.request_id),
                      values["shared"].quiescent_requests)

        for side in ("parent", "child"):
            values = fixture(session_label="final quiescence drift " + side)
            values["shared"].quiescent_hook = lambda _challenge, values=values: setattr(
                values["shared"], "changed", True)
            with self.assertRaises(ipc.CapabilityIpcError):
                values[side].verify_quiescent()

        values = fixture(session_label="final owner quiescence drift")
        finish(values)
        values["operation_owner"].quiescent_hook = lambda _challenge: setattr(
            values["operation_owner"], "changed", True)
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].verify_quiescent()

    def test_child_quiescence_reattests_exact_callback_drain(self):
        values = fixture(session_label="child drain terminal receipt")
        finish(values)
        before = len(values["drain"].calls)
        self.assertIsNone(values["child"].verify_quiescent())
        self.assertGreaterEqual(len(values["drain"].calls), before + 1)
        values["drain"].fail = True
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].verify_quiescent()

        values = fixture(session_label="child final drain authority drift")
        finish(values)
        def substitute_drain_during_proof(challenge):
            setattr(values["drain"], "verify_drained",
                    lambda _binding, _challenge: None)
            challenge.note_component_mutation("callback_drain")
        values["drain"].hook = substitute_drain_during_proof
        with self.assertRaises(ipc.CapabilityIpcError):
            values["child"].verify_quiescent()

    def test_child_operation_handle_is_opaque_and_exactly_resource_scoped(self):
        values = fixture(session_label="opaque child operation")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        self.assertEqual(repr(operation), "<ChildOperation opaque>")
        self.assertFalse(hasattr(operation, "__dict__"))
        self.assertEqual(
            set(dir(operation)),
            set(ipc.ChildOperation._PUBLIC_MEMBERS) | {"__class__"})
        for name in (
                "_child", "child", "session", "root", "key", "_key",
                "transport", "_transport", "owner", "_owner_handle",
                "resource", "resources", "_resources", "callback_sink",
                "lease", "policy", "request"):
            with self.subTest(hidden=name):
                self.assertFalse(hasattr(operation, name))
        for name in ("decode_request", "emit_callback", "seal_callbacks",
                     "publish_result"):
            method = getattr(operation, name)
            self.assertIs(method.__self__, operation)
            self.assertIsNone(method.__func__.__closure__)
        with self.assertRaises(TypeError):
            vars(operation)
        with self.assertRaises(ipc.CapabilityIpcError):
            pickle.dumps(operation)
        with self.assertRaises(ipc.CapabilityIpcError):
            type("ChildOperationAlias", (ipc.ChildOperation,), {})
        with self.assertRaises(ipc.CapabilityIpcError):
            type("ChildSessionAlias", (ipc.ChildCapabilitySession,), {})
        with self.assertRaises(ipc.CapabilityIpcError):
            type("ParentSessionAlias", (ipc.ParentCapabilitySession,), {})

        unauthenticated = object.__new__(ipc.ChildOperation)
        with self.assertRaises(ipc.CapabilityIpcError):
            unauthenticated.emit_callback("native_page_event.v1", {})
        self.assertEqual(
            operation.required_resource_ids,
            ("frida_device", "target_process"))
        self.assertNotIn("parent_owner", operation.required_resource_ids)
        operation.seal_callbacks()
        operation.publish_result({"opaque": True})
        self.assertEqual(
            values["parent"].settle(lease).result.decode(), {"opaque": True})

        authority_values = fixture(
            ipc.AUTHORITY_FACTORY_ID, "operation resource scope")
        authority_lease = authority_values["parent"].begin(
            first_operation(authority_values), {},
            operation_deadline(authority_values))
        authority_operation = authority_values["child"].receive_request()
        self.assertEqual(
            authority_operation.required_resource_ids,
            ("private_adb", "target_process"))
        self.assertNotIn("root_reader", authority_operation.required_resource_ids)
        self.assertNotIn("parent_owner", authority_operation.required_resource_ids)
        authority_operation.seal_callbacks()
        authority_operation.publish_result({"scoped": True})
        authority_values["parent"].settle(authority_lease)

    def test_exact_identity_dispatch_rejects_equal_hash_and_forged_aliases(self):
        values = fixture(session_label="exact identity dispatch")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()

        class EqualHashAlias:
            def __hash__(self):
                return hash(operation)

            def __eq__(self, _other):
                return True

        alias = EqualHashAlias()
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ChildOperation.emit_callback(
                alias, "native_page_event.v1", {"forged": True})
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ChildOperation.decode_request(alias)
        with self.assertRaises(ipc.CapabilityIpcError):
            ipc.ChildOperation.publish_result(alias, {"forged": True})
        self.assertEqual(values["shared"].child_to_parent, [])
        operation.seal_callbacks()
        operation.publish_result({"identity": "exact"})
        values["parent"].settle(lease)

    def _assert_sanitized_operation_failure(self, error, operation, values=None):
        self.assertIn(type(error), {
            ipc.CapabilityIpcError, ipc.CapabilityQuiescenceError})
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assertEqual(len(error.args), 1)
        self.assertIs(type(error.args[0]), str)
        self.assertNotIsInstance(error, BaseExceptionGroup)
        self.assertNotIn("ExceptionGroup", repr(error))
        sensitive = []
        if values is not None:
            sensitive.extend((
                values["parent"], values["child"], values["parent_transport"],
                values["child_transport"], values["shared"], values["handles"],
                values["owner_handle"], values["operation_owner"],
                values["drain"], SESSION_KEY,
            ))
            sensitive.extend(values["retained"])
            sensitive.extend(item.handle for item in values["retained"])
        trace = error.__traceback__
        self.assertIsNotNone(trace)
        while trace is not None:
            local_values = trace.tb_frame.f_locals
            self.assertNotIn("root", local_values)
            self.assertNotIn("authority", local_values)
            self.assertNotIn("session_key", local_values)
            for value in local_values.values():
                if value is operation:
                    continue
                self.assertTrue(all(value is not item for item in sensitive))
            trace = trace.tb_next

    def test_public_operation_failures_are_root_free_and_terminal(self):
        # Every public action uses the same no-throw internal dispatcher.  Even
        # a reconstructed exact-type handle must expose only the public frame
        # and a fixed primitive error after the internal traceback is gone.
        calls = (
            lambda value: value.operation_id,
            lambda value: value.decode_request(),
            lambda value: value.required_resource_ids,
            lambda value: value.callback_count,
            lambda value: value.callbacks_sealed,
            lambda value: value.emit_callback("native_page_event.v1", {}),
            lambda value: value.seal_callbacks(),
            lambda value: value.publish_result({}),
        )
        for call in calls:
            with self.subTest(public_action=inspect.getsource(call).strip()):
                operation = object.__new__(ipc.ChildOperation)
                try:
                    call(operation)
                except BaseException as error:
                    self._assert_sanitized_operation_failure(error, operation)
                else:
                    self.fail("unauthenticated operation unexpectedly dispatched")

        # A backend policy failure, a retained-resource failure, a callback
        # authority failure, and an ExceptionGroup are all sanitized only after
        # the exact operation root has been retired by terminal cleanup.
        cases = []

        values = fixture(session_label="sanitized backend failure")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        cases.append((values, operation, lambda: operation.emit_callback(
            "outside_policy.v1", {})))

        values = fixture(session_label="sanitized resource failure")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["handles"].stale(values["retained"][0].handle)
        cases.append((values, operation, operation.decode_request))

        values = fixture(session_label="sanitized drain failure")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["drain"].fail = True
        cases.append((values, operation, operation.seal_callbacks))

        values = fixture(session_label="sanitized exception group")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        values["drain"].hook = lambda _challenge: (_ for _ in ()).throw(
            ExceptionGroup("must not cross boundary", [RuntimeError("nested")]))
        cases.append((values, operation, operation.seal_callbacks))

        for values, operation, call in cases:
            with self.subTest(terminal_failure=values["binding"].session_id):
                try:
                    call()
                except BaseException as error:
                    self._assert_sanitized_operation_failure(
                        error, operation, values)
                else:
                    self.fail("terminal operation failure was not raised")
                self.assertIn(values["child"].state,
                              {"REVOKED", "QUIESCENCE_UNCERTAIN"})
                try:
                    _ = operation.operation_id
                except BaseException as stale_error:
                    self._assert_sanitized_operation_failure(
                        stale_error, operation, values)
                else:
                    self.fail("terminal operation root remained reachable")

        # Read APIs participate in the same child-action entry gate.  A read
        # paused in retained verification cannot return request data after a
        # concurrent public action requests terminal revocation.
        values = fixture(session_label="serialized operation read")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        entered = threading.Event()
        release = threading.Event()
        read_values = []
        read_errors = []
        concurrent_errors = []

        def pause_read_verification():
            entered.set()
            if not release.wait(2):
                raise ipc.CapabilityIpcError("read verification release timed out")

        values["shared"].verify_hook = pause_read_verification

        def read_request():
            try:
                read_values.append(operation.decode_request())
            except BaseException as error:
                read_errors.append(error)

        reader = threading.Thread(target=read_request)
        reader.start()
        self.assertTrue(entered.wait(2))
        try:
            try:
                _ = operation.callback_count
            except BaseException as error:
                concurrent_errors.append(error)
            else:
                self.fail("concurrent operation read unexpectedly succeeded")
        finally:
            release.set()
            reader.join(2)
        self.assertFalse(reader.is_alive())
        self.assertEqual(read_values, [])
        self.assertEqual(len(read_errors), 1)
        self.assertEqual(len(concurrent_errors), 1)
        self._assert_sanitized_operation_failure(
            concurrent_errors[0], operation, values)
        self._assert_sanitized_operation_failure(
            read_errors[0], operation, values)
        self.assertIn(values["child"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

    def test_provider_retained_exception_graphs_never_cross_root_boundary(self):
        STACK_STEAL_ATTEMPTS.clear()
        cases = (
            ("transport", ipc.FRIDA_FACTORY_ID,
             lambda values, error: setattr(
                values["shared"], "send_error", error),
             lambda operation: operation.emit_callback(
                 "native_page_event.v1", {"provider": "transport"})),
            ("resource", ipc.FRIDA_FACTORY_ID,
             lambda values, error: install_resource_identity_error(
                 values, error, "frida_device"),
             lambda operation: operation.decode_request()),
            ("private_adb", ipc.AUTHORITY_FACTORY_ID,
             lambda values, error: install_resource_identity_error(
                 values, error, "private_adb"),
             lambda operation: operation.decode_request()),
            ("drain", ipc.FRIDA_FACTORY_ID,
             lambda values, error: setattr(
                values["drain"], "held_error", error),
             lambda operation: operation.seal_callbacks()),
            ("crypto", ipc.FRIDA_FACTORY_ID,
             lambda values, error: setattr(
                 values["crypto"], "hmac_error", error),
             lambda operation: operation.emit_callback(
                 "native_page_event.v1", {"provider": "crypto"})),
        )
        for label, factory_id, install_error, invoke in cases:
            with self.subTest(provider=label):
                values = fixture(factory_id, "provider-held " + label)
                values["parent"].begin(
                    first_operation(values), {}, operation_deadline(values))
                operation = values["child"].receive_request()
                held, nodes = provider_exception_graph(label)
                install_error(values, held)
                try:
                    invoke(operation)
                except BaseException as error:
                    self._assert_sanitized_operation_failure(
                        error, operation, values)
                else:
                    self.fail("provider-retained exception did not terminate operation")
                provider_exception_graph_is_scrubbed(self, nodes)
                self.assertIn(values["child"].state,
                              {"REVOKED", "QUIESCENCE_UNCERTAIN"})
                with self.assertRaises(ipc.CapabilityIpcError):
                    operation.decode_request()
                self.assertEqual(STACK_STEAL_ATTEMPTS, [])

    def test_provider_exception_is_root_free_before_terminal_retirement(self):
        STACK_STEAL_ATTEMPTS.clear()
        values = fixture(session_label="provider exception watcher")
        values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        held, nodes = provider_exception_graph("watcher")
        values["shared"].send_error = held

        observe = threading.Event()
        release = threading.Event()
        observations = []
        watcher_errors = []
        sensitive = (
            values["parent"], values["child"], values["owner_handle"],
            values["retained"], SESSION_KEY,
            *(item for item in values["retained"]),
            *(item.handle for item in values["retained"]),
        )

        def watcher():
            try:
                if not observe.wait(2):
                    raise AssertionError("provider exception was not observed")
                for node_index, node in enumerate(nodes):
                    trace = RAW_TRACEBACK_SLOT.__get__(node, BaseException)
                    while trace is not None:
                        frame_values = dict(trace.tb_frame.f_locals)
                        observations.append((
                            node_index, trace.tb_frame.f_code.co_name, frame_values))
                        trace = trace.tb_next
            except BaseException as error:
                watcher_errors.append(error)
            finally:
                release.set()

        watcher_thread = threading.Thread(target=watcher)
        watcher_thread.start()

        def trace_provider_failure(frame, event, arg):
            if (event == "exception" and len(arg) == 3 and arg[1] is held and
                    frame.f_code.co_name == "_invoke_provider_no_throw"):
                observe.set()
                if not release.wait(2):
                    raise AssertionError("provider exception watcher did not release")
            return trace_provider_failure

        caught = None
        previous_trace = sys.gettrace()
        sys.settrace(trace_provider_failure)
        try:
            operation.emit_callback(
                "native_page_event.v1", {"provider": "watched"})
        except BaseException as error:
            caught = error
        finally:
            sys.settrace(previous_trace)
            release.set()
            watcher_thread.join(2)

        self.assertFalse(watcher_thread.is_alive())
        self.assertEqual(watcher_errors, [])
        self.assertTrue(observations)
        for _node_index, frame_name, frame_values in observations:
            self.assertNotIn(frame_name, {
                "_dispatch_emit_callback", "_operation_fail", "_abort_active",
                "_revoke", "call", "cleanup_call",
            })
            self.assertNotIn("root", frame_values)
            self.assertNotIn("authority", frame_values)
            self.assertNotIn("session_key", frame_values)
            for value in frame_values.values():
                self.assertTrue(all(value is not item for item in sensitive))
                self.assertNotIn(type(value).__name__, {
                    "_SessionAuthorities", "_ChildOperationAuthorities"})
        self.assertIsNotNone(caught)
        self._assert_sanitized_operation_failure(caught, operation)
        provider_exception_graph_is_scrubbed(self, nodes)
        self.assertEqual(STACK_STEAL_ATTEMPTS, [])
        self.assertIn(values["child"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

    def test_active_operations_attest_only_their_exact_resource_subset(self):
        subsets = (
            ("authority.read_device_state.v1", ("private_adb",)),
            ("authority.read_framework.v1", ("private_adb", "root_reader")),
            ("authority.read_activity_dump.v1",
             ("private_adb", "target_process")),
        )
        for operation_id, expected_ids in subsets:
            with self.subTest(operation_id=operation_id):
                values = fixture(
                    ipc.AUTHORITY_FACTORY_ID,
                    "scoped live identity " + operation_id)
                lease = values["parent"].begin(
                    operation_id, {}, operation_deadline(values))
                operation = values["child"].receive_request()
                values["handles"].calls.clear()

                self.assertEqual(operation.decode_request(), {})
                operation.seal_callbacks()
                operation.publish_result({"scope": list(expected_ids)})

                expected_handles = tuple(
                    item.handle for item in values["retained"]
                    if item.identity.capability_id in expected_ids)
                unrelated_handles = tuple(
                    item.handle for item in values["retained"]
                    if item.identity.capability_id not in expected_ids)
                self.assertTrue(values["handles"].calls)
                for retained_handle in values["handles"].calls:
                    self.assertTrue(any(
                        retained_handle is item for item in expected_handles))
                    self.assertTrue(all(
                        retained_handle is not item for item in unrelated_handles))
                    self.assertIsNot(retained_handle, values["owner_handle"])
                for retained_handle in expected_handles:
                    self.assertTrue(any(
                        retained_handle is item
                        for item in values["handles"].calls))

                outcome = values["parent"].settle(lease)
                self.assertEqual(
                    outcome.result.decode(), {"scope": list(expected_ids)})

        # Unrelated live-handle drift is deliberately deferred, not ignored:
        # a private_adb-only child operation can finish without touching it,
        # while the full parent terminal attestation still rejects the session.
        values = fixture(
            ipc.AUTHORITY_FACTORY_ID, "scoped drift caught at terminal")
        lease = values["parent"].begin(
            "authority.read_device_state.v1", {}, operation_deadline(values))
        operation = values["child"].receive_request()
        root_reader = next(
            item for item in values["retained"]
            if item.identity.capability_id == "root_reader")
        values["handles"].stale(root_reader.handle)
        values["handles"].calls.clear()
        self.assertEqual(operation.decode_request(), {})
        operation.seal_callbacks()
        operation.publish_result({"scoped": True})
        self.assertTrue(all(
            retained_handle is not root_reader.handle
            for retained_handle in values["handles"].calls))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertIn(values["parent"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

    def test_private_adb_failure_never_captures_unrelated_resource_locals(self):
        STACK_STEAL_ATTEMPTS.clear()
        values = fixture(
            ipc.AUTHORITY_FACTORY_ID, "private adb scoped watcher")
        lease = values["parent"].begin(
            "authority.read_device_state.v1", {}, operation_deadline(values))
        operation = values["child"].receive_request()
        self.assertEqual(lease.operation_id, "authority.read_device_state.v1")
        private_adb = next(
            item for item in values["retained"]
            if item.identity.capability_id == "private_adb")
        unrelated = tuple(
            item for item in values["retained"]
            if item.identity.capability_id in {"root_reader", "target_process"})
        held, nodes = provider_exception_graph("private adb scoped watcher")
        values["handles"].identity_errors[id(private_adb.handle)] = held

        observe = threading.Event()
        release = threading.Event()
        observations = []
        watcher_errors = []

        def watcher():
            try:
                if not observe.wait(2):
                    raise AssertionError("private_adb provider failure was not observed")
                for node_index, node in enumerate(nodes):
                    trace = RAW_TRACEBACK_SLOT.__get__(node, BaseException)
                    while trace is not None:
                        observations.append((
                            node_index, trace.tb_frame.f_code.co_name,
                            dict(trace.tb_frame.f_locals)))
                        trace = trace.tb_next
            except BaseException as error:
                watcher_errors.append(error)
            finally:
                release.set()

        watcher_thread = threading.Thread(target=watcher)
        watcher_thread.start()

        def trace_private_adb_failure(frame, event, arg):
            if (event == "exception" and len(arg) == 3 and arg[1] is held and
                    frame.f_code.co_name == "_invoke_provider_no_throw"):
                observe.set()
                if not release.wait(2):
                    raise AssertionError("private_adb watcher did not release")
            return trace_private_adb_failure

        caught = None
        previous_trace = sys.gettrace()
        sys.settrace(trace_private_adb_failure)
        try:
            operation.decode_request()
        except BaseException as error:
            caught = error
        finally:
            sys.settrace(previous_trace)
            release.set()
            watcher_thread.join(2)

        self.assertFalse(watcher_thread.is_alive())
        self.assertEqual(watcher_errors, [])
        self.assertTrue(observations)
        forbidden_identities = (
            values["parent"], values["child"], values["owner_handle"],
            values["retained"], SESSION_KEY,
            *(item for item in unrelated),
            *(item.handle for item in unrelated),
        )
        forbidden_strings = frozenset({"root_reader", "target_process"})
        for _node_index, frame_name, frame_values in observations:
            self.assertNotIn(frame_name, {
                "_verify_operation_resources", "_verify_authority_integrity",
                "_verify_authorities", "_dispatch_read_value", "_operation_fail",
                "_abort_active", "_revoke", "call", "cleanup_call",
            })
            self.assertFalse(exact_container_contains(
                frame_values, forbidden_identities, forbidden_strings))
            self.assertNotIn("root", frame_values)
            self.assertNotIn("authority", frame_values)
        self.assertIsNotNone(caught)
        self._assert_sanitized_operation_failure(caught, operation)
        provider_exception_graph_is_scrubbed(self, nodes)
        self.assertEqual(STACK_STEAL_ATTEMPTS, [])
        self.assertIn(values["child"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

    def test_callback_drain_drift_after_barrier_cannot_publish(self):
        values = fixture(session_label="drain drift after barrier")
        lease = values["parent"].begin(
            first_operation(values), {}, operation_deadline(values))
        operation = values["child"].receive_request()
        operation.emit_callback("native_page_event.v1", {"page": 1})
        operation.seal_callbacks()
        sends_before = values["shared"].send_counts["child"]

        def drift_after_proof(challenge):
            if challenge.phase == "child.publish":
                challenge.note_component_mutation("callback_drain")

        values["drain"].post_quiescent_hook = drift_after_proof
        with self.assertRaises(ipc.CapabilityIpcError):
            operation.publish_result({"must": "not publish"})
        self.assertEqual(values["shared"].send_counts["child"], sends_before)
        self.assertIn(values["child"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)

    def test_terminal_round_rejects_post_proof_cross_authority_mutation(self):
        values, lease, _ = self._prepared_result()

        def reactivate_owner(challenge):
            if challenge.phase == "parent.settle":
                values["operation_owner"].active = lease
                challenge.note_component_mutation("operation_owner")

        values["operation_owner"].post_quiescent_hook = reactivate_owner
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertIn(values["parent"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

        values, lease, _ = self._prepared_result()

        def inject_after_transport_proof(challenge):
            if challenge.phase == "parent.settle":
                values["shared"].child_to_parent.append(
                    values["shared"].history[-1][1])
                challenge.note_component_mutation("transport")

        values["shared"].post_quiescent_hook = inject_after_transport_proof
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertIn(values["parent"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

        values, lease, _ = self._prepared_result()
        injected = {"done": False}

        def inject_during_final_binding_verify():
            if (not injected["done"] and values["shared"].sealed and
                    not values["shared"].child_to_parent):
                injected["done"] = True
                values["shared"].child_to_parent.append(
                    values["shared"].history[-1][1])

        values["shared"].verify_hook = inject_during_final_binding_verify
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)
        self.assertTrue(injected["done"])
        self.assertIn(values["parent"].state,
                      {"REVOKED", "QUIESCENCE_UNCERTAIN"})

    def test_callback_drain_proof_is_exact_typed_and_nonreplayable(self):
        values, lease, _ = self._prepared_result()
        reply = values["shared"].child_to_parent[1]
        values["shared"].child_to_parent[1] = resign(
            reply, SESSION_KEY, values["crypto"],
            lambda header: header["body"]["callback_drain_proof"]
            ["receipts"][0].__setitem__("component_generation", True))
        with self.assertRaises(ipc.CapabilityIpcError):
            values["parent"].settle(lease)

        source, _source_lease, _ = self._prepared_result()
        source_reply = ipc.decode_canonical_json(
            source["shared"].child_to_parent[1].frame[4:])
        replayed_proof = source_reply["header"]["body"]["callback_drain_proof"]
        target, target_lease, _ = self._prepared_result()
        target_reply = target["shared"].child_to_parent[1]
        target["shared"].child_to_parent[1] = resign(
            target_reply, SESSION_KEY, target["crypto"],
            lambda header: header["body"].__setitem__(
                "callback_drain_proof", replayed_proof))
        with self.assertRaises(ipc.CapabilityIpcError):
            target["parent"].settle(target_lease)

    @staticmethod
    def _capture(target, function):
        try:
            function()
        except BaseException as error:
            target.append(error)


if __name__ == "__main__":
    unittest.main()
