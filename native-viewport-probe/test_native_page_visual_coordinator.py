"""S8 offline composition: real frozen runner, S0, S4, S5 and S5b over fakes.

No device or process launch. The only reference read at import is the exact
reviewed observer fixture used by the frozen runner's existing fake suite.
"""
from dataclasses import replace
import copy
import hashlib
import threading
import sys
import unittest
from unittest.mock import patch

import native_page_visual_coordinator as v
import native_page_coordinator_contracts as c
import native_page_cleanup_ledger as ledger
from native_page_cleanup_store import WindowsCleanupStore
import native_page_graph_v2_runner as runner
import native_page_pen_peer as pen
import test_native_page_graph_v2_runner as rf
from test_native_page_cleanup_store import FakeWin32


BOOT = "11111111-2222-4333-8444-555555555555"
CLOCK = "coordinator-host-clock-0001"
SESSION = "a" * 64
HOST = "host-session-v2:0001"
TOKEN = "b" * 64


def sha(value): return hashlib.sha256(value.encode()).hexdigest()
def wire(kind, key, incarnation="incarnation-0001"):
    return c.ResourceIdentity(kind, c.AUTHORIZED_SERIAL, key, incarnation).wire()


class PenTransport:
    peer_identity = pen.ProcessIdentity(2599, 6999999)
    def __init__(self, h): self.h, self.sequence, self.now, self.retained = h, 0, 10000, []
    def exchange(self, command):
        operation, *parts = command.decode().strip().split()
        self.h.edge("pen_" + operation.lower())
        fields = dict(part.split("=", 1) for part in parts)
        self.sequence += 1; self.now += 1
        kind = dict(ACQUIRE="ACQUIRED", CAPTURE="CAPTURED", FINISH="RELEASED")[operation]
        proof = fields.get("before_absence_proof", fields.get("final_absence_proof", "0" * 64))
        closed = "true" if operation == "FINISH" else "false"
        raw = (f"PEN_PAGE_PEER {kind} stage_session={SESSION} sequence={self.sequence} token={TOKEN} "
               "peer_pid=2599 peer_starttime=6999999 worker_pid=2600 worker_starttime=7000001 "
               f"guardian_pid=2601 guardian_starttime=7000002 guardian_session={'e' * 64} "
               "deviceClockDomain=android-boottime-v1 deadline_boottime_ms=60000 "
               f"device_boottime_ms={self.now} proof_sha256={proof} worker_closed={closed} guardian_closed={closed}\n").encode()
        return self.h.pen_mutate(raw)
    def wait_exact_peer_closed(self):
        self.h.edge("pen_peer_closed")
        return pen.ClosureProof(self.peer_identity, 0, True, b"")
    def retain_quarantine(self, command): self.retained.append(command)


class Resource:
    """Owner-side fake handle; absence comes from lifecycle state, not captures."""
    BINDING_SLOT = "value"
    def __init__(self, h, binding, absent): self.h, self.value, self.absent = h, binding, absent
    def verify(self):
        if self.h.resource_drift == self.value.role: raise OSError("retained resource drift")
    def binding(self): return self.value
    def prove_absent(self, request, deadline_ns):
        self.verify()
        if not self.absent(): raise OSError("owner exact resource is still alive")
        result = v.ResourceClosure(self.value, hashlib.sha256(request).hexdigest(), self.h.ns,
                                   True, True, True, sha("owner join:" + self.value.identity.key))
        if self.h.closure_mutator: result = self.h.closure_mutator(result)
        return result


class Port:
    RESOURCE_INVENTORY_SLOT="resources"
    def __init__(self, h, role): self.h, self.role, self.resources = h, role, ()
    def verify(self):
        if self.h.drift == self.role: raise OSError("retained authority lost")
    def canonical_bytes(self): return c.canonical_bytes({"retained": self.role})
    def retained_resources(self): return self.resources
    def stage_evidence(self, context, deadline_ns):
        self.verify()
        value = copy.deepcopy(self.h.owner_views[self.role])
        if self.h.owner_view_mutator: value = self.h.owner_view_mutator(self.role, value, context.stage_index)
        return c.canonical_bytes(value)
    def perform(self, operation, raw, deadline_ns):
        request = c.load_canonical(raw)
        self.h.deadlines.append((operation.value, deadline_ns, self.h.ns))
        self.h.edge(request["commandId"])
        body = self.h.body(operation, request["request"])
        mutator = self.h.mutators.get(operation)
        if mutator: body = mutator(copy.deepcopy(body))
        response = dict(authority=v.RECEIPT_AUTHORITY, requestSha256=hashlib.sha256(raw).hexdigest(),
            runSessionId=SESSION, commandId=request["commandId"], observedHostNs=str(self.h.ns), body=body)
        if self.h.envelope_mutator: response = self.h.envelope_mutator(response)
        result = c.canonical_bytes(response)
        self.h.completed_owner_operations.add(operation)
        return self.h.raw_mutate(result)


class CreationOwner:
    """Separate fake acquisition authority surviving coordinator loss.

    Its acquired handles are not supplied by the factory. Publication is part
    of this owner's materialization protocol, before it exposes the bundle.
    Actual production durability/kill-on-close remains an admission blocker.
    """
    def __init__(self,h):
        self.h,self.contexts,self.bundles=h,h.factory.contexts,h.factory.bundles
        self.window_raw=self.publish=self.receipt=None
        self.windows=set();self.acquired=();self.state="new"
    def verify(self):
        if self.h.drift=="creation_owner":raise OSError("independent owner authority lost")
    def canonical_bytes(self):return c.canonical_bytes(dict(retained="creation_owner",ownerInstance=SESSION,
        protocol="rtl-reader-stage-creation-owner-v1",lifetime="independent-durable-owner-v1"))
    def open_window(self,raw,publish,deadline):
        window=c.load_canonical(raw);v._creation_window(window,self.h.contract.value)
        if window["transactionId"] in self.windows or deadline!=int(window["absoluteDeadlineNs"]):raise OSError("window replay/rebase")
        if self.state not in ("new","published"):raise OSError("prior creation unresolved")
        if self.acquired and not all(handle.absent() is True for handle in self.acquired):raise OSError("prior owner acquisitions still live")
        self.windows.add(window["transactionId"]);self.window_raw=raw;self.publish=publish;self.receipt=None;self.state="armed"
        return c.canonical_bytes(dict(authority="rtl-reader-stage-creation-owner-window-v1",transactionId=window["transactionId"],
            windowSha256=c.digest(window),recoveryOwnerSha256=window["recoveryOwnerSha256"],
            lifetime="independent-durable-owner-v1",state="armed-unmaterialized"))
    def authenticate_materialization(self,window,receipt,deadline):
        if (self.state!="acquired" or not self.acquired or window!=self.window_raw or receipt!=self.receipt or
            deadline!=int(c.load_canonical(window)["absoluteDeadlineNs"])):raise OSError("not an actual current owner acquisition")
        for handle,check in self.acquisition_checks:check()
    def materialize(self, context, deadline_ns):
        if self.state!="armed":raise OSError("unarmed materialization")
        window=c.load_canonical(self.window_raw)
        if window["contextSha256"]!=v.context_sha256(context) or int(window["absoluteDeadlineNs"])!=deadline_ns:
            raise OSError("creation context differs")
        self.h.edge("prepare_" + str(context.stage_index)); self.contexts.append(context)
        binding = context.binding
        value = rf.manifest_value(binding, mark=self.h.mark)
        value["externalSession"].update(taskId=41, displayId=7, hostSessionId=HOST, displayGeneration=9)
        if self.h.manifest_mutator: value = self.h.manifest_mutator(value, context.stage_index)
        manifest = runner.load_canonical(runner.canonical_bytes(value), runner.MAX_MANIFEST_BYTES)
        bundle = rf.FakeBundle(); tool = runner.load_canonical(bundle.canonical_bytes(), runner.MAX_AUTHORITY_BYTES)
        before, after = (rf.stage_value(manifest, binding, tool.sha256, phase) for phase in ("before", "after"))
        for record in (before, after):
            record["host"].update(hostPackageName=c.HOST_PACKAGE,
                requestedFrame=list(c.STAGE_LAYOUTS[context.stage_index][5]),
                measuredGlobalFrame=list(c.STAGE_LAYOUTS[context.stage_index][5]))
            record["penLease"]["leaseId"] = TOKEN
            record["frida"]["serverPid"] += context.stage_index
            record["frida"]["serverStartTimeTicks"] = str(8000001 + context.stage_index)
            epoch = v.stage_epoch(context)
            record["providerSessionId"] = epoch["providerSessionId"]
            record["frida"].update(providerSessionId=epoch["providerSessionId"], serverSessionId=epoch["serverSessionId"],
                serverPath=epoch["stagingPath"], serverCmdline=epoch["stagingPath"],
                teardownOfSessionId=None if record["phase"] == "before" else epoch["serverSessionId"])
        selected_task = rf.task()
        # Independent retained owners use the unmodified expected fixture, not
        # the selected provider's mutable output or factory declarations.
        owner_files = rf.manifest_value(binding, mark=self.h.mark)["files"]
        self.h.owner_views = {
            "reader": {**{name:copy.deepcopy(before[name]) for name in ("privateAdbServer", "target", "firmware")},
                "files":owner_files, "fixtures":self.h.contract.value["fixtures"], "observerSha256":rf.OBSERVER_SHA},
            "host":dict(host=copy.deepcopy(before["host"]), display=self.h.display, hostSessionId=HOST),
            "supervisor":dict(foreign=self.h.foreign, task=c.load_canonical(selected_task.canonical_bytes())),
            "reopen":dict(ordinaryRouteAuthoritySha256=hashlib.sha256(self.h.ports["reopen"].canonical_bytes()).hexdigest())}
        selection_sha = c.digest(v.selection_authority(context,manifest.sha256))
        for role in ("reader","supervisor"): self.h.owner_views[role]["selectionAuthoritySha256"] = selection_sha
        if self.h.record_mutator:
            before, after, selected_task = self.h.record_mutator(before, after, selected_task, context.stage_index)
        admission = rf.admission_value(); admission["providerSessionId"] = epoch["providerSessionId"]
        provider = InventoryAuthority(before, after, selected_task=selected_task, admission=admission)
        frida = InventoryFrida(manifest)
        if self.h.snapshot_mutator:
            snapshot = self.h.snapshot_mutator(rf.snapshot_value(manifest), context.stage_index)
            frida = InventoryFrida(manifest, rf.success_frames(manifest, snapshot))
        if self.h.frida_fault: self.h.frida_fault(frida)
        frida_admission = rf.frida_admission_value(); frida_admission["providerSessionId"] = epoch["providerSessionId"]
        frida.admission_record = rf.wrapped(frida_admission)
        pins = runner.TrustedPins(tool.sha256, manifest.sha256, provider.admission_record.sha256,
            frida.admission_record.sha256, runner.stage_policy_sha256(before), rf.RECEIPT_KEY)
        resources = tuple(c.ResourceBinding(role, "isolated_ipc", c.ResourceIdentity("process", "windows-host/" + BOOT,
            str(5000 + context.stage_index * 2 + offset), BOOT + ":" + str(9000 + context.stage_index * 2 + offset)))
            for offset, role in enumerate(("authority_worker", "frida_worker")))
        server = c.ResourceBinding("root_frida_server", "mutating_private_adb", c.ResourceIdentity("process", c.AUTHORIZED_SERIAL,
            str(2718 + context.stage_index), BOOT + ":" + str(8000001 + context.stage_index)))
        authority_handle = Resource(self.h, resources[0], lambda:provider.fail_stopped)
        frida_handle = Resource(self.h, resources[1], lambda:frida.terminal)
        server_handle = Resource(self.h, server, lambda:frida.terminal)
        provider.inventory=(authority_handle,)
        frida.inventory=(frida_handle,server_handle)
        provider.retained_resources = lambda:provider.inventory
        frida.retained_resources = lambda:frida.inventory
        provider.verify_retained = lambda ctx:authority_handle.verify()
        frida.verify_retained = lambda ctx:(frida_handle.verify(), server_handle.verify())[-1]
        provider.predispatch = lambda ctx, deadline:v.PredispatchView(v.context_sha256(ctx), deadline,
                                                                      rf.wrapped(provider.before), provider.task)
        selected_frida = copy.deepcopy(before["frida"])
        selected_frida.update(serverPid=int(server.identity.key), serverStartTimeTicks=server.identity.incarnation.split(":")[1])
        def frida_predispatch(ctx, deadline):
            value = dict(contextSha256=v.context_sha256(ctx), deadlineNs=str(deadline), frida=selected_frida,
                epoch=v.stage_epoch(ctx), forbiddenOwnersSha256=hashlib.sha256(ctx.forbidden_owners_raw).hexdigest(),
                exclusionAppliedBeforeAttach=True)
            if self.h.frida_view_mutator: value=self.h.frida_view_mutator(value, ctx.stage_index)
            return c.canonical_bytes(value)
        frida.predispatch = frida_predispatch
        transitions = {}
        for item in (*resources, server):
            prior = None if context.stage_index == 0 else self.h.coordinator._identities[item.role+":"+str(context.stage_index-1)].identity.wire()
            transitions[item.role] = dict(previous=prior, current=item.identity.wire(),
                predecessorClosure=None if context.stage_index == 0 else c.load_canonical(context.previous_stage_closures_raw)[item.role],
                epoch=epoch["epoch"], contextSha256=v.context_sha256(context), retainedSuccessorOpen=True)
        if self.h.resources_mutator: resources=self.h.resources_mutator(resources, context.stage_index)
        if self.h.transitions_mutator: transitions=self.h.transitions_mutator(transitions, context.stage_index)
        result = v.StageBundle(manifest, rf.OBSERVER_TEXT, rf.OBSERVER_SHA, bundle, provider, frida, pins, resources,
                               c.canonical_bytes(transitions))
        self.acquired=(authority_handle,frida_handle,server_handle)
        self.acquisition_checks=tuple((handle,v._resource_slot(handle)[1]) for handle in self.acquired)
        self.receipt=c.canonical_bytes(dict(authority="rtl-reader-stage-owner-materialization-v1",schemaVersion=1,
            transactionId=window["transactionId"],windowSha256=c.digest(window),recoveryOwnerSha256=window["recoveryOwnerSha256"],
            contextSha256=window["contextSha256"],absoluteDeadlineNs=window["absoluteDeadlineNs"],
            acquisitionState="acquired-retained-unexposed",ownerSequence=context.stage_index+1,
            batches=[dict(owner="stage_authority",bindings=[v._binding_wire(authority_handle.value)]),
                     dict(owner="stage_frida",bindings=[v._binding_wire(frida_handle.value),v._binding_wire(server_handle.value)])]))
        self.state="acquired"
        if self.h.before_materialization_publish:self.h.before_materialization_publish()
        self.publish(self.receipt)
        self.state="published"
        self.bundles.append(result)
        return result


class Factory:
    def __init__(self,h):self.h,self.contexts,self.bundles=h,[],[]
    def verify(self):
        if self.h.drift=="stages":raise OSError("factory authority lost")
    def canonical_bytes(self):return c.canonical_bytes({"retained":"stages"})
    def prepare(self,context,deadline_ns):return self.h.creation_owner.materialize(context,deadline_ns)


class InventoryAuthority(rf.FakeAuthorityProvider):
    RESOURCE_INVENTORY_SLOT="inventory"


class InventoryFrida(rf.FakeFrida):
    RESOURCE_INVENTORY_SLOT="inventory"


class Harness:
    def __init__(self, *, stock=True, mark=True, run_stage=None):
        self.ns, self.count, self.mark = 1_000_000_000, 0, mark
        self.log, self.deadlines = [], []
        self.fail, self.crash, self.drift = None, None, None
        self.delays, self.mutators = {}, {}
        self.manifest_mutator = self.snapshot_mutator = self.envelope_mutator = None
        self.frida_fault = None
        self.record_mutator = self.owner_view_mutator = self.resources_mutator = None
        self.frida_view_mutator = self.transitions_mutator = self.closure_mutator = None
        self.resource_drift = None
        self.before_materialization_publish=None
        self.completed_owner_operations = set()
        self.owner_resources, self.owner_views = {}, {}
        self.raw_mutate = self.pen_mutate = lambda raw: raw
        self.hook = None
        self.clock_reads, self.clock_fault = [], None
        self.stock = dict(identity=wire("process", "3141", BOOT + ":9000001"), package=c.PACKAGE_NAME, uid=1000)
        self.initial_stock = copy.deepcopy(self.stock) if stock else None
        self.display = dict(identity=wire("virtual_display", "7", HOST + ":9"),
            displayId=7, generation=9, hostSessionId=HOST)
        self.foreign = dict(identity=wire("android_task", "41", HOST + ":9:def:" + c.digest(self.stock)),
            process=self.stock, taskId=41, activityToken="def", component=c.COMPONENT, display=self.display)
        fixture = dict(pdf=dict(identity=wire("file", "graph-v2.pdf"), sha256="2" * 64, size=4096),
            mark=dict(identity=wire("file", "graph-v2.pdf.mark"), sha256="4" * 64, size=512) if mark else None,
            savedInkSha256=sha("SavedInk"), uriResolutionSha256=c.digest({
                "authority":"rtl-reader-file-uri-resolution-v1", "documentUri":"file:///storage/emulated/0/Document/graph-v2.pdf",
                "resolvedPath":"/storage/emulated/0/Document/graph-v2.pdf", "evidenceSha256":"3" * 64}))
        self.contract = c.RunContract.create(run_session_id=SESSION, host_session_id=HOST,
            created=c.HostInstant(CLOCK, self.ns), deadline=c.HostInstant(CLOCK, 20_000_000_000), fixtures=fixture)
        self.selection = v.Selection("file:///storage/emulated/0/Document/graph-v2.pdf", 2)
        self.api = FakeWin32()
        # Chunking has its own S5 suite; keep S8's exhaustive state/fault matrix
        # focused on real publication barriers without thousands of tiny writes.
        self.api.chunk = 65536
        self.journal = WindowsCleanupStore.create_new(r"C:\sandbox\events", r"C:\authority\events", api=self.api)
        self.ownership = WindowsCleanupStore.create_new(r"C:\sandbox\owned", r"C:\authority\owned", api=self.api)
        self.transport = PenTransport(self)
        self.peer = pen.PenPeer(self.transport, pen.StageSession(SESSION), TOKEN, 50000)
        self.factory = Factory(self)
        self.creation_owner=CreationOwner(self)
        self.ports = {role: Port(self, role) for role in ("reader", "host", "supervisor", "reopen")}
        pins = {role: hashlib.sha256(port.canonical_bytes()).hexdigest() for role, port in self.ports.items()}
        pins["stages"] = hashlib.sha256(self.factory.canonical_bytes()).hexdigest()
        self.deps = v.Dependencies(self.ports["reader"], self.ports["host"], self.ports["supervisor"],
            self.ports["reopen"], self.factory, self.peer, self.read_clock, self.nonce,
            c.ResourceBinding("private_adb_server", "private_adb", c.ResourceIdentity("process", "windows-host/" + BOOT,
                "2222", BOOT + ":133700000000000000")), self.run_stage if run_stage is None else run_stage,
                self.creation_owner,hashlib.sha256(self.creation_owner.canonical_bytes()).hexdigest())
        def owned(role, identity, done):
            return Resource(self,c.ResourceBinding(role,c.RESOURCE_OWNERS[role][1],c.ResourceIdentity.parse(identity)),
                            lambda:done in self.completed_owner_operations)
        self.owner_resources = {
            "reader":(Resource(self,self.deps.private_adb_resource,lambda:v.Operation.CLOSE_PRIVATE_ADB in self.completed_owner_operations),),
            "host":(owned("host_session",wire("host_session",HOST,SESSION),v.Operation.RELEASE_DISPLAY),
                    owned("virtual_display",self.display["identity"],v.Operation.RELEASE_DISPLAY)),
            "supervisor":(owned("foreign_task",self.foreign["identity"],v.Operation.DESTROY_TASK),)}
        self.ports["reader"].resources=self.owner_resources["reader"]
        self.ports["host"].resources=self.owner_resources["host"][:1]
        self._coordinator, self._pins = None, pins

    @property
    def coordinator(self):
        # Test seams are installed before this construction boundary. Changes
        # to retained dependencies/methods after it are deliberately hostile.
        if self._coordinator is None:
            self._coordinator = v.VisualCoordinator(self.contract,self.selection,self.deps,
                self.journal,self.ownership,self._pins)
        return self._coordinator

    def read_clock(self):
        self.clock_reads.append(self.ns)
        return c.HostInstant(CLOCK,self.ns) if self.clock_fault is None else self.clock_fault

    def nonce(self):
        self.count += 1
        return sha("unique-challenge-" + str(self.count))

    def edge(self, label):
        self.log.append(label)
        if self.hook: self.hook(label)
        self.ns += 1 + self.delays.get(label, 0)
        if self.fail == label: raise OSError("injected failure: " + label)
        if self.crash == label: raise KeyboardInterrupt("power boundary: " + label)

    def run_stage(self, **kwargs):
        self.edge("run_" + str(len(self.factory.contexts) - 1))
        return runner.run_one_stage(**kwargs)

    def body(self, operation, request):
        o = v.Operation
        if operation is o.PREFLIGHT:
            return dict(target=self.contract.value["target"], bootId=BOOT, selection=self.selection.wire(),
                prechecked=dict(serial=c.AUTHORIZED_SERIAL, documentTasks=[], documentActivities=[],
                    stockProcess=self.initial_stock, evidenceSha256=sha("before absence"), fixtures=self.contract.value["fixtures"]))
        if operation is o.HOST_START:
            self.ports["host"].resources=self.owner_resources["host"]
            return dict(display=self.display,evidenceSha256=sha("display-ready"),
                        ownerInventory=[v._binding_wire(item.value) for item in self.ports["host"].resources])
        if operation is o.PRELAUNCH: return dict(documentTasks=[], documentActivities=[], evidenceSha256=sha("prelaunch"))
        if operation is o.LAUNCH:
            self.launch_sha = c.digest(request)
            return {"launchCommandSha256": self.launch_sha}
        if operation is o.ATTACH:
            self.ports["supervisor"].resources=self.owner_resources["supervisor"]
            return dict(foreign=self.foreign, launchCommandSha256=self.launch_sha,
                causalLaunchProofSha256=sha("causal launch"), hostAttachAckSha256=sha("host attach"),
                documentTasks=[self.foreign["identity"]], documentActivities=["def"],
                displayZeroDocumentTasks=[], displayZeroDocumentActivities=[], prelaunchAbsenceSha256=sha("prelaunch"),
                ownerInventory=[v._binding_wire(item.value) for item in self.ports["supervisor"].resources])
        if operation is o.PLACE:
            return dict(stage=request["stage"], foreign=self.foreign, evidenceSha256=sha(request["stage"]["commandId"]))
        if operation is o.EXACT_TASK: return dict(status="present", foreign=self.foreign)
        if operation is o.RESTORE: return dict(foreign=self.foreign, placement="FULL", performed=True)
        if operation is o.DESTROY_TASK: return dict(foreign=self.foreign, exactTaskAbsent=True)
        if operation is o.TASK_ABSENT:
            return dict(foreign=self.foreign, display=self.display, exactTaskAbsent=True,
                        hostAcknowledgedAbsent=True, noMigrationToDisplayZero=True)
        if operation is o.RELEASE_DISPLAY:
            return dict(display=self.display, exactDisplayAbsent=True, hostSessionQuiescent=True, noMigrationToDisplayZero=True)
        if operation is o.FINAL_ABSENCE:
            return dict(stockProcess=self.stock, documentTasks=[], documentActivities=[], foreignDisplayAbsent=True,
                        foreignSurfaceAbsent=True, foreignHelpersClosed=True)
        if operation is o.REACQUIRE:
            return dict(independentDeviceReacquireProven=True, testGrabClosed=True, penBinding=request["penBinding"])
        if operation is o.REOPEN:
            return dict(component=c.COMPONENT, displayId=0, process=self.stock, fixtureSha256="2" * 64,
                        ordinaryRouteAuthoritySha256=hashlib.sha256(self.ports["reopen"].canonical_bytes()).hexdigest())
        if operation is o.UNCHANGED: return self.contract.value["fixtures"]
        if operation is o.CLOSE_PRIVATE_ADB:
            return dict(identity=request["identity"], exactServerAbsent=True, clientsClosed=True, listenerAbsent=True)
        raise AssertionError(operation)

    def run(self): return c.load_canonical(self.coordinator.run_diagnostic())

    def declare_direct(self,*roles):
        """Construction-only complete inventories for isolated helper tests."""
        co=self.coordinator
        for name,available in self.owner_resources.items():
            selected=tuple(item for item in available if item.value.role in roles)
            if selected:
                co._begin_inventory_creation(self.ports[name],None)
                self.ports[name].resources=selected
                co._observe_inventory(self.ports[name],tuple(item.value for item in selected))


class CoordinatorTests(unittest.TestCase):
    def _pending_schema_cases(self):
        # Independent wire examples, not constructed with the production codec.
        # The supplied record maps stand for prefixes already authenticated by
        # the two store replayers; these tests exercise the output codec only.
        def binding(role,key,start=9000001):
            kind,owner=c.RESOURCE_OWNERS[role]
            return dict(role=role,owner=owner,identity=wire(kind,key,BOOT+":"+str(start)))
        host=binding("host_session",HOST);display=binding("virtual_display","7")
        adb=binding("private_adb_server","2222");authority=binding("authority_worker","5000")
        frida=binding("frida_worker","5001");server=binding("root_frida_server","2718")
        rows=[]
        def record(label,event,data):
            value=dict(hash=sha(label),event=event,data=data);rows.append(value);return value
        intent=record("pending-intent","s8_intent",dict(operation=v.Operation.HOST_START.value))
        expected=[dict(owner="stage_authority",roles=["authority_worker"]),dict(owner="stage_frida",roles=["frida_worker","root_frida_server"])]
        window=record("pending-window","s8_creation_window",dict(window=dict(expectedBatches=expected)))
        result=record("pending-result","s8_result",dict(operation=v.Operation.HOST_START.value,receipt=dict(body=dict(ownerInventory=[host,display]))))
        stage_batches=[dict(owner="stage_authority",bindings=[authority]),dict(owner="stage_frida",bindings=[frida,server])]
        materialized=record("pending-materialized","s8_creation_materialized",dict(receipt=dict(batches=stage_batches)))
        baseline=record("pending-baseline","s8_inventory_batch",dict(owner="reader",bindings=[adb],sourceRecordSha256=None))
        batch=record("pending-stage-batch","s8_inventory_batch",dict(owner="stage_frida",bindings=[frida,server],sourceRecordSha256=materialized["hash"]))
        registration=dict(hash=sha("pending-S5-registered"),event="registered",data=dict(owner=server["owner"],identity=server["identity"]))
        context=v._pending_inventory_context(rows,[registration])
        common=dict(owner="stage_creation_owner",state="materialized_pending",bindings=[authority,frida,server],
            unresolvedHandleCount=0,ownershipComplete=False,cleanupAuthority=False,sourceRecordSha256=materialized["hash"],
            inventoryRecordSha256=None,ownershipRecordSha256=None,ownershipIdentity=None,joinStatus="not_applicable",
            expectedRoles=[],expectedBatches=[],reportedEvidenceSha256=None)
        def item(**changes):value=copy.deepcopy(common);value.update(changes);return value
        cases=[item(owner="host",state="creation_result_missing",bindings=[],unresolvedHandleCount=1,
                    sourceRecordSha256=intent["hash"],expectedRoles=["virtual_display"]),
            item(state="creation_window_unmaterialized",bindings=[],unresolvedHandleCount=3,sourceRecordSha256=window["hash"],expectedBatches=expected),
            item(owner="host",state="creation_result_pending",bindings=[host,display],sourceRecordSha256=result["hash"]),
            item(),item(state="batch_registration_pending"),
            item(owner="reader",state="batch_registration_pending",bindings=[adb],sourceRecordSha256=None,inventoryRecordSha256=baseline["hash"]),
            item(state="registered_pending_closure",ownershipComplete=True),item(state="stage_retirement_pending",ownershipComplete=True),
            item(owner=server["owner"],state="ledger_registration_unlinked",bindings=[server],inventoryRecordSha256=batch["hash"],
                 ownershipRecordSha256=registration["hash"],ownershipIdentity=server["identity"],joinStatus="unique"),
            item(owner="coordinator",state="rejected_inventory_unresolved",bindings=[],unresolvedHandleCount=2,
                 sourceRecordSha256=None,reportedEvidenceSha256=sha("rejected observations"))]
        return cases,context,rows,registration

    def test_pending_inventory_closed_union_and_field_domains(self):
        cases,context,_,registration=self._pending_schema_cases()
        keys=set("owner state bindings unresolvedHandleCount ownershipComplete cleanupAuthority sourceRecordSha256 "
            "inventoryRecordSha256 ownershipRecordSha256 ownershipIdentity joinStatus expectedRoles expectedBatches reportedEvidenceSha256".split())
        self.assertEqual({value["state"] for value in cases},set(v.PENDING_INVENTORY_STATES))
        for original in cases:
            self.assertEqual(set(original),keys);v._validate_pending_inventory(original,context)
            mutations=[dict(original,unknown=True)]
            for key in keys:
                removed=copy.deepcopy(original);removed.pop(key);mutations.append(removed)
            for key,value in dict(owner=False,state="future_state",bindings=None,unresolvedHandleCount=True,
                ownershipComplete=1,cleanupAuthority=0,sourceRecordSha256=registration["hash"],
                inventoryRecordSha256=registration["hash"],ownershipRecordSha256=next(iter(context[0])),
                ownershipIdentity=[],joinStatus="first_match",expectedRoles=["root_frida_server"],expectedBatches=[{}],
                reportedEvidenceSha256="invalid").items():
                changed=copy.deepcopy(original);changed[key]=value;mutations.append(changed)
            if original["bindings"]:
                for key in ("role","owner","identity"):
                    changed=copy.deepcopy(original);changed["bindings"][0].pop(key);mutations.append(changed)
                changed=copy.deepcopy(original);changed["bindings"][0]["unknown"]=True;mutations.append(changed)
            for index,changed in enumerate(mutations):
                with self.subTest(state=original["state"],mutation=index),self.assertRaises((v.CoordinatorError,c.ContractError)):
                    v._validate_pending_inventory(changed,context)

    def test_pending_inventory_unique_absent_ambiguous_joins_and_hash_swaps(self):
        cases,context,rows,registration=self._pending_schema_cases()
        original=next(value for value in cases if value["state"]=="ledger_registration_unlinked")
        for target,replacement in (("ownershipRecordSha256",original["sourceRecordSha256"]),
                                   ("ownershipRecordSha256",original["inventoryRecordSha256"]),
                                   ("sourceRecordSha256",original["ownershipRecordSha256"]),
                                   ("inventoryRecordSha256",original["ownershipRecordSha256"]),
                                   ("sourceRecordSha256",original["inventoryRecordSha256"])):
            changed=copy.deepcopy(original);changed[target]=replacement
            with self.subTest(field=target,replacement=replacement),self.assertRaises(v.CoordinatorError):
                v._validate_pending_inventory(changed,context)
        for attack in ("absent","wrong_owner","wrong_incarnation","ambiguous","rejected_only"):
            copied=copy.deepcopy(rows)
            batch=next(record for record in copied if record["hash"]==original["inventoryRecordSha256"])
            if attack in ("absent","rejected_only"):batch["data"]["bindings"]=batch["data"]["bindings"][:1]
            if attack=="wrong_owner":batch["data"]["bindings"][1]["owner"]="isolated_ipc"
            if attack=="wrong_incarnation":batch["data"]["bindings"][1]["identity"]["incarnation"]=BOOT+":1"
            if attack=="ambiguous":
                duplicate=copy.deepcopy(batch);duplicate["hash"]=sha("second independently named candidate");copied.append(duplicate)
            if attack=="rejected_only":copied.append(dict(hash=sha("rejected-not-authority"),event="s8_quarantine",data=dict(
                pendingInventoryBatches=[dict(bindings=original["bindings"])])))
            changed_context=v._pending_inventory_context(copied,[registration])
            changed=copy.deepcopy(original);changed.update(bindings=[],sourceRecordSha256=None,inventoryRecordSha256=None,
                unresolvedHandleCount=1,joinStatus="ambiguous" if attack=="ambiguous" else "absent")
            v._validate_pending_inventory(changed,changed_context)
            self.assertFalse(changed["cleanupAuthority"])
            with self.assertRaises(v.CoordinatorError):v._validate_pending_inventory(original,changed_context)
        # A later complete host inventory legitimately repeats its already
        # registered session. It is not a new registration-origin candidate.
        first=dict(hash=sha("host-first"),event="s8_inventory_batch",data=dict(owner="host",bindings=original["bindings"],sourceRecordSha256=None))
        known=original["bindings"][0]
        owned=dict(hash=sha("host-linked"),event="s8_owned",data=dict(role=known["role"],owner=known["owner"],identity=known["identity"]))
        repeated=copy.deepcopy(first);repeated["hash"]=sha("host-repeated")
        candidate_context=v._pending_inventory_context([first,owned,repeated],[registration])
        self.assertEqual(len(candidate_context[2]),1)
        # Two different roles sharing the exact S5 owner/identity are ambiguous,
        # even when both roles are individually valid contract names.
        identity=wire("process","5010",BOOT+":99")
        candidates=[]
        for index,role in enumerate(("authority_worker","frida_worker")):
            binding=dict(role=role,owner="isolated_ipc",identity=identity)
            record=dict(hash=sha("role-candidate-"+str(index)),data=dict(sourceRecordSha256=None))
            candidates.append((record,binding))
        self.assertEqual(v._pending_registration_join("isolated_ipc",identity,candidates),("ambiguous",None,None,[]))

    def _lost_process(self,h,saved):
        self.assertIn("api",saved,"process-loss boundary was not reached")
        api=saved["api"];api.crash()
        events=WindowsCleanupStore.open_existing(h.journal.authority,api=api)
        owned=WindowsCleanupStore.open_existing(h.ownership.authority,api=api)
        journal=v.EventJournal(events,h.contract,h.selection,recover=True)
        self.assertNotIn("s8_quarantine",[record["event"] for record in journal.records],
                         "probe accidentally relied on the live exception handler")
        result=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,events,owned,h.deps.clock))
        self.assertEqual(result["status"],"RETAINED_QUARANTINE")
        self.assertTrue(result["recoveryRequired"])
        point=owned.load_checkpoint()
        with owned.exclusive():prefix=v._ownership_prefix(owned.read,point)
        context=v._pending_inventory_context(journal.records,prefix)
        for item in result["pendingInventoryBatches"]:
            self.assertEqual(set(item),set("owner state bindings unresolvedHandleCount ownershipComplete cleanupAuthority "
                "sourceRecordSha256 inventoryRecordSha256 ownershipRecordSha256 ownershipIdentity joinStatus "
                "expectedRoles expectedBatches reportedEvidenceSha256".split()))
            self.assertIsInstance(item["bindings"],list)
            v._validate_pending_inventory(item,context)
        return result,journal,owned

    def test_creation_true_process_loss_durable_host_result(self):
        h=Harness();saved={};append=v.EventJournal.append
        def cut(owner,event,data,remaining):
            result=append(owner,event,data,remaining)
            if event=="s8_result" and data["operation"]==v.Operation.HOST_START.value:
                saved["api"]=h.api.clone();raise OSError("process lost after durable host result")
            return result
        with patch.object(v.EventJournal,"append",cut):
            with self.assertRaises(v.RetainedQuarantine):h.run()
        result,journal,_=self._lost_process(h,saved)
        pending=result["pendingInventoryBatches"]
        self.assertTrue(any(value["state"]=="creation_result_pending" and
            h.display["identity"] in [binding["identity"] for binding in value["bindings"]] for value in pending))
        self.assertNotIn("virtual_display",[r["data"]["role"] for r in journal.records if r["event"]=="s8_owned"])

    def test_creation_true_process_loss_all_publication_and_registration_edges(self):
        cases=[("port_return",v.Operation.HOST_START.value),("port_return",v.Operation.ATTACH.value),
               ("result",v.Operation.ATTACH.value),
               ("batch","host"),("batch","supervisor"),("batch","stage_authority"),("batch","stage_frida"),
               ("owned","virtual_display"),("owned","foreign_task"),("owned","authority_worker"),
               ("owned","frida_worker"),("owned","root_frida_server"),
               ("ledger","virtual_display"),("ledger","foreign_task"),("ledger","authority_worker"),
               ("ledger","frida_worker"),("ledger","root_frida_server"),
               ("before_register","authority_worker"),("before_register","frida_worker"),("before_register","root_frida_server"),
               ("materialized",None),("return",None),("window",None)]
        for kind,target in cases:
            with self.subTest(kind=kind,target=target):
                h=Harness();saved={};append=v.EventJournal.append;register=ledger.CleanupLedger.register
                def loss():saved["api"]=h.api.clone();raise OSError("true process-loss cut")
                def cut(owner,event,data,remaining):
                    result=append(owner,event,data,remaining)
                    if ((kind=="result" and event=="s8_result" and data["operation"]==target) or
                        (kind=="batch" and event=="s8_inventory_batch" and data["owner"]==target and data["sourceRecordSha256"] is not None) or
                        (kind=="owned" and event=="s8_owned" and data["role"]==target) or
                        (kind=="materialized" and event=="s8_creation_materialized")):loss()
                    return result
                def registered(owner,identity,resource_owner,*args,**kwargs):
                    if kind in ("ledger","before_register"):
                        expected={"virtual_display":h.display["identity"],"foreign_task":h.foreign["identity"]}
                        if h.creation_owner.acquired:
                            expected.update({handle.value.role:handle.value.identity.wire() for handle in h.creation_owner.acquired})
                        if kind=="before_register" and identity.wire()==expected.get(target):loss()
                    result=register(owner,identity,resource_owner,*args,**kwargs)
                    if kind=="ledger":
                        if identity.wire()==expected.get(target):loss()
                    return result
                if kind=="return":
                    prepare=h.factory.prepare
                    def returned(context,deadline):result=prepare(context,deadline);loss();return result
                    h.factory.prepare=returned
                if kind=="window":h.before_materialization_publish=loss
                if kind=="port_return":
                    def raw_return(raw):
                        if c.load_canonical(raw)["commandId"]==target:loss()
                        return raw
                    h.raw_mutate=raw_return
                with patch.object(v.EventJournal,"append",cut),patch.object(ledger.CleanupLedger,"register",registered):
                    with self.assertRaises(v.RetainedQuarantine):h.run()
                result,journal,_=self._lost_process(h,saved)
                pending=result["pendingInventoryBatches"]
                self.assertTrue(pending)
                if kind=="window":
                    window=next(value for value in pending if value["state"]=="creation_window_unmaterialized")
                    self.assertEqual(window["bindings"],[])
                    self.assertEqual([role for batch in window["expectedBatches"] for role in batch["roles"]],
                                     ["authority_worker","frida_worker","root_frida_server"])
                    self.assertNotIn("s8_creation_materialized",[r["event"] for r in journal.records])
                elif h.creation_owner.acquired:
                    identities=[binding["identity"] for value in pending for binding in value["bindings"]]
                    for handle in h.creation_owner.acquired:self.assertIn(handle.value.identity.wire(),identities)
                if kind=="ledger":
                    unlinked=next(value for value in pending if value["state"]=="ledger_registration_unlinked")
                    self.assertEqual(unlinked["joinStatus"],"unique")
                    self.assertEqual([binding["role"] for binding in unlinked["bindings"]],[target])
                    self.assertIsNotNone(unlinked["inventoryRecordSha256"])
                    self.assertNotEqual(unlinked["ownershipRecordSha256"],unlinked["sourceRecordSha256"])
                    self.assertFalse(unlinked["cleanupAuthority"])
                if kind=="port_return":
                    unknown=next(value for value in pending if value["state"]=="creation_result_missing")
                    self.assertEqual(unknown["bindings"],[])
                    self.assertEqual(unknown["expectedRoles"],["virtual_display" if target==v.Operation.HOST_START.value else "foreign_task"])
                self.assertNotIn("run_0",h.log)

    def test_creation_owner_rejects_invented_early_copied_and_replayed_publication(self):
        for attack in ("early","invented","wrong_window","wrong_deadline","wrong_owner","wrong_state","duplicate"):
            with self.subTest(attack=attack):
                h=Harness();prepare=h.factory.prepare;reached=[]
                if attack=="early":
                    def forged(context,deadline):
                        reached.append(True);h.creation_owner.publish(b"{}");return prepare(context,deadline)
                    h.factory.prepare=forged
                elif attack=="duplicate":
                    def repeated(context,deadline):
                        result=prepare(context,deadline);reached.append(True)
                        h.creation_owner.publish(h.creation_owner.receipt);return result
                    h.factory.prepare=repeated
                else:
                    def publication():
                        reached.append(True);value=c.load_canonical(h.creation_owner.receipt)
                        if attack=="invented":value["batches"][1]["bindings"][1]["identity"]["key"]="9999"
                        if attack=="wrong_window":value["transactionId"]="0"*64
                        if attack=="wrong_deadline":value["absoluteDeadlineNs"]=str(int(value["absoluteDeadlineNs"])+1)
                        if attack=="wrong_owner":value["recoveryOwnerSha256"]="0"*64
                        if attack=="wrong_state":value["acquisitionState"]="not-acquired"
                        h.creation_owner.publish(c.canonical_bytes(value))
                    h.before_materialization_publish=publication
                with self.assertRaises(v.RetainedQuarantine):h.run()
                self.assertTrue(reached);self.assertNotIn("run_0",h.log)
                records=h.coordinator._journal.records
                self.assertEqual(sum(record["event"]=="s8_creation_materialized" for record in records),int(attack=="duplicate"))
                self.assertEqual(sum(record["event"]=="s8_creation_window" for record in records),1)
                self.assertFalse(any(record["event"]=="s8_owned" and record["data"]["role"]=="root_frida_server" for record in records))

    def test_creation_live_batch_order_matches_owner_receipt_before_registration(self):
        for role in ("host","stage_frida"):
            with self.subTest(role=role):
                h=Harness();reached=[]
                if role=="host":
                    def returned(raw):
                        if c.load_canonical(raw)["commandId"]==v.Operation.HOST_START.value:
                            reached.append(True);h.ports["host"].resources=tuple(reversed(h.ports["host"].resources))
                        return raw
                    h.raw_mutate=returned
                else:
                    prepare=h.factory.prepare
                    def prepared(context,deadline):
                        result=prepare(context,deadline);reached.append(True)
                        result.frida_provider.inventory=tuple(reversed(result.frida_provider.inventory))
                        return result
                    h.factory.prepare=prepared
                with self.assertRaisesRegex(v.RetainedQuarantine,"ordered creation batch"):h.run()
                self.assertTrue(reached);self.assertNotIn("run_0",h.log)
                rejected_role="virtual_display" if role=="host" else "authority_worker"
                self.assertNotIn(rejected_role,[record["data"]["role"] for record in h.coordinator._journal.records if record["event"]=="s8_owned"])
                self.assertNotIn("root_destroy_exact_task",h.log)
                if h.factory.bundles:
                    self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)
                    self.assertEqual(h.factory.bundles[0].frida_provider.session.load_count,0)

    def test_creation_replay_rejects_batch_registration_and_source_mutations(self):
        h=Harness();saved={};append=v.EventJournal.append
        def cut(owner,event,data,remaining):
            result=append(owner,event,data,remaining)
            if event=="s8_owned" and data["role"]=="root_frida_server":
                saved["api"]=h.api.clone();raise OSError("loss before first lifecycle")
            return result
        with patch.object(v.EventJournal,"append",cut):
            with self.assertRaises(v.RetainedQuarantine):h.run()
        _,journal,store=self._lost_process(h,saved)
        checkpoint=store.load_checkpoint()
        with store.exclusive():prefix=v._ownership_prefix(store.read,checkpoint)
        records=journal.records
        batch_index=[index for index,record in enumerate(records) if record["event"]=="s8_inventory_batch" and
                     record["data"]["owner"] in ("stage_authority","stage_frida")]
        materialized=next(index for index,record in enumerate(records) if record["event"]=="s8_creation_materialized")
        owned_index=[index for index,record in enumerate(records) if record["event"]=="s8_owned" and
                     record["data"]["role"] in ("authority_worker","frida_worker","root_frida_server")]
        result_index=[index for index,record in enumerate(records) if record["event"]=="s8_result" and
                      record["data"]["operation"] in (v.Operation.HOST_START.value,v.Operation.ATTACH.value)]
        for attack in ("duplicate_batch","reorder_batch","omit_batch","cross_owner","copy_batch","source_substitute",
                       "duplicate_owned","reorder_owned","checkpoint_copy","checkpoint_hash","owned_batch_copy",
                       "duplicate_materialization","window_copy","binding_duplicate","early_retirement",
                       "host_body_inventory","attach_body_inventory"):
            with self.subTest(attack=attack):
                changed=copy.deepcopy(records)
                if attack=="duplicate_batch":changed.insert(batch_index[1]+1,copy.deepcopy(changed[batch_index[1]]))
                if attack=="reorder_batch":changed[batch_index[0]],changed[batch_index[1]]=changed[batch_index[1]],changed[batch_index[0]]
                if attack=="omit_batch":changed.pop(batch_index[1])
                if attack=="cross_owner":changed[batch_index[1]]["data"]["owner"]="reader"
                if attack=="copy_batch":changed[batch_index[1]]["data"]["bindings"]=copy.deepcopy(changed[batch_index[0]]["data"]["bindings"])
                if attack=="source_substitute":changed[batch_index[1]]["data"]["sourceRecordSha256"]=changed[result_index[0]]["hash"]
                if attack=="duplicate_owned":changed.append(copy.deepcopy(changed[owned_index[-1]]))
                if attack=="reorder_owned":changed[owned_index[1]],changed[owned_index[2]]=changed[owned_index[2]],changed[owned_index[1]]
                if attack=="checkpoint_copy":changed[owned_index[1]]["data"]["checkpoint"]=copy.deepcopy(changed[owned_index[0]]["data"]["checkpoint"])
                if attack=="checkpoint_hash":changed[owned_index[1]]["data"]["checkpoint"]["sha256"]="0"*64
                if attack=="owned_batch_copy":changed[owned_index[1]]["data"]["inventoryRecordSha256"]=changed[batch_index[0]]["hash"]
                if attack=="duplicate_materialization":changed.insert(materialized+1,copy.deepcopy(changed[materialized]))
                if attack=="window_copy":changed[materialized]["data"]["windowRecordSha256"]=changed[result_index[0]]["hash"]
                if attack=="binding_duplicate":changed[materialized]["data"]["receipt"]["batches"][1]["bindings"][1]=copy.deepcopy(changed[materialized]["data"]["receipt"]["batches"][1]["bindings"][0])
                if attack=="early_retirement":changed.append(dict(event="s8_inventory_retired",hash="0"*64,data=dict(
                    sourceRecordSha256=changed[materialized]["hash"],keys=["authority_worker:0","frida_worker:0","root_frida_server:0"],
                    checkpoint=dict(ledgerId=checkpoint.ledger_id,sequence=checkpoint.sequence,sha256=checkpoint.record_sha256))))
                if attack in ("host_body_inventory","attach_body_inventory"):
                    index=result_index[0 if attack=="host_body_inventory" else 1]
                    changed[index]["data"]["receipt"]["body"]["ownerInventory"][-1]["identity"]["key"]="9999"
                with self.assertRaises((v.CoordinatorError,c.ContractError)):
                    v._replay_creations(changed,h.contract.value,prefix,checkpoint)
        # An omitted trailing s8_owned is a valid interrupted prefix, but the
        # independently durable registration is explicitly unlinked, not lost.
        interrupted=v._replay_creations(records[:-1],h.contract.value,prefix,checkpoint)
        self.assertFalse(interrupted["complete"])
        self.assertTrue(any(value["state"]=="ledger_registration_unlinked" for value in interrupted["pending"]))

    def test_inventory_unrequested_live_and_future_frida_alias_all_ports_and_providers(self):
        for role in ("reader","host","supervisor","reopen","authority_provider","frida_provider"):
            for pid,start in ((9999,777777),(2718,8000001)):
                h=Harness();closed=[]
                extra=Resource(h,c.ResourceBinding("root_frida_server","mutating_private_adb",
                    c.ResourceIdentity("process",c.AUTHORIZED_SERIAL,str(pid),BOOT+":"+str(start))),lambda:False)
                extra.prove_absent=lambda *args:closed.append(True)
                if role in h.ports:h.ports[role].resources+=(extra,)
                else:
                    prepare=h.factory.prepare
                    def prepared(context,deadline):
                        result=prepare(context,deadline)
                        owner=getattr(result,role);owner.inventory+=(extra,)
                        return result
                    h.factory.prepare=prepared
                with self.subTest(owner=role,pid=pid),self.assertRaises(v.RetainedQuarantine):h.run()
                co=h.coordinator
                self.assertTrue(any(any(handle is extra for handle in item[1]) for item in co._inventory_rejections()))
                self.assertFalse(any(value.identity==extra.value.identity for value in co._identities.values()))
                self.assertEqual(closed,[]);self.assertNotIn("run_0",h.log)
                self.assertNotIn("root_destroy_exact_task",h.log)
                if h.factory.bundles:
                    self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)
                    self.assertEqual(h.factory.bundles[0].frida_provider.session.load_count,0)
                else:self.assertEqual(h.log,[])
                recovery=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,h.journal,h.ownership,h.read_clock))
                self.assertEqual(recovery["status"],"RETAINED_QUARANTINE")
                self.assertTrue(recovery["pendingInventoryBatches"])
                with self.assertRaises(v.CoordinatorError):co._call("reader",v.Operation.PRELAUNCH,{})

    def test_inventory_complete_tuple_omission_duplicate_copy_and_cross_owner_claim(self):
        for role in ("reader","host","supervisor","authority_provider","frida_provider"):
            for mutation in ("omitted","duplicate","copy","cross_owner"):
                h=Harness();co=h.coordinator
                if role in h.owner_resources:
                    owner=h.ports[role];handles=h.owner_resources[role]
                else:
                    owner=Port(h,role)
                    names=("authority_worker",) if role=="authority_provider" else ("frida_worker","root_frida_server")
                    handles=tuple(Resource(h,c.ResourceBinding(name,c.RESOURCE_OWNERS[name][1],
                        c.ResourceIdentity("process",c.AUTHORIZED_SERIAL if name=="root_frida_server" else "windows-host/"+BOOT,
                            str(8000+index),BOOT+":"+str(9000+index))),lambda:False) for index,name in enumerate(names))
                    co._retain_methods(owner,v.PORT_METHODS)
                if role in h.owner_resources:co._begin_inventory_creation(owner,None)
                owner.resources=handles
                co._observe_inventory(owner,tuple(handle.value for handle in handles))
                for handle in handles:co._register(handle.value.role,handle.value.identity.wire(),handle=handle)
                if mutation=="cross_owner":
                    other=Port(h,"other");other.resources=handles;co._retain_methods(other,v.PORT_METHODS)
                    with self.assertRaises(v.CoordinatorError):co._observe_inventory(other,tuple(handle.value for handle in handles))
                elif mutation=="omitted":owner.resources=handles[:-1]
                elif mutation=="duplicate":owner.resources=handles+(handles[0],)
                else:owner.resources=tuple(list(handles))
                with self.subTest(owner=role,mutation=mutation),self.assertRaises(v.CoordinatorError):
                    co._call("reader",v.Operation.PRELAUNCH,{})
                self.assertEqual(h.log,[])
                self.assertEqual(len(co.ownership.remaining),len(handles))
                self.assertTrue(all(any(retained is handle for retained in co._resource_handles.values()) for handle in handles))
                self.assertEqual(co._completed_resources,set())

    def test_inventory_returned_subset_and_last_callback_tuple_drift_never_dispatch(self):
        for mode in ("subset","copy","last_clock","last_verifier"):
            h=Harness();entered=[];armed=[False];original=h.ports["reader"].retained_resources
            perform=h.ports["supervisor"].perform
            def actual(*args):entered.append(True);return perform(*args)
            h.ports["supervisor"].perform=actual
            if mode in ("subset","copy"):
                h.ports["reader"].retained_resources=lambda:() if mode=="subset" else tuple(list(original()))
                with self.assertRaises(v.RetainedQuarantine):h.run()
            else:
                def mutate():h.ports["reader"].resources=tuple(list(h.ports["reader"].resources))
                if mode=="last_clock":
                    clock=h.read_clock
                    def changed_clock():
                        result=clock()
                        if armed[0]:armed[0]=False;mutate()
                        return result
                    h.deps=replace(h.deps,clock=changed_clock)
                else:
                    verify=h.owner_resources["host"][0].verify;seen=[0]
                    def changed_verify():
                        verify()
                        if armed[0]:
                            seen[0]+=1
                            if seen[0]==2:mutate()
                    h.owner_resources["host"][0].verify=changed_verify
                co=h.coordinator;h.declare_direct("private_adb_server","host_session")
                for role in ("private_adb_server","host_session"):
                    source="reader" if role=="private_adb_server" else "host"
                    item=h.owner_resources[source][0];co._register(role,item.value.identity.wire(),handle=item)
                armed[0]=True
                with self.assertRaises(v.CoordinatorError):co._call("supervisor",v.Operation.DESTROY_TASK,{"foreign":h.foreign})
            self.assertEqual(entered,[]);self.assertEqual(h.log,[])

    def test_inventory_creation_result_must_authenticate_full_batch_before_cleanup_authority(self):
        for operation in (v.Operation.HOST_START,v.Operation.ATTACH):
            for mode in ("missing","omitted","extra","identity","throws"):
                h=Harness();owner=h.ports["host" if operation is v.Operation.HOST_START else "supervisor"]
                performed=owner.perform
                def changed(op,request,deadline):
                    raw=performed(op,request,deadline)
                    if op is not operation:return raw
                    value=c.load_canonical(raw)
                    if mode=="throws":raise OSError("creation response unavailable")
                    if mode=="missing":value["body"].pop("ownerInventory")
                    elif mode=="omitted":value["body"]["ownerInventory"]=[]
                    elif mode=="identity":value["body"]["ownerInventory"][-1]["identity"]["incarnation"]="wrong-incarnation"
                    else:
                        extra=Resource(h,c.ResourceBinding("root_frida_server","mutating_private_adb",
                            c.ResourceIdentity("process",c.AUTHORIZED_SERIAL,"9999",BOOT+":777777")),lambda:False)
                        owner.resources+=(extra,)
                        value["body"]["ownerInventory"].append(v._binding_wire(extra.value))
                    return c.canonical_bytes(value)
                owner.perform=changed
                with self.subTest(operation=operation,mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
                co=h.coordinator
                self.assertNotIn("virtual_display" if operation is v.Operation.HOST_START else "foreign_task",co._identities)
                self.assertNotIn("root_destroy_exact_task",h.log);self.assertNotIn("run_0",h.log)
                self.assertTrue(co._pending_inventory_evidence())
                self.assertEqual(co._completed_resources,set())
                recovery=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,h.journal,h.ownership,h.read_clock))
                self.assertEqual(recovery["status"],"RETAINED_QUARANTINE")

    def test_inventory_multi_handle_batch_registration_crashes_never_forget_or_retire(self):
        for role in ("authority_worker","frida_worker","root_frida_server"):
            for boundary in ("before","during","after"):
                h=Harness();hit=[];register=v.VisualCoordinator._register;record=v.VisualCoordinator._record
                def interrupted(self,name,identity,**kwargs):
                    if name==role and boundary=="before":hit.append(True);raise KeyboardInterrupt("before exact registration")
                    result=register(self,name,identity,**kwargs)
                    if name==role and boundary=="after":hit.append(True);raise KeyboardInterrupt("after exact registration")
                    return result
                def interrupted_record(self,event,data):
                    if event=="s8_owned" and data["role"]==role and boundary=="during":
                        hit.append(True);raise KeyboardInterrupt("registration publication interrupted")
                    return record(self,event,data)
                with patch.object(v.VisualCoordinator,"_register",interrupted),patch.object(v.VisualCoordinator,"_record",interrupted_record):
                    with self.subTest(role=role,boundary=boundary),self.assertRaises(v.RetainedQuarantine):h.run()
                self.assertEqual(hit,[True]);co=h.coordinator;bundle=h.factory.bundles[0]
                self.assertNotIn("run_0",h.log);self.assertEqual(bundle.frida_provider.attach_count,0)
                self.assertEqual(bundle.frida_provider.session.load_count,0);self.assertEqual(co._completed_resources,set())
                original_handles=(*bundle.authority_provider.inventory,*bundle.frida_provider.inventory)
                self.assertTrue(all(any(item is handle for item in co._retained_inventory_handles()) for handle in original_handles))
                raw=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,h.journal,h.ownership,h.read_clock))
                self.assertEqual(raw["status"],"RETAINED_QUARANTINE")
                declared=[binding for batch in raw["pendingInventoryBatches"] for binding in batch["bindings"]]
                for handle in (*bundle.authority_provider.inventory,*bundle.frida_provider.inventory):
                    self.assertIn(v._binding_wire(handle.value),declared)
                self.assertTrue(co._resource_handles or co._pending_inventory_evidence())
                bundle.authority_provider.inventory=();bundle.frida_provider.inventory=()
                self.assertTrue(all(any(item is handle for item in co._retained_inventory_handles()) for handle in original_handles))

    def test_inventory_requires_static_exact_slot_before_any_owner_callback(self):
        for mode in ("missing","computed","list"):
            h=Harness();calls=[]
            class Missing:
                def verify(self):calls.append("verify")
                def canonical_bytes(self):calls.append("canonical")
                def perform(self,*args):calls.append("perform")
                def retained_resources(self):calls.append("resources");return ()
                def stage_evidence(self,*args):calls.append("evidence")
            class Computed(Missing):
                RESOURCE_INVENTORY_SLOT="resources"
                @property
                def resources(self):calls.append("property");return ()
            class Mutable(Missing):
                RESOURCE_INVENTORY_SLOT="resources"
                def __init__(self):self.resources=[]
            owner=Missing() if mode=="missing" else Computed() if mode=="computed" else Mutable()
            h.deps=replace(h.deps,reader=owner)
            with self.subTest(mode=mode),self.assertRaises(v.CoordinatorError):h.coordinator
            self.assertEqual(calls,[])

    def test_inventory_closed_stage_handle_cannot_be_claimed_by_a_successor(self):
        h=Harness();prepare=h.factory.prepare;reused=[]
        def substitute(context,deadline):
            result=prepare(context,deadline)
            if context.stage_index==1:
                old=h.factory.bundles[0].authority_provider.inventory[0]
                self.assertIn("authority_worker:0",h.coordinator._completed_resources)
                old.value=result.resources[0]
                result.authority_provider.inventory=(old,);reused.append(old)
            return result
        h.factory.prepare=substitute
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertEqual(len(reused),1);self.assertNotIn("run_1",h.log)
        self.assertEqual(h.factory.bundles[1].frida_provider.attach_count,0)
        self.assertEqual(h.factory.bundles[1].frida_provider.session.load_count,0)
        self.assertTrue(any(any(handle is reused[0] for handle in item[1]) for item in h.coordinator._inventory_rejections()))

    def test_inventory_pending_creation_permit_is_single_dispatch_and_blocks_other_lifecycle(self):
        for mode in ("same_call","other_call","absence"):
            h=Harness();owner=h.ports["host"];perform=owner.perform;attempts=[]
            def creating(operation,request,deadline):
                raw=perform(operation,request,deadline)
                if operation is v.Operation.HOST_START:
                    co=h.coordinator
                    try:
                        if mode=="same_call":co._invoke(owner,"perform",operation,request,deadline)
                        elif mode=="other_call":co._invoke(h.ports["supervisor"],"perform",v.Operation.LAUNCH,request,deadline)
                        else:co._invoke(h.owner_resources["host"][0],"prove_absent",request,deadline)
                    except v.CoordinatorError:attempts.append("rejected")
                    else:raise AssertionError("pending batch authorized another operation")
                    raise OSError("creation response was lost after attempted reentry")
                return raw
            owner.perform=creating
            with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertEqual(attempts,["rejected"])
            self.assertEqual(h.log.count(v.Operation.HOST_START.value),1)
            self.assertNotIn(v.Operation.LAUNCH.value,h.log)
            self.assertNotIn("virtual_display",h.coordinator._identities)
            self.assertTrue(h.coordinator._pending_inventory_evidence())

    def test_static_slot_last_verifier_blocks_each_dispatch_family(self):
        for later in range(1,4):
            for earlier in range(later):
                for family in ("read","destroy","capture","cleanup"):
                    h=Harness();co=h.coordinator;armed=[False];seen=[0];changed=[False];called=[]
                    owners=[h.owner_resources["reader"][0],*h.owner_resources["host"],h.owner_resources["supervisor"][0]]
                    original=owners[later].verify
                    def verify():
                        original()
                        if armed[0]:
                            seen[0]+=1
                            if seen[0]==(1 if family=="capture" else 2):
                                value=owners[earlier].value
                                owners[earlier].value=(replace(value,identity=replace(value.identity,key="3333"))
                                    if earlier==0 else replace(value))
                                changed[0]=True
                    owners[later].verify=verify
                    proof=owners[0].prove_absent
                    def cleanup(request,deadline):called.append("cleanup");return proof(request,deadline)
                    owners[0].prove_absent=cleanup
                    h.declare_direct(*(owner.value.role for owner in owners))
                    for owner in owners:co._register(owner.value.role,owner.value.identity.wire(),handle=owner)
                    class Capture:
                        def capture(self):called.append("capture")
                    capture=Capture();co._retain_methods(capture,("capture",))
                    if family=="cleanup":
                        h.completed_owner_operations.add(v.Operation.CLOSE_PRIVATE_ADB)
                        co._install_cleanup_total(h.ns+250_000_000)
                    armed[0]=True
                    def dispatch():
                        if family=="read":co._call("reader",v.Operation.PRELAUNCH,{})
                        elif family=="destroy":co._call("supervisor",v.Operation.DESTROY_TASK,{"foreign":h.foreign})
                        elif family=="capture":v._guarded(co._retained_fence,lambda:co._invoke(capture,"capture"))
                        else:co._settle_resources(("private_adb_server",))
                    with self.subTest(later=later,earlier=earlier,family=family),self.assertRaises(v.CoordinatorError):dispatch()
                    self.assertTrue(changed[0]);self.assertEqual(h.log,[]);self.assertEqual(called,[])
                    self.assertEqual(len(co.ownership.remaining),4)

    def test_static_slot_missing_computed_and_descriptor_authority_is_rejected(self):
        h=Harness();co=h.coordinator;calls=[];binding=h.deps.private_adb_resource
        class Missing:
            def verify(self):calls.append("verify")
            def binding(self):calls.append("binding");return binding
            def prove_absent(self,*args):calls.append("proof")
        class MissingValue(Missing):BINDING_SLOT="value"
        class Computed(Missing):
            BINDING_SLOT="value"
            @property
            def value(self):calls.append("property");return binding
        class HostileDictionary(MissingValue):
            @property
            def __dict__(self):calls.append("dict descriptor");return {"value":binding}
        class WrongValue(MissingValue):
            def __init__(self):self.value=object()
        for owner in (Missing(),MissingValue(),Computed(),HostileDictionary(),WrongValue()):
            with self.assertRaises(v.CoordinatorError):co._retain_resource(owner)
        self.assertEqual(calls,[])

    def test_static_slot_final_clock_callback_cannot_replace_earlier_authority(self):
        for changed_owner in ("binding","clock","route","pin","store"):
            h=Harness();armed=[False];original_clock=h.read_clock;operation_entries=[]
            original_perform=h.ports["supervisor"].perform
            def perform(*args):operation_entries.append(True);return original_perform(*args)
            h.ports["supervisor"].perform=perform
            def clock():
                value=original_clock()
                if armed[0]:
                    armed[0]=False
                    if changed_owner=="binding":
                        owner=h.owner_resources["reader"][0];owner.value=replace(owner.value)
                    elif changed_owner=="clock":object.__setattr__(h.deps,"clock",lambda:value)
                    elif changed_owner=="route":object.__setattr__(h.deps,"reopen",Port(h,"reopen"))
                    elif changed_owner=="pin":h._pins["reopen"]="f"*64
                    else:h.ownership.authority=h.journal.authority
                return value
            h.deps=replace(h.deps,clock=clock);co=h.coordinator
            co._register("private_adb_server",h.deps.private_adb_resource.identity.wire())
            # Directly exercise the final clock edge, followed by the exact
            # same saved-callable dispatch used by the production wrapper.
            armed[0]=True
            with self.subTest(owner=changed_owner),self.assertRaises(v.CoordinatorError):
                v._guarded(lambda:co._retained_fence(h.ns+1_000_000_000),
                    lambda:co._invoke(h.ports["supervisor"],"perform",v.Operation.DESTROY_TASK,b"{}",h.ns+1_000_000_000))
            self.assertEqual(h.log,[])
            self.assertEqual(operation_entries,[])

    def test_static_slot_unrelated_concurrent_writes_are_an_explicit_blocker(self):
        h=Harness();co=h.coordinator;owner=h.owner_resources["reader"][0]
        co._register("private_adb_server",owner.value.identity.wire())
        reached=threading.Event();changed=threading.Event();counterfeit=[];used=[False]
        def mutate():
            if reached.wait(3):
                owner.value=replace(owner.value)
                h.ports["supervisor"].perform=lambda *args:counterfeit.append(True)
                changed.set()
        thread=threading.Thread(target=mutate);thread.start()
        def trace(frame,event,arg):
            if (not used[0] and event=="line" and frame.f_code is co._invoke.__code__ and
                frame.f_locals.get("name")=="perform" and "dispatched" in frame.f_locals):
                used[0]=True;reached.set();self.assertTrue(changed.wait(3))
            return trace
        prior=sys.gettrace();sys.settrace(trace)
        try:
            with self.assertRaises(v.CoordinatorError):co._call("supervisor",v.Operation.DESTROY_TASK,{"foreign":h.foreign})
        finally:sys.settrace(prior);thread.join(3)
        self.assertFalse(thread.is_alive());self.assertTrue(used[0]);self.assertEqual(counterfeit,[])
        # The saved exact callable was consumed; arbitrary foreign writes are
        # not prevented by a cooperative Python lock. The post-call fence
        # rejects the change, and real-device entry remains unconditionally
        # blocked pending immutable retained OS-handle dispatch authority.
        self.assertEqual(h.log,["root_destroy_exact_task"])
        self.assertIn("IMMUTABLE_OS_HANDLE_DISPATCH_AUTHORITY_REQUIRED",v.admission_status()["blockers"])
        with self.assertRaises(v.AdmissionBlocked):co.execute()

    def test_architectural_factory_context_is_frozen_before_success_and_exception(self):
        mutations = {
            "nonce":lambda x:object.__setattr__(x,"run_nonce","f"*64),
            "stage":lambda x:object.__setattr__(x,"stage_index",1),
            "deadline":lambda x:object.__setattr__(x.binding,"absolute_deadline_ns",x.binding.absolute_deadline_ns+1),
            "label":lambda x:object.__setattr__(x.binding,"stage","LEFT"),
            "rect":lambda x:object.__setattr__(x,"placement_raw",c.canonical_bytes({"rect":[0,0,1,1]})),
            "predecessor":lambda x:object.__setattr__(x,"previous_stage_closures_raw",b'{"replay":true}'),
            "forbidden":lambda x:object.__setattr__(x,"forbidden_owners_raw",b'[]'),
            "selection":lambda x:object.__setattr__(x,"selection_raw",c.canonical_bytes(dict(documentUri="file:///storage/emulated/0/Document/graph-v2.pdf",pageIndex=3))),
            "causal":lambda x:object.__setattr__(x,"causal_raw",b'{}'),
            "contract":lambda x:object.__setattr__(x.contract,"raw",x.contract.raw+b' '),
        }
        for name,mutate in mutations.items():
            for throws in (False,True):
                h=Harness(); original=h.factory.prepare
                def prepare(context,deadline):
                    result=original(context,deadline); mutate(context)
                    if throws:raise OSError("factory failed after mutation")
                    return result
                h.factory.prepare=prepare
                with self.subTest(name=name,throws=throws),self.assertRaises(v.RetainedQuarantine):h.run()
                self.assertNotIn("run_0",h.log)
                self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)

    def test_architectural_predispatch_and_pins_are_private_snapshots(self):
        for mode in ("context","deadline","record","task","pin","nested_manifest"):
            h=Harness(); original=h.factory.prepare; kept={}
            def prepare(context,deadline):
                bundle=original(context,deadline); pred=bundle.authority_provider.predispatch
                def retain_pre(ctx,bound):
                    kept["pre"]=pred(ctx,bound);return kept["pre"]
                bundle.authority_provider.predispatch=retain_pre
                return bundle
            h.factory.prepare=prepare
            def hook(label):
                if label!="run_0":return
                pre=kept["pre"]; bundle=h.factory.bundles[0]
                if mode=="context":object.__setattr__(pre,"context_sha256","f"*64)
                elif mode=="deadline":object.__setattr__(pre,"deadline_ns",pre.deadline_ns+1)
                elif mode=="record":object.__setattr__(pre.record,"raw",pre.record.raw+b' ')
                elif mode=="task":object.__setattr__(pre.task,"activity_token","abc123")
                elif mode=="pin":object.__setattr__(bundle.trusted_pins,"stage_policy_sha256","f"*64)
                else:bundle.manifest.value["expected"]["documentUri"]="file:///storage/emulated/0/Document/other.pdf"
            h.hook=hook
            with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)
            self.assertEqual(h.factory.bundles[0].frida_provider.session.load_count,0)

    def test_architectural_construction_roots_and_nested_identity_swaps(self):
        attacks = {
            "clock":lambda h:object.__setattr__(h.deps,"clock",lambda:c.HostInstant(CLOCK,0)),
            "dependencies":lambda h:setattr(h.coordinator,"deps",replace(h.deps)),
            "supervisor":lambda h:object.__setattr__(h.deps,"supervisor",Port(h,"supervisor")),
            "transport":lambda h:setattr(h.peer,"transport",PenTransport(h)),
            "session":lambda h:object.__setattr__(h.peer.stage_session,"value","f"*64),
            "peer_pid":lambda h:object.__setattr__(h.transport.peer_identity,"pid",3599),
            "adb_pid":lambda h:object.__setattr__(h.deps.private_adb_resource.identity,"key","3333"),
            "adb_start":lambda h:object.__setattr__(h.deps.private_adb_resource.identity,"incarnation",BOOT+":777777"),
            "selection":lambda h:object.__setattr__(h.selection,"page_index",3),
            "contract":lambda h:object.__setattr__(h.contract,"raw",h.contract.raw+b' '),
        }
        for name,attack in attacks.items():
            h=Harness(); original=h.ports["reopen"].canonical_bytes; armed=[False]
            # This last verifier is an explicit construction-time test seam.
            def final_verify():
                raw=original()
                if armed[0]:armed[0]=False;attack(h)
                return raw
            h.ports["reopen"].canonical_bytes=final_verify
            co=h.coordinator; armed[0]=True; before=len(h.clock_reads)
            with self.subTest(name=name),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertEqual(h.log,[])
            self.assertFalse(h.factory.contexts)
            # Shared class fixture identity must not infect subsequent cases.
            if name=="peer_pid":object.__setattr__(h.transport.peer_identity,"pid",2599)
            if name=="clock":self.assertEqual(len(h.clock_reads),before)

    def test_architectural_exact_type_anchors_never_call_hostile_hooks(self):
        calls=[]
        class IntAlias(int):
            def __eq__(self,other):calls.append("eq");return True
            def __repr__(self):calls.append("repr");return "alias"
            def __str__(self):calls.append("str");return "2"
        class ListAlias(list):
            def __iter__(self):calls.append("iter");return super().__iter__()
        class HostileMeta(type):
            def __eq__(self,other):calls.append("meta_eq");return False
        class Hostile(metaclass=HostileMeta):pass
        for value in (IntAlias(2),ListAlias([1]),{"x":IntAlias(2)},Hostile()):
            with self.assertRaises(v.CoordinatorError):v._anchor(value)
        original={"nested":[1,2]}; _,check,_=v._anchor(original)
        original["nested"][1]=IntAlias(2)
        with self.assertRaises(v.CoordinatorError):check()
        self.assertEqual(calls,[])

    def test_architectural_root_alias_and_pin_substitution_cannot_retarget(self):
        for pid in (3141,2600,2601,2599,2222,5000,5001):
            h=Harness()
            def hook(label):
                if label!="run_0":return
                co=h.coordinator
                # The private construction/admission set is independent of
                # caller contexts and forged policy/pin values.
                self.assertFalse(co._server_excluded(pid))
                bundle=h.factory.bundles[0];provider=bundle.authority_provider
                provider.before["frida"]["serverPid"]=pid
                provider.after["frida"]["serverPid"]=pid
                object.__setattr__(bundle.trusted_pins,"stage_policy_sha256",runner.stage_policy_sha256(provider.before))
                object.__setattr__(h.factory.contexts[0],"forbidden_owners_raw",b'[]')
                self.assertFalse(co._server_excluded(pid))
            h.hook=hook
            with self.subTest(pid=pid),self.assertRaises(v.RetainedQuarantine):h.run()
            frida=h.factory.bundles[0].frida_provider
            self.assertEqual(frida.attach_count,0);self.assertEqual(frida.session.load_count,0)
            self.assertNotIn("root_destroy_exact_task",h.log)

    def test_architectural_closed_stage_graphs_retire_to_detached_evidence(self):
        h=Harness(); original=h.factory.prepare
        def prepare(context,deadline):
            if context.stage_index:
                prior=context.stage_index-1;co=h.coordinator
                for role in ("authority_worker","frida_worker","root_frida_server"):
                    self.assertIn(role+":"+str(prior),co._completed_resources)
                old=h.factory.bundles[prior]
                object.__setattr__(h.factory.contexts[prior],"run_nonce","f"*64)
                object.__setattr__(old.trusted_pins,"stage_policy_sha256","f"*64)
                old.manifest.value["expected"]["documentUri"]="file:///storage/emulated/0/Document/retired.pdf"
                old.frida_provider.attach=lambda *args:(_ for _ in ()).throw(AssertionError("retired provider reused"))
            return original(context,deadline)
        h.factory.prepare=prepare
        result=h.run();self.assertEqual(result["status"],"CLEAN")
        recovered=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,h.journal,h.ownership,h.read_clock))
        self.assertEqual(recovered["status"],"CLEAN_EVIDENCE_ONLY")
        self.assertEqual(recovered["stageSelectionSha256"],result["stageSelectionSha256"])

    def test_architectural_dual_deadline_rebase_and_equal_binding_replacement(self):
        for mode in ("dual_rebase","equal_binding"):
            h=Harness();co=h.coordinator;resource=h.owner_resources["supervisor"][0]
            original=resource.prove_absent
            def proof(request,deadline):
                result=original(request,deadline)
                if mode=="dual_rebase":
                    h.ns+=30_000_000
                    co._cleanup_deadline=co._cleanup_original_deadline=h.ns+250_000_000
                else:resource.value=replace(resource.value)
                return result
            resource.prove_absent=proof
            h.declare_direct("foreign_task")
            co._register("foreign_task",h.foreign["identity"])
            h.completed_owner_operations.add(v.Operation.DESTROY_TASK)
            co._install_cleanup_total(h.ns+250_000_000)
            with self.subTest(mode=mode),self.assertRaises(v.CoordinatorError):co._settle_resources(("foreign_task",))
            self.assertTrue(co.ownership.remaining);self.assertNotIn("foreign_task",co._completed_resources)

    def test_architectural_recovery_preflight_types_single_clock_and_no_io(self):
        class IntAlias(int):pass
        class ContractAlias(c.RunContract):pass
        class SelectionAlias(v.Selection):pass
        h=Harness();h.coordinator
        valid=(h.contract,h.selection,h.journal,h.ownership,h.read_clock)
        bad_now=c.HostInstant(CLOCK,h.ns);object.__setattr__(bad_now,"nanoseconds",True)
        alias_now=c.HostInstant(CLOCK,h.ns);object.__setattr__(alias_now,"nanoseconds",IntAlias(h.ns))
        invalid=(
            (ContractAlias(h.contract.raw),*valid[1:]),
            (valid[0],SelectionAlias(h.selection.document_uri,2),*valid[2:]),
            (*valid[:2],object(),*valid[3:]),
            (*valid[:3],h.journal,valid[4]),
            (*valid[:4],lambda:bad_now),(*valid[:4],lambda:alias_now))
        for inputs in invalid:
            before=list(h.api.log)
            with self.assertRaises(v.CoordinatorError):v.VisualCoordinator.recover(*inputs)
            self.assertEqual(h.api.log,before)
        other=h.ownership.authority; h.ownership.authority=h.journal.authority
        before=list(h.api.log)
        with self.assertRaises(v.CoordinatorError):v.VisualCoordinator.recover(*valid)
        self.assertEqual(h.api.log,before);h.ownership.authority=other
        h.clock_reads.clear()
        result=c.load_canonical(v.VisualCoordinator.recover(*valid))
        self.assertEqual(result["status"],"RETAINED_QUARANTINE")
        self.assertEqual(len(h.clock_reads),1)

    def test_architectural_selection_envelope_requires_independent_page_binding(self):
        for mode in ("page","manifest","unknown"):
            h=Harness()
            def changed(role,value,index):
                if role=="reader":
                    context=h.factory.contexts[index];manifest=h.factory.bundles[index].manifest
                    envelope=v.selection_authority(context,manifest.sha256)
                    if mode=="page":envelope["requestedPageIndex"]=3
                    elif mode=="manifest":envelope["manifestSha256"]="f"*64
                    else:envelope["extra"]=True
                    value["selectionAuthoritySha256"]=c.digest(envelope)
                return value
            h.owner_view_mutator=changed
            with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("run_0",h.log)

    def test_architectural_finalization_drift_prevents_terminal_publication(self):
        original=ledger.CleanupLedger.finalize
        checkpoint=WindowsCleanupStore.load_checkpoint
        for mode in ("contract","selection","pen","clock","store","checkpoint"):
            h=Harness();attacked=[]
            def changed_checkpoint(store):
                result=checkpoint(store)
                if mode=="checkpoint" and h._coordinator is not None and store is h.ownership and h.coordinator.ownership.successful:
                    attacked.append(mode)
                    object.__setattr__(h.contract,"raw",h.contract.raw+b' ')
                return result
            def changed(owner):
                result=original(owner)
                if mode!="checkpoint":attacked.append(mode)
                if mode=="contract":object.__setattr__(h.contract,"raw",h.contract.raw+b' ')
                elif mode=="selection":object.__setattr__(h.selection,"page_index",3)
                elif mode=="pen":object.__setattr__(h.peer.binding.worker,"pid",3600)
                elif mode=="clock":object.__setattr__(h.deps,"clock",lambda:c.HostInstant(CLOCK,h.ns))
                elif mode=="store":owner._store=h.journal
                return result
            with patch.object(ledger.CleanupLedger,"finalize",changed),patch.object(WindowsCleanupStore,"load_checkpoint",changed_checkpoint):
                with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("s8_finished",[r["event"] for r in h.coordinator._journal.records])
            self.assertEqual(attacked,[mode])

    def test_review_exact_head_probe_cases(self):
        # Independently supplied s8_exact_head_probe.py cases: do not infer
        # absence from a provider declaration or silently accept a 30ms call.
        h = Harness(); resource = h.owner_resources["supervisor"][0]
        original = resource.prove_absent; observed = []
        def delayed(request, deadline):
            observed.append((h.ns, deadline)); h.ns += 30_000_000
            return original(request, deadline)
        resource.prove_absent = delayed
        with self.assertRaises(v.RetainedQuarantine): h.run()
        self.assertEqual(observed[0][1] - observed[0][0], 25_000_000)
        self.assertNotIn("foreign_task", h.coordinator._completed_resources)
        self.assertNotIn("pen_finish", h.log)
        h = Harness()
        def drift_before_destroy(label):
            if label == "host_restore_full_and_begin_close": h.resource_drift = "foreign_task"
        h.hook = drift_before_destroy
        with self.assertRaises(v.RetainedQuarantine): h.run()
        self.assertNotIn("root_destroy_exact_task", h.log)
        h = Harness()
        def drift_before_runner(label):
            if label == "run_0": h.resource_drift = "private_adb_server"
        h.hook = drift_before_runner
        with self.assertRaises(v.RetainedQuarantine): h.run()
        self.assertEqual(h.factory.bundles[0].frida_provider.attach_count, 0)
        self.assertEqual(h.factory.bundles[0].frida_provider.session.load_count, 0)
        self.assertNotIn("run_1", h.log)

    def test_all_retained_nonstage_handles_fence_capture_and_cleanup(self):
        mutations = (
            ("private_adb_server", lambda h:setattr(h, "resource_drift", "private_adb_server")),
            ("foreign_task", lambda h:setattr(h, "resource_drift", "foreign_task")),
            ("host_session", lambda h:setattr(h, "resource_drift", "host_session")),
            ("virtual_display", lambda h:setattr(h, "resource_drift", "virtual_display")),
            ("pen_worker", lambda h:setattr(h.peer, "binding", replace(h.peer.binding, worker=pen.ProcessIdentity(3600, 7000001)))),
            ("pen_guardian", lambda h:setattr(h.peer, "binding", replace(h.peer.binding, guardian=pen.ProcessIdentity(3601, 7000002)))),
            ("pen_lease", lambda h:setattr(h.peer, "binding", replace(h.peer.binding, token="f"*64))),
            ("device_peer", lambda h:setattr(h.transport, "peer_identity", pen.ProcessIdentity(3599, 6999999))),
        )
        for name, mutate in mutations:
            h = Harness(); prepare = h.factory.prepare
            def prepared(context, deadline):
                bundle = prepare(context, deadline); original = bundle.authority_provider.capture
                def captured(request, timeout, permit):
                    result = original(request, timeout, permit)
                    if request.phase == "before": mutate(h)
                    return result
                bundle.authority_provider.capture = captured
                return bundle
            h.factory.prepare = prepared
            with self.subTest(owner=name), self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertEqual(h.factory.bundles[0].frida_provider.attach_count, 0)
            self.assertEqual(h.factory.bundles[0].frida_provider.session.load_count, 0)
            self.assertTrue(h.coordinator._authority_sealed)
            self.assertNotIn("root_destroy_exact_task", h.log)
        # A verifier returning None cannot hide replacement of the retained
        # identity itself. Exercise the comparison, not only verifier failure.
        for role in ("private_adb_server", "foreign_task", "host_session", "virtual_display"):
            h = Harness(); co = h.coordinator
            identity = (h.deps.private_adb_resource.identity.wire() if role == "private_adb_server" else
                h.foreign["identity"] if role == "foreign_task" else
                wire("host_session", HOST, SESSION) if role == "host_session" else h.display["identity"])
            h.declare_direct(role)
            co._register(role, identity); handle = co._resource_handles[role]
            old = handle.value.identity
            handle.value = replace(handle.value, identity=c.ResourceIdentity(old.kind, old.namespace, old.key, old.incarnation+"0"))
            with self.subTest(binding=role), self.assertRaises(v.CoordinatorError): co._retained_fence()
            self.assertTrue(co._authority_sealed)

    def test_nonstage_semantic_identity_fence_after_admission_before_attach(self):
        mutations = (
            ("adb", lambda x:x["reader"]["privateAdbServer"].update(pid=3333, processCreationFileTime="777777")),
            ("target", lambda x:x["reader"]["target"].update(startTimeTicks="777777")),
            ("observer", lambda x:x["reader"].update(observerSha256="f"*64)),
            ("pdf", lambda x:x["reader"]["files"]["originalPdf"]["stat"].update(inode="9010", ctimeNs="9011")),
            ("mark", lambda x:x["reader"]["files"]["mark"]["stat"].update(inode="9020", ctimeNs="9021")),
            ("host_apk", lambda x:x["host"]["host"].update(hostApkSha256="f"*64)),
            ("host_task", lambda x:x["host"]["host"].update(hostTaskId=70, hostActivityToken="abc456")),
            ("host_display", lambda x:x["host"]["host"].update(displayId=8, displayGeneration=10)),
            ("host_session", lambda x:x["host"].update(hostSessionId="other-session")),
            ("foreign_activity", lambda x:x["supervisor"]["task"].update(activity_token="abc456")),
            ("route", lambda x:x["reopen"].update(ordinaryRouteAuthoritySha256="f"*64)),
        )
        for name, mutate in mutations:
            h = Harness(); prepare = h.factory.prepare
            def prepared(context, deadline):
                bundle = prepare(context, deadline); original = bundle.authority_provider.admission
                def admission(timeout, permit):
                    result = original(timeout, permit); mutate(h.owner_views); return result
                bundle.authority_provider.admission = admission
                return bundle
            h.factory.prepare = prepared
            with self.subTest(identity=name), self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertEqual(h.factory.bundles[0].frida_provider.attach_count, 0)
            self.assertEqual(h.factory.bundles[0].frida_provider.session.load_count, 0)
            self.assertTrue(h.coordinator._authority_sealed)

    def test_every_lifecycle_wrapper_checks_same_owner_before_and_after(self):
        class Target:
            def __init__(self, h, drift): self.h, self.drift, self.calls = h, drift, []
            def call(self, *args):
                self.calls.append(args)
                if self.drift: self.h.resource_drift = "private_adb_server"
                return None
            admission = attach = load = seal_callbacks = unload = detach = call
            teardown = assert_quiescent = cancel_and_quiesce = fail_stop_and_quiesce = call
        for phase in ("before", "after"):
            for kind, method, args in (
                ("session", "load", ("source", None, 25, None)),
                *(("session", name, (25,)) for name in ("seal_callbacks", "unload", "detach", "assert_quiescent")),
                ("frida", "admission", (25, None)), ("frida", "attach", (c.AUTHORIZED_SERIAL, 3141, 25, None)),
                *(("frida", name, (25,)) for name in ("teardown", "assert_quiescent")),
                ("authority", "admission", (25, None)),
                *(("authority", name, (25,)) for name in ("cancel_and_quiesce", "assert_quiescent", "fail_stop_and_quiesce")),
            ):
                h = Harness(); co = h.coordinator
                co._register("private_adb_server", h.deps.private_adb_resource.identity.wire())
                target = Target(h, phase == "after")
                cleanup = lambda op, timeout:co._stage_cleanup_call(co._retained_fence, h.ns+100_000_000, op, timeout)
                wrapper = (v._FencedSession(target, co._retained_fence, lambda:None, cleanup) if kind == "session" else
                    v._FencedFrida(target, co._retained_fence, lambda:None, cleanup) if kind == "frida" else
                    v._CapturedAuthority(target, co._retained_fence, lambda _:None, cleanup))
                if phase == "before": h.resource_drift = "private_adb_server"
                with self.subTest(phase=phase, method=method, kind=kind), self.assertRaises((OSError, v.CoordinatorError)):
                    getattr(wrapper, method)(*args)
                self.assertEqual(len(target.calls), 0 if phase == "before" else 1)
                self.assertTrue(co._authority_sealed)
                h.resource_drift = None
                with self.assertRaises(v.CoordinatorError): co._retained_fence()

    def test_cleanup_exact_per_call_boundaries_and_retained_obligation(self):
        for total, delay, succeeds in ((250,24,True), (250,25,False), (250,26,False), (250,30,False),
                                       (20,19,True), (20,20,False), (0,0,False)):
            h = Harness(); co = h.coordinator
            h.completed_owner_operations.add(v.Operation.DESTROY_TASK)
            resource = h.owner_resources["supervisor"][0]; original = resource.prove_absent; calls = []
            def delayed(request, deadline):
                body = c.load_canonical(request); calls.append((h.ns, deadline, body))
                h.ns += delay*1_000_000
                return original(request, deadline)
            resource.prove_absent = delayed
            h.declare_direct("foreign_task")
            co._register("foreign_task", h.foreign["identity"])
            co._install_cleanup_total(h.ns + total*1_000_000)
            with self.subTest(total=total, delay=delay):
                if succeeds: co._settle_resources(("foreign_task",))
                else:
                    with self.assertRaises(v.CoordinatorError): co._settle_resources(("foreign_task",))
                self.assertEqual("foreign_task" in co._completed_resources, succeeds)
                self.assertEqual(bool(co.ownership.remaining), not succeeds)
                if total:
                    issued, deadline, body = calls[0]
                    self.assertEqual(deadline, min(co._cleanup_original_deadline, issued+25_000_000))
                    self.assertEqual(body["issuedNs"], str(issued)); self.assertEqual(body["deadlineNs"], str(deadline))
                else: self.assertFalse(calls)

    def test_cleanup_clock_types_rebase_and_all_call_adapters(self):
        class IntAlias(int): pass
        for invalid in (True, False, 1.0, "2000000000", None, IntAlias(2_000_000_000)):
            h = Harness(); co = h.coordinator
            with self.subTest(parent=invalid), self.assertRaises(v.CoordinatorError): co._cleanup_call_window(invalid)
            with self.subTest(stage_parent=invalid), self.assertRaises(v.CoordinatorError):
                co._stage_cleanup_call(co._retained_fence, invalid, lambda _:None, 25)
        h = Harness(); co = h.coordinator
        co._install_cleanup_total(h.ns+250_000_000)
        for invalid in (True, h.ns+250_000_001):
            with self.assertRaises(v.CoordinatorError): co._cleanup_call_window(invalid)
        co._cleanup_deadline += 1
        with self.assertRaises(v.CoordinatorError): co._cleanup_call_window()
        # Construction uses precisely one trusted read. Later checks may only
        # narrow remaining time, never issue another 25ms window for this call.
        h = Harness(); co = h.coordinator; h.clock_reads.clear()
        self.assertEqual(co._cleanup_call_window(h.ns+250_000_000), (h.ns,h.ns+25_000_000))
        self.assertEqual(len(h.clock_reads), 1)
        for bad in (c.HostInstant("other-host-clock-0001", h.ns), c.HostInstant(CLOCK, h.ns-1)):
            h.clock_fault = bad
            with self.assertRaises(v.CoordinatorError): co._cleanup_call_window(h.ns+250_000_000)
        forged = c.HostInstant(CLOCK, h.ns); object.__setattr__(forged, "nanoseconds", IntAlias(h.ns))
        h.clock_fault = forged
        with self.assertRaises(v.CoordinatorError): co._cleanup_call_window(h.ns+250_000_000)
        for fault in ("rebase", "clock_back", "wrong_clock", "owner_drift"):
            h = Harness(); co = h.coordinator
            h.completed_owner_operations.add(v.Operation.DESTROY_TASK)
            resource = h.owner_resources["supervisor"][0]; original = resource.prove_absent
            def changed(request, deadline):
                result = original(request, deadline)
                if fault == "rebase": co._cleanup_deadline += 25_000_000
                elif fault == "clock_back": h.ns -= 1
                elif fault == "wrong_clock": co.deps = replace(h.deps, clock=lambda:c.HostInstant("other-host-clock-0001", h.ns))
                else: h.resource_drift = "foreign_task"
                return result
            resource.prove_absent = changed
            h.declare_direct("foreign_task")
            co._register("foreign_task", h.foreign["identity"])
            co._install_cleanup_total(h.ns+250_000_000)
            with self.subTest(post_call=fault), self.assertRaises((v.CoordinatorError,OSError)):
                co._settle_resources(("foreign_task",))
            self.assertTrue(co.ownership.remaining)
            self.assertNotIn("foreign_task", co._completed_resources)
        for adapter in ("port", "stage_cleanup"):
            for delay in (24,25,26,30):
                h = Harness(); co = h.coordinator; calls = []
                co._install_cleanup_total(h.ns+250_000_000)
                if adapter == "port":
                    h.delays[v.Operation.RESTORE.value] = delay*1_000_000-1
                    operation = lambda:co._call("host", v.Operation.RESTORE, {"foreign":h.foreign})
                else:
                    def target(timeout): calls.append(timeout); h.ns += delay*1_000_000
                    operation = lambda:co._stage_cleanup_call(co._retained_fence, h.ns, target, 25)
                with self.subTest(adapter=adapter, delay=delay):
                    if delay == 24: operation()
                    else:
                        with self.assertRaises(v.CoordinatorError): operation()
                    if adapter == "port":
                        _, deadline, issued = h.deadlines[0]; self.assertEqual(deadline-issued,25_000_000)
                    else: self.assertEqual(calls,[25])

    def test_review_cross_owner_repros_are_rejected_before_lifecycle(self):
        changes = (
            ("adb", lambda rec:rec["privateAdbServer"].update(pid=3333, processCreationFileTime="777777")),
            ("host_task", lambda rec:rec["host"].update(hostTaskId=70)),
            ("host_activity", lambda rec:rec["host"].update(hostActivityToken="abc123")),
            ("host_apk", lambda rec:rec["host"].update(hostApkSha256="f"*64)),
            ("target", lambda rec:rec["target"].update(startTimeTicks="777777")),
        )
        for name, change in changes:
            h=Harness()
            def mutate(before,after,task,index,change=change):
                change(before); change(after); return before,after,task
            h.record_mutator=mutate
            with self.subTest(name=name), self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("run_0",h.log)
            if h.factory.bundles:self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)
        for token in ("abc456", "abc123"):
            h=Harness()
            def mutate(before,after,task,index,token=token):
                task=replace(task,activity_token=token)
                for rec in (before,after):rec["taskAuthoritySha256"]=hashlib.sha256(task.canonical_bytes()).hexdigest()
                return before,after,task
            h.record_mutator=mutate
            with self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("run_0",h.log)
        h=Harness()
        h.coordinator.deps=replace(h.deps,private_adb_resource=replace(h.deps.private_adb_resource,
            identity=c.ResourceIdentity("process","windows-host/"+BOOT,"3333",BOOT+":777777")))
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertEqual(h.log,[])

    def test_review_worker_declarations_and_frida_selection_cannot_fabricate_owners(self):
        h=Harness()
        h.resources_mutator=lambda values,index:tuple(replace(value,identity=c.ResourceIdentity(
            "process","windows-host/"+BOOT,str(8000+index*2+j),BOOT+":"+str(9900+index*2+j)))
            for j,value in enumerate(values))
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertNotIn("run_0",h.log)
        h=Harness()
        h.frida_view_mutator=lambda value,index:{**value,"frida":{**value["frida"],"serverPid":6718+index}}
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertNotIn("run_0",h.log)
        for pid,start in ((3141,"9000001"),(2600,"7000001"),(2601,"7000002"),(2599,"6999999")):
            h=Harness()
            def mutate(before,after,task,index):
                for rec in (before,after):rec["frida"].update(serverPid=pid,serverStartTimeTicks=start)
                return before,after,task
            h.record_mutator=mutate
            h.frida_view_mutator=lambda value,index:{**value,"frida":{**value["frida"],"serverPid":pid,"serverStartTimeTicks":start}}
            with self.subTest(pid=pid),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("run_0",h.log)
            self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)

    def test_owner_join_receipt_required_even_when_capture_claims_teardown(self):
        h=Harness();prepare=h.factory.prepare
        def wrapped(context,deadline):
            result=prepare(context,deadline)
            result.authority_provider.fail_stop_and_quiesce=lambda timeout:None
            return result
        h.factory.prepare=wrapped
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertNotIn("authority_worker:0",h.coordinator._completed_resources)
        self.assertNotIn("stage_1_left",h.log)
        for field,value in (("absent",1),("joined",False),("channels_closed",False),("request_sha256","0"*64)):
            h=Harness();h.closure_mutator=lambda proof,field=field,value=value:replace(proof,**{field:value})
            with self.subTest(field=field),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("authority_worker:0",h.coordinator._completed_resources)

    def test_shared_host_and_file_identity_never_rotate_across_visual_stages(self):
        for mode in ("host_task","host_activity","host_apk","files"):
            h=Harness()
            def manifest(value,index):
                if mode=="files":
                    for j,key in enumerate(("originalPdf","mark")):
                        value["files"][key]["stat"].update(inode=str(9000+index*10+j),ctimeNs=str(9010+index*10+j))
                return value
            def owner(role,value,index):
                if role=="host":
                    if mode=="host_task":value["host"]["hostTaskId"]=70+index
                    if mode=="host_activity":value["host"]["hostActivityToken"]="host-token-"+str(index)
                    if mode=="host_apk":value["host"]["hostApkSha256"]=sha("host-apk-"+str(index))
                if role=="reader" and mode=="files":
                    for j,key in enumerate(("originalPdf","mark")):
                        value["files"][key]["stat"].update(inode=str(9000+index*10+j),ctimeNs=str(9010+index*10+j))
                return value
            def record(before,after,task,index):
                if mode.startswith("host_"):
                    for rec in (before,after):rec["host"]=owner("host",{"host":rec["host"]},index)["host"]
                return before,after,task
            h.manifest_mutator=manifest;h.owner_view_mutator=owner;h.record_mutator=record
            with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertIn("run_0",h.log);self.assertNotIn("run_1",h.log)

    def test_stage_epoch_and_original_deadline_require_exact_predecessor_closure(self):
        for mode in ("closure","epoch","deadline","missing_exclusion"):
            h=Harness()
            if mode=="closure":
                def change(value,index):
                    if index==1:value["frida_worker"]["predecessorClosure"]="0"*64
                    return value
                h.transitions_mutator=change
            else:
                def change(value,index):
                    if mode=="epoch":value["epoch"]["epoch"]="0"*64
                    elif mode=="deadline":value["deadlineNs"]=str(int(value["deadlineNs"])+1)
                    else:value["exclusionAppliedBeforeAttach"]=False
                    return value
                h.frida_view_mutator=change
            with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("run_1" if mode=="closure" else "run_0",h.log)

    def test_terminal_decision_wins_late_clock_and_forbids_later_publication(self):
        h=Harness();append=v.EventJournal.append
        def delayed(owner,event,data,remaining):
            result=append(owner,event,data,remaining)
            if event=="s8_finished":h.ns=h.coordinator._cleanup_deadline+1
            return result
        with patch.object(v.EventJournal,"append",delayed): result=h.run()
        self.assertEqual(result["status"],"CLEAN")
        h.coordinator._quarantine(OSError("late observation cannot revoke decision"))
        self.assertEqual(h.coordinator._journal.records[-1]["event"],"s8_finished")
        recovered=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,h.journal,h.ownership,h.deps.clock))
        self.assertEqual(recovered["status"],"CLEAN_EVIDENCE_ONLY")
        with self.assertRaises(v.CoordinatorError):h.coordinator._record("s8_quarantine",{})

    def test_terminal_publication_power_edges_have_one_recoverable_decision(self):
        h=Harness(); append=v.EventJournal.append; saved={}
        def stop_before(owner,event,data,remaining):
            if event=="s8_finished":
                saved.update(api=h.api.clone(),data=copy.deepcopy(data))
                raise OSError("crash before terminal transaction")
            return append(owner,event,data,remaining)
        with patch.object(v.EventJournal,"append",stop_before):
            with self.assertRaises(v.TerminalDecisionUncertain):h.run()
        self.assertEqual(h.coordinator.phase,"TERMINAL_DECISION_UNCERTAIN")
        self.assertNotIn("s8_quarantine",[r["event"] for r in h.coordinator._journal.records])
        def opened(api):
            events=WindowsCleanupStore.open_existing(h.journal.authority,api=api)
            owned=WindowsCleanupStore.open_existing(h.ownership.authority,api=api)
            journal=v.EventJournal(events,h.contract,h.selection,recover=True)
            return events,owned,journal
        base=saved["api"].clone();events,owned,journal=opened(base);start=len(base.log)
        journal.append("s8_finished",saved["data"],())
        operations=base.log[start:]
        first=operations.index("write")
        # All concrete publication edges: writes, file durability, record and
        # checkpoint rename, namespace durability, disposal, and postcommit close.
        edges=[i+1 for i,name in enumerate(operations) if i>=first and name in
               {"write","file_flush","rename","checkpoint_rename","directory_flush","delete","close"}]
        self.assertTrue(edges)
        for relative in edges:
            for when in ("before","after"):
                api=saved["api"].clone();events,owned,journal=opened(api)
                api.fault=(len(api.log)+relative,when)
                returned=False
                try:journal.append("s8_finished",saved["data"],());returned=True
                except (OSError,ledger.LedgerError,v.CoordinatorError):pass
                api.crash()
                try:
                    events,owned,journal=opened(api)
                    terminal=[r["event"] for r in journal.records if r["event"] in ("s8_finished","s8_quarantine")]
                    self.assertIn(terminal,([], ["s8_finished"]))
                    result=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,events,owned,h.deps.clock))
                    self.assertEqual(result["status"],"CLEAN_EVIDENCE_ONLY" if terminal else "RETAINED_QUARANTINE")
                    if returned:self.assertEqual(terminal,["s8_finished"])
                except (OSError,ledger.LedgerError,v.CoordinatorError):
                    self.assertFalse(returned,"a confirmed durable decision became unavailable")

    def test_per_lifecycle_retained_fence_rejects_late_owner_substitution(self):
        h=Harness()
        def hook(label):
            if label=="run_0":h.drift="reader"
        h.hook=hook
        with self.assertRaises(v.RetainedQuarantine):h.run()
        bundle=h.factory.bundles[0]
        self.assertEqual(bundle.authority_provider.admission_count,0)
        self.assertEqual(bundle.frida_provider.admission_count,0)
        self.assertEqual(bundle.frida_provider.attach_count,0)

    def test_retained_verifiers_reject_non_none_without_dispatch(self):
        for role in ("reader","host","supervisor","reopen","stages"):
            for value in (False,True,0,1,{},object()):
                h=Harness();source=h.factory if role=="stages" else h.ports[role]
                source.verify=lambda value=value:value
                with self.subTest(role=role,value=value),self.assertRaises(v.RetainedQuarantine):h.run()
                self.assertEqual(h.log,[])
            for mode in ("raise","side_effect"):
                h=Harness();source=h.factory if role=="stages" else h.ports[role]
                def verify():
                    if mode=="raise":raise OSError("retained verifier raised")
                    source.canonical_bytes=lambda:c.canonical_bytes({"retained":"substituted"})
                source.verify=verify
                with self.subTest(role=role,mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
                self.assertEqual(h.log,[])
        for value in (False,True,0,1,object()):
            h=Harness();h.owner_resources["reader"][0].verify=lambda value=value:value
            with self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertEqual(h.log,[])

    def test_capture_return_gate_seals_owner_mutations_before_runner_publication(self):
        mutations=(
            ("task_activity",lambda rec:None),
            ("task_token",lambda rec:None),
            ("adb",lambda rec:rec["privateAdbServer"].update(pid=3333,processCreationFileTime="777777")),
            ("host_task",lambda rec:rec["host"].update(hostTaskId=70)),
            ("host_activity",lambda rec:rec["host"].update(hostActivityToken="abc456")),
            ("host_session",lambda rec:rec["host"].update(hostSessionId="other-host-session")),
            ("display",lambda rec:rec["host"].update(displayId=8,displayGeneration=10)),
            ("host_apk",lambda rec:rec["host"].update(hostApkSha256="f"*64)),
            ("frida",lambda rec:rec["frida"].update(serverPid=6718)),
            ("frida_session",lambda rec:rec["frida"].update(serverSessionId="other-server-session")),
            ("adb_session",lambda rec:rec["privateAdbServer"].update(serverSessionId="other-adb-session")),
            ("target",lambda rec:rec["target"].update(startTimeTicks="777777")),
            ("firmware",lambda rec:rec["firmware"]["module"].update(sha256="f"*64)),
            ("observer_manifest",lambda rec:rec.update(manifestSha256="f"*64)),
            ("pen",lambda rec:rec["penLease"].update(helperPid=2601)),
            ("pen_session",lambda rec:rec["penLease"].update(holderSessionId="f"*64)),
            ("pdf",lambda rec:rec["files"]["originalPdf"]["stat"].update(inode="9000",ctimeNs="9001")),
            ("mark",lambda rec:rec["files"]["mark"]["stat"].update(inode="9010",ctimeNs="9011")),
        )
        for phase in ("before","after"):
            for name,mutation in mutations:
                h=Harness()
                def hook(label):
                    if label!="run_0":return
                    p=h.factory.bundles[0].authority_provider
                    if name.startswith("task_"):
                        changed=replace(p.task,**({"activity_token":"abc123"} if name=="task_activity" else {"task_token":"abc456"}))
                        if phase=="before":p.task=changed
                        p.task_after=changed
                        rec=p.before if phase=="before" else p.after
                        rec["taskAuthoritySha256"]=hashlib.sha256(changed.canonical_bytes()).hexdigest()
                    else:mutation(p.before if phase=="before" else p.after)
                    if phase=="before":
                        # The coordinator's immutable pre-dispatch owner view
                        # remains authoritative even if producer policy is rebuilt.
                        object.__setattr__(h.factory.bundles[0].trusted_pins,"stage_policy_sha256",
                                           runner.stage_policy_sha256(p.before))
                h.hook=hook
                with self.subTest(phase=phase,name=name),self.assertRaises(v.RetainedQuarantine):h.run()
                bundle=h.factory.bundles[0]
                self.assertEqual(bundle.frida_provider.attach_count,0 if phase=="before" else 1)
                self.assertEqual(bundle.frida_provider.session.load_count,0 if phase=="before" else 1)
                self.assertFalse(h.coordinator._stage_results)
                self.assertNotIn("run_1",h.log)

    def test_capture_return_gate_rechecks_retained_worker_and_route_handles(self):
        for phase in ("before","after"):
            for role in ("authority_worker","frida_worker","root_frida_server","reopen"):
                h=Harness();prepare=h.factory.prepare
                def wrapped(context,deadline):
                    bundle=prepare(context,deadline);capture=bundle.authority_provider.capture
                    def capture_then_drift(request,timeout,permit):
                        result=capture(request,timeout,permit)
                        if request.phase==phase:
                            if role=="reopen":h.ports["reopen"].canonical_bytes=lambda:c.canonical_bytes({"retained":"replaced-route"})
                            else:
                                owner=bundle.authority_provider if role=="authority_worker" else bundle.frida_provider
                                handle=next(item for item in owner.retained_resources() if item.binding().role==role)
                                identity=handle.value.identity
                                handle.value=replace(handle.value,identity=c.ResourceIdentity(identity.kind,identity.namespace,
                                    str(int(identity.key)+4000),identity.incarnation))
                        return result
                    bundle.authority_provider.capture=capture_then_drift
                    return bundle
                h.factory.prepare=wrapped
                with self.subTest(phase=phase,role=role),self.assertRaises(v.RetainedQuarantine):h.run()
                self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0 if phase=="before" else 1)
                self.assertFalse(h.coordinator._stage_results)

    def test_capture_mismatch_cannot_be_ignored_to_retry_provider_or_attach(self):
        h=Harness();original=h.run_stage;rejections=[]
        class Permit:
            def start(self,operation):operation()
        def hook(label):
            if label=="run_0":
                provider=h.factory.bundles[0].authority_provider
                provider.task=replace(provider.task,activity_token="abc123")
                provider.before["taskAuthoritySha256"]=hashlib.sha256(provider.task.canonical_bytes()).hexdigest()
        def attempted_retry(**kwargs):
            try:return original(**kwargs)
            except BaseException:
                for action in (
                    lambda:kwargs["authority_provider"].admission(1,Permit()),
                    lambda:kwargs["authority_provider"].capture(None,1,Permit()),
                    lambda:kwargs["frida_provider"].admission(1,Permit()),
                    lambda:kwargs["frida_provider"].attach(c.AUTHORIZED_SERIAL,3141,1,Permit())):
                    with self.assertRaises(v.CoordinatorError):action()
                    rejections.append(True)
                raise
        h.hook=hook;h.deps=replace(h.deps,run_stage=attempted_retry)
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertEqual(len(rejections),4)
        self.assertEqual(h.factory.bundles[0].frida_provider.attach_count,0)

    def test_separate_ordinary_route_is_pinned_at_admission_and_reopen(self):
        h=Harness();h.drift="reopen"
        with self.assertRaises(v.RetainedQuarantine):h.run()
        self.assertEqual(h.log, [])
        for mode in ("stale", "rebased", "substituted"):
            h=Harness()
            if mode == "substituted":
                h.mutators[v.Operation.REOPEN]=lambda value:{**value,"ordinaryRouteAuthoritySha256":"0"*64}
            else:
                def hook(label):
                    if label == "final_absence":
                        if mode == "stale":h.drift="reopen"
                        else:h.ports["reopen"].canonical_bytes=lambda:c.canonical_bytes({"retained":"another-route"})
                h.hook=hook
            with self.subTest(mode=mode),self.assertRaises(v.RetainedQuarantine):h.run()
            if mode != "substituted":self.assertNotIn("ordinary_stock_reopen",h.log)
            self.assertNotIn("verify_unchanged",h.log)

    def test_real_runner_callback_and_worker_cleanup_failures_keep_pen(self):
        for mutate in (lambda f:setattr(f.session, "late_on_seal", True),
                       lambda f:setattr(f.session, "fail_phase", "load"),
                       lambda f:setattr(f, "fail_teardown", True),
                       lambda f:setattr(f, "fail_quiesce", True)):
            h=Harness();h.frida_fault=mutate
            with self.assertRaises(v.RetainedQuarantine):h.run()
            self.assertNotIn("stage_1_left",h.log)
            self.assertNotIn("root_destroy_exact_task",h.log)
            self.assertNotIn("pen_finish",h.log)
            self.assertTrue(h.transport.retained)

    def test_versioned_type_preserving_signed_evidence_codec(self):
        value = {"integer": [-c.MAX_SAFE_INTEGER, -1, 0, 1, c.MAX_SAFE_INTEGER],
                 "string": ["-1", "0", "1"], "boolean": [False, True], "null": None}
        encoded = v.encode_evidence(value)
        self.assertEqual(v.decode_evidence(encoded), value)
        self.assertNotEqual(v.encode_evidence({"x": 1}), v.encode_evidence({"x": "1"}))
        for text in ('{"x":+1}', '{"x":01}', '{"x":-0}', '{"x":1.0}', '{"x":NaN}',
                     '{"x":9007199254740992}', '{"x":-9007199254740992}', '{"x":1,"x":1}'):
            bad = dict(codec="s0-canonical-json-text", version=1, sha256=sha(text), canonicalParts=[text])
            with self.subTest(text=text), self.assertRaises((v.CoordinatorError, c.ContractError)): v.decode_evidence(bad)
        for field, mutation in (("version", True), ("codec", "unknown"), ("canonicalParts", ["{", "}"])):
            bad = v.encode_evidence({}); bad[field] = mutation
            with self.assertRaises((v.CoordinatorError, c.ContractError)): v.decode_evidence(bad)

    def test_four_stages_real_runner_success_and_exact_order(self):
        h = Harness(); result = h.run()
        self.assertEqual(result["status"], "CLEAN")
        self.assertFalse(result["admission"]["admitted"])
        self.assertEqual(h.coordinator.model.phase, "CLEAN")
        self.assertTrue(h.coordinator.ownership.successful)
        self.assertEqual([x.stage_index for x in h.factory.contexts], [0, 1, 2, 3])
        self.assertEqual([x.binding.stage for x in h.factory.contexts], ["FULL", "LEFT", "RIGHT", "FULL"])
        self.assertEqual({x.binding.observer_session_id for x in h.factory.contexts}, {SESSION})
        self.assertEqual(len({x.run_nonce for x in h.factory.contexts}), 4)
        expected = ["preflight", "pen_acquire", "host_start_display", "prelaunch_absence", "root_causal_launch", "root_prove_causal_attach"]
        self.assertEqual(h.log[:6], expected)
        cleanup = ["exact_foreign_task", "host_restore_full_and_begin_close", "root_destroy_exact_task",
            "host_prove_task_absent", "host_ack_absent_release_display", "final_absence", "pen_finish",
            "pen_peer_closed", "independent_pen_reacquire", "ordinary_stock_reopen", "verify_unchanged", "close_exact_private_adb_server"]
        self.assertEqual(h.log[-len(cleanup):], cleanup)
        self.assertEqual(h.peer.state, pen.Lifecycle.RELEASED)
        self.assertFalse(h.transport.retained)
        for operation, deadline, began in h.deadlines:
            if operation in cleanup: self.assertLessEqual(deadline - began, 25_000_000)
        recovered = c.load_canonical(v.VisualCoordinator.recover(h.contract, h.selection, h.journal, h.ownership, h.deps.clock))
        self.assertEqual(recovered["status"], "CLEAN_EVIDENCE_ONLY")
        self.assertEqual(result["selection"],dict(documentUri=h.selection.document_uri,pageIndex=2))
        self.assertEqual(recovered["selection"],result["selection"])
        self.assertEqual(recovered["contractSha256"],result["contractSha256"])
        self.assertEqual(recovered["stageSelectionSha256"],result["stageSelectionSha256"])
        self.assertEqual(len(set(result["stageSelectionSha256"])),4)
        self.assertIn("REQUESTED_PAGE_TO_RAW_GRAPH_INDEX_HARDWARE_CALIBRATION_REQUIRED",result["admission"]["blockers"])
        self.assertFalse(recovered["resumeAllowed"])
        self.assertIn("REVIEWED_INDEPENDENT_DURABLE_STAGE_CREATION_OWNER_REQUIRED",result["admission"]["blockers"])
        checkpoint=h.ownership.load_checkpoint()
        with h.ownership.exclusive():prefix=v._ownership_prefix(h.ownership.read,checkpoint)
        records=h.coordinator._journal.records
        self.assertTrue(v._replay_creations(records,h.contract.value,prefix,checkpoint)["complete"])
        retired=[index for index,record in enumerate(records) if record["event"]=="s8_inventory_retired"]
        self.assertEqual(len(retired),4)
        for attack in ("retirement_duplicate","retirement_omitted","retirement_reordered","retirement_checkpoint_copy",
                       "closure_omitted","ownership_omitted","materialization_omitted"):
            with self.subTest(creation_transition=attack):
                changed=copy.deepcopy(records)
                if attack=="retirement_duplicate":changed.insert(retired[0]+1,copy.deepcopy(changed[retired[0]]))
                if attack=="retirement_omitted":changed.pop(retired[0])
                if attack=="retirement_reordered":changed[retired[0]],changed[retired[1]]=changed[retired[1]],changed[retired[0]]
                if attack=="retirement_checkpoint_copy":
                    owned=next(record for record in records if record["event"]=="s8_owned" and record["data"]["role"]=="authority_worker")
                    changed[retired[0]]["data"]["checkpoint"]=copy.deepcopy(owned["data"]["checkpoint"])
                event={"closure_omitted":"s8_owner_closed","ownership_omitted":"s8_owned","materialization_omitted":"s8_creation_materialized"}.get(attack)
                if event:changed.pop(next(index for index,record in enumerate(changed) if record["event"]==event and
                    (event=="s8_creation_materialized" or record["data"].get("key")=="authority_worker:0")))
                with self.assertRaises(v.CoordinatorError):v._replay_creations(changed,h.contract.value,prefix,checkpoint)

    def test_stock_process_may_live_or_be_absent_and_nullable_mark(self):
        for stock, mark in ((True, False), (False, True), (False, False)):
            with self.subTest(stock=stock, mark=mark): self.assertEqual(Harness(stock=stock, mark=mark).run()["status"], "CLEAN")

    def test_hardware_entry_never_uses_dependency(self):
        h = Harness()
        with self.assertRaises(v.AdmissionBlocked): h.coordinator.execute()
        self.assertEqual(h.log, [])
        self.assertIn("FROZEN_RUNNER_REMOTE_CLEANUP_BUDGET_UNPROVEN", v.admission_status()["blockers"])

    def test_every_operation_failure_and_crash_forbids_later_dispatch(self):
        baseline = Harness(); baseline.run()
        for mode in ("fail", "crash"):
            for edge in dict.fromkeys(baseline.log):
                h = Harness(); setattr(h, mode, edge)
                with self.subTest(mode=mode, edge=edge), self.assertRaises(v.RetainedQuarantine): h.run()
                self.assertEqual(h.log[-1], edge)
                calls = list(h.log)
                with self.assertRaises(v.CoordinatorError): h.run()
                self.assertEqual(h.log, calls)
                recovered = c.load_canonical(v.VisualCoordinator.recover(h.contract, h.selection, h.journal, h.ownership, h.deps.clock))
                self.assertEqual(recovered["status"], "RETAINED_QUARANTINE")
                self.assertFalse(recovered["resumeAllowed"])

    def test_preexisting_task_or_activity_any_display_blocks_before_pen(self):
        for name in ("documentTasks", "documentActivities"):
            h = Harness()
            h.mutators[v.Operation.PREFLIGHT] = lambda value, n=name: {**value,
                "prechecked": {**value["prechecked"], n: ["preexisting-display-7"]}}
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertEqual(h.log, ["preflight"])

    def test_launch_without_attach_never_becomes_disposable(self):
        for edge in ("root_causal_launch", "root_prove_causal_attach"):
            h = Harness(); h.fail = edge
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertIsNone(h.coordinator.model.disposable_foreign)
            self.assertNotIn("foreign_task", h.coordinator._identities)
            self.assertNotIn("root_destroy_exact_task", h.log)
            self.assertTrue(h.transport.retained)

    def test_reused_pid_task_display_or_migration_retains_quarantine(self):
        mutations = [
            (v.Operation.ATTACH, lambda x: {**x, "foreign": {**x["foreign"], "taskId": 42}}),
            (v.Operation.ATTACH, lambda x: {**x, "foreign": {**x["foreign"], "process": {**x["foreign"]["process"],
                "identity": {**x["foreign"]["process"]["identity"], "incarnation": BOOT + ":9999"}}}}),
            (v.Operation.HOST_START, lambda x: {**x, "display": {**x["display"], "generation": 10}}),
            (v.Operation.ATTACH, lambda x: {**x, "displayZeroDocumentTasks": [41]}),
            (v.Operation.EXACT_TASK, lambda x: {**x, "status": "absent"}),
            (v.Operation.TASK_ABSENT, lambda x: {**x, "noMigrationToDisplayZero": False}),
            (v.Operation.FINAL_ABSENCE, lambda x: {**x, "foreignSurfaceAbsent": False}),
        ]
        for operation, mutation in mutations:
            with self.subTest(operation=operation):
                h = Harness(); h.mutators[operation] = mutation
                with self.assertRaises(v.RetainedQuarantine): h.run()
                self.assertNotIn("pen_finish", h.log)
                self.assertNotIn("ordinary_stock_reopen", h.log)

    def test_result_and_capture_replay_or_stage_rotation_rejected(self):
        h = Harness(); h.deps = replace(h.deps, nonce=lambda: "9" * 64); h.coordinator.deps = h.deps
        with self.assertRaises(v.RetainedQuarantine): h.run()
        for changed in ("observerSessionId", "absoluteMonotonicDeadlineNs"):
            h = Harness()
            def mutate(value, index):
                value["coordinator"][changed] = "f" * 64 if changed == "observerSessionId" else "9999999999"
                return value
            h.manifest_mutator = mutate
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertNotIn("run_0", h.log)

    def test_native_page_geometry_and_writer_equivalence_across_all_stages(self):
        for area, field, value in (("document", "rawCurrentPage", 3), ("presenter", "rawPresenterPage", 3),
                                   ("pageInfo", "offset", [12, -7])):
            h = Harness()
            def mutate(snapshot, index):
                if index == 1: snapshot[area][field] = value
                return snapshot
            h.snapshot_mutator = mutate
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertNotIn("stage_2_right", h.log)

    def test_deadline_suspend_and_pen_release_gates(self):
        for edge, delay in (("prepare_0", 1_000_000_000), ("run_0", 1_000_000_000),
                            ("exact_foreign_task", 25_000_000), ("pen_finish", 25_000_000)):
            h = Harness(); h.delays[edge] = delay
            with self.subTest(edge=edge), self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertNotIn("ordinary_stock_reopen", h.log)
        h = Harness(); h.pen_mutate = lambda raw: raw.replace(b"device_boottime_ms=10001", b"device_boottime_ms=60000")
        with self.assertRaises(v.RetainedQuarantine): h.run()
        self.assertNotIn("host_start_display", h.log)

    def test_duplicate_unknown_partial_stale_and_bool_alias_receipts(self):
        for mutation in (lambda raw:raw[:-1], lambda raw:raw + b"{}", lambda raw:b'{"a":1,"a":2}',
                         lambda raw:raw.replace(b'"authority":', b'"unknown":0,"authority":')):
            h = Harness(); h.raw_mutate = mutation
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertEqual(h.log, ["preflight"])
        for mutation in (lambda x:{**x, "observedHostNs":"1"}, lambda x:{**x, "commandId":"replay"},
                         lambda x:{**x, "runSessionId":"f" * 64}):
            h = Harness(); h.envelope_mutator = mutation
            with self.assertRaises(v.RetainedQuarantine): h.run()
        h = Harness(); h.mutators[v.Operation.REACQUIRE] = lambda x:{**x, "independentDeviceReacquireProven":1}
        with self.assertRaises(v.RetainedQuarantine): h.run()
        self.assertNotIn("ordinary_stock_reopen", h.log)

    def test_final_pdf_mark_savedink_cannot_change(self):
        for role in ("pdf", "mark", "savedInkSha256"):
            h = Harness()
            def mutate(value):
                if role == "savedInkSha256": value[role] = "0" * 64
                else: value[role]["sha256"] = "0" * 64
                return value
            h.mutators[v.Operation.UNCHANGED] = mutate
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertFalse(h.coordinator.ownership.finalized)

    def test_concurrent_entry_and_authority_drift_fail_closed(self):
        h = Harness(); entered = threading.Event(); release = threading.Event(); errors=[]
        def hook(label):
            if label == "preflight": entered.set(); release.wait(1)
        h.hook = hook
        def run():
            try:h.run()
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1))
        with self.assertRaises(v.CoordinatorError):h.run()
        release.set();thread.join(60);self.assertFalse(thread.is_alive());self.assertEqual(errors, [])
        for role in ("reader", "host", "supervisor", "stages"):
            h = Harness(); h.drift = role
            with self.assertRaises(v.RetainedQuarantine): h.run()
            self.assertEqual(h.log, [])

    def test_s5b_power_publication_faults_keep_intent_without_dispatch(self):
        # Exercise every Win32 edge of one real journal transaction, both before
        # and after its action, using S5b's independently implemented power fake.
        base = Harness(); base.coordinator; start = len(base.api.log)
        base.coordinator._intent("diagnostic-boundary", {"exact": "scope"}, 2_000_000_000)
        edges = len(base.api.log) - start
        for relative in range(1, edges + 1):
            for when in ("before", "after"):
                h=Harness(); h.coordinator; h.api.fault=(len(h.api.log)+relative, when)
                try:h.coordinator._intent("diagnostic-boundary", {"exact": "scope"}, 2_000_000_000)
                except BaseException: pass
                self.assertEqual(h.log, [])
                self.assertFalse(h.coordinator._journal.usable)
                h.api.crash()
                # Torn/pending external checkpoints may deliberately prevent
                # opening; that is an explicit fail-closed recovery result.
                try:
                    events=WindowsCleanupStore.open_existing(h.journal.authority, api=h.api)
                    owned=WindowsCleanupStore.open_existing(h.ownership.authority, api=h.api)
                    result=c.load_canonical(v.VisualCoordinator.recover(h.contract,h.selection,events,owned,h.deps.clock))
                    self.assertEqual(result["status"], "RETAINED_QUARANTINE")
                except (ledger.LedgerError, v.CoordinatorError, OSError): pass


if __name__ == "__main__": unittest.main()
