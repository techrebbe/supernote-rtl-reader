"""Offline S0 tests; only exact named reference files are read for AST checks."""

import ast
import copy
from dataclasses import FrozenInstanceError
import hashlib
import itertools
from pathlib import Path
import unittest

import native_page_coordinator_contracts as c


BOOT = "11111111-2222-4333-8444-555555555555"
CLOCK = "host-clock-incarnation-0001"
SESSION = "a" * 64
HOST_SESSION = "host-session-0000000000000001"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def resource(kind, key, incarnation="incarnation-0001", namespace=c.AUTHORIZED_SERIAL):
    return c.ResourceIdentity(kind, namespace, key, incarnation).wire()


def process(pid=201, ticks=10201):
    return dict(identity=resource("process", str(pid), BOOT + ":" + str(ticks)),
                package=c.PACKAGE_NAME, uid=1000)


def fixtures(mark=True):
    def file(name):
        return dict(identity=resource("file", name), sha256=sha(name), size=123)
    return dict(pdf=file("disposable.pdf"), mark=file("disposable.pdf.mark") if mark else None,
                savedInkSha256=sha("saved-ink"), uriResolutionSha256=sha("uri-resolution"))


def plan(mark=True):
    return c.RunContract.create(run_session_id=SESSION, host_session_id=HOST_SESSION,
        created=c.HostInstant(CLOCK, 1_000_000_000), deadline=c.HostInstant(CLOCK, 20_000_000_000),
        fixtures=fixtures(mark))


class Trace:
    """Authenticated-proof *fixtures*, not mocks of a real device/provider."""

    def __init__(self, stock=True, mark=True):
        self.contract = plan(mark)
        self.model = c.CoordinatorModel(self.contract)
        self.ns = 1_000_000_000
        self.device_ms = 1000
        self.stock = process() if stock else None
        self.foreign_process = process()
        self.display = dict(identity=resource("virtual_display", "6", HOST_SESSION + ":1"),
                            displayId=6, generation=1, hostSessionId=HOST_SESSION)
        self.foreign = dict(process=self.foreign_process, taskId=77, activityToken="a12b",
                            component=c.COMPONENT, display=self.display)
        incarnation = HOST_SESSION + ":1:a12b:" + c.digest(self.foreign_process)
        self.foreign["identity"] = resource("android_task", "77", incarnation)
        self.pen = dict(observerSessionId=SESSION, leaseToken=sha("lease"),
                        peer=resource("process", "400", BOOT + ":10400"),
                        worker=resource("process", "401", BOOT + ":10401"),
                        guardian=resource("process", "402", BOOT + ":10402"),
                        guardianSession=sha("guardian-session"), deviceClockDomain=c.DEVICE_CLOCK_DOMAIN,
                        absoluteDeviceBoottimeExpiryMs="50000")
        self.started = None

    def raw(self, kind, body, observed=None):
        sequence, previous = self.model.event_head
        return c.canonical_bytes(dict(authority=c.EVENT_AUTHORITY, schemaVersion=1,
            contractSha256=self.contract.sha256, runSessionId=SESSION, sequence=sequence + 1,
            previousEventSha256=previous, observedHostNs=str(self.ns if observed is None else observed),
            kind=kind, body=body))

    def emit(self, kind, body, advance=1_000_000):
        self.ns += advance
        return self.model.apply(self.raw(kind, body), c.HostInstant(CLOCK, self.ns))

    def precheck(self):
        return dict(serial=c.AUTHORIZED_SERIAL, documentTasks=[], documentActivities=[],
                    stockProcess=self.stock, evidenceSha256=sha("initial-absence"),
                    fixtures=self.contract.value["fixtures"])

    def acquire(self):
        return dict(beforeAbsenceSha256=sha("initial-absence"), penBinding=self.pen, deviceBoottimeMs="1000")

    def launch(self):
        return dict(commandId="launch_foreign_document", component=c.COMPONENT, display=self.display,
                    beforeAbsenceSha256=sha("initial-absence"), prelaunchAbsenceSha256=sha("fresh-absence"),
                    documentTasks=[], documentActivities=[], commandSha256=sha("launch-command"),
                    fixtureSha256=self.contract.value["fixtures"]["pdf"]["sha256"])

    def attach(self):
        return dict(foreign=self.foreign, launchCommandSha256=sha("launch-command"),
                    prelaunchAbsenceSha256=sha("fresh-absence"),
                    causalLaunchProofSha256=sha("causal-proof"), hostAttachAckSha256=sha("attach-ack"),
                    documentTasks=[self.foreign["identity"]], documentActivities=["a12b"],
                    displayZeroDocumentTasks=[], displayZeroDocumentActivities=[])

    def reach(self, phase):
        events = [
            ("prechecked", self.precheck(), "PRECHECKED"),
            ("pen_acquired", self.acquire(), "PEN_BLOCKED"),
            ("display_ready", dict(display=self.display, evidenceSha256=sha("display-ready")), "DISPLAY_READY"),
            ("foreign_launch_recorded", self.launch(), "LAUNCH_UNPROVEN"),
            ("foreign_attached", self.attach(), "ONE_NATIVE_TASK_BOUND"),
        ]
        for kind, body, target in events:
            self.emit(kind, body)
            if target == phase:
                return self
        raise AssertionError("unknown fixture phase")

    def start_body(self, index=None):
        index = self.model.stage_index if index is None else index
        issued = self.ns + 1_000_000
        self.device_ms += 1
        return dict(stage=self.contract.value["stages"][index],
            window=dict(clockId=CLOCK, issuedNs=str(issued), absoluteNs=str(issued + 1_000_000_000),
                        hardDeadlineMs=1000, noRetry=True),
            runNonce=sha("nonce-" + str(index)), manifestSha256=sha("manifest-" + str(index)),
            placementAckSha256=sha("placement-" + str(index)), penBinding=self.pen,
            deviceBoottimeMs=str(self.device_ms), foreign=self.foreign)

    def start(self):
        self.started = self.start_body()
        return self.emit("capture_started", self.started)

    def complete_body(self):
        index = self.model.stage_index
        before = sha("before-" + str(index))
        self.device_ms += 1
        return dict(stage=self.started["stage"], runNonce=self.started["runNonce"],
            manifestSha256=self.started["manifestSha256"], beforeSequence=1, afterSequence=2,
            beforeReceiptSha256=before, afterPreviousReceiptSha256=before,
            afterReceiptSha256=sha("after-" + str(index)),
            beforeInvariantSha256=sha("stable-authorities-" + str(index)),
            afterInvariantSha256=sha("stable-authorities-" + str(index)),
            beforeGraphSha256=sha("stable-native-graph"), afterGraphSha256=sha("stable-native-graph"),
            quiescenceSha256=sha("frida-quiescence-" + str(index)),
            retainedAuthoritySha256=sha("retained-authorities-" + str(index)),
            stageLedgerRecordSha256=sha("stage-ledger-" + str(index)),
            durableCheckpointSha256=sha("stage-checkpoint-" + str(index)),
            penBinding=self.pen, deviceBoottimeMs=str(self.device_ms), foreign=self.foreign)

    def complete(self):
        return self.emit("capture_completed", self.complete_body())

    def observe_all(self):
        self.reach("ONE_NATIVE_TASK_BOUND")
        for _ in range(4):
            self.start()
            self.complete()
        return self

    def fail(self):
        return self.emit("failure", dict(reason="injected-primary-failure", evidenceSha256=sha("failure")))

    def begin_cleanup(self):
        return self.emit("begin_cleanup", dict(primaryFailure=bool(self.model.failures),
                                               evidenceSha256=sha("cleanup-begin")))

    def cleanup_body(self, index, *, foreign=True, display=True, pen=True):
        task = self.foreign if foreign else None
        disp = self.display if display else None
        lease = self.pen if pen else None
        details = [
            dict(callbacksSealed=True, unloaded=True, detached=True, isolatedWorkersClosed=True),
            dict(foreign=task, placement="FULL", performed=foreign),
            dict(foreign=task, display=disp, exactTaskAbsent=True, hostAcknowledgedAbsent=True,
                 noMigrationToDisplayZero=True),
            dict(display=disp, exactDisplayAbsent=True, hostSessionQuiescent=True, noMigrationToDisplayZero=True),
            dict(stockProcess=self.foreign_process if foreign else self.stock, documentTasks=[],
                 documentActivities=[], foreignDisplayAbsent=True, foreignSurfaceAbsent=True,
                 foreignHelpersClosed=True),
            dict(penBinding=lease, authenticatedReleased=pen, sealedControlAndPhaseBeforeRelease=pen,
                 workerGuardianPeerClosed=True, independentDeviceReacquireProven=pen),
            dict(component=c.COMPONENT, displayId=0, process=self.foreign_process,
                 fixtureSha256=self.contract.value["fixtures"]["pdf"]["sha256"],
                 ordinaryRouteAuthoritySha256=sha("ordinary-route")),
            self.contract.value["fixtures"],
        ][index]
        step, owner = c.CLEANUP_STEPS[index]
        return dict(stepIndex=index, stepId=step, owner=owner,
                    evidenceSha256=sha("cleanup-" + str(index)),
                    intentRecordSha256=sha("intent-" + str(index)),
                    completionRecordSha256=sha("completion-" + str(index)),
                    durableCheckpointSha256=sha("cleanup-checkpoint-" + str(index)), attempt=1, details=details)

    def clean(self, **options):
        self.begin_cleanup()
        for index in range(8):
            self.emit("cleanup_step", self.cleanup_body(index, **options))
        return self.model.phase


class CanonicalTests(unittest.TestCase):
    def test_pdf_mark_retained_slot_alias_rejected_across_incarnations(self):
        for incarnation in ("incarnation-0001", "changed-incarnation", BOOT + ":999"):
            for changed_bytes in (False, True):
                value = plan().value
                value["fixtures"]["mark"]["identity"] = copy.deepcopy(value["fixtures"]["pdf"]["identity"])
                value["fixtures"]["mark"]["identity"]["incarnation"] = incarnation
                if changed_bytes:
                    value["fixtures"]["mark"]["sha256"] = sha("replacement-bytes")
                    value["fixtures"]["mark"]["size"] += 1
                with self.subTest(incarnation=incarnation, changed_bytes=changed_bytes), self.assertRaises(c.ContractError):
                    c.RunContract(c.canonical_bytes(value))

    def test_distinct_pdf_mark_slots_may_share_incarnation(self):
        value = plan().value
        self.assertEqual(value["fixtures"]["pdf"]["identity"]["incarnation"],
                         value["fixtures"]["mark"]["identity"]["incarnation"])
        c.RunContract(c.canonical_bytes(value))
        value["fixtures"]["mark"]["identity"]["key"] = value["fixtures"]["pdf"]["identity"]["key"]
        value["fixtures"]["mark"]["identity"]["namespace"] = "independent-retained-file-namespace"
        c.RunContract(c.canonical_bytes(value))

    def test_roundtrip_and_immutability(self):
        contract = plan()
        self.assertEqual(c.RunContract(contract.raw), contract)
        value = contract.value
        value["stages"][0]["rect"][0] = 5
        self.assertEqual(contract.value["stages"][0]["rect"][0], 0)
        with self.assertRaises(FrozenInstanceError):
            contract.raw = b"{}"

    def test_wire_rejects_duplicate_type_encoding_and_topology(self):
        bad = [b'{"a":1,"a":1}', b'{"a":{"b":1,"b":2}}', b'{"a":1.0}', b'{"a":NaN}',
               b'{"a":Infinity}', b'{"a":-0}', b' {"a":1}', b'{"a":1}\n', b'\xef\xbb\xbf{}',
               b'"\\u0061"', b'"\\u0000"', b'"\\ud800"', b'"e\\u0301"', b'\xff', b'',
               b'[' * 1000 + b'0' + b']' * 1000, b'"' + b'a' * c.MAX_WIRE_BYTES + b'"',
               b'{"number":' + b'9' * 5000 + b'}']
        for raw in bad:
            with self.subTest(raw=raw[:60]), self.assertRaises(c.ContractError):
                c.load_canonical(raw)

    def test_exact_builtins_and_safe_integers(self):
        class IntChild(int):
            pass
        class DictChild(dict):
            pass
        for bad in [1.0, float("nan"), IntChild(1), DictChild(), (1, 2), {1: "x"},
                    1 << 53, -(1 << 53), object(), "\x00", "e\u0301"]:
            with self.subTest(value=type(bad)), self.assertRaises(c.ContractError):
                c.canonical_bytes(bad)
        self.assertEqual(c.load_canonical(c.canonical_bytes({"x": [True, None, -1]})), {"x": [True, None, -1]})

    def test_unknown_missing_fields_at_every_plan_object(self):
        baseline = plan().value

        def dictionaries(item, path=()):
            if type(item) is dict:
                yield path
                for key, child in item.items():
                    yield from dictionaries(child, path + (key,))
            elif type(item) is list:
                for index, child in enumerate(item):
                    yield from dictionaries(child, path + (index,))

        tested = 0
        for path in dictionaries(baseline):
            for mutation in ("unknown", "missing"):
                value = copy.deepcopy(baseline)
                target = value
                for key in path:
                    target = target[key]
                if mutation == "unknown":
                    target["unreviewed"] = True
                elif target:
                    del target[next(iter(target))]
                else:
                    continue
                with self.subTest(path=path, mutation=mutation), self.assertRaises(c.ContractError):
                    c.RunContract(c.canonical_bytes(value))
                tested += 1
        self.assertGreater(tested, 50)

    def test_fixed_fields_cannot_be_coerced_or_overridden(self):
        baseline = plan().value
        for section in ("target", "host", "canvas", "policy", "authorities"):
            for key in baseline[section]:
                for replacement in (None, False, True, 1, "unreviewed", [], {}):
                    value = copy.deepcopy(baseline)
                    if c.canonical_bytes(value[section][key]) == c.canonical_bytes(replacement):
                        continue
                    value[section][key] = replacement
                    with self.subTest(section=section, key=key, replacement=replacement), self.assertRaises(c.ContractError):
                        c.RunContract(c.canonical_bytes(value))

    def test_schema_session_and_fixture_types(self):
        for key, replacement in [("schemaVersion", True), ("runnerSchemaVersion", True),
                                 ("runSessionId", "A" * 64), ("hostSessionId", "short"),
                                 ("hostClockId", ""), ("createdHostNs", 1),
                                 ("absoluteRunDeadlineNs", "01"), ("authority", "other")]:
            value = plan().value
            value[key] = replacement
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.RunContract(c.canonical_bytes(value))
        for size in (True, -1, "123"):
            value = plan().value
            value["fixtures"]["pdf"]["size"] = size
            with self.assertRaises(c.ContractError):
                c.RunContract(c.canonical_bytes(value))
        self.assertIsNone(plan(False).value["fixtures"]["mark"])


class StageTests(unittest.TestCase):
    def test_all_stage_permutations_except_identity_rejected(self):
        for order in itertools.permutations(range(4)):
            value = plan().value
            value["stages"] = [value["stages"][index] for index in order]
            if order == (0, 1, 2, 3):
                c.RunContract(c.canonical_bytes(value))
            else:
                with self.subTest(order=order), self.assertRaises(c.ContractError):
                    c.RunContract(c.canonical_bytes(value))

    def test_stage_rotation_duplicate_ids_indices_and_geometry_rejected(self):
        mutations = [
            (0, "stageIndex", True), (0, "stageIndex", 1), (1, "commandId", "stage_0_full"),
            (3, "rect", [0, 0, 1404, 1872]), (3, "orientation", "PORTRAIT"),
            (1, "physicalSize", [1404, 1872]), (2, "rect", [935, 78, 936, 1248]),
            (2, "observerSessionId", "b" * 64), (3, "commandId", "stage_0_full"),
        ]
        for index, field, replacement in mutations:
            value = plan().value
            value["stages"][index][field] = replacement
            with self.subTest(index=index, field=field), self.assertRaises(c.ContractError):
                c.RunContract(c.canonical_bytes(value))

    def test_four_stages_and_shared_session_reach_clean_but_never_admitted(self):
        trace = Trace().observe_all()
        self.assertEqual(trace.model.stage_index, 4)
        self.assertEqual(trace.clean(), "CLEAN")
        self.assertIsNone(trace.model.disposable_foreign)
        self.assertEqual(trace.model.failures, ())
        self.assertFalse(c.admission_status()["admitted"])

    def test_runner_binding_exact_shape_with_shared_session(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        for index in range(4):
            trace.start()
            binding = trace.model.runner_binding_kwargs()
            self.assertEqual(set(binding), {"serial", "pid", "start_time_ticks", "observer_session_id",
                                           "deadline_ms", "absolute_deadline_ns", "stage"})
            self.assertEqual(binding["observer_session_id"], SESSION)
            self.assertEqual(binding["stage"], ("FULL", "LEFT", "RIGHT", "FULL")[index])
            trace.complete()

    def test_nonce_replay_receipt_chain_and_per_stage_binding_mutations(self):
        for key, replacement in [("beforeSequence", True), ("afterSequence", 1),
                                 ("afterPreviousReceiptSha256", sha("wrong")),
                                 ("runNonce", sha("wrong")), ("manifestSha256", sha("wrong")),
                                 ("afterGraphSha256", sha("changed")), ("afterInvariantSha256", sha("changed")),
                                 ("afterReceiptSha256", sha("before-0"))]:
            trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
            trace.start()
            body = trace.complete_body()
            body[key] = replacement
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                trace.emit("capture_completed", body)
            self.assertEqual(trace.model.phase, "FAILED")
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.start()
        old_nonce = trace.started["runNonce"]
        trace.complete()
        body = trace.start_body()
        body["runNonce"] = old_nonce
        with self.assertRaises(c.ContractError):
            trace.emit("capture_started", body)

    def test_graph_invariant_cannot_change_between_stages(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.start()
        trace.complete()
        trace.start()
        body = trace.complete_body()
        body["beforeGraphSha256"] = body["afterGraphSha256"] = sha("new-graph")
        with self.assertRaises(c.ContractError):
            trace.emit("capture_completed", body)


class IdentityTests(unittest.TestCase):
    def test_resource_set_rejects_duplicate_owners_and_pid_incarnations(self):
        identity = c.ResourceIdentity.parse(process()["identity"])
        stock = c.ResourceBinding("stock_process", "stock_reader", identity)
        pen = c.ResourceBinding("pen_worker", "pen_peer", identity)
        reused = c.ResourceBinding("stock_process", "stock_reader", c.ResourceIdentity.parse(process(ticks=999)["identity"]))
        for bindings in ((stock, stock), (stock, pen), (stock, reused), [stock]):
            with self.assertRaises(c.ContractError):
                c.validate_resource_bindings(bindings)
        self.assertEqual(c.validate_resource_bindings((stock,)), (stock,))

    def test_resources_match_exact_owner_and_protect_non_generic_roles(self):
        for role, (kind, owner) in c.RESOURCE_OWNERS.items():
            identity = c.ResourceIdentity(kind, c.AUTHORIZED_SERIAL, "201" if kind == "process" else "resource",
                                          BOOT + ":12345" if kind == "process" else "incarnation")
            bound = c.ResourceBinding(role, owner, identity)
            if role in c.GENERIC_CLEANUP_ROLES:
                bound.require_generic_cleanup(owner)
            else:
                with self.subTest(role=role), self.assertRaises(c.ContractError):
                    bound.require_generic_cleanup(owner)
            with self.assertRaises(c.ContractError):
                bound.require_generic_cleanup("wrong-owner")
            with self.assertRaises(c.ContractError):
                c.ResourceBinding(role, "wrong-owner", identity)

    def test_pid_reuse_boot_identity_and_weak_identity_rejected(self):
        identity = c.ResourceIdentity.parse(process()["identity"])
        reused = c.ResourceIdentity.parse(process(ticks=10202)["identity"])
        self.assertNotEqual(identity.resource_id, reused.resource_id)
        with self.assertRaises(c.ContractError):
            resource("process", "0201", BOOT + ":123")
        with self.assertRaises(c.ContractError):
            c.ResourceBinding("stock_process", "stock_reader",
                              c.ResourceIdentity.parse(resource("file", "201", "123")))
        for start in ("123", BOOT + ":0", BOOT.upper() + ":1", BOOT + ":01"):
            if start == BOOT.upper() + ":1":
                # This fixture UUID contains no alphabetic hex; use one that does.
                start = "AAAAAAAA-2222-4333-8444-555555555555:1"
            with self.subTest(start=start), self.assertRaises(c.ContractError):
                c.ResourceIdentity("process", c.AUTHORIZED_SERIAL, "201", start)

    def test_stock_process_may_live_but_document_tasks_or_activities_must_not(self):
        for stock in (True, False):
            self.assertEqual(Trace(stock).reach("ONE_NATIVE_TASK_BOUND").model.phase, "ONE_NATIVE_TASK_BOUND")
        for field in ("documentTasks", "documentActivities"):
            trace = Trace()
            body = trace.precheck()
            body[field] = [{"displayId": 0, "component": c.COMPONENT}]
            with self.subTest(field=field), self.assertRaises(c.ContractError):
                trace.emit("prechecked", body)

    def test_fresh_prelaunch_absence_no_ambient_task_reuse(self):
        for field in ("documentTasks", "documentActivities"):
            trace = Trace().reach("DISPLAY_READY")
            body = trace.launch()
            body[field] = [{"displayId": 0, "component": c.COMPONENT}]
            with self.assertRaises(c.ContractError):
                trace.emit("foreign_launch_recorded", body)
            self.assertIsNone(trace.model.disposable_foreign)

    def test_foreign_task_disposable_only_after_exact_causal_attach(self):
        trace = Trace().reach("LAUNCH_UNPROVEN")
        self.assertIsNone(trace.model.disposable_foreign)
        trace.emit("foreign_attached", trace.attach())
        self.assertEqual(trace.model.disposable_foreign, trace.foreign)
        copy_of_foreign = trace.model.disposable_foreign
        copy_of_foreign["taskId"] = 999
        self.assertEqual(trace.model.disposable_foreign["taskId"], 77)

    def test_every_attach_binding_edge(self):
        mutations = [
            ("launchCommandSha256", sha("other-command")), ("prelaunchAbsenceSha256", sha("stale")),
            ("causalLaunchProofSha256", None), ("hostAttachAckSha256", ""),
            ("documentTasks", []), ("documentActivities", ["a12b", "c34d"]),
            ("displayZeroDocumentTasks", [77]), ("displayZeroDocumentActivities", ["a12b"]),
        ]
        for key, value in mutations:
            trace = Trace().reach("LAUNCH_UNPROVEN")
            body = trace.attach()
            body[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                trace.emit("foreign_attached", body)
            self.assertIsNone(trace.model.disposable_foreign)
            trace.begin_cleanup()
            self.assertTrue(trace.model.retained_quarantine)

    def test_identity_swap_during_attach(self):
        for mutate in (lambda item: item["process"]["identity"].update(incarnation=BOOT + ":99999"),
                       lambda item: item.update(taskId=78),
                       lambda item: item.update(activityToken="d00d"),
                       lambda item: item["display"].update(displayId=0),
                       lambda item: item["process"].update(uid=True)):
            trace = Trace().reach("LAUNCH_UNPROVEN")
            body = copy.deepcopy(trace.attach())
            mutate(body["foreign"])
            with self.assertRaises(c.ContractError):
                trace.emit("foreign_attached", body)
            self.assertIsNone(trace.model.disposable_foreign)

    def test_pen_owner_alias_reboot_or_session_rotation_rejected(self):
        mutations = [lambda pen: pen.update(observerSessionId="b" * 64),
                     lambda pen: pen.update(guardian=pen["worker"]),
                     lambda pen: pen.update(deviceClockDomain="host-monotonic"),
                     lambda pen: pen["peer"].update(incarnation="aaaaaaaa-2222-4333-8444-555555555555:1"),
                     lambda pen: pen["worker"].update(key="1")]
        for mutate in mutations:
            trace = Trace().reach("PRECHECKED")
            body = copy.deepcopy(trace.acquire())
            mutate(body["penBinding"])
            with self.assertRaises(c.ContractError):
                trace.emit("pen_acquired", body)


class DeadlineTests(unittest.TestCase):
    def test_cleanup_start_at_and_after_run_deadline_retains_every_live_binding(self):
        for phase in ("PEN_BLOCKED", "DISPLAY_READY", "LAUNCH_UNPROVEN", "ONE_NATIVE_TASK_BOUND"):
            for lateness in (0, 1, 10_000_000_000):
                trace = Trace().reach(phase)
                trace.fail()
                retained = copy.deepcopy((trace.model._pen, trace.model._display, trace.model._launch,
                                          trace.model._foreign, trace.model._active))
                head = trace.model.event_head
                trace.ns = int(trace.contract.value["absoluteRunDeadlineNs"]) + 250_000_000 + lateness
                with self.subTest(phase=phase, lateness=lateness), self.assertRaises(c.ContractError):
                    trace.emit("begin_cleanup", dict(primaryFailure=True, evidenceSha256=sha("late-cleanup")), advance=0)
                self.assertTrue(trace.model.retained_quarantine)
                self.assertEqual(trace.model.phase, "QUARANTINED")
                self.assertEqual(trace.model.event_head, head)
                self.assertEqual((trace.model._pen, trace.model._display, trace.model._launch,
                                  trace.model._foreign, trace.model._active), retained)
                self.assertIsNone(trace.model._cleanup_deadline)
                self.assertEqual(trace.model._cleanup_index, 0)
                with self.assertRaises(c.ContractError):
                    trace.emit("cleanup_step", trace.cleanup_body(2), advance=0)
                self.assertTrue(trace.model.retained_quarantine)

    def test_cleanup_start_at_and_after_stage_deadline_uses_no_new_budget(self):
        for stage_completed in (False, True):
            for lateness in (0, 1, 1_000_000_000):
                trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
                trace.start()
                if stage_completed:
                    trace.complete()
                trace.fail()
                deadline = int(trace.started["window"]["absoluteNs"]) + 250_000_000
                trace.ns = deadline + lateness
                with self.subTest(completed=stage_completed, lateness=lateness), self.assertRaises(c.ContractError):
                    trace.emit("begin_cleanup", dict(primaryFailure=True, evidenceSha256=sha("expired-stage-cleanup")), advance=0)
                self.assertTrue(trace.model.retained_quarantine)
                self.assertEqual(trace.model._pen, trace.pen)
                self.assertEqual(trace.model._display, trace.display)
                self.assertEqual(trace.model._foreign, trace.foreign)
                self.assertIsNone(trace.model._cleanup_deadline)
                # A later request cannot reset the deadline by presenting an older sample.
                raw = trace.raw("begin_cleanup", dict(primaryFailure=True, evidenceSha256=sha("retry")), observed=deadline - 1)
                with self.assertRaises(c.ContractError):
                    trace.model.apply(raw, c.HostInstant(CLOCK, deadline - 1))
                self.assertTrue(trace.model.retained_quarantine)

    def test_last_nanosecond_cleanup_start_allowed_but_deadline_not_extended(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.start()
        trace.fail()
        deadline = int(trace.started["window"]["absoluteNs"]) + 250_000_000
        trace.ns = deadline - 1
        self.assertEqual(trace.emit("begin_cleanup", dict(primaryFailure=True, evidenceSha256=sha("last-nanosecond")),
                                    advance=0), "CLEANING")
        self.assertEqual(trace.model._cleanup_deadline, deadline)
        with self.assertRaises(c.ContractError):
            trace.emit("cleanup_step", trace.cleanup_body(0), advance=1)
        self.assertTrue(trace.model.retained_quarantine)

    def test_expired_cleanup_without_owned_live_obligation_is_failed_not_success(self):
        trace = Trace().reach("PRECHECKED")
        trace.fail()
        trace.ns = int(trace.contract.value["absoluteRunDeadlineNs"]) + 250_000_000
        with self.assertRaises(c.ContractError):
            trace.emit("begin_cleanup", dict(primaryFailure=True, evidenceSha256=sha("no-owned-resources")), advance=0)
        self.assertEqual(trace.model.phase, "FAILED")
        self.assertFalse(trace.model.retained_quarantine)
        self.assertIsNone(trace.model._cleanup_deadline)

    def test_unstartable_cleanup_quarantines_retained_obligations(self):
        for change in (lambda event: event["body"].update(primaryFailure=True),
                       lambda event: event["body"].update(unknown=True),
                       lambda event: event.update(contractSha256=sha("wrong-contract")),
                       lambda event: event.update(sequence=True)):
            trace = Trace().reach("PEN_BLOCKED")
            event = c.load_canonical(trace.raw("begin_cleanup", dict(primaryFailure=False, evidenceSha256=sha("unstartable"))))
            change(event)
            with self.assertRaises(c.ContractError):
                trace.model.apply(c.canonical_bytes(event), c.HostInstant(CLOCK, trace.ns))
            self.assertTrue(trace.model.retained_quarantine)
            self.assertEqual(trace.model._pen, trace.pen)
            self.assertEqual(trace.model._cleanup_index, 0)

    def test_typed_clock_domains_and_bounds(self):
        expiry = c.DeviceBoottime(2000)
        self.assertEqual(c.remaining_device_ms(expiry, c.DeviceBoottime(1500)), 500)
        for now in (c.HostInstant(CLOCK, 1500), 1500, True, c.DeviceBoottime(2000)):
            with self.assertRaises(c.ContractError):
                c.remaining_device_ms(expiry, now)
        deadline = c.HostDeadline(CLOCK, 100, 250_000_100, 250)
        for now in (c.DeviceBoottime(101), c.HostInstant("other-clock-000001", 101), c.HostInstant(CLOCK, 250_000_100)):
            with self.assertRaises(c.ContractError):
                deadline.require_live(now)
        for amount in (True, 249, 10001):
            with self.assertRaises(c.ContractError):
                c.HostDeadline(CLOCK, 1, 2, amount)

    def test_suspend_consumes_device_lease_independently_of_host(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        body = trace.start_body()
        body["deviceBoottimeMs"] = "49900"
        with self.assertRaises(c.ContractError):
            trace.emit("capture_started", body)
        self.assertEqual(trace.model.phase, "FAILED")

    def test_suspend_expiry_after_proof_before_event_publication(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.start()
        body = trace.complete_body()
        raw = trace.raw("capture_completed", body)
        now = c.HostInstant(CLOCK, int(trace.started["window"]["absoluteNs"]))
        with self.assertRaises(c.ContractError):
            trace.model.apply(raw, now)
        self.assertEqual(trace.model.stage_index, 0)
        self.assertEqual(trace.model.phase, "FAILED")

    def test_expired_stage_allows_only_original_bounded_cleanup_no_deadline_reset(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.start()
        trace.ns = int(trace.started["window"]["absoluteNs"])
        with self.assertRaises(c.ContractError):
            trace.complete()
        trace.begin_cleanup()
        trace.ns = int(trace.started["window"]["absoluteNs"]) + 250_000_000
        with self.assertRaises(c.ContractError):
            trace.emit("cleanup_step", trace.cleanup_body(0), advance=0)
        self.assertTrue(trace.model.retained_quarantine)

    def test_backwards_host_and_device_samples(self):
        trace = Trace().reach("PRECHECKED")
        raw = trace.raw("pen_acquired", trace.acquire(), observed=trace.ns - 1)
        with self.assertRaises(c.ContractError):
            trace.model.apply(raw, c.HostInstant(CLOCK, trace.ns))
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        body = trace.start_body()
        body["deviceBoottimeMs"] = "999"
        with self.assertRaises(c.ContractError):
            trace.emit("capture_started", body)

    def test_window_issue_time_no_retry_and_cross_clock_mutations(self):
        for field, value in [("clockId", "other-clock-0000001"), ("issuedNs", "1"),
                             ("hardDeadlineMs", True), ("noRetry", False),
                             ("absoluteNs", "999999999999999999999")]:
            trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
            body = trace.start_body()
            body["window"][field] = value
            with self.subTest(field=field), self.assertRaises(c.ContractError):
                trace.emit("capture_started", body)


class TransitionCleanupTests(unittest.TestCase):
    def test_oversized_integer_is_sticky_failure_not_uncaught_parser_error(self):
        trace = Trace()
        raw = b'{"number":' + b'9' * 5000 + b'}'
        with self.assertRaises(c.ContractError):
            trace.model.apply(raw, c.HostInstant(CLOCK, trace.ns))
        self.assertEqual(trace.model.phase, "FAILED")

    def test_cleanup_no_retry_and_durable_record_references_required(self):
        for field, value in (("attempt", 2), ("attempt", True), ("durableCheckpointSha256", None),
                             ("completionRecordSha256", sha("intent-0"))):
            trace = Trace().observe_all()
            trace.begin_cleanup()
            body = trace.cleanup_body(0)
            body[field] = value
            with self.subTest(field=field), self.assertRaises(c.ContractError):
                trace.emit("cleanup_step", body)
            self.assertTrue(trace.model.retained_quarantine)

    def test_invalid_event_at_every_edge_sticky_failure_and_no_retry(self):
        for phase in ("PRECHECKED", "PEN_BLOCKED", "DISPLAY_READY", "LAUNCH_UNPROVEN", "ONE_NATIVE_TASK_BOUND"):
            trace = Trace().reach(phase)
            with self.subTest(phase=phase), self.assertRaises(c.ContractError):
                trace.emit("prechecked", trace.precheck())
            self.assertEqual(trace.model.phase, "FAILED")
            with self.assertRaises(c.ContractError):
                trace.emit("capture_started", trace.start_body())

    def test_event_envelope_unknown_duplicate_replay_type_and_binding(self):
        for key, value in [("schemaVersion", True), ("sequence", True), ("sequence", 2),
                           ("runSessionId", "b" * 64), ("contractSha256", sha("wrong-contract")),
                           ("previousEventSha256", sha("other-head")), ("unknown", 1)]:
            trace = Trace()
            event = c.load_canonical(trace.raw("prechecked", trace.precheck()))
            event[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                trace.model.apply(c.canonical_bytes(event), c.HostInstant(CLOCK, trace.ns))
        trace = Trace()
        raw = trace.raw("prechecked", trace.precheck())
        trace.model.apply(raw, c.HostInstant(CLOCK, trace.ns))
        with self.assertRaises(c.ContractError):
            trace.model.apply(raw, c.HostInstant(CLOCK, trace.ns))

    def test_uncertain_orphan_launch_retains_quarantine_no_destroy_authority(self):
        trace = Trace().reach("LAUNCH_UNPROVEN")
        trace.fail()
        self.assertEqual(trace.begin_cleanup(), "QUARANTINED")
        self.assertIsNone(trace.model.disposable_foreign)
        with self.assertRaises(c.ContractError):
            trace.emit("cleanup_step", trace.cleanup_body(2))

    def test_failure_cleanup_cannot_erase_primary_failure(self):
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.fail()
        self.assertEqual(trace.clean(), "CLEANED_WITH_ERRORS")
        self.assertTrue(trace.model.failures)
        self.assertFalse(c.admission_status()["admitted"])

    def test_prelaunch_failure_uses_proven_absence_not_task_kill(self):
        trace = Trace().reach("PRECHECKED")
        trace.fail()
        self.assertEqual(trace.clean(foreign=False, display=False, pen=False), "CLEANED_WITH_ERRORS")

    def test_cleanup_every_owner_index_and_order_edge(self):
        for index in range(8):
            for field, replacement in (("owner", "generic_cleanup"), ("stepIndex", index + 1),
                                       ("stepId", "finish_pen_lease" if index != 5 else "destroy_foreign_task")):
                trace = Trace().observe_all()
                trace.begin_cleanup()
                for previous in range(index):
                    trace.emit("cleanup_step", trace.cleanup_body(previous))
                body = trace.cleanup_body(index)
                body[field] = replacement
                with self.subTest(index=index, field=field), self.assertRaises(c.ContractError):
                    trace.emit("cleanup_step", body)
                self.assertTrue(trace.model.retained_quarantine)

    def test_cleanup_exact_identity_absence_and_pen_terminal_edges(self):
        mutations = [
            (0, "callbacksSealed", False), (0, "isolatedWorkersClosed", False),
            (1, "placement", "LEFT"), (2, "exactTaskAbsent", False),
            (2, "hostAcknowledgedAbsent", False), (2, "noMigrationToDisplayZero", False),
            (3, "exactDisplayAbsent", False), (3, "hostSessionQuiescent", False),
            (4, "documentTasks", [77]), (4, "foreignSurfaceAbsent", False),
            (5, "authenticatedReleased", False), (5, "sealedControlAndPhaseBeforeRelease", False),
            (5, "workerGuardianPeerClosed", False), (5, "independentDeviceReacquireProven", False),
            (6, "displayId", 6), (6, "component", c.HOST_COMPONENT),
            (7, "savedInkSha256", sha("modified-ink")),
        ]
        for index, field, value in mutations:
            trace = Trace().observe_all()
            trace.begin_cleanup()
            for previous in range(index):
                trace.emit("cleanup_step", trace.cleanup_body(previous))
            body = trace.cleanup_body(index)
            body["details"][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(c.ContractError):
                trace.emit("cleanup_step", body)
            self.assertTrue(trace.model.retained_quarantine)

    def test_reopen_cannot_precede_task_display_absence_or_pen_closure(self):
        for completed_cleanup_steps in range(6):
            trace = Trace().observe_all()
            trace.begin_cleanup()
            for index in range(completed_cleanup_steps):
                trace.emit("cleanup_step", trace.cleanup_body(index))
            with self.subTest(completed=completed_cleanup_steps), self.assertRaises(c.ContractError):
                trace.emit("cleanup_step", trace.cleanup_body(6))

    def test_nullable_mark_and_unchanged_file_resource_identity(self):
        self.assertEqual(Trace(mark=False).observe_all().clean(), "CLEAN")
        trace = Trace().observe_all()
        trace.begin_cleanup()
        for index in range(7):
            trace.emit("cleanup_step", trace.cleanup_body(index))
        body = trace.cleanup_body(7)
        body["details"]["pdf"]["identity"]["incarnation"] = "replacement-file"
        with self.assertRaises(c.ContractError):
            trace.emit("cleanup_step", body)


class AdmissionAndReferenceTests(unittest.TestCase):
    def test_blockers_are_permanent_and_callers_cannot_mutate_shared_state(self):
        status = c.admission_status()
        self.assertEqual(status["cleanupBudget"], {"totalMs": 250, "perCallMs": 25,
                                                  "remoteAdbFridaHardwareProven": False})
        self.assertIn("REVIEWED_MUTATING_PRIVATE_ADB_OWNER_UNAVAILABLE", status["blockers"])
        self.assertEqual(len(status["mutatingPrivateAdb"]["capabilities"]), 5)
        status["admitted"] = True
        status["blockers"].clear()
        self.assertFalse(c.admission_status()["admitted"])
        self.assertEqual(len(c.admission_status()["blockers"]), 3)
        value = plan().value
        value["policy"]["admission"]["cleanupBudget"]["remoteAdbFridaHardwareProven"] = True
        with self.assertRaises(c.ContractError):
            c.RunContract(c.canonical_bytes(value))

    def test_frozen_runner_constant_and_binding_conformance_without_import(self):
        source = Path(__file__).with_name("native_page_graph_v2_runner.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        values = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    values[node.targets[0].id] = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    pass
        for name in ("AUTHORIZED_SERIAL", "PACKAGE_NAME", "APK_SHA256", "FRAMEWORK_SHA256",
                     "EXPECTED_OBSERVER_SHA256", "FIRMWARE_FINGERPRINT", "CLEANUP_TIMEOUT_MS",
                     "CLEANUP_STEP_TIMEOUT_MS", "MIN_DEADLINE_MS", "MAX_DEADLINE_MS"):
            self.assertEqual(getattr(c, name), values[name], name)
        self.assertEqual(c.RUNNER_SCHEMA_VERSION, values["SCHEMA_VERSION"])
        for key, constant in {
            "runner": "RUNNER", "manifest": "MANIFEST", "snapshot": "SNAPSHOT", "coordinator": "COORDINATOR",
            "externalSession": "EXTERNAL_SESSION", "calibration": "CALIBRATION", "file": "FILE",
            "providerAdmission": "PROVIDER_ADMISSION", "stage": "STAGE", "stageReceipt": "STAGE_RECEIPT",
            "stagePolicy": "STAGE_POLICY", "target": "TARGET", "host": "HOST", "pen": "PEN_LEASE",
            "adbServer": "ADB_SERVER", "frida": "FRIDA",
        }.items():
            self.assertEqual(c.AUTHORITIES[key], values[constant + "_AUTHORITY"])
        binding = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "StageBinding")
        fields = {node.target.id for node in binding.body if isinstance(node, ast.AnnAssign)}
        trace = Trace().reach("ONE_NATIVE_TASK_BOUND")
        trace.start()
        self.assertEqual(set(trace.model.runner_binding_kwargs()), fields)
        self.assertEqual(tuple(plan().value["canvas"][key] for key in ("width", "height", "densityDpi", "rotation")),
                         tuple(values[key] for key in ("VIRTUAL_DISPLAY_WIDTH", "VIRTUAL_DISPLAY_HEIGHT",
                                                      "VIRTUAL_DISPLAY_DENSITY_DPI", "VIRTUAL_DISPLAY_ROTATION")))

    def test_s1_s5_identity_authority_conformance_without_import(self):
        parent = Path(__file__).parent
        for filename, expected in (("native_page_private_adb.py", c.AUTHORITIES["privateAdb"]),
                                   ("native_page_windows_tool_authority.py", c.AUTHORITIES["windowsTools"])):
            tree = ast.parse((parent / filename).read_text(encoding="utf-8"))
            authority = next(node.value.value for node in tree.body if isinstance(node, ast.Assign) and
                             any(isinstance(target, ast.Name) and target.id == "AUTHORITY" for target in node.targets))
            self.assertEqual(authority, expected)
        tree = ast.parse((parent / "native_page_cleanup_ledger.py").read_text(encoding="utf-8"))
        identity = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ResourceIdentity")
        fields = [node.target.id for node in identity.body if isinstance(node, ast.AnnAssign)]
        self.assertEqual(fields, ["kind", "namespace", "key", "incarnation"])

    def test_module_has_no_production_io_import_or_dynamic_evaluation(self):
        tree = ast.parse(Path(c.__file__).read_text(encoding="utf-8"))
        allowed = {"dataclasses", "hashlib", "json", "re", "types", "unicodedata"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name in allowed for alias in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, allowed)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "exec", "eval", "compile", "__import__"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
