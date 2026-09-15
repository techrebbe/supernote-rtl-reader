"""Synthetic-only tests for native_page_visual_task_adapter.

No test opens a socket, starts a process, reads a file, or contacts Android.
The fake backend implements only the fixed protocol and returns constructed
ActivityManager/process evidence.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import threading
import unittest

import native_page_android_authority as android
import native_page_host_authority as host
import native_page_visual_session_harness as harness
import native_page_visual_task_adapter as task


SESSION = "12345678-1234-4234-8234-123456789abc"
BOOT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SERIAL = harness.AUTHORIZED_SERIAL
URI = (
    "file:///storage/emulated/0/Download/"
    "NativeViewportVisualOnly-task-adapter-test.pdf"
)
FIXTURE_SHA = "2" * 64
DISPLAY = 7
TASK_ID = 41
ACTIVITY_TOKEN = "11846f4"
PROCESS = host.ProcessIdentity(3141, 9_000_001, android.SYSTEM_UID,
                               android.PACKAGE)
CLOCK_INSTANCE = "6" * 64
CLOCK_DOMAIN = "7" * 64


def live_activity_wire(*, process: host.ProcessIdentity = PROCESS,
                       task_id: int = TASK_ID, display_id: int = DISPLAY,
                       token: str = ACTIVITY_TOKEN,
                       base_apk: str = task.STOCK_BASE_APK_PATH,
                       duplicate: bool = False) -> bytes:
    block = f"""Display #{display_id} (activities from top to bottom):
  Stack #{task_id}: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{{token} u0 {android.SHORT_COMPONENT} t{task_id}}}
    * Task{{66d8263 #{task_id} visible=true type=standard mode=fullscreen translucent=true A=1000:{android.PACKAGE} U=0 StackId={task_id} sz=1}}
      taskId={task_id} stackId={task_id}
      * Hist #0: ActivityRecord{{{token} u0 {android.SHORT_COMPONENT} t{task_id}}}
          packageName={android.PACKAGE} processName={android.PROCESS}
          app=ProcessRecord{{2083011 {process.pid}:{android.PROCESS}/{process.uid}}}
          mActivityComponent={android.SHORT_COMPONENT}
          baseDir={base_apk}
          CurrentConfiguration={{1.0 en_US 300dpi port winConfig={{ mBounds=Rect(0, 0 - 1404, 1872) mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}} s.186}}
          state=RESUMED stopped=false delayedResume=false finishing=false
          mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
          nowVisible=true lastVisibleTime=-1s
"""
    second = ""
    if duplicate:
        second = block.replace(f"Display #{display_id}", f"Display #{display_id + 1}", 1)
    return ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            "Display areas in focus order:\n"
            "Display #0 (activities from top to bottom):\n" + block +
            second).encode("utf-8")


def absent_activity_wire(extra: str = "") -> bytes:
    return ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            "Display #0 (activities from top to bottom):\n" +
            extra).encode("utf-8")


class FakeClock:
    def __init__(self, value: int = 10_000_000_000):
        self.value = value
        self.instance = CLOCK_INSTANCE
        self.domain = CLOCK_DOMAIN
        self.bad = False
        self.drift = False
        self.stall = False
        self.reads = 0
        self.jump_on_read: int | None = None
        self.jump_amount = 0

    def verify(self) -> None:
        if self.bad:
            raise RuntimeError("retained clock verification failed")

    def canonical_bytes(self) -> bytes:
        value = {
            "authority": task.CLOCK_AUTHORITY,
            "schemaVersion": 1,
            "clockInstanceId": ("8" * 64 if self.drift else self.instance),
            "monotonicDomainSha256": self.domain,
            "source": task.CLOCK_SOURCE,
            "retainedAuthority": True,
            "nanosecondDomain": True,
            "wallClock": False,
        }
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii")

    def monotonic_domain_identity(self) -> str:
        return self.domain

    def now_ns(self) -> int:
        self.reads += 1
        if self.jump_on_read == self.reads:
            self.value += self.jump_amount
        if not self.stall:
            self.value += 1
        return self.value

    def advance(self, amount: int = 1) -> int:
        self.value += amount
        return self.value


def valid_plan(clock: FakeClock) -> task.ExactFixtureTaskPlan:
    return task.ExactFixtureTaskPlan(
        SESSION, SERIAL, URI, FIXTURE_SHA, CLOCK_DOMAIN, DISPLAY,
        clock.value + 100_000_000, 10_000_000)


def valid_binding() -> task.TaskBackendBinding:
    return task.TaskBackendBinding(
        authority=task.BACKEND_AUTHORITY,
        backend_instance_id="1" * 64,
        serial=SERIAL,
        boot_id=BOOT,
        private_adb_session_id="3" * 64,
        private_adb_endpoint="tcp:127.0.0.1:47321",
        private_adb_pid=5100,
        private_adb_start_ticks=1001,
        worker_session_id="4" * 64,
        worker_pid=5200,
        worker_start_ticks=1002,
        worker_image_sha256="5" * 64,
        retained_private_adb_handle=True,
        retained_worker_handle=True,
        private_socket=True,
        explicit_serial_every_operation=True,
        fixed_operations_only=True,
        accepts_general_commands=False,
        accepts_caller_argv=False,
        fresh_reply_channel_per_operation=True,
        late_reply_channel_sealed_before_return=True,
        failure_returns_after_operation_quiescence=True,
        dispatch_witness_required=True,
        exact_fixture_uri_sha_gate=True,
        exact_display_gate=True,
        explicit_nonexported_component_only=True,
        compare_identity_before_remove=True,
        exact_task_id_remove_only=True,
        complete_activity_manager_capture=True,
        exact_stock_process_liveness_capture=True,
        broad_cleanup_capability=False,
        process_kill_capability=False,
    )


class FakeBackend:
    def __init__(self, clock: FakeClock):
        self.clock = clock
        self.base_binding = valid_binding()
        self.drift = False
        self.drift_on_launch = False
        self.drift_on_remove = False
        self.launch_mode = "ok"
        self.remove_mode = "ok"
        self.launch_mutator = lambda value: value
        self.remove_mutator = lambda value: value
        self.quiescence_mutator = lambda value: value
        self.live_raw = live_activity_wire()
        self.pre_remove_raw: bytes | None = None
        self.post_remove_raw: bytes | None = None
        self.final_raw: bytes | None = None
        self.launch_process_mutator = lambda value: value
        self.pre_process_mutator = lambda value: value
        self.post_process_mutator = lambda value: value
        self.final_process_mutator = lambda value: value
        self.operation_quiescence_error = False
        self.all_quiescence_error = False
        self.calls: list[str] = []
        self.quiesced: list[str] = []
        self.task_present = False
        self.saved_witness = None
        self.adapter: task.NativePageVisualTaskAdapter | None = None
        self.substitute_owner_after_verify: FakeBackend | None = None
        self.substitute_owner_after_launch: FakeBackend | None = None
        self.reentrant_error: BaseException | None = None

    def binding(self):
        return (replace(self.base_binding, worker_start_ticks=1003)
                if self.drift else self.base_binding)

    def verify(self, expected):
        if expected != self.base_binding:
            raise RuntimeError("unexpected retained binding")
        if self.substitute_owner_after_verify is not None:
            assert self.adapter is not None
            self.adapter._backend_adapter = self.substitute_owner_after_verify

    def _process(self, captured_ns: int) -> task.StockProcessEvidence:
        return task.StockProcessEvidence(
            task.PROCESS_EVIDENCE_AUTHORITY, SERIAL, BOOT, captured_ns,
            PROCESS, android.PROCESS, task.PROCESS_SOURCE,
            task.SHELL_UID, task.SHELL_GID, True, True, True, True, 0)

    @staticmethod
    def _ack(request: task.TaskOperationRequest,
             produced_ns: int) -> task.TaskOperationAck:
        return task.TaskOperationAck(
            task.ACK_AUTHORITY, request.session_id, request.serial,
            request.boot_id, request.operation, request.operation_id,
            request.sequence, request.sha256, request.issued_ns, produced_ns)

    def launch_exact_nonexported_document(self, request, plan, witness):
        self.calls.append("launch")
        self.saved_witness = witness
        if self.launch_mode == "raise_before":
            raise RuntimeError("backend rejected before dispatch")
        if self.launch_mode == "reenter":
            try:
                assert self.adapter is not None
                self.adapter.verify()
            except BaseException as error:
                self.reentrant_error = error
        if self.launch_mode == "no_witness":
            dispatched = self.clock.value
        else:
            dispatched = witness()
        self.task_present = True
        if self.launch_mode == "double_witness":
            try:
                witness()
            except BaseException:
                pass
        if self.launch_mode == "raise_after":
            raise RuntimeError("reply lost after dispatch")
        if self.launch_mode == "overrun":
            self.clock.value = request.deadline_ns
        else:
            self.clock.advance()
        captured = self.clock.value
        process = self.launch_process_mutator(self._process(captured))
        result = task.LaunchBackendReceipt(
            self._ack(request, captured), plan.fixture_uri,
            plan.fixture_sha256, plan.display_id, host.FOREIGN_COMPONENT,
            task.ACTION_VIEW, task.MIME_PDF, task.LAUNCH_ROUTE,
            dispatched, captured, self.live_raw, process,
            True, False, True, True, False, False, False, False)
        if self.drift_on_launch:
            self.drift = True
        if self.substitute_owner_after_launch is not None:
            assert self.adapter is not None
            self.adapter._backend_adapter = self.substitute_owner_after_launch
        return self.launch_mutator(result)

    def remove_exact_retained_task(self, request, foreign, witness):
        self.calls.append("remove")
        self.saved_witness = witness
        if self.remove_mode == "raise_before":
            raise RuntimeError("backend rejected removal before dispatch")
        pre_captured = self.clock.value
        pre_process = self.pre_process_mutator(self._process(pre_captured))
        pre_raw = self.pre_remove_raw or self.live_raw
        if self.remove_mode == "no_witness":
            dispatched = self.clock.value
        else:
            dispatched = witness()
        self.task_present = False
        if self.remove_mode == "raise_after":
            raise RuntimeError("removal reply lost")
        if self.remove_mode == "overrun":
            self.clock.value = request.deadline_ns
        else:
            self.clock.advance()
        post_captured = self.clock.value
        post_process = self.post_process_mutator(self._process(post_captured))
        post_raw = (self.post_remove_raw if self.post_remove_raw is not None
                    else absent_activity_wire())
        result = task.DestroyBackendReceipt(
            self._ack(request, post_captured), foreign, foreign.task_id,
            task.REMOVE_ROUTE, pre_captured, dispatched, post_captured,
            pre_raw, post_raw, pre_process, post_process,
            True, True, False, False, False, False, False, False)
        if self.drift_on_remove:
            self.drift = True
        return self.remove_mutator(result)

    def prove_exact_task_absent(self, request, foreign):
        self.calls.append("observe")
        self.clock.advance()
        captured = self.clock.value
        process = self.final_process_mutator(self._process(captured))
        raw = (self.final_raw if self.final_raw is not None else
               (self.live_raw if self.task_present else absent_activity_wire()))
        value = task.QuiescenceBackendReceipt(
            self._ack(request, captured), foreign, captured, raw, process,
            True, 0, False, False)
        return self.quiescence_mutator(value)

    def assert_operation_quiescent(self, expected, operation_id, deadline_ns):
        self.quiesced.append(operation_id)
        if expected != self.base_binding:
            raise RuntimeError("binding differs")
        if self.operation_quiescence_error:
            raise RuntimeError("operation did not quiesce")

    def assert_all_quiescent(self, expected, deadline_ns):
        self.calls.append("all_quiescent")
        if expected != self.base_binding or self.all_quiescence_error:
            raise RuntimeError("all operations did not quiesce")


def make_adapter():
    clock = FakeClock()
    plan = valid_plan(clock)
    backend = FakeBackend(clock)
    adapter = task.NativePageVisualTaskAdapter(
        plan=plan, backend=backend, clock=clock)
    backend.adapter = adapter
    return adapter, backend, clock, plan


def launch(adapter, plan):
    return adapter.launch_fixture(
        plan.serial, plan.fixture_uri, plan.fixture_sha256,
        plan.display_id, plan.absolute_deadline_ns)


def close(adapter, plan, foreign):
    return adapter.destroy_exact_task(
        plan.serial, foreign, plan.absolute_deadline_ns)


class PlanAndBindingTests(unittest.TestCase):
    def test_status_remains_hardware_blocked(self):
        status = task.admission_status()
        self.assertFalse(status["admitted"])
        self.assertFalse(status["realFixedBackendImplemented"])
        self.assertFalse(status["hardwareTimingProven"])
        self.assertTrue(status["blockers"])

    def test_plan_rejects_uri_command_text_and_wrong_scope(self):
        clock = FakeClock()
        candidates = (
            replace(valid_plan(clock), serial="OTHER"),
            replace(valid_plan(clock), fixture_uri=URI + ";id"),
            replace(valid_plan(clock), fixture_sha256="A" * 64),
            replace(valid_plan(clock), display_id=0),
            replace(valid_plan(clock), operation_budget_ns=0),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(task.TaskAdapterError):
                    candidate.validate()

    def test_constructor_rejects_ambient_or_general_command_backend(self):
        clock = FakeClock()
        plan = valid_plan(clock)
        for bad in (
                replace(valid_binding(), private_adb_endpoint="tcp:127.0.0.1:5037"),
                replace(valid_binding(), accepts_general_commands=True),
                replace(valid_binding(), accepts_caller_argv=True),
                replace(valid_binding(), broad_cleanup_capability=True),
                replace(valid_binding(), process_kill_capability=True),
                replace(valid_binding(), exact_task_id_remove_only=False)):
            backend = FakeBackend(clock)
            backend.base_binding = bad
            with self.subTest(bad=bad):
                with self.assertRaises(task.TaskAdapterError):
                    task.NativePageVisualTaskAdapter(
                        plan=plan, backend=backend, clock=clock)

    def test_constructor_rejects_expired_or_unbounded_deadline(self):
        clock = FakeClock()
        backend = FakeBackend(clock)
        with self.assertRaises(task.TaskAdapterError):
            task.NativePageVisualTaskAdapter(
                plan=replace(valid_plan(clock),
                             absolute_deadline_ns=clock.value),
                backend=backend, clock=clock)
        with self.assertRaises(task.TaskAdapterError):
            task.NativePageVisualTaskAdapter(
                plan=replace(valid_plan(clock), absolute_deadline_ns=
                             clock.value + task.MAX_TOTAL_BUDGET_NS + 2),
                backend=backend, clock=clock)

    def test_constructor_requires_exact_retained_clock_authority_and_domain(self):
        cases = ("wrong_domain", "bad_verify", "malformed_canonical")
        for case in cases:
            clock = FakeClock()
            plan = valid_plan(clock)
            backend = FakeBackend(clock)
            if case == "wrong_domain":
                plan = replace(plan, monotonic_domain_sha256="8" * 64)
            elif case == "bad_verify":
                clock.bad = True
            else:
                clock.instance = "not-a-sha256"
            with self.subTest(case=case):
                with self.assertRaises(task.TaskAdapterError):
                    task.NativePageVisualTaskAdapter(
                        plan=plan, backend=backend, clock=clock)

    def test_clock_authority_is_pinned_in_adapter_identity(self):
        adapter, _, _, _ = make_adapter()
        value = json.loads(adapter.canonical_bytes())
        self.assertEqual(value["monotonicDomainSha256"], CLOCK_DOMAIN)
        expected_clock = FakeClock().canonical_bytes()
        self.assertEqual(value["clockAuthoritySha256"],
                         hashlib.sha256(expected_clock).hexdigest())


class LaunchTests(unittest.TestCase):
    def test_harness_runtime_display_binding_keeps_adapter_pin_stable(self):
        clock = FakeClock()
        plan = replace(valid_plan(clock), display_id=None)
        backend = FakeBackend(clock)
        adapter = task.NativePageVisualTaskAdapter(
            plan=plan, backend=backend, clock=clock)
        backend.adapter = adapter
        before = adapter.canonical_bytes()
        receipt = adapter.launch_fixture(
            SERIAL, URI, FIXTURE_SHA, DISPLAY, plan.absolute_deadline_ns)
        self.assertEqual(receipt.foreign.task_id, TASK_ID)
        self.assertEqual(adapter.canonical_bytes(), before)

    def test_exact_launch_derives_foreign_and_stable_evidence(self):
        adapter, backend, _, plan = make_adapter()
        before = adapter.canonical_bytes()
        receipt = launch(adapter, plan)
        self.assertIs(type(receipt), harness.LaunchReceipt)
        self.assertEqual(receipt.foreign.process, PROCESS)
        self.assertEqual(receipt.foreign.task_id, TASK_ID)
        self.assertEqual(receipt.foreign.activity_token, ACTIVITY_TOKEN)
        parsed = android.parse_document_task_authority(
            backend.live_raw, expected_pid=PROCESS.pid)
        self.assertEqual(receipt.foreign.evidence_sha256,
                         android.stable_authority_sha256(parsed))
        self.assertFalse(receipt.broad_scope_used)
        self.assertFalse(receipt.process_kill_used)
        evidence = json.loads(receipt.launch_evidence)
        self.assertEqual(evidence["fixtureUri"], URI)
        self.assertFalse(evidence["attestation"]["componentExported"])
        self.assertFalse(evidence["attestation"]["callerCommandInputUsed"])
        self.assertFalse(evidence["hardwareTimingProven"])
        self.assertEqual(adapter.canonical_bytes(), before)
        self.assertEqual(adapter.state, "LIVE")
        self.assertEqual(len(backend.quiesced), 1)

    def test_caller_scope_mutations_never_reach_backend(self):
        mutations = (
            ("OTHER", URI, FIXTURE_SHA, DISPLAY),
            (SERIAL, URI + ";rm", FIXTURE_SHA, DISPLAY),
            (SERIAL, URI, "3" * 64, DISPLAY),
            (SERIAL, URI, FIXTURE_SHA, DISPLAY + 1),
            (SERIAL, URI, FIXTURE_SHA, True),
        )
        for values in mutations:
            adapter, backend, _, plan = make_adapter()
            with self.subTest(values=values):
                with self.assertRaises(task.LaunchNotDispatched) as caught:
                    adapter.launch_fixture(
                        *values, plan.absolute_deadline_ns)
                self.assertFalse(caught.exception.side_effect_possible)
                self.assertEqual(backend.calls, [])
                self.assertEqual(adapter.state, "LAUNCH_NOT_DISPATCHED")

    def test_deadline_mutation_and_expiry_do_not_dispatch(self):
        adapter, backend, clock, plan = make_adapter()
        with self.assertRaises(task.LaunchNotDispatched):
            adapter.launch_fixture(SERIAL, URI, FIXTURE_SHA, DISPLAY,
                                   plan.absolute_deadline_ns - 1)
        self.assertEqual(backend.calls, [])
        adapter, backend, clock, plan = make_adapter()
        clock.value = plan.absolute_deadline_ns
        with self.assertRaises(task.LaunchNotDispatched):
            launch(adapter, plan)
        self.assertEqual(backend.calls, [])

    def test_backend_failure_before_witness_is_proven_not_dispatched(self):
        adapter, backend, _, plan = make_adapter()
        backend.launch_mode = "raise_before"
        with self.assertRaises(task.LaunchNotDispatched) as caught:
            launch(adapter, plan)
        self.assertFalse(caught.exception.side_effect_possible)
        self.assertFalse(backend.task_present)
        self.assertEqual(len(backend.quiesced), 1)
        self.assertEqual(adapter.cleanup_obligations, ())

    def test_backend_failure_after_witness_is_uncertain(self):
        adapter, backend, _, plan = make_adapter()
        backend.launch_mode = "raise_after"
        with self.assertRaises(task.LaunchOutcomeUncertain) as caught:
            launch(adapter, plan)
        self.assertTrue(caught.exception.side_effect_possible)
        self.assertIsNone(caught.exception.retained_foreign)
        self.assertTrue(backend.task_present)
        self.assertEqual(adapter.state, "LAUNCH_UNCERTAIN_UNKNOWN")
        self.assertTrue(adapter.cleanup_obligations)

    def test_launch_uncertainty_is_harness_typed_immutable_bounded_evidence(self):
        adapter, backend, _, plan = make_adapter()
        backend.launch_mutator = lambda receipt: replace(
            receipt, component_exported=True)
        with self.assertRaises(task.LaunchOutcomeUncertain) as caught:
            launch(adapter, plan)
        error = caught.exception
        self.assertIsInstance(error, harness.TaskLaunchOutcomeUncertain)
        self.assertIsNotNone(error.retained_foreign)
        evidence = json.loads(error.evidence)
        self.assertEqual(evidence["authority"],
                         harness.TASK_LAUNCH_UNCERTAINTY_AUTHORITY)
        self.assertEqual(evidence["retainedForeign"]["task"], TASK_ID)
        with self.assertRaises(AttributeError):
            error.retained_foreign = None

    def test_substituted_drifting_stalled_or_offset_clock_never_dispatches(self):
        for case in ("substitute", "drift", "domain", "verify", "stall",
                     "offset"):
            adapter, backend, clock, plan = make_adapter()
            if case == "substitute":
                adapter._clock = FakeClock(clock.value)
            elif case == "drift":
                clock.drift = True
            elif case == "domain":
                clock.domain = "8" * 64
            elif case == "verify":
                clock.bad = True
            elif case == "stall":
                clock.stall = True
            else:
                clock.jump_on_read = clock.reads + 2
                clock.jump_amount = plan.operation_budget_ns + 1
            with self.subTest(case=case):
                with self.assertRaises(task.LaunchNotDispatched):
                    launch(adapter, plan)
                self.assertEqual(backend.calls, [])
                self.assertFalse(backend.task_present)

    def test_same_binding_backend_substitution_never_receives_dispatch(self):
        for case in ("before_verify", "during_verify"):
            adapter, backend, clock, plan = make_adapter()
            substitute = FakeBackend(clock)
            if case == "before_verify":
                adapter._backend_adapter = substitute
            else:
                backend.substitute_owner_after_verify = substitute
            with self.subTest(case=case):
                with self.assertRaises(task.LaunchNotDispatched) as caught:
                    launch(adapter, plan)
                self.assertFalse(caught.exception.side_effect_possible)
                self.assertEqual(backend.calls, [])
                self.assertEqual(substitute.calls, [])
                self.assertFalse(backend.task_present)
                self.assertFalse(substitute.task_present)

    def test_backend_substitution_after_real_dispatch_is_uncertain_and_sealed(self):
        adapter, backend, clock, plan = make_adapter()
        substitute = FakeBackend(clock)
        backend.substitute_owner_after_launch = substitute
        with self.assertRaises(task.LaunchOutcomeUncertain) as caught:
            launch(adapter, plan)
        self.assertTrue(caught.exception.side_effect_possible)
        self.assertTrue(backend.task_present)
        self.assertFalse(substitute.task_present)
        self.assertEqual(backend.calls, ["launch"])
        self.assertEqual(substitute.calls, [])
        self.assertEqual(adapter.state, "LAUNCH_UNCERTAIN_UNKNOWN")

    def test_success_without_witness_and_repeated_witness_are_uncertain(self):
        for mode in ("no_witness", "double_witness"):
            adapter, backend, _, plan = make_adapter()
            backend.launch_mode = mode
            with self.subTest(mode=mode):
                with self.assertRaises(task.LaunchOutcomeUncertain):
                    launch(adapter, plan)
                self.assertTrue(backend.task_present)
                self.assertEqual(adapter.state, "LAUNCH_UNCERTAIN_UNKNOWN")

    def test_operation_quiescence_failure_and_deadline_overrun_are_uncertain(self):
        adapter, backend, _, plan = make_adapter()
        backend.operation_quiescence_error = True
        with self.assertRaises(task.LaunchOutcomeUncertain):
            launch(adapter, plan)
        adapter, backend, _, plan = make_adapter()
        backend.launch_mode = "overrun"
        with self.assertRaises(task.LaunchOutcomeUncertain):
            launch(adapter, plan)

    def test_strict_activity_mutations_fail_after_dispatch(self):
        mutations = (
            live_activity_wire(display_id=DISPLAY + 1),
            live_activity_wire(process=replace(PROCESS, pid=PROCESS.pid + 1)),
            live_activity_wire(base_apk="/data/local/tmp/fake.apk"),
            live_activity_wire(duplicate=True),
            b"not activity manager\n",
        )
        for raw in mutations:
            adapter, backend, _, plan = make_adapter()
            backend.live_raw = raw
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(task.LaunchOutcomeUncertain) as caught:
                    launch(adapter, plan)
                self.assertTrue(caught.exception.side_effect_possible)

    def test_process_evidence_mutations_fail_after_dispatch(self):
        mutators = (
            lambda value: replace(value, alive=False),
            lambda value: replace(value, collector_uid=0),
            lambda value: replace(value, mutation_count=1),
            lambda value: replace(
                value, process=replace(PROCESS, uid=2000)),
            lambda value: replace(value, boot_id=
                                  "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"),
        )
        for mutate in mutators:
            adapter, backend, _, plan = make_adapter()
            backend.launch_process_mutator = mutate
            with self.subTest(mutate=mutate):
                with self.assertRaises(task.LaunchOutcomeUncertain):
                    launch(adapter, plan)

    def test_policy_mutation_retains_parser_derived_cleanup_identity(self):
        fields = {
            "component_exported": True,
            "fixture_hash_verified_before_dispatch": False,
            "user_document_selection_used": True,
            "caller_command_input_used": True,
            "broad_scope_used": True,
            "process_kill_used": True,
            "fixture_uri": URI + "-other",
            "display_id": DISPLAY + 1,
        }
        for name, value in fields.items():
            adapter, backend, _, plan = make_adapter()
            backend.launch_mutator = (
                lambda receipt, name=name, value=value:
                replace(receipt, **{name: value}))
            with self.subTest(name=name):
                with self.assertRaises(task.LaunchOutcomeUncertain) as caught:
                    launch(adapter, plan)
                self.assertIsNotNone(caught.exception.retained_foreign)
                self.assertEqual(adapter.state, "LAUNCH_UNCERTAIN_RETAINED")

    def test_backend_identity_drift_before_dispatch_is_clean_after_is_uncertain(self):
        adapter, backend, _, plan = make_adapter()
        backend.drift = True
        with self.assertRaises(task.LaunchNotDispatched):
            launch(adapter, plan)
        self.assertEqual(backend.calls, [])
        adapter, backend, _, plan = make_adapter()
        backend.drift_on_launch = True
        with self.assertRaises(task.LaunchOutcomeUncertain):
            launch(adapter, plan)
        self.assertTrue(backend.task_present)

    def test_reentrant_entry_seals_active_launch(self):
        adapter, backend, _, plan = make_adapter()
        backend.launch_mode = "reenter"
        with self.assertRaises(task.LaunchOutcomeUncertain):
            launch(adapter, plan)
        self.assertIsInstance(backend.reentrant_error, task.TaskAdapterError)
        with self.assertRaises(task.TaskAdapterError):
            adapter.verify()

    def test_late_dispatch_witness_is_permanently_rejected(self):
        adapter, backend, _, plan = make_adapter()
        launch(adapter, plan)
        with self.assertRaises(task.TaskAdapterError):
            backend.saved_witness()
        with self.assertRaises(task.TaskAdapterError):
            adapter.verify()

    def test_launch_is_one_shot(self):
        adapter, backend, _, plan = make_adapter()
        launch(adapter, plan)
        with self.assertRaises(task.TaskAdapterError):
            launch(adapter, plan)
        self.assertEqual(backend.calls, ["launch"])


class RemovalAndQuiescenceTests(unittest.TestCase):
    def setUp(self):
        self.adapter, self.backend, self.clock, self.plan = make_adapter()
        self.launch_receipt = launch(self.adapter, self.plan)
        self.foreign = self.launch_receipt.foreign

    def test_exact_removal_proves_absence_and_stock_process_liveness(self):
        closure = close(self.adapter, self.plan, self.foreign)
        self.assertIs(type(closure), harness.TaskClosure)
        self.assertEqual(closure.foreign, self.foreign)
        self.assertTrue(closure.task_absent)
        self.assertTrue(closure.stock_process_alive)
        self.assertFalse(closure.broad_scope_used)
        self.assertFalse(closure.process_kill_used)
        evidence = json.loads(closure.closure_evidence)
        self.assertEqual(evidence["removedTaskId"], TASK_ID)
        self.assertTrue(evidence["attestation"]["exactTaskIdOnly"])
        self.assertFalse(evidence["attestation"]["forceStopUsed"])
        self.assertFalse(evidence["hardwareTimingProven"])
        self.assertFalse(self.backend.task_present)
        self.adapter.assert_quiescent(
            self.foreign, self.plan.absolute_deadline_ns)
        self.assertEqual(self.adapter.state, "QUIESCENT")
        self.assertEqual(self.adapter.cleanup_obligations, ())
        self.assertEqual(self.backend.calls,
                         ["launch", "remove", "observe", "all_quiescent"])

    def test_wrong_serial_or_identity_never_dispatches_removal(self):
        wrong = replace(self.foreign, task_id=self.foreign.task_id + 1)
        with self.assertRaises(task.RemovalNotDispatched) as caught:
            self.adapter.destroy_exact_task(
                SERIAL, wrong, self.plan.absolute_deadline_ns)
        self.assertFalse(caught.exception.side_effect_possible)
        self.assertEqual(self.backend.calls, ["launch"])
        self.assertTrue(self.backend.task_present)

    def test_removal_failure_before_witness_is_not_dispatched(self):
        self.backend.remove_mode = "raise_before"
        with self.assertRaises(task.RemovalNotDispatched) as caught:
            close(self.adapter, self.plan, self.foreign)
        self.assertFalse(caught.exception.side_effect_possible)
        self.assertTrue(self.backend.task_present)
        self.assertEqual(self.adapter.state, "REMOVE_NOT_DISPATCHED")

    def test_removal_failure_after_witness_can_be_resolved_by_fresh_quiescence(self):
        self.backend.remove_mode = "raise_after"
        with self.assertRaises(task.RemovalOutcomeUncertain) as caught:
            close(self.adapter, self.plan, self.foreign)
        self.assertTrue(caught.exception.side_effect_possible)
        self.assertFalse(self.backend.task_present)
        self.adapter.assert_quiescent(
            self.foreign, self.plan.absolute_deadline_ns)
        self.assertEqual(self.adapter.state, "QUIESCENT")

    def test_pre_remove_identity_drift_is_rejected_after_dispatch(self):
        self.backend.pre_remove_raw = live_activity_wire(token="2222abcd")
        with self.assertRaises(task.RemovalOutcomeUncertain):
            close(self.adapter, self.plan, self.foreign)

    def test_post_remove_activity_or_process_restart_rejects_closure(self):
        self.backend.post_remove_raw = self.backend.live_raw
        with self.assertRaises(task.RemovalOutcomeUncertain):
            close(self.adapter, self.plan, self.foreign)
        adapter, backend, _, plan = make_adapter()
        foreign = launch(adapter, plan).foreign
        backend.post_process_mutator = lambda value: replace(
            value, process=replace(PROCESS, start_ticks=PROCESS.start_ticks + 1))
        with self.assertRaises(task.RemovalOutcomeUncertain):
            close(adapter, plan, foreign)

    def test_destroy_policy_mutations_are_uncertain(self):
        fields = {
            "removed_task_id": TASK_ID + 1,
            "compare_identity_before_remove": False,
            "exact_task_id_only": False,
            "package_selector_used": True,
            "wildcard_selector_used": True,
            "force_stop_used": True,
            "caller_command_input_used": True,
            "broad_scope_used": True,
            "process_kill_used": True,
        }
        for name, value in fields.items():
            adapter, backend, _, plan = make_adapter()
            foreign = launch(adapter, plan).foreign
            backend.remove_mutator = (
                lambda receipt, name=name, value=value:
                replace(receipt, **{name: value}))
            with self.subTest(name=name):
                with self.assertRaises(task.RemovalOutcomeUncertain):
                    close(adapter, plan, foreign)

    def test_removal_without_witness_drift_quiescence_failure_and_overrun(self):
        cases = ("no_witness", "drift", "quiescence", "overrun")
        for case in cases:
            adapter, backend, _, plan = make_adapter()
            foreign = launch(adapter, plan).foreign
            if case == "no_witness":
                backend.remove_mode = "no_witness"
            elif case == "drift":
                backend.drift_on_remove = True
            elif case == "quiescence":
                backend.operation_quiescence_error = True
            else:
                backend.remove_mode = "overrun"
            with self.subTest(case=case):
                with self.assertRaises(task.RemovalOutcomeUncertain):
                    close(adapter, plan, foreign)

    def test_quiescence_rejects_live_task_recreated_task_and_dead_process(self):
        self.backend.task_present = True
        with self.assertRaises(task.TaskQuiescenceUncertain):
            self.adapter.assert_quiescent(
                self.foreign, self.plan.absolute_deadline_ns)
        adapter, backend, _, plan = make_adapter()
        foreign = launch(adapter, plan).foreign
        close(adapter, plan, foreign)
        backend.final_raw = absent_activity_wire(
            f"note {android.SHORT_COMPONENT}\n")
        with self.assertRaises(task.TaskQuiescenceUncertain):
            adapter.assert_quiescent(foreign, plan.absolute_deadline_ns)
        adapter, backend, _, plan = make_adapter()
        foreign = launch(adapter, plan).foreign
        close(adapter, plan, foreign)
        backend.final_process_mutator = lambda value: replace(value, alive=False)
        with self.assertRaises(task.TaskQuiescenceUncertain):
            adapter.assert_quiescent(foreign, plan.absolute_deadline_ns)

    def test_all_quiescence_failure_is_sealed(self):
        close(self.adapter, self.plan, self.foreign)
        self.backend.all_quiescence_error = True
        with self.assertRaises(task.TaskQuiescenceUncertain):
            self.adapter.assert_quiescent(
                self.foreign, self.plan.absolute_deadline_ns)
        self.assertEqual(self.adapter.state, "QUIESCENCE_UNCERTAIN")
        self.assertTrue(self.adapter.cleanup_obligations)

    def test_quiescence_receipt_must_be_read_only_and_exact(self):
        close(self.adapter, self.plan, self.foreign)
        self.backend.quiescence_mutator = lambda value: replace(
            value, mutation_count=1)
        with self.assertRaises(task.TaskQuiescenceUncertain):
            self.adapter.assert_quiescent(
                self.foreign, self.plan.absolute_deadline_ns)

    def test_remove_is_one_shot(self):
        close(self.adapter, self.plan, self.foreign)
        with self.assertRaises(task.TaskAdapterError):
            close(self.adapter, self.plan, self.foreign)
        self.assertEqual(self.backend.calls.count("remove"), 1)


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_entry_is_rejected_and_recorded(self):
        adapter, backend, _, plan = make_adapter()
        adapter._lock.acquire()
        try:
            errors = []

            def enter():
                try:
                    adapter.verify()
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=enter)
            thread.start()
            thread.join()
        finally:
            adapter._lock.release()
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], task.TaskAdapterError)
        with self.assertRaises(task.LaunchNotDispatched):
            launch(adapter, plan)
        self.assertEqual(backend.calls, [])


if __name__ == "__main__":
    unittest.main()
