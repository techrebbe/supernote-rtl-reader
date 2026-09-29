"""Deterministic host lifecycle tests; no ADB, Frida, install or device use."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_protocol as subject


SHA_A = "a" * 64
SHA_B = "b" * 64
PINS = subject.Pins(SHA_A, SHA_B)
ENTRY = subject.ExpectedEntry((0, 0, 100, 200), (0, 0, 101, 200),
                              "4", "4", "3", "8")


def frame(phase: str = "ARMED") -> dict:
    return {"phase": phase, "fault": None,
            "hookRemoved": phase == "DISARMED",
            "callbacks": 3, "activeCallbacks": 0,
            "forwardAttempts": 3, "targetEntries": 1,
            "events": [{"ordinal": 1, "oldBounds": [0, 0, 100, 200],
                        "proposedBounds": [0, 0, 101, 200],
                        "parentRevision": "4", "observedWriteOrdinal": "4",
                        "layoutCallsBefore": "3", "paintCountBefore": "8",
                        "mainThread": True, "originalReturned": True}]}


class FakeHook:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.phase = "NEW"
        self.fail_arm = False
        self.arm_timeout = False
        self.fail_disarm = False
        self.fail_unload = False
        self.extra_after_disarm = False
        self.bad_frame = None
        self.config = None

    def arm(self, config: dict) -> dict:
        self.trace.append("arm")
        self.config = config
        if self.arm_timeout:
            raise TimeoutError("bounded RPC expired")
        if self.fail_arm:
            return {"ok": False, "phase": "UNCERTAIN", "code": "ARM_FAILED"}
        self.phase = "ARMED"
        return {"ok": True, "phase": "ARMED", "hookInstalled": True,
                "pid": config["pid"], "rootToken": config["rootToken"]}

    def snapshot(self) -> dict:
        self.trace.append("snapshot")
        value = frame(self.phase)
        if self.bad_frame is not None:
            self.bad_frame(value)
        if self.phase == "DISARMED" and self.extra_after_disarm:
            value["callbacks"] += 1
            value["forwardAttempts"] += 1
        return copy.deepcopy(value)

    def disarm(self) -> dict:
        self.trace.append("disarm")
        if self.fail_disarm:
            return {"ok": False, "phase": "UNCERTAIN",
                    "code": "REVERT_UNCERTAIN", "cleanupCertain": False}
        self.phase = "DISARMED"
        return {"ok": True, "phase": "DISARMED", "code": "DISARMED",
                "cleanupCertain": True, "callbacks": 3,
                "forwardAttempts": 3}

    def unload(self) -> None:
        self.trace.append("unload")
        if self.fail_unload:
            raise RuntimeError("private unload failure")


class FakeSession:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.hook = FakeHook(trace)

    def detach(self) -> None:
        self.trace.append("detach")


class FakeTransport:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.session = FakeSession(trace)

    def attach(self, pid: int) -> FakeSession:
        self.trace.append("attach:" + str(pid))
        return self.session


class FakeApp:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.admission = subject.Admission(
            subject.SERIAL, "1", 30, subject.PACKAGE, SHA_A, SHA_B,
            2468, "incarnation-1", 1, "activity-1", "root-1", True)
        self.expected = (ENTRY,)
        self.fail_post = False
        self.preflight_error: Exception | None = None
        self.execute_error: Exception | None = None

    def preflight(self) -> subject.Admission:
        self.trace.append("preflight")
        if self.preflight_error is not None:
            raise self.preflight_error
        return self.admission

    def prearm(self, admission: subject.Admission) -> None:
        self.trace.append("prearm")

    def freshen_baseline(self, admission: subject.Admission) -> None:
        self.trace.append("refresh")

    def execute_and_restore(self, variant: str, admission: subject.Admission) -> None:
        self.trace.append("execute:" + variant)
        if self.execute_error is not None:
            raise self.execute_error

    def main_barrier(self, admission: subject.Admission) -> None:
        self.trace.append("main_barrier")

    def expected_entries(self, variant: str,
                         admission: subject.Admission) -> tuple[subject.ExpectedEntry, ...]:
        self.trace.append("expected_entries")
        return self.expected

    def sentinel_after_revert(self, admission: subject.Admission) -> None:
        self.trace.append("sentinel")

    def post_unload_verify(self, admission: subject.Admission) -> None:
        self.trace.append("post_unload_verify")
        if self.fail_post:
            raise RuntimeError("private provider error")

    def sentinel_after_unload(self, admission: subject.Admission) -> None:
        self.trace.append("sentinel_after_unload")

    def finish_lease(self, admission: subject.Admission) -> None:
        self.trace.append("finish_lease")

    def stop_exact_process(self, admission: subject.Admission) -> None:
        self.trace.append("stop:" + str(admission.pid) + ":" + admission.incarnation)


class HostProtocolTests(unittest.TestCase):
    def setup_case(self):
        trace: list[str] = []
        return trace, FakeApp(trace), FakeTransport(trace)

    def test_positive_lifecycle_and_false_port_authority(self) -> None:
        trace, app, transport = self.setup_case()
        result = subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(result["verdict"], "PASS_SYNTHETIC_EDGE_ONLY")
        self.assertEqual(result["completeMutationCoverage"], False)
        self.assertEqual(result["portRevision"], -1)
        self.assertEqual(transport.session.hook.config,
                         app.admission.observer_config())
        self.assertEqual(trace, ["preflight", "prearm", "attach:2468", "arm", "refresh",
                                 "execute:parent-plus-one", "main_barrier",
                                 "expected_entries", "snapshot", "disarm",
                                 "sentinel", "snapshot", "unload", "detach",
                                 "sentinel_after_unload", "post_unload_verify",
                                 "finish_lease"])

    def test_preflight_rejects_non_emulator_before_attach(self) -> None:
        trace, app, transport = self.setup_case()
        app.admission = subject.Admission(
            "physical-serial", "0", 30, subject.PACKAGE, SHA_A, SHA_B,
            2468, "incarnation-1", 1, "activity-1", "root-1", True)
        with self.assertRaisesRegex(subject.TrialError, "PREFLIGHT_REJECTED"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(trace, ["preflight"])

    def test_unexpected_preflight_failure_has_fixed_code_and_no_attach(self) -> None:
        trace, app, transport = self.setup_case()
        app.preflight_error = RuntimeError("private launch response")
        with self.assertRaises(subject.TrialError) as caught:
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(str(caught.exception), "TRIAL_UNCERTAIN_PREFLIGHT")
        self.assertEqual(trace, ["preflight"])

    def test_missing_entry_stops_exact_disposable_process(self) -> None:
        trace, app, transport = self.setup_case()
        app.expected = ()
        with self.assertRaisesRegex(subject.TrialError, "ENTRY_COUNT_MISMATCH"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertIn("stop:2468:incarnation-1", trace)
        self.assertLess(trace.index("stop:2468:incarnation-1"), trace.index("unload"))
        self.assertIn("detach", trace)

    def test_hook_fault_stops_process(self) -> None:
        trace, app, transport = self.setup_case()
        transport.session.hook.bad_frame = lambda value: value.update(fault="ENTRY_CAPTURE_FAILED")
        with self.assertRaisesRegex(subject.TrialError, "HOOK_STATE_UNCERTAIN"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertIn("stop:2468:incarnation-1", trace)

    def test_arm_timeout_stops_only_attached_disposable_process(self) -> None:
        trace, app, transport = self.setup_case()
        transport.session.hook.arm_timeout = True
        with self.assertRaisesRegex(subject.TrialError, "^TRIAL_UNCERTAIN_ARM$"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(trace, ["preflight", "prearm", "attach:2468", "arm",
                                 "stop:2468:incarnation-1", "unload", "detach"])

    def test_unexpected_execute_failure_has_fixed_phase_and_same_cleanup(self) -> None:
        trace, app, transport = self.setup_case()
        app.execute_error = RuntimeError("private command response token")
        with self.assertRaises(subject.TrialError) as caught:
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(str(caught.exception), "TRIAL_UNCERTAIN_EXECUTE")
        self.assertEqual(trace, ["preflight", "prearm", "attach:2468", "arm",
                                 "refresh", "execute:parent-plus-one",
                                 "stop:2468:incarnation-1", "unload", "detach"])

    def test_every_unexpected_phase_has_fixed_code_and_exact_cleanup(self) -> None:
        steps = ("preflight", "prearm", "attach:2468", "arm", "refresh",
                 "execute:parent-plus-one", "main_barrier", "expected_entries",
                 "snapshot", "disarm", "sentinel", "snapshot", "unload",
                 "detach", "sentinel_after_unload", "post_unload_verify",
                 "finish_lease")
        # The second snapshot is a separate phase. Each literal is asserted
        # directly so a swapped or missing diagnostic cannot pass this table.
        cases = (
            ("TRIAL_UNCERTAIN_PREFLIGHT", "app", "preflight", 1, 0),
            ("TRIAL_UNCERTAIN_PREARM", "app", "prearm", 1, 1),
            ("TRIAL_UNCERTAIN_ATTACH", "transport", "attach", 1, 2),
            ("TRIAL_UNCERTAIN_ARM", "hook", "arm", 1, 3),
            ("TRIAL_UNCERTAIN_REFRESH", "app", "freshen_baseline", 1, 4),
            ("TRIAL_UNCERTAIN_EXECUTE", "app", "execute_and_restore", 1, 5),
            ("TRIAL_UNCERTAIN_BARRIER", "app", "main_barrier", 1, 6),
            ("TRIAL_UNCERTAIN_APP_EVIDENCE", "app", "expected_entries", 1, 7),
            ("TRIAL_UNCERTAIN_ARMED_SNAPSHOT", "hook", "snapshot", 1, 8),
            ("TRIAL_UNCERTAIN_DISARM", "hook", "disarm", 1, 9),
            ("TRIAL_UNCERTAIN_REVERT_SENTINEL", "app", "sentinel_after_revert", 1, 10),
            ("TRIAL_UNCERTAIN_DISARMED_SNAPSHOT", "hook", "snapshot", 2, 11),
            ("TRIAL_UNCERTAIN_UNLOAD", "hook", "unload", 1, 12),
            ("TRIAL_UNCERTAIN_DETACH", "session", "detach", 1, 13),
            ("TRIAL_UNCERTAIN_UNLOAD_SENTINEL", "app", "sentinel_after_unload", 1, 14),
            ("TRIAL_UNCERTAIN_POST_UNLOAD", "app", "post_unload_verify", 1, 15),
            ("TRIAL_UNCERTAIN_FINISH", "app", "finish_lease", 1, 16),
        )
        self.assertEqual(len(cases), len(steps))
        for code, owner, method, occurrence, step_index in cases:
            with self.subTest(code=code):
                trace, app, transport = self.setup_case()
                owners = {"app": app, "transport": transport,
                          "session": transport.session,
                          "hook": transport.session.hook}
                target = owners[owner]
                original = getattr(target, method)
                call_count = [0]

                def inject(*args, **kwargs):
                    call_count[0] += 1
                    result = original(*args, **kwargs)
                    if call_count[0] == occurrence:
                        raise RuntimeError("private untrusted command token")
                    return result

                setattr(target, method, inject)
                with self.assertRaises(subject.TrialError) as caught:
                    subject.run_mockable(app, transport, PINS, "parent-plus-one")
                self.assertEqual(str(caught.exception), code)
                self.assertNotIn("private", str(caught.exception))
                self.assertEqual(call_count[0], occurrence)
                cleanup = ([] if step_index == 0 else
                           ["stop:2468:incarnation-1"])
                if 3 <= step_index <= 11:
                    cleanup += ["unload", "detach"]
                elif step_index == 12:
                    cleanup += ["detach"]
                self.assertEqual(trace, list(steps[:step_index + 1]) + cleanup)

    def test_execute_trial_error_code_is_preserved(self) -> None:
        trace, app, transport = self.setup_case()
        app.execute_error = subject.TrialError("APP_TRIAL_TIMEOUT")
        with self.assertRaises(subject.TrialError) as caught:
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(str(caught.exception), "APP_TRIAL_TIMEOUT")
        self.assertEqual(trace[-3:], ["stop:2468:incarnation-1", "unload", "detach"])

    def test_revert_uncertainty_stops_process(self) -> None:
        trace, app, transport = self.setup_case()
        transport.session.hook.fail_disarm = True
        with self.assertRaisesRegex(subject.TrialError, "DISARM_UNCERTAIN"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertIn("stop:2468:incarnation-1", trace)
        self.assertNotIn("sentinel", trace)

    def test_post_revert_hook_callback_is_not_accepted(self) -> None:
        trace, app, transport = self.setup_case()
        transport.session.hook.extra_after_disarm = True
        with self.assertRaisesRegex(subject.TrialError, "REVERT_SENTINEL_FAILED"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertIn("stop:2468:incarnation-1", trace)

    def test_post_unload_failure_stops_exact_process(self) -> None:
        trace, app, transport = self.setup_case()
        app.fail_post = True
        with self.assertRaisesRegex(subject.TrialError, "^TRIAL_UNCERTAIN_POST_UNLOAD$"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(trace[-1], "stop:2468:incarnation-1")

    def test_unload_failure_is_not_retried(self) -> None:
        trace, app, transport = self.setup_case()
        transport.session.hook.fail_unload = True
        with self.assertRaisesRegex(subject.TrialError, "^TRIAL_UNCERTAIN_UNLOAD$"):
            subject.run_mockable(app, transport, PINS, "parent-plus-one")
        self.assertEqual(trace.count("unload"), 1)
        self.assertIn("stop:2468:incarnation-1", trace)

    def test_invalid_variant_has_no_external_action(self) -> None:
        trace, app, transport = self.setup_case()
        with self.assertRaisesRegex(subject.TrialError, "VARIANT_INVALID"):
            subject.run_mockable(app, transport, PINS, "pen-input")
        self.assertEqual(trace, [])

    def test_non_derivable_counters_remain_bounded_diagnostics(self) -> None:
        expected = (subject.ExpectedEntry((0, 0, 100, 200),
                                          (0, 0, 101, 200), "4"),)
        self.assertEqual(subject.checked_snapshot(frame(), expected,
                                                  phase="ARMED")["targetEntries"], 1)
        bad = frame()
        bad["events"][0]["paintCountBefore"] = "not-a-counter"
        with self.assertRaisesRegex(subject.TrialError, "FRAME_INVALID"):
            subject.checked_snapshot(bad, expected, phase="ARMED")


if __name__ == "__main__":
    unittest.main()
