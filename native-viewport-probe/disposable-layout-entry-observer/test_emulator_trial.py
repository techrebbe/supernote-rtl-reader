"""Offline app-adapter safety tests. No ADB, Frida, install or emulator."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import emulator_trial as subject
import host_protocol as host
from test_app_evidence import ADMISSION, B, cut


def identity(state: str) -> dict:
    return {"pid": ADMISSION.pid, "incarnation": ADMISSION.incarnation,
            "activitySerial": ADMISSION.activity_serial,
            "activityPresent": True, "identityPublished": True,
            "everRegistered": True, "sampleElapsedMs": 1000,
            "armDeadlineElapsedMs": 30000, "armState": state,
            "armFinished": state == "FINISHED"}


def refreshed_state() -> dict:
    frame = cut(B, 4, 4, 3, 9)
    frame["paintStartedElapsedMs"] = 905
    frame["completedPaintElapsedMs"] = 1010
    return {"schema": "layout-fence-synthetic-v1",
            "process": identity("REFRESH_REQUESTED"),
            "activityPresent": True, "activitySerial": 1,
            "activityToken": ADMISSION.activity_token,
            "rootToken": ADMISSION.root_token,
            "lifecycle": "RESUMED", "rootAttached": True,
            "rootHasFocus": True, "parentSoleChild": True,
            "rootLost": False, "originalsExact": True,
            "sessionTainted": False, "watchdogExpired": False,
            "rootLayoutRequested": False, "parentLayoutRequested": False,
            "sampleElapsedMs": 1100, "current": frame,
            "lastCompletedPaint": copy.deepcopy(frame),
            "refreshRequested": True, "refreshPaintFloorRevision": 8,
            "refreshCompletedPaintCountFloor": 5,
            "refreshRequestedElapsedMs": 900,
            "completedPaintCount": 6}


def restore_entry_witness() -> dict:
    return {"sameRoot": True, "sameRootToken": True,
            "sameScene": False, "childCount": [9, 9],
            "childIdentityMismatchIndices": [],
            "parentIdentityMismatchIndices": [],
            "childEvidenceMismatchIndices": [2],
            "bounds": [[0, 0, 1059, 200], [0, 0, 1059, 200]],
            "parentPreCallRevision": [2, 2],
            "observedWriteOrdinal": [2, 2],
            "rootLayoutCalls": [2, 2],
            "startedPaintRevision": [4, 5],
            "paintStartedElapsedMs": [1000, 1050],
            "paintStartParentRevision": [2, 2],
            "paintStartWriteOrdinal": [2, 2],
            "completedPaintRevision": [4, 5],
            "completedPaintElapsedMs": [1005, 1055]}


class FakeAdb:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.state = refreshed_state()
        self.stopped = False
        self.reject_refresh = False
        self.reject_command = False
        self.command_reply_loss = False
        self.command_identity_override: str | None = None
        self.post_command_process_drift = False
        self.command_accepted = False
        self.abort_dies_before_reply = False

    def same_process(self, pid, signature) -> bool:
        self.calls.append(("same_process", pid))
        return (not self.stopped and pid == ADMISSION.pid and
                not (self.command_accepted and self.post_command_process_drift))

    def check_emulator(self) -> None:
        self.calls.append(("check_emulator",))

    def provider_state(self, *, timeout: float = 3.0) -> dict:
        self.calls.append(("state", timeout))
        return copy.deepcopy(self.state)

    def provider_call(self, method, argument, extras, *, timeout=3.0) -> dict:
        self.calls.append((method, argument, copy.deepcopy(extras), timeout))
        if method == "refresh":
            if self.reject_refresh:
                return {"ok": "false", "error": "ambiguous"}
            return {"ok": "true", "refreshToken": "refresh-1",
                    "paintFloorRevision": "8",
                    "completedPaintCountFloor": "5",
                    "requestedElapsedMs": "900",
                    "json": json.dumps(identity("REFRESH_REQUESTED"))}
        if method == "command":
            if self.reject_command:
                return {"ok": "false", "error": "exact pins/token rejected"}
            self.command_accepted = True
            if self.command_reply_loss:
                raise host.TrialError("COMMAND_TIMEOUT_OR_FAILED")
            response = copy.deepcopy(self.state)
            response["process"] = identity("TRIAL_WATCHDOG_ACTIVE")
            if self.command_identity_override is not None:
                response["process"]["incarnation"] = self.command_identity_override
            response["trial"] = {"command": argument, "state": "PASS",
                                 "currentlyValid": True,
                                 "activeArmDeadlineElapsedMs": 30000,
                                 "trialDeadlineElapsedMs": 25000}
            self.state = copy.deepcopy(response)
            return {"ok": "true", "command": argument,
                    "json": json.dumps(response)}
        if method == "finish":
            return {"ok": "true", "json": json.dumps(identity("FINISHED"))}
        if method == "abort":
            self.stopped = True
            if self.abort_dies_before_reply:
                raise host.TrialError("COMMAND_TIMEOUT_OR_FAILED")
            return {"ok": "true"}
        raise AssertionError(method)

    def shell(self, *args, **kwargs) -> str:
        self.calls.append(("shell", *args))
        if args == ("am", "force-stop", host.PACKAGE):
            self.stopped = True
            return ""
        raise AssertionError(args)

    def pid(self):
        return None if self.stopped else ADMISSION.pid


def app_with_fake() -> tuple[subject.EmulatorApp, FakeAdb]:
    fake = FakeAdb()
    app = subject.EmulatorApp(fake, host.Pins("a" * 64, "b" * 64))
    app.admission = ADMISSION
    app.signature = (123, host.PACKAGE, "boot-id")
    app.arm_token = "arm-1"
    app.arm_deadline_ms = 30000
    app.host_deadline = time.monotonic() + 20
    app.prearm_host_start = time.monotonic()
    app.baseline_frame = cut(B, 4, 4, 3, 8)
    app.baseline_paint_revision = 8
    return app, fake


class TrialAdapterTests(unittest.TestCase):
    def test_refresh_requires_new_app_owned_paint_and_one_call(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        self.assertEqual(app.refresh_token, "refresh-1")
        self.assertEqual(app.baseline_paint_revision, 9)
        mutating = [call for call in fake.calls if call[0] == "refresh"]
        self.assertEqual(len(mutating), 1)
        self.assertEqual(mutating[0][2]["armToken"], ("s", "arm-1"))
        self.assertNotIn("refreshToken", mutating[0][2])
        self.assertEqual(app._extras(ADMISSION, armed=True,
                                     refreshed=True)["refreshToken"],
                         ("s", "refresh-1"))
        self.assertFalse(any(call[0] == "same_process" for call in fake.calls))

    def test_fast_cut_then_exact_command_has_no_precommand_os_probe(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        app.execute_and_restore("parent-plus-one", ADMISSION)
        refresh_at = next(i for i, call in enumerate(fake.calls)
                          if call[0] == "refresh")
        command_at = next(i for i, call in enumerate(fake.calls)
                          if call[0] == "command")
        self.assertFalse(any(call[0] == "same_process"
                             for call in fake.calls[refresh_at:command_at]))
        self.assertTrue(any(call[0] == "same_process"
                            for call in fake.calls[command_at + 1:]))
        command = fake.calls[command_at]
        self.assertEqual(command[2]["pid"], ("i", str(ADMISSION.pid)))
        self.assertEqual(command[2]["incarnation"],
                         ("s", ADMISSION.incarnation))
        self.assertEqual(command[2]["activityToken"],
                         ("s", ADMISSION.activity_token))
        self.assertEqual(command[2]["rootToken"],
                         ("s", ADMISSION.root_token))
        self.assertEqual(command[2]["armToken"], ("s", "arm-1"))
        self.assertEqual(command[2]["refreshToken"], ("s", "refresh-1"))

    def test_replacement_state_rejected_before_command_without_os_probe(self) -> None:
        for field, value in (("pid", ADMISSION.pid + 1),
                             ("incarnation", "new-incarnation"),
                             ("activitySerial", ADMISSION.activity_serial + 1)):
            app, fake = app_with_fake()
            fake.state["process"][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(host.TrialError,
                                            "APP_IDENTITY_DRIFT"):
                    app.freshen_baseline(ADMISSION)
            self.assertFalse(any(call[0] == "same_process" for call in fake.calls))
            self.assertFalse(any(call[0] == "command" for call in fake.calls))
        for field in ("activityToken", "rootToken"):
            app, fake = app_with_fake()
            fake.state[field] = "replacement-token"
            with self.subTest(field=field):
                with self.assertRaisesRegex(host.TrialError,
                                            "APP_IDENTITY_DRIFT"):
                    app.freshen_baseline(ADMISSION)
            self.assertFalse(any(call[0] == "command" for call in fake.calls))

    def test_replacement_between_cut_and_command_is_one_shot_rejection(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        now = time.monotonic()
        app.refresh_proof_host_received = now
        app.refresh_age_upper_at_receipt_ms = 1582
        fake.reject_command = True  # App's exact pins/token gate rejects ABA.
        with patch.object(subject.time, "monotonic", return_value=now):
            with self.assertRaisesRegex(host.TrialError,
                                        "CONTENT_CALL_REJECTED"):
                app.execute_and_restore("parent-plus-one", ADMISSION)
        self.assertEqual(sum(call[0] == "command" for call in fake.calls), 1)
        self.assertFalse(any(call[0] == "same_process" for call in fake.calls))

    def test_command_reply_loss_is_unknown_without_retry(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        now = time.monotonic()
        app.refresh_proof_host_received = now
        app.refresh_age_upper_at_receipt_ms = 1582
        fake.command_reply_loss = True
        with patch.object(subject.time, "monotonic", return_value=now):
            with self.assertRaisesRegex(host.TrialError,
                                        "COMMAND_TIMEOUT_OR_FAILED"):
                app.execute_and_restore("parent-plus-one", ADMISSION)
        self.assertEqual(sum(call[0] == "command" for call in fake.calls), 1)
        self.assertFalse(any(call[0] == "same_process" for call in fake.calls))

    def test_post_command_os_signature_is_required_before_pass(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        fake.post_command_process_drift = True
        with self.assertRaisesRegex(host.TrialError, "APP_PROCESS_DRIFT"):
            app.execute_and_restore("parent-plus-one", ADMISSION)
        command_at = next(i for i, call in enumerate(fake.calls)
                          if call[0] == "command")
        self.assertEqual(sum(call[0] == "command" for call in fake.calls), 1)
        self.assertTrue(any(call[0] == "same_process"
                            for call in fake.calls[command_at + 1:]))

    def test_accepted_command_response_with_new_incarnation_is_rejected(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        fake.command_identity_override = "new-incarnation"
        with self.assertRaisesRegex(host.TrialError,
                                    "APP_IDENTITY_DRIFT"):
            app.execute_and_restore("parent-plus-one", ADMISSION)
        self.assertEqual(sum(call[0] == "command" for call in fake.calls), 1)
        self.assertFalse(any(call[0] == "same_process" for call in fake.calls))

    def test_stale_paint_is_rejected_before_command(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        app.refresh_proof_host_received = time.monotonic() - 2.1
        with self.assertRaisesRegex(host.TrialError,
                                    "REFRESH_PAINT_TOO_OLD_FOR_COMMAND"):
            app.execute_and_restore("parent-plus-one", ADMISSION)
        self.assertFalse(any(call[0] == "command" for call in fake.calls))

    def test_command_conservative_age_boundary_is_strict(self) -> None:
        now = time.monotonic()
        for upper, accepted in ((1999, True), (2000, False)):
            app, fake = app_with_fake()
            app.freshen_baseline(ADMISSION)
            app.refresh_proof_host_received = now
            app.refresh_age_upper_at_receipt_ms = upper
            with self.subTest(upper=upper), \
                 patch.object(subject.time, "monotonic", return_value=now):
                if accepted:
                    app.execute_and_restore("parent-plus-one", ADMISSION)
                else:
                    with self.assertRaisesRegex(host.TrialError,
                        "REFRESH_PAINT_TOO_OLD_FOR_COMMAND"):
                        app.execute_and_restore("parent-plus-one", ADMISSION)
            self.assertEqual(sum(call[0] == "command" for call in fake.calls),
                             1 if accepted else 0)

    def test_elapsed_after_receipt_rejected_before_one_shot_command(self) -> None:
        app, fake = app_with_fake()
        now = time.monotonic()
        app.freshen_baseline(ADMISSION)
        app.refresh_proof_host_received = now - 0.418
        app.refresh_age_upper_at_receipt_ms = 1582
        with patch.object(subject.time, "monotonic", return_value=now):
            with self.assertRaisesRegex(host.TrialError,
                                        "REFRESH_PAINT_TOO_OLD_FOR_COMMAND"):
                app.execute_and_restore("parent-plus-one", ADMISSION)
        self.assertFalse(any(call[0] == "command" for call in fake.calls))

    def test_refresh_784_sample_plus_798_roundtrip_is_command_viable(self) -> None:
        app, fake = app_with_fake()
        fake.state["sampleElapsedMs"] = 1794  # 1794 - paint at 1010 = 784.
        clock = [100.0]
        app.host_deadline = 120.0
        original_state = fake.provider_state
        def delayed_state(*, timeout=3.0):
            clock[0] += 0.797999  # Ceils to 798 ms despite binary float rounding.
            return original_state(timeout=timeout)
        with patch.object(subject.time, "monotonic",
                          side_effect=lambda: clock[0]), \
             patch.object(fake, "provider_state", side_effect=delayed_state):
            app.freshen_baseline(ADMISSION)
            app.execute_and_restore("parent-plus-one", ADMISSION)
        sample = app.refresh_failure_evidence()["polls"][0]
        self.assertEqual(sample["sampleAgeMs"], 784)
        self.assertEqual(sample["pollRoundTripMs"], 798)
        self.assertEqual(sample["ageUpperAtReceiptMs"], 1582)
        self.assertTrue(sample["commandViable"])
        self.assertEqual(sum(call[0] == "command" for call in fake.calls), 1)

    def test_refresh_upper_age_2000_at_receipt_never_commands(self) -> None:
        app, fake = app_with_fake()
        fake.state["sampleElapsedMs"] = 2010  # 2010 - 1010 = 1000.
        clock = [100.0]
        app.host_deadline = 120.0
        original_state = fake.provider_state
        def delayed_state(*, timeout=3.0):
            clock[0] += 0.999999  # Ceils to 1000 ms.
            return original_state(timeout=timeout)
        with patch.object(subject.time, "monotonic",
                          side_effect=lambda: clock[0]), \
             patch.object(fake, "provider_state", side_effect=delayed_state):
            with self.assertRaisesRegex(host.TrialError,
                                        "REFRESHED_PAINT_UNAVAILABLE"):
                app.freshen_baseline(ADMISSION)
        first = app.refresh_failure_evidence()["polls"][0]
        self.assertEqual(first["sampleAgeMs"], 1000)
        self.assertEqual(first["pollRoundTripMs"], 1000)
        self.assertEqual(first["ageUpperAtReceiptMs"], 2000)
        self.assertFalse(first["commandViable"])
        self.assertFalse(any(call[0] == "command" for call in fake.calls))

    def test_slow_provider_response_cannot_admit_after_poll_expiry(self) -> None:
        app, fake = app_with_fake()
        ticks = iter((100.0, 100.0, 100.0, 100.0, 100.0, 103.0, 103.0))
        with patch.object(subject.time, "monotonic", side_effect=lambda: next(ticks)):
            with self.assertRaisesRegex(host.TrialError,
                                        "REFRESHED_PAINT_UNAVAILABLE"):
                app.freshen_baseline(ADMISSION)
        evidence = app.refresh_failure_evidence()
        self.assertIsNotNone(evidence)
        self.assertEqual(len(evidence["polls"]), 1)
        self.assertFalse(evidence["polls"][0]["withinHostDeadlines"])
        self.assertFalse(any(call[0] == "command" for call in fake.calls))

    def test_refresh_failure_trace_is_bounded_first_plus_latest(self) -> None:
        app, _ = app_with_fake()
        app.refresh_token = "refresh-1"
        for number in range(20):
            app._record_refresh_sample({"poll": number})
        evidence = app.refresh_failure_evidence()
        self.assertEqual([sample["poll"] for sample in evidence["polls"]],
                         [0, 13, 14, 15, 16, 17, 18, 19])

    def test_scene_drift_captures_only_existing_scalar_state(self) -> None:
        app, fake = app_with_fake()
        fake.state["parentLayoutRequested"] = True
        fake.state["sessionTaintReason"] = "NONE"
        fake.state["rootBounds"] = {"left": 0, "top": 0,
                                    "right": 100, "bottom": 200}
        fake.state["parentPreCallRevision"] = 4
        fake.state["observedWriteOrdinal"] = 4
        fake.state["rootLayoutCallCount"] = 3
        fake.state["trial"] = {"state": "WAIT_FIRST_CALL",
                               "reason": "PENDING",
                               "command": "parent-plus-one",
                               "currentlyValid": False}
        app.command_host_started = time.monotonic() - 0.1
        with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
            app._state(ADMISSION, phase="trial-poll", os_check=False)
        scene = app.scene_failure_evidence()
        evidence = scene["failedState"]
        self.assertEqual(evidence["phase"], "trial-poll")
        self.assertEqual(evidence["parentLayoutRequested"], True)
        self.assertEqual(evidence["rootLayoutRequested"], False)
        self.assertEqual(evidence["trialState"], "WAIT_FIRST_CALL")
        self.assertEqual(evidence["trialReason"], "PENDING")
        self.assertEqual(evidence["armState"], "REFRESH_REQUESTED")
        self.assertEqual(evidence["rootBounds"], fake.state["rootBounds"])
        self.assertGreaterEqual(evidence["hostMsSinceCommand"], 100)
        self.assertEqual(scene["firstTrialPoll"], evidence)
        self.assertEqual([call[0] for call in fake.calls], ["state"])
        serialized = json.dumps(scene)
        for secret in (ADMISSION.incarnation, ADMISSION.activity_token,
                       ADMISSION.root_token, "arm-1", "refresh-1"):
            self.assertNotIn(secret, serialized)

    def test_command_response_and_failed_trial_poll_have_distinct_phases(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        fake.state["parentLayoutRequested"] = True
        with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
            app.execute_and_restore("parent-plus-one", ADMISSION)
        evidence = app.scene_failure_evidence()
        self.assertEqual(evidence["commandResponse"]["phase"],
                         "command-response")
        self.assertTrue(evidence["commandResponse"]["parentLayoutRequested"])
        self.assertEqual(evidence["firstTrialPoll"]["phase"], "trial-poll")
        self.assertTrue(evidence["firstTrialPoll"]["parentLayoutRequested"])
        self.assertEqual(evidence["failedState"]["phase"], "trial-poll")
        self.assertTrue(evidence["failedState"]["parentLayoutRequested"])
        self.assertEqual(sum(call[0] == "state" for call in fake.calls), 2)

    def test_first_trial_poll_persists_before_later_scene_failure(self) -> None:
        app, fake = app_with_fake()
        app.command_host_started = time.monotonic()
        app._state(ADMISSION, phase="trial-poll", os_check=False)
        fake.state["parentLayoutRequested"] = True
        with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
            app._state(ADMISSION, phase="trial-poll", os_check=False)
        evidence = app.scene_failure_evidence()
        self.assertFalse(evidence["firstTrialPoll"]["parentLayoutRequested"])
        self.assertTrue(evidence["failedState"]["parentLayoutRequested"])
        self.assertEqual([call[0] for call in fake.calls], ["state", "state"])

    def test_unexpected_diagnostic_labels_cannot_leak_tokens(self) -> None:
        app, fake = app_with_fake()
        secret = "12345678-1234-1234-1234-123456789abc"
        fake.state["lifecycle"] = secret
        fake.state["sessionTaintReason"] = secret
        fake.state["process"]["armState"] = secret
        fake.state["trial"] = {"state": secret, "reason": secret,
                                "command": secret}
        with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
            app._state(ADMISSION, phase="trial-poll", os_check=False)
        evidence = app.scene_failure_evidence()
        self.assertNotIn(secret, json.dumps(evidence))
        for field in ("lifecycle", "sessionTaintReason", "armState",
                      "trialState", "trialReason", "trialCommand"):
            self.assertIsNone(evidence["failedState"][field])

    def test_non_scene_error_does_not_emit_scene_evidence(self) -> None:
        app, _ = app_with_fake()
        app.command_response_evidence = {"phase": "command-response"}
        app.first_trial_poll_evidence = {"phase": "trial-poll"}
        self.assertIsNone(app.scene_failure_evidence())

    def test_restore_entry_drift_projects_exact_primitive_witness(self) -> None:
        app, fake = app_with_fake()
        witness = restore_entry_witness()
        fake.state["trial"] = {"state": "UNKNOWN",
                               "reason": "RESTORE_ENTRY_DRIFT",
                               "command": "parent-plus-one",
                               "restoreEntryDrift": witness}
        fake.state["sessionTainted"] = True
        with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
            app._state(ADMISSION, phase="trial-poll", os_check=False)
        evidence = app.scene_failure_evidence()["failedState"]
        self.assertEqual(evidence["restoreEntryDrift"], witness)
        self.assertIsNot(evidence["restoreEntryDrift"], witness)
        self.assertEqual([call[0] for call in fake.calls], ["state"])

    def test_restore_entry_drift_rejects_malformed_or_text_payload(self) -> None:
        witness = restore_entry_witness()
        bad_values = []
        for key, replacement in (
                ("sameRoot", 1), ("childCount", [9, True]),
                ("childIdentityMismatchIndices", [2, 2]),
                ("parentIdentityMismatchIndices", [4, 1]),
                ("childEvidenceMismatchIndices", [9]),
                ("bounds", [[0, 0, "SECRET", 200], [0, 0, 1059, 200]]),
                ("startedPaintRevision", [4, "SECRET"])):
            bad = copy.deepcopy(witness)
            bad[key] = replacement
            bad_values.append(bad)
        extra = copy.deepcopy(witness)
        extra["rootToken"] = "SECRET"
        bad_values.append(extra)
        missing = copy.deepcopy(witness)
        del missing["sameScene"]
        bad_values.append(missing)
        for bad in bad_values:
            with self.subTest(bad=bad):
                state = refreshed_state()
                state["trial"] = {"state": "UNKNOWN",
                                  "reason": "RESTORE_ENTRY_DRIFT",
                                  "restoreEntryDrift": bad}
                projected = subject._scene_diagnostic(
                    state, "trial-poll", None)
                self.assertIsNone(projected["restoreEntryDrift"])
                self.assertNotIn("SECRET", json.dumps(projected))

    def test_restore_entry_witness_only_on_exact_unknown_reason(self) -> None:
        state = refreshed_state()
        state["trial"] = {"state": "PASS", "reason": "RESTORE_ENTRY_DRIFT",
                          "restoreEntryDrift": restore_entry_witness()}
        self.assertNotIn("restoreEntryDrift",
                         subject._scene_diagnostic(state, "trial-poll", None))
        state["trial"]["state"] = "UNKNOWN"
        state["trial"]["reason"] = "TRIAL_TIMEOUT"
        self.assertNotIn("restoreEntryDrift",
                         subject._scene_diagnostic(state, "trial-poll", None))

    def test_malformed_restore_witness_preserves_scene_failure(self) -> None:
        app, fake = app_with_fake()
        fake.state["sessionTainted"] = True
        fake.state["trial"] = {"state": "UNKNOWN",
                               "reason": "RESTORE_ENTRY_DRIFT",
                               "restoreEntryDrift": {"rawToken": "SECRET"}}
        with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
            app._state(ADMISSION, phase="trial-poll", os_check=False)
        self.assertIsNone(app.scene_failure_evidence()["failedState"]
                          ["restoreEntryDrift"])
        self.assertEqual([call[0] for call in fake.calls], ["state"])

    def test_diagnostic_failure_never_changes_scene_drift_verdict(self) -> None:
        app, fake = app_with_fake()
        fake.state["sessionTainted"] = True
        with patch.object(subject, "_scene_diagnostic",
                          side_effect=RuntimeError("diagnostic failed")):
            with self.assertRaisesRegex(host.TrialError, "APP_SCENE_DRIFT"):
                app._state(ADMISSION, phase="main-barrier", os_check=False)
        self.assertEqual(app.scene_failure_evidence()["failedState"],
                         {"phase": "main-barrier", "capture": "UNAVAILABLE"})

    def test_ambiguous_refresh_never_retries(self) -> None:
        app, fake = app_with_fake()
        fake.reject_refresh = True
        with self.assertRaisesRegex(host.TrialError, "CONTENT_CALL_REJECTED"):
            app.freshen_baseline(ADMISSION)
        self.assertEqual(sum(call[0] == "refresh" for call in fake.calls), 1)
        self.assertIsNone(app.refresh_token)

    def test_abort_reply_loss_waits_for_exact_self_death(self) -> None:
        app, fake = app_with_fake()
        fake.abort_dies_before_reply = True
        app.stop_exact_process(ADMISSION)
        self.assertTrue(fake.stopped)
        self.assertEqual(sum(call[0] == "abort" for call in fake.calls), 1)
        self.assertFalse(any(call[0] == "shell" for call in fake.calls))

    def test_force_stop_only_after_verified_finish(self) -> None:
        app, fake = app_with_fake()
        app.finish_lease(ADMISSION)
        self.assertEqual([call[:3] for call in fake.calls if call[0] == "shell"],
                         [("shell", "am", "force-stop")])
        self.assertTrue(fake.stopped)

    def test_unarmed_launch_cleanup_is_exact_and_unknown(self) -> None:
        app, fake = app_with_fake()
        app.launch_attempted = True
        app.prearm_host_start = None
        app.arm_token = None
        with patch.object(subject, "verify_installed_apk") as verify:
            app.cleanup_unarmed_launch()
        verify.assert_called_once_with(fake, app.pins.apk_sha256)
        self.assertEqual([call[:3] for call in fake.calls if call[0] == "shell"],
                         [("shell", "am", "force-stop")])
        self.assertTrue(fake.stopped)

    def test_unarmed_cleanup_forbidden_after_prearm_begins(self) -> None:
        app, fake = app_with_fake()
        app.launch_attempted = True
        with self.assertRaisesRegex(host.TrialError,
                                    "PREARM_CLEANUP_FORBIDDEN"):
            app.cleanup_unarmed_launch()
        self.assertFalse(any(call[0] == "shell" for call in fake.calls))


if __name__ == "__main__":
    unittest.main()
