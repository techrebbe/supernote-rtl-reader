"""One-shot synthetic app adapter; never targets the stock reader or Nomad.

Every action is exact-serial and bounded. The app owns all root invalidation,
layout/paint work, rollback, sentinels and the prearm self-kill watchdog.
"""
from __future__ import annotations

import math
from pathlib import Path
import time
from typing import Any

from app_evidence import _cut, derive_entries
from emulator_wire import (ExactAdb, TOKEN, bundle_json,
                           verify_installed_apk)
from frida_worker import WorkerSession
from host_protocol import Admission, ExpectedEntry, PACKAGE, Pins, SERIAL, \
    TrialError, need


ARM_MARGIN = 1.5
TRIAL_MS = 5000
APP_BASELINE_FRESHNESS_MS = 2000
HOST_SAMPLE_FRESHNESS_MS = 1000
COMMAND_DELIVERY_RESERVE_MS = 500
MAX_REFRESH_SAMPLES = 8

# Diagnostic strings are projected onto known, static app vocabulary. An
# unexpected reason (including one containing a token) is never serialized.
_LIFECYCLE_LABELS = frozenset({"NEW", "CREATED", "STARTED", "RESUMED",
                               "PAUSED", "STOPPED", "DESTROYED"})
_ARM_LABELS = frozenset({"UNPUBLISHED", "IDLE", "ARMED",
                         "REFRESH_DISPATCHING", "REFRESH_REQUESTED",
                         "COMMAND_DISPATCHING", "TRIAL_WATCHDOG_ACTIVE",
                         "DISARM_SENTINEL_DISPATCHING", "DISARM_SENTINEL_DONE",
                         "UNLOAD_SENTINEL_DISPATCHING", "UNLOAD_SENTINEL_DONE",
                         "FINISHED", "ABORTED", "FAILED"})
_TRIAL_LABELS = frozenset({"IDLE", "WAIT_FIRST_CALL", "WAIT_ABA_RETURN",
                           "WAIT_FIRST_PAINT", "WAIT_RESTORE_CALL",
                           "WAIT_RESTORE_PAINT", "WAIT_SECOND_PAINT_REQUEST",
                           "WAIT_SECOND_PAINT", "WAIT_FINAL_SAMPLE", "PASS",
                           "UNKNOWN"})
_COMMAND_LABELS = frozenset({"parent-plus-one", "parent-minus-one",
                             "unchanged-bounds", "direct-root-layout",
                             "direct-root-offset", "away-back-aba"})
_REASON_LABELS = frozenset({
    "NONE", "NOT_STARTED", "PENDING", "UNKNOWN", "TRIAL_TIMEOUT",
    "ACTIVITY_PAUSED", "ACTIVITY_STOPPED", "ACTIVITY_DESTROYED",
    "WINDOW_FOCUS_LOST", "ROOT_DETACHED", "PARENT_DETACHED",
    "ROOT_HIERARCHY_CHANGED", "PARENT_ROOT_NOT_ATTACHED",
    "PARENT_NOT_SOLE_OWNER", "PARENT_CHILD_REMOVED", "FOREIGN_PARENT_CHILD",
    "UNEXPECTED_UNFENCED_ROOT_LAYOUT", "ROOT_LAYOUT_AFTER_WRITE_UNFENCED",
    "POST_PASS_PARENT_LAYOUT", "POST_PASS_PAINT", "ARM_HANDOFF_REJECTED",
    "BASELINE_CUT_CHANGED", "BASELINE_NOT_READY", "BASELINE_PAINT_STALE",
    "DIRECT_LAYOUT_AFTER_WRITE", "DIRECT_OFFSET_AFTER_WRITE",
    "EXTRA_PAINT_BEFORE_RESTORE", "PAINT_ORDER_OR_NINE_MISMATCH",
    "PAINT_REVISION_OVERFLOW", "PAINT_STATE_CHANGED_OR_CHILD_SKIPPED",
    "NESTED_PAINT", "PARENT_PRECALL_NOT_EXCLUSIVE",
    "PARENT_LAYOUT_STAGE_MISMATCH", "PARENT_TARGET_MISMATCH",
    "FIRST_ENTRY_NOT_BASELINE", "ABA_RETURN_ENTRY_DRIFT",
    "ABA_REVISION_NOT_MONOTONIC", "COMPLETED_PAINT_MISMATCH",
    "RESTORE_ENTRY_DRIFT", "RESTORATION_PAINT_NOT_LATER",
    "SECOND_COMPLETED_PAINT_MISMATCH", "SECOND_SAMPLE_NOT_RESTORED",
    "SECOND_SAMPLE_DEADLINE_OR_MISSING_FRAME", "UNREQUESTED_SECOND_PAINT",
    "PARENT_LAYOUT_AFTER_MISMATCH", "UNEXPECTED_PARENT_PRECALL",
    "SECOND_PAINT_REQUEST_NOT_FRESH", "DIRECT_BYPASS_NOT_ISOLATED",
    "BYPASS_CONTROL_RESTORED", "PARENT_PATH_RESTORED",
    "SENTINEL_SCENE_OR_PAINT_DRIFT", "FINAL_SAMPLE_SCENE_NOT_STABLE",
    "SECOND_PAINT_SCENE_NOT_STABLE", "CLEANUP_SECOND_REQUEST_DRIFT",
    "CLEANUP_SECOND_PAINT_MISMATCH", "COMMAND_REJECTED",
    "WATCHDOG_START_FAILED", "QUARANTINED_UNSAFE_ROOT",
    "RESTORE_QUARANTINED", "RESTORED_VERIFIED",
    "RESTORED_AFTER_UNKNOWN_TWO_PAINTS", "UNKNOWN_CLEANUP_VERIFIED",
    "SENTINEL_REJECTED", "SENTINEL_UNKNOWN", "SENTINEL_PASS",
})


def _integer(value: Any, minimum: int = 0) -> int:
    need(type(value) is int and minimum <= value <= 2**63 - 1,
         "APP_WIRE_INVALID")
    return value


def _identity(value: Any, admission: Admission) -> dict[str, Any]:
    need(type(value) is dict and value.get("pid") == admission.pid and
         value.get("incarnation") == admission.incarnation and
         value.get("activitySerial") == admission.activity_serial and
         value.get("activityPresent") is True and
         value.get("identityPublished") is True and
         value.get("everRegistered") is True,
         "APP_IDENTITY_DRIFT")
    _integer(value.get("sampleElapsedMs"))
    return value


def _scene_diagnostic(state: dict[str, Any], phase: str,
                      command_started: float | None) -> dict[str, Any]:
    """Fixed scalar whitelist from an already-returned provider state only."""
    def number(value: Any) -> int | None:
        return value if type(value) is int and -(2**63) <= value < 2**63 else None

    def flag(value: Any) -> bool | None:
        return value if type(value) is bool else None

    def label(value: Any, allowed: frozenset[str]) -> str | None:
        return value if type(value) is str and value in allowed else None

    process = state.get("process") if type(state.get("process")) is dict else {}
    trial = state.get("trial") if type(state.get("trial")) is dict else {}
    current = state.get("current") if type(state.get("current")) is dict else {}
    completed = (state.get("lastCompletedPaint") if
                 type(state.get("lastCompletedPaint")) is dict else {})
    bounds = state.get("rootBounds") if type(state.get("rootBounds")) is dict else {}
    since_command = (None if command_started is None else
        number(math.ceil(max(0.0, time.monotonic() - command_started) * 1000)))
    return {
        "phase": phase,
        "hostMsSinceCommand": since_command,
        "sampleElapsedMs": number(state.get("sampleElapsedMs")),
        "lifecycle": label(state.get("lifecycle"), _LIFECYCLE_LABELS),
        "rootAttached": flag(state.get("rootAttached")),
        "rootHasFocus": flag(state.get("rootHasFocus")),
        "parentSoleChild": flag(state.get("parentSoleChild")),
        "rootLost": flag(state.get("rootLost")),
        "originalsExact": flag(state.get("originalsExact")),
        "sessionTainted": flag(state.get("sessionTainted")),
        "sessionTaintReason": label(state.get("sessionTaintReason"),
                                    _REASON_LABELS),
        "watchdogExpired": flag(state.get("watchdogExpired")),
        "rootLayoutRequested": flag(state.get("rootLayoutRequested")),
        "parentLayoutRequested": flag(state.get("parentLayoutRequested")),
        "armState": label(process.get("armState"), _ARM_LABELS),
        "trialState": label(trial.get("state"), _TRIAL_LABELS),
        "trialReason": label(trial.get("reason"), _REASON_LABELS),
        "trialCommand": label(trial.get("command"), _COMMAND_LABELS),
        "trialCurrentlyValid": flag(trial.get("currentlyValid")),
        "rootBounds": {key: number(bounds.get(key)) for key in
                       ("left", "top", "right", "bottom")},
        "parentPreCallRevision": number(state.get("parentPreCallRevision")),
        "observedWriteOrdinal": number(state.get("observedWriteOrdinal")),
        "rootLayoutCallCount": number(state.get("rootLayoutCallCount")),
        "completedPaintCount": number(state.get("completedPaintCount")),
        "currentStartedPaintRevision": number(current.get("startedPaintRevision")),
        "currentCompletedPaintRevision": number(current.get("completedPaintRevision")),
        "lastStartedPaintRevision": number(completed.get("startedPaintRevision")),
        "lastCompletedPaintRevision": number(completed.get("completedPaintRevision")),
        "lastCompletedPaintElapsedMs": number(completed.get("completedPaintElapsedMs")),
    }


class EmulatorApp:
    def __init__(self, adb: ExactAdb, pins: Pins) -> None:
        self.adb = adb
        self.pins = pins
        self.admission: Admission | None = None
        self.signature: tuple[int, str, str] | None = None
        self.arm_token: str | None = None
        self.arm_deadline_ms: int | None = None
        self.host_deadline: float | None = None
        self.barrier_state: dict[str, Any] | None = None
        self.expected: tuple[ExpectedEntry, ...] | None = None
        self.baseline_paint_revision: int | None = None
        self.baseline_frame: dict[str, Any] | None = None
        self.refresh_request_elapsed_ms: int | None = None
        self.refresh_paint_floor_revision: int | None = None
        self.refresh_completed_count_floor: int | None = None
        self.refresh_token: str | None = None
        self.refresh_proof_host_received: float | None = None
        self.refresh_age_upper_at_receipt_ms: int | None = None
        self.refresh_samples: list[dict[str, Any]] = []
        self.command_host_started: float | None = None
        self.command_response_evidence: dict[str, Any] | None = None
        self.first_trial_poll_evidence: dict[str, Any] | None = None
        self.scene_failure_sample: dict[str, Any] | None = None
        self.prearm_host_start: float | None = None
        self.launch_attempted = False

    def _time_left(self, maximum: float = 3.0) -> float:
        need(self.host_deadline is not None, "APP_NOT_ARMED")
        remaining = self.host_deadline - time.monotonic() - ARM_MARGIN
        need(remaining > 0.2, "ARM_LEASE_TOO_CLOSE")
        return min(maximum, remaining)

    def _require_process(self, admission: Admission) -> None:
        need(self.signature is not None and
             self.adb.same_process(admission.pid, self.signature),
             "APP_PROCESS_DRIFT")

    def _validated_identity_state(self, state: Any,
                                  admission: Admission) -> dict[str, Any]:
        need(type(state) is dict and state.get("schema") ==
             "layout-fence-synthetic-v1" and
             state.get("activityPresent") is True and
             state.get("activitySerial") == admission.activity_serial and
             state.get("activityToken") == admission.activity_token and
             state.get("rootToken") == admission.root_token,
             "APP_IDENTITY_DRIFT")
        process = _identity(state.get("process"), admission)
        need(self.arm_deadline_ms is None or
             process.get("armDeadlineElapsedMs") == self.arm_deadline_ms,
             "APP_ARM_DRIFT")
        return state

    def _state(self, admission: Admission, *, phase: str,
               os_check: bool = True) -> dict[str, Any]:
        if os_check:
            self._require_process(admission)
        state = self._validated_identity_state(
            self.adb.provider_state(timeout=self._time_left()), admission)
        if phase == "trial-poll" and self.first_trial_poll_evidence is None:
            try:
                self.first_trial_poll_evidence = _scene_diagnostic(
                    state, phase, self.command_host_started)
            except BaseException:
                self.first_trial_poll_evidence = {"phase": phase,
                                                  "capture": "UNAVAILABLE"}
        scene_ok = (
             state.get("lifecycle") == "RESUMED" and
             state.get("rootAttached") is True and
             state.get("rootHasFocus") is True and
             state.get("parentSoleChild") is True and
             state.get("rootLost") is False and
             state.get("originalsExact") is True and
             state.get("sessionTainted") is False and
             state.get("watchdogExpired") is False and
             state.get("rootLayoutRequested") is False and
             state.get("parentLayoutRequested") is False)
        if not scene_ok:
            try:
                self.scene_failure_sample = _scene_diagnostic(
                    state, phase, self.command_host_started)
            except BaseException:
                self.scene_failure_sample = {"phase": phase,
                                             "capture": "UNAVAILABLE"}
        need(scene_ok, "APP_SCENE_DRIFT")
        return state

    def refresh_failure_evidence(self) -> dict[str, Any] | None:
        if self.refresh_token is None:
            return None
        return {"phase": "refresh", "requestElapsedMs":
                self.refresh_request_elapsed_ms,
                "paintFloorRevision": self.refresh_paint_floor_revision,
                "completedPaintCountFloor": self.refresh_completed_count_floor,
                "polls": list(self.refresh_samples)}

    def scene_failure_evidence(self) -> dict[str, Any] | None:
        if self.scene_failure_sample is None:
            return None
        return {"commandResponse": self.command_response_evidence,
                "firstTrialPoll": self.first_trial_poll_evidence,
                "failedState": self.scene_failure_sample}

    def _record_refresh_sample(self, sample: dict[str, Any]) -> None:
        # First observation plus the seven most recent; no raw state/tokens.
        if len(self.refresh_samples) == MAX_REFRESH_SAMPLES:
            self.refresh_samples.pop(1)
        self.refresh_samples.append(sample)

    def _extras(self, admission: Admission, *, armed: bool,
                refreshed: bool = False) -> dict[str, tuple[str, str]]:
        result = {
            "pid": ("i", str(admission.pid)),
            "incarnation": ("s", admission.incarnation),
            "activitySerial": ("l", str(admission.activity_serial)),
            "activityToken": ("s", admission.activity_token),
            "rootToken": ("s", admission.root_token),
        }
        if armed:
            need(self.arm_token is not None, "ARM_TOKEN_MISSING")
            result["armToken"] = ("s", self.arm_token)
        if refreshed:
            need(self.refresh_token is not None, "REFRESH_TOKEN_MISSING")
            result["refreshToken"] = ("s", self.refresh_token)
        return result

    def preflight(self) -> Admission:
        self.adb.check_emulator()
        verify_installed_apk(self.adb, self.pins.apk_sha256)
        need(self.adb.pid() is None, "APP_PROCESS_ALREADY_PRESENT")
        self.launch_attempted = True
        launched = self.adb.shell("am", "start", "-W", "-n",
                                  f"{PACKAGE}/.TrialActivity", timeout=4.0)
        need("Status: ok" in launched and
             f"Activity: {PACKAGE}/.TrialActivity" in launched,
             "APP_LAUNCH_UNCERTAIN")
        pid = self.adb.pid()
        need(pid is not None, "APP_PROCESS_MISSING")
        self.signature = self.adb.process_signature(pid)
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            need(self.adb.same_process(pid, self.signature),
                 "APP_PROCESS_DRIFT")
            try:
                state = self.adb.provider_state(timeout=1.0)
                process = state.get("process")
                if (state.get("activityPresent") is True and
                        state.get("lifecycle") == "RESUMED" and
                        state.get("rootHasFocus") is True and
                        type(process) is dict and
                        process.get("activitySerial") == 1 and
                        process.get("pid") == pid and
                        process.get("activityPresent") is True and
                        process.get("identityPublished") is True and
                        type(state.get("current")) is dict and
                        type(state.get("lastCompletedPaint")) is dict and
                        state["lastCompletedPaint"].get("exactNinePainted") is True):
                    break
            except TrialError:
                pass  # Read-only polling for the initial focus paint only.
            time.sleep(0.05)
        else:
            raise TrialError("APP_BASELINE_UNAVAILABLE")
        incarnation = process.get("incarnation")
        activity_token = state.get("activityToken")
        root_token = state.get("rootToken")
        need(all(type(value) is str and TOKEN.fullmatch(value) is not None
                 for value in (incarnation, activity_token, root_token)),
             "APP_TOKEN_INVALID")
        admission = Admission(SERIAL, "1", 30, PACKAGE,
                              self.pins.apk_sha256, self.pins.signer_sha256,
                              pid, incarnation, 1, activity_token,
                              root_token, True)
        admission.check(self.pins)
        self.admission = admission
        need(state.get("schema") == "layout-fence-synthetic-v1" and
             state.get("rootAttached") is True and
             state.get("parentSoleChild") is True and
             state.get("rootLost") is False and
             state.get("originalsExact") is True and
             state.get("sessionTainted") is False and
             state.get("rootLayoutRequested") is False and
             state.get("parentLayoutRequested") is False and
             state.get("revisionScope") == "PARENT_LAYOUT_CALL_ONLY" and
             state.get("trial", {}).get("state") == "IDLE",
             "APP_BASELINE_INVALID")
        current = _cut(state.get("current"), admission)
        frame = _cut(state.get("lastCompletedPaint"), admission, current)
        need(frame["exactNinePainted"] is True and
             current["bounds"] == frame["bounds"] and
             current["effectivePaintOrder"] == frame["effectivePaintOrder"] and
             current["completedPaintRevision"] == frame["completedPaintRevision"] and
             state.get("rootBounds") == current["bounds"],
             "APP_BASELINE_PAINT_INVALID")
        self.baseline_paint_revision = _integer(frame["completedPaintRevision"])
        self.baseline_frame = frame
        return admission

    def cleanup_unarmed_launch(self) -> None:
        """Only before prearm/attach, and only the pinned synthetic package.

        A lost am-start or baseline response is UNKNOWN even when this cleanup
        succeeds. It may never be used after a prearm call might have begun.
        """
        need(self.launch_attempted and self.prearm_host_start is None and
             self.arm_token is None, "PREARM_CLEANUP_FORBIDDEN")
        self.adb.check_emulator()
        verify_installed_apk(self.adb, self.pins.apk_sha256)
        self.adb.shell("am", "force-stop", PACKAGE)
        need(self.adb.pid() is None, "PREARM_CLEANUP_UNCERTAIN")

    def prearm(self, admission: Admission) -> None:
        self._require_process(admission)
        started = time.monotonic()
        self.prearm_host_start = started
        fields = self.adb.provider_call("prearm", None,
                    self._extras(admission, armed=False), timeout=3.0)
        identity = bundle_json(fields,
                    {"ok", "armToken", "armDeadlineElapsedMs", "json"})
        token = fields["armToken"]
        need(TOKEN.fullmatch(token) is not None, "ARM_TOKEN_INVALID")
        deadline = _integer(int(fields["armDeadlineElapsedMs"]))
        _identity(identity, admission)
        sample = _integer(identity["sampleElapsedMs"])
        need(identity.get("armState") == "ARMED" and
             identity.get("armFinished") is False and
             identity.get("armDeadlineElapsedMs") == deadline and
             0 < deadline - sample <= 30_000,
             "APP_PREARM_INVALID")
        self.arm_token = token
        self.arm_deadline_ms = deadline
        # Conservative: the sample was collected after the host call began.
        self.host_deadline = started + (deadline - sample) / 1000.0
        need(self.host_deadline - time.monotonic() > 12.0,
             "ARM_LEASE_TOO_SHORT")

    def freshen_baseline(self, admission: Admission) -> None:
        # The refresh provider consumes the exact five identity pins and arm
        # token. Do not spend the two-second app paint freshness window on a
        # second multi-command /proc probe after the already-checked attach.
        need(self.baseline_frame is not None and
             self.baseline_paint_revision is not None,
             "BASELINE_PROOF_MISSING")
        self.refresh_samples.clear()
        self.refresh_proof_host_received = None
        self.refresh_age_upper_at_receipt_ms = None
        fields = self.adb.provider_call("refresh", None,
                    self._extras(admission, armed=True),
                    timeout=self._time_left(3.0))
        identity = bundle_json(fields, {"ok", "refreshToken",
                    "paintFloorRevision", "completedPaintCountFloor",
                    "requestedElapsedMs", "json"})
        _identity(identity, admission)
        token = fields["refreshToken"]
        need(TOKEN.fullmatch(token) is not None and
             identity.get("armState") == "REFRESH_REQUESTED" and
             identity.get("armDeadlineElapsedMs") == self.arm_deadline_ms,
             "REFRESH_TOKEN_INVALID")
        floor = _integer(int(fields["paintFloorRevision"]))
        count_floor = _integer(int(fields["completedPaintCountFloor"]))
        requested = _integer(int(fields["requestedElapsedMs"]))
        need(floor >= self.baseline_paint_revision and count_floor > 0 and
             requested <= _integer(identity.get("sampleElapsedMs")),
             "REFRESH_FLOOR_INVALID")
        self.refresh_token = token
        self.refresh_request_elapsed_ms = requested
        self.refresh_paint_floor_revision = floor
        self.refresh_completed_count_floor = count_floor
        expiry = min(time.monotonic() + 2.5,
                     (self.host_deadline or time.monotonic()) - ARM_MARGIN)
        while time.monotonic() < expiry:
            poll_started = time.monotonic()
            state = self._state(admission, phase="refresh-poll", os_check=False)
            poll_received = time.monotonic()
            current = _cut(state.get("current"), admission, self.baseline_frame)
            completed = _cut(state.get("lastCompletedPaint"), admission,
                             self.baseline_frame)
            sample = _integer(state.get("sampleElapsedMs"))
            completed_count = _integer(state.get("completedPaintCount"))
            age_at_sample_ms = sample - completed["completedPaintElapsedMs"]
            poll_ms = math.ceil(max(0.0, poll_received - poll_started) * 1000)
            age_upper_ms = age_at_sample_ms + poll_ms
            refresh_fields_match = (state.get("refreshRequested") is True and
                state.get("refreshPaintFloorRevision") == floor and
                state.get("refreshCompletedPaintCountFloor") == count_floor and
                state.get("refreshRequestedElapsedMs") == requested)
            new_complete = (completed["exactNinePainted"] is True and
                completed["startedPaintRevision"] > floor and
                completed["completedPaintRevision"] >
                    self.baseline_paint_revision and
                completed["paintStartedElapsedMs"] >= requested and
                completed["completedPaintElapsedMs"] >= requested and
                completed_count > count_floor)
            scene_same = current == completed
            arm_current = (state["process"].get("armState") ==
                           "REFRESH_REQUESTED" and
                           state["process"].get("armFinished") is False)
            within_host_deadlines = (poll_received <= expiry and
                poll_received < (self.host_deadline or 0) - ARM_MARGIN)
            command_viable = (0 <= age_at_sample_ms <=
                HOST_SAMPLE_FRESHNESS_MS and
                age_upper_ms + COMMAND_DELIVERY_RESERVE_MS <
                    APP_BASELINE_FRESHNESS_MS and within_host_deadlines)
            self._record_refresh_sample({
                "startedDelta": completed["startedPaintRevision"] - floor,
                "completedDelta": completed["completedPaintRevision"] -
                    self.baseline_paint_revision,
                "countDelta": completed_count - count_floor,
                "sampleAgeMs": age_at_sample_ms,
                "pollRoundTripMs": poll_ms,
                "ageUpperAtReceiptMs": age_upper_ms,
                "exactNine": completed["exactNinePainted"],
                "currentMatchesCompleted": scene_same,
                "refreshFieldsMatch": refresh_fields_match,
                "armCurrent": arm_current,
                "withinHostDeadlines": within_host_deadlines,
                "commandViable": command_viable})
            if (new_complete and scene_same and refresh_fields_match and
                    arm_current and command_viable):
                self.baseline_frame = completed
                self.baseline_paint_revision = completed["completedPaintRevision"]
                self.refresh_proof_host_received = poll_received
                self.refresh_age_upper_at_receipt_ms = age_upper_ms
                return
            time.sleep(0.05)
        raise TrialError("REFRESHED_PAINT_UNAVAILABLE")

    def execute_and_restore(self, variant: str, admission: Admission) -> None:
        need(self.refresh_token is not None and
             self.baseline_frame is not None and
             self.refresh_proof_host_received is not None and
             self.refresh_age_upper_at_receipt_ms is not None,
             "REFRESH_PROOF_MISSING")
        # The last /state cut pinned process incarnation, Activity and root.
        # The command consumes those exact pins plus both one-shot tokens; an
        # intervening replacement cannot accept it. Re-probe /proc only after
        # the command so the app's 2s paint-freshness gate remains attainable.
        started = time.monotonic()
        self.command_host_started = started
        age_upper_now_ms = (self.refresh_age_upper_at_receipt_ms +
            math.ceil(max(0.0, started - self.refresh_proof_host_received) * 1000))
        remaining_fresh_ms = APP_BASELINE_FRESHNESS_MS - age_upper_now_ms
        need(remaining_fresh_ms > COMMAND_DELIVERY_RESERVE_MS,
             "REFRESH_PAINT_TOO_OLD_FOR_COMMAND")
        # The app checks its own 2s freshness at command execution. A reply
        # may arrive later; shortening its wait would make an accepted one-shot
        # command appear lost and unrepeatable without increasing safety.
        fields = self.adb.provider_call("command", variant,
                    self._extras(admission, armed=True, refreshed=True),
                    timeout=self._time_left(3.0))
        response = self._validated_identity_state(
            bundle_json(fields, {"ok", "command", "json"}), admission)
        try:
            self.command_response_evidence = _scene_diagnostic(
                response, "command-response", self.command_host_started)
        except BaseException:
            self.command_response_evidence = {"phase": "command-response",
                                              "capture": "UNAVAILABLE"}
        need(fields["command"] == variant, "APP_COMMAND_MISMATCH")
        need(response["process"].get("armState") ==
             "TRIAL_WATCHDOG_ACTIVE" and
             type(response.get("trial")) is dict and
             response["trial"].get("command") == variant and
             response["trial"].get("state") != "UNKNOWN",
             "APP_COMMAND_RESPONSE_INVALID")
        self._require_process(admission)
        active_deadline = started + TRIAL_MS / 1000.0
        while time.monotonic() < active_deadline:
            state = self._state(admission, phase="trial-poll")
            trial = state.get("trial")
            need(type(trial) is dict and trial.get("command") == variant,
                 "APP_COMMAND_DRIFT")
            if trial.get("state") == "PASS":
                need(trial.get("currentlyValid") is True and
                     trial.get("activeArmDeadlineElapsedMs") ==
                         self.arm_deadline_ms and
                     _integer(trial.get("trialDeadlineElapsedMs")) > 0,
                     "APP_PASS_NOT_CURRENT")
                return
            need(trial.get("state") != "UNKNOWN", "APP_TRIAL_UNKNOWN")
            time.sleep(0.05)
        raise TrialError("APP_TRIAL_TIMEOUT")

    def main_barrier(self, admission: Admission) -> None:
        self.barrier_state = self._state(admission, phase="main-barrier")
        need(self.barrier_state.get("trial", {}).get("state") == "PASS" and
             self.barrier_state["trial"].get("currentlyValid") is True,
             "APP_BARRIER_INVALID")

    def expected_entries(self, variant: str,
                         admission: Admission) -> tuple[ExpectedEntry, ...]:
        need(self.barrier_state is not None, "APP_BARRIER_MISSING")
        self.expected = derive_entries(self.barrier_state, admission, variant)
        trial = self.barrier_state["trial"]
        need(trial.get("activeArmDeadlineElapsedMs") == self.arm_deadline_ms and
             _integer(trial.get("trialDeadlineElapsedMs")) <
               self.arm_deadline_ms and
             _integer(trial["secondSample"]["completedPaintElapsedMs"]) <
               trial["trialDeadlineElapsedMs"],
             "APP_DEADLINE_PROOF_INVALID")
        return self.expected

    def _sentinel(self, stage: str, admission: Admission) -> None:
        fields = self.adb.provider_call("sentinel", stage,
                    self._extras(admission, armed=True),
                    timeout=self._time_left(3.0))
        witness = bundle_json(fields, {"ok", "unchanged", "stage", "json"})
        need(fields["unchanged"] == "true" and fields["stage"] == stage and
             witness.get("stage") == stage and
             witness.get("pid") == admission.pid and
             witness.get("incarnation") == admission.incarnation and
             witness.get("activitySerial") == admission.activity_serial and
             witness.get("activityToken") == admission.activity_token and
             witness.get("rootToken") == admission.root_token and
             witness.get("unchanged") is True and
             witness.get("reason") == "EXACT_NOOP_LAYOUT" and
             witness.get("before") == witness.get("after") and
             witness.get("beforeLastCompletedPaint") ==
                 witness.get("afterLastCompletedPaint") and
             witness.get("beforePaintCount") == witness.get("afterPaintCount"),
             "APP_SENTINEL_INVALID")
        state = self._state(admission, phase="sentinel-" + stage)
        expected_state = ("DISARM_SENTINEL_DONE" if stage == "after-disarm"
                          else "UNLOAD_SENTINEL_DONE")
        need(state["process"].get("armState") == expected_state and
             state["trial"].get("currentlyValid") is True and
             state.get("current") == witness["after"],
             "APP_SENTINEL_DRIFT")

    def sentinel_after_revert(self, admission: Admission) -> None:
        self._sentinel("after-disarm", admission)

    def sentinel_after_unload(self, admission: Admission) -> None:
        self._sentinel("after-unload", admission)

    def post_unload_verify(self, admission: Admission) -> None:
        state = self._state(admission, phase="post-unload")
        need(self.barrier_state is not None and self.expected is not None and
             state["trial"].get("currentlyValid") is True and
             state["process"].get("armState") == "UNLOAD_SENTINEL_DONE" and
             derive_entries(state, admission,
                            self.barrier_state["trial"]["command"]) ==
                 self.expected and
             state["current"] == self.barrier_state["current"] and
             state["lastCompletedPaint"] ==
                 self.barrier_state["lastCompletedPaint"],
             "APP_POST_UNLOAD_DRIFT")

    def finish_lease(self, admission: Admission) -> None:
        fields = self.adb.provider_call("finish", None,
                    self._extras(admission, armed=True),
                    timeout=self._time_left(3.0))
        identity = bundle_json(fields, {"ok", "json"})
        _identity(identity, admission)
        need(identity.get("armState") == "FINISHED" and
             identity.get("armFinished") is True,
             "APP_FINISH_UNCERTAIN")
        self._require_process(admission)
        # Successful synthetic-package lifecycle cleanup only. This is never
        # a fallback for uncertain hook or app state.
        self.adb.shell("am", "force-stop", PACKAGE)
        expiry = time.monotonic() + 3.0
        while time.monotonic() < expiry:
            if self.adb.pid() is None:
                return
            time.sleep(0.05)
        raise TrialError("FINISHED_PROCESS_STILL_PRESENT")

    def stop_exact_process(self, admission: Admission) -> None:
        need(self.signature is not None, "APP_STOP_UNCERTAIN")
        if not self.adb.same_process(admission.pid, self.signature):
            need(self.adb.pid() is None, "APP_PROCESS_DRIFT")
            return
        if self.arm_token is not None:
            try:
                self.adb.provider_call("abort", None,
                    self._extras(admission, armed=True), timeout=1.0)
            except TrialError:
                pass  # Abort is allowed to kill itself before replying.
        # A lost prearm response can leave a live app watchdog, but cannot
        # authorize a host PID kill or package-wide force-stop. Wait for the
        # independently app-owned deadline, then require exact process death.
        need(self.prearm_host_start is not None, "APP_STOP_TOKEN_UNKNOWN")
        expiry = min(time.monotonic() + 32.0,
                     (self.host_deadline or self.prearm_host_start + 30.0) + 2.0)
        while time.monotonic() < expiry:
            if self.adb.pid() is None:
                return
            need(self.adb.same_process(admission.pid, self.signature),
                 "APP_PROCESS_DRIFT")
            time.sleep(0.1)
        raise TrialError("APP_WATCHDOG_NOT_OBSERVED")


class WorkerTransport:
    def __init__(self, app: EmulatorApp, python: Path, frida_site: Path,
                 bundle: Path, bundle_sha: str) -> None:
        self.app = app
        self.python = python
        self.frida_site = frida_site
        self.bundle = bundle
        self.bundle_sha = bundle_sha

    def attach(self, pid: int) -> WorkerSession:
        need(self.app.admission is not None and
             pid == self.app.admission.pid and
             self.app.host_deadline is not None and
             self.app.host_deadline - time.monotonic() > 8.0,
             "ATTACH_LEASE_TOO_SHORT")
        self.app._require_process(self.app.admission)
        return WorkerSession(self.python, self.frida_site, self.bundle,
                             self.bundle_sha, pid,
                             deadline_monotonic=self.app.host_deadline)
