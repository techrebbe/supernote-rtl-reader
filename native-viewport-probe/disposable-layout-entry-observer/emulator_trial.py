"""One-shot synthetic app adapter; never targets the stock reader or Nomad.

Every action is exact-serial and bounded. The app owns all root invalidation,
layout/paint work, rollback, sentinels and the prearm self-kill watchdog.
"""
from __future__ import annotations

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
        self.refresh_token: str | None = None
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

    def _state(self, admission: Admission) -> dict[str, Any]:
        self._require_process(admission)
        state = self.adb.provider_state(timeout=self._time_left())
        need(type(state) is dict and state.get("schema") ==
             "layout-fence-synthetic-v1" and
             state.get("activityPresent") is True and
             state.get("activitySerial") == admission.activity_serial and
             state.get("activityToken") == admission.activity_token and
             state.get("rootToken") == admission.root_token and
             state.get("lifecycle") == "RESUMED" and
             state.get("rootAttached") is True and
             state.get("rootHasFocus") is True and
             state.get("parentSoleChild") is True and
             state.get("rootLost") is False and
             state.get("originalsExact") is True and
             state.get("sessionTainted") is False and
             state.get("watchdogExpired") is False and
             state.get("rootLayoutRequested") is False and
             state.get("parentLayoutRequested") is False,
             "APP_SCENE_DRIFT")
        process = _identity(state.get("process"), admission)
        need(self.arm_deadline_ms is None or
             process.get("armDeadlineElapsedMs") == self.arm_deadline_ms,
             "APP_ARM_DRIFT")
        return state

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
        self._require_process(admission)
        need(self.baseline_frame is not None and
             self.baseline_paint_revision is not None,
             "BASELINE_PROOF_MISSING")
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
        expiry = min(time.monotonic() + 2.5,
                     (self.host_deadline or time.monotonic()) - ARM_MARGIN)
        while time.monotonic() < expiry:
            state = self._state(admission)
            current = _cut(state.get("current"), admission, self.baseline_frame)
            completed = _cut(state.get("lastCompletedPaint"), admission,
                             self.baseline_frame)
            sample = _integer(state.get("sampleElapsedMs"))
            if (completed["exactNinePainted"] is True and
                    completed["startedPaintRevision"] > floor and
                    completed["completedPaintRevision"] >
                        self.baseline_paint_revision and
                    completed["paintStartedElapsedMs"] >= requested and
                    completed["completedPaintElapsedMs"] >= requested and
                    current == completed and
                    sample >= completed["completedPaintElapsedMs"] and
                    sample - completed["completedPaintElapsedMs"] <= 1000 and
                    state.get("refreshRequested") is True and
                    state.get("refreshPaintFloorRevision") == floor and
                    state.get("refreshCompletedPaintCountFloor") == count_floor and
                    state.get("refreshRequestedElapsedMs") == requested and
                    state.get("completedPaintCount", 0) > count_floor and
                    state["process"].get("armState") == "REFRESH_REQUESTED"):
                self.baseline_frame = completed
                self.baseline_paint_revision = completed["completedPaintRevision"]
                return
            time.sleep(0.05)
        raise TrialError("REFRESHED_PAINT_UNAVAILABLE")

    def execute_and_restore(self, variant: str, admission: Admission) -> None:
        self._require_process(admission)
        started = time.monotonic()
        need(self.refresh_token is not None and
             self.baseline_frame is not None,
             "REFRESH_PROOF_MISSING")
        fields = self.adb.provider_call("command", variant,
                    self._extras(admission, armed=True, refreshed=True),
                    timeout=self._time_left(3.0))
        bundle_json(fields, {"ok", "command", "json"})
        need(fields["command"] == variant, "APP_COMMAND_MISMATCH")
        active_deadline = started + TRIAL_MS / 1000.0
        while time.monotonic() < active_deadline:
            state = self._state(admission)
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
        self.barrier_state = self._state(admission)
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
        state = self._state(admission)
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
        state = self._state(admission)
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
