"""Offline coordinator contract for the synthetic layout-entry emulator trial.

No ADB or Frida backend is supplied here. A later backend must authenticate the
exact disposable process, enforce per-operation deadlines, and own exact-PID
termination. This module deliberately cannot run against a device by itself.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Protocol


PACKAGE = "com.techrebbe.supernote.layoutfencetrial"
SERIAL = "emulator-5554"
MAX_EVENTS = 16
MAX_CALLBACKS = 4096
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]{0,18})\Z")
VARIANTS = frozenset({"parent-plus-one", "parent-minus-one",
                      "unchanged-bounds", "direct-root-layout",
                      "direct-root-offset", "away-back-aba"})


class TrialError(RuntimeError):
    """A fixed, path-free rejection code."""


def need(value: bool, code: str) -> None:
    if not value:
        raise TrialError(code)


def _number(value: Any, lo: int, hi: int) -> int:
    need(type(value) is int and lo <= value <= hi, "FRAME_INVALID")
    return value


def _decimal(value: Any) -> str:
    need(type(value) is str and DECIMAL_RE.fullmatch(value) is not None,
         "FRAME_INVALID")
    return value


def _bounds(value: Any) -> tuple[int, int, int, int]:
    need(type(value) is list and len(value) == 4, "FRAME_INVALID")
    return tuple(_number(item, -(2**31), 2**31 - 1) for item in value)  # type: ignore[return-value]


@dataclass(frozen=True)
class Pins:
    """Hashes come from the separately reviewed disposable APK build."""

    apk_sha256: str
    signer_sha256: str

    def __post_init__(self) -> None:
        need(type(self.apk_sha256) is str and type(self.signer_sha256) is str and
             SHA_RE.fullmatch(self.apk_sha256) is not None and
             SHA_RE.fullmatch(self.signer_sha256) is not None, "PINS_INVALID")


@dataclass(frozen=True)
class Admission:
    """Normalized output of a future independently authenticated preflight."""

    serial: str
    qemu: str
    api: int
    package: str
    apk_sha256: str
    signer_sha256: str
    pid: int
    incarnation: str
    activity_serial: int
    activity_token: str
    root_token: str
    baseline_paint_valid: bool

    def check(self, pins: Pins) -> None:
        need(self.serial == SERIAL and self.qemu == "1" and self.api == 30 and
             self.package == PACKAGE and self.apk_sha256 == pins.apk_sha256 and
             self.signer_sha256 == pins.signer_sha256 and
             type(self.pid) is int and 1 <= self.pid <= 2**31 - 1 and
             type(self.incarnation) is str and TOKEN_RE.fullmatch(self.incarnation) is not None and
             type(self.activity_serial) is int and self.activity_serial == 1 and
             type(self.activity_token) is str and TOKEN_RE.fullmatch(self.activity_token) is not None and
             type(self.root_token) is str and TOKEN_RE.fullmatch(self.root_token) is not None and
             self.baseline_paint_valid is True, "PREFLIGHT_REJECTED")

    def observer_config(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "pid": self.pid,
                "incarnation": self.incarnation,
                "activityToken": self.activity_token,
                "rootToken": self.root_token}


@dataclass(frozen=True)
class ExpectedEntry:
    """One app-normalized method-entry witness, not a raw provider schema."""

    old_bounds: tuple[int, int, int, int]
    proposed_bounds: tuple[int, int, int, int]
    parent_revision: str
    observed_write_ordinal: str | None = None
    layout_calls_before: str | None = None
    paint_count_before: str | None = None


class Hook(Protocol):
    def arm(self, config: dict[str, Any]) -> dict[str, Any]: ...
    def snapshot(self) -> dict[str, Any]: ...
    def disarm(self) -> dict[str, Any]: ...
    def unload(self) -> None: ...


class Session(Protocol):
    hook: Hook
    def detach(self) -> None: ...


class Transport(Protocol):
    def attach(self, pid: int) -> Session: ...


class App(Protocol):
    def preflight(self) -> Admission: ...
    def prearm(self, admission: Admission) -> None: ...
    def freshen_baseline(self, admission: Admission) -> None: ...
    def execute_and_restore(self, variant: str, admission: Admission) -> None: ...
    def main_barrier(self, admission: Admission) -> None: ...
    def expected_entries(self, variant: str, admission: Admission) -> tuple[ExpectedEntry, ...]: ...
    def sentinel_after_revert(self, admission: Admission) -> None: ...
    def sentinel_after_unload(self, admission: Admission) -> None: ...
    def post_unload_verify(self, admission: Admission) -> None: ...
    def finish_lease(self, admission: Admission) -> None: ...
    def stop_exact_process(self, admission: Admission) -> None: ...


def checked_snapshot(value: Any, expected: tuple[ExpectedEntry, ...],
                     *, phase: str) -> dict[str, Any]:
    need(type(value) is dict and set(value) == {"phase", "fault", "hookRemoved",
         "callbacks", "activeCallbacks", "forwardAttempts", "targetEntries", "events"},
         "FRAME_INVALID")
    need(value["phase"] == phase and value["fault"] is None and
         value["hookRemoved"] is (phase == "DISARMED"), "HOOK_STATE_UNCERTAIN")
    calls = _number(value["callbacks"], 0, MAX_CALLBACKS)
    need(_number(value["forwardAttempts"], 0, MAX_CALLBACKS) == calls and
         _number(value["activeCallbacks"], 0, MAX_CALLBACKS) == 0,
         "FORWARD_UNCERTAIN")
    entries = _number(value["targetEntries"], 0, MAX_EVENTS)
    events = value["events"]
    need(type(events) is list and len(events) == entries == len(expected),
         "ENTRY_COUNT_MISMATCH")
    for ordinal, (event, witness) in enumerate(zip(events, expected), 1):
        need(type(event) is dict and set(event) == {"ordinal", "oldBounds",
             "proposedBounds", "parentRevision", "observedWriteOrdinal",
             "layoutCallsBefore", "paintCountBefore", "mainThread",
             "originalReturned"}, "FRAME_INVALID")
        need(_number(event["ordinal"], ordinal, ordinal) == ordinal and
             _bounds(event["oldBounds"]) == witness.old_bounds and
             _bounds(event["proposedBounds"]) == witness.proposed_bounds and
             _decimal(event["parentRevision"]) == witness.parent_revision and
             (witness.observed_write_ordinal is None or
              _decimal(event["observedWriteOrdinal"]) == witness.observed_write_ordinal) and
             (witness.layout_calls_before is None or
              _decimal(event["layoutCallsBefore"]) == witness.layout_calls_before) and
             (witness.paint_count_before is None or
              _decimal(event["paintCountBefore"]) == witness.paint_count_before) and
             event["mainThread"] is True and event["originalReturned"] is True,
             "ENTRY_MISMATCH")
        # Diagnostic counters are still bounded numeric strings even when the
        # app did not independently snapshot their exact pre-call values.
        _decimal(event["observedWriteOrdinal"])
        _decimal(event["layoutCallsBefore"])
        _decimal(event["paintCountBefore"])
    return value


def run_mockable(app: App, transport: Transport, pins: Pins,
                 variant: str) -> dict[str, Any]:
    """Coordinate a single already-reviewed synthetic incarnation.

    Backend methods must be independently bounded. The app owns its deadline,
    restoration and separate watchdog; this function is not those authorities.
    On any uncertain attached path, it stops only the pinned disposable process.
    """
    need(type(variant) is str and variant in VARIANTS, "VARIANT_INVALID")
    admission = app.preflight()
    admission.check(pins)
    session: Session | None = None
    prearm_attempted = False
    attached = False
    unload_attempted = False
    detach_attempted = False
    failure: TrialError | None = None
    checked: dict[str, Any] | None = None
    try:
        prearm_attempted = True
        app.prearm(admission)
        session = transport.attach(admission.pid)
        attached = True
        arm = session.hook.arm(admission.observer_config())
        need(type(arm) is dict and arm == {"ok": True, "phase": "ARMED",
             "hookInstalled": True, "pid": admission.pid,
             "rootToken": admission.root_token}, "ARM_UNCERTAIN")
        app.freshen_baseline(admission)
        app.execute_and_restore(variant, admission)
        # This must be a completed provider round-trip on the app main Looper;
        # a hook-produced frame alone is not a quiescence barrier.
        app.main_barrier(admission)
        expected = app.expected_entries(variant, admission)
        need(type(expected) is tuple and len(expected) <= MAX_EVENTS and
             all(type(entry) is ExpectedEntry for entry in expected),
             "APP_EVIDENCE_INVALID")
        checked = checked_snapshot(session.hook.snapshot(), expected, phase="ARMED")
        disarm = session.hook.disarm()
        need(type(disarm) is dict and disarm == {"ok": True, "phase": "DISARMED",
             "code": "DISARMED", "cleanupCertain": True,
             "callbacks": checked["callbacks"],
             "forwardAttempts": checked["forwardAttempts"]},
             "DISARM_UNCERTAIN")
        app.sentinel_after_revert(admission)
        after_sentinel = checked_snapshot(session.hook.snapshot(), expected,
                                          phase="DISARMED")
        need(after_sentinel["callbacks"] == checked["callbacks"] and
             after_sentinel["forwardAttempts"] == checked["forwardAttempts"] and
             after_sentinel["events"] == checked["events"],
             "REVERT_SENTINEL_FAILED")
        unload_attempted = True
        session.hook.unload()
        detach_attempted = True
        session.detach()
        app.sentinel_after_unload(admission)
        app.post_unload_verify(admission)
        app.finish_lease(admission)
    except BaseException as error:
        failure = error if type(error) is TrialError else TrialError("TRIAL_UNCERTAIN")
    if failure is not None:
        stop_ok = False
        try:
            if prearm_attempted:
                app.stop_exact_process(admission)
            stop_ok = True
        except BaseException:
            pass
        if session is not None and not unload_attempted:
            unload_attempted = True
            try: session.hook.unload()
            except BaseException: pass
        if session is not None and not detach_attempted:
            detach_attempted = True
            try: session.detach()
            except BaseException: pass
        raise TrialError(str(failure) if stop_ok else "STOP_UNCERTAIN") from failure
    need(checked is not None, "TRIAL_UNCERTAIN")
    return {"verdict": "PASS_SYNTHETIC_EDGE_ONLY", "variant": variant,
            "pid": admission.pid, "incarnation": admission.incarnation,
            "targetEntries": checked["targetEntries"],
            "observationOnly": True, "compositingAdmitted": False,
            "completeMutationCoverage": False, "portRevision": -1,
            "hookRemoved": True, "postUnloadVerified": True}
