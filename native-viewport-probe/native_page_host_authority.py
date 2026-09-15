"""Typed, offline-injectable authority for the frozen visual-only host APK.

No launcher, logcat fallback, document launch, input, process kill, or path import
authority exists here. S6 must provide retained APK/process authority, complete
independent AM/window/display captures, and a producer-authenticated event
channel. A UUID printed in a log is not producer authentication.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Callable, Protocol
import uuid

HOST_PACKAGE = "com.techrebbe.supernote.nativepagehost"
HOST_COMPONENT = HOST_PACKAGE + "/" + HOST_PACKAGE + ".NativePageHostActivity"
# The reproducible reviewed build is unsigned; the byte-identical signed output
# is what may actually be installed. Never conflate those two package images.
REVIEWED_UNSIGNED_APK_SHA256 = "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178"
INSTALLED_APK_SHA256 = "39abffb0c55ff0cacd5ab7b9917a529d2744684b43a96ade63c1f3374121617e"
APK_SHA256 = INSTALLED_APK_SHA256
DEX_SHA256 = "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6"
SIGNER_CERT_SHA256 = "a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67"
FOREIGN_PACKAGE = "com.supernote.document"
FOREIGN_COMPONENT = FOREIGN_PACKAGE + "/" + FOREIGN_PACKAGE + ".document.DocumentActivity"
FLAGS = frozenset({"PUBLIC", "OWN_CONTENT_ONLY", "DESTROY_CONTENT_ON_REMOVAL"})
COMMAND_NS = 1_500_000_000
MAX_CAPTURE_ROWS = 256
MAX_EVENT_BYTES = 4096
MAX_EVENTS = 2048
HEX = re.compile(r"[0-9a-f]{64}\Z")


class HostAuthorityError(RuntimeError): pass
class HostQuiescenceError(HostAuthorityError): pass


class Placement(Enum):
    FULL = "FULL"
    LEFT = "LEFT"
    RIGHT = "RIGHT"


@dataclass(frozen=True)
class Rect:
    left: int
    top: int
    width: int
    height: int

    def wire(self) -> list[int]: return [self.left, self.top, self.width, self.height]


def placement_frame(placement: Placement, width: int, height: int) -> tuple[Placement, Rect]:
    if type(placement) is not Placement: raise HostAuthorityError("placement is not a closed typed value")
    if (width, height) == (1404, 1872): return Placement.FULL, Rect(0, 0, 1404, 1872)
    if (width, height) != (1872, 1404): raise HostAuthorityError("physical display geometry is not canonical")
    return placement, {Placement.FULL: Rect(409, 0, 1053, 1404),
                       Placement.LEFT: Rect(0, 78, 936, 1248),
                       Placement.RIGHT: Rect(936, 78, 936, 1248)}[placement]


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    uid: int
    package: str


@dataclass(frozen=True)
class PackageRecord:
    package: str
    apk_sha256: str
    reviewed_unsigned_apk_sha256: str
    dex_sha256: str
    signer_cert_sha256: str
    version_code: int
    version_name: str


PINNED_PACKAGE = PackageRecord(
    HOST_PACKAGE,
    INSTALLED_APK_SHA256,
    REVIEWED_UNSIGNED_APK_SHA256,
    DEX_SHA256,
    SIGNER_CERT_SHA256,
    2,
    "0.0.2-native-page-visual-only",
)


@dataclass(frozen=True)
class ActivityRecord:
    process: ProcessIdentity
    task_id: int
    component: str
    token: str
    display_id: int
    resumed: bool
    visible: bool


@dataclass(frozen=True)
class WindowRecord:
    process: ProcessIdentity
    task_id: int
    activity_token: str
    display_id: int
    frame: Rect
    visible: bool
    focused: bool
    surface_frame: Rect | None = None
    buffer: tuple[int, int] | None = None


@dataclass(frozen=True)
class DisplayRecord:
    display_id: int
    owner: ProcessIdentity | None
    name: str
    width: int | None
    height: int | None
    density: int | None
    flags: frozenset[str]


@dataclass(frozen=True)
class Snapshot:
    captured_ns: int
    package: PackageRecord
    processes: tuple[ProcessIdentity, ...]
    activities: tuple[ActivityRecord, ...]
    windows: tuple[WindowRecord, ...]
    displays: tuple[DisplayRecord, ...]
    # Captures are independent, complete bounded parser results, not Frida fields.
    am_sha256: str
    window_sha256: str
    display_sha256: str
    process_sha256: str
    complete: bool = True


@dataclass(frozen=True)
class HostEvent:
    cursor: int
    produced_ns: int
    producer: ProcessIdentity
    session: str
    generation: int
    kind: str
    body: dict[str, Any]


@dataclass(frozen=True)
class ForeignIdentity:
    process: ProcessIdentity
    task_id: int
    activity_token: str
    evidence_sha256: str
    component: str = FOREIGN_COMPONENT

    def wire(self) -> dict[str, Any]:
        # Activity tokens remain independent AM/window evidence; the clean APK
        # accepts exactly these foreign identity fields, not a synthetic token.
        return {"package": self.process.package, "component": self.component,
                "task": self.task_id, "pid": self.process.pid, "uid": self.process.uid,
                "start_ticks": str(self.process.start_ticks), "evidence_sha256": self.evidence_sha256}


@dataclass(frozen=True)
class HostCommand:
    action: str
    session: str
    generation: int
    display_id: int
    sequence: int
    body_json: bytes
    issued_ns: int
    deadline_ns: int


@dataclass(frozen=True)
class AppliedPlacement:
    session: str
    generation: int
    display_id: int
    sequence: int
    requested: Placement
    effective: Placement
    rect: Rect


@dataclass(frozen=True)
class TaskAbsence:
    session: str
    generation: int
    display_id: int
    foreign: ForeignIdentity | None
    evidence_sha256: str
    captured_ns: int


class RetainedHostAuthority(Protocol):
    """S6 retains the installed pinned APK and exact process handle/identity."""
    def verify(self) -> None: ...
    def identity(self) -> ProcessIdentity: ...


class Providers(Protocol):
    """No method may derive expected authority from a caller-supplied path.

    Events are bounded normalized safety events from the clean host. The
    adapter authenticates kernel producer PID/start/UID and monotonic capture
    cursor, and maps producer time to this monotonic clock. It may filter
    irrelevant host diagnostics but cannot synthesize ACKs or their fields.
    READY, WAIT_FOREIGN_DESTROY and FOREIGN_DESTROYED have no sequence in the
    clean log: one outstanding command + fresh cursor + exact identity binds
    them. PLACEMENT_READY must carry its actual logged command sequence.
    send() targets only the retained already-running host activity; it cannot
    relaunch a missing process or infer authority from a successful adb exit.
    """
    def now_ns(self) -> int: ...
    def sleep_ns(self, duration_ns: int) -> None: ...
    def capture(self, deadline_ns: int) -> Snapshot: ...
    def next_event(self, limit: int, deadline_ns: int) -> HostEvent | None: ...
    def attest_event(self, event: HostEvent) -> None: ...
    def send(self, command: HostCommand, deadline_ns: int) -> None: ...


def _json(value: Any) -> bytes:
    try: return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as error: raise HostAuthorityError("non-data host payload") from error


def _bounded_data(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if depth > 8 or count[0] > 512: raise HostAuthorityError("host event topology exceeds bound")
    if value is None or type(value) is bool: return
    if type(value) is int and -(2 ** 63) <= value < 2 ** 63: return
    if type(value) is str and len(value) <= MAX_EVENT_BYTES: return
    if type(value) is list:
        for item in value: _bounded_data(item, depth + 1, count)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str: raise HostAuthorityError("host event key is not text")
            _bounded_data(key, depth + 1, count)
            _bounded_data(item, depth + 1, count)
        return
    raise HostAuthorityError("host event contains untyped/noncanonical data")


def _process(value: ProcessIdentity) -> None:
    if (type(value) is not ProcessIdentity or type(value.pid) is not int or value.pid <= 0 or
            type(value.start_ticks) is not int or not 0 < value.start_ticks < 10 ** 32 or
            type(value.uid) is not int or value.uid < 0 or type(value.package) is not str or not value.package):
        raise HostAuthorityError("invalid retained process identity")


class HostAuthority:
    def __init__(self, retained: RetainedHostAuthority, providers: Providers, session: str,
                 host_task_id: int, host_activity_token: str):
        if retained is None or providers is None: raise HostAuthorityError("authenticated retained host providers are required")
        try: canonical_session = str(uuid.UUID(session))
        except (ValueError, AttributeError, TypeError) as error: raise HostAuthorityError("invalid host session UUID") from error
        if canonical_session != session or type(host_task_id) is not int or host_task_id <= 0 or not host_activity_token:
            raise HostAuthorityError("host session/task/token is not exact")
        self._retained_process_authority = retained
        self._retained_providers = providers
        self.retained, self.providers = retained, providers
        self._retained_call(lambda selected: selected.verify())
        process = self._retained_call(lambda selected: selected.identity())
        _process(process)
        if process.package != HOST_PACKAGE: raise HostAuthorityError("wrong host package process")
        self.process, self.session = process, session
        self.host_task_id, self.host_token = host_task_id, host_activity_token
        self.phase, self.failure = "STARTABLE", None
        self.generation, self.display_id, self.sequence = 0, None, 0
        self._cursor, self._produced_ns = 0, -1
        self._admitted = self._session_seen = False
        self._density = None
        self._foreign: ForeignIdentity | None = None
        self._requested = Placement.FULL
        self._pending: HostCommand | None = None
        self._expected_ack: tuple[str, dict[str, Any]] | None = None
        self._observed_ack: HostEvent | None = None
        self._release_command: HostCommand | None = None
        self._release_proof: TaskAbsence | None = None
        self._proofs: list[TaskAbsence] = []
        self._suspended_deadline: int | None = None
        self._suspended = False
        self._runtime_reacquired = False
        self._placement_commands: dict[int, str] = {}
        self._placement_progress_seen: set[int] = set()
        self._emergency = self._released = self._destroyed_ack = self._empty_ack = False
        self._pre_attach_empty_ack = False
        self._commands_sealed = False

    @property
    def state(self) -> str: return "FAILED" if self.failure else self.phase

    @property
    def cleanup_obligations(self) -> tuple[str, ...]:
        if self.phase == "QUIESCENT": return ()
        result = ["exact host task/process lease remains retained"]
        if self.display_id is not None and not self._released: result.append(f"exact host display {self.display_id} generation {self.generation}")
        if self._foreign is not None: result.append(f"exact foreign task {self._foreign.task_id}; process liveness is separate")
        return tuple(result)

    def _fail(self, error: BaseException | str) -> None:
        if self.failure is None: self.failure = str(error)
        if self.phase == "QUIESCENT": self.phase = "FAILED_CLEANUP"

    def _dependency_slots(self) -> None:
        if self.retained is not self._retained_process_authority:
            raise HostAuthorityError(
                "retained host process authority object was substituted")
        if self.providers is not self._retained_providers:
            raise HostAuthorityError(
                "retained host provider object was substituted")

    def _provider_call(self, function: Callable[[Providers], Any]) -> Any:
        self._dependency_slots()
        selected = self._retained_providers
        try:
            result = function(selected)
        except BaseException as error:
            try:
                self._dependency_slots()
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._dependency_slots()
        return result

    def _retained_call(
            self, function: Callable[[RetainedHostAuthority], Any]) -> Any:
        self._dependency_slots()
        selected = self._retained_process_authority
        try:
            result = function(selected)
        except BaseException as error:
            try:
                self._dependency_slots()
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._dependency_slots()
        return result

    def _deadline(self, deadline_ns: int) -> None:
        now = self._provider_call(lambda selected: selected.now_ns())
        if type(now) is not int or type(deadline_ns) is not int or not now < deadline_ns <= now + 60_000_000_000:
            raise HostAuthorityError("host absolute deadline expired or invalid")

    def _verify(self) -> None:
        self._retained_call(lambda selected: selected.verify())
        if self._retained_call(lambda selected: selected.identity()) != self.process:
            raise HostAuthorityError("retained host PID/start/UID/image drift")

    def _require_commands_open(self) -> None:
        # This seal is irreversible, including if a later read-only check sees
        # display/PID reuse and withdraws the earlier absence observation.
        if self._commands_sealed or self._released or self.phase in {"RELEASED", "QUIESCENT", "FAILED_CLEANUP"}:
            raise HostAuthorityError("host mutating commands are permanently sealed after release/quiescence")

    def _command_event_time(self, event: HostEvent) -> None:
        # A fresh capture cursor does not imply a fresh producer event. Both
        # timestamps are mapped into the same authenticated monotonic domain.
        if self._pending is not None and event.produced_ns < self._pending.issued_ns:
            raise HostAuthorityError("host command ACK/progress predates exact pending command issued time")

    def _capture(self, deadline_ns: int) -> Snapshot:
        self._deadline(deadline_ns)
        self._verify()
        before = self._provider_call(lambda selected: selected.now_ns())
        snap = self._provider_call(
            lambda selected: selected.capture(deadline_ns))
        self._verify()
        self._deadline(deadline_ns)
        if (type(snap) is not Snapshot or snap.complete is not True or snap.package != PINNED_PACKAGE or
                type(snap.captured_ns) is not int or not before <= snap.captured_ns <=
                self._provider_call(lambda selected: selected.now_ns())):
            raise HostAuthorityError("installed APK/package or complete fresh capture authority differs")
        for rows, expected in ((snap.processes, ProcessIdentity), (snap.activities, ActivityRecord),
                               (snap.windows, WindowRecord), (snap.displays, DisplayRecord)):
            if type(rows) is not tuple or len(rows) > MAX_CAPTURE_ROWS or any(type(row) is not expected for row in rows):
                raise HostAuthorityError("snapshot topology exceeds bounded typed capture")
        if (type(snap.package) is not PackageRecord
                or type(snap.package.version_code) is not int
                or type(snap.package.version_name) is not str
                or type(snap.package.package) is not str
                or any(type(value) is not str or not HEX.fullmatch(value) for value in (
                    snap.package.apk_sha256,
                    snap.package.reviewed_unsigned_apk_sha256,
                    snap.package.dex_sha256,
                    snap.package.signer_cert_sha256,
                ))):
            raise HostAuthorityError("package authority is not exact typed data")
        for process in snap.processes: _process(process)
        for row in snap.activities + snap.windows:
            _process(row.process)
            if (type(row.task_id) is not int or row.task_id <= 0 or type(row.display_id) is not int or row.display_id < 0 or
                    type(row.visible) is not bool): raise HostAuthorityError("AM/window identity is not typed")
        for row in snap.activities:
            if type(row.resumed) is not bool or type(row.token) is not str or not row.token:
                raise HostAuthorityError("AM activity token/readiness is not typed")
        for row in snap.windows:
            if (type(row.focused) is not bool or type(row.activity_token) is not str or not row.activity_token or
                    type(row.frame) is not Rect): raise HostAuthorityError("window authority is not typed")
            for rect in (row.frame, row.surface_frame):
                if rect is not None and (type(rect) is not Rect or any(type(v) is not int for v in rect.wire())):
                    raise HostAuthorityError("window rectangle is not exact typed geometry")
        for row in snap.displays:
            if (type(row.display_id) is not int or row.display_id < 0 or type(row.flags) is not frozenset or
                    any(value is not None and type(value) is not int for value in (row.width, row.height, row.density))):
                raise HostAuthorityError("display metrics/identity are not exact typed data")
        for digest in (snap.am_sha256, snap.window_sha256, snap.display_sha256, snap.process_sha256):
            if type(digest) is not str or not HEX.fullmatch(digest): raise HostAuthorityError("independent capture evidence digest missing")
        if (len({p.pid for p in snap.processes}) != len(snap.processes) or
                len({d.display_id for d in snap.displays}) != len(snap.displays) or
                len({a.task_id for a in snap.activities}) != len(snap.activities) or
                len({w.activity_token for w in snap.windows}) != len(snap.windows)):
            raise HostAuthorityError("duplicate/ambiguous independent snapshot identity")
        return snap

    def _physical(self, snap: Snapshot, allowed: tuple[Placement, ...], *, paused: bool = False) -> tuple[Placement, Rect]:
        if self.process not in snap.processes: raise HostAuthorityError("host process absent/reused")
        activities = [a for a in snap.activities if a.task_id == self.host_task_id or a.token == self.host_token]
        windows = [w for w in snap.windows if w.task_id == self.host_task_id or w.activity_token == self.host_token]
        physical = [d for d in snap.displays if d.display_id == 0]
        if len(activities) != 1 or len(windows) != 1 or len(physical) != 1:
            raise HostAuthorityError("host AM/window/default-display identity absent or ambiguous")
        activity, window, display = activities[0], windows[0], physical[0]
        if (activity.process != self.process or activity.task_id != self.host_task_id or activity.token != self.host_token or
                activity.component != HOST_COMPONENT or activity.display_id != 0 or window.process != self.process or
                window.task_id != self.host_task_id or window.activity_token != self.host_token or window.display_id != 0 or
                (not paused and not (activity.resumed is True and activity.visible is True and window.visible is True and window.focused is True))):
            raise HostAuthorityError("host runtime authority paused, migrated, or changed")
        if type(display.density) is not int or display.density <= 0 or (self._density is not None and display.density != self._density):
            raise HostAuthorityError("physical density drift")
        if window.frame != Rect(0, 0, display.width, display.height) or window.buffer != (1404, 1872):
            raise HostAuthorityError("host root/fixed surface buffer mismatch")
        choices = [placement_frame(p, display.width, display.height) for p in allowed]
        if not any(rect == window.surface_frame for _, rect in choices): raise HostAuthorityError("measured host frame mismatch")
        return next(value for value in choices if value[1] == window.surface_frame)

    def _display(self, snap: Snapshot, *, metrics: bool = True) -> DisplayRecord:
        if self.display_id is None or self.display_id <= 0 or self.generation != 1:
            raise HostAuthorityError("strict allocated authority has no retained positive display")
        owned = [d for d in snap.displays if d.display_id == self.display_id or d.owner == self.process]
        if len(owned) != 1: raise HostAuthorityError("owned virtual display absent/duplicated")
        display = owned[0]
        if (display.display_id != self.display_id or display.owner != self.process or
                display.name != f"NativePageVisualOnly-{self.session}-{self.generation}" or display.flags != FLAGS):
            raise HostAuthorityError("virtual display ownership/session/generation/flags drift")
        if metrics and (display.width, display.height, display.density) != (1404, 1872, self._density):
            raise HostAuthorityError("virtual display metrics pending or changed")
        return display

    def _check_foreign(self, identity: ForeignIdentity, snap: Snapshot) -> None:
        if type(identity) is not ForeignIdentity: raise HostAuthorityError("foreign identity must be exact typed data")
        _process(identity.process)
        if (identity.process.package != FOREIGN_PACKAGE or identity.process.uid != 1000 or identity.component != FOREIGN_COMPONENT or
                type(identity.task_id) is not int or identity.task_id <= 0 or not identity.activity_token or
                type(identity.evidence_sha256) is not str or not HEX.fullmatch(identity.evidence_sha256)):
            raise HostAuthorityError("foreign task/package/component/UID evidence is invalid")
        activities = [a for a in snap.activities if a.task_id == identity.task_id or a.token == identity.activity_token]
        windows = [w for w in snap.windows if w.task_id == identity.task_id or w.activity_token == identity.activity_token]
        if (identity.process not in snap.processes or len(activities) != 1 or len(windows) != 1):
            raise HostAuthorityError("exact foreign AM/window/process absent or ambiguous")
        activity, window = activities[0], windows[0]
        if (activity != ActivityRecord(identity.process, identity.task_id, identity.component, identity.activity_token,
                                       self.display_id, True, True) or
                window.process != identity.process or window.task_id != identity.task_id or window.activity_token != identity.activity_token or
                window.display_id != self.display_id or window.visible is not True or window.frame != Rect(0, 0, 1404, 1872)):
            raise HostAuthorityError("foreign task/token/display/geometry migrated or drifted")

    def _event(self, deadline_ns: int) -> HostEvent | None:
        self._deadline(deadline_ns)
        self._verify()
        event = self._provider_call(
            lambda selected: selected.next_event(
                MAX_EVENT_BYTES, deadline_ns))
        if event is None: return None
        self._provider_call(lambda selected: selected.attest_event(event))
        self._verify()
        if type(event) is not HostEvent: raise HostAuthorityError("host event is not exact typed data")
        _bounded_data(event.body)
        if (type(event) is not HostEvent or event.producer != self.process or event.session != self.session or
                type(event.cursor) is not int or event.cursor != self._cursor + 1 or event.cursor > MAX_EVENTS or
                type(event.produced_ns) is not int or not self._produced_ns <=
                event.produced_ns <= self._provider_call(
                    lambda selected: selected.now_ns()) or
                type(event.generation) is not int or type(event.body) is not dict or
                len(_json(event.body)) > MAX_EVENT_BYTES):
            raise HostAuthorityError("host event producer/session/cursor/time/bound is invalid")
        if event.generation != self.generation and not (event.kind == "DISPLAY_ALLOCATED" and self.generation == 0 and event.generation == 1):
            raise HostAuthorityError("stale/out-of-order host generation")
        self._command_event_time(event)
        self._cursor, self._produced_ns = event.cursor, event.produced_ns
        return event

    @staticmethod
    def _body(event: HostEvent, expected: dict[str, Any]) -> None:
        if _json(event.body) != _json(expected): raise HostAuthorityError(f"{event.kind} acknowledgement body mismatch")

    def _progress(self, event: HostEvent) -> bool:
        if event.kind == "SESSION":
            if self._session_seen or self.generation: raise HostAuthorityError("duplicate/stale host session")
            self._body(event, {})
            self._session_seen = True
        elif not self._session_seen: raise HostAuthorityError("host event preceded authenticated fresh session")
        elif event.kind == "DISPLAY_ALLOCATED":
            value = event.body.get("display")
            if self.display_id is not None or type(value) is not int or value <= 0: raise HostAuthorityError("invalid duplicate display allocation")
            # Retain cleanup identity before the first fallible metrics check.
            self.display_id, self.generation, self.phase = value, event.generation, "DISPLAY_ALLOCATED"
            self._body(event, {"display": value})
        elif event.kind == "HOST_AUTHORITY_SUSPENDED":
            remaining = event.body.get("remaining_ms")
            if type(remaining) is not int or not 0 <= remaining <= 1500: raise HostAuthorityError("invalid host suspension deadline")
            self._body(event, {"remaining_ms": remaining})
            proposed = event.produced_ns + remaining * 1_000_000
            self._suspended_deadline = proposed if self._suspended_deadline is None else min(self._suspended_deadline, proposed)
            self._suspended = True
            self._runtime_reacquired = False
        elif event.kind == "HOST_AUTHORITY_READY":
            self._body(event, {})
            self._suspended = False  # Deadline is intentionally retained until the entire command completes.
        elif event.kind in {"HOST_AUTHORITY", "FRAME_READY", "HOST_AUTHORITY_REACQUIRED"}:
            self._body(event, {})
            if event.kind == "HOST_AUTHORITY_REACQUIRED": self._runtime_reacquired = True
        elif event.kind in {"COMMAND_DEFERRED", "COMMAND_RESUMED"}:
            if self._pending is None: raise HostAuthorityError("unsolicited command progress")
            self._body(event, {"sequence": self._pending.sequence, "action": self._pending.action})
        elif event.kind == "PLACEMENT_REQUESTED":
            sequence = event.body.get("sequence")
            if type(sequence) is not int or sequence not in self._placement_commands or sequence in self._placement_progress_seen:
                raise HostAuthorityError("unsolicited placement progress")
            self._body(event, {"sequence": sequence, "requested": self._placement_commands[sequence]})
            self._placement_progress_seen.add(sequence)
        elif event.kind in {"FAILED", "TIMEOUT", "RELEASE_FAILED"}:
            if event.kind == "FAILED":
                self._body(event, {"display": self.display_id, "emergency": event.body.get("emergency")})
                if type(event.body["emergency"]) is not bool: raise HostAuthorityError("malformed emergency evidence")
                self._emergency |= event.body["emergency"]
            elif event.kind == "RELEASE_FAILED":
                self._body(event, {"display": self.display_id, "retained": True, "retry_addressable": True})
            else:
                if event.body not in ({"phase": "foreign_attach"}, {"phase": "foreign_destroy"}, {"phase": "placement"}):
                    raise HostAuthorityError("unknown timeout phase")
            self._fail(event.kind)
            if event.kind == "RELEASE_FAILED": raise HostAuthorityError("host release exception; exact cleanup ownership retained")
        else: return False
        return True

    def _wait(self, kind: str, deadline_ns: int, body: dict[str, Any], *, cleanup: bool = False) -> HostEvent:
        if self._pending is not None: self._expected_ack = kind, body
        while True:
            if self._suspended_deadline is not None: deadline_ns = min(deadline_ns, self._suspended_deadline)
            event = self._event(deadline_ns)
            if event is None:
                self._provider_call(
                    lambda selected: selected.sleep_ns(
                        min(1_000_000, deadline_ns -
                            self._provider_call(
                                lambda retained: retained.now_ns()))))
                continue
            if event.kind == kind:
                self._body(event, body)
                if self._pending is not None: self._observed_ack = event
                self._deadline(deadline_ns)
                if self._suspended:
                    if not self._runtime_reacquired: raise HostAuthorityError("host acknowledgement while authority remains paused")
                    if not cleanup: self._complete_transition(deadline_ns)
                if self.failure and not cleanup: raise HostAuthorityError("sticky host failure prevents readiness")
                return event
            if not self._progress(event): raise HostAuthorityError("duplicate/out-of-order or unsolicited host acknowledgement")
            self._deadline(deadline_ns)
            if self.failure and not cleanup: raise HostAuthorityError(self.failure)

    def _complete_transition(self, deadline_ns: int) -> None:
        # The clean Activity may publish its command ACK from the deferred
        # replay immediately BEFORE it logs HOST_AUTHORITY_READY. Hold that
        # ACK until the same original transition fully completes.
        while self._suspended:
            if self._suspended_deadline is not None: deadline_ns = min(deadline_ns, self._suspended_deadline)
            event = self._event(deadline_ns)
            if event is None:
                self._provider_call(
                    lambda selected: selected.sleep_ns(
                        min(1_000_000, deadline_ns -
                            self._provider_call(
                                lambda retained: retained.now_ns()))))
                continue
            if not self._progress(event): raise HostAuthorityError("unexpected ACK during pending frame transition")
            self._deadline(deadline_ns)
            if self.failure: raise HostAuthorityError(self.failure)

    def admit_startable(self, deadline_ns: int) -> None:
        try:
            if self._admitted or self.failure or self.phase != "STARTABLE": raise HostAuthorityError("startable admission is single-use")
            self._wait("SESSION", deadline_ns, {})
            self._session_seen = True
            snap = self._capture(deadline_ns)
            self._physical(snap, (Placement.FULL,))
            if any(d.owner == self.process for d in snap.displays): raise HostAuthorityError("preallocation cannot invent already-allocated display authority")
            self._density = next(d.density for d in snap.displays if d.display_id == 0)
            self._admitted = True
        except BaseException as error:
            self._fail(error)
            raise

    def await_display_ready(self, deadline_ns: int) -> int:
        try:
            if not self._admitted or self.failure or self.phase != "STARTABLE": raise HostAuthorityError("display readiness requires fresh startable authority")
            while self.display_id is None:
                event = self._event(deadline_ns)
                if event is None:
                    self._provider_call(
                        lambda selected: selected.sleep_ns(1_000_000))
                    continue
                if not self._progress(event): raise HostAuthorityError("display ready before exact allocation")
                if self.failure: raise HostAuthorityError(self.failure)
            self._display(self._capture(deadline_ns), metrics=False)
            self._wait("DISPLAY_READY", deadline_ns, {"display": self.display_id, "density": self._density, "width": 1404, "height": 1872})
            snap = self._capture(deadline_ns)
            self._physical(snap, (Placement.FULL,))
            self._display(snap)
            self.phase = "WAITING_FOR_FOREIGN_ACK"
            self._settled()
            return self.display_id
        except BaseException as error:
            self._fail(error)
            raise

    def _command(self, action: str, body: dict[str, Any], deadline_ns: int, *, cleanup: bool = False) -> HostCommand:
        self._require_commands_open()
        self._deadline(deadline_ns)
        self._verify()
        if self._pending is not None or self.display_id is None or (self.failure and not cleanup):
            raise HostAuthorityError("host command admission closed or already pending")
        now = self._provider_call(lambda selected: selected.now_ns())
        command = HostCommand(action, self.session, self.generation, self.display_id, self.sequence + 1,
                              _json(body), now, min(deadline_ns, now + COMMAND_NS))
        self.sequence = command.sequence
        self._pending = command
        if action.startswith("PLACE_"): self._placement_commands[command.sequence] = action[6:]
        self._observed_ack = None
        self._expected_ack = None
        if action in {"ACK_FOREIGN_DESTROYED", "ACK_NO_FOREIGN_AFTER_FAILURE", "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"}: self._release_command = command
        self._provider_call(
            lambda selected: selected.send(command, command.deadline_ns))
        self._deadline(command.deadline_ns)
        return command

    def _settled(self) -> None:
        self._pending = None
        self._suspended_deadline = None
        self._suspended = False
        self._runtime_reacquired = False

    def attach_ack(self, identity: ForeignIdentity, deadline_ns: int) -> None:
        self._require_commands_open()
        try:
            if self.phase != "WAITING_FOR_FOREIGN_ACK" or self.failure: raise HostAuthorityError("attach is not ready")
            snap = self._capture(deadline_ns)
            self._physical(snap, (self._requested,))
            self._display(snap)
            self._check_foreign(identity, snap)
            self._foreign = identity  # Cleanup ownership precedes an uncertain send/ACK.
            command = self._command("ACK_FOREIGN_ATTACHED", {"foreign": identity.wire()}, deadline_ns)
            self._wait("READY", command.deadline_ns, {"foreign": identity.wire()})
            snap = self._capture(command.deadline_ns)
            self._physical(snap, (self._requested,))
            self._display(snap)
            self._check_foreign(identity, snap)
            self.phase = "ACTIVE"
            self._settled()
        except BaseException as error:
            self._fail(error)
            raise

    def place(self, placement: Placement, deadline_ns: int) -> AppliedPlacement:
        self._require_commands_open()
        try:
            if self.phase != "ACTIVE" or self.failure or type(placement) is not Placement: raise HostAuthorityError("placement requires active typed host authority")
            snap = self._capture(deadline_ns)
            self._physical(snap, (self._requested,))
            self._display(snap)
            self._check_foreign(self._foreign, snap)
            physical = next(d for d in snap.displays if d.display_id == 0)
            effective, rect = placement_frame(placement, physical.width, physical.height)
            command = self._command("PLACE_" + placement.value, {}, deadline_ns)
            self._wait("PLACEMENT_READY", command.deadline_ns, {"sequence": command.sequence, "requested": placement.value,
                                                               "effective": effective.value, "rect": rect.wire()})
            snap = self._capture(command.deadline_ns)
            self._physical(snap, (placement,))
            self._display(snap)
            self._check_foreign(self._foreign, snap)
            self._requested = placement
            self._settled()
            return AppliedPlacement(self.session, self.generation, self.display_id, command.sequence, placement, effective, rect)
        except BaseException as error:
            self._fail(error)
            raise

    def begin_close(self, deadline_ns: int) -> None:
        self._require_commands_open()
        try:
            if self._foreign is None or self.phase == "WAIT_FOREIGN_DESTROY": raise HostAuthorityError("close requires one exact admitted foreign task")
            if self._pending is not None:
                raise HostAuthorityError("uncertain prior command requires exact late-ACK reconciliation before close")
            self._suspended_deadline = None
            command = self._command("BEGIN_CLOSE", {}, deadline_ns, cleanup=True)
            self._wait("WAIT_FOREIGN_DESTROY", command.deadline_ns, {"foreign": self._foreign.wire()}, cleanup=True)
            self.phase = "WAIT_FOREIGN_DESTROY"
            self._settled()
        except BaseException as error:
            self._fail(error)
            raise

    def _absence(self, deadline_ns: int, foreign: ForeignIdentity | None) -> TaskAbsence:
        snap = self._capture(deadline_ns)
        return self._absence_from_snapshot(snap, foreign)

    def _absence_from_snapshot(self, snap: Snapshot, foreign: ForeignIdentity | None) -> TaskAbsence:
        if self.display_id is None: raise HostAuthorityError("absence proof lacks exact retained display")
        if any(a.display_id == self.display_id for a in snap.activities) or any(w.display_id == self.display_id for w in snap.windows):
            raise HostAuthorityError("owned virtual display still has foreign task/window content")
        if foreign is not None:
            if any(a.task_id == foreign.task_id or a.token == foreign.activity_token for a in snap.activities) or any(
                    w.task_id == foreign.task_id or w.activity_token == foreign.activity_token for w in snap.windows):
                raise HostAuthorityError("exact foreign task migrated or remains; process liveness is not task absence")
        digests = {"am": snap.am_sha256, "window": snap.window_sha256, "display": snap.display_sha256,
                   "process": snap.process_sha256, "captured_ns": snap.captured_ns, "session": self.session,
                   "generation": self.generation, "display_id": self.display_id, "foreign": asdict(foreign) if foreign else None}
        proof = TaskAbsence(self.session, self.generation, self.display_id, foreign, hashlib.sha256(_json(digests)).hexdigest(), snap.captured_ns)
        self._proofs = (self._proofs + [proof])[-128:]
        return proof

    def prove_task_absent(self, deadline_ns: int) -> TaskAbsence:
        try:
            if self._foreign is None: raise HostAuthorityError("no exact foreign task retained")
            return self._absence(deadline_ns, self._foreign)
        except BaseException as error:
            self._fail(error)
            raise

    def prove_empty(self, deadline_ns: int) -> TaskAbsence:
        try:
            if self._foreign is not None or not self.failure: raise HostAuthorityError("empty ACK only exists after pre-attach failure")
            return self._absence(deadline_ns, None)
        except BaseException as error:
            self._fail(error)
            raise

    def _require_pre_attach_empty(self) -> None:
        self._require_commands_open()
        if (self.failure is not None or self._foreign is not None or self._pending is not None or
                self.phase not in {"DISPLAY_ALLOCATED", "WAITING_FOR_FOREIGN_ACK"}):
            raise HostAuthorityError("healthy pre-attach abort requires an eligible empty display without foreign or pending command")

    def _pre_attach_absence(self, deadline_ns: int) -> TaskAbsence:
        snap = self._capture(deadline_ns)
        # Allocation identity is sufficient even while display metrics are
        # pending. The retained owner/name/generation/flags must still match.
        self._display(snap, metrics=False)
        return self._absence_from_snapshot(snap, None)

    def prove_pre_attach_empty(self, deadline_ns: int) -> TaskAbsence:
        """Prove a healthy allocated pre-attach display empty without failing it."""
        try:
            self._require_pre_attach_empty()
            return self._pre_attach_absence(deadline_ns)
        except BaseException as error:
            self._fail(error)
            raise

    def _proof(self, proof: TaskAbsence, deadline_ns: int, *, pre_attach: bool = False) -> None:
        if pre_attach and (type(proof) is not TaskAbsence or type(proof.session) is not str or
                any(type(value) is not int for value in (proof.generation, proof.display_id, proof.captured_ns))):
            raise HostAuthorityError("healthy pre-attach absence proof is not exact typed authority")
        now = self._provider_call(lambda selected: selected.now_ns())
        if (type(proof) is not TaskAbsence or proof not in self._proofs or (proof.session, proof.generation, proof.display_id, proof.foreign) !=
                (self.session, self.generation, self.display_id, self._foreign) or
                type(proof.evidence_sha256) is not str or not HEX.fullmatch(proof.evidence_sha256) or
                not 0 <= now - proof.captured_ns <= COMMAND_NS):
            raise HostAuthorityError("absence ACK proof is stale or misbound")
        # Independent current absence; never trust only a caller's boolean/hash.
        if pre_attach:
            self._pre_attach_absence(deadline_ns)
            now = self._provider_call(lambda selected: selected.now_ns())
            if not 0 <= now - proof.captured_ns <= COMMAND_NS:
                raise HostAuthorityError("absence ACK proof expired during independent recapture")
        else: self._absence(deadline_ns, self._foreign)

    def _release(self, proof: TaskAbsence, deadline_ns: int, *, empty: bool, pre_attach: bool = False) -> None:
        self._require_commands_open()
        try:
            if pre_attach: self._require_pre_attach_empty()
            self._proof(proof, deadline_ns, pre_attach=pre_attach)
            if pre_attach:
                action, kind, body = "ACK_NO_FOREIGN_PRE_ATTACH_ABORT", "EMPTY_PRE_ATTACH_ABORT", {"absence_sha256": proof.evidence_sha256}
            elif empty:
                if self._foreign is not None or not self.failure: raise HostAuthorityError("empty cleanup cannot replace foreign destruction")
                action, kind, body = "ACK_NO_FOREIGN_AFTER_FAILURE", "EMPTY_ATTACH_ABORT", {"absence_sha256": proof.evidence_sha256}
            else:
                if self._foreign is None or (self.phase != "WAIT_FOREIGN_DESTROY" and not self._emergency):
                    raise HostAuthorityError("foreign destruction ACK precedes close/emergency")
                action, kind, body = "ACK_FOREIGN_DESTROYED", "FOREIGN_DESTROYED", {"foreign": self._foreign.wire()}
            if self._pending is not None:
                raise HostAuthorityError("uncertain command cannot be replaced by a fresh cleanup ACK")
            self._suspended_deadline = None
            self._release_proof = proof
            command = self._command(action, body, deadline_ns, cleanup=True)
            self._release_command, self._release_proof = command, proof
            self._wait(kind, command.deadline_ns, body, cleanup=True)
            self._empty_ack, self._destroyed_ack = empty, not empty
            self._pre_attach_empty_ack = pre_attach
            self._wait("DISPLAY_RELEASED", command.deadline_ns, {"display": self.display_id, "mode": "acknowledged_cleanup"}, cleanup=True)
            self._confirm_release(command.deadline_ns)
            self._settled()
        except BaseException as error:
            self._fail(error)
            raise

    def ack_destroyed(self, proof: TaskAbsence, deadline_ns: int) -> None: self._release(proof, deadline_ns, empty=False)
    def ack_empty(self, proof: TaskAbsence, deadline_ns: int) -> None: self._release(proof, deadline_ns, empty=True)
    def abort_pre_attach_empty(self, proof: TaskAbsence, deadline_ns: int) -> None:
        self._release(proof, deadline_ns, empty=True, pre_attach=True)

    def reconcile_late_ack(self, deadline_ns: int) -> None:
        """Read-only cleanup reconciliation; the original expired command stays failed.

        Never republishes AppliedPlacement/ready or sends a replacement command.
        Only an exact authenticated ACK for the retained outstanding command
        can advance the narrow cleanup phase.
        """
        self._require_commands_open()
        try:
            command = self._pending
            if (not self.failure or command is None or self._expected_ack is None or
                    self._provider_call(
                        lambda selected: selected.now_ns()) <
                    command.deadline_ns):
                raise HostAuthorityError("no expired exact outstanding ACK to reconcile")
            bound = min(
                deadline_ns,
                self._provider_call(
                    lambda selected: selected.now_ns()) + COMMAND_NS)
            kind, body = self._expected_ack
            observed = self._observed_ack
            # This is a separate read-only cleanup wait, not renewed command
            # processing authority. The immutable original deadline is untouched.
            self._suspended_deadline = None
            if observed is None or observed.kind != kind:
                observed = self._wait(kind, bound, body, cleanup=True)
            self._command_event_time(observed)
            self._body(observed, body)
            self._verify()
            if command.action == "ACK_FOREIGN_ATTACHED":
                self._check_foreign(self._foreign, self._capture(bound))
                self.phase = "ACTIVE"
            elif command.action == "BEGIN_CLOSE": self.phase = "WAIT_FOREIGN_DESTROY"
            elif command.action.startswith("PLACE_"):
                self._requested = Placement(command.action[6:])
            elif command.action in {"ACK_FOREIGN_DESTROYED", "ACK_NO_FOREIGN_AFTER_FAILURE", "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"}:
                self._destroyed_ack = command.action == "ACK_FOREIGN_DESTROYED"
                self._empty_ack = not self._destroyed_ack
                self._pre_attach_empty_ack = command.action == "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"
                if kind != "DISPLAY_RELEASED":
                    self._wait("DISPLAY_RELEASED", bound, {"display": self.display_id, "mode": "acknowledged_cleanup"}, cleanup=True)
                self._confirm_release(bound)
            else: raise HostAuthorityError("late ACK is not in the closed command set")
            self._deadline(bound)
            self._settled()
        except BaseException as error:
            self._fail(error)
            raise

    def retry_release(self, deadline_ns: int) -> None:
        """Only an already acknowledged exact release authorization is replayable."""
        self._require_commands_open()
        try:
            if self._release_command is None or not (self._destroyed_ack or self._empty_ack) or self._released:
                raise HostAuthorityError("no exact acknowledged failed release to retry")
            if self._pre_attach_empty_ack: self._pre_attach_absence(deadline_ns)
            else: self._absence(deadline_ns, self._foreign)
            original = self._release_command
            # A cleanup transport bound is not a renewal of the original command
            # deadline, and does not change its bytes/sequence/readiness outcome.
            bound = min(
                deadline_ns,
                self._provider_call(
                    lambda selected: selected.now_ns()) + COMMAND_NS)
            self._pending = original
            self._suspended_deadline = None
            self._provider_call(
                lambda selected: selected.send(original, bound))
            replay = ("DESTROY_REPLAY" if self._destroyed_ack else
                      "EMPTY_PRE_ATTACH_ABORT_REPLAY" if self._pre_attach_empty_ack else "EMPTY_ABORT_REPLAY")
            self._wait(replay, bound, {"release_retry": True}, cleanup=True)
            self._wait("DISPLAY_RELEASED", bound, {"display": self.display_id, "mode": "acknowledged_cleanup"}, cleanup=True)
            self._confirm_release(bound)
            self._settled()
        except BaseException as error:
            self._fail(error)
            raise

    def _confirm_release(self, deadline_ns: int) -> None:
        snap = self._capture(deadline_ns)
        if any(d.display_id == self.display_id or d.owner == self.process for d in snap.displays):
            self._released = False
            raise HostQuiescenceError("release log does not prove actual display absence")
        self._absence_from_snapshot(snap, self._foreign)
        self._released, self.phase = True, "RELEASED"
        self._commands_sealed = True

    def observe_failure(self, deadline_ns: int) -> None:
        """Consume an authenticated failure; does not itself grant cleanup success."""
        try:
            event = self._event(deadline_ns)
            if event is None or event.kind not in {"FAILED", "TIMEOUT", "RELEASE_FAILED"} or not self._progress(event):
                raise HostAuthorityError("no producer-authenticated host failure")
            self._deadline(deadline_ns)
        except BaseException as error:
            self._fail(error)
            raise

    def assert_quiescent(self, deadline_ns: int) -> None:
        try:
            if self.display_id is not None:
                if not self._released and not self._emergency: raise HostQuiescenceError("no normal release/emergency authority")
                self._confirm_release(deadline_ns)
            snap = self._capture(deadline_ns)
            if any(d.owner == self.process or (self.display_id is not None and d.display_id == self.display_id) for d in snap.displays):
                raise HostQuiescenceError("host-owned display remains even without an admitted allocation event")
            if self.display_id is not None: self._absence_from_snapshot(snap, self._foreign)
            if any(a.task_id == self.host_task_id or a.token == self.host_token for a in snap.activities) or any(
                    w.task_id == self.host_task_id or w.activity_token == self.host_token for w in snap.windows):
                raise HostQuiescenceError("exact host task/window still live")
            self.phase = "QUIESCENT"
            self._commands_sealed = True
        except BaseException as error:
            self._fail(error)
            raise HostQuiescenceError(f"host quiescence NOT established: {error}") from error
