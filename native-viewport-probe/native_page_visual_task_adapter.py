"""Host-only exact fixture task authority for the visual-session harness.

The module deliberately implements no ADB transport, shell command, Android
binder call, process launch, filesystem access, or device discovery.  It
accepts a retained, fixed-operation backend whose public surface has exactly
three operations: launch the immutable plan, remove the retained task, and
observe final absence.  No backend method accepts argv, shell text, a package
selector, a process selector, or a caller-chosen path.

The high-level adapter is useful only when paired with an independently
reviewed backend.  This repository does not provide that production backend;
therefore this module does not clear the visual harness's hardware-admission
blocker or assert that the target device is ready.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import wraps
import hashlib
import json
import re
import threading
from typing import Any, Callable, NoReturn, Protocol, TypeVar
import unicodedata
import uuid

import native_page_android_authority as android
import native_page_host_authority as host
import native_page_visual_session_harness as harness


AUTHORITY = "rtl-reader-native-page-visual-task-adapter-v1"
PLAN_AUTHORITY = "rtl-reader-native-page-visual-task-plan-v1"
BACKEND_AUTHORITY = "rtl-reader-fixed-visual-task-backend-v1"
REQUEST_AUTHORITY = "rtl-reader-native-page-task-request-v1"
ACK_AUTHORITY = "rtl-reader-native-page-task-ack-v1"
PROCESS_EVIDENCE_AUTHORITY = "rtl-reader-stock-process-evidence-v1"
LAUNCH_EVIDENCE_AUTHORITY = "rtl-reader-exact-fixture-launch-evidence-v1"
CLOSURE_EVIDENCE_AUTHORITY = "rtl-reader-exact-task-closure-evidence-v1"
CLOCK_AUTHORITY = "rtl-reader-retained-monotonic-clock-v1"
CLOCK_SOURCE = "retained-host-monotonic-domain-v1"

LAUNCH_OPERATION = "launch_exact_nonexported_document"
REMOVE_OPERATION = "remove_exact_retained_task"
QUIESCENCE_OPERATION = "prove_exact_task_absent"
OPERATIONS = frozenset((LAUNCH_OPERATION, REMOVE_OPERATION,
                        QUIESCENCE_OPERATION))

LAUNCH_ROUTE = "activity-task-manager-explicit-nonexported-document-v1"
REMOVE_ROUTE = "activity-task-manager-remove-exact-task-id-v1"
PROCESS_SOURCE = "proc-pid-stat-status-cmdline-fixed-v1"
ACTION_VIEW = "android.intent.action.VIEW"
MIME_PDF = "application/pdf"
STOCK_BASE_APK_PATH = "/system_ext/app/SupernoteDocument/SupernoteDocument.apk"

SHELL_UID = 2000
SHELL_GID = 2000
MAX_DISPLAY_ID = 1024
MAX_OPERATION_BUDGET_NS = 30_000_000_000
MAX_TOTAL_BUDGET_NS = 300_000_000_000
MAX_EVIDENCE_BYTES = 2_097_152
MAX_SEQUENCE = 2_147_483_647
DEFAULT_OPERATION_BUDGET_NS = 5_000_000_000
REAL_FIXED_BACKEND_IMPLEMENTED = False
HARDWARE_TIMING_PROVEN = False
UNRESOLVED_BLOCKERS = (
    "reviewed fixed-operation private task backend/bootstrap is not implemented",
    "integrated exact-head hardware review is not complete",
    "hardware operation timing is unproven",
)

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ENDPOINT = re.compile(r"tcp:127\.0\.0\.1:([0-9]{4,5})\Z")
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_ACTIVITY_TOKEN = re.compile(r"[0-9a-f]+\Z")
_PROCESS_NAME = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")


class TaskAdapterError(RuntimeError):
    """The task authority rejected input, retained identity, or evidence."""


class LaunchNotDispatched(TaskAdapterError):
    """The fixed backend proved quiescence without witnessing launch dispatch."""

    side_effect_possible = False
    retained_foreign: host.ForeignIdentity | None = None


class LaunchOutcomeUncertain(harness.TaskLaunchOutcomeUncertain,
                             TaskAdapterError):
    """Launch may have happened; broad or guessed cleanup is not authorized."""

    def __init__(self, message: str,
                 retained_foreign: host.ForeignIdentity | None = None):
        harness.TaskLaunchOutcomeUncertain.__init__(
            self, message, retained_foreign,
            reason_code="FIXED_BACKEND_LAUNCH_OUTCOME_UNCERTAIN")


class RemovalNotDispatched(TaskAdapterError):
    """Exact removal was not dispatched; the retained task still needs proof."""

    side_effect_possible = False

    def __init__(self, message: str, retained_foreign: host.ForeignIdentity):
        super().__init__(message)
        self.retained_foreign = retained_foreign


class RemovalOutcomeUncertain(TaskAdapterError):
    """Exact removal may have happened, but its closure was not proven."""

    side_effect_possible = True

    def __init__(self, message: str, retained_foreign: host.ForeignIdentity):
        super().__init__(message)
        self.retained_foreign = retained_foreign


class TaskQuiescenceUncertain(TaskAdapterError):
    """A backend operation/reply channel or final task state is unresolved."""


def _fail(message: str) -> NoReturn:
    raise TaskAdapterError(message)


def _exact(value: Any, expected: type, label: str) -> None:
    if type(value) is not expected:
        _fail(label + " has an inexact type")


def _literal(value: Any, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        _fail(label + " differs")
    return value


def _positive(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        _fail(label + " is outside exact integer bounds")
    return value


def _hex(value: Any, label: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        _fail(label + " is not a lowercase SHA-256")
    return value


def _uuid(value: Any, label: str) -> str:
    if type(value) is not str:
        _fail(label + " is not text")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as error:
        raise TaskAdapterError(label + " is not a UUID") from error
    if value != canonical:
        _fail(label + " is not a canonical lowercase UUID")
    return value


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise TaskAdapterError("authority is not canonical JSON") from error
    if not 0 < len(raw) <= MAX_EVIDENCE_BYTES:
        _fail("canonical authority is absent or oversized")
    return raw


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(raw: bytes) -> str:
    if type(raw) is not bytes:
        _fail("digest input is not exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _bounded_text(value: Any, label: str, maximum: int = 4096) -> str:
    if (type(value) is not str or not value or "\x00" in value or
            unicodedata.normalize("NFC", value) != value):
        _fail(label + " is not canonical bounded text")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as error:
        raise TaskAdapterError(label + " is not valid UTF-8") from error
    if size > maximum:
        _fail(label + " is oversized")
    return value


def admission_status() -> dict[str, Any]:
    """Status only: a protocol and synthetic tests are not hardware authority."""
    return {
        "admitted": False,
        "hostOnly": True,
        "realFixedBackendImplemented": REAL_FIXED_BACKEND_IMPLEMENTED,
        "hardwareTimingProven": HARDWARE_TIMING_PROVEN,
        "blockers": list(UNRESOLVED_BLOCKERS),
    }


@dataclass(frozen=True)
class ExactFixtureTaskPlan:
    session_id: str
    serial: str
    fixture_uri: str
    fixture_sha256: str
    monotonic_domain_sha256: str
    # ``None`` is the harness-compatible mode: bind exactly one positive ID
    # on the one launch entry, after HostAuthority has allocated it.  A caller
    # that already possesses independent display authority may pre-pin an ID.
    display_id: int | None
    absolute_deadline_ns: int
    operation_budget_ns: int = DEFAULT_OPERATION_BUDGET_NS

    def validate(self) -> None:
        _uuid(self.session_id, "task plan session")
        _literal(self.serial, harness.AUTHORIZED_SERIAL, "task plan serial")
        _bounded_text(self.fixture_uri, "fixture URI")
        if (harness.FIXTURE_URI.fullmatch(self.fixture_uri) is None or
                ".." in self.fixture_uri):
            _fail("task plan fixture URI is outside the disposable exact scope")
        _hex(self.fixture_sha256, "task plan fixture")
        _hex(self.monotonic_domain_sha256,
             "task plan monotonic clock domain")
        if self.display_id is not None:
            _positive(self.display_id, "task plan display ID", MAX_DISPLAY_ID)
        _positive(self.absolute_deadline_ns, "task plan absolute deadline")
        _positive(self.operation_budget_ns, "task plan operation budget",
                  MAX_OPERATION_BUDGET_NS)

    def wire(self) -> dict[str, Any]:
        self.validate()
        return {
            "authority": PLAN_AUTHORITY,
            "schemaVersion": 1,
            "sessionId": self.session_id,
            "serial": self.serial,
            "fixtureUri": self.fixture_uri,
            "fixtureSha256": self.fixture_sha256,
            "monotonicDomainSha256": self.monotonic_domain_sha256,
            "displayId": self.display_id,
            "displayBinding": ("pre-pinned" if self.display_id is not None else
                               "bind-one-positive-id-on-launch"),
            "absoluteDeadlineNs": str(self.absolute_deadline_ns),
            "operationBudgetNs": str(self.operation_budget_ns),
            "package": android.PACKAGE,
            "component": host.FOREIGN_COMPONENT,
            "action": ACTION_VIEW,
            "mimeType": MIME_PDF,
            "componentExported": False,
            "userDocumentSelection": False,
            "retryAllowed": False,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical(self.wire())

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class ExactLaunchScope:
    """Internally minted typed launch scope; never accepts command material."""

    plan_sha256: str
    serial: str
    fixture_uri: str
    fixture_sha256: str
    display_id: int
    component: str = host.FOREIGN_COMPONENT
    action: str = ACTION_VIEW
    mime_type: str = MIME_PDF

    def wire(self) -> dict[str, Any]:
        _hex(self.plan_sha256, "launch scope plan")
        _literal(self.serial, harness.AUTHORIZED_SERIAL, "launch scope serial")
        _bounded_text(self.fixture_uri, "launch scope fixture URI")
        if (harness.FIXTURE_URI.fullmatch(self.fixture_uri) is None or
                ".." in self.fixture_uri):
            _fail("launch scope fixture URI differs")
        _hex(self.fixture_sha256, "launch scope fixture")
        _positive(self.display_id, "launch scope display ID", MAX_DISPLAY_ID)
        _literal(self.component, host.FOREIGN_COMPONENT,
                 "launch scope component")
        _literal(self.action, ACTION_VIEW, "launch scope action")
        _literal(self.mime_type, MIME_PDF, "launch scope MIME type")
        return {
            "planSha256": self.plan_sha256,
            "serial": self.serial,
            "fixtureUri": self.fixture_uri,
            "fixtureSha256": self.fixture_sha256,
            "displayId": self.display_id,
            "component": self.component,
            "action": self.action,
            "mimeType": self.mime_type,
            "componentExported": False,
        }


@dataclass(frozen=True)
class TaskBackendBinding:
    authority: str
    backend_instance_id: str
    serial: str
    boot_id: str
    private_adb_session_id: str
    private_adb_endpoint: str
    private_adb_pid: int
    private_adb_start_ticks: int
    worker_session_id: str
    worker_pid: int
    worker_start_ticks: int
    worker_image_sha256: str
    retained_private_adb_handle: bool
    retained_worker_handle: bool
    private_socket: bool
    explicit_serial_every_operation: bool
    fixed_operations_only: bool
    accepts_general_commands: bool
    accepts_caller_argv: bool
    fresh_reply_channel_per_operation: bool
    late_reply_channel_sealed_before_return: bool
    failure_returns_after_operation_quiescence: bool
    dispatch_witness_required: bool
    exact_fixture_uri_sha_gate: bool
    exact_display_gate: bool
    explicit_nonexported_component_only: bool
    compare_identity_before_remove: bool
    exact_task_id_remove_only: bool
    complete_activity_manager_capture: bool
    exact_stock_process_liveness_capture: bool
    broad_cleanup_capability: bool
    process_kill_capability: bool

    def validate(self, plan: ExactFixtureTaskPlan) -> None:
        _exact(plan, ExactFixtureTaskPlan, "task plan")
        plan.validate()
        _literal(self.authority, BACKEND_AUTHORITY, "task backend authority")
        _hex(self.backend_instance_id, "task backend instance")
        _literal(self.serial, plan.serial, "task backend serial")
        _uuid(self.boot_id, "task backend boot ID")
        _hex(self.private_adb_session_id, "task backend private ADB session")
        _hex(self.worker_session_id, "task backend worker session")
        _hex(self.worker_image_sha256, "task backend worker image")
        endpoint = self.private_adb_endpoint
        if type(endpoint) is not str:
            _fail("task backend private ADB endpoint is not text")
        match = _ENDPOINT.fullmatch(endpoint)
        if (match is None or not 1024 <= int(match.group(1)) <= 65535 or
                int(match.group(1)) == 5037):
            _fail("task backend private ADB endpoint is absent or ambient")
        _positive(self.private_adb_pid, "task backend private ADB PID", 4_194_304)
        _positive(self.private_adb_start_ticks,
                  "task backend private ADB start time")
        _positive(self.worker_pid, "task backend worker PID", 4_194_304)
        _positive(self.worker_start_ticks, "task backend worker start time")
        if self.worker_pid == self.private_adb_pid:
            _fail("task backend worker aliases the private ADB process")
        exact_true = (
            self.retained_private_adb_handle,
            self.retained_worker_handle,
            self.private_socket,
            self.explicit_serial_every_operation,
            self.fixed_operations_only,
            self.fresh_reply_channel_per_operation,
            self.late_reply_channel_sealed_before_return,
            self.failure_returns_after_operation_quiescence,
            self.dispatch_witness_required,
            self.exact_fixture_uri_sha_gate,
            self.exact_display_gate,
            self.explicit_nonexported_component_only,
            self.compare_identity_before_remove,
            self.exact_task_id_remove_only,
            self.complete_activity_manager_capture,
            self.exact_stock_process_liveness_capture,
        )
        exact_false = (
            self.accepts_general_commands,
            self.accepts_caller_argv,
            self.broad_cleanup_capability,
            self.process_kill_capability,
        )
        if any(type(value) is not bool for value in exact_true + exact_false):
            _fail("task backend policy flags are not exact booleans")
        if not all(exact_true) or any(exact_false):
            _fail("task backend escapes the fixed exact-task authority")

    def canonical_bytes(self) -> bytes:
        return _canonical(asdict(self))

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class TaskOperationRequest:
    authority: str
    session_id: str
    serial: str
    boot_id: str
    sequence: int
    entry_generation: int
    state_generation: int
    lifecycle_state: str
    operation: str
    operation_id: str
    issued_ns: int
    deadline_ns: int
    plan_sha256: str
    backend_sha256: str
    arguments_sha256: str

    def canonical_bytes(self) -> bytes:
        return _canonical({
            "authority": self.authority,
            "sessionId": self.session_id,
            "serial": self.serial,
            "bootId": self.boot_id,
            "sequence": self.sequence,
            "entryGeneration": self.entry_generation,
            "stateGeneration": self.state_generation,
            "lifecycleState": self.lifecycle_state,
            "operation": self.operation,
            "operationId": self.operation_id,
            "issuedNs": str(self.issued_ns),
            "deadlineNs": str(self.deadline_ns),
            "planSha256": self.plan_sha256,
            "backendSha256": self.backend_sha256,
            "argumentsSha256": self.arguments_sha256,
        })

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class TaskOperationAck:
    authority: str
    session_id: str
    serial: str
    boot_id: str
    operation: str
    operation_id: str
    sequence: int
    request_sha256: str
    issued_ns: int
    produced_ns: int


@dataclass(frozen=True)
class StockProcessEvidence:
    authority: str
    serial: str
    boot_id: str
    captured_ns: int
    process: host.ProcessIdentity
    cmdline: str
    source: str
    collector_uid: int
    collector_gid: int
    alive: bool
    kernel_identity_exact: bool
    start_ticks_rechecked: bool
    read_only: bool
    mutation_count: int

    def canonical_bytes(self) -> bytes:
        process = self.process
        process_wire = (asdict(process) if type(process) is host.ProcessIdentity
                        else {"invalidType": type(process).__name__})
        return _canonical({
            "authority": self.authority,
            "serial": self.serial,
            "bootId": self.boot_id,
            "capturedNs": str(self.captured_ns),
            "process": process_wire,
            "cmdline": self.cmdline,
            "source": self.source,
            "collectorUid": self.collector_uid,
            "collectorGid": self.collector_gid,
            "alive": self.alive,
            "kernelIdentityExact": self.kernel_identity_exact,
            "startTicksRechecked": self.start_ticks_rechecked,
            "readOnly": self.read_only,
            "mutationCount": self.mutation_count,
        })

    @property
    def sha256(self) -> str:
        return _sha(self.canonical_bytes())


@dataclass(frozen=True)
class LaunchBackendReceipt:
    ack: TaskOperationAck
    fixture_uri: str
    fixture_sha256: str
    display_id: int
    component: str
    action: str
    mime_type: str
    route: str
    dispatched_ns: int
    captured_ns: int
    activity_manager_raw: bytes
    stock_process: StockProcessEvidence
    explicit_component: bool
    component_exported: bool
    fixture_uri_resolved_exact: bool
    fixture_hash_verified_before_dispatch: bool
    user_document_selection_used: bool
    caller_command_input_used: bool
    broad_scope_used: bool
    process_kill_used: bool


@dataclass(frozen=True)
class DestroyBackendReceipt:
    ack: TaskOperationAck
    foreign: host.ForeignIdentity
    removed_task_id: int
    route: str
    pre_captured_ns: int
    dispatched_ns: int
    post_captured_ns: int
    pre_activity_manager_raw: bytes
    post_activity_manager_raw: bytes
    pre_stock_process: StockProcessEvidence
    post_stock_process: StockProcessEvidence
    compare_identity_before_remove: bool
    exact_task_id_only: bool
    package_selector_used: bool
    wildcard_selector_used: bool
    force_stop_used: bool
    caller_command_input_used: bool
    broad_scope_used: bool
    process_kill_used: bool


@dataclass(frozen=True)
class QuiescenceBackendReceipt:
    ack: TaskOperationAck
    foreign: host.ForeignIdentity
    captured_ns: int
    activity_manager_raw: bytes
    stock_process: StockProcessEvidence
    read_only: bool
    mutation_count: int
    broad_scope_used: bool
    process_kill_used: bool


class RetainedClockAuthority(Protocol):
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def monotonic_domain_identity(self) -> str: ...
    def now_ns(self) -> int: ...


def _strict_clock_authority(raw: Any) -> tuple[bytes, str]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_EVIDENCE_BYTES:
        _fail("retained clock canonical authority is absent or oversized")
    try:
        text = raw.decode("ascii", "strict")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if type(key) is not str or key in result:
                    raise TaskAdapterError(
                        "retained clock authority has duplicate/non-text keys")
                result[key] = value
            return result

        value = json.loads(text, object_pairs_hook=pairs,
                           parse_constant=lambda token: (_fail(
                               "retained clock authority has non-finite data")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TaskAdapterError(
            "retained clock authority is not strict canonical JSON") from error
    if type(value) is not dict or set(value) != {
            "authority", "schemaVersion", "clockInstanceId",
            "monotonicDomainSha256", "source", "retainedAuthority",
            "nanosecondDomain", "wallClock"}:
        _fail("retained clock authority topology differs")
    _literal(value["authority"], CLOCK_AUTHORITY,
             "retained clock authority")
    _literal(value["source"], CLOCK_SOURCE, "retained clock source")
    if (type(value["schemaVersion"]) is not int or
            value["schemaVersion"] != 1 or
            value["retainedAuthority"] is not True or
            value["nanosecondDomain"] is not True or
            value["wallClock"] is not False):
        _fail("retained clock policy differs")
    _hex(value["clockInstanceId"], "retained clock instance")
    domain = _hex(value["monotonicDomainSha256"],
                  "retained clock monotonic domain")
    if _canonical(value) != raw:
        _fail("retained clock authority bytes are not canonical")
    return raw, domain


class FixedTaskBackend(Protocol):
    """Low-level fixed backend; intentionally no generic command primitive."""

    def binding(self) -> TaskBackendBinding: ...
    def verify(self, expected: TaskBackendBinding) -> None: ...
    def launch_exact_nonexported_document(
            self, request: TaskOperationRequest, scope: ExactLaunchScope,
            dispatch_witness: Callable[[], int]) -> LaunchBackendReceipt: ...
    def remove_exact_retained_task(
            self, request: TaskOperationRequest, foreign: host.ForeignIdentity,
            dispatch_witness: Callable[[], int]) -> DestroyBackendReceipt: ...
    def prove_exact_task_absent(
            self, request: TaskOperationRequest,
            foreign: host.ForeignIdentity) -> QuiescenceBackendReceipt: ...
    def assert_operation_quiescent(
            self, expected: TaskBackendBinding, operation_id: str,
            deadline_ns: int) -> None: ...
    def assert_all_quiescent(self, expected: TaskBackendBinding,
                             deadline_ns: int) -> None: ...


T = TypeVar("T")


def _serialized(function: Callable[..., T]) -> Callable[..., T]:
    @wraps(function)
    def guarded(self: "NativePageVisualTaskAdapter", *args: Any,
                **kwargs: Any) -> T:
        caller = threading.get_ident()
        if self._active_entry is not None:
            self._entry_violation = True
            if self._entry_owner == caller:
                raise TaskAdapterError("reentrant task-authority entry is not permitted")
            raise TaskAdapterError("concurrent task-authority entry is not permitted")
        if not self._lock.acquire(blocking=False):
            self._entry_violation = True
            raise TaskAdapterError("concurrent task-authority entry is not permitted")
        self._entry_counter += 1
        self._active_entry = self._entry_counter
        self._entry_owner = caller
        try:
            return function(self, *args, **kwargs)
        finally:
            self._active_entry = None
            self._entry_owner = None
            self._lock.release()
    return guarded


class _DispatchWitness:
    def __init__(self, owner: "NativePageVisualTaskAdapter",
                 request: TaskOperationRequest):
        self._owner = owner
        self._request = request
        self.attempted = False
        self.seen = False
        self.violation = False
        self.dispatched_ns: int | None = None
        self._sealed = False

    def __call__(self) -> int:
        self.attempted = True
        if self._sealed:
            self.violation = True
            self._owner._late_witness_violation = True
            raise TaskAdapterError("late task mutation dispatch is sealed")
        if self.seen:
            self.violation = True
            raise TaskAdapterError("task mutation dispatch witness was repeated")
        self._owner._current(self._request)
        now = self._owner._now()
        if now >= self._request.deadline_ns:
            self.violation = True
            raise TaskAdapterError("task mutation dispatch missed its deadline")
        self.seen = True
        self.dispatched_ns = now
        return now

    def seal(self) -> None:
        self._sealed = True


class _NotDispatched(Exception):
    def __init__(self, cause: BaseException):
        super().__init__(str(cause))
        self.cause = cause


class _InvocationUncertain(Exception):
    def __init__(self, cause: BaseException):
        super().__init__(str(cause))
        self.cause = cause


def _activity_text(raw: bytes) -> tuple[str, str]:
    if type(raw) is not bytes or not 0 < len(raw) <= android.MAX_DUMPSYS_BYTES:
        _fail("ActivityManager evidence is absent or oversized")
    if b"\x00" in raw:
        _fail("ActivityManager evidence contains NUL")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise TaskAdapterError("ActivityManager evidence is not UTF-8") from error
    if "\r" in text:
        if (text.count("\r") != text.count("\r\n") or
                text.count("\n") != text.count("\r\n")):
            _fail("ActivityManager evidence has mixed line endings")
        text = text.replace("\r\n", "\n")
    if (not text.endswith("\n") or
            not text.startswith(
                "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n")):
        _fail("ActivityManager evidence framing differs")
    if (any(ord(character) < 0x20 and character not in ("\n", "\t")
            for character in text) or "\x7f" in text or
            any(separator in text for separator in ("\x85", "\u2028", "\u2029"))):
        _fail("ActivityManager evidence contains a noncanonical control")
    if any(len(line) > android.MAX_LINE_CHARS for line in text.split("\n")):
        _fail("ActivityManager evidence contains an oversized line")
    return text, _sha(raw)


def _prove_absent(raw: bytes, foreign: host.ForeignIdentity) -> str:
    text, digest = _activity_text(raw)
    task = str(foreign.task_id)
    # Fail conservatively on the retained identifiers or any stock
    # DocumentActivity.  This is stronger than task-ID absence and prevents a
    # malformed/recreated document record from being treated as clean.
    forbidden = (
        re.compile(r"(?<![0-9A-Za-z])" + re.escape(foreign.activity_token) +
                   r"(?![0-9A-Za-z])"),
        re.compile(r"(?<![0-9])#" + re.escape(task) + r"(?![0-9])"),
        re.compile(r"(?<![0-9])t" + re.escape(task) + r"(?![0-9])"),
        re.compile(r"(?<![A-Za-z])taskId=" + re.escape(task) + r"(?![0-9])"),
        re.compile(re.escape(android.SHORT_COMPONENT)),
        re.compile(re.escape(android.FULL_COMPONENT)),
    )
    if any(pattern.search(text) is not None for pattern in forbidden):
        _fail("fresh ActivityManager evidence retains or recreates DocumentActivity")
    return digest


class NativePageVisualTaskAdapter:
    """One-plan TaskAuthority implementation over a retained fixed backend."""

    def __init__(self, *, plan: ExactFixtureTaskPlan,
                 backend: FixedTaskBackend,
                 clock: RetainedClockAuthority):
        _exact(plan, ExactFixtureTaskPlan, "task plan")
        plan.validate()
        if backend is None or clock is None:
            _fail("task backend and monotonic clock are required")
        self._plan = plan
        self._backend_adapter = backend
        self._retained_backend_adapter = backend
        self._clock = clock
        self._retained_clock = clock
        self._lock = threading.Lock()
        self._entry_counter = 0
        self._active_entry: int | None = None
        self._entry_owner: int | None = None
        self._entry_violation = False
        self._late_witness_violation = False
        self._sequence = 0
        self._state_generation = 0
        self._last_now = -1
        self._launch_consumed = False
        self._remove_consumed = False
        self._foreign: host.ForeignIdentity | None = None
        self._display_id: int | None = plan.display_id
        self.state = "NEW"
        self.cleanup_obligations: tuple[str, ...] = ()
        try:
            clock.verify()
        except BaseException as error:
            raise TaskAdapterError(
                "retained clock verification failed during construction") from error
        clock_raw, clock_domain = _strict_clock_authority(
            clock.canonical_bytes())
        clock_identity = clock.monotonic_domain_identity()
        _hex(clock_identity, "retained clock reported monotonic domain")
        if (clock_identity != clock_domain or
                clock_domain != plan.monotonic_domain_sha256):
            _fail("task plan and retained clock monotonic domains differ")
        try:
            clock.verify()
        except BaseException as error:
            raise TaskAdapterError(
                "retained clock verification failed during construction") from error
        repeated_raw, repeated_domain = _strict_clock_authority(
            clock.canonical_bytes())
        if repeated_raw != clock_raw or repeated_domain != clock_domain:
            _fail("retained clock authority drifted during construction")
        self._clock_raw = clock_raw
        self._clock_domain = clock_domain
        self._backend = self._backend_call(lambda selected: selected.binding())
        _exact(self._backend, TaskBackendBinding, "task backend binding")
        self._backend.validate(plan)
        created = self._now()
        if not created < plan.absolute_deadline_ns <= created + MAX_TOTAL_BUDGET_NS:
            _fail("task plan deadline is expired or outside the total bound")
        self._verify_dependencies()
        self._canonical = _canonical({
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "plan": plan.wire(),
            "backend": asdict(self._backend),
            "clockAuthoritySha256": _sha(self._clock_raw),
            "monotonicDomainSha256": self._clock_domain,
            "policy": {
                "fixedOperations": sorted(OPERATIONS),
                "launchRoute": LAUNCH_ROUTE,
                "removeRoute": REMOVE_ROUTE,
                "callerCommandInput": False,
                "broadCleanup": False,
                "processKill": False,
                "nonReentrant": True,
                "noRetry": True,
                "operationQuiescenceRequired": True,
                "realFixedBackendImplemented": REAL_FIXED_BACKEND_IMPLEMENTED,
                "hardwareTimingProven": HARDWARE_TIMING_PROVEN,
            },
        })

    @property
    def plan(self) -> ExactFixtureTaskPlan:
        return self._plan

    @property
    def retained_foreign(self) -> host.ForeignIdentity | None:
        return self._foreign

    @_serialized
    def monotonic_domain_identity(self) -> str:
        self._verify_clock()
        return self._clock_domain

    def _set_state(self, value: str) -> None:
        allowed = {
            "NEW", "LIVE", "LAUNCH_NOT_DISPATCHED",
            "LAUNCH_UNCERTAIN_UNKNOWN", "LAUNCH_UNCERTAIN_RETAINED",
            "REMOVE_NOT_DISPATCHED", "REMOVAL_UNCERTAIN", "CLOSED",
            "QUIESCENT", "QUIESCENCE_UNCERTAIN",
        }
        if type(value) is not str or value not in allowed:
            _fail("unknown task-adapter lifecycle state")
        if value != self.state:
            self.state = value
            self._state_generation += 1

    def _obligation(self, message: str) -> None:
        self.cleanup_obligations = (message,)

    def _clear_obligations(self) -> None:
        self.cleanup_obligations = ()

    def _verify_clock(self) -> None:
        if self._clock is not self._retained_clock:
            _fail("retained task clock object was substituted")
        try:
            self._retained_clock.verify()
        except BaseException as error:
            raise TaskAdapterError("retained task clock verification failed") from error
        raw, domain = _strict_clock_authority(
            self._retained_clock.canonical_bytes())
        reported = self._retained_clock.monotonic_domain_identity()
        _hex(reported, "retained clock reported monotonic domain")
        if (raw != self._clock_raw or domain != self._clock_domain or
                reported != self._clock_domain or
                domain != self.plan.monotonic_domain_sha256):
            _fail("retained task clock identity or domain drifted")

    def _backend_object(self) -> FixedTaskBackend:
        """Return only the construction-retained backend object.

        A canonical binding describes authority, not Python object ownership.
        A same-binding replacement must therefore fail before it can receive a
        request.  Calls use this retained local reference and recheck the
        public slot afterward so substitution during a callback is detected.
        """
        if self._backend_adapter is not self._retained_backend_adapter:
            _fail("retained task backend object was substituted")
        return self._retained_backend_adapter

    def _backend_call(self, function: Callable[[FixedTaskBackend], T]) -> T:
        selected = self._backend_object()
        try:
            result = function(selected)
        except BaseException as error:
            try:
                self._backend_object()
            except BaseException as identity_error:
                raise identity_error from error
            raise
        self._backend_object()
        return result

    def _now(self) -> int:
        self._verify_clock()
        value = self._retained_clock.now_ns()
        self._verify_clock()
        if (type(value) is not int or value < 0 or value < self._last_now or
                value > 2**63 - 1):
            _fail("task-adapter monotonic clock regressed or is inexact")
        self._last_now = value
        return value

    def _verify_dependencies(self) -> None:
        self._verify_clock()
        if self._entry_violation:
            _fail("task authority observed concurrent or reentrant entry")
        if self._late_witness_violation:
            _fail("task authority observed a late mutation dispatch")
        result = self._backend_call(
            lambda selected: selected.verify(self._backend))
        if result is not None:
            _fail("task backend verification returned unexpected data")
        current = self._backend_call(lambda selected: selected.binding())
        _exact(current, TaskBackendBinding, "current task backend binding")
        current.validate(self.plan)
        if current != self._backend:
            _fail("task backend retained identity drifted")

    def _deadline(self, value: Any) -> tuple[int, int]:
        if type(value) is not int or value != self.plan.absolute_deadline_ns:
            _fail("caller deadline differs from the immutable task plan")
        now = self._now()
        if now >= value:
            _fail("task adapter deadline expired")
        return min(value, now + self.plan.operation_budget_ns), now

    def _request(self, operation: str, arguments: Any,
                 caller_deadline_ns: int) -> TaskOperationRequest:
        if type(operation) is not str or operation not in OPERATIONS:
            _fail("task operation is outside the fixed registry")
        if (self._active_entry is None or
                self._entry_owner != threading.get_ident()):
            _fail("task operation is outside serialized lifecycle authority")
        deadline, checked_ns = self._deadline(caller_deadline_ns)
        if self._sequence >= MAX_SEQUENCE:
            _fail("task operation sequence is exhausted")
        self._sequence += 1
        issued = self._now()
        if (issued <= checked_ns or
                issued - checked_ns > self.plan.operation_budget_ns):
            _fail("retained task clock stalled or jumped before dispatch")
        operation_id = _digest({
            "authority": AUTHORITY,
            "session": self.plan.session_id,
            "bootId": self._backend.boot_id,
            "entry": self._active_entry,
            "sequence": self._sequence,
            "operation": operation,
            "stateGeneration": self._state_generation,
        })
        return TaskOperationRequest(
            REQUEST_AUTHORITY, self.plan.session_id, self.plan.serial,
            self._backend.boot_id, self._sequence, self._active_entry,
            self._state_generation, self.state, operation, operation_id,
            issued, deadline, self.plan.sha256, self._backend.sha256,
            _digest(arguments))

    def _current(self, request: TaskOperationRequest) -> None:
        if (type(request) is not TaskOperationRequest or
                self._active_entry != request.entry_generation or
                self._entry_owner != threading.get_ident() or
                self._state_generation != request.state_generation or
                self.state != request.lifecycle_state or
                self._sequence != request.sequence or self._entry_violation or
                self._late_witness_violation):
            _fail("task request lost current lifecycle authority")

    def _validate_ack(self, request: TaskOperationRequest,
                      ack: TaskOperationAck) -> None:
        _exact(ack, TaskOperationAck, request.operation + " ACK")
        for value, expected, label in (
                (ack.authority, ACK_AUTHORITY, "authority"),
                (ack.session_id, request.session_id, "session"),
                (ack.serial, request.serial, "serial"),
                (ack.boot_id, request.boot_id, "boot"),
                (ack.operation, request.operation, "operation"),
                (ack.operation_id, request.operation_id, "operation ID"),
                (ack.request_sha256, request.sha256, "request digest")):
            _literal(value, expected, request.operation + " ACK " + label)
        if any(type(value) is not int for value in (
                ack.sequence, ack.issued_ns, ack.produced_ns)):
            _fail(request.operation + " ACK has an inexact integer")
        self._current(request)
        now = self._now()
        if (ack.sequence != request.sequence or
                ack.issued_ns != request.issued_ns or
                not request.issued_ns <= ack.produced_ns <= now <
                request.deadline_ns):
            _fail(request.operation + " ACK is stale, late, or substituted")

    def _settle_operation(self, request: TaskOperationRequest) -> None:
        result = self._backend_call(
            lambda selected: selected.assert_operation_quiescent(
                self._backend, request.operation_id, request.deadline_ns))
        if result is not None:
            _fail(request.operation + " quiescence returned unexpected data")
        self._verify_dependencies()
        self._current(request)
        if self._now() >= request.deadline_ns:
            _fail(request.operation + " did not quiesce before its deadline")

    def _invoke_mutating(
            self, request: TaskOperationRequest,
            function: Callable[[TaskOperationRequest, Callable[[], int]], T]
            ) -> tuple[T, _DispatchWitness]:
        self._verify_dependencies()
        witness = _DispatchWitness(self, request)
        backend_error: BaseException | None = None
        result: T | None = None
        try:
            result = function(request, witness)
        except BaseException as error:
            backend_error = error
        witness.seal()
        try:
            self._settle_operation(request)
        except BaseException as error:
            raise _InvocationUncertain(error) from error
        if backend_error is not None:
            if witness.attempted or witness.seen or witness.violation:
                raise _InvocationUncertain(backend_error) from backend_error
            raise _NotDispatched(backend_error) from backend_error
        if (not witness.seen or witness.violation or
                type(witness.dispatched_ns) is not int):
            raise _InvocationUncertain(TaskAdapterError(
                "successful mutation lacks one exact dispatch witness"))
        return result, witness  # type: ignore[return-value]

    def _invoke_read_only(self, request: TaskOperationRequest,
                          function: Callable[[TaskOperationRequest], T]) -> T:
        self._verify_dependencies()
        backend_error: BaseException | None = None
        result: T | None = None
        try:
            result = function(request)
        except BaseException as error:
            backend_error = error
        try:
            self._settle_operation(request)
        except BaseException as error:
            raise TaskQuiescenceUncertain(
                "read-only task observation did not quiesce") from error
        if backend_error is not None:
            raise TaskAdapterError("read-only task observation failed") from backend_error
        return result  # type: ignore[return-value]

    def _validate_process(self, value: StockProcessEvidence,
                          captured_ns: int,
                          expected: host.ProcessIdentity | None = None
                          ) -> host.ProcessIdentity:
        _exact(value, StockProcessEvidence, "stock process evidence")
        _literal(value.authority, PROCESS_EVIDENCE_AUTHORITY,
                 "stock process evidence authority")
        _literal(value.serial, self.plan.serial, "stock process evidence serial")
        _literal(value.boot_id, self._backend.boot_id,
                 "stock process evidence boot")
        _literal(value.cmdline, android.PROCESS, "stock process command line")
        _literal(value.source, PROCESS_SOURCE, "stock process evidence source")
        _exact(value.process, host.ProcessIdentity, "stock process identity")
        process = value.process
        if (type(value.captured_ns) is not int or value.captured_ns != captured_ns or
                type(process.pid) is not int or
                not 1 <= process.pid <= android.MAX_PID or
                type(process.start_ticks) is not int or process.start_ticks <= 0 or
                type(process.uid) is not int or process.uid != android.SYSTEM_UID or
                type(process.package) is not str or process.package != android.PACKAGE or
                (value.collector_uid, value.collector_gid) !=
                (SHELL_UID, SHELL_GID) or
                value.alive is not True or value.kernel_identity_exact is not True or
                value.start_ticks_rechecked is not True or value.read_only is not True or
                type(value.mutation_count) is not int or value.mutation_count != 0):
            _fail("stock process PID/start/UID/package liveness authority differs")
        if expected is not None and process != expected:
            _fail("stock process identity drifted or was reused")
        # Force canonical serialization now; exotic nested values cannot be
        # smuggled into later evidence construction.
        value.canonical_bytes()
        return process

    def _bind_display(self, value: Any) -> int:
        _positive(value, "caller launch display ID", MAX_DISPLAY_ID)
        if self.plan.display_id is not None and value != self.plan.display_id:
            _fail("caller display differs from the pre-pinned task plan")
        if self._display_id is None:
            self._display_id = value
            # The immutable policy is unchanged, but requests must bind the
            # generation in which the one runtime display became concrete.
            self._state_generation += 1
        elif value != self._display_id:
            _fail("caller display differs from the retained runtime binding")
        return value

    def _derive_live_foreign(self, raw: bytes,
                             process_evidence: StockProcessEvidence,
                             captured_ns: int) -> tuple[host.ForeignIdentity,
                                                        android.DocumentTaskAuthority]:
        process = self._validate_process(process_evidence, captured_ns)
        try:
            task = android.parse_document_task_authority(
                raw, expected_pid=process.pid, require_live=True)
        except BaseException as error:
            raise TaskAdapterError(
                "strict fresh ActivityManager task authority was rejected") from error
        if (self._display_id is None or task.display_id != self._display_id or
                task.task_id <= 0 or
                task.pid != process.pid or task.uid != process.uid or
                task.package_name != process.package or
                task.process_name != android.PROCESS or
                task.component not in (android.SHORT_COMPONENT,
                                       android.FULL_COMPONENT) or
                task.base_apk_path != STOCK_BASE_APK_PATH or
                (task.width, task.height, task.density_dpi, task.rotation) !=
                (1404, 1872, 300, 0) or
                _ACTIVITY_TOKEN.fullmatch(task.activity_token) is None):
            _fail("strict task authority escaped the exact stock display identity")
        foreign = host.ForeignIdentity(
            process, task.task_id, task.activity_token,
            android.stable_authority_sha256(task), host.FOREIGN_COMPONENT)
        return foreign, task

    def _validate_retained_live(self, raw: bytes,
                                process_evidence: StockProcessEvidence,
                                captured_ns: int,
                                foreign: host.ForeignIdentity
                                ) -> android.DocumentTaskAuthority:
        derived, task = self._derive_live_foreign(
            raw, process_evidence, captured_ns)
        if derived != foreign:
            _fail("fresh pre-remove task authority differs from retained identity")
        return task

    def _validate_foreign(self, value: Any) -> host.ForeignIdentity:
        _exact(value, host.ForeignIdentity, "retained foreign identity")
        process = value.process
        _exact(process, host.ProcessIdentity, "retained stock process identity")
        if (process.package != android.PACKAGE or
                type(process.uid) is not int or process.uid != android.SYSTEM_UID or
                type(process.pid) is not int or
                not 1 <= process.pid <= android.MAX_PID or
                type(process.start_ticks) is not int or process.start_ticks <= 0 or
                type(value.task_id) is not int or value.task_id <= 0 or
                type(value.activity_token) is not str or
                _ACTIVITY_TOKEN.fullmatch(value.activity_token) is None or
                type(value.evidence_sha256) is not str or
                _HEX.fullmatch(value.evidence_sha256) is None or
                value.component != host.FOREIGN_COMPONENT):
            _fail("retained foreign identity fields differ")
        return value

    def _launch_evidence(self, request: TaskOperationRequest,
                         value: LaunchBackendReceipt,
                         foreign: host.ForeignIdentity,
                         task: android.DocumentTaskAuthority) -> bytes:
        return _canonical({
            "authority": LAUNCH_EVIDENCE_AUTHORITY,
            "adapterSha256": _sha(self._canonical),
            "planSha256": self.plan.sha256,
            "backendSha256": self._backend.sha256,
            "requestSha256": request.sha256,
            "operationId": request.operation_id,
            "fixtureUri": self.plan.fixture_uri,
            "fixtureSha256": self.plan.fixture_sha256,
            "displayId": self._display_id,
            "dispatchNs": str(value.dispatched_ns),
            "capturedNs": str(value.captured_ns),
            "activityManagerSha256": _sha(value.activity_manager_raw),
            "stableTaskAuthoritySha256": foreign.evidence_sha256,
            "taskAuthority": json.loads(task.canonical_bytes().decode("utf-8")),
            "stockProcessEvidenceSha256": value.stock_process.sha256,
            "foreign": {
                **foreign.wire(),
                "activityToken": foreign.activity_token,
            },
            "attestation": {
                "route": LAUNCH_ROUTE,
                "explicitComponent": True,
                "componentExported": False,
                "fixtureUriResolvedExact": True,
                "fixtureHashVerifiedBeforeDispatch": True,
                "userDocumentSelectionUsed": False,
                "callerCommandInputUsed": False,
                "broadScopeUsed": False,
                "processKillUsed": False,
            },
            "hardwareTimingProven": HARDWARE_TIMING_PROVEN,
        })

    def _closure_evidence(self, request: TaskOperationRequest,
                          value: DestroyBackendReceipt,
                          foreign: host.ForeignIdentity,
                          pre_task: android.DocumentTaskAuthority,
                          post_am_sha256: str) -> bytes:
        return _canonical({
            "authority": CLOSURE_EVIDENCE_AUTHORITY,
            "adapterSha256": _sha(self._canonical),
            "planSha256": self.plan.sha256,
            "backendSha256": self._backend.sha256,
            "requestSha256": request.sha256,
            "operationId": request.operation_id,
            "foreign": {
                **foreign.wire(),
                "activityToken": foreign.activity_token,
            },
            "removedTaskId": value.removed_task_id,
            "preCapturedNs": str(value.pre_captured_ns),
            "dispatchNs": str(value.dispatched_ns),
            "postCapturedNs": str(value.post_captured_ns),
            "preActivityManagerSha256": _sha(value.pre_activity_manager_raw),
            "preStableTaskAuthoritySha256":
                android.stable_authority_sha256(pre_task),
            "postActivityManagerSha256": post_am_sha256,
            "preStockProcessEvidenceSha256": value.pre_stock_process.sha256,
            "postStockProcessEvidenceSha256": value.post_stock_process.sha256,
            "attestation": {
                "route": REMOVE_ROUTE,
                "compareIdentityBeforeRemove": True,
                "exactTaskIdOnly": True,
                "packageSelectorUsed": False,
                "wildcardSelectorUsed": False,
                "forceStopUsed": False,
                "callerCommandInputUsed": False,
                "broadScopeUsed": False,
                "processKillUsed": False,
                "taskAbsent": True,
                "stockProcessAlive": True,
            },
            "hardwareTimingProven": HARDWARE_TIMING_PROVEN,
        })

    @_serialized
    def verify(self) -> None:
        self._verify_dependencies()

    @_serialized
    def canonical_bytes(self) -> bytes:
        self._verify_dependencies()
        return self._canonical

    @_serialized
    def launch_fixture(self, serial: str, fixture_uri: str,
                       fixture_sha256: str, display_id: int,
                       deadline_ns: int) -> harness.LaunchReceipt:
        if self._launch_consumed or self.state != "NEW":
            raise TaskAdapterError("task launch authority is one-shot")
        self._launch_consumed = True
        request: TaskOperationRequest | None = None
        witness: _DispatchWitness | None = None
        foreign: host.ForeignIdentity | None = None
        try:
            if (type(serial) is not str or serial != self.plan.serial or
                    type(fixture_uri) is not str or
                    fixture_uri != self.plan.fixture_uri or
                    type(fixture_sha256) is not str or
                    fixture_sha256 != self.plan.fixture_sha256 or
                    type(display_id) is not int):
                _fail("caller launch scope differs from the immutable task plan")
            bound_display = self._bind_display(display_id)
            scope = ExactLaunchScope(
                self.plan.sha256, self.plan.serial, self.plan.fixture_uri,
                self.plan.fixture_sha256, bound_display)
            request = self._request(
                LAUNCH_OPERATION, scope.wire(), deadline_ns)
            result, witness = self._invoke_mutating(
                request,
                lambda selected, callback:
                    self._backend_call(
                        lambda retained_backend:
                            retained_backend.launch_exact_nonexported_document(
                                selected, scope, callback)))
            _exact(result, LaunchBackendReceipt, "launch backend receipt")
            # Derive and retain cleanup identity before checking policy fields.
            foreign, task = self._derive_live_foreign(
                result.activity_manager_raw, result.stock_process,
                result.captured_ns)
            self._foreign = foreign
            self._validate_ack(request, result.ack)
            for actual, expected, label in (
                    (result.fixture_uri, self.plan.fixture_uri, "fixture URI"),
                    (result.fixture_sha256, self.plan.fixture_sha256,
                     "fixture digest"),
                    (result.component, host.FOREIGN_COMPONENT, "component"),
                    (result.action, ACTION_VIEW, "action"),
                    (result.mime_type, MIME_PDF, "MIME type"),
                    (result.route, LAUNCH_ROUTE, "launch route")):
                _literal(actual, expected, "launch receipt " + label)
            if (type(result.display_id) is not int or
                    result.display_id != bound_display or
                    type(result.dispatched_ns) is not int or
                    result.dispatched_ns != witness.dispatched_ns or
                    type(result.captured_ns) is not int or
                    not request.issued_ns <= result.dispatched_ns <=
                    result.captured_ns <= result.ack.produced_ns or
                    result.explicit_component is not True or
                    result.component_exported is not False or
                    result.fixture_uri_resolved_exact is not True or
                    result.fixture_hash_verified_before_dispatch is not True or
                    result.user_document_selection_used is not False or
                    result.caller_command_input_used is not False or
                    result.broad_scope_used is not False or
                    result.process_kill_used is not False):
                _fail("launch receipt escaped exact non-exported fixture authority")
            evidence = self._launch_evidence(request, result, foreign, task)
            self._set_state("LIVE")
            self._clear_obligations()
            return harness.LaunchReceipt(
                foreign, self.plan.fixture_uri, self.plan.fixture_sha256,
                evidence, False, False)
        except _NotDispatched as error:
            self._set_state("LAUNCH_NOT_DISPATCHED")
            self._clear_obligations()
            raise LaunchNotDispatched(
                "exact fixture launch was not dispatched") from error.cause
        except _InvocationUncertain as error:
            self._set_state("LAUNCH_UNCERTAIN_UNKNOWN")
            self._obligation("launch side effects are uncertain; no exact task identity is available")
            raise LaunchOutcomeUncertain(
                "exact fixture launch outcome is uncertain", None) from error.cause
        except BaseException as error:
            dispatched = bool(witness is not None and
                              (witness.attempted or witness.seen or
                               witness.violation))
            if request is None or not dispatched:
                self._set_state("LAUNCH_NOT_DISPATCHED")
                self._clear_obligations()
                if isinstance(error, LaunchNotDispatched):
                    raise
                raise LaunchNotDispatched(
                    "exact fixture launch was rejected before dispatch") from error
            if foreign is not None:
                self._foreign = foreign
                self._set_state("LAUNCH_UNCERTAIN_RETAINED")
                self._obligation(
                    "launch outcome is uncertain; remove only the retained exact task identity")
            else:
                self._set_state("LAUNCH_UNCERTAIN_UNKNOWN")
                self._obligation(
                    "launch side effects are uncertain; no exact task identity is available")
            if isinstance(error, LaunchOutcomeUncertain):
                raise
            raise LaunchOutcomeUncertain(
                "exact fixture launch may have occurred but its receipt was rejected",
                foreign) from error

    @_serialized
    def destroy_exact_task(self, serial: str, foreign: host.ForeignIdentity,
                           deadline_ns: int) -> harness.TaskClosure:
        retained = self._foreign
        if retained is None:
            raise TaskAdapterError("no exact foreign task identity is retained")
        if self._remove_consumed or self.state not in {
                "LIVE", "LAUNCH_UNCERTAIN_RETAINED"}:
            raise TaskAdapterError("exact task removal authority is one-shot or closed")
        self._remove_consumed = True
        request: TaskOperationRequest | None = None
        witness: _DispatchWitness | None = None
        try:
            if type(serial) is not str or serial != self.plan.serial:
                _fail("caller removal serial differs from the immutable task plan")
            self._validate_foreign(foreign)
            if foreign != retained:
                _fail("caller removal identity differs from the retained task")
            request = self._request(REMOVE_OPERATION, {
                "serial": self.plan.serial,
                "foreign": {
                    **retained.wire(),
                    "activityToken": retained.activity_token,
                },
                "removeRoute": REMOVE_ROUTE,
            }, deadline_ns)
            result, witness = self._invoke_mutating(
                request,
                lambda selected, callback:
                    self._backend_call(
                        lambda retained_backend:
                            retained_backend.remove_exact_retained_task(
                                selected, retained, callback)))
            _exact(result, DestroyBackendReceipt, "destroy backend receipt")
            self._validate_ack(request, result.ack)
            if result.foreign != retained:
                _fail("destroy receipt foreign identity differs")
            pre_task = self._validate_retained_live(
                result.pre_activity_manager_raw, result.pre_stock_process,
                result.pre_captured_ns, retained)
            self._validate_process(result.post_stock_process,
                                   result.post_captured_ns,
                                   expected=retained.process)
            post_am_sha256 = _prove_absent(
                result.post_activity_manager_raw, retained)
            _literal(result.route, REMOVE_ROUTE, "destroy receipt route")
            if (type(result.removed_task_id) is not int or
                    result.removed_task_id != retained.task_id or
                    type(result.pre_captured_ns) is not int or
                    type(result.dispatched_ns) is not int or
                    type(result.post_captured_ns) is not int or
                    result.dispatched_ns != witness.dispatched_ns or
                    not request.issued_ns <= result.pre_captured_ns <=
                    result.dispatched_ns <= result.post_captured_ns <=
                    result.ack.produced_ns or
                    result.compare_identity_before_remove is not True or
                    result.exact_task_id_only is not True or
                    result.package_selector_used is not False or
                    result.wildcard_selector_used is not False or
                    result.force_stop_used is not False or
                    result.caller_command_input_used is not False or
                    result.broad_scope_used is not False or
                    result.process_kill_used is not False):
                _fail("destroy receipt escaped exact retained-task authority")
            evidence = self._closure_evidence(
                request, result, retained, pre_task, post_am_sha256)
            self._set_state("CLOSED")
            self._clear_obligations()
            return harness.TaskClosure(
                retained, True, True, evidence, False, False)
        except _NotDispatched as error:
            self._set_state("REMOVE_NOT_DISPATCHED")
            self._obligation("retained exact task was not removed")
            raise RemovalNotDispatched(
                "exact retained-task removal was not dispatched",
                retained) from error.cause
        except _InvocationUncertain as error:
            self._set_state("REMOVAL_UNCERTAIN")
            self._obligation(
                "exact retained-task removal outcome requires fresh absence proof")
            raise RemovalOutcomeUncertain(
                "exact retained-task removal outcome is uncertain",
                retained) from error.cause
        except BaseException as error:
            dispatched = bool(witness is not None and
                              (witness.attempted or witness.seen or
                               witness.violation))
            if request is None or not dispatched:
                self._set_state("REMOVE_NOT_DISPATCHED")
                self._obligation("retained exact task was not removed")
                if isinstance(error, RemovalNotDispatched):
                    raise
                raise RemovalNotDispatched(
                    "exact retained-task removal was rejected before dispatch",
                    retained) from error
            self._set_state("REMOVAL_UNCERTAIN")
            self._obligation(
                "exact retained-task removal outcome requires fresh absence proof")
            if isinstance(error, RemovalOutcomeUncertain):
                raise
            raise RemovalOutcomeUncertain(
                "exact retained-task removal may have occurred but closure was rejected",
                retained) from error

    @_serialized
    def assert_quiescent(self, foreign: host.ForeignIdentity,
                         deadline_ns: int) -> None:
        retained = self._foreign
        if retained is None:
            raise TaskQuiescenceUncertain(
                "task quiescence lacks a retained exact foreign identity")
        self._validate_foreign(foreign)
        if foreign != retained:
            raise TaskQuiescenceUncertain(
                "task quiescence identity differs from retained authority")
        if self.state == "QUIESCENT":
            self._verify_dependencies()
            return
        if self.state not in {
                "LIVE", "LAUNCH_UNCERTAIN_RETAINED", "REMOVE_NOT_DISPATCHED",
                "REMOVAL_UNCERTAIN", "CLOSED"}:
            raise TaskQuiescenceUncertain(
                "task lifecycle cannot authorize exact quiescence proof")
        try:
            request = self._request(QUIESCENCE_OPERATION, {
                "foreign": {
                    **retained.wire(),
                    "activityToken": retained.activity_token,
                },
                "readOnly": True,
            }, deadline_ns)
            result = self._invoke_read_only(
                request,
                lambda selected: self._backend_call(
                    lambda retained_backend:
                        retained_backend.prove_exact_task_absent(
                            selected, retained)))
            _exact(result, QuiescenceBackendReceipt,
                   "task quiescence backend receipt")
            self._validate_ack(request, result.ack)
            if result.foreign != retained:
                _fail("task quiescence receipt foreign identity differs")
            self._validate_process(result.stock_process, result.captured_ns,
                                   expected=retained.process)
            _prove_absent(result.activity_manager_raw, retained)
            if (type(result.captured_ns) is not int or
                    not request.issued_ns <= result.captured_ns <=
                    result.ack.produced_ns or result.read_only is not True or
                    type(result.mutation_count) is not int or
                    result.mutation_count != 0 or
                    result.broad_scope_used is not False or
                    result.process_kill_used is not False):
                _fail("task quiescence receipt is mutable or out of bounds")
            all_result = self._backend_call(
                lambda selected: selected.assert_all_quiescent(
                    self._backend, request.deadline_ns))
            if all_result is not None:
                _fail("task backend all-quiescent check returned unexpected data")
            self._verify_dependencies()
            if self._now() >= request.deadline_ns:
                _fail("task backend all-quiescent proof missed its deadline")
            self._set_state("QUIESCENT")
            self._clear_obligations()
        except BaseException as error:
            self._set_state("QUIESCENCE_UNCERTAIN")
            self._obligation(
                "exact task absence, stock-process liveness, or backend quiescence is uncertain")
            if isinstance(error, TaskQuiescenceUncertain):
                raise
            raise TaskQuiescenceUncertain(
                "exact task authority did not prove quiescence") from error


__all__ = [
    "AUTHORITY", "PLAN_AUTHORITY", "BACKEND_AUTHORITY", "REQUEST_AUTHORITY",
    "ACK_AUTHORITY", "PROCESS_EVIDENCE_AUTHORITY",
    "LAUNCH_EVIDENCE_AUTHORITY", "CLOSURE_EVIDENCE_AUTHORITY",
    "CLOCK_AUTHORITY", "CLOCK_SOURCE",
    "LAUNCH_OPERATION", "REMOVE_OPERATION", "QUIESCENCE_OPERATION",
    "LAUNCH_ROUTE", "REMOVE_ROUTE", "PROCESS_SOURCE", "ACTION_VIEW",
    "MIME_PDF", "STOCK_BASE_APK_PATH", "REAL_FIXED_BACKEND_IMPLEMENTED",
    "HARDWARE_TIMING_PROVEN", "UNRESOLVED_BLOCKERS", "TaskAdapterError",
    "LaunchNotDispatched", "LaunchOutcomeUncertain", "RemovalNotDispatched",
    "RemovalOutcomeUncertain", "TaskQuiescenceUncertain",
    "ExactFixtureTaskPlan", "ExactLaunchScope", "TaskBackendBinding",
    "TaskOperationRequest",
    "TaskOperationAck", "StockProcessEvidence", "LaunchBackendReceipt",
    "DestroyBackendReceipt", "QuiescenceBackendReceipt",
    "RetainedClockAuthority",
    "FixedTaskBackend", "NativePageVisualTaskAdapter", "admission_status",
]
