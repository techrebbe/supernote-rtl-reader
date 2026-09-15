"""Complete, fail-closed platform inventory authority for the visual harness.

The adapter in this module is deliberately transport-injected.  It never
discovers or launches ``adb``, opens a socket, selects a document, or issues a
mutating Android service.  A retained backend must return one complete bundle
containing ActivityManager, WindowManager, relevant-process/package, and
DisplayManager evidence.  The process wire binds the other three exact byte
strings and the requested scope to one capture ID and monotonic timestamp.

The currently reviewed :mod:`native_page_private_adb` server does *not* expose
the complete-bundle operation required here.  ``admit_existing_private_adb``
therefore always fails closed; it is a blocker, not a convenience fallback.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
import threading
from typing import Any, Never, Protocol
import uuid

import native_page_android_authority as android
import native_page_host_authority as host
import native_page_visual_session_harness as harness


AUTHORITY = "rtl-reader-native-page-visual-platform-authority-v1"
BACKEND_CAPTURE_AUTHORITY = (
    "rtl-reader-native-page-private-adb-complete-platform-capture-v1"
)
PRODUCTION_BACKEND_BLOCKER = (
    "REVIEWED_PRIVATE_ADB_COMPLETE_PLATFORM_CAPTURE_BACKEND_REQUIRED"
)

MAX_BACKEND_AUTHORITY_BYTES = 1_048_576
MAX_ACTIVITY_BYTES = android.MAX_DUMPSYS_BYTES
MAX_WINDOW_BYTES = 2_097_152
MAX_PROCESS_BYTES = 262_144
MAX_DISPLAY_BYTES = 1_048_576
MAX_LINE_CHARS = 65_536
MAX_ROWS = host.MAX_CAPTURE_ROWS
MAX_CAPTURE_NS = 60_000_000_000
MAX_PID = android.MAX_PID
MAX_TASK_ID = 10_000_000
MAX_DISPLAY_ID = 1024
MAX_START_TICKS = 10**32 - 1
PHYSICAL_DISPLAY_NAME = "Built-in Screen"
DISPLAY_DENSITY_DPI = 300
PHYSICAL_GEOMETRIES = frozenset({(1404, 1872), (1872, 1404)})

HEX = re.compile(r"[0-9a-f]{64}\Z")
SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
LABEL = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z")
TOKEN = re.compile(r"[0-9a-f]{1,64}\Z")
NAME = re.compile(r"[A-Za-z0-9._:/@+-]{1,256}\Z")
COMPONENT = re.compile(
    r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/"
    r"(\.[A-Za-z0-9_.$]+|[A-Za-z][A-Za-z0-9_.$]*(?:\.[A-Za-z0-9_.$]+)*)\Z"
)
RELEVANT_PACKAGES = (host.FOREIGN_PACKAGE, host.HOST_PACKAGE)


class VisualPlatformError(RuntimeError):
    """Base failure for this authority."""


class PlatformAdmissionBlocked(VisualPlatformError):
    """A backend lacks independently reviewed complete-capture authority."""


class PlatformEvidenceRejected(VisualPlatformError):
    """One capture is incomplete, ambiguous, stale, or internally inconsistent."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformEvidenceRejected(message)


def _sha(raw: bytes) -> str:
    _need(type(raw) is bytes, "digest input is not exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise PlatformEvidenceRejected("authority data is not canonical JSON") from error


def _canonical_uuid(value: Any, label: str) -> str:
    _need(type(value) is str, label + " is not text")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as error:
        raise PlatformEvidenceRejected(label + " is not a UUID") from error
    _need(value == canonical, label + " is not a canonical lowercase UUID")
    return value


def _decimal(value: str, label: str, minimum: int, maximum: int) -> int:
    _need(re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
          label + " is not canonical decimal")
    selected = int(value, 10)
    _need(minimum <= selected <= maximum, label + " is out of range")
    return selected


def _boolean(value: str, label: str) -> bool:
    _need(value in ("true", "false"), label + " is not canonical boolean")
    return value == "true"


def _wire(raw: bytes, *, label: str, header: str, maximum: int) -> tuple[str, list[str]]:
    _need(type(raw) is bytes and 0 < len(raw) <= maximum,
          label + " wire is empty or oversized")
    _need(b"\x00" not in raw, label + " wire contains NUL")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise PlatformEvidenceRejected(label + " wire is not UTF-8") from error
    if "\r" in text:
        _need(text.count("\r") == text.count("\r\n") == text.count("\n"),
              label + " wire has mixed line endings")
        text = text.replace("\r\n", "\n")
    _need(text.endswith("\n"), label + " wire is truncated/unterminated")
    _need(text.startswith(header + "\n"), label + " wire header differs")
    _need(not text.startswith("\ufeff"), label + " wire has a byte-order mark")
    _need(all(
        (ord(character) >= 0x20 or character in ("\n", "\t")) and
        character not in ("\x7f", "\x85", "\u2028", "\u2029")
        for character in text
    ), label + " wire contains a noncanonical control or line separator")
    lines = text[:-1].split("\n")
    _need(all(len(line) <= MAX_LINE_CHARS for line in lines),
          label + " wire contains an oversized line")
    return text, lines


def _component(value: str) -> tuple[str, str]:
    match = COMPONENT.fullmatch(value)
    _need(match is not None, "activity component syntax differs")
    package, name = match.groups()
    if name.startswith("."):
        name = package + name
    return package, package + "/" + name


def _foreign_native_viewport(configuration: str) -> tuple[int, int, int, int]:
    """Parse the one structurally owned foreign ``winConfig`` viewport.

    These bytes are authority, not a bag of searchable hints.  In particular,
    an acceptable orientation or bounds value outside its Android configuration
    slot must not mask a malformed value inside that slot.
    """
    _need(type(configuration) is str and 0 < len(configuration) <= MAX_LINE_CHARS,
          "foreign native configuration differs")
    # This is the one exact normalized grammar admitted for the pinned firmware.
    # A future literal device variation requires a new retained fixture/review;
    # permissive token searching would let values be reordered or shadowed by
    # contradictory fields outside their actual Android slots.
    structure = re.fullmatch(
        r"\{1\.0 en_US 300dpi port winConfig=\{ "
        r"mBounds=Rect\(([0-9]+), ([0-9]+) - ([0-9]+), ([0-9]+)\) "
        r"mAppBounds=Rect\(([0-9]+), ([0-9]+) - ([0-9]+), ([0-9]+)\) "
        r"mRotation=ROTATION_([0-3])\} s\.(0|[1-9][0-9]*)\}",
        configuration,
    )
    _need(structure is not None,
          "foreign native configuration grammar differs")
    values = structure.groups()
    parsed_bounds = tuple(
        _decimal(value, "foreign native bounds coordinate", 0, 32768)
        for value in values[0:4]
    )
    parsed_app_bounds = tuple(
        _decimal(value, "foreign native app-bounds coordinate", 0, 32768)
        for value in values[4:8]
    )
    _decimal(values[9], "foreign native configuration sequence", 0,
             2_147_483_647)
    _need(parsed_bounds == (0, 0, 1404, 1872) and
          parsed_app_bounds == parsed_bounds and values[8] == "0",
          "foreign native app viewport differs")
    return parsed_app_bounds


def _process(value: host.ProcessIdentity, label: str = "process") -> None:
    _need(type(value) is host.ProcessIdentity and
          type(value.pid) is int and 1 <= value.pid <= MAX_PID and
          type(value.start_ticks) is int and
          1 <= value.start_ticks <= MAX_START_TICKS and
          type(value.uid) is int and 0 <= value.uid <= 2_147_483_647 and
          type(value.package) is str and PACKAGE.fullmatch(value.package) is not None,
          label + " identity differs")


def _foreign_digest(value: host.ForeignIdentity | None) -> str | None:
    if value is None:
        return None
    _need(type(value) is host.ForeignIdentity, "foreign scope is not exact typed identity")
    _process(value.process, "foreign process")
    _need(value.process.package == host.FOREIGN_PACKAGE and
          value.process.uid == android.SYSTEM_UID and
          type(value.task_id) is int and 1 <= value.task_id <= MAX_TASK_ID and
          type(value.activity_token) is str and TOKEN.fullmatch(value.activity_token) is not None and
          value.component == host.FOREIGN_COMPONENT and
          type(value.evidence_sha256) is str and HEX.fullmatch(value.evidence_sha256) is not None,
          "foreign identity is outside the stock task authority")
    return _sha(_json(value.wire()))


@dataclass(frozen=True)
class BackendIdentity:
    """Retained identity of a separately reviewed complete-capture backend."""

    authority: str
    authority_sha256: str
    serial: str
    boot_id: str
    generation: int
    read_only: bool
    complete_capture: bool
    ambient_discovery: bool


@dataclass(frozen=True)
class CaptureRequest:
    label: str
    serial: str
    boot_id: str
    display_id: int | None
    foreign_sha256: str | None


@dataclass(frozen=True)
class RawPlatformBundle:
    """One backend-returned bundle; individual command calls are not accepted."""

    activity_manager_raw: bytes
    window_manager_raw: bytes
    process_inventory_raw: bytes
    display_inventory_raw: bytes


class RetainedPrivateAdbBackend(Protocol):
    """Trusted boundary required by :class:`VisualPlatformAuthority`.

    ``capture_complete`` must acquire all four raw members under one retained
    private transport transaction.  It cannot implement this by accepting
    caller-provided command text or by borrowing results from prior calls.
    """

    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def identity(self) -> BackendIdentity: ...
    def now_ns(self) -> int: ...
    def capture_complete(self, request: CaptureRequest,
                         deadline_ns: int) -> RawPlatformBundle: ...


@dataclass(frozen=True)
class ProcessInventory:
    capture_id: str
    label: str
    serial: str
    boot_id: str
    started_ns: int
    captured_ns: int
    finished_ns: int
    display_id: int | None
    foreign_sha256: str | None
    package: host.PackageRecord
    processes: tuple[host.ProcessIdentity, ...]


@dataclass(frozen=True)
class _ActivityInventory:
    display_ids: tuple[int, ...]
    task_tokens: tuple[str, ...]
    activities: tuple[host.ActivityRecord, ...]


@dataclass(frozen=True)
class _WindowItem:
    handle: str
    record: host.WindowRecord
    component: str


@dataclass(frozen=True)
class _WindowInventory:
    focused: tuple[tuple[int, str], ...]
    items: tuple[_WindowItem, ...]


@dataclass(frozen=True)
class _DisplayInventory:
    unique_ids: tuple[str, ...]
    displays: tuple[host.DisplayRecord, ...]


def _parse_process_inventory(raw: bytes, *, activity_raw: bytes,
                             window_raw: bytes,
                             display_raw: bytes) -> ProcessInventory:
    _, lines = _wire(
        raw, label="process inventory",
        header="NATIVE PAGE PROCESS INVENTORY (visual-platform-v1)",
        maximum=MAX_PROCESS_BYTES,
    )
    _need(len(lines) >= 7, "process inventory is truncated")
    capture = re.fullmatch(
        r"capture authority=([^ ]+) captureId=([^ ]+) label=([^ ]+) "
        r"serial=([^ ]+) bootId=([^ ]+) startedNs=([^ ]+) "
        r"capturedNs=([^ ]+) finishedNs=([^ ]+)", lines[1])
    _need(capture is not None, "process capture header format differs")
    (capture_authority, capture_id, label, serial, boot_id, started_text,
     captured_text, finished_text) = capture.groups()
    _need(capture_authority == BACKEND_CAPTURE_AUTHORITY,
          "process capture authority differs")
    _canonical_uuid(capture_id, "capture ID")
    _need(LABEL.fullmatch(label) is not None, "capture label differs")
    _need(SERIAL.fullmatch(serial) is not None, "capture serial syntax differs")
    _canonical_uuid(boot_id, "boot ID")
    started_ns = _decimal(started_text, "capture start timestamp", 0, 2**63 - 1)
    captured_ns = _decimal(captured_text, "capture timestamp", 0, 2**63 - 1)
    finished_ns = _decimal(finished_text, "capture finish timestamp", 0,
                           2**63 - 1)
    _need(started_ns <= captured_ns <= finished_ns,
          "capture receipt monotonic bracket is inverted")

    scope = re.fullmatch(
        r"scope displayId=(none|0|[1-9][0-9]*) foreignSha256=(none|[0-9a-f]{64})",
        lines[2])
    _need(scope is not None, "process capture scope format differs")
    display_text, foreign_text = scope.groups()
    display_id = (None if display_text == "none" else
                  _decimal(display_text, "scope display ID", 0, MAX_DISPLAY_ID))
    foreign_sha256 = None if foreign_text == "none" else foreign_text

    binding = re.fullmatch(
        r"bind activityBytes=([^ ]+) activitySha256=([^ ]+) "
        r"windowBytes=([^ ]+) windowSha256=([^ ]+) "
        r"displayBytes=([^ ]+) displaySha256=([^ ]+)", lines[3])
    _need(binding is not None, "process capture digest binding format differs")
    (activity_bytes, activity_sha, window_bytes, window_sha,
     display_bytes, display_sha) = binding.groups()
    expected_bindings = (
        (_decimal(activity_bytes, "activity byte count", 1, MAX_ACTIVITY_BYTES),
         activity_sha, activity_raw, "activity"),
        (_decimal(window_bytes, "window byte count", 1, MAX_WINDOW_BYTES),
         window_sha, window_raw, "window"),
        (_decimal(display_bytes, "display byte count", 1, MAX_DISPLAY_BYTES),
         display_sha, display_raw, "display"),
    )
    for size, digest, bound_raw, bound_label in expected_bindings:
        _need(HEX.fullmatch(digest) is not None and
              size == len(bound_raw) and digest == _sha(bound_raw),
              bound_label + " raw is not bound to the process capture")

    expected_policy = (
        "policy complete=true readOnly=true mutationCount=0 "
        "userDocumentSelectionCount=0 scopePackages=" +
        ",".join(RELEVANT_PACKAGES)
    )
    _need(lines[4] == expected_policy,
          "process capture is truncated, mutable, or has unknown scope")

    package_match = re.fullmatch(
        r"package name=([^ ]+) installedApkSha256=([^ ]+) "
        r"reviewedUnsignedApkSha256=([^ ]+) dexSha256=([^ ]+) "
        r"signerCertSha256=([^ ]+) versionCode=([^ ]+) versionName=([^ ]+)",
        lines[5])
    _need(package_match is not None, "package inventory format differs")
    (package_name, installed_apk_sha, unsigned_apk_sha, dex_sha,
     signer_cert_sha, version_code_text, version_name) = package_match.groups()
    package = host.PackageRecord(
        package_name, installed_apk_sha, unsigned_apk_sha, dex_sha,
        signer_cert_sha,
        _decimal(version_code_text, "package version code", 1, 2_147_483_647),
        version_name,
    )
    _need(package == host.PINNED_PACKAGE,
          "installed host package/signer/reviewed-build authority differs")

    end = re.fullmatch(r"END processCount=([^ ]+) packageCount=([^ ]+)", lines[-1])
    _need(end is not None, "process inventory terminal is absent or malformed")
    process_count = _decimal(end.group(1), "process terminal count", 1, MAX_ROWS)
    package_count = _decimal(end.group(2), "package terminal count", 1, 1)
    _need(package_count == 1, "package inventory is incomplete or ambiguous")
    process_lines = lines[6:-1]
    _need(len(process_lines) == process_count,
          "process inventory count differs or is truncated")
    processes: list[host.ProcessIdentity] = []
    for line in process_lines:
        match = re.fullmatch(
            r"process pid=([^ ]+) startTicks=([^ ]+) uid=([^ ]+) package=([^ ]+)",
            line)
        _need(match is not None, "process inventory contains unknown format")
        pid_text, start_text, uid_text, process_package = match.groups()
        _need(process_package in RELEVANT_PACKAGES,
              "process inventory escaped its exact package scope")
        process = host.ProcessIdentity(
            _decimal(pid_text, "process PID", 1, MAX_PID),
            _decimal(start_text, "process start ticks", 1, MAX_START_TICKS),
            _decimal(uid_text, "process UID", 0, 2_147_483_647),
            process_package,
        )
        _process(process)
        processes.append(process)
    _need(processes == sorted(processes, key=lambda item: item.pid),
          "process inventory is not in canonical PID order")
    _need(len({item.pid for item in processes}) == len(processes) and
          len({item.package for item in processes}) == len(processes),
          "process inventory identity is duplicated or ambiguous")
    return ProcessInventory(
        capture_id, label, serial, boot_id, started_ns, captured_ns,
        finished_ns, display_id, foreign_sha256, package, tuple(processes),
    )


def _activity_task(lines: list[str], display_id: int, stack_id: int,
                   resumed_marker: tuple[str, str, int] | None,
                   processes: dict[int, host.ProcessIdentity]) -> tuple[host.ActivityRecord, str]:
    _need(len(lines) == 11, "ActivityManager task block is truncated or unknown")
    task = re.fullmatch(
        r"    \* Task\{([0-9a-f]{1,64}) #([0-9]+) visible=(true|false) "
        r"type=([a-z_]+) mode=([a-z_]+) translucent=(true|false) "
        r"A=([0-9]+):([^ ]+) U=0 StackId=([0-9]+) sz=1\}", lines[0])
    _need(task is not None, "ActivityManager task header format differs")
    (task_token, task_text, task_visible_text, task_type, task_mode,
     task_translucent_text, affinity_uid_text, affinity_package,
     stack_text) = task.groups()
    task_id = _decimal(task_text, "activity task ID", 1, MAX_TASK_ID)
    _need(task_type == "standard" and task_mode == "fullscreen" and
          _boolean(task_translucent_text, "task translucency") is False,
          "ActivityManager task presentation mode differs")
    _need(task_id == stack_id and
          _decimal(stack_text, "activity task stack ID", 0, MAX_TASK_ID) == stack_id,
          "ActivityManager task/stack identity differs")
    _need(PACKAGE.fullmatch(affinity_package) is not None,
          "ActivityManager task package syntax differs")
    affinity_uid = _decimal(affinity_uid_text, "task affinity UID", 0, 2_147_483_647)
    detail = re.fullmatch(r"      taskId=([0-9]+) stackId=([0-9]+)", lines[1])
    _need(detail is not None and
          _decimal(detail.group(1), "task detail ID", 1, MAX_TASK_ID) == task_id and
          _decimal(detail.group(2), "task detail stack ID", 0, MAX_TASK_ID) == stack_id,
          "ActivityManager task detail identity differs")
    history = re.fullmatch(
        r"      \* Hist #0: ActivityRecord\{([0-9a-f]{1,64}) u0 ([^ ]+) t([0-9]+)\}",
        lines[2])
    _need(history is not None, "ActivityManager activity boundary differs")
    activity_token, raw_component, history_task = history.groups()
    _need(_decimal(history_task, "history task ID", 1, MAX_TASK_ID) == task_id,
          "ActivityManager activity/task identity differs")
    component_package, normalized_component = _component(raw_component)

    package_line = re.fullmatch(
        r"          packageName=([^ ]+) processName=([^ ]+)", lines[3])
    app_line = re.fullmatch(
        r"          app=ProcessRecord\{[0-9a-f]{1,64} ([0-9]+):([^/ ]+)/([0-9]+)\}",
        lines[4])
    component_line = re.fullmatch(r"          mActivityComponent=([^ ]+)", lines[5])
    base_line = re.fullmatch(r"          baseDir=([^ ]+)", lines[6])
    _need(package_line is not None and app_line is not None and
          component_line is not None and base_line is not None,
          "ActivityManager package/process/component evidence is incomplete")
    package_name, process_name = package_line.groups()
    pid_text, app_process_name, uid_text = app_line.groups()
    detail_package, detail_component = _component(component_line.group(1))
    base_dir = base_line.group(1)
    _need(lines[7].startswith("          CurrentConfiguration=") and
          len(lines[7]) > len("          CurrentConfiguration=") and
          base_dir.startswith("/") and base_dir.endswith(".apk") and
          len(base_dir.encode("utf-8")) <= 4096,
          "ActivityManager configuration/base APK evidence differs")
    configuration = lines[7][len("          CurrentConfiguration="):]
    lifecycle = re.fullmatch(
        r"          state=([A-Z_]+) stopped=(true|false) "
        r"delayedResume=(true|false) finishing=(true|false)", lines[8])
    visibility = re.fullmatch(
        r"          mVisibleRequested=(true|false) mVisible=(true|false) "
        r"mClientVisible=(true|false) reportedDrawn=(true|false) "
        r"reportedVisible=(true|false)", lines[9])
    now_visible = re.fullmatch(r"          nowVisible=(true|false) [^\n]+", lines[10])
    _need(lifecycle is not None and visibility is not None and now_visible is not None,
          "ActivityManager lifecycle/visibility evidence is incomplete")
    pid = _decimal(pid_text, "activity PID", 1, MAX_PID)
    uid = _decimal(uid_text, "activity UID", 0, 2_147_483_647)
    _need(pid in processes, "ActivityManager activity process is absent")
    process = processes[pid]
    _need(affinity_uid == uid == process.uid and
          affinity_package == package_name == component_package == detail_package == process.package and
          process_name == app_process_name == process.package and
          detail_component == normalized_component,
          "ActivityManager process/package/component scopes disagree")
    if process.package == host.FOREIGN_PACKAGE:
        _foreign_native_viewport(configuration)
    marker_matches = resumed_marker == (activity_token, normalized_component, task_id)
    state = lifecycle.group(1)
    stopped, delayed, finishing = (
        _boolean(lifecycle.group(2), "activity stopped"),
        _boolean(lifecycle.group(3), "activity delayed resume"),
        _boolean(lifecycle.group(4), "activity finishing"),
    )
    requested, visible, client, drawn, reported = (
        _boolean(value, "activity visibility") for value in visibility.groups()
    )
    now = _boolean(now_visible.group(1), "activity now-visible")
    task_visible = _boolean(task_visible_text, "task visibility")
    _need((state == "RESUMED") == marker_matches and
          (not marker_matches or
           (not stopped and not delayed and not finishing and task_visible and
            requested and visible and client and drawn and reported and now)),
          "ActivityManager resumed/live fields disagree")
    return (host.ActivityRecord(
        process, task_id, normalized_component, activity_token, display_id,
        marker_matches, visible,
    ), task_token)


def _parse_activity_manager(raw: bytes,
                            processes: tuple[host.ProcessIdentity, ...]) -> _ActivityInventory:
    _, lines = _wire(
        raw, label="ActivityManager",
        header="ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)",
        maximum=MAX_ACTIVITY_BYTES,
    )
    process_map = {item.pid: item for item in processes}
    start = 1
    if len(lines) > 1 and lines[1] == "Display areas in focus order:":
        start = 2
    _need(start < len(lines), "ActivityManager display list is absent")
    display_header = re.compile(
        r"Display #([0-9]+) \(activities from top to bottom\):")
    positions = [index for index in range(start, len(lines))
                 if display_header.fullmatch(lines[index]) is not None]
    _need(positions and positions[0] == start,
          "ActivityManager display list is not header-anchored")
    for index in range(start, len(lines)):
        line = lines[index]
        if re.match(r"\s*Display\b", line, re.IGNORECASE):
            _need(display_header.fullmatch(line) is not None,
                  "ActivityManager display header is malformed")
        if not line.startswith((" ", "\t")):
            _need(index in positions,
                  "ActivityManager contains an unknown top-level section")

    display_ids: list[int] = []
    task_tokens: list[str] = []
    activities: list[host.ActivityRecord] = []
    seen_stacks: set[int] = set()
    for ordinal, position in enumerate(positions):
        display_match = display_header.fullmatch(lines[position])
        assert display_match is not None
        display_id = _decimal(
            display_match.group(1), "ActivityManager display ID", 0,
            MAX_DISPLAY_ID)
        display_ids.append(display_id)
        end = positions[ordinal + 1] if ordinal + 1 < len(positions) else len(lines)
        block = lines[position + 1:end]
        if not block:
            continue
        stack_header = re.compile(
            r"  Stack #([0-9]+): type=(standard) mode=(fullscreen)")
        stack_positions = [index for index, line in enumerate(block)
                           if stack_header.fullmatch(line) is not None]
        _need(stack_positions and stack_positions[0] == 0,
              "ActivityManager display content lacks a stack boundary")
        for line in block:
            if re.match(r"\s*Stack\b", line, re.IGNORECASE):
                _need(stack_header.fullmatch(line) is not None,
                      "ActivityManager stack header is malformed")
        for stack_ordinal, stack_position in enumerate(stack_positions):
            stack_match = stack_header.fullmatch(block[stack_position])
            assert stack_match is not None
            stack_id = _decimal(stack_match.group(1), "ActivityManager stack ID",
                                0, MAX_TASK_ID)
            _need(stack_id not in seen_stacks,
                  "ActivityManager stack ID is duplicated")
            seen_stacks.add(stack_id)
            stack_end = (stack_positions[stack_ordinal + 1]
                         if stack_ordinal + 1 < len(stack_positions) else len(block))
            stack = block[stack_position + 1:stack_end]
            _need(stack, "ActivityManager stack is truncated")
            resumed = re.fullmatch(
                r"    mResumedActivity: (null|ActivityRecord\{([0-9a-f]{1,64}) u0 ([^ ]+) t([0-9]+)\})",
                stack[0])
            _need(resumed is not None,
                  "ActivityManager resumed-activity marker is malformed")
            marker: tuple[str, str, int] | None = None
            if resumed.group(1) != "null":
                _, normalized = _component(resumed.group(3))
                marker = (
                    resumed.group(2), normalized,
                    _decimal(resumed.group(4), "resumed task ID", 1, MAX_TASK_ID),
                )
            cursor = 1
            stack_records: list[host.ActivityRecord] = []
            while cursor < len(stack):
                if not re.match(r"    \* Task\b", stack[cursor]):
                    raise PlatformEvidenceRejected(
                        "ActivityManager task boundary is malformed or unknown")
                task_end = cursor + 11
                _need(task_end <= len(stack), "ActivityManager task block is truncated")
                record, task_token = _activity_task(
                    stack[cursor:task_end], display_id, stack_id, marker,
                    process_map,
                )
                stack_records.append(record)
                task_tokens.append(task_token)
                cursor = task_end
            _need(len(stack_records) <= 1,
                  "pinned ActivityManager stack has ambiguous task cardinality")
            if marker is not None:
                _need(sum(item.resumed for item in stack_records) == 1,
                      "ActivityManager resumed marker borrows another scope")
            activities.extend(stack_records)
    _need(display_ids == sorted(display_ids) and
          len(set(display_ids)) == len(display_ids),
          "ActivityManager display IDs are duplicate or out of order")
    _need(len(activities) <= MAX_ROWS and
          len({item.task_id for item in activities}) == len(activities) and
          len({item.token for item in activities}) == len(activities) and
          len(set(task_tokens)) == len(task_tokens),
          "ActivityManager task/activity identity is duplicate or oversized")
    return _ActivityInventory(tuple(display_ids), tuple(task_tokens),
                              tuple(activities))


def _rect(value: str, label: str) -> host.Rect:
    match = re.fullmatch(r"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]", value)
    _need(match is not None, label + " rectangle format differs")
    left, top, right, bottom = (
        _decimal(item, label + " coordinate", 0, 32768)
        for item in match.groups()
    )
    _need(right > left and bottom > top,
          label + " rectangle is empty or inverted")
    return host.Rect(left, top, right - left, bottom - top)


def _parse_window_manager(raw: bytes,
                          processes: tuple[host.ProcessIdentity, ...]) -> _WindowInventory:
    _, lines = _wire(
        raw, label="WindowManager",
        header="WINDOW MANAGER WINDOWS (dumpsys window windows)",
        maximum=MAX_WINDOW_BYTES,
    )
    _need(len(lines) >= 2, "WindowManager inventory is truncated")
    process_map = {item.pid: item for item in processes}
    cursor = 1
    focused: list[tuple[int, str]] = []
    focus_pattern = re.compile(
        r"FocusedWindow displayId=([0-9]+) activityToken=([0-9a-f]{1,64})")
    while cursor < len(lines) and focus_pattern.fullmatch(lines[cursor]) is not None:
        match = focus_pattern.fullmatch(lines[cursor])
        assert match is not None
        focused.append((
            _decimal(match.group(1), "focused display ID", 0, MAX_DISPLAY_ID),
            match.group(2),
        ))
        cursor += 1
    items: list[_WindowItem] = []
    window_pattern = re.compile(
        r"Window #([0-9]+) Window\{([0-9a-f]{1,64}) u0 ([^ ]+)\}:")
    while cursor < len(lines) and not lines[cursor].startswith("END "):
        window = window_pattern.fullmatch(lines[cursor])
        _need(window is not None, "WindowManager window boundary is malformed or unknown")
        _need(_decimal(window.group(1), "window ordinal", 0, MAX_ROWS - 1) == len(items),
              "WindowManager window ordinal is missing or out of order")
        _need(cursor + 4 < len(lines), "WindowManager window block is truncated")
        component_package, normalized_component = _component(window.group(3))
        owner = re.fullmatch(
            r"  owner pid=([0-9]+) uid=([0-9]+) package=([^ ]+)",
            lines[cursor + 1])
        identity = re.fullmatch(
            r"  taskId=([0-9]+) activityToken=([0-9a-f]{1,64}) displayId=([0-9]+)",
            lines[cursor + 2])
        geometry = re.fullmatch(
            r"  frame=(\[[^ ]+\]\[[^ ]+\]) surfaceFrame=(none|\[[^ ]+\]\[[^ ]+\]) "
            r"buffer=(none|[0-9]+x[0-9]+)", lines[cursor + 3])
        state = re.fullmatch(r"  visible=(true|false) focused=(true|false)",
                             lines[cursor + 4])
        _need(owner is not None and identity is not None and
              geometry is not None and state is not None,
              "WindowManager window fields are incomplete or unknown")
        pid = _decimal(owner.group(1), "window PID", 1, MAX_PID)
        uid = _decimal(owner.group(2), "window UID", 0, 2_147_483_647)
        owner_package = owner.group(3)
        _need(pid in process_map, "WindowManager owner process is absent")
        process = process_map[pid]
        _need((uid, owner_package, component_package) ==
              (process.uid, process.package, process.package),
              "WindowManager process/package scope differs")
        task_id = _decimal(identity.group(1), "window task ID", 1, MAX_TASK_ID)
        activity_token = identity.group(2)
        display_id = _decimal(identity.group(3), "window display ID", 0,
                              MAX_DISPLAY_ID)
        frame = _rect(geometry.group(1), "window frame")
        surface_frame = (None if geometry.group(2) == "none" else
                         _rect(geometry.group(2), "window surface frame"))
        buffer: tuple[int, int] | None = None
        if geometry.group(3) != "none":
            width_text, height_text = geometry.group(3).split("x", 1)
            buffer = (
                _decimal(width_text, "window buffer width", 1, 32768),
                _decimal(height_text, "window buffer height", 1, 32768),
            )
        record = host.WindowRecord(
            process, task_id, activity_token, display_id, frame,
            _boolean(state.group(1), "window visibility"),
            _boolean(state.group(2), "window focus"), surface_frame, buffer,
        )
        items.append(_WindowItem(window.group(2), record, normalized_component))
        cursor += 5
    _need(cursor == len(lines) - 1, "WindowManager terminal position differs")
    terminal = re.fullmatch(r"END windowCount=([0-9]+) focusedCount=([0-9]+)",
                            lines[cursor])
    _need(terminal is not None and
          _decimal(terminal.group(1), "window terminal count", 0, MAX_ROWS) == len(items) and
          _decimal(terminal.group(2), "focus terminal count", 0, MAX_ROWS) == len(focused),
          "WindowManager terminal count differs or is truncated")
    _need(focused == sorted(focused) and
          len({display for display, _ in focused}) == len(focused) and
          len({token for _, token in focused}) == len(focused),
          "WindowManager focus identity is duplicate or out of order")
    records = [item.record for item in items]
    _need(records == sorted(records, key=lambda item: (item.display_id, item.task_id,
                                                        item.activity_token)) and
          len({item.handle for item in items}) == len(items) and
          len({item.activity_token for item in records}) == len(records) and
          len({item.task_id for item in records}) == len(records),
          "WindowManager identity is duplicate or out of order")
    focus_set = set(focused)
    _need(all(item.focused == ((item.display_id, item.activity_token) in focus_set)
              for item in records) and
          all(any(item.display_id == display and item.activity_token == token
                  for item in records) for display, token in focused),
          "WindowManager focus rows and window fields disagree")
    return _WindowInventory(tuple(focused), tuple(items))


def _parse_display_inventory(raw: bytes,
                             processes: tuple[host.ProcessIdentity, ...]) -> _DisplayInventory:
    _, lines = _wire(
        raw, label="DisplayManager",
        header="DISPLAY MANAGER DISPLAYS (dumpsys display)",
        maximum=MAX_DISPLAY_BYTES,
    )
    _need(len(lines) >= 2, "DisplayManager inventory is truncated")
    process_map = {item.pid: item for item in processes}
    cursor = 1
    displays: list[host.DisplayRecord] = []
    unique_ids: list[str] = []
    header_pattern = re.compile(r"Display #([0-9]+):")
    while cursor < len(lines) and not lines[cursor].startswith("END "):
        header_match = header_pattern.fullmatch(lines[cursor])
        _need(header_match is not None,
              "DisplayManager display boundary is malformed or unknown")
        _need(cursor + 6 < len(lines), "DisplayManager display block is truncated")
        display_id = _decimal(header_match.group(1), "display ID", 0,
                              MAX_DISPLAY_ID)
        unique = re.fullmatch(r"  uniqueId=([^ ]+)", lines[cursor + 1])
        name = re.fullmatch(r"  name=(.{1,256})", lines[cursor + 2])
        owner_none = lines[cursor + 3] == "  owner=none"
        owner_match = re.fullmatch(
            r"  ownerPid=([0-9]+) ownerUid=([0-9]+) ownerPackage=([^ ]+)",
            lines[cursor + 3])
        metrics = re.fullmatch(r"  metrics=([0-9]+)x([0-9]+) density=([0-9]+)",
                               lines[cursor + 4])
        flags = re.fullmatch(r"  flags=(none|[A-Z_]+(?:,[A-Z_]+)*)",
                             lines[cursor + 5])
        _need(unique is not None and NAME.fullmatch(unique.group(1)) is not None and
              name is not None and name.group(1).strip() == name.group(1) and
              (owner_none or owner_match is not None) and metrics is not None and
              flags is not None and lines[cursor + 6] == "  state=ON",
              "DisplayManager display fields are incomplete or unknown")
        owner: host.ProcessIdentity | None = None
        if owner_match is not None:
            pid = _decimal(owner_match.group(1), "display owner PID", 1, MAX_PID)
            uid = _decimal(owner_match.group(2), "display owner UID", 0,
                           2_147_483_647)
            owner_package = owner_match.group(3)
            _need(pid in process_map, "DisplayManager owner process is absent")
            owner = process_map[pid]
            _need((owner.uid, owner.package) == (uid, owner_package),
                  "DisplayManager owner process/package scope differs")
        width = _decimal(metrics.group(1), "display width", 1, 32768)
        height = _decimal(metrics.group(2), "display height", 1, 32768)
        density = _decimal(metrics.group(3), "display density", 72, 1280)
        flag_values = (() if flags.group(1) == "none" else
                       tuple(flags.group(1).split(",")))
        _need(tuple(sorted(flag_values)) == flag_values and
              len(set(flag_values)) == len(flag_values),
              "DisplayManager flags are duplicate or out of order")
        record = host.DisplayRecord(
            display_id, owner, name.group(1), width, height, density,
            frozenset(flag_values),
        )
        unique_ids.append(unique.group(1))
        displays.append(record)
        cursor += 7
    _need(cursor == len(lines) - 1, "DisplayManager terminal position differs")
    terminal = re.fullmatch(r"END displayCount=([0-9]+)", lines[cursor])
    _need(terminal is not None and
          _decimal(terminal.group(1), "display terminal count", 1, MAX_ROWS) == len(displays),
          "DisplayManager terminal count differs or is truncated")
    _need(displays == sorted(displays, key=lambda item: item.display_id) and
          len({item.display_id for item in displays}) == len(displays) and
          len(set(unique_ids)) == len(unique_ids),
          "DisplayManager identity is duplicate or out of order")
    return _DisplayInventory(tuple(unique_ids), tuple(displays))


def _expected_surface_frames(width: int, height: int) -> set[host.Rect]:
    placements = (host.Placement.FULL if (width, height) == (1404, 1872)
                  else None)
    if placements is not None:
        return {host.placement_frame(placements, width, height)[1]}
    return {
        host.placement_frame(value, width, height)[1]
        for value in (host.Placement.FULL, host.Placement.LEFT,
                      host.Placement.RIGHT)
    }


def _validate_snapshot_scope(
        *, process_inventory: ProcessInventory,
        activity_inventory: _ActivityInventory,
        window_inventory: _WindowInventory,
        display_inventory: _DisplayInventory,
        host_process: host.ProcessIdentity,
        host_task_id: int,
        host_activity_token: str,
        session_id: str,
        foreign: host.ForeignIdentity | None,
        display_id: int | None,
        activity_raw: bytes) -> None:
    processes = process_inventory.processes
    activities = activity_inventory.activities
    windows = tuple(item.record for item in window_inventory.items)
    displays = display_inventory.displays
    _need(sum(item == host_process for item in processes) == 1,
          "exact retained host process is absent or ambiguous")
    _need(all(item.package in RELEVANT_PACKAGES for item in processes),
          "process inventory escaped relevant package scope")
    _need(tuple(item.display_id for item in displays) == activity_inventory.display_ids,
          "ActivityManager and DisplayManager display scopes differ")
    display_ids = {item.display_id for item in displays}
    _need(all(item.display_id in display_ids for item in activities + windows),
          "task/window references an absent display")

    activity_by_token = {item.token: item for item in activities}
    _need(len(activity_by_token) == len(activities) and len(windows) == len(activities),
          "AM/window inventory cardinality differs")
    for item in window_inventory.items:
        window = item.record
        _need(window.activity_token in activity_by_token,
              "WindowManager window has no exact ActivityManager activity")
        activity = activity_by_token[window.activity_token]
        _need((window.process, window.task_id, window.display_id,
               window.visible, item.component) ==
              (activity.process, activity.task_id, activity.display_id,
               activity.visible, activity.component),
              "AM/window typed identity differs")

    expected_displays = {0} if display_id is None else {0, display_id}
    _need(display_id != 0 and display_ids == expected_displays,
          "display inventory is incomplete or has an unexpected display")
    physical = next(item for item in displays if item.display_id == 0)
    _need(physical.owner is None and physical.name == PHYSICAL_DISPLAY_NAME and
          (physical.width, physical.height) in PHYSICAL_GEOMETRIES and
          physical.density == DISPLAY_DENSITY_DPI and not physical.flags,
          "physical display authority differs")

    host_records = [item for item in activities
                    if item.process.package == host.HOST_PACKAGE or
                    item.task_id == host_task_id or item.token == host_activity_token]
    host_windows = [item for item in windows
                    if item.process.package == host.HOST_PACKAGE or
                    item.task_id == host_task_id or
                    item.activity_token == host_activity_token]
    foreign_records = [item for item in activities
                       if item.process.package == host.FOREIGN_PACKAGE or
                       item.component == host.FOREIGN_COMPONENT]
    foreign_windows = [item for item in windows
                       if item.process.package == host.FOREIGN_PACKAGE]

    if display_id is None:
        _need(not activities and not windows and not host_records and
              not host_windows and not foreign_records and not foreign_windows,
              "final absence scope retains a host/foreign task or window")
        return

    virtual = next(item for item in displays if item.display_id == display_id)
    _need(virtual == host.DisplayRecord(
        display_id, host_process,
        f"NativePageVisualOnly-{session_id}-1", 1404, 1872,
        DISPLAY_DENSITY_DPI, host.FLAGS,
    ), "owned virtual display authority differs")
    expected_host_activity = host.ActivityRecord(
        host_process, host_task_id, host.HOST_COMPONENT,
        host_activity_token, 0, True, True,
    )
    _need(host_records == [expected_host_activity] and len(host_windows) == 1,
          "exact live host task/activity/window authority differs")
    host_window = host_windows[0]
    _need(host_window.process == host_process and
          host_window.task_id == host_task_id and
          host_window.activity_token == host_activity_token and
          host_window.display_id == 0 and host_window.visible and
          host_window.focused and
          host_window.frame == host.Rect(0, 0, physical.width, physical.height) and
          host_window.surface_frame in _expected_surface_frames(
              physical.width, physical.height) and
          host_window.buffer == (1404, 1872),
          "host window geometry/focus/buffer authority differs")

    if foreign is None:
        _need(not foreign_records and not foreign_windows and
              activities == (expected_host_activity,) and windows == (host_window,),
              "prelaunch inventory contains an unexpected DocumentActivity")
        return

    _need(foreign.process in processes and len(foreign_records) == 1 and
          len(foreign_windows) == 1,
          "exact foreign process/task/window is absent or ambiguous")
    expected_foreign_activity = host.ActivityRecord(
        foreign.process, foreign.task_id, foreign.component,
        foreign.activity_token, display_id, True, True,
    )
    _need(foreign_records[0] == expected_foreign_activity,
          "foreign ActivityManager identity differs")
    foreign_window = foreign_windows[0]
    _need(foreign_window.process == foreign.process and
          foreign_window.task_id == foreign.task_id and
          foreign_window.activity_token == foreign.activity_token and
          foreign_window.display_id == display_id and
          foreign_window.frame == host.Rect(0, 0, 1404, 1872) and
          foreign_window.surface_frame == host.Rect(0, 0, 1404, 1872) and
          foreign_window.buffer == (1404, 1872) and
          foreign_window.visible and foreign_window.focused,
          "foreign WindowManager identity/surface/buffer geometry differs")
    _need(set(activities) == {expected_host_activity, expected_foreign_activity} and
          set(windows) == {host_window, foreign_window},
          "platform task/window inventory contains an unexpected record")
    try:
        task = android.parse_document_task_authority(
            activity_raw, expected_pid=foreign.process.pid, require_live=True)
    except android.AndroidAuthorityError as error:
        raise PlatformEvidenceRejected(
            "strict Android document-task authority rejected ActivityManager wire"
        ) from error
    _need(task.raw_sha256 == _sha(activity_raw) and
          android.stable_authority_sha256(task) == foreign.evidence_sha256 and
          task.display_id == display_id and task.task_id == foreign.task_id and
          task.activity_token == foreign.activity_token and
          task.pid == foreign.process.pid and task.uid == foreign.process.uid and
          task.package_name == foreign.process.package and
          (task.width, task.height, task.density_dpi, task.rotation) ==
          (virtual.width, virtual.height, virtual.density, 0),
          "foreign identity is not stable Android task authority")


class VisualPlatformAuthority:
    """Retained, one-bundle adapter implementing the harness PlatformAuthority."""

    def __init__(self, backend: RetainedPrivateAdbBackend, *,
                 host_process: host.ProcessIdentity, host_task_id: int,
                 host_activity_token: str, session_id: str,
                 expected_serial: str = harness.AUTHORIZED_SERIAL):
        _need(backend is not None, "retained private-ADB backend is absent")
        _process(host_process, "retained host process")
        _need(host_process.package == host.HOST_PACKAGE,
              "retained host process package differs")
        _need(type(host_task_id) is int and 1 <= host_task_id <= MAX_TASK_ID and
              type(host_activity_token) is str and
              TOKEN.fullmatch(host_activity_token) is not None,
              "retained host task/token authority differs")
        _canonical_uuid(session_id, "host session ID")
        _need(type(expected_serial) is str and SERIAL.fullmatch(expected_serial) is not None,
              "authorized serial syntax differs")
        self._backend = backend
        self.host_process = host_process
        self.host_task_id = host_task_id
        self.host_activity_token = host_activity_token
        self.session_id = session_id
        self.expected_serial = expected_serial
        self._failed: str | None = None
        self._capturing = False
        self._last_clock_ns = -1
        self._last_captured_ns = -1
        self._capture_ids: set[str] = set()
        self._mutex = threading.Lock()
        self._process_pins: dict[str, host.ProcessIdentity] = {
            host_process.package: host_process,
        }
        self._display_unique_pins: dict[int, str] = {}
        self._backend_raw, self._backend_identity = self._admit_backend()
        self._canonical = _json({
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "backendAuthoritySha256": _sha(self._backend_raw),
            "backendIdentity": asdict(self._backend_identity),
            "expectedSerial": expected_serial,
            "hostProcess": asdict(host_process),
            "hostTaskId": host_task_id,
            "hostActivityToken": host_activity_token,
            "sessionId": session_id,
            "capture": "single-complete-private-adb-bundle",
            "readOnly": True,
            "ambientAdbDiscovery": False,
            "userDocumentSelection": False,
            "deviceMutation": False,
        })
        self.verify()

    def _admit_backend(self) -> tuple[bytes, BackendIdentity]:
        try:
            self._backend.verify()
            raw = self._backend.canonical_bytes()
            identity = self._backend.identity()
            _need(type(raw) is bytes and
                  0 < len(raw) <= MAX_BACKEND_AUTHORITY_BYTES,
                  "backend canonical authority is absent or oversized")
            _need(type(identity) is BackendIdentity and
                  type(identity.authority) is str and
                  LABEL.fullmatch(identity.authority) is not None and
                  type(identity.authority_sha256) is str and
                  HEX.fullmatch(identity.authority_sha256) is not None and
                  identity.authority_sha256 == _sha(raw) and
                  identity.serial == self.expected_serial and
                  SERIAL.fullmatch(identity.serial) is not None and
                  type(identity.generation) is int and
                  identity.generation > 0 and
                  identity.read_only is True and
                  identity.complete_capture is True and
                  identity.ambient_discovery is False,
                  "backend lacks exact retained read-only complete-capture authority")
            _canonical_uuid(identity.boot_id, "retained backend boot ID")
        except BaseException as error:
            raise PlatformAdmissionBlocked(
                "retained private-ADB backend verification failed") from error
        return raw, identity

    def _verify_backend(self) -> None:
        try:
            self._backend.verify()
            raw = self._backend.canonical_bytes()
            identity = self._backend.identity()
        except BaseException as error:
            raise PlatformEvidenceRejected(
                "retained private-ADB backend verification failed") from error
        _need(raw == self._backend_raw and identity == self._backend_identity and
              _sha(raw) == identity.authority_sha256,
              "retained private-ADB backend identity/bytes drifted")

    def verify(self) -> None:
        _need(self._mutex.acquire(blocking=False),
              "platform authority is concurrent or reentrant")
        try:
            _need(self._failed is None,
                  "platform authority is sealed after evidence rejection")
            self._verify_backend()
        finally:
            self._mutex.release()

    def canonical_bytes(self) -> bytes:
        self.verify()
        return self._canonical

    def _now(self) -> int:
        try:
            value = self._backend.now_ns()
        except BaseException as error:
            raise PlatformEvidenceRejected("trusted monotonic clock failed") from error
        _need(type(value) is int and 0 <= value <= 2**63 - 1,
              "trusted monotonic clock is not canonical nanoseconds")
        _need(value >= self._last_clock_ns,
              "trusted monotonic clock moved backwards")
        self._last_clock_ns = value
        return value

    def capture(self, label: str, foreign: host.ForeignIdentity | None,
                display_id: int | None, deadline_ns: int) -> harness.PlatformCapture:
        _need(self._mutex.acquire(blocking=False),
              "platform capture is concurrent or reentrant")
        try:
            return self._capture_locked(label, foreign, display_id, deadline_ns)
        finally:
            self._mutex.release()

    def _capture_locked(self, label: str,
                        foreign: host.ForeignIdentity | None,
                        display_id: int | None,
                        deadline_ns: int) -> harness.PlatformCapture:
        _need(self._failed is None and not self._capturing,
              "platform capture is failed, concurrent, or reentrant")
        _need(type(label) is str and LABEL.fullmatch(label) is not None,
              "platform capture label differs")
        foreign_sha = _foreign_digest(foreign)
        _need((foreign is None or
               (type(display_id) is int and 1 <= display_id <= MAX_DISPLAY_ID)) and
              (display_id is None or
               (type(display_id) is int and 1 <= display_id <= MAX_DISPLAY_ID)),
              "platform capture display/foreign scope differs")
        before = self._now()
        _need(type(deadline_ns) is int and
              before < deadline_ns <= before + MAX_CAPTURE_NS,
              "platform capture deadline is expired or outside its bound")
        request = CaptureRequest(
            label, self.expected_serial, self._backend_identity.boot_id,
            display_id, foreign_sha,
        )
        self._capturing = True
        try:
            self._verify_backend()
            # Re-read immediately before dispatch so backend verification time
            # cannot be borrowed as evidence collection time.
            bracket_before = self._now()
            _need(bracket_before < deadline_ns,
                  "platform capture deadline expired before dispatch")
            bundle = self._backend.capture_complete(request, deadline_ns)
            bracket_after = self._now()
            _need(bracket_before <= bracket_after < deadline_ns,
                  "platform capture finished outside the trusted bracket")
            self._verify_backend()
            _need(type(bundle) is RawPlatformBundle and
                  all(type(value) is bytes and value for value in (
                      bundle.activity_manager_raw, bundle.window_manager_raw,
                      bundle.process_inventory_raw, bundle.display_inventory_raw)),
                  "backend returned an incomplete/untyped platform bundle")
            processes = _parse_process_inventory(
                bundle.process_inventory_raw,
                activity_raw=bundle.activity_manager_raw,
                window_raw=bundle.window_manager_raw,
                display_raw=bundle.display_inventory_raw,
            )
            _need(processes.label == label and
                  processes.serial == self.expected_serial == self._backend_identity.serial and
                  processes.boot_id == self._backend_identity.boot_id and
                  processes.display_id == display_id and
                  processes.foreign_sha256 == foreign_sha,
                  "platform bundle borrowed another serial/boot/request scope")
            _need(bracket_before <= processes.started_ns <=
                  processes.captured_ns <= processes.finished_ns <= bracket_after and
                  processes.captured_ns > self._last_captured_ns,
                  "platform timestamp is stale or future relative to its trusted bracket")
            _need(processes.capture_id not in self._capture_ids,
                  "platform capture ID was replayed")
            activity = _parse_activity_manager(
                bundle.activity_manager_raw, processes.processes)
            windows = _parse_window_manager(
                bundle.window_manager_raw, processes.processes)
            displays = _parse_display_inventory(
                bundle.display_inventory_raw, processes.processes)
            _validate_snapshot_scope(
                process_inventory=processes,
                activity_inventory=activity,
                window_inventory=windows,
                display_inventory=displays,
                host_process=self.host_process,
                host_task_id=self.host_task_id,
                host_activity_token=self.host_activity_token,
                session_id=self.session_id,
                foreign=foreign,
                display_id=display_id,
                activity_raw=bundle.activity_manager_raw,
            )
            self._verify_backend()
            finished_ns = self._now()
            _need(bracket_after <= finished_ns < deadline_ns,
                  "platform parsing/verification exceeded its absolute deadline")
            proposed_pins = dict(self._process_pins)
            for process in processes.processes:
                prior = proposed_pins.get(process.package)
                _need(prior is None or prior == process,
                      "relevant process PID/start/UID/package identity drifted")
                proposed_pins[process.package] = process
            proposed_display_pins = dict(self._display_unique_pins)
            for display, unique_id in zip(displays.displays,
                                          displays.unique_ids, strict=True):
                prior_unique_id = proposed_display_pins.get(display.display_id)
                _need(prior_unique_id is None or prior_unique_id == unique_id,
                      "display unique identity drifted between captures")
                proposed_display_pins[display.display_id] = unique_id
            snapshot = host.Snapshot(
                processes.captured_ns, processes.package,
                processes.processes, activity.activities,
                tuple(item.record for item in windows.items), displays.displays,
                _sha(bundle.activity_manager_raw),
                _sha(bundle.window_manager_raw),
                _sha(bundle.display_inventory_raw),
                _sha(bundle.process_inventory_raw), True,
            )
            result = harness.PlatformCapture(
                processes.captured_ns, snapshot,
                bundle.activity_manager_raw, bundle.window_manager_raw,
                bundle.process_inventory_raw, bundle.display_inventory_raw,
            )
            self._process_pins = proposed_pins
            self._display_unique_pins = proposed_display_pins
            self._last_captured_ns = processes.captured_ns
            self._capture_ids.add(processes.capture_id)
            return result
        except BaseException as error:
            self._failed = str(error)[:1000]
            if isinstance(error, VisualPlatformError):
                raise
            raise PlatformEvidenceRejected(
                "complete platform capture backend/parser failed") from error
        finally:
            self._capturing = False


def production_backend_status() -> dict[str, Any]:
    """Machine-readable reason the current PrivateAdbServer is not bridged."""
    return {
        "admitted": False,
        "authority": AUTHORITY,
        "blocker": PRODUCTION_BACKEND_BLOCKER,
        "missing": [
            "one retained four-source capture operation",
            "complete process PID/start-ticks/UID/package inventory",
            "complete DisplayManager inventory",
            "one capture receipt binding serial, boot, scope, raw digests, and monotonic time",
        ],
        "ambientAdbFallback": False,
        "readOnly": True,
    }


def admit_existing_private_adb(server: object) -> Never:
    """Reject bridging the current retained server without touching it.

    ``native_page_private_adb.PrivateAdbServer`` exposes only independent
    ``get_state``, ``wm_size``, ``wm_density``, ``dumpsys_window`` and
    ``dumpsys_activity`` commands.  It cannot establish process start ticks,
    package evidence, complete displays, or a shared capture bracket.  This
    function intentionally performs no duck typing, verification, or command.
    """
    del server
    raise PlatformAdmissionBlocked(
        PRODUCTION_BACKEND_BLOCKER +
        ": the current retained private-ADB interface cannot prove one complete coherent bundle"
    )


__all__ = [
    "AUTHORITY", "BACKEND_CAPTURE_AUTHORITY", "PRODUCTION_BACKEND_BLOCKER",
    "BackendIdentity", "CaptureRequest", "RawPlatformBundle",
    "RetainedPrivateAdbBackend", "VisualPlatformAuthority",
    "VisualPlatformError", "PlatformAdmissionBlocked",
    "PlatformEvidenceRejected", "ProcessInventory",
    "production_backend_status", "admit_existing_private_adb",
]
