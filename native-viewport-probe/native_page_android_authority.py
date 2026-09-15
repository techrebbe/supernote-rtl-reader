"""Strict parser for pinned-firmware DocumentActivity task/display evidence.

The parser consumes bounded raw ``dumpsys activity activities`` output.  It is
an external authority helper only: it never starts, resumes, moves, or resizes
an Android task.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any


AUTHORITY = "rtl-reader-android-document-task-authority-v2"
PACKAGE = "com.supernote.document"
PROCESS = "com.supernote.document"
SYSTEM_UID = 1000
SHORT_COMPONENT = "com.supernote.document/.document.DocumentActivity"
FULL_COMPONENT = "com.supernote.document/com.supernote.document.document.DocumentActivity"
MAX_DUMPSYS_BYTES = 2_097_152
MAX_LINE_CHARS = 65_536
MAX_PID = 4_194_304


class AndroidAuthorityError(RuntimeError):
    """ActivityManager evidence is absent, ambiguous, or internally inconsistent."""


@dataclass(frozen=True)
class DocumentTaskAuthority:
    authority: str
    raw_sha256: str
    display_id: int
    stack_id: int
    task_id: int
    task_token: str
    activity_token: str
    pid: int
    uid: int
    package_name: str
    process_name: str
    component: str
    base_apk_path: str
    state: str
    resumed: bool
    stopped: bool
    delayed_resume: bool
    finishing: bool
    task_visible: bool
    visible_requested: bool
    visible: bool
    client_visible: bool
    reported_drawn: bool
    reported_visible: bool
    now_visible: bool
    width: int
    height: int
    density_dpi: int
    rotation: int

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            asdict(self), ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")


def _wire(raw: bytes) -> tuple[str, str]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_DUMPSYS_BYTES:
        raise AndroidAuthorityError("ActivityManager wire is empty or oversized")
    if b"\x00" in raw:
        raise AndroidAuthorityError("ActivityManager wire contains NUL")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise AndroidAuthorityError("ActivityManager wire is not UTF-8") from error
    if "\r" in text:
        if (text.count("\r") != text.count("\r\n") or
                text.count("\n") != text.count("\r\n")):
            raise AndroidAuthorityError("ActivityManager wire has mixed line endings")
        text = text.replace("\r\n", "\n")
    if (any(ord(character) < 0x20 and character not in ("\n", "\t")
            for character in text) or "\x7f" in text or
            any(separator in text for separator in ("\x85", "\u2028", "\u2029"))):
        raise AndroidAuthorityError(
            "ActivityManager wire contains a noncanonical control or line separator")
    if any(len(line) > MAX_LINE_CHARS for line in text.split("\n")):
        raise AndroidAuthorityError("ActivityManager wire contains an oversized line")
    if not text.endswith("\n"):
        raise AndroidAuthorityError("ActivityManager wire is unterminated")
    if not text.startswith(
            "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"):
        raise AndroidAuthorityError("ActivityManager wire header differs")
    return text, digest


def _one(pattern: str, text: str, label: str, flags: int = re.MULTILINE) -> re.Match[str]:
    matches = list(re.finditer(pattern, text, flags))
    if len(matches) != 1:
        raise AndroidAuthorityError(label + " is absent or ambiguous")
    return matches[0]


def _require_one_prefixed_line(text: str, prefix: str, label: str) -> None:
    matches = [line for line in text.split("\n") if line.startswith(prefix)]
    if len(matches) != 1:
        raise AndroidAuthorityError(label + " line is absent or ambiguous")


def _boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise AndroidAuthorityError("invalid boolean")


def _bounded_int(value: str, label: str, minimum: int, maximum: int) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        raise AndroidAuthorityError(label + " is not canonical decimal")
    number = int(value, 10)
    if not minimum <= number <= maximum:
        raise AndroidAuthorityError(label + " is out of range")
    return number


def _reject_malformed_structural_headers(text: str) -> None:
    """Prevent a malformed boundary line from inheriting its predecessor's scope."""
    lines = text.split("\n")
    display_header = re.compile(
        r"^Display #[0-9]+ \(activities from top to bottom\):$")
    display_preamble = "Display areas in focus order:"
    display_headers = [
        index for index, line in enumerate(lines)
        if display_header.fullmatch(line) is not None]
    display_preambles = [
        index for index, line in enumerate(lines) if line == display_preamble]
    if display_preambles:
        placement_is_canonical = (
            display_preambles == [1] and bool(display_headers) and
            display_headers[0] == 2)
    else:
        placement_is_canonical = not display_headers or display_headers[0] == 1
    if not placement_is_canonical:
        raise AndroidAuthorityError(
            "ActivityManager display list is not header-anchored")
    for index, line in enumerate(lines):
        if re.match(r"^\s*Display\b", line, re.IGNORECASE):
            canonical_header = display_header.fullmatch(line) is not None
            canonical_preamble = display_preambles == [index]
            if not canonical_header and not canonical_preamble:
                raise AndroidAuthorityError(
                    "ActivityManager structural header is malformed")

    structural = (
        (r"^\s*Stack\b", r"^  Stack #[0-9]+:[^\n]*$"),
        (r"^\s*\*+\s*Task\b", r"^    \* Task\{[^\n]*\}$"),
        (r"^\s*\*+\s*Hist\b",
         r"^      \* Hist #[0-9]+: ActivityRecord\{[^\n]*\}$"),
        (r"^\s*mResumedActivity\b",
         r"^    mResumedActivity: (?:ActivityRecord\{[^\n]*\}|null)$"),
    )
    for line in lines:
        for header_like, admitted in structural:
            if (re.match(header_like, line, re.IGNORECASE) and
                    re.fullmatch(admitted, line) is None):
                raise AndroidAuthorityError("ActivityManager structural header is malformed")


def _display_stack_blocks(text: str) -> list[tuple[int, int, str]]:
    wire_lines = text.splitlines(keepends=True)
    display_preamble = "Display areas in focus order:\n"
    first_display_line = (
        2 if len(wire_lines) > 1 and wire_lines[1] == display_preamble else 1)
    display_header = re.compile(
        r"^Display #[0-9]+ \(activities from top to bottom\):$")
    region_end = len(wire_lines)
    for index in range(first_display_line + 1, len(wire_lines)):
        line = wire_lines[index]
        if (line == "\n" or line.startswith((" ", "\t")) or
                display_header.fullmatch(line[:-1]) is not None):
            continue
        region_end = index
        break
    remainder = wire_lines[region_end:]
    structural_after_boundary = re.compile(
        r"^\s*(?:Display\b|Stack\b|\*+\s*(?:Task|Hist)\b|"
        r"mResumedActivity\b)", re.IGNORECASE)
    if any(structural_after_boundary.match(line[:-1]) is not None
           for line in remainder):
        raise AndroidAuthorityError(
            "ActivityManager structural record follows display list")
    display_list = "".join(wire_lines[first_display_line:region_end])
    displays = list(re.finditer(
        r"^Display #([0-9]+) \(activities from top to bottom\):\n",
        display_list, re.MULTILINE))
    if not displays:
        raise AndroidAuthorityError("ActivityManager display list is absent")
    blocks: list[tuple[int, int, str]] = []
    seen_displays: set[int] = set()
    seen_stacks: set[int] = set()
    for display_index, display_match in enumerate(displays):
        display_id = _bounded_int(display_match.group(1), "display ID", 0, 1024)
        if display_id in seen_displays:
            raise AndroidAuthorityError("ActivityManager display ID is duplicated")
        seen_displays.add(display_id)
        display_end = (displays[display_index + 1].start()
                       if display_index + 1 < len(displays) else len(display_list))
        display_text = display_list[display_match.end():display_end]
        stacks = list(re.finditer(r"^  Stack #([0-9]+):[^\n]*\n", display_text,
                                  re.MULTILINE))
        for stack_index, stack_match in enumerate(stacks):
            stack_id = _bounded_int(stack_match.group(1), "stack ID", 0, 10_000_000)
            if stack_id in seen_stacks:
                raise AndroidAuthorityError("ActivityManager stack ID is duplicated")
            seen_stacks.add(stack_id)
            stack_end = (stacks[stack_index + 1].start()
                         if stack_index + 1 < len(stacks) else len(display_text))
            blocks.append((display_id, stack_id,
                           display_text[stack_match.start():stack_end]))
    return blocks


def _task_blocks(stack: str) -> list[str]:
    headers = list(re.finditer(r"^    \* Task\{[^\n]*\}$", stack,
                               re.MULTILINE))
    return [
        stack[header.start():(headers[index + 1].start()
                              if index + 1 < len(headers) else len(stack))]
        for index, header in enumerate(headers)
    ]


def _activity_block(task: str, activity: re.Match[str]) -> str:
    """Bound every ActivityRecord-owned field to the exact target Hist block."""
    histories = list(re.finditer(
        r"^      \* Hist #[0-9]+: ActivityRecord\{[^\n]*\}$",
        task, re.MULTILINE))
    matching_starts = [item.start() for item in histories
                       if item.start() == activity.start()]
    if len(matching_starts) != 1:
        raise AndroidAuthorityError("document activity block is ambiguous")
    end = next((item.start() for item in histories
                if item.start() > activity.start()), len(task))
    return task[activity.start():end]


def parse_document_task_authority(raw: bytes, *, expected_pid: int,
                                  require_live: bool = True) -> DocumentTaskAuthority:
    """Return one externally witnessed stock DocumentActivity or fail closed."""
    if type(expected_pid) is not int or not 1 <= expected_pid <= MAX_PID:
        raise AndroidAuthorityError("expected PID is invalid")
    if type(require_live) is not bool:
        raise AndroidAuthorityError("require_live is not boolean")
    text, digest = _wire(raw)
    _reject_malformed_structural_headers(text)
    display_stack_blocks = _display_stack_blocks(text)
    target_history_pattern = (
        rf"^      \* Hist #[0-9]+: ActivityRecord\{{[0-9a-f]+ u0 "
        rf"(?:{re.escape(SHORT_COMPONENT)}|{re.escape(FULL_COMPONENT)}) "
        rf"t[0-9]+\}}$")
    target_component_pattern = (
        rf"(?<!\S)(?:{re.escape(SHORT_COMPONENT)}|"
        rf"{re.escape(FULL_COMPONENT)})(?=\s|\}})")
    target_component_histories = [
        line for line in text.split("\n")
        if line.startswith("      * Hist #") and
        re.search(target_component_pattern, line)
    ]
    target_resumed_lines = [
        line for line in text.split("\n")
        if line.startswith("    mResumedActivity:") and
        re.search(target_component_pattern, line)
    ]
    if (len(target_component_histories) != 1 or
            len(list(re.finditer(target_history_pattern, text, re.MULTILINE))) != 1):
        raise AndroidAuthorityError("DocumentActivity record is absent or ambiguous")

    candidates: list[tuple[int, int, str, str]] = []
    for display_id, stack_id, stack_block in display_stack_blocks:
        for task_block in _task_blocks(stack_block):
            task_header = task_block.split("\n", 1)[0]
            if (re.search(
                    rf"(?<!\S)A={SYSTEM_UID}:{re.escape(PACKAGE)}(?=\s|\}})",
                    task_header) and
                    re.search(target_history_pattern, task_block, re.MULTILINE)):
                candidates.append((display_id, stack_id, stack_block, task_block))
    if len(candidates) != 1:
        raise AndroidAuthorityError("DocumentActivity task is absent or ambiguous")
    display_id, stack_id, stack_block, task_block = candidates[0]
    selected_target_resumed_lines = [
        line for line in stack_block.split("\n")
        if line.startswith("    mResumedActivity:") and
        re.search(target_component_pattern, line)
    ]
    if (len(target_resumed_lines) > 1 or
            len(target_resumed_lines) != len(selected_target_resumed_lines)):
        raise AndroidAuthorityError(
            "target resumed activity marker is outside document stack or ambiguous")

    task = _one(r"^    \* Task\{([0-9a-f]+) #([0-9]+) [^\n]*\}$",
                task_block, "document task")
    task_line = task.group(0)
    first_history = re.search(
        r"^      \* Hist #[0-9]+: ActivityRecord\{[^\n]*\}$",
        task_block, re.MULTILINE)
    if first_history is None:
        raise AndroidAuthorityError("document task has no activity boundary")
    task_owned = task_block[:first_history.start()]
    for key, label in (("visible=", "task visibility"),
                       ("A=", "task affinity"),
                       ("U=", "task user"),
                       ("StackId=", "task stack")):
        if len(re.findall(r"(?<!\S)" + re.escape(key), task_line)) != 1:
            raise AndroidAuthorityError(label + " key is ambiguous")
    task_token, task_id_text = task.groups()
    task_visible_text = _one(
        r"(?<!\S)visible=([^\s}]+)(?=\s|\})", task_line,
        "task visibility", flags=0).group(1)
    affinity = _one(
        r"(?<!\S)A=([^\s:}]+):([^\s}]+)(?=\s|\})", task_line,
        "task affinity", flags=0)
    task_user_text = _one(
        r"(?<!\S)U=([^\s}]+)(?=\s|\})", task_line,
        "task user", flags=0).group(1)
    task_stack_text = _one(
        r"(?<!\S)StackId=([^\s}]+)(?=\s|\})", task_line,
        "task stack", flags=0).group(1)
    affinity_uid = _bounded_int(affinity.group(1), "task affinity UID", 0,
                                2_147_483_647)
    task_user = _bounded_int(task_user_text, "task user", 0, 100_000)
    if (affinity_uid != SYSTEM_UID or affinity.group(2) != PACKAGE or
            task_user != 0):
        raise AndroidAuthorityError("task affinity or user authority differs")
    task_id = _bounded_int(task_id_text, "task ID", 0, 10_000_000)
    if (task_id != stack_id or
            _bounded_int(task_stack_text, "task stack ID", 0, 10_000_000) != stack_id):
        raise AndroidAuthorityError("task and stack IDs disagree")
    _require_one_prefixed_line(task_owned, "      taskId=", "document task detail")
    task_detail = _one(
        r"^      taskId=([0-9]+) stackId=([0-9]+)$",
        task_owned, "document task detail")
    detail_task_id = _bounded_int(
        task_detail.group(1), "detail task ID", 0, 10_000_000)
    detail_stack_id = _bounded_int(
        task_detail.group(2), "detail stack ID", 0, 10_000_000)
    if detail_task_id != task_id or detail_stack_id != stack_id:
        raise AndroidAuthorityError("task detail IDs disagree")

    activity = _one(
        rf"^      \* Hist #0: ActivityRecord\{{([0-9a-f]+) u0 "
        rf"(?:{re.escape(SHORT_COMPONENT)}|{re.escape(FULL_COMPONENT)}) t([0-9]+)\}}$",
        task_block, "document activity")
    activity_token, activity_task_text = activity.groups()
    if _bounded_int(activity_task_text, "activity task ID", 0, 10_000_000) != task_id:
        raise AndroidAuthorityError("activity and task IDs disagree")
    activity_owned = _activity_block(task_block, activity)
    for prefix, label in (
            ("          app=", "document process"),
            ("          packageName=", "package/process"),
            ("          mActivityComponent=", "component"),
            ("          baseDir=", "base APK"),
            ("          CurrentConfiguration=", "current configuration"),
            ("          state=", "activity lifecycle"),
            ("          mVisibleRequested=", "activity visibility"),
            ("          nowVisible=", "now-visible state")):
        _require_one_prefixed_line(activity_owned, prefix, label)

    app = _one(
        rf"^          app=ProcessRecord\{{[0-9a-f]+ ([0-9]+):"
        rf"{re.escape(PROCESS)}/([0-9]+)\}}$", activity_owned, "document process")
    pid = _bounded_int(app.group(1), "process PID", 1, MAX_PID)
    uid = _bounded_int(app.group(2), "process UID", 0, 2_147_483_647)
    if pid != expected_pid:
        raise AndroidAuthorityError("ActivityManager PID differs from target process")
    if uid != SYSTEM_UID:
        raise AndroidAuthorityError("DocumentActivity UID differs from pinned system authority")

    package = _one(r"^          packageName=([^ ]+) processName=([^\n]+)$",
                   activity_owned, "package/process")
    if package.groups() != (PACKAGE, PROCESS):
        raise AndroidAuthorityError("package/process authority differs")
    component = _one(r"^          mActivityComponent=([^\n]+)$", activity_owned,
                     "component").group(1)
    if component not in (SHORT_COMPONENT, FULL_COMPONENT):
        raise AndroidAuthorityError("component authority differs")
    base_apk = _one(r"^          baseDir=([^\n]+)$", activity_owned,
                    "base APK").group(1)
    if (not base_apk.startswith("/") or not base_apk.endswith(".apk") or
            "\x00" in base_apk or len(base_apk.encode("utf-8")) > 4096):
        raise AndroidAuthorityError("base APK path is invalid")

    lifecycle = _one(
        r"^          state=([A-Z_]+) stopped=(true|false) "
        r"delayedResume=(true|false) finishing=(true|false)$",
        activity_owned, "activity lifecycle")
    state, stopped_text, delayed_resume_text, finishing_text = lifecycle.groups()
    stopped = _boolean(stopped_text)
    delayed_resume = _boolean(delayed_resume_text)
    finishing = _boolean(finishing_text)
    visibility = _one(
        r"^          mVisibleRequested=(true|false) mVisible=(true|false) "
        r"mClientVisible=(true|false) reportedDrawn=(true|false) "
        r"reportedVisible=(true|false)$", activity_owned, "activity visibility")
    visible_requested, visible, client_visible, reported_drawn, reported_visible = map(
        _boolean, visibility.groups())
    now_visible_match = _one(r"^          nowVisible=(true|false) [^\n]+$",
                             activity_owned, "now-visible state")
    if now_visible_match.group(0).count("nowVisible=") != 1:
        raise AndroidAuthorityError("now-visible token is ambiguous")
    now_visible = _boolean(now_visible_match.group(1))

    configuration_line = next(
        line for line in activity_owned.split("\n")
        if line.startswith("          CurrentConfiguration="))
    configuration_tokens = configuration_line.split()
    density_tokens = [token for token in configuration_tokens
                      if token.endswith("dpi")]
    bounds_tokens = [token for token in configuration_tokens
                     if token.startswith("mBounds=")]
    rotation_tokens = [token for token in configuration_tokens
                       if token.startswith("mRotation=")]
    if (len(density_tokens) != 1 or len(bounds_tokens) != 1 or
            len(rotation_tokens) != 1):
        raise AndroidAuthorityError("current configuration token is ambiguous")
    density_token = density_tokens[0][:-3]
    bounds = re.search(
        r"(?<!\S)mBounds=Rect\(0, 0 - ([0-9]+), ([0-9]+)\)(?=\s|$)",
        configuration_line)
    rotation_match = re.search(
        r"(?<!\S)mRotation=ROTATION_([0-3])(?=\}|\s|$)",
        configuration_line)
    if bounds is None or rotation_match is None:
        raise AndroidAuthorityError("current configuration value is invalid")
    density = _bounded_int(density_token, "density", 72, 1280)
    width = _bounded_int(bounds.group(1), "display width", 1, 32768)
    height = _bounded_int(bounds.group(2), "display height", 1, 32768)
    rotation = _bounded_int(rotation_match.group(1), "rotation", 0, 3)

    first_task = re.search(r"^    \* Task\{[^\n]*\}$", stack_block,
                           re.MULTILINE)
    if first_task is None:
        raise AndroidAuthorityError("document stack has no task boundary")
    stack_owned = stack_block[:first_task.start()]
    resumed_lines = [line for line in stack_block.split("\n")
                     if line.startswith("    mResumedActivity:")]
    all_resumed_markers = list(re.finditer(
        r"^    mResumedActivity: ActivityRecord\{[^\n]+\}$",
        stack_owned, re.MULTILINE))
    if (len(resumed_lines) > 1 or
            (len(resumed_lines) == 1 and len(all_resumed_markers) != 1)):
        raise AndroidAuthorityError("resumed activity marker is ambiguous")
    resumed_marker = list(re.finditer(
        rf"^    mResumedActivity: ActivityRecord\{{{re.escape(activity_token)} u0 "
        rf"(?:{re.escape(SHORT_COMPONENT)}|{re.escape(FULL_COMPONENT)}) t{task_id}\}}$",
        stack_owned, re.MULTILINE))
    if (resumed_lines and
            re.search(target_component_pattern, resumed_lines[0]) and
            len(resumed_marker) != 1):
        raise AndroidAuthorityError("target resumed activity marker disagrees")
    resumed = len(resumed_marker) == 1

    authority = DocumentTaskAuthority(
        AUTHORITY, digest, display_id, stack_id, task_id, task_token,
        activity_token, pid, uid, PACKAGE, PROCESS, component, base_apk, state,
        resumed, stopped, delayed_resume, finishing, _boolean(task_visible_text),
        visible_requested, visible, client_visible, reported_drawn, reported_visible, now_visible,
        width, height, density, rotation)
    if require_live and not (
            authority.state == "RESUMED" and authority.resumed and
            not authority.stopped and not authority.delayed_resume and
            not authority.finishing and
            authority.task_visible and authority.visible_requested and
            authority.visible and authority.client_visible and
            authority.reported_drawn and authority.reported_visible and
            authority.now_visible):
        raise AndroidAuthorityError("DocumentActivity is not one live visible target")
    return authority


def stable_authority(before: DocumentTaskAuthority,
                     after: DocumentTaskAuthority) -> bool:
    """Compare semantic authority while allowing the raw dumpsys digest to differ."""
    if (type(before) is not DocumentTaskAuthority or
            type(after) is not DocumentTaskAuthority):
        raise AndroidAuthorityError("task authority wrapper type differs")
    string_fields = (
        "authority", "raw_sha256", "task_token", "activity_token",
        "package_name", "process_name", "component", "base_apk_path", "state",
    )
    integer_fields = (
        "display_id", "stack_id", "task_id", "pid", "uid", "width", "height",
        "density_dpi", "rotation",
    )
    boolean_fields = (
        "resumed", "stopped", "delayed_resume", "finishing", "task_visible",
        "visible_requested", "visible", "client_visible", "reported_drawn",
        "reported_visible", "now_visible",
    )
    for value in (before, after):
        if (any(type(getattr(value, name)) is not str for name in string_fields) or
                any(type(getattr(value, name)) is not int for name in integer_fields) or
                any(type(getattr(value, name)) is not bool for name in boolean_fields)):
            raise AndroidAuthorityError("task authority field type differs")
    left: dict[str, Any] = asdict(before)
    right: dict[str, Any] = asdict(after)
    left.pop("raw_sha256")
    right.pop("raw_sha256")
    return left == right


def stable_authority_bytes(value: DocumentTaskAuthority) -> bytes:
    """Canonical semantic task authority, excluding one observation's bytes."""
    # Reuse the exact field-domain validation above before serializing.  A
    # dumpsys digest identifies one capture; it is deliberately not the stable
    # identity of a task across later, independently retained observations.
    stable_authority(value, value)
    payload = asdict(value)
    payload.pop("raw_sha256")
    try:
        return json.dumps(
            payload, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise AndroidAuthorityError(
            "task stable authority is not canonical JSON") from error


def stable_authority_sha256(value: DocumentTaskAuthority) -> str:
    return hashlib.sha256(stable_authority_bytes(value)).hexdigest()
