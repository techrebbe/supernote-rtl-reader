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


def _reject_malformed_structural_headers(text: str) -> str:
    """Return only the canonical display list after validating any supervisor suffix.

    The pinned firmware appends an ``ActivityStackSupervisor state:`` section
    which repeats task-looking records at a different indentation.  That suffix
    is useful corroboration, but it is never task-selection authority.  Split it
    at one exact boundary, fail closed on structural dialect confusion, and
    return only the top ``Display #...`` region to the semantic parser.
    """
    all_lines = text.split("\n")
    lines = all_lines[:-1]  # _wire() already requires one terminating newline.
    supervisor_boundary = "ActivityStackSupervisor state:"
    supervisor_boundary_like = re.compile(
        r"^\s*ActivityStackSupervisor\b", re.IGNORECASE)
    boundary_indexes = [
        index for index, line in enumerate(lines)
        if line == supervisor_boundary]
    if len(boundary_indexes) > 1:
        raise AndroidAuthorityError(
            "ActivityManager supervisor boundary is ambiguous")
    for line in lines:
        if (supervisor_boundary_like.match(line) is not None and
                line != supervisor_boundary):
            raise AndroidAuthorityError(
                "ActivityManager supervisor boundary is malformed")

    if boundary_indexes:
        boundary_index = boundary_indexes[0]
        authority_lines = lines[:boundary_index]
        supervisor_lines = lines[boundary_index + 1:]
    else:
        boundary_index = None
        authority_lines = lines
        supervisor_lines = []

    display_header = re.compile(
        r"^Display #([0-9]+) \(activities from top to bottom\):$")
    display_summary = re.compile(
        r"^  Display: mDisplayId=(0|[1-9][0-9]{0,9}) "
        r"stacks=(0|[1-9][0-9]{0,9})$")
    display_preamble = "Display areas in focus order:"
    display_headers = [
        index for index, line in enumerate(authority_lines)
        if display_header.fullmatch(line) is not None]
    display_preambles = [
        index for index, line in enumerate(authority_lines)
        if line == display_preamble]
    if display_preambles:
        placement_is_canonical = (
            display_preambles == [1] and bool(display_headers) and
            display_headers[0] == 2)
    else:
        placement_is_canonical = not display_headers or display_headers[0] == 1
    if not placement_is_canonical:
        raise AndroidAuthorityError(
            "ActivityManager display list is not header-anchored")
    supervisor_prefixes = (
        "  topDisplayFocusedStack=",
        "  mLastOrientationSource=",
        "  deepestLastOrientationSource=",
        "  Task display areas in top down Z order:",
    )
    for index, line in enumerate(authority_lines):
        if (display_summary.fullmatch(line) is not None or
                line.startswith(supervisor_prefixes)):
            raise AndroidAuthorityError(
                "ActivityManager supervisor content precedes its boundary")
        if re.match(r"^\s*Display\b", line, re.IGNORECASE):
            canonical_header = display_header.fullmatch(line) is not None
            canonical_preamble = display_preambles == [index]
            if not canonical_header and not canonical_preamble:
                raise AndroidAuthorityError(
                    "ActivityManager structural header is malformed")

    first_display_line = 2 if display_preambles else 1
    display_region_end = len(authority_lines)
    for index in range(first_display_line + 1, len(authority_lines)):
        line = authority_lines[index]
        if (line == "" or line.startswith((" ", "\t")) or
                display_header.fullmatch(line) is not None):
            continue
        display_region_end = index
        break
    if boundary_index is not None and display_region_end != len(authority_lines):
        raise AndroidAuthorityError(
            "ActivityManager supervisor boundary does not follow display list")

    # Index canonical pre-boundary Hist identities by the display which owns
    # them.  Some pinned-firmware multi-display dumps repeat an ActivityRecord
    # orientation-source pair immediately before that display's redundant
    # summary.  Those repeats are corroborating metadata only; they may be
    # admitted only when the complete identity names exactly one canonical
    # Hist record in the corresponding display section.
    activity_identity = (
        r"ActivityRecord\{[0-9a-f]+ u0 [^\s{}]+ "
        r"t[1-9][0-9]{0,9}\}")
    canonical_activity_displays: dict[str, list[int]] = {}
    all_activity_displays: dict[str, list[int]] = {}
    activity_token_occurrences: dict[str, list[tuple[str, int]]] = {}
    for record_index, header_index in enumerate(display_headers):
        header_match = display_header.fullmatch(authority_lines[header_index])
        if header_match is None:  # Defensive: indexes came from this regex.
            raise AndroidAuthorityError(
                "ActivityManager display authority is inconsistent")
        canonical_display_id = _bounded_int(
            header_match.group(1), "display ID", 0, 1024)
        record_end = (display_headers[record_index + 1]
                      if record_index + 1 < len(display_headers)
                      else len(authority_lines))
        display_lines = authority_lines[header_index + 1:record_end]
        for line in display_lines:
            history_match = re.fullmatch(
                r"^      \* Hist #[0-9]+: (" + activity_identity + r")$",
                line)
            if history_match is not None:
                identity = history_match.group(1)
                identity_fields = re.fullmatch(
                    r"ActivityRecord\{([0-9a-f]+) u0 [^\s{}]+ "
                    r"t([1-9][0-9]{0,9})\}", identity)
                if identity_fields is None:  # Defensive: same strict grammar.
                    raise AndroidAuthorityError(
                        "ActivityManager canonical activity identity differs")
                _bounded_int(
                    identity_fields.group(2), "activity task ID", 0,
                    10_000_000)
                all_activity_displays.setdefault(identity, []).append(
                    canonical_display_id)
                activity_token_occurrences.setdefault(
                    identity_fields.group(1), []).append(
                        (identity, canonical_display_id))

        # A matching-looking Hist line is canonical binding evidence only when
        # it is nested inside one exact Stack/Task block and all four task
        # identities agree: Stack #N, Task #N, taskId/stackId=N, and the
        # ActivityRecord's tN.  Merely sharing display indentation is not
        # enough, because malformed or displaced Hist records must not become
        # orientation authority.
        stack_headers = [
            (index, match) for index, line in enumerate(display_lines)
            if (match := re.fullmatch(
                r"^  Stack #([1-9][0-9]{0,9}):[^\n]*$", line)) is not None
        ]
        for stack_index, (stack_start, stack_match) in enumerate(stack_headers):
            stack_id = _bounded_int(
                stack_match.group(1), "orientation stack ID", 1, 10_000_000)
            stack_end = (stack_headers[stack_index + 1][0]
                         if stack_index + 1 < len(stack_headers)
                         else len(display_lines))
            stack_lines = display_lines[stack_start + 1:stack_end]
            task_headers = [
                (index, match) for index, line in enumerate(stack_lines)
                if (match := re.fullmatch(
                    r"^    \* Task\{[0-9a-f]+ "
                    r"#([1-9][0-9]{0,9}) [^\n]*\}$", line)) is not None
            ]
            for task_index, (task_start, task_match) in enumerate(task_headers):
                task_id = _bounded_int(
                    task_match.group(1), "orientation task ID", 1,
                    10_000_000)
                task_end = (task_headers[task_index + 1][0]
                            if task_index + 1 < len(task_headers)
                            else len(stack_lines))
                task_lines = stack_lines[task_start:task_end]
                stack_id_tokens = re.findall(
                    r"(?<!\S)StackId=([1-9][0-9]{0,9})(?=\s|\})",
                    task_lines[0])
                details = [
                    (index, match) for index, line in enumerate(task_lines)
                    if (match := re.fullmatch(
                        r"^      taskId=([1-9][0-9]{0,9}) "
                        r"stackId=([1-9][0-9]{0,9})$", line)) is not None
                ]
                context_is_canonical = (
                    task_id == stack_id and len(stack_id_tokens) == 1 and
                    _bounded_int(
                        stack_id_tokens[0], "orientation Task StackId", 1,
                        10_000_000) == stack_id and len(details) == 1 and
                    _bounded_int(
                        details[0][1].group(1), "orientation detail task ID",
                        1, 10_000_000) == task_id and
                    _bounded_int(
                        details[0][1].group(2), "orientation detail stack ID",
                        1, 10_000_000) == stack_id)
                for line_index, line in enumerate(task_lines):
                    history_match = re.fullmatch(
                        r"^      \* Hist #[0-9]+: (" + activity_identity +
                        r")$", line)
                    if history_match is None:
                        continue
                    identity = history_match.group(1)
                    identity_fields = re.fullmatch(
                        r"ActivityRecord\{[0-9a-f]+ u0 [^\s{}]+ "
                        r"t([1-9][0-9]{0,9})\}", identity)
                    if identity_fields is None:  # Defensive: same grammar.
                        continue
                    activity_task_id = _bounded_int(
                        identity_fields.group(1), "orientation activity task ID",
                        1, 10_000_000)
                    if (context_is_canonical and
                            details[0][0] < line_index and
                            activity_task_id == task_id):
                        canonical_activity_displays.setdefault(
                            identity, []).append(canonical_display_id)

    # The exact pinned-firmware supervisor prologue proves that the boundary
    # was not injected into an arbitrary blank line inside the canonical list.
    # While an Activity owns orientation, both orientation-source fields are
    # ActivityRecord/null values.  When the pinned firmware is idle, both name
    # the same DefaultTaskDisplayArea instance instead.  The latter is one
    # coherent supervisor state, not two independently borrowable values.
    if supervisor_lines:
        labels = (
            "topDisplayFocusedStack",
            "mLastOrientationSource",
            "deepestLastOrientationSource",
        )
        if len(supervisor_lines) < len(labels):
            raise AndroidAuthorityError(
                "ActivityManager supervisor prologue differs")

        label_indexes: dict[str, list[int]] = {}
        for label in labels:
            label_like = re.compile(
                r"^\s*" + re.escape(label), re.IGNORECASE)
            label_indexes[label] = [
                index for index, line in enumerate(supervisor_lines)
                if label_like.match(line) is not None
            ]
        if label_indexes["topDisplayFocusedStack"] != [0]:
            raise AndroidAuthorityError(
                "ActivityManager supervisor prologue is ambiguous")
        last_indexes = label_indexes["mLastOrientationSource"]
        deepest_indexes = label_indexes["deepestLastOrientationSource"]
        if (not last_indexes or not deepest_indexes or
                last_indexes[0] != 1 or deepest_indexes[0] != 2 or
                len(last_indexes) != len(deepest_indexes)):
            raise AndroidAuthorityError(
                "ActivityManager supervisor prologue is ambiguous")

        if re.fullmatch(
                r"^  topDisplayFocusedStack=(?:Task\{[^\n]*\}|null)$",
                supervisor_lines[0]) is None:
            raise AndroidAuthorityError(
                "ActivityManager supervisor prologue differs")

        activity_or_null = r"(?:ActivityRecord\{[^\n]*\}|null)"
        last_active = re.fullmatch(
            r"^  mLastOrientationSource=" + activity_or_null + r"$",
            supervisor_lines[1])
        deepest_active = re.fullmatch(
            r"^  deepestLastOrientationSource=" + activity_or_null + r"$",
            supervisor_lines[2])
        last_display_area = re.fullmatch(
            r"^  mLastOrientationSource=DefaultTaskDisplayArea@"
            r"(0|[1-9][0-9]{0,9})$",
            supervisor_lines[1])
        deepest_display_area = re.fullmatch(
            r"^  deepestLastOrientationSource=DefaultTaskDisplayArea@"
            r"(0|[1-9][0-9]{0,9})$",
            supervisor_lines[2])
        if last_active is not None and deepest_active is not None:
            pass
        elif (last_display_area is not None and
              deepest_display_area is not None):
            last_identity = _bounded_int(
                last_display_area.group(1),
                "last orientation display-area identity", 0, 2_147_483_647)
            deepest_identity = _bounded_int(
                deepest_display_area.group(1),
                "deepest orientation display-area identity", 0,
                2_147_483_647)
            if last_identity != deepest_identity:
                raise AndroidAuthorityError(
                    "ActivityManager orientation display-area identities disagree")
        else:
            raise AndroidAuthorityError(
                "ActivityManager supervisor orientation sources differ")

        # A pinned multi-display firmware dialect repeats one display-area
        # orientation pair immediately before the redundant summary for a
        # non-primary display.  It is display metadata only: admitting the pair
        # must never make either line task/activity-selection authority.  Bind
        # every optional repeat to one unique summary.  Anything target-bearing,
        # partial, misplaced, duplicated, mixed, or numerically noncanonical
        # fails closed.
        orientation_pair_displays: set[int] = set()
        orientation_pair_identities: set[int] = set()
        orientation_pair_activities: set[str] = set()
        display_area_pattern = (
            r"^  {label}=DefaultTaskDisplayArea@"
            r"(0|[1-9][0-9]{{0,9}})$")
        for last_index, deepest_index in zip(
                last_indexes[1:], deepest_indexes[1:]):
            if (deepest_index != last_index + 1 or
                    deepest_index + 1 >= len(supervisor_lines)):
                raise AndroidAuthorityError(
                    "ActivityManager per-display orientation pair is misplaced")
            summary_match = display_summary.fullmatch(
                supervisor_lines[deepest_index + 1])
            if summary_match is None:
                raise AndroidAuthorityError(
                    "ActivityManager per-display orientation pair is misplaced")
            display_id = _bounded_int(
                summary_match.group(1), "orientation-pair display ID", 0, 1024)
            if display_id == 0 or display_id in orientation_pair_displays:
                raise AndroidAuthorityError(
                    "ActivityManager per-display orientation pair is ambiguous")

            last_match = re.fullmatch(
                display_area_pattern.format(
                    label="mLastOrientationSource"),
                supervisor_lines[last_index])
            deepest_match = re.fullmatch(
                display_area_pattern.format(
                    label="deepestLastOrientationSource"),
                supervisor_lines[deepest_index])
            last_activity = re.fullmatch(
                r"^  mLastOrientationSource=(" + activity_identity + r")$",
                supervisor_lines[last_index])
            deepest_activity = re.fullmatch(
                r"^  deepestLastOrientationSource=(" + activity_identity +
                r")$", supervisor_lines[deepest_index])
            if last_match is not None and deepest_match is not None:
                last_identity = _bounded_int(
                    last_match.group(1),
                    "per-display last orientation display-area identity",
                    0, 2_147_483_647)
                deepest_identity = _bounded_int(
                    deepest_match.group(1),
                    "per-display deepest orientation display-area identity",
                    0, 2_147_483_647)
                if last_identity != deepest_identity:
                    raise AndroidAuthorityError(
                        "ActivityManager per-display orientation identities disagree")
                if last_identity in orientation_pair_identities:
                    raise AndroidAuthorityError(
                        "ActivityManager per-display orientation identity is reused")
                orientation_pair_identities.add(last_identity)
            elif last_activity is not None and deepest_activity is not None:
                last_identity_text = last_activity.group(1)
                deepest_identity_text = deepest_activity.group(1)
                if last_identity_text != deepest_identity_text:
                    raise AndroidAuthorityError(
                        "ActivityManager per-display orientation activities disagree")
                locations = canonical_activity_displays.get(
                    last_identity_text, [])
                all_locations = all_activity_displays.get(
                    last_identity_text, [])
                activity_fields = re.fullmatch(
                    r"ActivityRecord\{([0-9a-f]+) u0 [^\s{}]+ "
                    r"t[1-9][0-9]{0,9}\}", last_identity_text)
                if activity_fields is None:  # Defensive: same strict grammar.
                    raise AndroidAuthorityError(
                        "ActivityManager per-display orientation activity differs")
                token_occurrences = activity_token_occurrences.get(
                    activity_fields.group(1), [])
                if (locations != [display_id] or
                        all_locations != [display_id] or
                        token_occurrences != [(last_identity_text, display_id)]):
                    raise AndroidAuthorityError(
                        "ActivityManager per-display orientation activity is unbound")
                if last_identity_text in orientation_pair_activities:
                    raise AndroidAuthorityError(
                        "ActivityManager per-display orientation activity is reused")
                orientation_pair_activities.add(last_identity_text)
            else:
                raise AndroidAuthorityError(
                    "ActivityManager per-display orientation sources differ")
            orientation_pair_displays.add(display_id)
    elif boundary_index is not None:
        raise AndroidAuthorityError("ActivityManager supervisor section is empty")
    else:
        orientation_pair_displays = set()

    supervisor_task = re.compile(r"^ {6}(?: {2})*\* Task\{[^\n]*\}$")
    supervisor_activity = re.compile(
        r"^ {8}(?: {2})*\* ActivityRecord\{[^\n]*\}$")
    for line in supervisor_lines:
        if re.match(r"^\s*Display\b", line, re.IGNORECASE):
            if display_summary.fullmatch(line) is None:
                raise AndroidAuthorityError(
                    "ActivityManager supervisor display record is malformed")
        if re.match(r"^\s*Stack\b", line, re.IGNORECASE):
            raise AndroidAuthorityError(
                "ActivityManager canonical stack follows supervisor boundary")
        if re.match(r"^\s*\*+\s*Task\b", line, re.IGNORECASE):
            if supervisor_task.fullmatch(line) is None:
                raise AndroidAuthorityError(
                    "ActivityManager supervisor task indentation is malformed")
        if re.match(r"^\s*\*+\s*ActivityRecord\b", line, re.IGNORECASE):
            if supervisor_activity.fullmatch(line) is None:
                raise AndroidAuthorityError(
                    "ActivityManager supervisor activity indentation is malformed")
        if (re.match(r"^\s*\*+\s*Hist\b", line, re.IGNORECASE) or
                re.match(r"^\s*mResumedActivity\b", line, re.IGNORECASE)):
            raise AndroidAuthorityError(
                "ActivityManager canonical record follows supervisor boundary")

    # Cross-check the redundant display summaries without permitting them to
    # contribute any task, activity, or target-component authority.
    summaries: list[tuple[int, int, int]] = []
    for index, line in enumerate(supervisor_lines):
        match = display_summary.fullmatch(line)
        if match is not None:
            summaries.append((
                index,
                _bounded_int(match.group(1), "display summary ID", 0, 1024),
                _bounded_int(
                    match.group(2), "display summary stack count", 0, 10_000_000),
            ))
    if boundary_index is not None:
        if not summaries:
            raise AndroidAuthorityError(
                "ActivityManager supervisor display summaries are absent")
        header_records: list[tuple[int, int]] = []
        for index in display_headers:
            match = display_header.fullmatch(authority_lines[index])
            if match is None:  # Defensive: display_headers came from this regex.
                raise AndroidAuthorityError(
                    "ActivityManager display authority is inconsistent")
            header_records.append((
                index,
                _bounded_int(match.group(1), "display ID", 0, 1024),
            ))
        header_ids = [display_id for _, display_id in header_records]
        summary_ids = [display_id for _, display_id, _ in summaries]
        if (len(set(header_ids)) != len(header_ids) or
                len(set(summary_ids)) != len(summary_ids) or
                summary_ids != header_ids):
            raise AndroidAuthorityError(
                "ActivityManager display summaries disagree with display sections")
        if not orientation_pair_displays.issubset(set(header_ids)):
            raise AndroidAuthorityError(
                "ActivityManager per-display orientation authority is unbound")

        expected_counts: dict[int, int] = {}
        for record_index, (start, display_id) in enumerate(header_records):
            end = (header_records[record_index + 1][0]
                   if record_index + 1 < len(header_records)
                   else len(authority_lines))
            expected_counts[display_id] = sum(
                re.fullmatch(r"^  Stack #[0-9]+:[^\n]*$", line) is not None
                for line in authority_lines[start + 1:end]
            )
        if any(expected_counts[display_id] != stack_count
               for _, display_id, stack_count in summaries):
            raise AndroidAuthorityError(
                "ActivityManager display summary stack count disagrees")

    structural = (
        (r"^\s*Stack\b", r"^  Stack #[0-9]+:[^\n]*$"),
        (r"^\s*\*+\s*Task\b", r"^    \* Task\{[^\n]*\}$"),
        (r"^\s*\*+\s*Hist\b",
         r"^      \* Hist #[0-9]+: ActivityRecord\{[^\n]*\}$"),
        (r"^\s*mResumedActivity\b",
         r"^    mResumedActivity: (?:ActivityRecord\{[^\n]*\}|null)$"),
    )
    for line in authority_lines:
        for header_like, admitted in structural:
            if (re.match(header_like, line, re.IGNORECASE) and
                    re.fullmatch(admitted, line) is None):
                raise AndroidAuthorityError("ActivityManager structural header is malformed")

    return "\n".join(authority_lines) + "\n"


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
    text = _reject_malformed_structural_headers(text)
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
