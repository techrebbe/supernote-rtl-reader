"""Host-only diagnosis of the Nomad's stock DocumentActivity display-0 dialect.

On the observed firmware, ActivityManager reports a RESUMED, drawn, visible
DocumentActivity while its task and topDisplayFocusedStack say visible=false.
WindowManager separately reports the stock window on-screen and visible.  This
module checks that *specific disagreement* in supplied before/after raw bytes.

It performs no I/O.  Its result is not a Frida, pen, task, or mutation permit:
raw-capture provenance, process start time, document identity, and unsaved ink
are outside this contract.  Test fixtures are synthetic mirrors of redacted
observations, not retained device dumps.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any

import native_page_android_authority as android
import native_page_graph_v2_runner as graph


AUTHORITY = "rtl-reader-native-page-display0-stock-dialect-diagnostic-v1"
SCHEMA_VERSION = 1
MAX_WINDOW_BYTES = 2_097_152
TOKEN = r"[0-9a-f]{1,16}"
COMPONENTS = frozenset((android.SHORT_COMPONENT, android.FULL_COMPONENT))


class StockDialectError(ValueError):
    """Stock task/window evidence is incomplete, contradictory, or ambiguous."""


@dataclass(frozen=True)
class StockDialectResult:
    raw: bytes
    sha256: str

    def value(self) -> dict[str, Any]:
        return graph.load_canonical(self.raw, graph.MAX_AUTHORITY_BYTES).value


@dataclass(frozen=True)
class _Observation:
    task: android.DocumentTaskAuthority
    activity_sha256: str
    window_sha256: str
    window_token: str
    session_token: str


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise StockDialectError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _window_text(raw: bytes) -> str:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_WINDOW_BYTES and b"\x00" not in raw,
          "WindowManager bytes are absent, oversized, or contain NUL")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise StockDialectError("WindowManager bytes are not UTF-8") from error
    _need(text.endswith("\n") and ("\r" not in text or
          text.count("\r") == text.count("\r\n") == text.count("\n")),
          "WindowManager line endings differ")
    text = text.replace("\r\n", "\n")
    _need(all(character in ("\n", "\t") or ord(character) >= 0x20
              for character in text) and
          not any(character in text for character in ("\x7f", "\x85", "\u2028", "\u2029")) and
          all(len(line) <= 65_536 for line in text.split("\n")),
          "WindowManager contains controls or an oversized line")
    _need(text.startswith("WINDOW MANAGER WINDOWS (dumpsys window windows)\n"),
          "WindowManager full-output header differs")
    return text


def _one(pattern: str, text: str, label: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    _need(len(matches) == 1, label + " is absent or ambiguous")
    return matches[0]


def _task(raw: bytes, expected_pid: int) -> android.DocumentTaskAuthority:
    try:
        task = android.parse_document_task_authority(
            raw, expected_pid=expected_pid, require_live=False)
    except android.AndroidAuthorityError as error:
        raise StockDialectError("one stock DocumentActivity task is not established") from error
    _need(task.display_id == 0 and task.uid == android.SYSTEM_UID and
          task.package_name == android.PACKAGE and task.process_name == android.PROCESS and
          task.component in COMPONENTS and task.state == "RESUMED" and task.resumed and
          not task.stopped and not task.delayed_resume and not task.finishing and
          not task.task_visible and task.visible_requested and task.visible and
          task.client_visible and task.reported_drawn and task.reported_visible and
          task.now_visible,
          "observed stock task/activity visibility dialect differs")
    return task


def _supervisor_focus(raw: bytes, task: android.DocumentTaskAuthority) -> str:
    # The Android task parser has already checked the full wire, structural
    # boundaries, unique target Hist record, and the task's exact owner fields.
    text = raw.decode("utf-8", "strict").replace("\r\n", "\n")
    boundary = "ActivityStackSupervisor state:\n"
    _need(text.count(boundary) == 1, "ActivityManager supervisor is absent or ambiguous")
    supervisor = text.split(boundary, 1)[1]
    top_like = re.findall(r"^[ \t]*topDisplayFocusedStack\b[^\n]*$", supervisor,
                          re.MULTILINE)
    _need(len(top_like) == 1, "top focused task marker is absent or ambiguous")
    expected_top = (
        r"  topDisplayFocusedStack=Task\{" + re.escape(task.task_token) +
        r" #" + str(task.task_id) +
        r" visible=false type=standard mode=fullscreen translucent=true A=" +
        str(task.uid) + r":" + re.escape(android.PACKAGE) +
        r" U=0 StackId=" + str(task.stack_id) + r" sz=1\}"
    )
    _need(re.fullmatch(expected_top, top_like[0]) is not None,
          "top focused stock task identity or visibility differs")

    summaries = list(re.finditer(
        r"^  Display: mDisplayId=(0|[1-9][0-9]{0,9}) stacks=(0|[1-9][0-9]{0,9})$",
        supervisor, re.MULTILINE))
    summary_like = re.findall(r"^[ \t]*Display:[^\n]*$", supervisor, re.MULTILINE)
    _need(len(summaries) == len(summary_like) and summaries and
          len({item.group(1) for item in summaries}) == len(summaries),
          "supervisor display summaries differ")
    primary = [index for index, item in enumerate(summaries) if item.group(1) == "0"]
    _need(len(primary) == 1, "one physical-display summary is required")
    index = primary[0]
    _need(not re.search(r"^[ \t]*m(?:CurrentFocus|FocusedApp)",
                        supervisor[:summaries[0].start()], re.MULTILINE),
          "focus/app claim precedes all display summaries")
    end = summaries[index + 1].start() if index + 1 < len(summaries) else len(supervisor)
    segment = supervisor[summaries[index].end():end]
    focus_like = re.findall(r"^[ \t]*mCurrentFocus\b[^\n]*$", segment, re.MULTILINE)
    app_like = re.findall(r"^[ \t]*mFocusedApp\b[^\n]*$", segment, re.MULTILINE)
    structural_focus = re.findall(r"^[ \t]*m(?:CurrentFocus|FocusedApp)[^\n]*$",
                                  segment, re.MULTILINE)
    _need(len(focus_like) == len(app_like) == 1 and len(structural_focus) == 2,
          "physical-display focus/app pair is absent or ambiguous")
    focus = re.fullmatch(r"  mCurrentFocus=Window\{(" + TOKEN + r") u0 ([^\s}]+)\}",
                         focus_like[0])
    app = re.fullmatch(r"  mFocusedApp=ActivityRecord\{(" + TOKEN +
                       r") u0 ([^\s}]+) t(0|[1-9][0-9]{0,9})\}", app_like[0])
    _need(focus is not None and app is not None,
          "physical-display focus/app grammar differs")
    assert focus is not None and app is not None
    _need(focus.group(2) == android.FULL_COMPONENT and
          app.group(1) == task.activity_token and app.group(2) in COMPONENTS and
          int(app.group(3)) == task.task_id,
          "physical-display focus/app is not the parsed stock activity")
    for other_index, summary in enumerate(summaries):
        if other_index == index:
            continue
        other_end = (summaries[other_index + 1].start()
                     if other_index + 1 < len(summaries) else len(supervisor))
        other = supervisor[summary.end():other_end]
        _need(not any(android.PACKAGE in line and
                      ("mCurrentFocus" in line or "mFocusedApp" in line)
                      for line in other.splitlines()),
              "another display also claims stock focus")
    return focus.group(1)


def _window(raw: bytes, task: android.DocumentTaskAuthority,
            focus_token: str) -> str:
    text = _window_text(raw)
    header_pattern = (r"^[ \t]*Window #[0-9]+ Window\{(" + TOKEN +
                      r") u0 ([^\s}]+)\}:$")
    headers = list(re.finditer(header_pattern, text, re.MULTILINE))
    stock = [item for item in headers if item.group(2).startswith(android.PACKAGE + "/")]
    _need(len(stock) == 1 and stock[0].group(1) == focus_token and
          stock[0].group(2) == android.FULL_COMPONENT,
          "one focused stock WindowManager header is not established")
    selected = stock[0]
    stock_header_like = [line for line in text.splitlines()
                         if re.match(r"^[ \t]*Window\b", line) and android.PACKAGE in line]
    _need(stock_header_like == [selected.group(0)],
          "malformed or alternate stock WindowManager header")
    next_header = next((item for item in headers if item.start() > selected.start()), None)
    block = text[selected.end():next_header.start() if next_header else len(text)]
    for key in ("mDisplayId", "rootTaskId", "mSession", "mToken",
                "mActivityRecord", "mHasSurface", "isReadyForDisplay",
                "mWindowRemovalAllowed", "isOnScreen", "isVisible"):
        _need(len(re.findall(r"(?<!\S)" + re.escape(key), block)) == 1,
              "stock window " + key + " is absent or ambiguous")
    session = _one(
        r"^[ \t]*mDisplayId=0 rootTaskId=" + str(task.task_id) +
        r" mSession=Session\{(" + TOKEN + r") " + str(task.pid) +
        r":" + str(task.uid) +
        r"\} mClient=android\.os\.BinderProxy@" + TOKEN + r"$",
        block, "stock window display/task/session")
    activity = (r"ActivityRecord\{" + re.escape(task.activity_token) +
                r" u0 (?:(?:" + re.escape(android.SHORT_COMPONENT) + r")|(?:" +
                re.escape(android.FULL_COMPONENT) + r")) t" +
                str(task.task_id) + r"\}")
    _one(r"^[ \t]*mBaseLayer=[0-9]+ mSubLayer=-?[0-9]+[ \t]+mToken=" +
         activity + r"$", block, "stock window activity token")
    _one(r"^[ \t]*mActivityRecord=" + activity + r"$", block,
         "stock window activity record")
    for label, pattern in (
        ("surface", r"^[ \t]*mHasSurface=true isReadyForDisplay\(\)=true "
                    r"mWindowRemovalAllowed=false$"),
        ("on-screen", r"^[ \t]*isOnScreen=true$"),
        ("visible", r"^[ \t]*isVisible=true$"),
    ):
        _one(pattern, block, "stock window " + label)
    owner_lines = re.findall(r"^[ \t]*mOwnerUid[^\n]*$", block, re.MULTILINE)
    _need(len(owner_lines) <= 1, "stock window owner UID is ambiguous")
    if owner_lines:
        _need(re.match(r"^[ \t]*mOwnerUid=" + str(task.uid) + r"(?:[ \t]|$)",
                       owner_lines[0]) is not None and
              len(re.findall(r"(?<!\S)package=", owner_lines[0])) == 1 and
              re.search(r"(?<!\S)package=" + re.escape(android.PACKAGE) +
                        r"(?=\s|$)", owner_lines[0]) is not None,
              "stock window owner UID/package differs")
    # Reject alternate or truncated stock window/activity references, even in
    # ancillary WindowManager fields outside the selected window block.
    expected_window = (r"Window\{" + re.escape(focus_token) + r" u0 " +
                       re.escape(android.FULL_COMPONENT) + r"\}")
    expected_activity = (r"ActivityRecord\{" + re.escape(task.activity_token) +
                         r" u0 (?:" + "|".join(re.escape(item) for item in sorted(COMPONENTS)) +
                         r") t" + str(task.task_id) + r"\}")
    for line in text.splitlines():
        if android.PACKAGE not in line:
            continue
        for kind, pattern in (("Window", expected_window),
                              ("ActivityRecord", expected_activity)):
            starts = [item.start() for item in re.finditer(re.escape(kind + "{"), line)]
            if not starts:
                continue
            matches = list(re.finditer(kind + r"\{[^\n{}]*\}", line))
            _need(starts == [item.start() for item in matches] and
                  all(re.fullmatch(pattern, item.group(0)) is not None
                      for item in matches if android.PACKAGE in item.group(0)),
                  "alternate or malformed stock " + kind + " identity")
    return session.group(1)


def _observe(activity_raw: bytes, window_raw: bytes,
             expected_pid: int) -> _Observation:
    task = _task(activity_raw, expected_pid)
    focus_token = _supervisor_focus(activity_raw, task)
    session_token = _window(window_raw, task, focus_token)
    return _Observation(task, _sha(activity_raw), _sha(window_raw),
                        focus_token, session_token)


def validate_stock_dialect(before_activity_raw: bytes, before_window_raw: bytes,
                           after_activity_raw: bytes, after_window_raw: bytes,
                           *, expected_pid: int) -> StockDialectResult:
    """Check two supplied snapshots; never authorize attach or device actions."""
    _need(type(expected_pid) is int and 1 <= expected_pid <= android.MAX_PID,
          "expected PID differs")
    before = _observe(before_activity_raw, before_window_raw, expected_pid)
    after = _observe(after_activity_raw, after_window_raw, expected_pid)
    try:
        stable_task = android.stable_authority(before.task, after.task)
    except android.AndroidAuthorityError as error:
        raise StockDialectError("task before/after authority is malformed") from error
    _need(stable_task and before.window_token == after.window_token and
          before.session_token == after.session_token,
          "stock task/window identity changed between supplied snapshots")
    record = {
        "schemaVersion": SCHEMA_VERSION,
        "authority": AUTHORITY,
        "displayId": 0,
        "taskId": before.task.task_id,
        "taskToken": before.task.task_token,
        "activityToken": before.task.activity_token,
        "windowToken": before.window_token,
        "windowSessionToken": before.session_token,
        "pid": before.task.pid,
        "uid": before.task.uid,
        "component": android.FULL_COMPONENT,
        "beforeActivitySha256": before.activity_sha256,
        "beforeWindowSha256": before.window_sha256,
        "afterActivitySha256": after.activity_sha256,
        "afterWindowSha256": after.window_sha256,
        "taskVisible": False,
        "activityVisible": True,
        "windowVisible": True,
        "focusShapeParsed": True,
        "rawCaptureProvenanceVerified": False,
        "processStartTimeVerified": False,
        "documentIdentityVerified": False,
        "hardwareAdmission": False,
        "mutationCommandsAuthorized": False,
    }
    try:
        raw = graph.canonical_bytes(record, graph.MAX_AUTHORITY_BYTES)
    except graph.GraphRunnerError as error:
        raise StockDialectError("stock diagnostic record is not canonical") from error
    return StockDialectResult(raw, _sha(raw))
