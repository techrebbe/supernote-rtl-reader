"""Preparatory, host-only focus witness for a stock DocumentActivity on display 0.

The known WindowManager grammar was retained for the diagnostic host, not for
the stock reader. This parser applies that narrow grammar to supplied stock
bytes and never promotes a match to hardware/Frida admission. It performs no
device I/O or task, display, window, input, or process operation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any

import native_page_android_authority as android
import native_page_graph_v2_runner as graph


SCHEMA_VERSION = 1
AUTHORITY = "rtl-reader-native-page-display0-focus-preflight-v1"
MAX_WINDOW_BYTES = 2_097_152
COMPONENTS = frozenset((android.SHORT_COMPONENT, android.FULL_COMPONENT))
TOKEN = r"[0-9a-f]{1,16}"


class FocusError(ValueError):
    """A focused stock window is absent, ambiguous, or not bound to the task."""


@dataclass(frozen=True)
class FocusResult:
    raw: bytes
    sha256: str

    def value(self) -> dict[str, Any]:
        return graph.load_canonical(self.raw, graph.MAX_AUTHORITY_BYTES).value


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FocusError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _wire(raw: bytes, label: str, limit: int) -> str:
    _need(type(raw) is bytes and 0 < len(raw) <= limit and b"\x00" not in raw,
          label + " bytes are absent, oversized, or contain NUL")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise FocusError(label + " is not UTF-8") from error
    _need(text.endswith("\n") and ("\r" not in text or
          text.count("\r") == text.count("\r\n") == text.count("\n")),
          label + " line endings differ")
    text = text.replace("\r\n", "\n")
    _need(all(character == "\n" or character == "\t" or ord(character) >= 0x20
              for character in text) and not any(character in text for character in
              ("\x7f", "\x85", "\u2028", "\u2029")),
          label + " contains control characters")
    _need(all(len(line) <= 65_536 for line in text.split("\n")),
          label + " line is oversized")
    return text


def _one(pattern: str, text: str, label: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    _need(len(matches) == 1, label + " is absent or ambiguous")
    return matches[0]


def _component(value: str, label: str) -> None:
    _need(value in COMPONENTS, label + " is not the stock DocumentActivity")


def _supervisor_focus(text: str, task: android.DocumentTaskAuthority) -> tuple[str, str]:
    _need(text.count("ActivityStackSupervisor state:") == 1,
          "ActivityManager supervisor boundary is absent or ambiguous")
    supervisor = text.split("ActivityStackSupervisor state:", 1)[1]
    _need(supervisor.count("topDisplayFocusedStack") == 1,
          "top focused task marker is absent or ambiguous")
    summaries = list(re.finditer(
        r"^  Display: mDisplayId=(0|[1-9][0-9]{0,9}) stacks=(0|[1-9][0-9]{0,9})$",
        supervisor, re.MULTILINE))
    summary_like = re.findall(r"^[ \t]*Display\b.*$", supervisor, re.MULTILINE)
    _need(len(summary_like) == len(summaries) and
          all(item.group(0) in summary_like for item in summaries),
          "malformed supervisor display summary")
    _need(summaries and len({item.group(1) for item in summaries}) == len(summaries),
          "supervisor display summaries are absent or duplicated")
    display_zero = [index for index, item in enumerate(summaries) if item.group(1) == "0"]
    _need(len(display_zero) == 1, "physical display 0 summary is absent")
    index = display_zero[0]
    end = summaries[index + 1].start() if index + 1 < len(summaries) else len(supervisor)
    segment = supervisor[summaries[index].end():end]
    focus_lines = re.findall(r"^[ \t]*mCurrentFocus=.*$", segment, re.MULTILINE)
    app_lines = re.findall(r"^[ \t]*mFocusedApp=.*$", segment, re.MULTILINE)
    structural_focus = re.findall(r"^[ \t]*m(?:CurrentFocus|FocusedApp)\b.*$",
                                  segment, re.MULTILINE)
    _need(len(focus_lines) == len(app_lines) == 1 and len(structural_focus) == 2,
          "physical display focus/app line is absent or ambiguous")
    focus = re.fullmatch(r"  mCurrentFocus=Window\{(" + TOKEN + r") u0 ([^\s}]+)\}",
                         focus_lines[0])
    app = re.fullmatch(r"  mFocusedApp=ActivityRecord\{(" + TOKEN +
                       r") u0 ([^\s}]+) t(0|[1-9][0-9]{0,9})\}", app_lines[0])
    _need(focus is not None and app is not None, "focus/app record dialect differs")
    assert focus is not None and app is not None
    _component(focus.group(2), "focused window component")
    _component(app.group(2), "focused app component")
    _need(app.group(1) == task.activity_token and int(app.group(3)) == task.task_id,
          "focused app is not the previously parsed activity")
    # A target-package focus line on another display cannot be borrowed by 0.
    for other_index, summary in enumerate(summaries):
        if other_index == index:
            continue
        other_end = (summaries[other_index + 1].start()
                     if other_index + 1 < len(summaries) else len(supervisor))
        other = supervisor[summary.end():other_end]
        _need(not any(android.PACKAGE in line and
                      ("mCurrentFocus" in line or "mFocusedApp" in line)
                      for line in other.splitlines()),
            "stock focus appears on another display")
    top = _one(r"^  topDisplayFocusedStack=Task\{" + re.escape(task.task_token) +
               r" #" + str(task.task_id) + r" visible=true\b[^\n}]*\bA=" +
               str(task.uid) + r":" + re.escape(android.PACKAGE) +
               r" U=0 StackId=" + str(task.stack_id) + r"(?:\s|\})[^\n}]*\}$",
               supervisor, "top focused stock task")
    _need(all(len(re.findall(r"\b" + key + r"=", top.group(0))) == 1
              for key in ("A", "U", "StackId")),
          "top focused task owner fields are ambiguous")
    return focus.group(1), focus.group(2)


def _window(text: str, task: android.DocumentTaskAuthority,
            focus_token: str, focus_component: str) -> str:
    _need(text.startswith("WINDOW MANAGER WINDOWS\n"),
          "WindowManager full-output header is absent")
    _need(re.search(r"^\s*m(?:CurrentFocus|FocusedApp)=", text, re.MULTILINE) is None,
          "unexpected WindowManager focus dialect requires review")
    headers = list(re.finditer(
        r"^\s*Window #[0-9]+ Window\{(" + TOKEN + r") u0 ([^\s}]+)\}:?$",
        text, re.MULTILINE))
    stock = [item for item in headers if item.group(2).startswith(android.PACKAGE + "/")]
    _need(len(stock) == 1 and stock[0].group(1) == focus_token and
          stock[0].group(2) == focus_component,
          "one focused stock window header is not established")
    selected = stock[0]
    stock_header_like = [line for line in text.splitlines()
                         if re.match(r"^\s*Window\b", line) and android.PACKAGE in line]
    _need(stock_header_like == [selected.group(0)],
          "malformed or alternate stock window header")
    _component(selected.group(2), "stock window header component")
    next_header = next((item for item in headers if item.start() > selected.start()), None)
    block = text[selected.end():next_header.start() if next_header else len(text)]
    for prefix in ("mDisplayId=", "mToken=", "mActivityRecord=", "mHasSurface=",
                   "isOnScreen=", "isVisible="):
        _need(len(re.findall(r"(?<!\S)" + re.escape(prefix), block)) == 1,
              "window " + prefix + " line is absent or ambiguous")
    session = _one(
        r"^\s*mDisplayId=0 rootTaskId=" + str(task.task_id) +
        r" mSession=Session\{(" + TOKEN + r") " + str(task.pid) +
        r":u0a" + str(task.uid) +
        r"\} mClient=android\.os\.BinderProxy@" + TOKEN + r"$",
        block, "window display/task/session owner")
    activity = (r"ActivityRecord\{" + re.escape(task.activity_token) +
                r" u0 ([^\s}]+) t" + str(task.task_id) + r"\}")
    token = _one(r"^\s*mBaseLayer=[0-9]+ mSubLayer=-?[0-9]+\s+"
                 r"mToken=" + activity + r"$", block, "window activity token")
    record = _one(r"^\s*mActivityRecord=" + activity + r"$",
                  block, "window activity record")
    _component(token.group(1), "window activity-token component")
    _component(record.group(1), "window activity-record component")
    _need(token.group(1) == record.group(1),
          "window activity-token component spelling changed")
    for label, pattern in (
        ("live surface", r"^\s*mHasSurface=true isReadyForDisplay\(\)=true mWindowRemovalAllowed=false$"),
        ("on-screen state", r"^\s*isOnScreen=true$"),
        ("visible state", r"^\s*isVisible=true$"),
    ):
        _one(pattern, block, label)
    # Do not let a malformed or alternate stock identity hide outside the
    # selected header or in a repeated Window/ActivityRecord reference.
    for kind, expression, admitted in (
        ("Window", r"Window\{[^\n{}]*\}",
         r"Window\{" + re.escape(focus_token) + r" u0 " +
         re.escape(focus_component) + r"\}"),
        ("ActivityRecord", r"ActivityRecord\{[^\n{}]*\}",
         r"ActivityRecord\{" + re.escape(task.activity_token) +
         r" u0 (?:" + "|".join(re.escape(item) for item in sorted(COMPONENTS)) +
         r") t" + str(task.task_id) + r"\}"),
    ):
        for line in text.splitlines():
            if android.PACKAGE not in line or kind + "{" not in line:
                continue
            starts = list(re.finditer(re.escape(kind + "{"), line))
            matches = list(re.finditer(expression, line))
            _need([item.start() for item in starts] == [item.start() for item in matches],
                  "malformed stock " + kind + " structural residue")
            for item in matches:
                if android.PACKAGE in item.group(0):
                    _need(re.fullmatch(admitted, item.group(0)) is not None,
                          "alternate stock " + kind + " identity")
    return session.group(1)


def validate_focus(task: android.DocumentTaskAuthority,
                   activity_raw: bytes, window_raw: bytes) -> FocusResult:
    """Bind parsed task and focus-shaped raw evidence, without authorizing attach."""
    _need(type(task) is android.DocumentTaskAuthority and
          tuple(android.DocumentTaskAuthority.__dataclass_fields__) ==
          tuple(type(task).__dataclass_fields__), "exact parsed task wrapper required")
    activity_text = _wire(activity_raw, "ActivityManager", android.MAX_DUMPSYS_BYTES)
    window_text = _wire(window_raw, "WindowManager", MAX_WINDOW_BYTES)
    try:
        reparsed = android.parse_document_task_authority(activity_raw,
                                                         expected_pid=task.pid, require_live=True)
    except android.AndroidAuthorityError as error:
        raise FocusError("task raw evidence is not one live stock activity") from error
    _need(task.canonical_bytes() == reparsed.canonical_bytes() and
          task.raw_sha256 == _sha(activity_raw) and task.display_id == 0,
          "supplied task is not exactly the display-0 raw capture")
    focus_token, focus_component = _supervisor_focus(activity_text, task)
    session_token = _window(window_text, task, focus_token, focus_component)
    record = {
        "schemaVersion": SCHEMA_VERSION, "authority": AUTHORITY,
        "taskAuthoritySha256": _sha(task.canonical_bytes()),
        "activityRawSha256": _sha(activity_raw), "windowRawSha256": _sha(window_raw),
        "taskId": task.task_id, "taskToken": task.task_token,
        "activityToken": task.activity_token, "windowToken": focus_token,
        "windowSessionToken": session_token, "displayId": 0,
        "pid": task.pid, "uid": task.uid, "component": android.FULL_COMPONENT,
        "focusShapeParsed": True, "hardwareAdmission": False,
        "stockWindowDialectHardwarePinned": False,
        "mutationCommandsAuthorized": False,
    }
    try:
        raw = graph.canonical_bytes(record, graph.MAX_AUTHORITY_BYTES)
    except graph.GraphRunnerError as error:
        raise FocusError("focus record is not canonical") from error
    return FocusResult(raw, _sha(raw))
