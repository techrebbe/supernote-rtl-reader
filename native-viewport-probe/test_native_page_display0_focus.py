"""Offline positive/adversarial checks for preparatory display-0 focus parsing."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest

import native_page_android_authority as android
import native_page_display0_focus as focus
from test_native_page_android_authority import PID, wire as task_wire


WINDOW_TOKEN = "f5d3f4a"
SESSION_TOKEN = "39e379f"


def activities() -> bytes:
    return task_wire() + (
        "ActivityStackSupervisor state:\n"
        "  topDisplayFocusedStack=Task{66d8263 #4538 visible=true type=standard "
        "mode=fullscreen A=1000:com.supernote.document U=0 StackId=4538 sz=1}\n"
        "  mLastOrientationSource=ActivityRecord{11846f4 u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
        "  deepestLastOrientationSource=ActivityRecord{11846f4 u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
        "  Display: mDisplayId=0 stacks=1\n"
        "  mCurrentFocus=Window{f5d3f4a u0 " + android.FULL_COMPONENT + "}\n"
        "  mFocusedApp=ActivityRecord{11846f4 u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
    ).encode("ascii")


def windows() -> bytes:
    return (
        "WINDOW MANAGER WINDOWS\n"
        "  Window #5 Window{f5d3f4a u0 " + android.FULL_COMPONENT + "}:\n"
        f"    mDisplayId=0 rootTaskId=4538 mSession=Session{{{SESSION_TOKEN} {PID}:u0a1000}} "
        "mClient=android.os.BinderProxy@dd48cb5\n"
        "    mBaseLayer=21000 mSubLayer=0    mToken=ActivityRecord{11846f4 u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
        "    mActivityRecord=ActivityRecord{11846f4 u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
        "    mHasSurface=true isReadyForDisplay()=true mWindowRemovalAllowed=false\n"
        "    isOnScreen=true\n"
        "    isVisible=true\n"
    ).encode("ascii")


def parsed_task(raw: bytes | None = None) -> android.DocumentTaskAuthority:
    return android.parse_document_task_authority(raw if raw is not None else activities(),
                                                 expected_pid=PID)


class FocusPreflightTests(unittest.TestCase):
    def reject(self, *, task=None, activity=None, window=None):
        raw_activity = activities() if activity is None else activity
        with self.assertRaises(focus.FocusError):
            focus.validate_focus(parsed_task() if task is None else task,
                                 raw_activity, windows() if window is None else window)

    def test_one_display_zero_stock_window_is_bound_but_not_hardware_admitted(self):
        result = focus.validate_focus(parsed_task(), activities(), windows())
        value = result.value()
        self.assertEqual(result.sha256, hashlib.sha256(result.raw).hexdigest())
        self.assertEqual(value["authority"], focus.AUTHORITY)
        self.assertEqual(value["taskId"], 4538)
        self.assertEqual(value["taskToken"], "66d8263")
        self.assertEqual(value["activityToken"], "11846f4")
        self.assertEqual(value["windowToken"], WINDOW_TOKEN)
        self.assertEqual(value["windowSessionToken"], SESSION_TOKEN)
        self.assertEqual((value["pid"], value["uid"], value["displayId"]), (PID, 1000, 0))
        self.assertTrue(value["focusShapeParsed"])
        self.assertFalse(value["hardwareAdmission"])
        self.assertFalse(value["stockWindowDialectHardwarePinned"])
        self.assertFalse(value["mutationCommandsAuthorized"])

    def test_task_wrapper_and_raw_digest_must_be_exactly_reparsed(self):
        self.reject(task=replace(parsed_task(), activity_token="badcafe"))
        self.reject(task=replace(parsed_task(), raw_sha256="0" * 64))
        self.reject(task=replace(parsed_task(), display_id=1))
        self.reject(task={"task_id": 4538})
        self.reject(activity=activities().replace(b"visible=true", b"visible=false", 1))

    def test_focus_pair_is_display_scoped_and_doubly_bound(self):
        base = activities()
        focus_line = ("  mCurrentFocus=Window{f5d3f4a u0 " +
                      android.FULL_COMPONENT + "}\n").encode("ascii")
        app_line = ("  mFocusedApp=ActivityRecord{11846f4 u0 " +
                    android.SHORT_COMPONENT + " t4538}\n").encode("ascii")
        cases = (
            base.replace(focus_line, focus_line.replace(b"f5d3f4a", b"badcafe"), 1),
            base.replace(app_line, app_line.replace(b"11846f4", b"badcafe"), 1),
            base.replace(app_line, app_line.replace(b"t4538", b"t4539"), 1),
            base.replace(focus_line, focus_line.replace(android.FULL_COMPONENT.encode(),
                                                        b"com.supernote.document/.OtherActivity"), 1),
            base.replace(focus_line, b"  mCurrentFocus=null\n", 1),
            base.replace(app_line, b"  mFocusedApp=null\n", 1),
            base.replace(focus_line, b"", 1),
            base.replace(app_line, b"", 1),
            base.replace(focus_line, focus_line + focus_line, 1),
            base.replace(app_line, app_line + app_line, 1),
            base.replace(focus_line, focus_line + b"    mCurrentFocus=null\n", 1),
            base.replace(focus_line, focus_line + b"   mCurrentFocus Window{badcafe}\n", 1),
            base.replace(b"  Display: mDisplayId=0 stacks=1\n",
                         b"  Display: mDisplayId=0 stacks=1\n"
                         b"  Display: mDisplayId=0 stacks=1\n", 1),
            base.replace(b"  Display: mDisplayId=0 stacks=1\n",
                         b"  Display: mDisplayId=0 stacks=1\n"
                         b"   Display: mDisplayId=0 stacks=1\n", 1),
            base.replace(b"  Display: mDisplayId=0 stacks=1\n",
                         b"  Display: mDisplayId=0 stacks=1\n"
                         b"  Display: mDisplayId=00 stacks=1\n", 1),
            base.replace(b"  Display: mDisplayId=0 stacks=1", b"  Display: mDisplayId=1 stacks=1", 1),
            base.replace(b"  topDisplayFocusedStack=Task{66d8263", b"  topDisplayFocusedStack=Task{badcafe", 1),
            base.replace(b"A=1000:com.supernote.document U=0 StackId=4538 sz=1",
                         b"A=1000:com.supernote.document U=1 StackId=9999 sz=1", 1),
            base.replace(b"A=1000:com.supernote.document U=0 StackId=4538 sz=1",
                         b"A=1000:com.supernote.document U=0 StackId=4538 U=1 sz=1", 1),
            base.replace(b"  topDisplayFocusedStack=Task{66d8263",
                         b"  topDisplayFocusedStack=bad\n  topDisplayFocusedStack=Task{66d8263", 1),
            base.replace(b"  topDisplayFocusedStack=Task{66d8263",
                         b"  topDisplayFocusedStack[bad]\n  topDisplayFocusedStack=Task{66d8263", 1),
            base + ("  Display: mDisplayId=1 stacks=1\n  mCurrentFocus=Window{" +
                    WINDOW_TOKEN + " u0 " + android.FULL_COMPONENT + "}\n").encode("ascii"),
            base + ("  Display: mDisplayId=1 stacks=1\n    mCurrentFocus=Window{" +
                    WINDOW_TOKEN + " u0 " + android.FULL_COMPONENT + "}\n").encode("ascii"),
        )
        for mutated in cases:
            with self.subTest(mutated=mutated[-120:]):
                self.reject(activity=mutated)

    def test_other_display_summary_does_not_require_a_fixed_zero_one_pair(self):
        raw = activities().replace(
            b"ActivityStackSupervisor state:\n",
            b"Display #4 (activities from top to bottom):\n"
            b"ActivityStackSupervisor state:\n", 1)
        raw += b"  Display: mDisplayId=4 stacks=0\n  mCurrentFocus=null\n  mFocusedApp=null\n"
        task = parsed_task(raw)
        value = focus.validate_focus(task, raw, windows()).value()
        self.assertEqual(value["displayId"], 0)
        self.assertFalse(value["hardwareAdmission"])

    def test_window_header_and_focus_token_must_match(self):
        base = windows()
        for mutated in (
            base.replace(b"Window{f5d3f4a", b"Window{badcafe", 1),
            base + ("  Window #6 Window{deadbeef u0 " + android.FULL_COMPONENT + "}:\n").encode(),
            base + ("  Window #6 Window[deadbeef u0 " + android.FULL_COMPONENT + "]:\n").encode(),
            base.replace(b"Window #5 Window{", b"Window #5 Window{bad u0 " +
                         android.FULL_COMPONENT.encode() + b"}\n  Window #5 Window{", 1),
            base.replace(b"WINDOW MANAGER WINDOWS\n", b"", 1),
        ):
            with self.subTest(mutated=mutated[:90]):
                self.reject(window=mutated)

    def test_window_session_binds_display_task_pid_and_uid(self):
        base = windows()
        for old, new in (
            (b"mDisplayId=0", b"mDisplayId=1"),
            (b"rootTaskId=4538", b"rootTaskId=4539"),
            (str(PID).encode() + b":u0a", str(PID + 1).encode() + b":u0a"),
            (b"u0a1000", b"u0a1001"),
        ):
            with self.subTest(old=old):
                self.reject(window=base.replace(old, new, 1))

    def test_window_activity_references_and_visibility_are_required(self):
        base = windows()
        for old, new in (
            (b"mToken=ActivityRecord{11846f4", b"mToken=ActivityRecord{badcafe"),
            (b"mActivityRecord=ActivityRecord{11846f4", b"mActivityRecord=ActivityRecord{badcafe"),
            (b"mHasSurface=true", b"mHasSurface=false"),
            (b"isReadyForDisplay()=true", b"isReadyForDisplay()=false"),
            (b"isOnScreen=true", b"isOnScreen=false"),
            (b"isVisible=true", b"isVisible=false"),
        ):
            with self.subTest(old=old):
                self.reject(window=base.replace(old, new, 1))

    def test_malformed_or_alternate_stock_window_residue_fails(self):
        base = windows()
        additions = (
            "  Window #6 Window{deadbeef u0 com.supernote.document/.AlternateActivity}:\n",
            "  Window #6 Window{deadbeef u10 com.supernote.document/.document.DocumentActivity}:\n",
            "  Window #6 Window{deadbeef u0 com.supernote.document/.document.DocumentActivity\n",
            "    parent=Window{deadbeef u0 com.supernote.document/.document.DocumentActivity}\n",
            "    mActivityRecord=ActivityRecord{badcafe u0 " + android.SHORT_COMPONENT + " t4538}\n",
        )
        for addition in additions:
            with self.subTest(addition=addition):
                self.reject(window=base + addition.encode("ascii"))

    def test_raw_wire_is_bounded_and_strict(self):
        self.reject(window=windows() + b"\x00")
        self.reject(window=windows()[:-1])
        self.reject(window=windows().replace(b"\n", b"\r\n", 1))
        self.reject(window=b"WINDOW MANAGER WINDOWS\n" + b"x" * (focus.MAX_WINDOW_BYTES + 1))
        self.reject(activity="not bytes")


if __name__ == "__main__":
    unittest.main()
