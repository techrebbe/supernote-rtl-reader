"""Synthetic, host-only checks mirroring redacted Nomad display-0 observations.

The live dumps were not retained.  A passing fixture proves parser behavior,
not independent capture provenance or permission to attach to the reader.
"""
from __future__ import annotations

import hashlib
import unittest

import native_page_android_authority as android
import native_page_display0_stock_dialect as stock
from test_native_page_android_authority import PID, wire as task_wire


TASK_ID = 4538
TASK_TOKEN = "66d8263"
ACTIVITY_TOKEN = "11846f4"
WINDOW_TOKEN = "f5d3f4a"
SESSION_TOKEN = "39e379f"


def activities(*, window_token: str = WINDOW_TOKEN) -> bytes:
    return task_wire(task_visible="false") + (
        "ActivityStackSupervisor state:\n"
        "  topDisplayFocusedStack=Task{" + TASK_TOKEN + " #4538 visible=false "
        "type=standard mode=fullscreen translucent=true "
        "A=1000:com.supernote.document U=0 StackId=4538 sz=1}\n"
        "  mLastOrientationSource=ActivityRecord{" + ACTIVITY_TOKEN + " u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
        "  deepestLastOrientationSource=ActivityRecord{" + ACTIVITY_TOKEN +
        " u0 " + android.SHORT_COMPONENT + " t4538}\n"
        "  Display: mDisplayId=0 stacks=1\n"
        "  mCurrentFocus=Window{" + window_token + " u0 " +
        android.FULL_COMPONENT + "}\n"
        "  mFocusedApp=ActivityRecord{" + ACTIVITY_TOKEN + " u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
    ).encode("ascii")


def windows(*, window_token: str = WINDOW_TOKEN) -> bytes:
    return (
        "WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
        "  Window #5 Window{" + window_token + " u0 " +
        android.FULL_COMPONENT + "}:\n"
        "    mDisplayId=0 rootTaskId=4538 mSession=Session{" +
        SESSION_TOKEN + " " + str(PID) + ":1000} "
        "mClient=android.os.BinderProxy@dd48cb5\n"
        "    mOwnerUid=1000 showForAllUsers=false package=com.supernote.document "
        "appop=NONE\n"
        "    mBaseLayer=21000 mSubLayer=0    mToken=ActivityRecord{" +
        ACTIVITY_TOKEN + " u0 " + android.SHORT_COMPONENT + " t4538}\n"
        "    mActivityRecord=ActivityRecord{" + ACTIVITY_TOKEN + " u0 " +
        android.SHORT_COMPONENT + " t4538}\n"
        "    mHasSurface=true isReadyForDisplay()=true "
        "mWindowRemovalAllowed=false\n"
        "    isOnScreen=true\n"
        "    isVisible=true\n"
    ).encode("ascii")


class StockDisplayZeroDialectTests(unittest.TestCase):
    def check(self, before_activity=None, before_window=None,
              after_activity=None, after_window=None):
        return stock.validate_stock_dialect(
            activities() if before_activity is None else before_activity,
            windows() if before_window is None else before_window,
            activities() if after_activity is None else after_activity,
            windows() if after_window is None else after_window,
            expected_pid=PID,
        )

    def reject(self, **arguments):
        with self.assertRaises(stock.StockDialectError):
            self.check(**arguments)

    def test_observed_visibility_disagreement_is_diagnostic_only(self):
        result = self.check(
            after_activity=activities().replace(b"lastVisibleTime=-1s",
                                                b"lastVisibleTime=-2s", 1),
            after_window=windows() + b"  unrelated=changed\n")
        value = result.value()
        self.assertEqual(result.sha256, hashlib.sha256(result.raw).hexdigest())
        self.assertEqual(value["authority"], stock.AUTHORITY)
        self.assertEqual((value["displayId"], value["taskId"], value["pid"],
                          value["uid"]), (0, TASK_ID, PID, 1000))
        self.assertEqual((value["taskToken"], value["activityToken"],
                          value["windowToken"], value["windowSessionToken"]),
                         (TASK_TOKEN, ACTIVITY_TOKEN, WINDOW_TOKEN, SESSION_TOKEN))
        self.assertFalse(value["taskVisible"])
        self.assertTrue(value["activityVisible"])
        self.assertTrue(value["windowVisible"])
        self.assertNotEqual(value["beforeActivitySha256"], value["afterActivitySha256"])
        self.assertNotEqual(value["beforeWindowSha256"], value["afterWindowSha256"])
        for key in ("rawCaptureProvenanceVerified", "processStartTimeVerified",
                    "documentIdentityVerified", "hardwareAdmission",
                    "mutationCommandsAuthorized"):
            self.assertFalse(value[key], key)

    def test_parent_task_visibility_can_be_false_but_activity_must_be_live(self):
        base = activities()
        for old, new in (
            (b"visible=false type=standard", b"visible=true type=standard"),
            (b"state=RESUMED", b"state=PAUSED"),
            (b"mVisibleRequested=true", b"mVisibleRequested=false"),
            (b"mVisible=true", b"mVisible=false"),
            (b"mClientVisible=true", b"mClientVisible=false"),
            (b"reportedDrawn=true", b"reportedDrawn=false"),
            (b"reportedVisible=true", b"reportedVisible=false"),
            (b"nowVisible=true", b"nowVisible=false"),
        ):
            with self.subTest(old=old):
                self.reject(before_activity=base.replace(old, new, 1))

    def test_top_supervisor_cannot_claim_true_or_another_task(self):
        base = activities()
        for old, new in (
            (b"topDisplayFocusedStack=Task{66d8263", b"topDisplayFocusedStack=Task{badcafe"),
            (b"#4538 visible=false", b"#4538 visible=true"),
            (b"U=0 StackId=4538 sz=1", b"U=1 StackId=4538 sz=1"),
            (b"StackId=4538 sz=1", b"StackId=4539 sz=1"),
        ):
            with self.subTest(old=old):
                self.reject(before_activity=base.replace(old, new, 1))

    def test_supervisor_focus_is_unique_and_display_scoped(self):
        base = activities()
        focus_line = ("  mCurrentFocus=Window{" + WINDOW_TOKEN + " u0 " +
                      android.FULL_COMPONENT + "}\n").encode()
        app_line = ("  mFocusedApp=ActivityRecord{" + ACTIVITY_TOKEN + " u0 " +
                    android.SHORT_COMPONENT + " t4538}\n").encode()
        for mutated in (
            base.replace(focus_line, focus_line.replace(WINDOW_TOKEN.encode(),
                                                       b"deadbeef"), 1),
            base.replace(app_line, app_line.replace(ACTIVITY_TOKEN.encode(),
                                                   b"deadbeef"), 1),
            base.replace(app_line, app_line.replace(b"t4538", b"t4539"), 1),
            base.replace(focus_line, b"  mCurrentFocus=null\n", 1),
            base.replace(app_line, b"  mFocusedApp=null\n", 1),
            base.replace(focus_line, focus_line + focus_line, 1),
            base.replace(app_line, app_line + app_line, 1),
            base.replace(focus_line, b"    mCurrentFocus=Window{" +
                         WINDOW_TOKEN.encode() + b" u0 " +
                         android.FULL_COMPONENT.encode() + b"}\n", 1),
            base + b"  Display: mDisplayId=1 stacks=1\n" + focus_line,
            base + b"  Display: mDisplayId=0 stacks=1\n",
            base.replace(b"  Display: mDisplayId=0 stacks=1\n",
                         focus_line + b"  Display: mDisplayId=0 stacks=1\n", 1),
            base.replace(focus_line, focus_line + b"  mCurrentFocus[bad]\n", 1),
        ):
            with self.subTest(mutated=mutated[-100:]):
                self.reject(before_activity=mutated)

    def test_window_identity_session_surface_and_visibility_must_bind(self):
        base = windows()
        for old, new in (
            (b"Window{f5d3f4a", b"Window{deadbeef"),
            (b"mDisplayId=0", b"mDisplayId=1"),
            (b"rootTaskId=4538", b"rootTaskId=4539"),
            (str(PID).encode() + b":1000", str(PID + 1).encode() + b":1000"),
            (b":1000} mClient", b":u0a1000} mClient"),
            (b"mOwnerUid=1000", b"mOwnerUid=1001"),
            (b"package=com.supernote.document appop=NONE",
             b"package=com.supernote.document.other appop=NONE"),
            (b"mToken=ActivityRecord{11846f4", b"mToken=ActivityRecord{badcafe"),
            (b"mActivityRecord=ActivityRecord{11846f4",
             b"mActivityRecord=ActivityRecord{badcafe"),
            (b"mHasSurface=true", b"mHasSurface=false"),
            (b"isReadyForDisplay()=true", b"isReadyForDisplay()=false"),
            (b"mWindowRemovalAllowed=false", b"mWindowRemovalAllowed=true"),
            (b"isOnScreen=true", b"isOnScreen=false"),
            (b"isVisible=true", b"isVisible=false"),
        ):
            with self.subTest(old=old):
                self.reject(before_window=base.replace(old, new, 1))

    def test_malformed_alternate_or_duplicated_stock_window_fails(self):
        base = windows()
        for mutated in (
            base + ("  Window #6 Window{deadbeef u0 " + android.FULL_COMPONENT +
                    ":\n").encode(),
            base + ("  Window #6 Window{deadbeef u0 " + android.FULL_COMPONENT +
                    "}:\n").encode(),
            base + b"    isVisible=true\n",
            base + b"    mSession=Session{deadbeef 10104:1000}\n",
            base + b"    mOwnerUid[bad]\n",
            base + b"    mHasSurface[bad]\n",
            base + b"    mToken[bad]\n",
            base.replace(b"WINDOW MANAGER WINDOWS (dumpsys window windows)\n", b"", 1),
            base[:-1],
            base + b"\x00",
        ):
            with self.subTest(mutated=mutated[-100:]):
                self.reject(before_window=mutated)

    def test_before_after_cannot_switch_window_or_task(self):
        self.reject(after_activity=activities(window_token="deadbeef"),
                    after_window=windows(window_token="deadbeef"))
        self.reject(after_activity=activities().replace(b"66d8263", b"deadbeef"),
                    after_window=windows())
        self.reject(after_window=windows().replace(SESSION_TOKEN.encode(), b"deadbeef"))
        self.reject(after_activity=activities().replace(
            (str(PID) + ":com.supernote.document").encode(),
            (str(PID + 1) + ":com.supernote.document").encode(), 1))


if __name__ == "__main__":
    unittest.main()
