from __future__ import annotations

from dataclasses import replace
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_page_alpha_runner as alpha
import native_page_host_authority as host
import recover_native_page_alpha_run as recovery


ROOT = Path(__file__).resolve().parent
REPORT = ROOT / recovery.REPORT_RELATIVE
AUTHORITY = recovery.load_report(REPORT)
HOST_UID = recovery.PINNED_HOST_UID
DOCUMENT_PID = 2140

# Exact bounded authority fragments captured from the retained Nomad on the
# pinned firmware after the first plan-mode parser rejection.  They are copied
# here verbatim so the regression does not depend on ignored build evidence.
REAL_ACTIVITY_AUTHORITY = b"""Display #0 (activities from top to bottom):
  Stack #4635: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
    * Task{6e5e3c1 #4635 visible=true type=standard mode=fullscreen translucent=false A=10142:com.techrebbe.supernote.nativepagehost U=0 StackId=4635 sz=1}
      taskId=4635 stackId=4635
      * Hist #0: ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
Display #1 (activities from top to bottom):
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{6e5e3c1 #4635 visible=true type=standard mode=fullscreen translucent=false A=10142:com.techrebbe.supernote.nativepagehost U=0 StackId=4635 sz=1}
  mLastOrientationSource=ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
  deepestLastOrientationSource=ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
  Display: mDisplayId=0 stacks=4
  mCurrentFocus=Window{f5d3f4a u0 com.techrebbe.supernote.nativepagehost/com.techrebbe.supernote.nativepagehost.NativePageHostActivity}
  mFocusedApp=ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
      * Task{6e5e3c1 #4635 visible=true type=standard mode=fullscreen translucent=false A=10142:com.techrebbe.supernote.nativepagehost U=0 StackId=4635 sz=1}
  Display: mDisplayId=1 stacks=0
  mCurrentFocus=null
  mFocusedApp=null
"""

REAL_WINDOW_AUTHORITY = b"""  Window #5 Window{f5d3f4a u0 com.techrebbe.supernote.nativepagehost/com.techrebbe.supernote.nativepagehost.NativePageHostActivity}:
    mDisplayId=0 rootTaskId=4635 mSession=Session{39e379f 8758:u0a10142} mClient=android.os.BinderProxy@dd48cb5
    mBaseLayer=21000 mSubLayer=0    mToken=ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
    mActivityRecord=ActivityRecord{1b5aca8 u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}
    mHasSurface=true isReadyForDisplay()=true mWindowRemovalAllowed=false
    isOnScreen=true
    isVisible=true
"""

REAL_DISPLAY_AUTHORITY = b"""    mSupportedColorModes=[0]  DisplayDeviceInfo{"NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1": uniqueId="virtual:com.techrebbe.supernote.nativepagehost,10142,NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1,0", 1404 x 1872, modeId 2, defaultModeId 2, supportedModes [{id=2, width=1404, height=1872, fps=60.0}], colorMode 0, supportedColorModes [0], HdrCapabilities null, allmSupported false, gameContentTypeSupported false, density 300, 300.0 x 300.0 dpi, appVsyncOff 0, presDeadline 16666666, touch NONE, rotation 0, type VIRTUAL, deviceProductInfo null, state ON, owner com.techrebbe.supernote.nativepagehost (uid 10142), FLAG_OWN_CONTENT_ONLY}
mAdapter=VirtualDisplayAdapter
    mUniqueId=virtual:com.techrebbe.supernote.nativepagehost,10142,NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1,0
    mDisplayToken=android.os.BinderProxy@ab87ef8
    mCurrentLayerStack=1
    mCurrentOrientation=0
    mCurrentLayerStackRect=Rect(0, 0 - 1404, 1872)
    mCurrentDisplayRect=Rect(0, 0 - 1404, 1872)
    mCurrentSurface=Surface(name=null)/@0x30dcfd1
    mFlags=265
    mDisplayState=ON
    mStopped=false
    mDisplayIdToMirror=0
  Display 1:
    mDisplayId=1
    mLayerStack=1
    mHasContent=false
    mDesiredDisplayModeSpecs={baseModeId=2 primaryRefreshRateRange=[0 60] appRequestRefreshRateRange=[0 Infinity]}
    mRequestedColorMode=0
    mDisplayOffset=(0, 0)
    mDisplayScalingDisabled=false
    mPrimaryDisplayDevice=NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1
    mBaseDisplayInfo=DisplayInfo{"NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1", displayId 1, real 1404 x 1872, largest app 1404 x 1872, smallest app 1404 x 1872, appVsyncOff 0, presDeadline 16666666, mode 2, defaultMode 2, modes [{id=2, width=1404, height=1872, fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported false, rotation 0, state ON, type VIRTUAL, uniqueId "virtual:com.techrebbe.supernote.nativepagehost,10142,NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1,0", app 1404 x 1872, density 300 (300.0 x 300.0) dpi, layerStack 1, colorMode 0, supportedColorModes [0], deviceProductInfo null, owner com.techrebbe.supernote.nativepagehost (uid 10142), removeMode 1}
    mOverrideDisplayInfo=DisplayInfo{"NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1", displayId 1, real 1404 x 1872, largest app 1872 x 1872, smallest app 1404 x 1404, appVsyncOff 0, presDeadline 16666666, mode 2, defaultMode 2, modes [{id=2, width=1404, height=1872, fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported false, rotation 0, state ON, type VIRTUAL, uniqueId "virtual:com.techrebbe.supernote.nativepagehost,10142,NativePageVisualOnly-b4284fd3-b5f5-4644-916a-053746e87abd-1,0", app 1404 x 1872, density 300 (300.0 x 300.0) dpi, layerStack 1, colorMode 0, supportedColorModes [0], deviceProductInfo null, owner com.techrebbe.supernote.nativepagehost (uid 10142), removeMode 1}
    mRequestedMinimalPostProcessing=false
"""


def file(path: str, sha256: str, inode: int, *, size: int = 4096,
         uid: int = 10088, gid: int = 10088, device: int = 54) -> alpha.DeviceFile:
    return alpha.DeviceFile(
        path, "regular file", size, uid, gid, inode, device, sha256)


def live_activities(*, document: bool = False, malformed_pair: bool = False,
                    task_id: int = 4635, task_token: str = "6e5e3c1",
                    activity_token: str = "1b5aca8",
                    window_token: str = "f5d3f4a") -> bytes:
    pair_identity = "140913323" if malformed_pair else "140913322"
    document_line = "    diagnostic=com.supernote.document\n" if document else ""
    return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display areas in focus order:
Display #0 (activities from top to bottom):
  Stack #{task_id}: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{{activity_token} u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t{task_id}}}
    * Task{{{task_token} #{task_id} visible=true type=standard mode=fullscreen A={HOST_UID}:com.techrebbe.supernote.nativepagehost U=0 StackId={task_id} sz=1}}
      taskId={task_id} stackId={task_id}
      * Hist #0: ActivityRecord{{{activity_token} u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t{task_id}}}
{document_line}Display #1 (activities from top to bottom):
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{{task_token} #{task_id} visible=true type=standard mode=fullscreen A={HOST_UID}:com.techrebbe.supernote.nativepagehost U=0 StackId={task_id} sz=1}}
  mLastOrientationSource=ActivityRecord{{{activity_token} u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t{task_id}}}
  deepestLastOrientationSource=ActivityRecord{{{activity_token} u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t{task_id}}}
  Display: mDisplayId=0 stacks=1
    Task display areas in top down Z order:
      TaskDisplayArea DefaultTaskDisplayArea
      * Task{{{task_token} #{task_id} visible=true A={HOST_UID}:com.techrebbe.supernote.nativepagehost sz=1}}
        * ActivityRecord{{{activity_token} u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t{task_id}}}
  mCurrentFocus=Window{{{window_token} u0 {alpha.HOST_COMPONENT}}}
  mFocusedApp=ActivityRecord{{{activity_token} u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t{task_id}}}
  mLastOrientationSource=DefaultTaskDisplayArea@140913322
  deepestLastOrientationSource=DefaultTaskDisplayArea@{pair_identity}
  Display: mDisplayId=1 stacks=0
  mCurrentFocus=null
  mFocusedApp=null
""".encode("utf-8")


def absent_activities(*, document: bool = False) -> bytes:
    package = "com.supernote.document" if document else "com.example.home"
    component = ("com.supernote.document/.document.DocumentActivity"
                 if document else "com.example.home/.HomeActivity")
    return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display areas in focus order:
Display #0 (activities from top to bottom):
  Stack #7: type=home mode=fullscreen
    mResumedActivity: ActivityRecord{{abcdef0 u0 {component} t7}}
    * Task{{7654321 #7 visible=true type=home mode=fullscreen A=1000:{package} U=0 StackId=7 sz=1}}
      taskId=7 stackId=7
      * Hist #0: ActivityRecord{{abcdef0 u0 {component} t7}}
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{7654321 #7 visible=true type=home mode=fullscreen A=1000:{package} U=0 StackId=7 sz=1}}
  mLastOrientationSource=ActivityRecord{{abcdef0 u0 {component} t7}}
  deepestLastOrientationSource=ActivityRecord{{abcdef0 u0 {component} t7}}
  Display: mDisplayId=0 stacks=1
""".encode("utf-8")


def live_windows(*, document: bool = False, window_token: str = "f5d3f4a",
                 activity_token: str = "1b5aca8", display_id: int = 0,
                 visible: bool = True) -> bytes:
    extra = ("Window #1 Window{deadc0de u0 com.supernote.document/"
             "com.supernote.document.document.DocumentActivity}\n  mDisplayId=0\n"
             if document else "")
    visibility = "true" if visible else "false"
    return ("WINDOW MANAGER WINDOWS\n"
            "  Window #5 Window{" + window_token + " u0 " +
            alpha.HOST_COMPONENT + "}:\n"
            f"    mDisplayId={display_id} rootTaskId=4635 mSession=Session{{39e379f 8758:u0a{HOST_UID}}} mClient=android.os.BinderProxy@dd48cb5\n"
            "    mBaseLayer=21000 mSubLayer=0    mToken=ActivityRecord{" +
            activity_token + " u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}\n"
            "    mActivityRecord=ActivityRecord{" + activity_token +
            " u0 com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}\n"
            f"    mHasSurface={visibility} isReadyForDisplay()={visibility} mWindowRemovalAllowed=false\n"
            f"    isOnScreen={visibility}\n"
            f"    isVisible={visibility}\n" + extra).encode("utf-8")


def absent_windows(*, document: bool = False) -> bytes:
    if document:
        return ("WINDOW MANAGER WINDOWS\nWindow #0 Window{deadc0de u0 " +
                alpha.DOCUMENT_COMPONENT + "}\n  mDisplayId=0\n").encode("utf-8")
    return b"WINDOW MANAGER WINDOWS\nWindow #0 Window{abc1234 u0 com.example.home/.HomeActivity}\n  mDisplayId=0\n"


class FakeDevice:
    def __init__(self) -> None:
        self.history: list[dict[str, object]] = []
        self.host_live = True
        self.host_state = "FAILED"
        self.host_start_ticks = AUTHORITY.host_start_ticks
        self.host_uid = HOST_UID
        self.document_start_ticks = 444444
        self.serial = alpha.AUTHORIZED_SERIAL
        self.model = alpha.MODEL
        self.sdk = alpha.SDK
        self.fingerprint = alpha.FINGERPRINT
        self.user = "0"
        self.rotation = ("1", "2")
        self.physical_rotation = 0
        self.sensor_physical_after_free = 0
        self.rotation_lock_transport = "ok"
        self.rotation_restore_lock_transport = "ok"
        self.rotation_free_transport = "ok"
        self.rotation_read_trace: list[str] = []
        self.adb = {
            "path": str(recovery.PINNED_ADB_PATH),
            "size": recovery.PINNED_ADB_SIZE,
            "sha256": recovery.PINNED_ADB_SHA256,
            "device": 3, "inode": 77, "mtimeNs": 123456,
        }
        self.host_version = (alpha.HOST_VERSION_CODE, alpha.HOST_VERSION_NAME)
        self.host_apk_hash = alpha.ALPHA_SIGNED_APK_SHA256
        self.document_present = False
        self.malformed_display_pair = False
        self.host_task_id = 4635
        self.host_task_token = "6e5e3c1"
        self.host_activity_token = "1b5aca8"
        self.host_window_token = "f5d3f4a"
        self.host_window_display = 0
        self.host_visible = True
        self.display_present = True
        self.logs = ""
        self.omit_refocus_log = False
        self.omit_accept_event = False
        self.omit_release_event = False
        self.reverse_release_events = False
        self.duplicate_release_event = False
        self.release_display = "1"
        self.release_mode = "acknowledged_cleanup"
        self.digest_suffix = ""
        self.extra_action_logs: list[tuple[str, str]] = []
        self.late_absence_logs: list[tuple[str, str]] = []
        self.absent_activity_calls = 0
        self.settle_after_log = False
        self.host_logs_calls = 0
        self.refocus_transport = "ok"
        self.action_transport = "ok"
        self.move_transport: dict[str, str] = {}
        self.remove_transport: dict[str, str] = {}
        self.mutations: list[str] = []
        self.journal = MemoryJournal()
        self.fd_targets: list[str] = [alpha.PARKING_PDF, alpha.PARKING_PDF]
        self.document_pids: tuple[int, ...] = (DOCUMENT_PID,)
        self.files: dict[str, alpha.DeviceFile] = {
            alpha.SOURCE_PDF: file(
                alpha.SOURCE_PDF, alpha.SOURCE_PDF_SHA256, 180001, size=4678),
            alpha.SOURCE_MARK: file(
                alpha.SOURCE_MARK, alpha.SOURCE_MARK_SHA256, 180002, size=5756),
            alpha.PARKING_PDF: file(
                alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 180003, size=4678),
            alpha.TARGET_PDF: AUTHORITY.retained_pdf,
            alpha.TARGET_MARK: AUTHORITY.retained_mark,
            alpha.DOCUMENT_APK: file(
                alpha.DOCUMENT_APK, alpha.DOCUMENT_APK_SHA256, 1234,
                size=alpha.DOCUMENT_APK_SIZE, uid=0, gid=0, device=10),
        }

    def _line(self, event: str, detail: str) -> str:
        return ("I/NATIVE_PAGE_HOST( 8758): " + event + " session=" +
                AUTHORITY.status.session + " generation=1 " + detail + "\n")

    def get_state(self) -> str: return "device"
    def adb_authority(self) -> dict[str, object]: return dict(self.adb)
    def get_serial(self) -> str: return self.serial
    def getprop(self, name: str) -> str:
        return {
            "ro.product.model": self.model,
            "ro.build.version.sdk": self.sdk,
            "ro.build.fingerprint": self.fingerprint,
        }[name]
    def current_user(self) -> str: return self.user

    def package_dump(self, package: str) -> str:
        if package == alpha.HOST_PACKAGE:
            code, name = self.host_version
            return (f"Package [{package}]\n  userId={self.host_uid}\n"
                    f"  versionCode={code} minSdk=30\n  versionName={name}\n")
        return (f"Package [{package}]\n  userId=1000\n"
                f"  versionCode={alpha.DOCUMENT_VERSION_CODE} minSdk=30\n"
                f"  versionName={alpha.DOCUMENT_VERSION_NAME}\n")

    def package_path(self, package: str) -> str:
        return ("/data/app/~~pinned/com.techrebbe.supernote.nativepagehost/base.apk"
                if package == alpha.HOST_PACKAGE else alpha.DOCUMENT_APK)

    def sha256_file(self, path: str) -> str:
        if path.endswith("/base.apk"):
            return self.host_apk_hash
        value = self.files.get(path)
        if value is None:
            raise alpha.AlphaError("missing hash target")
        return value.sha256

    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None:
        value = self.files.get(path)
        if value is None and not absent_ok:
            raise alpha.AlphaError("missing required file: " + path)
        return value

    def activities(self) -> bytes:
        if self.settle_after_log and self.host_logs_calls > 1:
            self.host_live = False
            self.display_present = False
            self.settle_after_log = False
        if not self.host_live:
            self.absent_activity_calls += 1
            if self.absent_activity_calls == 1:
                for event_name, event_detail in self.late_absence_logs:
                    self.logs += self._line(event_name, event_detail)
        return (live_activities(document=self.document_present,
                                malformed_pair=self.malformed_display_pair,
                                task_id=self.host_task_id,
                                task_token=self.host_task_token,
                                activity_token=self.host_activity_token,
                                window_token=self.host_window_token)
                if self.host_live else
                absent_activities(document=self.document_present))

    def windows(self) -> bytes:
        return (live_windows(
                    document=self.document_present,
                    window_token=self.host_window_token,
                    activity_token=self.host_activity_token,
                    display_id=self.host_window_display,
                    visible=self.host_visible) if self.host_live
                else absent_windows(document=self.document_present))

    def window_displays(self) -> bytes:
        self.rotation_read_trace.append("wm")
        width, height = ((1404, 1872) if self.physical_rotation in (0, 2)
                         else (1872, 1404))
        return f"""WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)
  Display: mDisplayId=0 stacks=1
    init=1404x1872 300dpi cur={width}x{height} app={width}x{height}
    mDisplayInfo=DisplayInfo{{"Built-in Screen", displayId 0, rotation {self.physical_rotation}, state ON, type INTERNAL}}
    DisplayFrames w={width} h={height} r={self.physical_rotation}
    mRotation={self.physical_rotation} mDeferredRotationPauseCount=0
""".encode()

    def rotation_settings(self) -> tuple[str, str]:
        self.rotation_read_trace.append("settings")
        return self.rotation

    @staticmethod
    def _transport_raises(mode: str) -> bool:
        return mode in {"applied_uncertain", "unapplied"}

    def lock_rotation_zero(self) -> None:
        self.mutations.append("rotation:lock0")
        if self.rotation_lock_transport != "unapplied":
            self.rotation = ("0", "0")
            self.physical_rotation = 0
        if self._transport_raises(self.rotation_lock_transport):
            raise alpha.AlphaError("simulated rotation lock transport uncertainty")

    def lock_rotation_two(self) -> None:
        self.mutations.append("rotation:lock2")
        if self.rotation_restore_lock_transport != "unapplied":
            self.rotation = ("0", "2")
            self.physical_rotation = 2
        if self._transport_raises(self.rotation_restore_lock_transport):
            raise alpha.AlphaError(
                "simulated rotation restore lock transport uncertainty")

    def free_rotation(self) -> None:
        self.mutations.append("rotation:free")
        if self.rotation_free_transport != "unapplied":
            self.rotation = ("1", self.rotation[1])
            self.physical_rotation = self.sensor_physical_after_free
        if self._transport_raises(self.rotation_free_transport):
            raise alpha.AlphaError("simulated rotation free transport uncertainty")

    def displays(self) -> bytes:
        if self.host_live and self.display_present:
            return REAL_DISPLAY_AUTHORITY
        return b"DISPLAY MANAGER\nDisplayDeviceInfo{\"Built-in Screen\", uniqueId=local:0}\n"

    def pidof(self, package: str) -> tuple[int, ...]:
        if package == alpha.HOST_PACKAGE:
            return (AUTHORITY.host_pid,) if self.host_live else ()
        return self.document_pids

    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity:
        if package == alpha.HOST_PACKAGE:
            return host.ProcessIdentity(
                pid, self.host_start_ticks, self.host_uid, package)
        return host.ProcessIdentity(pid, self.document_start_ticks, 1000, package)

    def process_fd_links(self, pid: int) -> str:
        records = self.fd_targets or ["/dev/null"]
        return "total 0\n" + "".join(
            f"lr-x------ 1 system system 64 2026-09-16 12:00 {number} -> {target}\n"
            for number, target in enumerate(records))

    def start_host(self) -> None:
        self.mutations.append("refocus")
        if self.refocus_transport != "unapplied" and not self.omit_refocus_log:
            self.logs += self._line("REFOCUS", "readiness=" + self.host_state)
        if self.refocus_transport in {"applied_uncertain", "unapplied"}:
            raise alpha.AlphaError("simulated refocus transport uncertainty")

    def host_logs(self, pid: int) -> str:
        self.host_logs_calls += 1
        return self.logs

    def send_recovery(self, status: alpha.HostStatus, action: str,
                      evidence_sha256: str) -> None:
        self.mutations.append("send:" + action.rsplit(".", 1)[-1])
        event = (recovery.EVENT_FAILED if action == recovery.ACTION_FAILED
                 else "UNSUPPORTED")
        if self.action_transport != "unapplied" and not self.omit_accept_event:
            abort = self._line(
                event, "absenceEvidenceSha256=" + evidence_sha256 +
                self.digest_suffix)
            release = self._line(
                recovery.EVENT_RELEASED,
                "display=" + self.release_display + " mode=" +
                self.release_mode)
            if self.omit_release_event:
                release = ""
            if self.reverse_release_events:
                self.logs += release + abort
            else:
                self.logs += abort + release
            if self.duplicate_release_event:
                self.logs += release
            for event_name, event_detail in self.extra_action_logs:
                self.logs += self._line(event_name, event_detail)
            self.host_live = False
            self.display_present = False
        if self.action_transport in {"applied_uncertain", "unapplied"}:
            raise alpha.AlphaError("simulated action transport uncertainty")

    def recovery_stat_file(self, path: str, *,
                           absent_ok: bool = False) -> alpha.DeviceFile | None:
        return self.stat_file(path, absent_ok=absent_ok)

    def move_to_quarantine(self, source: str, target: str) -> None:
        self.mutations.append("move:" + source + "->" + target)
        mode = self.move_transport.get(source, "ok")
        if mode != "unapplied":
            current = self.files.pop(source, None)
            if current is not None and target not in self.files:
                self.files[target] = replace(current, path=target)
            elif current is not None:
                self.files[source] = current
        if mode in {"applied_uncertain", "unapplied"}:
            raise alpha.AlphaError("simulated move transport uncertainty")

    def remove_quarantine(self, path: str) -> None:
        self.mutations.append("remove:" + path)
        mode = self.remove_transport.get(path, "ok")
        if mode != "unapplied":
            self.files.pop(path, None)
        if mode in {"applied_uncertain", "unapplied"}:
            raise alpha.AlphaError("simulated remove transport uncertainty")


class MemoryJournal:
    def __init__(self, header: dict[str, object] | None = None) -> None:
        self.records: list[dict[str, object]] = []
        self._head = "0" * 64
        self.fail_at: int | None = None
        self.record("header", header or {"authority": "test"})

    @property
    def count(self) -> int: return len(self.records)
    @property
    def head_hash(self) -> str: return self._head

    def record(self, kind: str, payload: dict[str, object]) -> dict[str, object]:
        if self.fail_at is not None and len(self.records) == self.fail_at:
            raise OSError("journal fsync failed")
        base = {"seq": len(self.records), "prevHash": self._head,
                "kind": kind, "payload": payload}
        value = {**base, "recordHash": alpha._canonical_sha(base)}
        self.records.append(value)
        self._head = value["recordHash"]
        return value


class PartialThenCrashStream:
    def __init__(self, stream: object, first_write: int):
        self.stream = stream
        self.first_write = first_write
        self.calls = 0

    @property
    def closed(self) -> bool:
        return self.stream.closed  # type: ignore[attr-defined]

    def fileno(self) -> int:
        return self.stream.fileno()  # type: ignore[attr-defined]

    def write(self, value: bytes) -> int:
        if self.calls:
            raise OSError("injected append crash")
        self.calls += 1
        return self.stream.write(  # type: ignore[attr-defined]
            value[:min(self.first_write, len(value))])

    def flush(self) -> None:
        self.stream.flush()  # type: ignore[attr-defined]

    def close(self) -> None:
        self.stream.close()  # type: ignore[attr-defined]


class BoundedShortWriteStream:
    def __init__(self, stream: object, maximum: int):
        self.stream = stream
        self.maximum = maximum

    @property
    def closed(self) -> bool:
        return self.stream.closed  # type: ignore[attr-defined]

    def fileno(self) -> int:
        return self.stream.fileno()  # type: ignore[attr-defined]

    def write(self, value: bytes) -> int:
        return self.stream.write(  # type: ignore[attr-defined]
            value[:min(self.maximum, len(value))])

    def flush(self) -> None:
        self.stream.flush()  # type: ignore[attr-defined]

    def close(self) -> None:
        self.stream.close()  # type: ignore[attr-defined]


class FullWriteFlushCrashStream(BoundedShortWriteStream):
    def __init__(self, stream: object, error: BaseException):
        super().__init__(stream, 1 << 30)
        self.error = error

    def flush(self) -> None:
        raise self.error


class RecoveryTests(unittest.TestCase):
    @staticmethod
    def execute_identities(device: FakeDevice) -> dict[str, object]:
        _, helper = recovery._read_pinned_regular(
            Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
            "recovery helper")
        return {
            "header_helper_identity": helper,
            "header_adb_identity": device.adb_authority(),
        }

    def run_recovery(self, device: FakeDevice, *, execute: bool = True) -> dict:
        return recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None,
            journal=device.journal,
            **(self.execute_identities(device) if execute else {})).run(
            execute=execute)

    @staticmethod
    def rotation_wire(accelerometer: str, user: str,
                      physical: int = 0) -> dict[str, object]:
        return {
            "settingsBefore": {
                "accelerometerRotation": accelerometer,
                "userRotation": user,
            },
            "physicalRotation": physical,
            "windowDisplaysSha256": "a" * 64,
            "settingsAfter": {
                "accelerometerRotation": accelerometer,
                "userRotation": user,
            },
        }

    @staticmethod
    def descriptor_authority(
            mode: str = recovery.DESCRIPTOR_AUTHORITY_PARKING_ONLY
    ) -> dict[str, object]:
        targets = ([alpha.PARKING_PDF]
                   if mode == recovery.DESCRIPTOR_AUTHORITY_PARKING_ONLY
                   else [])
        observation = {
            "activitiesSha256": "c" * 64,
            "documentTaskWindowAbsent": True,
            "fdInventorySha256": "d" * 64,
            "relevantTargets": targets,
            "windowsSha256": "e" * 64,
        }
        return {
            "documentProcess": {
                "package": alpha.DOCUMENT_PACKAGE,
                "pid": DOCUMENT_PID,
                "start_ticks": 444444,
                "uid": 1000,
            },
            "mode": mode,
            "observations": [copy.deepcopy(observation),
                             copy.deepcopy(observation)],
        }

    def restore_header(self, *, physical: int = 0,
                       serial: str = alpha.AUTHORIZED_SERIAL) -> dict[str, object]:
        _, helper = recovery._read_pinned_regular(
            Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
            "recovery helper")
        fake = FakeDevice()
        device = {
            "serial": serial,
            "model": alpha.MODEL,
            "sdk": alpha.SDK,
            "fingerprint": alpha.FINGERPRINT,
            "hostPackage": alpha.HOST_PACKAGE,
            "hostApkSha256": alpha.ALPHA_SIGNED_APK_SHA256,
            "documentPackage": alpha.DOCUMENT_PACKAGE,
            "documentApkSha256": alpha.DOCUMENT_APK_SHA256,
            "adb": fake.adb,
        }
        return {
            "authority": recovery.RECOVERY_AUTHORITY,
            "schemaVersion": 1,
            "reportSha256": AUTHORITY.report_sha256,
            "readOnlyAdmissionSha256": "b" * 64,
            "descriptorAuthority": self.descriptor_authority(),
            "evidenceReservation": {
                "path": str(ROOT / "restore-evidence.json"),
                "parent": str(ROOT),
                "parentDevice": 1,
                "parentInode": 2,
                "device": 1,
                "inode": 3,
                "initialSize": 0,
                "exclusive": True,
                "noFollow": True,
            },
            "helper": helper,
            "rotationLease": {
                "authority": recovery.ROTATION_LEASE_AUTHORITY,
                "originalPersisted": {
                    "accelerometerRotation": "1", "userRotation": "2"},
                "readOnlyAdmissionSandwich": self.rotation_wire(
                    "1", "2", physical),
                "commandDialects": recovery.ROTATION_COMMAND_DIALECTS,
            },
            "device": device,
        }

    def add_lock_intent(self, journal: recovery.DurableJournal, *,
                        physical: int = 0) -> None:
        journal.record("rotation_lock_intent", {
            "authority": recovery.ROTATION_LEASE_AUTHORITY,
            "reportSha256": AUTHORITY.report_sha256,
            "admissionSandwich": self.rotation_wire("1", "2", physical),
            "commandDialect": recovery.ROTATION_COMMAND_DIALECTS["acquire"],
            "rollbackCommandDialects": {
                "lockTwo": recovery.ROTATION_COMMAND_DIALECTS[
                    "restoreUserRotation"],
                "free": recovery.ROTATION_COMMAND_DIALECTS["restoreSensor"],
            },
            "target": {"accelerometerRotation": "0",
                       "userRotation": "0", "physicalRotation": 0},
        })

    def add_lock_settlement(self, journal: recovery.DurableJournal) -> None:
        journal.record("rotation_lock_settlement", {
            "authority": recovery.ROTATION_LEASE_AUTHORITY,
            "reportSha256": AUTHORITY.report_sha256,
            "commandDialect": recovery.ROTATION_COMMAND_DIALECTS["acquire"],
            "transportUncertain": None,
            "observations": [self.rotation_wire("0", "0"),
                             self.rotation_wire("0", "0")],
        })

    def add_complete_cleanup(
            self, journal: recovery.DurableJournal) -> None:
        source = FakeDevice()
        self.run_recovery(source)
        copying = False
        for record in source.journal.records:
            if record["kind"] == "rotation_lock_settlement":
                copying = True
                continue
            if not copying:
                continue
            if record["kind"] == "rotation_restore_intent":
                break
            journal.record(record["kind"], copy.deepcopy(record["payload"]))

    def add_complete_execution(
            self, journal: recovery.DurableJournal) -> None:
        source = FakeDevice()
        self.run_recovery(source)
        for record in source.journal.records[1:]:
            journal.record(record["kind"], copy.deepcopy(record["payload"]))

    @staticmethod
    def canonical_records(records: list[dict[str, object]]) -> bytes:
        previous = "0" * 64
        lines: list[bytes] = []
        for sequence, original in enumerate(records):
            base = {
                "seq": sequence,
                "prevHash": previous,
                "kind": original["kind"],
                "payload": original["payload"],
            }
            value = {**base, "recordHash": alpha._canonical_sha(base)}
            lines.append((json.dumps(
                value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                separators=(",", ":")) + "\n").encode("ascii"))
            previous = value["recordHash"]
        return b"".join(lines)

    def test_exact_retained_nomad_focus_dialect_is_a_mandatory_regression(self) -> None:
        scope = recovery._host_scope_identity(
            REAL_ACTIVITY_AUTHORITY, REAL_WINDOW_AUTHORITY, HOST_UID,
            AUTHORITY.host_pid)
        self.assertEqual((scope.task_id, scope.task_token), (4635, "6e5e3c1"))
        self.assertEqual(scope.activity_token, "1b5aca8")
        self.assertEqual(scope.window_token, "f5d3f4a")
        self.assertEqual(scope.window_session_token, "39e379f")
        self.assertEqual((scope.activity_display_id, scope.window_display_id), (0, 0))
        self.assertTrue(scope.resumed and scope.visible and scope.focused)

    def test_exact_retained_nomad_display_dialect_is_a_mandatory_regression(self) -> None:
        self.assertEqual(
            REAL_DISPLAY_AUTHORITY.decode().count(AUTHORITY.status.display_name),
            8)
        display = recovery._retained_virtual_display_identity(
            REAL_DISPLAY_AUTHORITY, AUTHORITY.status, HOST_UID)
        self.assertEqual((display.display_id, display.layer_stack), (1, 1))
        self.assertEqual(display.name, AUTHORITY.status.display_name)
        self.assertEqual(
            display.unique_id,
            "virtual:com.techrebbe.supernote.nativepagehost,10142," +
            AUTHORITY.status.display_name + ",0")
        self.assertEqual((display.owner_package, display.owner_uid),
                         (alpha.HOST_PACKAGE, HOST_UID))
        self.assertEqual(display.display_token, "ab87ef8")
        self.assertEqual(display.surface_token, "0x30dcfd1")

    def test_virtual_display_structure_rejects_duplicate_borrowed_and_mismatched_records(self) -> None:
        device, logical_tail = REAL_DISPLAY_AUTHORITY.split(b"  Display 1:\n", 1)
        logical = b"  Display 1:\n" + logical_tail
        borrowed = (
            b'    mSupportedColorModes=[0]  DisplayDeviceInfo{"' +
            AUTHORITY.status.display_name.encode() +
            b'": uniqueId="virtual:borrowed", 1404 x 1872}\n')
        borrowed_logical = (
            b"  Display 2:\n"
            b"    mDisplayId=2\n"
            b"    mLayerStack=2\n"
            b"    mPrimaryDisplayDevice=" +
            AUTHORITY.status.display_name.encode() + b"\n")
        second_host_device = (
            b'    DisplayDeviceInfo{"OtherHostDisplay": '
            b'uniqueId="virtual:com.techrebbe.supernote.nativepagehost,10142,'
            b'OtherHostDisplay,0", 100 x 100, type VIRTUAL, state ON, owner '
            b'com.techrebbe.supernote.nativepagehost (uid 10142)}\n')
        second_host_logical = (
            b"  Display 2:\n"
            b"    mDisplayId=2\n"
            b"    mLayerStack=2\n"
            b"    mPrimaryDisplayDevice=OtherHostDisplay\n"
            b"    mBaseDisplayInfo=DisplayInfo{\"OtherHostDisplay\", displayId 2, "
            b"type VIRTUAL, owner com.techrebbe.supernote.nativepagehost "
            b"(uid 10142)}\n")
        malformed_same_name = (
            b'    DisplayDeviceInfo{"' + AUTHORITY.status.display_name.encode() +
            b'", uniqueId="virtual:malformed"}\n')
        unique_id = (
            "virtual:com.techrebbe.supernote.nativepagehost,10142," +
            AUTHORITY.status.display_name + ",0").encode()
        mutations = {
            "duplicate device": device + device + logical,
            "duplicate logical": REAL_DISPLAY_AUTHORITY + b"\n" + logical,
            "borrowed device name": borrowed + REAL_DISPLAY_AUTHORITY,
            "borrowed logical name": REAL_DISPLAY_AUTHORITY + borrowed_logical,
            "second host-owned device":
                second_host_device + REAL_DISPLAY_AUTHORITY,
            "second host-owned logical display":
                REAL_DISPLAY_AUTHORITY + second_host_logical,
            "malformed same-name device header":
                malformed_same_name + REAL_DISPLAY_AUTHORITY,
            "owner UID": REAL_DISPLAY_AUTHORITY.replace(
                b"(uid 10142)", b"(uid 10143)", 1),
            "unique ID": REAL_DISPLAY_AUTHORITY.replace(
                unique_id, unique_id[:-1] + b"9"),
            "mixed unique ID": REAL_DISPLAY_AUTHORITY.replace(
                b"    mUniqueId=" + unique_id + b"\n",
                b"    mUniqueId=" + unique_id + b"\n"
                b"    mUniqueId=virtual:borrowed\n", 1),
            "logical display ID": REAL_DISPLAY_AUTHORITY.replace(
                b"    mDisplayId=1\n", b"    mDisplayId=2\n", 1),
            "mixed logical display ID": REAL_DISPLAY_AUTHORITY.replace(
                b"    mDisplayId=1\n",
                b"    mDisplayId=1\n    mDisplayId=2\n", 1),
            "device layer": REAL_DISPLAY_AUTHORITY.replace(
                b"    mCurrentLayerStack=1\n",
                b"    mCurrentLayerStack=2\n", 1),
            "logical layer": REAL_DISPLAY_AUTHORITY.replace(
                b"    mLayerStack=1\n", b"    mLayerStack=2\n", 1),
            "stopped": REAL_DISPLAY_AUTHORITY.replace(
                b"    mStopped=false\n", b"    mStopped=true\n", 1),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(recovery.RecoveryError):
                    recovery._retained_virtual_display_identity(
                        mutated, AUTHORITY.status, HOST_UID)

    def test_exact_report_loads_and_duplicate_or_mutated_authority_fails(self) -> None:
        self.assertEqual(recovery.load_report(REPORT), AUTHORITY)
        raw = REPORT.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            duplicate = raw.replace(
                b'"schemaVersion": 1,',
                b'"schemaVersion": 1, "schemaVersion": 1,', 1)
            path = Path(directory) / "report.json"
            path.write_bytes(duplicate)
            with self.assertRaisesRegex(recovery.RecoveryError, "duplicate"):
                recovery.load_report(path, expected_sha256=alpha._sha(duplicate))
            base = json.loads(raw)
            mutations = (
                ("host display", lambda value: value["host"].__setitem__("displayId", 2)),
                ("foreign launch", lambda value: value.__setitem__("documentLaunchAttempted", True)),
                ("pending command", lambda value: value.__setitem__("pendingHostCommand", {})),
                ("remove attempt", lambda value: value["fixture"]["cleanupObligations"]
                 [alpha.TARGET_PDF].__setitem__("remove_attempted", True)),
                ("file inode", lambda value: value["fixture"]["cleanupObligations"]
                 [alpha.TARGET_MARK]["retained"].__setitem__("inode", 999)),
            )
            for name, mutate in mutations:
                with self.subTest(name=name):
                    value = copy.deepcopy(base)
                    mutate(value)
                    encoded = json.dumps(value, sort_keys=True).encode()
                    path.write_bytes(encoded)
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.load_report(
                            path, expected_sha256=alpha._sha(encoded))

    def test_plan_is_read_only_and_requests_refocus_when_logs_expired(self) -> None:
        device = FakeDevice()
        result = self.run_recovery(device, execute=False)
        self.assertEqual(result["result"], "PLAN_REFOCUS_REQUIRED")
        self.assertEqual(device.mutations, [])
        self.assertEqual(len(device.journal.records), 1)
        live = next(item for item in result["proofs"]
                    if item["kind"] == "live_host")
        raw = live["stableRawAuthority"]
        self.assertEqual(raw["first"]["hostScope"]["task_id"], 4635)
        self.assertIn("mResumedActivity", "\n".join(
            raw["first"]["hostScope"]["activity_authority_lines"]))
        self.assertIn("mCurrentFocus", "\n".join(
            raw["second"]["hostScope"]["activity_authority_lines"]))
        self.assertEqual(
            raw["second"]["virtualDisplay"]["unique_id"],
            "virtual:com.techrebbe.supernote.nativepagehost,10142," +
            AUTHORITY.status.display_name + ",0")

    def test_execute_requires_journal_before_first_mutation(self) -> None:
        device = FakeDevice()
        runner = recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None,
            **self.execute_identities(device))
        with self.assertRaisesRegex(recovery.RecoveryError, "durable"):
            runner.run(execute=True)
        self.assertEqual(device.mutations, [])
        self.assertEqual(runner.evidence["mutations"], [])

    def test_journal_failure_prevents_the_corresponding_device_mutation(self) -> None:
        device = FakeDevice()
        rejected = MemoryJournal()
        rejected.fail_at = 1
        runner = recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None, journal=rejected,
            **self.execute_identities(device))
        with self.assertRaisesRegex(OSError, "journal fsync"):
            runner.run(execute=True)
        self.assertEqual(device.mutations, [])

    def test_sticky_failed_recovery_refocuses_sends_once_and_deletes_mark_first(self) -> None:
        device = FakeDevice()
        result = self.run_recovery(device)
        self.assertEqual(result["result"], "RECOVERED_CLEANLY")
        self.assertEqual(device.mutations, [
            "rotation:lock0", "refocus", "send:ACK_NO_FOREIGN_AFTER_FAILURE",
            "move:" + alpha.TARGET_MARK + "->" + recovery.QUARANTINE_MARK,
            "remove:" + recovery.QUARANTINE_MARK,
            "move:" + alpha.TARGET_PDF + "->" + recovery.QUARANTINE_PDF,
            "remove:" + recovery.QUARANTINE_PDF,
            "rotation:lock2", "rotation:free",
        ])
        self.assertEqual(
            [entry["payload"]["intent"]["kind"] for entry in
             device.journal.records if entry["kind"] == "mutation_intent"],
            ["host_main_refocus", "empty_display_abort",
             "quarantine_move_attempt", "quarantine_delete_attempt",
             "quarantine_move_attempt", "quarantine_delete_attempt"])
        self.assertNotIn(alpha.TARGET_PDF, device.files)
        self.assertNotIn(alpha.TARGET_MARK, device.files)

    def test_waiting_state_is_not_accepted_for_this_sticky_failed_run(self) -> None:
        device = FakeDevice()
        device.host_state = "WAITING_FOR_FOREIGN_ATTACH"
        with self.assertRaisesRegex(recovery.RecoveryError, "non-FAILED"):
            self.run_recovery(device)
        self.assertEqual(device.mutations, [
            "rotation:lock0", "refocus", "rotation:lock2", "rotation:free"])

    def test_already_released_deletes_without_sending(self) -> None:
        device = FakeDevice()
        device.host_live = False
        device.display_present = False
        self.run_recovery(device)
        self.assertEqual(device.mutations, [
            "rotation:lock0",
            "move:" + alpha.TARGET_MARK + "->" + recovery.QUARANTINE_MARK,
            "remove:" + recovery.QUARANTINE_MARK,
            "move:" + alpha.TARGET_PDF + "->" + recovery.QUARANTINE_PDF,
            "remove:" + recovery.QUARANTINE_PDF,
            "rotation:lock2", "rotation:free"])

    def test_already_attempted_settles_without_replay(self) -> None:
        device = FakeDevice()
        device.logs = (device._line(
            recovery.EVENT_FAILED, "absenceEvidenceSha256=" + "a" * 64) +
            device._line(recovery.EVENT_RELEASED,
                         "display=1 mode=acknowledged_cleanup"))
        device.settle_after_log = True
        self.run_recovery(device)
        self.assertFalse(any(value.startswith("send:") for value in device.mutations))
        self.assertEqual(device.mutations, [
            "rotation:lock0",
            "move:" + alpha.TARGET_MARK + "->" + recovery.QUARANTINE_MARK,
            "remove:" + recovery.QUARANTINE_MARK,
            "move:" + alpha.TARGET_PDF + "->" + recovery.QUARANTINE_PDF,
            "remove:" + recovery.QUARANTINE_PDF,
            "rotation:lock2", "rotation:free"])

    def test_already_attempted_live_host_is_never_replayed(self) -> None:
        device = FakeDevice()
        device.logs = (device._line(
            recovery.EVENT_FAILED, "absenceEvidenceSha256=" + "a" * 64) +
            device._line(recovery.EVENT_RELEASED,
                         "display=1 mode=acknowledged_cleanup"))
        with self.assertRaisesRegex(recovery.RecoveryError, "did not settle"):
            self.run_recovery(device)
        self.assertFalse(any(value.startswith("send:") for value in device.mutations))

    def test_action_transport_uncertainty_settles_only_when_event_and_absence_prove_apply(self) -> None:
        device = FakeDevice()
        device.action_transport = "applied_uncertain"
        result = self.run_recovery(device)
        self.assertEqual(result["result"], "RECOVERED_CLEANLY")
        self.assertEqual(sum(value.startswith("send:") for value in device.mutations), 1)
        blocked = FakeDevice()
        blocked.action_transport = "unapplied"
        with self.assertRaisesRegex(recovery.RecoveryError, "accepted-abort/released"):
            self.run_recovery(blocked)
        self.assertEqual(sum(value.startswith("send:") for value in blocked.mutations), 1)

    def test_delete_transport_uncertainty_never_retries(self) -> None:
        device = FakeDevice()
        device.remove_transport[recovery.QUARANTINE_MARK] = "applied_uncertain"
        self.run_recovery(device)
        self.assertEqual(device.mutations.count(
            "remove:" + recovery.QUARANTINE_MARK), 1)
        blocked = FakeDevice()
        blocked.remove_transport[recovery.QUARANTINE_MARK] = "unapplied"
        with self.assertRaisesRegex(recovery.RecoveryError, "refusing to retry"):
            self.run_recovery(blocked)
        self.assertEqual(blocked.mutations.count(
            "remove:" + recovery.QUARANTINE_MARK), 1)
        self.assertNotIn("move:" + alpha.TARGET_PDF + "->" +
                         recovery.QUARANTINE_PDF, blocked.mutations)

    def test_device_package_process_and_file_identity_drifts_fail_closed(self) -> None:
        cases = {
            "serial": lambda d: setattr(d, "serial", "OTHER"),
            "model": lambda d: setattr(d, "model", "OTHER"),
            "firmware": lambda d: setattr(d, "fingerprint", "OTHER"),
            "host version": lambda d: setattr(d, "host_version", ("3", "other")),
            "host apk": lambda d: setattr(d, "host_apk_hash", "0" * 64),
            "host pid start": lambda d: setattr(d, "host_start_ticks", 999999),
            "host uid": lambda d: setattr(d, "host_uid", HOST_UID + 1),
            "rotation settings": lambda d: setattr(d, "rotation", ("0", "2")),
            "physical rotation": lambda d: setattr(d, "physical_rotation", 4),
            "display": lambda d: setattr(d, "display_present", False),
            "target object": lambda d: d.files.__setitem__(
                alpha.TARGET_PDF, replace(d.files[alpha.TARGET_PDF], inode=999)),
            "target hash": lambda d: d.files.__setitem__(
                alpha.TARGET_MARK, replace(d.files[alpha.TARGET_MARK], sha256="0" * 64)),
            "source": lambda d: d.files.__setitem__(
                alpha.SOURCE_PDF, replace(
                    d.files[alpha.SOURCE_PDF], sha256="2" * 64)),
            "parking mark": lambda d: d.files.__setitem__(
                alpha.PARKING_MARK, file(alpha.PARKING_MARK, "1" * 64, 777)),
            "supervisor pair": lambda d: setattr(d, "malformed_display_pair", True),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                device = FakeDevice()
                mutate(device)
                with self.assertRaises((recovery.RecoveryError,
                                        alpha.AlphaError, Exception)):
                    self.run_recovery(device)
                self.assertFalse(any(value.startswith("send:") for value in device.mutations))

    def test_document_presence_and_target_fd_holders_block_mutation(self) -> None:
        document = FakeDevice()
        document.document_present = True
        with self.assertRaisesRegex(Exception, "Document"):
            self.run_recovery(document)
        self.assertEqual(document.mutations, [])
        holder = FakeDevice()
        holder.fd_targets.append(alpha.TARGET_MARK)
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "descriptor authority"):
            self.run_recovery(holder)
        self.assertNotIn("remove:" + alpha.TARGET_MARK, holder.mutations)

    def test_idle_zero_descriptor_authority_completes_and_is_fully_journaled(self) -> None:
        device = FakeDevice()
        device.fd_targets = []
        result = self.run_recovery(device)
        self.assertEqual(result["result"], "RECOVERED_CLEANLY")
        proofs = [item for item in result["proofs"]
                  if item["kind"] == "target_fds_absent"]
        self.assertGreater(len(proofs), 2)
        for proof in proofs:
            authority = proof["descriptorAuthority"]
            self.assertEqual(authority["mode"],
                             recovery.DESCRIPTOR_AUTHORITY_IDLE_ZERO)
            self.assertEqual(len(authority["observations"]), 2)
            for observation in authority["observations"]:
                self.assertEqual(observation["relevantTargets"], [])
                self.assertIs(observation["documentTaskWindowAbsent"], True)
                for name in ("activitiesSha256", "fdInventorySha256",
                             "windowsSha256"):
                    self.assertRegex(observation[name], r"^[0-9a-f]{64}$")
        mutation_records = [item for item in device.journal.records
                            if item["kind"] == "mutation_intent"]
        self.assertTrue(mutation_records)
        self.assertTrue(all(
            item["payload"]["descriptorAuthority"]["mode"] ==
            recovery.DESCRIPTOR_AUTHORITY_IDLE_ZERO
            for item in mutation_records))
        complete = next(
            item for item in device.journal.records
            if item["kind"] == "settlement" and
            item["payload"].get("kind") == "cleanup_complete")
        self.assertEqual(
            complete["payload"]["document"]["descriptorAuthority"]["mode"],
            recovery.DESCRIPTOR_AUTHORITY_IDLE_ZERO)

    def test_descriptor_authority_requires_stable_process_mode_and_no_document_scope(self) -> None:
        scoped = FakeDevice()
        scoped.fd_targets = []
        scoped.document_present = True
        with self.assertRaisesRegex(recovery.RecoveryError, "task or window"):
            self.run_recovery(scoped)
        self.assertEqual(scoped.mutations, [])

        process_drift = FakeDevice()
        original_identity = process_drift.process_identity
        document_calls = 0

        def drift_process(pid: int, package: str) -> host.ProcessIdentity:
            nonlocal document_calls
            value = original_identity(pid, package)
            if package == alpha.DOCUMENT_PACKAGE:
                document_calls += 1
                if document_calls == 3:
                    return replace(value, start_ticks=value.start_ticks + 1)
            return value

        process_drift.process_identity = drift_process  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "PID/start/UID changed"):
            self.run_recovery(process_drift)
        self.assertEqual(process_drift.mutations, [])

        mode_drift = FakeDevice()
        inventories = iter((
            "total 0\nlr-x------ 1 system system 64 2026-09-16 12:00 0 -> /dev/null\n",
            "total 0\nlr-x------ 1 system system 64 2026-09-16 12:00 0 -> " +
            alpha.PARKING_PDF + "\n",
        ))
        mode_drift.process_fd_links = lambda pid: next(inventories)  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "changed across observations"):
            self.run_recovery(mode_drift)
        self.assertEqual(mode_drift.mutations, [])

    def test_descriptor_inventory_is_structural_and_rejects_every_foreign_document(self) -> None:
        malformed = (
            "",
            "garbage\n",
            "warning: permission denied\n",
            "total 0\n",
            "lr-x------ 1 system system 64 2026-09-16 12:00 0 ->\n",
            "\x00",
            "x" * (alpha.MAX_TEXT_BYTES + 1),
        )
        for ordinal, value in enumerate(malformed):
            with self.subTest(malformed=ordinal):
                device = FakeDevice()
                device.process_fd_links = lambda pid, value=value: value  # type: ignore[method-assign]
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

        for target in (
                alpha.TARGET_PDF, alpha.TARGET_MARK,
                "/storage/emulated/0/Other.pdf",
                "/storage/emulated/0/Other.pdf.mark",
                alpha.PARKING_PDF + " (deleted)"):
            with self.subTest(target=target):
                device = FakeDevice()
                inventory = (
                    "total 0\n"
                    "lr-x------ 1 system system 64 2026-09-16 12:00 0 -> " +
                    target + "\n")
                device.process_fd_links = lambda pid, value=inventory: value  # type: ignore[method-assign]
                with self.assertRaisesRegex(recovery.RecoveryError,
                                            "descriptor authority"):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

    def test_durable_intent_reproves_descriptor_static_and_target_authority(self) -> None:
        descriptor_drift = FakeDevice()
        original_record = descriptor_drift.journal.record

        def drift_after_intent(kind: str,
                               payload: dict[str, object]) -> dict[str, object]:
            result = original_record(kind, payload)
            if kind == "mutation_intent":
                descriptor_drift.fd_targets = []
            return result

        descriptor_drift.journal.record = drift_after_intent  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "mode changed during recovery"):
            self.run_recovery(descriptor_drift)
        self.assertNotIn("refocus", descriptor_drift.mutations)

        static_drift = FakeDevice()
        static_record = static_drift.journal.record

        def drift_static_after_intent(
                kind: str, payload: dict[str, object]) -> dict[str, object]:
            result = static_record(kind, payload)
            if kind == "mutation_intent":
                static_drift.files[alpha.SOURCE_PDF] = replace(
                    static_drift.files[alpha.SOURCE_PDF], inode=999)
            return result

        static_drift.journal.record = drift_static_after_intent  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "source/parking object changed"):
            self.run_recovery(static_drift)
        self.assertNotIn("refocus", static_drift.mutations)

    def test_execute_descriptor_mode_is_pinned_to_read_only_admission(self) -> None:
        device = FakeDevice()
        device.fd_targets = []
        runner = recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None, journal=device.journal,
            expected_descriptor_authority=self.descriptor_authority(),
            **self.execute_identities(device))
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "differs from read-only admission"):
            runner.run(execute=True)
        self.assertEqual(device.mutations, [])

    def test_protocol_sequence_drift_and_wrong_state_fail_before_abort(self) -> None:
        for event, detail in (
                ("COMMAND_REJECTED", "reason=sequence readiness=FAILED"),
                ("READY", "foreignPackage=com.supernote.document readiness=ACTIVE"),
                ("REFOCUS", "readiness=ACTIVE")):
            with self.subTest(event=event):
                device = FakeDevice()
                device.logs = device._line(event, detail)
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertFalse(any(value.startswith("send:")
                                     for value in device.mutations))

    def test_post_refocus_identity_drift_or_missing_event_fails_closed(self) -> None:
        drift = FakeDevice()
        original_start = drift.start_host
        def changed_start() -> None:
            original_start()
            drift.host_start_ticks += 1
        drift.start_host = changed_start  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError, "process identity"):
            self.run_recovery(drift)
        self.assertFalse(any(value.startswith("send:") for value in drift.mutations))
        no_refocus = FakeDevice()
        no_refocus.omit_refocus_log = True
        with self.assertRaisesRegex(recovery.RecoveryError, "fresh exact FAILED"):
            self.run_recovery(no_refocus)
        no_accept = FakeDevice()
        no_accept.omit_accept_event = True
        with self.assertRaisesRegex(recovery.RecoveryError, "accepted-abort/released"):
            self.run_recovery(no_accept)

        display_drift = FakeDevice()
        original_display_start = display_drift.start_host
        def drift_display() -> None:
            original_display_start()
            mutated = REAL_DISPLAY_AUTHORITY.replace(
                b"android.os.BinderProxy@ab87ef8",
                b"android.os.BinderProxy@ab87ef9")
            display_drift.displays = lambda: mutated  # type: ignore[method-assign]
        display_drift.start_host = drift_display  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError, "identity changed"):
            self.run_recovery(display_drift)
        self.assertFalse(any(value.startswith("send:")
                             for value in display_drift.mutations))

    def test_document_process_and_rotation_are_rechecked_before_ack(self) -> None:
        process_drift = FakeDevice()
        original_start = process_drift.start_host
        def drift_document() -> None:
            original_start()
            process_drift.document_start_ticks += 1
        process_drift.start_host = drift_document  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError, "Document PID/start"):
            self.run_recovery(process_drift)
        self.assertFalse(any(value.startswith("send:")
                             for value in process_drift.mutations))
        rotation_drift = FakeDevice()
        original_rotation_start = rotation_drift.start_host
        def drift_rotation() -> None:
            original_rotation_start()
            rotation_drift.rotation = ("0", "2")
        rotation_drift.start_host = drift_rotation  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError, "rotation settings"):
            self.run_recovery(rotation_drift)
        self.assertFalse(any(value.startswith("send:")
                             for value in rotation_drift.mutations))

    def test_file_replacement_between_ordered_deletes_blocks_pdf_delete(self) -> None:
        device = FakeDevice()
        original_remove = device.remove_quarantine
        def mutate_after_mark(path: str) -> None:
            original_remove(path)
            if path == recovery.QUARANTINE_MARK:
                device.files[alpha.TARGET_PDF] = replace(
                    device.files[alpha.TARGET_PDF], inode=999)
        device.remove_quarantine = mutate_after_mark  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError, "object/hash changed"):
            self.run_recovery(device)
        self.assertEqual(device.mutations.count(
            "remove:" + recovery.QUARANTINE_MARK), 1)
        self.assertNotIn("move:" + alpha.TARGET_PDF + "->" +
                         recovery.QUARANTINE_PDF, device.mutations)

    def test_host_task_activity_window_identity_is_exact_and_stable(self) -> None:
        admission_cases = {
            "wrong window display": lambda d: setattr(d, "host_window_display", 1),
            "invisible window": lambda d: setattr(d, "host_visible", False),
            "activity token mismatch": lambda d: setattr(
                d, "host_activity_token", "abcdef0"),
        }
        for name, mutate in admission_cases.items():
            with self.subTest(name=name):
                device = FakeDevice()
                mutate(device)
                if name == "activity token mismatch":
                    # A window bound to a different token from the resumed
                    # Activity is an independent mismatch.
                    original = device.windows
                    device.windows = lambda: live_windows(  # type: ignore[method-assign]
                        activity_token="1b5aca8")
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

        for field, changed in (
                ("host_task_id", 4636),
                ("host_task_token", "7e5e3c1"),
                ("host_activity_token", "2b5aca8"),
                ("host_window_token", "aca0b11")):
            with self.subTest(post_refocus=field):
                device = FakeDevice()
                original = device.start_host
                def drift(field: str = field, changed: object = changed) -> None:
                    original()
                    setattr(device, field, changed)
                device.start_host = drift  # type: ignore[method-assign]
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "identity changed|resumed activity|focus|session owner"):
                    self.run_recovery(device)
                self.assertFalse(any(value.startswith("send:")
                                     for value in device.mutations))

        duplicate = FakeDevice()
        original_activities = duplicate.activities
        def duplicated_activity() -> bytes:
            raw = original_activities()
            marker = (b"    * Task{6e5e3c1 #4635 visible=true type=standard "
                      b"mode=fullscreen A=10142:com.techrebbe.supernote.nativepagehost "
                      b"U=0 StackId=4635 sz=1}\n")
            return raw.replace(marker, marker + marker, 1)
        duplicate.activities = duplicated_activity  # type: ignore[method-assign]
        with self.assertRaises(recovery.RecoveryError):
            self.run_recovery(duplicate)

        # The retained firmware emits the canonical Task once as ``* Task``
        # and then repeats the exact same Task identity in detail references.
        # Those references are not additional tasks and must be admitted.
        same_task_reference = FakeDevice()
        canonical_task = (
            b"    * Task{6e5e3c1 #4635 visible=true type=standard "
            b"mode=fullscreen A=10142:com.techrebbe.supernote.nativepagehost "
            b"U=0 StackId=4635 sz=1}\n")
        legitimate_reference = (
            b"      rootOfTask=true task=Task{6e5e3c1 #4635 visible=true "
            b"type=standard mode=fullscreen "
            b"A=10142:com.techrebbe.supernote.nativepagehost "
            b"U=0 StackId=4635 sz=1}\n")
        base_same_task = same_task_reference.activities
        same_task_reference.activities = lambda: base_same_task().replace(  # type: ignore[method-assign]
            canonical_task, canonical_task + legitimate_reference, 1)
        result = self.run_recovery(same_task_reference, execute=False)
        self.assertEqual(result["result"], "PLAN_REFOCUS_REQUIRED")
        self.assertEqual(same_task_reference.mutations, [])

        embedded_reference_mutations = {
            "different task token": legitimate_reference.replace(
                b"Task{6e5e3c1", b"Task{badcafe", 1),
            "different task id": legitimate_reference.replace(
                b"#4635", b"#4636", 1),
            "alternate task component": legitimate_reference.replace(
                b"U=0 StackId=4635",
                b"realActivity=com.techrebbe.supernote.nativepagehost/.AlternateActivity "
                b"U=0 StackId=4635", 1),
            "malformed unclosed task": legitimate_reference.replace(
                b" sz=1}", b" sz=1", 1),
        }
        for name, embedded_reference in embedded_reference_mutations.items():
            with self.subTest(embedded_task_reference=name):
                device = FakeDevice()
                original = device.activities
                device.activities = lambda embedded_reference=embedded_reference: (  # type: ignore[method-assign]
                    original().replace(
                        canonical_task,
                        canonical_task + embedded_reference,
                        1))
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

        # ActivityManager likewise repeats the one canonical activity in
        # detail collections.  The exact same identity is a reference, not a
        # second activity instance.
        same_activity_reference = FakeDevice()
        canonical_history = (
            b"      * Hist #0: ActivityRecord{1b5aca8 u0 "
            b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
            b"t4635}\n")
        legitimate_activity_reference = (
            b"      Activities=[ActivityRecord{1b5aca8 u0 "
            b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
            b"t4635}]\n")
        base_same_activity = same_activity_reference.activities
        same_activity_reference.activities = lambda: base_same_activity().replace(  # type: ignore[method-assign]
            canonical_history,
            canonical_history + legitimate_activity_reference,
            1)
        result = self.run_recovery(same_activity_reference, execute=False)
        self.assertEqual(result["result"], "PLAN_REFOCUS_REQUIRED")
        self.assertEqual(same_activity_reference.mutations, [])

        # The live firmware's detailed ActivityRecord block contains many
        # package-bearing metadata lines.  None starts a Task, ActivityRecord,
        # or Window structural identity and none represents another scope.
        live_detail_metadata = (
            b"      packageName=com.techrebbe.supernote.nativepagehost "
            b"processName=com.techrebbe.supernote.nativepagehost\n"
            b"      affinity=10142:com.techrebbe.supernote.nativepagehost\n"
            b"      intent={flg=0x10000000 cmp="
            b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity}\n"
            b"      mActivityComponent="
            b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity\n"
            b"      baseDir=/data/app/com.techrebbe.supernote.nativepagehost/base.apk\n"
            b"      dataDir=/data/user/0/com.techrebbe.supernote.nativepagehost\n"
            b"      app=ProcessRecord{abcd123 8758:"
            b"com.techrebbe.supernote.nativepagehost/u0a10142}\n"
            b"      taskAffinity=10142:com.techrebbe.supernote.nativepagehost\n")
        detailed_activity = FakeDevice()
        base_detailed_activity = detailed_activity.activities
        detailed_activity.activities = lambda: base_detailed_activity().replace(  # type: ignore[method-assign]
            canonical_history,
            canonical_history + live_detail_metadata,
            1)
        result = self.run_recovery(detailed_activity, execute=False)
        self.assertEqual(result["result"], "PLAN_REFOCUS_REQUIRED")
        self.assertEqual(detailed_activity.mutations, [])

        malformed_structural_details = {
            "unclosed activity after metadata": live_detail_metadata +
                b"      Activities=[ActivityRecord{1b5aca8 u0 "
                b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
                b"t4635]\n",
            "unclosed task after metadata": live_detail_metadata +
                b"      rootOfTask=true task=Task{6e5e3c1 #4635 "
                b"A=10142:com.techrebbe.supernote.nativepagehost\n",
            "unclosed window after metadata": live_detail_metadata +
                b"      parent=Window{f5d3f4a u0 "
                b"com.techrebbe.supernote.nativepagehost/"
                b"com.techrebbe.supernote.nativepagehost.NativePageHostActivity\n",
        }
        for name, detail in malformed_structural_details.items():
            with self.subTest(malformed_structural_detail=name):
                device = FakeDevice()
                original = device.activities
                device.activities = lambda detail=detail: original().replace(  # type: ignore[method-assign]
                    canonical_history,
                    canonical_history + detail,
                    1)
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "malformed host-package structural residue"):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

        embedded_activity_mutations = {
            "different activity token": legitimate_activity_reference.replace(
                b"ActivityRecord{1b5aca8", b"ActivityRecord{badcafe", 1),
            "different activity user": legitimate_activity_reference.replace(
                b" u0 ", b" u10 ", 1),
            "different activity task": legitimate_activity_reference.replace(
                b" t4635}", b" t4636}", 1),
            "alternate activity component": legitimate_activity_reference.replace(
                b"/.NativePageHostActivity", b"/.AlternateActivity", 1),
            "malformed unclosed activity": legitimate_activity_reference.replace(
                b" t4635}]", b" t4635]", 1),
        }
        for name, embedded_reference in embedded_activity_mutations.items():
            with self.subTest(embedded_activity_reference=name):
                device = FakeDevice()
                original = device.activities
                device.activities = lambda embedded_reference=embedded_reference: (  # type: ignore[method-assign]
                    original().replace(
                        canonical_history,
                        canonical_history + embedded_reference,
                        1))
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

        base_activity = live_activities()
        activity_mutations = {
            "focus token": base_activity.replace(b"mCurrentFocus=Window{f5d3f4a", b"mCurrentFocus=Window{deadbee", 1),
            "focus suffix": base_activity.replace(
                b"NativePageHostActivity}\n  mFocusedApp",
                b"NativePageHostActivity}extra\n  mFocusedApp", 1),
            "focused task": base_activity.replace(
                b"NativePageHostActivity t4635}\n  mLastOrientationSource",
                b"NativePageHostActivity t4636}\n  mLastOrientationSource", 1),
            "duplicate focus": base_activity.replace(
                b"  mCurrentFocus=Window{f5d3f4a",
                b"  mCurrentFocus=Window{f5d3f4a u0 " +
                alpha.HOST_COMPONENT.encode() + b"}\n  mCurrentFocus=Window{f5d3f4a", 1),
            "borrowed display focus": base_activity.replace(
                b"  mCurrentFocus=null\n  mFocusedApp=null",
                b"  mCurrentFocus=Window{f5d3f4a u0 " +
                alpha.HOST_COMPONENT.encode() +
                b"}\n  mFocusedApp=ActivityRecord{1b5aca8 u0 "
                b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity t4635}", 1),
            "hidden host task": base_activity.replace(
                b"Display #1 (activities from top to bottom):",
                b"    * Task{badcafe #4636 visible=false type=standard "
                b"mode=fullscreen A=10142:com.techrebbe.supernote.nativepagehost "
                b"U=0 StackId=4636 sz=0}\n"
                b"Display #1 (activities from top to bottom):", 1),
            "hidden host activity": base_activity.replace(
                b"Display #1 (activities from top to bottom):",
                b"      * Hist #1: ActivityRecord{badcafe u0 "
                b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
                b"t4636}\nDisplay #1 (activities from top to bottom):", 1),
            "supervisor hidden host scope": base_activity.replace(
                b"  Display: mDisplayId=1 stacks=0",
                b"      * Task{badcafe #4636 visible=false "
                b"A=10142:com.techrebbe.supernote.nativepagehost sz=1}\n"
                b"        * ActivityRecord{badcafe u0 "
                b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
                b"t4636}\n  Display: mDisplayId=1 stacks=0", 1),
            "supervisor alternate host activity": base_activity.replace(
                b"  Display: mDisplayId=1 stacks=0",
                b"        * ActivityRecord{1b5aca8 u0 "
                b"com.techrebbe.supernote.nativepagehost/.AlternateActivity "
                b"t4635}\n  Display: mDisplayId=1 stacks=0", 1),
            "supervisor alternate host activity without task suffix":
                base_activity.replace(
                    b"  Display: mDisplayId=1 stacks=0",
                    b"        * ActivityRecord{1b5aca8 u0 "
                    b"com.techrebbe.supernote.nativepagehost/.AlternateActivity}\n"
                    b"  Display: mDisplayId=1 stacks=0", 1),
            "malformed unclosed host activity reference":
                base_activity.replace(
                    b"  Display: mDisplayId=1 stacks=0",
                    b"        * ActivityRecord{1b5aca8 u0 "
                    b"com.techrebbe.supernote.nativepagehost/.AlternateActivity\n"
                    b"  Display: mDisplayId=1 stacks=0", 1),
            "malformed unclosed host task reference": base_activity.replace(
                b"  Display: mDisplayId=1 stacks=0",
                b"      * Task{badcafe #4636 visible=false "
                b"A=10142:com.techrebbe.supernote.nativepagehost\n"
                b"  Display: mDisplayId=1 stacks=0", 1),
            "supervisor alternate host task component": base_activity.replace(
                b"  Display: mDisplayId=1 stacks=0",
                b"      * Task{6e5e3c1 #4635 visible=true "
                b"A=10142:com.techrebbe.supernote.nativepagehost "
                b"realActivity=com.techrebbe.supernote.nativepagehost/.AlternateActivity "
                b"sz=1}\n  Display: mDisplayId=1 stacks=0", 1),
        }
        for name, mutated in activity_mutations.items():
            with self.subTest(activity_mutation=name):
                device = FakeDevice()
                device.activities = lambda mutated=mutated: mutated  # type: ignore[method-assign]
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)

        base_window = live_windows()
        window_mutations = {
            "session uid": base_window.replace(b"u0a10142", b"u0a10143", 1),
            "session pid": base_window.replace(b"8758:u0a", b"8759:u0a", 1),
            "root task": base_window.replace(b"rootTaskId=4635", b"rootTaskId=4636", 1),
            "token": base_window.replace(b"mToken=ActivityRecord{1b5aca8", b"mToken=ActivityRecord{deadbee", 1),
            "activity record": base_window.replace(
                b"mActivityRecord=ActivityRecord{1b5aca8",
                b"mActivityRecord=ActivityRecord{deadbee", 1),
            "surface": base_window.replace(b"mHasSurface=true", b"mHasSurface=false", 1),
            "visible": base_window.replace(b"isVisible=true", b"isVisible=false", 1),
            "alternate package window": base_window +
                b"  Window #6 Window{deadbee u0 "
                b"com.techrebbe.supernote.nativepagehost/"
                b"com.techrebbe.supernote.nativepagehost.AlternateActivity}:\n"
                b"    mDisplayId=0 rootTaskId=4635\n",
            "alternate user package window": base_window +
                b"  Window #6 Window{deadbee u10 "
                b"com.techrebbe.supernote.nativepagehost/"
                b"com.techrebbe.supernote.nativepagehost.AlternateActivity}:\n"
                b"    mDisplayId=0 rootTaskId=4635\n",
            "malformed unclosed package window": base_window +
                b"  Window #6 Window{deadbee u10 "
                b"com.techrebbe.supernote.nativepagehost/"
                b"com.techrebbe.supernote.nativepagehost.AlternateActivity:\n"
                b"    mDisplayId=0 rootTaskId=4635\n",
        }
        for name, mutated in window_mutations.items():
            with self.subTest(window_mutation=name):
                device = FakeDevice()
                device.windows = lambda mutated=mutated: mutated  # type: ignore[method-assign]
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)

    def test_failed_abort_requires_ordered_unique_release_pair(self) -> None:
        cases = {
            "missing": lambda d: setattr(d, "omit_release_event", True),
            "reversed": lambda d: setattr(d, "reverse_release_events", True),
            "duplicate": lambda d: setattr(d, "duplicate_release_event", True),
            "display prefix": lambda d: setattr(d, "release_display", "10"),
            "mode suffix": lambda d: setattr(
                d, "release_mode", "acknowledged_cleanup_extra"),
            "digest suffix": lambda d: setattr(d, "digest_suffix", "0"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                device = FakeDevice()
                mutate(device)
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(sum(value.startswith("send:")
                                     for value in device.mutations), 1)
        failed = FakeDevice()
        original_send = failed.send_recovery
        def failed_release(*args, **kwargs) -> None:
            original_send(*args, **kwargs)
            failed.logs += failed._line("RELEASE_FAILED", "display=1")
        failed.send_recovery = failed_release  # type: ignore[method-assign]
        with self.assertRaises(recovery.RecoveryError):
            self.run_recovery(failed)

        base_abort = failed._line(
            recovery.EVENT_FAILED, "absenceEvidenceSha256=" + "a" * 64)
        for release_detail in (
                "display=10 mode=acknowledged_cleanup",
                "display=1 mode=acknowledged_cleanup_extra",
                "display=1 display=1 mode=acknowledged_cleanup"):
            with self.subTest(prior=release_detail):
                lines = recovery._identity_lines(
                    base_abort + failed._line(
                        recovery.EVENT_RELEASED, release_detail),
                    AUTHORITY.status)
                with self.assertRaises(recovery.RecoveryError):
                    recovery._validate_prior_failed_cleanup(lines)
        bad_digest = recovery._identity_lines(
            failed._line(
                recovery.EVENT_FAILED,
                "absenceEvidenceSha256=" + "a" * 64 + "0") +
            failed._line(recovery.EVENT_RELEASED,
                         "display=1 mode=acknowledged_cleanup"),
            AUTHORITY.status)
        with self.assertRaises(recovery.RecoveryError):
            recovery._validate_prior_failed_cleanup(bad_digest)

    def test_cleanup_event_grammar_is_closed_before_prior_or_fresh_acceptance(self) -> None:
        def exact_pair(device: FakeDevice) -> str:
            return (device._line(
                recovery.EVENT_FAILED,
                "absenceEvidenceSha256=" + "a" * 64) +
                device._line(
                    recovery.EVENT_RELEASED,
                    "display=1 mode=acknowledged_cleanup"))

        prior_extras = (
            ("READY", "readiness=ACTIVE"),
            ("EMPTY_PRE_ATTACH_ABORT", "absenceEvidenceSha256=" + "a" * 64),
            ("EMPTY_PRE_ATTACH_ABORT_REPLAY", "absenceEvidenceSha256=" + "a" * 64),
            ("EMPTY_ABORT_REPLAY", "absenceEvidenceSha256=" + "a" * 64),
            ("EMPTY_ATTACH_ABORT_REPLAY", "absenceEvidenceSha256=" + "a" * 64),
            ("DISPLAY_RELEASED_EXTRA", "display=1 mode=acknowledged_cleanup"),
            ("DISPLAY_RELEASED", "display=2 mode=acknowledged_cleanup"),
        )
        for event, detail in prior_extras:
            with self.subTest(prior_event=event, detail=detail):
                device = FakeDevice()
                device.logs = exact_pair(device) + device._line(event, detail)
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

        fresh_extras = (
            ("READY", "readiness=ACTIVE"),
            ("EMPTY_PRE_ATTACH_ABORT", "absenceEvidenceSha256=" + "b" * 64),
            ("EMPTY_ATTACH_ABORT_REPLAY", "absenceEvidenceSha256=" + "b" * 64),
            ("DISPLAY_RELEASED", "display=2 mode=acknowledged_cleanup"),
            ("DISPLAY_RELEASED_EXTRA", "display=1 mode=acknowledged_cleanup"),
        )
        for event, detail in fresh_extras:
            with self.subTest(fresh_event=event, detail=detail):
                device = FakeDevice()
                device.extra_action_logs.append((event, detail))
                with self.assertRaises(recovery.RecoveryError):
                    self.run_recovery(device)
                self.assertEqual(sum(value.startswith("send:")
                                     for value in device.mutations), 1)

    def test_identity_bound_logs_reject_duplicate_or_conflicting_tokens(self) -> None:
        base = ("I/NATIVE_PAGE_HOST: REFOCUS session=" +
                AUTHORITY.status.session + " generation=1 readiness=FAILED")
        variants = (
            base + " session=" + AUTHORITY.status.session,
            base + " session=00000000-0000-0000-0000-000000000000",
            base + " generation=1",
            base + " generation=2",
        )
        for line in variants:
            with self.subTest(line=line):
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "identity tokens"):
                    recovery._identity_lines(line, AUTHORITY.status)

        for field in (
                "session=" + AUTHORITY.status.session,
                "session=00000000-0000-0000-0000-000000000000",
                "generation=1", "generation=2"):
            with self.subTest(cleanup_field=field):
                device = FakeDevice()
                device.logs = device._line(
                    recovery.EVENT_FAILED,
                    "absenceEvidenceSha256=" + "a" * 64 + " " + field)
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "identity tokens"):
                    self.run_recovery(device)
                self.assertEqual(device.mutations, [])

    def test_late_cleanup_event_drift_blocks_files_for_fresh_and_prior_paths(self) -> None:
        late_events = (
            ("DISPLAY_RELEASED", "display=2 mode=acknowledged_cleanup"),
            ("EMPTY_PRE_ATTACH_ABORT", "absenceEvidenceSha256=" + "b" * 64),
            ("READY", "readiness=ACTIVE"),
        )
        for path in ("fresh", "prior"):
            for event, detail in late_events:
                with self.subTest(path=path, event=event):
                    device = FakeDevice()
                    if path == "prior":
                        device.logs = (device._line(
                            recovery.EVENT_FAILED,
                            "absenceEvidenceSha256=" + "a" * 64) +
                            device._line(
                                recovery.EVENT_RELEASED,
                                "display=1 mode=acknowledged_cleanup"))
                        device.settle_after_log = True
                    device.late_absence_logs.append((event, detail))
                    with self.assertRaises(recovery.RecoveryError):
                        self.run_recovery(device)
                    self.assertFalse(any(
                        value.startswith("move:") or value.startswith("remove:")
                        for value in device.mutations))

    def test_refocus_transport_uncertainty_is_settled_without_replay(self) -> None:
        applied = FakeDevice()
        applied.refocus_transport = "applied_uncertain"
        self.run_recovery(applied)
        self.assertEqual(applied.mutations.count("refocus"), 1)
        unapplied = FakeDevice()
        unapplied.refocus_transport = "unapplied"
        with self.assertRaisesRegex(recovery.RecoveryError, "fresh exact FAILED"):
            self.run_recovery(unapplied)
        self.assertEqual(unapplied.mutations.count("refocus"), 1)
        self.assertFalse(any(value.startswith("send:")
                             for value in unapplied.mutations))

    def test_quarantine_move_is_one_shot_and_race_safe(self) -> None:
        applied = FakeDevice()
        applied.move_transport[alpha.TARGET_MARK] = "applied_uncertain"
        self.run_recovery(applied)
        self.assertEqual(sum(value.startswith("move:" + alpha.TARGET_MARK)
                             for value in applied.mutations), 1)
        unapplied = FakeDevice()
        unapplied.move_transport[alpha.TARGET_MARK] = "unapplied"
        with self.assertRaises(recovery.RecoveryError):
            self.run_recovery(unapplied)
        self.assertEqual(sum(value.startswith("move:" + alpha.TARGET_MARK)
                             for value in unapplied.mutations), 1)
        self.assertNotIn("remove:" + recovery.QUARANTINE_MARK,
                         unapplied.mutations)

        raced = FakeDevice()
        raced.files[recovery.QUARANTINE_MARK] = file(
            recovery.QUARANTINE_MARK, "f" * 64, 999, size=12)
        with self.assertRaisesRegex(recovery.RecoveryError, "both occupied"):
            self.run_recovery(raced)
        self.assertFalse(any(value.startswith("move:" + alpha.TARGET_MARK)
                             for value in raced.mutations))

        preexisting = FakeDevice()
        preexisting.host_live = False
        preexisting.display_present = False
        retained = preexisting.files.pop(alpha.TARGET_MARK)
        preexisting.files[recovery.QUARANTINE_MARK] = replace(
            retained, path=recovery.QUARANTINE_MARK)
        self.run_recovery(preexisting)
        self.assertNotIn("move:" + alpha.TARGET_MARK + "->" +
                         recovery.QUARANTINE_MARK, preexisting.mutations)
        self.assertEqual(preexisting.mutations.count(
            "remove:" + recovery.QUARANTINE_MARK), 1)

    def test_report_descriptor_rejects_symlink_and_opened_object_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_bytes(REPORT.read_bytes())
            link = root / "report.json"
            try:
                link.symlink_to(target)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(recovery.RecoveryError, "non-symlink"):
                    recovery.load_report(link)

            report = root / "report.json"
            if report.exists() or report.is_symlink():
                report.unlink()
            report.write_bytes(REPORT.read_bytes())
            other = root / "other.json"
            other.write_bytes(b"{}")
            descriptor = recovery.os.open(other, recovery.os.O_RDONLY)
            with mock.patch.object(recovery.os, "open", return_value=descriptor):
                with self.assertRaisesRegex(recovery.RecoveryError, "descriptor open"):
                    recovery.load_report(report)

    def test_adb_identity_drift_blocks_every_mutation(self) -> None:
        before = FakeDevice()
        before.adb["sha256"] = "0" * 64
        with self.assertRaisesRegex(recovery.RecoveryError, "exact host pin"):
            self.run_recovery(before)
        # Also drift only after admission to prove per-mutation revalidation.
        device = FakeDevice()
        original = device.start_host
        def drift_adb() -> None:
            original()
            device.adb["sha256"] = "0" * 64
        device.start_host = drift_adb  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError, "adb executable"):
            self.run_recovery(device)
        self.assertFalse(any(value.startswith("send:")
                             for value in device.mutations))

    def test_header_tool_identity_replacement_blocks_before_rotation(self) -> None:
        for tool in ("helper", "adb"):
            with self.subTest(tool=tool):
                device = FakeDevice()
                identities = self.execute_identities(device)
                if tool == "helper":
                    header = dict(identities["header_helper_identity"])
                    header["inode"] += 1
                    identities["header_helper_identity"] = header
                else:
                    header = dict(identities["header_adb_identity"])
                    header["inode"] += 1
                    identities["header_adb_identity"] = header
                runner = recovery.Recovery(
                    device, AUTHORITY, sleep=lambda _: None,
                    journal=device.journal, **identities)
                with self.assertRaisesRegex(
                        recovery.RecoveryError,
                        "helper source|adb executable"):
                    runner.run(execute=True)
                self.assertEqual(device.mutations, [])

    def test_adb_replacement_after_lock_zero_never_executes_through_replacement(self) -> None:
        device = FakeDevice()
        original_lock = device.lock_rotation_zero

        def replace_after_lock() -> None:
            original_lock()
            device.adb["inode"] += 1

        device.lock_rotation_zero = replace_after_lock  # type: ignore[method-assign]
        runner = recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None, journal=device.journal,
            **self.execute_identities(device))
        with self.assertRaisesRegex(
                recovery.RecoveryError, "adb executable identity"):
            runner.run(execute=True)
        self.assertEqual(device.mutations, ["rotation:lock0"])
        self.assertEqual(
            runner.evidence["result"],
            "CLEANUP_FAILED_ROTATION_RESTORE_FAILED")

    def test_restore_only_recovers_after_exact_adb_identity_returns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / recovery.CANONICAL_JOURNAL_BASENAME
            device = FakeDevice()
            original_adb = dict(device.adb)
            journal = recovery.DurableJournal(
                journal_path, self.restore_header())
            runner = recovery.Recovery(
                device, AUTHORITY, sleep=lambda _: None, journal=journal,
                **self.execute_identities(device))
            original_lock = device.lock_rotation_zero

            def replace_after_lock() -> None:
                original_lock()
                device.adb["inode"] += 1

            device.lock_rotation_zero = replace_after_lock  # type: ignore[method-assign]
            with self.assertRaises(recovery.RecoveryError):
                runner.run(execute=True)
            journal.close()
            self.assertEqual(device.mutations, ["rotation:lock0"])

            device.adb = original_adb
            reservation = recovery.EvidenceReservation(root / "restore.json")
            args = argparse.Namespace(adb=recovery.PINNED_ADB_PATH)
            try:
                with mock.patch.object(
                        recovery, "RecoveryNomad", return_value=device):
                    code = recovery._run_reserved_restore_only(
                        args, AUTHORITY, journal_path, reservation)
            finally:
                reservation.close()
            self.assertEqual(code, 0)
            self.assertEqual(device.mutations,
                             ["rotation:lock0", "rotation:lock2",
                              "rotation:free"])
            self.assertEqual(device.rotation, ("1", "2"))

    def test_journal_chain_detects_removal_reorder_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.jsonl"
            journal = recovery.DurableJournal(path, {"authority": "test"})
            journal.record("mutation_intent", {"n": 1})
            journal.record("settlement", {"n": 1})
            journal.close()
            lines = path.read_bytes().splitlines(keepends=True)
            recovery.validate_journal_bytes(b"".join(lines))
            variants = (
                b"".join((lines[0], lines[2])),
                b"".join((lines[0], lines[2], lines[1])),
                b"".join(lines).replace(b'"n":1', b'"n":2', 1),
            )
            for raw in variants:
                with self.assertRaises(recovery.RecoveryError):
                    recovery.validate_journal_bytes(raw)

    def test_durable_journal_loops_short_writes_and_poisons_partial_appends(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            success = recovery.DurableJournal(
                root / "short.jsonl", {"authority": "test"})
            success._stream = BoundedShortWriteStream(  # type: ignore[attr-defined]
                success._stream, 7)  # type: ignore[attr-defined]
            success.record("settlement", {"value": "complete"})
            success.close()
            self.assertEqual(
                recovery.validate_journal_bytes(
                    (root / "short.jsonl").read_bytes())[0], 2)

            payloads = {
                "rotation_lock_intent": {"authority": "lease"},
                "rotation_lock_settlement": {"authority": "lease"},
                "mutation_intent": {"authority": "cleanup"},
                "rotation_restore_intent": {"authority": "lease"},
                "settlement": {"authority": "cleanup"},
            }
            for ordinal, (kind, payload) in enumerate(payloads.items()):
                with self.subTest(kind=kind):
                    path = root / f"partial-{ordinal}.jsonl"
                    journal = recovery.DurableJournal(
                        path, {"authority": "test"})
                    before_count = journal.count
                    before_head = journal.head_hash
                    journal._stream = PartialThenCrashStream(  # type: ignore[attr-defined]
                        journal._stream, 23)  # type: ignore[attr-defined]
                    with self.assertRaisesRegex(OSError, "append crash"):
                        journal.record(kind, payload)
                    self.assertEqual(journal.count, before_count)
                    self.assertEqual(journal.head_hash, before_head)
                    after_failure_size = recovery.os.fstat(
                        journal._stream.fileno()).st_size  # type: ignore[attr-defined]
                    with self.assertRaisesRegex(
                            recovery.RecoveryError, "poisoned"):
                        journal.record("settlement", {"must": "not append"})
                    self.assertEqual(
                        recovery.os.fstat(
                            journal._stream.fileno()).st_size,  # type: ignore[attr-defined]
                        after_failure_size)
                    journal.close()
                    raw = path.read_bytes()
                    self.assertFalse(raw.endswith(b"\n"))
                    self.assertEqual(raw.count(b"\n"), 1)

    def test_full_write_flush_and_fsync_failures_poison_without_chain_advance(self) -> None:
        failures: tuple[tuple[str, BaseException], ...] = (
            ("flush", OSError("injected flush failure")),
            ("base", KeyboardInterrupt("injected interruption")),
        )
        for label, error in failures:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "flush.jsonl"
                journal = recovery.DurableJournal(
                    path, {"authority": "test"})
                before_count, before_head = journal.count, journal.head_hash
                journal._stream = FullWriteFlushCrashStream(  # type: ignore[attr-defined]
                    journal._stream, error)  # type: ignore[attr-defined]
                with self.assertRaises(type(error)):
                    journal.record("settlement", {"authority": "test"})
                self.assertEqual((journal.count, journal.head_hash),
                                 (before_count, before_head))
                uncertain_size = recovery.os.fstat(
                    journal._stream.fileno()).st_size  # type: ignore[attr-defined]
                with self.assertRaisesRegex(recovery.RecoveryError, "poisoned"):
                    journal.record("settlement", {"retry": True})
                self.assertEqual(
                    recovery.os.fstat(
                        journal._stream.fileno()).st_size,  # type: ignore[attr-defined]
                    uncertain_size)
                journal.close()
                raw = path.read_bytes()
                # A full newline-terminated append with uncertain durability is
                # valid authority after a crash if the bytes actually survived.
                self.assertEqual(recovery.validate_journal_bytes(raw)[0], 2)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fsync.jsonl"
            journal = recovery.DurableJournal(path, {"authority": "test"})
            before_count, before_head = journal.count, journal.head_hash
            with mock.patch.object(
                    recovery.os, "fsync",
                    side_effect=OSError("injected fsync failure")):
                with self.assertRaisesRegex(OSError, "fsync failure"):
                    journal.record("settlement", {"authority": "test"})
            self.assertEqual((journal.count, journal.head_hash),
                             (before_count, before_head))
            uncertain_size = recovery.os.fstat(
                journal._stream.fileno()).st_size  # type: ignore[attr-defined]
            with self.assertRaisesRegex(recovery.RecoveryError, "poisoned"):
                journal.record("settlement", {"retry": True})
            self.assertEqual(
                recovery.os.fstat(
                    journal._stream.fileno()).st_size,  # type: ignore[attr-defined]
                uncertain_size)
            journal.close()
            raw = path.read_bytes()
            self.assertEqual(recovery.validate_journal_bytes(raw)[0], 2)

    def test_partial_header_never_advances_authority_or_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "header-partial.jsonl"
            real_open = Path.open

            def partial_open(target: Path, *args: object,
                             **kwargs: object) -> PartialThenCrashStream:
                return PartialThenCrashStream(
                    real_open(target, *args, **kwargs), 17)

            with mock.patch.object(Path, "open", new=partial_open):
                with self.assertRaisesRegex(OSError, "append crash"):
                    recovery.DurableJournal(path, self.restore_header())
            self.assertTrue(path.exists())
            self.assertNotIn(b"\n", path.read_bytes())
            fake = FakeDevice()
            self.assertEqual(fake.rotation, ("1", "2"))
            self.assertEqual(fake.mutations, [])
            with self.assertRaises(recovery.RecoveryError):
                recovery._parse_journal_prefix(
                    path.read_bytes(), allow_torn_final=True)

    def test_header_only_and_torn_lock_intent_are_retired_without_device_mutation(self) -> None:
        _, helper = recovery._read_pinned_regular(
            Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
            "recovery helper")
        for torn in (b"", b'{"kind":"rotation_lock_int'):
            with self.subTest(torn=torn), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "no-attempt.jsonl"
                journal = recovery.DurableJournal(path, self.restore_header())
                journal.close()
                if torn:
                    with path.open("ab", buffering=0) as stream:
                        stream.write(torn)
                records, _, observed = recovery._parse_journal_prefix(
                    path.read_bytes(), allow_torn_final=True)
                self.assertEqual(observed, torn)
                state = recovery._validate_restore_journal(
                    records, AUTHORITY, helper)
                self.assertTrue(state["noAttempt"])
                fake = FakeDevice()
                fake.physical_rotation = 2 if torn else 0
                original = path.read_bytes()
                reservation = recovery.EvidenceReservation(
                    Path(directory) / "retirement.json")
                args = argparse.Namespace(adb=recovery.PINNED_ADB_PATH)
                try:
                    with mock.patch.object(
                            recovery, "RecoveryNomad", return_value=fake):
                        code = recovery._run_reserved_restore_only(
                            args, AUTHORITY, path, reservation)
                finally:
                    reservation.close()
                self.assertEqual(code, 0)
                self.assertEqual(fake.mutations, [])
                self.assertEqual(fake.rotation, ("1", "2"))
                self.assertFalse(path.exists())
                evidence = json.loads(
                    (Path(directory) / "retirement.json").read_text())
                self.assertEqual(evidence["result"],
                                 "NO_ATTEMPT_JOURNAL_RETIRED")
                archive = Path(evidence["journalArchive"]["path"])
                self.assertTrue(archive.exists())
                self.assertEqual(archive.read_bytes(), original)
                retry = recovery.DurableJournal(path, self.restore_header())
                retry.close()

    def test_partial_cleanup_and_restore_records_still_restore_rotation(self) -> None:
        cases = ("lock_intent", "lock_settlement", "cleanup_intent",
                 "restore_intent", "restore_settlement")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "journal.jsonl"
                journal = recovery.DurableJournal(path, self.restore_header())
                device = FakeDevice()
                runner = recovery.Recovery(
                    device, AUTHORITY, sleep=lambda _: None, journal=journal,
                    **self.execute_identities(device))
                if case == "lock_intent":
                    journal._stream = PartialThenCrashStream(  # type: ignore[attr-defined]
                        journal._stream, 31)  # type: ignore[attr-defined]
                elif case == "lock_settlement":
                    original_record_rotation = runner._record_rotation

                    def fail_lock_settlement(
                            kind: str, payload: dict[str, object]) -> dict:
                        if kind == "rotation_lock_settlement":
                            journal._stream = PartialThenCrashStream(  # type: ignore[attr-defined]
                                journal._stream, 37)  # type: ignore[attr-defined]
                        return original_record_rotation(kind, payload)

                    runner._record_rotation = fail_lock_settlement  # type: ignore[method-assign]
                elif case == "cleanup_intent":
                    original_mutation = runner._mutation

                    def fail_cleanup_intent(kind: str, **fields: object) -> None:
                        journal._stream = PartialThenCrashStream(  # type: ignore[attr-defined]
                            journal._stream, 41)  # type: ignore[attr-defined]
                        original_mutation(kind, **fields)

                    runner._mutation = fail_cleanup_intent  # type: ignore[method-assign]
                elif case == "restore_intent":
                    original_cleanup = runner._run_cleanup

                    def fail_restore_intent(*, execute: bool,
                                            host_uid: int) -> dict:
                        value = original_cleanup(
                            execute=execute, host_uid=host_uid)
                        if execute:
                            journal._stream = PartialThenCrashStream(  # type: ignore[attr-defined]
                                journal._stream, 47)  # type: ignore[attr-defined]
                        return value

                    runner._run_cleanup = fail_restore_intent  # type: ignore[method-assign]
                else:
                    original_record_rotation = runner._record_rotation

                    def fail_restore_settlement(
                            kind: str, payload: dict[str, object]) -> dict:
                        if kind == "rotation_restore_settlement":
                            journal._stream = PartialThenCrashStream(  # type: ignore[attr-defined]
                                journal._stream, 53)  # type: ignore[attr-defined]
                        return original_record_rotation(kind, payload)

                    runner._record_rotation = fail_restore_settlement  # type: ignore[method-assign]
                with self.assertRaises(Exception):
                    runner.run(execute=True)
                journal.close()
                self.assertEqual(device.rotation, ("1", "2"))
                if case == "lock_intent":
                    self.assertEqual(device.mutations, [])
                    self.assertEqual(
                        runner.evidence["result"],
                        "CLEANUP_NOT_STARTED_ROTATION_UNCHANGED")
                else:
                    self.assertEqual(device.mutations[-2:],
                                     ["rotation:lock2", "rotation:free"])
                if case == "lock_intent":
                    pass
                elif case in {"lock_settlement", "cleanup_intent"}:
                    self.assertEqual(runner.evidence["result"],
                                     "CLEANUP_FAILED_ROTATION_RESTORED")
                else:
                    self.assertEqual(
                        runner.evidence["result"],
                        "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED")

    def test_no_attempt_retirement_fails_closed_on_rotation_or_archive_collision(self) -> None:
        for case in ("rotation", "archive"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / recovery.CANONICAL_JOURNAL_BASENAME
                journal = recovery.DurableJournal(path, self.restore_header())
                journal.close()
                raw = path.read_bytes()
                if case == "archive":
                    digest = alpha._sha(raw)
                    archive = path.with_name(
                        path.name + ".no-attempt-" + digest[:16] +
                        ".retired")
                    archive.write_bytes(b"occupied")
                fake = FakeDevice()
                if case == "rotation":
                    fake.rotation = ("0", "0")
                reservation = recovery.EvidenceReservation(
                    root / "retirement.json")
                args = argparse.Namespace(adb=recovery.PINNED_ADB_PATH)
                try:
                    with mock.patch.object(
                            recovery, "RecoveryNomad", return_value=fake):
                        code = recovery._run_reserved_restore_only(
                            args, AUTHORITY, path, reservation)
                finally:
                    reservation.close()
                self.assertEqual(code, 1)
                self.assertTrue(path.exists())
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(fake.mutations, [])

    def test_every_journal_crash_boundary_stops_at_a_mutation_prefix(self) -> None:
        baseline = FakeDevice()
        self.run_recovery(baseline)
        expected = list(baseline.mutations)
        record_count = baseline.journal.count
        for failure_index in range(1, record_count):
            with self.subTest(failure_index=failure_index):
                device = FakeDevice()
                device.journal.fail_at = failure_index
                with self.assertRaises((OSError, recovery.RotationRestoreError)):
                    self.run_recovery(device)
                cleanup_prefix = [
                    item for item in device.mutations
                    if item not in {"rotation:lock2", "rotation:free"}]
                self.assertEqual(cleanup_prefix,
                                 expected[:len(cleanup_prefix)])
                if "rotation:lock0" in device.mutations:
                    self.assertEqual(device.mutations[-2:],
                                     ["rotation:lock2", "rotation:free"])
                for mutation in set(device.mutations):
                    self.assertEqual(device.mutations.count(mutation), 1)

    def test_canonical_journal_blocks_cross_process_replay_after_each_uncertain_action(self) -> None:
        cases = {
            "main": lambda d: setattr(d, "refocus_transport", "unapplied"),
            "ack": lambda d: setattr(d, "action_transport", "unapplied"),
            "move": lambda d: d.move_transport.__setitem__(
                alpha.TARGET_MARK, "unapplied"),
            "remove": lambda d: d.remove_transport.__setitem__(
                recovery.QUARANTINE_MARK, "unapplied"),
        }
        for name, configure in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / recovery.CANONICAL_JOURNAL_BASENAME
                first_journal = recovery.DurableJournal(
                    path, {"authority": recovery.RECOVERY_AUTHORITY,
                           "case": name})
                first = FakeDevice()
                configure(first)
                with self.assertRaises(Exception):
                    recovery.Recovery(
                        first, AUTHORITY, sleep=lambda _: None,
                        journal=first_journal,
                        **self.execute_identities(first)).run(execute=True)
                first_journal.close()
                self.assertTrue(first.mutations)

                second = FakeDevice()
                with self.assertRaisesRegex(recovery.RecoveryError, "reuse"):
                    # `main` creates this barrier before constructing/running a
                    # Recovery, so the fresh device remains completely untouched.
                    recovery.DurableJournal(
                        path, {"authority": recovery.RECOVERY_AUTHORITY,
                               "case": name})
                self.assertEqual(second.mutations, [])
                self.assertEqual(second.host_logs_calls, 0)

    def test_durable_journal_and_atomic_evidence_are_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = recovery.DurableJournal(
                root / "intent.jsonl", {"authority": "test"})
            journal.record("settlement", {"ordinal": 1})
            journal.close()
            raw = (root / "intent.jsonl").read_bytes()
            count, head = recovery.validate_journal_bytes(raw)
            self.assertEqual(count, 2)
            self.assertEqual(head, journal.head_hash)
            target = root / "evidence.json"
            recovery.write_evidence(target, {"result": "ok"})
            self.assertEqual(json.loads(target.read_text()), {"result": "ok"})
            with self.assertRaisesRegex(recovery.RecoveryError, "overwrite"):
                recovery.write_evidence(target, {"result": "changed"})

    def test_evidence_is_exclusively_reserved_and_bound_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "evidence.json"
            reservation = recovery.EvidenceReservation(target)
            authority = dict(reservation.authority)
            self.assertTrue(target.exists())
            self.assertEqual(target.stat().st_size, 0)
            journal = recovery.DurableJournal(
                root / "intent.jsonl",
                {"authority": recovery.RECOVERY_AUTHORITY,
                 "evidenceReservation": authority})
            journal.close()
            header = json.loads((root / "intent.jsonl").read_text().splitlines()[0])
            self.assertEqual(
                header["payload"]["evidenceReservation"], authority)
            reservation.write({"result": "ok", "authority": authority})
            reservation.close()
            self.assertEqual(json.loads(target.read_text())["result"], "ok")
            with self.assertRaisesRegex(recovery.RecoveryError, "overwrite|follow"):
                recovery.EvidenceReservation(target)

    def test_empty_crash_reservation_and_identity_race_are_never_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty-after-crash.json"
            reservation = recovery.EvidenceReservation(empty)
            reservation.close()
            self.assertEqual(empty.stat().st_size, 0)
            with self.assertRaisesRegex(recovery.RecoveryError, "overwrite|follow"):
                recovery.EvidenceReservation(empty)

            raced = recovery.EvidenceReservation(root / "raced.json")
            raced._file_identity = (  # type: ignore[attr-defined]
                raced._file_identity[0], raced._file_identity[1] + 1)
            with self.assertRaisesRegex(recovery.RecoveryError, "identity changed"):
                raced.write({"result": "must-not-write"})
            raced.close()

    def test_evidence_alias_and_unwritable_destination_fail_before_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.json"
            existing.write_text("occupied")
            with mock.patch.object(recovery, "RecoveryNomad") as adapter:
                with self.assertRaises(recovery.RecoveryError):
                    recovery.main([
                        "--adb", str(recovery.PINNED_ADB_PATH),
                        "--output", str(existing)])
                adapter.assert_not_called()

            real_parent = root / "real-parent"
            real_parent.mkdir()
            alias_parent = root / "alias-parent"
            try:
                alias_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(recovery.RecoveryError, "aliases"):
                    recovery.EvidenceReservation(alias_parent / "evidence.json")

            unwritable = root / "unwritable.json"
            with mock.patch.object(
                    recovery.os, "open", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(
                        recovery.RecoveryError, "exclusively reserved"):
                    recovery.EvidenceReservation(unwritable)

    def test_evidence_identity_drift_blocks_first_device_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reservation = recovery.EvidenceReservation(
                Path(directory) / "execute.json")
            reservation._file_identity = (  # type: ignore[attr-defined]
                reservation._file_identity[0],
                reservation._file_identity[1] + 1)
            device = FakeDevice()
            runner = recovery.Recovery(
                device, AUTHORITY, sleep=lambda _: None,
                journal=device.journal,
                evidence_guard=reservation.assert_reserved,
                **self.execute_identities(device))
            with self.assertRaisesRegex(
                    recovery.RecoveryError, "identity changed"):
                runner.run(execute=True)
            self.assertEqual(device.mutations, [])
            reservation.close()

    def test_rotation_lease_happy_order_accepts_physical_two_and_restores_sensor_two(self) -> None:
        device = FakeDevice()
        device.physical_rotation = 2
        device.sensor_physical_after_free = 2
        result = self.run_recovery(device)
        self.assertEqual(result["result"], "RECOVERED_CLEANLY")
        self.assertEqual(device.mutations[0], "rotation:lock0")
        self.assertEqual(device.mutations[-2:], [
            "rotation:lock2", "rotation:free"])
        first_cleanup = next(
            index for index, item in enumerate(device.mutations)
            if item == "refocus")
        self.assertGreater(first_cleanup, 0)
        records = device.journal.records
        kinds = [item["kind"] for item in records]
        self.assertLess(kinds.index("rotation_lock_intent"),
                        kinds.index("mutation_intent"))
        self.assertLess(kinds.index("settlement",
                                    kinds.index("rotation_lock_settlement")),
                        kinds.index("rotation_restore_intent"))
        self.assertEqual(device.rotation, ("1", "2"))
        self.assertEqual(device.physical_rotation, 2)
        # Every authority read is a persisted/WM/persisted sandwich.
        for index, token in enumerate(device.rotation_read_trace):
            if token == "wm":
                self.assertGreater(index, 0)
                self.assertLess(index + 1, len(device.rotation_read_trace))
                self.assertEqual(device.rotation_read_trace[index - 1:index + 2],
                                 ["settings", "wm", "settings"])

    def test_rotation_lock_applied_uncertain_succeeds_unapplied_never_cleans(self) -> None:
        applied = FakeDevice()
        applied.rotation_lock_transport = "applied_uncertain"
        self.assertEqual(self.run_recovery(applied)["result"],
                         "RECOVERED_CLEANLY")
        lock_settlement = next(
            item for item in applied.journal.records
            if item["kind"] == "rotation_lock_settlement")
        self.assertIn("AlphaError", lock_settlement["payload"][
            "transportUncertain"])

        unapplied = FakeDevice()
        unapplied.rotation_lock_transport = "unapplied"
        runner = recovery.Recovery(
            unapplied, AUTHORITY, sleep=lambda _: None,
            journal=unapplied.journal,
            **self.execute_identities(unapplied))
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "lock 0 was not proved"):
            runner.run(execute=True)
        self.assertEqual(unapplied.mutations,
                         ["rotation:lock0", "rotation:lock2", "rotation:free"])
        self.assertEqual(runner.evidence["result"],
                         "CLEANUP_FAILED_ROTATION_RESTORED")

    def test_rotation_drift_before_cleanup_mutation_fails_and_restores(self) -> None:
        device = FakeDevice()
        original = device.start_host

        def drift_after_refocus() -> None:
            original()
            device.physical_rotation = 1

        device.start_host = drift_after_refocus  # type: ignore[method-assign]
        runner = recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None, journal=device.journal,
            **self.execute_identities(device))
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "owned rotation lease"):
            runner.run(execute=True)
        self.assertNotIn("send:ACK_NO_FOREIGN_AFTER_FAILURE", device.mutations)
        self.assertEqual(device.mutations[-2:],
                         ["rotation:lock2", "rotation:free"])
        self.assertEqual(runner.evidence["result"],
                         "CLEANUP_FAILED_ROTATION_RESTORED")

    def test_restore_first_command_error_still_frees_and_classifies_failure(self) -> None:
        device = FakeDevice()
        device.rotation_restore_lock_transport = "unapplied"
        runner = recovery.Recovery(
            device, AUTHORITY, sleep=lambda _: None, journal=device.journal,
            **self.execute_identities(device))
        with self.assertRaises(recovery.RotationRestoreError):
            runner.run(execute=True)
        self.assertEqual(device.mutations[-2:],
                         ["rotation:lock2", "rotation:free"])
        self.assertEqual(runner.evidence["result"],
                         "CLEANUP_COMPLETE_ROTATION_RESTORE_FAILED")

        uncertain = FakeDevice()
        uncertain.rotation_restore_lock_transport = "applied_uncertain"
        result = self.run_recovery(uncertain)
        self.assertEqual(result["result"], "RECOVERED_CLEANLY")
        restored = next(item for item in uncertain.journal.records
                        if item["kind"] == "rotation_restore_settlement")
        self.assertIn("AlphaError", restored["payload"][
            "lockTwoTransportUncertain"])

    def test_rotation_admission_rejects_persisted_mismatch_sandwich_drift_and_malformed_wm(self) -> None:
        mismatch = FakeDevice()
        mismatch.rotation = ("0", "2")
        with self.assertRaisesRegex(recovery.RecoveryError, "exact 1/2"):
            self.run_recovery(mismatch)
        self.assertEqual(mismatch.mutations, [])

        drift = FakeDevice()
        original_window = drift.window_displays

        def drifting_window() -> bytes:
            raw = original_window()
            drift.rotation = ("0", "2")
            return raw

        drift.window_displays = drifting_window  # type: ignore[method-assign]
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "changed across WindowManager"):
            self.run_recovery(drift)
        self.assertEqual(drift.mutations, [])

        malformed = FakeDevice()
        malformed.window_displays = lambda: b"not WindowManager"  # type: ignore[method-assign]
        with self.assertRaises(Exception):
            self.run_recovery(malformed)
        self.assertEqual(malformed.mutations, [])

    def test_literal_rotation_command_argv_has_no_free_value_operand(self) -> None:
        calls: list[tuple[str, ...]] = []

        def executor(argv: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[bytes]:
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        device = recovery.RecoveryNomad.__new__(recovery.RecoveryNomad)
        device.adb = str(recovery.PINNED_ADB_PATH)
        device._executor = executor
        device.history = []
        device.lock_rotation_zero()
        device.lock_rotation_two()
        device.free_rotation()
        tails = [call[3:] for call in calls]
        self.assertEqual(tails, [
            ("shell", "wm", "set-user-rotation", "lock", "0"),
            ("shell", "wm", "set-user-rotation", "lock", "2"),
            ("shell", "wm", "set-user-rotation", "free"),
        ])
        self.assertNotIn("2", tails[-1])

    def test_restore_only_crash_prefixes_never_replay_cleanup_and_accept_one_torn_tail(self) -> None:
        stages = ("intent", "leased", "cleanup", "complete", "restore_intent")
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                journal_path = root / recovery.CANONICAL_JOURNAL_BASENAME
                journal = recovery.DurableJournal(
                    journal_path, self.restore_header(physical=2))
                self.add_lock_intent(journal, physical=2)
                if stage != "intent":
                    self.add_lock_settlement(journal)
                if stage == "cleanup":
                    journal.record("mutation_intent", {
                        "authority": recovery.RECOVERY_AUTHORITY,
                        "descriptorAuthority": self.descriptor_authority(),
                        "ordinal": 1,
                        "intent": {"kind": "host_main_refocus", "sequence": None},
                        "reportSha256": AUTHORITY.report_sha256,
                    })
                if stage in {"complete", "restore_intent"}:
                    self.add_complete_cleanup(journal)
                if stage == "restore_intent":
                    journal.record("rotation_restore_intent", {
                        "authority": recovery.ROTATION_LEASE_AUTHORITY,
                        "reportSha256": AUTHORITY.report_sha256,
                        "commandDialects": {
                            "lockTwo": recovery.ROTATION_COMMAND_DIALECTS[
                                "restoreUserRotation"],
                            "free": recovery.ROTATION_COMMAND_DIALECTS[
                                "restoreSensor"],
                        },
                        "targetPersisted": {
                            "accelerometerRotation": "1",
                            "userRotation": "2",
                        },
                    })
                journal.close()
                if stage == "leased":
                    with journal_path.open("ab") as stream:
                        stream.write(b'{"kind":"rotation_restore_int')
                fake = FakeDevice()
                fake.rotation = ("0", "0")
                fake.physical_rotation = 0
                reservation = recovery.EvidenceReservation(root / "restore.json")
                args = argparse.Namespace(adb=recovery.PINNED_ADB_PATH)
                try:
                    with mock.patch.object(
                            recovery, "RecoveryNomad", return_value=fake):
                        code = recovery._run_reserved_restore_only(
                            args, AUTHORITY, journal_path, reservation)
                finally:
                    reservation.close()
                self.assertEqual(code, 0)
                self.assertEqual(fake.mutations,
                                 ["rotation:lock2", "rotation:free"])
                self.assertIn(alpha.TARGET_MARK, fake.files)
                self.assertIn(alpha.TARGET_PDF, fake.files)
                count, _ = recovery.validate_journal_bytes(
                    journal_path.read_bytes())
                self.assertGreaterEqual(count, 4)

    def test_restore_only_rejects_semantic_tamper_wrong_device_and_concurrency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong = root / "wrong.jsonl"
            journal = recovery.DurableJournal(
                wrong, self.restore_header(serial="wrong-device"))
            self.add_lock_intent(journal)
            journal.close()
            records, _, _ = recovery._parse_journal_prefix(wrong.read_bytes())
            _, helper = recovery._read_pinned_regular(
                Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
                "recovery helper")
            with self.assertRaisesRegex(recovery.RecoveryError, "another device"):
                recovery._validate_restore_journal(records, AUTHORITY, helper)

            valid = root / "valid.jsonl"
            original = recovery.DurableJournal(valid, self.restore_header())
            self.add_lock_intent(original)
            original.close()
            records, valid_size, _ = recovery._parse_journal_prefix(
                valid.read_bytes())
            valid_sha = alpha._sha(valid.read_bytes())
            resumed = recovery.DurableJournal.resume(
                valid, count=len(records), head_hash=records[-1]["recordHash"],
                valid_size=valid_size,
                expected_prefix_sha256=valid_sha)
            try:
                with self.assertRaisesRegex(recovery.RecoveryError,
                                            "concurrently owned"):
                    recovery.DurableJournal.resume(
                        valid, count=len(records),
                        head_hash=records[-1]["recordHash"],
                        valid_size=valid_size,
                        expected_prefix_sha256=valid_sha)
            finally:
                resumed.close()

            tampered = bytearray(valid.read_bytes())
            tampered[-10] ^= 1
            with self.assertRaises(recovery.RecoveryError):
                recovery._parse_journal_prefix(bytes(tampered))

    def test_restore_grammar_rejects_rehashed_impossible_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "complete.jsonl"
            journal = recovery.DurableJournal(path, self.restore_header())
            self.add_complete_execution(journal)
            journal.close()
            baseline, _, _ = recovery._parse_journal_prefix(path.read_bytes())
            _, helper = recovery._read_pinned_regular(
                Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
                "recovery helper")
            recovery._validate_restore_journal(baseline, AUTHORITY, helper)

            cleanup_index = next(
                index for index, item in enumerate(baseline)
                if item["kind"] == "settlement" and
                item["payload"].get("kind") == "cleanup_complete")
            first_mutation = next(
                index for index, item in enumerate(baseline)
                if item["kind"] == "mutation_intent")
            abort_intent = next(
                index for index, item in enumerate(baseline)
                if item["kind"] == "mutation_intent" and
                item["payload"]["intent"]["kind"] ==
                "empty_display_abort")
            abort_settlement = next(
                index for index, item in enumerate(baseline)
                if item["kind"] == "settlement" and
                item["payload"].get("kind") ==
                "empty_display_abort_and_release")
            variants: list[list[dict[str, object]]] = []

            duplicate_complete = copy.deepcopy(baseline)
            duplicate_complete.insert(
                cleanup_index + 1,
                copy.deepcopy(duplicate_complete[cleanup_index]))
            variants.append(duplicate_complete)

            bad_ordinal = copy.deepcopy(baseline)
            bad_ordinal[first_mutation]["payload"]["ordinal"] = 2
            variants.append(bad_ordinal)

            boolean_ordinal = copy.deepcopy(baseline)
            boolean_ordinal[first_mutation]["payload"]["ordinal"] = True
            variants.append(boolean_ordinal)

            gap_ordinal = copy.deepcopy(baseline)
            second_mutation = next(
                index for index in range(first_mutation + 1, len(baseline))
                if baseline[index]["kind"] == "mutation_intent")
            gap_ordinal[second_mutation]["payload"]["ordinal"] += 1
            variants.append(gap_ordinal)

            premature = copy.deepcopy(baseline[:3])
            premature.append(copy.deepcopy(baseline[cleanup_index]))
            variants.append(premature)

            wrong_digest = copy.deepcopy(baseline)
            wrong_digest[abort_settlement]["payload"][
                "absenceEvidenceSha256"] = "f" * 64
            self.assertNotEqual(
                wrong_digest[abort_settlement]["payload"][
                    "absenceEvidenceSha256"],
                wrong_digest[abort_intent]["payload"]["intent"][
                    "absenceEvidenceSha256"])
            variants.append(wrong_digest)

            nested_extra = copy.deepcopy(baseline)
            nested_extra[cleanup_index]["payload"]["document"]["extra"] = True
            variants.append(nested_extra)

            unknown_settlement = copy.deepcopy(baseline)
            host_absence = next(
                index for index, item in enumerate(unknown_settlement)
                if item["kind"] == "settlement" and
                item["payload"].get("kind") == "host_absent_twice")
            unknown_settlement[host_absence]["payload"]["kind"] = "unknown"
            variants.append(unknown_settlement)

            post_terminal = copy.deepcopy(baseline)
            post_terminal.append(copy.deepcopy(baseline[first_mutation]))
            variants.append(post_terminal)

            unknown_descriptor_mode = copy.deepcopy(baseline)
            unknown_descriptor_mode[0]["payload"]["descriptorAuthority"][
                "mode"] = "UNKNOWN"
            variants.append(unknown_descriptor_mode)

            intent_mode_drift = copy.deepcopy(baseline)
            intent_mode_drift[first_mutation]["payload"][
                "descriptorAuthority"] = self.descriptor_authority(
                    recovery.DESCRIPTOR_AUTHORITY_IDLE_ZERO)
            variants.append(intent_mode_drift)

            completion_mode_drift = copy.deepcopy(baseline)
            completion_mode_drift[cleanup_index]["payload"]["document"][
                "descriptorAuthority"] = self.descriptor_authority(
                    recovery.DESCRIPTOR_AUTHORITY_IDLE_ZERO)
            variants.append(completion_mode_drift)

            descriptor_process_drift = copy.deepcopy(baseline)
            descriptor_process_drift[first_mutation]["payload"][
                "descriptorAuthority"]["documentProcess"][
                    "start_ticks"] += 1
            variants.append(descriptor_process_drift)

            bad_descriptor_targets = copy.deepcopy(baseline)
            bad_descriptor_targets[first_mutation]["payload"][
                "descriptorAuthority"]["observations"][0][
                    "relevantTargets"] = []
            variants.append(bad_descriptor_targets)

            bad_descriptor_hash = copy.deepcopy(baseline)
            bad_descriptor_hash[first_mutation]["payload"][
                "descriptorAuthority"]["observations"][0][
                    "fdInventorySha256"] = 7
            variants.append(bad_descriptor_hash)

            bad_descriptor_absence = copy.deepcopy(baseline)
            bad_descriptor_absence[first_mutation]["payload"][
                "descriptorAuthority"]["observations"][0][
                    "documentTaskWindowAbsent"] = False
            variants.append(bad_descriptor_absence)

            bad_descriptor_count = copy.deepcopy(baseline)
            bad_descriptor_count[first_mutation]["payload"][
                "descriptorAuthority"]["observations"].pop()
            variants.append(bad_descriptor_count)

            for ordinal, variant in enumerate(variants):
                with self.subTest(ordinal=ordinal):
                    raw = self.canonical_records(variant)
                    parsed, _, _ = recovery._parse_journal_prefix(raw)
                    with self.assertRaises(recovery.RecoveryError):
                        recovery._validate_restore_journal(
                            parsed, AUTHORITY, helper)

    def test_restore_grammar_accepts_a_complete_idle_zero_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "idle-zero.jsonl"
            header = self.restore_header()
            header["descriptorAuthority"] = self.descriptor_authority(
                recovery.DESCRIPTOR_AUTHORITY_IDLE_ZERO)
            journal = recovery.DurableJournal(path, header)
            source = FakeDevice()
            source.fd_targets = []
            self.run_recovery(source)
            for record in source.journal.records[1:]:
                journal.record(record["kind"],
                               copy.deepcopy(record["payload"]))
            journal.close()
            parsed, _, _ = recovery._parse_journal_prefix(path.read_bytes())
            _, helper = recovery._read_pinned_regular(
                Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
                "recovery helper")
            state = recovery._validate_restore_journal(
                parsed, AUTHORITY, helper)
            self.assertTrue(state["cleanupComplete"])
            self.assertEqual(state["phase"], "FINAL")

    def test_strict_header_types_and_closed_reservation_topology(self) -> None:
        _, helper = recovery._read_pinned_regular(
            Path(recovery.__file__), recovery.HELPER_MAX_BYTES,
            "recovery helper")
        mutations = []
        coerced_digest = self.restore_header()
        coerced_digest["readOnlyAdmissionSha256"] = 7
        mutations.append(coerced_digest)
        extra_reservation = self.restore_header()
        extra_reservation["evidenceReservation"]["extra"] = True
        mutations.append(extra_reservation)
        wrong_boolean = self.restore_header()
        wrong_boolean["evidenceReservation"]["exclusive"] = 1
        mutations.append(wrong_boolean)
        for ordinal, header in enumerate(mutations):
            with self.subTest(ordinal=ordinal), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "invalid-header.jsonl"
                journal = recovery.DurableJournal(path, header)
                self.add_lock_intent(journal)
                journal.close()
                records, _, _ = recovery._parse_journal_prefix(
                    path.read_bytes())
                with self.assertRaises(recovery.RecoveryError):
                    recovery._validate_restore_journal(
                        records, AUTHORITY, helper)

    def test_torn_tail_accepts_only_plausible_next_canonical_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix_path = root / "prefix.jsonl"
            journal = recovery.DurableJournal(
                prefix_path, self.restore_header())
            self.add_lock_intent(journal)
            count = journal.count
            head = journal.head_hash
            journal.close()
            payload = {
                "authority": recovery.ROTATION_LEASE_AUTHORITY,
                "reportSha256": AUTHORITY.report_sha256,
                "commandDialect": recovery.ROTATION_COMMAND_DIALECTS["acquire"],
                "transportUncertain": None,
                "observations": [self.rotation_wire("0", "0"),
                                 self.rotation_wire("0", "0")],
            }
            base = {"seq": count, "prevHash": head,
                    "kind": "rotation_lock_settlement", "payload": payload}
            complete = {**base, "recordHash": alpha._canonical_sha(base)}
            next_line = json.dumps(
                complete, ensure_ascii=True, allow_nan=False, sort_keys=True,
                separators=(",", ":")).encode("ascii")
            prefix = prefix_path.read_bytes()
            for size in (1, 5, 18, 45, len(next_line) // 2,
                         len(next_line) - 1, len(next_line)):
                with self.subTest(valid_size=size):
                    records, valid_size, torn = recovery._parse_journal_prefix(
                        prefix + next_line[:size], allow_torn_final=True)
                    self.assertEqual(len(records), count)
                    self.assertEqual(valid_size, len(prefix))
                    self.assertEqual(torn, next_line[:size])
            invalid = (
                b"\x00", b"garbage", b'{"kind":"rotation_lock_intent',
                b'{"kind":"settlement","payload":{"zzz":',
                b'{"kind":"rotation_restore_settlement","payload":{"authority":',
                b'{"kind":"rotation_lock_settlement","payload":[]',
                next_line.replace(head.encode(), b"f" * 64),
            )
            for ordinal, fragment in enumerate(invalid):
                with self.subTest(invalid_ordinal=ordinal):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery._parse_journal_prefix(
                            prefix + fragment, allow_torn_final=True)


if __name__ == "__main__":
    unittest.main()
