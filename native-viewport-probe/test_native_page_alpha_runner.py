from __future__ import annotations

from pathlib import Path
import hashlib
import inspect
import json
import stat as stat_module
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile
import zlib

import native_page_android_authority as android
import native_page_alpha_runner as alpha
import native_page_host_authority as host


SESSION = "01234567-89ab-4cde-8fab-0123456789ab"
CONTROLLER_ID = "0123456789abcdef0123456789abcdef"
PID = 10104
_TEST_TEMPORARIES: list[tempfile.TemporaryDirectory[str]] = []


def test_temporary_directory() -> tempfile.TemporaryDirectory[str]:
    temporary = tempfile.TemporaryDirectory()
    _TEST_TEMPORARIES.append(temporary)
    return temporary


def tearDownModule() -> None:
    while _TEST_TEMPORARIES:
        _TEST_TEMPORARIES.pop().cleanup()


def rewrite_journal_chain(
        path: Path, mutate: object,
        ) -> list[dict[str, object]]:
    """Rewrite a syntactically valid hash chain for semantic-tamper tests."""
    records = [json.loads(line) for line in path.read_text(
        encoding="ascii").splitlines()]
    assert callable(mutate)
    mutate(records)
    previous: str | None = None
    rendered = bytearray()
    for sequence, record in enumerate(records):
        record.pop("recordSha256", None)
        record["sequence"] = sequence
        record["previousRecordSha256"] = previous
        raw, digest = alpha._journal_record_bytes(record)
        rendered.extend(raw)
        previous = digest
    path.write_bytes(bytes(rendered))
    return records


def status(state: str = "ACTIVE") -> alpha.HostStatus:
    return alpha.HostStatus(SESSION, 1, 3, state, "test")


def foreign() -> host.ForeignIdentity:
    return host.ForeignIdentity(
        host.ProcessIdentity(PID, 123456, 1000, alpha.DOCUMENT_PACKAGE),
        4538, "11846f4", "a" * 64, alpha.DOCUMENT_COMPONENT,
    )


def activity_wire(*, second_task: bool = False,
                  uri: str = alpha.TARGET_URI,
                  display_id: int = 3) -> bytes:
    extra = ""
    if second_task:
        extra = """    * Task{7777777 #7777 visible=true type=standard mode=fullscreen translucent=false A=10001:com.example.other U=0 StackId=4538 sz=1}
      taskId=7777 stackId=4538
      * Hist #0: ActivityRecord{7654321 u0 com.example.other/.OtherActivity t7777}
"""
    return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #{display_id} (activities from top to bottom):
  Stack #4538: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}
    * Task{{66d8263 #4538 visible=true type=standard mode=fullscreen translucent=false A=1000:com.supernote.document U=0 StackId=4538 sz=1}}
      taskId=4538 stackId=4538
      intent={{act=android.intent.action.VIEW
        dat={uri} typ=application/pdf
        cmp=com.supernote.document/.document.DocumentActivity}}
      * Hist #0: ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}
          packageName=com.supernote.document processName=com.supernote.document
          app=ProcessRecord{{2083011 {PID}:com.supernote.document/1000}}
          mActivityComponent=com.supernote.document/.document.DocumentActivity
          baseDir={alpha.DOCUMENT_APK}
          CurrentConfiguration={{1.0 en_US 300dpi port winConfig={{ mBounds=Rect(0, 0 - 1404, 1872) mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}} s.186}}
          state=RESUMED stopped=false delayedResume=false finishing=false
          mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
          nowVisible=true lastVisibleTime=-1s
{extra}""".encode("utf-8")


def activity_wire_with_parent_resume_postamble() -> bytes:
    raw = activity_wire().replace(
        b"  Stack #4538: type=standard mode=fullscreen\n",
        b"  Stack #4538: type=standard mode=fullscreen\n"
        b"  isSleeping=false\n"
        b"  mBounds=Rect(0, 0 - 1404, 1872)\n",
        1,
    )
    return raw + f"""
  Resumed activities in task display areas (from top to bottom):
    Resumed: ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}

  ResumedActivity: ActivityRecord{{773f2a u0 {alpha.HOST_PACKAGE}/.NativePageHostActivity t4649}}

""".encode("utf-8")


def activity_supervisor_suffix(
        displays: tuple[tuple[int, int], ...],
        ) -> bytes:
    """Reduced pinned-firmware supervisor suffix with redundant summaries."""
    summaries = "".join(
        f"  Display: mDisplayId={display_id} stacks={stack_count}\n"
        for display_id, stack_count in displays)
    return f"""ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{66d8263 #4538 visible=true}}
  mLastOrientationSource=ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}
  deepestLastOrientationSource=ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}
{summaries}""".encode("utf-8")


def empty_activity_with_document_supervisor_ghost() -> bytes:
    """Real pinned shape: no canonical stack, stale Document supervisor state."""
    return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{{66d8263 #4538 visible=false A=1000:com.supernote.document sz=0}}
  mLastOrientationSource=ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}
  deepestLastOrientationSource=ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t4538}}
  mLastFocusedStack=Task{{66d8263 #4538 visible=false A=1000:com.supernote.document sz=0}}
  Display: mDisplayId=0 stacks=0
""".encode("utf-8")


def empty_activity_with_document_supervisor_ghost_and_pair() -> bytes:
    """Post-removal ghost while the owned nonprimary display remains present."""
    display_zero = b"  Display: mDisplayId=0 stacks=0\n"
    pair = (
        b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
        b"  deepestLastOrientationSource="
        b"DefaultTaskDisplayArea@140913322\n")
    return empty_activity_with_document_supervisor_ghost().replace(
        b"ActivityStackSupervisor state:\n",
        b"Display #3 (activities from top to bottom):\n"
        b"ActivityStackSupervisor state:\n",
        1).replace(
            display_zero,
            display_zero + pair +
            b"  Display: mDisplayId=3 stacks=0\n",
            1)


def empty_activity_with_document_supervisor_ghost_and_two_pairs() -> bytes:
    """Exact ghost shape with two independently identified nonprimary displays."""
    display_three = b"  Display: mDisplayId=3 stacks=0\n"
    pair_four = (
        b"  mLastOrientationSource=DefaultTaskDisplayArea@140913323\n"
        b"  deepestLastOrientationSource="
        b"DefaultTaskDisplayArea@140913323\n")
    return empty_activity_with_document_supervisor_ghost_and_pair().replace(
        b"ActivityStackSupervisor state:\n",
        b"Display #4 (activities from top to bottom):\n"
        b"ActivityStackSupervisor state:\n",
        1).replace(
            display_three,
            display_three + pair_four +
            b"  Display: mDisplayId=4 stacks=0\n",
            1)


def idle_activity_with_default_task_display_area() -> bytes:
    """Real idle Nomad shape after host display creation, before launch."""
    return b"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display areas in focus order:
Display #0 (activities from top to bottom):
  Stack #7: type=home mode=fullscreen
    mResumedActivity: ActivityRecord{abcdef0 u0 com.example.home/.HomeActivity t7}
    * Task{7654321 #7 visible=true type=home mode=fullscreen A=1000:com.example.home U=0 StackId=7 sz=1}
      taskId=7 stackId=7
      * Hist #0: ActivityRecord{abcdef0 u0 com.example.home/.HomeActivity t7}
Display #3 (activities from top to bottom):
ActivityStackSupervisor state:
  topDisplayFocusedStack=Task{7654321 #7 visible=true type=home mode=fullscreen A=1000:com.example.home U=0 StackId=7 sz=1}
  mLastOrientationSource=DefaultTaskDisplayArea@159915765
  deepestLastOrientationSource=DefaultTaskDisplayArea@159915765
  Display: mDisplayId=0 stacks=1
  Display: mDisplayId=3 stacks=0
"""


def idle_activity_with_per_display_orientation_pair() -> bytes:
    """Real two-display Nomad prelaunch shape after host creation."""
    raw = idle_activity_with_default_task_display_area()
    raw = raw.replace(
        b"  topDisplayFocusedStack=Task{7654321 #7 visible=true "
        b"type=home mode=fullscreen A=1000:com.example.home "
        b"U=0 StackId=7 sz=1}\n"
        b"  mLastOrientationSource=DefaultTaskDisplayArea@159915765\n"
        b"  deepestLastOrientationSource=DefaultTaskDisplayArea@159915765\n",
        b"  topDisplayFocusedStack=Task{7331948 #4634 visible=true "
        b"type=standard mode=fullscreen "
        b"A=10123:com.techrebbe.supernote.nativepagehost "
        b"U=0 StackId=4634 sz=1}\n"
        b"  mLastOrientationSource=ActivityRecord{c3b4284 u0 "
        b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
        b"t4634}\n"
        b"  deepestLastOrientationSource=ActivityRecord{c3b4284 u0 "
        b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
        b"t4634}\n",
        1)
    display_zero = b"  Display: mDisplayId=0 stacks=1\n"
    display_three = b"  Display: mDisplayId=3 stacks=0\n"
    pair = (
        b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
        b"  deepestLastOrientationSource="
        b"DefaultTaskDisplayArea@140913322\n")
    details = (
        b"    Task display areas in top down Z order:\n"
        b"      TaskDisplayArea DefaultTaskDisplayArea\n"
        b"      * Task{7331948 #4634 visible=true "
        b"A=10123:com.techrebbe.supernote.nativepagehost sz=1}\n"
        b"        * ActivityRecord{c3b4284 u0 "
        b"com.techrebbe.supernote.nativepagehost/.NativePageHostActivity "
        b"t4634}\n")
    return raw.replace(display_zero, display_zero + details, 1).replace(
        display_three, pair + display_three, 1)


def host_status_wire(state: str) -> bytes:
    value = (
        "NATIVE PAGE HOST — VISUAL ONLY\n"
        f"session={SESSION}\n"
        f"generation=1 display=3\nstate={state}\nstatus"
    ).replace("&", "&amp;").replace("\n", "&#10;")
    return ("<hierarchy><node text=\"" + value + "\"/></hierarchy>").encode(
        "utf-8")


def window_displays_wire(
        rotation: int = 1, dimensions: tuple[int, int] = (1872, 1404), *,
        app_dimensions: tuple[int, int] | None = None,
        frame_dimensions: tuple[int, int] | None = None,
        info_rotation: int | None = None,
        frame_rotation: int | None = None,
        final_rotation: int | None = None,
        deferred_rotation_suffix: str = " mDeferredRotationPauseCount=0",
        extra_display_zero_line: str = "",
        ) -> bytes:
    """Distilled real Nomad WindowManager dialect with controlled conflicts."""
    width, height = dimensions
    app_width, app_height = app_dimensions or dimensions
    frame_width, frame_height = frame_dimensions or dimensions
    info = rotation if info_rotation is None else info_rotation
    frame = rotation if frame_rotation is None else frame_rotation
    final = rotation if final_rotation is None else final_rotation
    return f"""WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)
  Display: mDisplayId=0 stacks=5
    init=1404x1872 300dpi cur={width}x{height} app={app_width}x{app_height}
    mDisplayInfo=DisplayInfo{{\"Built-in Screen\", displayId 0, rotation {info}, state ON, type INTERNAL}}
    DisplayFrames w={frame_width} h={frame_height} r={frame}
    mRotation={final}{deferred_rotation_suffix}
{extra_display_zero_line}  Display: mDisplayId=7 stacks=0
    init=1404x1872 300dpi cur=1404x1872 app=1404x1872
    mDisplayInfo=DisplayInfo{{\"NativePageVisualOnly\", displayId 7, rotation 0, state ON, type VIRTUAL}}
    DisplayFrames w=1404 h=1872 r=0
    mRotation=0
""".encode("utf-8")


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data +
            struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff))


def png(width: int, height: int, *, row_filter: int = 0,
        truncate_row: bool = False, compressed: bytes | None = None) -> bytes:
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    if compressed is None:
        row = bytes((row_filter,)) + bytes(width * 3)
        pixels = row * height
        if truncate_row:
            pixels = pixels[:-1]
        compressed = zlib.compress(pixels, 9)
    return (alpha.PNG_SIGNATURE + png_chunk(b"IHDR", ihdr_data) +
            png_chunk(b"IDAT", compressed) + png_chunk(b"IEND", b""))


def device_file(path: str, sha256: str, inode: int) -> alpha.DeviceFile:
    return alpha.DeviceFile(
        path, "regular file", 3768, 0, 0, inode, 77, sha256)


class FixtureDevice:
    """Small stateful device double for copy/remove uncertainty tests."""

    def __init__(self) -> None:
        self.history: list[dict[str, object]] = []
        self.state: dict[str, alpha.DeviceFile] = {
            alpha.SOURCE_PDF: device_file(
                alpha.SOURCE_PDF, alpha.SOURCE_PDF_SHA256, 11),
            alpha.SOURCE_MARK: device_file(
                alpha.SOURCE_MARK, alpha.SOURCE_MARK_SHA256, 12),
            alpha.PARKING_PDF: device_file(
                alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 13),
        }
        self.copy_calls: list[str] = []
        self.parking_copy_calls = 0
        self.publish_calls: list[str] = []
        self.move_calls: list[str] = []
        self.staging_remove_calls: list[str] = []
        self.remove_calls: list[str] = []
        self.stat_failures: dict[str, int] = {}
        self.copy_timeout_target: str | None = None
        self.publish_timeout_target: str | None = None
        self.publish_timeout_before_move: str | None = None
        self.move_timeout_target: str | None = None
        self.move_timeout_before_move: str | None = None
        self.remove_timeout_after_delete = False
        self.remove_timeout_before_delete = False
        self.staging_remove_timeout_after_delete = False
        self.staging_remove_timeout_before_delete = False

    @staticmethod
    def expected(path: str) -> str:
        if alpha.STAGING_PATTERN.fullmatch(path) is not None:
            path = alpha._staging_target(path)
        return (alpha.SOURCE_PDF_SHA256 if path == alpha.TARGET_PDF else
                alpha.SOURCE_MARK_SHA256)

    def stat_file(
            self, path: str, *, absent_ok: bool = False,
            ) -> alpha.DeviceFile | None:
        failures = self.stat_failures.get(path, 0)
        if failures:
            self.stat_failures[path] = failures - 1
            raise alpha.AlphaError("simulated post-copy stat timeout")
        value = self.state.get(path)
        if value is None and not absent_ok:
            raise alpha.AlphaError("simulated missing required file")
        return value

    def copy_fixture_member(self, source: str, staging: str) -> None:
        self.copy_calls.append(staging)
        if staging in self.state:
            raise alpha.AlphaError("simulated no-clobber copy skip")
        target = alpha._staging_target(staging)
        inode = 101 if target == alpha.TARGET_PDF else 102
        self.state[staging] = device_file(
            staging, self.expected(staging), inode)
        if target == self.copy_timeout_target:
            raise alpha.AlphaError("simulated copy reply timeout")

    def publish_fixture_member(self, staging: str, target: str) -> None:
        self.publish_calls.append(target)
        if target == self.publish_timeout_before_move:
            raise alpha.AlphaError("simulated publish timeout before mutation")
        if target in self.state:
            return
        current = self.state.pop(staging, None)
        if current is not None:
            self.state[target] = alpha.DeviceFile(
                target, current.kind, current.size, current.uid, current.gid,
                current.inode, current.device, current.sha256)
        if target == self.publish_timeout_target:
            raise alpha.AlphaError("simulated publish reply timeout")

    def copy_parking_pdf(self) -> None:
        self.parking_copy_calls += 1
        if alpha.PARKING_PDF in self.state:
            return
        self.state[alpha.PARKING_PDF] = device_file(
            alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 13)

    def move_fixture_to_quarantine(self, path: str, quarantine: str) -> None:
        self.move_calls.append(path)
        if path == self.move_timeout_before_move:
            raise alpha.AlphaError("simulated move timeout before mutation")
        if quarantine in self.state:
            return
        current = self.state.pop(path, None)
        if current is not None:
            self.state[quarantine] = alpha.DeviceFile(
                quarantine, current.kind, current.size, current.uid,
                current.gid, current.inode, current.device, current.sha256)
        if path == self.move_timeout_target:
            raise alpha.AlphaError("simulated move reply timeout")

    def remove_quarantine_member(self, quarantine: str) -> None:
        self.remove_calls.append(alpha._quarantine_target(quarantine))
        if self.remove_timeout_before_delete:
            raise alpha.AlphaError("simulated remove timeout before deletion")
        self.state.pop(quarantine, None)
        if self.remove_timeout_after_delete:
            raise alpha.AlphaError("simulated remove reply timeout")

    def remove_staging_member(self, staging: str) -> None:
        self.staging_remove_calls.append(alpha._staging_target(staging))
        if self.staging_remove_timeout_before_delete:
            raise alpha.AlphaError("simulated staging remove timeout before deletion")
        self.state.pop(staging, None)
        if self.staging_remove_timeout_after_delete:
            raise alpha.AlphaError("simulated staging remove reply timeout")

    @staticmethod
    def sha256_file(path: str) -> str:
        if path == alpha.SOURCE_PDF:
            return alpha.SOURCE_PDF_SHA256
        if path == alpha.SOURCE_MARK:
            return alpha.SOURCE_MARK_SHA256
        raise AssertionError("unexpected source hash path " + path)


def cleanup_ready_fixture_session(
        device: FixtureDevice, *, initialize: bool = True,
        provision_parking: bool = True,
        ) -> alpha.AlphaSession:
    temporary = test_temporary_directory()
    session = alpha.AlphaSession(
        device, Path(temporary.name), sleep=lambda _: None)
    session._test_temporary_directory = temporary  # type: ignore[attr-defined]
    session.source_pdf_file = device.state[alpha.SOURCE_PDF]
    session.source_mark_file = device.state[alpha.SOURCE_MARK]
    if initialize:
        if provision_parking:
            session._provision_parking(session.source_pdf_file)
        else:
            session.parking_file = device.state[alpha.PARKING_PDF]
            session._initialize_mutation_journal()
    session.cleanup["displayAbsent"] = True
    session.cleanup["hostTaskAbsent"] = True
    return session


def parking_provision_session(device: FixtureDevice) -> alpha.AlphaSession:
    temporary = test_temporary_directory()
    session = alpha.AlphaSession(
        device, Path(temporary.name), sleep=lambda _: None)
    session._test_temporary_directory = temporary  # type: ignore[attr-defined]
    session.source_pdf_file = device.state[alpha.SOURCE_PDF]
    session.source_mark_file = device.state[alpha.SOURCE_MARK]
    return session


class ParkingSwitchDevice(FixtureDevice):
    def __init__(self, mode: str = "success") -> None:
        super().__init__()
        self.mode = mode
        self.parking_launch_calls = 0
        self.process = foreign().process
        self.activity = activity_wire()
        self.parking_ui = (
            "<hierarchy rotation=\"1\"><node text=\"" +
            Path(alpha.PARKING_PDF).name + "\" package=\"" +
            alpha.DOCUMENT_PACKAGE +
            "\" displayed=\"true\" bounds=\"[20,20][620,90]\"/>"
            "<node text=\"1 / 1\"/></hierarchy>"
        ).encode("utf-8")
        self.links = (
            "lr-x------ 0 -> " + alpha.TARGET_PDF + "\n" +
            "lr-x------ 1 -> " + alpha.TARGET_MARK + "\n"
        )

    def pidof(self, package: str) -> tuple[int, ...]:
        if package != alpha.DOCUMENT_PACKAGE:
            raise AssertionError(package)
        return (self.process.pid,)

    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity:
        if (pid, package) != (self.process.pid, alpha.DOCUMENT_PACKAGE):
            raise AssertionError((pid, package))
        return self.process

    def activities(self) -> bytes:
        return self.activity

    def process_fd_links(self, pid: int) -> str:
        if pid != self.process.pid:
            raise AssertionError(pid)
        return self.links

    def ui_dump(self) -> bytes:
        return self.parking_ui

    def launch_parking_document(self, display_id: int) -> alpha.CommandResult:
        self.parking_launch_calls += 1
        if display_id != 3:
            raise AssertionError(display_id)
        # Real firmware keeps the original target task/activity intent stale
        # after delivering the parking URI to the same activity.
        self.activity = activity_wire()
        self.links = (
            "lr-x------ 0 -> " + alpha.PARKING_PDF + "\n" +
            "lr-x------ 1 -> " + alpha.PARKING_PDF + "\n"
        )
        if self.mode == "moved":
            self.activity = activity_wire(display_id=4)
        elif self.mode == "recreated":
            self.activity = self.activity.replace(b"4538", b"4539")
        elif self.mode == "token-changed":
            self.activity = self.activity.replace(b"11846f4", b"21846f4")
        elif self.mode == "intent-changed":
            self.activity = activity_wire(uri="file:///storage/emulated/0/Other.pdf")
        elif self.mode == "lingering-target":
            self.links += "lr-x------ 1 -> " + alpha.TARGET_PDF + "\n"
        elif self.mode == "unexpected-pdf":
            self.links += "lr-x------ 1 -> /storage/emulated/0/Other.pdf\n"
        elif self.mode == "unexpected-mark":
            self.links += "lr-x------ 1 -> /storage/emulated/0/Other.pdf.mark\n"
        elif self.mode == "parking-mark":
            self.state[alpha.PARKING_MARK] = device_file(
                alpha.PARKING_MARK, alpha.SOURCE_MARK_SHA256, 14)
        elif self.mode == "parking-inode-drift":
            self.state[alpha.PARKING_PDF] = device_file(
                alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 999)
        elif self.mode == "parking-hash-drift":
            self.state[alpha.PARKING_PDF] = device_file(
                alpha.PARKING_PDF, "e" * 64, 13)
        elif self.mode == "source-hash-drift":
            retained = self.state[alpha.SOURCE_PDF]
            self.state[alpha.SOURCE_PDF] = device_file(
                alpha.SOURCE_PDF, "e" * 64, retained.inode)
        elif self.mode == "target-hash-drift":
            retained = self.state[alpha.TARGET_PDF]
            self.state[alpha.TARGET_PDF] = device_file(
                alpha.TARGET_PDF, "f" * 64, retained.inode)
        elif self.mode == "mark-replaced":
            self.state[alpha.TARGET_MARK] = device_file(
                alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 777)
        elif self.mode == "mark-recreated":
            self.state.pop(alpha.TARGET_MARK, None)
            self.state[alpha.TARGET_MARK] = device_file(
                alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 778)
        elif self.mode == "mark-size-drift":
            value = device_file(
                alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 777)
            self.state[alpha.TARGET_MARK] = alpha.DeviceFile(
                value.path, value.kind, value.size + 1, value.uid, value.gid,
                value.inode, value.device, value.sha256)
        elif self.mode == "mark-hash-drift":
            value = device_file(alpha.TARGET_MARK, "d" * 64, 777)
            self.state[alpha.TARGET_MARK] = value
        elif self.mode == "mark-nonregular":
            value = device_file(
                alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 777)
            self.state[alpha.TARGET_MARK] = alpha.DeviceFile(
                value.path, "symbolic link", value.size, value.uid, value.gid,
                value.inode, value.device, value.sha256)
        elif self.mode == "ui-missing":
            self.parking_ui = (
                b"<hierarchy rotation=\"1\"><node text=\"other.pdf\"/>"
                b"</hierarchy>")
        result = alpha.CommandResult(
            "launch_parking_document", ("adb",), 0, b"Starting\n", b"")
        if self.mode == "lost-reply":
            raise alpha.AlphaError("simulated parking launch timeout")
        return result


def parking_switch_session(
        device: ParkingSwitchDevice,
        ) -> alpha.AlphaSession:
    clock = {"now": 0.0}

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    temporary = test_temporary_directory()
    session = alpha.AlphaSession(
        device, Path(temporary.name), sleep=sleep, now=lambda: clock["now"])
    session._test_temporary_directory = temporary  # type: ignore[attr-defined]
    session.source_pdf_file = device.state[alpha.SOURCE_PDF]
    session.source_mark_file = device.state[alpha.SOURCE_MARK]
    session._provision_parking(session.source_pdf_file)
    session._stage_fixture()
    authority = android.parse_document_task_authority(
        device.activity, expected_pid=PID)
    retained = host.ForeignIdentity(
        device.process, authority.task_id, authority.activity_token,
        android.stable_authority_sha256(authority), alpha.DOCUMENT_COMPONENT)
    session.status = status()
    session.foreign = retained
    session.foreign_authority = authority
    session.foreign_fixture_bound = True
    session.prelaunch_absence_sha256 = "a" * 64
    session.launch_owned = True
    session.document_launch_attempted = True
    session.attached = True
    session.close_started = True
    return session


class CommandBoundaryTests(unittest.TestCase):
    def test_document_launch_is_exact_and_serial_bound(self) -> None:
        argv = alpha.document_launch_argv("C:/sdk/adb.exe", 3)
        self.assertEqual(argv[1:3], ("-s", alpha.AUTHORIZED_SERIAL))
        self.assertEqual(argv[3:6], ("shell", "su", "-c"))
        self.assertEqual(
            argv[-1],
            "am start --user 0 --display 3 "
            "-a android.intent.action.VIEW "
            "-d file:///storage/emulated/0/Download/"
            "NativeViewportVisualOnly-Alpha-2eeadd7.pdf "
            "-t application/pdf "
            "-n com.supernote.document/"
            "com.supernote.document.document.DocumentActivity",
        )
        self.assertNotIn("force-stop", argv[-1])
        self.assertNotIn("input", argv[-1])

    def test_parking_launch_is_independently_exact_and_serial_bound(self) -> None:
        argv = alpha.parking_document_launch_argv("C:/sdk/adb.exe", 7)
        self.assertEqual(argv[1:6], (
            "-s", alpha.AUTHORIZED_SERIAL, "shell", "su", "-c"))
        self.assertEqual(
            argv[-1],
            "am start --user 0 --display 7 "
            "-a android.intent.action.VIEW "
            "-d file:///storage/emulated/0/Download/"
            ".NativeViewportParking-Alpha-2eeadd7.pdf "
            "-t application/pdf "
            "-n com.supernote.document/"
            "com.supernote.document.document.DocumentActivity",
        )
        target_command = alpha.document_launch_argv("C:/sdk/adb.exe", 7)[-1]
        self.assertNotEqual(argv[-1], target_command)

    def test_parking_launch_rejects_every_token_and_authority_mutation(self) -> None:
        command = alpha.parking_document_launch_argv("C:/sdk/adb.exe", 7)[-1]
        tokens = command.split(" ")
        for index in range(len(tokens)):
            changed = list(tokens)
            changed[index] = "changed"
            with self.subTest(index=index), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                    "shell", "su", "-c", " ".join(changed),
                ))
        variants = (
            command.replace(" --display 7 ", " --display 0 "),
            command.replace("android.intent.action.VIEW", "android.intent.action.MAIN"),
            command.replace(alpha.PARKING_URI, alpha.PARKING_URI + ".other"),
            command.replace("/Download/.", "/Document/."),
            command.replace("application/pdf", "application/octet-stream"),
            command.replace("DocumentActivity", "OtherActivity"),
            command + ";id",
        )
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                    "shell", "su", "-c", variant,
                ))
        target_command = alpha.document_launch_argv("C:/sdk/adb.exe", 7)[-1]
        self.assertNotEqual(target_command, command)
        self.assertEqual(
            alpha._safe_argv((
                "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                "shell", "su", "-c", target_command,
            ))[-1], target_command)
        for display in (False, 0, 1025, 7.0, "7"):
            with self.subTest(display=display), self.assertRaises(alpha.AlphaError):
                alpha.parking_document_launch_argv(
                    "C:/sdk/adb.exe", display)  # type: ignore[arg-type]

        mutations = (
            ("DOCUMENT_LAUNCH_USER", "10"),
            ("DOCUMENT_LAUNCH_ACTION", "android.intent.action.MAIN"),
            ("PARKING_URI", alpha.PARKING_URI + ".other"),
            ("DOCUMENT_LAUNCH_MIME", "application/octet-stream"),
            ("DOCUMENT_COMPONENT", alpha.DOCUMENT_COMPONENT + "Other"),
        )
        for name, value in mutations:
            with self.subTest(name=name), mock.patch.object(alpha, name, value):
                with self.assertRaises(alpha.AlphaError):
                    alpha.parking_document_launch_argv("C:/sdk/adb.exe", 7)

    def test_privileged_launch_rejects_every_command_token_mutation(self) -> None:
        argv = alpha.document_launch_argv("C:/sdk/adb.exe", 3)
        tokens = argv[-1].split(" ")
        self.assertEqual(len(tokens), 14)
        for index in range(len(tokens)):
            changed = list(tokens)
            changed[index] = "changed"
            with self.subTest(index=index), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                    "shell", "su", "-c", " ".join(changed),
                ))

    def test_privileged_launch_rejects_injection_and_path_variants(self) -> None:
        command = alpha.document_launch_argv("C:/sdk/adb.exe", 3)[-1]
        variants = (
            command + ";id",
            command + " && id",
            command.replace(" --display 3 ", " --display '3' "),
            command.replace("file:///storage/", "file:///data/"),
            command.replace("Alpha-2eeadd7.pdf", "Alpha-2eeadd7.pdf.mark"),
            command.replace("application/pdf", "application/octet-stream"),
            command.replace("DocumentActivity", "OtherActivity"),
            "am start --user 0 --display 3 -n " + alpha.DOCUMENT_COMPONENT,
        )
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                    "shell", "su", "-c", variant,
                ))
        for display in (False, 0, 1025, 3.0, "3"):
            with self.subTest(display=display), self.assertRaises(alpha.AlphaError):
                alpha.document_launch_argv("C:/sdk/adb.exe", display)  # type: ignore[arg-type]

    def test_privileged_launch_literals_are_independently_pinned(self) -> None:
        mutations = (
            ("DOCUMENT_LAUNCH_USER", "10"),
            ("DOCUMENT_LAUNCH_ACTION", "android.intent.action.MAIN"),
            ("TARGET_URI", alpha.TARGET_URI + ".other"),
            ("DOCUMENT_LAUNCH_MIME", "application/octet-stream"),
            ("DOCUMENT_COMPONENT", alpha.DOCUMENT_COMPONENT + "Other"),
        )
        for name, value in mutations:
            with self.subTest(name=name), mock.patch.object(alpha, name, value):
                with self.assertRaises(alpha.AlphaError):
                    alpha.document_launch_argv("C:/sdk/adb.exe", 3)

    def test_privileged_launch_preserves_full_argv_audit_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(returncode=0, stdout=b"Starting\n", stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            result = device.launch_document(7)
            expected = alpha.document_launch_argv(str(adb.resolve()), 7)
            self.assertEqual(calls, [expected])
            self.assertEqual(result.argv, expected)
            self.assertEqual(device.history[-1]["argv"], list(expected))
            self.assertEqual(device.history[-1]["operation"], "launch_document")

    def test_parking_copy_is_exact_no_clobber_and_not_removable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            device.copy_parking_pdf()
            self.assertEqual(calls[0][3:], (
                "shell", "cp", "-n", alpha.SOURCE_PDF, alpha.PARKING_PDF))
            with self.assertRaises(alpha.AlphaError):
                device.remove_quarantine_member(alpha.PARKING_PDF)

    def test_fixture_copy_uses_raw_exec_out_and_exact_created_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                values = tuple(argv)  # type: ignore[arg-type]
                calls.append(values)
                source = values[-2]
                return SimpleNamespace(
                    returncode=0,
                    stdout=("cp '" + source + "'\n").encode("ascii"),
                    stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            pairs = (
                (alpha.SOURCE_PDF, alpha.TARGET_PDF, "1" * 32),
                (alpha.SOURCE_MARK, alpha.TARGET_MARK, "2" * 32),
            )
            for index, (source, target, nonce) in enumerate(pairs):
                staging = alpha._staging_path(target, nonce)
                result = device.copy_fixture_member(source, staging)
                expected = (
                    str(adb.resolve()), "-s", alpha.AUTHORIZED_SERIAL,
                    "exec-out", "toybox", "cp", "-n", "-T", "-v",
                    source, staging,
                )
                self.assertEqual(calls[index], expected)
                self.assertEqual(result.argv, expected)
                self.assertEqual(device.history[index]["argv"], list(expected))
                self.assertEqual(result.stdout,
                                 ("cp '" + source + "'\n").encode("ascii"))

    def test_fixture_copy_rejects_every_raw_receipt_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            source = alpha.SOURCE_PDF
            staging = alpha._staging_path(alpha.TARGET_PDF, "1" * 32)
            exact = ("cp '" + source + "'\n").encode("ascii")
            mutations = (
                ("empty", b"", b""),
                ("no-terminal-lf", exact[:-1], b""),
                ("crlf", exact[:-1] + b"\r\n", b""),
                ("terminal-cr", exact[:-1] + b"\r", b""),
                ("double-lf", exact + b"\n", b""),
                ("leading-lf", b"\n" + exact, b""),
                ("leading-space", b" " + exact, b""),
                ("space-before-lf", exact[:-1] + b" \n", b""),
                ("extra-line", exact + b"extra\n", b""),
                ("wrong-source",
                 ("cp '" + alpha.SOURCE_MARK + "'\n").encode("ascii"), b""),
                ("destination-added",
                 ("cp '" + source + "' '" + staging + "'\n").encode("ascii"),
                 b""),
                ("quotes-removed", ("cp " + source + "\n").encode("ascii"),
                 b""),
                ("vertical-tab", exact[:-1] + b"\v", b""),
                ("form-feed", exact[:-1] + b"\f", b""),
                ("nul-after-lf", exact + b"\x00", b""),
                ("non-ascii", exact[:-1] + b"\xff\n", b""),
                ("stderr-warning", exact, b"warning"),
                ("stderr-lf", exact, b"\n"),
            )
            for label, stdout, stderr in mutations:
                with self.subTest(label=label):
                    rejected = alpha.AdbNomad(
                        adb, alpha.AUTHORIZED_SERIAL,
                        executor=lambda *args, output=stdout, error=stderr, **kwargs:
                        SimpleNamespace(returncode=0, stdout=output, stderr=error))
                    with self.assertRaises(alpha.AlphaError):
                        rejected.copy_fixture_member(source, staging)

    def test_fixture_copy_rejects_argv_pair_mutations_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            pdf_staging = alpha._staging_path(alpha.TARGET_PDF, "1" * 32)
            mark_staging = alpha._staging_path(alpha.TARGET_MARK, "2" * 32)
            mutations = (
                (alpha.SOURCE_MARK, pdf_staging),
                (alpha.SOURCE_PDF, mark_staging),
                (alpha.TARGET_PDF, pdf_staging),
                (alpha.SOURCE_PDF, alpha.TARGET_PDF),
                (alpha.SOURCE_PDF, pdf_staging + "-suffix"),
            )
            for source, staging in mutations:
                with self.subTest(source=source, staging=staging):
                    with self.assertRaises(alpha.AlphaError):
                        device.copy_fixture_member(source, staging)
            self.assertEqual(calls, [])

    def test_fixture_publication_uses_closed_one_shot_no_clobber_move(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            staging = alpha._staging_path(alpha.TARGET_MARK, "2" * 32)
            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            device.publish_fixture_member(staging, alpha.TARGET_MARK)
            device.remove_staging_member(staging)
            self.assertEqual(calls[0][3:], (
                "shell", "toybox", "mv", "-n", "-T", "-v",
                staging, alpha.TARGET_MARK))
            self.assertEqual(calls[1][3:], (
                "shell", "toybox", "rm", "-f", staging))
            with self.assertRaises(alpha.AlphaError):
                device.publish_fixture_member(staging, alpha.TARGET_PDF)
            with self.assertRaises(alpha.AlphaError):
                device.remove_staging_member(alpha.TARGET_MARK)
            rejected = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL,
                executor=lambda *args, **kwargs: SimpleNamespace(
                    returncode=0, stdout=b"unexpected\n", stderr=b""))
            with self.assertRaises(alpha.AlphaError):
                rejected.publish_fixture_member(staging, alpha.TARGET_MARK)

    def test_quarantine_move_and_remove_use_closed_random_path_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            quarantine = alpha._quarantine_path(alpha.TARGET_PDF, "a" * 32)
            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            device.move_fixture_to_quarantine(alpha.TARGET_PDF, quarantine)
            device.remove_quarantine_member(quarantine)
            self.assertEqual(calls[0][3:], (
                "shell", "toybox", "mv", "-n", "-T", "-v",
                alpha.TARGET_PDF, quarantine))
            self.assertEqual(calls[1][3:], (
                "shell", "toybox", "rm", "-f", quarantine))
            for target, value in (
                    (alpha.TARGET_MARK, quarantine),
                    (alpha.TARGET_PDF, quarantine + ".other"),
                    (alpha.PARKING_PDF, quarantine)):
                with self.subTest(target=target, value=value), self.assertRaises(
                        alpha.AlphaError):
                    device.move_fixture_to_quarantine(target, value)
            with self.assertRaises(alpha.AlphaError):
                device.remove_quarantine_member(alpha.TARGET_PDF)
            for operation in ("move", "remove"):
                with self.subTest(operation=operation):
                    rejected = alpha.AdbNomad(
                        adb, alpha.AUTHORIZED_SERIAL,
                        executor=lambda *args, **kwargs: SimpleNamespace(
                            returncode=0, stdout=b"unexpected\n", stderr=b""))
                    with self.assertRaises(alpha.AlphaError):
                        if operation == "move":
                            rejected.move_fixture_to_quarantine(
                                alpha.TARGET_PDF, quarantine)
                        else:
                            rejected.remove_quarantine_member(quarantine)

    def test_renamed_object_identity_is_path_specific_and_content_complete(self) -> None:
        original = device_file(
            alpha.TARGET_PDF, alpha.SOURCE_PDF_SHA256, 101)
        quarantine_path = alpha._quarantine_path(alpha.TARGET_PDF, "b" * 32)
        renamed = alpha.DeviceFile(
            quarantine_path, original.kind, original.size, original.uid,
            original.gid, original.inode, original.device, original.sha256)
        self.assertTrue(original.same_renamed_object(renamed))
        self.assertFalse(original.same_object(renamed))
        self.assertFalse(original.same_renamed_object(original))
        for changed in (
                alpha.DeviceFile(
                    quarantine_path, original.kind, original.size + 1,
                    original.uid, original.gid, original.inode,
                    original.device, original.sha256),
                alpha.DeviceFile(
                    quarantine_path, original.kind, original.size,
                    original.uid, original.gid, original.inode + 1,
                    original.device, original.sha256),
                alpha.DeviceFile(
                    quarantine_path, original.kind, original.size,
                    original.uid, original.gid, original.inode,
                    original.device, "f" * 64)):
            self.assertFalse(original.same_renamed_object(changed))

    def test_parking_launch_preserves_full_argv_audit_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(returncode=0, stdout=b"Starting\n", stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            result = device.launch_parking_document(7)
            expected = alpha.parking_document_launch_argv(
                str(adb.resolve()), 7)
            self.assertEqual(calls, [expected])
            self.assertEqual(result.argv, expected)
            self.assertEqual(
                device.history[-1]["operation"], "launch_parking_document")

    def test_safe_argv_rejects_any_unreviewed_magisk_command(self) -> None:
        for command in (
                "id", "rm -f /data/local/tmp/x", "am start -n x/.Y",
                "cat /proc/0/stat", "cat /proc/9999999/stat"):
            with self.subTest(command=command), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                    "shell", "su", "-c", command,
                ))

    def test_shell_and_su_aliases_never_bypass_the_exact_root_shape(self) -> None:
        command = alpha.document_launch_argv("C:/sdk/adb.exe", 3)[-1]
        variants = (
            ("shell", "/system/xbin/su", "-c", command),
            ("shell", "/system/bin/su", "-c", command),
            ("shell", "SU", "-c", command),
            ("shell", "/SYSTEM/BIN/SU", "-c", command),
            ("shell", "sh", "-c", command),
            ("shell", "/system/bin/sh", "-c", command),
            ("shell", "toybox", "sh", "-c", command),
            ("shell", "/system/bin/toybox", "/system/bin/sh", "-c", command),
            ("shell", "/system/bin/su -c " + command),
            ("shell", "toybox sh -c " + command),
            ("shell", "su", "-c", command, "extra"),
            ("shell", "Su", "-c", command),
            ("/system/bin/sh", "-c", command),
        )
        for tail in variants:
            with self.subTest(tail=tail), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "C:/sdk/adb.exe", "-s", alpha.AUTHORIZED_SERIAL, *tail,
                ))

    def test_remove_is_one_retained_root_task_and_never_process_kill(self) -> None:
        argv = alpha.exact_task_remove_argv("C:/sdk/adb.exe", 4538)
        self.assertEqual(
            argv[3:], ("shell", "am", "stack", "remove", "4538"))
        self.assertFalse(any(value in argv for value in ("kill", "force-stop", "pkill")))
        with self.assertRaises(alpha.AlphaError):
            alpha.exact_task_remove_argv("C:/sdk/adb.exe", 0)

    def test_attach_command_carries_complete_retained_identity(self) -> None:
        argv = alpha.host_command_argv(
            "C:/sdk/adb.exe", status(), 1, alpha.ACTION_ATTACH, foreign())
        self.assertEqual(argv[1:3], ("-s", alpha.AUTHORIZED_SERIAL))
        self.assertIn("foreignTask", argv)
        self.assertIn("4538", argv)
        self.assertIn("foreignStartTicks", argv)
        self.assertIn("123456", argv)
        self.assertIn("foreignEvidenceSha256", argv)

    def test_empty_abort_cannot_borrow_a_foreign_payload(self) -> None:
        argv = alpha.host_command_argv(
            "C:/sdk/adb.exe", status("WAITING_FOR_FOREIGN_ATTACH"), 1,
            alpha.ACTION_EMPTY_PRE_ATTACH, absence_sha256="b" * 64)
        self.assertIn("absenceEvidenceSha256", argv)
        self.assertNotIn("foreignTask", argv)
        with self.assertRaises(alpha.AlphaError):
            alpha.host_command_argv(
                "C:/sdk/adb.exe", status(), 1, alpha.ACTION_FULL,
                foreign=foreign())

    def test_serial_and_forbidden_primitives_are_rejected(self) -> None:
        with self.assertRaises(alpha.AlphaError):
            alpha._safe_argv(("adb.exe", "-s", "another-device", "get-state"))
        with self.assertRaises(alpha.AlphaError):
            alpha._safe_argv((
                "adb.exe", "-s", alpha.AUTHORIZED_SERIAL, "get-state", "-s",
                alpha.AUTHORIZED_SERIAL))
        for primitive in ("input", "keyevent", "force-stop", "kill", "settings"):
            with self.subTest(primitive=primitive), self.assertRaises(alpha.AlphaError):
                alpha._safe_argv((
                    "adb.exe", "-s", alpha.AUTHORIZED_SERIAL, "shell", primitive))
        with self.assertRaises(alpha.AlphaError):
            alpha._safe_argv((
                "adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                "shell", "getprop|id"))
        with self.assertRaises(alpha.AlphaError):
            alpha._safe_argv((
                "adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                "shell", "dumpsys", "input", "extra"))
        with self.assertRaises(alpha.AlphaError):
            alpha._safe_argv((
                "adb.exe", "-s", alpha.AUTHORIZED_SERIAL,
                "shell", "dumpsys", "input"))

    def test_read_only_window_displays_runs_through_real_adb_adapter_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []
            wire = window_displays_wire()

            def execute(argv: object, **kwargs: object) -> object:
                calls.append(tuple(argv))  # type: ignore[arg-type]
                return SimpleNamespace(
                    returncode=0, stdout=wire, stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            self.assertEqual(device.window_displays(), wire)
            self.assertEqual(calls, [(
                str(adb.resolve()), "-s", alpha.AUTHORIZED_SERIAL,
                "shell", "dumpsys", "window", "displays")])
            with self.assertRaises(alpha.AlphaError):
                alpha.AdbNomad(adb, "another-device", executor=execute)

    def test_root_proc_reads_use_closed_magisk_command_form(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adb = Path(directory) / "adb.exe"
            adb.write_bytes(b"test executable placeholder")
            calls: list[tuple[str, ...]] = []
            tail = ["S"] + ["1"] * 18 + ["123456"]

            def execute(argv: object, **kwargs: object) -> object:
                command = tuple(argv)[-1]  # type: ignore[arg-type]
                calls.append(tuple(argv))  # type: ignore[arg-type]
                if command.endswith("/stat"):
                    stdout = (f"{PID} (com.supernote.document) " +
                              " ".join(tail) + "\n").encode("ascii")
                elif command.endswith("/status"):
                    stdout = b"Name:\tdocument\nUid:\t1000\t1000\t1000\t1000\n"
                elif command.endswith("/cmdline"):
                    stdout = alpha.DOCUMENT_PACKAGE.encode("ascii") + b"\x00"
                elif command.endswith("/fd"):
                    stdout = b"total 0\n"
                else:
                    raise AssertionError("unexpected root command " + command)
                return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

            device = alpha.AdbNomad(
                adb, alpha.AUTHORIZED_SERIAL, executor=execute)
            identity = device.process_identity(PID, alpha.DOCUMENT_PACKAGE)
            self.assertEqual(identity.pid, PID)
            self.assertEqual(identity.start_ticks, 123456)
            self.assertEqual(device.process_fd_links(PID), "total 0\n")
            expected = (
                f"cat /proc/{PID}/stat",
                f"cat /proc/{PID}/status",
                f"cat /proc/{PID}/cmdline",
                f"ls -l /proc/{PID}/fd",
            )
            self.assertEqual(tuple(call[-1] for call in calls), expected)
            self.assertTrue(all(call[3:6] == ("shell", "su", "-c")
                                for call in calls))
            with self.assertRaises(alpha.AlphaError):
                device._root_proc_file(PID, "environ")

    def test_runner_has_no_inputmanager_orientation_command(self) -> None:
        source = Path(alpha.__file__).read_text(encoding="utf-8")
        self.assertNotIn("def input_dump", source)
        self.assertNotIn('(\"shell\", \"dumpsys\", \"input\")', source)

    def test_android_11_tilde_split_base_apk_is_in_the_closed_path_grammar(self) -> None:
        self.assertIsNotNone(alpha.SAFE_APK.fullmatch(
            "/data/app/~~token/com.techrebbe.supernote.nativepagehost-token/base.apk"))
        self.assertIsNone(alpha.SAFE_APK.fullmatch(
            "/data/app/~~token/../user-document.pdf"))

    def test_transport_error_retains_sequence_and_blocks_different_command(self) -> None:
        calls: list[str] = []

        def fail_send(*args: object, **kwargs: object) -> None:
            calls.append(str(args[2]))
            raise alpha.AlphaError("transport uncertain")

        device = SimpleNamespace(history=[], send_host=fail_send)
        session = alpha.AlphaSession(device, Path("."))
        session.status = status()
        with self.assertRaises(alpha.AlphaError):
            session._send(alpha.ACTION_FULL)
        self.assertEqual(session.pending_host_command, (alpha.ACTION_FULL, 1))
        with self.assertRaises(alpha.AlphaError):
            session._send(alpha.ACTION_CLOSE)
        self.assertEqual(session.sequence, 1)
        self.assertEqual(calls, [alpha.ACTION_FULL])

    def test_read_only_exact_placement_event_can_settle_cleanup_sequence(self) -> None:
        device = SimpleNamespace(
            history=[],
            host_logs=lambda pid: (
                "PLACEMENT_READY session=" + SESSION +
                " generation=1 sequence=4 requested=LEFT effective=LEFT\n"),
        )
        session = alpha.AlphaSession(device, Path("."))
        session.status = status()
        session.host_pid = 4321
        session.sequence = 4
        session.pending_host_command = (alpha.ACTION_LEFT, 4)
        session._read_status = lambda: status()  # type: ignore[method-assign]
        session._settle_placement_for_cleanup()
        self.assertIsNone(session.pending_host_command)


class CoordinatorScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = Path(alpha.__file__).with_name(
            "run-native-page-alpha.ps1").read_text(encoding="utf-8")

    def test_coordinator_is_fixed_to_the_one_authorized_nomad(self) -> None:
        self.assertIn("[ValidateSet('SN078C10015092')]", self.script)
        self.assertIn("$authorizedSerial = 'SN078C10015092'", self.script)
        self.assertIn(
            "& $installHelper -Serial $authorizedSerial -AndroidSdk $androidSdk",
            self.script)
        self.assertIn("--serial $authorizedSerial", self.script)
        self.assertNotIn("-AllowPersistentUpgrade", self.script)

    def test_rotation_authority_is_closed_and_manual_by_default(self) -> None:
        self.assertIn(
            "[ValidateSet('manual-physical-v1', 'adb-system-settings-v1')]",
            self.script)
        self.assertIn(
            "[string]$RotationAuthority = 'manual-physical-v1'", self.script)
        self.assertEqual(
            self.script.count("--rotation-authority $RotationAuthority"), 1)
        self.assertNotIn(" shell settings ", self.script.lower())
        self.assertIn(
            "$rotationController = Join-Path $PSScriptRoot "
            "'native_page_alpha_rotation_controller.py'", self.script)
        self.assertEqual(self.script.count("& $pythonRuntime -u $runner"), 1)
        self.assertEqual(
            self.script.count("& $pythonRuntime -u $rotationController"), 1)
        self.assertIn("$controllerNonce = [Guid]::NewGuid().ToString('N')",
                      self.script)
        self.assertIn("--journal $rotationJournal --evidence $rotationEvidence",
                      self.script)
        required_tools = self.script.index(
            "$requiredTools = @($adb, $pythonRuntime, $buildHelper, "
            "$installHelper, $runner)")
        controller_required = self.script.index(
            "$requiredTools += $rotationController", required_tools)
        adb_branch = self.script.rindex(
            "if ($RotationAuthority -ceq 'adb-system-settings-v1')",
            required_tools, controller_required)
        required_loop = self.script.index("foreach ($required in $requiredTools)",
                                          controller_required)
        self.assertLess(required_tools, adb_branch)
        self.assertLess(adb_branch, controller_required)
        self.assertLess(controller_required, required_loop)

    def test_read_only_nomad_gate_precedes_build_and_install(self) -> None:
        expected = (
            "$adb -s $authorizedSerial get-state",
            "$adb -s $authorizedSerial get-serialno",
            "$adb -s $authorizedSerial shell getprop ro.product.model",
            "$adb -s $authorizedSerial shell getprop ro.build.version.sdk",
            "$adb -s $authorizedSerial shell getprop ro.build.fingerprint",
            "$adb -s $authorizedSerial shell am get-current-user",
        )
        build = self.script.index("& $buildHelper")
        install = self.script.index("& $installHelper")
        for command in expected:
            with self.subTest(command=command):
                self.assertEqual(self.script.count(command), 1)
                self.assertLess(self.script.index(command), build)
        self.assertLess(build, install)
        self.assertIn("$authorizedModel = 'Supernote Nomad'", self.script)
        self.assertIn("$authorizedSdk = '30'", self.script)
        self.assertIn(
            "eng.supern.20260616.100032:user/release-keys'", self.script)
        self.assertIn("$authorizedUser = '0'", self.script)
        for line in self.script.splitlines():
            if "& $adb" in line:
                self.assertIn("-s $authorizedSerial", line)

    def test_exact_session_lock_spans_install_run_and_rollback(self) -> None:
        exact_path = (
            "SupernoteAlpha\\NativePageHostLocks\\SN078C10015092")
        self.assertIn(exact_path, self.script)
        opened = self.script.index("[IO.File]::Open(")
        exclusive = self.script.index("[IO.FileShare]::None", opened)
        install = self.script.index("-SessionLock $sessionLock", exclusive)
        run = self.script.index("& $pythonRuntime -u $runner", install)
        controlled_run = self.script.index(
            "& $pythonRuntime -u $rotationController", run)
        rollback = self.script.index(" uninstall $hostPackage", run)
        dispose = self.script.index("$sessionLock.Dispose()", rollback)
        final_exit = self.script.index("exit $coordinatorExitCode", dispose)
        self.assertLess(opened, exclusive)
        self.assertLess(exclusive, install)
        self.assertLess(install, run)
        self.assertLess(run, controlled_run)
        self.assertLess(controlled_run, rollback)
        self.assertLess(rollback, dispose)
        self.assertLess(dispose, final_exit)
        self.assertEqual(self.script.count("$sessionLock.Dispose()"), 1)
        self.assertEqual(self.script.count("\nexit "), 1)

    def test_coordinator_has_no_skip_build_route(self) -> None:
        self.assertNotIn("SkipBuild", self.script)
        self.assertEqual(self.script.count("& $buildHelper"), 1)

    def test_build_install_and_runner_order_is_closed(self) -> None:
        build = self.script.index("& $buildHelper")
        install = self.script.index("& $installHelper")
        run = self.script.index("& $pythonRuntime -u $runner")
        controlled_run = self.script.index(
            "& $pythonRuntime -u $rotationController")
        uninstall = self.script.index(
            "& $adb -s $authorizedSerial uninstall $hostPackage")
        self.assertLess(build, install)
        self.assertLess(install, run)
        self.assertLess(run, controlled_run)
        self.assertLess(controlled_run, uninstall)
        self.assertEqual(self.script.count(" uninstall $hostPackage"), 1)

    def test_installer_must_exit_zero_before_its_receipt_is_admitted(self) -> None:
        install = self.script.index("& $installHelper")
        capture = self.script.index(
            "$installExitCode = $LASTEXITCODE", install)
        require_zero = self.script.index(
            "if ($installExitCode -ne 0)", capture)
        receipt = self.script.index("$receiptPattern =", require_zero)
        self.assertLess(install, capture)
        self.assertLess(capture, require_zero)
        self.assertLess(require_zero, receipt)

    def test_new_install_is_retained_on_uncertain_cleanup(self) -> None:
        failed = self.script.index("if ($runnerExitCode -notin @(0, 3))")
        retained = self.script.index(
            "The newly installed host is retained", failed)
        success = self.script.index(
            "if ($priorPackage -ceq 'absent')", retained)
        uninstall = self.script.index(" uninstall $hostPackage", success)
        self.assertLess(failed, retained)
        self.assertLess(retained, success)
        self.assertLess(success, uninstall)

    def test_clean_diagnostic_failure_is_rolled_back_then_propagated(self) -> None:
        admitted = self.script.index("if ($runnerExitCode -notin @(0, 3))")
        uninstall = self.script.index(" uninstall $hostPackage", admitted)
        propagate = self.script.index("if ($runnerExitCode -eq 3)", uninstall)
        self.assertLess(admitted, uninstall)
        self.assertLess(uninstall, propagate)

    def test_package_receipt_is_exact_and_upgrade_fails_closed(self) -> None:
        self.assertIn("priorPackage=(absent|same|upgraded)", self.script)
        self.assertIn("absent = 'uninstall-required'", self.script)
        self.assertIn("same = 'unchanged'", self.script)
        self.assertIn("upgraded = 'not-exact'", self.script)
        self.assertIn("if ($priorPackage -ceq 'upgraded')", self.script)
        self.assertIn(
            "apkSha256=" + alpha.ALPHA_SIGNED_APK_SHA256, self.script)
        self.assertIn(
            "signerSha256=" + alpha.ALPHA_SIGNER_CERT_SHA256, self.script)
        self.assertIn("versionCode=2", self.script)

    def test_coordinator_has_no_broad_device_or_file_mutation(self) -> None:
        lowered = self.script.lower()
        for forbidden in (
                "force-stop", " shell input ", " shell am start", " pm clear ",
                " pkill ", " kill ", "remove-item", "remove-directory"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)


class ParserTests(unittest.TestCase):
    @staticmethod
    def runner_arguments() -> list[str]:
        return [
            "--adb", "adb.exe", "--serial", alpha.AUTHORIZED_SERIAL,
            "--output-root", ".", "--host-metadata", "metadata.json",
        ]

    def test_cli_rotation_authority_defaults_to_manual(self) -> None:
        arguments = alpha._parser().parse_args(self.runner_arguments())
        self.assertEqual(
            arguments.rotation_authority, alpha.ROTATION_MANUAL_PHYSICAL)

    def test_cli_adb_rotation_authority_is_explicit(self) -> None:
        arguments = alpha._parser().parse_args(
            self.runner_arguments() + [
                "--rotation-authority", alpha.ROTATION_ADB_SYSTEM_SETTINGS,
                "--rotation-controller-run-id", CONTROLLER_ID,
            ])
        self.assertEqual(
            arguments.rotation_authority,
            alpha.ROTATION_ADB_SYSTEM_SETTINGS)
        self.assertEqual(arguments.rotation_controller_run_id, CONTROLLER_ID)

    def test_rotation_controller_id_is_required_only_for_adb_mode(self) -> None:
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession(
                SimpleNamespace(history=[]), Path("."),
                rotation_authority=alpha.ROTATION_ADB_SYSTEM_SETTINGS)
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession(
                SimpleNamespace(history=[]), Path("."),
                rotation_authority=alpha.ROTATION_ADB_SYSTEM_SETTINGS,
                rotation_controller_run_id="A" * 32)
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession(
                SimpleNamespace(history=[]), Path("."),
                rotation_controller_run_id=CONTROLLER_ID)
        session = alpha.AlphaSession(
            SimpleNamespace(history=[]), Path("."),
            rotation_authority=alpha.ROTATION_ADB_SYSTEM_SETTINGS,
            rotation_controller_run_id=CONTROLLER_ID)
        self.assertEqual(session.rotation_controller_run_id, CONTROLLER_ID)

    def test_rotation_phase_wire_is_exact_flushed_and_ordered(self) -> None:
        class PartialBuffer:
            def __init__(self) -> None:
                self.raw = bytearray()
                self.flushes = 0
            def write(self, raw: bytes) -> int:
                count = min(3, len(raw))
                self.raw.extend(raw[:count])
                return count
            def flush(self) -> None:
                self.flushes += 1

        session = alpha.AlphaSession(
            SimpleNamespace(history=[]), Path("."),
            rotation_authority=alpha.ROTATION_ADB_SYSTEM_SETTINGS,
            rotation_controller_run_id=CONTROLLER_ID)
        buffer = PartialBuffer()
        stdout = SimpleNamespace(buffer=buffer)
        with mock.patch.object(alpha.sys, "stdout", stdout):
            session._emit_rotation_controller_phase("START_LANDSCAPE")
            session._emit_rotation_controller_phase("PORTRAIT")
            session._emit_rotation_controller_phase("RETURN_LANDSCAPE")
        expected = b"".join(
            alpha.ROTATION_CONTROLLER_PHASE_PREFIX +
            alpha._canonical_json_bytes({
                "authority": alpha.ROTATION_CONTROLLER_PHASE_AUTHORITY,
                "controllerId": CONTROLLER_ID,
                "phase": phase,
                "sequence": sequence,
            }) + b"\n"
            for sequence, phase in enumerate(
                alpha.ROTATION_CONTROLLER_PHASES, 1))
        self.assertEqual(bytes(buffer.raw), expected)
        self.assertEqual(buffer.flushes, 3)
        self.assertEqual(
            session.rotation_controller_phases,
            list(alpha.ROTATION_CONTROLLER_PHASES))
        with self.assertRaises(alpha.AlphaError):
            session._emit_rotation_controller_phase("RETURN_LANDSCAPE")

    def test_manual_mode_cannot_emit_a_controller_phase(self) -> None:
        session = alpha.AlphaSession(SimpleNamespace(history=[]), Path("."))
        with self.assertRaises(alpha.AlphaError):
            session._emit_rotation_controller_phase("START_LANDSCAPE")

    def test_session_rejects_rotation_authority_outside_closed_choices(self) -> None:
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession(
                SimpleNamespace(history=[]), Path("."),
                rotation_authority="automatic")

    def test_status_is_read_from_one_exact_ui_node(self) -> None:
        value = (
            "NATIVE PAGE HOST — VISUAL ONLY\n"
            f"session={SESSION}\n"
            "generation=1 display=3\n"
            "state=WAITING_FOR_FOREIGN_ATTACH\n"
            "Externally launch + verify Document"
        )
        escaped = value.replace("&", "&amp;").replace("\n", "&#10;")
        raw = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'
            '<hierarchy rotation="1"><node text="' + escaped + '"/></hierarchy>'
        ).encode("utf-8")
        parsed = alpha.parse_host_status(raw)
        self.assertEqual(
            (parsed.session, parsed.generation, parsed.display_id, parsed.state),
            (SESSION, 1, 3, "WAITING_FOR_FOREIGN_ATTACH"))
        self.assertEqual(
            parsed.display_name, "NativePageVisualOnly-" + SESSION + "-1")

    def test_parking_ui_witness_requires_exact_filename(self) -> None:
        filename = Path(alpha.PARKING_PDF).name
        raw = (
            "noise<hierarchy rotation=\"1\"><node text=\"" + filename +
            "\" package=\"" + alpha.DOCUMENT_PACKAGE +
            "\" displayed=\"true\" bounds=\"[10,20][610,90]\"/>"
            "<node text=\"1 / 7\"/></hierarchy>noise"
        ).encode("utf-8")
        witness = alpha.parse_parking_ui_witness(raw)
        self.assertEqual(witness["filename"], filename)
        self.assertEqual(witness["pageCount"], "1/7")
        self.assertEqual(witness["bounds"], [10, 20, 610, 90])
        self.assertEqual(witness["package"], alpha.DOCUMENT_PACKAGE)
        self.assertEqual(witness["rotation"], 1)
        without_package = raw.replace(
            (" package=\"" + alpha.DOCUMENT_PACKAGE + "\"").encode("utf-8"),
            b"", 1)
        self.assertIsNone(
            alpha.parse_parking_ui_witness(without_package)["package"])
        valid_node = (
            "<node text=\"" + filename + "\" package=\"" +
            alpha.DOCUMENT_PACKAGE +
            "\" displayed=\"true\" bounds=\"[10,20][610,90]\"/>")
        invalid = (
            b"<hierarchy rotation=\"1\"><node text=\"other.pdf\"/></hierarchy>",
            ("<hierarchy rotation=\"1\">" + valid_node +
             "<node text=\"" + Path(alpha.TARGET_PDF).name +
             "\"/></hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" + valid_node +
             "<node text=\"Open /storage/emulated/0/Download/" +
             Path(alpha.TARGET_PDF).name +
             " now\"/></hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" + valid_node +
             "<node text=\"1/7\"/><node text=\"2/7\"/>"
             "</hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" +
             valid_node.replace('displayed=\"true\"', 'displayed=\"false\"') +
             "</hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" +
             valid_node.replace("[10,20][610,90]", "[1800,20][1900,90]") +
             "</hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" +
             valid_node.replace("[10,20][610,90]", "[10,20][10,90]") +
             "</hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" + valid_node + valid_node +
             "</hierarchy>").encode("utf-8"),
            ("<hierarchy rotation=\"1\">" +
             valid_node.replace(alpha.DOCUMENT_PACKAGE, "com.example.other") +
             "</hierarchy>").encode("utf-8"),
            ("<hierarchy>" + valid_node + "</hierarchy>").encode("utf-8"),
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(alpha.AlphaError):
                alpha.parse_parking_ui_witness(value)

    def test_duplicate_status_node_is_rejected(self) -> None:
        value = (
            f"NATIVE PAGE HOST&#10;session={SESSION}&#10;"
            "generation=1 display=3&#10;state=ACTIVE"
        )
        raw = (
            '<hierarchy><node text="' + value + '"/><node text="' +
            value + '"/></hierarchy>'
        ).encode("ascii")
        with self.assertRaises(alpha.AlphaError):
            alpha.parse_host_status(raw)

    def test_png_dimensions_are_bound_to_each_manual_orientation(self) -> None:
        self.assertEqual(alpha.parse_png(png(1872, 1404), "left").width, 1872)
        self.assertEqual(alpha.parse_png(png(1404, 1872), "portrait").height, 1872)
        self.assertEqual(alpha._screen_dimensions("portrait"), (1404, 1872))
        self.assertEqual(alpha._screen_dimensions("landscape_return"), (1872, 1404))
        with self.assertRaises(alpha.AlphaError):
            alpha.parse_png(png(1404, 1872), "right")

    def test_png_requires_crc_chunks_exact_zlib_rows_and_eof(self) -> None:
        width, height = 1872, 1404
        ihdr = png_chunk(
            b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        valid = png(width, height)
        corrupt_crc = bytearray(valid)
        corrupt_crc[29] ^= 1
        cases = {
            "IHDR CRC": bytes(corrupt_crc),
            "trailing bytes": valid + b"x",
            "truncated IEND": valid[:-1],
            "missing IDAT": (
                alpha.PNG_SIGNATURE + ihdr + png_chunk(b"IEND", b"")),
            "duplicate IHDR": (
                alpha.PNG_SIGNATURE + ihdr + ihdr +
                png_chunk(b"IDAT", zlib.compress(
                    (b"\x00" + bytes(width * 3)) * height)) +
                png_chunk(b"IEND", b"")),
            "unknown critical": (
                alpha.PNG_SIGNATURE + ihdr + png_chunk(b"ABCD", b"") +
                valid[len(alpha.PNG_SIGNATURE) + len(ihdr):]),
            "nonzero reserved bit": (
                alpha.PNG_SIGNATURE + ihdr + png_chunk(b"aaad", b"") +
                valid[len(alpha.PNG_SIGNATURE) + len(ihdr):]),
            "bad zlib": png(width, height, compressed=b"not-zlib"),
            "short inflated row": png(
                width, height, truncate_row=True),
            "invalid row filter": png(width, height, row_filter=5),
        }
        for label, raw in cases.items():
            with self.subTest(label=label), self.assertRaises(alpha.AlphaError):
                alpha.parse_png(raw, "full")

    def test_real_nomad_display_zero_dialect_drives_physical_orientation(self) -> None:
        # The landscape record mirrors the second hardware preflight: the
        # natural display is 1404x1872, while current/app/frame are 1872x1404
        # and every display-0 rotation authority is 1.
        real_dialect = window_displays_wire()
        self.assertIn(
            b"  Display: mDisplayId=0 stacks=5\n", real_dialect)
        self.assertEqual(alpha._physical_orientation(real_dialect), 1)
        self.assertEqual(alpha._physical_orientation(
            window_displays_wire(3)), 3)
        self.assertEqual(alpha._physical_orientation(
            window_displays_wire(0, (1404, 1872))), 0)
        self.assertEqual(alpha._physical_orientation(
            window_displays_wire(2, (1404, 1872))), 2)
        self.assertEqual(alpha._physical_orientation(
            window_displays_wire(
                0, (1404, 1872), deferred_rotation_suffix="")), 0)
        self.assertEqual(alpha._starting_landscape_orientation(
            window_displays_wire()), 1)
        with self.assertRaises(alpha.AlphaError):
            alpha._starting_landscape_orientation(
                window_displays_wire(0, (1404, 1872)))

    def test_display_header_requires_one_canonical_stacks_suffix(self) -> None:
        valid = b"Display: mDisplayId=0 stacks=5"
        self.assertEqual(alpha._physical_orientation(
            window_displays_wire().replace(
                valid, b"Display: mDisplayId=0 stacks=0", 1)), 1)
        cases = {
            "missing stacks": b"Display: mDisplayId=0",
            "duplicate stacks": b"Display: mDisplayId=0 stacks=5 stacks=5",
            "leading-zero stacks": b"Display: mDisplayId=0 stacks=05",
            "negative stacks": b"Display: mDisplayId=0 stacks=-1",
            "empty stacks": b"Display: mDisplayId=0 stacks=",
            "extra suffix": b"Display: mDisplayId=0 stacks=5 extra=1",
            "leading-zero display": b"Display: mDisplayId=00 stacks=5",
        }
        wire = window_displays_wire()
        for label, replacement in cases.items():
            with self.subTest(label=label), self.assertRaises(alpha.AlphaError):
                alpha._physical_orientation(wire.replace(
                    valid, replacement, 1))

    def test_display_zero_orientation_rejects_duplicates_and_disagreement(self) -> None:
        cases = {
            "duplicate display zero": window_displays_wire().replace(
                b"Display: mDisplayId=7", b"Display: mDisplayId=0"),
            "duplicate scoped rotation": window_displays_wire(
                extra_display_zero_line="    mRotation=1\n"),
            "three rotations disagree": window_displays_wire(
                info_rotation=1, frame_rotation=3, final_rotation=1),
            "current and app disagree": window_displays_wire(
                app_dimensions=(1404, 1872)),
            "current and frame disagree": window_displays_wire(
                frame_dimensions=(1404, 1872)),
            "landscape dimensions with portrait rotation":
                window_displays_wire(0, (1872, 1404)),
            "portrait dimensions with landscape rotation":
                window_displays_wire(1, (1404, 1872)),
            "duplicate DisplayInfo rotation": window_displays_wire().replace(
                b"rotation 1, state", b"rotation 1, rotation 1, state", 1),
            "same-line duplicate metrics authority":
                window_displays_wire().replace(
                    b"app=1872x1404\n",
                    b"app=1872x1404 init=999x999\n", 1),
            "same-line duplicate frame rotation":
                window_displays_wire().replace(
                    b"DisplayFrames w=1872 h=1404 r=1\n",
                    b"DisplayFrames w=1872 h=1404 r=1 r=3\n", 1),
            "misplaced rotation authority":
                window_displays_wire().replace(
                    b"app=1872x1404\n",
                    b"app=1872x1404 mRotation=3\n", 1),
            "DisplayInfo belongs to another display":
                window_displays_wire().replace(
                    b"displayId 0, rotation", b"displayId 7, rotation", 1),
            "duplicate DisplayInfo identity":
                window_displays_wire().replace(
                    b"displayId 0, rotation",
                    b"displayId 0, displayId 0, rotation", 1),
            "deferred rotation still pending": window_displays_wire(
                deferred_rotation_suffix=" mDeferredRotationPauseCount=1"),
            "duplicate deferred rotation field": window_displays_wire(
                deferred_rotation_suffix=(
                    " mDeferredRotationPauseCount=0"
                    " mDeferredRotationPauseCount=0")),
            "malformed deferred rotation field": window_displays_wire(
                deferred_rotation_suffix=" mDeferredRotationPauseCount=-1"),
            "extra rotation suffix field": window_displays_wire(
                deferred_rotation_suffix=(
                    " mDeferredRotationPauseCount=0 extra=1")),
            "separate contradictory deferred rotation field":
                window_displays_wire(
                    extra_display_zero_line=(
                        "    mDeferredRotationPauseCount=1\n")),
            "separate misplaced deferred rotation field":
                window_displays_wire(
                    deferred_rotation_suffix="",
                    extra_display_zero_line=(
                        "    mDeferredRotationPauseCount=0\n")),
            "missing display zero": window_displays_wire().replace(
                b"Display: mDisplayId=0", b"Display: mDisplayId=2", 1),
        }
        for label, raw in cases.items():
            with self.subTest(label=label), self.assertRaises(alpha.AlphaError):
                alpha._physical_orientation(raw)

    def test_manual_rotation_gate_uses_windowmanager_for_both_directions(self) -> None:
        wires = iter((
            window_displays_wire(0, (1404, 1872)),
            window_displays_wire(3, (1872, 1404)),
        ))
        calls = {"count": 0}

        def read_displays() -> bytes:
            calls["count"] += 1
            return next(wires)

        device = SimpleNamespace(
            history=[], window_displays=read_displays)
        session = alpha.AlphaSession(
            device, Path("."), sleep=lambda _: None)
        session.status = status()
        session._wait_status = lambda states: status()  # type: ignore[method-assign]
        session._reverify_foreign = lambda: None  # type: ignore[method-assign]
        self.assertEqual(
            session._wait_physical_orientation(portrait=True), 0)
        self.assertEqual(
            session._wait_physical_orientation(portrait=False, exact=3), 3)
        self.assertEqual(calls["count"], 2)
        self.assertEqual(session.portrait_orientation, 0)
        self.assertEqual(session.returned_orientation, 3)

    def test_adb_rotation_gate_observes_without_claiming_physical_sensor(self) -> None:
        wires = iter((
            window_displays_wire(0, (1404, 1872)),
            window_displays_wire(1, (1872, 1404)),
        ))
        device = SimpleNamespace(
            history=[], window_displays=lambda: next(wires))
        session = alpha.AlphaSession(
            device, Path("."), sleep=lambda _: None,
            rotation_authority=alpha.ROTATION_ADB_SYSTEM_SETTINGS,
            rotation_controller_run_id=CONTROLLER_ID)
        session.status = status()
        session._wait_status = lambda states: status()  # type: ignore[method-assign]
        session._reverify_foreign = lambda: None  # type: ignore[method-assign]
        self.assertEqual(
            session._wait_physical_orientation(portrait=True), 0)
        self.assertEqual(
            session._wait_physical_orientation(portrait=False, exact=1), 1)
        self.assertEqual(
            [event["name"] for event in session.events],
            ["adb_rotation_orientation_observed"] * 2)
        self.assertTrue(all(
            event["rotationAuthority"] ==
            alpha.ROTATION_ADB_SYSTEM_SETTINGS
            for event in session.events))

    def test_starting_landscape_gate_accepts_portrait_launcher_then_landscape(self) -> None:
        wires = iter((
            window_displays_wire(0, (1404, 1872)),
            window_displays_wire(1, (1872, 1404)),
        ))
        device = SimpleNamespace(
            history=[],
            window_displays=lambda: next(wires),
        )
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None,
                                     now=iter((0.0, 0.1, 0.2)).__next__)
        session.status = status("ACTIVE")
        session.host_pid = PID
        session.foreign = foreign()
        session.attached = True
        session._wait_status = lambda states: status("ACTIVE")  # type: ignore[method-assign]
        session._reverify_foreign = lambda: None  # type: ignore[method-assign]
        self.assertEqual(session._wait_starting_landscape(), 1)
        self.assertEqual(session.starting_orientation, 1)
        self.assertEqual(session.returned_orientation, None)
        self.assertEqual(session.events[-1]["phase"], "post_attach")

    def test_starting_landscape_gate_requires_attached_foreign(self) -> None:
        session = alpha.AlphaSession(SimpleNamespace(history=[]), Path("."))
        session.status = status("ACTIVE")
        with self.assertRaises(alpha.AlphaError):
            session._wait_starting_landscape()

    def test_run_attaches_before_starting_landscape_and_first_capture(self) -> None:
        source = inspect.getsource(alpha.AlphaSession.run)
        ordered = (
            "self._start_host()",
            "self._launch_foreign()",
            "self._attach()",
            "self._wait_starting_landscape()",
            "self._capture_placement(placement, name)",
        )
        offsets = [source.index(value) for value in ordered]
        self.assertEqual(offsets, sorted(offsets))

    def test_adb_run_emits_each_phase_immediately_before_its_wait(self) -> None:
        source = inspect.getsource(alpha.AlphaSession.run)
        start = source.index(
            'self._emit_rotation_controller_phase("START_LANDSCAPE")')
        first_wait = source.index("self._wait_starting_landscape()", start)
        portrait = source.index(
            'self._emit_rotation_controller_phase("PORTRAIT")', first_wait)
        portrait_wait = source.index(
            "self._wait_physical_orientation(portrait=True)", portrait)
        returned = source.index(
            'self._emit_rotation_controller_phase("RETURN_LANDSCAPE")',
            portrait_wait)
        return_wait = source.index(
            "self._wait_physical_orientation(", returned)
        self.assertLess(start, first_wait)
        self.assertLess(portrait, portrait_wait)
        self.assertLess(returned, return_wait)

    def test_startup_waits_through_allocated_before_ready(self) -> None:
        statuses = iter((
            host_status_wire("DISPLAY_ALLOCATED"),
            host_status_wire("WAITING_FOR_FOREIGN_ATTACH"),
        ))
        process = host.ProcessIdentity(4321, 999, 10123, alpha.HOST_PACKAGE)
        device = SimpleNamespace(
            history=[], start_host=lambda: None,
            ui_dump=lambda: next(statuses),
            displays=lambda: (
                "NativePageVisualOnly-" + SESSION + "-1").encode("ascii"),
            pidof=lambda package: (4321,),
            process_identity=lambda pid, package: process,
            host_logs=lambda pid: (
                "DISPLAY_READY session=" + SESSION +
                " generation=1 display=3 readiness=WAITING_FOR_FOREIGN_ACK\n"),
        )
        session = alpha.AlphaSession(
            device, Path("."), sleep=lambda _: None,
            now=iter((0.0, 0.1, 0.2, 0.3, 0.4)).__next__)
        session._start_host()
        self.assertEqual(session.status.state, "WAITING_FOR_FOREIGN_ATTACH")

    def test_independent_fixed_alpha_pins_are_literal(self) -> None:
        self.assertEqual(
            alpha.ALPHA_SIGNED_APK_SHA256,
            "3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03")
        self.assertEqual(
            alpha.ALPHA_SIGNER_CERT_SHA256,
            "d3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4")
        self.assertEqual(alpha.ALPHA_HOST_VERSION_CODE, 2)
        self.assertEqual(alpha.ALPHA_HOST_VERSION_NAME,
                         "0.0.2-native-page-visual-only")
        self.assertEqual(
            alpha.REVIEWED_UNSIGNED_APK_SHA256,
            "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178")
        self.assertEqual(
            alpha.ALPHA_DEX_SHA256,
            "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6")
        self.assertEqual(
            alpha.REVIEWED_UNSIGNED_AUTHORITY_SHA256,
            "94783276471ad4797b9a4ebf2200ae7adfd1ce1fe6ad888e2b5df09b403cb647")

    def test_metadata_and_actual_embedded_dex_must_match_fixed_pins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "native-page-host-alpha.apk"
            dex = b"dex-alpha-test-authority"
            with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", dex)
            signed = hashlib.sha256(apk.read_bytes()).hexdigest()
            dex_sha256 = hashlib.sha256(dex).hexdigest()
            metadata = {
                "schema": "native-page-host-local-alpha-apk-v1",
                "package": alpha.HOST_PACKAGE,
                "versionCode": alpha.ALPHA_HOST_VERSION_CODE,
                "versionName": alpha.ALPHA_HOST_VERSION_NAME,
                "signedApkPath": "native-page-host-alpha.apk",
                "signedApkSha256": signed,
                "signerCertSha256": alpha.ALPHA_SIGNER_CERT_SHA256,
                "reviewedUnsignedApkSha256": alpha.REVIEWED_UNSIGNED_APK_SHA256,
                "reviewedUnsignedAuthoritySha256": (
                    alpha.REVIEWED_UNSIGNED_AUTHORITY_SHA256),
                "dexSha256": dex_sha256,
                "checkpoint": alpha.CHECKPOINT,
                "diagnosticOnly": True,
                "reproducibleUnsignedAuthorityPreserved": True,
                "formalReleaseArtifact": False,
            }
            path = root / "native-page-host-alpha.json"
            path.write_text(json.dumps(metadata), encoding="utf-8")
            with mock.patch.multiple(
                    alpha, ALPHA_SIGNED_APK_SHA256=signed,
                    ALPHA_DEX_SHA256=dex_sha256):
                artifact = alpha.load_host_artifact(path)
                self.assertEqual(artifact.signed_apk_sha256, signed)
                self.assertEqual(
                    artifact.source, "independent-fixed-alpha-pins")

                metadata["dexSha256"] = "e" * 64
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with self.assertRaises(alpha.AlphaError):
                    alpha.load_host_artifact(path)

                metadata["dexSha256"] = dex_sha256
                metadata["reviewedUnsignedAuthoritySha256"] = "c" * 64
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with self.assertRaises(alpha.AlphaError):
                    alpha.load_host_artifact(path)

                metadata["reviewedUnsignedAuthoritySha256"] = (
                    alpha.REVIEWED_UNSIGNED_AUTHORITY_SHA256)
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("classes.dex", b"changed-dex")
                changed_signed = hashlib.sha256(apk.read_bytes()).hexdigest()
                metadata["signedApkSha256"] = changed_signed
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with mock.patch.object(
                        alpha, "ALPHA_SIGNED_APK_SHA256", changed_signed):
                    with self.assertRaises(alpha.AlphaError):
                        alpha.load_host_artifact(path)

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                        archive.writestr("classes.dex", dex)
                        archive.writestr("classes.dex", dex)
                duplicate_signed = hashlib.sha256(apk.read_bytes()).hexdigest()
                metadata["signedApkSha256"] = duplicate_signed
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with mock.patch.object(
                        alpha, "ALPHA_SIGNED_APK_SHA256", duplicate_signed):
                    with self.assertRaises(alpha.AlphaError):
                        alpha.load_host_artifact(path)

                with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("classes.dex", dex)
                    archive.writestr("classes2.dex", dex)
                extra_signed = hashlib.sha256(apk.read_bytes()).hexdigest()
                metadata["signedApkSha256"] = extra_signed
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with mock.patch.object(
                        alpha, "ALPHA_SIGNED_APK_SHA256", extra_signed):
                    with self.assertRaises(alpha.AlphaError):
                        alpha.load_host_artifact(path)


class FixtureCleanupTests(unittest.TestCase):
    def test_preexisting_first_target_is_registered_but_never_deleted(self) -> None:
        device = FixtureDevice()
        device.state[alpha.TARGET_PDF] = device_file(
            alpha.TARGET_PDF, alpha.SOURCE_PDF_SHA256, 901)
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        self.assertEqual(
            set(session.fixture_obligations),
            {alpha.TARGET_PDF, alpha.TARGET_MARK})
        self.assertTrue(
            session.fixture_obligations[alpha.TARGET_PDF].ownership_ambiguous)
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.copy_calls, [])
        self.assertEqual(device.remove_calls, [])
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_target_appearing_at_copy_dispatch_is_not_overwritten_or_deleted(self) -> None:
        device = FixtureDevice()
        original_stat = device.stat_file
        pdf_observations = {"count": 0}

        def appear_on_second_pdf_stat(
                path: str, *, absent_ok: bool = False,
                ) -> alpha.DeviceFile | None:
            if path == alpha.TARGET_PDF:
                pdf_observations["count"] += 1
                if pdf_observations["count"] == 2:
                    device.state[path] = device_file(path, "d" * 64, 902)
            return original_stat(path, absent_ok=absent_ok)

        device.stat_file = appear_on_second_pdf_stat  # type: ignore[method-assign]
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        self.assertEqual(device.copy_calls, [])
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.remove_calls, [])
        self.assertEqual(device.state[alpha.TARGET_PDF].sha256, "d" * 64)
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_target_racing_after_final_stat_is_skipped_unowned_and_preserved(self) -> None:
        device = FixtureDevice()
        original_copy = device.copy_fixture_member

        def race_at_copy(source: str, staging: str) -> None:
            target = alpha._staging_target(staging)
            if target == alpha.TARGET_PDF:
                device.state[target] = device_file(target, "d" * 64, 903)
            original_copy(source, staging)

        device.copy_fixture_member = race_at_copy  # type: ignore[method-assign]
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        obligation = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertTrue(obligation.copy_attempted)
        self.assertTrue(obligation.copy_reply_proved)
        self.assertTrue(obligation.ownership_ambiguous)
        self.assertIsNotNone(obligation.staging_retained)
        self.assertIsNone(obligation.retained)
        self.assertEqual(device.state[alpha.TARGET_PDF].sha256, "d" * 64)
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.staging_remove_calls, [alpha.TARGET_PDF])
        self.assertEqual(device.move_calls, [])
        self.assertEqual(device.remove_calls, [])
        self.assertEqual(device.state[alpha.TARGET_PDF].sha256, "d" * 64)

    def test_staging_and_quarantine_names_are_registered_before_mutation(self) -> None:
        device = FixtureDevice()
        with mock.patch.object(
                alpha.secrets, "token_hex",
                side_effect=("a" * 32, "b" * 32,
                             "c" * 32, "d" * 32,
                             "e" * 32)) as token:
            session = cleanup_ready_fixture_session(
                device, initialize=False)
            session._provision_parking(session.source_pdf_file)
            session._stage_fixture()
        self.assertEqual(token.call_args_list, [mock.call(16)] * 5)
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertEqual(
            pdf.staging_path,
            alpha.STAGING_PREFIX + "a" * 32 + "-pdf")
        self.assertEqual(
            mark.staging_path,
            alpha.STAGING_PREFIX + "c" * 32 + "-mark")
        self.assertEqual(
            pdf.quarantine_path,
            alpha.QUARANTINE_PREFIX + "b" * 32 + "-pdf")
        self.assertEqual(
            mark.quarantine_path,
            alpha.QUARANTINE_PREFIX + "d" * 32 + "-mark")
        self.assertEqual(alpha._staging_target(pdf.staging_path), alpha.TARGET_PDF)
        self.assertEqual(alpha._staging_target(mark.staging_path), alpha.TARGET_MARK)
        self.assertEqual(alpha._quarantine_target(pdf.quarantine_path), alpha.TARGET_PDF)
        self.assertEqual(alpha._quarantine_target(mark.quarantine_path), alpha.TARGET_MARK)
        with self.assertRaises(alpha.AlphaError):
            alpha._staging_path(alpha.TARGET_PDF, "A" * 32)
        with self.assertRaises(alpha.AlphaError):
            alpha._quarantine_path(alpha.TARGET_PDF, "A" * 32)

    def test_preexisting_random_staging_leaf_is_recorded_and_preserved(self) -> None:
        device = FixtureDevice()
        staging = alpha._staging_path(alpha.TARGET_PDF, "a" * 32)
        device.state[staging] = device_file(staging, "e" * 64, 904)
        with mock.patch.object(
                alpha.secrets, "token_hex",
                side_effect=("a" * 32, "b" * 32,
                             "c" * 32, "d" * 32,
                             "f" * 32)):
            session = cleanup_ready_fixture_session(
                device, initialize=False)
            session._provision_parking(session.source_pdf_file)
            with self.assertRaises(alpha.AlphaError):
                session._stage_fixture()
        self.assertEqual(
            set(session.fixture_obligations),
            {alpha.TARGET_PDF, alpha.TARGET_MARK})
        obligation = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertEqual(obligation.staging_preexisting_observed, device.state[staging])
        self.assertTrue(obligation.staging_ownership_ambiguous)
        self.assertEqual(device.copy_calls, [])
        self.assertEqual(device.publish_calls, [])
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.staging_remove_calls, [])
        self.assertEqual(device.state[staging].sha256, "e" * 64)

    def test_staging_collision_at_copy_is_not_clobbered_or_cleaned(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        original_copy = device.copy_fixture_member

        def collide(source: str, staging: str) -> None:
            if alpha._staging_target(staging) == alpha.TARGET_PDF:
                device.state[staging] = device_file(staging, "d" * 64, 905)
            original_copy(source, staging)

        device.copy_fixture_member = collide  # type: ignore[method-assign]
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertTrue(pdf.copy_attempted)
        self.assertFalse(pdf.copy_reply_proved)
        self.assertTrue(pdf.staging_ownership_ambiguous)
        self.assertEqual(device.state[pdf.staging_path].sha256, "d" * 64)
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.staging_remove_calls, [])
        self.assertEqual(device.state[pdf.staging_path].sha256, "d" * 64)

    def test_identical_hash_staging_replacement_never_gains_publication_authority(
            self) -> None:
        device = FixtureDevice()
        staging = alpha._staging_path(alpha.TARGET_PDF, "a" * 32)
        original_stat = device.stat_file
        observations = 0

        def replace_after_post_copy_stat(
                path: str, *, absent_ok: bool = False,
                ) -> alpha.DeviceFile | None:
            nonlocal observations
            value = original_stat(path, absent_ok=absent_ok)
            if path == staging:
                observations += 1
                if observations == 4:
                    self.assertIsNotNone(value)
                    device.state[path] = device_file(
                        path, alpha.SOURCE_PDF_SHA256, 999)
            return value

        device.stat_file = replace_after_post_copy_stat  # type: ignore[method-assign]
        with mock.patch.object(
                alpha.secrets, "token_hex",
                side_effect=("a" * 32, "b" * 32,
                             "c" * 32, "d" * 32,
                             "e" * 32)):
            session = cleanup_ready_fixture_session(
                device, initialize=False)
            session._provision_parking(session.source_pdf_file)
            with self.assertRaises(alpha.AlphaError):
                session._stage_fixture()
        obligation = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertEqual(obligation.staging_retained.inode, 101)  # type: ignore[union-attr]
        self.assertEqual(device.state[staging].inode, 999)
        self.assertEqual(
            device.state[staging].sha256, obligation.expected_sha256)
        self.assertTrue(obligation.staging_ownership_ambiguous)
        self.assertEqual(device.publish_calls, [])
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.staging_remove_calls, [])
        self.assertEqual(device.state[staging].inode, 999)

    def test_publish_timeout_after_rename_is_settled_without_retry(self) -> None:
        device = FixtureDevice()
        device.publish_timeout_target = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertEqual(
            device.publish_calls, [alpha.TARGET_PDF, alpha.TARGET_MARK])
        self.assertTrue(pdf.publish_move_attempted)
        self.assertFalse(pdf.publish_move_reply_proved)
        self.assertEqual(pdf.publish_move_postcondition, "stage-absent/target-exact")
        self.assertIsNotNone(pdf.retained)
        session._remove_fixture()
        self.assertTrue(session.cleanup["fixtureRemoved"])

    def test_target_collision_at_publish_preserves_target_and_cleans_owned_stage(
            self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        original_publish = device.publish_fixture_member

        def collide(staging: str, target: str) -> None:
            if target == alpha.TARGET_PDF:
                device.state[target] = device_file(target, "c" * 64, 906)
            original_publish(staging, target)

        device.publish_fixture_member = collide  # type: ignore[method-assign]
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertEqual(device.publish_calls, [alpha.TARGET_PDF])
        self.assertTrue(pdf.ownership_ambiguous)
        self.assertIn(pdf.staging_path, device.state)
        self.assertEqual(device.state[alpha.TARGET_PDF].sha256, "c" * 64)
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.staging_remove_calls, [alpha.TARGET_PDF])
        self.assertNotIn(pdf.staging_path, device.state)
        self.assertEqual(device.state[alpha.TARGET_PDF].sha256, "c" * 64)

    def test_publish_timeout_before_rename_cleans_exact_stage_without_retry(
            self) -> None:
        device = FixtureDevice()
        device.publish_timeout_before_move = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertEqual(device.publish_calls, [alpha.TARGET_PDF])
        self.assertIn(pdf.staging_path, device.state)
        self.assertNotIn(alpha.TARGET_PDF, device.state)
        session._remove_fixture()
        self.assertEqual(device.publish_calls, [alpha.TARGET_PDF])
        self.assertEqual(device.staging_remove_calls, [alpha.TARGET_PDF])
        self.assertNotIn(pdf.staging_path, device.state)
        self.assertEqual(pdf.staging_cleanup_absence_observations, 2)
        self.assertTrue(pdf.staging_resolved_absent)

    def test_lost_staging_remove_reply_settles_absence_without_retry(self) -> None:
        device = FixtureDevice()
        device.publish_timeout_before_move = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        device.staging_remove_timeout_after_delete = True
        session._remove_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertEqual(device.staging_remove_calls, [alpha.TARGET_PDF])
        self.assertFalse(pdf.staging_cleanup_reply_proved)
        self.assertIn("timeout", str(pdf.staging_cleanup_transport_error))
        self.assertTrue(pdf.staging_resolved_absent)

    def test_staging_remove_timeout_before_unlink_is_not_retried(self) -> None:
        device = FixtureDevice()
        device.publish_timeout_before_move = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        device.staging_remove_timeout_before_delete = True
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.staging_remove_calls, [alpha.TARGET_PDF])
        self.assertIn(pdf.staging_path, device.state)
        self.assertFalse(pdf.staging_cleanup_reply_proved)

    def test_happy_cleanup_persists_complete_quarantine_evidence(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        session._remove_fixture()
        self.assertEqual(device.move_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertEqual(device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertEqual(
            set(device.state),
            {alpha.SOURCE_PDF, alpha.SOURCE_MARK, alpha.PARKING_PDF})
        for obligation in session.fixture_obligations.values():
            self.assertIsNotNone(obligation.staging_pre_absence_sha256)
            self.assertTrue(obligation.copy_attempted)
            self.assertTrue(obligation.copy_reply_proved)
            self.assertIsNotNone(obligation.staging_post_copy_observed)
            self.assertIsNotNone(obligation.staging_retained)
            self.assertTrue(obligation.publish_move_attempted)
            self.assertTrue(obligation.publish_move_reply_proved)
            self.assertEqual(
                obligation.publish_move_postcondition,
                "stage-absent/target-exact")
            self.assertIsNone(obligation.publish_move_source_observed)
            self.assertIsNotNone(obligation.publish_move_target_observed)
            self.assertFalse(obligation.staging_cleanup_attempted)
            self.assertEqual(obligation.staging_cleanup_absence_observations, 2)
            self.assertTrue(obligation.staging_resolved_absent)
            self.assertIsNotNone(obligation.quarantine_pre_absence_sha256)
            self.assertTrue(obligation.quarantine_move_attempted)
            self.assertTrue(obligation.quarantine_move_reply_proved)
            self.assertEqual(
                obligation.quarantine_move_postcondition,
                "source-absent/destination-exact")
            self.assertIsNone(obligation.quarantine_move_source_observed)
            self.assertIsNotNone(obligation.quarantine_move_destination_observed)
            self.assertIsNotNone(obligation.quarantine_retained)
            self.assertTrue(obligation.quarantine_remove_attempted)
            self.assertTrue(obligation.quarantine_remove_reply_proved)
            self.assertEqual(
                obligation.quarantine_remove_precondition,
                "source-absent/destination-exact")
            self.assertIsNone(obligation.quarantine_remove_source_observed)
            self.assertIsNotNone(obligation.quarantine_remove_pre_observed)
            self.assertEqual(
                obligation.quarantine_remove_postcondition,
                "destination-absent")
            self.assertIsNone(obligation.quarantine_remove_post_observed)
            self.assertEqual(
                obligation.quarantine_remove_absence_observations, 2)
            self.assertTrue(obligation.quarantine_resolved_absent)
            self.assertTrue(obligation.resolved_absent)
        report = session._report()
        staging_policy = report["fixture"]["stagingPolicy"]
        self.assertEqual(
            staging_policy["authority"], "random-capability-staging-v1")
        self.assertEqual(staging_policy["copyReceiptEncoding"], "exact-ascii-lf")
        self.assertIn("copy receipt", staging_policy["copyObservationAssumption"])
        self.assertIn("unguessable", staging_policy["leftoverRemovalAssumption"])
        policy = report["fixture"]["quarantinePolicy"]
        self.assertEqual(policy["authority"], "random-capability-quarantine-v1")
        self.assertEqual(policy["nonceBits"], 128)
        self.assertIn("unguessable", policy["immediateRemovalAssumption"])
        reported = report["fixture"]["cleanupObligations"][alpha.TARGET_PDF]
        self.assertEqual(
            reported["quarantine_path"],
            session.fixture_obligations[alpha.TARGET_PDF].quarantine_path)
        self.assertIsNotNone(reported["quarantine_retained"])
        self.assertEqual(
            reported["quarantine_move_postcondition"],
            "source-absent/destination-exact")
        self.assertEqual(
            reported["quarantine_remove_postcondition"],
            "destination-absent")
        self.assertEqual(
            reported["quarantine_remove_precondition"],
            "source-absent/destination-exact")
        self.assertEqual(
            reported["quarantine_remove_absence_observations"], 2)
        self.assertEqual(
            reported["publish_move_postcondition"],
            "stage-absent/target-exact")
        self.assertTrue(reported["staging_resolved_absent"])
        self.assertFalse(report["fixture"]["sourceWasModified"])
        self.assertFalse(report["parking"]["wasModified"])
        self.assertTrue(report["packageRollbackSafe"])

    def test_pre_copy_stat_timeout_cannot_be_reported_clean(self) -> None:
        device = FixtureDevice()
        device.stat_failures[alpha.TARGET_PDF] = 1
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        self.assertTrue(
            session.fixture_obligations[alpha.TARGET_PDF].ownership_ambiguous)
        session._remove_fixture()
        self.assertEqual(device.remove_calls, [])
        self.assertTrue(session.cleanup["fixtureRemoved"])


class MutationJournalTests(unittest.TestCase):
    def test_output_root_alias_or_link_is_rejected_before_run_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observed = alpha.os.lstat(root)
            linked = SimpleNamespace(st_mode=stat_module.S_IFLNK)
            with mock.patch.object(alpha.os, "lstat", return_value=linked):
                with self.assertRaises(alpha.AlphaError):
                    alpha.AlphaSession(FixtureDevice(), root)
            with (mock.patch.object(alpha.os, "lstat", return_value=observed),
                  mock.patch.object(
                      alpha.Path, "resolve", return_value=root.parent)):
                with self.assertRaises(alpha.AlphaError):
                    alpha.AlphaSession(FixtureDevice(), root)

    def test_posix_cross_directory_publication_syncs_both_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_parent = root / "run"
            archive_parent.mkdir()
            source = root / "active"
            target = archive_parent / "archive"
            source.write_bytes(b"authority")
            with (mock.patch.object(alpha.os, "name", "posix"),
                  mock.patch.object(alpha, "_sync_directory") as sync):
                alpha._publish_local_file_exclusive(source, target)
            self.assertFalse(source.exists())
            self.assertEqual(target.read_bytes(), b"authority")
            self.assertEqual(sync.call_args_list, [
                mock.call(archive_parent), mock.call(root)])

    def test_fixed_active_receipt_is_discoverable_and_blocks_future_run(
            self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        expected = session.output_root / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        self.assertEqual(session.mutation_journal_path, expected)
        self.assertTrue(expected.is_file())
        future = alpha.AlphaSession(
            device, session.output_root, sleep=lambda _: None)
        with self.assertRaises(alpha.AlphaError):
            future._ensure_output_dir()
        self.assertEqual(
            alpha.recover_mutation_journal(expected)["journalId"],
            session.mutation_journal_id)

    def test_clean_retirement_preserves_exact_archived_authority(self) -> None:
        session = cleanup_ready_fixture_session(FixtureDevice())
        active = session.mutation_journal_path
        session._stage_fixture()
        session._remove_fixture()
        self.assertTrue(session._report()["packageRollbackSafe"])
        session._retire_mutation_journal()
        assert session.output_dir is not None
        archive = session.output_dir / alpha.MUTATION_JOURNAL_FILENAME
        self.assertEqual(session.mutation_journal_path, archive)
        self.assertFalse(active.exists())  # type: ignore[union-attr]
        self.assertTrue(archive.is_file())
        recovered = alpha.recover_mutation_journal(archive)
        self.assertFalse(recovered["tornTail"])
        self.assertEqual(recovered["headSha256"],
                         session.mutation_journal_head_sha256)
        future = alpha.AlphaSession(
            session.device, session.output_root, sleep=lambda _: None)
        self.assertTrue(future._ensure_output_dir().is_dir())

    def test_one_torn_tail_recovers_only_prior_complete_authority(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        assert session.mutation_journal_path is not None
        prior = alpha.recover_mutation_journal(session.mutation_journal_path)
        with session.mutation_journal_path.open("ab") as stream:
            stream.write(b'{"authority":')
            stream.flush()
        recovered = alpha.recover_mutation_journal(
            session.mutation_journal_path)
        self.assertTrue(recovered["tornTail"])
        self.assertEqual(recovered["recordCount"], prior["recordCount"])
        self.assertEqual(recovered["headSha256"], prior["headSha256"])
        self.assertEqual(recovered["tornTailSize"], len(b'{"authority":'))
        self.assertFalse(session._mutation_journal_current())
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        self.assertEqual(device.copy_calls, [])

    def test_crash_before_copy_dispatch_retains_registered_capability(self) -> None:
        session = cleanup_ready_fixture_session(FixtureDevice())
        obligation = session.fixture_obligations[alpha.TARGET_PDF]
        obligation.pre_copy_absence_sha256 = alpha._canonical_sha({
            "authority": alpha.AUTHORITY,
            "kind": "pre-copy-target-absence",
            "source": obligation.source,
            "target": obligation.target,
            "expectedSha256": obligation.expected_sha256,
        })
        obligation.staging_pre_absence_sha256 = alpha._canonical_sha({
            "authority": alpha.AUTHORITY,
            "kind": "pre-copy-staging-absence",
            "source": obligation.source,
            "target": obligation.target,
            "staging": obligation.staging_path,
            "expectedSha256": obligation.expected_sha256,
            "observations": 2,
        })
        obligation.copy_attempted = True
        session._journal_transition(
            "FIXTURE_COPY_ATTEMPTED", source=obligation.source,
            target=obligation.target, staging=obligation.staging_path,
            retryAllowed=False)
        recovered = alpha.recover_mutation_journal(
            session.mutation_journal_path)  # type: ignore[arg-type]
        self.assertEqual(recovered["lastRecord"]["event"],
                         "FIXTURE_COPY_ATTEMPTED")
        self.assertEqual(
            recovered["lastRecord"]["obligations"][alpha.TARGET_PDF]
            ["staging_path"], obligation.staging_path)
        self.assertNotIn(obligation.staging_path, session.device.state)

    def test_crash_before_and_after_publish_retains_exact_obligations(
            self) -> None:
        class SimulatedCrash(BaseException):
            pass

        for boundary in ("before", "after"):
            device = FixtureDevice()
            session = cleanup_ready_fixture_session(device)
            original_transition = session._journal_transition
            if boundary == "before":
                def crash_before(obligation: alpha.FixtureObligation) -> None:
                    obligation.publish_move_attempted = True
                    original_transition(
                        "FIXTURE_PUBLISH_ATTEMPTED",
                        source=obligation.staging_path,
                        target=obligation.target, retryAllowed=False)
                    raise SimulatedCrash()
                session._publish_staged_fixture = crash_before  # type: ignore[method-assign]
            else:
                def crash_after(event: str, **details: object) -> None:
                    if event == "FIXTURE_PUBLISH_SETTLED":
                        raise SimulatedCrash()
                    original_transition(event, **details)
                session._journal_transition = crash_after  # type: ignore[method-assign]
            with self.subTest(boundary=boundary), self.assertRaises(
                    SimulatedCrash):
                session._stage_fixture()
            recovered = alpha.recover_mutation_journal(
                session.mutation_journal_path)  # type: ignore[arg-type]
            self.assertEqual(recovered["lastRecord"]["event"],
                             "FIXTURE_PUBLISH_ATTEMPTED")
            pdf = recovered["lastRecord"]["obligations"][alpha.TARGET_PDF]
            self.assertEqual(pdf["staging_path"],
                             session.fixture_obligations[alpha.TARGET_PDF]
                             .staging_path)
            if boundary == "before":
                self.assertIn(pdf["staging_path"], device.state)
                self.assertNotIn(alpha.TARGET_PDF, device.state)
            else:
                self.assertNotIn(pdf["staging_path"], device.state)
                self.assertIn(alpha.TARGET_PDF, device.state)

    def test_torn_first_record_has_no_recoverable_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
            path.write_bytes(b'{"authority":')
            with self.assertRaises(alpha.AlphaError):
                alpha.recover_mutation_journal(path)

    def test_every_short_canonical_torn_prefix_recovers_prior_head(self) -> None:
        for tail in (b"{", b'{"a', b'{"authority":'):
            session = cleanup_ready_fixture_session(FixtureDevice())
            assert session.mutation_journal_path is not None
            prior = alpha.recover_mutation_journal(
                session.mutation_journal_path)
            with session.mutation_journal_path.open("ab") as stream:
                stream.write(tail)
            recovered = alpha.recover_mutation_journal(
                session.mutation_journal_path)
            with self.subTest(tail=tail):
                self.assertTrue(recovered["tornTail"])
                self.assertEqual(recovered["headSha256"],
                                 prior["headSha256"])

    def test_rehashed_early_parking_state_is_not_a_legal_transition(self) -> None:
        session = cleanup_ready_fixture_session(FixtureDevice())
        assert session.mutation_journal_path is not None

        def change(records: list[dict[str, object]]) -> None:
            parking = records[1]["parkingProvisioning"]
            assert isinstance(parking, dict)
            parking["copyAttempted"] = True

        rewrite_journal_chain(session.mutation_journal_path, change)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_copied_parking_settlement_requires_prior_copy_intent(self) -> None:
        device = FixtureDevice()
        device.state.pop(alpha.PARKING_PDF)
        session = cleanup_ready_fixture_session(device)
        assert session.mutation_journal_path is not None

        def omit_attempt(records: list[dict[str, object]]) -> None:
            records[:] = [
                record for record in records
                if record["event"] != "PARKING_COPY_ATTEMPTED"]

        rewrite_journal_chain(session.mutation_journal_path, omit_attempt)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_success_settlement_drift_is_rejected(self) -> None:
        cases = (
            ("copy-observed", "FIXTURE_COPY_SETTLED",
             "staging_post_copy_observed"),
            ("publish-postcondition", "FIXTURE_PUBLISH_SETTLED",
             "publish_move_postcondition"),
            ("quarantine-move-postcondition", "QUARANTINE_MOVE_SETTLED",
             "quarantine_move_postcondition"),
            ("quarantine-remove-postcondition", "QUARANTINE_REMOVE_SETTLED",
             "quarantine_remove_postcondition"),
        )
        for name, event, field in cases:
            device = FixtureDevice()
            session = cleanup_ready_fixture_session(device)
            session._stage_fixture()
            if event.startswith("QUARANTINE_"):
                session._remove_fixture()
            assert session.mutation_journal_path is not None

            def drift(records: list[dict[str, object]]) -> None:
                start = next(
                    index for index, record in enumerate(records)
                    if record["event"] == event and
                    isinstance(record["details"], dict) and
                    record["details"].get("target",
                        record["details"].get("source")) == alpha.TARGET_PDF)
                for record in records[start:]:
                    obligations = record["obligations"]
                    assert isinstance(obligations, dict)
                    pdf = obligations[alpha.TARGET_PDF]
                    assert isinstance(pdf, dict)
                    if field == "staging_post_copy_observed":
                        observed = json.loads(json.dumps(pdf[field]))
                        assert isinstance(observed, dict)
                        observed["inode"] = 999999
                        pdf[field] = observed
                    elif field == "publish_move_postcondition":
                        pdf[field] = "stage-present/target-present"
                    elif field == "quarantine_move_postcondition":
                        pdf[field] = "source-present/destination-present"
                    else:
                        pdf[field] = "destination-present"

            rewrite_journal_chain(session.mutation_journal_path, drift)
            with self.subTest(name=name), self.assertRaises(alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_settlement_reply_without_error_is_rejected(self) -> None:
        session = cleanup_ready_fixture_session(FixtureDevice())
        session._stage_fixture()
        assert session.mutation_journal_path is not None

        def drift(records: list[dict[str, object]]) -> None:
            start = next(
                index for index, record in enumerate(records)
                if record["event"] == "FIXTURE_PUBLISH_SETTLED" and
                isinstance(record["details"], dict) and
                record["details"].get("target") == alpha.TARGET_PDF)
            for record in records[start:]:
                obligations = record["obligations"]
                assert isinstance(obligations, dict)
                pdf = obligations[alpha.TARGET_PDF]
                assert isinstance(pdf, dict)
                pdf["publish_move_reply_proved"] = False
            details = records[start]["details"]
            assert isinstance(details, dict)
            details["moveReplyProved"] = False

        rewrite_journal_chain(session.mutation_journal_path, drift)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_staging_removal_observation_drift_is_rejected(self) -> None:
        device = FixtureDevice()
        device.publish_timeout_before_move = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        session._remove_fixture()
        assert session.mutation_journal_path is not None

        def drift(records: list[dict[str, object]]) -> None:
            start = next(
                index for index, record in enumerate(records)
                if record["event"] == "STAGING_REMOVE_SETTLED" and
                isinstance(record["details"], dict) and
                record["details"].get("target") == alpha.TARGET_PDF)
            for record in records[start:]:
                obligations = record["obligations"]
                assert isinstance(obligations, dict)
                pdf = obligations[alpha.TARGET_PDF]
                assert isinstance(pdf, dict)
                pdf["staging_cleanup_post_observed"] = json.loads(
                    json.dumps(pdf["staging_retained"]))

        rewrite_journal_chain(session.mutation_journal_path, drift)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_attempt_record_cannot_carry_later_settlement_state(
            self) -> None:
        ordinary_cases = (
            ("FIXTURE_COPY_ATTEMPTED", "FIXTURE_COPY_SETTLED"),
            ("FIXTURE_PUBLISH_ATTEMPTED", "FIXTURE_PUBLISH_SETTLED"),
            ("QUARANTINE_MOVE_ATTEMPTED", "QUARANTINE_MOVE_SETTLED"),
            ("QUARANTINE_REMOVE_ATTEMPTED", "QUARANTINE_REMOVE_SETTLED"),
        )
        for attempted, settled in ordinary_cases:
            session = cleanup_ready_fixture_session(FixtureDevice())
            session._stage_fixture()
            session._remove_fixture()
            assert session.mutation_journal_path is not None

            def replace_attempt(records: list[dict[str, object]]) -> None:
                attempt_record = next(
                    record for record in records
                    if record["event"] == attempted and
                    isinstance(record["details"], dict) and
                    record["details"].get(
                        "target", record["details"].get("source")) ==
                    alpha.TARGET_PDF)
                settled_record = next(
                    record for record in records
                    if record["event"] == settled and
                    isinstance(record["details"], dict) and
                    record["details"].get(
                        "target", record["details"].get("source")) ==
                    alpha.TARGET_PDF)
                attempt_obligations = attempt_record["obligations"]
                settled_obligations = settled_record["obligations"]
                assert isinstance(attempt_obligations, dict)
                assert isinstance(settled_obligations, dict)
                attempt_obligations[alpha.TARGET_PDF] = json.loads(
                    json.dumps(settled_obligations[alpha.TARGET_PDF]))

            rewrite_journal_chain(
                session.mutation_journal_path, replace_attempt)
            with self.subTest(event=attempted), self.assertRaises(
                    alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

        device = FixtureDevice()
        device.publish_timeout_before_move = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        session._remove_fixture()
        assert session.mutation_journal_path is not None

        def replace_staging_attempt(records: list[dict[str, object]]) -> None:
            attempt_record = next(
                record for record in records
                if record["event"] == "STAGING_REMOVE_ATTEMPTED" and
                isinstance(record["details"], dict) and
                record["details"].get("target") == alpha.TARGET_PDF)
            settled_record = next(
                record for record in records
                if record["event"] == "STAGING_REMOVE_SETTLED" and
                isinstance(record["details"], dict) and
                record["details"].get("target") == alpha.TARGET_PDF)
            attempt_obligations = attempt_record["obligations"]
            settled_obligations = settled_record["obligations"]
            assert isinstance(attempt_obligations, dict)
            assert isinstance(settled_obligations, dict)
            attempt_obligations[alpha.TARGET_PDF] = json.loads(
                json.dumps(settled_obligations[alpha.TARGET_PDF]))

        rewrite_journal_chain(
            session.mutation_journal_path, replace_staging_attempt)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_final_settlement_requires_every_attempted_cleanup_terminal(
            self) -> None:
        cases = ("STAGING_REMOVE_SETTLED", "QUARANTINE_REMOVE_SETTLED")
        for omitted in cases:
            device = FixtureDevice()
            if omitted == "STAGING_REMOVE_SETTLED":
                device.publish_timeout_before_move = alpha.TARGET_PDF
            session = cleanup_ready_fixture_session(device)
            if omitted == "STAGING_REMOVE_SETTLED":
                with self.assertRaises(alpha.AlphaError):
                    session._stage_fixture()
            else:
                session._stage_fixture()
            session._remove_fixture()
            assert session.mutation_journal_path is not None

            def omit_terminal(records: list[dict[str, object]]) -> None:
                records[:] = [
                    record for record in records
                    if not (
                        record["event"] == omitted and
                        isinstance(record["details"], dict) and
                        record["details"].get(
                            "target", record["details"].get("source")) ==
                        alpha.TARGET_PDF)
                ]

            rewrite_journal_chain(
                session.mutation_journal_path, omit_terminal)
            with self.subTest(event=omitted), self.assertRaises(
                    alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_settlement_record_cannot_carry_next_phase_state(
            self) -> None:
        cases = (
            ("FIXTURE_COPY_SETTLED", "FIXTURE_PUBLISH_SETTLED"),
            ("QUARANTINE_MOVE_SETTLED", "QUARANTINE_REMOVE_SETTLED"),
        )
        for earlier, later in cases:
            session = cleanup_ready_fixture_session(FixtureDevice())
            session._stage_fixture()
            session._remove_fixture()
            assert session.mutation_journal_path is not None

            def replace_settlement(records: list[dict[str, object]]) -> None:
                earlier_record = next(
                    record for record in records
                    if record["event"] == earlier and
                    isinstance(record["details"], dict) and
                    record["details"].get(
                        "target", record["details"].get("source")) ==
                    alpha.TARGET_PDF)
                later_record = next(
                    record for record in records
                    if record["event"] == later and
                    isinstance(record["details"], dict) and
                    record["details"].get(
                        "target", record["details"].get("source")) ==
                    alpha.TARGET_PDF)
                earlier_obligations = earlier_record["obligations"]
                later_obligations = later_record["obligations"]
                assert isinstance(earlier_obligations, dict)
                assert isinstance(later_obligations, dict)
                earlier_obligations[alpha.TARGET_PDF] = json.loads(
                    json.dumps(later_obligations[alpha.TARGET_PDF]))

            rewrite_journal_chain(
                session.mutation_journal_path, replace_settlement)
            with self.subTest(event=earlier), self.assertRaises(
                    alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_unsettled_publish_outcome_is_fully_bound(self) -> None:
        for mode in (
                "reply-error", "detail-postcondition",
                "observed-postcondition", "exact-mislabeled"):
            device = FixtureDevice()
            device.publish_timeout_before_move = alpha.TARGET_PDF
            session = cleanup_ready_fixture_session(device)
            with self.assertRaises(alpha.AlphaError):
                session._stage_fixture()
            assert session.mutation_journal_path is not None

            def mutate(records: list[dict[str, object]]) -> None:
                record = next(
                    value for value in records
                    if value["event"] == "FIXTURE_PUBLISH_UNSETTLED" and
                    isinstance(value["details"], dict) and
                    value["details"].get("target") == alpha.TARGET_PDF)
                details = record["details"]
                obligations = record["obligations"]
                assert isinstance(details, dict)
                assert isinstance(obligations, dict)
                pdf = obligations[alpha.TARGET_PDF]
                assert isinstance(pdf, dict)
                if mode == "reply-error":
                    pdf["publish_move_transport_error"] = None
                elif mode == "detail-postcondition":
                    details["postcondition"] = "stage-present/target-present"
                elif mode == "observed-postcondition":
                    pdf["publish_move_postcondition"] = (
                        "stage-present/target-present")
                    details["postcondition"] = "stage-present/target-present"
                else:
                    retained = json.loads(json.dumps(pdf["staging_retained"]))
                    assert isinstance(retained, dict)
                    retained["path"] = alpha.TARGET_PDF
                    pdf["publish_move_source_observed"] = None
                    pdf["publish_move_target_observed"] = retained
                    pdf["publish_move_postcondition"] = (
                        "stage-absent/target-present")
                    details["postcondition"] = "stage-absent/target-present"

            rewrite_journal_chain(session.mutation_journal_path, mutate)
            with self.subTest(mode=mode), self.assertRaises(alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_ambiguous_publish_requires_coherent_command_outcome(
            self) -> None:
        device = FixtureDevice()
        original_publish = device.publish_fixture_member

        def publish_then_hide_postcondition(staging: str, target: str) -> None:
            original_publish(staging, target)
            if target == alpha.TARGET_PDF:
                device.stat_failures[staging] = 1

        device.publish_fixture_member = (  # type: ignore[method-assign]
            publish_then_hide_postcondition)
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        assert session.mutation_journal_path is not None

        def remove_reply(records: list[dict[str, object]]) -> None:
            record = next(
                value for value in records
                if value["event"] ==
                "FIXTURE_PUBLISH_POSTCONDITION_AMBIGUOUS" and
                isinstance(value["details"], dict) and
                value["details"].get("target") == alpha.TARGET_PDF)
            obligations = record["obligations"]
            assert isinstance(obligations, dict)
            pdf = obligations[alpha.TARGET_PDF]
            assert isinstance(pdf, dict)
            pdf["publish_move_reply_proved"] = False

        rewrite_journal_chain(session.mutation_journal_path, remove_reply)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_unsettled_quarantine_outcome_is_fully_bound(self) -> None:
        for mode in (
                "reply-error", "detail-postcondition",
                "observed-postcondition", "exact-mislabeled"):
            device = FixtureDevice()
            session = cleanup_ready_fixture_session(device)
            session._stage_fixture()
            device.move_timeout_before_move = alpha.TARGET_MARK
            with self.assertRaises(alpha.CleanupUncertain):
                session._remove_fixture()
            assert session.mutation_journal_path is not None

            def mutate(records: list[dict[str, object]]) -> None:
                record = next(
                    value for value in records
                    if value["event"] == "QUARANTINE_MOVE_UNSETTLED" and
                    isinstance(value["details"], dict) and
                    value["details"].get("source") == alpha.TARGET_MARK)
                details = record["details"]
                obligations = record["obligations"]
                assert isinstance(details, dict)
                assert isinstance(obligations, dict)
                mark = obligations[alpha.TARGET_MARK]
                assert isinstance(mark, dict)
                if mode == "reply-error":
                    mark["quarantine_move_transport_error"] = None
                elif mode == "detail-postcondition":
                    details["postcondition"] = (
                        "source-present/destination-present")
                elif mode == "observed-postcondition":
                    mark["quarantine_move_postcondition"] = (
                        "source-present/destination-present")
                    details["postcondition"] = (
                        "source-present/destination-present")
                else:
                    retained = json.loads(json.dumps(mark["retained"]))
                    assert isinstance(retained, dict)
                    retained["path"] = mark["quarantine_path"]
                    mark["quarantine_move_source_observed"] = None
                    mark["quarantine_move_destination_observed"] = retained
                    mark["quarantine_move_postcondition"] = (
                        "source-absent/destination-present")
                    details["postcondition"] = (
                        "source-absent/destination-present")

            rewrite_journal_chain(session.mutation_journal_path, mutate)
            with self.subTest(mode=mode), self.assertRaises(alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_staged_checkpoint_rejects_injected_no_attempt_cleanup_state(
            self) -> None:
        def inject_no_attempt_cleanup(obligation: dict[str, object]) -> None:
            obligation["staging_cleanup_absence_observations"] = 2
            obligation["staging_resolved_absent"] = True
            obligation["quarantine_pre_absence_sha256"] = alpha._canonical_sha({
                "authority": alpha.AUTHORITY,
                "kind": "pre-quarantine-absence",
                "target": obligation["target"],
                "quarantine": obligation["quarantine_path"],
                "expectedSha256": obligation["expected_sha256"],
                "observations": 2,
            })
            obligation["quarantine_move_attempted"] = False
            obligation["quarantine_move_reply_proved"] = False
            obligation["quarantine_move_transport_error"] = None
            obligation["quarantine_move_postcondition"] = None
            obligation["quarantine_move_source_observed"] = None
            obligation["quarantine_move_destination_observed"] = None
            obligation["quarantine_retained"] = None
            obligation["quarantine_remove_attempted"] = False
            obligation["quarantine_remove_reply_proved"] = False
            obligation["quarantine_remove_transport_error"] = None
            obligation["quarantine_remove_precondition"] = None
            obligation["quarantine_remove_source_observed"] = None
            obligation["quarantine_remove_postcondition"] = None
            obligation["quarantine_remove_pre_observed"] = None
            obligation["quarantine_remove_post_observed"] = None
            obligation["quarantine_remove_absence_observations"] = 0
            obligation["quarantine_resolved_absent"] = True
            obligation["resolved_absent"] = True

        for mode in ("truncated", "full-chain"):
            session = cleanup_ready_fixture_session(FixtureDevice())
            session._stage_fixture()
            if mode == "full-chain":
                session._remove_fixture()
            assert session.mutation_journal_path is not None

            def inject(records: list[dict[str, object]]) -> None:
                staged_index = next(
                    index for index, record in enumerate(records)
                    if record["event"] == "FIXTURE_STAGED")
                if mode == "truncated":
                    records[:] = records[:staged_index + 1]
                else:
                    records[:] = [
                        record for record in records
                        if not str(record["event"]).startswith("QUARANTINE_")
                    ]
                    staged_index = next(
                        index for index, record in enumerate(records)
                        if record["event"] == "FIXTURE_STAGED")
                for record in records[staged_index:]:
                    obligations = record["obligations"]
                    assert isinstance(obligations, dict)
                    for member in (alpha.TARGET_PDF, alpha.TARGET_MARK):
                        obligation = obligations[member]
                        assert isinstance(obligation, dict)
                        inject_no_attempt_cleanup(obligation)

            rewrite_journal_chain(session.mutation_journal_path, inject)
            with self.subTest(mode=mode), self.assertRaises(alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_target_event_cannot_inject_other_target_cleanup_authority(
            self) -> None:
        session = cleanup_ready_fixture_session(FixtureDevice())
        session._stage_fixture()
        assert session.mutation_journal_path is not None

        def inject_cross_target(records: list[dict[str, object]]) -> None:
            index = next(
                position for position, record in enumerate(records)
                if record["event"] == "FIXTURE_PUBLISH_SETTLED" and
                isinstance(record["details"], dict) and
                record["details"].get("target") == alpha.TARGET_MARK)
            records[:] = records[:index + 1]
            obligations = records[-1]["obligations"]
            assert isinstance(obligations, dict)
            pdf = obligations[alpha.TARGET_PDF]
            assert isinstance(pdf, dict)
            pdf["staging_cleanup_absence_observations"] = 2
            pdf["staging_resolved_absent"] = True
            pdf["quarantine_pre_absence_sha256"] = alpha._canonical_sha({
                "authority": alpha.AUTHORITY,
                "kind": "pre-quarantine-absence",
                "target": pdf["target"],
                "quarantine": pdf["quarantine_path"],
                "expectedSha256": pdf["expected_sha256"],
                "observations": 2,
            })
            pdf["quarantine_resolved_absent"] = True
            pdf["resolved_absent"] = True

        rewrite_journal_chain(
            session.mutation_journal_path, inject_cross_target)
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_no_attempt_final_absence_requires_every_quarantine_preproof(
            self) -> None:
        for removed in (
                (alpha.TARGET_PDF,),
                (alpha.TARGET_PDF, alpha.TARGET_MARK)):
            session = cleanup_ready_fixture_session(FixtureDevice())
            session._remove_fixture()
            assert session.mutation_journal_path is not None

            def remove_preproof(records: list[dict[str, object]]) -> None:
                final = next(
                    record for record in records
                    if record["event"] == "DEVICE_MUTATIONS_SETTLED")
                obligations = final["obligations"]
                assert isinstance(obligations, dict)
                for member in removed:
                    obligation = obligations[member]
                    assert isinstance(obligation, dict)
                    self.assertFalse(obligation["quarantine_move_attempted"])
                    self.assertTrue(obligation["quarantine_resolved_absent"])
                    obligation["quarantine_pre_absence_sha256"] = None

            rewrite_journal_chain(
                session.mutation_journal_path, remove_preproof)
            with self.subTest(removed=removed), self.assertRaises(
                    alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_noncanonical_raw_json_is_rejected_even_with_valid_hash(
            self) -> None:
        for mode in ("whitespace", "reordered", "crlf"):
            session = cleanup_ready_fixture_session(
                FixtureDevice(), provision_parking=False)
            assert session.mutation_journal_path is not None
            record = json.loads(session.mutation_journal_path.read_text(
                encoding="ascii"))
            if mode == "whitespace":
                raw = json.dumps(record, sort_keys=True).encode("ascii") + b"\n"
            elif mode == "reordered":
                raw = json.dumps(
                    dict(reversed(list(record.items()))),
                    ensure_ascii=True, allow_nan=False,
                    separators=(",", ":")).encode("ascii") + b"\n"
            else:
                raw = alpha._canonical_json_bytes(record) + b"\r\n"
            session.mutation_journal_path.write_bytes(raw)
            with self.subTest(mode=mode), self.assertRaises(alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_rehashed_type_capability_and_event_mutations_are_rejected(
            self) -> None:
        mutations = (
            "type", "device_type", "schema_bool", "capability", "event",
            "details")
        for mutation in mutations:
            session = cleanup_ready_fixture_session(FixtureDevice())
            assert session.mutation_journal_path is not None

            def change(records: list[dict[str, object]]) -> None:
                if mutation == "type":
                    obligations = records[0]["obligations"]
                    assert isinstance(obligations, dict)
                    pdf = obligations[alpha.TARGET_PDF]
                    assert isinstance(pdf, dict)
                    pdf["copy_attempted"] = 1
                elif mutation == "device_type":
                    sources = records[0]["sourceAuthorities"]
                    assert isinstance(sources, dict)
                    pdf_source = sources["pdf"]
                    assert isinstance(pdf_source, dict)
                    pdf_source["size"] = True
                elif mutation == "schema_bool":
                    records[0]["schemaVersion"] = True
                elif mutation == "capability":
                    obligations = records[1]["obligations"]
                    assert isinstance(obligations, dict)
                    pdf = obligations[alpha.TARGET_PDF]
                    assert isinstance(pdf, dict)
                    pdf["staging_path"] = alpha._staging_path(
                        alpha.TARGET_PDF, "f" * 32)
                elif mutation == "event":
                    duplicate = json.loads(json.dumps(records[0]))
                    records.insert(1, duplicate)
                else:
                    details = records[1]["details"]
                    assert isinstance(details, dict)
                    details["unexpected"] = True

            rewrite_journal_chain(session.mutation_journal_path, change)
            with self.subTest(mutation=mutation), self.assertRaises(
                    alpha.AlphaError):
                alpha.recover_mutation_journal(session.mutation_journal_path)

    def test_manifest_recovers_all_capabilities_before_first_copy(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(
            device, provision_parking=False)
        self.assertIsNotNone(session.mutation_journal_path)
        recovered = alpha.recover_mutation_journal(
            session.mutation_journal_path)  # type: ignore[arg-type]
        self.assertEqual(recovered["recordCount"], 1)
        self.assertEqual(
            set(recovered["initialObligations"]),
            {alpha.TARGET_PDF, alpha.TARGET_MARK})
        for target, obligation in session.fixture_obligations.items():
            manifest = recovered["initialObligations"][target]
            self.assertEqual(manifest["source"], obligation.source)
            self.assertEqual(manifest["staging_path"], obligation.staging_path)
            self.assertEqual(
                manifest["quarantine_path"], obligation.quarantine_path)
            self.assertEqual(
                manifest["expected_sha256"], obligation.expected_sha256)
        self.assertTrue(session.mutation_journal_directory_durable)
        self.assertTrue(session._mutation_journal_current())

    def test_copy_timeout_leaves_pre_dispatch_capability_record_recoverable(
            self) -> None:
        device = FixtureDevice()
        device.copy_timeout_target = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        recovered = alpha.recover_mutation_journal(
            session.mutation_journal_path)  # type: ignore[arg-type]
        self.assertEqual(
            recovered["lastRecord"]["event"], "FIXTURE_COPY_ATTEMPTED")
        pdf = recovered["lastRecord"]["obligations"][alpha.TARGET_PDF]
        self.assertTrue(pdf["copy_attempted"])
        self.assertEqual(
            pdf["staging_path"],
            session.fixture_obligations[alpha.TARGET_PDF].staging_path)
        self.assertEqual(device.copy_calls, [pdf["staging_path"]])

    def test_lost_publish_reply_is_settled_in_durable_journal(self) -> None:
        device = FixtureDevice()
        device.publish_timeout_target = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        recovered = alpha.recover_mutation_journal(
            session.mutation_journal_path)  # type: ignore[arg-type]
        self.assertEqual(recovered["lastRecord"]["event"], "FIXTURE_STAGED")
        pdf = recovered["lastRecord"]["obligations"][alpha.TARGET_PDF]
        self.assertTrue(pdf["publish_move_attempted"])
        self.assertFalse(pdf["publish_move_reply_proved"])
        self.assertEqual(
            pdf["publish_move_postcondition"],
            "stage-absent/target-exact")
        self.assertIsNotNone(pdf["retained"])

    def test_journal_is_exclusive_and_never_reused(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        assert session.mutation_journal_path is not None
        before = session.mutation_journal_path.read_bytes()
        with self.assertRaises(alpha.AlphaError):
            session._initialize_mutation_journal()
        self.assertEqual(session.mutation_journal_path.read_bytes(), before)

    def test_preexisting_journal_path_is_not_overwritten(self) -> None:
        device = FixtureDevice()
        temporary = test_temporary_directory()
        session = alpha.AlphaSession(
            device, Path(temporary.name), sleep=lambda _: None)
        session.source_pdf_file = device.state[alpha.SOURCE_PDF]
        session.source_mark_file = device.state[alpha.SOURCE_MARK]
        path = Path(temporary.name) / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        path.write_bytes(b"preexisting-local-evidence\n")
        with self.assertRaises(alpha.AlphaError):
            session._ensure_output_dir()
        self.assertEqual(path.read_bytes(), b"preexisting-local-evidence\n")
        self.assertEqual(device.copy_calls, [])
        self.assertEqual(device.parking_copy_calls, 0)

    def test_tampered_journal_invalidates_report_authority(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        assert session.mutation_journal_path is not None
        raw = session.mutation_journal_path.read_bytes()
        session.mutation_journal_path.write_bytes(raw.replace(
            b"MANIFEST_CREATED", b"MANIFEST_TAMPERED", 1))
        with self.assertRaises(alpha.AlphaError):
            alpha.recover_mutation_journal(session.mutation_journal_path)
        self.assertFalse(session._mutation_journal_current())
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_tampered_journal_blocks_copy_before_device_mutation(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        assert session.mutation_journal_path is not None
        raw = session.mutation_journal_path.read_bytes()
        session.mutation_journal_path.write_bytes(raw.replace(
            b"MANIFEST_CREATED", b"MANIFEST_TAMPERED", 1))
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        self.assertEqual(device.copy_calls, [])
        self.assertEqual(device.publish_calls, [])

    def test_symlinked_recovery_path_is_rejected_before_follow(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        assert session.mutation_journal_path is not None
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / alpha.MUTATION_JOURNAL_FILENAME
            real_lstat = alpha.os.lstat

            def symlink_lstat(path: object) -> object:
                if Path(path) == link:
                    return SimpleNamespace(st_mode=stat_module.S_IFLNK)
                return real_lstat(path)

            with mock.patch.object(alpha.os, "lstat", side_effect=symlink_lstat):
                with self.assertRaises(alpha.AlphaError):
                    alpha.recover_mutation_journal(link)

    def test_report_binds_current_journal_head_and_path(self) -> None:
        session = cleanup_ready_fixture_session(FixtureDevice())
        report = session._report()["fixture"]["mutationJournal"]
        self.assertEqual(report["authority"],
                         alpha.MUTATION_JOURNAL_AUTHORITY)
        self.assertEqual(report["path"], str(session.mutation_journal_path))
        self.assertEqual(report["headSha256"],
                         session.mutation_journal_head_sha256)
        self.assertEqual(report["fileSha256"],
                         session.mutation_journal_file_sha256)
        self.assertEqual(report["recordCount"],
                         session.mutation_journal_sequence)
        self.assertTrue(report["directoryDurable"])
        self.assertTrue(report["current"])
        self.assertFalse(report["discoveryByDirectoryScan"])


class ParkingProvisionTests(unittest.TestCase):
    def test_absent_parking_is_copied_once_and_never_removed(self) -> None:
        device = FixtureDevice()
        device.state.pop(alpha.PARKING_PDF)
        session = parking_provision_session(device)
        source = device.state[alpha.SOURCE_PDF]
        session.source_pdf_file = source
        session.source_mark_file = device.state[alpha.SOURCE_MARK]
        session._provision_parking(source)
        self.assertEqual(device.parking_copy_calls, 1)
        self.assertEqual(session.parking_file, device.state[alpha.PARKING_PDF])
        self.assertNotIn(alpha.PARKING_PDF, device.remove_calls)
        session.cleanup["displayAbsent"] = True
        session.cleanup["hostTaskAbsent"] = True
        session._remove_fixture()
        self.assertIn(alpha.PARKING_PDF, device.state)
        self.assertEqual(device.remove_calls, [])

    def test_existing_exact_parking_is_verified_without_overwrite(self) -> None:
        device = FixtureDevice()
        original = device.state[alpha.PARKING_PDF]
        session = parking_provision_session(device)
        session._provision_parking(device.state[alpha.SOURCE_PDF])
        self.assertEqual(device.parking_copy_calls, 0)
        self.assertIs(session.parking_file, original)

    def test_parking_drift_or_mark_fails_without_overwrite(self) -> None:
        cases = ("hash", "mark")
        for case in cases:
            device = FixtureDevice()
            if case == "hash":
                device.state[alpha.PARKING_PDF] = device_file(
                    alpha.PARKING_PDF, "f" * 64, 13)
            else:
                device.state[alpha.PARKING_MARK] = device_file(
                    alpha.PARKING_MARK, alpha.SOURCE_MARK_SHA256, 14)
            session = parking_provision_session(device)
            with self.subTest(case=case), self.assertRaises(alpha.AlphaError):
                session._provision_parking(device.state[alpha.SOURCE_PDF])
            self.assertEqual(device.parking_copy_calls, 0)

    def test_lost_parking_copy_reply_is_settled_without_retry(self) -> None:
        device = FixtureDevice()
        device.state.pop(alpha.PARKING_PDF)

        def copy_then_timeout() -> None:
            device.parking_copy_calls += 1
            device.state[alpha.PARKING_PDF] = device_file(
                alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 13)
            raise alpha.AlphaError("lost copy reply")

        device.copy_parking_pdf = copy_then_timeout  # type: ignore[method-assign]
        session = parking_provision_session(device)
        session._provision_parking(device.state[alpha.SOURCE_PDF])
        self.assertEqual(device.parking_copy_calls, 1)
        self.assertEqual(session.parking_file, device.state[alpha.PARKING_PDF])

    def test_ambiguous_post_copy_pdf_stat_cannot_claim_clean_rollback(self) -> None:
        device = FixtureDevice()
        device.state.pop(alpha.PARKING_PDF)
        original = device.copy_parking_pdf

        def copy_then_break_pdf_observation() -> None:
            original()
            device.stat_failures[alpha.PARKING_PDF] = 1

        device.copy_parking_pdf = copy_then_break_pdf_observation  # type: ignore[method-assign]
        session = parking_provision_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._provision_parking(device.state[alpha.SOURCE_PDF])
        self.assertTrue(session.parking_provisioning_reached)
        self.assertTrue(session.parking_copy_attempted)
        self.assertTrue(session.parking_copy_reply_proved)
        self.assertFalse(session.parking_provisioning_settled)
        self.assertIsNone(session.parking_file)
        session.cleanup["displayAbsent"] = True
        session.cleanup["hostTaskAbsent"] = True
        session._remove_fixture()
        report = session._report()
        self.assertTrue(session.cleanup["fixtureRemoved"])
        self.assertFalse(report["parking"]["cleanupCertain"])
        self.assertIsNone(report["parking"]["wasModified"])
        self.assertFalse(report["packageRollbackSafe"])
        self.assertEqual(report["result"],
                         "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN")

    def test_ambiguous_post_copy_mark_stat_cannot_claim_clean_rollback(self) -> None:
        device = FixtureDevice()
        device.state.pop(alpha.PARKING_PDF)
        original = device.copy_parking_pdf

        def copy_then_break_mark_observation() -> None:
            original()
            device.stat_failures[alpha.PARKING_MARK] = 1

        device.copy_parking_pdf = copy_then_break_mark_observation  # type: ignore[method-assign]
        session = parking_provision_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._provision_parking(device.state[alpha.SOURCE_PDF])
        self.assertTrue(session.parking_provisioning_reached)
        self.assertTrue(session.parking_copy_attempted)
        self.assertFalse(session.parking_provisioning_settled)
        session.cleanup["displayAbsent"] = True
        session.cleanup["hostTaskAbsent"] = True
        session._remove_fixture()
        report = session._report()
        self.assertFalse(report["parking"]["cleanupCertain"])
        self.assertIsNone(report["parking"]["wasModified"])
        self.assertFalse(report["packageRollbackSafe"])

    def test_settled_existing_parking_requires_fresh_final_revalidation(
            self) -> None:
        device = FixtureDevice()
        session = parking_provision_session(device)
        session._provision_parking(device.state[alpha.SOURCE_PDF])
        self.assertTrue(session.parking_provisioning_reached)
        self.assertTrue(session.parking_provisioning_settled)
        self.assertFalse(session._report()["parking"]["cleanupCertain"])
        session.cleanup["displayAbsent"] = True
        session.cleanup["hostTaskAbsent"] = True
        session._remove_fixture()
        report = session._report()
        self.assertTrue(report["parking"]["cleanupCertain"])
        self.assertFalse(report["parking"]["wasModified"])
        self.assertTrue(report["packageRollbackSafe"])

    def test_idle_document_may_retain_nothing_or_only_parking(self) -> None:
        device = FixtureDevice()
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.parking_file = device.state[alpha.PARKING_PDF]
        for links, expected in (
                ("", frozenset()),
                ("lr-x------ 0 -> " + alpha.PARKING_PDF + "\n",
                 frozenset((alpha.PARKING_PDF,)))):
            device.process_fd_links = lambda pid, value=links: value  # type: ignore[attr-defined]
            with self.subTest(links=links):
                self.assertEqual(session._assert_idle_document_fds(PID), expected)
        for links in (
                "lr-x------ 0 -> " + alpha.PARKING_MARK + "\n",
                "lr-x------ 0 -> " + alpha.TARGET_PDF + "\n",
                "lr-x------ 0 -> /storage/emulated/0/Other.pdf\n",
                "lr-x------ 0 -> " + alpha.PARKING_PDF + " (deleted)\n"):
            device.process_fd_links = lambda pid, value=links: value  # type: ignore[attr-defined]
            with self.subTest(links=links), self.assertRaises(alpha.AlphaError):
                session._assert_idle_document_fds(PID)

    def test_retained_parking_inode_hash_or_mark_drift_is_rejected(self) -> None:
        for case in ("inode", "hash", "mark"):
            device = FixtureDevice()
            session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
            session.parking_file = device.state[alpha.PARKING_PDF]
            if case == "inode":
                device.state[alpha.PARKING_PDF] = device_file(
                    alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 999)
            elif case == "hash":
                device.state[alpha.PARKING_PDF] = device_file(
                    alpha.PARKING_PDF, "f" * 64, 13)
            else:
                device.state[alpha.PARKING_MARK] = device_file(
                    alpha.PARKING_MARK, alpha.SOURCE_MARK_SHA256, 14)
            with self.subTest(case=case), self.assertRaises(alpha.AlphaError):
                session._assert_parking_file_current()

    def test_immediate_prelaunch_accepts_parking_only_process(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        device.activity = (
            b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            b"Display #0 (activities from top to bottom):\n"
            b"Display #3 (activities from top to bottom):\n"
        )
        device.links = "lr-x------ 0 -> " + alpha.PARKING_PDF + "\n"
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        digest = session._prove_prelaunch_absence()
        self.assertEqual(len(digest), 64)
        self.assertEqual(session.prelaunch_absence_sha256, digest)

    def test_immediate_prelaunch_accepts_real_idle_orientation_dialect(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        device.activity = idle_activity_with_default_task_display_area()
        device.links = "lr-x------ 0 -> " + alpha.PARKING_PDF + "\n"
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        digest = session._prove_prelaunch_absence()
        self.assertEqual(len(digest), 64)
        self.assertEqual(session.prelaunch_absence_sha256, digest)
        self.assertFalse(alpha._contains_document_task_or_window(device.activity))

    def test_immediate_prelaunch_accepts_per_display_orientation_dialect(
            self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        device.activity = idle_activity_with_per_display_orientation_pair()
        device.links = "lr-x------ 0 -> " + alpha.PARKING_PDF + "\n"
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        digest = session._prove_prelaunch_absence()
        self.assertEqual(len(digest), 64)
        self.assertEqual(session.prelaunch_absence_sha256, digest)
        self.assertFalse(alpha._contains_document_task_or_window(device.activity))


class ParkingSwitchTests(unittest.TestCase):
    def test_exact_target_to_parking_switch_preserves_owned_identity(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        retained = session.foreign
        session._park_document()
        self.assertEqual(device.parking_launch_calls, 1)
        self.assertEqual(session.foreign, retained)
        self.assertTrue(session.parking_switch_attempted)
        self.assertTrue(session.parking_bound)
        self.assertTrue(session.cleanup["documentParked"])
        self.assertEqual(
            alpha._document_file_targets(device.links),
            frozenset((alpha.PARKING_PDF,)))
        self.assertIn(alpha.TARGET_URI.encode("ascii"), device.activity)
        self.assertNotIn(alpha.PARKING_URI.encode("ascii"), device.activity)
        self.assertIn(b"Display #3", device.activity)
        self.assertEqual(
            session.parking_ui_witness["filename"],
            Path(alpha.PARKING_PDF).name)
        self.assertEqual(session.parking_ui_witness["pageCount"], "1/1")

    def test_lost_parking_reply_settles_without_retry(self) -> None:
        device = ParkingSwitchDevice("lost-reply")
        session = parking_switch_session(device)
        session._park_document()
        session._park_document()
        self.assertEqual(device.parking_launch_calls, 1)
        self.assertTrue(session.parking_bound)
        events = [event for event in session.events
                  if event["name"] == "document_parked"]
        self.assertTrue(events)
        self.assertIn("timeout", str(events[0]["launchTransportError"]))
        self.assertFalse(events[0]["retryUsed"])

    def test_parking_rejects_recreated_or_moved_task(self) -> None:
        for mode in (
                "recreated", "token-changed", "moved", "intent-changed"):
            device = ParkingSwitchDevice(mode)
            session = parking_switch_session(device)
            with self.subTest(mode=mode), self.assertRaises(alpha.CleanupUncertain):
                session._park_document()
            self.assertEqual(device.parking_launch_calls, 1)
            self.assertFalse(session.parking_bound)
            self.assertFalse(session.cleanup["documentParked"])

    def test_parking_rejects_lingering_or_unexpected_descriptors(self) -> None:
        for mode in (
                "lingering-target", "unexpected-pdf", "unexpected-mark"):
            device = ParkingSwitchDevice(mode)
            session = parking_switch_session(device)
            with self.subTest(mode=mode), self.assertRaises(alpha.CleanupUncertain):
                session._park_document()
            self.assertEqual(device.parking_launch_calls, 1)
            self.assertFalse(session.parking_bound)

    def test_parking_rejects_parking_mark_and_identity_drift(self) -> None:
        for mode in (
                "parking-mark", "parking-inode-drift", "parking-hash-drift",
                "source-hash-drift", "target-hash-drift"):
            device = ParkingSwitchDevice(mode)
            session = parking_switch_session(device)
            with self.subTest(mode=mode), self.assertRaises(alpha.CleanupUncertain):
                session._park_document()
            self.assertEqual(device.parking_launch_calls, 1)
            self.assertFalse(session.parking_bound)

    def test_exact_target_mark_replacement_is_authorized_only_at_parking(self) -> None:
        for mode, inode in (("mark-replaced", 777), ("mark-recreated", 778)):
            device = ParkingSwitchDevice(mode)
            session = parking_switch_session(device)
            original = session.fixture_obligations[alpha.TARGET_MARK].retained
            session._park_document()
            obligation = session.fixture_obligations[alpha.TARGET_MARK]
            with self.subTest(mode=mode):
                self.assertTrue(obligation.parking_recreated_or_replaced)
                self.assertEqual(obligation.pre_parking_retained, original)
                self.assertEqual(obligation.retained.inode, inode)
                self.assertEqual(
                    [event["name"] for event in session.events].count(
                        "target_mark_recreated_or_replaced_at_parking"), 1)

    def test_exact_missing_target_mark_may_be_recreated_by_parking_save(self) -> None:
        device = ParkingSwitchDevice("mark-recreated")
        session = parking_switch_session(device)
        device.state.pop(alpha.TARGET_MARK)
        session._park_document()
        obligation = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertTrue(obligation.parking_absent_before_switch)
        self.assertTrue(obligation.parking_recreated_or_replaced)
        self.assertEqual(obligation.retained.inode, 778)

    def test_recreated_mark_survives_park_reverify_and_fixture_removal(self) -> None:
        device = ParkingSwitchDevice("mark-recreated")
        session = parking_switch_session(device)
        device.state.pop(alpha.TARGET_MARK)
        session._park_document()
        session._reverify_parked_foreign()
        obligation = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertTrue(obligation.parking_absent_before_switch)
        self.assertTrue(obligation.parking_recreated_or_replaced)
        self.assertEqual(obligation.retained.inode, 778)
        self.assertEqual(
            [event["name"] for event in session.events].count(
                "target_mark_recreated_or_replaced_at_parking"), 1)

        device.activity = empty_activity_with_document_supervisor_ghost()
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        session._prove_global_document_absence()
        session.cleanup["displayAbsent"] = True
        session.cleanup["hostTaskAbsent"] = True
        session._remove_fixture()
        self.assertEqual(
            device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertTrue(session.cleanup["fixtureRemoved"])

    def test_target_mark_refresh_rejects_bad_bytes_type_or_unknown_ownership(self) -> None:
        for mode in (
                "mark-size-drift", "mark-hash-drift", "mark-nonregular"):
            device = ParkingSwitchDevice(mode)
            session = parking_switch_session(device)
            with self.subTest(mode=mode), self.assertRaises(alpha.CleanupUncertain):
                session._park_document()
            self.assertFalse(session.parking_bound)

        device = ParkingSwitchDevice("mark-replaced")
        session = parking_switch_session(device)
        session.fixture_obligations[alpha.TARGET_MARK].ownership_ambiguous = True
        with self.assertRaises(alpha.AlphaError):
            session._park_document()
        self.assertEqual(device.parking_launch_calls, 0)
        self.assertFalse(session.parking_bound)

    def test_target_mark_replacement_before_authenticated_switch_is_rejected(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        device.state[alpha.TARGET_MARK] = device_file(
            alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 777)
        with self.assertRaises(alpha.AlphaError):
            session._park_document()
        self.assertEqual(device.parking_launch_calls, 0)

    def test_parking_requires_fresh_exact_ui_filename_witness(self) -> None:
        device = ParkingSwitchDevice("ui-missing")
        session = parking_switch_session(device)
        with self.assertRaises(alpha.CleanupUncertain):
            session._park_document()
        self.assertEqual(device.parking_launch_calls, 1)
        self.assertFalse(session.parking_bound)

    def test_parking_requires_authenticated_begin_close_and_precedes_remove(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        session.close_started = False
        with self.assertRaises(alpha.CleanupUncertain):
            session._park_document()
        self.assertEqual(device.parking_launch_calls, 0)

        order: list[str] = []
        session.close_started = False
        session._begin_close = lambda: (  # type: ignore[method-assign]
            order.append("close"), setattr(session, "close_started", True))
        session._park_document = lambda: (  # type: ignore[method-assign]
            order.append("park"), setattr(session, "parking_bound", True),
            session.cleanup.__setitem__("documentParked", True))
        session._remove_foreign = lambda: order.append("remove")  # type: ignore[method-assign]
        session._release_after_destroy = lambda: order.append("release")  # type: ignore[method-assign]
        session._remove_fixture = lambda: order.append("files")  # type: ignore[method-assign]
        session._cleanup()
        self.assertEqual(order, ["close", "park", "remove", "release", "files"])

    def test_final_descriptor_proof_requires_exact_parking_twice(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        session._park_document()
        session._prove_disposable_descriptors_closed()
        self.assertTrue(session.cleanup["disposableDescriptorsClosed"])

        device.links += "lr-x------ 1 -> " + alpha.TARGET_PDF + " (deleted)\n"
        session.cleanup["disposableDescriptorsClosed"] = False
        with self.assertRaises(alpha.CleanupUncertain):
            session._prove_disposable_descriptors_closed()
        self.assertFalse(session.cleanup["disposableDescriptorsClosed"])

    def test_task_absence_ignores_validated_post_boundary_supervisor_ghost(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        session._park_document()
        device.activity = empty_activity_with_document_supervisor_ghost()
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        device.displays = (  # type: ignore[attr-defined]
            lambda: ("Display 3 name=" + session.status.display_name + "\n").encode(
                "ascii"))
        digest = session._prove_task_absent()
        self.assertEqual(len(digest), 64)
        self.assertTrue(session.cleanup["taskAbsent"])

    def test_task_absence_accepts_exact_multi_display_supervisor_ghost(
            self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        session._park_document()
        device.activity = empty_activity_with_document_supervisor_ghost_and_pair()
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        device.displays = (  # type: ignore[attr-defined]
            lambda: ("Display 3 name=" + session.status.display_name + "\n").encode(
                "ascii"))
        digest = session._prove_task_absent()
        self.assertEqual(len(digest), 64)
        self.assertTrue(session.cleanup["taskAbsent"])

    def test_final_fixture_deletion_keeps_persistent_parking_pdf(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        session._park_document()
        device.activity = empty_activity_with_document_supervisor_ghost()
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        session._prove_global_document_absence()
        session.cleanup["displayAbsent"] = True
        session.cleanup["hostTaskAbsent"] = True
        session._remove_fixture()
        self.assertEqual(
            device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertIn(alpha.PARKING_PDF, device.state)
        self.assertNotIn(alpha.PARKING_PDF, device.remove_calls)
        self.assertTrue(session.cleanup["documentParked"])
        self.assertTrue(session.cleanup["disposableDescriptorsClosed"])


class FixtureCleanupContinuationTests(unittest.TestCase):

    def test_copy_create_then_timeout_is_unowned_and_never_deleted(self) -> None:
        device = FixtureDevice()
        device.copy_timeout_target = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        self.assertEqual(
            set(session.fixture_obligations),
            {alpha.TARGET_PDF, alpha.TARGET_MARK})
        obligation = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertTrue(obligation.copy_attempted)
        self.assertTrue(obligation.staging_ownership_ambiguous)
        self.assertIsNone(obligation.retained)

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.move_calls, [])
        self.assertEqual(device.remove_calls, [])
        self.assertIn(obligation.staging_path, device.state)
        self.assertNotIn(alpha.TARGET_PDF, device.state)
        self.assertFalse(session.cleanup["fixtureRemoved"])
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_copy_success_then_stat_timeout_remains_a_cleanup_obligation(self) -> None:
        device = FixtureDevice()
        original_copy = device.copy_fixture_member

        def copy_then_arm_stat(source: str, staging: str) -> None:
            original_copy(source, staging)
            if alpha._staging_target(staging) == alpha.TARGET_PDF:
                device.stat_failures[staging] = 1

        device.copy_fixture_member = copy_then_arm_stat  # type: ignore[method-assign]
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        obligation = session.fixture_obligations[alpha.TARGET_PDF]
        self.assertTrue(obligation.copy_reply_proved)
        self.assertTrue(obligation.staging_ownership_ambiguous)
        self.assertIsNone(obligation.retained)

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.move_calls, [])
        self.assertEqual(device.remove_calls, [])
        self.assertIn(obligation.staging_path, device.state)
        self.assertNotIn(alpha.TARGET_PDF, device.state)
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_second_member_timeout_preserves_both_without_deleting_unowned_mark(self) -> None:
        device = FixtureDevice()
        device.copy_timeout_target = alpha.TARGET_MARK
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        pdf = session.fixture_obligations[alpha.TARGET_PDF]
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertIsNotNone(pdf.retained)
        self.assertFalse(pdf.ownership_ambiguous)
        self.assertIsNone(mark.retained)
        self.assertTrue(mark.staging_ownership_ambiguous)

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.move_calls, [])
        self.assertEqual(device.remove_calls, [])
        self.assertIn(mark.staging_path, device.state)
        self.assertNotIn(alpha.TARGET_MARK, device.state)
        self.assertIn(alpha.TARGET_PDF, device.state)
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_mismatched_replacement_is_never_deleted_or_claimed_clean(self) -> None:
        device = FixtureDevice()
        device.copy_timeout_target = alpha.TARGET_PDF
        session = cleanup_ready_fixture_session(device)
        with self.assertRaises(alpha.AlphaError):
            session._stage_fixture()
        device.state[alpha.TARGET_PDF] = device_file(
            alpha.TARGET_PDF, "f" * 64, 999)

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.remove_calls, [])
        self.assertIn(alpha.TARGET_PDF, device.state)
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_mark_replacement_with_reused_inode_is_never_deleted(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        retained_mark = session.fixture_obligations[alpha.TARGET_MARK].retained
        self.assertIsNotNone(retained_mark)
        assert retained_mark is not None
        device.state[alpha.TARGET_MARK] = device_file(
            alpha.TARGET_MARK, "c" * 64, retained_mark.inode)

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.remove_calls, [])
        self.assertIn(alpha.TARGET_MARK, device.state)
        self.assertFalse(session._report()["packageRollbackSafe"])

    def test_preexisting_random_quarantine_blocks_all_fixture_mutation(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        quarantine = session.fixture_obligations[alpha.TARGET_MARK].quarantine_path
        device.state[quarantine] = device_file(quarantine, "e" * 64, 700)

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.move_calls, [])
        self.assertEqual(device.remove_calls, [])
        self.assertIn(alpha.TARGET_MARK, device.state)
        self.assertIn(alpha.TARGET_PDF, device.state)
        self.assertEqual(device.state[quarantine].sha256, "e" * 64)
        observed = session.fixture_obligations[
            alpha.TARGET_MARK].quarantine_preexisting_observed
        self.assertEqual(observed, device.state[quarantine])
        reported = session._report()["fixture"]["cleanupObligations"][
            alpha.TARGET_MARK]
        self.assertEqual(
            reported["quarantine_preexisting_observed"]["sha256"], "e" * 64)

    def test_move_timeout_after_rename_settles_without_retry(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        device.move_timeout_target = alpha.TARGET_MARK

        session._remove_fixture()
        self.assertEqual(device.move_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertEqual(device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertTrue(mark.quarantine_move_attempted)
        self.assertFalse(mark.quarantine_move_reply_proved)
        self.assertIn("timeout", str(mark.quarantine_move_transport_error))
        self.assertEqual(
            [event["name"] for event in session.events].count(
                "fixture_quarantined"), 2)
        self.assertTrue(session.cleanup["fixtureRemoved"])

    def test_move_timeout_before_rename_is_never_retried_or_deleted(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        device.move_timeout_before_move = alpha.TARGET_MARK

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.move_calls, [alpha.TARGET_MARK])
        self.assertEqual(device.remove_calls, [])
        self.assertIn(alpha.TARGET_MARK, device.state)
        self.assertIn(alpha.TARGET_PDF, device.state)
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertTrue(mark.quarantine_move_attempted)
        self.assertFalse(mark.quarantine_move_reply_proved)
        self.assertIsNone(mark.quarantine_retained)

    def test_quarantine_racing_after_preproof_is_not_clobbered_or_deleted(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        original_move = device.move_fixture_to_quarantine

        def collide(path: str, quarantine: str) -> None:
            if path == alpha.TARGET_MARK:
                device.state[quarantine] = device_file(quarantine, "d" * 64, 701)
            original_move(path, quarantine)

        device.move_fixture_to_quarantine = collide  # type: ignore[method-assign]
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertEqual(device.move_calls, [alpha.TARGET_MARK])
        self.assertEqual(device.remove_calls, [])
        self.assertIn(alpha.TARGET_MARK, device.state)
        self.assertEqual(device.state[mark.quarantine_path].sha256, "d" * 64)

    def test_replaced_quarantine_after_move_is_preserved_without_unlink(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        original_move = device.move_fixture_to_quarantine

        def move_then_replace(path: str, quarantine: str) -> None:
            original_move(path, quarantine)
            if path == alpha.TARGET_MARK:
                device.state[quarantine] = device_file(quarantine, "c" * 64, 702)

        device.move_fixture_to_quarantine = move_then_replace  # type: ignore[method-assign]
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertNotIn(alpha.TARGET_MARK, device.state)
        self.assertEqual(device.state[mark.quarantine_path].sha256, "c" * 64)
        self.assertEqual(device.remove_calls, [])

    def test_source_reappearing_after_move_preserves_quarantine_and_replacement(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        original_move = device.move_fixture_to_quarantine

        def move_then_recreate(path: str, quarantine: str) -> None:
            original_move(path, quarantine)
            if path == alpha.TARGET_MARK:
                device.state[path] = device_file(path, "b" * 64, 703)

        device.move_fixture_to_quarantine = move_then_recreate  # type: ignore[method-assign]
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertEqual(device.state[alpha.TARGET_MARK].sha256, "b" * 64)
        self.assertIn(mark.quarantine_path, device.state)
        self.assertEqual(device.remove_calls, [])

    def test_quarantine_replacement_before_remove_is_never_deleted(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        original = session._move_owned_fixture_to_quarantine

        def move_then_replace(
                obligation: alpha.FixtureObligation,
                retained: alpha.DeviceFile) -> alpha.DeviceFile:
            result = original(obligation, retained)
            if obligation.target == alpha.TARGET_MARK:
                device.state[obligation.quarantine_path] = device_file(
                    obligation.quarantine_path, "a" * 64, 704)
            return result

        session._move_owned_fixture_to_quarantine = move_then_replace  # type: ignore[method-assign]
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertEqual(device.state[mark.quarantine_path].sha256, "a" * 64)
        self.assertEqual(device.remove_calls, [])

    def test_remove_timeout_before_unlink_is_never_retried(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        device.remove_timeout_before_delete = True

        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        mark = session.fixture_obligations[alpha.TARGET_MARK]
        self.assertEqual(device.move_calls, [alpha.TARGET_MARK])
        self.assertEqual(device.remove_calls, [alpha.TARGET_MARK])
        self.assertNotIn(alpha.TARGET_MARK, device.state)
        self.assertIn(mark.quarantine_path, device.state)
        self.assertFalse(mark.quarantine_remove_reply_proved)
        self.assertIn("timeout", str(mark.quarantine_remove_transport_error))

    def test_remove_timeout_is_not_retried_when_repeated_absence_settles_it(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        device.remove_timeout_after_delete = True

        session._remove_fixture()
        self.assertEqual(
            device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertEqual(
            [event["name"] for event in session.events].count(
                "quarantine_remove_transport_error_but_absent"), 2)
        self.assertTrue(session.cleanup["fixtureRemoved"])
        self.assertTrue(session._report()["packageRollbackSafe"])

    def test_mark_reappearance_during_pdf_deletion_fails_without_retry(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        original_remove = device.remove_quarantine_member

        def remove_and_recreate_mark(quarantine: str) -> None:
            original_remove(quarantine)
            if alpha._quarantine_target(quarantine) == alpha.TARGET_PDF:
                device.state[alpha.TARGET_MARK] = device_file(
                    alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 777)

        device.remove_quarantine_member = remove_and_recreate_mark  # type: ignore[method-assign]
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(
            device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertIn(alpha.TARGET_MARK, device.state)
        self.assertFalse(session.cleanup["fixtureRemoved"])
        self.assertFalse(any(
            obligation.resolved_absent
            for obligation in session.fixture_obligations.values()))

    def test_reappearance_between_joint_absence_observations_fails_no_retry(self) -> None:
        for reappearing, expected, inode in (
                (alpha.TARGET_MARK, alpha.SOURCE_MARK_SHA256, 778),
                (alpha.TARGET_PDF, alpha.SOURCE_PDF_SHA256, 779)):
            with self.subTest(reappearing=reappearing):
                device = FixtureDevice()
                qualifying_sleeps = 0

                def sleep(_: float) -> None:
                    nonlocal qualifying_sleeps
                    if (device.remove_calls ==
                            [alpha.TARGET_MARK, alpha.TARGET_PDF] and
                            alpha.TARGET_MARK not in device.state and
                            alpha.TARGET_PDF not in device.state):
                        qualifying_sleeps += 1
                        if qualifying_sleeps == 2:
                            device.state[reappearing] = device_file(
                                reappearing, expected, inode)

                session = cleanup_ready_fixture_session(device)
                session.sleep = sleep
                session._stage_fixture()
                with self.assertRaises(alpha.CleanupUncertain):
                    session._remove_fixture()
                self.assertEqual(qualifying_sleeps, 2)
                self.assertEqual(
                    device.remove_calls,
                    [alpha.TARGET_MARK, alpha.TARGET_PDF])
                self.assertIn(reappearing, device.state)
                self.assertFalse(session.cleanup["fixtureRemoved"])

    def test_quarantine_reappearance_during_joint_absence_is_preserved(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        quarantine = session.fixture_obligations[alpha.TARGET_PDF].quarantine_path
        qualifying_sleeps = 0

        def sleep(_: float) -> None:
            nonlocal qualifying_sleeps
            if (device.remove_calls == [alpha.TARGET_MARK, alpha.TARGET_PDF] and
                    alpha.TARGET_MARK not in device.state and
                    alpha.TARGET_PDF not in device.state and
                    quarantine not in device.state):
                qualifying_sleeps += 1
                if qualifying_sleeps == 2:
                    device.state[quarantine] = device_file(
                        quarantine, "9" * 64, 780)

        session.sleep = sleep
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.move_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertEqual(device.remove_calls, [alpha.TARGET_MARK, alpha.TARGET_PDF])
        self.assertIn(quarantine, device.state)
        self.assertFalse(session.cleanup["fixtureRemoved"])


class LaunchAmbiguityTests(unittest.TestCase):
    def test_launch_attempt_is_recorded_before_dispatch_can_time_out(self) -> None:
        observations = iter((b"empty\n", b"empty\n"))
        session: alpha.AlphaSession

        def launch(display_id: int) -> None:
            self.assertEqual(display_id, 3)
            self.assertTrue(session.document_launch_attempted)
            raise alpha.AlphaError("simulated launch transport timeout")

        device = SimpleNamespace(
            history=[], launch_document=launch,
            activities=lambda: next(observations),
        )
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.status = status()
        session._prove_prelaunch_absence = (  # type: ignore[method-assign]
            lambda: setattr(session, "prelaunch_absence_sha256", "a" * 64) or
            "a" * 64)
        with mock.patch.object(
                session, "_until", side_effect=alpha.AlphaError("no identity")):
            with self.assertRaises(alpha.AlphaError):
                session._launch_foreign()
        self.assertTrue(session.document_launch_attempted)
        self.assertIsNone(session.foreign)

    def test_ambiguous_launch_cannot_use_parking_to_manufacture_cleanup_authority(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        session.document_launch_attempted = True
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertEqual(device.remove_calls, [])
        self.assertFalse(session._report()["packageRollbackSafe"])

        session.cleanup["documentGloballyAbsent"] = True
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        self.assertFalse(session.cleanup["documentParked"])
        self.assertFalse(session.cleanup["disposableDescriptorsClosed"])
        self.assertEqual(device.remove_calls, [])

    def test_last_foreign_capture_error_is_reported_with_a_strict_bound(self) -> None:
        observations = iter((activity_wire(), activity_wire()))
        device = SimpleNamespace(
            history=[],
            launch_document=lambda display_id: SimpleNamespace(returncode=0),
            activities=lambda: next(observations),
        )
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.status = status()
        session._prove_prelaunch_absence = (  # type: ignore[method-assign]
            lambda: setattr(session, "prelaunch_absence_sha256", "a" * 64) or
            "a" * 64)
        session._capture_foreign = mock.Mock(  # type: ignore[method-assign]
            side_effect=android.AndroidAuthorityError("x" * 4096))

        def fail_after_observation(
                label: str, seconds: float, observe: object) -> object:
            self.assertIsNone(observe())  # type: ignore[operator]
            raise alpha.AlphaError("no identity")

        with mock.patch.object(session, "_until",
                               side_effect=fail_after_observation):
            with self.assertRaises(alpha.CleanupUncertain):
                session._launch_foreign()

        diagnostic = session._report()["lastForeignCaptureError"]
        self.assertIsInstance(diagnostic, str)
        self.assertTrue(diagnostic.startswith("AndroidAuthorityError: "))
        self.assertTrue(diagnostic.endswith("..."))
        self.assertLessEqual(
            len(diagnostic.encode("utf-8")),
            alpha.MAX_OBSERVATION_ERROR_BYTES,
        )

    def test_any_document_descriptor_or_multiple_processes_blocks_deletion(self) -> None:
        cases = (
            ((PID,), "lr-x------ 0 -> /storage/emulated/0/Other.pdf\n"),
            ((PID, PID + 1), ""),
        )
        for pids, links in cases:
            with self.subTest(pids=pids, links=links):
                device = SimpleNamespace(
                    history=[], pidof=lambda package, value=pids: value,
                    process_identity=lambda pid, package: host.ProcessIdentity(
                        pid, 123456, 1000, alpha.DOCUMENT_PACKAGE),
                    process_fd_links=lambda pid, value=links: value,
                )
                session = alpha.AlphaSession(
                    device, Path("."), sleep=lambda _: None)
                session.document_launch_attempted = True
                session.foreign = foreign()
                session.parking_bound = True
                session.cleanup["documentParked"] = True
                with self.assertRaises(alpha.CleanupUncertain):
                    session._prove_disposable_descriptors_closed()
                self.assertFalse(
                    session.cleanup["disposableDescriptorsClosed"])

    def test_other_stock_document_component_is_not_global_absence(self) -> None:
        other_activity = (
            b"Display #0 (activities from top to bottom):\n"
            b"  ActivityRecord{123 u0 "
            b"com.supernote.document/.OtherActivity t77}\n")
        device = SimpleNamespace(
            history=[], activities=lambda: other_activity,
            windows=lambda: b"WINDOW MANAGER WINDOWS\n",
        )
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.document_launch_attempted = True
        with self.assertRaises(alpha.CleanupUncertain):
            session._prove_global_document_absence()
        self.assertFalse(session.cleanup["documentGloballyAbsent"])
        self.assertTrue(alpha._contains_document_task_or_window(other_activity))
        self.assertFalse(alpha._contains_document_task_or_window(
            b"com.supernote.documenthelper/.OtherActivity\n"))

    def test_empty_supervisor_document_ghost_is_not_a_live_task(self) -> None:
        ghost = empty_activity_with_document_supervisor_ghost()
        self.assertIn(alpha.DOCUMENT_PACKAGE.encode("ascii"), ghost)
        # Unqualified absence is conservative: the supervisor suffix is never
        # task-selection authority, but it still contains Document evidence.
        self.assertTrue(alpha._contains_document_task_or_window(ghost))

        device = SimpleNamespace(
            history=[], activities=lambda: ghost,
            windows=lambda: b"WINDOW MANAGER WINDOWS\n")
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.document_launch_attempted = True
        session.foreign = foreign()
        session.foreign_authority = android.parse_document_task_authority(
            activity_wire(), expected_pid=PID)
        session._prove_global_document_absence()
        self.assertTrue(session.cleanup["documentGloballyAbsent"])

    def test_exact_multi_display_supervisor_ghost_proves_absence(self) -> None:
        ghost = empty_activity_with_document_supervisor_ghost_and_pair()
        retained = foreign()
        retained_authority = android.parse_document_task_authority(
            activity_wire(), expected_pid=PID)
        text, _ = android._wire(ghost)
        self.assertTrue(alpha._is_exact_stale_document_supervisor_ghost(
            text, retained, retained_authority))
        self.assertFalse(alpha._contains_document_scope_for_global_absence(
            ghost, retained, retained_authority))

        device = SimpleNamespace(
            history=[], activities=lambda: ghost,
            windows=lambda: b"WINDOW MANAGER WINDOWS\n")
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.document_launch_attempted = True
        session.foreign = retained
        session.foreign_authority = retained_authority
        session._prove_global_document_absence()
        self.assertTrue(session.cleanup["documentGloballyAbsent"])

    def test_multi_display_supervisor_ghost_pair_mutations_fail_closed(
            self) -> None:
        ghost = empty_activity_with_document_supervisor_ghost_and_pair()
        retained = foreign()
        retained_authority = android.parse_document_task_authority(
            activity_wire(), expected_pid=PID)
        pair = (
            b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
            b"  deepestLastOrientationSource="
            b"DefaultTaskDisplayArea@140913322\n")
        last = b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
        deepest = (
            b"  deepestLastOrientationSource="
            b"DefaultTaskDisplayArea@140913322\n")
        display_zero = b"  Display: mDisplayId=0 stacks=0\n"
        display_three = b"  Display: mDisplayId=3 stacks=0\n"
        target_last = (
            b"  mLastOrientationSource=ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        target_deepest = (
            b"  deepestLastOrientationSource=ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        mutations = {
            "misplaced": ghost.replace(pair, last + display_three + deepest, 1),
            "missing-last": ghost.replace(last, b"", 1),
            "missing-deepest": ghost.replace(deepest, b"", 1),
            "mismatched-identity": ghost.replace(
                deepest, deepest.replace(b"140913322", b"140913323"), 1),
            "duplicate-pair": ghost.replace(pair, pair + pair, 1),
            "primary-pair": ghost.replace(
                display_zero, pair + display_zero, 1),
            "target-last": ghost.replace(last, target_last, 1),
            "target-deepest": ghost.replace(deepest, target_deepest, 1),
            "target-pair": ghost.replace(last, target_last, 1).replace(
                deepest, target_deepest, 1),
            "leading-zero-identity": ghost.replace(
                b"@140913322", b"@0140913322", 1),
            "negative-identity": ghost.replace(
                b"@140913322", b"@-140913322", 1),
            "overflow-identity": ghost.replace(
                b"@140913322", b"@2147483648", 1),
            "duplicate-summary": ghost.replace(
                display_three, display_three + display_three, 1),
            "unknown-summary": ghost.replace(
                display_three, b"  Display: mDisplayId=4 stacks=0\n", 1),
            "nonempty-summary": ghost.replace(
                display_three, b"  Display: mDisplayId=3 stacks=1\n", 1),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name):
                text, _ = android._wire(raw)
                self.assertFalse(
                    alpha._is_exact_stale_document_supervisor_ghost(
                        text, retained, retained_authority))
                try:
                    document_scope = (
                        alpha._contains_document_scope_for_global_absence(
                            raw, retained, retained_authority))
                except android.AndroidAuthorityError:
                    # Malformed summary/header evidence may be rejected before
                    # the exact-ghost exception is considered; that is also a
                    # fail-closed result.
                    continue
                self.assertTrue(document_scope)

    def test_supervisor_ghost_pairs_require_unique_display_area_identities(
            self) -> None:
        retained = foreign()
        retained_authority = android.parse_document_task_authority(
            activity_wire(), expected_pid=PID)
        valid = empty_activity_with_document_supervisor_ghost_and_two_pairs()
        valid_text, _ = android._wire(valid)
        self.assertTrue(alpha._is_exact_stale_document_supervisor_ghost(
            valid_text, retained, retained_authority))
        self.assertFalse(alpha._contains_document_scope_for_global_absence(
            valid, retained, retained_authority))

        duplicate = valid.replace(
            b"DefaultTaskDisplayArea@140913323",
            b"DefaultTaskDisplayArea@140913322")
        duplicate_text, _ = android._wire(duplicate)
        self.assertFalse(alpha._is_exact_stale_document_supervisor_ghost(
            duplicate_text, retained, retained_authority))
        with self.assertRaises(android.AndroidAuthorityError):
            alpha._contains_document_scope_for_global_absence(
                duplicate, retained, retained_authority)

        device = SimpleNamespace(
            history=[], activities=lambda: duplicate,
            windows=lambda: b"WINDOW MANAGER WINDOWS\n")
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.document_launch_attempted = True
        session.foreign = retained
        session.foreign_authority = retained_authority
        with self.assertRaises(alpha.CleanupUncertain):
            session._prove_global_document_absence()
        self.assertFalse(session.cleanup["documentGloballyAbsent"])

    def test_exact_supervisor_ghost_requires_retained_task_authority(
            self) -> None:
        ghost = empty_activity_with_document_supervisor_ghost()
        device = SimpleNamespace(
            history=[], activities=lambda: ghost,
            windows=lambda: b"WINDOW MANAGER WINDOWS\n")
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.document_launch_attempted = True
        session.foreign = foreign()
        with self.assertRaises(alpha.CleanupUncertain):
            session._prove_global_document_absence()
        self.assertFalse(session.cleanup["documentGloballyAbsent"])

    def test_unqualified_absence_rejects_any_supervisor_document_evidence(
            self) -> None:
        idle = idle_activity_with_default_task_display_area()
        insertion = b"  Display: mDisplayId=0 stacks=1\n"
        mutations = {
            "focused-affinity": idle.replace(
                b"  topDisplayFocusedStack=Task{7654321 #7 visible=true "
                b"type=home mode=fullscreen A=1000:com.example.home "
                b"U=0 StackId=7 sz=1}\n",
                b"  topDisplayFocusedStack=Task{7654321 #7 visible=true "
                b"type=home mode=fullscreen A=1000:com.supernote.document "
                b"U=0 StackId=7 sz=1}\n",
                1),
            "arbitrary-retained-package": idle.replace(
                insertion,
                b"  retainedPackage=com.supernote.document\n" + insertion,
                1),
            "indented-live-task": idle.replace(
                insertion,
                b"      * Task{66d8263 #4538 visible=true "
                b"A=1000:com.supernote.document U=0 StackId=4538 sz=1}\n" +
                insertion,
                1),
        }
        self.assertFalse(alpha._contains_document_task_or_window(idle))
        for name, raw in mutations.items():
            with self.subTest(name=name):
                canonical = android._reject_malformed_structural_headers(
                    android._wire(raw)[0])
                self.assertNotIn(alpha.DOCUMENT_PACKAGE, canonical)
                self.assertTrue(alpha._contains_document_task_or_window(raw))

    def test_global_absence_rejects_every_nonexact_target_supervisor_suffix(self) -> None:
        ghost = empty_activity_with_document_supervisor_ghost()
        mutations = {
            "visible": ghost.replace(b"visible=false", b"visible=true", 1),
            "contradictory-visible": ghost.replace(
                b"visible=false", b"visible=false visible=true", 1),
            "nonempty": ghost.replace(b"sz=0", b"sz=1", 1),
            "contradictory-size": ghost.replace(
                b"sz=0", b"sz=0 sz=1", 1),
            "task": ghost.replace(b"#4538", b"#4539", 1),
            "task-token": ghost.replace(
                b"Task{66d8263", b"Task{76d8263"),
            "affinity-uid": ghost.replace(b"A=1000:", b"A=2000:"),
            "activity-token": ghost.replace(b"11846f4", b"21846f4", 1),
            "activity-component": ghost.replace(
                b"com.supernote.document/.document.DocumentActivity",
                b"com.supernote.document/"
                b"com.supernote.document.document.DocumentActivity"),
            "topology": ghost.replace(
                b"  mLastFocusedStack=Task{66d8263 #4538 visible=false "
                b"A=1000:com.supernote.document sz=0}\n"
                b"  Display: mDisplayId=0 stacks=0\n",
                b"  Display: mDisplayId=0 stacks=0\n"
                b"  mLastFocusedStack=Task{66d8263 #4538 visible=false "
                b"A=1000:com.supernote.document sz=0}\n", 1),
            "retained-identity-relabeled-package": ghost.replace(
                b"com.supernote.document", b"com.example.other"),
            "missing-last-focused": ghost.replace(
                b"  mLastFocusedStack=Task{66d8263 #4538 visible=false "
                b"A=1000:com.supernote.document sz=0}\n", b"", 1),
            "extra-target-record": ghost.replace(
                b"  Display: mDisplayId=0 stacks=0\n",
                b"  retainedPackage=com.supernote.document\n"
                b"  Display: mDisplayId=0 stacks=0\n", 1),
            "extra-retained-task-without-package": ghost.replace(
                b"  Display: mDisplayId=0 stacks=0\n",
                b"  mFocusedStack=Task{feedbeef #4538 visible=true sz=1}\n"
                b"  Display: mDisplayId=0 stacks=0\n", 1),
            "extra-root-task-id": ghost.replace(
                b"  Display: mDisplayId=0 stacks=0\n",
                b"  mFocusedRootTaskId=4538 visible=true\n"
                b"  Display: mDisplayId=0 stacks=0\n", 1),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name):
                # Supervisor records remain non-authoritative for selecting a
                # task, but their target evidence defeats generic absence.
                if alpha.DOCUMENT_PACKAGE.encode("ascii") in raw:
                    self.assertTrue(
                        alpha._contains_document_task_or_window(raw))
                device = SimpleNamespace(
                    history=[], activities=lambda value=raw: value,
                    windows=lambda: b"WINDOW MANAGER WINDOWS\n")
                session = alpha.AlphaSession(
                    device, Path("."), sleep=lambda _: None)
                session.document_launch_attempted = True
                session.foreign = foreign()
                session.foreign_authority = (
                    android.parse_document_task_authority(
                        activity_wire(), expected_pid=PID))
                with self.assertRaises(alpha.CleanupUncertain):
                    session._prove_global_document_absence()
                self.assertFalse(session.cleanup["documentGloballyAbsent"])

        device = SimpleNamespace(
            history=[], activities=lambda: ghost,
            windows=lambda: b"WINDOW MANAGER WINDOWS\n")
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session.document_launch_attempted = True
        with self.assertRaises(alpha.CleanupUncertain):
            session._prove_global_document_absence()

    def test_task_absence_rejects_unrecognized_supervisor_suffix(self) -> None:
        device = ParkingSwitchDevice()
        session = parking_switch_session(device)
        session._park_document()
        device.activity = empty_activity_with_document_supervisor_ghost().replace(
            b"  Display: mDisplayId=0 stacks=0\n",
            b"  mFocusedRootTaskId=4538 visible=true\n"
            b"  Display: mDisplayId=0 stacks=0\n", 1)
        device.windows = lambda: b"WINDOW MANAGER WINDOWS\n"  # type: ignore[attr-defined]
        device.displays = (  # type: ignore[attr-defined]
            lambda: ("Display 3 name=" + session.status.display_name + "\n").encode(
                "ascii"))
        with self.assertRaises(alpha.AlphaError):
            session._prove_task_absent()
        self.assertFalse(session.cleanup["taskAbsent"])

    def test_canonical_document_task_is_live_on_any_display(self) -> None:
        for display in (0, 3, 9):
            raw = activity_wire().replace(
                b"Display #3 (activities from top to bottom):",
                f"Display #{display} (activities from top to bottom):".encode(
                    "ascii"),
                1,
            )
            with self.subTest(display=display):
                self.assertTrue(alpha._contains_document_task_or_window(raw))

    def test_canonical_other_package_task_is_not_document(self) -> None:
        raw = b"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #77: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{abc u0 com.example.other/.OtherActivity t77}
    * Task{def #77 visible=true A=10001:com.example.other U=0 StackId=77 sz=1}
      taskId=77 stackId=77
      * Hist #0: ActivityRecord{abc u0 com.example.other/.OtherActivity t77}
"""
        self.assertFalse(alpha._contains_document_task_or_window(raw))

    def test_canonical_transition_document_evidence_fails_closed(self) -> None:
        transitioning = b"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #77: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{abc u0 com.example.other/.OtherActivity t77}
    * Task{def #77 visible=true A=10001:com.example.other U=0 StackId=77 sz=2}
      taskId=77 stackId=77
      * Hist #1: ActivityRecord{abc u0 com.example.other/.OtherActivity t77}
      * Hist #0: ActivityRecord{123 u0 com.supernote.document/.TransitionActivity t77}
"""
        self.assertTrue(
            alpha._contains_document_task_or_window(transitioning))

        malformed = empty_activity_with_document_supervisor_ghost().replace(
            b"ActivityStackSupervisor state:\n",
            b" ActivityStackSupervisor state:\n",
            1,
        )
        with self.assertRaises(android.AndroidAuthorityError):
            alpha._contains_document_task_or_window(malformed)

    def test_unowned_candidate_cannot_begin_close_or_remove(self) -> None:
        calls: list[str] = []
        device = SimpleNamespace(
            history=[], remove_exact_task=lambda task: calls.append("remove"),
            send_host=lambda *args, **kwargs: calls.append("close"),
        )
        session = alpha.AlphaSession(device, Path("."))
        session.status = status()
        session.unowned_foreign_candidate = foreign()
        session.attached = True
        with self.assertRaises(alpha.CleanupUncertain):
            session._begin_close()
        session._remove_foreign()
        self.assertEqual(calls, [])


class TaskScopeTests(unittest.TestCase):
    def test_root_task_scope_and_fixture_intent_fd_are_exact(self) -> None:
        raw = activity_wire()
        authority = android.parse_document_task_authority(raw, expected_pid=PID)
        block = alpha.AlphaSession._assert_exact_stack_scope(raw, authority)
        device = SimpleNamespace(
            history=[],
            process_fd_links=lambda pid: (
                "lr-x------ 1 root root 64 0 -> " + alpha.TARGET_PDF + "\n"))
        session = alpha.AlphaSession(device, Path("."))
        session._assert_exact_fixture_binding(block, PID)

    def test_fixture_intent_fields_must_share_one_exact_envelope(self) -> None:
        valid = (
            "      intent={act=android.intent.action.VIEW "
            f"dat={alpha.TARGET_URI} typ=application/pdf "
            "cmp=com.supernote.document/.document.DocumentActivity}"
        )
        alpha.AlphaSession._assert_exact_fixture_intent(valid)
        full = valid.replace(
            "cmp=com.supernote.document/.document.DocumentActivity",
            "cmp=" + alpha.DOCUMENT_COMPONENT,
        )
        alpha.AlphaSession._assert_exact_fixture_intent(full)

        wrapped = (
            "      intent={act=android.intent.action.VIEW\n"
            f"        dat={alpha.TARGET_URI} typ=application/pdf\n"
            "        cmp=com.supernote.document/.document.DocumentActivity}"
        )
        alpha.AlphaSession._assert_exact_fixture_intent(wrapped)
        wrapped_full = wrapped.replace(
            "cmp=com.supernote.document/.document.DocumentActivity",
            "cmp=" + alpha.DOCUMENT_COMPONENT,
        )
        alpha.AlphaSession._assert_exact_fixture_intent(wrapped_full)

        invalid = {
            "split authority": (
                "      intent={act=android.intent.action.VIEW "
                f"dat={alpha.TARGET_URI}}}\n"
                "      typ=application/pdf "
                "cmp=com.supernote.document/.document.DocumentActivity"
            ),
            "second intent": valid + "\n" + valid,
            "borrowed action": valid.replace(
                "act=android.intent.action.VIEW ", "") +
                "\n      act=android.intent.action.VIEW",
            "borrowed uri": valid.replace(
                f"dat={alpha.TARGET_URI} ", "") +
                f"\n      dat={alpha.TARGET_URI}",
            "malformed braces": valid[:-1],
            "nested braces": valid.replace(" typ=", " extra={nested} typ="),
            "space around equals": valid.replace("intent={", "intent ={"),
            "unexpected token": valid.replace(" typ=", " unexpected typ="),
            "uppercase spoof": valid + "\n      Intent={act=spoof}",
            "trailing line token": valid + " trailing",
            "carriage return": valid.replace(" typ=", "\r\n      typ="),
            "overlong whitespace": valid.replace(" typ=", " " * 257 + "typ="),
            "field key split": valid.replace("act=", "act\n        ="),
        }
        for label, task in invalid.items():
            with self.subTest(label=label), self.assertRaises(alpha.AlphaError):
                alpha.AlphaSession._assert_exact_fixture_intent(task)

    def test_retained_task_intent_never_claims_parking_authority(self) -> None:
        parking = (
            "      intent={act=android.intent.action.VIEW "
            f"dat={alpha.PARKING_URI} typ=application/pdf "
            "cmp=com.supernote.document/.document.DocumentActivity}"
        )
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession._assert_exact_fixture_intent(parking)
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession._assert_exact_document_intent(parking, "parking")

    def test_fixture_intent_rejects_missing_wrong_and_duplicate_fields(self) -> None:
        fields = (
            ("act", "android.intent.action.VIEW"),
            ("dat", alpha.TARGET_URI),
            ("typ", "application/pdf"),
            ("cmp", "com.supernote.document/.document.DocumentActivity"),
        )

        def envelope(values: list[tuple[str, str]]) -> str:
            return "      intent={" + " ".join(
                key + "=" + value for key, value in values) + "}"

        for index, (key, value) in enumerate(fields):
            missing = list(fields)
            missing.pop(index)
            with self.subTest(kind="missing", key=key), self.assertRaises(alpha.AlphaError):
                alpha.AlphaSession._assert_exact_fixture_intent(envelope(missing))

            wrong = list(fields)
            wrong[index] = (key, value + ".wrong")
            with self.subTest(kind="wrong", key=key), self.assertRaises(alpha.AlphaError):
                alpha.AlphaSession._assert_exact_fixture_intent(envelope(wrong))

            duplicate = list(fields) + [(key, value)]
            with self.subTest(kind="duplicate", key=key), self.assertRaises(alpha.AlphaError):
                alpha.AlphaSession._assert_exact_fixture_intent(envelope(duplicate))

        duplicate_unknown = list(fields) + [("flg", "0x1"), ("flg", "0x1")]
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession._assert_exact_fixture_intent(
                envelope(duplicate_unknown))

    def test_retained_scope_uses_validated_display_slice_and_hashes_full_wire(
            self) -> None:
        raw = activity_wire() + activity_supervisor_suffix(((3, 1),))
        authority = android.parse_document_task_authority(raw, expected_pid=PID)
        self.assertEqual(authority.raw_sha256, hashlib.sha256(raw).hexdigest())

        with mock.patch.object(
                android, "_display_stack_blocks",
                wraps=android._display_stack_blocks) as display_parser:
            block = alpha.AlphaSession._assert_exact_stack_scope(raw, authority)

        display_parser.assert_called_once()
        parsed_text = display_parser.call_args.args[0]
        self.assertNotIn("ActivityStackSupervisor state:", parsed_text)
        self.assertEqual(
            parsed_text,
            android._reject_malformed_structural_headers(
                android._wire(raw)[0]))
        self.assertIn(alpha.TARGET_URI, block)

    def test_parent_resume_postamble_is_excluded_from_exact_task_scope(self) -> None:
        raw = activity_wire_with_parent_resume_postamble()
        authority = android.parse_document_task_authority(raw, expected_pid=PID)

        block = alpha.AlphaSession._assert_exact_stack_scope(raw, authority)

        self.assertIn(alpha.TARGET_URI, block)
        self.assertNotIn("Resumed activities in task display areas", block)
        self.assertNotIn(alpha.HOST_COMPONENT, block)

    def test_host_records_before_parent_resume_postamble_remain_rejected(self) -> None:
        raw = activity_wire_with_parent_resume_postamble()
        mutations = {
            "stack-owned": raw.replace(
                b"    mResumedActivity:",
                (b"    topActivity=ActivityRecord{773f2a u0 " +
                 alpha.HOST_COMPONENT.encode("ascii") + b" t4649}\n"
                 b"    mResumedActivity:"),
                1,
            ),
            "task-owned": raw.replace(
                b"\n  Resumed activities in task display areas",
                (b"      * Hist #1: ActivityRecord{773f2a u0 " +
                 alpha.HOST_COMPONENT.encode("ascii") + b" t4538}\n"
                 b"\n  Resumed activities in task display areas"),
                1,
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                authority = android.parse_document_task_authority(
                    mutated, expected_pid=PID)
                with self.assertRaises(alpha.AlphaError):
                    alpha.AlphaSession._assert_exact_stack_scope(
                        mutated, authority)

    def test_parent_resume_postamble_mutations_fail_closed(self) -> None:
        raw = activity_wire_with_parent_resume_postamble()
        mutations = {
            "wrong document token": raw.replace(
                b"    Resumed: ActivityRecord{11846f4 ",
                b"    Resumed: ActivityRecord{11846f5 ",
                1,
            ),
            "wrong indentation": raw.replace(
                b"  Resumed activities in task display areas",
                b"    Resumed activities in task display areas",
                1,
            ),
            "arbitrary suffix": raw + b"  arbitrary-parent-record=true\n",
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                authority = android.parse_document_task_authority(
                    mutated, expected_pid=PID)
                with self.assertRaises(alpha.AlphaError):
                    alpha.AlphaSession._assert_exact_stack_scope(
                        mutated, authority)

    def test_root_task_with_second_child_is_rejected_before_remove(self) -> None:
        raw = activity_wire(second_task=True)
        authority = android.parse_document_task_authority(raw, expected_pid=PID)
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession._assert_exact_stack_scope(raw, authority)

    def test_sibling_root_task_on_owned_display_is_rejected(self) -> None:
        raw = activity_wire() + b"""  Stack #7777: type=standard mode=fullscreen
    * Task{7777777 #7777 visible=true type=standard mode=fullscreen A=10001:com.example.other U=0 StackId=7777 sz=1}
      taskId=7777 stackId=7777
      * Hist #0: ActivityRecord{7654321 u0 com.example.other/.OtherActivity t7777}
"""
        authority = android.parse_document_task_authority(raw, expected_pid=PID)
        with self.assertRaises(alpha.AlphaError):
            alpha.AlphaSession._assert_exact_stack_scope(raw, authority)

    def test_wrong_or_additional_pdf_fd_is_rejected(self) -> None:
        raw = activity_wire()
        authority = android.parse_document_task_authority(raw, expected_pid=PID)
        block = alpha.AlphaSession._assert_exact_stack_scope(raw, authority)
        device = SimpleNamespace(
            history=[],
            process_fd_links=lambda pid: (
                "lr-x------ 1 root root 64 0 -> " + alpha.TARGET_PDF + "\n"
                "lr-x------ 1 root root 64 1 -> /storage/emulated/0/Other.pdf\n"))
        session = alpha.AlphaSession(device, Path("."))
        with self.assertRaises(alpha.AlphaError):
            session._assert_exact_fixture_binding(block, PID)

    def test_nonfixture_mark_fd_is_rejected(self) -> None:
        raw = activity_wire()
        authority = android.parse_document_task_authority(raw, expected_pid=PID)
        block = alpha.AlphaSession._assert_exact_stack_scope(raw, authority)
        device = SimpleNamespace(
            history=[],
            process_fd_links=lambda pid: (
                "lr-x------ 1 root root 64 0 -> " + alpha.TARGET_PDF + "\n"
                "lr-x------ 1 root root 64 1 -> /storage/emulated/0/Personal.pdf.mark\n"))
        session = alpha.AlphaSession(device, Path("."))
        with self.assertRaises(alpha.AlphaError):
            session._assert_exact_fixture_binding(block, PID)

    def test_deleted_fixture_fd_is_not_treated_as_the_live_exact_path(self) -> None:
        links = (
            "lr-x------ 1 root root 64 0 -> " + alpha.TARGET_PDF +
            " (deleted)\n")
        self.assertEqual(
            alpha._document_file_targets(links),
            frozenset({alpha.TARGET_PDF + " (deleted)"}))

    def test_owned_display_must_have_no_root_task_after_removal(self) -> None:
        alpha._assert_owned_display_empty(
            b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            b"Display #0 (activities from top to bottom):\n",
            status())
        with self.assertRaises(alpha.AlphaError):
            alpha._assert_owned_display_empty(activity_wire(), status())
        alpha._assert_owned_display_windows_empty(
            b"WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
            b"  mDisplayId=0 rootTaskId=1\n", status())
        with self.assertRaises(alpha.AlphaError):
            alpha._assert_owned_display_windows_empty(
                b"WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
                b"  mDisplayId=3 rootTaskId=4538\n", status())

    def test_empty_inventory_uses_validated_display_slice_with_supervisor_suffix(
            self) -> None:
        raw = (
            b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            b"Display #0 (activities from top to bottom):\n"
            b"Display #3 (activities from top to bottom):\n" +
            activity_supervisor_suffix(((0, 0), (3, 0))))
        with mock.patch.object(
                android, "_display_stack_blocks",
                wraps=android._display_stack_blocks) as display_parser:
            alpha._assert_owned_display_empty(raw, status())

        display_parser.assert_called_once()
        parsed_text = display_parser.call_args.args[0]
        self.assertNotIn("ActivityStackSupervisor state:", parsed_text)
        self.assertEqual(
            parsed_text,
            android._reject_malformed_structural_headers(
                android._wire(raw)[0]))

        malformed = raw.replace(
            b"  Display: mDisplayId=3 stacks=0\n",
            b"  Display: mDisplayId=3 stacks=1\n")
        with self.assertRaises(android.AndroidAuthorityError):
            alpha._assert_owned_display_empty(malformed, status())

    def test_report_can_never_claim_formal_admission(self) -> None:
        session = alpha.AlphaSession(SimpleNamespace(history=[]), Path("."))
        report = session._report()
        self.assertTrue(report["diagnosticOnly"])
        self.assertFalse(report["formalAdmission"])
        self.assertFalse(report["manualPhysicalRotation"])
        self.assertFalse(report["packageRollbackSafe"])
        self.assertEqual(report["result"], "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN")
        self.assertIsNone(report["fixture"]["sourceWasModified"])
        self.assertIsNone(report["parking"]["wasModified"])

    def test_early_cleanup_failure_keeps_source_and_parking_report_unknown(
            self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        device.state[alpha.SOURCE_PDF] = device_file(
            alpha.SOURCE_PDF, "f" * 64, 909)
        quarantine = session.fixture_obligations[
            alpha.TARGET_MARK].quarantine_path
        device.state[quarantine] = device_file(quarantine, "e" * 64, 910)
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        report = session._report()
        self.assertIsNone(report["fixture"]["sourceWasModified"])
        self.assertIsNone(report["parking"]["wasModified"])

    def test_final_revalidation_reports_observed_source_change_separately(self) -> None:
        device = FixtureDevice()
        session = cleanup_ready_fixture_session(device)
        session._stage_fixture()
        device.state[alpha.SOURCE_PDF] = device_file(
            alpha.SOURCE_PDF, "f" * 64, 911)
        with self.assertRaises(alpha.CleanupUncertain):
            session._remove_fixture()
        report = session._report()
        self.assertTrue(report["fixture"]["sourceWasModified"])
        self.assertFalse(report["parking"]["wasModified"])

    def test_clean_result_is_partitioned_by_rotation_authority(self) -> None:
        def captured_report(rotation_authority: str) -> dict[str, object]:
            controller_id = (
                CONTROLLER_ID if
                rotation_authority == alpha.ROTATION_ADB_SYSTEM_SETTINGS else
                None)
            session = alpha.AlphaSession(
                SimpleNamespace(history=[]), Path("."),
                rotation_authority=rotation_authority,
                rotation_controller_run_id=controller_id)
            session.cleanup.update({
                key: True for key in session.cleanup
            })
            session.foreign = foreign()
            session.foreign_fixture_bound = True
            session.source_fixture_unchanged = True
            session.parking_fixture_unchanged = True
            session.starting_orientation = 1
            session.portrait_orientation = 0
            session.returned_orientation = 1
            session.screenshots = [
                alpha.Screenshot(name, 1, 1, 1, "a" * 64)
                for name in (
                    "full", "left", "right", "full_return", "portrait",
                    "landscape_return",
                )
            ]
            if rotation_authority == alpha.ROTATION_ADB_SYSTEM_SETTINGS:
                session.rotation_controller_phases = list(
                    alpha.ROTATION_CONTROLLER_PHASES)
            return session._report()

        manual = captured_report(alpha.ROTATION_MANUAL_PHYSICAL)
        self.assertEqual(manual["rotationAuthority"],
                         alpha.ROTATION_MANUAL_PHYSICAL)
        self.assertTrue(manual["manualPhysicalRotation"])
        self.assertFalse(manual["formalAdmission"])
        self.assertEqual(manual["result"], "ALPHA_VISUAL_CAPTURED_CLEAN")
        self.assertIsNone(manual["rotationController"])

        automated = captured_report(alpha.ROTATION_ADB_SYSTEM_SETTINGS)
        self.assertEqual(automated["rotationAuthority"],
                         alpha.ROTATION_ADB_SYSTEM_SETTINGS)
        self.assertFalse(automated["manualPhysicalRotation"])
        self.assertFalse(automated["formalAdmission"])
        self.assertEqual(
            automated["result"], "ALPHA_ADB_ROTATION_CAPTURED_CLEAN")
        self.assertEqual(automated["rotationController"], {
            "authority": alpha.ROTATION_CONTROLLER_PHASE_AUTHORITY,
            "runId": CONTROLLER_ID,
            "phases": list(alpha.ROTATION_CONTROLLER_PHASES),
        })
        self.assertNotEqual(automated["result"],
                            "ALPHA_VISUAL_CAPTURED_CLEAN")

    def test_no_start_cleanup_requires_two_fresh_host_absence_observations(self) -> None:
        calls = {"activities": 0, "windows": 0, "displays": 0, "pidof": 0}

        def empty(name: str) -> bytes:
            calls[name] += 1
            return b"empty\n"

        device = SimpleNamespace(
            history=[], activities=lambda: empty("activities"),
            windows=lambda: empty("windows"),
            displays=lambda: empty("displays"),
            pidof=lambda package: (
                calls.__setitem__("pidof", calls["pidof"] + 1) or ()),
        )
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session._cleanup()
        self.assertTrue(session.cleanup["displayAbsent"])
        self.assertTrue(session.cleanup["hostTaskAbsent"])
        self.assertTrue(session.cleanup["fixtureRemoved"])
        self.assertEqual(set(calls.values()), {2})
        report = session._report()
        self.assertTrue(report["packageRollbackSafe"])
        self.assertEqual(report["result"], "ALPHA_DIAGNOSTIC_FAILED_CLEAN")

    def test_observed_unretained_host_prevents_clean_rollback_claim(self) -> None:
        device = SimpleNamespace(
            history=[],
            activities=lambda: alpha.HOST_COMPONENT.encode("ascii"),
            windows=lambda: b"empty\n", displays=lambda: b"empty\n",
            pidof=lambda package: (),
        )
        session = alpha.AlphaSession(device, Path("."), sleep=lambda _: None)
        session._cleanup()
        report = session._report()
        self.assertFalse(report["packageRollbackSafe"])
        self.assertEqual(report["result"], "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN")

    def test_wrong_fixture_candidate_never_becomes_removal_authority(self) -> None:
        process = host.ProcessIdentity(PID, 123456, 1000, alpha.DOCUMENT_PACKAGE)
        parking = device_file(
            alpha.PARKING_PDF, alpha.SOURCE_PDF_SHA256, 13)

        def stat_file(path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None:
            if path == alpha.PARKING_PDF:
                return parking
            if path == alpha.PARKING_MARK and absent_ok:
                return None
            raise AssertionError(path)

        device = SimpleNamespace(
            history=[], pidof=lambda package: (PID,),
            process_identity=lambda pid, package: process,
            activities=lambda: activity_wire(),
            stat_file=stat_file,
            process_fd_links=lambda pid: (
                "lr-x------ 1 root root 64 0 -> /storage/emulated/0/Personal.pdf\n"),
        )
        session = alpha.AlphaSession(device, Path("."))
        session.status = status()
        session.parking_file = parking
        with self.assertRaises(alpha.AlphaError):
            session._capture_foreign()
        self.assertIsNone(session.foreign)
        self.assertIsNotNone(session.unowned_foreign_candidate)
        self.assertEqual(session.unowned_foreign_candidate.task_id, 4538)
        self.assertFalse(session.foreign_fixture_bound)
        self.assertFalse(session.launch_owned)


if __name__ == "__main__":
    unittest.main()
