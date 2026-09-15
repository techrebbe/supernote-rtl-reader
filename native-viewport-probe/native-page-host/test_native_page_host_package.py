#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import base64
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

import canonicalize_apk as canonical
import inspect_native_page_host as inspect_host


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MANIFEST = HERE / "AndroidManifest.xml"
ACTIVITY = HERE / "src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java"
LIFECYCLE = ROOT / "java/com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.java"
LAYOUT = ROOT / "java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java"
BUILD_SCRIPT = ROOT / "build-native-page-host.ps1"
WINDOWS_POWERSHELL_51_SHA256 = (
    "8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e")
POWERSHELL_7_SHA256 = (
    "362a356ce7f0940ec74f73a8fc2c990a2cc24a38a11c90bbd8eca947110ad139")


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_low", ctypes.c_uint32), ("creation_high", ctypes.c_uint32),
        ("access_low", ctypes.c_uint32), ("access_high", ctypes.c_uint32),
        ("write_low", ctypes.c_uint32), ("write_high", ctypes.c_uint32),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32), ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32), ("file_index_low", ctypes.c_uint32),
    ]


def _win32_kernel():
    if os.name != "nt":
        raise unittest.SkipTest("Windows retained executable authority")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation)]
    kernel.GetFileInformationByHandle.restype = ctypes.c_int
    kernel.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                                 ctypes.c_uint32, ctypes.c_uint32]
    kernel.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    kernel.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_longlong,
                                       ctypes.POINTER(ctypes.c_longlong), ctypes.c_uint32]
    kernel.SetFilePointerEx.restype = ctypes.c_int
    kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    kernel.ReadFile.restype = ctypes.c_int
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                                  ctypes.c_wchar_p,
                                                  ctypes.POINTER(ctypes.c_uint32)]
    kernel.QueryFullProcessImageNameW.restype = ctypes.c_int
    return kernel


def _normal_windows_path(value: Path | str) -> str:
    path = os.path.normcase(os.path.abspath(os.fspath(value)))
    return path[4:] if path.startswith("\\\\?\\") else path


def _reject_reparse_chain(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    drive, tail = os.path.splitdrive(str(absolute))
    if not drive or ":" in tail:
        raise AssertionError("authority path is relative or contains an ADS")
    current = Path(drive + os.sep)
    for part in absolute.parts[1:]:
        current /= part
        if (current.lstat().st_file_attributes & 0x400
                or current.is_symlink()) or _normal_windows_path(current) != _normal_windows_path(
                os.path.realpath(current)):
            raise AssertionError("authority path traverses a reparse point")


class _RetainedWindowsFile:
    """Child read authority nested inside the build's retained no-write handle."""

    def __init__(self, path: Path, expected_sha256: str | None, label: str):
        self.path = Path(path)
        self.expected_sha256 = expected_sha256
        self.label = label
        self.kernel = _win32_kernel()
        self.handle = None
        self.payload = b""
        self.identity = None

    def __enter__(self):
        if not self.path.is_absolute():
            raise AssertionError(f"{self.label} path is not absolute")
        _reject_reparse_chain(self.path)
        before = self.path.lstat()
        if not self.path.is_file() or before.st_nlink != 1:
            raise AssertionError(f"{self.label} is not an ordinary single-link file")
        invalid = ctypes.c_void_p(-1).value
        # The parent build retains snapshots with read/write access and
        # FILE_SHARE_READ. This nested reader must share that already-open write
        # access, while the parent's handle still denies every new writer/deleter.
        self.handle = self.kernel.CreateFileW(
            str(self.path), 0x80000000, 0x00000001 | 0x00000002, None, 3,
            0x00000080 | 0x00200000, None)
        if self.handle == invalid:
            raise AssertionError(f"{self.label} could not be retained")
        try:
            self.payload, self.identity, final_path = self._read_authority()
            if _normal_windows_path(final_path) != _normal_windows_path(self.path):
                raise AssertionError(f"{self.label} final path changed")
            digest = hashlib.sha256(self.payload).hexdigest()
            if self.expected_sha256 is not None and digest != self.expected_sha256:
                raise AssertionError(f"{self.label} fixed digest changed: {digest}")
            self.digest = digest
            self.require_mutation_denied()
            return self
        except BaseException:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
            raise

    def _read_authority(self):
        info = _ByHandleFileInformation()
        if not self.kernel.GetFileInformationByHandle(self.handle, ctypes.byref(info)):
            raise AssertionError(f"{self.label} identity query failed")
        if info.links != 1 or info.attributes & 0x400:
            raise AssertionError(f"{self.label} is linked or reparsed")
        size = (info.size_high << 32) | info.size_low
        if size <= 0 or size > 8 * 1024 * 1024:
            raise AssertionError(f"{self.label} size is outside authority")
        if not self.kernel.SetFilePointerEx(self.handle, 0, None, 0):
            raise AssertionError(f"{self.label} seek failed")
        chunks = []
        remaining = size
        while remaining:
            amount = min(remaining, 1024 * 1024)
            buffer = ctypes.create_string_buffer(amount)
            read = ctypes.c_uint32()
            if not self.kernel.ReadFile(self.handle, buffer, amount,
                                        ctypes.byref(read), None) or read.value == 0:
                raise AssertionError(f"{self.label} descriptor read failed")
            chunks.append(buffer.raw[:read.value])
            remaining -= read.value
        capacity = 32768
        final_buffer = ctypes.create_unicode_buffer(capacity)
        final_size = self.kernel.GetFinalPathNameByHandleW(
            self.handle, final_buffer, capacity, 0)
        if final_size == 0 or final_size >= capacity:
            raise AssertionError(f"{self.label} final-path query failed")
        identity = (info.volume_serial, info.file_index_high, info.file_index_low,
                    info.size_high, info.size_low, info.write_high, info.write_low)
        return b"".join(chunks), identity, final_buffer.value

    def require_mutation_denied(self):
        invalid = ctypes.c_void_p(-1).value
        for access, name in ((0x40000000, "write"), (0x00010000, "delete")):
            probe = self.kernel.CreateFileW(str(self.path), access,
                                            0x1 | 0x2 | 0x4, None, 3, 0x80, None)
            if probe != invalid:
                self.kernel.CloseHandle(probe)
                raise AssertionError(f"{self.label} retained authority permits {name}")
            if ctypes.get_last_error() != 32:
                raise AssertionError(f"{self.label} {name} denial was not sharing authority")

    def verify(self):
        payload, identity, final_path = self._read_authority()
        if (identity != self.identity or payload != self.payload
                or _normal_windows_path(final_path) != _normal_windows_path(self.path)
                or self.path.lstat().st_nlink != 1):
            raise AssertionError(f"{self.label} retained authority changed")
        self.require_mutation_denied()

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                self.verify()
        finally:
            if self.handle is not None:
                self.kernel.CloseHandle(self.handle)
                self.handle = None


def _powershell_authority_records():
    authority = getattr(sys, "_native_page_host_powershell_authority", None)
    if authority is None:
        raise unittest.SkipTest("requires the reviewed build bootstrap")
    if not isinstance(authority, tuple) or len(authority) != 4:
        raise AssertionError("PowerShell authority record topology changed")
    ps5_path, ps5_digest, ps7_path, ps7_digest = authority
    ps5_exact_path = ROOT / "powershell-engines/windows-powershell-5.1/powershell.exe"
    if (ps5_digest != WINDOWS_POWERSHELL_51_SHA256
            or ps7_digest != POWERSHELL_7_SHA256
            or _normal_windows_path(ps5_path) != _normal_windows_path(ps5_exact_path)
            or not Path(ps7_path).is_absolute()
            or _normal_windows_path(ps7_path) == _normal_windows_path(ps5_path)):
        raise AssertionError("PowerShell role/path/digest authority changed")
    return ((Path(ps5_path), ps5_digest, "Windows PowerShell 5.1"),
            (Path(ps7_path), ps7_digest, "PowerShell 7"))


@contextmanager
def _retained_cross_engine_authority():
    records = _powershell_authority_records()
    with ExitStack() as stack:
        engines = [stack.enter_context(_RetainedWindowsFile(*record))
                   for record in records]
        if engines[0].identity == engines[1].identity:
            raise AssertionError("PowerShell roles share one file identity")
        policy = stack.enter_context(_RetainedWindowsFile(
            BUILD_SCRIPT, None, "exact-head build policy"))
        yield engines, policy


def _clean_powershell_environment(extra=None):
    environment = os.environ.copy()
    prefixes = ("DOTNET_", "COREHOST_", "CORECLR_", "COMPLUS_", "COR_", "PYTHON")
    exact = {"PSMODULEPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
             "JDK_JAVAC_OPTIONS", "JAVA_OPTIONS", "CLASSPATH"}
    for name in list(environment):
        upper = name.upper()
        if upper in exact or any(upper.startswith(prefix) for prefix in prefixes):
            environment.pop(name)
    if extra:
        environment.update(extra)
    return _sanitize_powershell_startup_environment(environment)


def _sanitize_powershell_startup_environment(environment):
    # The launcher is pinned; the system CLR/GAC and private pwsh CoreCLR
    # closure are platform-trusted, not claimed to be individually authenticated.
    # Do not let caller-selected runtime/profiler/module startup paths widen that
    # trust. Keep explicit JVM/Python negative-test inputs for the policy to reject.
    result = environment.copy()
    prefixes = ("DOTNET_", "COREHOST_", "CORECLR_", "COMPLUS_", "COR_",
                "POWERSHELL_", "PS", "__PS")
    exact = {"APPDOMAIN_MANAGER_ASM", "APPDOMAIN_MANAGER_TYPE", "DEVPATH"}
    for name in list(result):
        if name.upper() in exact or any(name.upper().startswith(prefix) for prefix in prefixes):
            result.pop(name)
    return result


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_retained_policy(engine: _RetainedWindowsFile,
                         policy: _RetainedWindowsFile, output: Path, *,
                         environment=None, during_child=None):
    engine.verify()
    policy.verify()
    _reject_reparse_chain(output.parent)
    if engine.label == "Windows PowerShell 5.1":
        role_check = (b"$PSVersionTable.PSVersion.Major -ne 5 -or "
                      b"$PSVersionTable.PSVersion.Minor -ne 1 -or "
                      b"$PSVersionTable.PSEdition -cne 'Desktop'")
    elif engine.label == "PowerShell 7":
        role_check = (b"$PSVersionTable.PSVersion.Major -ne 7 -or "
                      b"$PSVersionTable.PSEdition -cne 'Core'")
    else:
        raise AssertionError("unknown PowerShell execution role")
    invocation = (b"try {\nif (" + role_check
                  + b") { throw 'PowerShell loaded runtime role changed' }\n& {\n" + policy.payload
                  + b"\n} -Jdk 'unused' -AndroidSdk 'unused' -Python "
                  + _quote_powershell(sys.executable).encode("utf-8")
                  + b" -CanonicalTextPolicySelfTestOutput "
                  + _quote_powershell(str(output)).encode("utf-8")
                  + b"\nif (-not $?) { exit 1 }\n"
                  + b"} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n")
    if during_child is not None:
        invocation = b"Start-Sleep -Milliseconds 250\n" + invocation
    # -Command - is line-oriented and can silently drop an unterminated
    # multiline construct at EOF. Read the exact UTF-8 stdin payload to EOF and
    # compile it once instead. This fixed driver is itself in the pinned helper.
    # It waits for the parent to verify the child image before policy is sent.
    driver = ("$ErrorActionPreference='Stop'; "
              "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false,$true); "
              "try { & ([ScriptBlock]::Create([Console]::In.ReadToEnd())) } "
              "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
    command = [str(engine.path), "-NoProfile", "-NonInteractive", "-NoLogo",
               "-ExecutionPolicy", "Bypass", "-Command", driver]
    process = subprocess.Popen(command, shell=False, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=_sanitize_powershell_startup_environment(
                                   environment or _clean_powershell_environment()),
                               cwd=output.parent,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        capacity = ctypes.c_uint32(32768)
        image = ctypes.create_unicode_buffer(capacity.value)
        if not engine.kernel.QueryFullProcessImageNameW(
                ctypes.c_void_p(process._handle), 0, image, ctypes.byref(capacity)):
            raise AssertionError("PowerShell child image query failed")
        if _normal_windows_path(image.value) != _normal_windows_path(engine.path):
            raise AssertionError("PowerShell child image escaped admitted launcher")
        if during_child is not None:
            during_child()
        stdout, stderr = process.communicate(invocation, timeout=30)
    except BaseException:
        process.kill()
        process.communicate()
        raise
    if len(stdout) > 1024 * 1024 or len(stderr) > 1024 * 1024:
        raise AssertionError("PowerShell policy output exceeded bound")
    engine.verify()
    policy.verify()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def archive_bytes(entries, *, reverse=False, year=2024):
    output = io.BytesIO()
    sequence = list(entries)
    if reverse:
        sequence.reverse()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in sequence:
            info = zipfile.ZipInfo(name, (year, 2, 3, 4, 5, 6))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(info, payload)
    return output.getvalue()


def xmltree_fixture() -> str:
    return '''N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=2)
    A: android:versionCode(0x0101021b)=(type 0x10)0x2
    A: android:versionName(0x0101021c)="0.0.2-native-page-visual-only"
    A: android:compileSdkVersion(0x01010572)=(type 0x10)0x23
    A: android:compileSdkVersionCodename(0x01010573)="15"
    A: package="com.techrebbe.supernote.nativepagehost"
    A: platformBuildVersionCode=(type 0x10)0x23
    A: platformBuildVersionName=(type 0x10)0xf
    E: uses-sdk (line=5)
      A: android:minSdkVersion(0x0101020c)=(type 0x10)0x1e
      A: android:targetSdkVersion(0x01010270)=(type 0x10)0x1e
    E: application (line=7)
      A: android:theme(0x01010000)=@0x01030241
      A: android:label(0x01010001)="Native Page Host - Visual Only"
      A: android:allowBackup(0x01010280)=(type 0x12)0x0
      A: android:supportsRtl(0x010103af)=(type 0x12)0x0
      A: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0x0
      E: activity (line=10)
        A: android:name(0x01010003)=".NativePageHostActivity"
        A: android:exported(0x01010010)=(type 0x12)0xffffffff
        A: android:launchMode(0x0101001d)=(type 0x10)0x2
        A: android:configChanges(0x0101001f)=(type 0x11)0x1d80
        A: android:resizeableActivity(0x010104f6)=(type 0x12)0xffffffff
        E: intent-filter (line=13)
          E: action (line=14)
            A: android:name(0x01010003)="android.intent.action.MAIN"
          E: category (line=15)
            A: android:name(0x01010003)="android.intent.category.LAUNCHER"
'''


def bytecode_fixture() -> bytes:
    return b'''public final class X {
  public void onCreate(android.os.Bundle);
    Code:
       0: sipush        1404
       3: sipush        1872
       6: invokeinterface #1 // InterfaceMethod android/view/SurfaceHolder.setFixedSize:(II)V
       9: invokevirtual #2 // Method finishAndRemoveTask:()V

  public boolean dispatchTouchEvent(android.view.MotionEvent);
    Code:
       0: invokevirtual #3 // Method android/view/MotionEvent.getToolType:(I)I
       3: iconst_2
       4: if_icmpeq 10
       7: iconst_4
       8: if_icmpne 12
      10: ldc #4 // String STYLUS_SWALLOWED
      13: iconst_1
      14: ireturn

  protected void onNewIntent(android.content.Intent);
    Code:
       0: invokevirtual #4 // Method decodeCommandEnvelope:(Landroid/content/Intent;Ljava/lang/String;)Lcom/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope;
       3: astore_3
       4: invokevirtual #5 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.commandEnvelopeMatches:(Ljava/lang/String;JIJ)Z
       7: ifne          20
      10: ldc #6 // String reason=unauthenticated_or_stale action=
      13: invokevirtual #7 // Method log:(Ljava/lang/String;Ljava/lang/String;)V
      16: return
      20: ldc #8 // String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT
      23: aload_2
      24: invokevirtual #9 // Method java/lang/String.equals:(Ljava/lang/Object;)Z
      27: ifeq          40
      30: aload_0
      31: aload_3
      32: aconst_null
      33: invokespecial #10 // Method processAuthenticatedCommand:(Lcom/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope;Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;)V
      36: return
      40: invokestatic #11 // Method isCleanupCommand:(Ljava/lang/String;)Z
      43: invokevirtual #12 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.hostAuthoritySuspended:()Z
      46: invokevirtual #13 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.canDeferFreshCommand:(J)Z
      49: invokevirtual #14 // Method parseForeignIdentity:(Landroid/os/Bundle;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;
      52: invokevirtual #15 // Method deferAuthenticatedCommand:(Lcom/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope;ILcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;)V
      55: invokevirtual #16 // Method verifyRuntimeAuthorityOrFail:(Ljava/lang/String;)Z
      58: invokespecial #10 // Method processAuthenticatedCommand:(Lcom/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope;Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;)V
      61: return

  private void processAuthenticatedCommand(com.techrebbe.supernote.nativepagehost.NativePageHostActivity$CommandEnvelope, com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle$ForeignTaskIdentity);
    Code:
       0: invokevirtual #20 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.acknowledgeForeignAttached:(Ljava/lang/String;JIJLcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
       3: invokevirtual #21 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.canPublishFreshAttachReady:()Z
       6: invokevirtual #22 // Method cancelAttachTimeout:()V
       9: ldc #23 // String ATTACH_REPLAY
      12: ldc #24 // String PLACEMENT_REPLAY
      15: invokevirtual #25 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.authorizePlacement:(Ljava/lang/String;JIJLcom/techrebbe/supernote/viewportprobe/DisplayProbeLayout$Placement;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      18: invokevirtual #26 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.beginClose:(Ljava/lang/String;JIJ)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      21: invokevirtual #27 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.canPublishFreshCloseWait:()Z
      24: invokevirtual #28 // Method armDestroyTimeout:()V
      27: ldc #29 // String WAIT_FOREIGN_DESTROY
      30: ldc #30 // String CLOSE_REPLAY
      33: invokevirtual #31 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.acknowledgeForeignDestroyed:(Ljava/lang/String;JIJLcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      36: ldc #32 // String DESTROY_REPLAY
      39: ldc #33 // String EMPTY_ABORT_REPLAY
      42: ldc #34 // String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT
      45: aload_3
      46: invokevirtual #35 // Method java/lang/String.equals:(Ljava/lang/Object;)Z
      49: ifeq          150
      52: aload_1
      53: getfield #36 // Field com/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope.extras:Landroid/os/Bundle;
      56: ldc #37 // String absenceEvidenceSha256
      59: invokestatic #38 // Method exactString:(Landroid/os/Bundle;Ljava/lang/String;)Ljava/lang/String;
      62: astore        4
      64: invokevirtual #39 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.acknowledgeNoForeignPreAttachAbort:(Ljava/lang/String;JIJLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      67: astore        5
      69: aload         5
      71: getstatic #40 // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult.ACCEPTED:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      74: if_acmpne     100
      77: ldc #41 // String EMPTY_PRE_ATTACH_ABORT
      80: aload_0
      81: invokevirtual #42 // Method releaseNormally:()Z
      84: ifeq          91
      87: aload_0
      88: invokevirtual #43 // Method finishAndRemoveTask:()V
      91: return
     100: aload         5
     102: getstatic #44 // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult.IDEMPOTENT:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
     105: if_acmpne     140
     108: ldc #45 // String EMPTY_PRE_ATTACH_ABORT_REPLAY
     111: aload_0
     112: invokevirtual #46 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.displayRemoved:()Z
     115: ifne          135
     118: aload_0
     119: invokevirtual #42 // Method releaseNormally:()Z
     122: ifeq          135
     125: aload_0
     126: invokevirtual #43 // Method finishAndRemoveTask:()V
     135: return
     140: aload_0
     141: invokevirtual #47 // Method rejectAlreadyFailed:(Ljava/lang/String;)V
     144: return
     150: ldc #48 // String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_AFTER_FAILURE
     153: invokevirtual #49 // Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.acknowledgeNoForeignAfterFailure:(Ljava/lang/String;JIJLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
     156: return

  private static int deferredCommandKind(java.lang.String);
    Code:
       0: ldc #20 // String com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_ATTACHED
       3: iconst_1
       4: ireturn
       5: ldc #20 // String com.techrebbe.supernote.nativepagehost.PLACE_FULL
       8: iconst_2
       9: ireturn
      10: ldc #20 // String com.techrebbe.supernote.nativepagehost.PLACE_LEFT
      13: iconst_3
      14: ireturn
      15: ldc #20 // String com.techrebbe.supernote.nativepagehost.PLACE_RIGHT
      18: iconst_4
      19: ireturn
      20: ldc #20 // String com.techrebbe.supernote.nativepagehost.BEGIN_CLOSE
      23: iconst_5
      24: ireturn
      25: ldc #20 // String com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_DESTROYED
      28: bipush        6
      30: ireturn
      31: iconst_0
      32: ireturn

  private static boolean isKnownCommand(java.lang.String);
    Code:
       0: ldc #21 // String com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_ATTACHED
       3: ldc #22 // String com.techrebbe.supernote.nativepagehost.PLACE_FULL
       6: ldc #23 // String com.techrebbe.supernote.nativepagehost.PLACE_LEFT
       9: ldc #24 // String com.techrebbe.supernote.nativepagehost.PLACE_RIGHT
      12: ldc #25 // String com.techrebbe.supernote.nativepagehost.BEGIN_CLOSE
      15: ldc #26 // String com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_DESTROYED
      18: ldc #27 // String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_AFTER_FAILURE
      21: ldc #28 // String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT
      24: iconst_1
      25: ireturn

  private static boolean isCleanupCommand(java.lang.String);
    Code:
       0: ldc #25 // String com.techrebbe.supernote.nativepagehost.BEGIN_CLOSE
       3: ldc #26 // String com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_DESTROYED
       6: ldc #27 // String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_AFTER_FAILURE
       9: iconst_1
      10: ireturn

  private X decodeCommandEnvelope(android.content.Intent, java.lang.String);
    Code:
       0: invokevirtual #12 // Method android/content/Intent.getExtras
       3: instanceof #13 // class java/lang/String
       6: instanceof #14 // class java/lang/Long
       9: instanceof #15 // class java/lang/Integer
      12: ldc #16 // class java/lang/RuntimeException

  public void onConfigurationChanged(android.content.res.Configuration);
    Code:
       0: invokevirtual #12 // Method onConfigurationDensity
       3: invokevirtual #13 // Method releaseForUnexpectedLoss

  private void maybeCreateVirtualDisplay();
    Code:
       0: sipush        1404
       3: sipush        1872
       6: sipush        265
       9: invokevirtual #14 // Method verifyPreAllocationHostAuthorityOrFail
      12: invokevirtual #14 // Method verifyPhysicalFrameOrFail
      15: invokevirtual #14 // Method beginDisplayCreation
      18: invokevirtual #14 // Method android/hardware/display/DisplayManager.createVirtualDisplay
      21: invokevirtual #15 // Method android/hardware/display/VirtualDisplay.getDisplay
      24: invokevirtual #15 // Method android/view/Display.getDisplayId
      27: invokevirtual #16 // Method onDisplayAllocated
      30: invokevirtual #16 // Method virtualDisplayMetrics
      33: invokevirtual #17 // Method onDisplayCreated

  private android.util.DisplayMetrics virtualDisplayMetrics();
    Code:
       0: invokevirtual #18 // Method android/hardware/display/VirtualDisplay.getDisplay
       3: invokevirtual #19 // Method android/view/Display.getRealMetrics

  private boolean verifyRuntimeAuthorityOrFail(java.lang.String);
    Code:
       0: invokevirtual #20 // Method verifyHostAuthorityOrFail
       3: invokevirtual #20 // Method verifyPhysicalFrameOrFail
       6: invokevirtual #20 // Method virtualDisplayMetrics
       9: invokevirtual #20 // Method onVirtualDisplayMetrics
      12: invokevirtual #21 // Method releaseForUnexpectedLoss

  private boolean verifyPhysicalFrameOrFail(java.lang.String);
    Code:
       0: invokevirtual #20 // Method android/view/View.getLocationOnScreen
       3: invokevirtual #20 // Method pendingPlacementSequence
       6: invokevirtual #20 // Method onPhysicalFrameMeasured
       9: invokevirtual #21 // Method releaseForUnexpectedLoss

  private boolean verifyHostAuthorityOrFail(java.lang.String);
    Code:
       0: invokevirtual #20 // Method physicalDisplayId
       3: invokevirtual #20 // Method physicalDensityDpi
       6: invokevirtual #20 // Method hostVisible
       9: invokevirtual #20 // Method hasWindowFocus
      12: invokevirtual #20 // Method onHostAuthority
      15: invokevirtual #21 // Method releaseForUnexpectedLoss

  private boolean verifyPreAllocationHostAuthorityOrFail(java.lang.String);
    Code:
       0: invokevirtual #20 // Method physicalDisplayId
       3: invokevirtual #20 // Method physicalDensityDpi
       6: invokevirtual #20 // Method hostVisible
       9: invokevirtual #20 // Method hasWindowFocus
      12: invokevirtual #20 // Method revalidatePreAllocationHostAuthority
      15: invokevirtual #21 // Method rejectAlreadyFailed

  private boolean hostVisible();
    Code:
       0: invokevirtual #20 // Method android/view/Window.getDecorView
       3: invokevirtual #20 // Method android/view/View.getWindowVisibility
       6: invokevirtual #20 // Method android/view/View.isShown
       9: invokevirtual #20 // Method android/app/Activity.isFinishing

  private void beginBoundedHostAuthoritySuspension(java.lang.String);
    Code:
       0: invokevirtual #20 // Method suspendHostAuthority
       3: invokestatic  #20 // Method android/os/SystemClock.elapsedRealtime
       6: ldc #20 // String HOST_AUTHORITY_SUSPENDED
       9: invokevirtual #20 // Method android/os/Handler.postDelayed

  private void deferAuthenticatedCommand(com.techrebbe.supernote.nativepagehost.NativePageHostActivity$CommandEnvelope, int, com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle$ForeignTaskIdentity);
    Code:
       0: invokestatic  #20 // Method android/os/SystemClock.elapsedRealtime
       3: invokevirtual #20 // Method physicalDisplayAuthorityStableWhilePaused
       6: invokevirtual #20 // Method reserveDeferredCommand
       9: ldc #20 // String COMMAND_DEFERRED
      12: invokevirtual #20 // Method releaseForUnexpectedLoss

  private void drainDeferredCommandIfReady();
    Code:
       0: invokevirtual #20 // Method verifyRuntimeAuthorityOrFail
       3: invokevirtual #20 // Method consumeDeferredCommand
       6: ldc #20 // String COMMAND_RESUMED
       9: invokevirtual #20 // Method processAuthenticatedCommand

  private boolean releaseNormally();
    Code:
       0: invokevirtual #20 // Method android/hardware/display/VirtualDisplay.release
       3: ldc #21 // class java/lang/RuntimeException
       6: invokevirtual #20 // Method onReleaseAttemptFailed
       7: invokevirtual #20 // Method retainedDisplayCleanupAddressable
       8: invokevirtual #20 // Method escalateOwnProcessCleanup
       9: iconst_0
      10: invokevirtual #20 // Method markReleased

  private boolean releaseForUnexpectedLoss(java.lang.String);
    Code:
       0: invokevirtual #20 // Method android/hardware/display/VirtualDisplay.release
       3: ldc #21 // class java/lang/RuntimeException
       6: invokevirtual #20 // Method onReleaseAttemptFailed
       7: invokevirtual #20 // Method retainedDisplayCleanupAddressable
       8: invokevirtual #20 // Method escalateOwnProcessCleanup
       9: iconst_1
      10: invokevirtual #20 // Method markReleased

  public void onBackPressed();
    Code:
       0: invokevirtual #22 // Method canFinishWithoutCleanup
       3: invokevirtual #23 // Method finishAndRemoveTask

  protected void onDestroy();
    Code:
       0: invokevirtual #23 // Method releaseForUnexpectedLoss
       3: invokevirtual #23 // Method escalateOwnProcessCleanup

  private void escalateOwnProcessCleanup(java.lang.String);
    Code:
       0: ldc #23 // String PROCESS_CLEANUP_ESCALATED
       3: invokestatic #23 // Method android/os/Process.myPid
       6: invokestatic #23 // Method android/os/Process.killProcess
}
'''


def layout_bytecode_fixture() -> bytes:
    return b'''public final class com.techrebbe.supernote.viewportprobe.DisplayProbeLayout {
  public boolean exactlyMatches(int, int, int, int);
    Code:
       0: aload_0
       1: getfield      #1 // Field left:I
       4: getfield      #2 // Field top:I
       7: getfield      #3 // Field width:I
      10: getfield      #4 // Field height:I

  public static com.techrebbe.supernote.viewportprobe.DisplayProbeLayout fit(int, int, com.techrebbe.supernote.viewportprobe.DisplayProbeLayout$Placement);
    Code:
       0: sipush        8192
       3: iconst_3
       4: idiv
       5: iconst_4
       6: idiv
       7: getstatic     #5 // Field Placement.FULL
      10: getstatic     #6 // Field Placement.LEFT
      13: getstatic     #7 // Field Placement.RIGHT
}
'''


def lifecycle_bytecode_fixture() -> bytes:
    return b'''public final class com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle {
  public com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle$CommandResult acknowledgeNoForeignPreAttachAbort(java.lang.String, long, int, long, java.lang.String);
    Code:
       0: aload_0
       1: aload_1
       2: lload_2
       3: iload         4
       5: invokespecial #178                // Method authorize:(Ljava/lang/String;JI)Z
       8: ifne          16
      11: aload_0
      12: invokespecial #257                // Method stale:()Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      15: areturn
      16: new           #212                // class java/lang/StringBuilder
      19: dup
      20: invokespecial #214                // Method java/lang/StringBuilder."<init>":()V
      23: ldc_w         #344                // String PRE_ATTACH_ABORT|
      26: invokevirtual #217                // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
      29: aload         7
      31: invokestatic  #346                // Method java/lang/String.valueOf:(Ljava/lang/Object;)Ljava/lang/String;
      34: invokevirtual #217                // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
      37: invokevirtual #225                // Method java/lang/StringBuilder.toString:()Ljava/lang/String;
      40: astore        8
      42: aload_0
      43: lload         5
      45: aload         8
      47: invokespecial #263                // Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      50: astore        9
      52: aload         9
      54: ifnull        60
      57: aload         9
      59: areturn
      60: aload_0
      61: getfield      #77                 // Field failure:Ljava/lang/String;
      64: ifnonnull     126
      67: aload_0
      68: getfield      #122                // Field foreignTask:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;
      71: ifnonnull     126
      74: aload_0
      75: getfield      #165                // Field deferredCommandKey:Ljava/lang/String;
      78: ifnonnull     126
      81: aload_0
      82: getfield      #72                 // Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
      85: getstatic     #248                // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.DISPLAY_ALLOCATED:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
      88: if_acmpeq     101
      91: aload_0
      92: getfield      #72                 // Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
      95: getstatic     #141                // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.WAITING_FOR_FOREIGN_ATTACH:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
      98: if_acmpne     126
     101: aload_0
     102: iload         4
     104: invokevirtual #350                // Method retainedDisplayCleanupAddressable:(I)Z
     107: ifeq          126
     110: aload         7
     112: ifnull        126
     115: aload         7
     117: ldc_w         #354                // String [0-9a-f]{64}
     120: invokevirtual #356                // Method java/lang/String.matches:(Ljava/lang/String;)Z
     123: ifne          134
     126: aload_0
     127: ldc_w         #360                // String healthy pre-attach abort lacked exact empty-display authority
     130: invokespecial #200                // Method contradiction:(Ljava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
     133: areturn
     134: aload_0
     135: iconst_1
     136: putfield      #147                // Field emptyPreAttachAbortAuthorized:Z
     139: aload_0
     140: getstatic     #339                // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.RELEASE_AUTHORIZED:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
     143: putfield      #72                 // Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
     146: aload_0
     147: lload         5
     149: aload         8
     151: invokespecial #273                // Method commit:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
     154: areturn

  public com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle$CommandResult acknowledgeNoForeignAfterFailure(java.lang.String, long, int, long, java.lang.String);
    Code:
       0: aload_0
       1: aload_1
       2: lload_2
       3: iload         4
       5: invokespecial #178                // Method authorize:(Ljava/lang/String;JI)Z
       8: ifne          16
      11: aload_0
      12: invokespecial #257                // Method stale:()Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      15: areturn
      16: new           #212                // class java/lang/StringBuilder
      19: dup
      20: invokespecial #214                // Method java/lang/StringBuilder."<init>":()V
      23: ldc_w         #362                // String NO_FOREIGN|
      26: invokevirtual #217                // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
      29: aload         7
      31: invokestatic  #346                // Method java/lang/String.valueOf:(Ljava/lang/Object;)Ljava/lang/String;
      34: invokevirtual #217                // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
      37: invokevirtual #225                // Method java/lang/StringBuilder.toString:()Ljava/lang/String;
      40: astore        8
      42: aload_0
      43: lload         5
      45: aload         8
      47: invokespecial #263                // Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
      50: astore        9
      52: aload         9
      54: ifnull        60
      57: aload         9
      59: areturn
      60: aload_0
      61: getfield      #77                 // Field failure:Ljava/lang/String;
      64: ifnull        107
      67: aload_0
      68: getfield      #72                 // Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
      71: getstatic     #66                 // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.FAILED:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
      74: if_acmpne     107
      77: aload_0
      78: getfield      #122                // Field foreignTask:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;
      81: ifnonnull     107
      84: aload_0
      85: getfield      #147                // Field emptyPreAttachAbortAuthorized:Z
      88: ifne          107
      91: aload         7
      93: ifnull        107
      96: aload         7
      98: ldc_w         #354                // String [0-9a-f]{64}
     101: invokevirtual #356                // Method java/lang/String.matches:(Ljava/lang/String;)Z
     104: ifne          115
     107: aload_0
     108: ldc_w         #364                // String empty failed-session cleanup lacked exact absence authority
     111: invokespecial #200                // Method contradiction:(Ljava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
     114: areturn
     115: aload_0
     116: iconst_1
     117: putfield      #144                // Field emptyFailureCleanupAuthorized:Z
     120: aload_0
     121: getstatic     #339                // Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.RELEASE_AUTHORIZED:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
     124: putfield      #72                 // Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;
     127: aload_0
     128: lload         5
     130: aload         8
     132: invokespecial #273                // Method commit:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;
     135: areturn

  public boolean canReleaseNormally();
    Code:
       0: aload_0
       1: getfield      #135                // Field normalReleaseAuthorized:Z
       4: ifne          21
       7: aload_0
       8: getfield      #144                // Field emptyFailureCleanupAuthorized:Z
      11: ifne          21
      14: aload_0
      15: getfield      #147                // Field emptyPreAttachAbortAuthorized:Z
      18: ifeq          25
      21: iconst_1
      22: goto          26
      25: iconst_0
      26: ireturn
}
'''


class SourceScopeTests(unittest.TestCase):
    def test_actual_manifest_and_sources_pass(self):
        inspect_host.validate_manifest_source(MANIFEST.read_bytes())
        inspect_host.validate_activity_source(ACTIVITY.read_bytes())
        inspect_host.validate_lifecycle_source(LIFECYCLE.read_bytes())
        inspect_host.validate_layout_source(LAYOUT.read_bytes())
        inspect_host.validate_lifecycle_test_source(
            (ROOT / "test/NativePageHostLifecycleTest.java").read_bytes())
        inspect_host.validate_build_script_source(BUILD_SCRIPT.read_bytes())

    def test_source_manifest_exact_allowlists_reject_every_expansion(self):
        text = MANIFEST.read_text(encoding="utf-8")
        mutations = (
            text.replace('android:allowBackup="false"', 'android:allowBackup="true"'),
            text.replace('android:resizeableActivity="true"', 'android:resizeableActivity="false"'),
            text.replace(' android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|density"', ''),
            text.replace('android:launchMode="singleTask"', 'android:launchMode="standard"'),
            text.replace('</application>', '<activity-alias android:name=".Alias"/></application>'),
            text.replace('</manifest>', '<instrumentation android:name=".I"/></manifest>'),
            text.replace('</application>', '<service android:name=".Unexpected"/></application>'),
            text.replace('android:exported="true"', 'android:exported="false"'),
            text.replace('<application ', '<application android:debuggable="true" '),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-120:]), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_manifest_source(mutation.encode())

    def test_activity_rejects_each_forbidden_capability(self):
        source = ACTIVITY.read_bytes()
        for forbidden in inspect_host.FORBIDDEN_SOURCE:
            with self.subTest(forbidden=forbidden), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_source(source + forbidden.encode("ascii"))
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.validate_activity_source(
                source + b"\nboolean accepted(CommandResult result) { return true; }\n")

    def test_activity_and_lifecycle_require_each_boundary(self):
        activity = ACTIVITY.read_text(encoding="utf-8")
        for marker in ("MotionEvent.TOOL_TYPE_STYLUS", "MotionEvent.TOOL_TYPE_ERASER",
                       "lifecycle.commandEnvelopeMatches(", "lifecycle.onVirtualDisplayMetrics(",
                       "lifecycle.canPublishFreshAttachReady()",
                       "lifecycle.canPublishFreshCloseWait()",
                       "lifecycle.canDeferFreshCommand(",
                       "lifecycle.reserveDeferredCommand(",
                       "lifecycle.consumeDeferredCommand(",
                       "lifecycle.hostAuthoritySuspended()",
                       "lifecycle.hostAuthorityDeadlineElapsed()",
                       "lifecycle.hasHostAuthorityTransition()",
                       "lifecycle.completeHostAuthorityTransition(exactDeadline)",
                       'beginBoundedHostAuthoritySuspension("configuration_changed")',
                       "completeHostAuthorityTransitionIfReady()",
                       "WAIT_CONFIGURATION_FRAME",
                       "admitExpectedHostGeometry(configuration)",
                       "hostGeometryMatchesExpectedConfiguration(",
                       "Configuration.ORIENTATION_PORTRAIT",
                       "Configuration.ORIENTATION_LANDSCAPE",
                       'verifyRuntimeAuthorityOrFail("host_authority_transition_complete")',
                       "deferAuthenticatedCommand(envelope, commandKind, identity);",
                       "processAuthenticatedCommand(envelope, null);",
                       "hostAuthorityDeadlineElapsed <= 0",
                       "now > hostAuthorityDeadlineElapsed",
                       "physicalDisplayAuthorityStableWhilePaused()",
                       "deferredCommandPending", "clearDeferredCommand()",
                       "lifecycle.onDisplayAllocated(admittedGeneration, displayId)",
                       'verifyPreAllocationHostAuthorityOrFail("before_display_creation")',
                       "lifecycle.revalidatePreAllocationHostAuthority(",
                       "int allocatedDisplayId = allocatedDisplay.getDisplayId();",
                       "cleanupAddressable=true",
                       "PROCESS_CLEANUP_ESCALATED",
                       "lifecycle.acknowledgeNoForeignAfterFailure(",
                       "lifecycle.acknowledgeNoForeignPreAttachAbort(",
                       'PREFIX + "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"',
                       'log("EMPTY_PRE_ATTACH_ABORT"',
                       'log("EMPTY_PRE_ATTACH_ABORT_REPLAY"',
                       "lifecycle.onHostAuthority(",
                       "lifecycle.onPhysicalFrameMeasured(",
                       "lifecycle.onReleaseAttemptFailed(",
                       "lifecycle.retainedDisplayCleanupAddressable(",
                       "lifecycle.state() == NativePageHostLifecycle.State.RELEASED",
                       "catch (RuntimeException malformedBundle)",
                       "generation instanceof Long", "sequence instanceof Long",
                       "canonicalFrameInstalled", "fixedBufferReady",
                       "failedExactReplay", "suspendedExactReplay",
                       'log("ATTACH_REPLAY"',
                       'log("PLACEMENT_REPLAY"', 'log("CLOSE_REPLAY"',
                       'log("DESTROY_REPLAY"', 'log("EMPTY_ABORT_REPLAY"',
                       "lifecycle.canFinishWithoutCleanup()", "if (!isKnownCommand(action))",
                       "getWindow().getDecorView().isShown()",
                       "root.getLocationOnScreen(rootLocation);",
                       "surface.getLocationOnScreen(surfaceLocation);",
                       'log("COMMAND_IGNORED"', "if (!Intent.ACTION_MAIN.equals(initialAction))"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_source(activity.replace(marker, "REMOVED").encode())
        terminal_guard = "lifecycle.state() == NativePageHostLifecycle.State.RELEASED"
        first_guard = activity.find(terminal_guard)
        self.assertGreaterEqual(first_guard, 0)
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.validate_activity_source(
                (activity[:first_guard] + "false" + activity[first_guard + len(terminal_guard):])
                .encode())
        second_guard = activity.find(terminal_guard, first_guard + 1)
        self.assertGreaterEqual(second_guard, 0)
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.validate_activity_source(
                (activity[:second_guard] + "false" + activity[second_guard + len(terminal_guard):])
                .encode())
        lifecycle = LIFECYCLE.read_text(encoding="utf-8")
        for marker in ("REQUIRED_FOREIGN_COMPONENT", "MessageDigest.isEqual(",
                       "UNAUTHENTICATED_OR_STALE", "onHostAuthority(",
                       "suspendHostAuthority(", "canDeferFreshCommand(",
                       "reserveDeferredCommand(", "consumeDeferredCommand(",
                       "onDisplayAllocated(", "DISPLAY_ALLOCATED",
                       "retainedDisplayCleanupAddressable(",
                       "onVirtualDisplayMetrics(", "acknowledgeNoForeignAfterFailure(",
                       "acknowledgeNoForeignPreAttachAbort(",
                       "emptyPreAttachAbortAuthorized",
                       "canPublishFreshAttachReady(",
                       "canPublishFreshCloseWait(",
                       "onPhysicalFrameMeasured(", "onReleaseAttemptFailed(",
                       "canFinishWithoutCleanup("):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_lifecycle_source(lifecycle.replace(marker, "REMOVED").encode())
        layout = LAYOUT.read_text(encoding="utf-8")
        for marker in ("BUFFER_WIDTH = 1404", "BUFFER_HEIGHT = 1872",
                       "enum Placement", "exactlyMatches(", "hostWidth > hostHeight",
                       "slotWidth / 3", "hostHeight / 4"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_layout_source(layout.replace(marker, "REMOVED").encode())
        lifecycle_test_path = ROOT / "test/NativePageHostLifecycleTest.java"
        lifecycle_test = lifecycle_test_path.read_text(encoding="utf-8")
        for marker in ("replayDuringPlacement", "replayWhileClosing",
                       "replayReleaseAuthorized", "replayAfterReleaseFailure",
                       "replayWhileStickyFailed", "closeReplayWaiting",
                       "closeReplayCannotBecomeNewClose", "closeSequenceEquivocation",
                       "deferredAttach", "deferredPlace", "deferredClose",
                       "deferredDestroy", "persistentPause", "duplicatePause",
                       "persistentGeometryChurn", "deferredPlacementKinds",
                       "hostAuthorityDeadlineElapsed()",
                       "completeHostAuthorityTransition(",
                       "duplicateDeferred", "equivocatedDeferred",
                       "directDeferredBypass", "attachReplayDuringPause",
                       "directDeferredPlaceBypass", "directDeferredCloseBypass",
                       "directDeferredDestroyBypass", "wrongDeferredConsumption",
                       "closeReplayDuringPause", "placementReplayDuringPause",
                       "destroyReplayDuringPause", "invalidDeferredPhase",
                       "failedDeferredDestroy", "contradictionCleanupThroughPause",
                       "attachTimeoutCleanupThroughPause",
                       "destroyTimeoutCleanupThroughPause",
                       "retainsPhysicalHostAuthority", "metricsException",
                       "preIdReleaseFailure"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_lifecycle_test_source(
                    lifecycle_test.replace(marker, "REMOVED").encode())
        activity = ACTIVITY.read_text(encoding="utf-8")
        for marker in ('log("FAILED_FRAME_AUTHORITY"',
                       "lifecycle.retainsPhysicalHostAuthority()"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_source(
                    activity.replace(marker, "REMOVED").encode())

    def test_healthy_pre_attach_abort_activity_mutations_fail_closed(self):
        activity = ACTIVITY.read_text(encoding="utf-8")
        inspect_host.validate_activity_source(activity.encode())
        early_route = '''        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {
            processAuthenticatedCommand(envelope, null);
            return;
        }
'''
        self.assertEqual(activity.count(early_route), 1)
        authentication = "        if (!lifecycle.commandEnvelopeMatches("
        method_start = activity.index("private void processAuthenticatedCommand(")
        abort_start = activity.index(
            "        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {", method_start)
        abort_end = activity.index("        if (ACTION_ACK_NO_FOREIGN.equals(action)) {", abort_start)
        abort = activity[abort_start:abort_end]
        def replace_abort(changed):
            self.assertNotEqual(changed, abort)
            return activity[:abort_start] + changed + activity[abort_end:]
        moved_early = activity.replace(early_route, "", 1).replace(
            authentication, early_route + authentication, 1)
        mutations = [
            moved_early,
            activity.replace(early_route, "", 1),
            activity.replace(early_route, early_route.replace("            return;\n", ""), 1),
            activity.replace(early_route, early_route.replace(
                "processAuthenticatedCommand(envelope, null);",
                "deferAuthenticatedCommand(envelope, 7, null);"), 1),
            activity.replace("    private static int deferredCommandKind(String action) {",
                "    private static int deferredCommandKind(String action) {\n"
                "        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) return 7;", 1),
            replace_abort(abort.replace("exactString(envelope.extras, EXTRA_ABSENCE_EVIDENCE)",
                                        "String.valueOf(envelope.extras.get(EXTRA_ABSENCE_EVIDENCE))", 1)),
            replace_abort(abort.replace("lifecycle.acknowledgeNoForeignPreAttachAbort(",
                                        "lifecycle.acknowledgeNoForeignAfterFailure(", 1)),
            replace_abort(abort.replace('log("EMPTY_PRE_ATTACH_ABORT",',
                                        'log("EMPTY_ATTACH_ABORT",', 1)),
            replace_abort(abort.replace('log("EMPTY_PRE_ATTACH_ABORT_REPLAY",',
                                        'log("EMPTY_PRE_ATTACH_ABORT",', 1)),
            replace_abort(abort.replace("if (releaseNormally()) finishAndRemoveTask();",
                                        "finishAndRemoveTask();", 1)),
            replace_abort(abort.replace("!lifecycle.displayRemoved() && ", "", 1)),
            replace_abort(abort.replace("if (releaseNormally()) finishAndRemoveTask();",
                                        "if (releaseForUnexpectedLoss(\"abort\")) finishAndRemoveTask();", 1)),
            replace_abort(abort.replace("            String evidence =",
                                        '            lifecycle.onProtocolFailure("synthetic");\n'
                                        "            String evidence =", 1)),
            replace_abort(abort.replace('                log("EMPTY_PRE_ATTACH_ABORT",',
                                        '                log("READY", "readiness=ACTIVE");\n'
                                        '                log("EMPTY_PRE_ATTACH_ABORT",', 1)),
            replace_abort(abort.replace("            String evidence =",
                                        "            if (!verifyRuntimeAuthorityOrFail(\"abort\")) return;\n"
                                        "            String evidence =", 1)),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_source(mutation.encode())

    def test_healthy_pre_attach_abort_lifecycle_mutations_fail_closed(self):
        source = LIFECYCLE.read_text(encoding="utf-8")
        inspect_host.validate_lifecycle_source(source.encode())
        start = source.index("    public CommandResult acknowledgeNoForeignPreAttachAbort(")
        end = source.index("    /** Exact external absence evidence", start)
        abort = source[start:end]
        def replace_abort(changed):
            self.assertNotEqual(changed, abort)
            return source[:start] + changed + source[end:]
        guards = ("failure != null || ", "foreignTask != null || ",
                  "deferredCommandKey != null", "state != State.DISPLAY_ALLOCATED",
                  "state != State.WAITING_FOR_FOREIGN_ATTACH",
                  "!retainedDisplayCleanupAddressable(commandDisplayId)",
                  "absenceEvidenceSha256 == null", '!absenceEvidenceSha256.matches("[0-9a-f]{64}")')
        mutations = [replace_abort(abort.replace(marker,
                     "" if marker.endswith(" || ") else "false", 1)) for marker in guards]
        sequence_classification = '''        CommandResult replay = classifySequence(commandSequence, key);
        if (replay != null) return replay;
'''
        self.assertIn(sequence_classification, abort)
        mutations.extend([
            replace_abort(abort.replace("if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();",
                                        "", 1)),
            replace_abort(abort.replace('"PRE_ATTACH_ABORT|"', '"NO_FOREIGN|"', 1)),
            replace_abort(abort.replace(sequence_classification, "", 1).replace(
                "        emptyPreAttachAbortAuthorized = true;",
                sequence_classification + "        emptyPreAttachAbortAuthorized = true;", 1)),
            replace_abort(abort.replace("        emptyPreAttachAbortAuthorized = true;",
                                        '        fail("synthetic");\n'
                                        "        emptyPreAttachAbortAuthorized = true;", 1)),
            replace_abort(abort.replace("emptyPreAttachAbortAuthorized = true;",
                                        "emptyFailureCleanupAuthorized = true;", 1)),
            replace_abort(abort.replace("state = State.RELEASE_AUTHORIZED;", "state = State.ACTIVE;", 1)),
            source.replace("                || emptyPreAttachAbortAuthorized\n", "", 1),
        ])
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_lifecycle_source(mutation.encode())

    def test_legacy_failure_cleanup_hidden_authority_fails_closed(self):
        source = LIFECYCLE.read_text(encoding="utf-8")
        guard = "        if (failure == null || state != State.FAILED || foreignTask != null"
        timeout = "    public boolean onAttachTimeout"
        self.assertIn(guard, source)
        self.assertIn(timeout, source)
        helper = (
            "    private void authorizeLegacyWithoutAbsence() {\n"
            "        emptyFailureCleanupAuthorized = true;\n"
            "    }\n\n"
        )
        mutation = source.replace(
                guard, "        authorizeLegacyWithoutAbsence();\n" + guard, 1).replace(
                timeout, helper + timeout, 1)
        with self.assertRaisesRegex(
                inspect_host.InspectionError, "legacy failure cleanup authority/order"):
            inspect_host.validate_lifecycle_source(mutation.encode())

    def test_healthy_pre_attach_abort_regression_coverage_is_required(self):
        source = (ROOT / "test/NativePageHostLifecycleTest.java").read_text(encoding="utf-8")
        for marker in ("testHealthyPreAttachAbort();", "healthyPreAttachAbort",
                       "pausedPreAttachAbort", "preAttachAbortReleaseFailure",
                       "unauthenticatedPreAttachAbort", "invalidPreAttachEvidence",
                       "preAttachAbortSequenceGap", "preAttachAbortEquivocation",
                       "failedEmptyAbortEquivocation", "attachedPreAttachAbort",
                       "deferredPreAttachAbort", "preAttachAbortNotDeferrable",
                       "failedPreAttachAbort", "unallocatedPreAttachAbort"):
            self.assertIn(marker, source)
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_lifecycle_test_source(source.replace(marker, "REMOVED").encode())

    def test_build_script_canonical_text_policy_rejects_every_removed_boundary(self):
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        for marker in ("ConvertTo-CanonicalEvidenceUtf8", "Invoke-JavapCanonicalEvidence",
                       "CanonicalTextPolicySelfTestOutput", "contains a UTF-8 BOM",
                       "contains an embedded NUL", "contains a lone CR",
                       "mixes LF and CRLF newlines",
                       "StandardOutput.BaseStream.CopyToAsync",
                       "StandardError.BaseStream.CopyToAsync", "activityBytecodeBytes",
                       "layoutBytecodeBytes", "-J-Dfile.encoding=UTF-8",
                       "lifecycleBytecodeBytes", "--lifecycle-bytecode",
                       "lifecycle-bytecode.txt",
                       "CANONICAL_TEXT_POLICY_V1", "forbiddenInheritedEnvironment",
                       "pythonIsolatedBootstrap", "flags.isolated == 1",
                       "flags.no_site == 1", "flags.ignore_environment == 1",
                       "flags.dont_write_bytecode == 1",
                       "sys.meta_path=[frozen_importlib.BuiltinImporter",
                       "sys.path=[]", "sys.path_hooks=[]",
                       "sys.addaudithook(runtime_audit)",
                       "actual_directories != {relative_key(value) for value in expected_directories}",
                       "unreviewed python runtime/review-root open rejected",
                       "unreviewed python import origin rejected",
                       "python runtime/review-root mutation rejected",
                       "Get-ReviewedPythonRuntimeFiles",
                       "Copy-LockedPythonRuntimeFile",
                       "New-PythonBootstrapZipBytes", "python-bootstrap.zip",
                       "python312._pth", "Raw ZIP_STORED writer",
                       "ExactSourceLoader", "ExactAuthorityFinder",
                       "frozen_importlib_external.ExtensionFileLoader",
                       "Assert-ReviewedPythonRuntimeAuthority",
                       "Invoke-PythonRuntimeAuthorityMutationSelfTest",
                        "reviewedPythonHelperSha256", "reviewedPythonBootstrapSha256",
                        "Assert-ReviewedPythonHelperAuthority",
                        "reviewed Python entry script bytes differed before compilation",
                        "powershell5Launcher", "powershell7Launcher",
                       "powershell-engines/windows-powershell-5.1/powershell.exe",
                       "reviewedPythonRuntimeDirectoryCount=55",
                       "reviewedPythonRuntimeRecordCount=838",
                       "reviewedPythonRuntimeInventorySha256",
                       "unretained package-shadow directory",
                       "directory reparse point",
                       "$pythonVersion='Python 3.12.14'",
                       "reviewedProductionClassSha256", "reviewedTestClassSha256",
                       "reviewedDexSha256", "reviewedApkSha256",
                       "Assert-ReviewedFileSet", "Invoke-ReviewedPythonCaptured",
                       "native-page-host-evidence-bundle-v1",
                       "Write-ToRetainedAuthority"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_build_script_source(
                    script.replace(marker, "REMOVED").encode())
        for forbidden in ("Out-File", "-Encoding utf8"):
            with self.subTest(forbidden=forbidden), self.assertRaises(
                    inspect_host.InspectionError):
                inspect_host.validate_build_script_source(
                    (script + "\n" + forbidden).encode())

    @unittest.skipUnless(os.name == "nt", "PowerShell environment regression is Windows-only")
    def test_every_inherited_java_python_injection_variable_fails_before_self_test(self):
        variables = ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
                     "JDK_JAVAC_OPTIONS", "JAVA_OPTIONS", "CLASSPATH",
                     "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
                     "PYTHONUSERBASE", "PYTHONNOUSERSITE", "PYTHONSAFEPATH",
                     "PYTHONUTF8", "PYTHONIOENCODING", "PYTHONHASHSEED",
                     "PYTHONPYCACHEPREFIX", "PYTHONBREAKPOINT", "PYTHONWARNINGS",
                     "PYTHONUNKNOWNFUTURE")
        with _retained_cross_engine_authority() as (authority, policy), \
                tempfile.TemporaryDirectory() as directory:
            for engine in authority:
                for variable in variables:
                    with self.subTest(engine=engine.label, variable=variable):
                        output = Path(directory) / (
                            engine.label.replace(" ", "-") + "-" +
                            variable.replace("_", "x") + ".txt")
                        environment = _clean_powershell_environment(
                            {variable: "hostile-injection"})
                        result = _run_retained_policy(
                            engine, policy, output, environment=environment)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(output.exists())

    def test_every_fixed_compiler_output_authority_family_rejects_mutation(self):
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        authorities = (
            next(iter(inspect_host.REVIEWED_BUILD_SOURCE_SHA256.values())),
            next(iter(inspect_host.REVIEWED_PRODUCTION_CLASS_SHA256.values())),
            next(iter(inspect_host.REVIEWED_TEST_CLASS_SHA256.values())),
            inspect_host.REVIEWED_DEX_SHA256,
            inspect_host.REVIEWED_APK_SHA256,
            inspect_host.REVIEWED_PYTHON_RUNTIME_INVENTORY_SHA256,
        )
        for authority in authorities:
            replacement = ("0" if authority[0] != "0" else "1") + authority[1:]
            with self.subTest(authority=authority), self.assertRaises(
                    inspect_host.InspectionError):
                inspect_host.validate_build_script_source(
                    script.replace(authority, replacement, 1).encode("utf-8"))

    def test_every_python_helper_and_bootstrap_pin_rejects_mutation(self):
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        helper_block = script[script.index("$reviewedPythonHelperSha256="):
                              script.index("$reviewedPythonBootstrapSha256=")]
        authorities = [value for _, value in re.findall(
            r"'([^']+)'='([0-9a-f]{64})'", helper_block)]
        authorities += re.findall(
            r"\$reviewedPythonBootstrapSha256='([0-9a-f]{64})'", script)
        self.assertEqual(len(authorities), 4)
        for authority in authorities:
            replacement = ("0" if authority[0] != "0" else "1") + authority[1:]
            with self.subTest(authority=authority), self.assertRaises(
                    inspect_host.InspectionError):
                inspect_host.validate_build_script_source(
                    script.replace(authority, replacement, 1).encode("utf-8"))

    def test_reviewed_python_runtime_guard_rejects_transient_shadow_namespace(self):
        authority = getattr(sys, "_native_page_host_import_authority", None)
        if authority is None:
            self.skipTest("runs authoritatively only through the reviewed bootstrap")
        runtime_root, digest, file_count, directory_count = authority
        self.assertEqual(file_count, 783)
        self.assertEqual(directory_count, 55)
        self.assertEqual(digest, inspect_host.REVIEWED_PYTHON_RUNTIME_INVENTORY_SHA256)
        hostile_package = Path(runtime_root) / "Lib" / "argparse" / "__init__.py"
        hostile_file = Path(runtime_root) / "Lib" / "transient-shadow.py"
        for candidate in (hostile_package, hostile_file):
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                sys.audit("open", str(candidate), "r", os.O_RDONLY)
        with self.assertRaises(RuntimeError):
            sys.audit("os.mkdir", str(hostile_package.parent), 0o777, -1)
        original_path = list(sys.path)
        try:
            sys.path.append(str(Path(runtime_root) / "hostile-search-root"))
            with self.assertRaises(RuntimeError):
                sys.audit("import", "argparse", str(hostile_package),
                          list(sys.path), [], [])
        finally:
            sys.path[:] = original_path

    @unittest.skipUnless(os.name == "nt", "PowerShell cross-engine regression is Windows-only")
    def test_canonical_text_policy_bytes_match_both_reviewed_powershell_engines(self):
        expected = (b"CANONICAL_TEXT_POLICY_V1 "
                    b"sha256=4cce75f4e4dcdd0119627d7674ef7747a4634666bcb9b13e29cf0e4742ad9803 "
                    b"base64=YWxwaGEKzrIK bytes=9\n")
        digests = []
        with _retained_cross_engine_authority() as (engines, policy), \
                tempfile.TemporaryDirectory() as directory:
            hostile = Path(directory) / "hostile-path"
            hostile.mkdir()
            (hostile / "powershell.exe").write_bytes(b"not an executable")
            (hostile / "pwsh.exe").write_bytes(b"not an executable")
            environment = _clean_powershell_environment({
                "PATH": str(hostile) + os.pathsep + os.environ.get("PATH", "")})
            # Exercise the final child-spawn sanitizer too, not just the helper
            # used to assemble an ordinary clean environment.
            environment.update({
                "DOTNET_STARTUP_HOOKS": str(hostile / "unreviewed.dll"),
                "DOTNET_ADDITIONAL_DEPS": str(hostile / "unreviewed.deps.json"),
                "COR_ENABLE_PROFILING": "1",
                "COR_PROFILER_PATH": str(hostile / "unreviewed-profiler.dll"),
                "COMPlus_ReadyToRun": "0",
                "PSModulePath": str(hostile),
                "PSModuleAnalysisCachePath": str(hostile / "analysis.cache"),
            })
            for index, engine in enumerate(engines):
                output = Path(directory) / f"canonical-{index}.txt"
                result = _run_retained_policy(
                    engine, policy, output, environment=environment,
                    during_child=lambda: (
                        engine.require_mutation_denied(), policy.require_mutation_denied()))
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
                payload = output.read_bytes()
                self.assertEqual(payload, expected)
                self.assertFalse(payload.startswith(b"\xef\xbb\xbf"))
                self.assertNotIn(b"\r", payload)
                self.assertNotIn(b"\x00", payload)
                self.assertTrue(payload.endswith(b"\n"))
                self.assertFalse(payload.endswith(b"\n\n"))
                digests.append(inspect_host.sha256(payload))
            self.assertEqual(len(engines), 2)
            self.assertEqual(len(set(digests)), 1)

    @unittest.skipUnless(os.name == "nt", "Windows engine-path authority")
    def test_engine_authority_rejects_relative_hardlink_symlink_and_substitute(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "engine.exe"
            original.write_bytes(b"reviewed-engine")
            digest = hashlib.sha256(original.read_bytes()).hexdigest()
            with self.assertRaises(AssertionError):
                with _RetainedWindowsFile(Path("engine.exe"), digest, "relative engine"):
                    pass
            hardlink = root / "hardlink.exe"
            os.link(original, hardlink)
            with self.assertRaises(AssertionError):
                with _RetainedWindowsFile(original, digest, "hardlinked engine"):
                    pass
            hardlink.unlink()
            substitute = root / "substitute.exe"
            substitute.write_bytes(b"substitute")
            with self.assertRaises(AssertionError):
                with _RetainedWindowsFile(substitute, digest, "substitute engine"):
                    pass
            try:
                symlink = root / "symlink.exe"
                symlink.symlink_to(original)
            except OSError:
                pass
            else:
                with self.assertRaises(AssertionError):
                    with _RetainedWindowsFile(symlink, digest, "symlink engine"):
                        pass

    def test_powershell_role_records_reject_missing_swapped_or_equivocated_authority(self):
        original = getattr(sys, "_native_page_host_powershell_authority", None)
        if original is None:
            self.skipTest("requires the reviewed build bootstrap")
        ps5_path, ps5_digest, ps7_path, ps7_digest = original
        mutations = (
            (),
            (ps5_path, ps5_digest, ps7_path),
            (ps7_path, ps7_digest, ps5_path, ps5_digest),
            (ps5_path, ps7_digest, ps7_path, ps5_digest),
            (ps5_path, ps5_digest, ps5_path, ps7_digest),
            (ps5_path, ps5_digest, "relative-pwsh.exe", ps7_digest),
            (ps5_path, "0" * 64, ps7_path, ps7_digest),
            (str(ROOT / "wrong-root/powershell-engines/windows-powershell-5.1/powershell.exe"),
             ps5_digest, ps7_path, ps7_digest),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), mock.patch.object(
                    sys, "_native_page_host_powershell_authority", mutation):
                with self.assertRaises(AssertionError):
                    _powershell_authority_records()

    def test_powershell_startup_environment_is_sanitized_without_mutating_caller(self):
        hostile_names = ("DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS",
                         "DOTNET_SHARED_STORE", "COREHOST_TRACEFILE", "CORECLR_PROFILER_PATH",
                         "COMPlus_EnableDiagnostics", "COR_ENABLE_PROFILING",
                         "COR_PROFILER_PATH", "POWERSHELL_DISTRIBUTION_CHANNEL",
                         "PSModulePath", "PSModuleAnalysisCachePath",
                         "PSExecutionPolicyPreference", "__PSLockdownPolicy",
                         "APPDOMAIN_MANAGER_ASM", "APPDOMAIN_MANAGER_TYPE", "DEVPATH",
                         "DOTNET_UNKNOWN_FUTURE", "POWERSHELL_UNKNOWN_FUTURE")
        original = {name: "hostile-startup" for name in hostile_names}
        original["PATH"] = "hostile-path-remains-for-absolute-launch-test"
        cleaned = _sanitize_powershell_startup_environment(original)
        self.assertEqual(cleaned, {"PATH": original["PATH"]})
        self.assertEqual(len(original), len(hostile_names) + 1)

    @unittest.skipUnless(os.name == "nt", "Windows retained replacement authority")
    def test_retained_engine_and_policy_reject_write_rename_and_replacement(self):
        kernel = _win32_kernel()
        with tempfile.TemporaryDirectory() as directory:
            for role in ("engine.exe", "policy.ps1"):
                target = Path(directory) / role
                payload = ("reviewed-" + role).encode("ascii")
                target.write_bytes(payload)
                replacement = Path(directory) / (role + ".replacement")
                replacement.write_bytes(b"hostile replacement")
                parent = kernel.CreateFileW(str(target), 0x80000000, 0x1,
                                             None, 3, 0x80, None)
                self.assertNotEqual(parent, ctypes.c_void_p(-1).value)
                try:
                    with _RetainedWindowsFile(target, hashlib.sha256(payload).hexdigest(),
                                              role) as admitted:
                        for action in (lambda: target.write_bytes(b"hostile writer"),
                                       lambda: target.rename(target.with_suffix(".moved")),
                                       lambda: os.replace(replacement, target)):
                            with self.subTest(role=role), self.assertRaises(OSError):
                                action()
                            admitted.verify()
                finally:
                    kernel.CloseHandle(parent)
                self.assertEqual(target.read_bytes(), payload)

    def test_build_script_contains_dual_build_bytecode_and_snapshot_inspection(self):
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        for marker in ("Build-One", "first", "second", "Get-FileHash", "SHA256",
                       "javap.exe", "--activity-bytecode", "inspect_native_page_host.py",
                       "NativePageHostLifecycleTest", "native-page-host-toolchain-v1",
                       "private-retained-namespace-audit-v2", "-I','-S','-B','-c",
                       "pythonRuntimeFileCount", "pythonRuntimeDirectoryCount",
                       "pythonRuntimeRecordCount", "pythonRuntimeInventorySha256",
                       "Copy-LockedPythonRuntimeFile",
                       "Assert-ReviewedPythonRuntimeAuthority",
                         "Invoke-PythonRuntimeAuthorityMutationSelfTest",
                         "reviewedPythonHelperSha256",
                         "reviewedPythonBootstrapSha256",
                         "Assert-ReviewedPythonHelperAuthority",
                         "powershell5Launcher", "powershell7Launcher",
                       "--expected-dex", "--toolchain-authority", "Assert-PinnedHash",
                       "Copy-ToRetainedAuthority", "Read-RetainedBytes",
                       "Get-RetainedHash", "--layout-bytecode",
                       "descriptorSnapshotSha256", "permissionsSha256",
                       "$sourceAuthorityMismatch",
                        "NativePageHostActivity.javap.txt",
                        "DisplayProbeLayout.javap.txt",
                         "reviewedProductionClassSha256",
                         "Assert-ReviewedFileSet $classesRaw",
                         "Assert-PinnedHash (Join-Path $dexRaw 'classes.dex')",
                         "Assert-PinnedHash $alignedRaw $reviewedApkSha256",
                         "Invoke-ReviewedPythonCaptured $inspector",
                         "evidenceBundleBytes",
                         "bundled authority digest differed",
                         "Final artifacts differ from package-authority.json",
                        "Retained toolchain authority changed across the build"):
            self.assertIn(marker, script)
        self.assertNotIn("Out-File", script)
        self.assertNotIn("-Encoding utf8", script)
        zip_writer = script[script.index("function New-PythonBootstrapZipBytes"):
                            script.index("function Get-ReviewedPythonRuntimeFiles")]
        self.assertIn("$entryNames.Sort([StringComparer]::Ordinal)", zip_writer)
        self.assertNotIn("Sort-Object", zip_writer)
        self.assertLess(script.index("$toolLocks="), script.index("$toolHashes="))
        self.assertNotRegex(script, r"&\s*\$Python\b")
        package_source = Path(__file__).read_text(encoding="utf-8")
        engine_boundary = package_source[:package_source.index("def archive_bytes")]
        self.assertNotIn("shutil.which", engine_boundary)
        self.assertNotIn('"-File"', engine_boundary)
        self.assertIn("_retained_cross_engine_authority", engine_boundary)
        self.assertIn("QueryFullProcessImageNameW", engine_boundary)
        self.assertLess(script.index("$pythonRuntimeFiles=Get-ReviewedPythonRuntimeFiles"),
                        script.index("$pythonVersion='Python 3.12.14'"))
        self.assertLess(script.index("Assert-ReviewedPythonRuntimeAuthority",
                                     script.index("$pythonRuntimeFiles=")),
                        script.index("$pythonVersion='Python 3.12.14'"))
        self.assertLess(script.index("$pythonRuntimeInventoryPath=Write-LockedSnapshot"),
                        script.index("$pythonVersion='Python 3.12.14'"))
        self.assertLess(script.index("$pythonVersion='Python 3.12.14'"),
                        script.index("Invoke-ReviewedPython $packageTests"))
        self.assertLess(script.index("Copy-LockedSnapshot $testClass.FullName"),
                        script.index("& $java -cp $retainedTestClasses"))
        self.assertLess(script.index("Assert-ReviewedFileSet $testClasses"),
                        script.index("Copy-LockedSnapshot $testClass.FullName"))
        self.assertLess(script.index("Assert-ReviewedFileSet $classesRaw"),
                        script.index("Copy-LockedSnapshot $classFile.FullName"))
        self.assertLess(script.index("Copy-LockedSnapshot (Join-Path $dexRaw 'classes.dex')"),
                        script.index("Invoke-ReviewedPython $canonicalizer"))
        self.assertLess(script.index("Copy-ToRetainedAuthority $alignedRaw"),
                        script.index("Invoke-ReviewedPythonCaptured $inspector"))
        self.assertNotIn("--evidence-dir", script)
        inspector = (HERE / "inspect_native_page_host.py").read_text(encoding="utf-8")
        lock_marker = "with _deny_snapshot_replacement(args.apk)"
        first_read_marker = "apk, source_descriptor = read_regular_with_descriptor("
        aapt_marker = 'permissions = run_aapt(args.aapt, ["dump", "permissions", str(args.apk)])'
        retained_marker = '"allAaptInputs": "lockedBeforeFirstReadAndRetainedAcrossInspection"'
        self.assertIn(lock_marker, inspector)
        self.assertIn(first_read_marker, inspector)
        self.assertIn(aapt_marker, inspector)
        self.assertIn(retained_marker, inspector)
        self.assertNotIn("_write_private_snapshot", inspector)
        self.assertLess(inspector.index(lock_marker), inspector.index(first_read_marker))
        self.assertLess(inspector.index(first_read_marker), inspector.index(aapt_marker))


class BytecodeEvidenceTests(unittest.TestCase):
    def test_semantic_fixture_passes(self):
        inspect_host.validate_activity_bytecode(
                bytecode_fixture(), allow_test_fixture=True)
        inspect_host.validate_lifecycle_bytecode(
                lifecycle_bytecode_fixture(), allow_test_fixture=True)
        inspect_host.validate_layout_bytecode(
                layout_bytecode_fixture(), allow_test_fixture=True)

    def test_synthetic_javap_fixtures_are_not_production_authority(self):
        for label, validator, payload in (
                ("activity", inspect_host.validate_activity_bytecode, bytecode_fixture()),
                ("lifecycle", inspect_host.validate_lifecycle_bytecode,
                 lifecycle_bytecode_fixture()),
                ("layout", inspect_host.validate_layout_bytecode, layout_bytecode_fixture())):
            with self.subTest(label=label), self.assertRaisesRegex(
                    inspect_host.InspectionError, "exact complete topology"):
                validator(payload)

    def test_instruction_parser_rejects_nonmonotonic_and_external_targets(self):
        mutations = (
            "  public void x();\n    Code:\n       0: nop\n       2: nop\n       1: return\n",
            "  public void x();\n    Code:\n       0: goto          9\n       3: return\n",
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(inspect_host.InspectionError):
                inspect_host.bytecode_instructions(mutation)

    def test_exact_javap_topology_rejects_unparsed_or_extra_content(self):
        activity = bytecode_fixture()
        mutations = (
            activity + b"UNREVIEWED TRAILING EVIDENCE\n",
            activity[:-2] + (
                b"  private void unreviewed();\n"
                b"    Code:\n"
                b"       0: return\n"
                b"}\n"),
            activity + b"public final class Unreviewed {\n}\n",
            activity.replace(
                b"       9: invokevirtual #2 // Method finishAndRemoveTask:()V\n",
                b"       8: nop\n"
                b"       9: invokevirtual #2 // Method finishAndRemoveTask:()V\n", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaisesRegex(
                    inspect_host.InspectionError, "exact complete topology"):
                inspect_host.validate_activity_bytecode(
                        mutation, allow_test_fixture=True)
        for label, validator, payload in (
                ("lifecycle", inspect_host.validate_lifecycle_bytecode,
                 lifecycle_bytecode_fixture()),
                ("layout", inspect_host.validate_layout_bytecode,
                 layout_bytecode_fixture())):
            with self.subTest(label=label), self.assertRaisesRegex(
                    inspect_host.InspectionError, "exact complete topology"):
                validator(payload + b"UNREVIEWED TRAILING EVIDENCE\n",
                          allow_test_fixture=True)

    def test_legacy_failure_cleanup_hidden_helper_and_guard_bypass_fail(self):
        evidence = lifecycle_bytecode_fixture().decode()
        hidden_helper = evidence.replace(
            "      64: ifnull        107\n",
            "      64: ifnull        107\n"
            "      65: aload_0\n"
            "      66: invokespecial #999 // Method authorizeLegacyWithoutAbsence:()V\n",
            1)
        bypass = evidence.replace(
                "      64: ifnull        107", "      64: ifnull        115", 1)
        for index, mutation in enumerate((hidden_helper, bypass)):
            with self.subTest(index=index), self.assertRaisesRegex(
                    inspect_host.InspectionError, "legacy failure cleanup"):
                inspect_host.validate_lifecycle_bytecode(
                        mutation.encode(), allow_test_fixture=True)

    def test_each_lifecycle_bytecode_authority_mutation_fails(self):
        evidence = lifecycle_bytecode_fixture().decode()
        for marker in (
                "Method authorize:(Ljava/lang/String;JI)Z",
                "Method stale:()Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;",
                "String PRE_ATTACH_ABORT|",
                "Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;",
                "Field failure:Ljava/lang/String;",
                "Field foreignTask:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;",
                "Field deferredCommandKey:Ljava/lang/String;",
                "NativePageHostLifecycle$State.DISPLAY_ALLOCATED",
                "NativePageHostLifecycle$State.WAITING_FOR_FOREIGN_ATTACH",
                "Method retainedDisplayCleanupAddressable:(I)Z",
                "String [0-9a-f]{64}",
                "healthy pre-attach abort lacked exact empty-display authority",
                "Field emptyPreAttachAbortAuthorized:Z",
                "NativePageHostLifecycle$State.RELEASE_AUTHORIZED",
                "Method commit:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;",
                "empty failed-session cleanup lacked exact absence authority",
                "Field emptyFailureCleanupAuthorized:Z",
                "Field normalReleaseAuthorized:Z"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_lifecycle_bytecode(
                        evidence.replace(marker, "REMOVED", 1).encode(),
                        allow_test_fixture=True)

    def test_each_semantic_branch_mutation_fails(self):
        evidence = bytecode_fixture().decode()
        for marker in ("iconst_2", "iconst_4", "iconst_1", "sipush        265",
                       "sipush        1404", "sipush        1872",
                       "commandEnvelopeMatches", "parseForeignIdentity",
                       "canPublishFreshAttachReady", "cancelAttachTimeout", "ATTACH_REPLAY",
                       "canPublishFreshCloseWait", "armDestroyTimeout",
                       "WAIT_FOREIGN_DESTROY", "CLOSE_REPLAY", "PLACEMENT_REPLAY",
                       "DESTROY_REPLAY", "EMPTY_ABORT_REPLAY",
                       "acknowledgeNoForeignPreAttachAbort", "EMPTY_PRE_ATTACH_ABORT_REPLAY",
                       "EMPTY_PRE_ATTACH_ABORT\n", "absenceEvidenceSha256",
                       "decodeCommandEnvelope", "verifyRuntimeAuthorityOrFail",
                       "verifyPreAllocationHostAuthorityOrFail",
                       "revalidatePreAllocationHostAuthority",
                       "beginDisplayCreation",
                       "onVirtualDisplayMetrics", "onPhysicalFrameMeasured",
                       "onHostAuthority", "onReleaseAttemptFailed",
                       "hostAuthoritySuspended", "canDeferFreshCommand",
                       "reserveDeferredCommand", "consumeDeferredCommand",
                       "deferAuthenticatedCommand", "processAuthenticatedCommand",
                       "COMMAND_DEFERRED", "COMMAND_RESUMED",
                       "com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_ATTACHED",
                       "com.techrebbe.supernote.nativepagehost.PLACE_FULL",
                       "com.techrebbe.supernote.nativepagehost.PLACE_LEFT",
                       "com.techrebbe.supernote.nativepagehost.PLACE_RIGHT",
                       "com.techrebbe.supernote.nativepagehost.BEGIN_CLOSE",
                       "com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_DESTROYED",
                       "bipush        6",
                       "onDisplayAllocated",
                       "retainedDisplayCleanupAddressable", "escalateOwnProcessCleanup",
                       "PROCESS_CLEANUP_ESCALATED", "android/os/Process.killProcess",
                       "View.getLocationOnScreen", "View.isShown",
                       "canFinishWithoutCleanup"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_bytecode(
                        evidence.replace(marker, "REMOVED", 1).encode(),
                        allow_test_fixture=True)

    def test_bytecode_evidence_requires_canonical_utf8_and_lf_bytes(self):
        inspect_host.validate_canonical_text_evidence(b"valid\n", "fixture")
        for mutation in (b"\xef\xbb\xbfvalid\n", b"valid\r\n", b"va\x00lid\n",
                         b"valid", b"valid\n\n", b"\xc3\x28\n"):
            with self.subTest(mutation=mutation), self.assertRaises(
                    inspect_host.InspectionError):
                inspect_host.validate_canonical_text_evidence(mutation, "fixture")

    def test_each_layout_bytecode_mutation_fails(self):
        evidence = layout_bytecode_fixture().decode()
        for marker in ("sipush        8192", "iconst_3", "iconst_4", "idiv",
                       "Placement.FULL", "Placement.LEFT", "Placement.RIGHT",
                       "left", "top", "width", "height"):
            with self.subTest(marker=marker), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_layout_bytecode(
                        evidence.replace(marker, "REMOVED", 1).encode(),
                        allow_test_fixture=True)

    def test_payload_parse_before_authentication_fails(self):
        evidence = bytecode_fixture().decode()
        evidence = evidence.replace("commandEnvelopeMatches", "TEMP", 1)
        evidence = evidence.replace("parseForeignIdentity", "commandEnvelopeMatches", 1)
        evidence = evidence.replace("TEMP", "parseForeignIdentity", 1)
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.validate_activity_bytecode(
                    evidence.encode(), allow_test_fixture=True)

    def test_pre_attach_abort_bytecode_cannot_move_before_authentication_or_defer(self):
        evidence = bytecode_fixture().decode()
        action = "com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT"
        admission_marker = "      20: ldc #8 // String " + action + "\n"
        mutations = (
            evidence.replace(admission_marker, "", 1),
            evidence.replace("commandEnvelopeMatches", "TEMP", 1)
                    .replace(action, "commandEnvelopeMatches", 1)
                    .replace("TEMP", action, 1),
            evidence.replace("  private static int deferredCommandKind(java.lang.String);\n    Code:\n",
                             "  private static int deferredCommandKind(java.lang.String);\n    Code:\n"
                             "       0: ldc #6 // String " + action + "\n", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_bytecode(
                        mutation.encode(), allow_test_fixture=True)

    def test_activity_pre_attach_control_flow_mutations_fail(self):
        evidence = bytecode_fixture().decode()
        mutations = (
            evidence.replace("       7: ifne          20", "       7: ifeq          20", 1),
            evidence.replace("      16: return", "      16: nop", 1),
            evidence.replace("      27: ifeq          40", "      27: ifeq          61", 1),
            evidence.replace("      74: if_acmpne     100", "      74: if_acmpne     108", 1),
            evidence.replace("      84: ifeq          91", "      84: ifeq          100", 1),
            evidence.replace("     115: ifne          135", "     115: ifeq          135", 1),
            evidence.replace("     122: ifeq          135", "     122: ifeq          140", 1),
            evidence.replace(
                "NativePageHostLifecycle.acknowledgeNoForeignPreAttachAbort:",
                "NativePageHostLifecycle.acknowledgeNoForeignAfterFailure:", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_activity_bytecode(
                        mutation.encode(), allow_test_fixture=True)

    def test_lifecycle_pre_attach_control_flow_mutations_fail(self):
        evidence = lifecycle_bytecode_fixture().decode()
        mutations = (
            evidence.replace("       8: ifne          16", "       8: ifeq          16", 1),
            evidence.replace("      15: areturn", "      15: nop", 1),
            evidence.replace("      54: ifnull        60", "      54: ifnull        67", 1),
            evidence.replace("      64: ifnonnull     126", "      64: ifnull        126", 1),
            evidence.replace("      88: if_acmpeq     101", "      88: if_acmpeq     110", 1),
            evidence.replace("     107: ifeq          126", "     107: ifne          126", 1),
            evidence.replace("     123: ifne          134", "     123: ifne          126", 1),
            evidence.replace("      88: ifne          107", "      88: ifeq          107", 1),
            evidence.replace("      18: ifeq          25", "      18: ifne          25", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_lifecycle_bytecode(
                        mutation.encode(), allow_test_fixture=True)


class CanonicalApkTests(unittest.TestCase):
    def test_descriptor_evidence_is_reproducible_but_exactly_typed(self):
        descriptor = {"name": "classes.dex", "device": 4, "inode": 9,
                      "size": 12, "mtimeNs": 15, "sha256": "a" * 64}
        self.assertEqual(inspect_host.stable_descriptor_evidence(descriptor), {
            "name": "classes.dex", "size": 12, "sha256": "a" * 64})
        for mutation in ({**descriptor, "extra": 1},
                         {key: value for key, value in descriptor.items()
                          if key != "inode"}):
            with self.assertRaises(inspect_host.InspectionError):
                inspect_host.stable_descriptor_evidence(mutation)

    @unittest.skipUnless(os.name == "nt", "Windows retained-handle authority")
    def test_path_only_inspection_requires_parent_retained_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "authority.bin"
            target.write_bytes(b"exact authority")
            with self.assertRaises(inspect_host.InspectionError):
                with inspect_host._deny_snapshot_replacement(target):
                    pass

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create = kernel32.CreateFileW
            create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_void_p]
            create.restype = ctypes.c_void_p
            close = kernel32.CloseHandle
            close.argtypes = [ctypes.c_void_p]
            close.restype = ctypes.c_int
            retained = create(str(target), 0x80000000 | 0x40000000,
                              0x00000001, None, 3, 0x80, None)
            self.assertNotEqual(retained, ctypes.c_void_p(-1).value)
            try:
                with inspect_host._deny_snapshot_replacement(target):
                    self.assertEqual(target.read_bytes(), b"exact authority")
            finally:
                close(retained)

    def test_canonical_output_ignores_base_order_and_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = [("resources.arsc", b"resources"),
                       ("AndroidManifest.xml", b"binary-manifest")]
            first_base, second_base = root / "first.apk", root / "second.apk"
            first_base.write_bytes(archive_bytes(entries, year=2024))
            second_base.write_bytes(archive_bytes(entries, reverse=True, year=2025))
            dex = root / "classes.dex"
            dex.write_bytes(b"dex\n035\0" + b"x" * 128)
            first, second = root / "first-out.apk", root / "second-out.apk"
            canonical.canonicalize(first_base, dex, first)
            canonical.canonicalize(second_base, dex, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(io.BytesIO(first.read_bytes()), "r") as archive:
                names = tuple(sorted(entry.filename for entry in archive.infolist()))
            self.assertEqual(names, ("AndroidManifest.xml", "classes.dex", "resources.arsc"))

    def test_expected_dex_requires_exact_executable_bytes(self):
        inspect_host.require_expected_dex(b"reviewed", b"reviewed")
        for candidate in (b"substitute", b"reviewed\x00", b"RevieweD"):
            with self.subTest(candidate=candidate), self.assertRaises(inspect_host.InspectionError):
                inspect_host.require_expected_dex(candidate, b"reviewed")

    def test_header_only_dex_is_not_executable_authority(self):
        fake = b"dex\n039\0" + b"\x00" * 200
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.dex_class_descriptors(fake)

    def test_archives_reject_duplicates_traversal_extra_and_forbidden_dex(self):
        fixtures = (
            [("AndroidManifest.xml", b"a"), ("AndroidManifest.xml", b"b")],
            [("AndroidManifest.xml", b"a"), ("../escape", b"b")],
            [("AndroidManifest.xml", b"a"), ("assets/payload", b"b")],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dex = root / "classes.dex"
            dex.write_bytes(b"dex\n035\0fixture")
            for index, entries in enumerate(fixtures):
                base = root / f"bad-{index}.apk"
                base.write_bytes(archive_bytes(entries))
                with self.subTest(index=index), self.assertRaises(canonical.CanonicalApkError):
                    canonical.canonicalize(base, dex, root / f"out-{index}.apk")
        for dex in (b"dex\n035\0startActivity", b"dex\n035\0android.permission.INTERNET"):
            with self.assertRaises(inspect_host.InspectionError):
                inspect_host.inspect_apk(archive_bytes([
                    ("AndroidManifest.xml", b"m"), ("classes.dex", dex)]))

    def test_descriptor_reader_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "input.apk"
            original.write_bytes(b"fixed")
            payload, descriptor = inspect_host.read_regular_with_descriptor(original, 100)
            self.assertEqual(payload, b"fixed")
            self.assertEqual(descriptor["sha256"], inspect_host.sha256(payload))
            hardlink = root / "hard.apk"
            os.link(original, hardlink)
            with self.assertRaises(inspect_host.InspectionError):
                inspect_host.read_regular_with_descriptor(original, 100)
            try:
                symlink = root / "soft.apk"
                symlink.symlink_to(hardlink)
                with self.assertRaises(inspect_host.InspectionError):
                    inspect_host.read_regular_with_descriptor(symlink, 100)
            except OSError:
                pass

    def test_descriptor_readers_reject_path_replacement_between_lstat_and_open(self):
        for reader, error in (
                (inspect_host.read_regular_with_descriptor, inspect_host.InspectionError),
                (lambda path, limit: canonical._read_regular_once(path, limit),
                 canonical.CanonicalApkError)):
            with self.subTest(reader=reader), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                original = root / "authority.bin"
                replacement = root / "replacement.bin"
                original.write_bytes(b"reviewed")
                replacement.write_bytes(b"substitute")
                real_open = os.open
                swapped = False

                def swap_open(path, flags, *args):
                    nonlocal swapped
                    if not swapped and Path(path) == original.absolute():
                        swapped = True
                        replacement.replace(original)
                    return real_open(path, flags, *args)

                with mock.patch.object(os, "open", side_effect=swap_open), \
                        self.assertRaises(error):
                    reader(original, 100)

    def test_canonicalizer_crash_never_publishes_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.apk"
            base.write_bytes(archive_bytes([("AndroidManifest.xml", b"manifest")]))
            dex = root / "classes.dex"
            dex.write_bytes(b"dex\n035\0" + b"x" * 128)
            output = root / "published.apk"
            with mock.patch.object(zipfile.ZipFile, "writestr",
                                   side_effect=RuntimeError("injected crash")), \
                    self.assertRaises(RuntimeError):
                canonical.canonicalize(base, dex, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob("published.apk.*.tmp")), [])

    def test_evidence_atomic_replace_failure_preserves_prior_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "package-authority.json"
            target.write_bytes(b"prior-authority\n")
            with mock.patch.object(os, "replace", side_effect=OSError("injected crash")), \
                    self.assertRaises(OSError):
                inspect_host.write_atomic(target, b"new-uncommitted-authority\n")
            self.assertEqual(target.read_bytes(), b"prior-authority\n")
            self.assertEqual(list(target.parent.glob(target.name + ".*.tmp")), [])

    def test_inspector_evidence_bundle_is_canonical_complete_and_self_authenticating(self):
        payloads = {
            "permissions.txt": b"permissions\n",
            "badging.txt": b"badging\n",
            "manifest-xmltree.txt": b"xmltree\n",
            "apk-descriptor-snapshot.json": b"{}\n",
            "activity-bytecode.txt": b"activity\n",
            "lifecycle-bytecode.txt": b"lifecycle\n",
            "layout-bytecode.txt": b"layout\n",
            "package-authority.json": b'{"schema":"fixture"}\n',
        }
        first = inspect_host.evidence_bundle_wire(payloads)
        second = inspect_host.evidence_bundle_wire(dict(reversed(list(payloads.items()))))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(b"\r", first)
        bundle = json.loads(first)
        self.assertEqual(bundle["schema"], "native-page-host-evidence-bundle-v1")
        self.assertEqual(bundle["authoritySha256"],
                         inspect_host.sha256(payloads["package-authority.json"]))
        self.assertEqual(set(bundle["files"]), set(payloads))
        for name, payload in payloads.items():
            record = bundle["files"][name]
            self.assertEqual(base64.b64decode(record["base64"], validate=True), payload)
            self.assertEqual(record["sha256"], inspect_host.sha256(payload))
            self.assertEqual(record["size"], len(payload))

        for mutation in (
                {name: value for name, value in payloads.items() if name != "permissions.txt"},
                {**payloads, "unexpected.txt": b"unexpected\n"},
                {**payloads, "permissions.txt": b""},
                {**payloads, "permissions.txt": "not-bytes"},
        ):
            with self.subTest(mutation=set(mutation)), self.assertRaises(
                    inspect_host.InspectionError):
                inspect_host.evidence_bundle_wire(mutation)


class AaptEvidenceTests(unittest.TestCase):
    def test_exact_packaged_manifest_passes(self):
        inspect_host.validate_permissions("package: com.techrebbe.supernote.nativepagehost\n")
        inspect_host.validate_badging(
            "package: name='com.techrebbe.supernote.nativepagehost' versionCode='2' "
            "versionName='0.0.2-native-page-visual-only'\n")
        inspect_host.validate_xmltree(xmltree_fixture())

    def test_every_packaged_topology_and_attribute_bypass_fails(self):
        text = xmltree_fixture()
        mutations = (
            text.replace("android:allowBackup(0x01010280)=(type 0x12)0x0",
                         "android:allowBackup(0x01010280)=(type 0x12)0xffffffff"),
            text.replace("android:resizeableActivity(0x010104f6)=(type 0x12)0xffffffff",
                         "android:resizeableActivity(0x010104f6)=(type 0x12)0x0"),
            text.replace("        A: android:configChanges(0x0101001f)=(type 0x11)0x1d80\n", ""),
            text.replace("        E: intent-filter", "        E: activity-alias (line=12)\n        E: intent-filter"),
            text.replace("    E: uses-sdk", "    E: instrumentation (line=4)\n    E: uses-sdk"),
            text.replace("      E: activity", "      E: service (line=9)\n      E: activity"),
            text.replace("android:launchMode(0x0101001d)=(type 0x10)0x2",
                         "android:launchMode(0x0101001d)=(type 0x10)0x0"),
            text.replace("android:exported(0x01010010)=(type 0x12)0xffffffff",
                         "android:exported(0x01010010)=(type 0x12)0x0"),
            text.replace("      A: android:theme", "      A: android:debuggable=(type 0x12)0xffffffff\n      A: android:theme"),
            text.replace("N: android=http://schemas.android.com/apk/res/android",
                         "N: android=http://schemas.android.com/apk/res/android\nN: extra=urn:unexpected"),
            text.replace("(type 0x12)0xffffffff", "(type 0x12)0xffffffff-extra", 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-150:]), self.assertRaises(inspect_host.InspectionError):
                inspect_host.validate_xmltree(mutation)

    def test_permissions_and_identity_fail_closed(self):
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.validate_permissions(
                "package: com.techrebbe.supernote.nativepagehost\nuses-permission: android.permission.INTERNET\n")
        with self.assertRaises(inspect_host.InspectionError):
            inspect_host.validate_badging(
                "package: name='other' versionCode='2' versionName='0.0.2-native-page-visual-only'\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
