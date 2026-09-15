#!/usr/bin/env python3
"""Fail-closed source and packaged-scope inspection for Native Page Host."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import ctypes
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
import xml.etree.ElementTree as ET
import zlib


PACKAGE = "com.techrebbe.supernote.nativepagehost"
VERSION_NAME = "0.0.2-native-page-visual-only"
VERSION_CODE = "2"
ACTIVITY = ".NativePageHostActivity"
MAX_TOOL_OUTPUT = 4 * 1024 * 1024
MAX_APK_ENTRY = 32 * 1024 * 1024
ALLOWED_APK_ENTRIES = {"AndroidManifest.xml", "resources.arsc", "classes.dex"}
REQUIRED_DEX_CLASSES = {
    "Lcom/techrebbe/supernote/nativepagehost/NativePageHostActivity;",
    "Lcom/techrebbe/supernote/viewportprobe/DisplayProbeLayout;",
    "Lcom/techrebbe/supernote/viewportprobe/DisplayProbeLayout$Placement;",
    "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle;",
    "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;",
    "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$FrameResult;",
    "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity;",
    "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;",
}
REVIEWED_BUILD_SOURCE_SHA256 = {
    "activity": "6a1183d3e134fe4a71788d572bb951265baf66c6a6d80f6adc59e75356be8242",
    "lifecycle": "ec5bb0136ec9b1ace86cd29efe45b7854645113ab3f09235af213bafd9b4e953",
    "layout": "3a343c107ff4ce4ffdaa92005e2af5a950aec9e3658071e7a5b10296f86c90ec",
    "manifest": "eb2a9c41b7000dd381cf88458fd7d42dd309e7b1e281070f62e50f6d9198462a",
    "lifecycleTest": "af862012cc140517273352b5b412591124804280825c6fb1672483fa8862cfaa",
}
REVIEWED_PRODUCTION_CLASS_SHA256 = {
    "com/techrebbe/supernote/nativepagehost/NativePageHostActivity.class": "eea7dbd939b87988c8f9bb846b7b26e9638d6eb8dc2916e401a5ea3e0621e075",
    "com/techrebbe/supernote/nativepagehost/NativePageHostActivity$1.class": "0ae3ba58f8a4742e556f582e7a6b4ca03d04b14af375a4c925523c068dc1047b",
    "com/techrebbe/supernote/nativepagehost/NativePageHostActivity$2.class": "f16e0bfae5bf1aa87f97f829ec4a919a366b3fb6e47bfbae11a1900c9913f55e",
    "com/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope.class": "9e0314e9321ce8082d9dce0bd4311c06b0a1eda12d7b79a31a1839eff8a27461",
    "com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.class": "3cc57303ed38aca6e98774296bed4c6a481762f17b87fa704d0a6f06390a30dc",
    "com/techrebbe/supernote/viewportprobe/DisplayProbeLayout$Placement.class": "19b573f1df309daaaa3688a234c147007c1dc20eb0c13fde6cc991ba8b9033f4",
    "com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.class": "d24dc72c36bbe93de035fb29faae09a9989430d4522ab6087a1042daa28e01a3",
    "com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult.class": "60ff0e47db6ba128a617562be4e580252a05192bfca7b9f8b3d84386ec3c08e1",
    "com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity.class": "c9d65fabd9985dd4d6c0d0d98ec593405158f286292b5900ae3f5a0225560d0c",
    "com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$FrameResult.class": "77acab1e5dfdbc5a571be657de424ebedb3d28f8d43aedb6e995bc71dd47afd8",
    "com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.class": "f015dea20db899e378df5daa9ac093dea167368c86b0e75d344e9cdaa70c9aee",
}
REVIEWED_TEST_CLASS_SHA256 = {
    "NativePageHostLifecycleTest.class": "932bef7a231ee4d1a24ca2a53348c083486df75b71c51a9a4d336ba4390bd515",
    **{name: digest for name, digest in REVIEWED_PRODUCTION_CLASS_SHA256.items()
       if "/viewportprobe/" in name},
}
REVIEWED_DEX_SHA256 = "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6"
REVIEWED_APK_SHA256 = "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178"
REVIEWED_ACTIVITY_JAVAP_SHA256 = (
    "cda787169b3d7ca8c278ed46f3168f9e7c2770985cbcae0b6133505a09ef6918")
REVIEWED_LIFECYCLE_JAVAP_SHA256 = (
    "d6429e0a48ee981cd6f6c2f3aee39cede0960d74202ecd705d25e3dc093263f4")
REVIEWED_LAYOUT_JAVAP_SHA256 = (
    "f8b854600275eef7093a0e9aed92a72767b570aa313f787c35bb87e2f00cb438")
# These exact synthetic records exercise semantic rejection without widening the
# production CLI's accepted evidence set. They are reachable only through the
# private keyword used by this module's package tests.
TEST_ACTIVITY_JAVAP_SHA256 = (
    "e577b70ff0aae97a82324564ffefeb463870cfd12d6d4eed80b5aa56cf43b027")
TEST_LIFECYCLE_JAVAP_SHA256 = (
    "16a0400bc3372e631ccefeedb57fc52894bbb435fea0561f9eceab9787759f19")
TEST_LAYOUT_JAVAP_SHA256 = (
    "091b3c7b3217c121305df7941afb73ea6ec6802416f85184492101141fd6aff1")
REVIEWED_PYTHON_RUNTIME_FILE_COUNT = 783
REVIEWED_PYTHON_RUNTIME_DIRECTORY_COUNT = 55
REVIEWED_PYTHON_RUNTIME_RECORD_COUNT = 838
REVIEWED_PYTHON_RUNTIME_INVENTORY_SHA256 = (
    "3aa15c911493f4107b5860a9bccd9107781fe63efb56e07f83a72078c6d49f57")
REVIEWED_WINDOWS_POWERSHELL_51_SHA256 = (
    "8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e")
REVIEWED_POWERSHELL_7_SHA256 = (
    "362a356ce7f0940ec74f73a8fc2c990a2cc24a38a11c90bbd8eca947110ad139")
ALLOWED_DEX_CLASS_BASES = (
    "Lcom/techrebbe/supernote/nativepagehost/NativePageHostActivity",
    "Lcom/techrebbe/supernote/viewportprobe/DisplayProbeLayout",
    "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle",
)
FORBIDDEN_SOURCE = (
    "startActivity(", "startActivityAsUser(", "startService(", "bindService(",
    "Runtime.getRuntime", "ProcessBuilder", "injectInputEvent", "UiAutomation",
    "Instrumentation", "InputManager", "FileInputStream", "FileOutputStream",
    "ContentResolver", "/storage/", "/data/", "de.robv.android.xposed",
)
FORBIDDEN_DEX = tuple(value.encode("ascii") for value in (
    "startActivity", "startActivityAsUser", "startService", "bindService",
    "Ljava/lang/Runtime;", "Ljava/lang/ProcessBuilder;", "injectInputEvent",
    "android/app/UiAutomation", "android/app/Instrumentation",
    "android/hardware/input/InputManager", "java/io/FileInputStream",
    "java/io/FileOutputStream", "android/content/ContentResolver", "/storage/",
    "/data/", "de/robv/android/xposed", "android.permission.",
))


class InspectionError(ValueError):
    pass


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_regular_with_descriptor(path: Path, limit: int) -> tuple[bytes, dict[str, object]]:
    path = Path(path).absolute()
    before = path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > limit):
        raise InspectionError(f"unsafe or oversized input: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > limit
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise InspectionError(f"descriptor authority changed: {path.name}")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise InspectionError(f"short descriptor read: {path.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise InspectionError(f"descriptor changed while read: {path.name}")
        return payload, {
            "name": path.name, "device": opened.st_dev, "inode": opened.st_ino,
            "size": opened.st_size, "mtimeNs": opened.st_mtime_ns,
            "sha256": sha256(payload),
        }
    finally:
        os.close(descriptor)


def read_regular(path: Path, limit: int) -> bytes:
    return read_regular_with_descriptor(path, limit)[0]


def stable_descriptor_evidence(value: dict[str, object]) -> dict[str, object]:
    """Publish reproducible content authority after full identity checks passed."""
    expected = {"name", "device", "inode", "size", "mtimeNs", "sha256"}
    if set(value) != expected:
        raise InspectionError("descriptor evidence topology changed")
    return {key: value[key] for key in ("name", "size", "sha256")}


def _uleb128(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(payload):
            raise InspectionError("truncated DEX uleb128")
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            return value, offset
    raise InspectionError("oversized DEX uleb128")


def dex_class_descriptors(payload: bytes) -> tuple[str, ...]:
    """Strictly parse the DEX header/string/type/class tables used for authority."""
    if (len(payload) < 0x70 or not re.fullmatch(rb"dex\n0(?:3[5-9]|4[0-1])\x00", payload[:8])
            or struct.unpack_from("<I", payload, 32)[0] != len(payload)
            or struct.unpack_from("<I", payload, 36)[0] != 0x70
            or struct.unpack_from("<I", payload, 40)[0] != 0x12345678
            or hashlib.sha1(payload[32:]).digest() != payload[12:32]
            or zlib.adler32(payload[12:]) & 0xffffffff != struct.unpack_from("<I", payload, 8)[0]):
        raise InspectionError("invalid DEX header/checksum/signature")

    def table(count_at: int, offset_at: int, item_size: int) -> tuple[int, int]:
        count, offset = struct.unpack_from("<II", payload, count_at)
        if count == 0:
            if offset != 0:
                raise InspectionError("empty DEX table has a nonzero offset")
            return count, offset
        if offset < 0x70 or offset % 4 or count > (len(payload) - offset) // item_size:
            raise InspectionError("DEX table exceeds file authority")
        return count, offset

    string_count, string_offset = table(56, 60, 4)
    type_count, type_offset = table(64, 68, 4)
    class_count, class_offset = table(96, 100, 32)
    strings: list[bytes] = []
    for index in range(string_count):
        data_offset = struct.unpack_from("<I", payload, string_offset + index * 4)[0]
        if data_offset < 0x70 or data_offset >= len(payload):
            raise InspectionError("DEX string offset is outside file")
        _, at = _uleb128(payload, data_offset)
        end = payload.find(b"\x00", at)
        if end < 0:
            raise InspectionError("unterminated DEX string")
        strings.append(payload[at:end])
    types: list[str] = []
    for index in range(type_count):
        string_index = struct.unpack_from("<I", payload, type_offset + index * 4)[0]
        if string_index >= len(strings):
            raise InspectionError("DEX type references invalid string")
        try:
            types.append(strings[string_index].decode("ascii"))
        except UnicodeError as error:
            raise InspectionError("non-ASCII DEX type authority") from error
    classes: list[str] = []
    for index in range(class_count):
        type_index = struct.unpack_from("<I", payload, class_offset + index * 32)[0]
        if type_index >= len(types):
            raise InspectionError("DEX class references invalid type")
        classes.append(types[type_index])
    if len(classes) != len(set(classes)):
        raise InspectionError("duplicate DEX class definition")
    actual = set(classes)
    if not REQUIRED_DEX_CLASSES.issubset(actual):
        raise InspectionError("DEX lacks required executable class topology")
    for descriptor in actual:
        if not any(descriptor == base + ";" or descriptor.startswith(base + "$")
                   for base in ALLOWED_DEX_CLASS_BASES):
            raise InspectionError("DEX contains an unreviewed class: " + descriptor)
    return tuple(sorted(classes))


@contextmanager
def _deny_snapshot_replacement(path: Path):
    """Prove the parent retains write/delete denial while path-only tools run."""
    if os.name != "nt":
        # A retained POSIX descriptor does not prevent another process from
        # replacing the pathname consumed by aapt. Refuse to claim authority on
        # platforms where this build's mandatory Windows sharing mode is absent.
        raise InspectionError("path-only inspection authority requires Windows locking")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.c_void_p]
    create.restype = ctypes.c_void_p
    close = kernel32.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    invalid = ctypes.c_void_p(-1).value
    # The parent intentionally retains newly generated files through their
    # original read/write handle. This read-only observer must therefore share
    # existing read/write access, while the parent's FileShare.Read still denies
    # every new writer and delete/rename handle. Prove those denials before and
    # after the path-only aapt subprocesses; without the parent authority this
    # function fails closed because either probe would succeed.
    share_all = 0x00000001 | 0x00000002 | 0x00000004
    handle = create(str(path), 0x80000000, share_all, None, 3, 0x80, None)
    if handle == invalid:
        raise InspectionError("could not observe retained parent authority")

    def require_parent_denial() -> None:
        for desired_access, label in ((0x40000000, "write"), (0x00010000, "delete")):
            probe = create(str(path), desired_access, share_all, None, 3, 0x80, None)
            if probe != invalid:
                close(probe)
                raise InspectionError(f"retained parent authority permits {label}")
            if ctypes.get_last_error() != 32:  # ERROR_SHARING_VIOLATION
                raise InspectionError(f"retained parent {label} denial was not authoritative")
    try:
        require_parent_denial()
        yield
        require_parent_denial()
    finally:
        close(handle)


def validate_manifest_source(payload: bytes) -> None:
    try:
        root = ET.fromstring(payload.decode("utf-8"))
    except (UnicodeError, ET.ParseError) as error:
        raise InspectionError("invalid source manifest") from error
    android = "{http://schemas.android.com/apk/res/android}"
    if root.tag != "manifest" or root.attrib != {
            "package": PACKAGE,
            android + "versionCode": VERSION_CODE,
            android + "versionName": VERSION_NAME}:
        raise InspectionError("wrong source package")
    if [node.tag for node in root] != ["uses-sdk", "application"]:
        raise InspectionError("source manifest topology changed")
    sdk, app = list(root)
    if sdk.attrib != {android + "minSdkVersion": "30",
                     android + "targetSdkVersion": "30"}:
        raise InspectionError("source SDK contract changed")
    if app.attrib != {
            android + "allowBackup": "false",
            android + "usesCleartextTraffic": "false",
            android + "label": "Native Page Host - Visual Only",
            android + "supportsRtl": "false",
            android + "theme": "@android:style/Theme.Material.Light.NoActionBar"}:
        raise InspectionError("source application attributes changed")
    if [node.tag for node in app] != ["activity"]:
        raise InspectionError("source application topology changed")
    activity = list(app)[0]
    if activity.attrib != {
            android + "name": ACTIVITY,
            android + "exported": "true",
            android + "launchMode": "singleTask",
            android + "resizeableActivity": "true",
            android + "configChanges":
                "orientation|screenSize|screenLayout|smallestScreenSize|density"}:
        raise InspectionError("source activity admission changed")
    if [node.tag for node in activity] != ["intent-filter"]:
        raise InspectionError("source launcher topology changed")
    children = list(list(activity)[0])
    if ([node.tag for node in children] != ["action", "category"]
            or children[0].attrib != {android + "name": "android.intent.action.MAIN"}
            or children[1].attrib != {android + "name": "android.intent.category.LAUNCHER"}):
        raise InspectionError("source launcher intent changed")


def validate_activity_source(payload: bytes) -> None:
    try:
        source = payload.decode("utf-8")
    except UnicodeError as error:
        raise InspectionError("activity source is not UTF-8") from error
    for forbidden in FORBIDDEN_SOURCE:
        if forbidden in source:
            raise InspectionError(f"forbidden activity capability: {forbidden}")
    if "boolean accepted(CommandResult" in source or "accepted(result)" in source:
        raise InspectionError("activity conflates fresh acceptance with idempotent replay")
    required = (
        "VIRTUAL_DISPLAY_FLAG_PUBLIC",
        "VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY",
        "private static final int VIRTUAL_DISPLAY_FLAG_DESTROY_CONTENT_ON_REMOVAL = 1 << 8;",
        "setFixedSize(",
        "DisplayProbeLayout.BUFFER_WIDTH, DisplayProbeLayout.BUFFER_HEIGHT",
        "MotionEvent.TOOL_TYPE_STYLUS",
        "MotionEvent.TOOL_TYPE_ERASER",
        "return true;",
        "@Override protected void onNewIntent(Intent intent)",
        "lifecycle.acknowledgeForeignAttached(",
        "lifecycle.canPublishFreshAttachReady()",
        "lifecycle.canPublishFreshCloseWait()",
        "lifecycle.acknowledgeForeignDestroyed(",
        "lifecycle.authorizePlacement(",
        "lifecycle.commandEnvelopeMatches(",
        "lifecycle.canDeferFreshCommand(",
        "lifecycle.reserveDeferredCommand(",
        "lifecycle.consumeDeferredCommand(",
        "lifecycle.hostAuthoritySuspended()",
        "lifecycle.hostAuthorityDeadlineElapsed()",
        "lifecycle.hasHostAuthorityTransition()",
        "lifecycle.completeHostAuthorityTransition(exactDeadline)",
        "deferAuthenticatedCommand(envelope, commandKind, identity);",
        "processAuthenticatedCommand(envelope, null);",
        "HOST_AUTHORITY_REACQUIRE_TIMEOUT_MS",
        "hostAuthorityDeadlineElapsed <= 0",
        "now > hostAuthorityDeadlineElapsed",
        "physicalDisplayAuthorityStableWhilePaused()",
        "deferredCommandPending",
        "clearDeferredCommand()",
        "HOST_AUTHORITY_SUSPENDED",
        "HOST_AUTHORITY_REACQUIRED",
        "HOST_AUTHORITY_READY",
        "WAIT_CONFIGURATION_FRAME",
        "admitExpectedHostGeometry(configuration)",
        "hostGeometryMatchesExpectedConfiguration(",
        "Configuration.ORIENTATION_PORTRAIT",
        "Configuration.ORIENTATION_LANDSCAPE",
        "COMMAND_DEFERRED",
        "COMMAND_RESUMED",
        "lifecycle.onVirtualDisplayMetrics(",
        "lifecycle.onHostAuthority(",
        "lifecycle.onPhysicalFrameMeasured(",
        "lifecycle.onPlacementTimeout(",
        "lifecycle.onReleaseAttemptFailed(",
        "lifecycle.retainsPhysicalHostAuthority()",
        "lifecycle.retainedDisplayCleanupAddressable(",
        "lifecycle.canFinishWithoutCleanup()",
        "lifecycle.acknowledgeNoForeignAfterFailure(",
        "lifecycle.acknowledgeNoForeignPreAttachAbort(",
        "verifyRuntimeAuthorityOrFail(",
        "verifyPreAllocationHostAuthorityOrFail(",
        "lifecycle.revalidatePreAllocationHostAuthority(",
        'verifyRuntimeAuthorityOrFail("host_authority_transition_complete")',
        "verifyHostAuthorityOrFail(",
        "verifyPhysicalFrameOrFail(",
        "isCleanupCommand(action)",
        "boolean failedCleanup = lifecycle.isFailed() && isCleanupCommand(action);",
        "boolean failedExactReplay = lifecycle.isFailed()",
        "boolean suspendedExactReplay = lifecycle.hostAuthoritySuspended()",
        "if (lifecycle.isFailed() && !failedCleanup && !failedExactReplay)",
        "if (result == CommandResult.ACCEPTED)",
        "if (result == CommandResult.IDEMPOTENT)",
        'log("ATTACH_REPLAY", "state=" + lifecycle.state().name()',
        'log("PLACEMENT_REPLAY", "state=" + lifecycle.state().name()',
        'log("CLOSE_REPLAY", "state=" + lifecycle.state().name()',
        'log("DESTROY_REPLAY", "state=" + lifecycle.state().name()',
        'log("EMPTY_ABORT_REPLAY", "state=" + lifecycle.state().name()',
        'log("EMPTY_PRE_ATTACH_ABORT", "absenceEvidenceSha256=" + scrub(evidence))',
        'log("EMPTY_PRE_ATTACH_ABORT_REPLAY", "state=" + lifecycle.state().name()',
        "ACK_NO_FOREIGN_AFTER_FAILURE",
        "private static final String ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT =\n"
        '            PREFIX + "ACK_NO_FOREIGN_PRE_ATTACH_ABORT";',
        "canonicalFrameInstalled",
        'log("FAILED_FRAME_AUTHORITY"',
        "fixedBufferReady",
        "EXTRA_SEQUENCE",
        "decodeCommandEnvelope(",
        "catch (RuntimeException malformedBundle)",
        "capability instanceof String",
        "generation instanceof Long",
        "display instanceof Integer",
        "sequence instanceof Long",
        "if (!isKnownCommand(action))",
        "if (!lifecycle.commandEnvelopeMatches(envelope.capability, envelope.generation,",
        'log("COMMAND_IGNORED"',
        "if (!Intent.ACTION_MAIN.equals(initialAction))",
        "finishAndRemoveTask();",
        'EXTRA_FOREIGN_UID = "foreignUid"',
        'EXTRA_FOREIGN_EVIDENCE = "foreignEvidenceSha256"',
        "physicalDisplayId() == Display.DEFAULT_DISPLAY",
        "Display display = getDisplay();",
        "resumed, hostVisible(), hasWindowFocus()",
        "getWindow().getDecorView().isShown()",
        "root.getLocationOnScreen(rootLocation);",
        "surface.getLocationOnScreen(surfaceLocation);",
        "catch (RuntimeException releaseFailure)",
        "old.release();",
        "lifecycle.onDisplayAllocated(admittedGeneration, displayId)",
        "int allocatedDisplayId = allocatedDisplay.getDisplayId();",
        "cleanupAddressable=true",
        "PROCESS_CLEANUP_ESCALATED",
        "android.os.Process.killProcess(android.os.Process.myPid());",
        "lifecycle.markReleased(false);",
        "lifecycle.markReleased(true);",
    )
    for value in required:
        if value not in source:
            raise InspectionError(f"missing activity safety invariant: {value}")
    if source.count("class NativePageHostActivity") != 1:
        raise InspectionError("activity class topology changed")
    allocation = source.find("lifecycle.onDisplayAllocated(admittedGeneration, displayId)")
    metrics_read = source.find("DisplayMetrics actual = virtualDisplayMetrics();", allocation)
    if allocation < 0 or metrics_read < 0 or allocation > metrics_read:
        raise InspectionError("allocated display ID is not admitted before fallible metrics")
    deferred = source.find("private void deferAuthenticatedCommand(")
    drain = source.find("private void drainDeferredCommandIfReady()")
    suspend = source.find("private void beginBoundedHostAuthoritySuspension(")
    reacquire = source.find("private boolean reacquireHostAuthorityIfReady()")
    if min(deferred, drain, suspend, reacquire) < 0:
        raise InspectionError("bounded singleTask command deferral boundary is incomplete")
    on_new_intent = source.find("@Override protected void onNewIntent(Intent intent)")
    command_processor = source.find("private void processAuthenticatedCommand(")
    admission = source[on_new_intent:command_processor]
    envelope_auth = admission.find("lifecycle.commandEnvelopeMatches(")
    pre_attach_abort_route = admission.find(
            "if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action))")
    pre_attach_abort_process = admission.find(
            "processAuthenticatedCommand(envelope, null);", pre_attach_abort_route)
    failed_cleanup = admission.find(
            "boolean failedCleanup = lifecycle.isFailed() && isCleanupCommand(action);")
    payload_parse = admission.find("parseForeignIdentity(envelope.extras)")
    reservation = admission.find("deferAuthenticatedCommand(envelope, commandKind, identity);")
    runtime_verify = admission.find('verifyRuntimeAuthorityOrFail("authenticated_command")')
    processing = admission.rfind("processAuthenticatedCommand(envelope, null);")
    exact_early_abort_route = (
        "        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {\n"
        "            processAuthenticatedCommand(envelope, null);\n"
        "            return;\n"
        "        }\n"
    )
    exact_authenticated_abort_admission = (
        "        CommandEnvelope envelope = decodeCommandEnvelope(intent, action);\n"
        "        if (envelope == null) return;\n"
        "        if (!lifecycle.commandEnvelopeMatches(envelope.capability, envelope.generation,\n"
        "                envelope.displayId, envelope.sequence)) {\n"
        "            log(\"COMMAND_IGNORED\", \"reason=unauthenticated_or_stale action=\" + scrub(action));\n"
        "            return;\n"
        "        }\n"
        "        // This exact action can only end an empty display. It never reserves a\n"
        "        // command or acquires presentation authority during Android's pause.\n"
        "        // Payload access remains after authentication; lifecycle classifies\n"
        "        // exact replays before checking first-acceptance health and phase.\n"
        "        if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {\n"
        "            processAuthenticatedCommand(envelope, null);\n"
        "            return;\n"
        "        }\n"
    )
    if min(on_new_intent, command_processor, envelope_auth, pre_attach_abort_route,
           pre_attach_abort_process, failed_cleanup, payload_parse, reservation,
           runtime_verify, processing) < 0 \
            or admission.count("processAuthenticatedCommand(envelope, null);") != 2 \
            or admission.count(exact_early_abort_route) != 1 \
            or admission.count(exact_authenticated_abort_admission) != 1 \
            or not (envelope_auth < pre_attach_abort_route < pre_attach_abort_process
                    < failed_cleanup < payload_parse < reservation < runtime_verify
                    < processing):
        raise InspectionError("pause-gap commands are not authenticated, typed, and deferred exactly")
    # The healthy empty-display abort is a known, authenticated command, but it
    # must bypass both host-pause deferral and the failure-only cleanup policy.
    # Its payload is intentionally not touched until processAuthenticatedCommand,
    # after the exact capability/generation/display/sequence envelope matched.
    known_start = source.find("private static boolean isKnownCommand(String action)")
    cleanup_start = source.find("private static boolean isCleanupCommand(String action)")
    identity_start = source.find("private ForeignTaskIdentity parseForeignIdentity(", cleanup_start)
    kind_start = source.find("private static int deferredCommandKind(String action)")
    kind_end = source.find("private void deferAuthenticatedCommand(", kind_start)
    if min(known_start, cleanup_start, identity_start, kind_start, kind_end) < 0:
        raise InspectionError("command classification topology is incomplete")
    known = source[known_start:cleanup_start]
    failure_cleanup = source[cleanup_start:identity_start]
    deferred_kind = source[kind_start:kind_end]
    if (known.count("ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)") != 1
            or "ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT" in failure_cleanup
            or "ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT" in deferred_kind):
        raise InspectionError(
                "healthy pre-attach abort is not a distinct known nondeferrable command")
    for constant in ("DEFER_ATTACH", "DEFER_PLACE_FULL", "DEFER_PLACE_LEFT",
                     "DEFER_PLACE_RIGHT", "DEFER_BEGIN_CLOSE", "DEFER_ACK_DESTROYED"):
        if constant not in source:
            raise InspectionError("deferred command kind is not closed: " + constant)
    destroy_method = source.find("@Override protected void onDestroy()")
    destroy_end = source.find("\n    }\n}", destroy_method)
    destroy = source[destroy_method:destroy_end]
    if ("releaseForUnexpectedLoss(" not in destroy
            or "if (processCleanupRequired)" not in destroy
            or "escalateOwnProcessCleanup(" not in destroy):
        raise InspectionError("destroy-time release failure lacks process cleanup owner")
    if source.count("android.os.Process.killProcess(android.os.Process.myPid());") != 1:
        raise InspectionError("self-process cleanup escalation is not uniquely bounded")
    create_start = source.find("private void maybeCreateVirtualDisplay()")
    create_end = source.find("private DisplayMetrics virtualDisplayMetrics()", create_start)
    create = source[create_start:create_end]
    preallocation_verify = create.find(
        'verifyPreAllocationHostAuthorityOrFail("before_display_creation")')
    preallocation_frame = create.find(
        'verifyPhysicalFrameOrFail("before_display_creation")')
    begin_creation = create.find("lifecycle.beginDisplayCreation()")
    if (create.count("allocatedDisplay.getDisplayId()") != 1
            or min(preallocation_verify, preallocation_frame, begin_creation) < 0
            or not (preallocation_verify < preallocation_frame < begin_creation)
            or "verifyHostAuthorityOrFail(\"before_display_creation\")" in create
            or create.find("int allocatedDisplayId = allocatedDisplay.getDisplayId();")
                > create.find("lifecycle.onDisplayAllocated(admittedGeneration, displayId)")):
        raise InspectionError("preallocation/allocated display authority ordering changed")
    configuration = source[source.find("@Override public void onConfigurationChanged("):
                           source.find("@Override public void surfaceCreated(")]
    cancel_watchdog = configuration.find("cancelDisplayWatchdog();")
    suspend_configuration = configuration.find(
            'beginBoundedHostAuthoritySuspension("configuration_changed");')
    super_configuration = configuration.find("super.onConfigurationChanged(configuration);")
    expected_configuration = configuration.find("admitExpectedHostGeometry(configuration)")
    post_configuration = configuration.find("root.post(this::layoutSurface);")
    if min(cancel_watchdog, suspend_configuration, super_configuration,
           expected_configuration, post_configuration) < 0 \
            or not (cancel_watchdog < suspend_configuration < super_configuration
                    < expected_configuration < post_configuration):
        raise InspectionError("configuration change does not suspend frame authority first")
    layout = source[source.find("private void layoutSurface()"):
                    source.find("@Override public void onConfigurationChanged(")]
    if "lifecycle.state() == NativePageHostLifecycle.State.RELEASED" not in layout:
        raise InspectionError("terminal release can re-enter physical layout authority")
    expected_layout = layout.find("hostGeometryMatchesExpectedConfiguration(width, height)")
    frame_measure = layout.find("lifecycle.onPhysicalFrameMeasured(")
    if min(expected_layout, frame_measure) < 0 or expected_layout > frame_measure:
        raise InspectionError("layout can publish a stale pre-configuration frame")
    if "lifecycle.state() == NativePageHostLifecycle.State.RELEASED" not in create:
        raise InspectionError("terminal release can re-enter display allocation")
    physical_verify = source[source.find("private boolean verifyPhysicalFrameOrFail("):
                             source.find("@Override public void surfaceDestroyed(")]
    if "hostGeometryMatchesExpectedConfiguration(hostWidth, hostHeight)" not in physical_verify:
        raise InspectionError("continuous frame admission ignores configuration authority")
    reacquire_body = source[reacquire:source.find(
            "private void completeHostAuthorityTransitionIfReady()", reacquire)]
    if "armDisplayWatchdog();" in reacquire_body \
            or "cancelHostAuthorityTimeout(false)" in reacquire_body:
        raise InspectionError("authority reacquire falsely completes frame transition")
    attach_start = source.find("if (ACTION_ACK_ATTACHED.equals(action))", command_processor)
    attach_end = source.find("if (ACTION_PLACE_FULL.equals(action)", attach_start)
    if attach_start < 0 or attach_end < 0:
        raise InspectionError("attach command block is missing")
    attach = source[attach_start:attach_end]
    accepted_at = attach.find("if (result == CommandResult.ACCEPTED)")
    cancel_at = attach.find("cancelAttachTimeout();")
    ready_at = attach.find('log("READY"')
    replay_branch_at = attach.find("if (result == CommandResult.IDEMPOTENT)")
    replay_at = attach.find('log("ATTACH_REPLAY"')
    if (min(accepted_at, cancel_at, ready_at, replay_branch_at, replay_at) < 0
            or not (accepted_at < cancel_at < ready_at < replay_branch_at < replay_at)
            or attach.count("cancelAttachTimeout();") != 1
            or attach.count('log("READY"') != 1
            or attach.count('log("ATTACH_REPLAY"') != 1):
        raise InspectionError("attach READY/replay phase reporting is not exact")
    placement_start = source.find("if (ACTION_PLACE_FULL.equals(action)", attach_end)
    close_start = source.find("if (ACTION_BEGIN_CLOSE.equals(action))", placement_start)
    destroy_start = source.find("if (ACTION_ACK_DESTROYED.equals(action))", close_start)
    empty_start = source.find("if (ACTION_ACK_NO_FOREIGN.equals(action))", destroy_start)
    command_end = source.find("private static final class CommandEnvelope", empty_start)
    if min(placement_start, close_start, destroy_start, empty_start, command_end) < 0:
        raise InspectionError("authenticated command blocks are incomplete")
    placement = source[placement_start:close_start]
    placement_replay = placement.find("if (result == CommandResult.IDEMPOTENT)")
    if placement.find("if (result == CommandResult.ACCEPTED)") < 0 \
            or placement_replay < 0 or 'log("PLACEMENT_REPLAY"' not in placement \
            or placement.count("layoutSurface();") != 1 \
            or "layoutSurface();" in placement[placement_replay:]:
        raise InspectionError("placement replay can restart or misreport a fresh placement")
    close = source[close_start:destroy_start]
    close_accepted = close.find("if (result == CommandResult.ACCEPTED)")
    close_ready = close.find("lifecycle.canPublishFreshCloseWait()")
    close_cancel = close.find("cancelPlacementTimeout();")
    close_arm = close.find("armDestroyTimeout(envelope.generation);")
    close_wait = close.find('log("WAIT_FOREIGN_DESTROY"')
    close_idempotent = close.find("if (result == CommandResult.IDEMPOTENT)")
    close_replay = close.find('log("CLOSE_REPLAY"')
    if min(close_accepted, close_ready, close_cancel, close_arm, close_wait,
           close_idempotent, close_replay) < 0 \
            or not (close_accepted < close_ready < close_cancel < close_arm < close_wait
                    < close_idempotent < close_replay) \
            or close.count("cancelPlacementTimeout();") != 1 \
            or close.count("armDestroyTimeout(envelope.generation);") != 1 \
            or close.count('log("WAIT_FOREIGN_DESTROY"') != 1 \
            or any(value in close[close_idempotent:] for value in (
                "cancelPlacementTimeout();", "armDestroyTimeout(envelope.generation);",
                'log("WAIT_FOREIGN_DESTROY"')):
        raise InspectionError("BEGIN_CLOSE fresh/replay phase reporting is not exact")
    pre_attach_abort_start = source.find(
            "if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action))", destroy_start)
    if pre_attach_abort_start < 0 or pre_attach_abort_start > empty_start:
        raise InspectionError("healthy pre-attach abort command block is missing")
    destroy = source[destroy_start:pre_attach_abort_start]
    destroy_idempotent = destroy.find("if (result == CommandResult.IDEMPOTENT)")
    if destroy_idempotent < 0 or 'log("DESTROY_REPLAY"' not in destroy \
            or destroy.count("cancelDestroyTimeout();") != 1 \
            or "cancelDestroyTimeout();" in destroy[destroy_idempotent:] \
            or destroy.count("releaseNormally()") != 2:
        raise InspectionError("destroy replay cannot retain exact release-retry authority")
    pre_attach_abort = source[pre_attach_abort_start:empty_start]
    exact_pre_attach_abort = (
        "if (ACTION_ACK_NO_FOREIGN_PRE_ATTACH_ABORT.equals(action)) {\n"
        "            String evidence = exactString(envelope.extras, EXTRA_ABSENCE_EVIDENCE);\n"
        "            CommandResult result = lifecycle.acknowledgeNoForeignPreAttachAbort(\n"
        "                    envelope.capability, envelope.generation, envelope.displayId,\n"
        "                    envelope.sequence, evidence);\n"
        "            if (result == CommandResult.ACCEPTED) {\n"
        "                log(\"EMPTY_PRE_ATTACH_ABORT\", \"absenceEvidenceSha256=\" + scrub(evidence));\n"
        "                if (releaseNormally()) finishAndRemoveTask();\n"
        "                return;\n"
        "            }\n"
        "            if (result == CommandResult.IDEMPOTENT) {\n"
        "                log(\"EMPTY_PRE_ATTACH_ABORT_REPLAY\", \"state=\" + lifecycle.state().name()\n"
        "                        + \" freshAbort=false releaseRetry=\" + lifecycle.canReleaseNormally()\n"
        "                        + \" failureSticky=\" + lifecycle.isFailed());\n"
        "                if (!lifecycle.displayRemoved() && releaseNormally()) finishAndRemoveTask();\n"
        "                return;\n"
        "            }\n"
        "            rejectAlreadyFailed(\"healthy pre-attach abort rejected\");\n"
        "            return;\n"
        "        }"
    )
    exact_evidence_read = (
        "String evidence = exactString(envelope.extras, EXTRA_ABSENCE_EVIDENCE);"
    )
    pre_attach_accepted = pre_attach_abort.find("if (result == CommandResult.ACCEPTED)")
    pre_attach_log = pre_attach_abort.find('log("EMPTY_PRE_ATTACH_ABORT"')
    pre_attach_release = pre_attach_abort.find(
            "if (releaseNormally()) finishAndRemoveTask();")
    pre_attach_return = pre_attach_abort.find("return;", pre_attach_release)
    pre_attach_idempotent = pre_attach_abort.find(
            "if (result == CommandResult.IDEMPOTENT)")
    pre_attach_replay_log = pre_attach_abort.find('log("EMPTY_PRE_ATTACH_ABORT_REPLAY"')
    pre_attach_replay_release = pre_attach_abort.find(
            "if (!lifecycle.displayRemoved() && releaseNormally()) finishAndRemoveTask();")
    pre_attach_replay_return = pre_attach_abort.find("return;", pre_attach_replay_release)
    if (min(pre_attach_accepted, pre_attach_log, pre_attach_release, pre_attach_return,
            pre_attach_idempotent, pre_attach_replay_log, pre_attach_replay_release,
            pre_attach_replay_return) < 0
            or not (pre_attach_accepted < pre_attach_log < pre_attach_release
                    < pre_attach_return < pre_attach_idempotent < pre_attach_replay_log
                    < pre_attach_replay_release < pre_attach_replay_return)
            or pre_attach_abort.count("acknowledgeNoForeignPreAttachAbort(") != 1
            or pre_attach_abort.count(exact_evidence_read) != 1
            or pre_attach_abort.count("releaseNormally()") != 2
            or pre_attach_abort.count("finishAndRemoveTask()") != 2
            or pre_attach_abort.count("lifecycle.displayRemoved()") != 1
            or pre_attach_abort.count('log("EMPTY_PRE_ATTACH_ABORT",') != 1
            or pre_attach_abort.count('log("EMPTY_PRE_ATTACH_ABORT_REPLAY",') != 1
            or pre_attach_abort.rstrip() != exact_pre_attach_abort
            or any(forbidden in pre_attach_abort for forbidden in (
                    "acknowledgeNoForeignAfterFailure(", "lifecycle.onProtocolFailure(",
                    "releaseForUnexpectedLoss(", "verifyRuntimeAuthorityOrFail(",
                    'log("READY"', "readiness=ACTIVE"))):
        raise InspectionError(
                "healthy pre-attach abort fresh/replay release semantics are not exact")
    empty = source[empty_start:command_end]
    empty_idempotent = empty.find("if (result == CommandResult.IDEMPOTENT)")
    if empty_idempotent < 0 or 'log("EMPTY_ABORT_REPLAY"' not in empty \
            or empty.count("releaseNormally()") != 2 \
            or "acknowledgeNoForeignPreAttachAbort(" in empty:
        raise InspectionError("empty-abort replay cannot retain exact release-retry authority")


def validate_lifecycle_source(payload: bytes) -> None:
    try:
        source = payload.decode("utf-8")
    except UnicodeError as error:
        raise InspectionError("lifecycle source is not UTF-8") from error
    required = (
        'REQUIRED_FOREIGN_PACKAGE = "com.supernote.document"',
        "REQUIRED_FOREIGN_COMPONENT",
        'com.supernote.document/com.supernote.document.document.DocumentActivity',
        "uid != 1000",
        'verificationSha256.matches("[0-9a-f]{64}")',
        "MessageDigest.isEqual(",
        "acknowledgeForeignAttached(",
        "canPublishFreshAttachReady(",
        "canPublishFreshCloseWait(",
        "authorizePlacement(",
        "acknowledgeForeignDestroyed(",
        "onUnexpectedHostLoss(",
        "normalReleaseAuthorized",
        "emergencyReleaseRequired",
        "commandEnvelopeMatches(",
        "REQUIRED_PHYSICAL_DISPLAY_ID = 0",
        "admitHostAuthority(",
        "revalidatePreAllocationHostAuthority(",
        "onHostAuthority(",
        "suspendHostAuthority(",
        "canDeferFreshCommand(",
        "reserveDeferredCommand(",
        "consumeDeferredCommand(",
        "DEFER_ATTACH", "DEFER_PLACE_FULL", "DEFER_PLACE_LEFT",
        "DEFER_PLACE_RIGHT", "DEFER_BEGIN_CLOSE", "DEFER_ACK_DESTROYED",
        "hostAuthoritySuspended",
        "hostAuthorityDeadlineElapsed",
        "hasHostAuthorityTransition(",
        "completeHostAuthorityTransition(",
        "DISPLAY_ALLOCATED",
        "onDisplayAllocated(",
        "onVirtualDisplayMetrics(",
        "acknowledgeNoForeignAfterFailure(",
        "acknowledgeNoForeignPreAttachAbort(",
        "onPhysicalFrameMeasured(",
        "onPlacementTimeout(",
        "onReleaseAttemptFailed(",
        "retainsPhysicalHostAuthority(",
        "retainedDisplayCleanupAddressable(",
        "PLACEMENT_PENDING",
        "pendingPlacementSequence",
        "lastCommandSequence",
        "destroyAcknowledgmentEligible",
        "emptyFailureCleanupAuthorized",
        "emptyPreAttachAbortAuthorized",
        "canFinishWithoutCleanup(",
        "UNAUTHENTICATED_OR_STALE",
    )
    for value in required:
        if value not in source:
            raise InspectionError(f"missing lifecycle safety invariant: {value}")
    pre_attach_start = source.find(
            "public CommandResult acknowledgeNoForeignPreAttachAbort(")
    failed_empty_start = source.find(
            "public CommandResult acknowledgeNoForeignAfterFailure(", pre_attach_start)
    timeout_start = source.find("public boolean onAttachTimeout(", failed_empty_start)
    if min(pre_attach_start, failed_empty_start, timeout_start) < 0:
        raise InspectionError("pre-attach abort lifecycle topology is incomplete")
    pre_attach = source[pre_attach_start:failed_empty_start]
    authorize_at = pre_attach.find(
            "if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();")
    body_open = pre_attach.find(") {")
    key_at = pre_attach.find(
            'String key = "PRE_ATTACH_ABORT|" + String.valueOf(absenceEvidenceSha256);')
    classify_at = pre_attach.find(
            "CommandResult replay = classifySequence(commandSequence, key);")
    replay_at = pre_attach.find("if (replay != null) return replay;")
    eligibility_at = pre_attach.find(
            "if (failure != null || foreignTask != null || deferredCommandKey != null")
    display_allocated_at = pre_attach.find("state != State.DISPLAY_ALLOCATED", eligibility_at)
    waiting_at = pre_attach.find("state != State.WAITING_FOR_FOREIGN_ATTACH", eligibility_at)
    addressable_at = pre_attach.find(
            "!retainedDisplayCleanupAddressable(commandDisplayId)", eligibility_at)
    evidence_null_at = pre_attach.find(
            "absenceEvidenceSha256 == null", eligibility_at)
    evidence_at = pre_attach.find(
            '!absenceEvidenceSha256.matches("[0-9a-f]{64}")', eligibility_at)
    authorize_release_at = pre_attach.find("emptyPreAttachAbortAuthorized = true;")
    state_at = pre_attach.find("state = State.RELEASE_AUTHORIZED;", authorize_release_at)
    commit_at = pre_attach.find("return commit(commandSequence, key);", state_at)
    before_authorize = pre_attach[body_open + len(") {"):authorize_at]
    before_classify = pre_attach[
            authorize_at + len(
                "if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();"):
            classify_at]
    exact_classify_replay = (
        "CommandResult replay = classifySequence(commandSequence, key);\n"
        "        if (replay != null) return replay;"
    )
    exact_pre_attach_prefix = (
        "public CommandResult acknowledgeNoForeignPreAttachAbort(String capability,\n"
        "            long commandGeneration, int commandDisplayId, long commandSequence,\n"
        "            String absenceEvidenceSha256) {\n"
        "        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();\n"
        "        String key = \"PRE_ATTACH_ABORT|\" + String.valueOf(absenceEvidenceSha256);\n"
        "        // An exact accepted replay remains release-retry authority even if the\n"
        "        // first release attempt failed. Fresh commands still require health.\n"
        "        CommandResult replay = classifySequence(commandSequence, key);\n"
        "        if (replay != null) return replay;"
    )
    if (min(body_open, authorize_at, key_at, classify_at, replay_at, eligibility_at,
            display_allocated_at, waiting_at, addressable_at, evidence_at,
            evidence_null_at, authorize_release_at, state_at, commit_at) < 0
            or before_authorize.strip()
            or any(forbidden in before_classify for forbidden in (
                    "if (", "failure", "foreignTask", "deferredCommandKey", "state",
                    "return", "contradiction(", "fail("))
            or pre_attach.count(exact_classify_replay) != 1
            or not pre_attach.startswith(exact_pre_attach_prefix)
            or not (authorize_at < key_at < classify_at < replay_at < eligibility_at
                    < display_allocated_at < waiting_at < addressable_at
                    < evidence_null_at < evidence_at
                    < authorize_release_at < state_at < commit_at)
            or pre_attach.count("classifySequence(commandSequence, key)") != 1
            or pre_attach.count("emptyPreAttachAbortAuthorized = true;") != 1
            or any(forbidden in pre_attach for forbidden in (
                    "emptyFailureCleanupAuthorized = true;", "normalReleaseAuthorized = true;",
                    "foreignTask =", "fail("))):
        raise InspectionError(
                "healthy pre-attach abort lifecycle authority/order changed")
    failed_empty = source[failed_empty_start:timeout_start]
    exact_failed_empty = (
        "public CommandResult acknowledgeNoForeignAfterFailure(String capability,\n"
        "            long commandGeneration, int commandDisplayId, long commandSequence,\n"
        "            String verificationSha256) {\n"
        "        if (!authorize(capability, commandGeneration, commandDisplayId)) return stale();\n"
        "        String key = \"NO_FOREIGN|\" + String.valueOf(verificationSha256);\n"
        "        CommandResult replay = classifySequence(commandSequence, key);\n"
        "        if (replay != null) return replay;\n"
        "        if (failure == null || state != State.FAILED || foreignTask != null\n"
        "                || emptyPreAttachAbortAuthorized\n"
        "                || verificationSha256 == null\n"
        "                || !verificationSha256.matches(\"[0-9a-f]{64}\")) {\n"
        "            return contradiction(\"empty failed-session cleanup lacked exact absence authority\");\n"
        "        }\n"
        "        emptyFailureCleanupAuthorized = true;\n"
        "        state = State.RELEASE_AUTHORIZED;\n"
        "        return commit(commandSequence, key);\n"
        "    }\n\n    "
    )
    if (failed_empty != exact_failed_empty
            or source.count("emptyFailureCleanupAuthorized") != 3):
        raise InspectionError(
                "legacy failure cleanup authority/order changed")
    release_policy_start = source.find("public boolean canReleaseNormally()")
    release_policy_end = source.find("public boolean mustReleaseForHostLoss()", release_policy_start)
    release_policy = source[release_policy_start:release_policy_end]
    if (release_policy.count("emptyPreAttachAbortAuthorized") != 1
            or "return normalReleaseAuthorized || emptyFailureCleanupAuthorized\n"
               "                || emptyPreAttachAbortAuthorized;" not in release_policy
            or "emptyPreAttachAbortAuthorized = false" in source
            or source.count("emptyPreAttachAbortAuthorized = true;") != 1):
        raise InspectionError("healthy pre-attach abort is not exact normal-release authority")


def validate_layout_source(payload: bytes) -> None:
    try:
        source = payload.decode("utf-8")
    except UnicodeError as error:
        raise InspectionError("layout source is not UTF-8") from error
    required = (
        "public final class DisplayProbeLayout",
        "public static final int BUFFER_WIDTH = 1404;",
        "public static final int BUFFER_HEIGHT = 1872;",
        "public enum Placement { FULL, LEFT, RIGHT }",
        "public boolean exactlyMatches(",
        "Placement placement = hostWidth > hostHeight ? requested : Placement.FULL;",
        "int unit = Math.min(slotWidth / 3, hostHeight / 4);",
        "return new DisplayProbeLayout(slotLeft + (slotWidth - width) / 2,",
    )
    for value in required:
        if value not in source:
            raise InspectionError(f"missing layout authority invariant: {value}")
    if source.count("class DisplayProbeLayout") != 1 or source.count("enum Placement") != 1:
        raise InspectionError("layout class topology changed")


def validate_lifecycle_test_source(payload: bytes) -> None:
    try:
        source = payload.decode("utf-8")
    except UnicodeError as error:
        raise InspectionError("lifecycle test source is not UTF-8") from error
    required = (
        "normal.acknowledgeForeignAttached(",
        "normal.canPublishFreshAttachReady()",
        "replayDuringPlacement", "State.PLACEMENT_PENDING",
        "replayWhileClosing", "State.WAITING_FOR_FOREIGN_DESTROY",
        "replayReleaseAuthorized", "State.RELEASE_AUTHORIZED",
        "replayAfterReleaseFailure", "onReleaseAttemptFailed(false, \"injected\")",
        "replayWhileStickyFailed", "replayWhileStickyFailed.failure()",
        "CommandResult.IDEMPOTENT", "!replayDuringPlacement.canPublishFreshAttachReady()",
        "closeReplayWaiting", "canPublishFreshCloseWait()",
        "injected-close-replay", "State.RELEASE_AUTHORIZED",
        "closeReplayCannotBecomeNewClose", "injected-new-close",
        "closeSequenceEquivocation",
        "deferredAttach", "deferredPlace", "deferredClose", "deferredDestroy",
        "persistentPause", "duplicatePause", "persistentGeometryChurn",
        "deferredPlacementKinds",
        "hostAuthorityDeadlineElapsed()", "completeHostAuthorityTransition(",
        "duplicateDeferred", "equivocatedDeferred", "directDeferredBypass",
        "directDeferredPlaceBypass", "directDeferredCloseBypass",
        "directDeferredDestroyBypass", "wrongDeferredConsumption",
        "attachReplayDuringPause", "closeReplayDuringPause", "invalidDeferredPhase",
        "placementReplayDuringPause", "destroyReplayDuringPause",
        "failedDeferredDestroy", "contradictionCleanupThroughPause",
        "attachTimeoutCleanupThroughPause", "destroyTimeoutCleanupThroughPause",
        "retainsPhysicalHostAuthority", "metricsException", "preIdReleaseFailure",
        "State.DISPLAY_ALLOCATED", "freshStartup", "preallocationNoFrame",
        "invalidPreallocationAuthority", "preallocationWrongState",
        "revalidatePreAllocationHostAuthority(",
        "healthyPreAttachAbort", "pausedPreAttachAbort",
        "preAttachAbortReleaseFailure", "unauthenticatedPreAttachAbort",
        "invalidPreAttachEvidence", "preAttachAbortSequenceGap",
        "preAttachAbortEquivocation", "failedEmptyAbortEquivocation",
        "attachedPreAttachAbort", "deferredPreAttachAbort",
        "preAttachAbortNotDeferrable", "failedPreAttachAbort",
        "unallocatedPreAttachAbort", "acknowledgeNoForeignPreAttachAbort(",
        "testHealthyPreAttachAbort();",
    )
    for value in required:
        if value not in source:
            raise InspectionError("attach replay lifecycle regression is missing: " + value)


def validate_build_script_source(payload: bytes) -> None:
    try:
        source = payload.decode("utf-8")
    except UnicodeError as error:
        raise InspectionError("build script is not UTF-8") from error
    required = (
        "ConvertTo-CanonicalEvidenceUtf8", "Invoke-JavapCanonicalEvidence",
        "CanonicalTextPolicySelfTestOutput", "UTF8Encoding]::new($false,$true)",
        "contains a UTF-8 BOM", "contains an embedded NUL", "contains a lone CR",
        "mixes LF and CRLF newlines", "StandardOutput.BaseStream.CopyToAsync",
        "StandardError.BaseStream.CopyToAsync", "activityBytecodeBytes",
        "lifecycleBytecodeBytes", "layoutBytecodeBytes", "--lifecycle-bytecode",
        "lifecycle-bytecode.txt",
        "Write-LockedSnapshot", "-J-Dfile.encoding=UTF-8",
        "CANONICAL_TEXT_POLICY_V1", "YWxwaGEKzrIK",
        "4cce75f4e4dcdd0119627d7674ef7747a4634666bcb9b13e29cf0e4742ad9803",
        "forbiddenInheritedEnvironment", "StartsWith('PYTHON'",
        "pythonIsolatedBootstrap", "-I','-S','-B','-c",
        "flags.isolated == 1", "flags.no_site == 1",
        "flags.ignore_environment == 1", "flags.dont_write_bytecode == 1",
        "runpy.__spec__.origin != 'frozen'",
        "sys.meta_path=[frozen_importlib.BuiltinImporter",
        "sys.path=[]", "sys.path_hooks=[]", "sys.addaudithook(runtime_audit)",
        "actual_directories != {relative_key(value) for value in expected_directories}",
        "python runtime namespace differed from retained inventory",
        "unreviewed python runtime/review-root open rejected",
        "unreviewed python import origin rejected",
        "python runtime/review-root mutation rejected",
        "pythonRuntimeAuthority='private-retained-namespace-audit-v2'",
        "reviewedPythonRuntimeFileCount=783",
        "reviewedPythonRuntimeDirectoryCount=55",
        "reviewedPythonRuntimeRecordCount=838",
        "reviewedPythonRuntimeInventorySha256='3aa15c911493f4107b5860a9bccd9107781fe63efb56e07f83a72078c6d49f57'",
        "Get-ReviewedPythonRuntimeFiles", "Copy-LockedPythonRuntimeFile",
        "New-PythonBootstrapZipBytes", "python-bootstrap.zip", "python312._pth",
        "Raw ZIP_STORED writer", "$entryNames.Sort([StringComparer]::Ordinal)",
        "ExactSourceLoader", "ExactAuthorityFinder",
        "reviewed Python helper bytes differed before compilation",
        "reviewed Python entry script bytes differed before compilation",
        "frozen_importlib_external.ExtensionFileLoader",
        "Assert-ReviewedPythonRuntimeAuthority",
        "Assert-ReviewedPythonHelperAuthority",
        "Invoke-PythonHelperAuthorityMutationSelfTest",
        "Changed retained Python helper admitted before launch",
        "Changed inline Python bootstrap admitted before launch",
        "reviewedPythonHelperSha256", "reviewedPythonBootstrapSha256",
        "powershell5Launcher", "powershell7Launcher",
        "parsedBuildPolicyText=$MyInvocation.MyCommand.ScriptBlock.ToString()",
        "Retained build policy differs from the caller-reviewed parsed root",
        "powershell-engines/windows-powershell-5.1/powershell.exe",
        "Private Windows PowerShell 5.1 launcher differs from reviewed authority",
        "Invoke-PythonRuntimeAuthorityMutationSelfTest",
        "Private Python runtime contains an unretained file",
        "Private Python runtime admitted an unretained package-shadow directory",
        "Private Python runtime admitted a directory reparse point",
        "Private Python runtime retained handle admitted a writer",
        "$pythonVersion='Python 3.12.14'",
        "reviewedProductionClassSha256", "reviewedTestClassSha256",
        "reviewedDexSha256", "reviewedApkSha256", "Assert-ReviewedFileSet",
        "Invoke-ReviewedPythonCaptured", "native-page-host-evidence-bundle-v1",
        "Write-ToRetainedAuthority", "bundled authority digest differed",
    )
    for value in required:
        if value not in source:
            raise InspectionError("canonical build evidence policy is missing: " + value)
    if "Out-File" in source or "-Encoding utf8" in source:
        raise InspectionError("build uses engine-dependent PowerShell text serialization")
    if "\r" in source:
        raise InspectionError("build script authority must use LF-only source bytes")
    helper_start = source.find("$reviewedPythonHelperSha256=")
    helper_end = source.find("$reviewedPythonBootstrapSha256=", helper_start)
    helper_block = source[helper_start:helper_end]
    helper_records = dict(re.findall(
        r"^\s*'([^']+)'='([0-9a-f]{64})'\s*$", helper_block, re.MULTILINE))
    expected_helper_paths = {
        "canonicalize_apk.py": Path(__file__).resolve().parent / "canonicalize_apk.py",
        "inspect_native_page_host.py": Path(__file__).resolve().parent / "inspect_native_page_host.py",
        "test_native_page_host_package.py":
            Path(__file__).resolve().parent / "test_native_page_host_package.py",
    }
    actual_helper_records = {
        name: sha256(path.read_bytes()) for name, path in expected_helper_paths.items()}
    if helper_records != actual_helper_records:
        raise InspectionError("fixed pre-execution Python helper authority changed")
    bootstrap_match = re.search(
        r"\$pythonIsolatedBootstrap=@'\n(?P<body>.*?)\n'@\n", source, re.DOTALL)
    bootstrap_records = re.findall(
        r"\$reviewedPythonBootstrapSha256='([0-9a-f]{64})'", source)
    if (bootstrap_match is None or len(bootstrap_records) != 1
            or sha256(bootstrap_match.group("body").encode("utf-8"))
                != bootstrap_records[0]):
        raise InspectionError("fixed Python bootstrap authority changed")
    zip_writer = source[source.find("function New-PythonBootstrapZipBytes"):
                        source.find("function Get-ReviewedPythonRuntimeFiles")]
    if "Sort-Object" in zip_writer:
        raise InspectionError("bootstrap ZIP entry ordering is culture-dependent")
    if re.search(r"&\s*\$Python\b", source):
        raise InspectionError("build executes the mutable original Python runtime")
    runtime_copy = source.find("$pythonRuntimeFiles=Get-ReviewedPythonRuntimeFiles")
    helper_copy = max(source.find(
        "Copy-LockedSnapshot $canonicalizer 'native-page-host/canonicalize_apk.py'"),
        source.find(
            "Copy-LockedSnapshot $inspector 'native-page-host/inspect_native_page_host.py'"),
        source.find(
            "Copy-LockedSnapshot $packageTests 'native-page-host/test_native_page_host_package.py'"))
    helper_admission = source.find("Assert-ReviewedPythonHelperAuthority", helper_copy)
    helper_mutation_test = source.find("Invoke-PythonHelperAuthorityMutationSelfTest",
                                      helper_admission)
    runtime_admission = source.find("Assert-ReviewedPythonRuntimeAuthority", runtime_copy)
    runtime_inventory = source.find(
        "$pythonRuntimeInventoryPath=Write-LockedSnapshot", runtime_admission)
    version_admission = source.find("$pythonVersion='Python 3.12.14'", runtime_copy)
    first_reviewed_invocation = source.find(
        "Invoke-ReviewedPython $packageTests", runtime_copy)
    if min(helper_copy, helper_admission, helper_mutation_test, runtime_copy, runtime_admission,
           runtime_inventory, version_admission,
           first_reviewed_invocation) < 0 \
            or not (helper_copy < helper_admission < helper_mutation_test < runtime_copy
                    < runtime_admission < runtime_inventory
                    < version_admission < first_reviewed_invocation):
        raise InspectionError("private Python executes before full runtime admission")
    invoke_body = source[source.find("function Invoke-ReviewedPython("):
                         source.find("function Invoke-JavapCanonicalEvidence(")]
    if invoke_body.count("Assert-ReviewedPythonHelperAuthority") < 4:
        raise InspectionError("reviewed Python helper authority is not rechecked per launch")
    if "--evidence-dir" in source:
        raise InspectionError("build reopens inspector-created evidence paths")
    if "PENDING_" in source or len(re.findall(
            r"\$reviewed(?:Dex|Apk)Sha256='[0-9a-f]{64}'", source)) != 2:
        raise InspectionError("fixed reviewed output authority is not concrete")
    source_block = source[source.find("$reviewedSourceSha256="):
                          source.find("$reviewedProductionClassSha256=")]
    production_block = source[source.find("$reviewedProductionClassSha256="):
                              source.find("$reviewedTestClassSha256=")]
    test_block = source[source.find("$reviewedTestClassSha256="):
                        source.find("$reviewedDexSha256=")]
    source_records = dict(re.findall(
        r"^\s*([A-Za-z][A-Za-z0-9]*)='([0-9a-f]{64})'\s*$", source_block, re.MULTILINE))
    production_records = dict(re.findall(
        r"^\s*'([^']+)'='([0-9a-f]{64})'\s*$", production_block, re.MULTILINE))
    test_records = dict(re.findall(
        r"^\s*'([^']+)'='([0-9a-f]{64})'\s*$", test_block, re.MULTILINE))
    dex_record = re.findall(r"\$reviewedDexSha256='([0-9a-f]{64})'", source)
    apk_record = re.findall(r"\$reviewedApkSha256='([0-9a-f]{64})'", source)
    if (source_records != REVIEWED_BUILD_SOURCE_SHA256
            or production_records != REVIEWED_PRODUCTION_CLASS_SHA256
            or test_records != REVIEWED_TEST_CLASS_SHA256
            or dex_record != [REVIEWED_DEX_SHA256]
            or apk_record != [REVIEWED_APK_SHA256]):
        raise InspectionError("fixed reviewed compiler-output authority changed")
    order = (
        source.find("Assert-ReviewedFileSet $testClasses"),
        source.find("Copy-LockedSnapshot $testClass.FullName"),
        source.find("Assert-ReviewedFileSet $classesRaw"),
        source.find("$classFiles += Copy-LockedSnapshot $classFile.FullName"),
        source.find("Assert-PinnedHash (Join-Path $dexRaw 'classes.dex')"),
        source.find("Copy-LockedSnapshot (Join-Path $dexRaw 'classes.dex')"),
        source.find("Assert-PinnedHash $alignedRaw $reviewedApkSha256"),
        source.find("Copy-ToRetainedAuthority $alignedRaw"),
        source.find("Invoke-ReviewedPythonCaptured $inspector"),
        source.find("Write-ToRetainedAuthority (Join-Path $evidence $evidenceName)"),
    )
    if min(order) < 0 or not (order[0] < order[1] and order[2] < order[3]
                              and order[4] < order[5] and order[6] < order[7]
                              and order[8] < order[9]):
        raise InspectionError("raw output/evidence authority ordering changed")


def validate_canonical_text_evidence(payload: bytes, label: str) -> str:
    if payload.startswith(b"\xef\xbb\xbf") or b"\x00" in payload or b"\r" in payload \
            or not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise InspectionError(f"{label} violates canonical UTF-8/LF byte policy")
    try:
        return payload.decode("utf-8")
    except UnicodeError as error:
        raise InspectionError(f"{label} is not strict UTF-8") from error


def bytecode_method(text: str, signature: str) -> str:
    lines = text.splitlines(keepends=True)
    declarations = [
        index for index, line in enumerate(lines)
        if (line.startswith("  ") and not line.startswith("    ")
            and (re.fullmatch(r"  static \{\};\r?\n?", line) is not None
                 or ("(" in line and re.fullmatch(r"  [^\r\n]+\);\r?\n?", line)
                     is not None)))
    ]
    matches = [
        index for index in declarations
        if lines[index].strip().endswith(signature)
    ]
    if len(matches) != 1:
        raise InspectionError(f"bytecode method missing: {signature}")
    start = matches[0]
    following = next((index for index in declarations if index > start), len(lines))
    return "".join(lines[start:following])


def bytecode_instructions(method: str) -> list[tuple[int, str, str]]:
    instructions: list[tuple[int, str, str]] = []
    for line in method.splitlines():
        match = re.fullmatch(r"\s*(\d+):\s+([a-z][a-z0-9_]*)\s*(.*?)\s*", line)
        if match is not None:
            instructions.append((int(match.group(1)), match.group(2), match.group(3)))
    offsets = [offset for offset, _, _ in instructions]
    if (not instructions or len(set(offsets)) != len(instructions)
            or any(current <= previous for previous, current in zip(offsets, offsets[1:]))):
        raise InspectionError("bytecode instruction topology changed")
    instruction_offsets = set(offsets)
    for instruction in instructions:
        opcode = instruction[1]
        if opcode.startswith("if") or opcode in {"goto", "goto_w", "jsr", "jsr_w"}:
            target = bytecode_branch_target(instruction, "instruction topology")
            if target not in instruction_offsets:
                raise InspectionError("bytecode branch target is outside the method")
    return instructions


def validate_exact_javap_topology(payload: bytes, label: str, reviewed_sha256: str,
                                  test_sha256: str, allow_test_fixture: bool) -> None:
    accepted = {reviewed_sha256}
    if allow_test_fixture:
        accepted.add(test_sha256)
    if sha256(payload) not in accepted:
        raise InspectionError(f"{label} exact complete topology changed")


def bytecode_unique_index(instructions: list[tuple[int, str, str]], marker: str,
                          label: str) -> int:
    matches = [index for index, (_, _, operand) in enumerate(instructions)
               if marker in operand]
    if len(matches) != 1:
        raise InspectionError(f"{label} bytecode marker is not unique: {marker}")
    return matches[0]


def bytecode_branch_target(instruction: tuple[int, str, str], label: str) -> int:
    match = re.match(r"(-?\d+)\b", instruction[2])
    if match is None:
        raise InspectionError(f"{label} bytecode branch target is malformed")
    return int(match.group(1))


def bytecode_control_ops(instructions: list[tuple[int, str, str]]) -> list[
        tuple[int, str, str]]:
    return [instruction for instruction in instructions
            if (instruction[1].startswith("if") or instruction[1] in {
                "goto", "goto_w", "return", "ireturn", "lreturn", "freturn",
                "dreturn", "areturn", "athrow", "tableswitch", "lookupswitch"})]


def validate_activity_bytecode(payload: bytes, *, allow_test_fixture: bool = False) -> None:
    text = validate_canonical_text_evidence(payload, "activity bytecode evidence")
    touch = bytecode_method(text, "dispatchTouchEvent(android.view.MotionEvent);")
    swallow = (r"MotionEvent\.getToolType.*?iconst_2\s+.*?if_icmpeq\s+\d+"
               r".*?iconst_4\s+.*?if_icmpne\s+\d+.*?STYLUS_SWALLOWED"
               r".*?iconst_1\s+.*?ireturn")
    if re.search(swallow, touch, re.DOTALL) is None:
        raise InspectionError("stylus/eraser swallow branch missing from bytecode")
    create = bytecode_method(text, "maybeCreateVirtualDisplay();")
    for marker in ("sipush        1404", "sipush        1872", "sipush        265",
                   "DisplayManager.createVirtualDisplay", "onDisplayAllocated",
                   "onDisplayCreated",
                   "VirtualDisplay.getDisplay", "Display.getDisplayId",
                   "virtualDisplayMetrics", "verifyPreAllocationHostAuthorityOrFail",
                   "verifyPhysicalFrameOrFail", "beginDisplayCreation"):
        if marker not in create:
            raise InspectionError("fixed display semantics missing from bytecode: " + marker)
    if create.count("Display.getDisplayId") != 1:
        raise InspectionError("allocated display ID is not read exactly once in bytecode")
    on_create = bytecode_method(text, "onCreate(android.os.Bundle);")
    for marker in ("SurfaceHolder.setFixedSize", "sipush        1404", "sipush        1872",
                   "finishAndRemoveTask"):
        if marker not in on_create:
            raise InspectionError("fixed host admission missing from bytecode: " + marker)
    command = bytecode_method(text, "onNewIntent(android.content.Intent);")
    command_processor = bytecode_method(text,
        "processAuthenticatedCommand(com.techrebbe.supernote.nativepagehost.NativePageHostActivity$CommandEnvelope, com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle$ForeignTaskIdentity);")
    admission_calls = ("commandEnvelopeMatches", "hostAuthoritySuspended",
                        "canDeferFreshCommand", "deferAuthenticatedCommand",
                        "verifyRuntimeAuthorityOrFail", "processAuthenticatedCommand")
    if any(marker not in command for marker in admission_calls):
        raise InspectionError("authenticated command admission missing from bytecode")
    envelope_auth = command.find("commandEnvelopeMatches")
    pre_attach_abort_action = command.find("ACK_NO_FOREIGN_PRE_ATTACH_ABORT", envelope_auth)
    pre_attach_abort_process = command.find(
            "processAuthenticatedCommand", pre_attach_abort_action)
    defer_call = command.find("deferAuthenticatedCommand", pre_attach_abort_process)
    runtime_verify = command.find("verifyRuntimeAuthorityOrFail", defer_call)
    ordinary_process = command.rfind("processAuthenticatedCommand")
    if (min(envelope_auth, pre_attach_abort_action, pre_attach_abort_process,
            defer_call, runtime_verify, ordinary_process) < 0
            or command.count("processAuthenticatedCommand") != 2
            or not (envelope_auth < pre_attach_abort_action < pre_attach_abort_process
                    < defer_call < runtime_verify < ordinary_process)):
        raise InspectionError(
                "healthy pre-attach abort is not authenticated before its nondeferrable dispatch")
    command_instructions = bytecode_instructions(command)
    auth_call = bytecode_unique_index(
        command_instructions,
        "Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle."
        "commandEnvelopeMatches:(Ljava/lang/String;JIJ)Z",
        "authenticated command admission")
    auth_offset = command_instructions[auth_call][0]
    for instruction in bytecode_control_ops(command_instructions[:auth_call]):
        if instruction[1].startswith("if") or instruction[1] in {"goto", "goto_w"}:
            if bytecode_branch_target(instruction, "pre-authentication admission") > auth_offset:
                raise InspectionError("command control flow can skip envelope authentication")
    if (auth_call + 1 >= len(command_instructions)
            or command_instructions[auth_call + 1][1] != "ifne"):
        raise InspectionError("failed command authentication does not branch fail-closed")
    authenticated_offset = bytecode_branch_target(
        command_instructions[auth_call + 1], "command authentication")
    offset_to_index = {instruction[0]: index
                       for index, instruction in enumerate(command_instructions)}
    authenticated_index = offset_to_index.get(authenticated_offset, -1)
    if authenticated_index <= auth_call + 1:
        raise InspectionError("authenticated command target is not forward and exact")
    authentication_failure = command_instructions[auth_call + 2:authenticated_index]
    if (not authentication_failure
            or authentication_failure[-1][1] != "return"
            or [opcode for _, opcode, _ in bytecode_control_ops(authentication_failure)]
                != ["return"]
            or sum("reason=unauthenticated_or_stale action=" in operand
                   for _, _, operand in authentication_failure) != 1
            or sum("Method log:(Ljava/lang/String;Ljava/lang/String;)V" in operand
                   for _, _, operand in authentication_failure) != 1):
        raise InspectionError("failed command authentication can fall through")
    if "String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT" \
            not in command_instructions[authenticated_index][2]:
        raise InspectionError("healthy pre-attach dispatch does not immediately follow authentication")
    dispatch_equals = next((index for index in range(authenticated_index,
                                                     len(command_instructions))
                            if "Method java/lang/String.equals:(Ljava/lang/Object;)Z"
                            in command_instructions[index][2]), -1)
    if (dispatch_equals < 0 or dispatch_equals + 1 >= len(command_instructions)
            or command_instructions[dispatch_equals + 1][1] != "ifeq"):
        raise InspectionError("healthy pre-attach action comparison is not exact")
    ordinary_offset = bytecode_branch_target(
        command_instructions[dispatch_equals + 1], "healthy pre-attach dispatch")
    ordinary_index = offset_to_index.get(ordinary_offset, -1)
    process_marker = (
        "Method processAuthenticatedCommand:(Lcom/techrebbe/supernote/nativepagehost/"
        "NativePageHostActivity$CommandEnvelope;Lcom/techrebbe/supernote/viewportprobe/"
        "NativePageHostLifecycle$ForeignTaskIdentity;)V")
    dispatch_matches = [
        index for index in range(dispatch_equals + 2, max(dispatch_equals + 2,
                                                           ordinary_index))
        if process_marker in command_instructions[index][2]]
    dispatch_process = dispatch_matches[0] if len(dispatch_matches) == 1 else -1
    dispatch_body = command_instructions[dispatch_equals + 2:ordinary_index]
    if (ordinary_index <= dispatch_process
            or dispatch_process not in range(dispatch_equals + 2, ordinary_index)
            or not dispatch_body or dispatch_body[-1][1] != "return"
            or [opcode for _, opcode, _ in bytecode_control_ops(dispatch_body)] != ["return"]
            or sum("processAuthenticatedCommand:" in operand
                   for _, _, operand in dispatch_body) != 1):
        raise InspectionError("healthy pre-attach dispatch can fall through or be deferred")
    command_kind = bytecode_method(text, "deferredCommandKind(java.lang.String);")
    kind_patterns = (
        ("ACK_FOREIGN_ATTACHED", "iconst_1"),
        ("PLACE_FULL", "iconst_2"),
        ("PLACE_LEFT", "iconst_3"),
        ("PLACE_RIGHT", "iconst_4"),
        ("BEGIN_CLOSE", "iconst_5"),
        ("ACK_FOREIGN_DESTROYED", "bipush        6"),
    )
    cursor = 0
    for action, opcode in kind_patterns:
        action_at = command_kind.find(action, cursor)
        opcode_at = command_kind.find(opcode, action_at)
        if action_at < 0 or opcode_at < 0:
            raise InspectionError("deferred command kind mapping missing: " + action)
        cursor = opcode_at + len(opcode)
    if ("ACK_NO_FOREIGN_AFTER_FAILURE" in command_kind
            or "ACK_NO_FOREIGN_PRE_ATTACH_ABORT" in command_kind):
        raise InspectionError("empty-display cleanup must never be deferred")
    known = bytecode_method(text, "isKnownCommand(java.lang.String);")
    failure_cleanup = bytecode_method(text, "isCleanupCommand(java.lang.String);")
    if (known.count("ACK_NO_FOREIGN_PRE_ATTACH_ABORT") != 1
            or "ACK_NO_FOREIGN_PRE_ATTACH_ABORT" in failure_cleanup):
        raise InspectionError(
                "healthy pre-attach abort bytecode is not a distinct known command")
    required_calls = ("acknowledgeForeignAttached", "canPublishFreshAttachReady",
                       "canPublishFreshCloseWait", "authorizePlacement", "beginClose",
                       "acknowledgeForeignDestroyed", "acknowledgeNoForeignPreAttachAbort",
                       "cancelAttachTimeout",
                       "ATTACH_REPLAY", "PLACEMENT_REPLAY", "CLOSE_REPLAY",
                       "DESTROY_REPLAY", "EMPTY_PRE_ATTACH_ABORT",
                       "EMPTY_PRE_ATTACH_ABORT_REPLAY", "EMPTY_ABORT_REPLAY",
                       "WAIT_FOREIGN_DESTROY")
    if any(marker not in command_processor for marker in required_calls):
        raise InspectionError("authenticated command lifecycle missing from bytecode")
    if "parseForeignIdentity" not in command:
        raise InspectionError("foreign identity parsing missing from bytecode")
    if (command_processor.count("cancelAttachTimeout") != 1
            or command_processor.index("canPublishFreshAttachReady")
                > command_processor.index("cancelAttachTimeout")
            or command_processor.index("cancelAttachTimeout")
                > command_processor.index("ATTACH_REPLAY")):
        raise InspectionError("attach replay can publish or cancel the ACTIVE phase")
    if (command_processor.count("armDestroyTimeout") != 1
            or command_processor.count("WAIT_FOREIGN_DESTROY") != 1
            or command_processor.count("CLOSE_REPLAY") != 1
            or not (command_processor.index("canPublishFreshCloseWait")
                    < command_processor.index("armDestroyTimeout")
                    < command_processor.index("WAIT_FOREIGN_DESTROY")
                    < command_processor.index("CLOSE_REPLAY"))):
        raise InspectionError("close replay can publish or arm a fresh wait phase")
    pre_attach_start = command_processor.find("ACK_NO_FOREIGN_PRE_ATTACH_ABORT")
    legacy_empty_start = command_processor.find(
            "ACK_NO_FOREIGN_AFTER_FAILURE", pre_attach_start)
    if min(pre_attach_start, legacy_empty_start) < 0:
        raise InspectionError("healthy/failed empty-abort bytecode blocks are incomplete")
    pre_attach = command_processor[pre_attach_start:legacy_empty_start]
    evidence_at = pre_attach.find("exactString")
    lifecycle_at = pre_attach.find("acknowledgeNoForeignPreAttachAbort")
    accepted_at = pre_attach.find("CommandResult.ACCEPTED")
    accepted_log = pre_attach.find("EMPTY_PRE_ATTACH_ABORT", accepted_at)
    accepted_release = pre_attach.find("releaseNormally", accepted_log)
    accepted_finish = pre_attach.find("finishAndRemoveTask", accepted_release)
    idempotent_at = pre_attach.find("CommandResult.IDEMPOTENT", accepted_finish)
    replay_log = pre_attach.find("EMPTY_PRE_ATTACH_ABORT_REPLAY", idempotent_at)
    removed_guard = pre_attach.find("displayRemoved", replay_log)
    replay_release = pre_attach.find("releaseNormally", removed_guard)
    replay_finish = pre_attach.find("finishAndRemoveTask", replay_release)
    if (min(evidence_at, lifecycle_at, accepted_at, accepted_log, accepted_release,
            accepted_finish, idempotent_at, replay_log, removed_guard, replay_release,
            replay_finish) < 0
            or not (evidence_at < lifecycle_at < accepted_at < accepted_log
                    < accepted_release < accepted_finish < idempotent_at < replay_log
                    < removed_guard < replay_release < replay_finish)
            or pre_attach.count("acknowledgeNoForeignPreAttachAbort") != 1
            or pre_attach.count("releaseNormally") != 2
            or pre_attach.count("finishAndRemoveTask") != 2
            or pre_attach.count("displayRemoved") != 1
            or "acknowledgeNoForeignAfterFailure" in pre_attach):
        raise InspectionError(
                "healthy pre-attach abort bytecode fresh/replay release semantics are not exact")
    processor_instructions = bytecode_instructions(command_processor)
    processor_offsets = {instruction[0]: index
                         for index, instruction in enumerate(processor_instructions)}
    pre_action = bytecode_unique_index(
        processor_instructions,
        "String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT",
        "healthy pre-attach processor")
    legacy_action = bytecode_unique_index(
        processor_instructions,
        "String com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_AFTER_FAILURE",
        "legacy empty-abort processor")
    if pre_action >= legacy_action:
        raise InspectionError("healthy pre-attach processor does not precede legacy cleanup")
    action_equals = next((index for index in range(pre_action, legacy_action)
                          if "Method java/lang/String.equals:(Ljava/lang/Object;)Z"
                          in processor_instructions[index][2]), -1)
    if (action_equals < 0 or action_equals + 1 >= legacy_action
            or processor_instructions[action_equals + 1][1] != "ifeq"
            or bytecode_branch_target(processor_instructions[action_equals + 1],
                                      "healthy pre-attach action")
                != processor_instructions[legacy_action][0]):
        raise InspectionError("healthy pre-attach action can bypass legacy separation")
    healthy_instructions = processor_instructions[pre_action:legacy_action]
    healthy_offsets = {instruction[0]: index
                       for index, instruction in enumerate(healthy_instructions)}
    pre_attach_owner = (
        "Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle."
        "acknowledgeNoForeignPreAttachAbort:(Ljava/lang/String;JIJLjava/lang/String;)"
        "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;")
    legacy_owner = (
        "Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle."
        "acknowledgeNoForeignAfterFailure:(Ljava/lang/String;JIJLjava/lang/String;)"
        "Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult;")
    lifecycle_call_i = bytecode_unique_index(
        healthy_instructions, pre_attach_owner, "healthy pre-attach lifecycle")
    evidence_literal_matches = [
        index for index, (_, _, operand) in enumerate(healthy_instructions)
        if operand.split("// ", 1)[-1] == "String absenceEvidenceSha256"]
    evidence_literal_i = (evidence_literal_matches[0]
                          if len(evidence_literal_matches) == 1 else -1)
    exact_string_i = bytecode_unique_index(
        healthy_instructions,
        "Method exactString:(Landroid/os/Bundle;Ljava/lang/String;)Ljava/lang/String;",
        "healthy pre-attach evidence read")
    if (evidence_literal_i <= 0 or exact_string_i != evidence_literal_i + 1
            or "Field com/techrebbe/supernote/nativepagehost/NativePageHostActivity$"
               "CommandEnvelope.extras:Landroid/os/Bundle;"
                not in healthy_instructions[evidence_literal_i - 1][2]
            or exact_string_i + 1 >= len(healthy_instructions)
            or healthy_instructions[exact_string_i + 1][1] != "astore"):
        raise InspectionError("healthy pre-attach evidence key/read bytecode changed")
    accepted_field_i = bytecode_unique_index(
        healthy_instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$"
        "CommandResult.ACCEPTED:",
        "healthy pre-attach ACCEPTED")
    idempotent_field_i = bytecode_unique_index(
        healthy_instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$"
        "CommandResult.IDEMPOTENT:",
        "healthy pre-attach IDEMPOTENT")
    if (not (lifecycle_call_i < accepted_field_i < idempotent_field_i)
            or accepted_field_i + 1 >= len(healthy_instructions)
            or healthy_instructions[accepted_field_i + 1][1] != "if_acmpne"
            or idempotent_field_i == 0
            or idempotent_field_i + 1 >= len(healthy_instructions)
            or healthy_instructions[idempotent_field_i + 1][1] != "if_acmpne"):
        raise InspectionError("healthy pre-attach result classification bytecode changed")
    idempotent_start_i = idempotent_field_i - 1
    if (healthy_instructions[idempotent_start_i][1] not in {"aload", "aload_0",
                                                             "aload_1", "aload_2",
                                                             "aload_3"}
            or bytecode_branch_target(healthy_instructions[accepted_field_i + 1],
                                      "healthy pre-attach ACCEPTED")
                != healthy_instructions[idempotent_start_i][0]):
        raise InspectionError("ACCEPTED branch does not terminate at IDEMPOTENT classification")
    accepted_body = healthy_instructions[accepted_field_i + 2:idempotent_start_i]
    accepted_releases = [index for index, (_, _, operand) in enumerate(accepted_body)
                         if "Method releaseNormally:()Z" in operand]
    accepted_finishes = [index for index, (_, _, operand) in enumerate(accepted_body)
                         if "Method finishAndRemoveTask:()V" in operand]
    accepted_controls = bytecode_control_ops(accepted_body)
    if (len(accepted_releases) != 1 or len(accepted_finishes) != 1
            or len(accepted_controls) != 2
            or [opcode for _, opcode, _ in accepted_controls] != ["ifeq", "return"]
            or accepted_releases[0] + 1 >= len(accepted_body)
            or accepted_body[accepted_releases[0] + 1] != accepted_controls[0]
            or accepted_finishes[0] + 1 >= len(accepted_body)
            or accepted_body[accepted_finishes[0] + 1][1] != "return"
            or bytecode_branch_target(accepted_controls[0], "ACCEPTED release")
                != accepted_controls[1][0]
            or accepted_body[-1] != accepted_controls[1]):
        raise InspectionError("ACCEPTED abort does not release, finish, and return exactly")
    reject_offset = bytecode_branch_target(
        healthy_instructions[idempotent_field_i + 1], "healthy pre-attach IDEMPOTENT")
    reject_i = healthy_offsets.get(reject_offset, -1)
    if reject_i <= idempotent_field_i + 1:
        raise InspectionError("IDEMPOTENT branch target is not the exact rejection branch")
    replay_body = healthy_instructions[idempotent_field_i + 2:reject_i]
    display_i = bytecode_unique_index(
        replay_body,
        "Method com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle."
        "displayRemoved:()Z",
        "healthy pre-attach replay display guard")
    replay_releases = [index for index, (_, _, operand) in enumerate(replay_body)
                       if "Method releaseNormally:()Z" in operand]
    replay_finishes = [index for index, (_, _, operand) in enumerate(replay_body)
                       if "Method finishAndRemoveTask:()V" in operand]
    replay_controls = bytecode_control_ops(replay_body)
    if (len(replay_releases) != 1 or len(replay_finishes) != 1
            or [opcode for _, opcode, _ in replay_controls]
                != ["ifne", "ifeq", "return"]
            or display_i + 1 >= len(replay_body)
            or replay_body[display_i + 1] != replay_controls[0]
            or replay_releases[0] + 1 >= len(replay_body)
            or replay_body[replay_releases[0] + 1] != replay_controls[1]
            or replay_finishes[0] + 1 >= len(replay_body)
            or replay_body[replay_finishes[0] + 1][1] != "return"
            or bytecode_branch_target(replay_controls[0], "replay display guard")
                != replay_controls[2][0]
            or bytecode_branch_target(replay_controls[1], "replay release")
                != replay_controls[2][0]
            or replay_body[-1] != replay_controls[2]):
        raise InspectionError("IDEMPOTENT abort release retry/display guard is not exact")
    reject_body = healthy_instructions[reject_i:]
    if (sum("Method rejectAlreadyFailed:(Ljava/lang/String;)V" in operand
            for _, _, operand in reject_body) != 1
            or [opcode for _, opcode, _ in bytecode_control_ops(reject_body)] != ["return"]
            or reject_body[-1][1] != "return"):
        raise InspectionError("healthy pre-attach rejection branch is not exact")
    if (sum(pre_attach_owner in operand for _, _, operand in processor_instructions) != 1
            or sum(legacy_owner in operand for _, _, operand in processor_instructions) != 1
            or any(legacy_owner in operand for _, _, operand in healthy_instructions)
            or any(pre_attach_owner in operand
                   for _, _, operand in processor_instructions[legacy_action:])):
        raise InspectionError("healthy and legacy empty-abort lifecycle owners are conflated")
    legacy_empty = command_processor[legacy_empty_start:]
    if ("acknowledgeNoForeignAfterFailure" not in legacy_empty
            or "acknowledgeNoForeignPreAttachAbort" in legacy_empty):
        raise InspectionError(
                "failure-only empty cleanup bytecode can substitute for healthy abort")
    if command.index("commandEnvelopeMatches") > command.index("parseForeignIdentity"):
        raise InspectionError("foreign payload is parsed before envelope authentication")
    if ("decodeCommandEnvelope" not in command
            or command.index("decodeCommandEnvelope") > command.index("commandEnvelopeMatches")
            or "verifyRuntimeAuthorityOrFail" not in command
            or "isCleanupCommand" not in command):
        raise InspectionError("exception-contained authenticated envelope path missing")
    decode = bytecode_method(text,
            "decodeCommandEnvelope(android.content.Intent, java.lang.String);")
    for marker in ("Intent.getExtras", "java/lang/String", "java/lang/Long",
                   "java/lang/Integer", "java/lang/RuntimeException"):
        if marker not in decode:
            raise InspectionError("pre-auth Bundle decoding is not fail-closed in bytecode")
    verify = bytecode_method(text, "verifyRuntimeAuthorityOrFail(java.lang.String);")
    for marker in ("verifyHostAuthorityOrFail", "verifyPhysicalFrameOrFail",
                   "virtualDisplayMetrics", "onVirtualDisplayMetrics",
                   "releaseForUnexpectedLoss"):
        if marker not in verify:
            raise InspectionError("continuous display-metric authority missing from bytecode")
    metrics = bytecode_method(text, "virtualDisplayMetrics();")
    for marker in ("VirtualDisplay.getDisplay", "Display.getRealMetrics"):
        if marker not in metrics:
            raise InspectionError("actual display metrics are not measured in bytecode")
    physical = bytecode_method(text, "verifyPhysicalFrameOrFail(java.lang.String);")
    for marker in ("onPhysicalFrameMeasured", "pendingPlacementSequence",
                   "View.getLocationOnScreen", "releaseForUnexpectedLoss"):
        if marker not in physical:
            raise InspectionError("physical frame authority missing from bytecode")
    host = bytecode_method(text, "verifyHostAuthorityOrFail(java.lang.String);")
    for marker in ("physicalDisplayId", "physicalDensityDpi", "hostVisible",
                   "hasWindowFocus", "onHostAuthority", "releaseForUnexpectedLoss"):
        if marker not in host:
            raise InspectionError("host visibility/display authority missing from bytecode")
    preallocation = bytecode_method(
        text, "verifyPreAllocationHostAuthorityOrFail(java.lang.String);")
    for marker in ("physicalDisplayId", "physicalDensityDpi", "hostVisible",
                   "hasWindowFocus", "revalidatePreAllocationHostAuthority",
                   "rejectAlreadyFailed"):
        if marker not in preallocation:
            raise InspectionError(
                "preallocation physical-host authority missing from bytecode")
    visible = bytecode_method(text, "hostVisible();")
    for marker in ("Window.getDecorView", "View.getWindowVisibility", "View.isShown",
                   "isFinishing"):
        if marker not in visible:
            raise InspectionError("host visible-window authority missing from bytecode")
    suspend = bytecode_method(text, "beginBoundedHostAuthoritySuspension(java.lang.String);")
    for marker in ("suspendHostAuthority", "SystemClock.elapsedRealtime",
                   "HOST_AUTHORITY_SUSPENDED", "postDelayed"):
        if marker not in suspend:
            raise InspectionError("bounded host-authority suspension missing from bytecode")
    deferred = bytecode_method(text,
            "deferAuthenticatedCommand(com.techrebbe.supernote.nativepagehost.NativePageHostActivity$CommandEnvelope, int, com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle$ForeignTaskIdentity);")
    for marker in ("SystemClock.elapsedRealtime", "physicalDisplayAuthorityStableWhilePaused",
                   "reserveDeferredCommand", "COMMAND_DEFERRED",
                   "releaseForUnexpectedLoss"):
        if marker not in deferred:
            raise InspectionError("authenticated deferred command boundary missing from bytecode")
    drain = bytecode_method(text, "drainDeferredCommandIfReady();")
    for marker in ("verifyRuntimeAuthorityOrFail", "consumeDeferredCommand",
                   "COMMAND_RESUMED", "processAuthenticatedCommand"):
        if marker not in drain:
            raise InspectionError("deferred command is not reauthenticated before commit")
    normal_release = bytecode_method(text, "releaseNormally();")
    emergency_release = bytecode_method(text,
            "releaseForUnexpectedLoss(java.lang.String);")
    for method, emergency in ((normal_release, "iconst_0"),
                              (emergency_release, "iconst_1")):
        for marker in ("VirtualDisplay.release", "onReleaseAttemptFailed",
                       "retainedDisplayCleanupAddressable", "escalateOwnProcessCleanup",
                       "RuntimeException", "markReleased", emergency):
            if marker not in method:
                raise InspectionError("exception-safe release authority missing from bytecode")
        if method.index("VirtualDisplay.release") > method.index("markReleased"):
            raise InspectionError("release is claimed before VirtualDisplay.release returns")
    back = bytecode_method(text, "onBackPressed();")
    if "canFinishWithoutCleanup" not in back or "finishAndRemoveTask" not in back:
        raise InspectionError("Back cleanup-authority guard missing from bytecode")
    destroy = bytecode_method(text, "onDestroy();")
    for marker in ("releaseForUnexpectedLoss", "escalateOwnProcessCleanup"):
        if marker not in destroy:
            raise InspectionError("destroy-time process cleanup owner missing from bytecode")
    escalation = bytecode_method(text, "escalateOwnProcessCleanup(java.lang.String);")
    for marker in ("PROCESS_CLEANUP_ESCALATED", "android/os/Process.myPid",
                   "android/os/Process.killProcess"):
        if marker not in escalation:
            raise InspectionError("self-process cleanup escalation missing from bytecode")
    validate_exact_javap_topology(
        payload, "activity bytecode evidence", REVIEWED_ACTIVITY_JAVAP_SHA256,
        TEST_ACTIVITY_JAVAP_SHA256, allow_test_fixture)


def validate_lifecycle_bytecode(payload: bytes, *, allow_test_fixture: bool = False) -> None:
    text = validate_canonical_text_evidence(payload, "lifecycle bytecode evidence")
    pre_attach = bytecode_method(
        text,
        "acknowledgeNoForeignPreAttachAbort(java.lang.String, long, int, long, "
        "java.lang.String);")
    instructions = bytecode_instructions(pre_attach)
    offsets = {instruction[0]: index for index, instruction in enumerate(instructions)}
    authorize_i = bytecode_unique_index(
        instructions, "Method authorize:(Ljava/lang/String;JI)Z",
        "healthy pre-attach authorization")
    if (authorize_i + 1 >= len(instructions)
            or instructions[authorize_i + 1][1] != "ifne"):
        raise InspectionError("healthy pre-attach lifecycle does not authenticate first")
    authorized_offset = bytecode_branch_target(
        instructions[authorize_i + 1], "healthy pre-attach authorization")
    authorized_i = offsets.get(authorized_offset, -1)
    stale_body = instructions[authorize_i + 2:authorized_i]
    if (authorized_i <= authorize_i + 1
            or [opcode for _, opcode, _ in bytecode_control_ops(stale_body)] != ["areturn"]
            or not stale_body or stale_body[-1][1] != "areturn"
            or sum("Method stale:()Lcom/techrebbe/supernote/viewportprobe/"
                   "NativePageHostLifecycle$CommandResult;" in operand
                   for _, _, operand in stale_body) != 1):
        raise InspectionError("unauthenticated pre-attach lifecycle command can continue")
    key_i = bytecode_unique_index(
        instructions, "String PRE_ATTACH_ABORT|", "healthy pre-attach key")
    classify_i = bytecode_unique_index(
        instructions,
        "Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "healthy pre-attach sequence classification")
    if not (authorized_i <= key_i < classify_i):
        raise InspectionError("pre-attach key is not classified after authentication")
    prefix_calls = [operand.split("// ", 1)[-1] for _, opcode, operand
                    in instructions[authorized_i:classify_i + 1]
                    if opcode.startswith("invoke")]
    expected_prefix_calls = [
        'Method java/lang/StringBuilder."<init>":()V',
        "Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        "Method java/lang/String.valueOf:(Ljava/lang/Object;)Ljava/lang/String;",
        "Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        "Method java/lang/StringBuilder.toString:()Ljava/lang/String;",
        "Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
    ]
    if prefix_calls != expected_prefix_calls:
        raise InspectionError("pre-attach authorization/key/classification prefix gained processing")
    replay_tail = instructions[classify_i + 1:classify_i + 6]
    if ([opcode for _, opcode, _ in replay_tail]
            != ["astore", "aload", "ifnull", "aload", "areturn"]):
        raise InspectionError("pre-attach exact replay is not returned before health checks")
    eligibility_offset = bytecode_branch_target(
        replay_tail[2], "healthy pre-attach replay")
    eligibility_i = offsets.get(eligibility_offset, -1)
    if (eligibility_i != classify_i + 6
            or eligibility_i + 1 >= len(instructions)
            or "Field failure:Ljava/lang/String;" not in instructions[eligibility_i + 1][2]):
        raise InspectionError("fresh pre-attach eligibility can run before exact replay")

    failure_i = bytecode_unique_index(
        instructions, "Field failure:Ljava/lang/String;", "pre-attach failure guard")
    foreign_i = bytecode_unique_index(
        instructions,
        "Field foreignTask:Lcom/techrebbe/supernote/viewportprobe/"
        "NativePageHostLifecycle$ForeignTaskIdentity;",
        "pre-attach foreign-task guard")
    deferred_i = bytecode_unique_index(
        instructions, "Field deferredCommandKey:Ljava/lang/String;",
        "pre-attach deferred-command guard")
    display_state_i = bytecode_unique_index(
        instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State."
        "DISPLAY_ALLOCATED:",
        "pre-attach allocated-state guard")
    waiting_state_i = bytecode_unique_index(
        instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State."
        "WAITING_FOR_FOREIGN_ATTACH:",
        "pre-attach waiting-state guard")
    addressable_i = bytecode_unique_index(
        instructions, "Method retainedDisplayCleanupAddressable:(I)Z",
        "pre-attach retained-display guard")
    evidence_pattern_i = bytecode_unique_index(
        instructions, "String [0-9a-f]{64}", "pre-attach evidence syntax")
    matches_i = bytecode_unique_index(
        instructions, "Method java/lang/String.matches:(Ljava/lang/String;)Z",
        "pre-attach evidence check")
    contradiction_i = bytecode_unique_index(
        instructions,
        "Method contradiction:(Ljava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "pre-attach contradiction")
    contradiction_message_i = bytecode_unique_index(
        instructions, "String healthy pre-attach abort lacked exact empty-display authority",
        "pre-attach contradiction message")
    if contradiction_message_i == 0 or contradiction_i != contradiction_message_i + 1:
        raise InspectionError("pre-attach contradiction block changed")
    contradiction_start = instructions[contradiction_message_i - 1][0]
    if instructions[contradiction_message_i - 1][1] != "aload_0":
        raise InspectionError("pre-attach contradiction target is not exact")
    guarded_fields = (failure_i, foreign_i, deferred_i)
    if any(index + 1 >= len(instructions)
           or instructions[index + 1][1] != "ifnonnull"
           or bytecode_branch_target(instructions[index + 1], "pre-attach field guard")
                != contradiction_start
           for index in guarded_fields):
        raise InspectionError("healthy pre-attach nonempty-state guard polarity changed")
    if (display_state_i == 0 or display_state_i + 1 >= len(instructions)
            or "Field state:" not in instructions[display_state_i - 1][2]
            or instructions[display_state_i + 1][1] != "if_acmpeq"
            or waiting_state_i == 0 or waiting_state_i + 1 >= len(instructions)
            or "Field state:" not in instructions[waiting_state_i - 1][2]
            or instructions[waiting_state_i + 1][1] != "if_acmpne"
            or bytecode_branch_target(instructions[waiting_state_i + 1],
                                      "pre-attach waiting state") != contradiction_start):
        raise InspectionError("healthy pre-attach lifecycle-state eligibility changed")
    addressable_start = instructions[addressable_i - 2][0] if addressable_i >= 2 else -1
    if (instructions[addressable_i - 2][1] != "aload_0"
            or not instructions[addressable_i - 1][1].startswith("iload")
            or bytecode_branch_target(instructions[display_state_i + 1],
                                      "pre-attach allocated state") != addressable_start
            or addressable_i + 1 >= len(instructions)
            or instructions[addressable_i + 1][1] != "ifeq"
            or bytecode_branch_target(instructions[addressable_i + 1],
                                      "pre-attach display addressability")
                != contradiction_start):
        raise InspectionError("healthy pre-attach retained-display eligibility changed")
    null_guard_i = next((index for index in range(addressable_i + 2, evidence_pattern_i)
                         if instructions[index][1] == "ifnull"), -1)
    if (null_guard_i < 0
            or bytecode_branch_target(instructions[null_guard_i],
                                      "pre-attach evidence presence")
                != contradiction_start
            or matches_i + 1 >= len(instructions)
            or instructions[matches_i + 1][1] != "ifne"):
        raise InspectionError("healthy pre-attach evidence eligibility changed")
    contradiction_return_i = contradiction_i + 1
    if (contradiction_return_i >= len(instructions)
            or instructions[contradiction_return_i][1] != "areturn"):
        raise InspectionError("pre-attach contradiction does not terminate")
    success_offset = bytecode_branch_target(
        instructions[matches_i + 1], "pre-attach evidence syntax")
    success_i = offsets.get(success_offset, -1)
    if success_i != contradiction_return_i + 1:
        raise InspectionError("valid pre-attach evidence does not enter exact authorization")
    eligibility_controls = bytecode_control_ops(
        instructions[eligibility_i:contradiction_message_i - 1])
    if [opcode for _, opcode, _ in eligibility_controls] != [
            "ifnonnull", "ifnonnull", "ifnonnull", "if_acmpeq", "if_acmpne",
            "ifeq", "ifnull", "ifne"]:
        raise InspectionError("healthy pre-attach eligibility control flow changed")
    pre_attach_authority_i = bytecode_unique_index(
        instructions, "Field emptyPreAttachAbortAuthorized:Z",
        "pre-attach release authority")
    release_state_i = bytecode_unique_index(
        instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State."
        "RELEASE_AUTHORIZED:",
        "pre-attach release state")
    commit_i = bytecode_unique_index(
        instructions,
        "Method commit:(JLjava/lang/String;)Lcom/techrebbe/supernote/viewportprobe/"
        "NativePageHostLifecycle$CommandResult;",
        "pre-attach commit")
    success = instructions[success_i:]
    if (not (success_i < pre_attach_authority_i < release_state_i < commit_i)
            or instructions[pre_attach_authority_i - 1][1] != "iconst_1"
            or instructions[pre_attach_authority_i][1] != "putfield"
            or release_state_i + 1 >= len(instructions)
            or instructions[release_state_i + 1][1] != "putfield"
            or "Field state:" not in instructions[release_state_i + 1][2]
            or commit_i + 1 >= len(instructions)
            or instructions[commit_i + 1][1] != "areturn"
            or instructions[commit_i + 1] != success[-1]
            or [opcode for _, opcode, _ in bytecode_control_ops(success)] != ["areturn"]):
        raise InspectionError("healthy pre-attach release authorization/commit changed")

    legacy = bytecode_method(
        text,
        "acknowledgeNoForeignAfterFailure(java.lang.String, long, int, long, "
        "java.lang.String);")
    legacy_instructions = bytecode_instructions(legacy)
    legacy_offsets = {instruction[0]: index
                      for index, instruction in enumerate(legacy_instructions)}
    expected_legacy_opcodes = [
        "aload_0", "aload_1", "lload_2", "iload", "invokespecial", "ifne",
        "aload_0", "invokespecial", "areturn", "new", "dup", "invokespecial",
        "ldc_w", "invokevirtual", "aload", "invokestatic", "invokevirtual",
        "invokevirtual", "astore", "aload_0", "lload", "aload", "invokespecial",
        "astore", "aload", "ifnull", "aload", "areturn", "aload_0", "getfield",
        "ifnull", "aload_0", "getfield", "getstatic", "if_acmpne", "aload_0",
        "getfield", "ifnonnull", "aload_0", "getfield", "ifne", "aload", "ifnull",
        "aload", "ldc_w", "invokevirtual", "ifne", "aload_0", "ldc_w",
        "invokespecial", "areturn", "aload_0", "iconst_1", "putfield", "aload_0",
        "getstatic", "putfield", "aload_0", "lload", "aload", "invokespecial",
        "areturn",
    ]
    legacy_calls = [operand.split("// ", 1)[-1] for _, opcode, operand
                    in legacy_instructions if opcode.startswith("invoke")]
    expected_legacy_calls = [
        "Method authorize:(Ljava/lang/String;JI)Z",
        "Method stale:()Lcom/techrebbe/supernote/viewportprobe/"
        "NativePageHostLifecycle$CommandResult;",
        'Method java/lang/StringBuilder."<init>":()V',
        "Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        "Method java/lang/String.valueOf:(Ljava/lang/Object;)Ljava/lang/String;",
        "Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        "Method java/lang/StringBuilder.toString:()Ljava/lang/String;",
        "Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "Method java/lang/String.matches:(Ljava/lang/String;)Z",
        "Method contradiction:(Ljava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "Method commit:(JLjava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
    ]
    legacy_fields = [operand.split("// ", 1)[-1] for _, opcode, operand
                     in legacy_instructions if opcode in {"getfield", "putfield"}]
    expected_legacy_fields = [
        "Field failure:Ljava/lang/String;",
        "Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;",
        "Field foreignTask:Lcom/techrebbe/supernote/viewportprobe/"
        "NativePageHostLifecycle$ForeignTaskIdentity;",
        "Field emptyPreAttachAbortAuthorized:Z",
        "Field emptyFailureCleanupAuthorized:Z",
        "Field state:Lcom/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State;",
    ]
    if ([opcode for _, opcode, _ in legacy_instructions] != expected_legacy_opcodes
            or legacy_calls != expected_legacy_calls
            or legacy_fields != expected_legacy_fields):
        raise InspectionError("legacy failure cleanup bytecode topology changed")

    legacy_authorize_i = bytecode_unique_index(
        legacy_instructions, "Method authorize:(Ljava/lang/String;JI)Z",
        "legacy failure-cleanup authorization")
    legacy_classify_i = bytecode_unique_index(
        legacy_instructions,
        "Method classifySequence:(JLjava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "legacy failure-cleanup sequence classification")
    legacy_failure_i = bytecode_unique_index(
        legacy_instructions, "Field failure:Ljava/lang/String;",
        "legacy failure guard")
    legacy_state_i = bytecode_unique_index(
        legacy_instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.FAILED:",
        "legacy failed-state guard")
    legacy_foreign_i = bytecode_unique_index(
        legacy_instructions,
        "Field foreignTask:Lcom/techrebbe/supernote/viewportprobe/"
        "NativePageHostLifecycle$ForeignTaskIdentity;",
        "legacy foreign-task guard")
    legacy_guard_i = bytecode_unique_index(
        legacy_instructions, "Field emptyPreAttachAbortAuthorized:Z",
        "legacy empty-abort healthy-authority guard")
    legacy_pattern_i = bytecode_unique_index(
        legacy_instructions, "String [0-9a-f]{64}", "legacy absence-evidence syntax")
    legacy_matches_i = bytecode_unique_index(
        legacy_instructions, "Method java/lang/String.matches:(Ljava/lang/String;)Z",
        "legacy absence-evidence check")
    legacy_contradiction_i = bytecode_unique_index(
        legacy_instructions,
        "Method contradiction:(Ljava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "legacy empty-abort contradiction")
    legacy_message_i = bytecode_unique_index(
        legacy_instructions,
        "String empty failed-session cleanup lacked exact absence authority",
        "legacy empty-abort contradiction message")
    legacy_authority_i = bytecode_unique_index(
        legacy_instructions, "Field emptyFailureCleanupAuthorized:Z",
        "legacy empty-abort release authority")
    legacy_release_state_i = bytecode_unique_index(
        legacy_instructions,
        "Field com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State."
        "RELEASE_AUTHORIZED:", "legacy release state")
    legacy_commit_i = bytecode_unique_index(
        legacy_instructions,
        "Method commit:(JLjava/lang/String;)Lcom/techrebbe/supernote/"
        "viewportprobe/NativePageHostLifecycle$CommandResult;",
        "legacy failure-cleanup commit")
    authorized_i = legacy_offsets.get(bytecode_branch_target(
        legacy_instructions[legacy_authorize_i + 1], "legacy authorization"), -1)
    stale_body = legacy_instructions[legacy_authorize_i + 2:authorized_i]
    replay_tail = legacy_instructions[legacy_classify_i + 1:legacy_classify_i + 6]
    eligibility_i = legacy_offsets.get(bytecode_branch_target(
        replay_tail[2], "legacy exact replay"), -1) if len(replay_tail) == 5 else -1
    if (legacy_authorize_i + 1 >= len(legacy_instructions)
            or legacy_instructions[legacy_authorize_i + 1][1] != "ifne"
            or authorized_i <= legacy_authorize_i + 1
            or [opcode for _, opcode, _ in bytecode_control_ops(stale_body)] != ["areturn"]
            or not stale_body or stale_body[-1][1] != "areturn"
            or [opcode for _, opcode, _ in replay_tail]
                != ["astore", "aload", "ifnull", "aload", "areturn"]
            or eligibility_i != legacy_classify_i + 6
            or legacy_failure_i != eligibility_i + 1):
        raise InspectionError("legacy failure cleanup auth/replay prefix changed")

    if (legacy_message_i == 0 or legacy_contradiction_i != legacy_message_i + 1
            or legacy_instructions[legacy_message_i - 1][1] != "aload_0"
            or legacy_instructions[legacy_failure_i + 1][1] != "ifnull"
            or legacy_instructions[legacy_state_i - 1][1] != "getfield"
            or "Field state:" not in legacy_instructions[legacy_state_i - 1][2]
            or legacy_instructions[legacy_state_i + 1][1] != "if_acmpne"
            or legacy_instructions[legacy_foreign_i + 1][1] != "ifnonnull"
            or legacy_guard_i + 1 >= len(legacy_instructions)
            or legacy_instructions[legacy_guard_i + 1][1] != "ifne"
            or legacy_pattern_i == 0
            or legacy_instructions[legacy_pattern_i - 1][1] != "aload"
            or legacy_matches_i != legacy_pattern_i + 1
            or legacy_instructions[legacy_matches_i + 1][1] != "ifne"
            or any(bytecode_branch_target(legacy_instructions[index + 1],
                                          "legacy eligibility guard")
                   != legacy_instructions[legacy_message_i - 1][0]
                   for index in (legacy_failure_i, legacy_state_i, legacy_foreign_i,
                                 legacy_guard_i))
            or bytecode_branch_target(legacy_instructions[legacy_pattern_i - 2],
                                      "legacy absence-evidence presence")
                != legacy_instructions[legacy_message_i - 1][0]
            or legacy_instructions[legacy_pattern_i - 2][1] != "ifnull"
            or legacy_offsets.get(bytecode_branch_target(
                legacy_instructions[legacy_matches_i + 1],
                "legacy valid absence evidence"), -1) != legacy_contradiction_i + 2
            or [opcode for _, opcode, _ in bytecode_control_ops(
                legacy_instructions[eligibility_i:legacy_message_i - 1])]
                != ["ifnull", "if_acmpne", "ifnonnull", "ifne", "ifnull", "ifne"]
            or legacy_authority_i != legacy_contradiction_i + 4
            or legacy_instructions[legacy_authority_i - 1][1] != "iconst_1"
            or legacy_instructions[legacy_authority_i][1] != "putfield"
            or legacy_release_state_i != legacy_authority_i + 2
            or legacy_instructions[legacy_release_state_i + 1][1] != "putfield"
            or "Field state:" not in legacy_instructions[legacy_release_state_i + 1][2]
            or legacy_commit_i + 1 != len(legacy_instructions) - 1
            or legacy_instructions[legacy_commit_i + 1][1] != "areturn"):
        raise InspectionError("legacy failure cleanup authority/guard dominance changed")

    release = bytecode_method(text, "canReleaseNormally();")
    release_instructions = bytecode_instructions(release)
    release_fields = [operand.split("// ", 1)[-1] for _, opcode, operand
                      in release_instructions if opcode == "getfield"]
    if ([opcode for _, opcode, _ in release_instructions] != [
            "aload_0", "getfield", "ifne", "aload_0", "getfield", "ifne",
            "aload_0", "getfield", "ifeq", "iconst_1", "goto", "iconst_0",
            "ireturn"]
            or release_fields != [
                "Field normalReleaseAuthorized:Z",
                "Field emptyFailureCleanupAuthorized:Z",
                "Field emptyPreAttachAbortAuthorized:Z"]):
        raise InspectionError("normal release bytecode authority changed")
    release_true = release_instructions[9][0]
    release_false = release_instructions[11][0]
    release_return = release_instructions[12][0]
    if (bytecode_branch_target(release_instructions[2], "normal release authority")
            != release_true
            or bytecode_branch_target(release_instructions[5], "failed cleanup authority")
            != release_true
            or bytecode_branch_target(release_instructions[8], "pre-attach abort authority")
            != release_false
            or bytecode_branch_target(release_instructions[10], "release result")
            != release_return):
        raise InspectionError("normal release bytecode branch polarity changed")
    validate_exact_javap_topology(
        payload, "lifecycle bytecode evidence", REVIEWED_LIFECYCLE_JAVAP_SHA256,
        TEST_LIFECYCLE_JAVAP_SHA256, allow_test_fixture)


def validate_layout_bytecode(payload: bytes, *, allow_test_fixture: bool = False) -> None:
    text = validate_canonical_text_evidence(payload, "layout bytecode evidence")
    fit = bytecode_method(text,
            "fit(int, int, com.techrebbe.supernote.viewportprobe.DisplayProbeLayout$Placement);")
    exact = bytecode_method(text, "exactlyMatches(int, int, int, int);")
    for marker in ("sipush        8192", "iconst_3", "iconst_4",
                   "Placement.FULL", "Placement.LEFT", "Placement.RIGHT"):
        if marker not in fit:
            raise InspectionError("layout fit bytecode authority changed: " + marker)
    if fit.count("idiv") < 2:
        raise InspectionError("layout fit bytecode lost exact 3:4 divisions")
    for marker in ("getfield", "left", "top", "width", "height"):
        if marker not in exact:
            raise InspectionError("layout exact-match bytecode authority changed: " + marker)
    validate_exact_javap_topology(
        payload, "layout bytecode evidence", REVIEWED_LAYOUT_JAVAP_SHA256,
        TEST_LAYOUT_JAVAP_SHA256, allow_test_fixture)


def validate_permissions(text: str) -> None:
    if not re.search(r"(?m)^package:\s*" + re.escape(PACKAGE) + r"\s*$", text):
        raise InspectionError("aapt permissions reports another package")
    if re.search(r"(?i)uses-permission|permission:", text):
        raise InspectionError("packaged APK requests a permission")


def validate_badging(text: str) -> None:
    pattern = (r"(?m)^package: name='" + re.escape(PACKAGE)
               + r"' versionCode='" + re.escape(VERSION_CODE)
               + r"' versionName='" + re.escape(VERSION_NAME) + r"'")
    if re.search(pattern, text) is None:
        raise InspectionError("packaged badging identity changed")


def parse_xmltree(text: str) -> dict[str, object]:
    roots: list[dict[str, object]] = []
    stack: list[tuple[int, dict[str, object]]] = []
    for raw in text.splitlines():
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        element = re.fullmatch(r"E: ([A-Za-z0-9_-]+) \(line=\d+\)", line)
        if element:
            node: dict[str, object] = {"tag": element.group(1), "attrs": {}, "children": []}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1]["children"].append(node)  # type: ignore[union-attr]
            else:
                roots.append(node)
            stack.append((indent, node))
            continue
        attribute = re.match(r"A: ([^\s(=]+)(?:\([^)]*\))?=(.*)$", line)
        if attribute and stack:
            attrs = stack[-1][1]["attrs"]
            assert isinstance(attrs, dict)
            name = attribute.group(1)
            if name in attrs:
                raise InspectionError("duplicate packaged manifest attribute")
            attrs[name] = attribute.group(2)
        elif line and not line.startswith("N:"):
            raise InspectionError("unparsed packaged manifest evidence")
    if len(roots) != 1:
        raise InspectionError("packaged manifest root topology changed")
    return roots[0]


def require_node(node: dict[str, object], tag: str, attrs: dict[str, str],
                 child_tags: list[str]) -> list[dict[str, object]]:
    if node.get("tag") != tag or set(node.get("attrs", {})) != set(attrs):
        raise InspectionError(f"packaged {tag} topology/attribute allowlist changed")
    actual = node["attrs"]
    assert isinstance(actual, dict)
    for name, required in attrs.items():
        normalized = re.sub(r' \(Raw: ".*"\)$', "", str(actual[name]))
        if normalized != required:
            raise InspectionError(f"packaged {tag} attribute changed: {name}")
    children = node.get("children")
    assert isinstance(children, list)
    if [child.get("tag") for child in children] != child_tags:
        raise InspectionError(f"packaged {tag} child topology changed")
    return children


def validate_xmltree(text: str) -> None:
    namespaces = [line.strip() for line in text.splitlines() if line.strip().startswith("N:")]
    if namespaces != ["N: android=http://schemas.android.com/apk/res/android"]:
        raise InspectionError("packaged manifest namespace topology changed")
    manifest = parse_xmltree(text)
    children = require_node(manifest, "manifest", {
        "android:versionCode": "(type 0x10)0x2",
        "android:versionName": f'"{VERSION_NAME}"',
        "android:compileSdkVersion": "(type 0x10)0x23",
        "android:compileSdkVersionCodename": '"15"',
        "package": f'"{PACKAGE}"',
        "platformBuildVersionCode": "(type 0x10)0x23",
        "platformBuildVersionName": "(type 0x10)0xf",
    }, ["uses-sdk", "application"])
    require_node(children[0], "uses-sdk", {
        "android:minSdkVersion": "(type 0x10)0x1e",
        "android:targetSdkVersion": "(type 0x10)0x1e",
    }, [])
    application_children = require_node(children[1], "application", {
        "android:theme": "@0x01030241",
        "android:label": '"Native Page Host - Visual Only"',
        "android:allowBackup": "(type 0x12)0x0",
        "android:supportsRtl": "(type 0x12)0x0",
        "android:usesCleartextTraffic": "(type 0x12)0x0",
    }, ["activity"])
    activity_children = require_node(application_children[0], "activity", {
        "android:name": '".NativePageHostActivity"',
        "android:exported": "(type 0x12)0xffffffff",
        "android:launchMode": "(type 0x10)0x2",
        "android:configChanges": "(type 0x11)0x1d80",
        "android:resizeableActivity": "(type 0x12)0xffffffff",
    }, ["intent-filter"])
    filter_children = require_node(activity_children[0], "intent-filter", {},
                                   ["action", "category"])
    require_node(filter_children[0], "action", {
        "android:name": '"android.intent.action.MAIN"'}, [])
    require_node(filter_children[1], "category", {
        "android:name": '"android.intent.category.LAUNCHER"'}, [])


def inspect_apk(payload: bytes, expected_dex: bytes | None = None) -> tuple[
        str, tuple[str, ...], tuple[str, ...], bytes]:
    seen: set[str] = set()
    dex = None
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            for entry in archive.infolist():
                name = entry.filename
                posix = PurePosixPath(name)
                if (entry.is_dir() or name in seen or name not in ALLOWED_APK_ENTRIES
                        or name.startswith("/") or "\\" in name or ".." in posix.parts
                        or entry.flag_bits & 1 or entry.file_size > MAX_APK_ENTRY):
                    raise InspectionError("unsafe or unexpected APK entry")
                seen.add(name)
                if name == "classes.dex":
                    dex = archive.read(entry)
    except zipfile.BadZipFile as error:
        raise InspectionError("invalid APK ZIP") from error
    if "AndroidManifest.xml" not in seen or dex is None or not dex.startswith(b"dex\n"):
        raise InspectionError("APK lacks manifest or valid classes.dex")
    for forbidden in FORBIDDEN_DEX:
        if forbidden in dex:
            raise InspectionError("DEX contains forbidden capability: "
                                  + forbidden.decode("ascii"))
    classes = dex_class_descriptors(dex)
    if expected_dex is not None:
        require_expected_dex(dex, expected_dex)
    return sha256(dex), tuple(sorted(seen)), classes, dex


def require_expected_dex(packaged: bytes, reviewed: bytes) -> None:
    """Bind executable package bytes to the exact reviewed compiler output."""
    if len(packaged) != len(reviewed) or not hmac.compare_digest(packaged, reviewed):
        raise InspectionError("packaged DEX differs from the reviewed build DEX")


def run_aapt(aapt: Path, arguments: list[str]) -> bytes:
    result = subprocess.run([str(aapt), *arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, check=False)
    if result.returncode != 0 or len(result.stdout) > MAX_TOOL_OUTPUT \
            or len(result.stderr) > MAX_TOOL_OUTPUT:
        raise InspectionError("aapt inspection failed or exceeded output limit")
    return result.stdout


def write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def evidence_bundle_wire(evidence_payloads: dict[str, bytes]) -> bytes:
    required = {
        "permissions.txt", "badging.txt", "manifest-xmltree.txt",
        "apk-descriptor-snapshot.json", "activity-bytecode.txt",
        "lifecycle-bytecode.txt", "layout-bytecode.txt", "package-authority.json",
    }
    if set(evidence_payloads) != required or any(
            not isinstance(value, bytes) or not value for value in evidence_payloads.values()):
        raise InspectionError("evidence bundle input topology changed")
    bundle = {
        "schema": "native-page-host-evidence-bundle-v1",
        "authoritySha256": sha256(evidence_payloads["package-authority.json"]),
        "files": {
            name: {
                "base64": base64.b64encode(payload).decode("ascii"),
                "sha256": sha256(payload),
                "size": len(payload),
            }
            for name, payload in sorted(evidence_payloads.items())
        },
    }
    wire = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(wire) > MAX_TOOL_OUTPUT:
        raise InspectionError("evidence bundle exceeded output limit")
    return wire


def inspect(args: argparse.Namespace) -> tuple[dict[str, object], dict[str, bytes]]:
    manifest = read_regular(args.manifest, 256 * 1024)
    activity = read_regular(args.activity_source, 1024 * 1024)
    lifecycle = read_regular(args.lifecycle_source, 1024 * 1024)
    layout = read_regular(args.layout_source, 256 * 1024)
    lifecycle_test = read_regular(args.lifecycle_test, 1024 * 1024)
    canonicalizer = read_regular(args.canonicalizer, 1024 * 1024)
    package_tests = read_regular(args.package_tests, 1024 * 1024)
    readme = read_regular(args.readme, 1024 * 1024)
    build_script = read_regular(args.build_script, 1024 * 1024)
    inspector_source = read_regular(Path(__file__), 1024 * 1024)
    activity_bytecode = read_regular(args.activity_bytecode, 4 * 1024 * 1024)
    lifecycle_bytecode = read_regular(args.lifecycle_bytecode, 4 * 1024 * 1024)
    layout_bytecode = read_regular(args.layout_bytecode, 1024 * 1024)
    toolchain_authority, toolchain_descriptor = read_regular_with_descriptor(
            args.toolchain_authority, 256 * 1024)
    try:
        parsed_toolchain = json.loads(toolchain_authority.decode("ascii"))
        build_text = build_script.decode("utf-8")
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InspectionError("invalid toolchain authority") from error
    bootstrap_pin = re.findall(
        r"\$reviewedPythonBootstrapSha256='([0-9a-f]{64})'", build_text)
    if (not isinstance(parsed_toolchain, dict)
            or parsed_toolchain.get("schema") != "native-page-host-toolchain-v1"):
        raise InspectionError("wrong toolchain authority schema")
    if (set(parsed_toolchain) != {"schema", "jdk", "androidPlatform", "buildTools",
                                 "python", "pythonRuntimeAuthority", "pythonFlags",
                                 "pythonRuntimeFileCount", "pythonRuntimeDirectoryCount",
                                 "pythonRuntimeRecordCount",
                                 "pythonRuntimeInventorySha256", "pythonHelperSha256",
                                 "pythonBootstrapSha256", "powershellEvidenceAuthority",
                                 "sha256"}
            or parsed_toolchain.get("pythonRuntimeAuthority")
                != "private-retained-namespace-audit-v2"
            or parsed_toolchain.get("pythonFlags") != "-I -S -B"
            or type(parsed_toolchain.get("pythonRuntimeFileCount")) is not int
            or parsed_toolchain["pythonRuntimeFileCount"]
                != REVIEWED_PYTHON_RUNTIME_FILE_COUNT
            or type(parsed_toolchain.get("pythonRuntimeDirectoryCount")) is not int
            or parsed_toolchain["pythonRuntimeDirectoryCount"]
                != REVIEWED_PYTHON_RUNTIME_DIRECTORY_COUNT
            or type(parsed_toolchain.get("pythonRuntimeRecordCount")) is not int
            or parsed_toolchain["pythonRuntimeRecordCount"]
                != REVIEWED_PYTHON_RUNTIME_RECORD_COUNT
            or not isinstance(parsed_toolchain.get("pythonRuntimeInventorySha256"), str)
            or parsed_toolchain["pythonRuntimeInventorySha256"]
                != REVIEWED_PYTHON_RUNTIME_INVENTORY_SHA256
            or parsed_toolchain.get("powershellEvidenceAuthority")
                != "fixed-launchers-retained-policy-platform-runtime-trusted-v1"
            or parsed_toolchain.get("pythonHelperSha256") != {
                "canonicalize_apk.py": sha256(canonicalizer),
                "inspect_native_page_host.py": sha256(inspector_source),
                "test_native_page_host_package.py": sha256(package_tests),
            }
            or not isinstance(parsed_toolchain.get("pythonBootstrapSha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}",
                                parsed_toolchain["pythonBootstrapSha256"])
            or bootstrap_pin != [parsed_toolchain["pythonBootstrapSha256"]]
            or not isinstance(parsed_toolchain.get("sha256"), dict)
            or parsed_toolchain["sha256"].get("powershell5Launcher")
                != REVIEWED_WINDOWS_POWERSHELL_51_SHA256
            or parsed_toolchain["sha256"].get("powershell7Launcher")
                != REVIEWED_POWERSHELL_7_SHA256):
        raise InspectionError("wrong Python runtime authority")
    validate_manifest_source(manifest)
    validate_activity_source(activity)
    validate_lifecycle_source(lifecycle)
    validate_layout_source(layout)
    validate_lifecycle_test_source(lifecycle_test)
    validate_build_script_source(build_script)
    validate_activity_bytecode(activity_bytecode)
    validate_lifecycle_bytecode(lifecycle_bytecode)
    validate_layout_bytecode(layout_bytecode)
    # Lock each path before its first descriptor read and retain all three locks
    # across DEX comparison and every aapt subprocess. The parent build also holds
    # the exact same generated/tool authorities, so there is no close/reopen gap.
    with _deny_snapshot_replacement(args.apk), \
            _deny_snapshot_replacement(args.aapt), \
            _deny_snapshot_replacement(args.expected_dex):
        apk, source_descriptor = read_regular_with_descriptor(
                args.apk, 64 * 1024 * 1024)
        expected_dex, expected_dex_descriptor = read_regular_with_descriptor(
                args.expected_dex, MAX_APK_ENTRY)
        aapt_payload, aapt_descriptor = read_regular_with_descriptor(
                args.aapt, 16 * 1024 * 1024)
        if sha256(aapt_payload) != args.aapt_sha256:
            raise InspectionError("aapt executable differs from pinned toolchain authority")
        dex_digest, entries, dex_classes, packaged_dex = inspect_apk(apk, expected_dex)
        snapshot_before = source_descriptor
        aapt_before = aapt_descriptor
        dex_before = expected_dex_descriptor
        permissions = run_aapt(args.aapt, ["dump", "permissions", str(args.apk)])
        badging = run_aapt(args.aapt, ["dump", "badging", str(args.apk)])
        xmltree = run_aapt(args.aapt,
                           ["dump", "xmltree", str(args.apk), "AndroidManifest.xml"])
        snapshot_after_payload, snapshot_after = read_regular_with_descriptor(
                args.apk, 64 * 1024 * 1024)
        aapt_after_payload, aapt_after = read_regular_with_descriptor(
                args.aapt, 16 * 1024 * 1024)
        dex_after_payload, dex_after = read_regular_with_descriptor(
                args.expected_dex, MAX_APK_ENTRY)
        if (snapshot_after_payload != apk or snapshot_before != snapshot_after
                or aapt_after_payload != aapt_payload or aapt_before != aapt_after
                or dex_after_payload != expected_dex or dex_before != dex_after):
            raise InspectionError("retained input authority changed during inspection")
    try:
        validate_permissions(permissions.decode("utf-8"))
        validate_badging(badging.decode("utf-8"))
        validate_xmltree(xmltree.decode("utf-8"))
    except UnicodeError as error:
        raise InspectionError("aapt output is not UTF-8") from error
    sources = {
        "native-page-host/AndroidManifest.xml": sha256(manifest),
        "native-page-host/src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java": sha256(activity),
        "java/com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.java": sha256(lifecycle),
        "java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java": sha256(layout),
        "test/NativePageHostLifecycleTest.java": sha256(lifecycle_test),
        "native-page-host/canonicalize_apk.py": sha256(canonicalizer),
        "native-page-host/inspect_native_page_host.py": sha256(inspector_source),
        "native-page-host/test_native_page_host_package.py": sha256(package_tests),
        "native-page-host/README.md": sha256(readme),
        "build-native-page-host.ps1": sha256(build_script),
        "native-page-host/evidence/NativePageHostActivity.javap.txt":
            sha256(activity_bytecode),
        "native-page-host/evidence/NativePageHostLifecycle.javap.txt":
            sha256(lifecycle_bytecode),
        "native-page-host/evidence/DisplayProbeLayout.javap.txt": sha256(layout_bytecode),
    }
    authority = {
        "schema": "native-page-host-package-v2",
        "package": PACKAGE,
        "versionCode": int(VERSION_CODE),
        "versionName": VERSION_NAME,
        "visualOnly": True,
        "apkSha256": sha256(apk),
        "dexSha256": dex_digest,
        "dexClasses": list(dex_classes),
        "reviewedDexSha256": sha256(expected_dex),
        "packagedDexExactReviewedMatch": packaged_dex == expected_dex,
        "aaptSha256": sha256(aapt_payload),
        "toolchainAuthoritySha256": sha256(toolchain_authority),
        "apkEntries": list(entries),
        "permissionsSha256": sha256(permissions),
        "badgingSha256": sha256(badging),
        "manifestXmltreeSha256": sha256(xmltree),
        "sources": sources,
    }
    descriptor_evidence = {
        "schema": "native-page-host-descriptor-snapshot-v2",
        "sourceDescriptor": stable_descriptor_evidence(source_descriptor),
        "reviewedDexDescriptor": stable_descriptor_evidence(expected_dex_descriptor),
        "aaptSourceDescriptor": stable_descriptor_evidence(aapt_descriptor),
        "toolchainDescriptor": stable_descriptor_evidence(toolchain_descriptor),
        "privateSnapshotBefore": stable_descriptor_evidence(snapshot_before),
        "privateSnapshotAfter": stable_descriptor_evidence(snapshot_after),
        "privateAaptBefore": stable_descriptor_evidence(aapt_before),
        "privateAaptAfter": stable_descriptor_evidence(aapt_after),
        "privateReviewedDexBefore": stable_descriptor_evidence(dex_before),
        "privateReviewedDexAfter": stable_descriptor_evidence(dex_after),
        "descriptorIdentityRevalidated": True,
        "allAaptInputs": "lockedBeforeFirstReadAndRetainedAcrossInspection",
    }
    descriptor_wire = json.dumps(descriptor_evidence, sort_keys=True,
                                 separators=(",", ":")).encode("ascii") + b"\n"
    authority["descriptorSnapshotSha256"] = sha256(descriptor_wire)
    wire = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    evidence_payloads = {
        "permissions.txt": permissions,
        "badging.txt": badging,
        "manifest-xmltree.txt": xmltree,
        "apk-descriptor-snapshot.json": descriptor_wire,
        "activity-bytecode.txt": activity_bytecode,
        "lifecycle-bytecode.txt": lifecycle_bytecode,
        "layout-bytecode.txt": layout_bytecode,
        "package-authority.json": wire,
    }
    return authority, evidence_payloads


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--aapt", type=Path, required=True)
    parser.add_argument("--aapt-sha256", required=True)
    parser.add_argument("--expected-dex", type=Path, required=True)
    parser.add_argument("--toolchain-authority", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--activity-source", type=Path, required=True)
    parser.add_argument("--lifecycle-source", type=Path, required=True)
    parser.add_argument("--layout-source", type=Path, required=True)
    parser.add_argument("--lifecycle-test", type=Path, required=True)
    parser.add_argument("--canonicalizer", type=Path, required=True)
    parser.add_argument("--package-tests", type=Path, required=True)
    parser.add_argument("--readme", type=Path, required=True)
    parser.add_argument("--build-script", type=Path, required=True)
    parser.add_argument("--activity-bytecode", type=Path, required=True)
    parser.add_argument("--lifecycle-bytecode", type=Path, required=True)
    parser.add_argument("--layout-bytecode", type=Path, required=True)
    args = parser.parse_args()
    authority, evidence_payloads = inspect(args)
    # The parent captures this bounded canonical stdout pipe directly and writes
    # retained evidence itself. No inspector-created path is reopened after exit.
    sys.stdout.buffer.write(evidence_bundle_wire(evidence_payloads))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
