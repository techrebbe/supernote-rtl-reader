"""Adversarial host tests for the production-blocked graph-v2 runner seam."""
from __future__ import annotations

from dataclasses import dataclass, replace
import copy
import hashlib
import hmac
import io
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock

import native_page_graph_v2_runner as runner
from native_page_android_authority import DocumentTaskAuthority


HERE = Path(__file__).resolve().parent
OBSERVER = HERE / "native_page_graph_snapshot_v2.js"
OBSERVER_RAW = OBSERVER.read_bytes()
OBSERVER_TEXT = OBSERVER_RAW.decode("utf-8")
OBSERVER_SHA = hashlib.sha256(OBSERVER_RAW).hexdigest()
ZERO_SHA = "0" * 64
RECEIPT_KEY = b"R" * 32
ADB_FILE_HASHES = {
    "adb.exe": "b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f",
    "AdbWinApi.dll": "c1d653030b4bde65d3e07e4d0b0979e17be56df1436cdd15528630f27808050d",
    "AdbWinUsbApi.dll": "0710e894d9b40f71a670c13c694079d564c92c1279da382cfe4850983aaebe1b",
}


def canon(value):
    return runner.canonical_bytes(value)


def wrapped(value):
    raw = canon(value)
    return runner.CanonicalAuthority(raw, hashlib.sha256(raw).hexdigest())


def stat(seed=1):
    return {"device": "17", "inode": str(1000 + seed), "mode": "33188", "uid": 1000,
            "gid": 1000, "mtimeNs": "1700000000000000000",
            "ctimeNs": "1700000000000000001"}


class Clock:
    def __init__(self, now=1_000_000_000):
        self.now = now
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            return self.now

    def set(self, value):
        with self.lock:
            self.now = value


class RunningClock:
    """Controllable authoritative clock that also advances with real time."""
    def __init__(self, now=1_000_000_000):
        self.lock = threading.Lock()
        self.value_anchor = now
        self.real_anchor = time.monotonic_ns()

    def __call__(self):
        with self.lock:
            return self.value_anchor + (time.monotonic_ns() - self.real_anchor)

    def set(self, value):
        with self.lock:
            self.value_anchor = value
            self.real_anchor = time.monotonic_ns()


def binding(clock, *, deadline_ms=1000, stage="FULL"):
    deadline = clock() + deadline_ms * 1_000_000
    return runner.StageBinding(runner.AUTHORIZED_SERIAL, 3141, "9000001",
                               "observer-session-v2:0001", deadline_ms, deadline, stage)


def manifest_value(bound, *, mark=True, uri_kind="file"):
    pdf_path = "/storage/emulated/0/Document/graph-v2.pdf"
    uri = ("file://" + pdf_path) if uri_kind == "file" else "content://docs/graph-v2"
    if uri_kind == "file":
        resolution = {"authority": "rtl-reader-file-uri-resolution-v1", "documentUri": uri,
                      "resolvedPath": pdf_path, "evidenceSha256": "3" * 64}
    else:
        resolution = {"authority": "rtl-reader-content-uri-resolution-v1", "documentUri": uri,
                      "resolvedPath": pdf_path, "providerPackage": "com.example.provider",
                      "providerApkSha256": "5" * 64, "evidenceSha256": "3" * 64}
    return {
        "schemaVersion": 2, "authority": runner.MANIFEST_AUTHORITY,
        "attachment": {
            "packageName": runner.PACKAGE_NAME, "processName": runner.OBSERVER_PROCESS_LABEL,
            "pid": bound.pid, "startTimeTicks": bound.start_time_ticks,
            "firmwareFingerprint": runner.FIRMWARE_FINGERPRINT,
            "apk": {"path": "/data/app/document/base.apk", "size": runner.APK_SIZE,
                    "sha256": runner.APK_SHA256},
            "framework": {"path": "/system/framework/framework.jar",
                          "size": runner.FRAMEWORK_SIZE, "sha256": runner.FRAMEWORK_SHA256},
            "module": {"name": "libart.so", "path": "/apex/runtime/lib64/libart.so",
                       "size": 1_234_567, "sha256": "1" * 64},
            "observerSha256": OBSERVER_SHA,
        },
        "externalSession": {
            "authority": runner.EXTERNAL_SESSION_AUTHORITY,
            "authorizedSerial": bound.serial, "taskId": 41, "displayId": 7,
            "hostSessionId": "host-session-v2:0001", "displayGeneration": 9,
        },
        "files": {
            "authority": runner.FILE_AUTHORITY, "verification": "external-before-and-after-exact",
            "originalPdf": {"present": True, "path": pdf_path, "size": "4096",
                            "sha256": "2" * 64, "stat": stat(1), "documentUri": uri,
                            "uriResolution": resolution},
            "mark": ({"present": True, "path": pdf_path + ".mark", "size": "512",
                      "sha256": "4" * 64, "stat": stat(2)} if mark else
                     {"present": False, "path": None, "size": None,
                      "sha256": None, "stat": None}),
        },
        "coordinator": {
            "authority": runner.COORDINATOR_AUTHORITY,
            "observerSessionId": bound.observer_session_id,
            "absoluteMonotonicDeadlineNs": str(bound.absolute_deadline_ns),
            "hardDeadlineMs": bound.deadline_ms, "maxJavaChooseWalks": 1,
            "retainedRootSamples": 2, "detachOnDeadline": True, "abortOnAnyError": True,
            "verifyTargetLivenessAfter": True, "noRetry": True,
        },
        "expected": {"documentUri": uri, "calibrationProfile": {
            "authority": runner.CALIBRATION_AUTHORITY, "status": "calibration-only",
            "pageIndexSemantics": "independent-raw", "matrixSemantics": "independent-raw"}},
    }


def loaded_manifest(bound, **kwargs):
    return runner.load_canonical(canon(manifest_value(bound, **kwargs)), runner.MAX_MANIFEST_BYTES)


def b64(number):
    return {"binary64": "0x" + struct.pack(">d", number).hex()}


def rect(left=0.0, top=0.0, right=100.0, bottom=200.0):
    return [b64(left), b64(top), b64(right), b64(bottom)]


def matrix(values=(2.0, 0.0, 0.0, 3.0, 17.0, 19.0)):
    return [b64(value) for value in values]


def pointer(value="0x0000000000001234"):
    return {"present": value is not None, "value": value}


def bitmap(present=True):
    return ({"present": True, "width": 1404, "height": 1872,
             "nativePointer": pointer()} if present else
            {"present": False, "width": None, "height": None, "nativePointer": None})


VIEW_CLASSES = dict(runner._VIEW_CLASSES)


def snapshot_value(manifest):
    value = manifest.value
    attachment = value["attachment"]
    external = value["externalSession"]
    return {
        "event": "native_page_graph_snapshot", "schemaVersion": 2,
        "authority": runner.SNAPSHOT_AUTHORITY, "manifestSha256": manifest.sha256,
        "observationOnly": True, "atomic": False,
        "attachment": {
            "packageName": attachment["packageName"], "processName": attachment["processName"],
            "pid": attachment["pid"], "processStartTimeTicks": attachment["startTimeTicks"],
            "architecture": "arm64", "pointerSize": 8,
            "firmwareFingerprint": attachment["firmwareFingerprint"],
            "apk": {"path": attachment["apk"]["path"], "size": attachment["apk"]["size"],
                    "externallyVerifiedSha256": attachment["apk"]["sha256"]},
            "framework": {"path": attachment["framework"]["path"],
                          "size": attachment["framework"]["size"],
                          "externallyVerifiedSha256": attachment["framework"]["sha256"]},
            "module": {"name": attachment["module"]["name"],
                       "path": attachment["module"]["path"],
                       "size": attachment["module"]["size"],
                       "externallyVerifiedSha256": attachment["module"]["sha256"]},
            "observerExternallyVerifiedSha256": attachment["observerSha256"],
        },
        "externalSession": {"authority": external["authority"], "source": "external-coordinator",
                            "authorizedSerial": external["authorizedSerial"],
                            "taskId": external["taskId"], "displayId": external["displayId"],
                            "hostSessionId": external["hostSessionId"],
                            "displayGeneration": external["displayGeneration"]},
        "fileAuthority": copy.deepcopy(value["files"]),
        "coordinator": {
            "authority": value["coordinator"]["authority"],
            "observerSessionId": value["coordinator"]["observerSessionId"],
            "absoluteMonotonicDeadlineNs": value["coordinator"]["absoluteMonotonicDeadlineNs"],
            "hardDeadlineMs": value["coordinator"]["hardDeadlineMs"], "heapWalks": 1,
            "retainedRootSamples": 2, "externalDetachOnDeadline": True,
            "externalTargetLivenessPostconditionRequired": True, "noRetry": True,
        },
        "calibrationProfile": copy.deepcopy(value["expected"]["calibrationProfile"]),
        "lifecycle": {"resumed": True, "finished": False, "destroyed": False,
                      "graphStable": True},
        "document": {"uri": value["expected"]["documentUri"], "rawCurrentPage": 2,
                     "pageCount": 7, "rawPageInfoPage": 3,
                     "rectangles": {name: rect() for name in
                                    ("scaleRect", "portraitScaleRect", "landscapeScaleRect",
                                     "showRect", "trimmingRect", "landscapeTrimmingRect")}},
        "pageInfo": {"ctm": matrix(), "revertCtm": matrix((7, 1, 2, 11, 23, 29)),
                     "offset": [11, -7], "scale": b64(-0.0), "trimmingRect": rect(1, 2, 99, 198),
                     "bitmaps": {"originBitmap": bitmap(), "displayBitmap": bitmap(False),
                                 "digestBitmap": bitmap()}},
        "presenter": {"uri": value["expected"]["documentUri"], "rawPresenterPage": 4,
                      "markPath": (value["files"]["mark"]["path"]
                                   if value["files"]["mark"]["present"] else None),
                      "rawRotationCode": 1, "bitmap": bitmap(), "notePointer": pointer(),
                      "binders": {"iBinder": {"present": True, "referenceStable": True},
                                  "mSFBinder": {"present": False, "referenceStable": True}}},
        "views": {name: {"className": cls, "bounds": [0, 0, 1404, 1872],
                         "scroll": [0, 0], "windowAttachCount": 2, "attached": True,
                         "referenceStable": True, "attachInfoStable": True}
                  for name, cls in VIEW_CLASSES.items()},
        "layers": {"status": "unavailable", "reasonCode": "DIRECT_LAYER_PROVENANCE_NOT_PINNED",
                   "evidenceId": "native-page-graph-v2-static-map"},
    }


def task(raw="a" * 64):
    return DocumentTaskAuthority(
        authority="rtl-reader-android-document-task-authority-v2", raw_sha256=raw,
        display_id=7, stack_id=41, task_id=41, task_token="abc",
        activity_token="def", pid=3141, uid=runner.ANDROID_SYSTEM_UID,
        package_name=runner.PACKAGE_NAME, process_name=runner.PACKAGE_NAME,
        component="com.supernote.document/.document.DocumentActivity",
        base_apk_path="/data/app/document/base.apk", state="RESUMED", resumed=True,
        stopped=False, delayed_resume=False, finishing=False, task_visible=True,
        visible_requested=True, visible=True, client_visible=True, reported_drawn=True,
        reported_visible=True, now_visible=True,
        width=runner.VIRTUAL_DISPLAY_WIDTH, height=runner.VIRTUAL_DISPLAY_HEIGHT,
        density_dpi=runner.VIRTUAL_DISPLAY_DENSITY_DPI,
        rotation=runner.VIRTUAL_DISPLAY_ROTATION)


class FakeBundle:
    def __init__(self):
        self.verify_count = 0
        self.open = True
        self.fail_verify_at = None
        self.used_while_open = []
        self.clock = None
        self.advance_verify_at = None
        self.advance_to = None

    @property
    def executable(self):
        if not self.open:
            raise RuntimeError("closed")
        return "C:/locked/adb.exe"

    def verify(self):
        self.verify_count += 1
        if self.verify_count == self.advance_verify_at:
            self.clock.set(self.advance_to)
        if not self.open or self.verify_count == self.fail_verify_at:
            raise RuntimeError("bundle drift")

    def canonical_bytes(self):
        files = {}
        for index, name in enumerate(runner.WINDOWS_TOOL_FILENAMES):
            files[name] = {"basename": name, "path": "C:/locked/" + name,
                           "size": 1000 + index, "sha256": ADB_FILE_HASHES[name],
                           "identity": {"attributes": 32, "volume_serial": 1,
                                        "file_index": index + 1, "link_count": 1,
                                        "size": 1000 + index, "creation_time": 1,
                                        "last_write_time": 2}}
        return canon({"authority": runner.WINDOWS_TOOL_AUTHORITY, "files": files})


def admission_value(receipt_key=RECEIPT_KEY):
    return {"schemaVersion": 2, "authority": runner.PROVIDER_ADMISSION_AUTHORITY,
            "implementationSha256": "6" * 64,
            "providerSessionId": "frida-provider-session:0001",
            "independentCapture": True,
            "doesNotEchoManifest": True, "usesLockedAdbBundle": True,
            "privateAdbServer": True, "serverNodaemon": True,
            "serverProcessHandleRetained": True, "fixedMinimalEnvironment": True,
            "explicitSerialEveryCommand": True,
            "rejectsAmbientOverrides": list(runner.ADB_OVERRIDE_NAMES),
            "noSharedServer": True, "authenticatesFridaHostAndServer": True,
            "exactFridaTeardown": True, "capturesBeforeAndAfter": True,
            "providerProcessIsolated": True, "failurePathKillAndJoin": True,
            "failureReturnsOnlyAfterQuiescence": True, "atomicStartPermit": True,
            "challengeBoundReceipts": True, "freshCaptureIds": True,
            "receiptSequenceChain": True, "receiptMacAlgorithm": "HMAC-SHA256",
            "receiptKeyId": hashlib.sha256(receipt_key).hexdigest(),
            "receiptAcquisitionOwnsSources": True}


def frida_admission_value():
    return {"schemaVersion": 1, "authority": "rtl-reader-frida-provider-admission-v1",
            "implementationSha256": "7" * 64,
            "providerSessionId": "frida-provider-session:0001",
            "isolatedCancellableLifecycle": True, "callbackQuiescenceBarrier": True,
            "singleAttach": True, "singleLoad": True, "exactTeardown": True,
            "teardownReturnsOnlyAfterKillJoin": True,
            "callbackChannelSealedBeforeReturn": True, "atomicStartPermit": True,
            "noRetry": True}


def stage_value(manifest, bound, tool_sha, phase, task_value=None):
    selected_task = task() if task_value is None else task_value
    task_loaded = runner.load_canonical(selected_task.canonical_bytes(), runner.MAX_AUTHORITY_BYTES)
    files = copy.deepcopy(manifest.value["files"])
    cmdline = runner.PACKAGE_NAME
    frida = {
        "authority": runner.FRIDA_AUTHORITY,
        "providerSessionId": "frida-provider-session:0001",
        "hostPythonPath": "C:/pinned/python.exe", "hostPythonSha256": "8" * 64,
        "hostFridaVersion": "17.2.17", "hostFridaPackageSha256": "9" * 64,
        "hostNativeDependenciesSha256": "a" * 64,
        "serverPath": "/data/local/tmp/pinned-frida-server", "serverSha256": "b" * 64,
        "serverUid": 0, "serverPid": 2718, "serverStartTimeTicks": "8000001",
        "serverCmdline": "/data/local/tmp/pinned-frida-server",
        "serverVersion": "17.2.17", "serverSessionId": "frida-server-session:0001",
        "serverState": "ready" if phase == "before" else "torn-down",
        "exactTeardownRequired": True, "processAbsent": phase == "after",
        "fileAbsent": phase == "after",
        "teardownOfSessionId": (None if phase == "before" else "frida-server-session:0001"),
    }
    return {
        "schemaVersion": 2, "authority": runner.STAGE_AUTHORITY, "phase": phase,
        "captureId": "authority-capture-" + phase + ":0001",
        "providerSessionId": "frida-provider-session:0001",
        "manifestSha256": manifest.sha256, "toolBundleSha256": tool_sha,
        "taskAuthoritySha256": task_loaded.sha256,
        "privateAdbServer": {
            "authority": runner.ADB_SERVER_AUTHORITY, "host": "127.0.0.1", "port": 5038,
            "pid": 2222, "processCreationFileTime": "133700000000000000",
            "executablePath": "C:/locked/adb.exe",
            "executableSha256": ADB_FILE_HASHES["adb.exe"],
            "serverSessionId": "private-adb-session:0001", "launchMode": "server-nodaemon",
            "processHandleRetained": True, "fixedMinimalEnvironment": True,
            "minimalEnvironmentSha256": "c" * 64, "explicitSerialEveryCommand": True,
            "rejectsAmbientOverrides": list(runner.ADB_OVERRIDE_NAMES), "noSharedServer": True,
            "toolBundleSha256": tool_sha, "state": "ready",
        },
        "target": {
            "authority": runner.TARGET_AUTHORITY, "serial": bound.serial, "pid": bound.pid,
            "startTimeTicks": bound.start_time_ticks, "cmdline": cmdline,
            "cmdlineSha256": hashlib.sha256(cmdline.encode()).hexdigest(),
            "packageName": runner.PACKAGE_NAME, "processName": runner.PACKAGE_NAME,
            "alive": True,
        },
        "firmware": {"fingerprint": runner.FIRMWARE_FINGERPRINT,
                     "apk": copy.deepcopy(manifest.value["attachment"]["apk"]),
                     "framework": copy.deepcopy(manifest.value["attachment"]["framework"]),
                     "module": copy.deepcopy(manifest.value["attachment"]["module"])},
        "files": files,
        "host": {
            "authority": runner.HOST_AUTHORITY,
            "hostSessionId": manifest.value["externalSession"]["hostSessionId"],
            "stage": bound.stage, "displayId": manifest.value["externalSession"]["displayId"],
            "defaultDisplayId": 0,
            "displayGeneration": manifest.value["externalSession"]["displayGeneration"],
            "placementRequestGeneration": 12, "placementReadyGeneration": 12,
            "hostPackageName": "com.techrebbe.displayhost", "hostApkSha256": "d" * 64,
            "hostTaskId": 52, "hostActivityToken": "ActivityRecord{host}",
            "displaySize": [runner.VIRTUAL_DISPLAY_WIDTH, runner.VIRTUAL_DISPLAY_HEIGHT],
            "densityDpi": runner.VIRTUAL_DISPLAY_DENSITY_DPI,
            "requestedFrame": [0, 0, 1404, 1872],
            "measuredGlobalFrame": [0, 0, 1404, 1872], "applied": True,
            "activityResumed": True, "activityVisible": True, "activityFocused": True,
            "surfaceAttached": True, "surfaceValid": True,
        },
        "penLease": {
            "authority": runner.PEN_LEASE_AUTHORITY, "leaseId": "pen-lease-session:0001",
            "serial": bound.serial, "helperPid": 2600, "helperStartTimeTicks": "7000001",
            "holderSessionId": bound.observer_session_id, "mode": "observation-only",
            "deviceClockDomain": "android-boottime-v1",
            "remainingLeaseMs": bound.deadline_ms + runner.CLEANUP_TIMEOUT_MS + 1000,
            "active": True,
        },
        "frida": frida,
    }


class FakeAuthorityProvider:
    def __init__(self, before, after, selected_task=None, admission=None,
                 receipt_key=RECEIPT_KEY):
        self.before = before
        self.after = after
        self.task = task() if selected_task is None else selected_task
        self.task_after = self.task
        self.admission_record = wrapped(admission_value() if admission is None else admission)
        self.admission_count = 0
        self.capture_phases = []
        self.cancel_count = 0
        self.quiesce_count = 0
        self.failure_phase = None
        self.clock = None
        self.advance_on_phase = None
        self.advance_to = None
        self.block_phase = None
        self.cancel_event = threading.Event()
        self.timeouts = []
        self.active_after_failure = False
        self.after_started_while_active = False
        self.fail_quiesce_once = False
        self.fail_cancel = False
        self.fail_stop_count = 0
        self.admission_failure = None
        self.typed_failure_phase = None
        self.capture_counter = 0
        self.receipt_mutator = None
        self.runtime_lease_decay_ms = 0
        self.emitted_records = []
        self.fixed_capture_id = None
        self.receipt_key = receipt_key
        self.receipt_authenticator_override = None
        self.advance_quiesce_at = None
        self.advance_quiesce_to = None
        self.mutate_shared_task_after = None
        self.mutate_request_binding_deadline_ms = None
        self.register_block_phase = None
        self.register_entered = threading.Event()
        self.register_device_work = []
        self.fail_stopped = False
        self.post_register_block_phase = None
        self.post_register_entered = threading.Event()

    def _register_operation(self, phase, timeout_ms, operation):
        if self.register_block_phase == phase:
            self.register_entered.set()
            self.cancel_event.wait(2)
        if self.fail_stopped:
            return
        self.register_device_work.append(phase)
        self.timeouts.append(("admission" if phase == "admission" else
                              "capture-" + phase, timeout_ms))
        operation()

    def _post_registration_wait(self, phase):
        if self.post_register_block_phase == phase:
            self.post_register_entered.set()
            self.cancel_event.wait(2)
            if self.fail_stopped:
                raise runner.AuthorityProviderQuiescenceFailure(
                    "isolated authority operation was fail-stopped")

    def admission(self, timeout_ms, start_permit):
        def register():
            self._register_operation(
                "admission", timeout_ms,
                lambda: setattr(self, "admission_count", self.admission_count + 1))
        start_permit.start(register)
        self._post_registration_wait("admission")
        if self.admission_failure is not None:
            raise self.admission_failure
        return self.admission_record

    def capture(self, request, timeout_ms, start_permit):
        def register():
            def commit():
                self.capture_phases.append(request.phase)
                self.capture_counter += 1
            self._register_operation(request.phase, timeout_ms, commit)
        start_permit.start(register)
        self._post_registration_wait(request.phase)
        if request.phase == "before" and self.mutate_request_binding_deadline_ms is not None:
            object.__setattr__(request.binding, "deadline_ms",
                               self.mutate_request_binding_deadline_ms)
        if request.phase == "after" and self.active_after_failure:
            self.after_started_while_active = True
        if self.block_phase == request.phase:
            self.cancel_event.wait(2)
        if self.advance_on_phase == request.phase:
            self.clock.set(self.advance_to)
        if self.failure_phase == request.phase:
            self.active_after_failure = True
            raise RuntimeError("capture failure")
        if self.typed_failure_phase == request.phase:
            self.active_after_failure = True
            raise runner.AuthorityProviderQuiescenceFailure("provider channel lost")
        stage = copy.deepcopy(self.before if request.phase == "before" else self.after)
        if request.phase == "after" and self.mutate_shared_task_after is not None:
            name, value = self.mutate_shared_task_after
            object.__setattr__(self.task, name, value)
            self.task_after = self.task
            stage["taskAuthoritySha256"] = hashlib.sha256(
                self.task_after.canonical_bytes()).hexdigest()
        stage["captureId"] = (self.fixed_capture_id or
                              ("authority-capture-" + request.phase + ":" +
                               f"{self.capture_counter:016d}"))
        if request.phase == "after":
            stage["penLease"]["remainingLeaseMs"] -= self.runtime_lease_decay_ms
        record = wrapped(stage)
        admission = runner.load_canonical(self.admission_record.raw,
                                          runner.MAX_AUTHORITY_BYTES).value
        receipt_value = {
            "schemaVersion": 2, "authority": runner.STAGE_RECEIPT_AUTHORITY,
            "providerImplementationSha256": admission["implementationSha256"],
            "providerSessionId": admission["providerSessionId"],
            "runNonce": request.run_nonce, "manifestSha256": request.manifest_sha256,
            "observerSessionId": request.binding.observer_session_id,
            "stage": request.binding.stage, "phase": request.phase,
            "sequence": request.sequence,
            "previousReceiptSha256": request.previous_receipt_sha256,
            "captureSha256": record.sha256,
            "absoluteMonotonicDeadlineNs": str(request.absolute_deadline_ns),
            "receiptKeyId": admission["receiptKeyId"],
        }
        if self.receipt_mutator is not None:
            self.receipt_mutator(receipt_value, request)
        receipt_value["authenticator"] = (
            self.receipt_authenticator_override or
            hmac.new(self.receipt_key, canon(receipt_value), hashlib.sha256).hexdigest())
        self.emitted_records.append((copy.deepcopy(stage), copy.deepcopy(receipt_value)))
        return runner.StageAuthorityCapture(
            record, self.task if request.phase == "before" else self.task_after,
            wrapped(receipt_value))

    def cancel_and_quiesce(self, timeout_ms):
        self.timeouts.append(("cancel", timeout_ms))
        self.cancel_count += 1
        if self.fail_cancel:
            raise RuntimeError("cancel failed")
        self.active_after_failure = False
        self.cancel_event.set()

    def assert_quiescent(self, timeout_ms):
        self.timeouts.append(("quiesce", timeout_ms))
        self.quiesce_count += 1
        if self.quiesce_count == self.advance_quiesce_at:
            self.clock.set(self.advance_quiesce_to)
        if self.fail_quiesce_once:
            self.fail_quiesce_once = False
            raise RuntimeError("transient non-quiescence")
        if self.active_after_failure:
            raise RuntimeError("provider still active")

    def fail_stop_and_quiesce(self, timeout_ms):
        self.timeouts.append(("fail-stop", timeout_ms))
        self.fail_stop_count += 1
        self.active_after_failure = False
        self.fail_stopped = True
        self.cancel_event.set()


class FakeSession:
    def __init__(self, provider, manifest, frames=None):
        self.provider = provider
        self.manifest = manifest
        self.frames = frames
        self.load_count = 0
        self.seal_count = 0
        self.unload_count = 0
        self.detach_count = 0
        self.quiesce_count = 0
        self.fail_phase = None
        self.block_phase = None
        self.late_on_seal = False
        self.callback = None
        self.timeouts = []
        self.advance_phase = None
        self.advance_ns = 0

    def _phase(self, name):
        if self.advance_phase == name:
            self.provider.clock.set(self.provider.clock() + self.advance_ns)
        if self.block_phase == name:
            self.provider.teardown_event.wait(2)
        if self.fail_phase == name:
            raise RuntimeError(name)

    def load(self, source, on_message, timeout_ms, start_permit):
        def register():
            self.provider._register_operation(
                "load", timeout_ms,
                lambda: setattr(self, "load_count", self.load_count + 1))
        start_permit.start(register)
        self.provider._post_registration_wait("load")
        self.callback = on_message
        self._phase("load")
        frames = self.frames
        if frames is None:
            frames = success_frames(self.manifest)
        for message, data in frames:
            on_message(message, data)

    def seal_callbacks(self, timeout_ms):
        self.timeouts.append(("seal", timeout_ms))
        self.seal_count += 1
        if self.late_on_seal and self.callback is not None:
            self.callback({"type": "send", "payload":
                           {"event": "native_page_graph_snapshot_complete", "success": True}}, None)
        self._phase("seal")

    def unload(self, timeout_ms):
        self.timeouts.append(("unload", timeout_ms))
        self.unload_count += 1
        self._phase("unload")

    def detach(self, timeout_ms):
        self.timeouts.append(("detach", timeout_ms))
        self.detach_count += 1
        self._phase("detach")

    def assert_quiescent(self, timeout_ms):
        self.timeouts.append(("quiesce", timeout_ms))
        self.quiesce_count += 1
        self._phase("quiesce")


class FakeFrida:
    def __init__(self, manifest, frames=None):
        self.manifest = manifest
        self.frames = frames
        self.admission_record = wrapped(frida_admission_value())
        self.admission_count = 0
        self.attach_count = 0
        self.teardown_count = 0
        self.quiesce_count = 0
        self.teardown_event = threading.Event()
        self.session = FakeSession(self, manifest, frames)
        self.fail_attach = False
        self.block_admission = False
        self.block_attach = False
        self.fail_teardown = False
        self.fail_quiesce = False
        self.timeouts = []
        self.clock = None
        self.rollback_on_attach_to = None
        self.register_block_phase = None
        self.register_entered = threading.Event()
        self.register_device_work = []
        self.terminal = False
        self.post_register_block_phase = None
        self.post_register_entered = threading.Event()

    def _register_operation(self, phase, timeout_ms, operation):
        if self.register_block_phase == phase:
            self.register_entered.set()
            self.teardown_event.wait(2)
        if self.terminal:
            return
        self.register_device_work.append(phase)
        self.timeouts.append((phase, timeout_ms))
        operation()

    def _post_registration_wait(self, phase):
        if self.post_register_block_phase == phase:
            self.post_register_entered.set()
            self.teardown_event.wait(2)
            if self.terminal:
                raise runner.FridaProviderQuiescenceFailure(
                    "isolated Frida operation was torn down")

    def admission(self, timeout_ms, start_permit):
        def register():
            self._register_operation(
                "admission", timeout_ms,
                lambda: setattr(self, "admission_count", self.admission_count + 1))
        start_permit.start(register)
        self._post_registration_wait("admission")
        if self.block_admission:
            self.teardown_event.wait(2)
        return self.admission_record

    def attach(self, serial, pid, timeout_ms, start_permit):
        def register():
            self._register_operation(
                "attach", timeout_ms,
                lambda: setattr(self, "attach_count", self.attach_count + 1))
        start_permit.start(register)
        self._post_registration_wait("attach")
        if self.block_attach:
            self.teardown_event.wait(2)
        if self.fail_attach:
            raise RuntimeError("attach")
        if self.rollback_on_attach_to is not None:
            self.clock.set(self.rollback_on_attach_to)
        return self.session

    def teardown(self, timeout_ms):
        self.timeouts.append(("teardown", timeout_ms))
        self.teardown_count += 1
        self.terminal = True
        self.teardown_event.set()
        if self.fail_teardown:
            raise RuntimeError("teardown")

    def assert_quiescent(self, timeout_ms):
        self.timeouts.append(("quiesce", timeout_ms))
        self.quiesce_count += 1
        if self.fail_quiesce:
            raise RuntimeError("not quiescent")


def environment(*, mark=True, stage="FULL", deadline_ms=1000,
                clock=None, clock_factory=None):
    if clock is not None and clock_factory is not None:
        raise ValueError("supply either clock or clock_factory")
    if clock is None:
        clock = (Clock if clock_factory is None else clock_factory)()
    bound = binding(clock, deadline_ms=deadline_ms, stage=stage)
    manifest = loaded_manifest(bound, mark=mark)
    bundle = FakeBundle()
    tool = runner.load_canonical(bundle.canonical_bytes(), runner.MAX_AUTHORITY_BYTES)
    before = stage_value(manifest, bound, tool.sha256, "before")
    after = stage_value(manifest, bound, tool.sha256, "after")
    provider = FakeAuthorityProvider(before, after)
    frida = FakeFrida(manifest)
    bundle.clock = clock
    provider.clock = clock
    frida.clock = clock
    pins = runner.TrustedPins(
        tool.sha256, manifest.sha256, provider.admission_record.sha256,
        frida.admission_record.sha256, runner.stage_policy_sha256(before), RECEIPT_KEY)
    return clock, bound, manifest, bundle, provider, frida, pins


def run_env(values, **overrides):
    clock, bound, manifest, bundle, provider, frida, pins = values
    arguments = dict(manifest=manifest, observer_source=OBSERVER_TEXT,
                     observer_sha256=OBSERVER_SHA, binding=bound, tool_bundle=bundle,
                     authority_provider=provider, frida_provider=frida,
                     trusted_pins=pins, ambient_environment={}, clock_ns=clock)
    arguments["nonce_factory"] = lambda: "e" * 64
    arguments.update(overrides)
    return runner.run_one_stage(**arguments)


def authorize_test_policy(values):
    clock, bound, manifest, bundle, provider, frida, _ = values
    pins = replace(values[6], stage_policy_sha256=runner.stage_policy_sha256(provider.before))
    return clock, bound, manifest, bundle, provider, frida, pins


def authorize_test_admissions(values):
    clock, bound, manifest, bundle, provider, frida, pins = values
    pins = replace(pins, provider_admission_sha256=provider.admission_record.sha256,
                   frida_admission_sha256=frida.admission_record.sha256)
    return clock, bound, manifest, bundle, provider, frida, pins


def success_frames(manifest, first=None, terminal=True):
    return [({"type": "send", "payload": snapshot_value(manifest) if first is None else first}, None),
            ({"type": "send", "payload": {"event": "native_page_graph_snapshot_complete",
                                            "success": terminal}}, None)]


class BaselineTests(unittest.TestCase):
    def test_complete_stage_and_exact_lifecycle(self):
        values = environment()
        result = run_env(values)
        _, _, manifest, bundle, provider, frida, pins = values
        self.assertEqual(result["authority"], runner.RUNNER_AUTHORITY)
        self.assertEqual(result["manifestSha256"], manifest.sha256)
        self.assertEqual(result["toolBundleSha256"], pins.tool_bundle_sha256)
        self.assertEqual(provider.admission_count, 1)
        self.assertEqual(provider.capture_phases, ["before", "after"])
        self.assertEqual(frida.admission_count, 1)
        self.assertEqual(frida.attach_count, 1)
        self.assertEqual(frida.session.load_count, 1)
        self.assertEqual(frida.session.seal_count, 1)
        self.assertEqual(frida.session.unload_count, 1)
        self.assertEqual(frida.session.detach_count, 1)
        self.assertEqual(frida.session.quiesce_count, 1)
        self.assertEqual(frida.teardown_count, 1)
        self.assertGreaterEqual(bundle.verify_count, 8)

    def test_live_capture_values_are_fresh_outputs_not_future_digest_inputs(self):
        values = environment()
        pins_before_capture = values[6]
        values[4].runtime_lease_decay_ms = 137
        result = run_env(values)
        self.assertEqual(values[6], pins_before_capture)
        self.assertEqual(len(values[4].emitted_records), 2)
        before, after = (item[0] for item in values[4].emitted_records)
        self.assertNotEqual(before["captureId"], after["captureId"])
        self.assertEqual(after["penLease"]["remainingLeaseMs"],
                         before["penLease"]["remainingLeaseMs"] - 137)
        self.assertNotEqual(result["beforeAuthoritySha256"],
                            result["afterAuthoritySha256"])
        self.assertNotEqual(result["beforeReceiptSha256"], result["afterReceiptSha256"])

    def test_receipt_challenge_phase_sequence_chain_and_capture_digest_are_bound(self):
        mutations = (
            lambda receipt, request: receipt.update(runNonce="f" * 64),
            lambda receipt, request: receipt.update(phase="after" if request.phase == "before"
                                                     else "before"),
            lambda receipt, request: receipt.update(sequence=request.sequence + 1),
            lambda receipt, request: receipt.update(sequence=True),
            lambda receipt, request: receipt.update(schemaVersion=True),
            lambda receipt, request: receipt.update(previousReceiptSha256=ZERO_SHA),
            lambda receipt, request: receipt.update(captureSha256=ZERO_SHA),
            lambda receipt, request: receipt.update(observerSessionId="other-session-id:0001"),
            lambda receipt, request: receipt.update(
                providerSessionId="other-provider-session:0001"),
            lambda receipt, request: receipt.update(providerImplementationSha256=ZERO_SHA),
            lambda receipt, request: receipt.update(manifestSha256=ZERO_SHA),
        )
        for index, mutation in enumerate(mutations):
            values = environment()
            values[4].receipt_mutator = mutation
            with self.subTest(index=index), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertEqual(values[4].fail_stop_count, 1)

    def test_receipt_requires_independently_provisioned_hmac_capability(self):
        values = environment()
        values[4].receipt_authenticator_override = ZERO_SHA
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, ["before"])
        self.assertEqual(values[4].fail_stop_count, 1)

        values = environment()
        values[4].receipt_key = b"X" * 32
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, ["before"])
        self.assertEqual(values[4].fail_stop_count, 1)

        values = environment()
        pins = replace(values[6], receipt_hmac_key=b"X" * 32)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values, trusted_pins=pins)
        self.assertEqual(values[4].capture_phases, [])

    def test_stale_capture_cannot_be_reenveloped_for_fresh_nonce_without_hmac_key(self):
        first = environment()
        run_env(first, nonce_factory=lambda: "a" * 64)
        old_stage, old_receipt = first[4].emitted_records[0]

        second = environment()
        second[4].before = copy.deepcopy(old_stage)
        second[4].fixed_capture_id = old_stage["captureId"]
        second[4].receipt_authenticator_override = old_receipt["authenticator"]
        with self.assertRaises(runner.GraphRunnerError):
            run_env(second, nonce_factory=lambda: "b" * 64)
        self.assertEqual(second[4].capture_phases, ["before"])
        self.assertEqual(second[4].fail_stop_count, 1)

    def test_capture_id_replay_is_rejected_even_with_valid_fresh_receipt_chain(self):
        values = environment()
        values[4].fixed_capture_id = "authority-capture-replayed:0001"
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_runner_nonce_is_generated_once_and_must_be_strict_random_wire(self):
        values = environment()
        calls = []
        result = run_env(values, nonce_factory=lambda: calls.append(1) or "a" * 64)
        self.assertEqual(calls, [1])
        self.assertEqual(result["runNonce"], "a" * 64)
        for invalid in ("A" * 64, "a" * 63, 1, None):
            values = environment()
            with self.subTest(invalid=invalid), self.assertRaises(runner.GraphRunnerError):
                run_env(values, nonce_factory=lambda invalid=invalid: invalid)
            self.assertEqual(values[4].admission_count, 0)

    def test_nullable_mark_and_content_uri(self):
        values = environment(mark=False)
        self.assertIsNone(run_env(values)["snapshot"]["presenter"]["markPath"])
        clock = Clock()
        bound = binding(clock)
        manifest = loaded_manifest(bound, mark=False, uri_kind="content")
        runner.validate_manifest(manifest, bound, OBSERVER_SHA)

    def test_all_exact_stages(self):
        for stage in sorted(runner.STAGES):
            with self.subTest(stage=stage):
                self.assertEqual(run_env(environment(stage=stage))["stage"], stage)

    def test_source_injection_is_bytes_and_digest_only(self):
        values = environment()
        injected = runner.build_injected_observer(values[2], OBSERVER_TEXT)
        self.assertTrue(injected.startswith("globalThis.NATIVE_PAGE_GRAPH_MANIFEST_UTF8=Object.freeze(["))
        self.assertIn(values[2].sha256, injected[:len(values[2].raw) * 5 + 500])
        self.assertTrue(injected.endswith(OBSERVER_TEXT))

    def test_cli_is_intentionally_blocked(self):
        output = io.BytesIO()
        with mock.patch.object(runner.sys, "stdout") as stdout:
            stdout.buffer = output
            status = runner.main(["--manifest", "m", "--observer", "o"])
        self.assertEqual(status, 2)
        record = json.loads(output.getvalue())
        self.assertEqual(record["code"], "HARDWARE_ADMISSION_BLOCKED")


class ManifestAndSourceTests(unittest.TestCase):
    def assert_manifest_rejected(self, mutate):
        clock = Clock()
        bound = binding(clock)
        value = manifest_value(bound)
        mutate(value)
        loaded = runner.load_canonical(canon(value), runner.MAX_MANIFEST_BYTES)
        with self.assertRaises(runner.GraphRunnerError):
            runner.validate_manifest(loaded, bound, OBSERVER_SHA)

    def test_manifest_field_pin_mutations(self):
        mutations = [
            lambda m: m.update(extra=1),
            lambda m: m.pop("expected"),
            lambda m: m["attachment"].update(packageName="evil"),
            lambda m: m["attachment"].update(processName=runner.PACKAGE_NAME),
            lambda m: m["attachment"].update(pid=4_194_305),
            lambda m: m["attachment"].update(startTimeTicks="01"),
            lambda m: m["attachment"]["apk"].update(sha256=ZERO_SHA),
            lambda m: m["attachment"]["framework"].update(size=1),
            lambda m: m["attachment"].update(observerSha256=ZERO_SHA),
            lambda m: m["externalSession"].update(authorizedSerial="other"),
            lambda m: m["externalSession"].update(taskId=10_000_001),
            lambda m: m["externalSession"].update(displayId=0),
            lambda m: m["externalSession"].update(displayId=False),
            lambda m: m["externalSession"].update(displayGeneration=0),
            lambda m: m["externalSession"].update(displayGeneration=False),
            lambda m: m["externalSession"].update(hostSessionId="short"),
            lambda m: m["files"].update(verification="echo"),
            lambda m: m["files"]["originalPdf"].update(present=False),
            lambda m: m["files"]["originalPdf"].update(size="01"),
            lambda m: m["files"]["originalPdf"]["uriResolution"].update(resolvedPath="/other"),
            lambda m: m["files"]["mark"].update(present=False),
            lambda m: m["coordinator"].update(maxJavaChooseWalks=2),
            lambda m: m["coordinator"].update(noRetry=False),
            lambda m: m["coordinator"].update(hardDeadlineMs=10_001),
            lambda m: m["coordinator"].update(absoluteMonotonicDeadlineNs="01"),
            lambda m: m["expected"]["calibrationProfile"].update(matrixSemantics="inverse"),
            lambda m: m["expected"].update(documentUri="file:///other"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_manifest_rejected(mutation)

    def test_absent_mark_requires_exact_null_payload(self):
        self.assert_manifest_rejected(
            lambda m: m["files"].update(mark={"present": False, "path": "/stale",
                                               "size": None, "sha256": None, "stat": None}))

    def test_binding_mismatches_are_rejected(self):
        clock = Clock()
        bound = binding(clock)
        manifest = loaded_manifest(bound)
        changes = [
            {"serial": "other"}, {"serial": "x; reboot"}, {"pid": 7},
            {"start_time_ticks": "1"},
            {"observer_session_id": "observer-session-v2:9999"}, {"deadline_ms": 999},
            {"absolute_deadline_ns": bound.absolute_deadline_ns + 1}, {"stage": "BAD"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(runner.GraphRunnerError):
                runner.validate_manifest(manifest, replace(bound, **change), OBSERVER_SHA)

    def test_canonical_json_rejects_duplicate_float_whitespace_and_nul(self):
        wires = [b'{"a":1,"a":2}', b'{"a":1.0}', b'{ "a":1}', b'{"a":"x\\u0000y"}',
                 b'{"a":9007199254740992}']
        for wire in wires:
            with self.subTest(wire=wire), self.assertRaises(runner.GraphRunnerError):
                runner.load_canonical(wire, 1024)

    def test_regular_snapshot_reads_and_rejects_symlink_and_replacement(self):
        clock = Clock()
        bound = binding(clock)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(canon(manifest_value(bound)))
            loaded = runner.load_manifest(manifest_path, bound, OBSERVER_SHA)
            self.assertEqual(loaded.value["schemaVersion"], 2)
            link = root / "manifest-link.json"
            try:
                link.symlink_to(manifest_path)
            except OSError:
                pass
            else:
                with self.assertRaises(runner.GraphRunnerError):
                    runner.load_manifest(link, bound, OBSERVER_SHA)
            wrong = root / "observer.js"
            wrong.write_text("'use strict';", encoding="utf-8")
            with self.assertRaises(runner.GraphRunnerError):
                runner.load_observer_source(wrong)
        text, digest = runner.load_observer_source(OBSERVER)
        self.assertEqual(text, OBSERVER_TEXT)
        self.assertEqual(digest, OBSERVER_SHA)

    def test_regular_snapshot_rejects_size_eof_growth_and_final_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "retained.bin"
            selected.write_bytes(b"abc")
            real_fstat = runner.os.fstat
            real_read = runner.os.read
            real_lstat = runner.os.lstat
            real_close = runner.os.close

            def stat_with(stat_value, index, value):
                fields = list(stat_value)
                fields[index] = value
                return runner.os.stat_result(fields)

            def zero_size(descriptor):
                current = real_fstat(descriptor)
                return stat_with(current, 6, 0)

            with self.subTest(case="invalid-open-size"), \
                    mock.patch.object(runner.os, "fstat", side_effect=zero_size), \
                    self.assertRaises(runner.GraphRunnerError):
                runner._read_regular_snapshot(selected, 1024, "fixture")

            with self.subTest(case="early-eof"), \
                    mock.patch.object(runner.os, "read", return_value=b""), \
                    self.assertRaises(runner.GraphRunnerError):
                runner._read_regular_snapshot(selected, 1024, "fixture")

            read_count = 0

            def growing_read(descriptor, amount):
                nonlocal read_count
                read_count += 1
                if read_count == 1:
                    return real_read(descriptor, amount)
                return b"x"

            with self.subTest(case="growth"), \
                    mock.patch.object(runner.os, "read", side_effect=growing_read), \
                    self.assertRaises(runner.GraphRunnerError):
                runner._read_regular_snapshot(selected, 1024, "fixture")

            closed = False

            def tracked_close(descriptor):
                nonlocal closed
                real_close(descriptor)
                closed = True

            def replaced_lstat(path):
                current = real_lstat(path)
                if closed:
                    return stat_with(current, 1, current.st_ino + 1)
                return current

            with self.subTest(case="final-path-replacement"), \
                    mock.patch.object(runner.os, "close", side_effect=tracked_close), \
                    mock.patch.object(runner.os, "lstat", side_effect=replaced_lstat), \
                    self.assertRaises(runner.GraphRunnerError):
                runner._read_regular_snapshot(selected, 1024, "fixture")

    def test_private_manifest_reconstruction_defeats_caller_mutation(self):
        values = environment()
        manifest = values[2]
        private = runner.load_canonical(manifest.raw, runner.MAX_MANIFEST_BYTES)
        values[5].manifest = private
        values[5].session.manifest = private
        manifest.value["attachment"]["pid"] = 9999
        self.assertEqual(run_env(values)["snapshot"]["attachment"]["pid"], 3141)

    def test_injected_observer_text_is_hashed_not_labeled_by_caller(self):
        values = environment()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values, observer_source=OBSERVER_TEXT + "\n")
        self.assertEqual(values[4].admission_count, 0)
        self.assertEqual(values[5].attach_count, 0)

    def test_observer_source_requires_exact_builtin_string(self):
        class HostileString(str):
            def encode(self, *args, **kwargs):
                return OBSERVER_TEXT.encode("utf-8")

        values = environment()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values, observer_source=HostileString("hostile"))
        self.assertEqual(values[4].admission_count, 0)


class SnapshotValidationTests(unittest.TestCase):
    def setUp(self):
        self.values = environment()
        self.manifest = self.values[2]
        self.external = self.values[4].before

    def reject(self, mutate):
        value = snapshot_value(self.manifest)
        mutate(value)
        with self.assertRaises(runner.GraphRunnerError):
            runner.validate_snapshot(value, self.manifest, self.external)

    def test_success_and_independent_raw_calibration(self):
        value = snapshot_value(self.manifest)
        value["document"]["rawCurrentPage"] = 7
        value["document"]["rawPageInfoPage"] = 0
        value["presenter"]["rawPresenterPage"] = 6
        value["pageInfo"]["revertCtm"] = matrix((0.5, 0, 0, 0.5, -123, 99))
        value["pageInfo"]["scale"] = b64(-0.0)
        self.assertIs(runner.validate_snapshot(value, self.manifest, self.external), value)

    def test_top_attachment_session_and_file_mutations(self):
        mutations = [
            lambda s: s.update(extra=1), lambda s: s.pop("layers"),
            lambda s: s.update(schemaVersion=3), lambda s: s.update(atomic=True),
            lambda s: s["attachment"].update(pid=9),
            lambda s: s["attachment"].update(architecture="x64"),
            lambda s: s["attachment"]["module"].update(size=1),
            lambda s: s["externalSession"].update(source="observer"),
            lambda s: s["externalSession"].update(displayGeneration=10),
            lambda s: s["fileAuthority"]["originalPdf"].update(sha256=ZERO_SHA),
            lambda s: s["coordinator"].update(heapWalks=2),
            lambda s: s["coordinator"].update(noRetry=False),
            lambda s: s["calibrationProfile"].update(matrixSemantics="inverse"),
            lambda s: s["lifecycle"].update(graphStable=False),
            lambda s: s.update(layers={"status": "available"}),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.reject(mutation)

    def test_file_authority_boolean_integer_aliases_reject(self):
        self.reject(lambda s: s["fileAuthority"]["originalPdf"].update(present=1))
        absent = environment(mark=False)
        value = snapshot_value(absent[2])
        value["fileAuthority"]["mark"]["present"] = 0
        with self.assertRaises(runner.GraphRunnerError):
            runner.validate_snapshot(value, absent[2], absent[4].before)

    def test_document_rect_and_page_mutations(self):
        mutations = [
            lambda s: s["document"].update(uri="file:///other"),
            lambda s: s["document"].update(pageCount=0),
            lambda s: s["document"].update(rawCurrentPage=8),
            lambda s: s["document"].update(rawPageInfoPage=-1),
            lambda s: s["document"]["rectangles"].pop("showRect"),
            lambda s: s["document"]["rectangles"]["scaleRect"].append(b64(1)),
            lambda s: s["document"]["rectangles"].update(scaleRect=rect(0, 0, 0, 1)),
            lambda s: s["document"]["rectangles"]["scaleRect"][0].update(binary64="0X0000000000000000"),
            lambda s: s["document"]["rectangles"]["scaleRect"][0].update(binary64="0x7ff0000000000000"),
            lambda s: s["document"]["rectangles"]["scaleRect"][0].update(binary64="0x7ff8000000000000"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.reject(mutation)

    def test_matrix_bitmap_pointer_and_numeric_mutations(self):
        mutations = [
            lambda s: s["pageInfo"].update(ctm=matrix((1, 0, 0, 0, 0, 0))),
            lambda s: s["pageInfo"].update(ctm=matrix((1e-300, 0, 0, 1e-300, 0, 0))),
            lambda s: s["pageInfo"].update(offset=[1]),
            lambda s: s["pageInfo"].update(offset=[1, 2.0]),
            lambda s: s["pageInfo"]["bitmaps"]["displayBitmap"].update(width=1),
            lambda s: s["pageInfo"]["bitmaps"]["originBitmap"].update(width=0),
            lambda s: s["pageInfo"]["bitmaps"]["originBitmap"]["nativePointer"].update(
                value="0x0000000000000000"),
            lambda s: s["presenter"]["notePointer"].update(present=False),
            lambda s: s["presenter"]["binders"]["iBinder"].update(referenceStable=False),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.reject(mutation)

    def test_presenter_view_and_layer_mutations(self):
        mutations = [
            lambda s: s["presenter"].update(uri="content://other"),
            lambda s: s["presenter"].update(rawPresenterPage=8),
            lambda s: s["presenter"].update(markPath="/other.mark"),
            lambda s: s["views"]["handWriteView"].update(className="android.view.View"),
            lambda s: s["views"]["contentView"].update(bounds=[0, 0, 0, 1]),
            lambda s: s["views"]["documentLayout"].update(scroll=[0]),
            lambda s: s["views"]["digestImage"].update(attached=False),
            lambda s: s["views"].pop("documentImage"),
            lambda s: s["layers"].update(evidenceId="other"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.reject(mutation)

    def test_external_record_is_independent_authority(self):
        external = copy.deepcopy(self.external)
        external["files"]["originalPdf"]["sha256"] = ZERO_SHA
        with self.assertRaises(runner.GraphRunnerError):
            runner.validate_snapshot(snapshot_value(self.manifest), self.manifest, external)


class AuthorityTests(unittest.TestCase):
    def mutate_both_and_reject(self, mutate):
        values = environment()
        mutate(values[4].before)
        mutate(values[4].after)
        values = authorize_test_policy(values)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)


class FramingTests(unittest.TestCase):
    def collector(self, deadline_offset=1_000_000_000):
        values = environment()
        clock = values[0]
        return (runner._V2MessageCollector(values[2], values[4].before,
                                           clock() + deadline_offset, clock), values, clock)

    def test_exact_success_and_exact_rejection_frames(self):
        collector, values, _ = self.collector()
        for frame in success_frames(values[2]):
            collector.on_message(*frame)
        collector.wait()
        self.assertEqual(collector.result()["event"], "native_page_graph_snapshot")

        collector, _, _ = self.collector()
        collector.on_message({"type": "send", "payload": {
            "event": "native_page_graph_snapshot_error", "schemaVersion": 2,
            "code": "GRAPH_SNAPSHOT_REJECTED"}}, None)
        collector.on_message({"type": "send", "payload": {
            "event": "native_page_graph_snapshot_complete", "success": False}}, None)
        with self.assertRaises(runner.SnapshotRejected):
            collector.result()

    def test_wait_resamples_authoritative_clock_after_relative_timeout(self):
        collector, _, clock = self.collector(deadline_offset=100_000_000)

        class TerminalAfterSecondWait:
            def __init__(self):
                self.waits = []

            def wait(self, timeout):
                self.waits.append(timeout)
                return len(self.waits) == 2

        terminal = TerminalAfterSecondWait()
        collector._terminal = terminal
        collector.wait()
        self.assertEqual(terminal.waits, [0.1, 0.1])
        self.assertLess(clock(), collector._deadline_ns)

        collector, _, clock = self.collector(deadline_offset=100_000_000)

        class AdvanceToDeadline:
            def __init__(self):
                self.waits = []

            def wait(self, timeout):
                self.waits.append(timeout)
                clock.set(collector._deadline_ns)
                return False

        terminal = AdvanceToDeadline()
        collector._terminal = terminal
        with self.assertRaises(runner.DeadlineExceeded):
            collector.wait()
        self.assertEqual(terminal.waits, [0.1])
        self.assertEqual(clock(), collector._deadline_ns)

    def test_envelope_and_order_mutations(self):
        bad_sequences = [
            [({"type": "error", "payload": {}}, None)],
            [({"type": "send", "payload": {"event": "native_page_graph_snapshot_complete",
                                              "success": True}}, None)],
            [({"type": "send", "payload": snapshot_value(environment()[2]), "extra": 1}, None)],
            [({"type": "send", "payload": snapshot_value(environment()[2])}, b"binary")],
            [({"type": "send", "payload": {"event": "unknown"}}, None)],
        ]
        for index, frames in enumerate(bad_sequences):
            collector, _, _ = self.collector()
            for frame in frames:
                collector.on_message(*frame)
            with self.subTest(index=index), self.assertRaises(runner.GraphRunnerError):
                collector.result()

    def test_missing_duplicate_extra_and_terminal_disagreement(self):
        collector, values, _ = self.collector()
        collector.on_message(*success_frames(values[2])[0])
        with self.assertRaises(runner.SnapshotRejected):
            collector.result()

        collector, values, _ = self.collector()
        first, terminal = success_frames(values[2])
        collector.on_message(*first)
        collector.on_message(terminal[0] | {"payload": terminal[0]["payload"] | {"success": False}}, None)
        with self.assertRaises(runner.GraphRunnerError):
            collector.result()

        collector, values, _ = self.collector()
        for frame in success_frames(values[2]):
            collector.on_message(*frame)
        collector.on_message(*success_frames(values[2])[1])
        with self.assertRaises(runner.GraphRunnerError):
            collector.result()

    def test_floats_and_oversized_or_unknown_payloads_reject(self):
        collector, _, _ = self.collector()
        collector.on_message({"type": "send", "payload": {"event": "x", "value": 1.5}}, None)
        with self.assertRaises(runner.GraphRunnerError):
            collector.result()
        collector, _, _ = self.collector()
        collector.on_message({"type": "send", "payload": {
            "event": "native_page_graph_snapshot", "padding": ["x" * 30] * 70_000}}, None)
        with self.assertRaises(runner.GraphRunnerError):
            collector.result()
        collector, _, _ = self.collector()
        collector.on_message({"type": "send", "payload": {"event": "x",
                                                              "value": "a" * 5000}}, None)
        with self.assertRaises(runner.GraphRunnerError):
            collector.result()

    def test_aggregate_oversize_rejects_before_whole_wire_serialization(self):
        collector, _, _ = self.collector()
        payload = {"event": "native_page_graph_snapshot",
                   "padding": ["x" * 4096] * 100_000}
        original = runner.json.dumps
        aggregate_serialized = []

        def guarded_dumps(value, *args, **kwargs):
            if value is payload:
                aggregate_serialized.append(True)
                raise AssertionError("aggregate payload reached serializer")
            return original(value, *args, **kwargs)

        with mock.patch.object(runner.json, "dumps", side_effect=guarded_dumps):
            collector.on_message({"type": "send", "payload": payload}, None)
        self.assertEqual(aggregate_serialized, [])
        with self.assertRaises(runner.GraphRunnerError):
            collector.result()

    def test_deadline_is_exclusive_and_late_after_seal_rejects(self):
        collector, values, clock = self.collector(deadline_offset=10)
        clock.set(clock() + 10)
        collector.on_message(*success_frames(values[2])[0])
        with self.assertRaises(runner.DeadlineExceeded):
            collector.result()

        collector, values, _ = self.collector()
        collector.seal()
        collector.on_message(*success_frames(values[2])[0])
        with self.assertRaises(runner.SnapshotRejected):
            collector.assert_clean_after_quiescence()

    def test_callback_payload_is_privately_snapshotted_before_adapter_mutation(self):
        collector, values, _ = self.collector()
        payload = snapshot_value(values[2])
        collector.on_message({"type": "send", "payload": payload}, None)
        payload["attachment"]["pid"] = 9999
        collector.on_message(*success_frames(values[2])[1])
        self.assertEqual(collector.result()["attachment"]["pid"], 3141)

    def test_monotonic_clock_rollback_rejects(self):
        values = iter((100, 101, 99))
        guarded = runner._MonotonicGuard(lambda: next(values))
        self.assertEqual(guarded(), 100)
        self.assertEqual(guarded(), 101)
        with self.assertRaises(runner.GraphRunnerError):
            guarded()


class LifecycleAndDeadlineTests(unittest.TestCase):
    def assert_no_native_page_v2_threads(self):
        live = [thread.name for thread in threading.enumerate()
                if thread.is_alive() and thread.name.startswith("native-page-v2-")]
        self.assertEqual(live, [])

    def test_environment_shares_explicit_clock_across_deadline_authorities(self):
        clock = RunningClock()
        values = environment(clock=clock)
        self.assertIs(values[0], clock)
        self.assertIs(values[3].clock, clock)
        self.assertIs(values[4].clock, clock)
        self.assertIs(values[5].clock, clock)
        self.assertEqual(
            values[2].value["coordinator"]["absoluteMonotonicDeadlineNs"],
            str(values[1].absolute_deadline_ns))
        with mock.patch.object(runner, "run_one_stage", return_value={}) as execute:
            self.assertEqual(run_env(values), {})
        self.assertIs(execute.call_args.kwargs["clock_ns"], clock)

    def test_ambient_adb_overrides_all_fail_before_authority_use(self):
        for name in runner.ADB_OVERRIDE_NAMES:
            values = environment()
            with self.subTest(name=name), self.assertRaises(runner.GraphRunnerError):
                run_env(values, ambient_environment={name.lower(): "hostile"})
            self.assertEqual(values[4].admission_count, 0)
            self.assertEqual(values[5].attach_count, 0)

    def test_deadline_binding_expired_too_far_and_exact_boundary(self):
        values = environment()
        values[0].set(values[1].absolute_deadline_ns)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        values = environment()
        bad = replace(values[1], absolute_deadline_ns=values[1].absolute_deadline_ns + 1)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values, binding=bad)
        values = environment()
        # Manifest deadline exceeds its authenticated duration from this start.
        values[0].set(values[0]() - 1)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_provider_before_failure_still_tears_down_and_suppresses_unchained_after(self):
        values = environment()
        values[4].failure_phase = "before"
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, ["before"])
        self.assertEqual(values[5].teardown_count, 1)
        self.assertGreaterEqual(values[3].verify_count, 6)

    def test_early_provider_failure_is_cancelled_before_after_capture(self):
        values = environment()
        values[4].failure_phase = "before"
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].cancel_count, 1)
        self.assertFalse(values[4].after_started_while_active)
        self.assertEqual(values[4].capture_phases, ["before"])

    def test_initial_quiescence_failure_recovers_but_aborts_stage(self):
        values = environment()
        values[4].fail_quiesce_once = True
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].cancel_count, 1)
        self.assertEqual(values[4].capture_phases, [])
        self.assertEqual(values[4].fail_stop_count, 1)
        self.assertEqual(values[5].attach_count, 0)

    def test_failed_cancel_is_fail_stopped_before_any_later_provider_work(self):
        values = environment()
        values[4].failure_phase = "before"
        values[4].fail_cancel = True
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, ["before"])
        self.assertEqual(values[4].fail_stop_count, 1)
        self.assertFalse(values[4].active_after_failure)
        self.assertEqual(values[5].attach_count, 0)

    def test_provider_after_failure_rejects_completed_snapshot(self):
        values = environment()
        values[4].failure_phase = "after"
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[5].attach_count, 1)
        self.assertEqual(values[4].capture_phases, ["before", "after"])

    def test_admission_failures_teardown_and_suppress_unchained_capture(self):
        for which in ("authority", "frida"):
            values = environment()
            if which == "authority":
                values[4].admission_record = wrapped({**admission_value(),
                                                       "independentCapture": False})
            else:
                values[5].admission_record = wrapped({**frida_admission_value(),
                                                       "singleLoad": False})
            with self.subTest(which=which), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertEqual(values[5].teardown_count, 1)
            self.assertEqual(values[4].capture_phases, [])
            self.assertEqual(values[4].fail_stop_count, 1)
            self.assertGreaterEqual(values[3].verify_count, 4)

    def test_generic_authority_admission_failure_suppresses_same_provider_capture(self):
        values = environment()
        values[4].admission_failure = RuntimeError("admission transport failed")
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, [])
        self.assertEqual(values[4].fail_stop_count, 1)
        self.assertEqual(values[5].attach_count, 0)

    def test_direct_typed_provider_failures_remain_fatal_channel_failures(self):
        for phase in ("admission", "before", "after"):
            values = environment()
            if phase == "admission":
                values[4].admission_failure = runner.AuthorityProviderQuiescenceFailure(
                    "provider channel lost")
            else:
                values[4].typed_failure_phase = phase
            with self.subTest(phase=phase), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            expected = [] if phase == "admission" else (["before"] if phase == "before" else
                                                          ["before", "after"])
            self.assertEqual(values[4].capture_phases, expected)
            self.assertEqual(values[4].fail_stop_count, 1)
            self.assertFalse(values[4].active_after_failure)

    def test_typed_provider_failure_cannot_be_masked_by_same_call_deadline_expiry(self):
        for phase, quiesce_call in (("before", 2), ("after", 3)):
            values = environment()
            values[4].typed_failure_phase = phase
            values[4].clock = values[0]
            # Admission quiescence is call 1; before capture is 2; after is 3.
            # The direct fatal failure must retain its type even when that
            # otherwise successful final quiescence consumes the exact hard
            # deadline.  This is especially important after capture, where no
            # missing-before-receipt fallback can terminally fence the channel.
            values[4].advance_quiesce_at = quiesce_call
            values[4].advance_quiesce_to = values[1].absolute_deadline_ns
            with self.subTest(phase=phase), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertEqual(values[4].capture_phases,
                             ["before"] if phase == "before" else ["before", "after"])
            self.assertEqual(values[4].fail_stop_count, 1)
            self.assertFalse(values[4].active_after_failure)

    def test_watchdog_resamples_absolute_deadline_after_delayed_thread_start(self):
        clock = Clock(1_000_000_000)
        deadline = clock() + 100_000_000
        cancellations = []
        operations = []

        class DelayedStartThread:
            def __init__(self, *, target, name, daemon):
                self.target = target

            def start(self):
                clock.set(deadline)
                self.target()

            def join(self):
                return None

        with mock.patch.object(runner.threading, "Thread", DelayedStartThread):
            with self.assertRaises(runner.DeadlineExceeded):
                runner._bounded_call(lambda permit: permit.start(
                                         lambda: operations.append("started")),
                                     deadline, clock, "delayed",
                                     lambda: cancellations.append("cancel"))
        self.assertEqual(cancellations, ["cancel"])
        self.assertEqual(operations, [])

    def test_watchdog_wait_timeout_requires_fresh_authoritative_clock_expiry(self):
        clock = Clock(1_000_000_000)
        deadline = clock() + 100_000_000

        class StopAfterSecondWait:
            def __init__(self):
                self.waits = []

            def is_set(self):
                return False

            def wait(self, timeout):
                self.waits.append(timeout)
                return len(self.waits) == 2

        stop = StopAfterSecondWait()
        self.assertFalse(runner._watchdog_reached_deadline(stop, deadline, clock))
        self.assertEqual(stop.waits, [0.1, 0.1])

    def test_watchdog_timeout_then_authoritative_deadline_is_terminal(self):
        clock = Clock(1_000_000_000)
        deadline = clock() + 100_000_000

        class AdvanceToDeadline:
            def __init__(self):
                self.waits = []

            def is_set(self):
                return False

            def wait(self, timeout):
                self.waits.append(timeout)
                clock.set(deadline)
                return False

        stop = AdvanceToDeadline()
        self.assertTrue(runner._watchdog_reached_deadline(stop, deadline, clock))
        self.assertEqual(stop.waits, [0.1])

    def test_watchdog_pre_set_stop_wins_without_clock_sample(self):
        samples = []

        class AlreadyStopped:
            def is_set(self):
                return True

            def wait(self, timeout):
                raise AssertionError("pre-set stop must not wait")

        def raising_clock():
            samples.append(True)
            raise RuntimeError("clock must not be sampled")

        self.assertFalse(runner._watchdog_reached_deadline(
            AlreadyStopped(), 1_100_000_000, raising_clock))
        self.assertEqual(samples, [])

    def test_bounded_call_late_stop_cannot_erase_proven_expiry(self):
        clock = Clock(1_000_000_000)
        deadline = clock() + 100_000_000
        target_calls = []
        cancellations = []
        terminal_cancellations = []
        quiescence = []

        class RunDuringJoinThread:
            def __init__(self, *, target, name, daemon):
                self.target = target

            def start(self):
                return None

            def join(self):
                target_calls.append("join")
                self.target()

        def proven_expiry(stop, supplied_deadline, supplied_clock):
            self.assertTrue(stop.is_set())
            self.assertEqual(supplied_deadline, deadline)
            self.assertIs(supplied_clock, clock)
            self.assertLess(clock(), deadline)
            return True

        with mock.patch.object(runner.threading, "Thread", RunDuringJoinThread), \
                mock.patch.object(runner, "_watchdog_reached_deadline",
                                  side_effect=proven_expiry):
            with self.assertRaises(runner.DeadlineExceeded):
                runner._bounded_call(
                    lambda permit: permit.start(lambda: "registered"),
                    deadline, clock, "late-stop",
                    cancel=lambda: cancellations.append("cancel"),
                    quiesce=lambda: quiescence.append("quiescent"),
                    terminal_cancel=lambda: terminal_cancellations.append("terminal"))
        self.assertEqual(target_calls, ["join"])
        self.assertEqual(cancellations, [])
        self.assertEqual(terminal_cancellations, [])
        self.assertEqual(quiescence, ["quiescent"])
        self.assertLess(clock(), deadline)

    def test_frida_late_stop_cannot_erase_proven_expiry(self):
        values = environment()
        clock, bound, manifest, _, _, frida, pins = values
        external = stage_value(manifest, bound, pins.tool_bundle_sha256, "before")
        target_calls = []

        class RecordingTeardown:
            def __init__(self):
                self.calls = 0

            def call(self, timeout_ms):
                self.calls += 1
                frida.teardown(timeout_ms)

        teardown = RecordingTeardown()

        class RunDuringJoinThread:
            def __init__(self, *, target, name, daemon):
                self.target = target

            def start(self):
                return None

            def join(self):
                target_calls.append("join")
                self.target()

        def proven_expiry(stop, supplied_deadline, supplied_clock):
            self.assertTrue(stop.is_set())
            self.assertEqual(supplied_deadline, bound.absolute_deadline_ns)
            self.assertIs(supplied_clock, clock)
            self.assertLess(clock(), supplied_deadline)
            return True

        budget = runner._CleanupBudget(
            bound.absolute_deadline_ns, runner._MonotonicGuard(clock))
        with mock.patch.object(runner.threading, "Thread", RunDuringJoinThread), \
                mock.patch.object(runner, "_watchdog_reached_deadline",
                                  side_effect=proven_expiry):
            with self.assertRaises(runner.GraphRunnerError):
                runner._run_frida_lifecycle(
                    frida, "observer", bound, manifest, external,
                    bound.absolute_deadline_ns, clock, teardown, budget)
        self.assertEqual(target_calls, ["join"])
        self.assertEqual(teardown.calls, 1)
        self.assertEqual(frida.teardown_count, 1)
        self.assertEqual(frida.session.seal_count, 1)
        self.assertEqual(frida.session.unload_count, 1)
        self.assertEqual(frida.session.detach_count, 1)
        self.assertEqual(frida.session.quiesce_count, 1)
        self.assertEqual(frida.quiesce_count, 1)
        self.assertLess(clock(), bound.absolute_deadline_ns)

    def test_start_permit_checks_absolute_deadline_without_watchdog_scheduling(self):
        clock = Clock()
        deadline = clock() + 10
        permit = runner.OperationStartPermit(
            deadline, clock, runner.AuthorityProviderQuiescenceFailure)
        clock.set(deadline)
        operations = []
        with self.assertRaises(runner.DeadlineExceeded):
            permit.start(lambda: operations.append("started"))
        self.assertEqual(operations, [])

    def test_register_callback_runs_outside_mutex_and_expire_never_blocks(self):
        callback_entered = threading.Event()
        release_callback = threading.Event()
        permit_ready = threading.Event()
        holder = {}
        errors = []

        def owner():
            clock = Clock()
            permit = runner.OperationStartPermit(
                clock() + 1_000_000_000, clock,
                runner.AuthorityProviderQuiescenceFailure)
            holder["permit"] = permit
            permit_ready.set()
            try:
                permit.start(lambda: (callback_entered.set(),
                                      release_callback.wait(1)))
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=owner, name="permit-owner")
        thread.start()
        self.assertTrue(permit_ready.wait(1))
        self.assertTrue(callback_entered.wait(1))
        started = time.monotonic()
        holder["permit"].expire()
        self.assertLess(time.monotonic() - started, 0.1)
        release_callback.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], runner.DeadlineExceeded)

    def test_expire_before_start_and_foreign_thread_start_never_invoke_register(self):
        clock = Clock()
        permit = runner.OperationStartPermit(
            clock() + 1_000_000_000, clock,
            runner.AuthorityProviderQuiescenceFailure)
        permit.expire()
        work = []
        with self.assertRaises(runner.DeadlineExceeded):
            permit.start(lambda: work.append("expired"))
        self.assertEqual(work, [])

        permit = runner.OperationStartPermit(
            clock() + 1_000_000_000, clock,
            runner.AuthorityProviderQuiescenceFailure)
        errors = []
        thread = threading.Thread(
            target=lambda: self._capture_error(
                errors, lambda: permit.start(lambda: work.append("foreign"))))
        thread.start()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], runner.AuthorityProviderQuiescenceFailure)
        self.assertEqual(work, [])

    @staticmethod
    def _capture_error(errors, operation):
        try:
            operation()
        except BaseException as error:
            errors.append(error)

    def test_require_exact_start_rejects_failed_reused_and_unsettled_permits(self):
        clock = Clock()
        failure = runner.AuthorityProviderQuiescenceFailure
        failed = runner.OperationStartPermit(clock() + 1_000_000_000, clock, failure)
        with self.assertRaises(RuntimeError):
            failed.start(lambda: (_ for _ in ()).throw(RuntimeError("register")))
        with self.assertRaises(failure):
            failed.require_exact_start(failure)

        reused = runner.OperationStartPermit(clock() + 1_000_000_000, clock, failure)
        reused.start(lambda: None)
        with self.assertRaises(failure):
            reused.start(lambda: None)
        with self.assertRaises(failure):
            reused.require_exact_start(failure)

        sealed = runner.OperationStartPermit(clock() + 1_000_000_000, clock, failure)
        sealed.seal()
        with self.assertRaises(failure):
            sealed.start(lambda: None)
        with self.assertRaises(failure):
            sealed.require_exact_start(failure)

    def test_bounded_call_deadline_terminally_fences_blocked_registration(self):
        terminal = threading.Event()
        callback_entered = threading.Event()
        device_work = []
        quiescence = []
        deadline = time.monotonic_ns() + 40_000_000

        def operation(permit):
            def register():
                callback_entered.set()
                terminal.wait(1)
                if not terminal.is_set():
                    device_work.append("late")
            permit.start(register)
            return "unreachable"

        with self.assertRaises(runner.DeadlineExceeded):
            runner._bounded_call(
                operation, deadline, time.monotonic_ns, "blocked registration",
                cancel=lambda: None,
                quiesce=lambda: quiescence.append(terminal.is_set()),
                quiescence_failure=runner.AuthorityProviderQuiescenceFailure,
                terminal_cancel=terminal.set)
        self.assertTrue(callback_entered.is_set())
        self.assertEqual(device_work, [])
        self.assertEqual(quiescence, [True])
        self.assertFalse(any(thread.is_alive() and
                             thread.name.startswith("native-page-v2-watchdog-blocked")
                             for thread in threading.enumerate()))

    def test_watchdog_clock_fault_before_frida_attach_never_starts_lifecycle(self):
        values = environment()
        clock = values[0]
        real_thread = runner.threading.Thread

        class FaultOnceClock:
            def __init__(self, delegate):
                self.delegate = delegate
                self.fail_next = False

            def __call__(self):
                if self.fail_next:
                    self.fail_next = False
                    raise RuntimeError("watchdog clock failed")
                return self.delegate()

        fault_clock = FaultOnceClock(clock)

        class FridaFaultThread:
            def __init__(self, *, target, name, daemon):
                self.target = target
                self.name = name
                self.real = (None if name == "native-page-v2-frida-watchdog" else
                             real_thread(target=target, name=name, daemon=daemon))

            def start(self):
                if self.real is not None:
                    self.real.start()
                else:
                    fault_clock.fail_next = True
                    self.target()

            def join(self):
                if self.real is not None:
                    self.real.join()

        before_record = stage_value(values[2], values[1], values[6].tool_bundle_sha256,
                                    "before")
        teardown = runner._TeardownOnce(values[5])
        budget = runner._CleanupBudget(values[1].absolute_deadline_ns,
                                       runner._MonotonicGuard(fault_clock))
        with mock.patch.object(runner.threading, "Thread", FridaFaultThread):
            with self.assertRaises(runner.GraphRunnerError):
                runner._run_frida_lifecycle(values[5], "observer", values[1], values[2],
                                            before_record, values[1].absolute_deadline_ns,
                                            fault_clock, teardown, budget)
        self.assertEqual(values[5].attach_count, 0)
        self.assertEqual(values[5].teardown_count, 1)

    def test_provider_cannot_claim_success_without_atomic_start_permit(self):
        values = environment()

        def ignored_permit_admission(timeout_ms, start_permit):
            return values[4].admission_record

        values[4].admission = ignored_permit_admission
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, [])
        self.assertEqual(values[4].fail_stop_count, 1)

    def test_frida_attach_cannot_claim_success_without_atomic_start_permit(self):
        values = environment()

        def ignored_permit_attach(serial, pid, timeout_ms, start_permit):
            values[5].attach_count += 1
            return values[5].session

        values[5].attach = ignored_permit_attach
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[5].attach_count, 1)
        self.assertEqual(values[5].session.load_count, 0)
        self.assertEqual(values[5].teardown_count, 1)

    def test_unconsumed_authority_permit_is_terminally_sealed_on_failure(self):
        for phase, cleanup_after in (("admission", False), ("before", False),
                                     ("after", False), ("after", True)):
            values = environment()
            retained = []
            if phase == "admission":
                def fail(timeout_ms, start_permit):
                    retained.append(start_permit)
                    raise RuntimeError("before registration")
                values[4].admission = fail
            else:
                original_capture = values[4].capture
                def fail(request, timeout_ms, start_permit,
                         selected_phase=phase, original=original_capture):
                    if request.phase == selected_phase:
                        retained.append(start_permit)
                        raise RuntimeError("before registration")
                    return original(request, timeout_ms, start_permit)
                values[4].capture = fail
            if cleanup_after:
                values[5].session.advance_phase = "load"
                values[5].session.advance_ns = (
                    values[1].absolute_deadline_ns - values[0]())
            with self.subTest(phase=phase, cleanup_after=cleanup_after), \
                    self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            late = []
            with self.assertRaises(runner.AuthorityProviderQuiescenceFailure):
                retained[0].start(lambda: late.append("registered"))
            self.assertEqual(late, [])
            self.assertEqual(values[4].fail_stop_count, 1)

    def test_unconsumed_frida_permits_are_terminally_sealed_on_failure(self):
        for phase in ("admission", "attach", "load"):
            values = environment()
            retained = []
            if phase == "admission":
                def fail(timeout_ms, start_permit):
                    retained.append(start_permit)
                    raise RuntimeError("before registration")
                values[5].admission = fail
            elif phase == "attach":
                def fail(serial, pid, timeout_ms, start_permit):
                    retained.append(start_permit)
                    raise RuntimeError("before registration")
                values[5].attach = fail
            else:
                def fail(source, callback, timeout_ms, start_permit):
                    retained.append(start_permit)
                    raise RuntimeError("before registration")
                values[5].session.load = fail
            with self.subTest(phase=phase), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            late = []
            with self.assertRaises(runner.FridaProviderQuiescenceFailure):
                retained[0].start(lambda: late.append("registered"))
            self.assertEqual(late, [])
            self.assertEqual(values[5].teardown_count, 1)

    def test_blocked_provider_capture_is_cancelled_and_no_worker_survives(self):
        values = environment(deadline_ms=250, clock_factory=RunningClock)
        values[4].block_phase = "before"
        started = time.monotonic()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
        self.assertEqual(values[4].fail_stop_count, 1)
        self.assertEqual(values[4].cancel_count, 0)
        self.assertEqual(values[4].quiesce_count, 2)
        self.assertEqual(values[4].register_device_work.count("before"), 1)
        self.assertEqual(values[4].capture_phases, ["before"])
        self.assertTrue(values[4].cancel_event.is_set())
        self.assertEqual(values[5].teardown_count, 1)
        self.assertEqual(values[5].quiesce_count, 2)
        self.assertEqual((values[5].session.load_count,
                          values[5].session.seal_count,
                          values[5].session.unload_count,
                          values[5].session.detach_count,
                          values[5].session.quiesce_count), (0, 0, 0, 0, 0))
        self.assert_no_native_page_v2_threads()

    def test_blocked_authority_registration_is_fail_stopped_in_all_four_paths(self):
        expected = {
            ("admission", False): (0, [], 1, 1, (0, 0, 0, 0, 0)),
            ("before", False): (1, [], 2, 2, (0, 0, 0, 0, 0)),
            ("after", False): (1, ["before"], 3, 3, (1, 1, 1, 1, 1)),
            ("after", True): (1, ["before"], 5, 3, (1, 1, 1, 1, 1)),
        }
        for phase, cleanup_after in (("admission", False), ("before", False),
                                     ("after", False), ("after", True)):
            values = environment(deadline_ms=250, clock_factory=RunningClock)
            provider = values[4]
            provider.register_block_phase = phase
            if cleanup_after:
                values[5].session.advance_phase = "load"
                values[5].session.advance_ns = (
                    values[1].absolute_deadline_ns - values[0]())
            started = time.monotonic()
            with self.subTest(phase=phase, cleanup_after=cleanup_after), \
                    self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
            self.assertTrue(provider.register_entered.is_set())
            self.assertEqual(provider.fail_stop_count, 1)
            self.assertEqual(provider.cancel_count, 0)
            self.assertEqual(provider.register_device_work.count(phase), 0)
            admission, captures, authority_quiesce, frida_quiesce, session_counts = \
                expected[(phase, cleanup_after)]
            self.assertEqual(provider.admission_count, admission)
            self.assertEqual(provider.capture_phases, captures)
            self.assertEqual(provider.quiesce_count, authority_quiesce)
            self.assertEqual(values[5].teardown_count, 1)
            self.assertEqual(values[5].quiesce_count, frida_quiesce)
            self.assertEqual((values[5].session.load_count,
                              values[5].session.seal_count,
                              values[5].session.unload_count,
                              values[5].session.detach_count,
                              values[5].session.quiesce_count), session_counts)
            self.assertTrue(provider.cancel_event.is_set())
            self.assert_no_native_page_v2_threads()

    def test_blocked_frida_registration_is_torn_down_in_all_three_paths(self):
        expected = {
            "admission": ((0, 0, 0), 1, (0, 0, 0, 0, 0), 2, 1),
            "attach": ((1, 0, 0), 3, (0, 0, 0, 0, 0), 3, 0),
            "load": ((1, 1, 0), 3, (0, 1, 1, 1, 1), 3, 0),
        }
        for phase in ("admission", "attach", "load"):
            values = environment(deadline_ms=250, clock_factory=RunningClock)
            frida = values[5]
            frida.register_block_phase = phase
            started = time.monotonic()
            with self.subTest(phase=phase), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
            self.assertTrue(frida.register_entered.is_set())
            self.assertEqual(frida.teardown_count, 1)
            self.assertEqual(frida.register_device_work.count(phase), 0)
            registrations, frida_quiesce, session_counts, authority_quiesce, \
                authority_fail_stop = expected[phase]
            self.assertEqual((frida.admission_count, frida.attach_count,
                              frida.session.load_count), registrations)
            self.assertEqual(frida.quiesce_count, frida_quiesce)
            self.assertEqual((frida.session.load_count,
                              frida.session.seal_count,
                              frida.session.unload_count,
                              frida.session.detach_count,
                              frida.session.quiesce_count), session_counts)
            self.assertEqual(values[4].quiesce_count, authority_quiesce)
            self.assertEqual(values[4].fail_stop_count, authority_fail_stop)
            self.assertTrue(frida.teardown_event.is_set())
            self.assert_no_native_page_v2_threads()

    def test_post_registration_hangs_are_terminally_quiesced_in_all_seven_paths(self):
        expected = {
            ("authority", "admission", False): (1, 1, (0, 0, 0, 0, 0), 1),
            ("authority", "before", False): (2, 2, (0, 0, 0, 0, 0), 1),
            ("authority", "after", False): (3, 3, (1, 1, 1, 1, 1), 1),
            ("authority", "after", True): (5, 3, (1, 1, 1, 1, 1), 1),
            ("frida", "admission", False): (2, 1, (0, 0, 0, 0, 0), 1),
            ("frida", "attach", False): (3, 3, (0, 0, 0, 0, 0), 0),
            ("frida", "load", False): (3, 3, (1, 1, 1, 1, 1), 0),
        }
        for provider_kind, phase, cleanup_after in (
                ("authority", "admission", False),
                ("authority", "before", False),
                ("authority", "after", False),
                ("authority", "after", True),
                ("frida", "admission", False),
                ("frida", "attach", False),
                ("frida", "load", False)):
            values = environment(deadline_ms=250, clock_factory=RunningClock)
            provider = values[4] if provider_kind == "authority" else values[5]
            provider.post_register_block_phase = phase
            if cleanup_after:
                values[5].session.advance_phase = "load"
                values[5].session.advance_ns = (
                    values[1].absolute_deadline_ns - values[0]())
            started = time.monotonic()
            with self.subTest(provider=provider_kind, phase=phase,
                              cleanup_after=cleanup_after), \
                    self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
            self.assertTrue(provider.post_register_entered.is_set())
            self.assertEqual(provider.register_device_work.count(phase), 1)
            authority_quiesce, frida_quiesce, session_counts, authority_fail_stop = \
                expected[(provider_kind, phase, cleanup_after)]
            self.assertEqual(values[4].quiesce_count, authority_quiesce)
            self.assertEqual(values[5].quiesce_count, frida_quiesce)
            self.assertEqual((values[5].session.load_count,
                              values[5].session.seal_count,
                              values[5].session.unload_count,
                              values[5].session.detach_count,
                              values[5].session.quiesce_count), session_counts)
            self.assertEqual(values[4].fail_stop_count, authority_fail_stop)
            self.assertEqual(values[5].teardown_count, 1)
            if provider_kind == "authority":
                self.assertEqual(provider.fail_stop_count, 1)
                self.assertEqual(provider.cancel_count, 0)
                self.assertTrue(provider.cancel_event.is_set())
            else:
                self.assertEqual(provider.teardown_count, 1)
                self.assertTrue(provider.teardown_event.is_set())
            self.assert_no_native_page_v2_threads()

    def test_observer_negative_frame_and_missing_terminal_are_fail_closed(self):
        values = environment()
        values[5].session.frames = [
            ({"type": "send", "payload": {"event": "native_page_graph_snapshot_error",
                                             "schemaVersion": 2,
                                             "code": "GRAPH_SNAPSHOT_REJECTED"}}, None),
            ({"type": "send", "payload": {"event": "native_page_graph_snapshot_complete",
                                             "success": False}}, None),
        ]
        with self.assertRaises(runner.SnapshotRejected):
            run_env(values)
        self.assertEqual(values[5].attach_count, 1)
        self.assertEqual(values[5].teardown_count, 1)
        self.assertEqual(values[4].capture_phases, ["before", "after"])

        values = environment(deadline_ms=250, clock_factory=RunningClock)
        values[5].session.frames = success_frames(values[2])[:1]
        started = time.monotonic()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
        self.assertEqual(values[5].teardown_count, 1)
        self.assertEqual(values[5].quiesce_count, 3)
        self.assertEqual((values[5].session.load_count,
                          values[5].session.seal_count,
                          values[5].session.unload_count,
                          values[5].session.detach_count,
                          values[5].session.quiesce_count), (1, 1, 1, 1, 1))
        self.assertTrue(values[5].teardown_event.is_set())
        self.assert_no_native_page_v2_threads()

    def test_attach_and_load_hangs_are_cancelled_and_quiesced_without_retry(self):
        for phase in ("attach", "load"):
            values = environment(deadline_ms=250, clock_factory=RunningClock)
            if phase == "attach":
                values[5].block_attach = True
            else:
                values[5].session.block_phase = "load"
            started = time.monotonic()
            with self.subTest(phase=phase), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
            self.assertEqual(values[5].attach_count, 1)
            self.assertEqual(values[5].teardown_count, 1)
            self.assertEqual(values[5].quiesce_count, 3)
            self.assertEqual(values[5].register_device_work.count(phase), 1)
            self.assertEqual(values[5].session.load_count, 0 if phase == "attach" else 1)
            self.assertEqual((values[5].session.seal_count,
                              values[5].session.unload_count,
                              values[5].session.detach_count,
                              values[5].session.quiesce_count), (1, 1, 1, 1))
            self.assertEqual(values[4].capture_phases, ["before", "after"])
            self.assertEqual(values[4].fail_stop_count, 0)
            self.assertTrue(values[5].teardown_event.is_set())
            self.assert_no_native_page_v2_threads()

    def test_frida_admission_hang_uses_exactly_one_teardown(self):
        values = environment(deadline_ms=250, clock_factory=RunningClock)
        values[5].block_admission = True
        started = time.monotonic()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertGreaterEqual(values[0](), values[1].absolute_deadline_ns)
        self.assertEqual(values[5].admission_count, 1)
        self.assertEqual(values[5].register_device_work.count("admission"), 1)
        self.assertEqual(values[5].teardown_count, 1)
        self.assertEqual(values[5].quiesce_count, 1)
        self.assertEqual((values[5].session.load_count,
                          values[5].session.seal_count,
                          values[5].session.unload_count,
                          values[5].session.detach_count,
                          values[5].session.quiesce_count), (0, 0, 0, 0, 0))
        self.assertEqual(values[5].attach_count, 0)
        self.assertEqual(values[4].fail_stop_count, 1)
        self.assertEqual(values[4].quiesce_count, 2)
        self.assertTrue(values[5].teardown_event.is_set())
        self.assert_no_native_page_v2_threads()

    def test_clock_rollback_after_attach_still_runs_every_cleanup_phase(self):
        values = environment()
        values[5].clock = values[0]
        values[5].rollback_on_attach_to = values[0]() - 1
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[5].attach_count, 1)
        self.assertEqual(values[5].session.seal_count, 1)
        self.assertEqual(values[5].session.unload_count, 1)
        self.assertEqual(values[5].session.detach_count, 1)
        self.assertEqual(values[5].session.quiesce_count, 1)
        self.assertEqual(values[5].teardown_count, 1)
        self.assertFalse(any(thread.is_alive() and
                             thread.name.startswith("native-page-v2-")
                             for thread in threading.enumerate()))

    def test_cleanup_slice_overrun_rejects_but_continues_exact_cleanup(self):
        values = environment()
        values[5].clock = values[0]
        values[5].session.advance_phase = "seal"
        values[5].session.advance_ns = runner.CLEANUP_STEP_TIMEOUT_MS * 1_000_000
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[5].session.seal_count, 1)
        self.assertEqual(values[5].session.unload_count, 1)
        self.assertEqual(values[5].session.detach_count, 1)
        self.assertEqual(values[5].session.quiesce_count, 1)
        self.assertEqual(values[5].teardown_count, 1)

    def test_every_frida_phase_failure_is_fail_closed_and_cleanup_continues(self):
        for phase in ("load", "seal", "unload", "detach", "quiesce"):
            values = environment()
            values[5].session.fail_phase = phase
            with self.subTest(phase=phase), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertEqual(values[5].attach_count, 1)
            self.assertEqual(values[5].session.seal_count, 1)
            self.assertEqual(values[5].session.unload_count, 1)
            self.assertEqual(values[5].session.detach_count, 1)
            self.assertEqual(values[5].session.quiesce_count, 1)
            self.assertEqual(values[5].teardown_count, 1)
            self.assertEqual(values[4].capture_phases, ["before", "after"])

    def test_attach_teardown_and_provider_quiescence_failures_reject(self):
        values = environment()
        values[5].fail_attach = True
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[5].teardown_count, 1)

        values = environment()
        values[5].fail_teardown = True
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

        values = environment()
        values[5].fail_quiesce = True
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_callback_during_seal_is_not_silently_ignored(self):
        values = environment()
        values[5].session.late_on_seal = True
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_final_tool_revalidation_failure_rejects_success(self):
        values = environment()
        values[3].fail_verify_at = 8
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[5].attach_count, 1)
        self.assertEqual(values[4].capture_phases, ["before", "after"])

    def test_stage_before_after_mutation_rejects(self):
        values = environment()
        values[4].after["host"]["placementRequestGeneration"] = 13
        values[4].after["host"]["placementReadyGeneration"] = 13
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_target_death_and_pid_reuse_after_detach_are_rejected(self):
        mutations = (
            {"alive": False},
            {"pid": 3142},
            {"startTimeTicks": "9000002"},
            {"cmdline": "com.supernote.document:replacement",
             "cmdlineSha256": hashlib.sha256(
                 b"com.supernote.document:replacement").hexdigest()},
        )
        for mutation in mutations:
            values = environment()
            values[4].after["target"].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(runner.GraphRunnerError):
                run_env(values)
            self.assertEqual(values[5].attach_count, 1)
            self.assertEqual(values[5].teardown_count, 1)

    def test_after_capture_must_complete_before_hard_deadline(self):
        values = environment()
        values[4].clock = values[0]
        values[4].advance_on_phase = "after"
        values[4].advance_to = values[1].absolute_deadline_ns
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[4].capture_phases, ["before", "after"])

    def test_final_result_publication_has_an_exclusive_deadline_check(self):
        values = environment()
        values[3].clock = values[0]
        values[3].advance_verify_at = 8
        values[3].advance_to = values[1].absolute_deadline_ns
        with self.assertRaises(runner.DeadlineExceeded):
            run_env(values)

    def test_timeout_contracts_are_positive_bounded_and_cleanup_is_sliced(self):
        values = environment()
        run_env(values)
        timeouts = values[4].timeouts + values[5].timeouts + values[5].session.timeouts
        self.assertTrue(all(type(timeout) is int and 1 <= timeout <= runner.MAX_DEADLINE_MS
                            for _, timeout in timeouts))
        cleanup_names = {"teardown", "seal", "unload", "detach"}
        self.assertTrue(all(timeout <= runner.CLEANUP_STEP_TIMEOUT_MS
                            for name, timeout in timeouts if name in cleanup_names))

    def test_cleanup_uses_one_absolute_grace_and_never_skips_expired_attempt(self):
        clock = Clock()
        hard_deadline = clock() + 1_000_000_000
        budget = runner._CleanupBudget(hard_deadline, clock)
        deadline = budget.deadline_ns()
        self.assertEqual(deadline,
                         hard_deadline + runner.CLEANUP_TIMEOUT_MS * 1_000_000)
        clock.set(deadline - 1)
        timeout, expired = budget.step_timeout_millis()
        self.assertEqual((timeout, expired), (1, False))
        clock.set(deadline)
        calls = []
        error = runner._cleanup_call(lambda timeout_ms: calls.append(timeout_ms),
                                     "expired cleanup", budget)
        self.assertIsInstance(error, runner.GraphRunnerError)
        self.assertEqual(calls, [1])

    def test_lease_duration_may_decrease_without_changing_lease_identity(self):
        values = environment()
        values[4].after["penLease"]["remainingLeaseMs"] -= 100
        self.assertEqual(run_env(values)["authority"], runner.RUNNER_AUTHORITY)

    def test_after_lease_requires_only_the_shared_cleanup_reserve(self):
        values = environment()
        values[4].before["penLease"]["remainingLeaseMs"] = (
            values[1].deadline_ms + runner.CLEANUP_TIMEOUT_MS)
        values[4].after["penLease"]["remainingLeaseMs"] = runner.CLEANUP_TIMEOUT_MS
        self.assertEqual(run_env(values)["authority"], runner.RUNNER_AUTHORITY)

        values = environment()
        values[4].after["penLease"]["remainingLeaseMs"] = runner.CLEANUP_TIMEOUT_MS - 1
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_reviewed_adb_hashes_and_retained_path_are_not_self_attested(self):
        class MutatedBundle(FakeBundle):
            def canonical_bytes(self):
                value = json.loads(super().canonical_bytes())
                value["files"]["adb.exe"]["sha256"] = ZERO_SHA
                return canon(value)

        values = environment()
        bundle = MutatedBundle()
        tool = runner.load_canonical(bundle.canonical_bytes(), runner.MAX_AUTHORITY_BYTES)
        pins = replace(values[6], tool_bundle_sha256=tool.sha256)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values, tool_bundle=bundle, trusted_pins=pins)

        values = environment()
        value = json.loads(values[3].canonical_bytes())
        value["files"]["adb.exe"]["path"] = "C:/replacement/adb.exe"
        raw = canon(value)

        class PathBundle(FakeBundle):
            def canonical_bytes(self):
                return raw

        bundle = PathBundle()
        pins = replace(values[6], tool_bundle_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values, tool_bundle=bundle, trusted_pins=pins)

    def test_trusted_digest_pins_are_all_enforced(self):
        names = ("tool_bundle_sha256", "manifest_sha256", "provider_admission_sha256",
                 "frida_admission_sha256", "stage_policy_sha256")
        for name in names:
            values = environment()
            values = (*values[:6], replace(values[6], **{name: ZERO_SHA}))
            with self.subTest(name=name), self.assertRaises(runner.GraphRunnerError):
                run_env(values)

        values = environment()
        for invalid in (b"short", bytearray(RECEIPT_KEY), "R" * 32):
            with self.subTest(receipt_hmac_key=type(invalid).__name__), \
                    self.assertRaises(runner.GraphRunnerError):
                run_env(values, trusted_pins=replace(values[6], receipt_hmac_key=invalid))

    def test_provider_and_frida_admission_shapes_are_pinned(self):
        values = environment()
        values[4].admission_record = wrapped({**admission_value(), "independentCapture": False})
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

        for name in ("atomicStartPermit", "challengeBoundReceipts", "freshCaptureIds",
                     "receiptSequenceChain", "receiptAcquisitionOwnsSources"):
            values = environment()
            admission = admission_value()
            admission[name] = False
            values[4].admission_record = wrapped(admission)
            values = authorize_test_admissions(values)
            with self.subTest(provider_property=name), self.assertRaises(runner.GraphRunnerError):
                run_env(values)

        values = environment()
        admission = admission_value()
        admission["receiptMacAlgorithm"] = "none"
        values[4].admission_record = wrapped(admission)
        values = authorize_test_admissions(values)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        values = environment()
        values[5].admission_record = wrapped({**frida_admission_value(), "singleAttach": False})
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

        values = environment()
        values[5].admission_record = wrapped({**frida_admission_value(), "schemaVersion": True})
        values = authorize_test_admissions(values)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_stage_authority_mutation_matrix(self):
        mutations = [
            lambda a: a.update(extra=True),
            lambda a: a.update(providerSessionId="other-provider-session:0001"),
            lambda a: a["privateAdbServer"].update(host="0.0.0.0"),
            lambda a: a["privateAdbServer"].update(executablePath="C:/other/adb.exe"),
            lambda a: a["privateAdbServer"].update(executableSha256=ZERO_SHA),
            lambda a: a["privateAdbServer"].update(launchMode="start-server"),
            lambda a: a["privateAdbServer"].update(processHandleRetained=False),
            lambda a: a["privateAdbServer"].update(fixedMinimalEnvironment=False),
            lambda a: a["privateAdbServer"].update(explicitSerialEveryCommand=False),
            lambda a: a["privateAdbServer"].update(noSharedServer=False),
            lambda a: a["privateAdbServer"].update(rejectsAmbientOverrides=[]),
            lambda a: a["target"].update(pid=99),
            lambda a: a["target"].update(startTimeTicks="9000002"),
            lambda a: a["target"].update(alive=False),
            lambda a: a["target"].update(cmdline="other"),
            lambda a: a["firmware"].update(fingerprint="other"),
            lambda a: a["firmware"]["module"].update(sha256=ZERO_SHA),
            lambda a: a["files"]["originalPdf"].update(sha256=ZERO_SHA),
            lambda a: a["host"].update(defaultDisplayId=1),
            lambda a: a["host"].update(defaultDisplayId=False),
            lambda a: a["host"].update(displayId=0),
            lambda a: a["host"].update(displayId=False),
            lambda a: a["host"].update(displayGeneration=0),
            lambda a: a["host"].update(displayGeneration=False),
            lambda a: a["host"].update(placementRequestGeneration=0,
                                        placementReadyGeneration=0),
            lambda a: a["host"].update(placementReadyGeneration=11),
            lambda a: a["host"].update(activityResumed=False),
            lambda a: a["host"].update(activityVisible=False),
            lambda a: a["host"].update(activityFocused=False),
            lambda a: a["host"].update(surfaceAttached=False),
            lambda a: a["host"].update(surfaceValid=False),
            lambda a: a["host"].update(measuredGlobalFrame=[0, 0, 700, 1872]),
            lambda a: a["penLease"].update(deviceClockDomain="windows-qpc"),
            lambda a: a["penLease"].update(remainingLeaseMs=1),
            lambda a: a["penLease"].update(active=False),
            lambda a: a["frida"].update(providerSessionId="other-frida-session:0001"),
            lambda a: a["frida"].update(serverUid=False),
            lambda a: a["frida"].update(serverUid=1000),
            lambda a: a["frida"].update(exactTeardownRequired=False),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                values = environment()
                mutation(values[4].before)
                mutation(values[4].after)
                values = authorize_test_policy(values)
                with self.assertRaises(runner.GraphRunnerError):
                    run_env(values)

    def test_phase_specific_frida_teardown_is_enforced(self):
        values = environment()
        values[4].after["frida"].update(serverState="ready", processAbsent=False,
                                         fileAbsent=False, teardownOfSessionId=None)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_stage_record_must_match_independent_pin(self):
        values = environment()
        values[4].before["target"]["alive"] = False
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_android_task_raw_capture_digest_may_change_but_semantics_may_not(self):
        values = environment()
        after_task = task("b" * 64)
        values[4].task_after = after_task
        values[4].after["taskAuthoritySha256"] = hashlib.sha256(after_task.canonical_bytes()).hexdigest()
        self.assertEqual(run_env(values)["authority"], runner.RUNNER_AUTHORITY)

        values = environment()
        after_task = replace(task("b" * 64), rotation=1)
        values[4].task_after = after_task
        values[4].after["taskAuthoritySha256"] = hashlib.sha256(after_task.canonical_bytes()).hexdigest()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

        values = environment()
        full_component = replace(
            task(),
            component=("com.supernote.document/"
                       "com.supernote.document.document.DocumentActivity"),
        )
        values[4].task = full_component
        values[4].task_after = full_component
        digest = hashlib.sha256(full_component.canonical_bytes()).hexdigest()
        values[4].before["taskAuthoritySha256"] = digest
        values[4].after["taskAuthoritySha256"] = digest
        self.assertEqual(run_env(values)["authority"], runner.RUNNER_AUTHORITY)

    def test_every_android_task_field_is_strictly_validated(self):
        changes = (
            {"authority": "wrong-authority"}, {"raw_sha256": "not-a-digest"},
            {"display_id": False}, {"display_id": 0}, {"stack_id": 40}, {"task_id": 42},
            {"task_token": "Task{abc}"}, {"activity_token": ""},
            {"pid": False}, {"uid": -1}, {"uid": 10042},
            {"package_name": "other.package"},
            {"process_name": "other.process"}, {"component": "not.the.DocumentActivity"},
            {"base_apk_path": "/other.apk"}, {"state": "STOPPED"},
            {"resumed": 1}, {"resumed": "false"}, {"resumed": False},
            {"stopped": 0}, {"stopped": True},
            {"delayed_resume": 0}, {"delayed_resume": True},
            {"finishing": 0}, {"finishing": True},
            {"task_visible": 1}, {"task_visible": False},
            {"visible_requested": 1}, {"visible_requested": False},
            {"visible": 1}, {"visible": False},
            {"client_visible": 1}, {"client_visible": False},
            {"reported_drawn": 1}, {"reported_drawn": False},
            {"reported_visible": 1}, {"reported_visible": False},
            {"now_visible": 1}, {"now_visible": False},
            {"width": False}, {"width": -1}, {"width": 32769},
            {"height": False}, {"height": -1}, {"height": 32769},
            {"density_dpi": False}, {"density_dpi": 71}, {"density_dpi": 1281},
            {"rotation": False}, {"rotation": 1}, {"rotation": 4},
        )
        for change in changes:
            values = environment()
            changed = replace(task(), **change)
            values[4].task = changed
            values[4].task_after = changed
            digest = hashlib.sha256(changed.canonical_bytes()).hexdigest()
            values[4].before["taskAuthoritySha256"] = digest
            values[4].after["taskAuthoritySha256"] = digest
            with self.subTest(change=change), self.assertRaises(runner.GraphRunnerError):
                run_env(values)

    def test_after_only_bool_integer_aliases_cannot_pass_task_stability(self):
        values = environment()
        changed = replace(task(), display_id=False, resumed=1)
        values[4].task_after = changed
        values[4].after["taskAuthoritySha256"] = hashlib.sha256(
            changed.canonical_bytes()).hexdigest()
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_android_task_must_match_authenticated_host_configuration(self):
        for change in ({"width": 1405}, {"height": 1871}, {"density_dpi": 227}):
            values = environment()
            changed = replace(task(), **change)
            values[4].task = changed
            values[4].task_after = changed
            digest = hashlib.sha256(changed.canonical_bytes()).hexdigest()
            values[4].before["taskAuthoritySha256"] = digest
            values[4].after["taskAuthoritySha256"] = digest
            with self.subTest(change=change), self.assertRaises(runner.GraphRunnerError):
                run_env(values)

    def test_fixed_virtual_display_contract_rejects_jointly_stable_wrong_values(self):
        cases = (
            ({"width": 1405}, {"displaySize": [1405, 1872]}),
            ({"height": 1871}, {"displaySize": [1404, 1871]}),
            ({"density_dpi": 301}, {"densityDpi": 301}),
        )
        for task_change, host_change in cases:
            values = environment()
            changed = replace(task(), **task_change)
            values[4].task = changed
            values[4].task_after = changed
            digest = hashlib.sha256(changed.canonical_bytes()).hexdigest()
            for record in (values[4].before, values[4].after):
                record["taskAuthoritySha256"] = digest
                record["host"].update(host_change)
            values = authorize_test_policy(values)
            with self.subTest(task_change=task_change), \
                    self.assertRaises(runner.GraphRunnerError):
                run_env(values)

    def test_outer_presentation_move_preserves_fixed_native_display(self):
        values = environment(stage="LEFT")
        frame = [0, 78, 936, 1248]
        for record in (values[4].before, values[4].after):
            record["host"]["requestedFrame"] = list(frame)
            record["host"]["measuredGlobalFrame"] = list(frame)
        values = authorize_test_policy(values)
        self.assertEqual(run_env(values)["stage"], "LEFT")

    def test_provider_cannot_mutate_shared_task_to_hide_before_after_drift(self):
        values = environment()
        values[4].mutate_shared_task_after = ("rotation", 1)
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)

    def test_provider_receives_no_reference_to_retained_deadline_binding(self):
        values = environment()
        values[4].mutate_request_binding_deadline_ms = 1
        values[4].before["penLease"]["remainingLeaseMs"] = 251
        values[4].after["penLease"]["remainingLeaseMs"] = 251
        original_deadline_ms = values[1].deadline_ms
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)
        self.assertEqual(values[1].deadline_ms, original_deadline_ms)

    def test_caller_retained_binding_and_pins_cannot_mutate_active_run(self):
        values = environment()
        caller_binding = values[1]
        caller_pins = values[6]

        def mutate_after_entry():
            object.__setattr__(caller_binding, "deadline_ms", 1)
            object.__setattr__(caller_pins, "stage_policy_sha256", ZERO_SHA)
            object.__setattr__(caller_pins, "receipt_hmac_key", b"z" * 32)
            return "e" * 64

        result = run_env(values, nonce_factory=mutate_after_entry)
        self.assertEqual(result["authority"], runner.RUNNER_AUTHORITY)
        self.assertEqual(caller_binding.deadline_ms, 1)
        self.assertEqual(caller_pins.stage_policy_sha256, ZERO_SHA)
        self.assertEqual(caller_pins.receipt_hmac_key, b"z" * 32)

    def test_snapshot_and_target_integer_aliases_are_rejected(self):
        clock = Clock()
        bound = runner.StageBinding(runner.AUTHORIZED_SERIAL, 1, "9000001",
                                    "observer-session-v2:0001", 1000,
                                    clock() + 1_000_000_000, "FULL")
        manifest = loaded_manifest(bound)
        payload = snapshot_value(manifest)
        payload["attachment"]["pid"] = True
        with self.assertRaises(runner.GraphRunnerError):
            runner.validate_snapshot(payload, manifest,
                                     {"files": copy.deepcopy(manifest.value["files"])})

        manifest_wire = manifest_value(bound)
        manifest_wire["attachment"]["module"]["size"] = 1
        module_manifest = runner.load_canonical(
            canon(manifest_wire), runner.MAX_MANIFEST_BYTES)
        payload = snapshot_value(module_manifest)
        payload["attachment"]["module"]["size"] = True
        with self.assertRaises(runner.GraphRunnerError):
            runner.validate_snapshot(payload, module_manifest,
                                     {"files": copy.deepcopy(module_manifest.value["files"])})

        target = {
            "authority": runner.TARGET_AUTHORITY, "serial": bound.serial,
            "pid": True, "startTimeTicks": bound.start_time_ticks,
            "cmdline": runner.PACKAGE_NAME,
            "cmdlineSha256": hashlib.sha256(runner.PACKAGE_NAME.encode()).hexdigest(),
            "packageName": runner.PACKAGE_NAME, "processName": runner.PACKAGE_NAME,
            "alive": True,
        }
        with self.assertRaises(runner.GraphRunnerError):
            runner._validate_target(target, bound)

    def test_host_and_frida_self_assertions_cannot_be_re_pinned_selectively(self):
        values = environment()
        values[4].before["host"]["hostApkSha256"] = ZERO_SHA
        values[4].after["host"]["hostApkSha256"] = ZERO_SHA
        # Trusted stage digests deliberately remain unchanged.
        with self.assertRaises(runner.GraphRunnerError):
            run_env(values)


@dataclass(frozen=True)
class _V2Binding:
    authority: str = "capability-binding"
    version: int = 2
    factory_id: str = "factory-v2"
    role: str = "frida"
    session_id: str = "0" * 64
    session_epoch: str = "1" * 64
    effect_deadline_ns: int = 2_000_000_000
    closure_deadline_ns: int = 2_250_000_000
    key_id: str = "6" * 64
    resource_binding_sha256: str = "2" * 64
    operation_table_sha256: str = "3" * 64
    transport_attestation_sha256: str = "4" * 64
    epoch_attestation_sha256: str = "5" * 64


@dataclass(frozen=True)
class _V2Lease:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    factory_id: str
    role: str
    sequence: int
    operation_id: str
    operation_purpose: str
    request_id: str
    challenge: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    owner_object_id: str


@dataclass(frozen=True)
class _V2Payload:
    request_id: str


@dataclass(frozen=True)
class _V2Callback:
    callback_id: str


@dataclass(frozen=True)
class _V2Outcome:
    authority: str
    binding_sha256: str
    request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    lease: _V2Lease
    result: object
    callbacks: tuple[_V2Callback, ...]
    settlement_evidence: object
    cleanup_completed: bool
    outcome_sha256: str


@dataclass(frozen=True)
class _V2IdleReceipt:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    generation: int
    state: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    active_operations: int
    live_callbacks: int
    epoch_admitted_sides: tuple[str, ...]
    open_endpoints: tuple[str, ...]
    terminal: bool
    receipt_id: str
    authentication_tag: str


@dataclass(frozen=True)
class _V2ComponentClosure:
    component: str


@dataclass(frozen=True)
class _V2SuccessfulClosure:
    authority: str
    binding_sha256: str
    session_id: str
    session_epoch: str
    factory_id: str
    role: str
    generation: int
    closure_request_id: str
    operation_id: str
    operation_purpose: str
    effect_deadline_ns: int
    closure_deadline_ns: int
    sealed_directions: tuple[str, ...]
    authenticated_eof_drained_directions: tuple[str, ...]
    active_operations: int
    live_callbacks: int
    revoked_epoch_sides: tuple[str, ...]
    closed_endpoints: tuple[str, ...]
    owner_closed: bool
    component_receipts: tuple[_V2ComponentClosure, ...]
    component_set_sha256: str
    receipt_id: str
    authentication_tag: str


class _V2Session:
    def __init__(self, binding_value):
        self._construction_kind = "production"
        self.binding = binding_value
        self.state = "OPEN"
        self.generation = 0
        self.completed_purposes = ()
        self.successful_closure_receipt = None
        self.partial_closure_receipts = ()
        self.active_lease = None
        self.callbacks = []
        self.bad_idle = None
        self.close_hook = None

    def begin_operation(self, lease, request_value):
        if self.state != "OPEN" or lease.sequence != len(self.completed_purposes) + 1:
            raise RuntimeError("bad begin")
        self.state = "ACTIVE"
        self.generation += 1
        self.active_lease = lease
        self.callbacks = []
        return _V2Payload(lease.request_id)

    def note_callback(self, callback):
        if self.state != "ACTIVE" or type(callback) is not _V2Callback:
            raise RuntimeError("bad callback")
        self.callbacks.append(callback)

    def complete_operation(self, outcome):
        if self.state != "ACTIVE" or outcome.lease != self.active_lease:
            raise RuntimeError("bad complete")
        if tuple(self.callbacks) != outcome.callbacks:
            raise RuntimeError("callback mismatch")
        self.completed_purposes += (outcome.operation_purpose,)
        self.state = "OPEN"
        self.generation += 1
        self.active_lease = None

    def verify_operation_idle(self):
        if self.bad_idle is not None:
            return self.bad_idle
        return _V2IdleReceipt(
            "idle", self._binding_sha(), self.binding.session_id,
            self.binding.session_epoch, self.generation, "OPEN",
            runner.CAPABILITY_OPERATION_IDLE_PURPOSE_V2,
            self.binding.effect_deadline_ns, self.binding.closure_deadline_ns,
            0, 0, ("parent", "child"), ("p2c-control", "p2c-payload",
                                          "c2p-control", "c2p-payload"),
            False, "6" * 64, "7" * 64)

    def _binding_sha(self):
        return "a" * 64

    def close_successfully(self):
        if self.close_hook is not None:
            self.close_hook()
        if self.state != "OPEN":
            raise RuntimeError("not idle")
        self.state = "CLOSING"
        component = _V2ComponentClosure("transport")
        self.partial_closure_receipts = (component,)
        self.generation += 1
        receipt = _V2SuccessfulClosure(
            "closure", self._binding_sha(), self.binding.session_id,
            self.binding.session_epoch, self.binding.factory_id,
            self.binding.role, self.generation, "8" * 64,
            runner.CAPABILITY_SESSION_CLOSE_OPERATION_ID_V2,
            runner.CAPABILITY_SESSION_CLOSE_PURPOSE_V2,
            self.binding.effect_deadline_ns, self.binding.closure_deadline_ns,
            ("parent", "child"), ("parent", "child"), 0, 0,
            ("parent", "child"), ("p2c-control", "p2c-payload",
                                          "c2p-control", "c2p-payload"),
            True, (component,), "9" * 64, "b" * 64, "c" * 64)
        self.successful_closure_receipt = receipt
        self.state = "CLOSED"
        return receipt


def _v2_api():
    return runner._CapabilityApiV2(
        _V2Binding, _V2Session, _V2Lease, _V2Payload, _V2Callback,
        _V2Outcome, _V2IdleReceipt, _V2ComponentClosure,
        _V2SuccessfulClosure, "factory-v2")


def _v2_lease(bound, sequence):
    if sequence == 1:
        operation_id = runner.CAPABILITY_CAPTURE_OPERATION_ID_V2
        purpose = runner.CAPABILITY_CAPTURE_PURPOSE_V2
    else:
        operation_id = runner.CAPABILITY_CLEANUP_OPERATION_ID_V2
        purpose = runner.CAPABILITY_CLEANUP_PURPOSE_V2
    return _V2Lease(
        "lease", "a" * 64, bound.session_id, bound.session_epoch,
        bound.factory_id, bound.role, sequence, operation_id, purpose,
        ("d" if sequence == 1 else "e") * 64,
        ("f" if sequence == 1 else "0") * 64,
        bound.effect_deadline_ns, bound.closure_deadline_ns, "owner-v2")


def _v2_outcome(lease, *, cleanup=None, callbacks=()):
    if cleanup is None:
        cleanup = lease.sequence == 2
    return _V2Outcome(
        "outcome", lease.binding_sha256, lease.request_id,
        lease.operation_id, lease.operation_purpose,
        lease.effect_deadline_ns, lease.closure_deadline_ns, lease,
        {"success": True}, callbacks, {"settled": True}, cleanup,
        "f" * 64)


class CapabilityGraphSequencerV2Tests(unittest.TestCase):
    def test_frozen_capability_module_exports_the_exact_adapter_types(self):
        api = runner._load_capability_api_v2()
        self.assertEqual(api.binding_type.__name__, "CapabilityBindingBodyV2")
        self.assertEqual(api.session_type.__name__, "CapabilitySessionV2")
        self.assertEqual(api.outcome_type.__name__, "OperationOutcomeV2")
        self.assertIsNot(api.open_idle_receipt_type,
                         api.successful_closure_receipt_type)

    def test_contract_fake_session_is_never_admitted_by_production_adapter(self):
        clock, bound, session, _ = self.make()
        session._construction_kind = "contract_fake"
        with mock.patch.object(runner, "_load_capability_api_v2",
                               return_value=_v2_api()), self.assertRaises(
                                   runner.HardwareAdmissionBlocked):
            runner.CapabilityGraphSequencerV2(session, clock)

    def make(self):
        clock = Clock()
        bound = _V2Binding(effect_deadline_ns=clock() + 100_000_000,
                           closure_deadline_ns=clock() + 300_000_000)
        session = _V2Session(bound)
        with mock.patch.object(runner, "_load_capability_api_v2",
                               return_value=_v2_api()):
            sequencer = runner.CapabilityGraphSequencerV2(session, clock)
        return clock, bound, session, sequencer

    @staticmethod
    def callbacks():
        calls = []
        return calls, calls.append, lambda: calls.append("quiesce"), calls.append

    @staticmethod
    def invoke(outcome, observed):
        def perform(payload, callback_sink, permit):
            observed.append((permit.operation_id, permit.operation_purpose,
                             permit.sequence, permit.request_deadline_ns,
                             permit.execution_deadline_ns, permit.session_epoch))

            def registered():
                for callback in outcome.callbacks:
                    callback_sink(callback)
                return outcome

            return permit.start(registered)
        return perform

    def execute(self, sequencer, lease, outcome, observed=None):
        if observed is None:
            observed = []
        return sequencer.execute_operation(
            lease=lease, request_value={"request": lease.sequence},
            invoke=self.invoke(outcome, observed), cancel=lambda: None,
            quiesce=lambda: None, terminal_cancel=lambda: None)

    def test_capture_cleanup_and_typed_terminal_closure(self):
        clock, bound, session, sequencer = self.make()
        observed = []
        capture_lease = _v2_lease(bound, 1)
        capture = self.execute(sequencer, capture_lease,
                               _v2_outcome(capture_lease), observed)
        self.assertEqual(capture.sequence, 1)
        self.assertEqual(capture.generation, 2)
        self.assertIsInstance(capture.open_idle_receipt, _V2IdleReceipt)
        clock.set(bound.effect_deadline_ns)  # cleanup grace, not new request authority
        cleanup_lease = _v2_lease(bound, 2)
        cleanup = self.execute(sequencer, cleanup_lease,
                               _v2_outcome(cleanup_lease), observed)
        self.assertEqual(cleanup.generation, 4)
        self.assertEqual(observed[0][3:5],
                         (bound.effect_deadline_ns, bound.effect_deadline_ns))
        self.assertEqual(observed[1][3:5],
                         (bound.effect_deadline_ns, bound.closure_deadline_ns))
        terminal = sequencer.close_terminal(
            cancel=lambda: None, quiesce=lambda: None,
            terminal_cancel=lambda: None)
        self.assertEqual(terminal.generation, 5)
        self.assertIsInstance(terminal.session_receipt, _V2SuccessfulClosure)
        self.assertEqual(terminal.component_receipts,
                         session.partial_closure_receipts)
        self.assertEqual(session.state, "CLOSED")
        self.assertEqual(len(sequencer.operations), 2)

    def test_operation_start_permit_identity_is_immutable(self):
        _, bound, _, sequencer = self.make()
        lease = _v2_lease(bound, 1)
        outcome = _v2_outcome(lease)

        def invoke(payload, callback_sink, permit):
            for name, value in (
                    ("_operation_id", runner.CAPABILITY_CLEANUP_OPERATION_ID_V2),
                    ("operation_id", runner.CAPABILITY_CLEANUP_OPERATION_ID_V2),
                    ("_execution_deadline_ns", bound.closure_deadline_ns)):
                with self.assertRaises(AttributeError):
                    setattr(permit, name, value)
            self.assertEqual(permit.operation_id,
                             runner.CAPABILITY_CAPTURE_OPERATION_ID_V2)
            self.assertEqual(permit.execution_deadline_ns,
                             bound.effect_deadline_ns)
            return permit.start(lambda: outcome)

        completion = sequencer.execute_operation(
            lease=lease, request_value={}, invoke=invoke,
            cancel=lambda: None, quiesce=lambda: None,
            terminal_cancel=lambda: None)
        self.assertEqual(completion.sequence, 1)

    def test_wrong_epoch_sequence_and_purpose_reject_before_begin(self):
        mutations = (
            {"session_epoch": "0" * 64},
            {"sequence": 2},
            {"operation_id": runner.CAPABILITY_CLEANUP_OPERATION_ID_V2},
            {"operation_purpose": runner.CAPABILITY_CLEANUP_PURPOSE_V2},
            {"effect_deadline_ns": 1},
            {"closure_deadline_ns": 1},
        )
        for changes in mutations:
            _, bound, session, sequencer = self.make()
            good = _v2_lease(bound, 1)
            changes = dict(changes)
            if "effect_deadline_ns" in changes:
                changes["effect_deadline_ns"] = good.effect_deadline_ns + 1
            if "closure_deadline_ns" in changes:
                changes["closure_deadline_ns"] = good.closure_deadline_ns + 1
            lease = replace(good, **changes)
            with self.subTest(changes=changes), self.assertRaises(
                    runner.CapabilityProviderQuiescenceFailure):
                self.execute(sequencer, lease, _v2_outcome(lease))
            self.assertEqual(session.state, "OPEN")
            self.assertEqual(session.generation, 0)

    def test_rejected_capture_lease_cannot_be_corrected_and_retried(self):
        _, bound, session, sequencer = self.make()
        good = _v2_lease(bound, 1)
        wrong = replace(good, session_epoch="0" * 64)
        with self.assertRaises(runner.CapabilityProviderQuiescenceFailure):
            self.execute(sequencer, wrong, _v2_outcome(wrong))
        with self.assertRaisesRegex(
                runner.CapabilityProviderQuiescenceFailure,
                "cannot retry"):
            self.execute(sequencer, good, _v2_outcome(good))
        self.assertEqual(session.state, "OPEN")
        self.assertEqual(session.generation, 0)
        self.assertEqual(sequencer.operations, ())

    def test_outcome_identity_mismatch_is_terminal_and_never_published(self):
        _, bound, session, sequencer = self.make()
        lease = _v2_lease(bound, 1)
        outcome = replace(_v2_outcome(lease),
                          operation_id=runner.CAPABILITY_CLEANUP_OPERATION_ID_V2)
        terminal = []
        with self.assertRaises(runner.CapabilityProviderQuiescenceFailure):
            sequencer.execute_operation(
                lease=lease, request_value={}, invoke=self.invoke(outcome, []),
                cancel=lambda: None, quiesce=lambda: None,
                terminal_cancel=lambda: terminal.append("terminal"))
        self.assertEqual(session.state, "ACTIVE")
        self.assertEqual(sequencer.operations, ())
        self.assertEqual(terminal, ["terminal"])

    def test_open_idle_receipt_cannot_substitute_for_terminal_closure(self):
        _, bound, session, sequencer = self.make()
        lease = _v2_lease(bound, 1)
        session.bad_idle = session.close_successfully()
        # Restore a fresh logical session but retain the wrong concrete receipt.
        session.state = "OPEN"
        session.generation = 0
        session.completed_purposes = ()
        session.successful_closure_receipt = None
        session.partial_closure_receipts = ()
        with self.assertRaises(runner.CapabilityProviderQuiescenceFailure):
            self.execute(sequencer, lease, _v2_outcome(lease))
        self.assertEqual(sequencer.operations, ())

    def test_late_capture_result_is_never_returned_as_success_but_cleanup_can_run(self):
        clock, bound, session, sequencer = self.make()
        lease = _v2_lease(bound, 1)
        outcome = _v2_outcome(lease)

        def late(payload, callback_sink, permit):
            return permit.start(lambda: (clock.set(bound.effect_deadline_ns),
                                         session.note_callback
                                         if False else outcome)[-1])

        with self.assertRaises(runner.DeadlineExceeded):
            sequencer.execute_operation(
                lease=lease, request_value={}, invoke=late,
                cancel=lambda: None, quiesce=lambda: None,
                terminal_cancel=lambda: None)
        self.assertEqual(sequencer.operations, ())
        self.assertIsNotNone(sequencer.publication_failure)
        self.assertEqual(session.completed_purposes,
                         (runner.CAPABILITY_CAPTURE_PURPOSE_V2,))
        cleanup_lease = _v2_lease(bound, 2)
        cleanup = self.execute(sequencer, cleanup_lease,
                               _v2_outcome(cleanup_lease))
        self.assertEqual(cleanup.sequence, 2)

    def test_reentrant_operation_is_rejected_without_consuming_second_lease(self):
        _, bound, _, sequencer = self.make()
        lease = _v2_lease(bound, 1)
        outcome = _v2_outcome(lease)
        nested = []

        def invoke(payload, callback_sink, permit):
            try:
                self.execute(sequencer, lease, outcome)
            except BaseException as error:
                nested.append(error)
            return permit.start(lambda: outcome)

        result = sequencer.execute_operation(
            lease=lease, request_value={}, invoke=invoke,
            cancel=lambda: None, quiesce=lambda: None,
            terminal_cancel=lambda: None)
        self.assertEqual(result.sequence, 1)
        self.assertEqual(len(nested), 1)
        self.assertIsInstance(nested[0], runner.CapabilityProviderQuiescenceFailure)

    def test_mutated_binding_and_session_generation_fail_closed(self):
        _, bound, session, sequencer = self.make()
        lease = _v2_lease(bound, 1)
        object.__setattr__(bound, "session_epoch", "0" * 64)
        with self.assertRaises(runner.CapabilityProviderQuiescenceFailure):
            self.execute(sequencer, lease, _v2_outcome(lease))
        object.__setattr__(bound, "session_epoch", "1" * 64)
        session.generation = 1
        with self.assertRaises(runner.CapabilityProviderQuiescenceFailure):
            self.execute(sequencer, lease, _v2_outcome(lease))

    def test_late_terminal_receipt_is_retained_but_not_returned_as_success(self):
        clock, bound, session, sequencer = self.make()
        capture_lease = _v2_lease(bound, 1)
        self.execute(sequencer, capture_lease, _v2_outcome(capture_lease))
        cleanup_lease = _v2_lease(bound, 2)
        self.execute(sequencer, cleanup_lease, _v2_outcome(cleanup_lease))
        session.close_hook = lambda: clock.set(bound.closure_deadline_ns)
        with self.assertRaises(runner.DeadlineExceeded):
            sequencer.close_terminal(cancel=lambda: None, quiesce=lambda: None,
                                     terminal_cancel=lambda: None)
        self.assertIsNotNone(sequencer.terminal_closure)
        self.assertEqual(sequencer.terminal_closure.session_receipt,
                         session.successful_closure_receipt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
