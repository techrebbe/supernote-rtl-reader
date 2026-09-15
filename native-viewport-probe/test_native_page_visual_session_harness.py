"""Host-only tests for the visual session evidence harness.

All device/process/network entry points are fake.  The semantic fake delegates
its sample construction to the reviewed graph-v2 validator/runner test
components, so the harness receives the same strict result shape it will demand
from a future reviewed no-pen adapter.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, replace
import binascii
import hashlib
import json
import socket
import subprocess
import unittest
from unittest.mock import patch
import zlib

import native_page_android_authority as android
import native_page_cleanup_ledger as ledger
import native_page_graph_v2_runner as graph
import native_page_host_authority as host
import native_page_visual_session_harness as harness
from native_page_cleanup_store import WindowsCleanupStore
from test_native_page_cleanup_store import EXTERNAL, RUN, FakeWin32
import test_native_page_graph_v2_runner as graph_fakes


SESSION = "12345678-1234-4234-8234-123456789abc"
HOST_PROCESS = host.ProcessIdentity(900, 12345, 10123, host.HOST_PACKAGE)
STOCK_PROCESS = host.ProcessIdentity(3141, 9_000_001, 1000,
                                     host.FOREIGN_PACKAGE)
HOST_TASK = 90
FOREIGN_TASK = 41
DISPLAY = 7
ACTIVITY_TOKEN = "11846f4"
FIXTURE_URI = (
    "file:///storage/emulated/0/Download/"
    "NativeViewportVisualOnly-harness-test.pdf"
)
FIXTURE_PATH = FIXTURE_URI[len("file://"):]
FIXTURE_SHA = "2" * 64
CLOCK_DOMAIN = "7" * 64


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def stable_task_sha(raw: bytes) -> str:
    task = android.parse_document_task_authority(
        raw, expected_pid=STOCK_PROCESS.pid)
    return android.stable_authority_sha256(task)


def live_activity_wire(pid: int = STOCK_PROCESS.pid,
                       task: int = FOREIGN_TASK,
                       display: int = DISPLAY) -> bytes:
    return f"""ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display areas in focus order:
Display #0 (activities from top to bottom):
  Stack #90: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{abc1234 u0 {host.HOST_COMPONENT} t90}}
    * Task{{def1234 #90 visible=true type=standard mode=fullscreen translucent=false A=10123:{host.HOST_PACKAGE} U=0 StackId=90 sz=1}}
      taskId=90 stackId=90
      * Hist #0: ActivityRecord{{abc1234 u0 {host.HOST_COMPONENT} t90}}
Display #{display} (activities from top to bottom):
  Stack #{task}: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{{ACTIVITY_TOKEN} u0 com.supernote.document/.document.DocumentActivity t{task}}}
    * Task{{66d8263 #{task} visible=true type=standard mode=fullscreen translucent=true A=1000:com.supernote.document U=0 StackId={task} sz=1}}
      taskId={task} stackId={task}
      * Hist #0: ActivityRecord{{{ACTIVITY_TOKEN} u0 com.supernote.document/.document.DocumentActivity t{task}}}
          packageName=com.supernote.document processName=com.supernote.document
          app=ProcessRecord{{2083011 {pid}:com.supernote.document/1000}}
          mActivityComponent=com.supernote.document/.document.DocumentActivity
          baseDir=/system_ext/app/SupernoteDocument/SupernoteDocument.apk
          CurrentConfiguration={{1.0 en_US 300dpi port winConfig={{ mBounds=Rect(0, 0 - 1404, 1872) mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}} s.186}}
          state=RESUMED stopped=false delayedResume=false finishing=false
          mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
          nowVisible=true lastVisibleTime=-1s
""".encode("utf-8")


def absent_activity_wire(host_present: bool) -> bytes:
    host_block = (f"""  Stack #90: type=standard mode=fullscreen
    mResumedActivity: ActivityRecord{{abc1234 u0 {host.HOST_COMPONENT} t90}}
    * Task{{def1234 #90 visible=true type=standard mode=fullscreen translucent=false A=10123:{host.HOST_PACKAGE} U=0 StackId=90 sz=1}}
      taskId=90 stackId=90
      * Hist #0: ActivityRecord{{abc1234 u0 {host.HOST_COMPONENT} t90}}
""" if host_present else "")
    return ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            "Display #0 (activities from top to bottom):\n" +
            host_block).encode("utf-8")


class RetainedHost:
    def __init__(self) -> None:
        self.process = HOST_PROCESS
        self.bad = False

    def verify(self) -> None:
        if self.bad:
            raise host.HostAuthorityError("retained host changed")

    def identity(self) -> host.ProcessIdentity:
        return self.process


class HostProviders:
    def __init__(self) -> None:
        self.clock = 10_000_000_000
        self.clock_domain = CLOCK_DOMAIN
        self.generation = 0
        self.cursor = 0
        self.events: list[tuple[host.HostEvent, object | None]] = []
        self.commands: list[host.HostCommand] = []
        self.current_placement = host.Placement.FULL
        self.fail_release = False
        self.owner: host.HostAuthority | None = None
        self.substitute_after_next_now: HostProviders | None = None
        physical = host.DisplayRecord(0, None, "physical", 1404, 1872, 300,
                                      frozenset())
        activity = host.ActivityRecord(
            HOST_PROCESS, HOST_TASK, host.HOST_COMPONENT, "host-token", 0,
            True, True)
        window = host.WindowRecord(
            HOST_PROCESS, HOST_TASK, "host-token", 0,
            host.Rect(0, 0, 1404, 1872), True, True,
            host.Rect(0, 0, 1404, 1872), (1404, 1872))
        self.snapshot = host.Snapshot(
            self.clock, host.PINNED_PACKAGE, (HOST_PROCESS, STOCK_PROCESS),
            (activity,), (window,), (physical,), "a" * 64, "b" * 64,
            "c" * 64, "d" * 64)

    def now_ns(self) -> int:
        value = self.clock
        if self.substitute_after_next_now is not None:
            assert self.owner is not None
            replacement = self.substitute_after_next_now
            self.substitute_after_next_now = None
            self.owner.providers = replacement
        return value

    def monotonic_domain_identity(self) -> str:
        return self.clock_domain

    def sleep_ns(self, value: int) -> None:
        self.clock += value

    def capture(self, _deadline: int) -> host.Snapshot:
        return replace(self.snapshot, captured_ns=self.clock)

    def attest_event(self, _event: host.HostEvent) -> None:
        return None

    def emit(self, kind: str, body: dict | None = None, *, generation: int | None = None,
             mutate=None) -> None:
        self.cursor += 1
        selected_generation = (self.generation if generation is None
                               else generation)
        event = host.HostEvent(
            self.cursor, self.clock, HOST_PROCESS, SESSION,
            selected_generation, kind, body or {})
        self.events.append((event, mutate))

    def next_event(self, _limit: int, _deadline: int) -> host.HostEvent | None:
        if not self.events:
            return None
        event, mutate = self.events.pop(0)
        if mutate is not None:
            mutate()
        return event

    def queue_start(self) -> None:
        self.emit("SESSION", generation=0)
        self.emit("DISPLAY_ALLOCATED", {"display": DISPLAY}, generation=1,
                  mutate=self.allocate_pending)
        self.emit("DISPLAY_READY", {
            "display": DISPLAY, "density": 300, "width": 1404,
            "height": 1872}, generation=1, mutate=self.allocate_ready)

    def allocate_pending(self) -> None:
        self.generation = 1
        display = host.DisplayRecord(
            DISPLAY, HOST_PROCESS, f"NativePageVisualOnly-{SESSION}-1",
            None, None, None, host.FLAGS)
        self.snapshot = replace(
            self.snapshot, displays=(self.snapshot.displays[0], display))

    def allocate_ready(self) -> None:
        self.generation = 1
        display = host.DisplayRecord(
            DISPLAY, HOST_PROCESS, f"NativePageVisualOnly-{SESSION}-1",
            1404, 1872, 300, host.FLAGS)
        self.snapshot = replace(
            self.snapshot, displays=(self.snapshot.displays[0], display))

    def set_orientation(self, width: int, height: int) -> None:
        physical = replace(self.snapshot.displays[0], width=width, height=height)
        _, surface = host.placement_frame(self.current_placement, width, height)
        window = replace(
            self.snapshot.windows[0], frame=host.Rect(0, 0, width, height),
            surface_frame=surface)
        self.snapshot = replace(
            self.snapshot,
            displays=(physical,) + self.snapshot.displays[1:],
            windows=(window,) + self.snapshot.windows[1:])

    def add_foreign(self, foreign: host.ForeignIdentity) -> None:
        activity = host.ActivityRecord(
            foreign.process, foreign.task_id, foreign.component,
            foreign.activity_token, DISPLAY, True, True)
        window = host.WindowRecord(
            foreign.process, foreign.task_id, foreign.activity_token,
            DISPLAY, host.Rect(0, 0, 1404, 1872), True, True)
        self.snapshot = replace(
            self.snapshot,
            activities=self.snapshot.activities + (activity,),
            windows=self.snapshot.windows + (window,))

    def remove_foreign(self, foreign: host.ForeignIdentity) -> None:
        self.snapshot = replace(
            self.snapshot,
            activities=tuple(item for item in self.snapshot.activities
                             if item.task_id != foreign.task_id),
            windows=tuple(item for item in self.snapshot.windows
                          if item.task_id != foreign.task_id))

    def release_host(self) -> None:
        self.snapshot = replace(
            self.snapshot,
            displays=(self.snapshot.displays[0],),
            activities=tuple(item for item in self.snapshot.activities
                             if item.task_id != HOST_TASK),
            windows=tuple(item for item in self.snapshot.windows
                          if item.task_id != HOST_TASK))

    def send(self, command: host.HostCommand, _deadline: int) -> None:
        self.commands.append(command)
        body = json.loads(command.body_json)
        if command.action == "ACK_FOREIGN_ATTACHED":
            self.emit("READY", body)
        elif command.action.startswith("PLACE_"):
            placement = host.Placement(command.action[6:])
            display = self.snapshot.displays[0]
            effective, rect = host.placement_frame(
                placement, display.width, display.height)
            self.emit("PLACEMENT_REQUESTED", {
                "sequence": command.sequence, "requested": placement.value})

            def apply() -> None:
                self.current_placement = placement
                root = replace(self.snapshot.windows[0], surface_frame=rect)
                self.snapshot = replace(
                    self.snapshot,
                    windows=(root,) + self.snapshot.windows[1:])

            self.emit("PLACEMENT_READY", {
                "sequence": command.sequence,
                "requested": placement.value,
                "effective": effective.value,
                "rect": rect.wire()}, mutate=apply)
        elif command.action == "BEGIN_CLOSE":
            foreign = next(item for item in self.snapshot.activities
                           if item.component == host.FOREIGN_COMPONENT)
            identity = host.ForeignIdentity(
                foreign.process, foreign.task_id, foreign.token,
                stable_task_sha(live_activity_wire()))
            self.emit("WAIT_FOREIGN_DESTROY", {"foreign": identity.wire()})
        elif command.action in {"ACK_FOREIGN_DESTROYED", "ACK_NO_FOREIGN_AFTER_FAILURE", "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"}:
            kinds = {"ACK_FOREIGN_DESTROYED": "FOREIGN_DESTROYED",
                     "ACK_NO_FOREIGN_AFTER_FAILURE": "EMPTY_ATTACH_ABORT",
                     "ACK_NO_FOREIGN_PRE_ATTACH_ABORT": "EMPTY_PRE_ATTACH_ABORT"}
            self.emit(kinds[command.action], body)
            if self.fail_release:
                self.emit("RELEASE_FAILED", {
                    "display": DISPLAY, "retained": True,
                    "retry_addressable": True})
            else:
                self.emit("DISPLAY_RELEASED", {
                    "display": DISPLAY, "mode": "acknowledged_cleanup"},
                    mutate=self.release_host)
        else:
            raise AssertionError("unexpected host command: " + command.action)


class StaticAdapter:
    label = "adapter"

    def __init__(self) -> None:
        self.bad = False

    def verify(self) -> None:
        if self.bad:
            raise harness.EvidenceRejected(self.label + " changed")

    def canonical_bytes(self) -> bytes:
        return graph.canonical_bytes({
            "authority": "test-retained-" + self.label + "-v1",
            "visualOnly": True,
        })


class ArtifactAdapter(StaticAdapter):
    label = "artifact"

    def __init__(self) -> None:
        super().__init__()
        self.refs: dict[str, harness.ArtifactRef] = {}
        self.raws: dict[str, bytes] = {}
        self.fail_quiescent = False
        self.retain_count = 0
        self.split_store_at: int | None = None
        self.fail_logical_name: str | None = None

    def retain(self, logical_name, raw, media_type, producer, _captured_ns):
        if logical_name == self.fail_logical_name:
            raise harness.EvidenceRejected("injected artifact publication failure")
        if logical_name in self.refs:
            raise harness.EvidenceRejected("artifact logical name replay")
        self.retain_count += 1
        store_identity = ("e" * 64 if self.split_store_at == self.retain_count
                          else "f" * 64)
        value = harness.ArtifactRef(
            logical_name, media_type, len(raw), sha(raw), producer,
            store_identity, True)
        self.refs[logical_name] = value
        self.raws[logical_name] = raw
        return value

    def verify_ref(self, reference):
        if self.refs.get(reference.logical_name) != reference:
            raise harness.EvidenceRejected("artifact reference changed")

    def assert_quiescent(self):
        if self.fail_quiescent:
            raise harness.EvidenceRejected("artifact store not quiescent")


class PlatformAdapter(StaticAdapter):
    label = "platform"

    def __init__(self, runtime: HostProviders) -> None:
        super().__init__()
        self.runtime = runtime
        self.drift_after_label: str | None = None
        self.fail_label: str | None = None
        self.retain_display_in_final = False
        self.kill_stock_in_final = False
        self.advance_after_label: str | None = None
        self.replay_timestamp_label: str | None = None
        self.future_timestamp_label: str | None = None
        self.first_captured_ns: int | None = None
        self.semantic_equivalent_activity_label: str | None = None
        self.activity_raw_by_label: dict[str, bytes] = {}

    @staticmethod
    def _wire(value) -> bytes:
        return graph.canonical_bytes(value)

    def capture(self, label, foreign, _display_id, _deadline):
        if self.fail_label == label:
            raise harness.EvidenceRejected("injected platform capture failure")
        captured_ns = self.runtime.clock
        if self.first_captured_ns is None:
            self.first_captured_ns = captured_ns
        if self.replay_timestamp_label == label:
            captured_ns = self.first_captured_ns
        if self.future_timestamp_label == label:
            captured_ns = self.runtime.clock + 1
        snapshot = replace(self.runtime.snapshot,
                           captured_ns=captured_ns)
        if label == "final-clean-inventory" and self.retain_display_in_final:
            stale = host.DisplayRecord(
                DISPLAY, HOST_PROCESS,
                f"NativePageVisualOnly-{SESSION}-1", 1404, 1872, 300,
                host.FLAGS)
            snapshot = replace(snapshot, displays=snapshot.displays + (stale,))
        if label == "final-clean-inventory" and self.kill_stock_in_final:
            snapshot = replace(
                snapshot,
                processes=tuple(item for item in snapshot.processes
                                if item != STOCK_PROCESS))
        am = (live_activity_wire() if foreign is not None else
              absent_activity_wire(any(item.task_id == HOST_TASK
                                       for item in snapshot.activities)))
        if (foreign is not None and
                self.semantic_equivalent_activity_label == label):
            am = am.replace(
                b"lastVisibleTime=-1s",
                b"lastVisibleTime=-2s", 1)
        self.activity_raw_by_label[label] = am
        inventory = harness._snapshot_inventory(snapshot)
        window = self._wire(inventory["windows"])
        process = self._wire(inventory["processes"])
        display = self._wire(inventory["displays"])
        snapshot = replace(snapshot, am_sha256=sha(am),
                           window_sha256=sha(window), process_sha256=sha(process),
                           display_sha256=sha(display))
        if self.drift_after_label == label:
            display = display + b"drift"
        self.runtime.snapshot = snapshot
        result = harness.PlatformCapture(
            captured_ns, snapshot, am, window, process, display)
        if self.advance_after_label == label:
            self.runtime.clock += 1
        return result


class OrientationAdapter(StaticAdapter):
    label = "orientation"

    def __init__(self, runtime: HostProviders) -> None:
        super().__init__()
        self.runtime = runtime
        self.calls: list[str] = []
        self.wrong_rotation_at: int | None = None

    def await_observation(self, phase, _deadline):
        self.calls.append(phase.name)
        self.runtime.set_orientation(phase.width, phase.height)
        rotation = (0 if phase.physical == "PORTRAIT" else 1)
        if self.wrong_rotation_at == len(self.calls):
            rotation = 0 if phase.physical == "LANDSCAPE" else 1
        raw = graph.canonical_bytes({
            "authority": harness.ORIENTATION_AUTHORITY,
            "schemaVersion": 1,
            "capturedNs": str(self.runtime.clock),
            "phase": phase.name,
            "width": phase.width,
            "height": phase.height,
            "rotation": rotation,
            "source": "physical-user-rotation-observation-only",
            "inputEventsGenerated": 0,
        })
        return harness.OrientationObservation(
            self.runtime.clock, phase.width, phase.height,
            rotation,
            "physical-user-rotation-observation-only", 0, raw)


class VisualAdapter(StaticAdapter):
    label = "visual"

    def __init__(self, runtime: HostProviders) -> None:
        super().__init__()
        self.runtime = runtime
        self.calls: list[str] = []
        self.wrong_dimensions_at: int | None = None
        self.corrupt_at: int | None = None
        self.advance_after_at: int | None = None
        self.replay_at: int | None = None
        self.future_timestamp_at: int | None = None
        self.first_capture: tuple[int, int, int, bytes] | None = None

    @staticmethod
    def _png(width: int, height: int, marker: int) -> bytes:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            checksum = binascii.crc32(kind + payload) & 0xffffffff
            return (len(payload).to_bytes(4, "big") + kind + payload +
                    checksum.to_bytes(4, "big"))

        # Valid one-bit grayscale pixels keep full physical dimensions cheap.
        row = b"\x00" + bytes((width + 7) // 8)
        first = bytearray(row)
        first[1] = marker & 0xff
        pixels = bytes(first) + row * (height - 1)
        header = (width.to_bytes(4, "big") + height.to_bytes(4, "big") +
                  b"\x01\x00\x00\x00\x00")
        return (harness.PNG_SIGNATURE + chunk(b"IHDR", header) +
                chunk(b"IDAT", zlib.compress(pixels, 9)) +
                chunk(b"IEND", b""))

    def capture(self, phase, foreign, applied, _deadline):
        self.calls.append(phase.name)
        width = (phase.width + 1 if self.wrong_dimensions_at == len(self.calls)
                 else phase.width)
        png = self._png(width, phase.height, len(self.calls))
        captured_ns = self.runtime.clock
        if self.replay_at == len(self.calls) and self.first_capture is not None:
            captured_ns, width, height, png = self.first_capture
        else:
            height = phase.height
        if self.corrupt_at == len(self.calls):
            png = png[:-1]
        if self.future_timestamp_at == len(self.calls):
            captured_ns = self.runtime.clock + 1
        result = harness.VisualCapture(
            captured_ns, width, height, foreign.task_id,
            applied.display_id, applied.sequence,
            png, 0)
        if self.first_capture is None:
            self.first_capture = (captured_ns, width, height, png)
        if self.advance_after_at == len(self.calls):
            self.runtime.clock += 1
        return result


class TaskAdapter(StaticAdapter):
    label = "task"

    def __init__(self, runtime: HostProviders) -> None:
        super().__init__()
        self.runtime = runtime
        self.foreign: host.ForeignIdentity | None = None
        self.destroyed = False
        self.fail_launch_after_add = False
        self.uncertain_launch_mode: str | None = None
        self.fail_destroy_after_remove = False
        self.clock_domain = CLOCK_DOMAIN
        self.reported_clock_domain = CLOCK_DOMAIN
        self.before_uncertainty_throw = None

    def monotonic_domain_identity(self):
        return self.reported_clock_domain

    def canonical_bytes(self):
        return graph.canonical_bytes({
            "authority": "test-retained-task-v1",
            "visualOnly": True,
            "monotonicDomainSha256": self.clock_domain,
        })

    def launch_fixture(self, serial, fixture_uri, fixture_sha, display, _deadline):
        if (serial, fixture_uri, fixture_sha, display) != (
                harness.AUTHORIZED_SERIAL, FIXTURE_URI, FIXTURE_SHA, DISPLAY):
            raise harness.EvidenceRejected("launch scope differs")
        raw = live_activity_wire()
        self.foreign = host.ForeignIdentity(
            STOCK_PROCESS, FOREIGN_TASK, ACTIVITY_TOKEN,
            stable_task_sha(raw))
        self.runtime.add_foreign(self.foreign)
        if self.fail_launch_after_add:
            raise harness.EvidenceRejected("launch outcome uncertain after exact side effect")
        if self.uncertain_launch_mode is not None:
            if self.before_uncertainty_throw is not None:
                self.before_uncertainty_throw()
            if self.uncertain_launch_mode == "typed-known-drift":
                self.bad = True
            if self.uncertain_launch_mode in {"typed-known", "typed-known-drift"}:
                raise harness.TaskLaunchOutcomeUncertain(
                    "typed exact launch outcome uncertainty", self.foreign,
                    reason_code="TEST_TYPED_KNOWN")
            if self.uncertain_launch_mode == "typed-unknown":
                raise harness.TaskLaunchOutcomeUncertain(
                    "typed unknown launch outcome uncertainty", None,
                    reason_code="TEST_TYPED_UNKNOWN")
            if self.uncertain_launch_mode == "untyped-lookalike":
                class Lookalike(harness.EvidenceRejected):
                    pass
                error = Lookalike("untyped lookalike")
                error.retained_foreign = self.foreign
                error.evidence = b"not typed authority"
                raise error
            if self.uncertain_launch_mode == "invalid-foreign":
                invalid = replace(
                    self.foreign,
                    process=replace(self.foreign.process, uid=2000))
                raise harness.TaskLaunchOutcomeUncertain(
                    "invalid retained identity", invalid,
                    reason_code="TEST_INVALID_FOREIGN")
            raise AssertionError("unknown uncertainty mode")
        return harness.LaunchReceipt(
            self.foreign, fixture_uri, fixture_sha,
            b"exact fixture launch", False, False)

    def destroy_exact_task(self, serial, foreign, _deadline):
        if serial != harness.AUTHORIZED_SERIAL or foreign != self.foreign:
            raise harness.EvidenceRejected("destroy scope differs")
        self.runtime.remove_foreign(foreign)
        self.destroyed = True
        if self.fail_destroy_after_remove:
            raise harness.EvidenceRejected("destroy receipt lost after exact task removal")
        return harness.TaskClosure(
            foreign, True, True, b"exact task absent; stock process alive",
            False, False)

    def assert_quiescent(self, foreign, _deadline):
        if (not self.destroyed or any(item.task_id == foreign.task_id
                                     for item in self.runtime.snapshot.activities)):
            raise harness.EvidenceRejected("exact task remains")


def stat(seed: int) -> dict:
    return {
        "device": str(seed), "inode": str(seed + 1), "mode": "33188",
        "uid": 2000, "gid": 2000,
        "mtimeNs": "100", "ctimeNs": "101"}


def files_authority() -> dict:
    return {
        "authority": graph.FILE_AUTHORITY,
        "verification": "external-before-and-after-exact",
        "originalPdf": {
            "present": True, "path": FIXTURE_PATH, "size": "4096",
            "sha256": FIXTURE_SHA, "stat": stat(1),
            "documentUri": FIXTURE_URI,
            "uriResolution": {
                "authority": "rtl-reader-file-uri-resolution-v1",
                "documentUri": FIXTURE_URI, "resolvedPath": FIXTURE_PATH,
                "evidenceSha256": "3" * 64,
            },
        },
        "mark": {
            "present": True, "path": FIXTURE_PATH + ".mark", "size": "512",
            "sha256": "4" * 64,
            "stat": stat(2),
        },
    }


class FileAdapter(StaticAdapter):
    label = "file"

    def __init__(self, runtime: HostProviders) -> None:
        super().__init__()
        self.runtime = runtime
        self.mutate_after = False
        self.mutate_mark_after = False
        self.mutate_ink_after = False
        self.wrong_initial_sha = False
        self.stat_mismatch = False
        self.saved_ink_raw_mismatch = False
        self.files = files_authority()
        self.capture_calls = 0
        self.after_capture = None

    def capture(self, phase, serial, uri, _deadline):
        self.capture_calls += 1
        if serial != harness.AUTHORIZED_SERIAL or uri != FIXTURE_URI:
            raise harness.EvidenceRejected("file capture scope differs")
        pdf_sha = ("8" * 64 if phase == "before" and self.wrong_initial_sha else
                   "9" * 64 if phase == "after" and self.mutate_after else
                   FIXTURE_SHA)
        pdf = harness.DeviceFile(
            True, FIXTURE_PATH, 4096, pdf_sha, 1, 2, 33188, 2000, 2000,
            100, 101)
        mark_sha = ("5" * 64 if phase == "after" and self.mutate_mark_after
                    else "4" * 64)
        mark = harness.DeviceFile(
            True, FIXTURE_PATH + ".mark", 512, mark_sha, 2, 3, 33188,
            2000, 2000, 100, 101)
        ink_records = ([{"evidence": "changed"}]
                       if phase == "after" and self.mutate_ink_after else [])
        raw = graph.canonical_bytes({
            "authority": harness.SAVED_INK_AUTHORITY,
            "schemaVersion": 1,
            "state": "PRESENT",
            "sourceMarkSha256": mark.sha256,
            "records": ink_records,
        })
        if self.saved_ink_raw_mismatch:
            raw = graph.canonical_bytes({
                "authority": harness.SAVED_INK_AUTHORITY,
                "schemaVersion": 1,
                "state": "MARK_ABSENT",
                "sourceMarkSha256": mark.sha256,
                "records": [],
            })
        ink = harness.SavedInkEvidence(
            "PRESENT", 2000, "6" * 64, mark.sha256, sha(raw),
            len(ink_records), raw)
        selected = copy.deepcopy(self.files)
        selected["originalPdf"]["sha256"] = pdf_sha
        selected["mark"]["sha256"] = mark_sha
        if self.stat_mismatch:
            selected["originalPdf"]["stat"]["inode"] = "999"
        result = harness.FileEvidenceCapture(
            self.runtime.clock, phase, pdf, mark, ink, selected,
            ("file-evidence-" + phase).encode("ascii"))
        if self.after_capture is not None:
            self.after_capture()
        return result


class SemanticAdapter(StaticAdapter):
    label = "semantic"

    def __init__(self, session: str) -> None:
        super().__init__()
        self.session = session
        self.count = 0
        self.fail_at: int | None = None
        self.drift_at: int | None = None
        self.reuse_identity_at: int | None = None
        self.pen_at: int | None = None
        self.bad_on_quiescent = False
        self.quiescent_calls = 0
        self.clock_domain = CLOCK_DOMAIN
        self.reported_clock_domain = CLOCK_DOMAIN

    def monotonic_domain_identity(self):
        return self.reported_clock_domain

    def canonical_bytes(self):
        return graph.canonical_bytes({
            "authority": "test-retained-semantic-v1",
            "visualOnly": True,
            "monotonicDomainSha256": self.clock_domain,
        })

    def capture(self, phase, ordinal, foreign, applied, task,
                file_authority, _deadline):
        self.count += 1
        if self.fail_at == self.count:
            raise harness.EvidenceRejected("injected semantic capture failure")
        clock = graph_fakes.Clock()
        identity = 1 if self.reuse_identity_at == self.count else self.count
        observer_session = f"visual-sample:{identity:04d}"
        bound = graph.StageBinding(
            graph.AUTHORIZED_SERIAL, foreign.process.pid,
            str(foreign.process.start_ticks), observer_session, 1000,
            clock() + 1_000_000_000, phase.placement.value)
        manifest_value = graph_fakes.manifest_value(bound)
        manifest_value["attachment"]["apk"]["path"] = task.base_apk_path
        manifest_value["externalSession"] = {
            "authority": graph.EXTERNAL_SESSION_AUTHORITY,
            "authorizedSerial": graph.AUTHORIZED_SERIAL,
            "taskId": foreign.task_id,
            "displayId": applied.display_id,
            "hostSessionId": self.session,
            "displayGeneration": applied.generation,
        }
        manifest_value["files"] = copy.deepcopy(file_authority)
        manifest_value["expected"]["documentUri"] = FIXTURE_URI
        manifest = graph.load_canonical(
            graph.canonical_bytes(manifest_value), graph.MAX_MANIFEST_BYTES)
        bundle = graph_fakes.FakeBundle()
        tool = graph.load_canonical(bundle.canonical_bytes(),
                                    graph.MAX_AUTHORITY_BYTES)
        before = graph_fakes.stage_value(
            manifest, bound, tool.sha256, "before", task)
        after = graph_fakes.stage_value(
            manifest, bound, tool.sha256, "after", task)
        for value in (before, after):
            value["host"]["placementRequestGeneration"] = applied.sequence
            value["host"]["placementReadyGeneration"] = applied.sequence
            value["host"]["hostPackageName"] = host.HOST_PACKAGE
            value["host"]["hostApkSha256"] = host.APK_SHA256
            value["host"]["hostTaskId"] = HOST_TASK
            value["host"]["hostActivityToken"] = "host-token"
            value["host"]["requestedFrame"] = phase.rect.wire()
            value["host"]["measuredGlobalFrame"] = phase.rect.wire()
        provider = graph_fakes.FakeAuthorityProvider(
            before, after, selected_task=task)
        frida = graph_fakes.FakeFrida(manifest)
        bundle.clock = provider.clock = frida.clock = clock
        pins = graph.TrustedPins(
            tool.sha256, manifest.sha256,
            provider.admission_record.sha256,
            frida.admission_record.sha256,
            graph.stage_policy_sha256(before), graph_fakes.RECEIPT_KEY)
        nonce = f"{identity:064x}"
        result = graph.run_one_stage(
            manifest=manifest,
            observer_source=graph_fakes.OBSERVER_TEXT,
            observer_sha256=graph_fakes.OBSERVER_SHA,
            binding=bound, tool_bundle=bundle,
            authority_provider=provider, frida_provider=frida,
            trusted_pins=pins, ambient_environment={}, clock_ns=clock,
            nonce_factory=lambda: nonce)
        if self.drift_at == self.count:
            result = copy.deepcopy(result)
            result["snapshot"]["document"]["rawCurrentPage"] += 1
        receipt = sha(graph.canonical_bytes({
            "sample": self.count, "phase": phase.name, "ordinal": ordinal,
            "resultSha256": sha(graph.canonical_bytes(result)),
        }))
        return harness.SemanticCapture(
            f"sample:{identity:04d}", receipt, manifest,
            provider.emitted_records[0][0], result,
            b"reviewed semantic transcript", 0, 0,
            1 if self.pen_at == self.count else 0)

    def assert_quiescent(self, _deadline):
        self.quiescent_calls += 1
        if self.bad_on_quiescent:
            self.bad = True


def adapter_pins(adapters: harness.Adapters) -> dict[str, str]:
    return {
        item.name: sha(getattr(adapters, item.name).canonical_bytes())
        for item in harness.fields(harness.Adapters)
    }


def resign_session_records(records: list[dict]) -> list[dict]:
    """Test-only independent re-signer for adversarial full-log fixtures."""
    result: list[dict] = []
    previous = ledger.ZERO_HASH
    intent_hashes: dict[str, str] = {}
    for sequence, source in enumerate(copy.deepcopy(records)):
        record = {name: value for name, value in source.items()
                  if name != "hash"}
        record["sequence"] = sequence
        record["previous_hash"] = previous
        data = record["data"]
        if record["event"] == "operation_result":
            data["intentSha256"] = intent_hashes[data["operation"]]
        elif record["event"] == "cleanup_started":
            data["headSha256"] = previous
        elif record["event"] == "manifest":
            data["journalHeadBeforeManifest"] = previous
            data["recordCountBeforeManifest"] = sequence
        elif record["event"] == "quarantine":
            data["journalHeadBeforeTerminal"] = previous
            data["recordCountBeforeTerminal"] = sequence
        record["hash"] = sha(ledger.canonical_json(record))
        if record["event"] == "operation_intent":
            intent_hashes[data["operation"]] = record["hash"]
        previous = record["hash"]
        result.append(record)
    return result


class VisualSessionHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        for guard in (
                patch.object(socket, "socket",
                             side_effect=AssertionError("no network")),
                patch.object(subprocess, "Popen",
                             side_effect=AssertionError("no process launch"))):
            guard.start()
            self.addCleanup(guard.stop)
        self.runtime = HostProviders()
        self.runtime.queue_start()
        self.host = host.HostAuthority(
            RetainedHost(), self.runtime, SESSION, HOST_TASK, "host-token")
        self.runtime.owner = self.host
        self.artifact = ArtifactAdapter()
        self.platform = PlatformAdapter(self.runtime)
        self.semantic = SemanticAdapter(SESSION)
        self.task = TaskAdapter(self.runtime)
        self.file = FileAdapter(self.runtime)
        self.orientation = OrientationAdapter(self.runtime)
        self.visual = VisualAdapter(self.runtime)
        self.adapters = harness.Adapters(
            self.artifact, self.platform, self.semantic, self.task,
            self.file, self.orientation, self.visual)
        pins = {
            name: sha(getattr(self.adapters, name).canonical_bytes())
            for name in ("artifact", "platform", "semantic", "task", "file",
                         "orientation", "visual")}
        self.plan = harness.SessionPlan(
            SESSION, FIXTURE_URI, FIXTURE_SHA, CLOCK_DOMAIN,
            self.runtime.clock + 50_000_000_000, True, pins)
        self.api = FakeWin32()
        self.store = WindowsCleanupStore.create_new(
            RUN, EXTERNAL, api=self.api)
        self.addCleanup(self.store.close)
        self.log = harness.AppendOnlySessionLog(self.store, self.plan)
        self.subject = harness.VisualSessionHarness(
            self.plan, self.host, self.adapters, self.log)

    def assert_forged_log_rejected(self, forged: list[dict],
                                   message: str) -> None:
        checkpoint = ledger.RecoveryCheckpoint(
            self.log.ledger_id, len(forged) - 1, forged[-1]["hash"])

        def validated_read() -> list[dict]:
            selected: list[dict] = []
            for record in forged:
                self.log._validate_record(record)
                self.log._validate_transition(
                    selected, record["event"], record["data"])
                selected.append(record)
            return copy.deepcopy(selected)

        with patch.object(self.log, "_read", side_effect=validated_read), \
                patch.object(self.store, "load_checkpoint",
                             return_value=checkpoint):
            with self.assertRaisesRegex(harness.EvidenceRejected, message):
                self.log.verify()

    def test_complete_full_left_right_full_and_physical_rotation_bundle(self):
        manifest = self.subject.run()
        self.assertEqual(manifest["status"],
                         "VISUAL_EVIDENCE_COMPLETE_DIAGNOSTIC")
        self.assertFalse(manifest["hardwareAdmission"])
        self.assertEqual(len(manifest["phaseEvidence"]), 6)
        self.assertTrue(manifest["fileEvidence"]["unchanged"])
        self.assertEqual(self.semantic.count, 12)
        self.assertEqual(self.orientation.calls,
                         [phase.name for phase in self.plan.phases])
        self.assertEqual(self.visual.calls,
                         [phase.name for phase in self.plan.phases])
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertEqual(self.subject.remaining, set())
        self.assertEqual(self.log.records[-1]["event"], "manifest")
        self.assertEqual(self.log.verify(), manifest)
        semantic_rows = [record["data"] for record in self.log.records
                         if record["event"] == "semantic_sample"]
        self.assertEqual([row["ordinal"] for row in semantic_rows],
                         [1, 2] * 6)
        self.assertEqual(len({row["observerSessionId"]
                              for row in semantic_rows}), 12)
        self.assertEqual(len({row["manifestSha256"]
                              for row in semantic_rows}), 12)
        self.assertTrue(all(row["inputEventsGenerated"] == 0 and
                            row["writerCalls"] == 0 and
                            row["penOperations"] == 0
                            for row in semantic_rows))
        visual_rows = [record["data"] for record in self.log.records
                       if record["event"] == "visual_capture"]
        self.assertEqual(len(visual_rows), 6)
        self.assertEqual(len({row["artifact"]["sha256"]
                              for row in visual_rows}), 6)
        self.assertEqual(manifest["policy"]["penOperationCount"], 0)
        self.assertFalse(manifest["policy"]["booxAddressed"])

        without_operations = resign_session_records([
            record for record in self.log.records
            if record["event"] not in {"operation_intent", "operation_result"}
        ])
        self.assert_forged_log_rejected(
            without_operations, "operation sequence")

        wrong_producer = copy.deepcopy(self.log.records)
        target_name = next(
            record["data"]["reference"]["logicalName"]
            for record in wrong_producer
            if record["event"] == "artifact_retained" and
            record["data"]["reference"]["logicalName"].startswith(
                "orientation/"))
        for record in wrong_producer:
            if (record["event"] == "artifact_retained" and
                    record["data"]["reference"]["logicalName"] == target_name):
                record["data"]["reference"]["producerAuthoritySha256"] = \
                    self.plan.adapter_pins["file"]
            elif record["event"] == "manifest":
                reference = next(
                    item for item in record["data"]["artifacts"]
                    if item["logicalName"] == target_name)
                reference["producerAuthoritySha256"] = \
                    self.plan.adapter_pins["file"]
        self.assert_forged_log_rejected(
            resign_session_records(wrong_producer), "artifact producer")

        admitted_opening = copy.deepcopy(self.log.records)
        admitted_opening[0]["data"]["admission"]["admitted"] = True
        self.assert_forged_log_rejected(
            resign_session_records(admitted_opening), "session opening")

        wrong_ledger = copy.deepcopy(self.log.records)
        wrong_ledger[0]["data"]["ledger_id"] = "f" * 32
        self.assert_forged_log_rejected(
            resign_session_records(wrong_ledger), "session opening")

        wrong_provenance = copy.deepcopy(self.log.records)
        wrong_provenance[-1]["data"]["provenance"]["hostDexSha256"] = \
            "0" * 64
        self.assert_forged_log_rejected(
            resign_session_records(wrong_provenance),
            "terminal manifest differs")

        for field in ("hostApkSha256", "hostUnsignedApkSha256",
                      "hostSignerCertSha256"):
            wrong_package_provenance = copy.deepcopy(self.log.records)
            wrong_package_provenance[-1]["data"]["provenance"][field] = "0" * 64
            with self.subTest(field=field):
                self.assert_forged_log_rejected(
                    resign_session_records(wrong_package_provenance),
                    "terminal manifest differs")

    def test_injected_sample_failure_runs_exact_cleanup_and_seals_failed_manifest(self):
        self.semantic.fail_at = 6
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        manifest = caught.exception.manifest
        self.assertEqual(manifest["status"], "FAILED_CLEAN")
        self.assertEqual(manifest["primaryFailure"]["code"],
                         "EvidenceRejected")
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertEqual(self.subject.remaining, set())
        self.assertEqual(self.log.records[-1]["event"], "manifest")
        self.assertEqual(self.log.verify(), manifest)
        self.assertEqual([row["phaseIndex"] for row in
                          manifest["phaseEvidence"]], [0, 1])
        with self.assertRaises(harness.EvidenceRejected):
            self.log.append("cleanup_started", {
                "primaryFailure": None, "headSha256": self.log.head}, ())

    def test_semantic_identity_drift_aborts_before_next_phase_and_cleans(self):
        self.semantic.drift_at = 4
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("semantic samples disagree",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertEqual(self.semantic.count, 4)
        self.assertTrue(self.task.destroyed)

    def test_pdf_mark_savedink_change_cannot_publish_clean_manifest(self):
        self.semantic.fail_at = 1
        self.file.mutate_after = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        terminal = caught.exception.terminal
        self.assertTrue(terminal["recoveryRequired"])
        self.assertTrue(any(row["step"] == "unchanged_pdf_mark_savedink"
                            for row in terminal["cleanupFailures"]))
        self.assertEqual(self.log.records[-1]["event"], "quarantine")

    def test_artifact_quiescence_failure_retains_exact_obligation(self):
        self.semantic.fail_at = 1
        self.artifact.fail_quiescent = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("artifact_store", caught.exception.terminal["remaining"])
        self.assertTrue(any(row["step"] == "artifact_authority_quiescent"
                            for row in caught.exception.terminal["cleanupFailures"]))

    def test_wrong_adapter_pin_rejects_before_host_or_device_operation(self):
        api = FakeWin32()
        store = WindowsCleanupStore.create_new(
            r"C:\sandbox\run2", r"C:\authority\checkpoints2", api=api)
        self.addCleanup(store.close)
        pins = dict(self.plan.adapter_pins)
        pins["semantic"] = "0" * 64
        plan = replace(self.plan, adapter_pins=pins)
        log = harness.AppendOnlySessionLog(store, plan)
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "adapter pin differs"):
            harness.VisualSessionHarness(plan, self.host, self.adapters, log)
        self.assertEqual(self.runtime.commands, [])

    def test_plan_cannot_omit_physical_rotation_round_trip(self):
        with self.assertRaisesRegex(
                harness.EvidenceRejected, "physical-rotation return"):
            harness.SessionPlan(
                SESSION, FIXTURE_URI, FIXTURE_SHA, CLOCK_DOMAIN,
                self.runtime.clock + 50_000_000_000, False,
                dict(self.plan.adapter_pins))
        self.assertEqual(self.runtime.commands, [])

    def test_harness_constructor_requires_host_plan_clock_domain_match(self):
        self.runtime.clock_domain = "8" * 64
        with self.assertRaisesRegex(
                harness.EvidenceRejected, "host provider and session-plan"):
            harness.VisualSessionHarness(
                self.plan, self.host, self.adapters, self.log)
        self.assertEqual(self.runtime.commands, [])

    def test_harness_constructor_requires_task_host_clock_domain_match(self):
        self.task.reported_clock_domain = "8" * 64
        with self.assertRaisesRegex(
                harness.EvidenceRejected, "task adapter and host"):
            harness.VisualSessionHarness(
                self.plan, self.host, self.adapters, self.log)
        self.assertEqual(self.runtime.commands, [])

    def test_harness_constructor_requires_semantic_host_clock_domain_match(self):
        self.semantic.reported_clock_domain = "8" * 64
        with self.assertRaisesRegex(
                harness.EvidenceRejected, "semantic adapter and host"):
            harness.VisualSessionHarness(
                self.plan, self.host, self.adapters, self.log)
        self.assertEqual(self.runtime.commands, [])

    def test_host_clock_domain_drift_is_detected_before_any_host_dispatch(self):
        self.runtime.clock_domain = "8" * 64
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("monotonic clock domain changed",
                      caught.exception.terminal["primaryFailure"]["message"])
        self.assertIsNone(self.task.foreign)
        self.assertEqual(self.runtime.commands, [])

    def test_task_clock_domain_drift_cannot_reach_launch_dispatch(self):
        self.task.reported_clock_domain = "8" * 64
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertIsNone(self.task.foreign)
        self.assertFalse(self.task.destroyed)

    def test_same_canonical_adapter_objects_and_container_are_not_authority(self):
        for name in ("artifact", "platform", "semantic", "task", "file",
                     "orientation", "visual"):
            original = getattr(self.adapters, name)
            substitute = copy.copy(original)
            self.assertEqual(substitute.canonical_bytes(),
                             original.canonical_bytes())
            object.__setattr__(self.adapters, name, substitute)
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                        harness.EvidenceRejected,
                        "retained adapter object was substituted"):
                    self.subject._verify_adapter(name)
            object.__setattr__(self.adapters, name, original)

        same_members = harness.Adapters(
            self.artifact, self.platform, self.semantic, self.task,
            self.file, self.orientation, self.visual)
        self.subject.adapters = same_members
        with self.assertRaisesRegex(
                harness.EvidenceRejected,
                "retained adapters container was substituted"):
            self.subject._verify_adapter("file")
        self.assertEqual(self.runtime.commands, [])

    def test_adapter_substitution_during_call_is_detected_after_retained_call(self):
        substitute = copy.copy(self.file)
        self.assertEqual(substitute.canonical_bytes(),
                         self.file.canonical_bytes())
        self.file.after_capture = lambda: object.__setattr__(
            self.adapters, "file", substitute)
        with self.assertRaisesRegex(
                harness.EvidenceRejected,
                "retained adapter object was substituted"):
            self.subject._file_capture("before")
        self.assertEqual(self.file.capture_calls, 1)
        self.assertEqual(self.runtime.commands, [])

    def test_typed_launch_uncertainty_cannot_transfer_from_substituted_adapter(self):
        substitute = TaskAdapter(self.runtime)
        self.assertEqual(substitute.canonical_bytes(),
                         self.task.canonical_bytes())
        self.task.uncertain_launch_mode = "typed-known"
        self.task.before_uncertainty_throw = lambda: object.__setattr__(
            self.adapters, "task", substitute)
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertFalse(self.task.destroyed)
        self.assertIsNone(substitute.foreign)
        self.assertTrue(any(item.task_id == FOREIGN_TASK
                            for item in self.runtime.snapshot.activities))

    def test_host_and_provider_same_domain_substitutions_fail_exact_identity(self):
        replacement_provider = HostProviders()
        replacement_provider.clock = self.runtime.clock
        replacement_host = host.HostAuthority(
            RetainedHost(), self.runtime, SESSION, HOST_TASK, "host-token")
        for case in ("host", "provider"):
            if case == "host":
                self.subject.host = replacement_host
                expected = "retained host authority object was substituted"
            else:
                self.subject.host = self.host
                self.host.providers = replacement_provider
                expected = "retained host provider object was substituted"
            with self.subTest(case=case):
                with self.assertRaisesRegex(harness.EvidenceRejected,
                                            expected):
                    self.subject._trusted_capture_start()
            self.host.providers = self.runtime
        self.assertEqual(self.runtime.commands, [])

    def test_host_provider_substitution_during_host_operation_is_detected(self):
        replacement = HostProviders()
        replacement.clock = self.runtime.clock
        self.runtime.substitute_after_next_now = replacement
        with self.assertRaisesRegex(
                harness.EvidenceRejected,
                "retained host provider object was substituted"):
            self.subject._host_call(
                lambda authority: authority.admit_startable(
                    self.plan.absolute_deadline_ns))
        self.assertEqual(self.runtime.commands, [])

    def test_platform_raw_digest_mismatch_fails_closed_then_exact_cleanup(self):
        self.platform.drift_after_label = "phase-00-sample-1-before"
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("raw evidence digest differs",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)

    def test_foreign_task_identity_accepts_semantically_equal_raw_capture(self):
        label = "phase-00-sample-1-before"
        self.platform.semantic_equivalent_activity_label = label
        launch_raw = live_activity_wire()

        manifest = self.subject.run()

        captured_raw = self.platform.activity_raw_by_label[label]
        self.assertNotEqual(sha(captured_raw), sha(launch_raw))
        self.assertEqual(stable_task_sha(captured_raw),
                         stable_task_sha(launch_raw))
        self.assertEqual(manifest["status"],
                         "VISUAL_EVIDENCE_COMPLETE_DIAGNOSTIC")

    def test_wrong_initial_fixture_digest_is_rejected_before_host_start(self):
        self.file.wrong_initial_sha = True
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "admitted fixture digest"):
            self.subject._file_capture("before")
        self.assertEqual(self.runtime.commands, [])

    def test_file_stat_must_match_graph_authority_exactly(self):
        self.file.stat_mismatch = True
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "PDF graph/file evidence differs"):
            self.subject._file_capture("before")
        self.assertEqual(self.runtime.commands, [])

    def test_saved_ink_raw_and_typed_authority_must_match(self):
        self.file.saved_ink_raw_mismatch = True
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "SavedInk typed evidence"):
            self.subject._file_capture("before")
        self.assertEqual(self.runtime.commands, [])

    def test_invalid_physical_rotation_fails_then_cleans_exactly(self):
        self.orientation.wrong_rotation_at = 1
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("physical orientation observation differs",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")

    def test_corrupt_visual_capture_fails_then_cleans_exactly(self):
        self.visual.corrupt_at = 1
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("visual PNG", caught.exception.manifest[
            "primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")

    def test_semantic_identities_cannot_be_reused_across_phases(self):
        self.semantic.reuse_identity_at = 3
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("identity was reused",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertEqual(self.semantic.count, 3)
        self.assertTrue(self.task.destroyed)

    def test_nonzero_pen_operation_claim_is_rejected_and_cleaned(self):
        self.semantic.pen_at = 1
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("input, pen, or writer",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)

    def test_mark_change_is_independently_quarantined(self):
        self.semantic.fail_at = 1
        self.file.mutate_mark_after = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(any(row["step"] == "unchanged_pdf_mark_savedink"
                            for row in caught.exception.terminal[
                                "cleanupFailures"]))

    def test_saved_ink_change_is_independently_quarantined(self):
        self.semantic.fail_at = 1
        self.file.mutate_ink_after = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(any(row["step"] == "unchanged_pdf_mark_savedink"
                            for row in caught.exception.terminal[
                                "cleanupFailures"]))

    def test_final_inventory_rejects_a_retained_created_display(self):
        self.semantic.fail_at = 1
        self.platform.retain_display_in_final = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(any(row["step"] == "final_platform_inventory"
                            for row in caught.exception.terminal[
                                "cleanupFailures"]))

    def test_final_inventory_requires_stock_process_liveness(self):
        self.semantic.fail_at = 1
        self.platform.kill_stock_in_final = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(any(row["step"] == "final_platform_inventory"
                            for row in caught.exception.terminal[
                                "cleanupFailures"]))

    def test_destroy_receipt_loss_still_attempts_safe_absence_release(self):
        self.semantic.fail_at = 1
        self.task.fail_destroy_after_remove = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertTrue(any(row["step"] == "destroy_exact_foreign_task"
                            for row in caught.exception.terminal[
                                "cleanupFailures"]))

    def test_release_failure_is_quarantined_and_cleanup_keeps_running(self):
        self.semantic.fail_at = 1
        self.runtime.fail_release = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("virtual_display", caught.exception.terminal["remaining"])
        self.assertTrue(self.task.destroyed)
        self.assertIsNotNone(self.subject._file_after)

    def test_cleanup_adapter_pin_drift_is_quarantined(self):
        self.semantic.fail_at = 1
        self.semantic.bad_on_quiescent = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        failed = {row["step"] for row in caught.exception.terminal[
            "cleanupFailures"]}
        self.assertIn("semantic_sampler_quiescent", failed)
        self.assertIn("all_adapters_still_pinned", failed)

    def test_uncertain_launcher_side_effect_is_never_broadly_cleaned(self):
        self.task.fail_launch_after_add = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertFalse(self.task.destroyed)
        self.assertTrue(any(item.component == host.FOREIGN_COMPONENT
                            for item in self.runtime.snapshot.activities))
        self.assertEqual(self.runtime.commands, [])

    def test_typed_uncertainty_transfers_exact_identity_then_cleans_it(self):
        self.task.uncertain_launch_mode = "typed-known"
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertEqual(self.subject.remaining, set())
        self.assertEqual(caught.exception.manifest["status"], "FAILED_CLEAN")
        launch_ref = self.artifact.refs["launch/exact-fixture-task.txt"]
        retained = json.loads(self.artifact.raws[launch_ref.logical_name])
        self.assertEqual(retained["authority"],
                         harness.TASK_LAUNCH_UNCERTAINTY_AUTHORITY)
        self.assertEqual(retained["retainedForeign"]["task"], FOREIGN_TASK)

    def test_typed_uncertainty_without_identity_preserves_unknown_creation(self):
        self.task.uncertain_launch_mode = "typed-unknown"
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertFalse(self.task.destroyed)
        self.assertEqual(self.runtime.commands, [])

    def test_untyped_lookalike_cannot_transfer_cleanup_identity(self):
        self.task.uncertain_launch_mode = "untyped-lookalike"
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertFalse(self.task.destroyed)
        self.assertEqual(self.runtime.commands, [])

    def test_invalid_typed_identity_cannot_transfer_cleanup_ownership(self):
        self.task.uncertain_launch_mode = "invalid-foreign"
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertFalse(self.task.destroyed)
        self.assertEqual(self.runtime.commands, [])

    def test_adapter_drift_after_typed_throw_blocks_identity_transfer(self):
        self.task.uncertain_launch_mode = "typed-known-drift"
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation",
                      caught.exception.terminal["remaining"])
        self.assertFalse(self.task.destroyed)
        self.assertEqual(self.runtime.commands, [])

    def test_artifact_fault_after_typed_transfer_still_cleans_exact_task(self):
        self.task.uncertain_launch_mode = "typed-known"
        self.artifact.fail_logical_name = "launch/exact-fixture-task.txt"
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertEqual(self.subject.remaining, set())
        self.assertIn("injected artifact publication failure",
                      caught.exception.manifest["primaryFailure"]["message"])

    def test_pre_attach_capture_failure_destroys_only_known_task_then_healthy_abort(self):
        self.platform.fail_label = "postlaunch-preack"
        original_send = self.runtime.send
        def after_exact_destroy(command, deadline):
            self.assertTrue(self.task.destroyed)
            self.assertFalse(any(item.task_id == FOREIGN_TASK for item in self.runtime.snapshot.activities))
            return original_send(command, deadline)
        self.runtime.send = after_exact_destroy
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        self.assertFalse(self.subject._host_attached)
        self.assertFalse(self.subject._host_attach_attempted)
        self.assertIsNone(self.host.failure)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertEqual(self.subject.remaining, set())
        manifest = caught.exception.manifest
        self.assertEqual(manifest["status"], "FAILED_CLEAN")
        self.assertEqual(self.log.verify(), manifest)
        self.assertTrue(all(row["status"] == "SUCCESS" for row in manifest["cleanup"]))
        close = next(row for row in manifest["cleanup"] if row["step"] == "host_begin_close")
        self.assertEqual(close["evidenceSha256"], harness._digest({
            "notApplicable": True, "reason": "host attach was never attempted"}))
        self.assertEqual([command.action for command in self.runtime.commands],
                         ["ACK_NO_FOREIGN_PRE_ATTACH_ABORT"])

    def test_prelaunch_capture_failure_uses_healthy_abort_without_launch_or_host_failure(self):
        self.platform.fail_label = "prelaunch"
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertEqual(caught.exception.manifest["status"], "FAILED_CLEAN")
        self.assertIsNone(self.task.foreign)
        self.assertFalse(self.task.destroyed)
        self.assertIsNone(self.host.failure)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertEqual(self.subject.remaining, set())
        self.assertEqual([command.action for command in self.runtime.commands],
                         ["ACK_NO_FOREIGN_PRE_ATTACH_ABORT"])
        self.assertEqual(self.log.verify(), caught.exception.manifest)

    def test_prelaunch_authenticated_host_failure_keeps_legacy_empty_route(self):
        original = self.platform.capture
        def fail_host(label, foreign, display_id, deadline):
            if label == "prelaunch":
                self.runtime.emit("TIMEOUT", {"phase": "foreign_attach"})
                self.host.observe_failure(deadline)
                raise harness.EvidenceRejected("authenticated pre-attach host failure")
            return original(label, foreign, display_id, deadline)
        self.platform.capture = fail_host
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertEqual(caught.exception.manifest["status"], "FAILED_CLEAN")
        self.assertEqual(self.host.phase, "QUIESCENT")
        self.assertEqual(self.host.failure, "TIMEOUT")
        self.assertEqual([command.action for command in self.runtime.commands],
                         ["ACK_NO_FOREIGN_AFTER_FAILURE"])
        self.assertEqual(self.log.verify(), caught.exception.manifest)

    def test_pre_attach_destroy_receipt_loss_still_attempts_healthy_empty_release(self):
        self.platform.fail_label = "postlaunch-preack"
        self.task.fail_destroy_after_remove = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertTrue(self.task.destroyed)
        self.assertIsNone(self.host.failure)
        self.assertTrue(any(row["step"] == "destroy_exact_foreign_task"
                            for row in caught.exception.terminal["cleanupFailures"]))
        self.assertEqual([command.action for command in self.runtime.commands],
                         ["ACK_NO_FOREIGN_PRE_ATTACH_ABORT"])

    def test_unknown_launcher_outcome_quarantines_even_when_display_is_observed_empty(self):
        def unknown(*_args):
            raise harness.EvidenceRejected("launch side effect unknown")
        self.task.launch_fixture = unknown
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task_creation", caught.exception.terminal["remaining"])
        self.assertIn("virtual_display", caught.exception.terminal["remaining"])
        self.assertEqual(self.runtime.commands, [])
        self.assertFalse(self.task.destroyed)

    def test_known_pre_attach_task_remaining_blocks_healthy_abort(self):
        self.platform.fail_label = "postlaunch-preack"
        def leave_task(*_args):
            self.runtime.snapshot = replace(self.runtime.snapshot,
                activities=tuple(replace(item, display_id=0) if item.task_id == FOREIGN_TASK else item
                                 for item in self.runtime.snapshot.activities),
                windows=tuple(replace(item, display_id=0) if item.task_id == FOREIGN_TASK else item
                              for item in self.runtime.snapshot.windows))
            raise harness.EvidenceRejected("task migrated instead of being destroyed")
        self.task.destroy_exact_task = leave_task
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("foreign_task", caught.exception.terminal["remaining"])
        self.assertIn("virtual_display", caught.exception.terminal["remaining"])
        self.assertEqual(self.runtime.commands, [])

    def test_pre_attach_abort_release_failure_quarantines_and_keeps_other_checks_running(self):
        self.platform.fail_label = "postlaunch-preack"
        self.runtime.fail_release = True
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        self.assertIn("virtual_display", caught.exception.terminal["remaining"])
        self.assertIsNotNone(self.subject._file_after)
        self.assertEqual([command.action for command in self.runtime.commands],
                         ["ACK_NO_FOREIGN_PRE_ATTACH_ABORT"])

    def test_uncertain_attempted_attach_is_not_reported_as_not_applicable(self):
        original_send = self.runtime.send
        def uncertain_attach(command, deadline):
            if command.action == "ACK_FOREIGN_ATTACHED":
                self.runtime.commands.append(command)
                raise host.HostAuthorityError("uncertain attach send")
            return original_send(command, deadline)
        self.runtime.send = uncertain_attach
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(self.subject._host_attach_attempted)
        self.assertFalse(self.subject._host_attached)
        self.assertTrue(self.task.destroyed)
        close = next(row for row in caught.exception.terminal["cleanupFailures"]
                     if row["step"] == "host_begin_close")
        self.assertEqual(close["status"], "FAILED")
        self.assertIn("acknowledgement is uncertain or failed", close["message"])
        self.assertIn("virtual_display", caught.exception.terminal["remaining"])
        self.assertEqual([command.action for command in self.runtime.commands],
                         ["ACK_FOREIGN_ATTACHED"])

    def test_journal_fault_cannot_prevent_exact_cleanup_or_publish_success(self):
        original = self.log.append

        def fail_after_attach(event, data, remaining):
            if (event == "operation_result" and
                    data.get("operation") == "host_attach_exact_foreign"):
                self.log.usable = False
                raise OSError("injected journal publication failure")
            return original(event, data, remaining)

        self.log.append = fail_after_attach
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertTrue(self.task.destroyed)
        self.assertEqual(self.host.state, "QUIESCENT")
        self.assertIn("session_log", caught.exception.terminal["remaining"])
        self.assertIsNotNone(caught.exception.terminal["journalFailure"])

    def test_visual_dimension_mismatch_is_rejected(self):
        self.visual.wrong_dimensions_at = 1
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("visual capture task/display/placement",
                      caught.exception.manifest["primaryFailure"]["message"])

    def test_replayed_platform_timestamp_is_outside_trusted_host_bracket(self):
        self.platform.advance_after_label = "prelaunch"
        self.platform.replay_timestamp_label = "postlaunch-preack"
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("trusted host bracket",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)
        self.assertFalse(self.subject._host_attached)

    def test_future_platform_timestamp_is_outside_trusted_host_bracket(self):
        self.platform.future_timestamp_label = "prelaunch"
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("trusted host bracket",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertFalse(self.task.destroyed)

    def test_replayed_visual_png_and_timestamp_are_rejected(self):
        self.visual.advance_after_at = 1
        self.visual.replay_at = 2
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("trusted host bracket",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)

    def test_future_visual_timestamp_is_rejected(self):
        self.visual.future_timestamp_at = 1
        with self.assertRaises(harness.SessionFailed) as caught:
            self.subject.run()
        self.assertIn("trusted host bracket",
                      caught.exception.manifest["primaryFailure"]["message"])
        self.assertTrue(self.task.destroyed)

    def test_split_artifact_store_identity_reaches_quarantine_terminal(self):
        self.artifact.split_store_at = 2
        with self.assertRaises(harness.SessionQuarantined) as caught:
            self.subject.run()
        self.assertIn("artifact_store", caught.exception.terminal["remaining"])
        self.assertTrue(any(
            row["step"] == "artifact_authority_quiescent" and
            row["status"] == "FAILED"
            for row in caught.exception.terminal["cleanupFailures"]))

    def test_log_record_rejects_nonzero_semantic_operation_counter(self):
        def reference(name: str, digest: str) -> dict:
            return harness.ArtifactRef(
                "semantic/" + name, "application/json", 1, digest,
                "2" * 64, "3" * 64, True).wire()

        record = {
            "sequence": 1,
            "event": "semantic_sample",
            "data": {
                "phaseIndex": 0, "phase": "LANDSCAPE_FULL_INITIAL",
                "ordinal": 1, "sampleId": "sample:1",
                "observerSessionId": "observer:1", "runNonce": "4" * 64,
                "manifestSha256": "5" * 64, "resultSha256": "6" * 64,
                "projectionSha256": "7" * 64,
                "adapterReceiptSha256": "8" * 64,
                "artifact": {
                    "manifest": reference("manifest", "5" * 64),
                    "external": reference("external", "9" * 64),
                    "result": reference("result", "6" * 64),
                    "transcript": reference("transcript", "a" * 64),
                },
                "inputEventsGenerated": 0, "writerCalls": 0,
                "penOperations": 1,
            },
            "remaining": [],
        }
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "input/writer/pen"):
            harness.AppendOnlySessionLog._validate_record(record)

    def test_log_transition_rejects_phase_evidence_after_completion(self):
        records = [
            {"event": "semantic_sample",
             "data": {"phaseIndex": 0, "ordinal": 1}},
            {"event": "visual_capture", "data": {"phaseIndex": 0}},
            {"event": "semantic_sample",
             "data": {"phaseIndex": 0, "ordinal": 2}},
            {"event": "phase_complete", "data": {"phaseIndex": 0}},
        ]
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "next open phase"):
            harness.AppendOnlySessionLog._validate_transition(
                records, "semantic_sample", {"phaseIndex": 0, "ordinal": 1})

    def test_log_transition_rejects_cleanup_step_reordering(self):
        records = [{"event": "cleanup_started", "data": {}}]
        with self.assertRaisesRegex(harness.EvidenceRejected,
                                    "cleanup step sequence"):
            harness.AppendOnlySessionLog._validate_transition(
                records, "cleanup_step",
                {"stepIndex": 0, "step": "final_platform_inventory"})

    def test_cli_is_status_only_and_hardware_blocked(self):
        status = harness.admission_status()
        self.assertFalse(status["admitted"])
        self.assertIn("REVIEWED_NO_PEN_SEMANTIC_SAMPLE_ADAPTER_REQUIRED",
                      status["blockers"])
        self.assertEqual(harness.main(["--status"]), 2)
        with self.assertRaises(harness.HarnessAdmissionBlocked):
            harness.main([])


if __name__ == "__main__":
    unittest.main()
