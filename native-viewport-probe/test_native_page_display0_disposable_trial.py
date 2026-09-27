"""Mocked only: the disposable trial never contacts ADB or Frida in tests."""
from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import io
import json
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_page_display0_disposable_trial as trial
import native_page_display0_one_shot as one
import native_page_graph_v2_runner as graph
from test_native_page_android_authority import PID
from test_native_page_display0_stock_dialect import activities, windows


BOOT = b"12345678-1234-1234-1234-123456789abc\n"
SERVER_PID = 9901
PDF_STAT = b"1:998:2419:12345:81a4\n"


def stat(pid: int, ticks: str = "4134") -> bytes:
    fields = ["1"] * 20
    fields[0] = "S"
    fields[19] = ticks
    return (str(pid) + " (Document) " + " ".join(fields) + "\n").encode("ascii")


class FakeBackend(trial.Backend):
    def __init__(self):
        self.calls = []
        self.server_live = False
        self.forwarded = False
        self.change_pdf = False
        self.mark_present = False
        self.fail_child = False
        self.fail_kill = False
        self.start_pid_unknown = False
        self.conflicting_forward = False
        self.blank_forward_list = False
        self.extra_forward_after_child = False
        self.replace_process = False
        self.extra_frame = False
        self.process_cmdline = b"com.supernote.document\x00"
        self.ready_after_checks = 0
        self.ready_poll_count = 0

    def adb(self, *args: str, timeout: float = 12.0) -> bytes:
        self.calls.append(("adb", args))
        if args == ("get-state",):
            return b"device\n"
        if args == ("shell", "getprop", "ro.build.fingerprint"):
            return trial.FINGERPRINT.encode("ascii") + b"\n"
        if args == ("shell", "pidof", "com.supernote.document"):
            return str(PID).encode("ascii") + b"\n"
        if args == ("shell", "cat", "/proc/sys/kernel/random/boot_id"):
            return BOOT
        if args == ("shell", "dumpsys", "activity", "activities"):
            return activities()
        if args == ("shell", "dumpsys", "window", "windows"):
            return windows()
        if args == ("shell", "stat", "-c", "%d:%i:%s:%Y:%f", trial.PDF):
            return PDF_STAT
        if args == ("shell", "sha256sum", trial.PDF):
            digest = "0" * 64 if self.change_pdf else trial.PDF_SHA256
            return (digest + "  " + trial.PDF + "\n").encode("ascii")
        if args == ("forward", "--list"):
            if self.conflicting_forward:
                return ("DIFFERENT " + trial.PORT + " " + trial.PORT + "\n").encode()
            if self.forwarded:
                owned = trial.SERIAL + " " + trial.PORT + " " + trial.PORT + "\n"
                extra = "OTHER tcp:27111 " + trial.PORT + "\n" if self.extra_forward_after_child else ""
                return (owned + extra).encode()
            return b"\r\n" if self.blank_forward_list else b""
        if args == ("forward", "--no-rebind", trial.PORT, trial.PORT):
            if self.forwarded:
                raise trial.TrialError("FRIDA_FORWARD_PRESENT")
            self.forwarded = True
            return b""
        if args == ("forward", "--remove", trial.PORT):
            self.forwarded = False
            return b""
        raise AssertionError("unexpected mocked adb operation: " + repr(args))

    def root(self, command: str, timeout: float = 12.0) -> bytes:
        self.calls.append(("root", command))
        if command == "ps -A -o PID,ARGS":
            return (trial.SERVER.encode() + b"\n") if self.server_live else b"PID ARGS\n"
        if command == "ss -ltn":
            if self.server_live:
                self.ready_poll_count += 1
                if self.ready_poll_count > self.ready_after_checks:
                    return b"LISTEN 127.0.0.1:27042\n"
            return b"State Local\n"
        if command == "cat /proc/" + str(PID) + "/cmdline":
            return self.process_cmdline
        if command == "cat /proc/" + str(PID) + "/stat":
            return stat(PID, "4135" if self.replace_process else "4134")
        if command == "sha256sum " + trial.SERVER:
            return (trial.SERVER_SHA256 + "  " + trial.SERVER + "\n").encode()
        if command.startswith(trial.SERVER + " --listen"):
            self.server_live = True
            return b"garbled\n" if self.start_pid_unknown else str(SERVER_PID).encode() + b"\n"
        if command == "cat /proc/" + str(SERVER_PID) + "/cmdline":
            if not self.server_live:
                raise trial.TrialError("ADB_COMMAND_FAILED")
            return (trial.SERVER + "\x00--listen\x00127.0.0.1:27042\x00").encode()
        if command == "cat /proc/" + str(SERVER_PID) + "/stat":
            if not self.server_live:
                raise trial.TrialError("ADB_COMMAND_FAILED")
            return stat(SERVER_PID)
        if command.startswith("if [ -e " + trial.PDF + ".mark ]"):
            return b"PRESENT\n" if self.mark_present else b"ABSENT\n"
        if command == "kill -TERM " + str(SERVER_PID) or command == "kill -KILL " + str(SERVER_PID):
            if not self.fail_kill:
                self.server_live = False
            return b""
        if command == "if [ -e /proc/" + str(SERVER_PID) + " ]; then echo PRESENT; else echo ABSENT; fi":
            return b"PRESENT\n" if self.server_live else b"ABSENT\n"
        raise AssertionError("unexpected mocked root operation: " + command)

    def child(self, pid: int, manifest: bytes, timeout: float) -> tuple[bytes, bytes]:
        self.calls.append(("child", pid, timeout))
        if self.fail_child:
            raise trial.TrialError("FRIDA_CHILD_TIMEOUT")
        digest = hashlib.sha256(manifest).hexdigest()
        identity = graph.canonical_bytes({
            "event": "native_page_display0_identity", "schemaVersion": 1,
            "authority": one.RECORD_AUTHORITY, "manifestSha256": digest,
            "observationOnly": True, "hardwareAdmission": False,
            "hostAssertionsOnly": True, "runtimePidMatched": True,
            "heapWalks": 1, "retainedRootSamples": 2,
            "lifecycle": {"resumed": True, "finished": False, "destroyed": False},
            "uriAgreementAndExpectedMatch": True, "markPathPresent": False,
            "markPathMatchedExpected": None,
        })
        complete = graph.canonical_bytes({
            "event": "native_page_display0_identity_complete", "success": True,
        })
        return (identity, identity) if self.extra_frame else (identity, complete)


class TrialTests(unittest.TestCase):
    def setUp(self):
        # The device runner is mocked throughout this suite. Bundle-specific
        # provenance, compilation, and tamper cases have their own host suite.
        build = patch.object(trial.bundle, "build_verified_bundle",
                             return_value=b"compiled observer")
        load = patch.object(trial.bundle, "load_verified_bundle",
                            return_value=b"compiled observer")
        build.start()
        load.start()
        self.addCleanup(build.stop)
        self.addCleanup(load.stop)

    def test_parent_accepts_only_fixed_child_failure_tokens(self):
        valid = subprocess.CompletedProcess([], 2, b"", b"FRIDA_CHILD_ATTACH_FAILED\n")
        with patch.object(trial.subprocess, "run", return_value=valid):
            with self.assertRaisesRegex(trial.TrialError, "^FRIDA_CHILD_ATTACH_FAILED$"):
                trial.Backend().child(PID, b"{}", 8.0)
        windows = subprocess.CompletedProcess([], 2, b"", b"FRIDA_CHILD_ATTACH_FAILED\r\n")
        with patch.object(trial.subprocess, "run", return_value=windows):
            with self.assertRaisesRegex(trial.TrialError, "^FRIDA_CHILD_ATTACH_FAILED$"):
                trial.Backend().child(PID, b"{}", 8.0)
        observer_code = "FRIDA_CHILD_OBSERVER_REJECTED_URI_WRAPPER"
        self.assertIn(observer_code, trial.CHILD_FAILURE_CODES)
        self.assertIn("FRIDA_CHILD_OBSERVER_REJECTED_URI_SUBTYPE",
                      trial.CHILD_FAILURE_CODES)
        observer = subprocess.CompletedProcess([], 2, b"",
                                               observer_code.encode() + b"\r\n")
        with patch.object(trial.subprocess, "run", return_value=observer):
            with self.assertRaisesRegex(trial.TrialError, "^" + observer_code + "$"):
                trial.Backend().child(PID, b"{}", 8.0)
        for stderr in (b"private /storage/emulated/0/path\n",
                       b"FRIDA_CHILD_ATTACH_FAILED\nprivate path\n",
                       b"FRIDA_CHILD_ATTACH_FAILED", b"FRIDA_CHILD_UNKNOWN\n",
                       b"FRIDA_CHILD_OBSERVER_REJECTED_URI_PRIVATE_PATH\n"):
            with self.subTest(stderr=stderr):
                result = subprocess.CompletedProcess([], 2, b"", stderr)
                with patch.object(trial.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(trial.TrialError,
                                                "^FRIDA_CHILD_FAILED$"):
                        trial.Backend().child(PID, b"{}", 8.0)
        result = subprocess.CompletedProcess([], 2, b"private stdout", b"FRIDA_CHILD_ATTACH_FAILED\n")
        with patch.object(trial.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(trial.TrialError, "^FRIDA_CHILD_FAILED$"):
                trial.Backend().child(PID, b"{}", 8.0)

    def test_child_main_never_exposes_unexpected_private_exception(self):
        output = io.StringIO()
        with patch.object(trial, "_child", side_effect=RuntimeError("private PDF path")):
            with redirect_stderr(output):
                self.assertEqual(trial.main(["__child", str(PID), "e30="]), 2)
        self.assertEqual(output.getvalue(), "FRIDA_CHILD_FAILED\n")

    def test_mocked_frida_stage_codes_and_cleanup(self):
        manifest = trial._source_and_manifest(trial.preflight(FakeBackend()))[1]

        def execute(stage: str):
            observed = []
            scripts = []

            class FakeScript:
                callback = None

                def on(self, name, callback):
                    self.callback = callback

                def load(self):
                    if stage == "LOAD":
                        raise RuntimeError("private load path")
                    if stage in {"OBSERVER", "FRAME", "UNLOAD", "DETACH",
                                 "LATE_UNLOAD", "LATE_DETACH", "LATE_EXTRA",
                                 "OBSERVER_UNLOAD", "OBSERVER_DETACH",
                                 "OBSERVER_LATE_UNLOAD", "OBSERVER_LATE_DETACH",
                                 "OBSERVER_LATE_EXTRA"}:
                        if stage.startswith("OBSERVER"):
                            frames = (
                                graph.canonical_bytes({
                                    "event": "native_page_display0_identity_error",
                                    "schemaVersion": 1,
                                    "code": "DISPLAY0_IDENTITY_REJECTED",
                                    "phase": "URI", "reason": "WRAPPER"}),
                                graph.canonical_bytes({
                                    "event": "native_page_display0_identity_complete",
                                    "success": False}),
                            )
                        elif stage == "FRAME":
                            frames = (b"{}", b"{}")
                        else:
                            frames = FakeBackend().child(PID, manifest, 8.0)
                        for frame in frames:
                            self.callback({"type": "send",
                                           "payload": json.loads(frame)}, None)

                def unload(self):
                    observed.append("unload")
                    if stage in {"UNLOAD", "OBSERVER_UNLOAD"}:
                        raise RuntimeError("private unload path")
                    if stage in {"LATE_UNLOAD", "LATE_EXTRA",
                                 "OBSERVER_LATE_UNLOAD", "OBSERVER_LATE_EXTRA"}:
                        event = ({"type": "error"} if stage.endswith("LATE_UNLOAD") else
                                 {"type": "send", "payload": {"unexpected": True}})
                        self.callback(event, None)

            class FakeSession:
                def create_script(self, source):
                    if stage == "SCRIPT":
                        raise RuntimeError("private script path")
                    script = FakeScript()
                    scripts.append(script)
                    return script

                def detach(self):
                    observed.append("detach")
                    if stage in {"DETACH", "OBSERVER_DETACH"}:
                        raise RuntimeError("private detach path")
                    if stage in {"LATE_DETACH", "OBSERVER_LATE_DETACH"}:
                        scripts[0].callback({"type": "error"}, None)

            class FakeDevice:
                def attach(self, pid):
                    if stage == "ATTACH":
                        raise RuntimeError("private attach path")
                    return FakeSession()

            class FakeManager:
                def add_remote_device(self, address):
                    if stage == "CONNECT":
                        raise RuntimeError("private connect path")
                    return FakeDevice()

            fake_frida = SimpleNamespace(get_device_manager=lambda: FakeManager())
            with patch.dict(sys.modules, {"frida": fake_frida}):
                with patch.object(trial.importlib.metadata, "version", return_value="17.9.11"):
                    if stage == "WAIT":
                        with patch.object(trial.threading.Event, "wait", return_value=False):
                            trial._child(PID, manifest)
                    else:
                        trial._child(PID, manifest)
            return observed

        expected = {
            "CONNECT": "FRIDA_CHILD_CONNECT_FAILED",
            "ATTACH": "FRIDA_CHILD_ATTACH_FAILED",
            "SCRIPT": "FRIDA_CHILD_SCRIPT_FAILED",
            "LOAD": "FRIDA_CHILD_LOAD_FAILED",
            "WAIT": "FRIDA_CHILD_WAIT_TIMEOUT",
            "OBSERVER": "FRIDA_CHILD_OBSERVER_REJECTED_URI_WRAPPER",
            "OBSERVER_UNLOAD": "FRIDA_CHILD_UNLOAD_FAILED",
            "OBSERVER_DETACH": "FRIDA_CHILD_DETACH_FAILED",
            "OBSERVER_LATE_UNLOAD": "FRIDA_CHILD_FRAME_REJECTED",
            "OBSERVER_LATE_DETACH": "FRIDA_CHILD_FRAME_REJECTED",
            "OBSERVER_LATE_EXTRA": "FRIDA_CHILD_FRAME_REJECTED",
            "FRAME": "FRIDA_CHILD_FRAME_REJECTED",
            "UNLOAD": "FRIDA_CHILD_UNLOAD_FAILED",
            "DETACH": "FRIDA_CHILD_DETACH_FAILED",
            "LATE_UNLOAD": "FRIDA_CHILD_FRAME_REJECTED",
            "LATE_DETACH": "FRIDA_CHILD_FRAME_REJECTED",
            "LATE_EXTRA": "FRIDA_CHILD_FRAME_REJECTED",
        }
        for stage, code in expected.items():
            with self.subTest(stage=stage), self.assertRaisesRegex(trial.TrialError,
                                                                    "^" + code + "$"):
                execute(stage)

    def test_root_command_preserves_server_pid_expansion_for_root_shell(self):
        calls = []

        def fake_adb(self, *args, timeout=12.0):
            calls.append(args)
            return b""

        with patch.object(trial.Backend, "adb", fake_adb):
            trial.Backend().root("echo $!")
        self.assertEqual(calls, [("shell", "su -c 'echo $!'")])

    def test_start_ticks_parses_field_22_not_a_neighbor(self):
        self.assertEqual(trial._start_ticks(stat(PID), PID), "4134")
        self.assertEqual(trial._start_ticks(stat(PID, "5151"), PID), "5151")
        with self.assertRaises(trial.TrialError):
            trial._start_ticks(stat(PID), PID + 1)

    def test_preflight_is_read_only_and_does_not_start_server(self):
        backend = FakeBackend()
        result = trial.preflight(backend)
        self.assertEqual(result.pid, PID)
        self.assertEqual(result.start_ticks, "4134")
        self.assertFalse(backend.server_live)
        self.assertFalse(backend.forwarded)
        self.assertFalse(any(call[0] == "child" for call in backend.calls))
        self.assertFalse(any("--listen" in call[1] for call in backend.calls
                             if call[0] == "root"))

    def test_invalid_bundle_never_starts_server_or_attaches(self):
        backend = FakeBackend()
        with patch.object(trial.bundle, "build_verified_bundle",
                          side_effect=trial.bundle.BundleError("BUNDLE_HASH_MISMATCH")):
            with self.assertRaisesRegex(trial.TrialError, "^BUNDLE_INVALID$"):
                trial.run_trial(backend, announce=lambda _: None)
        self.assertFalse(backend.server_live)
        self.assertFalse(backend.forwarded)
        self.assertFalse(any(call[0] == "child" for call in backend.calls))
        self.assertFalse(any("--listen" in call[1] for call in backend.calls
                             if call[0] == "root"))

    def test_child_rejects_bundle_tamper_before_frida_connect(self):
        manifest = trial._source_and_manifest(trial.preflight(FakeBackend()))[1]
        with patch.object(trial.bundle, "load_verified_bundle",
                          side_effect=trial.bundle.BundleError("BUNDLE_HASH_MISMATCH")):
            with self.assertRaisesRegex(trial.TrialError,
                                        "^FRIDA_CHILD_BUNDLE_INVALID$"):
                trial._child(PID, manifest)

    def test_android_process_cmdline_nul_padding_is_accepted_but_not_arguments(self):
        backend = FakeBackend()
        backend.process_cmdline += b"\x00" * 32
        self.assertEqual(trial.preflight(backend).pid, PID)
        backend.process_cmdline = b"com.supernote.document\x00foreign\x00"
        with self.assertRaisesRegex(trial.TrialError, "DOCUMENT_PROCESS_CHANGED"):
            trial.preflight(backend)

    def test_blank_crlf_forward_list_means_no_forward(self):
        backend = FakeBackend()
        backend.blank_forward_list = True
        self.assertEqual(trial.preflight(backend).pid, PID)
        self.assertFalse(backend.server_live)

    def test_one_attempt_and_exact_cleanup(self):
        backend = FakeBackend()
        result = trial.run_trial(backend, announce=lambda _: None)
        self.assertEqual(result["trial"], "alpha-disposable-only")
        self.assertEqual(result["bundleSha256"], trial.bundle.BUNDLE_SHA256)
        self.assertFalse(result["hardwareAdmission"])
        self.assertFalse(result["mutationAuthorized"])
        self.assertFalse(backend.server_live)
        self.assertFalse(backend.forwarded)
        self.assertEqual(len([c for c in backend.calls if c[0] == "child"]), 1)
        self.assertEqual(len([c for c in backend.calls if c ==
                              ("root", "kill -TERM " + str(SERVER_PID))]), 1)

    def test_server_ready_poll_is_bounded_and_does_not_retry_child(self):
        backend = FakeBackend()
        backend.ready_after_checks = 2
        with patch.object(trial.time, "sleep", return_value=None):
            trial.run_trial(backend, announce=lambda _: None)
        self.assertEqual(backend.ready_poll_count, 3)
        self.assertEqual(len([c for c in backend.calls if c[0] == "child"]), 1)
        self.assertFalse(backend.server_live)

        backend = FakeBackend()
        backend.ready_after_checks = 30
        with patch.object(trial.time, "sleep", return_value=None):
            with self.assertRaisesRegex(trial.TrialError,
                                        "^FRIDA_SERVER_READY_TIMEOUT$"):
                trial.run_trial(backend, announce=lambda _: None)
        self.assertEqual(backend.ready_poll_count, 30)
        self.assertEqual(len([c for c in backend.calls if c[0] == "child"]), 0)
        self.assertFalse(backend.server_live)
        self.assertFalse(backend.forwarded)

    def test_child_timeout_still_cleans_up_without_retry(self):
        backend = FakeBackend()
        backend.fail_child = True
        with self.assertRaisesRegex(trial.TrialError, "FRIDA_CHILD_TIMEOUT"):
            trial.run_trial(backend, announce=lambda _: None)
        self.assertFalse(backend.server_live)
        self.assertFalse(backend.forwarded)
        child_index = next(i for i, call in enumerate(backend.calls) if call[0] == "child")
        self.assertEqual(len([c for c in backend.calls if c[0] == "child"]), 1)
        self.assertTrue(any(call == ("adb", ("shell", "sha256sum", trial.PDF))
                            for call in backend.calls[child_index + 1:]))

    def test_observer_rejection_still_cleans_up(self):
        backend = FakeBackend()
        backend.extra_frame = True
        with self.assertRaisesRegex(trial.TrialError, "IDENTITY_OBSERVER_REJECTED"):
            trial.run_trial(backend, announce=lambda _: None)
        self.assertFalse(backend.server_live)
        self.assertFalse(backend.forwarded)

    def test_cleanup_removes_owned_forward_if_unrelated_remote_mapping_appears(self):
        class ExtraForwardAfterChild(FakeBackend):
            def child(self, pid, manifest, timeout):
                frames = super().child(pid, manifest, timeout)
                self.extra_forward_after_child = True
                return frames

        backend = ExtraForwardAfterChild()
        result = trial.run_trial(backend, announce=lambda _: None)
        self.assertTrue(result["forwardRemoved"])
        self.assertFalse(backend.forwarded)

    def test_mark_creation_before_attach_is_rejected(self):
        backend = FakeBackend()
        backend.mark_present = True
        with self.assertRaisesRegex(trial.TrialError, "DISPOSABLE_MARK_PRESENT"):
            trial.preflight(backend)
        self.assertFalse(backend.server_live)

    def test_forward_conflict_never_starts_server(self):
        backend = FakeBackend()
        backend.conflicting_forward = True
        with self.assertRaisesRegex(trial.TrialError, "FRIDA_FORWARD_PRESENT"):
            trial.preflight(backend)
        self.assertFalse(backend.server_live)

    def test_unknown_server_pid_is_cleanup_uncertainty(self):
        backend = FakeBackend()
        backend.start_pid_unknown = True
        diagnostics = []
        with self.assertRaisesRegex(trial.TrialError, "CLEANUP_UNCERTAIN"):
            trial.run_trial(backend, announce=diagnostics.append)
        self.assertTrue(backend.server_live)
        self.assertIn("FRIDA_SERVER_CLEANUP_UNCERTAIN", diagnostics[0])
        self.assertFalse(backend.forwarded)

    def test_exact_server_that_wont_stop_is_cleanup_uncertainty(self):
        backend = FakeBackend()
        backend.fail_kill = True
        with patch.object(trial.time, "sleep", return_value=None):
            with self.assertRaisesRegex(trial.TrialError, "CLEANUP_UNCERTAIN"):
                trial.run_trial(backend, announce=lambda _: None)
        self.assertTrue(backend.server_live)
        self.assertFalse(backend.forwarded)

    def test_pdf_or_process_changed_after_child_is_rejected(self):
        for field in ("change_pdf", "replace_process", "mark_present"):
            class MutatingFake(FakeBackend):
                def child(self, pid, manifest, timeout):
                    result = super().child(pid, manifest, timeout)
                    setattr(self, field, True)
                    return result

            backend = MutatingFake()
            with self.subTest(field=field), self.assertRaises(trial.TrialError):
                trial.run_trial(backend, announce=lambda _: None)
            self.assertFalse(backend.server_live)
            self.assertFalse(backend.forwarded)

    def test_cli_suppresses_unexpected_private_exception(self):
        output = io.StringIO()
        with patch.object(trial, "preflight", side_effect=OSError("private PDF path")):
            with redirect_stderr(output):
                self.assertEqual(trial.main(["--preflight-only"]), 2)
        self.assertEqual(output.getvalue().strip(),
                         "trial=REJECTED code=TRIAL_RUNTIME_FAILED")

    def test_bad_callback_before_two_good_frames_is_latched(self):
        collector = trial._FrameCollector()
        good = {"type": "send", "payload": {"value": 1}}
        collector.on_message({"type": "error"}, None)
        collector.on_message(good, None)
        collector.on_message(good, None)
        self.assertTrue(collector.complete.is_set())
        self.assertTrue(collector.failed)
        with self.assertRaisesRegex(trial.TrialError, "FRIDA_CHILD_INCOMPLETE"):
            collector.checked_frames()

    def test_bad_callback_after_first_or_second_frame_is_latched(self):
        good = {"type": "send", "payload": {"value": 1}}
        for good_count in (1, 2):
            with self.subTest(good_count=good_count):
                collector = trial._FrameCollector()
                for _ in range(good_count):
                    collector.on_message(good, None)
                collector.on_message({"type": "send", "payload": good}, b"unexpected")
                self.assertTrue(collector.failed)
                with self.assertRaisesRegex(trial.TrialError, "FRIDA_CHILD_INCOMPLETE"):
                    collector.checked_frames()

    def test_extra_third_callback_is_rejected(self):
        collector = trial._FrameCollector()
        good = {"type": "send", "payload": {"value": 1}}
        for _ in range(3):
            collector.on_message(good, None)
        self.assertTrue(collector.failed)
        with self.assertRaisesRegex(trial.TrialError, "FRIDA_CHILD_INCOMPLETE"):
            collector.checked_frames()


if __name__ == "__main__":
    unittest.main()
