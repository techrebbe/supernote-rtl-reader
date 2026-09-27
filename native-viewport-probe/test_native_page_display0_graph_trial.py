"""Fake-device failure-order tests; this module never invokes ADB or Frida."""
from __future__ import annotations

from contextlib import ExitStack
import subprocess
from unittest import TestCase, main
from unittest.mock import patch

import native_page_display0_disposable_trial as identity
import native_page_display0_graph_trial as trial
import test_native_page_display0_graph_contract as fixture


SNAPSHOT = identity.Snapshot(1234, "5678", "12345678-1234-1234-1234-123456789abc",
                             b"activity", b"window", b"1:2:3:4:5")


class FakeBackend:
    def __init__(self, *, error: Exception | None = None):
        self.forward = False
        self.calls: list[str] = []
        self.error = error

    def adb(self, *args: str, **_kwargs) -> bytes:
        self.calls.append("adb:" + "/".join(args))
        if args == ("forward", "--no-rebind", identity.PORT, identity.PORT):
            if self.forward:
                raise AssertionError("duplicate forward")
            self.forward = True
        elif args == ("forward", "--remove", identity.PORT):
            if not self.forward:
                raise AssertionError("missing forward")
            self.forward = False
        else:
            raise AssertionError("unexpected fake ADB command")
        return b""

    def child_graph(self, _pid: int, _manifest: bytes) -> tuple[bytes, bytes]:
        self.calls.append("child")
        if self.error is not None:
            raise self.error
        return fixture.frames(fixture.success())


class GraphTrialTests(TestCase):
    def _patches(self, stack: ExitStack, backend: FakeBackend,
                 *, after_error: bool = False):
        stack.enter_context(patch.object(trial, "preflight", return_value=SNAPSHOT))
        stack.enter_context(patch.object(trial, "_pinned_images", return_value=None))
        stack.enter_context(patch.object(identity, "_launch_server",
                                         side_effect=lambda _b: backend.calls.append(
                                             "server_start") or 2468))
        stack.enter_context(patch.object(identity, "_server_identity",
                                         return_value="8901"))
        stack.enter_context(patch.object(identity, "_await_server_ready",
                                         return_value=None))
        stack.enter_context(patch.object(identity, "_owned_forward",
                                         side_effect=lambda _b: self.assertTrue(
                                             backend.forward)))
        stack.enter_context(patch.object(identity, "_forward_entries",
                                         side_effect=lambda _b: [[identity.SERIAL,
                                             identity.PORT, identity.PORT]]
                                             if backend.forward else []))
        stop = stack.enter_context(patch.object(
            identity, "_stop_exact_server",
            side_effect=lambda *_args: backend.calls.append("server_stop")))
        stack.enter_context(patch.object(identity, "_server_absent",
                                         return_value=None))
        stack.enter_context(patch.object(identity, "_forward_absent",
                                         return_value=None))
        capture = stack.enter_context(patch.object(identity, "capture",
                                                   return_value=SNAPSHOT))
        if after_error:
            stack.enter_context(patch.object(identity, "_stable",
                                             side_effect=identity.TrialError(
                                                 "POST_CHANGED")))
        else:
            stack.enter_context(patch.object(identity, "_stable", return_value=None))
        return stop, capture

    def test_success_cleans_owned_helpers_and_never_admits_mutation(self):
        backend = FakeBackend()
        with ExitStack() as stack:
            stop, capture = self._patches(stack, backend)
            # The host parser requires the actual per-run manifest digest.
            original_child = backend.child_graph

            def bound_child(pid: int, manifest: bytes):
                backend.calls.append("child")
                value = fixture.success()
                value["manifestSha256"] = trial._sha(manifest)
                return fixture.frames(value)

            backend.child_graph = bound_child  # type: ignore[assignment]
            result = trial.run_trial(backend)  # type: ignore[arg-type]
        self.assertEqual(result["trial"], "alpha-disposable-graph-only")
        self.assertIs(result["hardwareAdmission"], False)
        self.assertIs(result["mutationAuthorized"], False)
        self.assertIs(result["pdfUnchanged"], True)
        self.assertEqual(capture.call_count, 1)
        stop.assert_called_once()
        self.assertEqual(backend.calls, [
            "server_start", "adb:forward/--no-rebind/tcp:27042/tcp:27042",
            "child", "adb:forward/--remove/tcp:27042", "server_stop"])
        self.assertFalse(backend.forward)
        self.assertIsNotNone(original_child)

    def test_child_failure_still_cleans_and_rechecks_reader(self):
        backend = FakeBackend(error=trial.GraphTrialError("GRAPH_CHILD_FRAME_REJECTED"))
        with ExitStack() as stack:
            stop, capture = self._patches(stack, backend)
            with self.assertRaisesRegex(trial.GraphTrialError,
                                        "GRAPH_CHILD_FRAME_REJECTED"):
                trial.run_trial(backend)  # type: ignore[arg-type]
        self.assertEqual(capture.call_count, 1)
        stop.assert_called_once()
        self.assertFalse(backend.forward)

    def test_post_state_change_rejects_even_with_good_frames(self):
        backend = FakeBackend()
        with ExitStack() as stack:
            stop, capture = self._patches(stack, backend, after_error=True)
            with self.assertRaisesRegex(trial.GraphTrialError,
                                        "GRAPH_POST_STATE_UNCERTAIN"):
                trial.run_trial(backend)  # type: ignore[arg-type]
        self.assertEqual(capture.call_count, 1)
        stop.assert_called_once()
        self.assertFalse(backend.forward)

    def test_server_stop_failure_overrides_valid_graph(self):
        backend = FakeBackend()
        with ExitStack() as stack:
            _, capture = self._patches(stack, backend)
            stack.enter_context(patch.object(
                identity, "_stop_exact_server",
                side_effect=identity.TrialError("SERVER_STILL_PRESENT")))
            with self.assertRaisesRegex(trial.GraphTrialError,
                                        "GRAPH_CLEANUP_UNCERTAIN"):
                trial.run_trial(backend)  # type: ignore[arg-type]
        self.assertEqual(capture.call_count, 1)
        self.assertFalse(backend.forward)

    def test_forward_removal_failure_overrides_valid_graph(self):
        class RemovalFailure(FakeBackend):
            def adb(self, *args: str, **kwargs) -> bytes:
                if args == ("forward", "--remove", identity.PORT):
                    self.calls.append("forward_remove_failed")
                    raise identity.TrialError("FORWARD_REMOVE_FAILED")
                return super().adb(*args, **kwargs)

        backend = RemovalFailure()
        with ExitStack() as stack:
            stop, capture = self._patches(stack, backend)
            with self.assertRaisesRegex(trial.GraphTrialError,
                                        "GRAPH_CLEANUP_UNCERTAIN"):
                trial.run_trial(backend)  # type: ignore[arg-type]
        self.assertEqual(capture.call_count, 1)
        stop.assert_called_once()
        self.assertTrue(backend.forward)

    def test_child_boundary_rejects_extra_and_malformed_frames(self):
        backend = trial.GraphBackend()
        for stdout in (b"e30=\ne30=\ne30=\n", b"not-base64\ne30=\n"):
            with self.subTest(stdout=stdout):
                completed = subprocess.CompletedProcess([], 0, stdout, b"")
                with patch.object(trial.subprocess, "run", return_value=completed):
                    with self.assertRaises(trial.GraphTrialError):
                        backend.child_graph(1234, b"{}")

    def test_extra_callback_latches_collector_failure(self):
        collector = trial.FrameCollector()
        for index in range(3):
            collector.on_message({"type": "send", "payload": {"index": index}}, None)
        with self.assertRaisesRegex(trial.GraphTrialError,
                                    "GRAPH_CHILD_INCOMPLETE"):
            collector.checked_frames()

    def test_callback_with_binary_attachment_rejects(self):
        collector = trial.FrameCollector()
        collector.on_message({"type": "send", "payload": {}}, b"unexpected")
        with self.assertRaises(trial.GraphTrialError):
            collector.checked_frames()

    def test_wrong_pinned_image_blocks_before_attach(self):
        class WrongImage(FakeBackend):
            def adb(self, *args: str, **_kwargs) -> bytes:
                self.calls.append("adb:" + "/".join(args))
                return b"0\n"

        backend = WrongImage()
        with self.assertRaisesRegex(trial.GraphTrialError,
                                    "GRAPH_PINNED_IMAGE_CHANGED"):
            trial._pinned_images(backend)  # type: ignore[arg-type]
        self.assertEqual(len(backend.calls), 1)


if __name__ == "__main__":
    main()
