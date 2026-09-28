"""Offline app-adapter safety tests. No ADB, Frida, install or emulator."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import emulator_trial as subject
import host_protocol as host
from test_app_evidence import ADMISSION, B, cut


def identity(state: str) -> dict:
    return {"pid": ADMISSION.pid, "incarnation": ADMISSION.incarnation,
            "activitySerial": ADMISSION.activity_serial,
            "activityPresent": True, "identityPublished": True,
            "everRegistered": True, "sampleElapsedMs": 1000,
            "armDeadlineElapsedMs": 30000, "armState": state,
            "armFinished": state == "FINISHED"}


def refreshed_state() -> dict:
    frame = cut(B, 4, 4, 3, 9)
    frame["paintStartedElapsedMs"] = 905
    frame["completedPaintElapsedMs"] = 1010
    return {"schema": "layout-fence-synthetic-v1",
            "process": identity("REFRESH_REQUESTED"),
            "activityPresent": True, "activitySerial": 1,
            "activityToken": ADMISSION.activity_token,
            "rootToken": ADMISSION.root_token,
            "lifecycle": "RESUMED", "rootAttached": True,
            "rootHasFocus": True, "parentSoleChild": True,
            "rootLost": False, "originalsExact": True,
            "sessionTainted": False, "watchdogExpired": False,
            "rootLayoutRequested": False, "parentLayoutRequested": False,
            "sampleElapsedMs": 1100, "current": frame,
            "lastCompletedPaint": copy.deepcopy(frame),
            "refreshRequested": True, "refreshPaintFloorRevision": 8,
            "refreshCompletedPaintCountFloor": 5,
            "refreshRequestedElapsedMs": 900,
            "completedPaintCount": 6}


class FakeAdb:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.state = refreshed_state()
        self.stopped = False
        self.reject_refresh = False
        self.abort_dies_before_reply = False

    def same_process(self, pid, signature) -> bool:
        return not self.stopped and pid == ADMISSION.pid

    def check_emulator(self) -> None:
        self.calls.append(("check_emulator",))

    def provider_state(self, *, timeout: float = 3.0) -> dict:
        self.calls.append(("state", timeout))
        return copy.deepcopy(self.state)

    def provider_call(self, method, argument, extras, *, timeout=3.0) -> dict:
        self.calls.append((method, argument, copy.deepcopy(extras), timeout))
        if method == "refresh":
            if self.reject_refresh:
                return {"ok": "false", "error": "ambiguous"}
            return {"ok": "true", "refreshToken": "refresh-1",
                    "paintFloorRevision": "8",
                    "completedPaintCountFloor": "5",
                    "requestedElapsedMs": "900",
                    "json": json.dumps(identity("REFRESH_REQUESTED"))}
        if method == "finish":
            return {"ok": "true", "json": json.dumps(identity("FINISHED"))}
        if method == "abort":
            self.stopped = True
            if self.abort_dies_before_reply:
                raise host.TrialError("COMMAND_TIMEOUT_OR_FAILED")
            return {"ok": "true"}
        raise AssertionError(method)

    def shell(self, *args, **kwargs) -> str:
        self.calls.append(("shell", *args))
        if args == ("am", "force-stop", host.PACKAGE):
            self.stopped = True
            return ""
        raise AssertionError(args)

    def pid(self):
        return None if self.stopped else ADMISSION.pid


def app_with_fake() -> tuple[subject.EmulatorApp, FakeAdb]:
    fake = FakeAdb()
    app = subject.EmulatorApp(fake, host.Pins("a" * 64, "b" * 64))
    app.admission = ADMISSION
    app.signature = (123, host.PACKAGE, "boot-id")
    app.arm_token = "arm-1"
    app.arm_deadline_ms = 30000
    app.host_deadline = time.monotonic() + 20
    app.prearm_host_start = time.monotonic()
    app.baseline_frame = cut(B, 4, 4, 3, 8)
    app.baseline_paint_revision = 8
    return app, fake


class TrialAdapterTests(unittest.TestCase):
    def test_refresh_requires_new_app_owned_paint_and_one_call(self) -> None:
        app, fake = app_with_fake()
        app.freshen_baseline(ADMISSION)
        self.assertEqual(app.refresh_token, "refresh-1")
        self.assertEqual(app.baseline_paint_revision, 9)
        mutating = [call for call in fake.calls if call[0] == "refresh"]
        self.assertEqual(len(mutating), 1)
        self.assertEqual(mutating[0][2]["armToken"], ("s", "arm-1"))
        self.assertNotIn("refreshToken", mutating[0][2])
        self.assertEqual(app._extras(ADMISSION, armed=True,
                                     refreshed=True)["refreshToken"],
                         ("s", "refresh-1"))

    def test_ambiguous_refresh_never_retries(self) -> None:
        app, fake = app_with_fake()
        fake.reject_refresh = True
        with self.assertRaisesRegex(host.TrialError, "CONTENT_CALL_REJECTED"):
            app.freshen_baseline(ADMISSION)
        self.assertEqual(sum(call[0] == "refresh" for call in fake.calls), 1)
        self.assertIsNone(app.refresh_token)

    def test_abort_reply_loss_waits_for_exact_self_death(self) -> None:
        app, fake = app_with_fake()
        fake.abort_dies_before_reply = True
        app.stop_exact_process(ADMISSION)
        self.assertTrue(fake.stopped)
        self.assertEqual(sum(call[0] == "abort" for call in fake.calls), 1)
        self.assertFalse(any(call[0] == "shell" for call in fake.calls))

    def test_force_stop_only_after_verified_finish(self) -> None:
        app, fake = app_with_fake()
        app.finish_lease(ADMISSION)
        self.assertEqual([call[:3] for call in fake.calls if call[0] == "shell"],
                         [("shell", "am", "force-stop")])
        self.assertTrue(fake.stopped)

    def test_unarmed_launch_cleanup_is_exact_and_unknown(self) -> None:
        app, fake = app_with_fake()
        app.launch_attempted = True
        app.prearm_host_start = None
        app.arm_token = None
        with patch.object(subject, "verify_installed_apk") as verify:
            app.cleanup_unarmed_launch()
        verify.assert_called_once_with(fake, app.pins.apk_sha256)
        self.assertEqual([call[:3] for call in fake.calls if call[0] == "shell"],
                         [("shell", "am", "force-stop")])
        self.assertTrue(fake.stopped)

    def test_unarmed_cleanup_forbidden_after_prearm_begins(self) -> None:
        app, fake = app_with_fake()
        app.launch_attempted = True
        with self.assertRaisesRegex(host.TrialError,
                                    "PREARM_CLEANUP_FORBIDDEN"):
            app.cleanup_unarmed_launch()
        self.assertFalse(any(call[0] == "shell" for call in fake.calls))


if __name__ == "__main__":
    unittest.main()
