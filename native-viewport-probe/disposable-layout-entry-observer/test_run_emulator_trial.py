"""Entry-point controls tested with all device/Frida calls mocked."""
from __future__ import annotations

from argparse import Namespace
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_protocol as host
import run_emulator_trial as subject


def args(enabled=True) -> Namespace:
    return Namespace(execute_synthetic_api30_only=enabled,
                     variant="parent-plus-one", adb=Path(sys.executable),
                     apksigner=Path(sys.executable), apk=Path(sys.executable),
                     server=Path(sys.executable), python=Path(sys.executable),
                     frida_site=Path(sys.prefix), bundle=Path(sys.executable),
                     apk_sha256=subject.REVIEWED_APK_SHA256,
                     signer_sha256=subject.REVIEWED_SIGNER_SHA256,
                     server_sha256=subject.REVIEWED_SERVER_SHA256,
                     bundle_sha256=subject.REVIEWED_BUNDLE_SHA256)


class FakeServer:
    def __init__(self, *unused) -> None:
        self.prepared = False
        self.cleaned = False
        self.fail_cleanup = False

    def prepare(self) -> None:
        self.prepared = True

    def cleanup(self) -> None:
        self.cleaned = True
        if self.fail_cleanup:
            raise host.TrialError("SERVER_CLEANUP_UNCERTAIN")


class EntryTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows handle-deletion regression")
    def test_windows_lock_closes_without_unlinking_open_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(subject, "__file__", str(Path(directory) / "runner.py")):
            fd, path = subject._lock()
            self.assertTrue(path.exists())
            self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                             (path.lstat().st_dev, path.lstat().st_ino))
            with patch.object(Path, "unlink",
                              side_effect=PermissionError("open Windows fd")) as unlink:
                subject._unlock(fd, path)
            unlink.assert_not_called()
            self.assertFalse(path.exists())

    def test_existing_stale_lock_blocks_without_modification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".synthetic-emulator.lock"
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with patch.object(subject, "__file__", str(Path(directory) / "runner.py")):
                    with self.assertRaisesRegex(host.TrialError,
                                                "TRIAL_LOCK_PRESENT"):
                        subject._lock()
                self.assertEqual(path.stat().st_size, 0)
                self.assertEqual(os.fstat(fd).st_ino, path.stat().st_ino)
            finally:
                os.close(fd)
            self.assertTrue(path.exists())
            with patch.object(subject, "__file__", str(Path(directory) / "runner.py")):
                with self.assertRaisesRegex(host.TrialError,
                                            "TRIAL_LOCK_PRESENT"):
                    subject._lock()

    def test_replaced_lock_is_never_unlinked_as_ours(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(subject, "__file__", str(Path(directory) / "runner.py")):
            fd, path = subject._lock()
            path.unlink()
            replacement = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                                  0o600)
            os.close(replacement)
            with self.assertRaisesRegex(host.TrialError,
                                        "LOCK_CLEANUP_UNCERTAIN"):
                subject._unlock(fd, path)
            self.assertTrue(path.exists())

    def test_missing_owned_lock_is_not_clean_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(subject, "__file__", str(Path(directory) / "runner.py")):
            fd, path = subject._lock()
            path.unlink()
            with self.assertRaisesRegex(host.TrialError,
                                        "LOCK_CLEANUP_UNCERTAIN"):
                subject._unlock(fd, path)

    def test_zero_file_identity_is_not_ownership_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(subject, "__file__", str(Path(directory) / "runner.py")):
            fd, path = subject._lock()
            actual = os.fstat(fd)
            zero = SimpleNamespace(st_mode=actual.st_mode, st_ino=0,
                                   st_dev=actual.st_dev)
            with patch.object(subject.os, "fstat", return_value=zero):
                with self.assertRaisesRegex(host.TrialError,
                                            "LOCK_CLEANUP_UNCERTAIN"):
                    subject._unlock(fd, path)

    def test_missing_explicit_optin_does_not_touch_device(self) -> None:
        with patch.object(subject, "verify_signed_apk") as verify:
            with self.assertRaisesRegex(host.TrialError,
                                        "SYNTHETIC_OPT_IN_REQUIRED"):
                subject.run(args(False))
        verify.assert_not_called()

    def test_caller_cannot_replace_reviewed_artifact_pins(self) -> None:
        changed = args(); changed.apk_sha256 = "f" * 64
        with patch.object(subject, "verify_signed_apk") as verify:
            with self.assertRaisesRegex(host.TrialError,
                                        "REVIEWED_PIN_MISMATCH"):
                subject.run(changed)
        verify.assert_not_called()

    def test_installed_apk_mismatch_prevents_server_mutation(self) -> None:
        class Adb:
            def check_emulator(self): pass
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=lambda *a: None,
                            ExactAdb=lambda *a: Adb()), \
             patch.object(subject, "verify_installed_apk",
                          side_effect=host.TrialError("INSTALLED_APK_HASH_MISMATCH")), \
             patch.object(subject, "OwnedFridaServer") as server:
            with self.assertRaisesRegex(host.TrialError,
                                        "INSTALLED_APK_HASH_MISMATCH"):
                subject.run(args())
        server.assert_not_called()

    def test_success_requires_server_cleanup(self) -> None:
        server = FakeServer()
        result = {"verdict": "PASS_SYNTHETIC_EDGE_ONLY"}
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            verify_installed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=lambda *a: None,
                            ExactAdb=lambda *a: type("A", (),
                                {"check_emulator": lambda self: None})(),
                            OwnedFridaServer=lambda *a: server,
                            EmulatorApp=lambda *a: object(),
                            WorkerTransport=lambda *a: object(),
                            run_mockable=lambda *a: result):
            self.assertEqual(subject.run(args()), result)
        self.assertTrue(server.prepared and server.cleaned)

    def test_uncertain_server_cleanup_overrides_trial_pass(self) -> None:
        server = FakeServer()
        server.fail_cleanup = True
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            verify_installed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=lambda *a: None,
                            ExactAdb=lambda *a: type("A", (),
                                {"check_emulator": lambda self: None})(),
                            OwnedFridaServer=lambda *a: server,
                            EmulatorApp=lambda *a: object(),
                            WorkerTransport=lambda *a: object(),
                            run_mockable=lambda *a: {"verdict":
                                "PASS_SYNTHETIC_EDGE_ONLY"}):
            with self.assertRaisesRegex(host.TrialError,
                                        "SERVER_CLEANUP_UNCERTAIN"):
                subject.run(args())
        self.assertTrue(server.cleaned)

    def test_uncertain_lock_cleanup_overrides_trial_pass(self) -> None:
        server = FakeServer()
        def unlock_failed(*unused):
            raise PermissionError("open Windows fd")
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            verify_installed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=unlock_failed,
                            ExactAdb=lambda *a: type("A", (),
                                {"check_emulator": lambda self: None})(),
                            OwnedFridaServer=lambda *a: server,
                            EmulatorApp=lambda *a: object(),
                            WorkerTransport=lambda *a: object(),
                            run_mockable=lambda *a: {"verdict":
                                "PASS_SYNTHETIC_EDGE_ONLY"}):
            with self.assertRaises(subject.RunnerFailure) as caught:
                subject.run(args())
        self.assertEqual(str(caught.exception), "LOCK_CLEANUP_UNCERTAIN")
        self.assertIsNone(caught.exception.primary_code)
        self.assertEqual(caught.exception.cleanup_codes,
                         ("LOCK_CLEANUP_UNCERTAIN",))
        self.assertTrue(server.cleaned)

    def test_prearm_launch_failure_uses_only_scoped_cleanup(self) -> None:
        server = FakeServer()
        class App:
            launch_attempted = True
            prearm_host_start = None
            cleaned = False
            def cleanup_unarmed_launch(self):
                self.cleaned = True
        app = App()
        def failed(*unused):
            raise host.TrialError("APP_BASELINE_UNAVAILABLE")
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            verify_installed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=lambda *a: None,
                            ExactAdb=lambda *a: type("A", (),
                                {"check_emulator": lambda self: None})(),
                            OwnedFridaServer=lambda *a: server,
                            EmulatorApp=lambda *a: app,
                            WorkerTransport=lambda *a: object(),
                            run_mockable=failed):
            with self.assertRaisesRegex(host.TrialError,
                                        "PREFLIGHT_UNKNOWN_CLEANED"):
                subject.run(args())
        self.assertTrue(app.cleaned and server.cleaned)

    def test_post_prearm_failure_never_force_stops_as_fallback(self) -> None:
        server = FakeServer()
        class App:
            launch_attempted = True
            prearm_host_start = 123.0
            cleaned = False
            def cleanup_unarmed_launch(self): self.cleaned = True
        app = App()
        def failed(*unused):
            raise host.TrialError("TRIAL_UNCERTAIN")
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            verify_installed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=lambda *a: None,
                            ExactAdb=lambda *a: type("A", (),
                                {"check_emulator": lambda self: None})(),
                            OwnedFridaServer=lambda *a: server,
                            EmulatorApp=lambda *a: app,
                            WorkerTransport=lambda *a: object(),
                            run_mockable=failed):
            with self.assertRaisesRegex(host.TrialError, "TRIAL_UNCERTAIN"):
                subject.run(args())
        self.assertFalse(app.cleaned)
        self.assertTrue(server.cleaned)

    def test_cleanup_uncertainty_dominates_but_preserves_primary_code(self) -> None:
        server = FakeServer()
        server.fail_cleanup = True
        app = type("App", (), {"launch_attempted": False,
                               "prearm_host_start": None})()
        def failed(*unused):
            raise host.TrialError("TRIAL_PRIMARY_FAILURE")
        def unlock_failed(*unused):
            raise PermissionError("open Windows fd")
        with patch.multiple(subject, verify_signed_apk=lambda *a: None,
                            verify_installed_apk=lambda *a: None,
                            _exact_size=lambda *a: None,
                            file_sha=lambda *a, **k: None,
                            _lock=lambda: (17, Path("ignored")),
                            _unlock=unlock_failed,
                            ExactAdb=lambda *a: type("A", (),
                                {"check_emulator": lambda self: None})(),
                            OwnedFridaServer=lambda *a: server,
                            EmulatorApp=lambda *a: app,
                            WorkerTransport=lambda *a: object(),
                            run_mockable=failed):
            with self.assertRaises(subject.RunnerFailure) as caught:
                subject.run(args())
        error = caught.exception
        self.assertEqual(str(error), "LOCK_CLEANUP_UNCERTAIN")
        self.assertEqual(error.primary_code, "TRIAL_PRIMARY_FAILURE")
        self.assertEqual(error.cleanup_codes,
                         ("SERVER_CLEANUP_UNCERTAIN", "LOCK_CLEANUP_UNCERTAIN"))
        output = io.StringIO()
        with patch.object(subject, "parser") as parser, \
             patch.object(subject, "run", side_effect=error), \
             redirect_stdout(output):
            parser.return_value.parse_args.return_value = args()
            self.assertEqual(subject.main([]), 2)
        reported = json.loads(output.getvalue())
        self.assertEqual(reported["verdict"], "UNKNOWN")
        self.assertEqual(reported["code"], "LOCK_CLEANUP_UNCERTAIN")
        self.assertEqual(reported["primaryCode"], "TRIAL_PRIMARY_FAILURE")
        self.assertEqual(reported["cleanupCodes"], list(error.cleanup_codes))


if __name__ == "__main__":
    unittest.main()
