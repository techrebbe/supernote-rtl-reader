"""Offline exact-serial/content framing tests. Never invokes ADB."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import emulator_wire as subject
from host_protocol import TrialError


class WireTests(unittest.TestCase):
    def test_apksigner_digest_accepts_crlf_and_lf_without_loosening_pin(self) -> None:
        executable = Path(sys.executable).resolve()
        signer = "4d4f0f18e10114c7a801bcdb87dd4fd2d75ebc24ca0ad5bcb6967009e62ead6a"
        digest_line = f"Signer #1 certificate SHA-256 digest: {signer}"
        with patch.object(subject, "file_sha"):
            for newline in ("\r\n", "\n"):
                with self.subTest(newline=repr(newline)):
                    output = newline.join(("Verifies", digest_line, "Number of signers: 1", ""))
                    with patch.object(subject, "_invoke", return_value=(0, output)):
                        subject.verify_signed_apk(executable, executable,
                                                  "a" * 64, signer)
            for output in (digest_line.replace(signer, "b" * 64) + "\r\n",
                           digest_line + "x\r\n",
                           "Verifies\r" + digest_line + "\n",
                           "Verifies\u2028" + digest_line + "\n",
                           digest_line + "\r\n" +
                           f"Signer #2 certificate SHA-256 digest: {signer}\r\n"):
                with self.subTest(output=output):
                    with patch.object(subject, "_invoke", return_value=(0, output)):
                        with self.assertRaisesRegex(TrialError,
                                                    "APK_SIGNER_MISMATCH"):
                            subject.verify_signed_apk(executable, executable,
                                                      "a" * 64, signer)

    def test_query_requires_one_exact_row(self) -> None:
        self.assertEqual(subject.query_json('Row: 0 json={"pid":2468}\n'),
                         {"pid": 2468})
        for invalid in ('Row: 1 json={"pid":2468}\n',
                        'Row: 0 json={"pid":2468}\nRow: 1 json={}\n',
                        'No result found.\n'):
            with self.assertRaises(TrialError):
                subject.query_json(invalid)

    def test_bundle_handles_nested_json_without_split(self) -> None:
        fields = subject.call_bundle(
            'Result: Bundle[{json={"scene":"x,y","cut":{"n":2}}, '
            'armToken=abc-123, ok=true, armDeadlineElapsedMs=30000}]\n')
        self.assertEqual(subject.bundle_json(fields,
            {"json", "armToken", "ok", "armDeadlineElapsedMs"}),
            {"scene": "x,y", "cut": {"n": 2}})
        self.assertEqual(fields["armToken"], "abc-123")

    def test_reject_duplicate_or_changed_bundle(self) -> None:
        for value in ('Result: Bundle[{ok=true, ok=true, json={}}]',
                      'Result: Bundle[{ok=false, json={}}]',
                      'Result: Bundle[{ok=true, json={}}] trailing'):
            with self.assertRaises(TrialError):
                fields = subject.call_bundle(value)
                subject.bundle_json(fields, {"ok", "json"})

    def test_provider_call_carries_exact_serial_and_typed_pins(self) -> None:
        adb = subject.ExactAdb(Path(sys.executable).resolve())
        with patch.object(subject, "_invoke", return_value=(0,
              'Result: Bundle[{ok=true, json={"pid":2468}}]\n')) as invoke:
            fields = adb.provider_call("prearm", None,
                    {"pid": ("i", "2468"), "activitySerial": ("l", "1"),
                     "rootToken": ("s", "root-1")})
        self.assertEqual(fields["ok"], "true")
        argv = invoke.call_args.args[0]
        self.assertEqual(argv[:3], [str(Path(sys.executable).resolve()),
                                    "-s", "emulator-5554"])
        self.assertIn("pid:i:2468", argv)
        self.assertIn("activitySerial:l:1", argv)
        self.assertIn("rootToken:s:root-1", argv)

    def test_unknown_method_never_reaches_transport(self) -> None:
        adb = subject.ExactAdb(Path(sys.executable).resolve())
        with patch.object(subject, "_invoke") as invoke:
            with self.assertRaisesRegex(TrialError, "CONTENT_METHOD_INVALID"):
                adb.provider_call("delete", None, {})
        invoke.assert_not_called()

    def test_colon_in_provider_extra_is_rejected_before_cli(self) -> None:
        adb = subject.ExactAdb(Path(sys.executable).resolve())
        with patch.object(subject, "_invoke") as invoke:
            with self.assertRaisesRegex(TrialError, "CONTENT_EXTRA_INVALID"):
                adb.provider_call("prearm", None,
                                  {"rootToken": ("s", "old:unsafe:token")})
        invoke.assert_not_called()

    def test_partial_server_launch_never_deletes_staged_binary_as_clean(self) -> None:
        class FakeAdb:
            def __init__(self): self.actions = []
            def shell(self, *args, **kwargs):
                self.actions.append(args)
                return ""
        fake = FakeAdb()
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable),
                                              "a" * 64)
        server.staged = True
        server.launch_attempted = True
        server.pid = 2468  # launcher returned, but stat never authenticated
        with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
            server.cleanup()
        self.assertFalse(any(action[0] in {"rm", "kill"}
                             for action in fake.actions))

    def test_server_identity_read_failure_after_term_is_not_exit_proof(self) -> None:
        class FakeAdb:
            def __init__(self): self.actions = []
            def shell(self, *args, **kwargs):
                self.actions.append(args)
                return ""
        fake = FakeAdb()
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable),
                                              "a" * 64)
        server.staged = server.started = server.launch_attempted = True
        server.pid = 2468
        server.start_ticks = 123
        with patch.object(server, "_server_status",
                          side_effect=["SAME", TrialError("SERVER_PROC_UNCERTAIN")]):
            with self.assertRaisesRegex(TrialError,
                                        "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertIn(("kill", "-TERM", "2468"), fake.actions)
        self.assertFalse(any(action[0] == "rm" for action in fake.actions))

    def test_staged_binary_in_use_after_exit_blocks_unlink(self) -> None:
        class FakeAdb:
            def __init__(self): self.actions = []
            def shell(self, *args, **kwargs):
                self.actions.append(args)
                if args == ("ps", "-A", "-o", "PID,ARGS"):
                    return "PID ARGS\n999 /data/local/tmp/layout-frida-aaaaaaaaaaaaaaaa\n"
                return ""
        fake = FakeAdb()
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable),
                                              "a" * 64)
        server.staged = True
        with patch.object(server, "_remote_listening", return_value=False):
            with self.assertRaisesRegex(TrialError,
                                        "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertFalse(any(action[0] == "rm" for action in fake.actions))


if __name__ == "__main__":
    unittest.main()
