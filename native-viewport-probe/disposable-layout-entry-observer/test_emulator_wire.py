"""Offline exact-serial/content framing tests. Never invokes ADB."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import emulator_wire as subject
from host_protocol import TrialError


NET_HEADER = ("sl local_address rem_address st tx_queue rx_queue tr "
              "tm->when retrnsmt uid timeout inode\n")
NET6_HEADER = ("sl local_address remote_address st tx_queue rx_queue tr "
               "tm->when retrnsmt uid timeout inode\n")
TCP_ROW = ("0: 0100007F:69A2 00000000:0000 0A "
           "00000000:00000000 00:00000000 00000000 0 0 123 1\n")
TCP6_ROW = ("1: " + "0" * 32 + ":69A2 " + "0" * 32 + ":0000 0A "
            "00000000:00000000 00:00000000 00000000 0 0 124 1\n")


class CleanupAdb:
    """Offline responses for the exact cleanup operations only."""

    def __init__(self, digest: str) -> None:
        self.digest = digest
        self.remote = f"/data/local/tmp/layout-frida-{digest[:16]}"
        self.actions: list[tuple[str, ...]] = []
        self.forward_rows = ""
        self.post_remove_rows: str | None = None
        self.ps_rows = "PID ARGS\n"
        self.stage_hash = digest
        self.rm_error: TrialError | None = None
        self.proc_presence = "ABSENT"
        self.proc_cmdline = self.remote + "\x00"
        self.stage_exists = True
        self.stage_symlink = False
        self.rm_removes_stage = True
        self.post_rm_symlink = False
        self.net_tcp = NET_HEADER
        self.net_tcp6 = NET6_HEADER

    def run(self, *args: str, **unused) -> str:
        self.actions.append(("run", *args))
        if args == ("forward", "--list"):
            return self.forward_rows
        if args == ("forward", "--remove", "tcp:27042"):
            self.forward_rows = ("" if self.post_remove_rows is None
                                 else self.post_remove_rows)
            return ""
        raise AssertionError(f"unexpected run args: {args}")

    def shell(self, *args: str, **unused) -> str:
        self.actions.append(("shell", *args))
        if args == ("ps", "-A", "-o", "PID,ARGS"):
            return self.ps_rows
        if args == ("pidof", "frida-server"):
            return ""
        if args == ("cat", "/proc/net/tcp"):
            return self.net_tcp
        if args == ("cat", "/proc/net/tcp6"):
            return self.net_tcp6
        if args == ("sha256sum", self.remote):
            return f"{self.stage_hash}  {self.remote}\n"
        if args == ("rm", self.remote):
            if self.rm_error is not None:
                raise self.rm_error
            if self.rm_removes_stage:
                self.stage_exists = False
                self.stage_symlink = self.post_rm_symlink
            return ""
        if len(args) == 3 and args[:2] == ("kill", "-TERM"):
            return ""
        if len(args) == 2 and args[0] == "cat" and args[1].endswith("/cmdline"):
            return self.proc_cmdline
        raise AssertionError(f"unexpected shell args: {args}")

    def server_script(self, script: str, **unused) -> str:
        self.actions.append(("script", script))
        if script == (f"[ ! -e {self.remote} ] && "
                      f"[ ! -L {self.remote} ] && echo ABSENT"):
            return "" if self.stage_exists or self.stage_symlink else "ABSENT\n"
        if script.startswith("if [ -d /proc/"):
            return self.proc_presence + "\n"
        raise AssertionError(f"unexpected script: {script}")


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

    def test_server_scripts_are_one_quoted_remote_argument(self) -> None:
        adb = subject.ExactAdb(Path(sys.executable).resolve())
        remote = "/data/local/tmp/layout-frida-" + "a" * 16
        scripts = (
            f"[ ! -e {remote} ] && [ ! -L {remote} ] && echo ABSENT",
            f"{remote} -l 127.0.0.1:27042 >/dev/null 2>&1 & echo $!",
            "if [ -d /proc/2468 ]; then echo PRESENT; else echo ABSENT; fi",
        )
        for script in scripts:
            with self.subTest(script=script):
                with patch.object(subject, "_invoke", return_value=(0, "OK\n")) as invoke:
                    self.assertEqual(adb.server_script(script), "OK\n")
                self.assertEqual(invoke.call_args.args[0],
                    [str(Path(sys.executable).resolve()), "-s", "emulator-5554",
                     "shell", "sh", "-c", f"'{script}'"])

    def test_server_script_rejects_injection_and_unreviewed_commands(self) -> None:
        adb = subject.ExactAdb(Path(sys.executable).resolve())
        remote = "/data/local/tmp/layout-frida-" + "a" * 16
        safe = f"[ ! -e {remote} ] && [ ! -L {remote} ] && echo ABSENT"
        with patch.object(subject, "_invoke") as invoke:
            for script in (safe + "; id", safe + "'", safe + "\n", "id",
                           "if [ -d /proc/1 ]; then echo PRESENT; rm /x; fi",
                           f"[ ! -e {remote} ] && echo ABSENT",
                           (f"[ ! -e {remote} ] && [ ! -L "
                            "/data/local/tmp/layout-frida-" + "b" * 16 +
                            " ] && echo ABSENT"),
                           "[ ! -e /data/local/tmp/layout-frida-../../x ] && echo ABSENT"):
                with self.subTest(script=script):
                    with self.assertRaisesRegex(TrialError,
                                                "SERVER_SCRIPT_INVALID"):
                        adb.server_script(script)
        invoke.assert_not_called()

    def test_net_tables_must_both_have_exact_header_and_sane_rows(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        self.assertFalse(server._remote_listening())  # Valid header-only tables.
        fake.net_tcp = NET_HEADER + TCP_ROW
        fake.net_tcp6 = NET6_HEADER + TCP6_ROW
        self.assertTrue(server._remote_listening())
        self.assertIn(("shell", "cat", "/proc/net/tcp6"), fake.actions)
        for table in ("net_tcp", "net_tcp6"):
            header = NET_HEADER if table == "net_tcp" else NET6_HEADER
            wrong_spelling = NET6_HEADER if table == "net_tcp" else NET_HEADER
            for malformed in ("", "different header\n", wrong_spelling,
                              header + "0: 0100007F:69A2\n",
                              header + "0: ZZ00007F:69A2 00000000:0000 0A "
                                       "00000000:00000000 00:00000000 "
                                       "00000000 0 0 123 1\n"):
                with self.subTest(table=table, malformed=malformed):
                    setattr(fake, table, malformed)
                    with self.assertRaisesRegex(TrialError,
                                                "SERVER_NET_TABLE_INVALID"):
                        server._remote_listening()
                    setattr(fake, table, header +
                            (TCP_ROW if table == "net_tcp" else TCP6_ROW))

    def test_invalid_net_table_retains_stage_with_fixed_cleanup_evidence(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.net_tcp6 = ""
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = True
        with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
            server.cleanup()
        self.assertTrue(server.staged)
        self.assertEqual(server.cleanup_evidence,
            [{"phase": "stage", "code": "SERVER_NET_TABLE_INVALID"}])
        self.assertFalse(any(action[:2] == ("shell", "rm")
                             for action in fake.actions))

    def test_prepare_rejects_dangling_staged_symlink_without_push(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.stage_exists = False
        fake.stage_symlink = True
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        with self.assertRaisesRegex(TrialError, "SERVER_STAGE_OCCUPIED"):
            server.prepare()
        self.assertFalse(server.staged)
        self.assertFalse(any(action[:2] == ("run", "push")
                             for action in fake.actions))

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
        self.assertEqual(server.cleanup_evidence,
                         [{"phase": "process", "code": "SERVER_PROC_UNCERTAIN"}])

    def test_confirmed_gone_before_cleanup_never_kills_and_removes_owned_stage(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = server.started = server.launch_attempted = True
        server.pid = 2468
        server.start_ticks = 123
        with patch.object(server, "_remote_listening", return_value=False):
            server.cleanup()
        self.assertFalse(server.started or server.staged)
        self.assertEqual(server.cleanup_evidence, [])
        self.assertFalse(any(action[:2] == ("shell", "kill")
                             for action in fake.actions))
        self.assertEqual(sum(action[:2] == ("shell", "rm")
                             for action in fake.actions), 1)

    def test_owned_forward_removed_then_gone_server_allows_checked_stage_removal(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.forward_rows = "emulator-5554 tcp:27042 tcp:27042\n"
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.forwarded = server.staged = server.started = True
        server.launch_attempted = True
        server.prior_forwards = []
        server.pid = 2468
        server.start_ticks = 123
        with patch.object(server, "_remote_listening", return_value=False):
            server.cleanup()
        self.assertFalse(server.forwarded or server.started or server.staged)
        self.assertEqual(server.cleanup_evidence, [])
        self.assertEqual(sum(action[:3] == ("run", "forward", "--remove")
                             for action in fake.actions), 1)
        self.assertEqual(sum(action[:2] == ("shell", "rm")
                             for action in fake.actions), 1)
        self.assertFalse(any(action[:2] == ("shell", "kill")
                             for action in fake.actions))

    def test_changed_pid_incarnation_is_gone_without_killing_reused_pid(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.proc_presence = "PRESENT"
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = server.started = server.launch_attempted = True
        server.pid = 2468
        server.start_ticks = 123
        with patch.object(subject, "_proc_start", return_value=124), \
             patch.object(server, "_remote_listening", return_value=False):
            server.cleanup()
        self.assertFalse(server.started or server.staged)
        self.assertFalse(any(action[:2] == ("shell", "kill")
                             for action in fake.actions))
        self.assertEqual(sum(action[:2] == ("shell", "rm")
                             for action in fake.actions), 1)

    def test_unreadable_status_never_kills_or_removes_stage(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = server.started = server.launch_attempted = True
        server.pid = 2468
        server.start_ticks = 123
        with patch.object(server, "_server_status",
                          side_effect=TrialError("SERVER_PROC_UNCERTAIN")):
            with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertTrue(server.started and server.staged)
        self.assertEqual(server.cleanup_evidence,
                         [{"phase": "process", "code": "SERVER_PROC_UNCERTAIN"}])
        self.assertFalse(any(action[:2] in (("shell", "kill"), ("shell", "rm"))
                             for action in fake.actions))

    def test_changed_cmdline_with_same_start_remains_uncertain(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.proc_presence = "PRESENT"
        fake.proc_cmdline = "/data/local/tmp/not-our-server\x00"
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = server.started = server.launch_attempted = True
        server.pid = 2468
        server.start_ticks = 123
        with patch.object(subject, "_proc_start", return_value=123):
            with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertTrue(server.started and server.staged)
        self.assertEqual(server.cleanup_evidence,
                         [{"phase": "process", "code": "SERVER_OWNERSHIP_LOST"}])
        self.assertFalse(any(action[:2] in (("shell", "kill"), ("shell", "rm"))
                             for action in fake.actions))

    def test_forward_ownership_drift_preserves_stage_and_fixed_evidence(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.forward_rows = "emulator-5554 tcp:27042 tcp:12345\n"
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.forwarded = server.staged = True
        server.prior_forwards = []
        with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
            server.cleanup()
        self.assertEqual(server.cleanup_evidence,
                         [{"phase": "forward", "code": "FORWARD_OWNERSHIP_LOST"}])
        self.assertFalse(any(action[:3] == ("run", "forward", "--remove") or
                             action[:2] == ("shell", "rm")
                             for action in fake.actions))

    def test_forward_post_remove_drift_retains_stage(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.forward_rows = "emulator-5554 tcp:27042 tcp:27042\n"
        fake.post_remove_rows = "emulator-5554 tcp:27042 tcp:12345\n"
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.forwarded = server.staged = True
        server.prior_forwards = []
        with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
            server.cleanup()
        self.assertFalse(server.forwarded)
        self.assertTrue(server.staged)
        self.assertEqual(server.cleanup_evidence,
                         [{"phase": "forward", "code": "FORWARD_CLEANUP_UNCERTAIN"}])
        self.assertFalse(any(action[:2] == ("shell", "rm")
                             for action in fake.actions))

    def test_stage_checks_keep_binary_on_ps_hash_or_rm_uncertainty(self) -> None:
        digest = "a" * 64
        for name, expected_code in (("ps", "SERVER_STAGE_STILL_IN_USE"),
                                    ("hash", "SERVER_STAGE_OWNERSHIP_LOST"),
                                    ("rm", "ADB_COMMAND_FAILED")):
            with self.subTest(name=name):
                fake = CleanupAdb(digest)
                if name == "ps":
                    fake.ps_rows = "PID CMDLINE\n"
                elif name == "hash":
                    fake.stage_hash = "b" * 64
                else:
                    fake.rm_error = TrialError("ADB_COMMAND_FAILED")
                with patch.object(subject, "file_sha"):
                    server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
                server.staged = True
                with patch.object(server, "_remote_listening", return_value=False):
                    with self.assertRaisesRegex(TrialError,
                                                "SERVER_CLEANUP_UNCERTAIN"):
                        server.cleanup()
                self.assertTrue(server.staged)
                self.assertEqual(server.cleanup_evidence,
                    [{"phase": "stage", "code": expected_code}])
                self.assertEqual(sum(action[:2] == ("shell", "rm")
                                     for action in fake.actions),
                                 1 if name == "rm" else 0)

    def test_rm_success_without_exact_absence_keeps_stage_uncertain(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.rm_removes_stage = False
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = True
        with patch.object(server, "_remote_listening", return_value=False):
            with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertTrue(server.staged)
        self.assertEqual(server.cleanup_evidence,
            [{"phase": "stage", "code": "SERVER_STAGE_REMOVAL_UNCERTAIN"}])
        self.assertEqual(sum(action[:2] == ("shell", "rm")
                             for action in fake.actions), 1)
        self.assertIn(("script", f"[ ! -e {server.remote} ] && "
                                  f"[ ! -L {server.remote} ] && echo ABSENT"),
                      fake.actions)

    def test_rm_success_leaving_dangling_symlink_keeps_stage_uncertain(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.post_rm_symlink = True
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = True
        with patch.object(server, "_remote_listening", return_value=False):
            with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertTrue(server.staged)
        self.assertEqual(server.cleanup_evidence,
            [{"phase": "stage", "code": "SERVER_STAGE_REMOVAL_UNCERTAIN"}])
        self.assertEqual(sum(action[:2] == ("shell", "rm")
                             for action in fake.actions), 1)

    def test_unknown_cleanup_error_text_is_never_exposed(self) -> None:
        digest = "a" * 64
        fake = CleanupAdb(digest)
        fake.rm_error = TrialError("private-token-123")
        with patch.object(subject, "file_sha"):
            server = subject.OwnedFridaServer(fake, Path(sys.executable), digest)
        server.staged = True
        with patch.object(server, "_remote_listening", return_value=False):
            with self.assertRaisesRegex(TrialError, "SERVER_CLEANUP_UNCERTAIN"):
                server.cleanup()
        self.assertEqual(server.cleanup_evidence,
            [{"phase": "stage", "code": "CLEANUP_DIAGNOSTIC_UNAVAILABLE"}])

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
