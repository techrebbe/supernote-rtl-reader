"""Deterministic structural gates for security-critical collector plumbing."""
from __future__ import annotations

import pathlib
import re
import unittest


HERE = pathlib.Path(__file__).resolve().parent
COLLECTOR = (HERE / "native_page_platform_collector.cpp").read_text(
    encoding="utf-8")
CORE = (HERE / "collector_core.cpp").read_text(encoding="utf-8")
BUILD = (HERE / "build-and-test.ps1").read_text(encoding="utf-8")
ADMISSION = (HERE / "collector-admission.txt").read_text(encoding="utf-8")


class CollectorHardeningContractTest(unittest.TestCase):
    def test_child_pipe_writers_remain_blocking(self) -> None:
        self.assertIn("pipe2(stdout_pipe, O_CLOEXEC)", COLLECTOR)
        self.assertIn("pipe2(stderr_pipe, O_CLOEXEC)", COLLECTOR)
        self.assertNotRegex(COLLECTOR, r"pipe2\([^\n]*O_NONBLOCK")
        fork = COLLECTOR.index("const pid_t child = fork()")
        child_begin = COLLECTOR.index("if (child == 0)", fork)
        child_exec = COLLECTOR.index("execve(argv[0]", child_begin)
        parent_close = COLLECTOR.index(
            "close_if_open(&stdout_pipe[1]);", child_exec)
        nonblocking = COLLECTOR.index(
            "set_nonblocking(stdout_pipe[0])", parent_close)
        self.assertLess(fork, parent_close)
        self.assertLess(parent_close, nonblocking)
        child_end = parent_close
        self.assertNotIn("O_NONBLOCK", COLLECTOR[child_begin:child_end])
        self.assertIn("dup2(stdout_pipe[1], STDOUT_FILENO)",
                      COLLECTOR[child_begin:child_end])
        self.assertIn("dup2(stderr_pipe[1], STDERR_FILENO)",
                      COLLECTOR[child_begin:child_end])

    def test_large_outputs_are_drained_in_bounded_chunks(self) -> None:
        append_begin = COLLECTOR.index("bool append_pipe(")
        append_end = COLLECTOR.index("bool run_command(", append_begin)
        append = COLLECTOR[append_begin:append_end]
        self.assertIn("std::array<char, 16384> buffer", append)
        self.assertIn("for (;;)", append)
        self.assertIn("maximum - output->size()", append)
        runner_begin = append_end
        runner_end = COLLECTOR.index("bool single_line(", runner_begin)
        runner = COLLECTOR[runner_begin:runner_end]
        self.assertIn("poll(pollers.data(), count, timeout_ms)", runner)
        self.assertIn("append_pipe(stdout_pipe[0], stdout_limit", runner)
        self.assertIn("append_pipe(stderr_pipe[0], 65536U", runner)

    def test_only_closed_frozen_command_authority_reaches_execve(self) -> None:
        self.assertIn("run_command(nppcap::FrozenCommand command", COLLECTOR)
        self.assertNotIn(
            "run_command(const std::vector<std::string> &arguments", COLLECTOR)
        self.assertIn("nppcap::frozen_command_spec(command)", COLLECTOR)
        self.assertIn("execve(argv[0], argv.data(), environment)", COLLECTOR)
        command_rows = re.findall(
            r"\{(?:2U|3U|4U), \{\{\"/system/bin/(?:getprop|cmd|dumpsys)\"",
            CORE,
        )
        self.assertEqual(len(command_rows), 6)

    def test_outer_watchdog_bounds_all_blocking_and_cleanup_work(self) -> None:
        self.assertIn("timer_create(CLOCK_MONOTONIC", COLLECTOR)
        self.assertIn("timer_settime(watchdog_timer", COLLECTOR)
        self.assertIn("sigprocmask(SIG_UNBLOCK", COLLECTOR)
        self.assertIn("_exit(70)", COLLECTOR)
        main = COLLECTOR.index("int main(int argc, char **argv)")
        arm = COLLECTOR.index("arm_hard_watchdog()", main)
        collect = COLLECTOR.index("return collect()", arm)
        self.assertLess(arm, collect)
        self.assertIn("waitpid(child, &status, WNOHANG)", COLLECTOR)
        self.assertNotIn("waitpid(child, &status, 0)", COLLECTOR)
        self.assertIn("kChildCleanupGraceNs", COLLECTOR)
        self.assertIn("kill_and_require_reaped(child, cleanup_deadline)",
                      COLLECTOR)

    def test_pinned_python_runs_both_fatal_python_gates(self) -> None:
        self.assertIn("$pythonPath = (Resolve-Path", BUILD)
        self.assertIn("$pythonHashBefore", BUILD)
        self.assertIn("test_downstream_contract.py", BUILD)
        self.assertIn("Frozen downstream parser contract tests failed", BUILD)
        self.assertIn("test_collector_hardening_contract.py", BUILD)
        self.assertIn("Collector hardening source contract tests failed", BUILD)

    def test_downstream_parser_sources_are_exact_staged_authorities(self) -> None:
        self.assertIn("Read-OrdinaryFileAuthority", BUILD)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", BUILD)
        self.assertIn("native_page_private_adb_platform_backend.py", BUILD)
        self.assertIn("native_page_visual_platform_authority.py", BUILD)
        self.assertIn("$backendAuthorityBefore.Sha256", BUILD)
        self.assertIn("$platformAuthorityBefore.Sha256", BUILD)
        self.assertIn("$backendAuthorityAfter", BUILD)
        self.assertIn("$platformAuthorityAfter", BUILD)
        self.assertIn("$stagedBackendAfter", BUILD)
        self.assertIn("$stagedPlatformAfter", BUILD)
        self.assertIn("NATIVE_PAGE_PLATFORM_COLLECTOR_DOWNSTREAM_CONTRACT_V1", BUILD)
        self.assertIn("downstreamContractSha256", BUILD)
        self.assertIn("downstreamBackendSha256=", ADMISSION)
        self.assertIn("downstreamPlatformSha256=", ADMISSION)
        self.assertIn("downstreamContractSha256=", ADMISSION)


if __name__ == "__main__":
    unittest.main()
