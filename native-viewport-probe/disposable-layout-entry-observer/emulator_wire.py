"""Exact, bounded CLI wire format for the disposable API-30 emulator only.

Import is inert. No device action occurs until an ExactAdb method is called.
The parsers deliberately accept one narrowly pinned Android `content` format;
an unfamiliar shell rendering is UNKNOWN, never an invitation to retry a write.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any

from host_protocol import PACKAGE, SERIAL, TrialError, need


MAX_OUTPUT = 131_072
REMOTE_APK = re.compile(r"/data/app/[A-Za-z0-9_./=+~-]+/base\.apk\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"[1-9][0-9]{0,9}\Z")
TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SERVER_PATH = re.compile(r"/data/local/tmp/layout-frida-[0-9a-f]{16}\Z")


def file_sha(path: Path, expected: str, *, maximum: int) -> None:
    need(type(expected) is str and SHA.fullmatch(expected) is not None and
         path.is_file() and not path.is_symlink() and
         0 < path.stat().st_size <= maximum, "FILE_PIN_INVALID")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    need(digest.hexdigest() == expected, "FILE_HASH_MISMATCH")


def _json(value: str) -> dict[str, Any]:
    need(0 < len(value) <= MAX_OUTPUT, "CONTENT_JSON_INVALID")
    try:
        parsed = json.loads(value)
    except (ValueError, UnicodeError) as error:
        raise TrialError("CONTENT_JSON_INVALID") from error
    need(type(parsed) is dict, "CONTENT_JSON_INVALID")
    return parsed


def query_json(text: str) -> dict[str, Any]:
    """Accept exactly one `content query --uri .../state` row."""
    match = re.fullmatch(r"Row: 0 json=(\{[^\r\n]*\})\r?\n?", text)
    need(match is not None, "CONTENT_QUERY_INVALID")
    return _json(match.group(1))


def call_bundle(text: str) -> dict[str, str]:
    """Split Bundle's flat top-level fields, allowing nested JSON in `json`."""
    match = re.fullmatch(r"Result: Bundle\[\{(.*)\}\]\r?\n?", text, re.DOTALL)
    need(match is not None and "\n" not in match.group(1) and
         "\r" not in match.group(1), "CONTENT_CALL_INVALID")
    body = match.group(1)
    pieces: list[str] = []
    start = depth = 0
    quoted = escaped = False
    for index, char in enumerate(body):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            need(depth >= 0, "CONTENT_CALL_INVALID")
        elif char == "," and depth == 0 and body[index:index + 2] == ", ":
            pieces.append(body[start:index])
            start = index + 2
    need(not quoted and depth == 0, "CONTENT_CALL_INVALID")
    pieces.append(body[start:])
    answer: dict[str, str] = {}
    for piece in pieces:
        key, separator, value = piece.partition("=")
        need(separator == "=" and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key)
             is not None and key not in answer and value != "", "CONTENT_CALL_INVALID")
        answer[key] = value
    return answer


def bundle_json(fields: dict[str, str], required: set[str]) -> dict[str, Any]:
    need(set(fields) == required and fields.get("ok") == "true" and
         "json" in fields, "CONTENT_CALL_REJECTED")
    return _json(fields["json"])


def _invoke(argv: list[str], timeout: float) -> tuple[int, str]:
    need(0 < timeout <= 6.0 and all(type(item) is str and item for item in argv),
         "COMMAND_INVALID")
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, shell=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrialError("COMMAND_TIMEOUT_OR_FAILED") from error
    need(len(result.stdout) <= MAX_OUTPUT and len(result.stderr) <= MAX_OUTPUT,
         "COMMAND_OUTPUT_OVERSIZE")
    try:
        return result.returncode, result.stdout.decode("utf-8", "strict")
    except UnicodeError as error:
        raise TrialError("COMMAND_OUTPUT_INVALID") from error


class ExactAdb:
    def __init__(self, executable: Path) -> None:
        need(executable.is_absolute() and executable.is_file() and
             not executable.is_symlink(), "ADB_PATH_INVALID")
        self.executable = executable

    def run(self, *args: str, timeout: float = 3.0, allow_failure: bool = False) -> str:
        code, output = _invoke([str(self.executable), "-s", SERIAL, *args], timeout)
        need(code == 0 or allow_failure, "ADB_COMMAND_FAILED")
        return output

    def shell(self, *args: str, timeout: float = 3.0,
              allow_failure: bool = False) -> str:
        return self.run("shell", *args, timeout=timeout,
                        allow_failure=allow_failure)

    def check_emulator(self) -> None:
        need(self.run("get-state").strip() == "device" and
             self.run("get-serialno").strip() == SERIAL and
             self.shell("getprop", "ro.kernel.qemu").strip() == "1" and
             self.shell("getprop", "ro.build.version.sdk").strip() == "30" and
             self.shell("getprop", "ro.product.cpu.abi").strip() == "x86_64",
             "EMULATOR_IDENTITY_REJECTED")

    def pid(self) -> int | None:
        value = self.shell("pidof", PACKAGE, allow_failure=True).strip()
        if not value:
            return None
        need(DECIMAL.fullmatch(value) is not None, "PROCESS_AMBIGUOUS")
        return int(value)

    def process_signature(self, pid: int) -> tuple[int, str, str]:
        need(type(pid) is int and 1 <= pid <= 2**31 - 1, "PROCESS_INVALID")
        stat = self.shell("cat", f"/proc/{pid}/stat").strip()
        close = stat.rfind(")")
        need(close > 0 and stat.startswith(f"{pid} (") and
             len(stat[close + 2:].split()) >= 20, "PROCESS_STAT_INVALID")
        fields = stat[close + 2:].split()
        # field 22 (starttime), where fields[0] is field 3.
        start = fields[19]
        need(DECIMAL.fullmatch(start) is not None, "PROCESS_STAT_INVALID")
        cmdline = self.shell("cat", f"/proc/{pid}/cmdline")
        need(cmdline.rstrip("\x00\r\n") == PACKAGE and
             self.pid() == pid, "PROCESS_IDENTITY_DRIFT")
        boot = self.shell("cat", "/proc/sys/kernel/random/boot_id").strip()
        need(re.fullmatch(r"[0-9a-f-]{36}", boot) is not None,
             "BOOT_ID_INVALID")
        return int(start), cmdline, boot

    def same_process(self, pid: int, signature: tuple[int, str, str]) -> bool:
        if self.pid() != pid:
            return False
        return self.process_signature(pid) == signature

    def provider_state(self, *, timeout: float = 3.0) -> dict[str, Any]:
        return query_json(self.shell("content", "query", "--uri",
            "content://com.techrebbe.supernote.layoutfencetrial.probe/state",
            timeout=timeout))

    def provider_call(self, method: str, argument: str | None,
                      extras: dict[str, tuple[str, str]],
                      *, timeout: float = 3.0) -> dict[str, str]:
        need(method in {"prearm", "refresh", "command", "sentinel", "finish", "abort"},
             "CONTENT_METHOD_INVALID")
        argv = ["content", "call", "--uri",
                "content://com.techrebbe.supernote.layoutfencetrial.probe",
                "--method", method]
        if argument is not None:
            need(TOKEN.fullmatch(argument) is not None, "CONTENT_ARG_INVALID")
            argv += ["--arg", argument]
        for key in sorted(extras):
            kind, value = extras[key]
            need(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key) is not None and
                 kind in {"i", "l", "s"} and
                 TOKEN.fullmatch(value) is not None,
                 "CONTENT_EXTRA_INVALID")
            argv += ["--extra", f"{key}:{kind}:{value}"]
        return call_bundle(self.shell(*argv, timeout=timeout))


def verify_signed_apk(apksigner: Path, apk: Path, apk_sha: str,
                      signer_sha: str) -> None:
    file_sha(apk, apk_sha, maximum=100_000_000)
    need(apksigner.is_absolute() and apksigner.is_file() and
         not apksigner.is_symlink() and SHA.fullmatch(signer_sha) is not None,
         "APK_SIGNER_INPUT_INVALID")
    code, output = _invoke([str(apksigner), "verify", "--print-certs",
                            "--verbose", str(apk)], 6.0)
    need(code == 0, "APK_SIGNATURE_INVALID")
    digest_line = re.compile(
        r"Signer #([0-9]+) certificate SHA-256 digest: ([0-9a-f]{64})")
    matches = [match.groups() for line in output.split("\n")
               if (match := digest_line.fullmatch(line.removesuffix("\r"))) is not None]
    need(matches == [("1", signer_sha)], "APK_SIGNER_MISMATCH")


def verify_installed_apk(adb: ExactAdb, apk_sha: str) -> None:
    row = adb.shell("pm", "path", PACKAGE).strip()
    need(row.startswith("package:") and "\n" not in row,
         "INSTALLED_APK_AMBIGUOUS")
    path = row[len("package:"):]
    need(REMOTE_APK.fullmatch(path) is not None,
         "INSTALLED_APK_PATH_INVALID")
    remote = adb.shell("sha256sum", path).strip()
    need(remote == f"{apk_sha}  {path}" or remote == f"{apk_sha} {path}",
         "INSTALLED_APK_HASH_MISMATCH")


def _proc_start(adb: ExactAdb, pid: int) -> int:
    stat = adb.shell("cat", f"/proc/{pid}/stat").strip()
    close = stat.rfind(")")
    need(close > 0 and stat.startswith(f"{pid} (") and
         len(stat[close + 2:].split()) >= 20, "SERVER_STAT_INVALID")
    start = stat[close + 2:].split()[19]
    need(DECIMAL.fullmatch(start) is not None, "SERVER_STAT_INVALID")
    return int(start)


class OwnedFridaServer:
    """Own one staged binary, exact process incarnation, and one ADB forward.

    No cleanup operation is allowed on a changed identity. A failure may leave
    an owned artifact for manual review rather than target another process.
    """

    def __init__(self, adb: ExactAdb, binary: Path, digest: str) -> None:
        file_sha(binary, digest, maximum=120_000_000)
        self.adb = adb
        self.binary = binary
        self.digest = digest
        self.remote = f"/data/local/tmp/layout-frida-{digest[:16]}"
        need(SERVER_PATH.fullmatch(self.remote) is not None,
             "SERVER_PATH_INVALID")
        self.staged = False
        self.started = False
        self.launch_attempted = False
        self.forwarded = False
        self.pid: int | None = None
        self.start_ticks: int | None = None
        self.prior_forwards: list[str] | None = None

    def _forward_rows(self) -> list[str]:
        output = self.adb.run("forward", "--list")
        return [row.strip() for row in output.splitlines() if row.strip()]

    def _remote_listening(self) -> bool:
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            content = self.adb.shell("cat", table)
            for line in content.splitlines()[1:]:
                fields = line.split()
                if (len(fields) >= 4 and fields[1].endswith(":69A2") and
                        fields[3] == "0A"):
                    return True
        return False

    def prepare(self) -> None:
        prior = self._forward_rows()
        need(not self.staged and not self.started and not self.forwarded and
             not any("tcp:27042" in row for row in prior) and
             not self._remote_listening() and
             self.adb.shell("pidof", "frida-server", allow_failure=True).strip() == "",
             "SERVER_OCCUPIED")
        self.prior_forwards = prior
        # The shell expression is constant except for a SHA-derived safe path.
        absent = self.adb.shell("sh", "-c",
                                f"[ ! -e {self.remote} ] && echo ABSENT")
        need(absent.strip() == "ABSENT", "SERVER_STAGE_OCCUPIED")
        self.adb.run("push", str(self.binary), self.remote, timeout=6.0)
        self.staged = True
        self.adb.shell("chmod", "700", self.remote)
        need(self.adb.shell("sha256sum", self.remote).strip() in
             {f"{self.digest}  {self.remote}", f"{self.digest} {self.remote}"},
             "SERVER_STAGE_HASH_MISMATCH")
        need(self.adb.shell(self.remote, "--version").strip() == "17.9.11",
             "SERVER_VERSION_MISMATCH")
        launch = (f"{self.remote} -l 127.0.0.1:27042 "
                  ">/dev/null 2>&1 & echo $!")
        self.launch_attempted = True
        value = self.adb.shell("sh", "-c", launch).strip()
        need(DECIMAL.fullmatch(value) is not None, "SERVER_START_INVALID")
        self.pid = int(value)
        self.start_ticks = _proc_start(self.adb, self.pid)
        self.started = True
        cmdline = self.adb.shell("cat", f"/proc/{self.pid}/cmdline")
        need(cmdline.split("\x00", 1)[0] == self.remote,
             "SERVER_IDENTITY_INVALID")
        expiry = time.monotonic() + 1.0
        while not self._remote_listening() and time.monotonic() < expiry:
            need(self._server_status() == "SAME", "SERVER_IDENTITY_DRIFT")
            time.sleep(0.05)
        need(self._remote_listening(), "SERVER_LISTEN_MISSING")
        self.adb.run("forward", "--no-rebind", "tcp:27042", "tcp:27042")
        self.forwarded = True
        need(sorted(self._forward_rows()) == sorted((self.prior_forwards or []) +
             [f"{SERIAL} tcp:27042 tcp:27042"]),
             "SERVER_FORWARD_INVALID")

    def _server_status(self) -> str:
        """SAME or confirmed GONE; unreadable identity raises UNKNOWN."""
        need(self.pid is not None and self.start_ticks is not None,
             "SERVER_IDENTITY_UNCERTAIN")
        presence = self.adb.shell("sh", "-c", f"if [ -d /proc/{self.pid} ]; "
                                  "then echo PRESENT; else echo ABSENT; fi").strip()
        need(presence in {"PRESENT", "ABSENT"}, "SERVER_PROC_UNCERTAIN")
        if presence == "ABSENT":
            return "GONE"
        current_start = _proc_start(self.adb, self.pid)
        if current_start != self.start_ticks:
            return "GONE"  # PID reused; the retained incarnation is gone.
        cmdline = self.adb.shell("cat", f"/proc/{self.pid}/cmdline")
        need(cmdline.split("\x00", 1)[0] == self.remote,
             "SERVER_OWNERSHIP_LOST")
        return "SAME"

    def cleanup(self) -> None:
        # A launch may have succeeded even when its PID/stat response was
        # lost. In that case neither the process nor staged binary may be
        # declared cleaned up from a guessed identity.
        uncertain = self.launch_attempted and not self.started
        if self.forwarded:
            try:
                need(sorted(self._forward_rows()) ==
                     sorted((self.prior_forwards or []) +
                            [f"{SERIAL} tcp:27042 tcp:27042"]),
                     "FORWARD_OWNERSHIP_LOST")
                self.adb.run("forward", "--remove", "tcp:27042")
                self.forwarded = False
                need(sorted(self._forward_rows()) ==
                     sorted(self.prior_forwards or []),
                     "FORWARD_CLEANUP_UNCERTAIN")
            except TrialError:
                uncertain = True
        if self.started:
            try:
                need(self._server_status() == "SAME", "SERVER_OWNERSHIP_LOST")
                self.adb.shell("kill", "-TERM", str(self.pid))
                expiry = time.monotonic() + 1.0
                status = self._server_status()
                while status == "SAME" and time.monotonic() < expiry:
                    time.sleep(0.05)
                    status = self._server_status()
                need(status == "GONE", "SERVER_EXIT_UNCERTAIN")
                self.started = False
            except TrialError:
                uncertain = True
        if self.staged and not self.started and not uncertain:
            try:
                need(not self._remote_listening(), "SERVER_LISTENER_REMAINING")
                processes = self.adb.shell("ps", "-A", "-o", "PID,ARGS")
                header = processes.splitlines()[0].split() if processes else []
                need(header == ["PID", "ARGS"] and
                     self.remote not in processes,
                     "SERVER_STAGE_STILL_IN_USE")
                actual = self.adb.shell("sha256sum", self.remote).strip()
                need(actual in {f"{self.digest}  {self.remote}",
                                f"{self.digest} {self.remote}"},
                     "SERVER_STAGE_OWNERSHIP_LOST")
                self.adb.shell("rm", self.remote)
                self.staged = False
            except TrialError:
                uncertain = True
        need(not uncertain, "SERVER_CLEANUP_UNCERTAIN")
