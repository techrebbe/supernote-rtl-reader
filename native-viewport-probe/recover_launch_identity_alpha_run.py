"""Exact, plan-bound recovery for alpha-20260917-020337Z-f27af080.

This is deliberately not a general cleanup utility.  It is pinned to one
failed run whose stock Document task and visual host remain live.  Plan mode
is read-only and is the default.  Execute mode requires the exact canonical
plan emitted by plan mode, creates a new O_EXCL ledger, and never guesses a
task, display, process, or file identity.

The failed runner's task parser rejected a legitimate Nomad supervisor tail.
This helper consequently separates the canonical per-display task list from
the redundant supervisor tail.  Task authority comes only from the canonical
list; every display-level supervisor summary is independently checked against
that list and cannot contribute task identity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable, NoReturn, Protocol, Sequence

import native_page_alpha_runner as alpha
import native_page_android_authority as android
import native_page_host_authority as host
import recover_orientation_source_alpha_run as prior


AUTHORITY = "native-page-alpha-launch-identity-recovery-v1"
PLAN_AUTHORITY = "native-page-alpha-launch-identity-recovery-plan-v1"
REPORT_RELATIVE = Path(
    "build/native-page-alpha-runs/alpha-20260917-020337Z-f27af080/report.json")
ACTIVE_RELATIVE = Path("build/native-page-alpha-runs") / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
RETIRED_BASENAME = "alpha-20260917-020337Z-f27af080-active-journal.retired.jsonl"
LEDGER_BASENAME = "launch-identity-recovery.jsonl"
EVIDENCE_BASENAME = "launch-identity-recovery-evidence.json"

REPORT_BYTES = 105_421
REPORT_SHA256 = "bd0ed2936693c58b2027f8c729f4ee16b127c82c95b2d304280e383b8042179c"
ACTIVE_BYTES = 82_094
ACTIVE_SHA256 = "3d5bf708704093f0eac01f0beb91e1ad9588474ed03dde1e64cabe17d47a9e5b"
ACTIVE_HEAD = "125c76506333cf469bda397d79d64f2e4608d267890d020fa34008552cf1fc00"
ACTIVE_ID = "16e26abd-9827-4ee4-92fc-eeed69ffa6e0"
ACTIVE_RECORDS = 12

RUNNER_BYTES = 281_850
RUNNER_SHA256 = "11ca5c31f6ce25d009f3a7c259202bda1180fd303001be3840337b32fdf92695"
ANDROID_BYTES = 47_398
ANDROID_SHA256 = "85401c12825935ecdbdae1e07e32ccedb4afaabdef30df0498d9a42b3e6b1a22"
HOST_BYTES = 52_293
HOST_SHA256 = "daec1201f090c1488af16745a52c50e0d114b9b96cacd1c1257f9292bed1d29e"

SESSION = "f1724fb7-ebba-4181-a438-b9ba8da3c1af"
GENERATION = 1
DISPLAY_ID = 2
HOST_PID = 28_990
HOST_START_TICKS = 3_038_998
HOST_UID = 10_142
DOCUMENT_PID = 22_015
DOCUMENT_UID = 1_000
DISPLAY_NAME = f"NativePageVisualOnly-{SESSION}-{GENERATION}"

TARGET_PDF = alpha.TARGET_PDF
TARGET_MARK = alpha.TARGET_MARK
PARKING_PDF = alpha.PARKING_PDF
PARKING_MARK = alpha.PARKING_MARK
ORIGINAL_PDF = alpha.SOURCE_PDF
ORIGINAL_MARK = alpha.SOURCE_MARK
TARGET_URI = alpha.TARGET_URI
STAGING_PDF = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "staging-b8fd4a74e7502245913d96721d800bac-pdf")
STAGING_MARK = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "staging-bd2f2991cadca6c3d66e268a07672673-mark")
QUARANTINE_PDF = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "quarantine-b23b79747e03650c5afedf130def7269-pdf")
QUARANTINE_MARK = (
    "/storage/emulated/0/Download/.NativeViewportVisualOnly-Alpha-2eeadd7-"
    "quarantine-805260ad905e9a4378b1b89a3820e153-mark")

ORIGINALS = {
    ORIGINAL_PDF: alpha.DeviceFile(
        ORIGINAL_PDF, "regular file", 4_678, 10_088, 10_088, 183_984, 54,
        "e470c33c6525e02acf88e51352d73b7ed8b6c1591be8d40629a42c708484e720"),
    ORIGINAL_MARK: alpha.DeviceFile(
        ORIGINAL_MARK, "regular file", 5_756, 10_088, 10_088, 185_219, 54,
        "b95c02b05abd9a4f5a3106ffbe442f1f893256a66f8cac3628f04d300992ffd6"),
}
PARKING = alpha.DeviceFile(
    PARKING_PDF, "regular file", 4_678, 10_088, 10_088, 182_600, 54,
    ORIGINALS[ORIGINAL_PDF].sha256)
TARGETS = {
    TARGET_PDF: alpha.DeviceFile(
        TARGET_PDF, "regular file", 4_678, 10_088, 10_088, 186_723, 54,
        ORIGINALS[ORIGINAL_PDF].sha256),
    TARGET_MARK: alpha.DeviceFile(
        TARGET_MARK, "regular file", 5_756, 10_088, 10_088, 186_724, 54,
        ORIGINALS[ORIGINAL_MARK].sha256),
}
STAGING = {TARGET_PDF: STAGING_PDF, TARGET_MARK: STAGING_MARK}
QUARANTINES = {TARGET_PDF: QUARANTINE_PDF, TARGET_MARK: QUARANTINE_MARK}
PROTECTED_PATHS = frozenset({
    *ORIGINALS, PARKING_PDF, PARKING_MARK, *TARGETS,
    STAGING_PDF, STAGING_MARK, QUARANTINE_PDF, QUARANTINE_MARK,
})

MAX_LOCAL_BYTES = 2 * 1024 * 1024
MAX_ACTIVITY_BYTES = 8 * 1024 * 1024
POLL_SECONDS = 0.20
POLL_LIMIT = 60


class RecoveryError(RuntimeError):
    """The exact retained-run authority is insufficient or changed."""


class MutationTransportUncertain(RecoveryError):
    """A one-shot mutation reply was lost; only observation may settle it."""


def _fail(message: str) -> NoReturn:
    raise RecoveryError(message)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=True, sort_keys=True,
            separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as error:
        raise RecoveryError("value is not canonical JSON data") from error


def _sha(raw: bytes) -> str:
    return prior._sha(raw)  # type: ignore[attr-defined]


def _canonical_sha(value: Any) -> str:
    return _sha(_canonical(value))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON contains a duplicate key")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError(label + " is not strict canonical JSON") from error
    if type(value) is not dict or _canonical(value) != raw:
        _fail(label + " is not one canonical JSON object")
    return value


def _read_regular(path: Path, maximum: int, label: str) -> tuple[bytes, dict[str, Any]]:
    raw, identity = prior._read_regular(path, maximum, label)  # type: ignore[attr-defined]
    return raw, identity


def _write_exclusive(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    raw = _canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        _fail("publication path is already occupied: " + str(path))
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags, 0o600)
    try:
        created = os.fstat(descriptor)
        if (not stat.S_ISREG(created.st_mode) or created.st_nlink != 1 or
                os.write(descriptor, raw) != len(raw)):
            _fail("exclusive publication failed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    prior._fsync_directory(path.parent)  # type: ignore[attr-defined]
    observed, identity = _read_regular(path, len(raw), "exclusive publication")
    if observed != raw:
        _fail("exclusive publication reread differs")
    return identity


def _verify_active_journal(raw: bytes) -> None:
    lines = raw.splitlines()
    if len(lines) != ACTIVE_RECORDS or raw[-1:] != b"\n":
        _fail("active mutation journal framing differs")
    previous: str | None = None
    for index, line in enumerate(lines):
        try:
            record = json.loads(line.decode("ascii"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RecoveryError("active journal is not canonical JSONL") from error
        if (type(record) is not dict or record.get("sequence") != index or
                record.get("journalId") != ACTIVE_ID or
                record.get("authority") != "native-page-alpha-mutation-journal-v1" or
                record.get("previousRecordSha256") != previous):
            _fail("active journal chain metadata differs")
        digest = record.get("recordSha256")
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            _fail("active journal record digest is malformed")
        unsigned = dict(record)
        del unsigned["recordSha256"]
        if _canonical_sha(unsigned) != digest:
            _fail("active journal record digest differs")
        previous = digest
    if previous != ACTIVE_HEAD:
        _fail("active journal head differs")


@dataclass(frozen=True)
class Authority:
    root: Path
    report_path: Path
    active_path: Path
    retired_path: Path
    ledger_path: Path
    evidence_path: Path
    report_identity: dict[str, Any]
    active_identity: dict[str, Any]
    dependency_identities: dict[str, dict[str, Any]]


def _device_file(value: Any, expected: alpha.DeviceFile, label: str) -> None:
    if type(value) is not dict or value != asdict(expected):
        _fail(label + " differs from the fixed run")


def load_authority(root: Path) -> Authority:
    root = root.resolve()
    report_path = (root / REPORT_RELATIVE).absolute()
    active_path = (root / ACTIVE_RELATIVE).absolute()
    run_dir = report_path.parent
    retired_path = run_dir / RETIRED_BASENAME
    ledger_path = run_dir / LEDGER_BASENAME
    evidence_path = run_dir / EVIDENCE_BASENAME
    if not os.path.lexists(active_path) or os.path.lexists(retired_path):
        _fail("the fixed active journal is absent or already retired")
    report_raw, report_identity = _read_regular(
        report_path, 128 * 1024, "fixed failed-run report")
    active_raw, active_identity = _read_regular(
        active_path, 256 * 1024, "fixed active mutation journal")
    if (len(report_raw) != REPORT_BYTES or report_identity["sha256"] != REPORT_SHA256 or
            len(active_raw) != ACTIVE_BYTES or active_identity["sha256"] != ACTIVE_SHA256):
        _fail("report or active journal bytes differ from the fixed run")
    _verify_active_journal(active_raw)
    try:
        report = json.loads(report_raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError("fixed report is not strict JSON") from error
    if (type(report) is not dict or report.get("authority") != alpha.AUTHORITY or
            report.get("authorizedSerial") != alpha.AUTHORIZED_SERIAL or
            report.get("checkpoint") != alpha.CHECKPOINT or
            report.get("result") != "ALPHA_FAILED_OR_CLEANUP_UNCERTAIN" or
            report.get("primaryError") !=
            "CleanupUncertain: Document launch may have occurred but no exact task identity was derivable; no guessed task cleanup was attempted" or
            report.get("documentLaunchAttempted") is not True or
            report.get("launchOwned") is not False or report.get("foreign") is not None or
            report.get("host") != {"displayId": DISPLAY_ID, "generation": GENERATION,
                                   "hostPid": HOST_PID, "session": SESSION}):
        _fail("failed report semantic state differs")
    events = report.get("events")
    ready = [item for item in events if type(item) is dict and
             item.get("name") == "host_ready"] if type(events) is list else []
    if (len(ready) != 1 or ready[0].get("hostStartTicks") != str(HOST_START_TICKS) or
            ready[0].get("displayId") != DISPLAY_ID or
            ready[0].get("generation") != GENERATION or
            ready[0].get("session") != SESSION):
        _fail("host-ready authority differs")
    fixture = report.get("fixture")
    obligations = fixture.get("cleanupObligations") if type(fixture) is dict else None
    mutation = fixture.get("mutationJournal") if type(fixture) is dict else None
    if (type(obligations) is not dict or set(obligations) != set(TARGETS) or
            type(mutation) is not dict or mutation.get("journalId") != ACTIVE_ID or
            mutation.get("fileSha256") != ACTIVE_SHA256 or
            mutation.get("headSha256") != ACTIVE_HEAD or
            mutation.get("recordCount") != ACTIVE_RECORDS or
            mutation.get("size") != ACTIVE_BYTES or mutation.get("retired") is not False):
        _fail("fixture/journal authority differs")
    for path, expected in TARGETS.items():
        obligation = obligations[path]
        _device_file(obligation.get("retained"), expected, "retained target")
        _device_file(obligation.get("publish_move_target_observed"), expected,
                     "published target")
        staged = alpha.DeviceFile(
            STAGING[path], expected.kind, expected.size, expected.uid, expected.gid,
            expected.inode, expected.device, expected.sha256)
        _device_file(obligation.get("staging_post_copy_observed"), staged,
                     "published staging identity")
        if (obligation.get("staging_path") != STAGING[path] or
                obligation.get("quarantine_path") != QUARANTINES[path] or
                obligation.get("publish_move_postcondition") != "stage-absent/target-exact" or
                obligation.get("quarantine_move_attempted") is not False or
                obligation.get("quarantine_remove_attempted") is not False):
            _fail("cleanup obligation state differs")
    dependencies: dict[str, dict[str, Any]] = {}
    for name, size, digest in (
            ("native_page_alpha_runner.py", RUNNER_BYTES, RUNNER_SHA256),
            ("native_page_android_authority.py", ANDROID_BYTES, ANDROID_SHA256),
            ("native_page_host_authority.py", HOST_BYTES, HOST_SHA256)):
        raw, identity = _read_regular(root / name, size, name)
        if len(raw) != size or identity["sha256"] != digest:
            _fail(name + " differs from the pinned dependency")
        dependencies[name] = identity
    return Authority(
        root, report_path, active_path, retired_path, ledger_path, evidence_path,
        report_identity, {**active_identity, "path": str(active_path)}, dependencies)


def _display_summary_split(raw: bytes) -> tuple[bytes, str, tuple[tuple[int, int], ...]]:
    """Separate task authority from the redundant supervisor summaries.

    The returned prefix is the only input to task parsers.  The suffix is
    nevertheless structurally checked: its one display summary per canonical
    display must use the same order and exact stack count.  This fixes the
    failed runner's final-display tail scope without borrowing task identity
    from a supervisor echo.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_ACTIVITY_BYTES:
        _fail("ActivityManager wire is absent or oversized")
    text, digest = android._wire(raw)  # type: ignore[attr-defined]
    boundary = "ActivityStackSupervisor state:\n"
    if text.count(boundary) != 1:
        _fail("ActivityManager supervisor boundary is absent or ambiguous")
    prefix, suffix = text.split(boundary, 1)
    if not prefix.endswith("\n") or "ActivityStackSupervisor state:" in prefix:
        _fail("ActivityManager authority prefix is malformed")
    display_matches = list(re.finditer(
        r"^Display #([0-9]+) \(activities from top to bottom\):$",
        prefix, re.MULTILINE))
    if not display_matches:
        _fail("ActivityManager canonical display list is absent")
    expected: list[tuple[int, int]] = []
    seen: set[int] = set()
    for index, match in enumerate(display_matches):
        display_id = int(match.group(1), 10)
        if display_id > 1024 or display_id in seen:
            _fail("ActivityManager canonical display ID is invalid or duplicated")
        seen.add(display_id)
        end = (display_matches[index + 1].start()
               if index + 1 < len(display_matches) else len(prefix))
        block = prefix[match.end():end]
        count = len(re.findall(r"^  Stack #[0-9]+:[^\n]*$", block, re.MULTILINE))
        expected.append((display_id, count))
    summary_like = [line for line in suffix.splitlines()
                    if line.lstrip().startswith("Display:")]
    summary_pattern = re.compile(r"^  Display: mDisplayId=([0-9]+) stacks=([0-9]+)$")
    summaries: list[tuple[int, int]] = []
    for line in summary_like:
        match = summary_pattern.fullmatch(line)
        if match is None:
            _fail("ActivityManager display summary is malformed")
        summaries.append((int(match.group(1), 10), int(match.group(2), 10)))
    if tuple(summaries) != tuple(expected):
        _fail("ActivityManager display summaries disagree with canonical displays")
    return prefix.encode("utf-8"), digest, tuple(summaries)


def _root_task_blocks(prefix: bytes) -> list[tuple[int, int, str]]:
    text, _ = android._wire(prefix)  # type: ignore[attr-defined]
    canonical = android._reject_malformed_structural_headers(text)  # type: ignore[attr-defined]
    result: list[tuple[int, int, str]] = []
    for display_id, stack_id, stack in android._display_stack_blocks(canonical):  # type: ignore[attr-defined]
        tasks = android._task_blocks(stack)  # type: ignore[attr-defined]
        if len(tasks) > 1:
            # Multiple children are legal on unrelated stacks, but cannot be a
            # removal candidate; preserve the block for ambiguity rejection.
            for task in tasks:
                result.append((display_id, stack_id, task))
        elif tasks:
            result.append((display_id, stack_id, tasks[0]))
    return result


def _exact_intent(task: str) -> None:
    alpha.AlphaSession._assert_exact_document_intent(task, "fixture")


def _derive_document(prefix: bytes, process: host.ProcessIdentity,
                     fd_targets: frozenset[str]) -> dict[str, Any]:
    authority = android.parse_document_task_authority(
        prefix, expected_pid=process.pid, require_live=True)
    if (process != host.ProcessIdentity(DOCUMENT_PID, process.start_ticks,
                                       DOCUMENT_UID, alpha.DOCUMENT_PACKAGE) or
            authority.display_id != DISPLAY_ID or authority.stack_id != authority.task_id or
            (authority.width, authority.height, authority.density_dpi,
             authority.rotation) != (1404, 1872, 300, 0) or
            authority.base_apk_path != alpha.DOCUMENT_APK):
        _fail("live Document authority differs from the retained viewport")
    candidates = [(display, stack, task) for display, stack, task in
                  _root_task_blocks(prefix)
                  if display == authority.display_id and stack == authority.stack_id]
    if len(candidates) != 1:
        _fail("Document root task scope is absent or ambiguous")
    task = candidates[0][2]
    direct_children = re.findall(r"^    \* Task\{[^\n]*\}$", task, re.MULTILINE)
    histories = re.findall(r"^      \* Hist #[0-9]+: ActivityRecord\{[^\n]*\}$",
                           task, re.MULTILINE)
    if len(direct_children) != 1 or len(histories) != 1:
        _fail("Document root-task removal is not one exact child/activity")
    _exact_intent(task)
    if (fd_targets != frozenset((TARGET_PDF, TARGET_MARK)) and
            fd_targets != frozenset((TARGET_PDF,))):
        _fail("Document descriptors escape the exact disposable fixture")
    return {
        "displayId": authority.display_id, "taskId": authority.task_id,
        "stackId": authority.stack_id, "taskToken": authority.task_token,
        "activityToken": authority.activity_token,
        "component": alpha.DOCUMENT_COMPONENT,
        "process": asdict(process), "fdTargets": sorted(fd_targets),
        "authoritySha256": android.stable_authority_sha256(authority),
    }


def _derive_host(prefix: bytes, process: host.ProcessIdentity,
                 host_apk: str) -> dict[str, Any]:
    if process != host.ProcessIdentity(
            HOST_PID, HOST_START_TICKS, HOST_UID, alpha.HOST_PACKAGE):
        _fail("live host process identity differs")
    short = alpha.HOST_PACKAGE + "/.NativePageHostActivity"
    full = alpha.HOST_COMPONENT
    candidates: list[tuple[int, int, str]] = []
    for display, stack, task in _root_task_blocks(prefix):
        if re.search(r"(?<!\S)(?:" + re.escape(short) + "|" +
                     re.escape(full) + r")(?=\s|\})", task):
            candidates.append((display, stack, task))
    if len(candidates) != 1:
        _fail("host task is absent or ambiguous")
    display, stack, task = candidates[0]
    headers = re.findall(r"^    \* Task\{([^\n]*)\}$", task, re.MULTILINE)
    histories = re.findall(
        r"^      \* Hist #0: ActivityRecord\{([0-9a-f]+) u0 (?:" +
        re.escape(short) + "|" + re.escape(full) + r") t([0-9]+)\}$",
        task, re.MULTILINE)
    task_match = re.search(
        r"^    \* Task\{([0-9a-f]+) #([0-9]+) visible=true [^\n]*"
        r"A=" + str(HOST_UID) + ":" + re.escape(alpha.HOST_PACKAGE) +
        r" U=0 StackId=([0-9]+) sz=1\}$", task, re.MULTILINE)
    app = re.findall(
        r"^          app=ProcessRecord\{[0-9a-f]+ ([0-9]+):" +
        re.escape(alpha.HOST_PACKAGE) + r"/([0-9]+)\}$", task, re.MULTILINE)
    base = re.findall(r"^          baseDir=([^\n]+)$", task, re.MULTILINE)
    if (display != 0 or len(headers) != 1 or len(histories) != 1 or
            task_match is None or len(app) != 1 or len(base) != 1 or
            int(task_match.group(2)) != stack or int(task_match.group(3)) != stack or
            int(histories[0][1]) != stack or app[0] != (str(HOST_PID), str(HOST_UID)) or
            base[0] != host_apk):
        _fail("host task/process/root scope differs")
    return {
        "displayId": display, "taskId": stack, "stackId": stack,
        "taskToken": task_match.group(1), "activityToken": histories[0][0],
        "component": full, "process": asdict(process), "baseApk": host_apk,
    }


def _fd_targets(links: str) -> frozenset[str]:
    return prior._validated_fd_targets(links)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class Observation:
    environment: dict[str, Any]
    host: dict[str, Any]
    document: dict[str, Any]
    display_summaries: tuple[tuple[int, int], ...]
    activity_sha256: str
    window_sha256: str
    display_sha256: str
    files: dict[str, dict[str, Any] | None]
    rotation: tuple[str, str]

    def wire(self) -> dict[str, Any]:
        return {
            "environment": self.environment, "host": self.host,
            "document": self.document,
            "displaySummaries": [list(item) for item in self.display_summaries],
            "activitySha256": self.activity_sha256,
            "windowSha256": self.window_sha256,
            "displaySha256": self.display_sha256,
            "files": self.files, "rotation": list(self.rotation),
        }


class Device(Protocol):
    history: list[dict[str, Any]]
    def adb_authority(self) -> dict[str, Any]: ...
    def environment(self) -> dict[str, Any]: ...
    def activities(self) -> bytes: ...
    def windows(self) -> bytes: ...
    def displays(self) -> bytes: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def package_path(self, package: str) -> str: ...
    def remove_task(self, task_id: int) -> alpha.CommandResult: ...
    def force_stop_document(self) -> alpha.CommandResult: ...
    def move_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult: ...
    def delete_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult: ...


def _result(operation: str, argv: tuple[str, ...], completed: Any) -> alpha.CommandResult:
    stdout, stderr = bytes(completed.stdout or b""), bytes(completed.stderr or b"")
    if len(stdout) > alpha.MAX_TEXT_BYTES or len(stderr) > alpha.MAX_TEXT_BYTES:
        _fail(operation + " returned oversized output")
    return alpha.CommandResult(operation, argv, int(completed.returncode), stdout, stderr)


def _validate_mutation_result(result: Any, operation: str) -> None:
    try:
        prior._validate_mutation_result(  # type: ignore[attr-defined]
            result, operation, empty_stdout=True)
    except prior.RecoveryError as error:
        raise RecoveryError(str(error)) from error


class Nomad(prior.RecoveryNomad):
    """Closed transport exposing only this recovery's fixed operations."""

    def activities(self) -> bytes:
        return self._require_zero(self._invoke(
            "activities", ("shell", "dumpsys", "activity", "activities")))

    def windows(self) -> bytes:
        return self._require_zero(self._invoke(
            "windows", ("shell", "dumpsys", "window", "windows")))

    def displays(self) -> bytes:
        return self._require_zero(self._invoke(
            "displays", ("shell", "dumpsys", "display")))

    def package_path(self, package: str) -> str:
        if package not in {alpha.HOST_PACKAGE, alpha.DOCUMENT_PACKAGE}:
            _fail("package path escaped the fixed recovery package set")
        result = self._invoke("package_path", ("shell", "pm", "path", package))
        text = self._require_zero(result).decode("ascii").strip()
        if package == alpha.DOCUMENT_PACKAGE:
            expected = "package:" + alpha.DOCUMENT_APK
            if text != expected:
                _fail("stock Document package path is malformed")
            return alpha.DOCUMENT_APK
        match = re.fullmatch(r"package:(/data/app/[^\s]+/base\.apk)", text)
        if match is None:
            _fail("host package path is malformed")
        return match.group(1)

    def _mutation(self, operation: str, tail: tuple[str, ...]) -> alpha.CommandResult:
        argv = (self.adb, "-s", alpha.AUTHORIZED_SERIAL, "exec-out", *tail)
        started = time.monotonic_ns()
        try:
            completed = self._executor(
                argv, capture_output=True, timeout=alpha.STEP_TIMEOUT_SECONDS,
                check=False)
        except subprocess.TimeoutExpired as error:
            self.history.append({"operation": operation, "argv": list(argv),
                                 "startedNs": str(started),
                                 "finishedNs": str(time.monotonic_ns()),
                                 "returncode": None, "timeout": True})
            raise MutationTransportUncertain(operation + " reply was lost") from error
        value = _result(operation, argv, completed)
        self.history.append({
            "operation": operation, "argv": list(argv),
            "startedNs": str(started), "finishedNs": str(time.monotonic_ns()),
            "returncode": value.returncode,
            "stdoutSha256": _sha(value.stdout), "stderrSha256": _sha(value.stderr)})
        return value

    def remove_task(self, task_id: int) -> alpha.CommandResult:
        if type(task_id) is not int or not 1 <= task_id <= 10_000_000:
            _fail("task removal ID is invalid")
        return self._mutation("remove_exact_task", (
            "shell", "am", "stack", "remove", str(task_id)))

    def force_stop_document(self) -> alpha.CommandResult:
        return self._mutation("force_stop_document", (
            "shell", "am", "force-stop", "--user", "0", alpha.DOCUMENT_PACKAGE))

    def move_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult:
        return self._file_mutation("move", source, quarantine)

    def delete_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult:
        return self._file_mutation("delete", source, quarantine)

    def _file_mutation(self, mode: str, source: str,
                       quarantine: str) -> alpha.CommandResult:
        if (mode not in {"move", "delete"} or source not in TARGETS or
                QUARANTINES[source] != quarantine):
            _fail("file mutation escaped fixed authority")
        expected = TARGETS[source]
        current_path = source if mode == "move" else quarantine
        opposite = quarantine if mode == "move" else source
        stat_wire = ",".join((expected.kind, str(expected.size), str(expected.uid),
                              str(expected.gid), str(expected.inode),
                              str(expected.device), "1"))
        script = (
            "set -f; current=$1; opposite=$2; digest=$3; stat_wire=$4; "
            "[ ! -L \"$current\" ] || exit 71; "
            "actual=$(stat -c '%F,%s,%u,%g,%i,%d,%h' \"$current\" 2>/dev/null) || exit 72; "
            "[ \"$actual\" = \"$stat_wire\" ] || exit 73; "
            "sum=$(sha256sum \"$current\" 2>/dev/null) || exit 74; "
            "set -- $sum; [ \"$#\" -eq 2 ] && [ \"$1\" = \"$digest\" ] "
            "&& [ \"$2\" = \"$current\" ] || exit 75; "
            "[ ! -e \"$opposite\" ] && [ ! -L \"$opposite\" ] || exit 76; " +
            ("exec toybox mv -n -T \"$current\" \"$opposite\"" if mode == "move"
             else "exec toybox rm -f \"$current\""))
        operation = (("recovery_quarantine_" + Path(source).name)
                     if mode == "move" else
                     ("recovery_remove_" + Path(quarantine).name))
        return self._mutation(operation, (
            "shell", "sh", "-c", script, "fixed-launch-recovery",
            current_path, opposite, expected.sha256, stat_wire))


def _file_wire(value: alpha.DeviceFile | None) -> dict[str, Any] | None:
    return None if value is None else asdict(value)


def _assert_file_set(device: Device, phase: str) -> dict[str, dict[str, Any] | None]:
    values: dict[str, dict[str, Any] | None] = {}
    for path in sorted(PROTECTED_PATHS):
        value = device.stat_file(path, absent_ok=True)
        values[path] = _file_wire(value)
        if path in ORIGINALS and value != ORIGINALS[path]:
            _fail(phase + ": original file identity changed")
        if path == PARKING_PDF and value != PARKING:
            _fail(phase + ": parking PDF identity changed")
        if path == PARKING_MARK and value is not None:
            _fail(phase + ": parking mark unexpectedly exists")
        if path in STAGING.values() and value is not None:
            _fail(phase + ": published staging leaf unexpectedly exists")
    return values


def _assert_window_tokens(raw: bytes, host_task: dict[str, Any],
                          document_task: dict[str, Any]) -> None:
    text = alpha._decode_text(raw, "window inventory")
    for label, task in (("host", host_task), ("Document", document_task)):
        component = task["component"]
        token = task["activityToken"]
        if text.count(component) < 1 or text.count(token) < 1:
            _fail(label + " task is not bound to a live WindowManager window")


def _assert_display(raw: bytes, host_process: host.ProcessIdentity) -> None:
    text = alpha._decode_text(raw, "display inventory")
    if text.count(DISPLAY_NAME) != 1:
        _fail("owned virtual display name is absent or ambiguous")
    selected = [block.group(0) for block in re.finditer(
        r"(?ms)^  Display " + str(DISPLAY_ID) + r":\s*\n.*?"
        r"(?=^  Display (?:0|[1-9][0-9]*):|\Z)", text)]
    if len(selected) != 1:
        _fail("owned virtual display logical record is absent or ambiguous")
    block = selected[0]
    required = (DISPLAY_NAME, "real 1404 x 1872", "density 300",
                "owner " + alpha.HOST_PACKAGE)
    if any(value not in block for value in required):
        _fail("owned virtual display geometry/owner differs")
    if host_process.uid != HOST_UID:
        _fail("owned display process UID differs")


def observe(device: Device) -> Observation:
    environment = device.environment()
    host_pids = device.pidof(alpha.HOST_PACKAGE)
    document_pids = device.pidof(alpha.DOCUMENT_PACKAGE)
    if host_pids != (HOST_PID,) or document_pids != (DOCUMENT_PID,):
        _fail("host or Document process is absent/ambiguous/drifted")
    host_process = device.process_identity(HOST_PID, alpha.HOST_PACKAGE)
    document_process = device.process_identity(DOCUMENT_PID, alpha.DOCUMENT_PACKAGE)
    activities = device.activities()
    prefix, activity_digest, summaries = _display_summary_split(activities)
    host_task = _derive_host(prefix, host_process,
                             device.package_path(alpha.HOST_PACKAGE))
    document_task = _derive_document(
        prefix, document_process,
        _fd_targets(device.process_fd_links(DOCUMENT_PID)))
    windows, displays = device.windows(), device.displays()
    _assert_window_tokens(windows, host_task, document_task)
    _assert_display(displays, host_process)
    files = _assert_file_set(device, "live observation")
    for path, expected in TARGETS.items():
        if files[path] != asdict(expected):
            _fail("disposable target identity differs")
        if files[QUARANTINES[path]] is not None:
            _fail("random quarantine leaf is already occupied")
    rotation = device.rotation_settings()
    if rotation != ("1", "2"):
        _fail("persisted rotation settings differ from restored 1/2")
    return Observation(
        environment, host_task, document_task, summaries, activity_digest,
        _sha(windows), _sha(displays), files, rotation)


def _stable_identity(observation: Observation) -> dict[str, Any]:
    value = observation.wire()
    # Dumpsys text hashes may carry harmless volatile counters.  Exact task,
    # process, summary, file, and rotation identities must be stable.
    value.pop("activitySha256")
    value.pop("windowSha256")
    value.pop("displaySha256")
    return value


def _assert_stable(first: Observation, second: Observation) -> None:
    if _stable_identity(first) != _stable_identity(second):
        _fail("live authority drifted between observations")


def _authority_guard(authority: Authority) -> None:
    _, report = _read_regular(authority.report_path, 128 * 1024, "fixed report")
    _, active = _read_regular(authority.active_path, 256 * 1024, "active journal")
    active = {**active, "path": str(authority.active_path)}
    if report != authority.report_identity or active != authority.active_identity:
        _fail("fixed report or active journal changed")
    for name, identity in authority.dependency_identities.items():
        _, current = _read_regular(authority.root / name, identity["size"], name)
        if current != identity:
            _fail(name + " changed after admission")


def build_plan(authority: Authority, device: Device) -> dict[str, Any]:
    _authority_guard(authority)
    first = observe(device)
    _authority_guard(authority)
    second = observe(device)
    _assert_stable(first, second)
    _authority_guard(authority)
    body = {
        "authority": PLAN_AUTHORITY, "schemaVersion": 1,
        "report": authority.report_identity,
        "activeJournal": authority.active_identity,
        "dependencies": authority.dependency_identities,
        "adb": device.adb_authority(),
        "first": first.wire(), "second": second.wire(),
        "mutationOrder": [
            "remove-exact-document-root-task",
            "remove-exact-host-root-task",
            "force-stop-document-only-if-same-process-retains-disposable-fds",
            "quarantine-delete-mark", "quarantine-delete-pdf",
            "archive-active-journal", "publish-evidence"],
        "protectedOriginals": {path: asdict(value) for path, value in ORIGINALS.items()},
        "persistentParking": asdict(PARKING),
    }
    return {**body, "bindingSha256": _canonical_sha(body)}


def load_plan(path: Path, authority: Authority) -> tuple[dict[str, Any], dict[str, Any]]:
    raw, identity = _read_regular(path, MAX_LOCAL_BYTES, "exact recovery plan")
    plan = _strict_json(raw, "exact recovery plan")
    binding = plan.get("bindingSha256")
    unsigned = dict(plan)
    unsigned.pop("bindingSha256", None)
    if (type(binding) is not str or binding != _canonical_sha(unsigned) or
            plan.get("authority") != PLAN_AUTHORITY or plan.get("schemaVersion") != 1 or
            plan.get("report") != authority.report_identity or
            plan.get("activeJournal") != authority.active_identity or
            plan.get("dependencies") != authority.dependency_identities):
        _fail("plan binding or exact-run authority differs")
    if plan.get("first") != plan.get("second"):
        # Raw dumpsys hashes may differ.  Compare stable projections below.
        for key in ("activitySha256", "windowSha256", "displaySha256"):
            plan["first"].pop(key, None)
            plan["second"].pop(key, None)
        if plan["first"] != plan["second"]:
            _fail("plan observations are not stable")
    return plan, identity


def _stable_plan_projection(plan: dict[str, Any]) -> dict[str, Any]:
    """Exclude only raw capture digests and their derived plan binding.

    The durable plan binding authenticates the original plan bytes, so it is
    retained separately in the execution ledger.  It cannot participate in
    the live stable-state comparison because it necessarily changes whenever
    one of the explicitly volatile dumpsys digests changes.
    """
    projected = dict(plan)
    projected.pop("bindingSha256", None)
    for side in ("first", "second"):
        observation = projected.get(side)
        if type(observation) is not dict:
            _fail("plan observation is malformed")
        stable = dict(observation)
        for key in ("activitySha256", "windowSha256", "displaySha256"):
            stable.pop(key, None)
        projected[side] = stable
    return projected


class Journal(prior.Journal):
    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("recovery ledger record is malformed")
        unsigned = {
            "authority": AUTHORITY, "kind": kind, "payload": payload,
            "previousSha256": (None if not self.records else
                               self.records[-1]["recordSha256"]),
            "sequence": len(self.records)}
        record = {**unsigned, "recordSha256": _canonical_sha(unsigned)}
        encoded = _canonical(record) + b"\n"
        self._assert_open_authority()
        if os.write(self._descriptor, encoded) != len(encoded):
            _fail("short recovery ledger write")
        os.fsync(self._descriptor)
        self._encoded += encoded
        self._assert_open_authority()
        prior._fsync_directory(self.path.parent)  # type: ignore[attr-defined]
        self.records.append(record)
        return record


def _poll(predicate: Callable[[], bool]) -> bool:
    for _ in range(POLL_LIMIT):
        if predicate():
            return True
        time.sleep(POLL_SECONDS)
    return False


def _document_task_absent(device: Device, pinned: dict[str, Any]) -> bool:
    try:
        prefix, _, _ = _display_summary_split(device.activities())
    except RecoveryError:
        return False
    text = alpha._decode_text(prefix, "post-remove activity inventory")
    token = pinned["activityToken"]
    component = pinned["component"]
    return token not in text and component not in text


def _host_task_absent_and_display_gone(device: Device,
                                       pinned: dict[str, Any]) -> bool:
    try:
        prefix, _, _ = _display_summary_split(device.activities())
        activity = alpha._decode_text(prefix, "post-host activity inventory")
        display = alpha._decode_text(device.displays(), "post-host display inventory")
    except RecoveryError:
        return False
    return (pinned["activityToken"] not in activity and
            pinned["component"] not in activity and
            DISPLAY_NAME not in display)


def _dispatch_one(journal: Journal, kind: str, operation: str,
                  identity: dict[str, Any],
                  action: Callable[[], alpha.CommandResult],
                  settled: Callable[[], bool]) -> None:
    journal.append(kind + "-intent", identity)
    error: BaseException | None = None
    result: alpha.CommandResult | None = None
    try:
        result = action()
        _validate_mutation_result(result, operation)
    except MutationTransportUncertain as caught:
        error = caught
    if not _poll(settled):
        journal.append(kind + "-unsettled", {
            "reply": None if result is None else result.returncode,
            "transportError": None if error is None else str(error)})
        _fail(kind + " did not reach its exact postcondition; no retry is permitted")
    journal.append(kind + "-settled", {
        "reply": None if result is None else result.returncode,
        "transportError": None if error is None else str(error)})


def _archive_active(authority: Authority, journal: Journal) -> None:
    _authority_guard(authority)
    if os.path.lexists(authority.retired_path):
        _fail("retired active-journal path is occupied")
    journal.append("archive-active-intent", {
        "source": str(authority.active_path), "target": str(authority.retired_path),
        "sha256": ACTIVE_SHA256})
    os.replace(authority.active_path, authority.retired_path)
    prior._fsync_directory(authority.active_path.parent)  # type: ignore[attr-defined]
    raw, identity = _read_regular(
        authority.retired_path, 256 * 1024, "retired active journal")
    if (len(raw) != ACTIVE_BYTES or identity["sha256"] != ACTIVE_SHA256 or
            os.path.lexists(authority.active_path)):
        _fail("active journal retirement did not reach exact postcondition")
    journal.append("archive-active-settled", identity)


def execute(authority: Authority, device: Device, plan: dict[str, Any],
            plan_identity: dict[str, Any]) -> dict[str, Any]:
    if os.path.lexists(authority.ledger_path) or os.path.lexists(authority.evidence_path):
        _fail("one-shot recovery ledger/evidence is already occupied")
    current_plan = build_plan(authority, device)
    # The plan's stable authority must still match.  Fresh raw hashes and the
    # binding derived from those hashes may vary; the original binding remains
    # authenticated by load_plan and is recorded in the recovery ledger.
    if _stable_plan_projection(current_plan) != _stable_plan_projection(plan):
        _fail("live authority no longer matches the exact plan")
    journal = Journal(authority.ledger_path, {
        "plan": plan_identity, "planBindingSha256": plan["bindingSha256"],
        "reportSha256": REPORT_SHA256, "activeJournalSha256": ACTIVE_SHA256})
    evidence: dict[str, Any] = {
        "authority": AUTHORITY, "schemaVersion": 1,
        "plan": plan_identity, "mutations": [], "result": "RECOVERY_PENDING"}
    try:
        before = observe(device)
        document = before.document
        host_task = before.host
        _dispatch_one(
            journal, "remove-document-task", "remove_exact_task", document,
            lambda: device.remove_task(document["taskId"]),
            lambda: _document_task_absent(device, document))
        _dispatch_one(
            journal, "remove-host-task", "remove_exact_task", host_task,
            lambda: device.remove_task(host_task["taskId"]),
            lambda: _host_task_absent_and_display_gone(device, host_task))

        pids = device.pidof(alpha.DOCUMENT_PACKAGE)
        if pids:
            if pids != (DOCUMENT_PID,):
                _fail("Document process changed after task removal")
            process = device.process_identity(DOCUMENT_PID, alpha.DOCUMENT_PACKAGE)
            if process != host.ProcessIdentity(
                    DOCUMENT_PID, before.document["process"]["start_ticks"],
                    DOCUMENT_UID, alpha.DOCUMENT_PACKAGE):
                _fail("Document process identity changed after task removal")
            targets = _fd_targets(device.process_fd_links(DOCUMENT_PID))
            if targets.intersection({TARGET_PDF, TARGET_MARK}):
                journal.append("force-stop-document-intent", {
                    "process": asdict(process), "fdTargets": sorted(targets)})
                error: BaseException | None = None
                result: alpha.CommandResult | None = None
                try:
                    result = device.force_stop_document()
                    _validate_mutation_result(result, "force_stop_document")
                except MutationTransportUncertain as caught:
                    error = caught
                if not _poll(lambda: not device.pidof(alpha.DOCUMENT_PACKAGE)):
                    journal.append("force-stop-document-unsettled", {
                        "reply": None if result is None else result.returncode,
                        "transportError": None if error is None else str(error)})
                    _fail("Document force-stop did not reach exact process absence")
                journal.append("force-stop-document-settled", {
                    "reply": None if result is None else result.returncode,
                    "transportError": None if error is None else str(error)})

        for source in (TARGET_MARK, TARGET_PDF):
            quarantine = QUARANTINES[source]
            expected = TARGETS[source]
            journal.append("quarantine-intent", {
                "source": source, "quarantine": quarantine,
                "identity": asdict(expected)})
            error = None
            result = None
            try:
                result = device.move_if_exact(source, quarantine)
                _validate_mutation_result(
                    result, "recovery_quarantine_" + Path(source).name)
            except MutationTransportUncertain as caught:
                error = caught
            moved = device.stat_file(quarantine, absent_ok=True)
            source_now = device.stat_file(source, absent_ok=True)
            renamed = alpha.DeviceFile(
                quarantine, expected.kind, expected.size, expected.uid, expected.gid,
                expected.inode, expected.device, expected.sha256)
            if moved != renamed or source_now is not None:
                journal.append("quarantine-unsettled", {"source": source})
                _fail("quarantine move did not reach exact postcondition")
            journal.append("quarantine-settled", {
                "source": source, "reply": None if result is None else result.returncode,
                "transportError": None if error is None else str(error)})
            journal.append("delete-quarantine-intent", {
                "source": source, "quarantine": quarantine,
                "identity": asdict(renamed)})
            error = None
            result = None
            try:
                result = device.delete_if_exact(source, quarantine)
                _validate_mutation_result(
                    result, "recovery_remove_" + Path(quarantine).name)
            except MutationTransportUncertain as caught:
                error = caught
            if (device.stat_file(quarantine, absent_ok=True) is not None or
                    device.stat_file(source, absent_ok=True) is not None):
                journal.append("delete-quarantine-unsettled", {"source": source})
                _fail("quarantine deletion did not reach exact postcondition")
            journal.append("delete-quarantine-settled", {
                "source": source, "reply": None if result is None else result.returncode,
                "transportError": None if error is None else str(error)})
            _assert_file_set(device, "post-delete")

        # Final global closure: no tasks, no virtual display, no disposable
        # targets/quarantines, originals and parking exact, rotation restored.
        activity = alpha._decode_text(device.activities(), "final activities")
        windows = alpha._decode_text(device.windows(), "final windows")
        displays = alpha._decode_text(device.displays(), "final displays")
        if (alpha.DOCUMENT_PACKAGE in activity or alpha.DOCUMENT_PACKAGE in windows or
                alpha.HOST_PACKAGE in activity or alpha.HOST_PACKAGE in windows or
                DISPLAY_NAME in displays):
            _fail("final task/window/display closure is not clean")
        files = _assert_file_set(device, "final closure")
        if any(files[path] is not None for path in (*TARGETS, *QUARANTINES.values())):
            _fail("final disposable file closure is not clean")
        if device.rotation_settings() != ("1", "2"):
            _fail("final persisted rotation settings differ")
        _archive_active(authority, journal)
        evidence.update({
            "result": "LAUNCH_IDENTITY_RECOVERED_CLEANLY",
            "finalFiles": files, "commands": list(device.history),
            "ledgerHeadSha256": journal.records[-1]["recordSha256"],
            "ledgerRecordCount": len(journal.records)})
        journal.append("evidence-intent", {
            "path": str(authority.evidence_path),
            "payloadSha256": _canonical_sha(evidence)})
        _write_exclusive(authority.evidence_path, evidence)
        return evidence
    finally:
        journal.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        help="new canonical plan path; required for plan mode")
    parser.add_argument("--plan", type=Path,
                        help="exact canonical plan consumed by --execute")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    authority = load_authority(root)
    device = Nomad(args.adb, alpha.AUTHORIZED_SERIAL)
    if args.execute:
        if args.plan is None or args.output is not None:
            _fail("execute requires --plan and forbids --output")
        plan, identity = load_plan(args.plan, authority)
        evidence = execute(authority, device, plan, identity)
        print(json.dumps({"result": evidence["result"],
                          "evidence": str(authority.evidence_path)}, sort_keys=True))
        return 0
    if args.plan is not None or args.output is None:
        _fail("read-only plan mode requires --output and forbids --plan")
    plan = build_plan(authority, device)
    identity = _write_exclusive(args.output, plan)
    print(json.dumps({"result": "PLAN_READY", "plan": str(args.output),
                      "sha256": identity["sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
