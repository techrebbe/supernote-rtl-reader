"""Exact continuation after the validated host-task removal stopped short.

This helper is bound to the partial recovery of
``alpha-20260916-190148Z-b28865bb``.  The prior one-shot recovery ledger is
immutable evidence: it contains exactly its header, the removal intent for
task 4646, and a validated zero/empty receipt for that dispatch.  This helper
never exposes or dispatches visual-host task removal.  It first settles the
already-completed removal from fresh absence evidence, then makes opening the
report-pinned parking PDF its first possible device mutation.

Plan mode is read-only.  Execute mode owns a new O_EXCL continuation ledger;
the old recovery ledger is never appended, renamed, or deleted.
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


AUTHORITY = "native-page-alpha-orientation-source-continuation-v1"
JOURNAL_ID = "0df2bd13-53ce-44e9-9d0f-9c02e3304e3a"
CONTINUATION_BASENAME = "orientation-source-continuation.jsonl"
EVIDENCE_BASENAME = "orientation-source-continuation-evidence.json"
PRIOR_RECOVERY_BYTES = 5_448
PRIOR_RECOVERY_SHA256 = (
    "1e5524d3d2efa7ed0141cfa637c40940a8c0f39952699363be31dc8976620aaa")
PRIOR_RECOVERY_HEAD = (
    "080c1f146a86d3d0a790e5314adfb9c5add8ef662892e265a801957292aa0fed")
PRIOR_RECORD_HASHES = (
    "2c63055cae26c680bdd9d15ad0958f0728abf305c94355d5afede8b1573591f0",
    "60c85c3caab1273cb3624df6fae61cc1495e30c710a7f1ec5ea290c117cfacc8",
    PRIOR_RECOVERY_HEAD,
)
PRIOR_HELPER_SHA256 = (
    "f18c0fdde6e305e89515bfc068e2964034953851c9edf1ccb5bcdd84d57ae725")
STABLE_AUTHORITY_SHA256 = (
    "7365dd3b3779ef51b547a8e6b12104b915a162404a0abee57bacb0594a367b5f")
PINNED_FREEZE_RESIDUE = (
    "  mLastDisplayFreezeDuration=+259ms due to Window{d295460 u0 "
    "com.techrebbe.supernote.nativepagehost/"
    "com.techrebbe.supernote.nativepagehost.NativePageHostActivity}")
PINNED_HOST_PROCESS_TOKEN = "9a99e5c"
PINNED_WINDOW_TOKEN = "d295460"
POLL_SECONDS = prior.POLL_SECONDS
POLL_LIMIT = prior.POLL_LIMIT
MAX_LOCAL_BYTES = prior.MAX_LOCAL_BYTES


class ContinuationError(prior.RecoveryError):
    """The exact partial recovery cannot be continued safely."""


class DocumentScopePresent(ContinuationError):
    """The one removed parking task/window has not yet left inventories."""


def _fail(message: str) -> NoReturn:
    raise ContinuationError(message)


@dataclass(frozen=True)
class Authority:
    root: Path
    run_dir: Path
    report_path: Path
    active_path: Path
    recovery_path: Path
    evidence_path: Path
    retired_path: Path
    report_identity: dict[str, Any]
    active_identity: dict[str, Any]
    active_present: bool
    prior_recovery_path: Path
    prior_recovery_identity: dict[str, Any]
    prior_recovery_summary: dict[str, Any]
    prior_helper_path: Path


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"),
                           object_pairs_hook=prior._unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContinuationError(label + " is not canonical JSON") from error
    if type(value) is not dict:
        _fail(label + " is not a JSON object")
    return value


def _read_sole_regular(
        path: Path, maximum: int, label: str,
        ) -> tuple[bytes, dict[str, Any]]:
    raw, identity = prior._read_regular(path, maximum, label)
    observed = os.lstat(path)
    if (not stat.S_ISREG(observed.st_mode) or
            stat.S_ISLNK(observed.st_mode) or observed.st_nlink != 1 or
            (observed.st_dev, observed.st_ino, observed.st_size,
             getattr(observed, "st_mtime_ns", None)) !=
            (identity["device"], identity["inode"], identity["size"],
             identity["mtimeNs"])):
        _fail(label + " is not a sole regular path")
    return raw, identity


def _read_prior_ledger(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw, identity = _read_sole_regular(
        path, 16 * 1024, "partial recovery ledger")
    if (len(raw) != PRIOR_RECOVERY_BYTES or
            identity["sha256"] != PRIOR_RECOVERY_SHA256):
        _fail("partial recovery ledger bytes differ")
    return raw, identity


def _validate_prior_ledger(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or b"\r" in raw:
        _fail("partial recovery ledger framing differs")
    encoded = raw.splitlines(keepends=True)
    if len(encoded) != 3 or any(not line.endswith(b"\n") for line in encoded):
        _fail("partial recovery ledger does not contain exactly three records")
    records = [_strict_json(line[:-1], "partial recovery record")
               for line in encoded]
    previous: str | None = None
    kinds = (
        "header", "released_host_task_remove_intent",
        "released_host_task_remove_dispatch_outcome")
    for index, record in enumerate(records):
        if set(record) != {
                "authority", "kind", "payload", "previousSha256",
                "recordSha256", "sequence"}:
            _fail("partial recovery record fields differ")
        if (record["authority"] != prior.AUTHORITY or
                record["kind"] != kinds[index] or
                record["sequence"] != index or
                record["previousSha256"] != previous or
                record["recordSha256"] != PRIOR_RECORD_HASHES[index]):
            _fail("partial recovery record topology differs")
        unsigned = dict(record)
        digest = unsigned.pop("recordSha256")
        if prior._canonical_sha(unsigned) != digest:
            _fail("partial recovery record hash chain differs")
        previous = digest
    if previous != PRIOR_RECOVERY_HEAD:
        _fail("partial recovery ledger head differs")

    header = records[0]["payload"]
    if (type(header) is not dict or header.get("authority") != prior.AUTHORITY or
            header.get("runId") != prior.RUN_ID or
            header.get("journalId") != prior.JOURNAL_ID or
            header.get("report", {}).get("sha256") != prior.REPORT_SHA256 or
            header.get("activeJournal", {}).get("sha256") !=
            prior.ACTIVE_JOURNAL_SHA256 or
            header.get("helper", {}).get("sha256") != PRIOR_HELPER_SHA256 or
            header.get("host") != {
                "displayId": prior.DISPLAY_ID,
                "generation": prior.GENERATION,
                "pid": prior.HOST_PID,
                "session": prior.SESSION,
                "startTicks": prior.HOST_START_TICKS,
                "uid": prior.HOST_UID,
            }):
        _fail("partial recovery header authority differs")
    intent = records[1]["payload"]
    if (type(intent) is not dict or intent.get("taskId") != prior.HOST_TASK_ID or
            intent.get("stableAuthoritySha256") != STABLE_AUTHORITY_SHA256):
        _fail("partial recovery removal intent differs")
    stable = intent.get("stableAuthority")
    if (type(stable) is not dict or stable.get("taskId") != prior.HOST_TASK_ID or
            stable.get("taskToken") != "93d94cf" or
            stable.get("activityToken") != "45537a9" or
            stable.get("processToken") != PINNED_HOST_PROCESS_TOKEN or
            stable.get("windowToken") != PINNED_WINDOW_TOKEN or
            stable.get("windowSessionToken") != "7171c1d" or
            stable.get("component") !=
            alpha.HOST_PACKAGE + "/.NativePageHostActivity" or
            stable.get("windowComponent") != alpha.HOST_COMPONENT or
            stable.get("process") != asdict(host.ProcessIdentity(
                prior.HOST_PID, prior.HOST_START_TICKS,
                prior.HOST_UID, alpha.HOST_PACKAGE)) or
            prior._canonical_sha(stable) != STABLE_AUTHORITY_SHA256):
        _fail("partial recovery stable host authority differs")
    receipt = records[2]["payload"]
    empty = prior._sha(b"")
    if receipt != {
            "mode": "VALIDATED_RECEIPT",
            "operation": "remove_exact_task",
            "receiptGrammar": "EXACT_EMPTY_STREAMS",
            "returncode": 0,
            "stderrSha256": empty,
            "stderrSize": 0,
            "stdoutSha256": empty,
            "stdoutSize": 0,
            }:
        _fail("partial recovery removal receipt differs")
    return {
        "recordCount": 3,
        "sha256": PRIOR_RECOVERY_SHA256,
        "head": PRIOR_RECOVERY_HEAD,
        "recordHashes": list(PRIOR_RECORD_HASHES),
        "stableAuthority": stable,
        "stableAuthoritySha256": STABLE_AUTHORITY_SHA256,
        "receipt": receipt,
        "priorHelper": header["helper"],
    }


def load_authority(root: Path, report_path: Path,
                   active_path: Path) -> Authority:
    base = prior.load_authority(root, report_path, active_path)
    if not base.active_present:
        _fail("active mutation journal was already retired")
    prior_path = base.run_dir / prior.RECOVERY_BASENAME
    raw, prior_identity = _read_prior_ledger(prior_path)
    summary = _validate_prior_ledger(raw)
    prior_helper_path = root.absolute() / "recover_orientation_source_alpha_run.py"
    helper_raw, helper_identity = prior._read_regular(
        prior_helper_path, MAX_LOCAL_BYTES, "prior recovery helper")
    if (prior._sha(helper_raw) != PRIOR_HELPER_SHA256 or
            helper_identity != summary["priorHelper"]):
        _fail("prior recovery helper identity differs from its ledger")
    if os.path.lexists(base.run_dir / prior.EVIDENCE_BASENAME):
        _fail("prior recovery unexpectedly published final evidence")
    return Authority(
        base.root, base.run_dir, base.report_path, base.active_path,
        base.run_dir / CONTINUATION_BASENAME,
        base.run_dir / EVIDENCE_BASENAME, base.retired_path,
        base.report_identity, base.active_identity, base.active_present,
        prior_path, prior_identity, summary, prior_helper_path)


def _assert_publication_paths_clear(authority: Authority, *,
                                    before_journal: bool) -> None:
    if not authority.active_present:
        _fail("active mutation journal is already retired")
    if os.path.lexists(authority.evidence_path):
        _fail("continuation evidence path is already occupied")
    if os.path.lexists(authority.retired_path):
        _fail("retired active-journal path is already occupied")
    if before_journal and os.path.lexists(authority.recovery_path):
        _fail("continuation journal path is already occupied")


class Journal(prior.Journal):
    """New one-shot ledger; the prior three-record ledger stays immutable."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.external_guard: Callable[[], None] | None = None
        super().__init__(path, header)

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.external_guard is not None:
            self.external_guard()
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("continuation journal record is malformed")
        unsigned = {
            "authority": AUTHORITY,
            "kind": kind,
            "payload": payload,
            "previousSha256": (
                None if not self.records else self.records[-1]["recordSha256"]),
            "sequence": len(self.records),
        }
        record = {**unsigned, "recordSha256": prior._canonical_sha(unsigned)}
        encoded = prior._canonical(record) + b"\n"
        self._assert_open_authority()
        if os.write(self._descriptor, encoded) != len(encoded):
            _fail("short continuation journal write")
        os.fsync(self._descriptor)
        self._encoded += encoded
        self._assert_open_authority()
        prior._fsync_directory(self.path.parent)
        self.records.append(record)
        return record

    def assert_authority(self) -> None:
        super().assert_authority()
        if self.external_guard is not None:
            self.external_guard()


class Device(Protocol):
    history: list[dict[str, Any]]
    def adb_authority(self) -> dict[str, Any]: ...
    def environment(self) -> dict[str, Any]: ...
    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def host_logs(self, pid: int) -> str: ...
    def host_processes(self) -> bytes: ...
    def absence_raw(self) -> tuple[bytes, bytes, bytes]: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def launch_parking(self) -> Any: ...
    def parking_identity(self) -> dict[str, Any]: ...
    def remove_parking_task(self, task_id: int) -> Any: ...
    def move_quarantine(self, source: str, target: str) -> Any: ...
    def remove_quarantine(self, path: str) -> Any: ...


class ContinuationNomad(prior.RecoveryNomad):
    """Closed transport with no usable generic/host task-removal entrypoint."""

    def activities(self) -> bytes:
        raw = super().activities()
        _complete_activity_envelope(raw)
        return raw

    def windows(self) -> bytes:
        raw = super().windows()
        _complete_window_envelope(raw)
        return raw

    def displays(self) -> bytes:
        raw = super().displays()
        _strict_display0_state(raw)
        return raw

    def host_processes(self) -> bytes:
        result = self._invoke(
            "host_processes", ("shell", "dumpsys", "activity", "processes"))
        return self._require_zero(result)

    def _parking_ui_evidence_once(self) -> dict[str, Any]:
        retained = getattr(self, "_retained_parking_ui_evidence", None)
        if retained is not None:
            return retained
        try:
            ui_raw = self.ui_dump()
            try:
                ui = alpha.parse_parking_ui_witness(ui_raw)
                retained = {
                    "mode": "PARSED", "semantic": ui,
                    "rawSha256": prior._sha(ui_raw), "size": len(ui_raw),
                }
            except Exception as error:
                retained = {
                    "mode": "UNAVAILABLE", "errorType": type(error).__name__,
                    "error": str(error), "rawSha256": prior._sha(ui_raw),
                    "size": len(ui_raw),
                }
        except Exception as error:
            retained = {
                "mode": "UNAVAILABLE", "errorType": type(error).__name__,
                "error": str(error),
            }
        self._retained_parking_ui_evidence = retained
        return retained

    def parking_identity(self) -> dict[str, Any]:
        # Optional UI is sampled once *before* all authoritative state.  It can
        # neither strand the one-shot task nor open a stale-ID window between
        # the final AM/WM/FD/process capture and numeric removal.
        ui_evidence = self._parking_ui_evidence_once()
        pids = self.pidof(alpha.DOCUMENT_PACKAGE)
        if len(pids) != 1:
            _fail("parking launch lacks one stock Document process")
        process_before = self.process_identity(pids[0], alpha.DOCUMENT_PACKAGE)
        raw = self.activities()
        windows = self.windows()
        authority = android.parse_document_task_authority(
            raw, expected_pid=process_before.pid, require_live=True)
        if (authority.display_id != 0 or
                authority.stack_id != authority.task_id or
                authority.base_apk_path != alpha.DOCUMENT_APK or
                authority.density_dpi != 300 or
                authority.rotation not in range(4) or
                (authority.width, authority.height) not in {
                    (1404, 1872), (1872, 1404)}):
            _fail("parking task differs from stock physical-display authority")
        task_block = alpha.AlphaSession._assert_exact_stack_scope(
            raw, authority)
        if (task_block.count("intent={") != 1 or
                "act=" + alpha.DOCUMENT_LAUNCH_ACTION not in task_block or
                "dat=" + alpha.PARKING_URI not in task_block or
                "typ=" + alpha.DOCUMENT_LAUNCH_MIME not in task_block or
                not any("cmp=" + component in task_block
                        for component in alpha._document_components())):
            _fail("parking task lacks the exact ACTION_VIEW intent")
        scope = prior._assert_sole_document_scope(
            raw, windows, authority, process_before)
        targets = prior._validated_fd_targets(
            self.process_fd_links(process_before.pid))
        if targets != frozenset((alpha.PARKING_PDF,)):
            _fail("parking process descriptors are not parking-only")
        process_after = self.process_identity(pids[0], alpha.DOCUMENT_PACKAGE)
        if process_after != process_before:
            _fail("stock Document process changed during parking capture")
        return {
            "process": asdict(process_before), "taskId": authority.task_id,
            "displayId": authority.display_id,
            "authoritySha256": android.stable_authority_sha256(authority),
            "activityToken": authority.activity_token,
            "documentAuthority": asdict(authority),
            "documentScope": scope["stable"],
            "uiEvidence": ui_evidence, "fdTargets": sorted(targets),
            "activitiesSha256": prior._sha(raw),
            "windowsSha256": scope["evidence"]["windowsSha256"],
        }

    def remove_task(self, task_id: int) -> Any:
        del task_id
        _fail("generic task removal is unavailable in continuation")

    def remove_parking_task(self, task_id: int) -> alpha.CommandResult:
        if (type(task_id) is not int or task_id <= 0 or
                task_id == prior.HOST_TASK_ID):
            _fail("parking removal task ID is outside the continuation domain")
        return prior.RecoveryNomad.remove_task(self, task_id)


def _process_inventory_text(raw: bytes) -> tuple[str, dict[str, int]]:
    """Authenticate the complete pinned-firmware process-dump envelope."""
    text = alpha._decode_text(raw, "host process inventory")
    if (not text.endswith("\n") or not text.startswith(
            "ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)\n"
            "  All known processes:\n") or
            not text.endswith("\n  mForceBackgroundCheck=false\n")):
        _fail("host process inventory framing is truncated or malformed")
    section_patterns = {
        "uid": r"(?m)^  UID states:$",
        "oom": (r"(?m)^  Process OOM control \([1-9][0-9]* total, "
                r"non-act at [0-9]+, non-svc at [0-9]+\):$"),
        "lru": (r"(?m)^  Process LRU list \(sorted by oom_adj, "
                r"[1-9][0-9]* total, non-act at [0-9]+, "
                r"non-svc at [0-9]+\):$"),
        "pid": r"(?m)^  PID mappings:$",
        "services": r"(?m)^  ServiceManager statistics:$",
    }
    indexes: dict[str, int] = {}
    for label, pattern in section_patterns.items():
        matches = list(re.finditer(pattern, text))
        if len(matches) != 1:
            _fail("host process inventory " + label +
                  " section is absent or ambiguous")
        indexes[label] = matches[0].start()
    if [indexes[key] for key in ("oom", "uid", "lru", "pid", "services")] != sorted(
            indexes.values()):
        _fail("host process inventory section order differs")
    if text.count("\n    Stats:\n") != 1:
        _fail("host process inventory service statistics are ambiguous")
    return text, indexes


def _absent_process_semantics(raw: bytes, stable: dict[str, Any]) -> dict[str, Any]:
    text, _ = _process_inventory_text(raw)
    forbidden = (
        alpha.HOST_PACKAGE,
        str(stable["processToken"]),
        "PID #" + str(prior.HOST_PID) + ":",
        " " + str(prior.HOST_PID) + ":" + alpha.HOST_PACKAGE + "/",
    )
    if any(marker in text for marker in forbidden):
        _fail("host process inventory still contains the removed host")
    return {"rawSha256": prior._sha(raw), "hostRecords": 0}


def _cached_process_semantics(raw: bytes, stable: dict[str, Any]) -> dict[str, Any]:
    text, sections = _process_inventory_text(raw)
    token = stable["processToken"]
    package = alpha.HOST_PACKAGE
    pattern = re.compile(
        r"(?m)^  \*APP\* UID " + str(prior.HOST_UID) +
        r" ProcessRecord\{" + re.escape(token) + r" " +
        str(prior.HOST_PID) + r":" + re.escape(package) +
        r"/u0a" + str(prior.HOST_UID - 10_000) + r"\}\s*$")
    headers = list(pattern.finditer(text))
    if len(headers) != 1:
        _fail("cached host process record is absent or ambiguous")
    start = headers[0].start()
    following = re.search(r"(?m)^  \*APP\* UID ",
                          text[headers[0].end():sections["oom"]])
    end = (sections["oom"] if following is None else
           headers[0].end() + following.start())
    block = text[start:end]
    required = (
        r"(?m)^    pid=" + str(prior.HOST_PID) + r" starting=false\s*$",
        r"(?m)^    packageList=\{" + re.escape(package) + r"\}\s*$",
        r"(?m)^    curProcState=19 .* setProcState=19 .*\s*$",
        r"(?m)^    cached=true empty=true\s*$",
    )
    if any(len(re.findall(value, block)) != 1 for value in required):
        _fail("cached host process is not exact empty state 19")
    if (re.search(r"(?m)^    cached=false\b|^    empty=false\b", block) is not None or
            "ActivityRecord{" in block):
        _fail("cached host process still owns activity state")
    records = re.findall(
        r"ProcessRecord\{([0-9a-f]+) ([1-9][0-9]*):" +
        re.escape(package) + r"/u0a([1-9][0-9]*)\}", text)
    if (not records or any(value != (
            token, str(prior.HOST_PID), str(prior.HOST_UID - 10_000))
            for value in records)):
        _fail("host process inventory contains another process identity")
    summary_pattern = re.compile(
        r"(?m)^    Proc #[ 0-9]+: [^\r\n]* " + str(prior.HOST_PID) +
        r":" + re.escape(package) + r"/u0a" +
        str(prior.HOST_UID - 10_000) + r" \(cch-empty\)\s*$")
    oom_region = text[sections["oom"]:sections["uid"]]
    lru_region = text[sections["lru"]:sections["pid"]]
    if (len(summary_pattern.findall(oom_region)) != 1 or
            len(summary_pattern.findall(lru_region)) != 1 or
            len(summary_pattern.findall(text)) != 2):
        _fail("cached host process OOM/LRU aliases are absent or ambiguous")
    pid_record = (
        "    PID #" + str(prior.HOST_PID) + ": ProcessRecord{" + token + " " +
        str(prior.HOST_PID) + ":" + package + "/u0a" +
        str(prior.HOST_UID - 10_000) + "}")
    if text.splitlines().count(pid_record) != 1:
        _fail("cached host PID mapping is absent or ambiguous")
    return {
        "processToken": token,
        "cached": True,
        "empty": True,
        "procState": 19,
        "rawSha256": prior._sha(raw),
    }


def _complete_window_envelope(raw: bytes) -> tuple[str, list[str], int]:
    text = alpha._decode_text(raw, "WindowManager inventory")
    if (not text.endswith("\n") or
            not text.startswith("WINDOW MANAGER WINDOWS (dumpsys window windows)\n") or
            not text.endswith(
                "  PolicyControl.sImmersivePreconfirmationsFilter=null\n")):
        _fail("WindowManager inventory framing is truncated or malformed")
    lines = text.splitlines()
    window_indexes = [index for index, line in enumerate(lines)
                      if re.match(r"^  Window #[0-9]+ Window\{", line)]
    global_indexes = [index for index, line in enumerate(lines)
                      if line.startswith("  mGlobalConfiguration=")]
    if (not window_indexes or len(global_indexes) != 1 or
            any(index >= global_indexes[0] for index in window_indexes)):
        _fail("WindowManager structural boundary is absent or ambiguous")
    global_index = global_indexes[0]
    freeze = re.findall(
        r"(?m)^  mDisplayFrozen=false windows=0 client=false apps=0  "
        r"mRotation=([0-3])  mLastOrientation=-1\s*$", text)
    if len(freeze) != 1:
        _fail("WindowManager is not in one exact non-frozen state")
    tail_markers = (
        " waitingForConfig=false",
        "  Animation settings:",
        "  PolicyControl.sImmersiveStatusFilter=",
        "  PolicyControl.sImmersiveNavigationFilter=",
        "  PolicyControl.sImmersivePreconfirmationsFilter=null",
    )
    tail_indexes: list[int] = []
    for marker in tail_markers:
        indexes = [index for index, line in enumerate(lines)
                   if line.startswith(marker)]
        if len(indexes) != 1:
            _fail("WindowManager terminal structure is absent or ambiguous")
        tail_indexes.append(indexes[0])
    freeze_index = next(index for index, line in enumerate(lines)
                        if line.startswith("  mDisplayFrozen="))
    if [freeze_index] + tail_indexes != sorted([freeze_index] + tail_indexes):
        _fail("WindowManager terminal structure order differs")
    return text, lines, global_index


def _window_residue_state(raw: bytes, stable: dict[str, Any]) -> dict[str, Any]:
    text, lines, global_index = _complete_window_envelope(raw)
    freeze = re.findall(
        r"(?m)^  mDisplayFrozen=false windows=0 client=false apps=0  "
        r"mRotation=([0-3])  mLastOrientation=-1\s*$", text)
    host_markers = (
        alpha.HOST_PACKAGE, str(stable["taskToken"]),
        str(stable["activityToken"]), str(stable["processToken"]),
        str(stable["windowToken"]), str(stable["windowSessionToken"]),
        "Stack #" + str(prior.HOST_TASK_ID),
        " #" + str(prior.HOST_TASK_ID) + " ",
        " t" + str(prior.HOST_TASK_ID) + "}",
        "taskId=" + str(prior.HOST_TASK_ID),
        "rootTaskId=" + str(prior.HOST_TASK_ID),
        "stackId=" + str(prior.HOST_TASK_ID),
        "StackId=" + str(prior.HOST_TASK_ID),
    )
    relevant = [line for line in lines
                if any(marker in line for marker in host_markers)]
    if relevant not in ([], [PINNED_FREEZE_RESIDUE]):
        _fail("post-removal WindowManager contains live or altered host scope")
    if relevant and lines.index(PINNED_FREEZE_RESIDUE) <= global_index:
        _fail("historical host residue is outside the WM global region")
    if any(alpha.HOST_PACKAGE in line and "Window #" in line
           for line in lines):
        _fail("post-removal WindowManager still has a live host window")
    return {
        "residuePresent": relevant == [PINNED_FREEZE_RESIDUE],
        "rotation": int(freeze[0]),
        "rawSha256": prior._sha(raw),
    }


def _complete_activity_envelope(raw: bytes) -> str:
    try:
        text, _ = android._wire(raw)  # type: ignore[attr-defined]
        android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            text)
    except android.AndroidAuthorityError as error:
        raise ContinuationError(
            "post-removal ActivityManager framing is malformed") from error
    if (not text.startswith(
            "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n") or
            text.count("ActivityStackSupervisor state:\n") != 1 or
            "Display #0 (activities from top to bottom):\n" not in text):
        _fail("post-removal ActivityManager inventory is truncated")
    tail_sections = (
        "  KeyguardController:",
        "  LockTaskController:",
        "  TaskOrganizerController:",
        "    Per windowing mode:",
        "      split-screen-primary:",
        "      split-screen-secondary:",
    )
    tail_indexes: list[int] = []
    lines = text.splitlines()
    for section in tail_sections:
        indexes = [index for index, line in enumerate(lines)
                   if line == section]
        if len(indexes) != 1:
            _fail("ActivityManager terminal section is absent or ambiguous")
        tail_indexes.append(indexes[0])
    if tail_indexes != sorted(tail_indexes):
        _fail("ActivityManager terminal section order differs")
    organizer_index = tail_indexes[2]
    if (not text.endswith("\n\n") or len(lines) < 2 or lines[-1] != "" or
            re.fullmatch(r" {10}Task\{[^\r\n]+\}", lines[-2]) is None or
            any(re.match(r"^  [A-Za-z].*:$", line) is not None
                for line in lines[organizer_index + 1:])):
        _fail("ActivityManager terminal organizer section is truncated")
    return text


def _strict_activity_absence(raw: bytes, stable: dict[str, Any]) -> dict[str, Any]:
    text = _complete_activity_envelope(raw)
    markers = (
        alpha.HOST_PACKAGE, str(stable["taskToken"]),
        str(stable["activityToken"]), str(stable["processToken"]),
        str(stable["windowToken"]), str(stable["windowSessionToken"]),
        "Stack #" + str(prior.HOST_TASK_ID),
        " #" + str(prior.HOST_TASK_ID) + " ",
        " t" + str(prior.HOST_TASK_ID) + "}",
        "taskId=" + str(prior.HOST_TASK_ID),
        "rootTaskId=" + str(prior.HOST_TASK_ID),
        "stackId=" + str(prior.HOST_TASK_ID),
        "StackId=" + str(prior.HOST_TASK_ID),
    )
    # The structural parser returns only the canonical display region; this
    # continuation intentionally admits no supervisor ghost either, so scan
    # the already-validated full wire for every retained host marker.
    if any(marker in text for marker in markers):
        _fail("post-removal ActivityManager still contains host scope")
    return {"rawSha256": prior._sha(raw)}


def _strict_display0_state(raw: bytes) -> dict[str, int | str]:
    text = alpha._decode_text(raw, "post-removal display inventory")
    if (not text.endswith("\n") or
            not text.startswith("DISPLAY MANAGER (dumpsys display)\n") or
            text.count("\nLogical Displays: size=") != 1):
        _fail("display inventory framing is truncated or malformed")
    tail_sections = (
        "Display Power State:",
        "Photonic Modulator State:",
        "Color Fade State:",
        "Automatic Brightness Controller Configuration:",
        "Automatic Brightness Controller State:",
        "SimpleMappingStrategy",
        "BrightnessTracker state:",
        "PersistentDataStore",
    )
    tail_indexes: list[int] = []
    lines = text.splitlines()
    for section in tail_sections:
        indexes = [index for index, line in enumerate(lines)
                   if line == section]
        if len(indexes) != 1:
            _fail("display inventory terminal section is absent or ambiguous")
        tail_indexes.append(indexes[0])
    if tail_indexes != sorted(tail_indexes):
        _fail("display inventory terminal section order differs")
    persistent = lines[tail_indexes[-1]:]
    expected_tail = (
        "PersistentDataStore",
        "  mLoaded=true",
        "  mDirty=false",
        "  RememberedWifiDisplays:",
        "  DisplayStates:",
        "  StableDeviceValues:",
        "      StableDisplayWidth=1404",
        "      StableDisplayHeight=1872",
        "  BrightnessConfigurations:",
    )
    if tuple(persistent) != expected_tail:
        _fail("display inventory persistent-store tail differs")
    physical = prior._physical_display0_override(raw)
    prior._assert_no_virtual_display(raw)
    return {
        "width": physical["width"],
        "height": physical["height"],
        "rotation": physical["rotation"],
        "rawSha256": prior._sha(raw),
    }


def _parking_stable(identity: dict[str, Any]) -> dict[str, Any]:
    required = {
        "process", "taskId", "displayId", "authoritySha256",
        "activityToken", "documentAuthority", "documentScope", "uiEvidence",
        "fdTargets", "activitiesSha256", "windowsSha256",
    }
    if type(identity) is not dict or set(identity) != required:
        _fail("continuation parking identity fields differ")
    if (re.fullmatch(r"[0-9a-f]{64}",
                     str(identity["activitiesSha256"])) is None or
            re.fullmatch(r"[0-9a-f]{64}",
                         str(identity["windowsSha256"])) is None or
            type(identity["uiEvidence"]) is not dict or
            identity["uiEvidence"].get("mode") not in {
                "PARSED", "UNAVAILABLE"}):
        _fail("continuation parking evidence fields differ")
    if identity["fdTargets"] != [alpha.PARKING_PDF]:
        _fail("continuation parking descriptors are not parking-only")
    authority_wire = identity["documentAuthority"]
    process_wire = identity["process"]
    if (type(authority_wire) is not dict or type(process_wire) is not dict or
            set(process_wire) != {"pid", "start_ticks", "uid", "package"}):
        _fail("continuation parking Document authority is malformed")
    try:
        authority = android.DocumentTaskAuthority(**authority_wire)
        authority_sha = android.stable_authority_sha256(authority)
        process = host.ProcessIdentity(**process_wire)
    except (TypeError, android.AndroidAuthorityError) as error:
        raise ContinuationError(
            "continuation parking Document authority is malformed") from error
    if (authority_sha != identity["authoritySha256"] or
            authority.task_id != identity["taskId"] or
            authority.display_id != identity["displayId"] or
            authority.activity_token != identity["activityToken"] or
            process.pid != authority.pid or process.uid != authority.uid or
            process.package != authority.process_name):
        _fail("continuation parking authority aliases disagree")
    scope = identity["documentScope"]
    scope_fields = {
        "taskId", "displayId", "taskToken", "activityToken",
        "processToken", "windowToken", "windowSessionToken",
        "windowComponent", "pid", "uid", "oneChildRootTask",
        "solePackageWindow",
    }
    if (type(scope) is not dict or set(scope) != scope_fields or
            scope["taskId"] != authority.task_id or
            scope["displayId"] != authority.display_id or
            scope["taskToken"] != authority.task_token or
            scope["activityToken"] != authority.activity_token or
            scope["pid"] != process.pid or scope["uid"] != process.uid or
            scope["windowComponent"] not in {
                android.SHORT_COMPONENT, android.FULL_COMPONENT} or
            scope["oneChildRootTask"] is not True or
            scope["solePackageWindow"] is not True or
            any(type(scope[key]) is not str or not scope[key]
                for key in ("processToken", "windowToken",
                            "windowSessionToken"))):
        _fail("continuation parking package-wide scope aliases disagree")
    stable_authority = asdict(authority)
    stable_authority.pop("raw_sha256")
    return {
        "process": identity["process"], "taskId": identity["taskId"],
        "displayId": identity["displayId"],
        "authoritySha256": identity["authoritySha256"],
        "activityToken": identity["activityToken"],
        "documentAuthority": stable_authority,
        "documentScope": scope, "fdTargets": identity["fdTargets"],
    }


def _parking_absence_authorities(
        identity: dict[str, Any],
        ) -> tuple[host.ForeignIdentity, android.DocumentTaskAuthority]:
    _parking_stable(identity)
    try:
        authority = android.DocumentTaskAuthority(
            **identity["documentAuthority"])
        process = host.ProcessIdentity(**identity["process"])
    except (KeyError, TypeError) as error:
        raise ContinuationError(
            "continuation parking absence authority is malformed") from error
    foreign = host.ForeignIdentity(
        process, authority.task_id, authority.activity_token,
        identity["authoritySha256"], alpha.DOCUMENT_COMPONENT)
    return foreign, authority


def _contains_document_scope_for_continuation(
        raw: bytes, foreign: host.ForeignIdentity,
        authority: android.DocumentTaskAuthority,
        ) -> bool:
    present = alpha._contains_document_scope_for_global_absence(
        raw, foreign, authority)
    if not present:
        return False
    text = alpha._decode_text(raw, "continuation Document inventory")
    if not text.startswith("ACTIVITY MANAGER"):
        return True
    _complete_activity_envelope(raw)
    terminal = "  KeyguardController:\n"
    if text.count(terminal) != 1:
        return True
    prefix, tail = text.split(terminal, 1)
    retained_markers = (
        alpha.DOCUMENT_PACKAGE, foreign.activity_token,
        authority.task_token, "#" + str(foreign.task_id),
        "t" + str(foreign.task_id),
    )
    if any(marker in tail for marker in retained_markers):
        return True
    reduced = (prefix.encode("utf-8") if prefix.endswith("\n") else
               (prefix + "\n").encode("utf-8"))
    return alpha._contains_document_scope_for_global_absence(
        reduced, foreign, authority)


class Recovery(prior.Recovery):
    def __init__(self, device: Device, authority: Authority, *,
                 sleep: Callable[[float], None] = time.sleep,
                 journal: Journal | None = None,
                 durable_header: dict[str, Any] | None = None,
                 prior_admission: dict[str, Any] | None = None):
        super().__init__(device, authority, sleep=sleep, journal=journal)
        self.authority: Authority = authority
        self.prior_summary = authority.prior_recovery_summary
        self.prior_helper_identity: dict[str, Any] | None = None
        self.environment: dict[str, Any] | None = None
        self.host_process_gone = False
        self.host_residue_gone = False
        self.document_scope_gone = False
        if (durable_header is None) != (prior_admission is None):
            _fail("durable continuation seed is incomplete")
        if durable_header is not None and prior_admission is not None:
            self._seed_durable_admission(durable_header, prior_admission)

    def _seed_durable_admission(
            self, header: dict[str, Any], admission: dict[str, Any]) -> None:
        if (header.get("authority") != AUTHORITY or
                header.get("runId") != prior.RUN_ID or
                header.get("journalId") != JOURNAL_ID or
                header.get("admissionSha256") !=
                prior._canonical_sha(admission) or
                header.get("report") != self.authority.report_identity or
                header.get("activeJournal") != self.authority.active_identity or
                header.get("priorRecovery", {}).get("sha256") !=
                PRIOR_RECOVERY_SHA256 or
                header.get("priorRecovery", {}).get("head") !=
                PRIOR_RECOVERY_HEAD):
            _fail("durable continuation header differs from admission")
        tools = (
            header.get("adb"), header.get("continuationHelper"),
            header.get("priorHelper"))
        if any(type(value) is not dict for value in tools):
            _fail("durable continuation tool authority is malformed")
        self.adb_identity = tools[0]
        self.helper_identity = tools[1]
        self.prior_helper_identity = tools[2]
        environment = admission.get("environment")
        if type(environment) is not dict:
            _fail("durable continuation environment is malformed")
        self.environment = environment
        self.host_apk = environment.get("hostApk")
        observations = admission.get(
            "adoptedHostRemovalAbsence", {}).get("observations")
        if type(observations) is not list or len(observations) != 2:
            _fail("durable continuation absence proof is malformed")
        self.host_process_gone = any(
            item.get("hostProcess", {}).get("mode") == "PROCESS_ABSENT"
            for item in observations if type(item) is dict)
        self.host_residue_gone = any(
            item.get("windows", {}).get("residuePresent") is False
            for item in observations if type(item) is dict)

    def _assert_prior_ledger(self) -> None:
        raw, identity = _read_prior_ledger(self.authority.prior_recovery_path)
        summary = _validate_prior_ledger(raw)
        if (identity != self.authority.prior_recovery_identity or
                summary != self.prior_summary):
            _fail("partial recovery ledger identity changed")

    def _assert_unpublished_evidence(self) -> None:
        if os.path.lexists(self.authority.evidence_path):
            _fail("continuation evidence path became occupied")
        prior_evidence = self.authority.run_dir / prior.EVIDENCE_BASENAME
        if os.path.lexists(prior_evidence):
            _fail("prior recovery evidence path became occupied")

    def _assert_local_input_authority(self) -> None:
        self._assert_unpublished_evidence()
        if os.path.lexists(self.authority.retired_path):
            _fail("retired active-journal path became occupied")
        _, report = _read_sole_regular(
            self.authority.report_path, 128 * 1024, "failed-run report")
        if report != self.authority.report_identity:
            _fail("failed-run report identity changed")
        _, observed = _read_sole_regular(
            self.authority.active_path, 256 * 1024,
            "active mutation journal")
        active = {**observed, "path": str(self.authority.active_path)}
        if active != self.authority.active_identity:
            _fail("active mutation journal identity changed")

    def _assert_post_archive_local_authority(self) -> None:
        self._assert_unpublished_evidence()
        _, report = _read_sole_regular(
            self.authority.report_path, 128 * 1024, "failed-run report")
        if report != self.authority.report_identity:
            _fail("failed-run report identity changed after archive")
        if os.path.lexists(self.authority.active_path):
            _fail("active mutation journal reappeared after archive")
        _, observed = _read_sole_regular(
            self.authority.retired_path, 256 * 1024,
            "retired active mutation journal")
        retired = {**observed, "path": str(self.authority.active_path)}
        if retired != self.authority.active_identity:
            _fail("retired mutation journal identity changed")

    def _assert_dispatch_authority(self) -> None:
        archive_intent = (
            self.journal is not None and
            self.journal.one("active_journal_archive_intent") is not None)
        active_present = os.path.lexists(self.authority.active_path)
        retired_present = os.path.lexists(self.authority.retired_path)
        if not archive_intent:
            if not active_present or retired_present:
                _fail("active-journal archive state lacks durable authority")
            self._assert_local_input_authority()
        elif active_present and not retired_present:
            self._assert_local_input_authority()
        elif not active_present and retired_present:
            self._assert_post_archive_local_authority()
        else:
            _fail("active-journal archive state is ambiguous")
        self._assert_prior_ledger()
        if (self.adb_identity is None or self.helper_identity is None or
                self.prior_helper_identity is None):
            _fail("continuation dispatch tool authority is uninitialized")
        adb = self.device.adb_authority()
        _, helper = prior._read_regular(
            Path(__file__), MAX_LOCAL_BYTES, "continuation helper")
        _, prior_helper = prior._read_regular(
            self.authority.prior_helper_path, MAX_LOCAL_BYTES,
            "prior recovery helper")
        if (adb != self.adb_identity or helper != self.helper_identity or
                prior_helper != self.prior_helper_identity):
            _fail("continuation dispatch tool identity changed")

    def _assert_tools(self) -> None:
        self._assert_local_input_authority()
        self._assert_prior_ledger()
        adb = self.device.adb_authority()
        _, helper = prior._read_regular(
            Path(__file__), MAX_LOCAL_BYTES, "continuation helper")
        _, prior_helper = prior._read_regular(
            self.authority.prior_helper_path, MAX_LOCAL_BYTES,
            "prior recovery helper")
        if (prior_helper != self.prior_summary["priorHelper"] or
                prior_helper["sha256"] != PRIOR_HELPER_SHA256):
            _fail("prior recovery helper changed")
        if self.adb_identity is None:
            self.adb_identity = adb
            self.helper_identity = helper
            self.prior_helper_identity = prior_helper
        elif (adb != self.adb_identity or helper != self.helper_identity or
              prior_helper != self.prior_helper_identity):
            _fail("continuation tool identity changed")

    def _header(self) -> dict[str, Any]:
        self._assert_tools()
        assert self.adb_identity is not None
        assert self.helper_identity is not None
        assert self.prior_helper_identity is not None
        return {
            "authority": AUTHORITY,
            "runId": prior.RUN_ID,
            "journalId": JOURNAL_ID,
            "report": self.authority.report_identity,
            "activeJournal": self.authority.active_identity,
            "continuationHelper": self.helper_identity,
            "priorHelper": self.prior_helper_identity,
            "adb": self.adb_identity,
            "priorRecovery": {
                "identity": self.authority.prior_recovery_identity,
                "recordCount": 3,
                "sha256": PRIOR_RECOVERY_SHA256,
                "head": PRIOR_RECOVERY_HEAD,
                "recordHashes": list(PRIOR_RECORD_HASHES),
            },
            "adoptedHostRemoval": {
                "taskId": prior.HOST_TASK_ID,
                "stableAuthoritySha256": STABLE_AUTHORITY_SHA256,
                "receiptRecordSha256": PRIOR_RECOVERY_HEAD,
                "dispatchMayRepeat": False,
            },
            "targets": {
                path: asdict(value)
                for path, value in prior.PINNED_TARGETS.items()},
            "quarantines": prior.QUARANTINES,
            "residualAssumption": prior.RESIDUAL_ASSUMPTION,
        }

    def _host_process_observation(self) -> dict[str, Any]:
        pids = self.device.pidof(alpha.HOST_PACKAGE)
        if not pids:
            semantics = _absent_process_semantics(
                self.device.host_processes(),
                self.prior_summary["stableAuthority"])
            if self.device.pidof(alpha.HOST_PACKAGE):
                _fail("visual-host process appeared during absence proof")
            return {"mode": "PROCESS_ABSENT", "process": None,
                    "semantics": semantics, "failedLifecycleSha256": None,
                    "fdTargets": []}
        if pids != (prior.HOST_PID,):
            _fail("visual-host process set changed after validated removal")
        try:
            process = self.device.process_identity(
                prior.HOST_PID, alpha.HOST_PACKAGE)
            processes = self.device.host_processes()
        except Exception as error:
            if self.device.pidof(alpha.HOST_PACKAGE):
                raise ContinuationError(
                    "cached host process could not be authenticated") from error
            semantics = _absent_process_semantics(
                self.device.host_processes(),
                self.prior_summary["stableAuthority"])
            if self.device.pidof(alpha.HOST_PACKAGE):
                _fail("visual-host process appeared during reconciliation")
            return {"mode": "PROCESS_ABSENT", "process": None,
                    "semantics": semantics, "failedLifecycleSha256": None,
                    "fdTargets": []}
        expected = host.ProcessIdentity(
            prior.HOST_PID, prior.HOST_START_TICKS,
            prior.HOST_UID, alpha.HOST_PACKAGE)
        if process != expected:
            _fail("cached host process identity changed")
        semantics = _cached_process_semantics(
            processes, self.prior_summary["stableAuthority"])
        try:
            fd_raw = self.device.process_fd_links(prior.HOST_PID)
        except Exception as error:
            return self._reconcile_cached_process_exit(
                "descriptor inventory", error)
        targets = prior._validated_fd_targets(fd_raw)
        forbidden = {
            alpha.SOURCE_PDF, alpha.SOURCE_MARK,
            alpha.PARKING_PDF, alpha.PARKING_MARK,
            alpha.TARGET_PDF, alpha.TARGET_MARK,
            prior.STAGING_PDF, prior.STAGING_MARK,
            prior.QUARANTINE_PDF, prior.QUARANTINE_MARK,
        }
        if targets.intersection(forbidden):
            _fail("cached host process still owns disposable/source descriptors")
        try:
            log_raw = self.device.host_logs(prior.HOST_PID)
        except Exception as error:
            return self._reconcile_cached_process_exit(
                "lifecycle log", error)
        selected = prior._validate_failed_host_log(log_raw)
        return {
            "mode": "CACHED_EMPTY_PROCESS",
            "process": asdict(process),
            "semantics": semantics,
            "failedLifecycleSha256": prior._canonical_sha(selected),
            "fdTargets": sorted(targets),
        }

    def _reconcile_cached_process_exit(
            self, boundary: str, error: BaseException) -> dict[str, Any]:
        if self.device.pidof(alpha.HOST_PACKAGE):
            raise ContinuationError(
                "cached host process lost its " + boundary) from error
        semantics = _absent_process_semantics(
            self.device.host_processes(),
            self.prior_summary["stableAuthority"])
        if self.device.pidof(alpha.HOST_PACKAGE):
            _fail("visual-host process appeared during " +
                  boundary + " reconciliation")
        return {
            "mode": "PROCESS_ABSENT", "process": None,
            "semantics": semantics, "failedLifecycleSha256": None,
            "fdTargets": [],
        }

    def _assert_host_scope_before_dispatch(
            self, *, require_document_absent: bool = False,
            ) -> dict[str, Any]:
        observation = self._scope_observation(
            parking=(self.retained_parking_identity
                     if require_document_absent else None))
        self._accept_monotonic_host_observation(observation, None)
        if require_document_absent and observation["documentScopePresent"]:
            _fail("stock Document task/window reappeared before file mutation")
        if require_document_absent:
            process = self._document_process()
            targets = prior._validated_fd_targets(
                self.device.process_fd_links(process.pid))
            if targets != frozenset((alpha.PARKING_PDF,)):
                _fail("stock Document descriptors are not parking-only "
                      "before file mutation")
            observation["documentProcess"] = asdict(process)
            observation["documentFdTargets"] = sorted(targets)
        return observation

    def _scope_observation(
            self, *,
            parking: dict[str, Any] | None = None) -> dict[str, Any]:
        raw = self.device.absence_raw()
        stable = self.prior_summary["stableAuthority"]
        activity = _strict_activity_absence(raw[0], stable)
        windows = _window_residue_state(raw[1], stable)
        display = _strict_display0_state(raw[2])
        if windows["rotation"] != display["rotation"]:
            _fail("WindowManager and physical display rotations differ")
        activity_text = alpha._decode_text(
            raw[0], "post-removal activity inventory")
        window_text = alpha._decode_text(
            raw[1], "post-removal window inventory")
        if parking is None:
            document_scope_present = (
                alpha.DOCUMENT_PACKAGE in activity_text or
                alpha.DOCUMENT_PACKAGE in window_text)
        else:
            foreign, document_authority = _parking_absence_authorities(
                parking)
            document_scope_present = (
                _contains_document_scope_for_continuation(
                    raw[0], foreign, document_authority) or
                alpha._contains_document_scope_for_global_absence(
                    raw[1], foreign, document_authority))
        process = self._host_process_observation()
        return {
            "activities": activity,
            "windows": windows,
            "display": display,
            "hostProcess": process,
            "documentScopePresent": document_scope_present,
        }

    def _accept_monotonic_host_observation(
            self, observation: dict[str, Any],
            previous: dict[str, Any] | None) -> None:
        process_absent = observation["hostProcess"]["mode"] == "PROCESS_ABSENT"
        residue_absent = not observation["windows"]["residuePresent"]
        if self.host_process_gone and not process_absent:
            _fail("cached host process reappeared")
        if self.host_residue_gone and not residue_absent:
            _fail("historical host window residue reappeared")
        if previous is not None:
            previous_process_absent = (
                previous["hostProcess"]["mode"] == "PROCESS_ABSENT")
            previous_residue_absent = not previous["windows"]["residuePresent"]
            if previous_process_absent and not process_absent:
                _fail("cached host process reappeared across proofs")
            if previous_residue_absent and not residue_absent:
                _fail("historical host window residue reappeared across proofs")
        self.host_process_gone = self.host_process_gone or process_absent
        self.host_residue_gone = self.host_residue_gone or residue_absent

    def _prove_host_absence_twice(
            self, *, parking: dict[str, Any] | None = None,
            kind: str = "adopted_host_removal_absence",
            poll_transient: bool = False) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        last_error: Exception | None = None
        limit = POLL_LIMIT if poll_transient else 2
        for _ in range(limit):
            observation = self._scope_observation(parking=parking)
            previous = observations[-1] if observations else None
            self._accept_monotonic_host_observation(
                observation, previous)
            if observation["documentScopePresent"]:
                error = DocumentScopePresent(
                    "stock Document task/window is still present")
                if not poll_transient:
                    raise error
                if parking is None or self.document_scope_gone or observations:
                    raise ContinuationError(
                        "stock Document task/window reappeared") from error
                observations = []
                last_error = error
                self.sleep(POLL_SECONDS)
                continue
            if parking is not None:
                self.document_scope_gone = True
            observations.append(observation)
            if len(observations) == 2:
                break
            self.sleep(POLL_SECONDS)
        if len(observations) != 2:
            suffix = "" if last_error is None else ": " + str(last_error)
            _fail("post-removal absence was not proved twice" + suffix)
        return self._proof(kind, observations=observations,
                           priorReceiptRecordSha256=PRIOR_RECOVERY_HEAD,
                           hostRemovalDispatchMayRepeat=False)

    def _document_before_parking(self) -> dict[str, Any]:
        document = self._document_process()
        targets = prior._validated_fd_targets(
            self.device.process_fd_links(document.pid))
        if (alpha.TARGET_PDF not in targets or
                alpha.PARKING_PDF not in targets or
                not targets.issubset({
                    alpha.TARGET_PDF, alpha.TARGET_MARK,
                    alpha.PARKING_PDF})):
            _fail("pre-continuation Document descriptors differ")
        return {"process": asdict(document), "targets": sorted(targets)}

    def _first_mutation_boundary(self) -> dict[str, Any]:
        self._assert_tools()
        environment = self.device.environment()
        if self.environment is not None and environment != self.environment:
            _fail("package environment changed before parking launch")
        self.environment = environment
        self._assert_rotation()
        self._assert_static()
        self._assert_initial_targets()
        absence = self._prove_host_absence_twice(
            kind="immediate_pre_parking_host_absence")
        document = self._document_before_parking()
        return self._proof(
            "first_mutation_boundary", absenceSha256=absence["sha256"],
            document=document,
            priorRecoverySha256=PRIOR_RECOVERY_SHA256)

    def plan(self) -> dict[str, Any]:
        _assert_publication_paths_clear(
            self.authority, before_journal=self.journal is None)
        self._assert_tools()
        environment = self.device.environment()
        if self.environment is None:
            self.environment = environment
        elif environment != self.environment:
            _fail("package environment changed during admission")
        self.host_apk = environment["hostApk"]
        self._assert_rotation()
        self._assert_static()
        self._assert_initial_targets()
        absence = self._prove_host_absence_twice()
        document = self._document_before_parking()
        return {
            "authority": AUTHORITY,
            "mode": "plan",
            "result": "CONTINUATION_PLAN_READY",
            "deviceMutationAttempted": False,
            "environment": environment,
            "priorRecovery": {
                "identity": self.authority.prior_recovery_identity,
                "summary": self.prior_summary,
                "immutable": True,
            },
            "adoptedHostRemovalAbsence": absence,
            "documentBeforeParking": document,
            "plannedSequence": [
                "ADOPT_VALIDATED_HOST_REMOVAL_WITHOUT_REDISPATCH",
                "LAUNCH_PARKING_DISPLAY_0",
                "REMOVE_EXACT_PARKING_TASK",
                "DELETE_MARK", "DELETE_PDF", "ARCHIVE_ACTIVE_JOURNAL",
            ],
            "proofs": self.proofs,
        }

    def _launch_and_remove_parking(self) -> dict[str, Any]:
        launch_payload = {"displayId": 0, "uri": alpha.PARKING_URI}
        fresh = self._intent("parking_launch", launch_payload)
        if fresh:
            # This is the first possible device mutation in this program.
            # Reauthenticate every inherited/local/device authority after the
            # durable intent and immediately before the single dispatch.
            self._first_mutation_boundary()
            assert self.journal is not None
            self.journal.assert_authority()
            try:
                result = self.device.launch_parking()
                prior._validate_mutation_result(
                    result, "launch_parking_document")
                self._record_dispatch_outcome("parking_launch", result=result)
            except prior.MutationTransportUncertain as error:
                self._record_dispatch_outcome(
                    "parking_launch", uncertain=error)
            except Exception as error:
                self._record_mutation_failure("parking_launch", error)
                raise
        parking: dict[str, Any] | None = None
        parking_error: Exception | None = None
        for _ in range(POLL_LIMIT):
            try:
                parking = self.device.parking_identity()
                break
            except Exception as error:
                parking_error = error
                # A readiness failure may itself be caused by a transient
                # visual-host scope.  Authenticate monotonic host absence on
                # every failed sample before retrying; never let a host
                # reappearance vanish between polls.
                self._assert_host_scope_before_dispatch()
                self.sleep(POLL_SECONDS)
        if parking is None:
            suffix = ("" if parking_error is None else
                      ": " + str(parking_error))
            _fail("parking launch was attempted once but did not settle "
                  "exactly" + suffix)
        retained_document = self._document_process()
        if parking.get("process") != asdict(retained_document):
            _fail("parking task belongs to a changed stock Document process")
        self.retained_parking_identity = parking
        self._settle("parking_launch", parking)
        parking_stable = _parking_stable(parking)
        mark_authority: dict[str, Any] | None = None
        mark_error: prior.RecoveryError | None = None
        try:
            mark_authority = self._authorize_target_mark_after_parking()
        except prior.RecoveryError as error:
            mark_error = error
        task_id = parking.get("taskId")
        if (type(task_id) is not int or task_id <= 0 or
                task_id == prior.HOST_TASK_ID):
            _fail("parking task ID is malformed or aliases the removed host")
        remove_payload = {
            "taskId": task_id,
            "stableAuthority": parking_stable,
            "stableAuthoritySha256": prior._canonical_sha(parking_stable),
        }
        fresh, remove_payload = self._parking_task_remove_intent(remove_payload)
        if fresh:
            assert self.journal is not None
            self.journal.assert_authority()
            self._assert_host_scope_before_dispatch()
            try:
                removal_identity = self.device.parking_identity()
            except Exception as error:
                raise ContinuationError(
                    "parking identity disappeared before removal") from error
            if _parking_stable(removal_identity) != parking_stable:
                _fail("parking identity changed before removal")
            self.journal.assert_authority()
            try:
                result = self.device.remove_parking_task(task_id)
                prior._validate_mutation_result(result, "remove_exact_task")
                self._record_dispatch_outcome(
                    "parking_task_remove", result=result)
            except prior.MutationTransportUncertain as error:
                self._record_dispatch_outcome(
                    "parking_task_remove", uncertain=error)
            except Exception as error:
                self._record_mutation_failure("parking_task_remove", error)
                raise
        absence = self._prove_parking_absence_twice(parking)
        descriptors = self._parking_fd_proof()
        if mark_error is None:
            try:
                mark_authority = self._authorize_target_mark_after_parking()
            except prior.RecoveryError as error:
                mark_error = error
        settled = {
            "taskId": task_id,
            "absence": absence,
            "descriptorProofSha256": descriptors["sha256"],
            "targetMarkAuthority": mark_authority,
            "targetMarkRejected": (
                None if mark_error is None else str(mark_error)),
        }
        self._settle("parking_task_remove", settled)
        if mark_error is not None:
            raise ContinuationError(
                "parking task was safely removed but target mark authority "
                "was rejected: " + str(mark_error))
        return settled

    def _quarantine_delete(self, path: str) -> None:
        expected = self.retained_targets[path]
        quarantine = prior.QUARANTINES[path]
        stem = "mark" if path == alpha.TARGET_MARK else "pdf"
        target_now = self.device.stat_file(path, absent_ok=True)
        quarantine_now = self.device.stat_file(quarantine, absent_ok=True)
        if target_now is None and quarantine_now is None:
            if (self.journal is None or self.journal.one(
                    stem + "_quarantine_delete_intent") is None):
                _fail("target disappeared without its durable delete intent")
            self._prove_path_absent_twice(path)
            self._prove_path_absent_twice(quarantine)
            self._settle(stem + "_quarantine_delete", {
                "source": path, "quarantine": quarantine,
                "observations": 2})
            return
        if target_now is not None and target_now != expected:
            _fail("target changed before quarantine: " + path)
        if (quarantine_now is not None and not prior._same_renamed(
                expected, quarantine_now, quarantine)):
            _fail("quarantine changed before cleanup: " + quarantine)
        if target_now is not None and quarantine_now is not None:
            _fail("target and quarantine are both occupied")
        move_payload = {
            "source": path, "quarantine": quarantine,
            "retained": asdict(expected)}
        if quarantine_now is None:
            fresh = self._intent(stem + "_quarantine_move", move_payload)
            if fresh:
                assert self.journal is not None
                self.journal.assert_authority()
                self._assert_host_scope_before_dispatch(
                    require_document_absent=True)
                if (self.device.stat_file(path, absent_ok=True) != expected or
                        self.device.stat_file(
                            quarantine, absent_ok=True) is not None):
                    _fail("quarantine-move authority changed before dispatch")
                self.journal.assert_authority()
                try:
                    result = self.device.move_quarantine(path, quarantine)
                    prior._validate_mutation_result(
                        result, "recovery_quarantine_" + Path(path).name,
                        empty_stdout=True)
                    self._record_dispatch_outcome(
                        stem + "_quarantine_move", result=result)
                except prior.MutationTransportUncertain as error:
                    self._record_dispatch_outcome(
                        stem + "_quarantine_move", uncertain=error)
                except Exception as error:
                    self._record_mutation_failure(
                        stem + "_quarantine_move", error)
                    raise
            self._prove_path_absent_twice(path)
            quarantine_now = self.device.stat_file(quarantine)
            if not prior._same_renamed(expected, quarantine_now, quarantine):
                _fail("one-shot quarantine move did not settle exactly")
            self._settle(stem + "_quarantine_move", {
                "source": path, "quarantine": quarantine,
                "retained": asdict(quarantine_now)})
        else:
            if (self.journal is None or self.journal.one(
                    stem + "_quarantine_move_intent") is None):
                _fail("quarantine exists without its durable move intent")
            self._prove_path_absent_twice(path)
        delete_payload = {
            "source": path, "quarantine": quarantine,
            "retained": asdict(quarantine_now)}
        fresh = self._intent(stem + "_quarantine_delete", delete_payload)
        if fresh:
            assert self.journal is not None
            self.journal.assert_authority()
            self._assert_host_scope_before_dispatch(
                require_document_absent=True)
            current_quarantine = self.device.stat_file(
                quarantine, absent_ok=True)
            if (self.device.stat_file(path, absent_ok=True) is not None or
                    current_quarantine is None or
                    not prior._same_renamed(
                        expected, current_quarantine, quarantine)):
                _fail("quarantine-delete authority changed before dispatch")
            self.journal.assert_authority()
            try:
                result = self.device.remove_quarantine(quarantine)
                prior._validate_mutation_result(
                    result, "recovery_remove_" + Path(quarantine).name,
                    empty_stdout=True)
                self._record_dispatch_outcome(
                    stem + "_quarantine_delete", result=result)
            except prior.MutationTransportUncertain as error:
                self._record_dispatch_outcome(
                    stem + "_quarantine_delete", uncertain=error)
            except Exception as error:
                self._record_mutation_failure(
                    stem + "_quarantine_delete", error)
                raise
        self._prove_path_absent_twice(quarantine)
        self._prove_path_absent_twice(path)
        self._settle(stem + "_quarantine_delete", {
            "source": path, "quarantine": quarantine, "observations": 2})

    def _prove_parking_absence_twice(
            self, parking: dict[str, Any]) -> list[dict[str, Any]]:
        proof = self._prove_host_absence_twice(
            parking=parking, kind="post_parking_task_absence",
            poll_transient=True)
        return proof["observations"]

    def _host_absent_twice(self) -> dict[str, Any]:
        return self._prove_host_absence_twice(
            parking=self.retained_parking_identity,
            kind="final_host_document_absence", poll_transient=True)

    def _adopt_prior_host_removal(
            self, admission: dict[str, Any]) -> dict[str, Any]:
        absence = admission["adoptedHostRemovalAbsence"]
        payload = {
            "taskId": prior.HOST_TASK_ID,
            "priorRecoverySha256": PRIOR_RECOVERY_SHA256,
            "priorRecoveryHead": PRIOR_RECOVERY_HEAD,
            "intentRecordSha256": PRIOR_RECORD_HASHES[1],
            "validatedReceiptRecordSha256": PRIOR_RECORD_HASHES[2],
            "stableAuthoritySha256": STABLE_AUTHORITY_SHA256,
            "freshAbsenceProofSha256": absence["sha256"],
            "dispatchRepeated": False,
        }
        self._settle("released_host_task_remove_adopted", payload)
        return payload

    def execute(self) -> dict[str, Any]:
        if self.journal is None:
            _fail("execute mode requires the continuation ledger")
        admission = self.plan()
        adopted = self._adopt_prior_host_removal(admission)
        parking = self._launch_and_remove_parking()
        self._quarantine_delete(alpha.TARGET_MARK)
        self._quarantine_delete(alpha.TARGET_PDF)
        joint_absence = self._joint_target_absence()
        self._assert_static()
        self._assert_rotation()
        self._parking_fd_proof()
        self._host_absent_twice()
        self._assert_prior_ledger()
        retired = self._archive_active()
        self._assert_post_archive_local_authority()
        self._assert_prior_ledger()
        result = {
            "authority": AUTHORITY,
            "mode": "execute",
            "result": "CONTINUATION_RECOVERED_CLEANLY",
            "runId": prior.RUN_ID,
            "reportSha256": prior.REPORT_SHA256,
            "activeJournalArchived": retired,
            "priorRecovery": {
                "identity": self.authority.prior_recovery_identity,
                "summary": self.prior_summary,
                "preservedImmutable": True,
            },
            "adoptedHostRemovalSettlement": adopted,
            "parkingSettlement": parking,
            "jointTargetAbsence": joint_absence,
            "mutations": self.mutations,
            "dispatchOutcomes": self.dispatch_outcomes,
            "proofs": self.proofs,
            "rotation": {
                "accelerometerRotation": "1", "userRotation": "2"},
            "originalsUnchanged": [
                asdict(value) for value in prior.STATIC_FILES],
            "deletedDisposablePaths": [alpha.TARGET_MARK, alpha.TARGET_PDF],
            "continuationJournal": str(self.authority.recovery_path),
            "priorRecoveryJournal": str(self.authority.prior_recovery_path),
            "residualAssumption": prior.RESIDUAL_ASSUMPTION,
        }
        encoded = json.dumps(
            result, indent=2, sort_keys=True,
            ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
        self.journal.assert_authority()
        self._assert_post_archive_local_authority()
        self._assert_prior_ledger()
        try:
            descriptor = os.open(
                self.authority.evidence_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError as error:
            raise ContinuationError(
                "continuation evidence path became occupied") from error
        try:
            if os.write(descriptor, encoded) != len(encoded):
                _fail("short continuation evidence write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        prior._fsync_directory(self.authority.evidence_path.parent)
        return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="perform the exact continuation")
    parser.add_argument("--adb", type=Path, default=prior.PINNED_ADB)
    parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--active-journal", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    root = arguments.root.absolute()
    report = arguments.report or root / prior.REPORT_RELATIVE
    active = arguments.active_journal or root / prior.ACTIVE_RELATIVE
    try:
        authority = load_authority(root, report, active)
        if arguments.execute:
            _assert_publication_paths_clear(authority, before_journal=True)
        device = ContinuationNomad(arguments.adb, alpha.AUTHORIZED_SERIAL)
        recovery = Recovery(device, authority)
        if not arguments.execute:
            result = recovery.plan()
        else:
            admission = recovery.plan()
            header = recovery._header()
            header["admissionSha256"] = prior._canonical_sha(admission)
            journal = Journal(authority.recovery_path, header)
            durable_header = journal.records[0]["payload"]
            recovery = Recovery(
                device, authority, journal=journal,
                durable_header=durable_header,
                prior_admission=admission)
            journal.external_guard = recovery._assert_dispatch_authority
            result = recovery.execute()
        print(json.dumps(result, indent=2, sort_keys=True,
                         ensure_ascii=True, allow_nan=False))
        return 0
    except (ContinuationError, prior.RecoveryError, alpha.AlphaError,
            android.AndroidAuthorityError, host.HostAuthorityError,
            OSError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
