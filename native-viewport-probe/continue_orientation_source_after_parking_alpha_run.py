"""Exact second continuation after the physical-display parking launch.

This program is bound to ``alpha-20260916-190148Z-b28865bb`` and to the
immutable four-record first-continuation ledger.  That ledger proves that the
physical-display parking launch was dispatched once with the exact validated
receipt.  This program therefore exposes neither a host-removal operation nor
a parking-launch operation.  It may remove only the already-live, report-bound
parking task 4648.

Plan mode is read-only.  Execute mode owns a new O_EXCL ledger.  If the stock
reader retains any disposable PDF/mark descriptor after the parking task is
removed, execution records ``DESCRIPTOR_RELEASE_PENDING`` and stops without
moving or deleting files and without archiving the active run journal.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, NoReturn, Protocol, Sequence

import continue_orientation_source_alpha_run as first
import native_page_alpha_runner as alpha
import native_page_android_authority as android
import native_page_host_authority as host
import recover_orientation_source_alpha_run as prior


AUTHORITY = "native-page-alpha-orientation-source-after-parking-v1"
JOURNAL_ID = "bf749a52-2f9d-4652-9ead-c7a8c371be5c"
JOURNAL_BASENAME = "orientation-source-after-parking.jsonl"
EVIDENCE_BASENAME = "orientation-source-after-parking-evidence.json"
FIRST_BYTES = 6_489
FIRST_SHA256 = "d730bf4c62df16063cd4eaf9d87f6e832eb8a5cfeb00bb4538a16b2645dde99f"
FIRST_HEAD = "1c11cb4a38aed5a9763ad72b23d0b80da0b1bb21b0ec0bc2789385f54ef69e84"
FIRST_RECORD_HASHES = (
    "5b4b07a5b87f9406a14aa509e6dd237bc7386f3030fd654e0eac1b9664915f82",
    "0f1f3ff123038c1b70552cf7e9d64caf5a7ec7df7964fb431e631ac3b9687d34",
    "0f97ced802c165b467316c001d62ca5a00303987bbb0be2f1d02df915f76d9c3",
    FIRST_HEAD,
)
FIRST_HELPER_SHA256 = "bce5515e62696ae2a85480ea79947b3d5a220c7ff8fb2530e8ac35029774e2e5"
PINNED_TASK_ID = 4648
PINNED_TASK_TOKEN = "a2a9794"
PINNED_ACTIVITY_TOKEN = "6f539a6"
PINNED_WINDOW_TOKEN = "a330753"
PINNED_PROCESS_TOKEN = "8081090"
PINNED_WINDOW_SESSION_TOKEN = "2bac998"
PINNED_DOCUMENT_PROCESS = host.ProcessIdentity(
    2053, 3382, android.SYSTEM_UID, alpha.DOCUMENT_PACKAGE)
PRE_REMOVE_SHARED_FDS = {
    44: alpha.TARGET_PDF,
    65: alpha.PARKING_PDF,
    93: alpha.PARKING_PDF,
}
PINNED_HOST_SCOPE = {
    "taskToken": "93d94cf", "activityToken": "45537a9",
    "processToken": first.PINNED_HOST_PROCESS_TOKEN,
    "windowToken": first.PINNED_WINDOW_TOKEN,
    "windowSessionToken": "7171c1d",
}
ROTATION_VALUES = {"0": 0, "90": 1, "180": 2, "270": 3}
POLL_SECONDS = prior.POLL_SECONDS
POLL_LIMIT = prior.POLL_LIMIT
MAX_LOCAL_BYTES = prior.MAX_LOCAL_BYTES
DEPENDENCY_SPECS = {
    "alpha": {
        "filename": "native_page_alpha_runner.py", "size": 278_148,
        "sha256":
        "0a9cb3eca9e8cc7920d18ad4e4a7541046e809d81962517e148094f598b05c38",
    },
    "android": {
        "filename": "native_page_android_authority.py", "size": 47_398,
        "sha256":
        "85401c12825935ecdbdae1e07e32ccedb4afaabdef30df0498d9a42b3e6b1a22",
    },
    "host": {
        "filename": "native_page_host_authority.py", "size": 52_293,
        "sha256":
        "daec1201f090c1488af16745a52c50e0d114b9b96cacd1c1257f9292bed1d29e",
    },
}
DEPENDENCY_MODULES = {"alpha": alpha, "android": android, "host": host}


class ContinuationError(prior.RecoveryError):
    """The exact after-parking continuation cannot proceed safely."""


def _fail(message: str) -> NoReturn:
    raise ContinuationError(message)


@dataclass(frozen=True)
class Authority:
    root: Path
    run_dir: Path
    report_path: Path
    active_path: Path
    journal_path: Path
    evidence_path: Path
    retired_path: Path
    report_identity: dict[str, Any]
    active_identity: dict[str, Any]
    prior_path: Path
    prior_identity: dict[str, Any]
    prior_summary: dict[str, Any]
    first_path: Path
    first_identity: dict[str, Any]
    first_summary: dict[str, Any]
    prior_helper_path: Path
    first_helper_path: Path
    dependency_paths: dict[str, Path]


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("ascii"), object_pairs_hook=prior._unique_pairs)
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


def _dependency_authority(paths: dict[str, Path]) -> dict[str, Any]:
    if set(paths) != set(DEPENDENCY_SPECS):
        _fail("after-parking dependency path set differs")
    result: dict[str, Any] = {}
    for name in sorted(DEPENDENCY_SPECS):
        spec = DEPENDENCY_SPECS[name]
        authority_raw, authority_identity = _read_sole_regular(
            paths[name], MAX_LOCAL_BYTES,
            "after-parking " + name + " dependency")
        module_file = getattr(DEPENDENCY_MODULES[name], "__file__", None)
        if type(module_file) is not str or not module_file:
            _fail("loaded " + name + " dependency has no source path")
        imported_raw, imported_identity = _read_sole_regular(
            Path(module_file).absolute(), MAX_LOCAL_BYTES,
            "loaded " + name + " dependency")
        expected = (spec["size"], spec["sha256"])
        if ((len(authority_raw), prior._sha(authority_raw)) != expected or
                (len(imported_raw), prior._sha(imported_raw)) != expected):
            _fail("after-parking " + name + " dependency bytes differ")
        result[name] = {
            "authoritySource": authority_identity,
            "importedSource": imported_identity,
            "expectedSize": spec["size"],
            "expectedSha256": spec["sha256"],
        }
    return result


def _validate_first_ledger(raw: bytes) -> dict[str, Any]:
    if (len(raw) != FIRST_BYTES or prior._sha(raw) != FIRST_SHA256 or
            not raw.endswith(b"\n") or b"\r" in raw):
        _fail("first-continuation ledger bytes differ")
    encoded = raw.splitlines(keepends=True)
    if len(encoded) != 4 or any(not line.endswith(b"\n") for line in encoded):
        _fail("first-continuation ledger must contain exactly four records")
    records = [_strict_json(line[:-1], "first-continuation record")
               for line in encoded]
    kinds = (
        "header", "released_host_task_remove_adopted_settled",
        "parking_launch_intent", "parking_launch_dispatch_outcome")
    previous: str | None = None
    for index, record in enumerate(records):
        if set(record) != {
                "authority", "kind", "payload", "previousSha256",
                "recordSha256", "sequence"}:
            _fail("first-continuation record fields differ")
        if (record["authority"] != first.AUTHORITY or
                record["kind"] != kinds[index] or
                record["sequence"] != index or
                record["previousSha256"] != previous or
                record["recordSha256"] != FIRST_RECORD_HASHES[index]):
            _fail("first-continuation record topology differs")
        unsigned = dict(record)
        digest = unsigned.pop("recordSha256")
        if prior._canonical_sha(unsigned) != digest:
            _fail("first-continuation hash chain differs")
        previous = digest
    if previous != FIRST_HEAD:
        _fail("first-continuation ledger head differs")
    header = records[0]["payload"]
    if (header.get("authority") != first.AUTHORITY or
            header.get("runId") != prior.RUN_ID or
            header.get("journalId") != first.JOURNAL_ID or
            header.get("continuationHelper", {}).get("sha256") !=
            FIRST_HELPER_SHA256 or
            header.get("priorRecovery", {}).get("sha256") !=
            first.PRIOR_RECOVERY_SHA256 or
            header.get("priorRecovery", {}).get("head") !=
            first.PRIOR_RECOVERY_HEAD):
        _fail("first-continuation header authority differs")
    adopted = records[1]["payload"]
    if (adopted.get("taskId") != prior.HOST_TASK_ID or
            adopted.get("dispatchRepeated") is not False or
            adopted.get("priorRecoverySha256") != first.PRIOR_RECOVERY_SHA256 or
            adopted.get("priorRecoveryHead") != first.PRIOR_RECOVERY_HEAD):
        _fail("first-continuation host-removal adoption differs")
    if records[2]["payload"] != {"displayId": 0, "uri": alpha.PARKING_URI}:
        _fail("first-continuation parking intent differs")
    receipt = records[3]["payload"]
    if receipt != {
            "mode": "VALIDATED_RECEIPT",
            "operation": "launch_parking_document",
            "receiptGrammar": "EXACT_PARKING_START_CRLF",
            "returncode": 0,
            "stderrSha256": prior._sha(b""), "stderrSize": 0,
            "stdoutSha256":
            "99723a04cfa8541c41ca98bd4d0e867a74fac04e3897482c1c9caa4e5c82bf3f",
            "stdoutSize": 208,
            }:
        _fail("first-continuation parking receipt differs")
    return {
        "recordCount": 4, "sha256": FIRST_SHA256, "head": FIRST_HEAD,
        "recordHashes": list(FIRST_RECORD_HASHES),
        "header": header, "parkingIntent": records[2]["payload"],
        "parkingReceipt": receipt,
    }


def load_authority(root: Path, report_path: Path,
                   active_path: Path) -> Authority:
    base = first.load_authority(root, report_path, active_path)
    prior_raw, prior_identity = first._read_prior_ledger(
        base.prior_recovery_path)
    prior_summary = first._validate_prior_ledger(prior_raw)
    first_path = base.recovery_path
    first_raw, first_identity = _read_sole_regular(
        first_path, 32 * 1024, "first-continuation ledger")
    first_summary = _validate_first_ledger(first_raw)
    first_helper_path = root.absolute() / "continue_orientation_source_alpha_run.py"
    _, first_helper = _read_sole_regular(
        first_helper_path, MAX_LOCAL_BYTES, "first-continuation helper")
    if first_helper != first_summary["header"]["continuationHelper"]:
        _fail("first-continuation helper differs from its ledger")
    prior_helper_path = root.absolute() / "recover_orientation_source_alpha_run.py"
    _, prior_helper = _read_sole_regular(
        prior_helper_path, MAX_LOCAL_BYTES, "prior recovery helper")
    if prior_helper != prior_summary["priorHelper"]:
        _fail("prior recovery helper differs from its ledger")
    dependency_paths = {
        name: root.absolute() / spec["filename"]
        for name, spec in DEPENDENCY_SPECS.items()}
    _dependency_authority(dependency_paths)
    return Authority(
        base.root, base.run_dir, base.report_path, base.active_path,
        base.run_dir / JOURNAL_BASENAME,
        base.run_dir / EVIDENCE_BASENAME, base.retired_path,
        base.report_identity, base.active_identity,
        base.prior_recovery_path, prior_identity, prior_summary,
        first_path, first_identity, first_summary,
        prior_helper_path, first_helper_path, dependency_paths)


def _assert_publication_paths_clear(authority: Authority, *,
                                    before_journal: bool) -> None:
    forbidden = (
        authority.evidence_path,
        authority.run_dir / first.EVIDENCE_BASENAME,
        authority.run_dir / prior.EVIDENCE_BASENAME,
        authority.retired_path,
    )
    if any(os.path.lexists(path) for path in forbidden):
        _fail("an expected-absent publication path is occupied")
    if not os.path.lexists(authority.active_path):
        _fail("active mutation journal is absent")
    if before_journal and os.path.lexists(authority.journal_path):
        _fail("after-parking continuation ledger is already occupied")


class Journal(prior.Journal):
    """Exclusive second-continuation ledger with retained-handle authority."""

    def __init__(self, path: Path, header: dict[str, Any]):
        self.external_guard: Callable[[], None] | None = None
        super().__init__(path, header)

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.external_guard is not None:
            self.external_guard()
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("after-parking ledger record is malformed")
        unsigned = {
            "authority": AUTHORITY, "kind": kind, "payload": payload,
            "previousSha256": (
                None if not self.records else self.records[-1]["recordSha256"]),
            "sequence": len(self.records),
        }
        record = {**unsigned, "recordSha256": prior._canonical_sha(unsigned)}
        encoded = prior._canonical(record) + b"\n"
        self._assert_open_authority()
        if os.write(self._descriptor, encoded) != len(encoded):
            _fail("short after-parking ledger write")
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
    def parking_identity(self) -> dict[str, Any]: ...
    def remove_parking_task(self, task_id: int) -> Any: ...
    def move_quarantine(self, source: str, target: str) -> Any: ...
    def remove_quarantine(self, path: str) -> Any: ...


def _selected_configuration(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    """Normalize only the exact selected task's closed Android rotation token."""
    text = first._complete_activity_envelope(raw)
    stack_lines = [line for line in text.splitlines()
                   if line.startswith("  Stack #" + str(PINNED_TASK_ID) + ":")]
    if len(stack_lines) != 1:
        _fail("pinned parking root is absent or ambiguous")
    resumed = (
        "    mResumedActivity: ActivityRecord{" + PINNED_ACTIVITY_TOKEN +
        " u0 " + android.SHORT_COMPONENT + " t" + str(PINNED_TASK_ID) + "}")
    if text.splitlines().count(resumed) != 1:
        _fail("pinned parking resumed activity differs")
    hist = (
        "      * Hist #0: ActivityRecord{" + PINNED_ACTIVITY_TOKEN +
        " u0 " + android.SHORT_COMPONENT + " t" + str(PINNED_TASK_ID) + "}")
    lines = text.splitlines()
    indexes = [index for index, line in enumerate(lines) if line == hist]
    if len(indexes) != 1:
        _fail("pinned parking activity block is absent or ambiguous")
    start = indexes[0]
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith(("      * Hist #", "    * Task{",
                                             "  Stack #"))), len(lines))
    block = lines[start:end]
    block_text = "\n".join(block)
    # The real ActivityRecord legitimately contains mGlobalConfig and
    # mOverrideConfig siblings with their own geometry.  They are not the
    # selected current configuration.  Count the authority label broadly,
    # regardless of indentation, then validate every field inside that one
    # canonical CurrentConfiguration line below.
    if block_text.count("CurrentConfiguration=") != 1:
        _fail("pinned parking configuration envelope is ambiguous")
    configs = [line for line in block
               if line.startswith("          CurrentConfiguration=")]
    if len(configs) != 1:
        _fail("pinned parking current configuration is absent or ambiguous")
    configuration = configs[0]
    if (configuration.count("mBounds=") != 1 or
            configuration.count("mAppBounds=") != 1 or
            configuration.count("mRotation=") != 1 or
            len(re.findall(r"(?<!\S)[0-9]+dpi(?=\s|$)", configuration)) != 1):
        _fail("pinned parking configuration fields are ambiguous")
    bounds = re.search(
        r"(?<!\S)mBounds=Rect\(0, 0 - ([1-9][0-9]*), ([1-9][0-9]*)\)"
        r"(?=\s|$)", configuration)
    app_bounds = re.search(
        r"(?<!\S)mAppBounds=Rect\(0, 0 - ([1-9][0-9]*), ([1-9][0-9]*)\)"
        r"(?=\s|$)", configuration)
    rotation = re.search(
        r"(?<!\S)mRotation=ROTATION_(0|90|180|270)(?=\}|\s|$)",
        configuration)
    if bounds is None or app_bounds is None or rotation is None:
        _fail("pinned parking configuration value is invalid")
    if configuration.count("300dpi") != 1:
        _fail("pinned parking density differs")
    width, height = map(int, bounds.groups())
    if tuple(map(int, app_bounds.groups())) != (width, height):
        _fail("pinned parking app bounds differ from display bounds")
    surface_rotation = ROTATION_VALUES[rotation.group(1)]
    expected_geometry = (
        (1404, 1872) if surface_rotation in (0, 2) else (1872, 1404))
    if (width, height) != expected_geometry:
        _fail("pinned parking bounds disagree with closed rotation")
    normalized_line = (
        configuration[:rotation.start(1)] + str(surface_rotation) +
        configuration[rotation.end(1):])
    if text.count(configuration) != 1:
        _fail("pinned parking configuration line is not uniquely owned")
    normalized = text.replace(configuration, normalized_line, 1).encode("utf-8")
    return normalized, {
        "rotationLiteral": "ROTATION_" + rotation.group(1),
        "rotation": surface_rotation, "width": width, "height": height,
        "configurationSha256": prior._sha(configuration.encode("utf-8")),
    }


def _closed_document_authority(
        raw: bytes, expected_pid: int,
        ) -> tuple[android.DocumentTaskAuthority, dict[str, Any]]:
    normalized, configuration = _selected_configuration(raw)
    try:
        authority = android.parse_document_task_authority(
            normalized, expected_pid=expected_pid, require_live=True)
    except android.AndroidAuthorityError as error:
        raise ContinuationError(
            "pinned parking task authority is invalid") from error
    if (authority.task_id != PINNED_TASK_ID or
            authority.stack_id != PINNED_TASK_ID or
            authority.task_token != PINNED_TASK_TOKEN or
            authority.activity_token != PINNED_ACTIVITY_TOKEN or
            authority.display_id != 0 or authority.pid != expected_pid or
            authority.uid != android.SYSTEM_UID or
            authority.base_apk_path != alpha.DOCUMENT_APK or
            authority.density_dpi != 300 or
            (authority.width, authority.height, authority.rotation) !=
            (configuration["width"], configuration["height"],
             configuration["rotation"])):
        _fail("pinned parking task semantic authority differs")
    return authority, configuration


def _selected_task_intent(raw: bytes, authority: android.DocumentTaskAuthority) -> None:
    text = first._complete_activity_envelope(raw)
    try:
        canonical = android._reject_malformed_structural_headers(  # type: ignore[attr-defined]
            text)
        stacks = [(display_id, stack_id, block)
                  for display_id, stack_id, block
                  in android._display_stack_blocks(canonical)  # type: ignore[attr-defined]
                  if stack_id == PINNED_TASK_ID]
        tasks = ([] if len(stacks) != 1 else
                 android._task_blocks(stacks[0][2]))  # type: ignore[attr-defined]
    except android.AndroidAuthorityError as error:
        raise ContinuationError("pinned parking root is malformed") from error
    if (len(stacks) != 1 or stacks[0][0] != 0 or len(tasks) != 1 or
            authority.component not in tasks[0]):
        _fail("pinned parking root does not have one exact child")
    task = tasks[0]
    if task.count("intent={") != 1 or task.count("Intent {") != 1:
        _fail("pinned parking task contains ambiguous intent envelopes")
    envelopes = re.findall(r"(?m)^      intent=\{([^\r\n{}]+)\}$", task)
    if len(envelopes) != 1:
        _fail("pinned parking root intent is absent or ambiguous")
    fields: dict[str, str] = {}
    for token in envelopes[0].split():
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*)=([^\s={}]+)", token)
        if match is None or match.group(1) in fields:
            _fail("pinned parking root intent fields are malformed")
        fields[match.group(1)] = match.group(2)
    if fields != {
            "act": alpha.DOCUMENT_LAUNCH_ACTION,
            "dat": alpha.PARKING_URI,
            "typ": alpha.DOCUMENT_LAUNCH_MIME,
            "flg": "0x10000000",
            "cmp": authority.component,
            }:
        _fail("pinned parking root intent differs")
    activity_intents = re.findall(
        r"(?m)^          Intent \{ ([^\r\n{}]+) \}$", task)
    if len(activity_intents) != 1:
        _fail("pinned parking activity intent is absent or ambiguous")
    activity_fields: dict[str, str] = {}
    for token in activity_intents[0].split():
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*)=([^\s={}]+)", token)
        if match is None or match.group(1) in activity_fields:
            _fail("pinned parking activity intent fields are malformed")
        activity_fields[match.group(1)] = match.group(2)
    if activity_fields != fields:
        _fail("pinned parking root/activity intents disagree")


def _window_rotation(raw: bytes) -> int:
    text, _, _ = first._complete_window_envelope(raw)
    values = re.findall(
        r"(?m)^  mDisplayFrozen=false windows=0 client=false apps=0  "
        r"mRotation=([0-3])  mLastOrientation=-1\s*$", text)
    if len(values) != 1:
        _fail("physical WindowManager rotation is absent or ambiguous")
    return int(values[0])


def _selected_window_frame(raw: bytes, width: int, height: int) -> dict[str, Any]:
    text, lines, _ = first._complete_window_envelope(raw)
    headers = [index for index, line in enumerate(lines)
               if re.match(r"^  Window #[0-9]+ Window\{", line) and
               alpha.DOCUMENT_PACKAGE in line]
    if len(headers) != 1:
        _fail("pinned parking package window is absent or ambiguous")
    start = headers[0]
    end = next((index for index in range(start + 1, len(lines))
                if re.match(r"^  Window #[0-9]+ Window\{", lines[index])),
               len(lines))
    block = lines[start:end]
    header = block[0].strip()
    match = re.fullmatch(
        r"Window #[0-9]+ Window\{([0-9a-f]+) u0 (?:" +
        re.escape(android.SHORT_COMPONENT) + "|" +
        re.escape(android.FULL_COMPONENT) + r")\}:", header)
    if match is None or match.group(1) != PINNED_WINDOW_TOKEN:
        _fail("pinned parking window token differs")
    required = (
        "mDisplayId=0 rootTaskId=" + str(PINNED_TASK_ID),
        "mActivityRecord=ActivityRecord{" + PINNED_ACTIVITY_TOKEN,
        "mFrame=[0,0][" + str(width) + "," + str(height) + "]",
        "display=[0,0][" + str(width) + "," + str(height) + "]",
        "mHasSurface=true", "isOnScreen=true", "isVisible=true",
    )
    if any(sum(marker in line for line in block) != 1 for marker in required):
        _fail("pinned parking window geometry or visibility differs")
    return {
        "windowToken": PINNED_WINDOW_TOKEN, "width": width,
        "height": height, "rawSha256": prior._sha(raw),
    }


def _fd_inventory(raw: str) -> tuple[frozenset[str], dict[int, str]]:
    targets = prior._validated_fd_targets(raw)
    lines = raw.splitlines()
    if lines and re.fullmatch(r"total [0-9]+", lines[0]):
        lines = lines[1:]
    pattern = re.compile(
        r"^l[rwxstST-]{9} [1-9][0-9]* \S+ \S+ [0-9]+ \S+ \S+ "
        r"([0-9]+) -> (.+)$")
    result: dict[int, str] = {}
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None:
            _fail("descriptor inventory framing differs")
        fd = int(match.group(1))
        target = match.group(2)
        if target.startswith("/storage/emulated/0/"):
            if fd in result:
                _fail("shared-storage descriptor number is duplicated")
            result[fd] = target
    return targets, result


def _shared_storage_fds(raw: str) -> dict[int, str]:
    targets, result = _fd_inventory(raw)
    if targets != frozenset((alpha.TARGET_PDF, alpha.PARKING_PDF)):
        _fail("pre-removal PDF/mark descriptor set differs")
    return result


def _pre_remove_fd_authority(raw: str) -> dict[str, Any]:
    shared = _shared_storage_fds(raw)
    if shared != PRE_REMOVE_SHARED_FDS:
        _fail("pre-removal shared-storage descriptors differ")
    return {
        "shared": {str(key): value for key, value in sorted(shared.items())},
        "rawSha256": prior._sha(raw.encode("utf-8")),
    }


def _parking_stable(identity: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "process", "taskId", "taskToken", "activityToken", "windowToken",
        "documentAuthority", "documentScope", "configuration", "display",
        "window", "fdAuthority", "activitiesSha256", "windowsSha256",
    }
    if type(identity) is not dict or set(identity) != expected:
        _fail("after-parking identity fields differ")
    if (identity["process"] != asdict(PINNED_DOCUMENT_PROCESS) or
            identity["taskId"] != PINNED_TASK_ID or
            identity["taskToken"] != PINNED_TASK_TOKEN or
            identity["activityToken"] != PINNED_ACTIVITY_TOKEN or
            identity["windowToken"] != PINNED_WINDOW_TOKEN or
            identity["documentScope"].get("processToken") !=
            PINNED_PROCESS_TOKEN or
            identity["documentScope"].get("windowSessionToken") !=
            PINNED_WINDOW_SESSION_TOKEN or
            identity["fdAuthority"].get("shared") !=
            {str(key): value for key, value in sorted(PRE_REMOVE_SHARED_FDS.items())}):
        _fail("after-parking stable aliases differ")
    authority_wire = identity["documentAuthority"]
    try:
        authority = android.DocumentTaskAuthority(**authority_wire)
    except (TypeError, android.AndroidAuthorityError) as error:
        raise ContinuationError("after-parking authority is malformed") from error
    if (authority.task_id != PINNED_TASK_ID or
            authority.task_token != PINNED_TASK_TOKEN or
            authority.activity_token != PINNED_ACTIVITY_TOKEN):
        _fail("after-parking task authority aliases differ")
    stable_authority = asdict(authority)
    stable_authority.pop("raw_sha256")
    return {
        "process": identity["process"], "taskId": identity["taskId"],
        "taskToken": identity["taskToken"],
        "activityToken": identity["activityToken"],
        "windowToken": identity["windowToken"],
        "documentAuthority": stable_authority,
        "documentScope": identity["documentScope"],
        "configuration": identity["configuration"],
        "display": {key: identity["display"][key]
                    for key in ("width", "height", "rotation")},
        "window": {key: identity["window"][key]
                   for key in ("windowToken", "width", "height")},
        "fdShared": identity["fdAuthority"]["shared"],
    }


class SecondNomad:
    """Closed transport that exposes only one exact parking-task removal."""

    def __init__(self, adb: Path, serial: str):
        self._transport = prior.RecoveryNomad(adb, serial)

    @property
    def history(self) -> list[dict[str, Any]]:
        return self._transport.history

    def adb_authority(self) -> dict[str, Any]:
        return self._transport.adb_authority()

    def environment(self) -> dict[str, Any]:
        return self._transport.environment()

    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None:
        return self._transport.stat_file(path, absent_ok=absent_ok)

    def pidof(self, package: str) -> tuple[int, ...]:
        return self._transport.pidof(package)

    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity:
        return self._transport.process_identity(pid, package)

    def process_fd_links(self, pid: int) -> str:
        return self._transport.process_fd_links(pid)

    def host_logs(self, pid: int) -> str:
        return self._transport.host_logs(pid)

    def host_processes(self) -> bytes:
        result = self._transport._invoke(
            "host_processes", ("shell", "dumpsys", "activity", "processes"))
        return self._transport._require_zero(result)

    def activities(self) -> bytes:
        raw = self._transport.activities()
        first._complete_activity_envelope(raw)
        return raw

    def windows(self) -> bytes:
        raw = self._transport.windows()
        first._complete_window_envelope(raw)
        return raw

    def displays(self) -> bytes:
        raw = self._transport.displays()
        first._strict_display0_state(raw)
        return raw

    def absence_raw(self) -> tuple[bytes, bytes, bytes]:
        return self.activities(), self.windows(), self.displays()

    def rotation_settings(self) -> tuple[str, str]:
        return self._transport.rotation_settings()

    def parking_identity(self) -> dict[str, Any]:
        if self.pidof(alpha.DOCUMENT_PACKAGE) != (PINNED_DOCUMENT_PROCESS.pid,):
            _fail("pinned stock Document process set differs")
        process_before = self.process_identity(
            PINNED_DOCUMENT_PROCESS.pid, alpha.DOCUMENT_PACKAGE)
        if process_before != PINNED_DOCUMENT_PROCESS:
            _fail("pinned stock Document process identity differs")
        activities = self.activities()
        windows = self.windows()
        displays = self.displays()
        first._strict_activity_absence(activities, PINNED_HOST_SCOPE)
        host_windows = first._window_residue_state(windows, PINNED_HOST_SCOPE)
        authority, configuration = _closed_document_authority(
            activities, process_before.pid)
        _selected_task_intent(activities, authority)
        scope = prior._assert_sole_document_scope(
            activities, windows, authority, process_before)
        if (scope["stable"].get("windowToken") != PINNED_WINDOW_TOKEN or
                scope["stable"].get("processToken") != PINNED_PROCESS_TOKEN or
                scope["stable"].get("windowSessionToken") !=
                PINNED_WINDOW_SESSION_TOKEN):
            _fail("pinned stock Document process/window scope differs")
        display = first._strict_display0_state(displays)
        wm_rotation = _window_rotation(windows)
        if ((display["width"], display["height"], display["rotation"]) !=
                (configuration["width"], configuration["height"],
                 configuration["rotation"]) or
                wm_rotation != configuration["rotation"]):
            _fail("parking configuration, WindowManager, and display disagree")
        if host_windows["rotation"] != configuration["rotation"]:
            _fail("host-free WindowManager proof and parking rotation disagree")
        window = _selected_window_frame(
            windows, configuration["width"], configuration["height"])
        fd_authority = _pre_remove_fd_authority(
            self.process_fd_links(process_before.pid))
        process_after = self.process_identity(
            PINNED_DOCUMENT_PROCESS.pid, alpha.DOCUMENT_PACKAGE)
        if (process_after != process_before or
                self.pidof(alpha.DOCUMENT_PACKAGE) !=
                (PINNED_DOCUMENT_PROCESS.pid,)):
            _fail("stock Document process changed during parking capture")
        return {
            "process": asdict(process_before), "taskId": authority.task_id,
            "taskToken": authority.task_token,
            "activityToken": authority.activity_token,
            "windowToken": PINNED_WINDOW_TOKEN,
            "documentAuthority": asdict(authority),
            "documentScope": scope["stable"],
            "configuration": configuration, "display": display,
            "window": window, "fdAuthority": fd_authority,
            "activitiesSha256": prior._sha(activities),
            "windowsSha256": prior._sha(windows),
        }

    def remove_parking_task(self, task_id: int) -> alpha.CommandResult:
        if task_id != PINNED_TASK_ID or task_id == prior.HOST_TASK_ID:
            _fail("task removal escaped the one exact parking task")
        return prior.RecoveryNomad.remove_task(self._transport, task_id)

    def move_quarantine(self, source: str, target: str) -> alpha.CommandResult:
        return self._transport.move_quarantine(source, target)

    def remove_quarantine(self, path: str) -> alpha.CommandResult:
        return self._transport.remove_quarantine(path)


class Recovery:
    def __init__(self, device: Device, authority: Authority, *,
                 sleep: Callable[[float], None] = time.sleep,
                 journal: Journal | None = None,
                 durable_header: dict[str, Any] | None = None,
                 prior_admission: dict[str, Any] | None = None):
        self.device = device
        self.authority = authority
        self.sleep = sleep
        self.journal = journal
        self.proofs: list[dict[str, Any]] = []
        self.mutations: list[dict[str, Any]] = []
        self.dispatch_outcomes: list[dict[str, Any]] = []
        self.retained_targets = dict(prior.PINNED_TARGETS)
        self.target_mark_adoption: dict[str, Any] | None = None
        self.environment: dict[str, Any] | None = None
        self.adb_identity: dict[str, Any] | None = None
        self.helper_identity: dict[str, Any] | None = None
        self.first_helper_identity: dict[str, Any] | None = None
        self.prior_helper_identity: dict[str, Any] | None = None
        self.dependency_identities: dict[str, Any] | None = None
        self.host_process_gone = False
        self.host_residue_gone = False
        self.document_scope_gone = False
        self.retained_parking: dict[str, Any] | None = None
        if (durable_header is None) != (prior_admission is None):
            _fail("durable after-parking seed is incomplete")
        if durable_header is not None and prior_admission is not None:
            self._seed_durable_admission(durable_header, prior_admission)

    def _proof(self, kind: str, **fields: Any) -> dict[str, Any]:
        payload = {"kind": kind, **fields}
        proof = {**payload, "sha256": prior._canonical_sha(payload)}
        self.proofs.append(proof)
        return proof

    def _assert_ledgers(self) -> None:
        prior_raw, prior_identity = first._read_prior_ledger(
            self.authority.prior_path)
        if (prior_identity != self.authority.prior_identity or
                first._validate_prior_ledger(prior_raw) !=
                self.authority.prior_summary):
            _fail("immutable partial-recovery ledger changed")
        first_raw, first_identity = _read_sole_regular(
            self.authority.first_path, 32 * 1024,
            "immutable first-continuation ledger")
        if (first_identity != self.authority.first_identity or
                _validate_first_ledger(first_raw) !=
                self.authority.first_summary):
            _fail("immutable first-continuation ledger changed")

    def _assert_unpublished(self) -> None:
        for path in (
                self.authority.evidence_path,
                self.authority.run_dir / first.EVIDENCE_BASENAME,
                self.authority.run_dir / prior.EVIDENCE_BASENAME):
            if os.path.lexists(path):
                _fail("an immutable predecessor/final evidence path appeared")

    def _assert_local_before_archive(self) -> None:
        self._assert_unpublished()
        if os.path.lexists(self.authority.retired_path):
            _fail("retired active-journal path became occupied")
        _, report = _read_sole_regular(
            self.authority.report_path, 128 * 1024, "failed-run report")
        if report != self.authority.report_identity:
            _fail("failed-run report identity changed")
        _, active = _read_sole_regular(
            self.authority.active_path, 256 * 1024,
            "active mutation journal")
        active = {**active, "path": str(self.authority.active_path)}
        if active != self.authority.active_identity:
            _fail("active mutation journal identity changed")

    def _assert_local_after_archive(self) -> None:
        self._assert_unpublished()
        if os.path.lexists(self.authority.active_path):
            _fail("active mutation journal reappeared")
        _, retired = _read_sole_regular(
            self.authority.retired_path, 256 * 1024,
            "retired active mutation journal")
        retired = {**retired, "path": str(self.authority.active_path)}
        if retired != self.authority.active_identity:
            _fail("retired active mutation journal identity changed")

    def _assert_dispatch_authority(self) -> None:
        archive_intent = (
            self.journal is not None and
            self.journal.one("active_journal_archive_intent") is not None)
        active = os.path.lexists(self.authority.active_path)
        retired = os.path.lexists(self.authority.retired_path)
        if not archive_intent:
            if not active or retired:
                _fail("active-journal phase lacks durable archive authority")
            self._assert_local_before_archive()
        elif active and not retired:
            self._assert_local_before_archive()
        elif retired and not active:
            self._assert_local_after_archive()
        else:
            _fail("active-journal archive state is ambiguous")
        self._assert_ledgers()
        if any(value is None for value in (
                self.adb_identity, self.helper_identity,
                self.first_helper_identity, self.prior_helper_identity,
                self.dependency_identities)):
            _fail("after-parking tool authority is uninitialized")
        adb = self.device.adb_authority()
        _, helper = _read_sole_regular(
            Path(__file__), MAX_LOCAL_BYTES, "after-parking helper")
        _, first_helper = _read_sole_regular(
            self.authority.first_helper_path, MAX_LOCAL_BYTES,
            "first-continuation helper")
        _, prior_helper = _read_sole_regular(
            self.authority.prior_helper_path, MAX_LOCAL_BYTES,
            "prior recovery helper")
        dependencies = _dependency_authority(
            self.authority.dependency_paths)
        if (adb != self.adb_identity or helper != self.helper_identity or
                first_helper != self.first_helper_identity or
                prior_helper != self.prior_helper_identity or
                dependencies != self.dependency_identities):
            _fail("after-parking dispatch tool identity changed")

    def _assert_tools(self) -> None:
        self._assert_local_before_archive()
        self._assert_ledgers()
        adb = self.device.adb_authority()
        _, helper = _read_sole_regular(
            Path(__file__), MAX_LOCAL_BYTES, "after-parking helper")
        _, first_helper = _read_sole_regular(
            self.authority.first_helper_path, MAX_LOCAL_BYTES,
            "first-continuation helper")
        _, prior_helper = _read_sole_regular(
            self.authority.prior_helper_path, MAX_LOCAL_BYTES,
            "prior recovery helper")
        dependencies = _dependency_authority(
            self.authority.dependency_paths)
        if (first_helper !=
                self.authority.first_summary["header"]["continuationHelper"] or
                prior_helper != self.authority.prior_summary["priorHelper"]):
            _fail("predecessor helper identity changed")
        values = (adb, helper, first_helper, prior_helper, dependencies)
        retained = (self.adb_identity, self.helper_identity,
                    self.first_helper_identity, self.prior_helper_identity,
                    self.dependency_identities)
        if self.adb_identity is None:
            (self.adb_identity, self.helper_identity,
             self.first_helper_identity,
             self.prior_helper_identity,
             self.dependency_identities) = values
        elif values != retained:
            _fail("after-parking tool identity changed")

    def _assert_rotation(self) -> None:
        if self.device.rotation_settings() != ("1", "2"):
            _fail("rotation settings changed from the admitted 1/2 state")

    def _assert_static(self) -> None:
        for expected in prior.STATIC_FILES:
            if self.device.stat_file(expected.path) != expected:
                _fail("source/parking identity changed: " + expected.path)
        if self.device.stat_file(alpha.PARKING_MARK, absent_ok=True) is not None:
            _fail("parking mark path became occupied")
        for path in (prior.STAGING_MARK, prior.STAGING_PDF):
            if self.device.stat_file(path, absent_ok=True) is not None:
                _fail("staging path became occupied: " + path)

    def _assert_initial_targets(self) -> None:
        for path, expected in self.retained_targets.items():
            if self.device.stat_file(path, absent_ok=True) != expected:
                _fail("disposable target identity changed: " + path)
            if self.device.stat_file(
                    prior.QUARANTINES[path], absent_ok=True) is not None:
                _fail("quarantine path became occupied: " +
                      prior.QUARANTINES[path])

    def _header(self) -> dict[str, Any]:
        self._assert_tools()
        assert self.adb_identity is not None
        assert self.helper_identity is not None
        assert self.first_helper_identity is not None
        assert self.prior_helper_identity is not None
        assert self.dependency_identities is not None
        return {
            "authority": AUTHORITY, "runId": prior.RUN_ID,
            "journalId": JOURNAL_ID,
            "report": self.authority.report_identity,
            "activeJournal": self.authority.active_identity,
            "helper": self.helper_identity, "adb": self.adb_identity,
            "priorHelper": self.prior_helper_identity,
            "firstHelper": self.first_helper_identity,
            "dependencies": self.dependency_identities,
            "priorRecovery": {
                "identity": self.authority.prior_identity,
                "sha256": first.PRIOR_RECOVERY_SHA256,
                "head": first.PRIOR_RECOVERY_HEAD,
                "recordCount": 3,
            },
            "firstContinuation": {
                "identity": self.authority.first_identity,
                "sha256": FIRST_SHA256, "head": FIRST_HEAD,
                "recordCount": 4,
                "recordHashes": list(FIRST_RECORD_HASHES),
                "parkingLaunchMayRepeat": False,
            },
            "parking": {
                "taskId": PINNED_TASK_ID, "taskToken": PINNED_TASK_TOKEN,
                "activityToken": PINNED_ACTIVITY_TOKEN,
                "windowToken": PINNED_WINDOW_TOKEN,
                "processToken": PINNED_PROCESS_TOKEN,
                "windowSessionToken": PINNED_WINDOW_SESSION_TOKEN,
                "process": asdict(PINNED_DOCUMENT_PROCESS),
                "uri": alpha.PARKING_URI,
                "preRemoveSharedFds": {
                    str(key): value
                    for key, value in sorted(PRE_REMOVE_SHARED_FDS.items())},
            },
            "targets": {path: asdict(value)
                        for path, value in prior.PINNED_TARGETS.items()},
            "quarantines": prior.QUARANTINES,
            "residualAssumption": prior.RESIDUAL_ASSUMPTION,
        }

    def _seed_durable_admission(
            self, header: dict[str, Any], admission: dict[str, Any]) -> None:
        if (header.get("authority") != AUTHORITY or
                header.get("runId") != prior.RUN_ID or
                header.get("journalId") != JOURNAL_ID or
                header.get("admissionSha256") !=
                prior._canonical_sha(admission) or
                header.get("firstContinuation", {}).get("sha256") !=
                FIRST_SHA256 or
                header.get("firstContinuation", {}).get("head") != FIRST_HEAD):
            _fail("durable after-parking header differs from admission")
        tools = (header.get("adb"), header.get("helper"),
                 header.get("firstHelper"), header.get("priorHelper"),
                 header.get("dependencies"))
        if any(type(value) is not dict for value in tools):
            _fail("durable after-parking tool authority is malformed")
        (self.adb_identity, self.helper_identity,
         self.first_helper_identity, self.prior_helper_identity,
         self.dependency_identities) = tools
        environment = admission.get("environment")
        if type(environment) is not dict:
            _fail("durable after-parking environment is malformed")
        self.environment = environment
        observations = admission.get("hostAbsence", {}).get("observations")
        if type(observations) is not list or len(observations) != 2:
            _fail("durable after-parking host proof is malformed")
        self.host_process_gone = any(
            item.get("hostProcess", {}).get("mode") == "PROCESS_ABSENT"
            for item in observations if type(item) is dict)
        self.host_residue_gone = any(
            item.get("windows", {}).get("residuePresent") is False
            for item in observations if type(item) is dict)

    def _host_process_observation(self) -> dict[str, Any]:
        stable = self.authority.prior_summary["stableAuthority"]
        pids = self.device.pidof(alpha.HOST_PACKAGE)
        if not pids:
            semantics = first._absent_process_semantics(
                self.device.host_processes(), stable)
            if self.device.pidof(alpha.HOST_PACKAGE):
                _fail("visual-host process appeared during absence proof")
            return {"mode": "PROCESS_ABSENT", "process": None,
                    "semantics": semantics,
                    "failedLifecycleSha256": None, "fdTargets": []}
        if pids != (prior.HOST_PID,):
            _fail("visual-host process set changed")
        try:
            process = self.device.process_identity(
                prior.HOST_PID, alpha.HOST_PACKAGE)
        except Exception as error:
            return self._reconcile_cached_host_exit(
                "process identity", error)
        expected = host.ProcessIdentity(
            prior.HOST_PID, prior.HOST_START_TICKS,
            prior.HOST_UID, alpha.HOST_PACKAGE)
        if process != expected:
            _fail("cached visual-host process identity changed")
        try:
            processes = self.device.host_processes()
        except Exception as error:
            return self._reconcile_cached_host_exit(
                "process inventory", error)
        try:
            semantics = first._cached_process_semantics(processes, stable)
        except Exception as error:
            if self.device.pidof(alpha.HOST_PACKAGE):
                raise ContinuationError(
                    "cached visual-host process inventory changed") from error
            return self._reconcile_cached_host_exit(
                "process inventory", error)
        try:
            fd_raw = self.device.process_fd_links(prior.HOST_PID)
        except Exception as error:
            return self._reconcile_cached_host_exit(
                "descriptor inventory", error)
        targets = prior._validated_fd_targets(fd_raw)
        forbidden = {
            alpha.SOURCE_PDF, alpha.SOURCE_MARK, alpha.PARKING_PDF,
            alpha.PARKING_MARK, alpha.TARGET_PDF, alpha.TARGET_MARK,
            prior.STAGING_PDF, prior.STAGING_MARK,
            prior.QUARANTINE_PDF, prior.QUARANTINE_MARK,
        }
        if targets.intersection(forbidden):
            _fail("cached visual-host process owns protected descriptors")
        try:
            log_raw = self.device.host_logs(prior.HOST_PID)
        except Exception as error:
            return self._reconcile_cached_host_exit(
                "lifecycle log", error)
        lifecycle = prior._validate_failed_host_log(log_raw)
        return {
            "mode": "CACHED_EMPTY_PROCESS", "process": asdict(process),
            "semantics": semantics, "fdTargets": sorted(targets),
            "failedLifecycleSha256": prior._canonical_sha(lifecycle),
        }

    def _reconcile_cached_host_exit(
            self, boundary: str, error: BaseException) -> dict[str, Any]:
        if self.device.pidof(alpha.HOST_PACKAGE):
            raise ContinuationError(
                "cached visual-host process lost its " + boundary) from error
        semantics = first._absent_process_semantics(
            self.device.host_processes(),
            self.authority.prior_summary["stableAuthority"])
        if self.device.pidof(alpha.HOST_PACKAGE):
            _fail("visual-host process appeared during " +
                  boundary + " reconciliation")
        return {
            "mode": "PROCESS_ABSENT", "process": None,
            "semantics": semantics,
            "failedLifecycleSha256": None, "fdTargets": [],
        }

    def _scope_observation(
            self, parking: dict[str, Any] | None = None) -> dict[str, Any]:
        raw = self.device.absence_raw()
        stable = self.authority.prior_summary["stableAuthority"]
        activity = first._strict_activity_absence(raw[0], stable)
        windows = first._window_residue_state(raw[1], stable)
        display = first._strict_display0_state(raw[2])
        if windows["rotation"] != display["rotation"]:
            _fail("WindowManager and display rotations disagree")
        if parking is None:
            activity_text = alpha._decode_text(
                raw[0], "after-parking activity inventory")
            window_text = alpha._decode_text(
                raw[1], "after-parking window inventory")
            document_present = (
                alpha.DOCUMENT_PACKAGE in activity_text or
                alpha.DOCUMENT_PACKAGE in window_text)
        else:
            authority = android.DocumentTaskAuthority(
                **parking["documentAuthority"])
            process = host.ProcessIdentity(**parking["process"])
            foreign = host.ForeignIdentity(
                process, authority.task_id, authority.activity_token,
                android.stable_authority_sha256(authority),
                alpha.DOCUMENT_COMPONENT)
            document_present = (
                first._contains_document_scope_for_continuation(
                    raw[0], foreign, authority) or
                alpha._contains_document_scope_for_global_absence(
                    raw[1], foreign, authority))
        return {
            "activities": activity, "windows": windows,
            "display": display,
            "hostProcess": self._host_process_observation(),
            "documentScopePresent": document_present,
        }

    def _accept_host_observation(
            self, observation: dict[str, Any],
            previous: dict[str, Any] | None = None) -> None:
        process_absent = observation["hostProcess"]["mode"] == "PROCESS_ABSENT"
        residue_absent = not observation["windows"]["residuePresent"]
        if self.host_process_gone and not process_absent:
            _fail("visual-host process reappeared")
        if self.host_residue_gone and not residue_absent:
            _fail("historical visual-host residue reappeared")
        if previous is not None:
            if (previous["hostProcess"]["mode"] == "PROCESS_ABSENT" and
                    not process_absent):
                _fail("visual-host process reappeared across proofs")
            if (not previous["windows"]["residuePresent"] and
                    not residue_absent):
                _fail("visual-host residue reappeared across proofs")
        self.host_process_gone = self.host_process_gone or process_absent
        self.host_residue_gone = self.host_residue_gone or residue_absent

    def _prove_host_absence_twice(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        for index in range(2):
            observation = self._scope_observation()
            self._accept_host_observation(
                observation, observations[-1] if observations else None)
            observations.append(observation)
            if index == 0:
                self.sleep(POLL_SECONDS)
        return self._proof("host_absence", observations=observations)

    def _capture_parking_twice(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        stable: dict[str, Any] | None = None
        for index in range(2):
            self._assert_initial_targets()
            identity = self.device.parking_identity()
            current = _parking_stable(identity)
            if stable is None:
                stable = current
            elif current != stable:
                _fail("pinned parking authority changed across admission")
            observations.append(identity)
            if index == 0:
                self.sleep(POLL_SECONDS)
        assert stable is not None
        self.retained_parking = observations[-1]
        return self._proof(
            "parking_launch_adoption", stableAuthority=stable,
            stableAuthoritySha256=prior._canonical_sha(stable),
            observations=observations,
            priorDispatchRecordSha256=FIRST_HEAD,
            parkingLaunchDispatchMayRepeat=False)

    def plan(self) -> dict[str, Any]:
        _assert_publication_paths_clear(
            self.authority, before_journal=self.journal is None)
        self._assert_tools()
        environment = self.device.environment()
        if self.environment is None:
            self.environment = environment
        elif environment != self.environment:
            _fail("package environment changed during admission")
        self._assert_rotation()
        self._assert_static()
        self._assert_initial_targets()
        host_absence = self._prove_host_absence_twice()
        parking = self._capture_parking_twice()
        return {
            "authority": AUTHORITY, "mode": "plan",
            "result": "AFTER_PARKING_PLAN_READY",
            "deviceMutationAttempted": False,
            "environment": environment,
            "priorRecovery": {
                "identity": self.authority.prior_identity,
                "summary": self.authority.prior_summary,
                "immutable": True,
            },
            "firstContinuation": {
                "identity": self.authority.first_identity,
                "summary": self.authority.first_summary,
                "immutable": True, "parkingLaunchMayRepeat": False,
            },
            "hostAbsence": host_absence,
            "parkingLaunchAdoption": parking,
            "plannedSequence": [
                "ADOPT_VALIDATED_PARKING_LAUNCH_WITHOUT_REDISPATCH",
                "REMOVE_EXACT_TASK_4648",
                "PROVE_DOCUMENT_ABSENCE",
                "WAIT_FOR_DESCRIPTOR_RELEASE_OR_STOP_PENDING",
                "DELETE_MARK_IF_RELEASED", "DELETE_PDF_IF_RELEASED",
                "ARCHIVE_ACTIVE_JOURNAL_IF_CLEAN",
            ],
            "proofs": self.proofs,
        }

    def _intent(self, name: str, payload: dict[str, Any]) -> None:
        if self.journal is None:
            _fail("execute mode lacks an after-parking ledger")
        if self.journal.one(name + "_intent") is not None:
            _fail("after-parking ledger cannot be resumed in place")
        self._assert_dispatch_authority()
        self._assert_rotation()
        self._assert_static()
        record = self.journal.append(name + "_intent", payload)
        self.mutations.append({
            "kind": name, "sequence": record["sequence"], **payload})

    def _settle(self, name: str, payload: dict[str, Any]) -> None:
        if self.journal is None:
            _fail("execute mode lacks an after-parking ledger")
        existing = self.journal.one(name + "_settled")
        if existing is not None:
            if existing["payload"] != payload:
                _fail("after-parking settlement differs: " + name)
            return
        self.journal.append(name + "_settled", payload)

    def _record_dispatch_outcome(
            self, name: str, *, result: alpha.CommandResult | None = None,
            uncertain: prior.MutationTransportUncertain | None = None,
            ) -> dict[str, Any]:
        if self.journal is None or (result is None) == (uncertain is None):
            _fail("mutation outcome is ambiguous")
        if result is not None:
            payload = {
                "mode": "VALIDATED_RECEIPT", "operation": result.operation,
                "returncode": result.returncode,
                "stdoutSize": len(result.stdout),
                "stdoutSha256": prior._sha(result.stdout),
                "stderrSize": len(result.stderr),
                "stderrSha256": prior._sha(result.stderr),
                "receiptGrammar": "EXACT_EMPTY_STREAMS",
            }
        else:
            assert uncertain is not None
            payload = {
                "mode": "TRANSPORT_UNCERTAIN",
                "errorType": type(uncertain).__name__,
                "error": str(uncertain),
            }
        record = self.journal.append(name + "_dispatch_outcome", payload)
        retained = {"kind": name, "sequence": record["sequence"], **payload}
        self.dispatch_outcomes.append(retained)
        return retained

    def _record_mutation_failure(self, name: str, error: BaseException) -> None:
        if self.journal is None:
            _fail("execute mode lacks an after-parking ledger")
        self.journal.append(name + "_semantic_failure", {
            "errorType": type(error).__name__, "error": str(error)})

    def _adopt_parking_launch(self, admission: dict[str, Any]) -> dict[str, Any]:
        adoption = admission["parkingLaunchAdoption"]
        payload = {
            "firstContinuationSha256": FIRST_SHA256,
            "firstContinuationHead": FIRST_HEAD,
            "validatedReceiptRecordSha256": FIRST_HEAD,
            "stableAuthoritySha256": adoption["stableAuthoritySha256"],
            "taskId": PINNED_TASK_ID,
            "dispatchRepeated": False,
        }
        self._settle("parking_launch_adopted", payload)
        return payload

    def _runtime_remove_boundary(
            self, expected_stable: dict[str, Any]) -> dict[str, Any]:
        self._assert_dispatch_authority()
        environment = self.device.environment()
        if self.environment is None or environment != self.environment:
            _fail("package environment changed before parking removal")
        self._assert_rotation()
        self._assert_static()
        self._assert_initial_targets()
        host_observation = self._scope_observation()
        self._accept_host_observation(host_observation)
        identity = self.device.parking_identity()
        if _parking_stable(identity) != expected_stable:
            _fail("pinned parking authority changed before removal")
        self._assert_initial_targets()
        # The final device sample again binds the numeric task, host-free
        # AM/WM/DM state, exact process, and exact 44/65/93 FD authority.
        final_identity = self.device.parking_identity()
        if _parking_stable(final_identity) != expected_stable:
            _fail("pinned parking authority changed at removal boundary")
        assert self.journal is not None
        self.journal.assert_authority()
        return self._proof(
            "immediate_pre_remove_boundary",
            hostObservation=host_observation,
            parkingStable=expected_stable,
            finalParkingEvidence={
                "activitiesSha256": final_identity["activitiesSha256"],
                "windowsSha256": final_identity["windowsSha256"],
                "fdRawSha256": final_identity["fdAuthority"]["rawSha256"],
            })

    def _prove_document_absence_twice(
            self, parking: dict[str, Any]) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        last_present: dict[str, Any] | None = None
        for _ in range(POLL_LIMIT):
            observation = self._scope_observation(parking)
            self._accept_host_observation(
                observation, observations[-1] if observations else None)
            if observation["documentScopePresent"]:
                if self.document_scope_gone or observations:
                    _fail("stock Document scope reappeared after task removal")
                last_present = observation
                self.sleep(POLL_SECONDS)
                continue
            self.document_scope_gone = True
            observations.append(observation)
            if len(observations) == 2:
                break
            self.sleep(POLL_SECONDS)
        if len(observations) != 2:
            _fail("stock Document task/window did not leave after exact removal")
        return self._proof(
            "post_remove_document_absence", observations=observations,
            lastPresentSha256=(None if last_present is None else
                               prior._canonical_sha(last_present)))

    def _document_inventory(self) -> dict[str, Any]:
        raw = self.device.host_processes()
        text, _ = first._process_inventory_text(raw)
        package_lines = [line for line in text.splitlines()
                         if "ProcessRecord{" in line and
                         alpha.DOCUMENT_PACKAGE in line]
        record_pattern = re.compile(r"ProcessRecord\{[^{}\r\n]+\}")
        exact_pattern = re.compile(
            r"ProcessRecord\{([0-9a-f]+) ([1-9][0-9]*):" +
            re.escape(alpha.DOCUMENT_PACKAGE) + r"/(1000)\}")
        records: set[tuple[str, str]] = set()
        malformed: list[str] = []
        for line in package_lines:
            occurrences = list(record_pattern.finditer(line))
            owned = [match.group(0) for match in occurrences
                     if alpha.DOCUMENT_PACKAGE in match.group(0)]
            residual = record_pattern.sub("", line)
            structurally_malformed = (
                line.count("ProcessRecord{") != len(occurrences) or
                alpha.DOCUMENT_PACKAGE in residual)
            if not owned or structurally_malformed:
                malformed.append(line)
            for encoded in owned:
                match = exact_pattern.fullmatch(encoded)
                if match is None:
                    malformed.append(encoded)
                else:
                    token, pid, _uid = match.groups()
                    records.add((token, pid))
        # Account for every numeric-PID alias whose process token begins with
        # the Document package, before deciding whether it is canonical.  The
        # UID portion is intentionally broad: a non-production spelling such
        # as /9999 or /u0a1000, or /1000/u0 in a colon-form alias, must remain
        # visible evidence rather than disappearing from the process set.
        alias_candidate = re.compile(
            r"(?<![A-Za-z0-9_])([0-9]+)(:|[ \t]+)(" +
            re.escape(alpha.DOCUMENT_PACKAGE) +
            r"[^/\s{}\[\](),]*)/([^\s{}\[\](),]*)")
        aliases: set[tuple[int, str, str]] = set()
        malformed_aliases: set[str] = set()
        for match in alias_candidate.finditer(text):
            pid, separator, name, uid = match.groups()
            canonical_uid = (
                uid == "1000" if separator == ":" else
                uid in ("1000", "1000/u0"))
            if (pid == str(PINNED_DOCUMENT_PROCESS.pid) and
                    name == alpha.DOCUMENT_PACKAGE and canonical_uid):
                aliases.add((int(pid), name, "1000"))
            else:
                malformed_aliases.add(match.group(0))
        lines = text.splitlines()
        process_header = re.compile(
            r"^  \*[A-Z]+\* UID ([1-9][0-9]*) "
            r"ProcessRecord\{([0-9a-f]+) ([1-9][0-9]*):"
            r"([^/\s{}]+)/(1000)\}$")
        header_candidate = re.compile(
            r"^(?:[ \t]*\*[^*\r\n]+\*| {0,3}\S)[^\r\n]*"
            r"ProcessRecord\{")
        headers = [(index, process_header.fullmatch(line))
                   for index, line in enumerate(lines)
                   if header_candidate.match(line) is not None]
        owners: set[tuple[str, int, str, str]] = set()
        owned_package_lines: set[int] = set()
        malformed_owners: list[str] = []
        for position, (start, match) in enumerate(headers):
            next_header = (headers[position + 1][0]
                           if position + 1 < len(headers) else len(lines))
            section_end = next((index for index in range(start + 1, next_header)
                                if lines[index].startswith(
                                    "  Process OOM control (")), next_header)
            for index in range(start + 1, section_end):
                line = lines[index]
                if "packageList=" not in line or \
                        alpha.DOCUMENT_PACKAGE not in line:
                    continue
                owned_package_lines.add(index)
                package_match = re.fullmatch(
                    r"    packageList=\{([^{}]*)\}", line)
                if package_match is None:
                    malformed_owners.append(line)
                    continue
                encoded_packages = package_match.group(1)
                if re.fullmatch(
                        r"[A-Za-z0-9_.]+(?:, [A-Za-z0-9_.]+)*",
                        encoded_packages) is None:
                    malformed_owners.append(line)
                    continue
                packages = encoded_packages.split(", ")
                if alpha.DOCUMENT_PACKAGE not in packages:
                    # The raw line contains the package spelling but not as a
                    # closed package-list token.  It cannot be ignored.
                    malformed_owners.append(line)
                    continue
                if match is None:
                    malformed_owners.append(lines[start])
                    continue
                header_uid, token, pid, name, _uid = match.groups()
                if header_uid != "1000":
                    malformed_owners.append(lines[start])
                owners.add((token, int(pid), name, "1000"))
        for index, line in enumerate(lines):
            if ("packageList=" in line and
                    alpha.DOCUMENT_PACKAGE in line and
                    index not in owned_package_lines):
                malformed_owners.append(line)
        return {
            "rawSha256": prior._sha(raw),
            "records": [{"token": token, "pid": int(pid)}
                        for token, pid in sorted(records)],
            "malformedPackageRecords": malformed,
            "processAliases": [
                {"pid": pid, "processName": name, "uid": uid}
                for pid, name, uid in sorted(aliases)],
            "malformedProcessAliases": sorted(malformed_aliases),
            "packageOwners": [
                {"token": token, "pid": pid, "processName": name,
                 "uid": uid}
                for token, pid, name, uid in sorted(owners)],
            "malformedPackageOwners": malformed_owners,
        }

    def _descriptor_observation(self) -> dict[str, Any]:
        pids_before = self.device.pidof(alpha.DOCUMENT_PACKAGE)
        inventory_before = self._document_inventory()
        inventory_pairs = {(item["token"], item["pid"])
                           for item in inventory_before["records"]}
        expected_pair = {(PINNED_PROCESS_TOKEN, PINNED_DOCUMENT_PROCESS.pid)}
        expected_alias = {(
            PINNED_DOCUMENT_PROCESS.pid, alpha.DOCUMENT_PACKAGE, "1000")}
        expected_owner = {(
            PINNED_PROCESS_TOKEN, PINNED_DOCUMENT_PROCESS.pid,
            alpha.DOCUMENT_PACKAGE, "1000")}
        aliases_before = {
            (item["pid"], item["processName"], item["uid"])
            for item in inventory_before["processAliases"]}
        owners_before = {
            (item["token"], item["pid"], item["processName"], item["uid"])
            for item in inventory_before["packageOwners"]}
        if not pids_before:
            pids_after = self.device.pidof(alpha.DOCUMENT_PACKAGE)
            inventory_after = self._document_inventory()
            if (pids_after or inventory_before["records"] or
                    inventory_before["malformedPackageRecords"] or
                    inventory_before["processAliases"] or
                    inventory_before["malformedProcessAliases"] or
                    inventory_before["packageOwners"] or
                    inventory_before["malformedPackageOwners"] or
                    inventory_after["records"] or
                    inventory_after["malformedPackageRecords"] or
                    inventory_after["processAliases"] or
                    inventory_after["malformedProcessAliases"] or
                    inventory_after["packageOwners"] or
                    inventory_after["malformedPackageOwners"]):
                return {
                    "state": "PENDING_UNCERTAIN_PROCESS",
                    "pidofBefore": list(pids_before),
                    "pidofAfter": list(pids_after),
                    "inventoryBefore": inventory_before,
                    "inventoryAfter": inventory_after,
                }
            return {
                "state": "CLOSED", "mode": "PROCESS_ABSENT",
                "pidof": [], "inventory": inventory_after,
                "relevantFdTargets": [], "sharedFds": {},
            }
        if (pids_before != (PINNED_DOCUMENT_PROCESS.pid,) or
                inventory_pairs != expected_pair or
                aliases_before != expected_alias or
                owners_before != expected_owner or
                inventory_before["malformedPackageRecords"] or
                inventory_before["malformedProcessAliases"] or
                inventory_before["malformedPackageOwners"]):
            return {
                "state": "PENDING_CHANGED_PROCESS_SET",
                "pidof": list(pids_before), "inventory": inventory_before,
            }
        try:
            process = self.device.process_identity(
                PINNED_DOCUMENT_PROCESS.pid, alpha.DOCUMENT_PACKAGE)
            if process != PINNED_DOCUMENT_PROCESS:
                return {
                    "state": "PENDING_CHANGED_PROCESS_IDENTITY",
                    "pidof": list(pids_before), "inventory": inventory_before,
                    "process": asdict(process),
                }
            fd_raw = self.device.process_fd_links(process.pid)
        except Exception as error:
            pids_after = self.device.pidof(alpha.DOCUMENT_PACKAGE)
            inventory_after = self._document_inventory()
            if (not pids_after and not inventory_after["records"] and
                    not inventory_after["malformedPackageRecords"] and
                    not inventory_after["processAliases"] and
                    not inventory_after["malformedProcessAliases"] and
                    not inventory_after["packageOwners"] and
                    not inventory_after["malformedPackageOwners"]):
                return {
                    "state": "CLOSED", "mode": "PROCESS_EXIT_RECONCILED",
                    "pidof": [], "inventory": inventory_after,
                    "relevantFdTargets": [], "sharedFds": {},
                    "readError": type(error).__name__ + ": " + str(error),
                }
            return {
                "state": "PENDING_UNCERTAIN_PROCESS_READ",
                "pidof": list(pids_after), "inventory": inventory_after,
                "readError": type(error).__name__ + ": " + str(error),
            }
        targets, shared = _fd_inventory(fd_raw)
        relevant = sorted(targets.intersection({
            alpha.TARGET_PDF, alpha.TARGET_MARK,
            alpha.PARKING_PDF, alpha.PARKING_MARK,
        }))
        state = "CLOSED" if not targets and not shared else "PENDING_OPEN_FDS"
        pids_after = self.device.pidof(alpha.DOCUMENT_PACKAGE)
        inventory_after = self._document_inventory()
        after_pairs = {(item["token"], item["pid"])
                       for item in inventory_after["records"]}
        aliases_after = {
            (item["pid"], item["processName"], item["uid"])
            for item in inventory_after["processAliases"]}
        owners_after = {
            (item["token"], item["pid"], item["processName"], item["uid"])
            for item in inventory_after["packageOwners"]}
        try:
            process_after = self.device.process_identity(
                process.pid, alpha.DOCUMENT_PACKAGE)
        except Exception as error:
            return {
                "state": "PENDING_PROCESS_CHANGED_DURING_FD_READ",
                "process": asdict(process), "inventory": inventory_before,
                "pidofAfter": list(pids_after),
                "inventoryAfter": inventory_after,
                "readError": type(error).__name__ + ": " + str(error),
            }
        if (pids_after != (process.pid,) or process_after != process or
                after_pairs != expected_pair or
                aliases_after != expected_alias or
                owners_after != expected_owner or
                inventory_after["malformedPackageRecords"] or
                inventory_after["malformedProcessAliases"] or
                inventory_after["malformedPackageOwners"]):
            return {
                "state": "PENDING_PROCESS_CHANGED_DURING_FD_READ",
                "process": asdict(process), "processAfter": asdict(process_after),
                "inventory": inventory_before,
                "pidofAfter": list(pids_after),
                "inventoryAfter": inventory_after,
            }
        return {
            "state": state, "mode": "RETAINED_PROCESS",
            "process": asdict(process), "inventory": inventory_before,
            "inventoryAfter": inventory_after,
            "relevantFdTargets": relevant,
            "allPdfMarkTargets": sorted(targets),
            "sharedFds": {str(key): value for key, value in sorted(shared.items())},
            "fdRawSha256": prior._sha(fd_raw.encode("utf-8")),
        }

    def _descriptor_release(self) -> tuple[bool, dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        closed: list[dict[str, Any]] = []
        for _ in range(POLL_LIMIT):
            scope = self._scope_observation(self.retained_parking)
            self._accept_host_observation(scope)
            if scope["documentScopePresent"]:
                _fail("stock Document scope reappeared during descriptor wait")
            observation = self._descriptor_observation()
            observations.append(observation)
            if observation["state"] == "CLOSED":
                closed.append(observation)
                if len(closed) == 2:
                    payload = self._proof(
                        "descriptor_release", observations=observations,
                        terminal="CLOSED_TWICE")
                    self._settle("descriptor_release", payload)
                    return True, payload
            else:
                if closed:
                    _fail("disposable descriptors reappeared after closure")
            self.sleep(POLL_SECONDS)
        payload = self._proof(
            "descriptor_release_pending", observations=observations,
            terminal="DESCRIPTOR_RELEASE_PENDING",
            fileMutationAuthorized=False,
            activeJournalArchiveAuthorized=False)
        self._settle("descriptor_release_pending", payload)
        return False, payload

    def _remove_parking(self, admission: dict[str, Any]) -> dict[str, Any]:
        stable = admission["parkingLaunchAdoption"]["stableAuthority"]
        payload = {
            "taskId": PINNED_TASK_ID, "stableAuthority": stable,
            "stableAuthoritySha256": prior._canonical_sha(stable),
            "priorParkingReceiptRecordSha256": FIRST_HEAD,
            "dispatchMayRepeat": False,
        }
        self._intent("parking_task_remove", payload)
        boundary = self._runtime_remove_boundary(stable)
        try:
            result = self.device.remove_parking_task(PINNED_TASK_ID)
            prior._validate_mutation_result(result, "remove_exact_task")
            dispatch = self._record_dispatch_outcome(
                "parking_task_remove", result=result)
        except prior.MutationTransportUncertain as error:
            dispatch = self._record_dispatch_outcome(
                "parking_task_remove", uncertain=error)
        except Exception as error:
            self._record_mutation_failure("parking_task_remove", error)
            raise
        absence = self._prove_document_absence_twice(self.retained_parking or {})
        settled = {
            "taskId": PINNED_TASK_ID,
            "boundarySha256": boundary["sha256"],
            "dispatch": dispatch,
            "absenceSha256": absence["sha256"],
        }
        self._settle("parking_task_remove", settled)
        return settled

    def _authorize_target_mark(self) -> dict[str, Any]:
        if (self.device.stat_file(
                alpha.TARGET_PDF, absent_ok=True) !=
                self.retained_targets[alpha.TARGET_PDF]):
            _fail("target PDF changed at parking removal")
        for quarantine in prior.QUARANTINES.values():
            if self.device.stat_file(quarantine, absent_ok=True) is not None:
                _fail("quarantine appeared at parking removal")
        current = self.device.stat_file(alpha.TARGET_MARK, absent_ok=True)
        retained = self.retained_targets[alpha.TARGET_MARK]
        if current == retained:
            return {"mode": "ORIGINAL_RETAINED", "retained": asdict(retained)}
        original = prior.PINNED_TARGET_MARK
        eligible = (
            current is not None and current.path == alpha.TARGET_MARK and
            current.kind == original.kind == "regular file" and
            current.inode != original.inode and
            (current.size, current.uid, current.gid, current.device,
             current.sha256) ==
            (original.size, original.uid, original.gid, original.device,
             original.sha256))
        if not eligible or self.target_mark_adoption is not None:
            _fail("target mark changed outside the one eligible replacement")
        assert current is not None
        adoption = {
            "path": alpha.TARGET_MARK, "previous": asdict(original),
            "current": asdict(current), "sameContentOwnerDevice": True,
        }
        self.retained_targets[alpha.TARGET_MARK] = current
        self.target_mark_adoption = adoption
        self._settle("target_mark_authority_adopted", adoption)
        return {"mode": "ADOPTED_REPLACEMENT", "retained": asdict(current),
                "adoption": adoption}

    def _runtime_file_boundary(
            self, path: str, quarantine: str,
            expected: alpha.DeviceFile, *, source_present: bool) -> dict[str, Any]:
        self._assert_dispatch_authority()
        self._assert_rotation()
        self._assert_static()
        scope = self._scope_observation(self.retained_parking)
        self._accept_host_observation(scope)
        if scope["documentScopePresent"]:
            _fail("stock Document scope reappeared before file mutation")
        descriptor = self._descriptor_observation()
        if descriptor["state"] != "CLOSED":
            _fail("disposable descriptor authority reopened before file mutation")
        source = self.device.stat_file(path, absent_ok=True)
        quarantined = self.device.stat_file(quarantine, absent_ok=True)
        if source_present:
            if source != expected or quarantined is not None:
                _fail("quarantine-move file authority changed")
        elif (source is not None or quarantined is None or
              not prior._same_renamed(expected, quarantined, quarantine)):
            _fail("quarantine-delete file authority changed")
        assert self.journal is not None
        self.journal.assert_authority()
        return self._proof(
            "immediate_pre_file_mutation", path=path,
            quarantine=quarantine, sourcePresent=source_present,
            descriptor=descriptor, scope=scope)

    def _prove_path_absent_twice(self, path: str) -> None:
        for index in range(2):
            if self.device.stat_file(path, absent_ok=True) is not None:
                _fail("path remains present: " + path)
            if index == 0:
                self.sleep(POLL_SECONDS)

    def _quarantine_delete(self, path: str) -> None:
        expected = self.retained_targets[path]
        quarantine = prior.QUARANTINES[path]
        stem = "mark" if path == alpha.TARGET_MARK else "pdf"
        if (self.device.stat_file(path, absent_ok=True) != expected or
                self.device.stat_file(quarantine, absent_ok=True) is not None):
            _fail("initial quarantine authority differs for " + path)
        move_payload = {
            "source": path, "quarantine": quarantine,
            "retained": asdict(expected)}
        self._intent(stem + "_quarantine_move", move_payload)
        self._runtime_file_boundary(
            path, quarantine, expected, source_present=True)
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
            self._record_mutation_failure(stem + "_quarantine_move", error)
            raise
        self._prove_path_absent_twice(path)
        quarantined = self.device.stat_file(quarantine, absent_ok=True)
        if (quarantined is None or
                not prior._same_renamed(expected, quarantined, quarantine)):
            _fail("one-shot quarantine move did not settle exactly")
        self._settle(stem + "_quarantine_move", {
            "source": path, "quarantine": quarantine,
            "retained": asdict(quarantined)})
        delete_payload = {
            "source": path, "quarantine": quarantine,
            "retained": asdict(quarantined)}
        self._intent(stem + "_quarantine_delete", delete_payload)
        self._runtime_file_boundary(
            path, quarantine, expected, source_present=False)
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
            self._record_mutation_failure(stem + "_quarantine_delete", error)
            raise
        self._prove_path_absent_twice(quarantine)
        self._prove_path_absent_twice(path)
        self._settle(stem + "_quarantine_delete", {
            "source": path, "quarantine": quarantine, "observations": 2})

    def _joint_absence(self) -> dict[str, Any]:
        paths = (alpha.TARGET_MARK, alpha.TARGET_PDF,
                 prior.QUARANTINE_MARK, prior.QUARANTINE_PDF)
        observations: list[dict[str, Any]] = []
        for index in range(2):
            present = [path for path in paths
                       if self.device.stat_file(path, absent_ok=True) is not None]
            if present:
                _fail("joint disposable-file absence is not stable")
            observations.append({"observation": index + 1,
                                 "absent": list(paths)})
            if index == 0:
                self.sleep(POLL_SECONDS)
        return self._proof("joint_target_absence", observations=observations)

    def _archive_active(self) -> dict[str, Any]:
        payload = {
            "activePath": str(self.authority.active_path),
            "retiredPath": str(self.authority.retired_path),
            "sha256": self.authority.active_identity["sha256"],
            "device": self.authority.active_identity["device"],
            "inode": self.authority.active_identity["inode"],
        }
        self._intent("active_journal_archive", payload)
        raw, identity = _read_sole_regular(
            self.authority.active_path, 256 * 1024,
            "active journal immediately before archive")
        identity = {**identity, "path": str(self.authority.active_path)}
        if identity != self.authority.active_identity:
            _fail("active journal changed before archive")
        prior._verify_mutation_journal(raw)
        assert self.journal is not None
        self.journal.assert_authority()
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
            move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR,
                             wintypes.DWORD)
            move.restype = wintypes.BOOL
            if not move(str(self.authority.active_path),
                        str(self.authority.retired_path), 0x00000008):
                raise ContinuationError(
                    "active-journal archive failed with Windows error " +
                    str(ctypes.get_last_error()))
        else:
            os.rename(self.authority.active_path, self.authority.retired_path)
        prior._fsync_directory(self.authority.active_path.parent)
        _, retired = _read_sole_regular(
            self.authority.retired_path, 256 * 1024,
            "retired active mutation journal")
        if ((retired["device"], retired["inode"], retired["size"],
             retired["sha256"]) !=
                (self.authority.active_identity["device"],
                 self.authority.active_identity["inode"],
                 self.authority.active_identity["size"],
                 self.authority.active_identity["sha256"])):
            _fail("archived active journal identity differs")
        self._settle("active_journal_archive", retired)
        return retired

    def _publish_clean_evidence(self, result: dict[str, Any]) -> None:
        encoded = json.dumps(
            result, indent=2, sort_keys=True, ensure_ascii=True,
            allow_nan=False).encode("ascii") + b"\n"
        assert self.journal is not None
        self.journal.assert_authority()
        self._assert_local_after_archive()
        try:
            descriptor = os.open(
                self.authority.evidence_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError as error:
            raise ContinuationError(
                "after-parking evidence path became occupied") from error
        try:
            if os.write(descriptor, encoded) != len(encoded):
                _fail("short after-parking evidence write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        prior._fsync_directory(self.authority.evidence_path.parent)

    def execute(self) -> dict[str, Any]:
        if self.journal is None:
            _fail("execute mode requires the after-parking ledger")
        admission = self.plan()
        adopted = self._adopt_parking_launch(admission)
        parking = self._remove_parking(admission)
        released, descriptor = self._descriptor_release()
        if not released:
            return {
                "authority": AUTHORITY, "mode": "execute",
                "result": "DESCRIPTOR_RELEASE_PENDING",
                "runId": prior.RUN_ID,
                "parkingLaunchAdoption": adopted,
                "parkingTaskRemoval": parking,
                "descriptorRelease": descriptor,
                "fileMutationAttempted": False,
                "activeJournalArchived": False,
                "firstContinuationPreserved": True,
                "priorRecoveryPreserved": True,
                "afterParkingJournal": str(self.authority.journal_path),
                "mutations": self.mutations,
                "dispatchOutcomes": self.dispatch_outcomes,
                "proofs": self.proofs,
            }
        mark = self._authorize_target_mark()
        self._quarantine_delete(alpha.TARGET_MARK)
        self._quarantine_delete(alpha.TARGET_PDF)
        joint = self._joint_absence()
        self._assert_static()
        self._assert_rotation()
        final_scope = self._scope_observation(self.retained_parking)
        self._accept_host_observation(final_scope)
        if final_scope["documentScopePresent"]:
            _fail("stock Document scope reappeared at final settlement")
        if self._descriptor_observation()["state"] != "CLOSED":
            _fail("disposable descriptor authority reopened at final settlement")
        retired = self._archive_active()
        self._assert_ledgers()
        result = {
            "authority": AUTHORITY, "mode": "execute",
            "result": "AFTER_PARKING_RECOVERED_CLEANLY",
            "runId": prior.RUN_ID,
            "parkingLaunchAdoption": adopted,
            "parkingTaskRemoval": parking,
            "descriptorRelease": descriptor,
            "targetMarkAuthority": mark,
            "jointTargetAbsence": joint,
            "activeJournalArchived": retired,
            "firstContinuationPreserved": True,
            "priorRecoveryPreserved": True,
            "mutations": self.mutations,
            "dispatchOutcomes": self.dispatch_outcomes,
            "proofs": self.proofs,
            "deletedDisposablePaths": [alpha.TARGET_MARK, alpha.TARGET_PDF],
            "residualAssumption": prior.RESIDUAL_ASSUMPTION,
        }
        self._publish_clean_evidence(result)
        return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="perform the exact after-parking continuation")
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
    journal: Journal | None = None
    try:
        authority = load_authority(root, report, active)
        if arguments.execute:
            _assert_publication_paths_clear(authority, before_journal=True)
        device = SecondNomad(arguments.adb, alpha.AUTHORIZED_SERIAL)
        recovery = Recovery(device, authority)
        if not arguments.execute:
            result = recovery.plan()
        else:
            admission = recovery.plan()
            header = recovery._header()
            header["admissionSha256"] = prior._canonical_sha(admission)
            journal = Journal(authority.journal_path, header)
            executor = Recovery(
                device, authority, journal=journal,
                durable_header=journal.records[0]["payload"],
                prior_admission=admission)
            journal.external_guard = executor._assert_dispatch_authority
            result = executor.execute()
        print(json.dumps(result, indent=2, sort_keys=True,
                         ensure_ascii=True, allow_nan=False))
        return 0
    except (ContinuationError, prior.RecoveryError,
            android.AndroidAuthorityError, alpha.AlphaError,
            OSError, ValueError) as error:
        print("AFTER_PARKING_CONTINUATION_ERROR: " + str(error),
              file=sys.stderr)
        return 1
    finally:
        if journal is not None:
            journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
