"""Plan-bound post-restart orphan cleanup for one retained alpha run.

This helper is deliberately separate from ``recover_launch_identity_alpha_run``.
The launch-identity helper remains authoritative when its exact task, process,
window, and display identities are still live.  This helper admits only the
opposite state: that retained launch authority is positively absent, the
disposable files still have their exact retained identities, and any current
stock Document task is provably unrelated to those files.

Plan mode is read-only and is the default.  Execute mode is one-shot and may
only quarantine/delete the exact disposable MARK followed by the exact PDF,
retire the retained active journal after verified closure, and publish bounded
evidence.  It has no task-removal or package-force-stop operation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, NoReturn, Protocol, Sequence

import native_page_alpha_runner as alpha
import native_page_android_authority as android
import native_page_host_authority as host
import recover_launch_identity_alpha_run as launch


AUTHORITY = "native-page-alpha-post-restart-orphan-recovery-v2"
PLAN_AUTHORITY = "native-page-alpha-post-restart-orphan-recovery-plan-v2"
PLAN_BASENAME = "post-restart-orphan-recovery-plan.json"
LEDGER_BASENAME = "post-restart-orphan-recovery.jsonl"
EVIDENCE_BASENAME = "post-restart-orphan-recovery-evidence.json"

LAUNCH_HELPER_BYTES = 50_689
LAUNCH_HELPER_SHA256 = (
    "5ea5115d65bce00fcda175850c2b271b252defa589461dcfbad3d8a769d5705c")

MAX_LOCAL_BYTES = 2 * 1024 * 1024

TARGET_PDF = launch.TARGET_PDF
TARGET_MARK = launch.TARGET_MARK
TARGETS = launch.TARGETS
STAGING = launch.STAGING
QUARANTINES = launch.QUARANTINES
ORIGINALS = launch.ORIGINALS
PARKING = launch.PARKING
PARKING_PDF = launch.PARKING_PDF
PARKING_MARK = launch.PARKING_MARK
PROTECTED_PATHS = launch.PROTECTED_PATHS
DISPLAY_NAME = launch.DISPLAY_NAME


class RecoveryError(RuntimeError):
    """The fixed post-restart orphan authority is absent or changed."""


MutationTransportUncertain = launch.MutationTransportUncertain


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
    return launch._sha(raw)  # type: ignore[attr-defined]


def _canonical_sha(value: Any) -> str:
    return _sha(_canonical(value))


def _read_regular(path: Path, maximum: int,
                  label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        return launch._read_regular(path, maximum, label)  # type: ignore[attr-defined]
    except launch.RecoveryError as error:
        raise RecoveryError(str(error)) from error


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
    launch.prior._fsync_directory(path.parent)  # type: ignore[attr-defined]
    observed, identity = _read_regular(path, len(raw), "exclusive publication")
    if observed != raw:
        _fail("exclusive publication reread differs")
    return identity


@dataclass(frozen=True)
class Authority:
    root: Path
    report_path: Path
    active_path: Path
    retired_path: Path
    ledger_path: Path
    evidence_path: Path
    plan_path: Path
    report_identity: dict[str, Any]
    active_identity: dict[str, Any]
    dependency_identities: dict[str, dict[str, Any]]


def load_authority(root: Path) -> Authority:
    root = root.resolve()
    try:
        retained = launch.load_authority(root)
    except launch.RecoveryError as error:
        raise RecoveryError(str(error)) from error
    if (os.path.lexists(retained.ledger_path) or
            os.path.lexists(retained.evidence_path)):
        _fail("launch-identity recovery already owns this retained run")
    run_dir = retained.report_path.parent
    ledger_path = run_dir / LEDGER_BASENAME
    evidence_path = run_dir / EVIDENCE_BASENAME
    plan_path = run_dir / PLAN_BASENAME
    if os.path.lexists(ledger_path) or os.path.lexists(evidence_path):
        _fail("post-restart recovery is already occupied")

    dependencies = dict(retained.dependency_identities)
    launch_raw, launch_identity = _read_regular(
        root / "recover_launch_identity_alpha_run.py",
        LAUNCH_HELPER_BYTES, "launch-identity recovery helper")
    if (len(launch_raw) != LAUNCH_HELPER_BYTES or
            launch_identity["sha256"] != LAUNCH_HELPER_SHA256):
        _fail("launch-identity recovery helper differs")
    dependencies["recover_launch_identity_alpha_run.py"] = launch_identity
    self_path = Path(__file__).resolve()
    _, self_identity = _read_regular(
        self_path, MAX_LOCAL_BYTES, "post-restart recovery helper")
    dependencies[self_path.name] = self_identity
    return Authority(
        root, retained.report_path, retained.active_path,
        retained.retired_path, ledger_path, evidence_path, plan_path,
        retained.report_identity, retained.active_identity, dependencies)


def _authority_guard(authority: Authority) -> None:
    report_raw, report = _read_regular(
        authority.report_path, 128 * 1024, "fixed report")
    active_raw, active = _read_regular(
        authority.active_path, 256 * 1024, "active journal")
    active = {**active, "path": str(authority.active_path)}
    if (report != authority.report_identity or
            active != authority.active_identity or
            len(report_raw) != launch.REPORT_BYTES or
            len(active_raw) != launch.ACTIVE_BYTES):
        _fail("fixed report or active journal changed")
    for name, identity in authority.dependency_identities.items():
        _, current = _read_regular(authority.root / name, identity["size"], name)
        if current != identity:
            _fail(name + " changed after admission")


def _file_wire(value: alpha.DeviceFile | None) -> dict[str, Any] | None:
    return None if value is None else asdict(value)


def _assert_file_set(
        device: "Device", phase: str,
        present_targets: frozenset[str]) -> dict[str, dict[str, Any] | None]:
    if not present_targets.issubset(TARGETS):
        _fail(phase + ": disposable-presence set escaped fixed targets")
    values: dict[str, dict[str, Any] | None] = {}
    for path in sorted(PROTECTED_PATHS):
        value = device.stat_file(path, absent_ok=True)
        values[path] = _file_wire(value)
        if path in ORIGINALS and value != ORIGINALS[path]:
            _fail(phase + ": original file identity changed")
        if path == PARKING_PDF and value != PARKING:
            _fail(phase + ": parking PDF identity changed")
        if path == PARKING_MARK and value is not None:
            _fail(phase + ": parking MARK unexpectedly exists")
        if path in STAGING.values() and value is not None:
            _fail(phase + ": staging leaf unexpectedly exists")
        if path in QUARANTINES.values() and value is not None:
            _fail(phase + ": quarantine leaf unexpectedly exists")
        if path in TARGETS:
            expected = TARGETS[path] if path in present_targets else None
            if value != expected:
                _fail(phase + ": disposable target identity changed")
    return values


def _decode_envelope(raw: bytes, label: str, header: str) -> str:
    try:
        text = alpha._decode_text(raw, label)
    except alpha.AlphaError as error:
        raise RecoveryError(str(error)) from error
    if (not text.endswith("\n") or not text.startswith(header + "\n") or
            text.count(header + "\n") != 1):
        _fail(label + " framing is truncated or ambiguous")
    return text


def _normalized_fd_target(value: str) -> str:
    suffix = " (deleted)"
    return value[:-len(suffix)] if value.endswith(suffix) else value


def _assert_no_disposable_fd_target(targets: frozenset[str]) -> None:
    forbidden = set(TARGETS) | set(STAGING.values()) | set(QUARANTINES.values())
    if any(_normalized_fd_target(value) in forbidden for value in targets):
        _fail("stock Document retains a disposable alpha descriptor")


def _document_task_block(prefix: bytes,
                         authority: android.DocumentTaskAuthority) -> str:
    candidates = [
        task for display, stack, task in launch._root_task_blocks(prefix)
        if display == authority.display_id and stack == authority.stack_id and
        authority.component in task]
    if len(candidates) != 1:
        _fail("current Document root task is absent or ambiguous")
    return candidates[0]


def _one_record_field(record: str, pattern: str, label: str) -> str:
    values = re.findall(pattern, record)
    if len(values) != 1:
        _fail(label + " is absent or ambiguous")
    return values[0]


def _display_info_authority(record: str, label: str) -> dict[str, Any]:
    prefix = 'DisplayInfo{"Built-in Screen",'
    if not record.startswith(prefix):
        _fail(label + " name differs")
    display_id = _one_record_field(
        record, r"(?<![A-Za-z0-9_])displayId (0|[1-9][0-9]*)",
        label + " display ID")
    dimensions = re.findall(
        r"(?<![A-Za-z0-9_])real ([0-9]{1,5}) x ([0-9]{1,5})",
        record)
    if len(dimensions) != 1:
        _fail(label + " geometry is absent or ambiguous")
    rotation = _one_record_field(
        record, r"(?<![A-Za-z0-9_])rotation ([0-3])",
        label + " rotation")
    state = _one_record_field(
        record, r"(?<![A-Za-z0-9_])state ([A-Z]+)",
        label + " state")
    display_type = _one_record_field(
        record, r"(?<![A-Za-z0-9_])type ([A-Z]+)",
        label + " type")
    unique_id = _one_record_field(
        record, r'(?<![A-Za-z0-9_])uniqueId "([^"\r\n]+)"',
        label + " unique ID")
    return {
        "displayId": int(display_id),
        "width": int(dimensions[0][0]),
        "height": int(dimensions[0][1]),
        "rotation": int(rotation),
        "state": state,
        "type": display_type,
        "uniqueId": unique_id,
    }


def _physical_display0_authority(displays: bytes) -> dict[str, Any]:
    """Authenticate physical power separately from logical presentation.

    On the pinned Nomad firmware the logical override's state token can flicker
    between ON and OFF while the built-in display, logical base display, and
    PowerManager remain positively awake.  The physical device and base record
    therefore own physical display state.  The override remains authoritative
    only for the active frame and rotation; its state is retained as advisory
    evidence and accepts only the two known tokens.
    """
    text = _decode_envelope(
        displays, "display inventory", "DISPLAY MANAGER (dumpsys display)")
    device_sizes = re.findall(
        r"(?m)^Display Devices: size=(0|[1-9][0-9]*)\r?$", text)
    device_lines = [line.strip() for line in text.splitlines()
                    if "DisplayDeviceInfo{" in line]
    if device_sizes != ["1"] or len(device_lines) != 1:
        _fail("physical display inventory is incomplete or ambiguous")
    device = device_lines[0]
    if device.count('DisplayDeviceInfo{"Built-in Screen":') != 1:
        _fail("physical display-0 device name differs")
    unique_id = _one_record_field(
        device, r'uniqueId="([^"\r\n]+)"',
        "physical display-0 device unique ID")
    dimensions = re.findall(
        r'uniqueId="local:0", ([0-9]{1,5}) x ([0-9]{1,5}),', device)
    rotation = _one_record_field(
        device, r"(?<![A-Za-z0-9_])rotation ([0-3])",
        "physical display-0 device rotation")
    state = _one_record_field(
        device, r"(?<![A-Za-z0-9_])state ([A-Z]+)",
        "physical display-0 device state")
    display_type = _one_record_field(
        device, r"(?<![A-Za-z0-9_])type ([A-Z]+)",
        "physical display-0 device type")
    if (unique_id != "local:0" or dimensions != [("1404", "1872")] or
            rotation != "0" or state != "ON" or
            display_type != "INTERNAL"):
        _fail("physical display-0 device identity differs")

    logical_pattern = re.compile(
        r"(?ms)^  Display (0|[1-9][0-9]*):\s*\n"
        r"(.*?)(?=^  Display (?:0|[1-9][0-9]*):|\Z)")
    blocks = list(logical_pattern.finditer(text))
    inventory_sizes = re.findall(
        r"(?m)^Logical Displays: size=(0|[1-9][0-9]*)\r?$", text)
    if inventory_sizes != ["1"] or len(blocks) != 1:
        _fail("logical display inventory is truncated or ambiguous")
    display_ids = [int(item.group(1)) for item in blocks]
    if display_ids != [0]:
        _fail("physical display-0 logical record is absent or ambiguous")
    block_ids = [line.strip() for line in blocks[0].group(2).splitlines()
                 if line.lstrip().startswith("mDisplayId=")]
    if block_ids != ["mDisplayId=0"]:
        _fail("physical display-0 logical ID differs")
    block = blocks[0].group(2)

    def one_info(key: str, label: str) -> dict[str, Any]:
        lines = [line.strip() for line in block.splitlines()
                 if line.lstrip().startswith(key + "=")]
        if len(lines) != 1:
            _fail(label + " is absent or ambiguous")
        prefix = key + "="
        return _display_info_authority(lines[0][len(prefix):], label)

    base = one_info("mBaseDisplayInfo", "physical display-0 base")
    if base != {
            "displayId": 0, "width": 1404, "height": 1872,
            "rotation": 0, "state": "ON", "type": "INTERNAL",
            "uniqueId": "local:0"}:
        _fail("physical display-0 base identity differs")

    override = one_info(
        "mOverrideDisplayInfo", "physical display-0 override")
    if (override["displayId"] != 0 or override["type"] != "INTERNAL" or
            override["uniqueId"] != "local:0" or
            override["state"] not in {"ON", "OFF"}):
        _fail("physical display-0 override identity differs")
    expected = ((1404, 1872) if override["rotation"] in (0, 2)
                else (1872, 1404))
    if (override["width"], override["height"]) != expected:
        _fail("physical display-0 override geometry/rotation differs")
    return {
        "device": {
            "name": "Built-in Screen", "uniqueId": "local:0",
            "width": 1404, "height": 1872, "rotation": 0,
            "state": "ON", "type": "INTERNAL"},
        "base": base,
        "override": override,
    }


def _power_authority(power: bytes) -> dict[str, Any]:
    text = _decode_envelope(
        power, "power inventory", "POWER MANAGER (dumpsys power)")
    expected = {
        "mWakefulness": "Awake",
        "mDisplayReady": "true",
        "mHoldingDisplaySuspendBlocker": "true",
        "mUserActivitySummary": "0x1",
        "mWakeLockSummary": "0x0",
    }
    observed: dict[str, str] = {}
    for field, value in expected.items():
        matches = re.findall(
            r"(?m)^([ \t]*)" + re.escape(field) +
            r"=([^\r\n]+)\r?$", text)
        if len(matches) != 1:
            _fail("PowerManager " + field + " is absent or ambiguous")
        indentation, observed[field] = matches[0]
        if indentation != "  ":
            _fail("PowerManager " + field + " has malformed indentation")
        if observed[field] != value:
            _fail("PowerManager " + field + " differs")
    return {
        "wakefulness": observed["mWakefulness"],
        "displayReady": True,
        "holdingDisplaySuspendBlocker": True,
        "userActivitySummary": observed["mUserActivitySummary"],
        "wakeLockSummary": observed["mWakeLockSummary"],
    }


def _capture_scope(device: "Device") -> dict[str, Any]:
    environment = device.environment()
    host_before = device.pidof(alpha.HOST_PACKAGE)
    document_before = device.pidof(alpha.DOCUMENT_PACKAGE)
    if host_before:
        _fail("retained visual-host process authority is still present")
    if len(document_before) > 1:
        _fail("stock Document process authority is ambiguous")

    activities = device.activities()
    try:
        prefix, activity_digest, summaries = launch._display_summary_split(activities)
    except (launch.RecoveryError, android.AndroidAuthorityError) as error:
        raise RecoveryError("ActivityManager authority is malformed") from error
    activity_text = alpha._decode_text(activities, "activity inventory")
    launch._root_task_blocks(prefix)

    windows = device.windows()
    window_text = _decode_envelope(
        windows, "window inventory",
        "WINDOW MANAGER WINDOWS (dumpsys window windows)")
    displays = device.displays()
    display_text = _decode_envelope(
        displays, "display inventory", "DISPLAY MANAGER (dumpsys display)")
    power = device.power()
    try:
        physical = _physical_display0_authority(displays)
        power_authority = _power_authority(power)
        launch.prior._assert_no_virtual_display(displays)  # type: ignore[attr-defined]
    except (launch.prior.RecoveryError, alpha.AlphaError) as error:
        raise RecoveryError(str(error)) from error

    host_markers = (alpha.HOST_PACKAGE, alpha.HOST_COMPONENT, DISPLAY_NAME)
    if any(marker in activity_text or marker in window_text or marker in display_text
           for marker in host_markers):
        _fail("retained visual-host task/window/display authority is still present")

    document: dict[str, Any]
    if not document_before:
        document_markers = (alpha.DOCUMENT_PACKAGE, alpha.DOCUMENT_COMPONENT)
        if any(marker in activity_text or marker in window_text
               for marker in document_markers):
            _fail("Document task/window exists without exact process authority")
        document = {"mode": "absent", "stable": {"process": None,
                                                    "fdTargets": []},
                    "evidence": {}}
    else:
        pid = document_before[0]
        process = device.process_identity(pid, alpha.DOCUMENT_PACKAGE)
        expected = host.ProcessIdentity(
            pid, process.start_ticks, launch.DOCUMENT_UID,
            alpha.DOCUMENT_PACKAGE)
        if process != expected:
            _fail("current stock Document process identity differs")
        try:
            task_authority = android.parse_document_task_authority(
                prefix, expected_pid=pid, require_live=True)
            scope = launch.prior._assert_sole_document_scope(  # type: ignore[attr-defined]
                activities, windows, task_authority, process)
            fd_targets = launch._fd_targets(device.process_fd_links(pid))
        except (android.AndroidAuthorityError, launch.prior.RecoveryError,
                launch.RecoveryError, alpha.AlphaError) as error:
            raise RecoveryError(
                "current stock Document authority is malformed or ambiguous") from error
        _assert_no_disposable_fd_target(fd_targets)
        task = _document_task_block(prefix, task_authority)
        target_markers = (
            TARGET_PDF, TARGET_MARK, alpha.TARGET_URI,
            Path(TARGET_PDF).name, Path(TARGET_MARK).name)
        if any(marker in task for marker in target_markers):
            _fail("current Document task still names the disposable alpha target")
        authority_wire = asdict(task_authority)
        authority_wire.pop("raw_sha256")
        document = {
            "mode": "live-unrelated",
            "stable": {
                "process": asdict(process),
                "taskAuthority": authority_wire,
                "documentScope": scope["stable"],
                "fdTargets": sorted(fd_targets),
            },
            "evidence": {
                "taskSha256": _sha(task.encode("utf-8")),
                "authorityRawSha256": task_authority.raw_sha256,
                **scope["evidence"],
            },
        }

    host_after = device.pidof(alpha.HOST_PACKAGE)
    document_after = device.pidof(alpha.DOCUMENT_PACKAGE)
    if host_after != host_before or document_after != document_before:
        _fail("package process authority drifted during observation")
    if document_after:
        after_process = device.process_identity(
            document_after[0], alpha.DOCUMENT_PACKAGE)
        if asdict(after_process) != document["stable"]["process"]:
            _fail("stock Document process identity drifted during observation")

    rotation = device.rotation_settings()
    if rotation != ("1", "2"):
        _fail("persisted rotation settings differ from restored 1/2")
    return {
        "environment": environment,
        "host": {
            "processes": [], "taskWindowDisplayAbsent": True,
            "physicalDisplay": physical,
        },
        "power": power_authority,
        "document": document,
        "displaySummaries": [list(item) for item in summaries],
        "rotation": list(rotation),
        "activitySha256": activity_digest,
        "windowSha256": _sha(windows),
        "displaySha256": _sha(displays),
        "powerSha256": _sha(power),
    }


@dataclass(frozen=True)
class Observation:
    scope: dict[str, Any]
    files: dict[str, dict[str, Any] | None]

    def wire(self) -> dict[str, Any]:
        return {**copy.deepcopy(self.scope), "files": self.files}


def observe(device: "Device") -> Observation:
    scope = _capture_scope(device)
    files = _assert_file_set(
        device, "live observation", frozenset(TARGETS))
    return Observation(scope, files)


def _stable_scope(scope: dict[str, Any]) -> dict[str, Any]:
    stable = copy.deepcopy(scope)
    for key in ("activitySha256", "windowSha256", "displaySha256",
                "powerSha256"):
        stable.pop(key, None)
    host_scope = stable.get("host")
    if type(host_scope) is not dict:
        _fail("host scope is malformed")
    physical = host_scope.get("physicalDisplay")
    if type(physical) is not dict:
        _fail("physical display scope is malformed")
    override = physical.get("override")
    if type(override) is not dict:
        _fail("physical display override is malformed")
    override_state = override.get("state")
    if (type(override_state) is not str or
            override_state not in {"ON", "OFF"}):
        _fail("physical display override state is malformed")
    del override["state"]
    document = stable.get("document")
    if type(document) is not dict:
        _fail("Document scope is malformed")
    document.pop("evidence", None)
    return stable


def _stable_observation(value: dict[str, Any]) -> dict[str, Any]:
    stable = _stable_scope(value)
    stable["files"] = copy.deepcopy(value.get("files"))
    return stable


def _assert_stable(first: Observation, second: Observation) -> None:
    if _stable_observation(first.wire()) != _stable_observation(second.wire()):
        _fail("post-restart orphan authority drifted between observations")


class Device(Protocol):
    history: list[dict[str, Any]]
    def adb_authority(self) -> dict[str, Any]: ...
    def environment(self) -> dict[str, Any]: ...
    def activities(self) -> bytes: ...
    def windows(self) -> bytes: ...
    def displays(self) -> bytes: ...
    def power(self) -> bytes: ...
    def pidof(self, package: str) -> tuple[int, ...]: ...
    def process_identity(self, pid: int, package: str) -> host.ProcessIdentity: ...
    def process_fd_links(self, pid: int) -> str: ...
    def stat_file(self, path: str, *, absent_ok: bool = False) -> alpha.DeviceFile | None: ...
    def rotation_settings(self) -> tuple[str, str]: ...
    def move_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult: ...
    def delete_if_exact(self, source: str, quarantine: str) -> alpha.CommandResult: ...


class Nomad(launch.Nomad):
    """Closed post-restart transport; task/package mutations always reject."""

    def remove_task(self, task_id: int) -> alpha.CommandResult:
        _fail("post-restart recovery has no task-removal capability")

    def force_stop_document(self) -> alpha.CommandResult:
        _fail("post-restart recovery has no package-force-stop capability")

    def power(self) -> bytes:
        return self._require_zero(self._invoke(
            "power", ("shell", "dumpsys", "power")))


def build_plan(authority: Authority, device: Device) -> dict[str, Any]:
    _authority_guard(authority)
    first = observe(device)
    _authority_guard(authority)
    second = observe(device)
    _assert_stable(first, second)
    _authority_guard(authority)
    body = {
        "authority": PLAN_AUTHORITY,
        "schemaVersion": 2,
        "report": authority.report_identity,
        "activeJournal": authority.active_identity,
        "dependencies": authority.dependency_identities,
        "adb": device.adb_authority(),
        "first": first.wire(),
        "second": second.wire(),
        "mutationOrder": [
            "quarantine-delete-mark",
            "quarantine-delete-pdf",
            "archive-active-journal",
            "publish-evidence",
        ],
        "forbiddenMutations": ["remove-task", "force-stop-package"],
    }
    return {**body, "bindingSha256": _canonical_sha(body)}


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"),
                           object_pairs_hook=launch._unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError(label + " is not strict canonical JSON") from error
    if type(value) is not dict or _canonical(value) != raw:
        _fail(label + " is not one canonical JSON object")
    return value


def _stable_plan_projection(plan: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(plan)
    value.pop("bindingSha256", None)
    for side in ("first", "second"):
        observation = value.get(side)
        if type(observation) is not dict:
            _fail("plan observation is malformed")
        value[side] = _stable_observation(observation)
    return value


def load_plan(path: Path, authority: Authority) -> tuple[dict[str, Any], dict[str, Any]]:
    if path.resolve() != authority.plan_path.resolve():
        _fail("plan path differs from the fixed post-restart plan path")
    raw, identity = _read_regular(path, MAX_LOCAL_BYTES, "exact recovery plan")
    plan = _strict_json(raw, "exact recovery plan")
    binding = plan.get("bindingSha256")
    unsigned = dict(plan)
    unsigned.pop("bindingSha256", None)
    if (type(binding) is not str or binding != _canonical_sha(unsigned) or
            plan.get("authority") != PLAN_AUTHORITY or
            plan.get("schemaVersion") != 2 or
            plan.get("report") != authority.report_identity or
            plan.get("activeJournal") != authority.active_identity or
            plan.get("dependencies") != authority.dependency_identities):
        _fail("plan binding or exact-run authority differs")
    first = plan.get("first")
    second = plan.get("second")
    if (type(first) is not dict or type(second) is not dict or
            _stable_observation(first) != _stable_observation(second)):
        _fail("plan observations are not stable")
    return plan, identity


class Journal(launch.prior.Journal):
    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if type(kind) is not str or not kind or type(payload) is not dict:
            _fail("recovery ledger record is malformed")
        unsigned = {
            "authority": AUTHORITY,
            "kind": kind,
            "payload": payload,
            "previousSha256": (None if not self.records else
                               self.records[-1]["recordSha256"]),
            "sequence": len(self.records),
        }
        record = {**unsigned, "recordSha256": _canonical_sha(unsigned)}
        encoded = _canonical(record) + b"\n"
        self._assert_open_authority()
        if os.write(self._descriptor, encoded) != len(encoded):
            _fail("short recovery ledger write")
        os.fsync(self._descriptor)
        self._encoded += encoded
        self._assert_open_authority()
        launch.prior._fsync_directory(self.path.parent)  # type: ignore[attr-defined]
        self.records.append(record)
        return record


def _validate_mutation_result(result: Any, operation: str) -> None:
    try:
        launch._validate_mutation_result(result, operation)
    except launch.RecoveryError as error:
        raise RecoveryError(str(error)) from error


def _renamed(expected: alpha.DeviceFile, path: str) -> alpha.DeviceFile:
    return alpha.DeviceFile(
        path, expected.kind, expected.size, expected.uid, expected.gid,
        expected.inode, expected.device, expected.sha256)


def _dispatch_disposable(
        journal: Journal, device: Device, source: str,
        remaining: frozenset[str]) -> None:
    quarantine = QUARANTINES[source]
    expected = TARGETS[source]
    journal.append("quarantine-intent", {
        "source": source, "quarantine": quarantine,
        "identity": asdict(expected)})
    move_result: alpha.CommandResult | None = None
    move_error: BaseException | None = None
    try:
        move_result = device.move_if_exact(source, quarantine)
        _validate_mutation_result(
            move_result, "recovery_quarantine_" + Path(source).name)
    except MutationTransportUncertain as error:
        move_error = error
    moved = device.stat_file(quarantine, absent_ok=True)
    source_now = device.stat_file(source, absent_ok=True)
    if moved != _renamed(expected, quarantine) or source_now is not None:
        journal.append("quarantine-unsettled", {"source": source})
        _fail("quarantine move did not reach exact postcondition; no retry is permitted")
    journal.append("quarantine-settled", {
        "source": source,
        "reply": None if move_result is None else move_result.returncode,
        "transportError": None if move_error is None else str(move_error),
    })

    journal.append("delete-quarantine-intent", {
        "source": source, "quarantine": quarantine,
        "identity": asdict(_renamed(expected, quarantine))})
    delete_result: alpha.CommandResult | None = None
    delete_error: BaseException | None = None
    try:
        delete_result = device.delete_if_exact(source, quarantine)
        _validate_mutation_result(
            delete_result, "recovery_remove_" + Path(quarantine).name)
    except MutationTransportUncertain as error:
        delete_error = error
    if (device.stat_file(quarantine, absent_ok=True) is not None or
            device.stat_file(source, absent_ok=True) is not None):
        journal.append("delete-quarantine-unsettled", {"source": source})
        _fail("quarantine deletion did not reach exact postcondition; no retry is permitted")
    journal.append("delete-quarantine-settled", {
        "source": source,
        "reply": None if delete_result is None else delete_result.returncode,
        "transportError": None if delete_error is None else str(delete_error),
    })
    _assert_file_set(device, "post-delete", remaining)


def _archive_active(authority: Authority, journal: Journal) -> None:
    _authority_guard(authority)
    if os.path.lexists(authority.retired_path):
        _fail("retired active-journal path is occupied")
    journal.append("archive-active-intent", {
        "source": str(authority.active_path),
        "target": str(authority.retired_path),
        "sha256": launch.ACTIVE_SHA256,
    })
    os.replace(authority.active_path, authority.retired_path)
    launch.prior._fsync_directory(authority.active_path.parent)  # type: ignore[attr-defined]
    raw, identity = _read_regular(
        authority.retired_path, 256 * 1024, "retired active journal")
    if (len(raw) != launch.ACTIVE_BYTES or
            identity["sha256"] != launch.ACTIVE_SHA256 or
            os.path.lexists(authority.active_path)):
        _fail("active journal retirement did not reach exact postcondition")
    journal.append("archive-active-settled", identity)


def _require_planned_scope(plan: dict[str, Any], scope: dict[str, Any]) -> None:
    first = plan.get("first")
    if type(first) is not dict:
        _fail("plan observation is malformed")
    planned = dict(first)
    planned.pop("files", None)
    if _stable_scope(scope) != _stable_scope(planned):
        _fail("live post-restart scope no longer matches the exact plan")


def execute(authority: Authority, device: Device, plan: dict[str, Any],
            plan_identity: dict[str, Any]) -> dict[str, Any]:
    if os.path.lexists(authority.ledger_path) or os.path.lexists(authority.evidence_path):
        _fail("one-shot recovery ledger/evidence is already occupied")
    current_plan = build_plan(authority, device)
    if _stable_plan_projection(current_plan) != _stable_plan_projection(plan):
        _fail("live authority no longer matches the exact plan")

    # One final scope observation is made before the O_EXCL ledger and first
    # mutation.  Any drift here still leaves the retained run untouched.
    preledger_scope = _capture_scope(device)
    _require_planned_scope(plan, preledger_scope)
    journal = Journal(authority.ledger_path, {
        "plan": plan_identity,
        "planBindingSha256": plan["bindingSha256"],
        "reportSha256": launch.REPORT_SHA256,
        "activeJournalSha256": launch.ACTIVE_SHA256,
    })
    evidence: dict[str, Any] = {
        "authority": AUTHORITY,
        "schemaVersion": 2,
        "plan": plan_identity,
        "mutations": [],
        "result": "RECOVERY_PENDING",
    }
    try:
        _require_planned_scope(plan, _capture_scope(device))
        _dispatch_disposable(
            journal, device, TARGET_MARK, frozenset((TARGET_PDF,)))
        _require_planned_scope(plan, _capture_scope(device))
        _dispatch_disposable(journal, device, TARGET_PDF, frozenset())
        final_scope = _capture_scope(device)
        _require_planned_scope(plan, final_scope)
        final_files = _assert_file_set(
            device, "final closure", frozenset())
        _archive_active(authority, journal)
        evidence.update({
            "result": "POST_RESTART_ORPHAN_RECOVERED_CLEANLY",
            "finalScope": final_scope,
            "finalFiles": final_files,
            "commands": list(device.history),
            "ledgerHeadSha256": journal.records[-1]["recordSha256"],
            "ledgerRecordCount": len(journal.records),
        })
        journal.append("evidence-intent", {
            "path": str(authority.evidence_path),
            "payloadSha256": _canonical_sha(evidence),
        })
        _write_exclusive(authority.evidence_path, evidence)
        return evidence
    finally:
        journal.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        help="fixed canonical plan path; required for plan mode")
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
    if args.output.resolve() != authority.plan_path.resolve():
        _fail("--output differs from the fixed post-restart plan path")
    plan = build_plan(authority, device)
    identity = _write_exclusive(args.output, plan)
    print(json.dumps({"result": "PLAN_READY", "plan": str(args.output),
                      "sha256": identity["sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
