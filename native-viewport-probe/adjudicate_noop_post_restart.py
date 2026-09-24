"""Read-only adjudication of one interrupted post-restart MARK quarantine.

The occupied recovery ledger has a header and a MARK quarantine intent, but
no settlement.  This helper can prove that the intended move did *not* take
effect: both disposable sources still have their exact identities and every
staging/quarantine leaf is absent.  It never resumes cleanup, retires the
active journal, changes a device file, or treats the old ledger as closed.

Default mode prints a complete read-only plan to stdout.  ``--attest`` makes
the same fresh observations and exclusively publishes one local attestation
only after all authority checks pass.  Neither mode changes the Nomad.
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
from typing import Any, Callable, NoReturn, Sequence

import native_page_alpha_runner as alpha
import recover_launch_identity_alpha_run as launch
import recover_post_restart_orphan_alpha_run as recovery


AUTHORITY = "native-page-alpha-post-restart-noop-adjudication-v1"
ATTESTATION_BASENAME = "post-restart-orphan-noop-attestation.json"
PLAN_SHA256 = "579491eb7ec3b98cf40646b7c0038c151f07d96e897813e9aac31d6e4b827924"
PLAN_BYTES = 13_803
PLAN_BINDING = "76a72280211bc8ae3d70efd230364ae52d24c23f328a17d9e216611f356f34c4"
LEDGER_SHA256 = "0f109020e696139134cff6db77e3d73f422eb442e3e4f17c4cad98f98a468040"
LEDGER_BYTES = 1_664
LEDGER_HEAD = "25403af41ef5f54de30cc4265563fcf1d5845ad14725d3a8e2c5612a52b23620"


class AdjudicationError(RuntimeError):
    """This exact interrupted attempt cannot be adjudicated safely."""


def _fail(message: str) -> NoReturn:
    raise AdjudicationError(message)


def _read(path: Path, maximum: int, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        return recovery._read_regular(path, maximum, label)
    except recovery.RecoveryError as error:
        raise AdjudicationError(str(error)) from error


def _strict(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return recovery._strict_json(raw, label)
    except (recovery.RecoveryError, launch.RecoveryError) as error:
        raise AdjudicationError(str(error)) from error


def _digest(value: Any) -> str:
    return recovery._canonical_sha(value)


def _verify_ledger(raw: bytes, plan_identity: dict[str, Any], *,
                   pinned_sha256: str = LEDGER_SHA256,
                   pinned_head: str = LEDGER_HEAD) -> None:
    if (not raw.endswith(b"\n") or raw.count(b"\n") != 2 or
            recovery._sha(raw) != pinned_sha256):
        _fail("occupied recovery ledger bytes or record count differ")
    records = [_strict(line, "occupied recovery record")
               for line in raw[:-1].split(b"\n")]
    previous: str | None = None
    for index, record in enumerate(records):
        if set(record) != {"authority", "kind", "payload", "previousSha256",
                           "sequence", "recordSha256"}:
            _fail("occupied recovery record fields differ")
        unsigned = dict(record)
        digest = unsigned.pop("recordSha256")
        if (record["authority"] != recovery.AUTHORITY or
                type(record["sequence"]) is not int or
                record["sequence"] != index or
                record["previousSha256"] != previous or
                type(digest) is not str or digest != _digest(unsigned)):
            _fail("occupied recovery record chain differs")
        previous = digest
    if previous != pinned_head:
        _fail("occupied recovery ledger head differs")
    header, intent = records
    expected_header = {
        "plan": plan_identity,
        "planBindingSha256": PLAN_BINDING,
        "reportSha256": launch.REPORT_SHA256,
        "activeJournalSha256": launch.ACTIVE_SHA256,
    }
    expected_intent = {
        "source": recovery.TARGET_MARK,
        "quarantine": recovery.QUARANTINES[recovery.TARGET_MARK],
        "identity": asdict(recovery.TARGETS[recovery.TARGET_MARK]),
    }
    if (header["kind"] != "header" or
            header["payload"] != expected_header or
            intent["kind"] != "quarantine-intent" or
            intent["payload"] != expected_intent):
        _fail("occupied recovery ledger semantics differ")


@dataclass(frozen=True)
class Context:
    authority: recovery.Authority
    plan: dict[str, Any]
    plan_identity: dict[str, Any]
    ledger_identity: dict[str, Any]
    producer_identity: dict[str, Any]
    attestation_path: Path


def _guard(context: Context) -> None:
    """Reread all local authority, including the exact occupied ledger."""
    try:
        recovery._authority_guard(context.authority)
    except recovery.RecoveryError as error:
        raise AdjudicationError(str(error)) from error
    _, plan_identity = _read(
        context.authority.plan_path, PLAN_BYTES, "exact old recovery plan")
    raw, ledger_identity = _read(
        context.authority.ledger_path, LEDGER_BYTES,
        "exact occupied recovery ledger")
    if (plan_identity != context.plan_identity or
            ledger_identity != context.ledger_identity):
        _fail("old plan or occupied ledger identity changed")
    _, producer_identity = _read(
        Path(__file__).resolve(), recovery.MAX_LOCAL_BYTES,
        "no-op adjudication producer")
    if producer_identity != context.producer_identity:
        _fail("no-op adjudication producer changed")
    _verify_ledger(raw, context.plan_identity)
    if (os.path.lexists(context.authority.retired_path) or
            os.path.lexists(context.authority.evidence_path)):
        _fail("old recovery has already retired or published evidence")


def load_context(root: Path) -> Context:
    """Authenticate the frozen failed run without the old ledger's admission ban."""
    root = root.resolve(strict=True)
    try:
        retained = launch.load_authority(root)
    except launch.RecoveryError as error:
        raise AdjudicationError(str(error)) from error
    if (os.path.lexists(retained.ledger_path) or
            os.path.lexists(retained.evidence_path)):
        _fail("launch-identity recovery has claimed this run")
    dependencies = dict(retained.dependency_identities)
    launch_path = root / "recover_launch_identity_alpha_run.py"
    launch_raw, launch_identity = _read(
        launch_path, recovery.LAUNCH_HELPER_BYTES, "launch recovery helper")
    if (len(launch_raw) != recovery.LAUNCH_HELPER_BYTES or
            launch_identity["sha256"] != recovery.LAUNCH_HELPER_SHA256):
        _fail("launch recovery helper differs")
    dependencies[launch_path.name] = launch_identity
    recovery_path = root / "recover_post_restart_orphan_alpha_run.py"
    _, recovery_identity = _read(
        recovery_path, recovery.MAX_LOCAL_BYTES, "post-restart recovery helper")
    dependencies[recovery_path.name] = recovery_identity
    run_dir = retained.report_path.parent
    authority = recovery.Authority(
        root, retained.report_path, retained.active_path,
        retained.retired_path, run_dir / recovery.LEDGER_BASENAME,
        run_dir / recovery.EVIDENCE_BASENAME,
        run_dir / recovery.PLAN_BASENAME,
        retained.report_identity, retained.active_identity, dependencies)
    try:
        plan, plan_identity = recovery.load_plan(authority.plan_path, authority)
    except recovery.RecoveryError as error:
        raise AdjudicationError(str(error)) from error
    if (plan_identity["sha256"] != PLAN_SHA256 or
            plan_identity["size"] != PLAN_BYTES or
            plan.get("bindingSha256") != PLAN_BINDING or
            set(plan) != {"authority", "schemaVersion", "report",
                          "activeJournal", "dependencies", "adb", "first",
                          "second", "mutationOrder", "forbiddenMutations",
                          "bindingSha256"} or
            plan["mutationOrder"] != [
                "quarantine-delete-mark", "quarantine-delete-pdf",
                "archive-active-journal", "publish-evidence"] or
            plan["forbiddenMutations"] != [
                "remove-task", "force-stop-package"]):
        _fail("exact old plan identity or semantics differ")
    raw, ledger_identity = _read(
        authority.ledger_path, LEDGER_BYTES, "occupied recovery ledger")
    if (ledger_identity["sha256"] != LEDGER_SHA256 or
            ledger_identity["size"] != LEDGER_BYTES):
        _fail("occupied recovery ledger identity differs")
    _verify_ledger(raw, plan_identity)
    _, producer_identity = _read(
        Path(__file__).resolve(), recovery.MAX_LOCAL_BYTES,
        "no-op adjudication producer")
    context = Context(
        authority, plan, plan_identity, ledger_identity, producer_identity,
        run_dir / ATTESTATION_BASENAME)
    _guard(context)
    return context


class ReadOnlyNomad:
    """Expose only observation methods; there is no mutation dispatcher."""

    def __init__(self, adb: Path):
        self._device = recovery.Nomad(adb, alpha.AUTHORIZED_SERIAL)

    @property
    def history(self) -> list[dict[str, Any]]:
        return self._device.history

    def adb_authority(self) -> dict[str, Any]:
        return self._device.adb_authority()

    def environment(self) -> dict[str, Any]:
        return self._device.environment()

    def activities(self) -> bytes:
        return self._device.activities()

    def windows(self) -> bytes:
        return self._device.windows()

    def displays(self) -> bytes:
        return self._device.displays()

    def power(self) -> bytes:
        return self._device.power()

    def pidof(self, package: str) -> tuple[int, ...]:
        return self._device.pidof(package)

    def process_identity(self, pid: int, package: str):
        return self._device.process_identity(pid, package)

    def process_fd_links(self, pid: int) -> str:
        return self._device.process_fd_links(pid)

    def stat_file(self, path: str, *, absent_ok: bool = False):
        return self._device.stat_file(path, absent_ok=absent_ok)

    def rotation_settings(self) -> tuple[str, str]:
        return self._device.rotation_settings()


def build_read_only_plan(context: Context, device: ReadOnlyNomad, *,
                         pause: Callable[[float], None] | None = None,
                         ) -> dict[str, Any]:
    if pause is None:
        pause = time.sleep
    _guard(context)
    if device.adb_authority() != context.plan["adb"]:
        _fail("ADB executable identity differs from the old plan")
    try:
        recovery._await_quiet_power(device, pause=pause)
        first = recovery.observe(device)
        _verify_observation(first.wire(), context.plan["first"])
        _guard(context)
        recovery._await_quiet_power(device, pause=pause)
        second = recovery.observe(device)
        _verify_observation(second.wire(), context.plan["first"])
        recovery._assert_stable(first, second)
    except recovery.RecoveryError as error:
        raise AdjudicationError(str(error)) from error
    _guard(context)
    if device.adb_authority() != context.plan["adb"]:
        _fail("ADB executable identity changed during observation")
    body = {
        "authority": AUTHORITY,
        "schemaVersion": 1,
        "result": "MARK_QUARANTINE_INTENT_NOT_APPLIED",
        "meaning": "No cleanup completed; old recovery ledger and active journal remain occupied",
        "oldPlan": context.plan_identity,
        "oldPlanBindingSha256": PLAN_BINDING,
        "occupiedLedger": context.ledger_identity,
        "occupiedLedgerHeadSha256": LEDGER_HEAD,
        "producer": context.producer_identity,
        "report": context.authority.report_identity,
        "activeJournal": context.authority.active_identity,
        "dependencies": context.authority.dependency_identities,
        "adb": device.adb_authority(),
        "first": first.wire(),
        "second": second.wire(),
        "deviceMutationCount": 0,
    }
    return {**body, "bindingSha256": _digest(body)}


def _expected_files() -> dict[str, dict[str, Any] | None]:
    files: dict[str, dict[str, Any] | None] = {
        path: None for path in recovery.PROTECTED_PATHS}
    files.update({path: asdict(value)
                  for path, value in recovery.ORIGINALS.items()})
    files[recovery.PARKING_PDF] = asdict(recovery.PARKING)
    files.update({path: asdict(value)
                  for path, value in recovery.TARGETS.items()})
    return files


def _require_shape(value: Any, exemplar: Any, path: tuple[str, ...] = ()) -> None:
    """Reject absent/extra nested fields, not merely invalid selected values."""
    if type(exemplar) is dict:
        if type(value) is not dict or set(value) != set(exemplar):
            _fail("no-op observation schema differs at " + ".".join(path))
        for key, expected in exemplar.items():
            _require_shape(value[key], expected, (*path, key))
    elif type(exemplar) is list:
        if type(value) is not list:
            _fail("no-op observation list differs at " + ".".join(path))
        if path == ("document", "stable", "fdTargets"):
            if not value or any(type(item) is not str for item in value):
                _fail("no-op observation descriptor list differs")
        elif len(value) != len(exemplar):
            _fail("no-op observation list length differs at " + ".".join(path))
        else:
            for index, item in enumerate(value):
                _require_shape(item, exemplar[index], (*path, str(index)))
    elif type(value) is not type(exemplar):
        _fail("no-op observation scalar type differs at " + ".".join(path))


def _is_sha256(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _verify_observation(value: Any, exemplar: dict[str, Any]) -> None:
    _require_shape(value, exemplar)
    if type(value) is not dict or value.get("files") != _expected_files():
        _fail("no-op observation does not retain the exact protected file set")
    environment = value["environment"]
    if (environment["documentApk"] != alpha.DOCUMENT_APK or
            environment["hostUid"] != launch.HOST_UID or
            re.fullmatch(r"/data/app/[^\s]+/base\.apk",
                         environment["hostApk"]) is None or
            ".." in environment["hostApk"]):
        _fail("no-op observation environment differs")
    host = value.get("host")
    if (type(host) is not dict or host.get("processes") != [] or
            host.get("taskWindowDisplayAbsent") is not True):
        _fail("no-op observation still has visual-host authority")
    physical = host["physicalDisplay"]
    if (physical["device"] != exemplar["host"]["physicalDisplay"]["device"] or
            physical["base"] != exemplar["host"]["physicalDisplay"]["base"]):
        _fail("no-op observation physical display differs")
    override = physical["override"]
    expected_geometry = ((1404, 1872) if override["rotation"] in (0, 2)
                         else (1872, 1404))
    if (override["displayId"] != 0 or
            override["uniqueId"] != "local:0" or
            override["type"] != "INTERNAL" or
            override["state"] not in {"ON", "OFF"} or
            override["rotation"] not in (0, 1, 2, 3) or
            (override["width"], override["height"]) != expected_geometry):
        _fail("no-op observation logical display differs")
    power = value.get("power")
    if (type(power) is not dict or power.get("wakefulness") != "Awake" or
            power.get("wakeLockSummary") != "0x0" or
            power.get("displayReady") is not True or
            power.get("holdingDisplaySuspendBlocker") is not True or
            power.get("userActivitySummary") != "0x1"):
        _fail("no-op observation is not quiet and awake")
    document = value.get("document")
    if type(document) is not dict or document.get("mode") != "live-unrelated":
        _fail("unrelated stock Document activity is not positively present")
    stable = document.get("stable")
    fd_targets = stable.get("fdTargets") if type(stable) is dict else None
    if (type(fd_targets) is not list or not fd_targets or
            any(type(path) is not str or not path.startswith("/")
                for path in fd_targets) or
            fd_targets != sorted(set(fd_targets))):
        _fail("unrelated stock Document descriptors are malformed")
    try:
        recovery._assert_no_disposable_fd_target(frozenset(fd_targets))
    except recovery.RecoveryError as error:
        raise AdjudicationError(str(error)) from error
    if value["rotation"] != ["1", "2"]:
        _fail("no-op observation persisted rotation differs")
    summaries = value["displaySummaries"]
    if (len(summaries) != 1 or summaries[0][0] != 0 or
            type(summaries[0][1]) is not int or
            not 0 <= summaries[0][1] <= 10000):
        _fail("no-op observation display summary differs")
    process = stable["process"]
    task = stable["taskAuthority"]
    configuration = stable["configuration"]
    scope = stable["documentScope"]
    expected_task = exemplar["document"]["stable"]["taskAuthority"]
    if any(task[key] != expected for key, expected in expected_task.items()
           if type(expected) is bool):
        _fail("no-op observation Document task flags differ")
    if (task["authority"] != expected_task["authority"] or
            task["component"] != expected_task["component"] or
            task["base_apk_path"] != alpha.DOCUMENT_APK or
            task["package_name"] != alpha.DOCUMENT_PACKAGE or
            task["process_name"] != alpha.DOCUMENT_PACKAGE or
            task["state"] != "RESUMED" or
            process["package"] != alpha.DOCUMENT_PACKAGE or
            process["uid"] != launch.DOCUMENT_UID or
            process["pid"] != task["pid"] or
            task["uid"] != process["uid"] or
            task["display_id"] != 0 or
            task["rotation"] != override["rotation"] or
            (task["width"], task["height"]) != expected_geometry or
            (configuration["width"], configuration["height"],
             configuration["rotation"]) !=
            (task["width"], task["height"], task["rotation"]) or
            configuration["rotationDialect"] != "android-degrees" or
            configuration["rotationLiteral"] !=
            "ROTATION_" + ("0", "90", "180", "270")[task["rotation"]] or
            scope["activityToken"] != task["activity_token"] or
            scope["taskToken"] != task["task_token"] or
            scope["taskId"] != task["task_id"] or
            scope["displayId"] != task["display_id"] or
            scope["pid"] != process["pid"] or
            scope["uid"] != process["uid"] or
            scope["oneChildRootTask"] is not True or
            scope["solePackageWindow"] is not True):
        _fail("no-op observation Document authority differs")
    for key in ("activitySha256", "windowSha256", "displaySha256", "powerSha256"):
        if not _is_sha256(value[key]):
            _fail("no-op observation top-level hash is malformed")
    if any(not _is_sha256(digest) for digest in document["evidence"].values()):
        _fail("no-op observation Document evidence hash is malformed")


def _validate_attestation(context: Context, plan: dict[str, Any]) -> None:
    if set(plan) != {
            "authority", "schemaVersion", "result", "meaning", "oldPlan",
            "oldPlanBindingSha256", "occupiedLedger", "occupiedLedgerHeadSha256",
            "producer", "report", "activeJournal", "dependencies", "adb",
            "first", "second",
            "deviceMutationCount", "bindingSha256"}:
        _fail("no-op attestation fields differ")
    unsigned = dict(plan)
    binding = unsigned.pop("bindingSha256", None)
    if (plan["authority"] != AUTHORITY or
            type(plan["schemaVersion"]) is not int or plan["schemaVersion"] != 1 or
            plan["result"] != "MARK_QUARANTINE_INTENT_NOT_APPLIED" or
            plan["meaning"] !=
            "No cleanup completed; old recovery ledger and active journal remain occupied" or
            plan["oldPlan"] != context.plan_identity or
            plan["oldPlanBindingSha256"] != PLAN_BINDING or
            plan["occupiedLedger"] != context.ledger_identity or
            plan["occupiedLedgerHeadSha256"] != LEDGER_HEAD or
            plan["producer"] != context.producer_identity or
            plan["report"] != context.authority.report_identity or
            plan["activeJournal"] != context.authority.active_identity or
            plan["dependencies"] != context.authority.dependency_identities or
            plan["adb"] != context.plan["adb"] or
            type(plan["deviceMutationCount"]) is not int or
            plan["deviceMutationCount"] != 0 or
            type(binding) is not str or binding != _digest(unsigned)):
        _fail("no-op attestation binding or exact-run authority differs")
    _verify_observation(plan["first"], context.plan["first"])
    _verify_observation(plan["second"], context.plan["first"])
    try:
        if (recovery._stable_observation(plan["first"]) !=
                recovery._stable_observation(plan["second"])):
            _fail("no-op attestation observations drifted")
    except recovery.RecoveryError as error:
        raise AdjudicationError(str(error)) from error


def load_attestation(context: Context) -> tuple[dict[str, Any], dict[str, Any]]:
    """Strictly reread one published proof for a later recovery adapter."""
    _guard(context)
    if context.attestation_path != (
            context.authority.report_path.parent / ATTESTATION_BASENAME):
        _fail("no-op attestation path differs from the fixed run")
    raw, identity = _read(context.attestation_path,
                          recovery.MAX_LOCAL_BYTES, "no-op attestation")
    plan = _strict(raw, "no-op attestation")
    _validate_attestation(context, plan)
    _guard(context)
    return plan, identity


def _publication_parent(target: Path,
                        expected_resolved_parent: Path) -> tuple[int, int]:
    if target.parent.resolve(strict=True) != expected_resolved_parent:
        _fail("attestation directory differs from the fixed run")
    parent = os.stat(target.parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        _fail("attestation parent is not an ordinary directory")
    return parent.st_dev, parent.st_ino


def _assert_publication_location(target: Path, expected_resolved_parent: Path,
                                 parent_identity: tuple[int, int],
                                 descriptor: int) -> None:
    if _publication_parent(target, expected_resolved_parent) != parent_identity:
        _fail("attestation directory changed during publication")
    if target.resolve(strict=True) != expected_resolved_parent / target.name:
        _fail("attestation leaf resolves outside the fixed run")
    opened = os.fstat(descriptor)
    linked = os.stat(target, follow_symlinks=False)
    if (not stat.S_ISREG(opened.st_mode) or
            not stat.S_ISREG(linked.st_mode) or
            opened.st_nlink != 1 or linked.st_nlink != 1 or
            (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)):
        _fail("attestation leaf changed after exclusive open")


def publish_attestation(context: Context, plan: dict[str, Any]) -> dict[str, Any]:
    """Publish only a complete adjudication; an interrupted write stays occupied."""
    _validate_attestation(context, plan)
    _guard(context)
    target = context.attestation_path
    expected_resolved_parent = context.authority.report_path.parent.resolve(
        strict=True)
    parent_identity = _publication_parent(target, expected_resolved_parent)
    if os.path.lexists(target):
        _fail("no-op attestation publication is already occupied")
    raw = recovery._canonical(plan)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(target, flags, 0o600)
    try:
        _assert_publication_location(
            target, expected_resolved_parent, parent_identity, descriptor)
        if os.write(descriptor, raw) != len(raw):
            _fail("exclusive attestation publication failed")
        os.fsync(descriptor)
        _assert_publication_location(
            target, expected_resolved_parent, parent_identity, descriptor)
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    launch.prior._fsync_directory(target.parent)  # type: ignore[attr-defined]
    observed, identity = load_attestation(context)
    if (recovery._canonical(observed) != raw or
            (identity["device"], identity["inode"]) !=
            (opened.st_dev, opened.st_ino)):
        _fail("published no-op attestation reread differs")
    return identity


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True, type=Path)
    parser.add_argument("--attest", action="store_true",
                        help="exclusively publish one local attestation after fresh proof")
    args = parser.parse_args(argv)
    context = load_context(Path(__file__).resolve().parent)
    device = ReadOnlyNomad(args.adb)
    plan = build_read_only_plan(context, device)
    if args.attest:
        identity = publish_attestation(context, plan)
        print(json.dumps({"result": plan["result"], "attestation":
                          str(context.attestation_path),
                          "sha256": identity["sha256"]}, sort_keys=True))
    else:
        print(recovery._canonical(plan).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
