"""Closed, read-only device-evidence authority for the native-page experiment.

The public object accepts one preauthenticated :class:`EvidencePlan` and a
deadline.  It deliberately exposes no command, path, URI, package, or payload
parameter after construction.  The injected backend is operation-specific and
must be bound to one retained private ADB server and one retained isolated
worker.  Ordinary evidence is always collected as Android shell (2000:2000).

Protected firmware bytes are the sole exception: a backend may use one typed
root helper to copy one preauthenticated source to a derived private staging
path, open/hash that exact staged inode as shell, and remove both helper and
staging path before returning.  Missing or invalid cleanup evidence seals the
authority; this layer never retries, searches, kills by name, or broadens a
path.

This module performs no I/O when imported.  A real backend/bootstrap and the
25/250 ms hardware timing target remain explicitly unproven here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import wraps
import hashlib
import json
import re
import threading
import unicodedata
from typing import Any, Callable, NoReturn, Protocol, TypeVar
from urllib.parse import quote

from native_page_private_adb_mutator import (
    PRIVATE_ADB_AUTHORITY,
    PrivateAdbBinding,
    RetainedPrivateAdbAuthority as RetainedPrivateAdb,
)
from native_page_windows_worker_runtime import WorkerBinding


AUTHORITY = "rtl-reader-private-adb-reader-v1"
PLAN_AUTHORITY = "rtl-reader-device-evidence-plan-v1"
WORKER_ROLE = "authority_worker"
WORKER_FACTORY_ID = "authority_worker-v1"
BACKEND_AUTHORITY = "rtl-reader-fixed-device-read-backend-v1"
ACK_AUTHORITY = "rtl-reader-device-read-ack-v1"
SNAPSHOT_AUTHORITY = "rtl-reader-device-evidence-snapshot-v1"
PROTECTED_AUTHORITY = "rtl-reader-protected-read-cleanup-v1"
PROTECTED_PROTOCOL = "rtl-reader-protected-read-v1"
PROTECTED_PROTOCOL_VERSION = 1

TARGET_CALL_BUDGET_NS = 25_000_000
TARGET_TOTAL_BUDGET_NS = 250_000_000
MAX_OPERATION_BUDGET_NS = 30_000_000_000
MAX_TOTAL_BUDGET_NS = 300_000_000_000
MAX_DUMP_BYTES = 4 * 1024 * 1024
HARDWARE_TIMING_PROVEN = False
REAL_RUNTIME_BACKEND_IMPLEMENTED = False
REAL_READER_EPOCH_AUTHORITY_IMPLEMENTED = False
CONTENT_URI_SUPPORTED = False
TARGET_PACKAGE = "com.supernote.document"
READER_EPOCH_AUTHORITY = "rtl-reader-instance-epoch-v1"
UNRESOLVED_BLOCKERS = (
    "real fixed-operation private-ADB backend/bootstrap is not implemented",
    "real retained one-shot reader-instance epoch authority is not implemented",
    "content URI resolution lacks exact provider authority and remains unsupported",
    "25 ms operation and 250 ms total hardware timing targets are unproven",
)

ORDINARY_PREFIX = "/storage/emulated/0"
PROTECTED_ROOTS = (
    "/data/adb/modules",
    "/product",
    "/system",
    "/system_ext",
    "/vendor",
)
PROTECTED_KINDS = ("framework", "module_apk", "target_base_apk")
STAGING_PREFIX = "/data/local/tmp/rtl-reader-native-page/read"

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_PACKAGE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_PURPOSE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class DeviceReadError(RuntimeError):
    """The fixed evidence collection could not be admitted or proven."""


class ReadCleanupUncertain(DeviceReadError):
    """Protected staging cleanup is not proven; this authority is sealed."""


class QuiescenceUncertain(DeviceReadError):
    """A worker/reply channel may remain live; no evidence may be released."""


def _fail(message: str) -> NoReturn:
    raise DeviceReadError(message)


def _exact(value: Any, expected: type, label: str) -> None:
    if type(value) is not expected:
        _fail(label + " has an inexact type")


def _literal(value: Any, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        _fail(label + " differs")
    return value


def _token(value: Any, label: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        _fail(label + " is not a canonical token")
    return value


def _positive(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        _fail(label + " is outside exact integer bounds")
    return value


def _bounded_text(value: Any, label: str, maximum: int = 4096) -> str:
    if (type(value) is not str or not value or len(value.encode("utf-8")) > maximum or
            "\x00" in value or unicodedata.normalize("NFC", value) != value):
        _fail(label + " is not canonical bounded text")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _path(value: Any, label: str) -> str:
    _bounded_text(value, label, 4096)
    if (not value.startswith("/") or value.startswith("//") or "\\" in value or
            value.endswith("/") or any(part in {"", ".", ".."} for part in value.split("/")[1:])):
        _fail(label + " is not a canonical absolute Android path")
    return value


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def canonical_file_uri(path: str) -> str:
    _path(path, "file URI path")
    return "file://" + quote(path, safe="/-._~", encoding="utf-8", errors="strict")


def _ordinary_root(root: Any) -> str:
    _path(root, "ordinary allowed root")
    if not _under(root, ORDINARY_PREFIX) or root == ORDINARY_PREFIX:
        _fail("ordinary allowed root is outside scoped shared storage")
    return root


def _protected_path(path: Any) -> str:
    _path(path, "protected source path")
    if not any(_under(path, root) and path != root for root in PROTECTED_ROOTS):
        _fail("protected source path is outside fixed protected roots")
    return path


@dataclass(frozen=True)
class ReaderBackendBinding:
    authority: str
    serial: str
    private_adb_session_id: str
    private_adb_endpoint: str
    private_adb_pid: int
    private_adb_start_ticks: int
    private_adb_bundle_sha256: str
    worker_session_id: str
    worker_pid: int
    worker_creation_ticks: int
    worker_image_path: str
    worker_image_sha256: str
    worker_source_sha256: str
    worker_parent_pid: int
    worker_parent_creation_ticks: int
    worker_role: str
    worker_factory_id: str
    ordinary_uid: int
    ordinary_gid: int
    private_socket: bool
    explicit_serial_every_operation: bool
    retained_worker_handle: bool
    fixed_operations_only: bool
    accepts_general_commands: bool
    fresh_reply_channel_per_operation: bool
    late_reply_channel_sealed: bool
    failure_returns_after_operation_quiescence: bool
    root_only_for_protected_reads: bool
    protected_cleanup_before_return: bool
    protected_dispatch_witness_required: bool
    protected_anchor_descriptor_retained: bool
    protected_handle_relative_nofollow: bool
    protected_descriptor_bound_cleanup: bool

    def validate(self, adb: PrivateAdbBinding, worker: WorkerBinding) -> None:
        _exact(adb, PrivateAdbBinding, "backend private ADB binding")
        _exact(worker, WorkerBinding, "backend authority worker binding")
        try:
            adb_result = adb.validate()
            worker_bytes = worker.canonical_bytes()
        except BaseException as error:
            raise DeviceReadError("backend retained dependency binding is invalid") from error
        if adb_result is not None or type(worker_bytes) is not bytes or not worker_bytes:
            _fail("backend retained dependency validation returned unexpected data")
        _literal(worker.role, WORKER_ROLE, "backend authority worker role")
        _literal(worker.factory_id, WORKER_FACTORY_ID,
                 "backend authority worker factory")
        _literal(self.authority, BACKEND_AUTHORITY, "reader backend authority")
        for value, expected, label in (
                (self.serial, adb.serial, "backend serial"),
                (self.private_adb_session_id, adb.session_id, "backend ADB session"),
                (self.private_adb_endpoint, adb.endpoint, "backend ADB endpoint"),
                (self.private_adb_bundle_sha256, adb.bundle_sha256,
                 "backend ADB bundle"),
                (self.worker_session_id, worker.session, "backend worker session"),
                (self.worker_image_path, worker.image_path, "backend worker image path"),
                (self.worker_image_sha256, worker.image_sha256, "backend worker image"),
                (self.worker_source_sha256, worker.source_sha256, "backend worker source"),
                (self.worker_role, worker.role, "backend worker role"),
                (self.worker_factory_id, worker.factory_id, "backend worker factory")):
            _literal(value, expected, label)
        for value, label in (
                (self.private_adb_pid, "backend ADB PID"),
                (self.private_adb_start_ticks, "backend ADB start time"),
                (self.worker_pid, "backend worker PID"),
                (self.worker_creation_ticks, "backend worker creation time"),
                (self.worker_parent_pid, "backend worker parent PID"),
                (self.worker_parent_creation_ticks, "backend worker parent creation time")):
            _positive(value, label)
        if (self.private_adb_pid != adb.server_pid or
                self.private_adb_start_ticks != adb.server_start_ticks or
                self.worker_pid != worker.pid or
                self.worker_creation_ticks != worker.creation_ticks or
                self.worker_parent_pid != worker.parent_pid or
                self.worker_parent_creation_ticks != worker.parent_creation_ticks or
                type(self.ordinary_uid) is not int or type(self.ordinary_gid) is not int or
                (self.ordinary_uid, self.ordinary_gid) != (2000, 2000) or
                self.private_socket is not True or
                self.explicit_serial_every_operation is not True or
                self.retained_worker_handle is not True or
                self.fixed_operations_only is not True or
                self.accepts_general_commands is not False or
                self.fresh_reply_channel_per_operation is not True or
                self.late_reply_channel_sealed is not True or
                self.failure_returns_after_operation_quiescence is not True or
                self.root_only_for_protected_reads is not True or
                self.protected_cleanup_before_return is not True or
                self.protected_dispatch_witness_required is not True or
                self.protected_anchor_descriptor_retained is not True or
                self.protected_handle_relative_nofollow is not True or
                self.protected_descriptor_bound_cleanup is not True):
            _fail("reader backend is outside fixed private read authority")


@dataclass(frozen=True)
class DirectoryIdentity:
    path: str
    uid: int
    gid: int
    mode: int
    device: int
    inode: int
    directory: bool
    symlink: bool


@dataclass(frozen=True)
class FileIdentity:
    path: str
    resolved_path: str
    sha256: str
    size: int
    uid: int
    gid: int
    mode: int
    device: int
    inode: int
    nlink: int
    regular: bool
    symlink: bool
    parent: DirectoryIdentity


def _validate_directory(value: DirectoryIdentity, expected: DirectoryIdentity,
                        label: str) -> None:
    _exact(value, DirectoryIdentity, label)
    _exact(expected, DirectoryIdentity, label + " expectation")
    _path(value.path, label + " path")
    for field, name in ((value.uid, "UID"), (value.gid, "GID"), (value.mode, "mode"),
                        (value.device, "device"), (value.inode, "inode")):
        if type(field) is not int or field < 0 or (name in {"device", "inode"} and field == 0):
            _fail(label + " " + name + " has an invalid exact integer")
    if value.directory is not True or value.symlink is not False or value != expected:
        _fail(label + " identity differs")


def _validate_file_identity(value: FileIdentity, expected: FileIdentity, label: str,
                            *, require_single_link: bool) -> None:
    _exact(value, FileIdentity, label)
    _exact(expected, FileIdentity, label + " expectation")
    _path(value.path, label + " path")
    _path(value.resolved_path, label + " resolved path")
    _token(value.sha256, label + " digest")
    for field, name in ((value.size, "size"), (value.uid, "UID"), (value.gid, "GID"),
                        (value.mode, "mode"), (value.device, "device"),
                        (value.inode, "inode"), (value.nlink, "link count")):
        if type(field) is not int or field < 0 or (name in {"device", "inode", "link count"} and field == 0):
            _fail(label + " " + name + " has an invalid exact integer")
    if (value.path != value.resolved_path or value.regular is not True or
            value.symlink is not False or (require_single_link and value.nlink != 1)):
        _fail(label + " is not one exact regular non-link file")
    if (value.path.rsplit("/", 1)[0] != value.parent.path or
            value.device != value.parent.device):
        _fail(label + " parent path/device differs from its exact file authority")
    _validate_directory(value.parent, expected.parent, label + " parent")
    if value != expected:
        _fail(label + " identity differs")


def _relative_beneath(path: str, anchor: str, label: str) -> str:
    _path(path, label + " path")
    _path(anchor, label + " anchor")
    if path == anchor or not _under(path, anchor):
        _fail(label + " is not strictly beneath its anchor")
    relative = path[len(anchor) + 1:]
    if (not relative or relative.startswith("/") or relative.endswith("/") or
            any(part in {"", ".", ".."} for part in relative.split("/"))):
        _fail(label + " relative path is not canonical")
    return relative


def _directory_chain_paths(anchor: str, parent: str, label: str) -> tuple[str, ...]:
    _path(parent, label + " parent")
    if parent == anchor:
        return (anchor,)
    parent_relative = _relative_beneath(parent, anchor, label)
    paths = [anchor]
    current = anchor
    if parent_relative:
        for part in parent_relative.split("/"):
            current += "/" + part
            paths.append(current)
    if paths[-1] != parent:
        _fail(label + " parent chain differs")
    return tuple(paths)


@dataclass(frozen=True)
class ExactFilePlan:
    purpose: str
    allowed_root: str
    uri: str
    expected: FileIdentity
    disposable_fixture: bool

    def validate(self) -> None:
        if type(self.purpose) is not str or _PURPOSE.fullmatch(self.purpose) is None:
            _fail("ordinary file purpose is invalid")
        if self.disposable_fixture is not True:
            _fail("ordinary PDF is not explicitly authorized as disposable")
        root = _ordinary_root(self.allowed_root)
        _exact(self.expected, FileIdentity, self.purpose + " expected file")
        if not _under(_path(self.expected.path, self.purpose + " path"), root):
            _fail(self.purpose + " path is outside its authorized root")
        _literal(self.uri, canonical_file_uri(self.expected.path), self.purpose + " URI")
        _validate_file_identity(self.expected, self.expected, self.purpose + " plan file",
                                require_single_link=True)


@dataclass(frozen=True)
class NullableFilePlan:
    purpose: str
    allowed_root: str
    path: str
    uri: str
    expected: FileIdentity | None
    absent_parent: DirectoryIdentity | None
    disposable_companion: bool

    def validate(self) -> None:
        if type(self.purpose) is not str or _PURPOSE.fullmatch(self.purpose) is None:
            _fail("nullable file purpose is invalid")
        if self.disposable_companion is not True:
            _fail("nullable mark is not bound to the disposable fixture")
        root = _ordinary_root(self.allowed_root)
        path = _path(self.path, self.purpose + " path")
        if not _under(path, root):
            _fail(self.purpose + " path is outside its authorized root")
        _literal(self.uri, canonical_file_uri(path), self.purpose + " URI")
        if self.expected is not None:
            _exact(self.expected, FileIdentity, self.purpose + " expected file")
            if self.expected.path != path or self.absent_parent is not None:
                _fail("present nullable file plan is inconsistent")
            _validate_file_identity(self.expected, self.expected, self.purpose + " plan file",
                                    require_single_link=True)
        else:
            if self.absent_parent is None:
                _fail("absent nullable file requires exact parent authority")
            _validate_directory(self.absent_parent, self.absent_parent,
                                self.purpose + " absent parent")
            if path.rsplit("/", 1)[0] != self.absent_parent.path:
                _fail("absent nullable file parent path differs")


@dataclass(frozen=True)
class ProtectedArtifactPlan:
    kind: str
    expected: FileIdentity
    source_anchor: DirectoryIdentity
    source_ancestors: tuple[DirectoryIdentity, ...]

    def validate(self) -> None:
        if type(self.kind) is not str or self.kind not in PROTECTED_KINDS:
            _fail("protected artifact kind is invalid")
        _exact(self.expected, FileIdentity, self.kind + " expected file")
        _protected_path(self.expected.path)
        _validate_file_identity(self.expected, self.expected, self.kind + " plan file",
                                require_single_link=False)
        _exact(self.source_anchor, DirectoryIdentity, self.kind + " source anchor")
        matching_roots = tuple(root for root in PROTECTED_ROOTS
                               if _under(self.expected.path, root) and self.expected.path != root)
        if not matching_roots:
            _fail(self.kind + " has no protected source root")
        expected_anchor_path = max(matching_roots, key=len)
        if self.source_anchor.path != expected_anchor_path:
            _fail(self.kind + " source anchor is not its exact protected root")
        _validate_directory(self.source_anchor, self.source_anchor,
                            self.kind + " source anchor")
        if type(self.source_ancestors) is not tuple or not self.source_ancestors:
            _fail(self.kind + " source ancestors are not an exact nonempty tuple")
        expected_paths = _directory_chain_paths(
            self.source_anchor.path, self.expected.parent.path,
            self.kind + " source authority")
        if len(self.source_ancestors) != len(expected_paths):
            _fail(self.kind + " source ancestor count differs")
        for index, (item, expected_path) in enumerate(zip(self.source_ancestors,
                                                          expected_paths)):
            _exact(item, DirectoryIdentity, self.kind + " source ancestor")
            _validate_directory(item, item,
                                self.kind + f" source ancestor {index}")
            if item.path != expected_path or item.device != self.expected.device:
                _fail(self.kind + " source ancestor path/mount differs")
        if (self.source_ancestors[0] != self.source_anchor or
                self.source_ancestors[-1] != self.expected.parent):
            _fail(self.kind + " source ancestor endpoints differ")
        _relative_beneath(self.expected.path, self.source_anchor.path,
                          self.kind + " source")


@dataclass(frozen=True)
class DeviceStatePlan:
    serial: str
    adb_state: str
    adb_authorized: bool
    build_fingerprint: str
    build_id: str
    build_incremental: str
    product: str
    device: str
    model: str
    sdk_int: int
    boot_id: str
    verified_boot_state: str
    flash_locked: bool

    def validate(self) -> None:
        if type(self.serial) is not str or _SERIAL.fullmatch(self.serial) is None:
            _fail("device-state serial is invalid")
        _literal(self.adb_state, "device", "authorized ADB device state")
        if self.adb_authorized is not True:
            _fail("ADB device is not explicitly authorized")
        for value, label in ((self.build_fingerprint, "fingerprint"),
                             (self.build_id, "build ID"),
                             (self.build_incremental, "build incremental"),
                             (self.product, "product"), (self.device, "device"),
                             (self.model, "model")):
            _bounded_text(value, "device-state " + label, 1024)
        if type(self.sdk_int) is not int or not 27 <= self.sdk_int <= 100:
            _fail("device-state SDK is invalid")
        if type(self.boot_id) is not str or _BOOT_ID.fullmatch(self.boot_id) is None:
            _fail("device-state boot ID is invalid")
        if (type(self.verified_boot_state) is not str or
                self.verified_boot_state not in {"green", "yellow", "orange"} or
                type(self.flash_locked) is not bool):
            _fail("device-state boot authority is invalid")


@dataclass(frozen=True)
class TargetProcessPlan:
    package: str
    process: str
    pid: int
    start_ticks: int
    uid: int
    gid: int
    cmdline: tuple[str, ...]
    base_apk_path: str

    def validate(self) -> None:
        if (type(self.package) is not str or len(self.package) > 255 or
                _PACKAGE.fullmatch(self.package) is None):
            _fail("target package is invalid")
        _literal(self.package, TARGET_PACKAGE, "fixed target package")
        _literal(self.process, self.package, "target process")
        _positive(self.pid, "target PID", 4_194_304)
        _positive(self.start_ticks, "target start time")
        if type(self.uid) is not int or type(self.gid) is not int or self.uid < 0 or self.gid < 0:
            _fail("target UID/GID is invalid")
        if (type(self.cmdline) is not tuple or not self.cmdline or len(self.cmdline) > 16 or
                any(type(item) is not str or not item or "\x00" in item or
                    len(item.encode("utf-8")) > 4096 or
                    unicodedata.normalize("NFC", item) != item for item in self.cmdline) or
                self.cmdline[0] != self.process):
            _fail("target cmdline is invalid")
        _protected_path(self.base_apk_path)


@dataclass(frozen=True)
class DumpLimits:
    activity: int
    window: int
    display: int

    def validate(self) -> None:
        for value, label in ((self.activity, "activity"), (self.window, "window"),
                             (self.display, "display")):
            if type(value) is not int or not 1 <= value <= MAX_DUMP_BYTES:
                _fail(label + " dump bound is invalid")


@dataclass(frozen=True)
class EvidencePlan:
    authority: str
    session_id: str
    serial: str
    device: DeviceStatePlan
    target: TargetProcessPlan
    original_pdf: ExactFilePlan
    mark: NullableFilePlan
    protected: tuple[ProtectedArtifactPlan, ...]
    staging_anchor: DirectoryIdentity
    dumps: DumpLimits
    operation_budget_ns: int = MAX_OPERATION_BUDGET_NS
    total_budget_ns: int = MAX_TOTAL_BUDGET_NS

    def validate(self) -> None:
        _literal(self.authority, PLAN_AUTHORITY, "evidence plan authority")
        _token(self.session_id, "evidence plan session")
        if type(self.serial) is not str or _SERIAL.fullmatch(self.serial) is None:
            _fail("evidence plan serial is invalid")
        _exact(self.device, DeviceStatePlan, "device-state plan")
        _exact(self.target, TargetProcessPlan, "target-process plan")
        _exact(self.original_pdf, ExactFilePlan, "original PDF plan")
        _exact(self.mark, NullableFilePlan, "mark plan")
        _exact(self.staging_anchor, DirectoryIdentity, "staging anchor")
        _exact(self.dumps, DumpLimits, "dump limits")
        self.device.validate(); self.target.validate(); self.original_pdf.validate()
        self.mark.validate(); self.dumps.validate()
        _literal(self.original_pdf.purpose, "original_pdf", "original PDF purpose")
        _literal(self.mark.purpose, "mark", "nullable mark purpose")
        _literal(self.mark.path, self.original_pdf.expected.path + ".mark",
                 "nullable mark companion path")
        if self.device.serial != self.serial:
            _fail("device-state serial differs from evidence plan")
        if type(self.protected) is not tuple:
            _fail("protected artifact plan is not an exact tuple")
        for item in self.protected:
            _exact(item, ProtectedArtifactPlan, "protected artifact plan")
            item.validate()
        if tuple(item.kind for item in self.protected) != PROTECTED_KINDS:
            _fail("protected artifact kinds/order differ from fixed plan")
        _validate_directory(self.staging_anchor, self.staging_anchor,
                            "protected staging anchor")
        if (self.staging_anchor.path != STAGING_PREFIX or
                (self.staging_anchor.uid, self.staging_anchor.gid,
                 self.staging_anchor.mode) != (2000, 2000, 0o700)):
            _fail("protected staging anchor differs from fixed shell authority")
        anchors: dict[str, DirectoryIdentity] = {}
        for item in self.protected:
            previous = anchors.setdefault(item.source_anchor.path, item.source_anchor)
            if previous != item.source_anchor:
                _fail("shared protected source anchor identity differs")
        if (len({item.expected.path for item in self.protected}) != len(self.protected) or
                len({(item.expected.device, item.expected.inode)
                     for item in self.protected}) != len(self.protected)):
            _fail("protected artifact paths or inodes are not distinct")
        base = next(item for item in self.protected if item.kind == "target_base_apk")
        if base.expected.path != self.target.base_apk_path:
            _fail("target base APK process/path authority differs")
        if (type(self.operation_budget_ns) is not int or
                not 1 <= self.operation_budget_ns <= MAX_OPERATION_BUDGET_NS or
                type(self.total_budget_ns) is not int or
                not self.operation_budget_ns <= self.total_budget_ns <= MAX_TOTAL_BUDGET_NS):
            _fail("evidence timing plan is invalid")

    def sha256(self) -> str:
        self.validate()
        return _digest(asdict(self))


@dataclass(frozen=True)
class ReaderInstanceEpoch:
    authority: str
    epoch_id: str
    issuer_id: str
    plan_sha256: str
    serial: str
    admission_sequence: int
    one_shot_consumed: bool
    retained_live_authority: bool

    def validate(self, plan: EvidencePlan) -> None:
        _exact(plan, EvidencePlan, "reader epoch plan")
        _literal(self.authority, READER_EPOCH_AUTHORITY,
                 "reader instance epoch authority")
        _token(self.epoch_id, "reader instance epoch")
        _token(self.issuer_id, "reader epoch issuer")
        _literal(self.plan_sha256, plan.sha256(), "reader epoch plan digest")
        _literal(self.serial, plan.serial, "reader epoch serial")
        _positive(self.admission_sequence, "reader epoch admission sequence")
        if (self.epoch_id in {plan.session_id, self.issuer_id} or
                self.one_shot_consumed is not True or
                self.retained_live_authority is not True):
            _fail("reader epoch is not one-shot and retained")


@dataclass(frozen=True)
class DeviceStateEvidence:
    plan_sha256: str
    operation_id: str
    reader_epoch_id: str
    value: DeviceStatePlan
    collector_uid: int
    collector_gid: int


@dataclass(frozen=True)
class TargetProcessEvidence:
    plan_sha256: str
    operation_id: str
    reader_epoch_id: str
    value: TargetProcessPlan
    alive: bool
    collector_uid: int
    collector_gid: int


@dataclass(frozen=True)
class OpenedFileEvidence:
    plan_sha256: str
    operation_id: str
    reader_epoch_id: str
    uri: str
    resolved_uri_path: str
    uri_scheme: str
    uri_resolution_exact: bool
    descriptor_id: str
    descriptor_read_only: bool
    descriptor_nofollow: bool
    descriptor_bound_to_stat: bool
    hash_from_descriptor: bool
    collector_uid: int
    collector_gid: int
    stat_before: FileIdentity
    stat_after: FileIdentity
    bytes_sha256: str
    bytes_read: int


@dataclass(frozen=True)
class MissingFileEvidence:
    plan_sha256: str
    operation_id: str
    reader_epoch_id: str
    path: str
    uri: str
    resolved_uri_path: str
    uri_scheme: str
    uri_resolution_exact: bool
    errno: int
    parent_before: DirectoryIdentity
    parent_after: DirectoryIdentity
    collector_uid: int
    collector_gid: int
    nofollow_checked: bool


@dataclass(frozen=True)
class NullableFileEvidence:
    reader_epoch_id: str
    present: bool
    opened: OpenedFileEvidence | None
    missing: MissingFileEvidence | None


@dataclass(frozen=True)
class AnchoredPathEvidence:
    anchor_before: DirectoryIdentity
    anchor_after: DirectoryIdentity
    ancestors_before: tuple[DirectoryIdentity, ...]
    ancestors_after: tuple[DirectoryIdentity, ...]
    anchor_descriptor_id: str
    anchor_descriptor_retained: bool
    relative_path: str
    resolved_path: str
    resolve_beneath: bool
    resolve_no_symlinks: bool
    resolve_no_magiclinks: bool
    resolve_no_xdev: bool
    descriptor_bound_to_resolved_inode: bool


@dataclass(frozen=True)
class ProtectedReadEvidence:
    plan_sha256: str
    operation_id: str
    reader_epoch_id: str
    source_before: FileIdentity
    source_after: FileIdentity
    source_descriptor_id: str
    source_descriptor_read_only: bool
    source_descriptor_nofollow: bool
    source_copy_bound_to_inode: bool
    source_path_authority: AnchoredPathEvidence
    staging_path: str
    staging_parent_before_read: DirectoryIdentity
    staging_parent_after_read: DirectoryIdentity
    staging_directory_created_exclusively: bool
    staging_device: int
    staging_inode: int
    staging_nlink: int
    staging_uid: int
    staging_gid: int
    staging_mode: int
    staging_sha256: str
    staging_size: int
    staging_regular: bool
    staging_symlink: bool
    descriptor_id: str
    descriptor_read_only: bool
    descriptor_nofollow: bool
    descriptor_bound_to_staging_inode: bool
    staging_hash_from_descriptor: bool
    descriptor_collector_uid: int
    descriptor_collector_gid: int
    staging_path_authority: AnchoredPathEvidence
    root_protocol: str
    root_protocol_version: int
    root_session_id: str
    root_guardian_pid: int
    root_guardian_start_ticks: int
    root_guardian_uid: int
    root_guardian_gid: int
    root_control_id: str
    root_cmdline: tuple[str, ...]
    private_adb_session_id: str
    worker_session_id: str
    root_guardian_cleanup_armed: bool
    root_scope_protected_only: bool
    staging_file_absent: bool
    staging_inode_absent: bool
    staging_directory_absent: bool
    root_guardian_absent: bool
    root_guardian_pid_not_reused: bool
    root_control_closed: bool
    path_not_replaced: bool
    cleanup_anchor_descriptor_id: str
    cleanup_handle_relative: bool
    cleanup_descriptor_bound_to_staging_inode: bool


@dataclass(frozen=True)
class RawDumpEvidence:
    operation_id: str
    reader_epoch_id: str
    kind: str
    source: str
    raw: bytes
    sha256: str
    byte_count: int
    truncated: bool
    collector_uid: int
    collector_gid: int


@dataclass(frozen=True)
class ReadRequest:
    authority: str
    session_id: str
    serial: str
    sequence: int
    entry_generation: int
    state_generation: int
    lifecycle_state: str
    operation: str
    operation_id: str
    reader_epoch_id: str
    issued_ns: int
    deadline_ns: int
    plan_sha256: str
    private_adb_binding_sha256: str
    worker_binding_sha256: str
    backend_binding_sha256: str
    arguments_sha256: str

    def sha256(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class ReadAck:
    authority: str
    session_id: str
    serial: str
    sequence: int
    operation: str
    operation_id: str
    reader_epoch_id: str
    request_sha256: str
    issued_ns: int
    produced_ns: int


@dataclass(frozen=True)
class DeviceStateReceipt:
    ack: ReadAck
    evidence: DeviceStateEvidence


@dataclass(frozen=True)
class TargetProcessReceipt:
    ack: ReadAck
    evidence: TargetProcessEvidence


@dataclass(frozen=True)
class OpenedFileReceipt:
    ack: ReadAck
    evidence: OpenedFileEvidence


@dataclass(frozen=True)
class NullableFileReceipt:
    ack: ReadAck
    evidence: NullableFileEvidence


@dataclass(frozen=True)
class ProtectedReadReceipt:
    ack: ReadAck
    evidence: ProtectedReadEvidence


@dataclass(frozen=True)
class DumpReceipt:
    ack: ReadAck
    evidence: RawDumpEvidence


@dataclass(frozen=True)
class DeviceEvidenceSnapshot:
    authority: str
    plan_sha256: str
    session_id: str
    serial: str
    reader_epoch: ReaderInstanceEpoch
    private_adb: PrivateAdbBinding
    worker: WorkerBinding
    backend: ReaderBackendBinding
    device: DeviceStateEvidence
    target: TargetProcessEvidence
    original_pdf: OpenedFileEvidence
    mark: NullableFileEvidence
    protected: tuple[ProtectedReadEvidence, ...]
    activity: RawDumpEvidence
    window: RawDumpEvidence
    display: RawDumpEvidence
    operation_count: int
    content_uri_supported: bool
    real_runtime_backend_implemented: bool
    real_reader_epoch_authority_implemented: bool
    hardware_timing_proven: bool
    unresolved_blockers: tuple[str, ...]


class Clock(Protocol):
    def now_ns(self) -> int: ...


class RetainedWorkerRuntime(Protocol):
    def binding(self, process: Any) -> WorkerBinding: ...


class RetainedReaderEpochAuthority(Protocol):
    def consume(self, plan_sha256: str, serial: str) -> ReaderInstanceEpoch: ...
    def verify(self, expected: ReaderInstanceEpoch) -> None: ...


class FixedReadBackend(Protocol):
    """Operation-specific adapter; no method accepts command text or arbitrary paths."""

    def binding(self) -> ReaderBackendBinding: ...
    def verify(self, expected: ReaderBackendBinding) -> None: ...
    def assert_operation_quiescent(self, expected: ReaderBackendBinding,
                                   operation_id: str, deadline_ns: int) -> None: ...
    def assert_all_quiescent(self, expected: ReaderBackendBinding,
                             deadline_ns: int) -> None: ...
    def read_device_state(self, request: ReadRequest,
                          plan: DeviceStatePlan) -> DeviceStateReceipt: ...
    def read_target_process(self, request: ReadRequest,
                            plan: TargetProcessPlan) -> TargetProcessReceipt: ...
    def read_original_pdf(self, request: ReadRequest,
                          plan: ExactFilePlan) -> OpenedFileReceipt: ...
    def read_nullable_mark(self, request: ReadRequest,
                           plan: NullableFilePlan) -> NullableFileReceipt: ...
    def read_target_base_apk(self, request: ReadRequest, plan: ProtectedArtifactPlan,
                             staging_path: str,
                             dispatch_witness: Callable[[], None]) -> ProtectedReadReceipt: ...
    def read_framework(self, request: ReadRequest, plan: ProtectedArtifactPlan,
                       staging_path: str,
                       dispatch_witness: Callable[[], None]) -> ProtectedReadReceipt: ...
    def read_module_apk(self, request: ReadRequest, plan: ProtectedArtifactPlan,
                        staging_path: str,
                        dispatch_witness: Callable[[], None]) -> ProtectedReadReceipt: ...
    def read_activity_dump(self, request: ReadRequest,
                           maximum: int) -> DumpReceipt: ...
    def read_window_dump(self, request: ReadRequest,
                         maximum: int) -> DumpReceipt: ...
    def read_display_dump(self, request: ReadRequest,
                          maximum: int) -> DumpReceipt: ...


T = TypeVar("T")


def _serialized(function: Callable[..., T]) -> Callable[..., T]:
    @wraps(function)
    def guarded(self: "AuthenticatedDeviceEvidenceReader", *args: Any, **kwargs: Any) -> T:
        caller = threading.get_ident()
        if self._active_entry is not None and self._entry_owner == caller:
            _fail("reentrant device-evidence entry is not permitted")
        if not self._lock.acquire(blocking=False):
            _fail("concurrent device-evidence entry is not permitted")
        if self._active_entry is not None:
            self._lock.release()
            _fail("concurrent device-evidence entry is not permitted")
        self._entry_counter += 1
        self._active_entry = self._entry_counter
        self._entry_owner = caller
        try:
            return function(self, *args, **kwargs)
        finally:
            self._active_entry = None
            self._entry_owner = None
            self._lock.release()
    return guarded


class AuthenticatedDeviceEvidenceReader:
    """One-shot S7-facing collector for one immutable evidence plan."""

    _OPERATIONS = frozenset({
        "device_state_before", "target_process_before", "original_pdf", "nullable_mark",
        "target_base_apk", "framework", "module_apk", "activity_dump", "window_dump",
        "display_dump", "target_process_after", "device_state_after",
    })

    def __init__(self, *, plan: EvidencePlan, private_adb: RetainedPrivateAdb,
                 worker_runtime: RetainedWorkerRuntime, worker_process: Any,
                 epoch_authority: RetainedReaderEpochAuthority,
                 backend: FixedReadBackend, clock: Clock,
                 allow_unproven_epoch_authority_for_tests: bool = False):
        _exact(plan, EvidencePlan, "evidence plan")
        plan.validate()
        if type(allow_unproven_epoch_authority_for_tests) is not bool:
            _fail("reader epoch test-only admission flag is inexact")
        if (not REAL_READER_EPOCH_AUTHORITY_IMPLEMENTED and
                not allow_unproven_epoch_authority_for_tests):
            _fail("real one-shot reader epoch authority is unavailable")
        if any(value is None for value in (
                private_adb, worker_runtime, worker_process, epoch_authority,
                backend, clock)):
            _fail("all retained authorities and monotonic clock are required")
        self._plan = plan
        self._private_adb_authority = private_adb
        self._worker_runtime = worker_runtime
        self._worker_process = worker_process
        self._epoch_authority = epoch_authority
        self._backend_adapter = backend
        self._clock = clock
        self._lock = threading.Lock()
        self._entry_counter = 0
        self._active_entry: int | None = None
        self._entry_owner: int | None = None
        self._state_generation = 0
        self._sequence = 0
        self._last_now = -1
        self.state = "NEW"
        self.cleanup_obligations: tuple[str, ...] = ()
        self._snapshot: DeviceEvidenceSnapshot | None = None
        self._protected_pending: tuple[str, str, str] | None = None
        self._protected_completed = False
        try:
            self._epoch = epoch_authority.consume(plan.sha256(), plan.serial)
        except BaseException as error:
            raise DeviceReadError("reader instance epoch admission failed") from error
        _exact(self._epoch, ReaderInstanceEpoch, "reader instance epoch")
        self._epoch.validate(plan)
        self._adb = private_adb.binding()
        self._worker = self._read_worker_binding()
        self._backend = backend.binding()
        _exact(self._adb, PrivateAdbBinding, "private ADB binding")
        _exact(self._worker, WorkerBinding, "worker binding")
        _exact(self._backend, ReaderBackendBinding, "reader backend binding")
        self._validate_private_adb(self._adb)
        self._validate_worker(self._worker)
        self._backend.validate(self._adb, self._worker)
        if self._adb.serial != plan.serial:
            _fail("plan serial differs from retained private ADB serial")
        self._verify_dependencies()

    @property
    def plan(self) -> EvidencePlan:
        return self._plan

    def _set_state(self, value: str) -> None:
        if type(value) is not str or value not in {
                "NEW", "COLLECTING", "READY", "VERIFYING", "CLOSED",
                "FAILED", "FAILED_CLEAN", "CLEANUP_UNCERTAIN",
                "QUIESCENCE_UNCERTAIN"}:
            _fail("unknown device-evidence state")
        if self.state != value:
            self.state = value
            self._state_generation += 1

    def _now(self) -> int:
        value = self._clock.now_ns()
        if type(value) is not int or value < 0 or value < self._last_now:
            _fail("device-evidence clock regressed or is inexact")
        self._last_now = value
        return value

    def _deadline(self, value: int) -> int:
        now = self._now()
        if type(value) is not int or not now < value <= now + self.plan.total_budget_ns:
            _fail("collection deadline is expired or outside the frozen budget")
        return value

    def _verify_dependencies(self) -> None:
        if self._epoch_authority.verify(self._epoch) is not None:
            _fail("reader epoch verification returned unexpected data")
        if self._private_adb_authority.verify(self._adb) is not None:
            _fail("private ADB verification returned unexpected data")
        adb = self._private_adb_authority.binding()
        self._validate_private_adb(adb)
        if adb != self._adb:
            _fail("private ADB identity drifted")
        worker = self._read_worker_binding()
        if worker != self._worker:
            _fail("isolated worker identity drifted")
        if self._backend_adapter.verify(self._backend) is not None:
            _fail("backend verification returned unexpected data")
        backend = self._backend_adapter.binding()
        _exact(backend, ReaderBackendBinding, "current backend binding")
        backend.validate(self._adb, self._worker)
        if backend != self._backend:
            _fail("reader backend identity drifted")

    @staticmethod
    def _validate_private_adb(value: Any) -> None:
        _exact(value, PrivateAdbBinding, "private ADB binding")
        try:
            result = value.validate()
        except BaseException as error:
            raise DeviceReadError("private ADB binding is invalid") from error
        if result is not None:
            _fail("private ADB validation returned unexpected data")

    @staticmethod
    def _validate_worker(value: Any) -> None:
        _exact(value, WorkerBinding, "authority worker binding")
        try:
            canonical = value.canonical_bytes()
        except BaseException as error:
            raise DeviceReadError("authority worker binding is invalid") from error
        if type(canonical) is not bytes or not canonical:
            _fail("authority worker canonical binding is invalid")
        _literal(value.role, WORKER_ROLE, "worker role")
        _literal(value.factory_id, WORKER_FACTORY_ID, "worker factory ID")

    def _read_worker_binding(self) -> WorkerBinding:
        try:
            value = self._worker_runtime.binding(self._worker_process)
        except BaseException as error:
            raise DeviceReadError("retained authority worker is unavailable") from error
        self._validate_worker(value)
        return value

    def _request(self, operation: str, arguments: Any, deadline: int) -> ReadRequest:
        if type(operation) is not str or operation not in self._OPERATIONS:
            _fail("operation is outside the fixed evidence registry")
        if self._active_entry is None or self._entry_owner != threading.get_ident():
            _fail("operation is outside serialized lifecycle authority")
        now = self._now()
        if now >= deadline or self._sequence >= 2**31 - 1:
            _fail("operation deadline or sequence authority is exhausted")
        self._sequence += 1
        operation_id = _digest({"authority": AUTHORITY, "session": self.plan.session_id,
                                "readerEpoch": self._epoch.epoch_id,
                                "entry": self._active_entry, "sequence": self._sequence,
                                "operation": operation})
        return ReadRequest(
            AUTHORITY, self.plan.session_id, self.plan.serial, self._sequence,
            self._active_entry, self._state_generation, self.state, operation, operation_id,
            self._epoch.epoch_id, now,
            min(deadline, now + self.plan.operation_budget_ns), self.plan.sha256(),
            _digest(asdict(self._adb)),
            hashlib.sha256(self._worker.canonical_bytes()).hexdigest(),
            _digest(asdict(self._backend)), _digest(arguments))

    def _current(self, request: ReadRequest) -> None:
        if (self._active_entry != request.entry_generation or
                self._entry_owner != threading.get_ident() or
                self._state_generation != request.state_generation or
                self.state != request.lifecycle_state or self._sequence != request.sequence):
            _fail(request.operation + " request lost current lifecycle authority")

    def _validate_ack(self, request: ReadRequest, ack: ReadAck) -> None:
        _exact(ack, ReadAck, request.operation + " ACK")
        for value, expected, label in (
                (ack.authority, ACK_AUTHORITY, "authority"),
                (ack.session_id, request.session_id, "session"),
                (ack.serial, request.serial, "serial"),
                (ack.operation, request.operation, "operation"),
                (ack.operation_id, request.operation_id, "operation ID"),
                (ack.reader_epoch_id, request.reader_epoch_id, "reader epoch"),
                (ack.request_sha256, request.sha256(), "request digest")):
            _literal(value, expected, request.operation + " ACK " + label)
        if (type(ack.sequence) is not int or type(ack.issued_ns) is not int or
                type(ack.produced_ns) is not int):
            _fail(request.operation + " ACK has an inexact integer")
        now = self._now(); self._current(request)
        if (ack.sequence != request.sequence or ack.issued_ns != request.issued_ns or
                not request.issued_ns <= ack.produced_ns <= now < request.deadline_ns):
            _fail(request.operation + " ACK is stale, late, replayed, or substituted")

    def _call(self, operation: str, arguments: Any, deadline: int, expected: type[T],
              function: Callable[[ReadRequest], T]) -> T:
        self._verify_dependencies()
        request = self._request(operation, arguments, deadline)
        try:
            result = function(request)
            _exact(result, expected, operation + " receipt")
            self._validate_ack(request, result.ack)  # type: ignore[attr-defined]
        finally:
            try:
                if self._backend_adapter.assert_operation_quiescent(
                        self._backend, request.operation_id, request.deadline_ns) is not None:
                    _fail(operation + " quiescence check returned unexpected data")
            except BaseException as error:
                self._seal_quiescence(operation, request.operation_id, error)
                raise QuiescenceUncertain(self.cleanup_obligations[0]) from error
        self._verify_dependencies(); self._current(request)
        if self._now() >= request.deadline_ns:
            _fail(operation + " completed after its deadline")
        return result

    def _validate_device(self, value: DeviceStateEvidence, operation_id: str) -> None:
        _exact(value, DeviceStateEvidence, "device-state evidence")
        _literal(value.plan_sha256, _digest(asdict(self.plan.device)), "device-state plan digest")
        _literal(value.operation_id, operation_id, "device-state operation ID")
        _literal(value.reader_epoch_id, self._epoch.epoch_id,
                 "device-state reader epoch")
        _exact(value.value, DeviceStatePlan, "device-state value"); value.value.validate()
        if (value.value != self.plan.device or type(value.collector_uid) is not int or
                type(value.collector_gid) is not int or
                (value.collector_uid, value.collector_gid) != (2000, 2000)):
            _fail("device-state evidence differs")

    def _validate_target(self, value: TargetProcessEvidence, operation_id: str) -> None:
        _exact(value, TargetProcessEvidence, "target-process evidence")
        _literal(value.plan_sha256, _digest(asdict(self.plan.target)), "target plan digest")
        _literal(value.operation_id, operation_id, "target-process operation ID")
        _literal(value.reader_epoch_id, self._epoch.epoch_id,
                 "target-process reader epoch")
        _exact(value.value, TargetProcessPlan, "target-process value"); value.value.validate()
        if (value.value != self.plan.target or value.alive is not True or
                type(value.collector_uid) is not int or type(value.collector_gid) is not int or
                (value.collector_uid, value.collector_gid) != (2000, 2000)):
            _fail("target process PID/start/cmdline/UID/base APK differs")

    def _validate_opened(self, value: OpenedFileEvidence, plan: ExactFilePlan | NullableFilePlan,
                         label: str, operation_id: str) -> None:
        _exact(value, OpenedFileEvidence, label)
        _literal(value.plan_sha256, _digest(asdict(plan)), label + " plan digest")
        _literal(value.operation_id, operation_id, label + " operation ID")
        _literal(value.reader_epoch_id, self._epoch.epoch_id,
                 label + " reader epoch")
        expected = plan.expected
        if expected is None:
            _fail(label + " unexpectedly has no file expectation")
        _literal(value.uri, plan.uri, label + " URI")
        _literal(value.resolved_uri_path, expected.path, label + " resolved URI path")
        _literal(value.uri_scheme, "file", label + " URI scheme")
        expected_descriptor_id = _digest({
            "authority": AUTHORITY, "operationId": operation_id,
            "purpose": plan.purpose, "path": expected.path,
            "device": expected.device, "inode": expected.inode})
        _literal(value.descriptor_id, expected_descriptor_id, label + " descriptor ID")
        _validate_file_identity(value.stat_before, expected, label + " stat before",
                                require_single_link=True)
        _validate_file_identity(value.stat_after, expected, label + " stat after",
                                require_single_link=True)
        _literal(value.bytes_sha256, expected.sha256, label + " bytes digest")
        if (value.uri_resolution_exact is not True or
                value.descriptor_read_only is not True or value.descriptor_nofollow is not True or
                value.descriptor_bound_to_stat is not True or
                value.hash_from_descriptor is not True or
                type(value.collector_uid) is not int or type(value.collector_gid) is not int or
                (value.collector_uid, value.collector_gid) != (2000, 2000) or
                type(value.bytes_read) is not int or value.bytes_read != expected.size or
                value.stat_before != value.stat_after):
            _fail(label + " descriptor/stat/hash authority differs")

    def _validate_mark(self, value: NullableFileEvidence, operation_id: str) -> None:
        _exact(value, NullableFileEvidence, "nullable mark evidence")
        _literal(value.reader_epoch_id, self._epoch.epoch_id,
                 "nullable mark reader epoch")
        if type(value.present) is not bool:
            _fail("nullable mark presence is inexact")
        if self.plan.mark.expected is not None:
            if value.present is not True or value.opened is None or value.missing is not None:
                _fail("expected mark is absent")
            self._validate_opened(value.opened, self.plan.mark, "mark file", operation_id)
            return
        if value.present is not False or value.opened is not None or value.missing is None:
            _fail("absent mark evidence is inconsistent")
        missing = value.missing
        _exact(missing, MissingFileEvidence, "missing mark evidence")
        _literal(missing.plan_sha256, _digest(asdict(self.plan.mark)), "missing mark plan digest")
        _literal(missing.operation_id, operation_id, "missing mark operation ID")
        _literal(missing.reader_epoch_id, self._epoch.epoch_id,
                 "missing mark reader epoch")
        _literal(missing.path, self.plan.mark.path, "missing mark path")
        _literal(missing.uri, self.plan.mark.uri, "missing mark URI")
        _literal(missing.resolved_uri_path, self.plan.mark.path,
                 "missing mark resolved URI path")
        _literal(missing.uri_scheme, "file", "missing mark URI scheme")
        if type(missing.errno) is not int or missing.errno != 2:
            _fail("missing mark does not prove ENOENT")
        expected_parent = self.plan.mark.absent_parent
        if expected_parent is None:
            _fail("absent mark parent authority disappeared")
        _validate_directory(missing.parent_before, expected_parent,
                            "missing mark parent before")
        _validate_directory(missing.parent_after, expected_parent,
                            "missing mark parent after")
        if (missing.uri_resolution_exact is not True or
                missing.parent_before != missing.parent_after or
                type(missing.collector_uid) is not int or
                type(missing.collector_gid) is not int or
                (missing.collector_uid, missing.collector_gid) != (2000, 2000) or
                missing.nofollow_checked is not True):
            _fail("missing mark absence authority differs")

    def _staging_path(self, plan: ProtectedArtifactPlan) -> str:
        suffix = _digest({"session": self.plan.session_id, "kind": plan.kind,
                          "readerEpoch": self._epoch.epoch_id,
                          "source": plan.expected.path, "sha256": plan.expected.sha256})[:24]
        return (f"{STAGING_PREFIX}/{self.plan.session_id}/{self._epoch.epoch_id}/"
                f"{plan.kind}-{suffix}")

    def _validate_anchored_path(
            self, value: AnchoredPathEvidence, *, anchor: DirectoryIdentity,
            target_path: str, target_device: int, root_session: str, role: str,
            expected_ancestors: tuple[DirectoryIdentity, ...] | None = None) -> str:
        _exact(value, AnchoredPathEvidence, role + " anchored path authority")
        _validate_directory(value.anchor_before, anchor, role + " anchor before")
        _validate_directory(value.anchor_after, anchor, role + " anchor after")
        if value.anchor_before != value.anchor_after:
            _fail(role + " anchor changed across the protected operation")
        if (type(value.ancestors_before) is not tuple or
                type(value.ancestors_after) is not tuple or
                not value.ancestors_before or
                len(value.ancestors_before) != len(value.ancestors_after)):
            _fail(role + " ancestor evidence is not exact and complete")
        expected_paths = _directory_chain_paths(
            anchor.path, target_path.rsplit("/", 1)[0], role + " path")
        if len(value.ancestors_before) != len(expected_paths):
            _fail(role + " ancestor count differs")
        for index, (before, after, expected_path) in enumerate(zip(
                value.ancestors_before, value.ancestors_after, expected_paths)):
            _exact(before, DirectoryIdentity, role + " ancestor before")
            _validate_directory(before, before, role + f" ancestor before {index}")
            _validate_directory(after, before, role + f" ancestor after {index}")
            if (before.path != expected_path or before.device != target_device or
                    (role == "staging" and
                     (before.uid, before.gid, before.mode) != (2000, 2000, 0o700))):
                _fail(role + " ancestor path, mount, or ownership differs")
        if (value.ancestors_before[0] != anchor or
                value.ancestors_after[0] != anchor):
            _fail(role + " ancestor chain is not rooted at the retained anchor")
        if (expected_ancestors is not None and
                (type(expected_ancestors) is not tuple or
                 value.ancestors_before != expected_ancestors or
                 value.ancestors_after != expected_ancestors)):
            _fail(role + " preauthenticated ancestor identities differ")
        relative = _relative_beneath(target_path, anchor.path, role + " resolved path")
        _literal(value.relative_path, relative, role + " anchor-relative path")
        _literal(value.resolved_path, target_path, role + " resolved path")
        expected_anchor_descriptor = _digest({
            "authority": PROTECTED_AUTHORITY, "rootSession": root_session,
            "role": role + "-anchor", "path": anchor.path,
            "device": anchor.device, "inode": anchor.inode})
        _literal(value.anchor_descriptor_id, expected_anchor_descriptor,
                 role + " anchor descriptor ID")
        if (value.anchor_descriptor_retained is not True or
                value.resolve_beneath is not True or
                value.resolve_no_symlinks is not True or
                value.resolve_no_magiclinks is not True or
                value.resolve_no_xdev is not True or
                value.descriptor_bound_to_resolved_inode is not True):
            _fail(role + " handle-relative no-follow resolution authority differs")
        return relative

    def _validate_protected(self, value: ProtectedReadEvidence,
                            plan: ProtectedArtifactPlan, operation_id: str) -> None:
        _exact(value, ProtectedReadEvidence, plan.kind + " protected evidence")
        _literal(value.plan_sha256, _digest(asdict(plan)), plan.kind + " plan digest")
        _literal(value.operation_id, operation_id, plan.kind + " operation ID")
        _literal(value.reader_epoch_id, self._epoch.epoch_id,
                 plan.kind + " reader epoch")
        _validate_file_identity(value.source_before, plan.expected,
                                plan.kind + " source before", require_single_link=False)
        _validate_file_identity(value.source_after, plan.expected,
                                plan.kind + " source after", require_single_link=False)
        _literal(value.staging_path, self._staging_path(plan), plan.kind + " staging path")
        _literal(value.staging_sha256, plan.expected.sha256, plan.kind + " staged digest")
        for field, label in (
                (value.staging_device, "staging device"),
                (value.staging_inode, "staging inode"),
                (value.staging_nlink, "staging link count"),
                (value.staging_uid, "staging UID"), (value.staging_gid, "staging GID"),
                (value.staging_mode, "staging mode"), (value.staging_size, "staging size"),
                (value.descriptor_collector_uid, "descriptor collector UID"),
                (value.descriptor_collector_gid, "descriptor collector GID"),
                (value.root_protocol_version, "root protocol version"),
                (value.root_guardian_pid, "root guardian PID"),
                (value.root_guardian_start_ticks, "root guardian start time"),
                (value.root_guardian_uid, "root guardian UID"),
                (value.root_guardian_gid, "root guardian GID")):
            if type(field) is not int or field < 0:
                _fail(plan.kind + " " + label + " is inexact")
        expected_root_session = _digest({
            "authority": PROTECTED_AUTHORITY, "planSession": self.plan.session_id,
            "readerEpoch": self._epoch.epoch_id,
            "operationId": operation_id,
            "kind": plan.kind, "source": plan.expected.path,
            "staging": value.staging_path, "privateAdbSession": self._adb.session_id,
            "workerSession": self._worker.session,
            "sourceAnchor": asdict(plan.source_anchor),
            "stagingAnchor": asdict(self.plan.staging_anchor)})
        _literal(value.root_session_id, expected_root_session, plan.kind + " root session")
        source_relative = self._validate_anchored_path(
            value.source_path_authority, anchor=plan.source_anchor,
            target_path=plan.expected.path, target_device=plan.expected.device,
            root_session=expected_root_session, role="source",
            expected_ancestors=plan.source_ancestors)
        staging_relative = self._validate_anchored_path(
            value.staging_path_authority, anchor=self.plan.staging_anchor,
            target_path=value.staging_path, target_device=value.staging_device,
            root_session=expected_root_session, role="staging")
        expected_source_descriptor = _digest({
            "authority": PROTECTED_AUTHORITY, "rootSession": expected_root_session,
            "role": "source", "path": plan.expected.path,
            "relativePath": source_relative,
            "anchorDescriptor": value.source_path_authority.anchor_descriptor_id,
            "device": plan.expected.device, "inode": plan.expected.inode})
        _literal(value.source_descriptor_id, expected_source_descriptor,
                 plan.kind + " source descriptor ID")
        expected_staging_descriptor = _digest({
            "authority": PROTECTED_AUTHORITY, "rootSession": expected_root_session,
            "role": "staging", "path": value.staging_path,
            "relativePath": staging_relative,
            "anchorDescriptor": value.staging_path_authority.anchor_descriptor_id,
            "device": value.staging_device, "inode": value.staging_inode})
        _literal(value.descriptor_id, expected_staging_descriptor,
                 plan.kind + " staging descriptor ID")
        expected_root_control = _digest({
            "authority": PROTECTED_AUTHORITY, "rootSession": expected_root_session,
            "pid": value.root_guardian_pid, "startTicks": value.root_guardian_start_ticks})
        _literal(value.root_control_id, expected_root_control, plan.kind + " root control ID")
        _literal(value.root_protocol, PROTECTED_PROTOCOL, plan.kind + " root protocol")
        expected_cmdline = (PROTECTED_PROTOCOL, str(PROTECTED_PROTOCOL_VERSION),
                             self.plan.session_id, self._epoch.epoch_id,
                             operation_id, plan.kind,
                             plan.source_anchor.path, source_relative,
                             self.plan.staging_anchor.path, staging_relative)
        _literal(value.private_adb_session_id, self._adb.session_id,
                 plan.kind + " root ADB session")
        _literal(value.worker_session_id, self._worker.session,
                 plan.kind + " root worker session")
        _validate_directory(value.staging_parent_before_read,
                            value.staging_parent_before_read,
                            plan.kind + " staging parent before read")
        _validate_directory(value.staging_parent_after_read,
                            value.staging_parent_after_read,
                            plan.kind + " staging parent after read")
        staging_parent_path = value.staging_path.rsplit("/", 1)[0]
        expected_cleanup_descriptor = _digest({
            "authority": PROTECTED_AUTHORITY, "rootSession": expected_root_session,
            "role": "cleanup", "anchorDescriptor":
            value.staging_path_authority.anchor_descriptor_id,
            "stagingDescriptor": value.descriptor_id,
            "device": value.staging_device, "inode": value.staging_inode})
        _literal(value.cleanup_anchor_descriptor_id, expected_cleanup_descriptor,
                 plan.kind + " cleanup descriptor ID")
        if (value.source_before != value.source_after or
                value.source_descriptor_read_only is not True or
                value.source_descriptor_nofollow is not True or
                value.source_copy_bound_to_inode is not True or
                value.staging_parent_before_read != value.staging_parent_after_read or
                value.staging_parent_before_read.path != staging_parent_path or
                (value.staging_parent_before_read.uid,
                 value.staging_parent_before_read.gid,
                 value.staging_parent_before_read.mode) != (2000, 2000, 0o700) or
                value.staging_parent_before_read.device != value.staging_device or
                value.staging_path_authority.ancestors_before[-1] !=
                value.staging_parent_before_read or
                value.staging_path_authority.ancestors_after[-1] !=
                value.staging_parent_after_read or
                value.staging_directory_created_exclusively is not True or
                value.staging_device <= 0 or value.staging_inode <= 0 or
                value.staging_nlink != 1 or
                (value.staging_uid, value.staging_gid, value.staging_mode) != (2000, 2000, 0o600) or
                value.staging_size != plan.expected.size or
                value.staging_regular is not True or value.staging_symlink is not False or
                value.descriptor_read_only is not True or
                value.descriptor_bound_to_staging_inode is not True or
                value.staging_hash_from_descriptor is not True or
                value.descriptor_nofollow is not True or
                (value.descriptor_collector_uid, value.descriptor_collector_gid) != (2000, 2000) or
                type(value.root_cmdline) is not tuple or value.root_cmdline != expected_cmdline or
                any(type(item) is not str for item in value.root_cmdline) or
                value.root_protocol_version != PROTECTED_PROTOCOL_VERSION or
                value.root_guardian_pid <= 0 or value.root_guardian_start_ticks <= 0 or
                (value.root_guardian_uid, value.root_guardian_gid) != (0, 0) or
                value.root_guardian_cleanup_armed is not True or
                value.root_scope_protected_only is not True or
                value.staging_file_absent is not True or
                value.staging_inode_absent is not True or
                value.staging_directory_absent is not True or
                value.root_guardian_absent is not True or
                value.root_guardian_pid_not_reused is not True or
                value.root_control_closed is not True or
                value.path_not_replaced is not True or
                value.cleanup_handle_relative is not True or
                value.cleanup_descriptor_bound_to_staging_inode is not True):
            _fail(plan.kind + " protected read/cleanup authority differs")

    def _validate_dump(self, value: RawDumpEvidence, kind: str, maximum: int,
                       operation_id: str) -> None:
        _exact(value, RawDumpEvidence, kind + " dump")
        _literal(value.operation_id, operation_id, kind + " dump operation ID")
        _literal(value.reader_epoch_id, self._epoch.epoch_id,
                 kind + " dump reader epoch")
        sources = {"activity": "dumpsys activity activities",
                   "window": "dumpsys window windows",
                   "display": "dumpsys display"}
        _literal(value.kind, kind, kind + " dump kind")
        _literal(value.source, sources[kind], kind + " dump source")
        _token(value.sha256, kind + " dump digest")
        if (type(value.raw) is not bytes or not value.raw or b"\x00" in value.raw or
                type(value.byte_count) is not int or value.byte_count != len(value.raw) or
                not value.byte_count <= maximum or
                hashlib.sha256(value.raw).hexdigest() != value.sha256 or
                value.truncated is not False or type(value.collector_uid) is not int or
                type(value.collector_gid) is not int or
                (value.collector_uid, value.collector_gid) != (2000, 2000)):
            _fail(kind + " dump is empty, oversized, truncated, substituted, or rooted")

    def _protected_call(self, plan: ProtectedArtifactPlan, deadline: int) -> ProtectedReadEvidence:
        path = self._staging_path(plan)
        methods = {"target_base_apk": self._backend_adapter.read_target_base_apk,
                   "framework": self._backend_adapter.read_framework,
                   "module_apk": self._backend_adapter.read_module_apk}

        dispatch_seen = False

        def dispatch(request: ReadRequest) -> ProtectedReadReceipt:
            nonlocal dispatch_seen

            def witness() -> None:
                nonlocal dispatch_seen
                self._current(request)
                if dispatch_seen or self._protected_pending is not None:
                    _fail("protected request dispatch witness was reused")
                dispatch_seen = True
                self._protected_pending = (plan.kind, path, request.operation_id)

            if self._protected_pending is not None:
                _fail("another protected dispatch is already pending")
            return methods[plan.kind](request, plan, path, witness)

        receipt = self._call(plan.kind, {"plan": asdict(plan), "stagingPath": path}, deadline,
                             ProtectedReadReceipt, dispatch)
        if not dispatch_seen:
            _fail(plan.kind + " backend returned without an exact dispatch witness")
        self._validate_protected(receipt.evidence, plan, receipt.ack.operation_id)
        self._protected_pending = None
        self._protected_completed = True
        return receipt.evidence

    def _collect(self, deadline: int) -> DeviceEvidenceSnapshot:
        before_device_receipt = self._call(
            "device_state_before", asdict(self.plan.device), deadline, DeviceStateReceipt,
            lambda request: self._backend_adapter.read_device_state(request, self.plan.device))
        self._validate_device(before_device_receipt.evidence,
                              before_device_receipt.ack.operation_id)
        before_target_receipt = self._call(
            "target_process_before", asdict(self.plan.target), deadline, TargetProcessReceipt,
            lambda request: self._backend_adapter.read_target_process(request, self.plan.target))
        self._validate_target(before_target_receipt.evidence,
                              before_target_receipt.ack.operation_id)
        pdf_receipt = self._call(
            "original_pdf", asdict(self.plan.original_pdf), deadline, OpenedFileReceipt,
            lambda request: self._backend_adapter.read_original_pdf(
                request, self.plan.original_pdf))
        self._validate_opened(pdf_receipt.evidence, self.plan.original_pdf, "original PDF",
                              pdf_receipt.ack.operation_id)
        mark_receipt = self._call(
            "nullable_mark", asdict(self.plan.mark), deadline, NullableFileReceipt,
            lambda request: self._backend_adapter.read_nullable_mark(request, self.plan.mark))
        self._validate_mark(mark_receipt.evidence, mark_receipt.ack.operation_id)
        protected = tuple(self._protected_call(item, deadline) for item in self.plan.protected)
        dump_values: dict[str, RawDumpEvidence] = {}
        for kind, maximum, method in (
                ("activity", self.plan.dumps.activity, self._backend_adapter.read_activity_dump),
                ("window", self.plan.dumps.window, self._backend_adapter.read_window_dump),
                ("display", self.plan.dumps.display, self._backend_adapter.read_display_dump)):
            receipt = self._call(kind + "_dump", {"maximum": maximum}, deadline, DumpReceipt,
                                 lambda request, m=method, x=maximum: m(request, x))
            self._validate_dump(receipt.evidence, kind, maximum, receipt.ack.operation_id)
            dump_values[kind] = receipt.evidence
        after_target_receipt = self._call(
            "target_process_after", asdict(self.plan.target), deadline, TargetProcessReceipt,
            lambda request: self._backend_adapter.read_target_process(request, self.plan.target))
        self._validate_target(after_target_receipt.evidence,
                              after_target_receipt.ack.operation_id)
        after_device_receipt = self._call(
            "device_state_after", asdict(self.plan.device), deadline, DeviceStateReceipt,
            lambda request: self._backend_adapter.read_device_state(request, self.plan.device))
        self._validate_device(after_device_receipt.evidence,
                              after_device_receipt.ack.operation_id)
        if (before_device_receipt.evidence.value != after_device_receipt.evidence.value or
                before_target_receipt.evidence.value != after_target_receipt.evidence.value):
            _fail("device or target process changed across evidence collection")
        return DeviceEvidenceSnapshot(
            SNAPSHOT_AUTHORITY, self.plan.sha256(), self.plan.session_id, self.plan.serial,
            self._epoch, self._adb, self._worker, self._backend,
            before_device_receipt.evidence,
            before_target_receipt.evidence, pdf_receipt.evidence, mark_receipt.evidence,
            protected, dump_values["activity"], dump_values["window"], dump_values["display"],
            self._sequence, CONTENT_URI_SUPPORTED, REAL_RUNTIME_BACKEND_IMPLEMENTED,
            REAL_READER_EPOCH_AUTHORITY_IMPLEMENTED, HARDWARE_TIMING_PROVEN,
            UNRESOLVED_BLOCKERS)

    def _seal_quiescence(self, operation: str, operation_id: str,
                         error: BaseException) -> None:
        self._snapshot = None
        self._set_state("QUIESCENCE_UNCERTAIN")
        obligations = [
            "operation quiescence and late-reply sealing are not proven for exact " +
            operation + " operation " + operation_id +
            "; do not retry, reuse, accept evidence, or broaden cleanup: " + str(error)]
        if self._protected_pending is not None:
            kind, path, protected_operation_id = self._protected_pending
            obligations.append(
                "protected cleanup is also not proven for exact " + kind +
                " staging path " + path + " operation " + protected_operation_id +
                "; do not retry, reuse, search, or broaden cleanup")
        self.cleanup_obligations = tuple(obligations)

    def _seal_failure(self, error: BaseException) -> None:
        if self.state == "QUIESCENCE_UNCERTAIN":
            return
        self._snapshot = None
        if self._protected_pending is not None:
            kind, path, operation_id = self._protected_pending
            self._set_state("CLEANUP_UNCERTAIN")
            self.cleanup_obligations = (
                "protected cleanup is not proven for exact " + kind + " staging path " + path +
                " operation " + operation_id +
                "; do not retry, reuse, search, or broaden cleanup: " + str(error),)
        else:
            self._set_state("FAILED_CLEAN" if self._protected_completed else "FAILED")
            self.cleanup_obligations = ()

    @_serialized
    def collect(self, deadline_ns: int) -> DeviceEvidenceSnapshot:
        if self.state != "NEW":
            _fail("device-evidence reader is one-shot")
        deadline = self._deadline(deadline_ns)
        self._set_state("COLLECTING")
        try:
            snapshot = self._collect(deadline)
            self._verify_dependencies()
            if self._now() >= deadline:
                _fail("device-evidence collection completed after its deadline")
            self._snapshot = snapshot
            self._set_state("READY")
            return snapshot
        except BaseException as error:
            self._seal_failure(error)
            if self.state == "CLEANUP_UNCERTAIN":
                raise ReadCleanupUncertain(self.cleanup_obligations[0]) from error
            if self.state == "QUIESCENCE_UNCERTAIN":
                raise QuiescenceUncertain(self.cleanup_obligations[0]) from error
            raise

    @_serialized
    def verify_unchanged(self, deadline_ns: int) -> DeviceEvidenceSnapshot:
        if self.state != "READY" or self._snapshot is None:
            _fail("verified evidence snapshot is unavailable")
        deadline = self._deadline(deadline_ns)
        self._set_state("VERIFYING")
        try:
            snapshot = self._collect(deadline)
            self._verify_dependencies()
            if self._now() >= deadline:
                _fail("device-evidence verification completed after its deadline")
            self._snapshot = snapshot
            self._set_state("READY")
            return snapshot
        except BaseException as error:
            self._seal_failure(error)
            if self.state == "CLEANUP_UNCERTAIN":
                raise ReadCleanupUncertain(self.cleanup_obligations[0]) from error
            if self.state == "QUIESCENCE_UNCERTAIN":
                raise QuiescenceUncertain(self.cleanup_obligations[0]) from error
            raise

    @_serialized
    def close(self, deadline_ns: int) -> DeviceEvidenceSnapshot | None:
        if self.state == "CLOSED":
            if self._snapshot is None or self.cleanup_obligations:
                _fail("closed device evidence is sealed or unavailable")
            return self._snapshot
        if self.state != "READY":
            if self.state == "CLEANUP_UNCERTAIN":
                raise ReadCleanupUncertain(self.cleanup_obligations[0])
            if self.state == "QUIESCENCE_UNCERTAIN":
                raise QuiescenceUncertain(self.cleanup_obligations[0])
            if self.state in {"FAILED", "FAILED_CLEAN"}:
                _fail("device evidence is sealed after terminal failure")
            _fail("device-evidence close is unavailable in this state")
        if self._snapshot is None or self.cleanup_obligations:
            _fail("ready device evidence is sealed or unavailable")
        deadline = self._deadline(deadline_ns)
        try:
            self._verify_dependencies()
            try:
                if self._backend_adapter.assert_all_quiescent(
                        self._backend, deadline) is not None:
                    _fail("final quiescence check returned unexpected data")
            except BaseException as error:
                self._seal_quiescence("final_close", _digest({
                    "readerEpoch": self._epoch.epoch_id,
                    "sequence": self._sequence,
                    "stateGeneration": self._state_generation}), error)
                raise QuiescenceUncertain(self.cleanup_obligations[0]) from error
            self._verify_dependencies()
            if self._now() >= deadline:
                _fail("device-evidence close completed after its deadline")
            self._set_state("CLOSED")
            return self._snapshot
        except BaseException as error:
            self._seal_failure(error)
            raise

    @_serialized
    def evidence(self) -> DeviceEvidenceSnapshot | None:
        if self.state == "CLEANUP_UNCERTAIN":
            raise ReadCleanupUncertain(self.cleanup_obligations[0])
        if self.state == "QUIESCENCE_UNCERTAIN":
            raise QuiescenceUncertain(self.cleanup_obligations[0])
        if self.state in {"FAILED", "FAILED_CLEAN"}:
            _fail("device evidence is sealed after terminal failure")
        if self.state in {"READY", "CLOSED"}:
            if self._snapshot is None or self.cleanup_obligations:
                _fail("authenticated device evidence is sealed or unavailable")
            return self._snapshot
        if self._snapshot is not None or self.cleanup_obligations:
            _fail("non-success state retained publishable device evidence")
        return None


__all__ = [
    "ACK_AUTHORITY", "AUTHORITY", "AnchoredPathEvidence",
    "AuthenticatedDeviceEvidenceReader",
    "BACKEND_AUTHORITY", "CONTENT_URI_SUPPORTED", "DeviceEvidenceSnapshot",
    "DeviceReadError", "DeviceStateEvidence", "DeviceStatePlan", "DeviceStateReceipt",
    "DirectoryIdentity", "DumpLimits", "DumpReceipt", "EvidencePlan", "ExactFilePlan",
    "FileIdentity", "FixedReadBackend", "HARDWARE_TIMING_PROVEN", "MAX_DUMP_BYTES",
    "MissingFileEvidence", "NullableFileEvidence", "NullableFilePlan",
    "NullableFileReceipt", "OpenedFileEvidence", "OpenedFileReceipt", "PLAN_AUTHORITY",
    "PRIVATE_ADB_AUTHORITY", "PROTECTED_AUTHORITY", "PROTECTED_KINDS",
    "PROTECTED_PROTOCOL", "PROTECTED_PROTOCOL_VERSION",
    "PrivateAdbBinding", "ProtectedArtifactPlan", "ProtectedReadEvidence",
    "ProtectedReadReceipt", "RawDumpEvidence", "ReadAck", "ReadCleanupUncertain",
    "QuiescenceUncertain", "ReadRequest", "READER_EPOCH_AUTHORITY",
    "ReaderBackendBinding", "ReaderInstanceEpoch",
    "REAL_READER_EPOCH_AUTHORITY_IMPLEMENTED", "REAL_RUNTIME_BACKEND_IMPLEMENTED",
    "RetainedReaderEpochAuthority", "RetainedWorkerRuntime",
    "SNAPSHOT_AUTHORITY", "STAGING_PREFIX", "TARGET_CALL_BUDGET_NS", "TARGET_PACKAGE",
    "TARGET_TOTAL_BUDGET_NS", "TargetProcessEvidence", "TargetProcessPlan",
    "TargetProcessReceipt", "UNRESOLVED_BLOCKERS", "WORKER_FACTORY_ID",
    "WORKER_ROLE", "WorkerBinding",
    "canonical_file_uri",
]
