"""S7 production candidate: isolated, challenge-bound, read-only authority capture.

There is deliberately no default launcher, device transport, shell, or mutation
API. AuthorityEngine belongs INSIDE the retained S2 authority_worker image. Its
configuration/HMAC capability and source handles must be provisioned through that
image's authenticated private bootstrap, never through an evidence record.
AuthorityProvider is the runner-side S2 channel owner; it never calls a source.

S1c is an explicit unimplemented read-only device interface, not an extension of
the clean S1 command list. S6 and platform containment adapters remain separately
reviewed dependencies. Offline tests do not prove the frozen 250/25ms remote
cleanup budget. No function in this module grants hardware admission.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from enum import Enum
import hashlib
import hmac
import queue
import re
import secrets
import stat
import threading
import time
from typing import Any, Callable, Protocol
from types import SimpleNamespace

import native_page_android_authority as android
import native_page_coordinator_contracts as contracts
import native_page_graph_v2_runner as runner
import native_page_host_authority as host
import native_page_isolated_ipc as isolated
import native_page_pen_peer as pen
from native_page_cleanup_ledger import ResourceIdentity


S1C_AUTHORITY = "rtl-reader-native-page-read-only-device-authority-v1"
S1C_OPERATIONS = (
    "read_exact_pid_stat_cmdline_boot_id", "read_build_fingerprint",
    "read_retained_regular_file_bytes_and_stat", "prove_exact_mark_absence",
    "resolve_exact_file_or_content_uri", "read_device_boottime",
)
SOURCE_NAMES = ("private_adb", "device_read", "host", "pen", "frida", "ledger", "tool_bundle")
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_BOOTSTRAP_MS = 10000
STABILITY_AUTHORITY = "rtl-reader-s7-retained-host-stability-v1"


def admission_status() -> dict:
    return {"admitted": False, "blockers": [*contracts.ADMISSION_BLOCKERS,
            "S1C_REVIEWED_READ_ONLY_DEVICE_INTERFACE_UNAVAILABLE",
            "S7_PLATFORM_WORKER_BOOTSTRAP_AND_CONTAINMENT_UNPROVEN"],
            "s1cAuthority": S1C_AUTHORITY, "s1cOperations": list(S1C_OPERATIONS),
            "ambientFallback": False, "mutationsAuthorized": False,
            "cleanupBudget": {"totalMs": 250, "perCallMs": 25, "hardwareProven": False}}


class AuthorityError(runner.AuthorityProviderQuiescenceFailure):
    pass


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise AuthorityError(message)


def _sha(raw: bytes) -> str:
    _require(type(raw) is bytes, "exact detached bytes required")
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes) -> dict:
    result = runner.load_canonical(raw, runner.MAX_AUTHORITY_BYTES).value
    _require(type(result) is dict, "exact evidence object required")
    return result


def _copy(value: Any) -> Any:
    return runner.load_canonical(runner.canonical_bytes(value), runner.MAX_AUTHORITY_BYTES).value


def _same(actual: Any, expected: Any, label: str) -> None:
    _require(runner.canonical_bytes(actual) == runner.canonical_bytes(expected), label)


def _wrap(value: dict) -> runner.CanonicalAuthority:
    raw = runner.canonical_bytes(value, runner.MAX_AUTHORITY_BYTES)
    return runner.CanonicalAuthority(raw, _sha(raw))


def _stability_body(capture: runner.StageAuthorityCapture, process: dict) -> dict:
    """S7-only witness; the frozen runner record/receipt schemas stay intact."""
    return dict(authority=STABILITY_AUTHORITY, hostProcess=_copy(process),
                captureSha256=capture.record.sha256, receiptSha256=capture.receipt.sha256)


def _stability_wire(capture: runner.StageAuthorityCapture, process: dict, key: bytes) -> str:
    body = _stability_body(capture, process)
    body["authenticator"] = hmac.new(key, runner.canonical_bytes(body), hashlib.sha256).hexdigest()
    return runner.canonical_bytes(body).decode("utf-8")


def _validate_stability(wire: Any, capture: runner.StageAuthorityCapture, key: bytes) -> dict:
    _require(type(wire) is str, "detached S7 stability witness required")
    value = _json(wire.encode("utf-8"))
    runner._exact(value, {"authority", "hostProcess", "captureSha256", "receiptSha256", "authenticator"},
                  "S7 retained host stability")
    process = value["hostProcess"]
    runner._exact(process, {"pid", "start_ticks", "uid", "package"}, "S7 host process")
    host._process(host.ProcessIdentity(**process))
    _same(process["package"], host.HOST_PACKAGE, "S7 host process package differs")
    contracts._sha(value["authenticator"])
    body = _stability_body(capture, process)
    _same({name: item for name, item in value.items() if name != "authenticator"}, body,
          "S7 stability witness belongs to another capture/receipt")
    expected = hmac.new(key, runner.canonical_bytes(body), hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(expected, value["authenticator"]), "S7 stability witness MAC differs")
    return _copy(process)


class Read(Enum):
    SERVER = "private_server"
    TOOL = "locked_tool_bundle"
    PROCESS = "target_process"
    FINGERPRINT = "firmware_fingerprint"
    FILE = "retained_file"
    URI = "uri_resolution"
    TASK = "android_task"
    HOST = "host_snapshot"
    PEN = "live_pen_lease"
    FRIDA = "frida_lifecycle"
    LEDGER = "retained_checkpoint"


@dataclass(frozen=True)
class ReadEvidence:
    """Returned by a retained source, not constructed from caller expectations.

    The source independently binds the challenge and sampling instant to its
    acquisition. Re-enveloping cached data is forbidden. FILE/PROCESS/HOST/PEN
    use the exact typed payloads below; other operations return raw bytes.
    """
    challenge: str
    capture_id: str
    captured_ns: int
    payload: Any


@dataclass(frozen=True)
class ProcessRead:
    stat_bytes: bytes
    cmdline_bytes: bytes
    boot_id: str


@dataclass(frozen=True)
class FileRead:
    path: str
    identity: ResourceIdentity
    present: bool
    contents: bytes | None
    stat_before: bytes | None
    stat_after: bytes | None
    absence_proof: bytes | None = None


@dataclass(frozen=True)
class HostRead:
    snapshot: host.Snapshot
    placement: host.AppliedPlacement
    ready_event: host.HostEvent


def _detach_read(value: Any, depth: int = 0) -> Any:
    """Copy exact source dataclasses without invoking foreign copying hooks."""
    _require(depth <= 16, "source data topology too deep")
    if value is None or type(value) in (str, bytes, int, bool):
        return value
    if type(value) is host.Placement:
        return value
    if type(value) in (tuple, list, frozenset):
        _require(len(value) <= 4096, "source collection oversized")
        return type(value)(_detach_read(item, depth + 1) for item in value)
    if type(value) is dict:
        return _copy(value)
    allowed = (ProcessRead, FileRead, HostRead, ResourceIdentity, host.Snapshot, host.PackageRecord,
               host.ProcessIdentity, host.ActivityRecord, host.WindowRecord, host.DisplayRecord,
               host.Rect, host.AppliedPlacement, host.HostEvent, pen.CaptureLease, pen.LeaseBinding,
               pen.StageSession, pen.ProcessIdentity)
    _require(type(value) in allowed, "foreign source wrapper/reference rejected")
    return type(value)(**{item.name: _detach_read(getattr(value, item.name), depth + 1) for item in fields(value)})


class ReadOnlySource(Protocol):
    """One retained S1/S1c/S3/S4/S5/S6 authority in the isolated worker.

    verify() must attest retained process/file/channel identity, not reopen a
    path/PID. canonical_bytes() is its independently pinned descriptor. read()
    admits ONLY its enumerated Read operations and selector fields, takes no
    expected hashes/statuses/manifest, and returns only after read quiescence.
    Cancellation of a stalled read is owned by S2 worker kill/join containment.
    Source handles must not own stock/host/pen/Frida mutation or close authority.
    """
    def verify(self) -> None: ...
    def canonical_bytes(self) -> bytes: ...
    def read(self, operation: Read, selector: dict, challenge: str,
             deadline_ns: int) -> ReadEvidence: ...


@dataclass(frozen=True)
class Configuration:
    contract: contracts.RunContract
    stage_index: int
    binding: runner.StageBinding
    manifest_raw: bytes
    tool_raw: bytes
    frida_admission_raw: bytes
    implementation_sha256: str
    worker_image_sha256: str
    stage_policy_sha256: str
    source_pins: tuple[tuple[str, str], ...]
    receipt_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require(type(self.contract) is contracts.RunContract, "immutable S0 contract required")
        _require(type(self.stage_index) is int and 0 <= self.stage_index < 4, "exact indexed stage required")
        _require(type(self.binding) is runner.StageBinding, "exact runner binding required")
        _require(type(self.receipt_key) is bytes and len(self.receipt_key) == 32, "private 256-bit receipt key required")
        for digest in (self.implementation_sha256, self.worker_image_sha256, self.stage_policy_sha256):
            contracts._sha(digest)
        _require(type(self.source_pins) is tuple and all(type(pair) is tuple and len(pair) == 2 for pair in self.source_pins)
                 and tuple(pair[0] for pair in self.source_pins) == SOURCE_NAMES,
                 "exact ordered source pin set required")
        for pair in self.source_pins:
            _require(type(pair) is tuple and len(pair) == 2, "immutable source pin required")
            contracts._sha(pair[1])
        manifest = runner.load_canonical(self.manifest_raw, runner.MAX_MANIFEST_BYTES)
        runner.validate_manifest(manifest, self.binding, runner.EXPECTED_OBSERVER_SHA256)
        plan = self.contract.value
        _same(self.binding.observer_session_id, plan["runSessionId"], "S0/runner shared session differs")
        _same(self.binding.stage, plan["stages"][self.stage_index]["stage"], "indexed S0 stage differs")
        _same(manifest.value["externalSession"]["hostSessionId"], plan["hostSessionId"], "host session differs")
        _require(self.binding.absolute_deadline_ns <= int(plan["absoluteRunDeadlineNs"]), "stage exceeds run deadline")
        _json(self.tool_raw)
        admission = _json(self.frida_admission_raw)
        _same(admission["providerSessionId"], plan["runSessionId"], "S6/provider shared session differs")

    @property
    def session(self) -> str:
        return self.contract.value["runSessionId"]

    def admission(self) -> runner.CanonicalAuthority:
        values = dict(schemaVersion=2, authority=runner.PROVIDER_ADMISSION_AUTHORITY,
                      implementationSha256=self.implementation_sha256, providerSessionId=self.session,
                      rejectsAmbientOverrides=list(runner.ADB_OVERRIDE_NAMES),
                      receiptMacAlgorithm="HMAC-SHA256", receiptKeyId=_sha(self.receipt_key))
        for key in ("independentCapture", "doesNotEchoManifest", "usesLockedAdbBundle", "privateAdbServer",
                    "serverNodaemon", "serverProcessHandleRetained", "fixedMinimalEnvironment",
                    "explicitSerialEveryCommand", "noSharedServer", "authenticatesFridaHostAndServer",
                    "exactFridaTeardown", "capturesBeforeAndAfter", "providerProcessIsolated",
                    "failurePathKillAndJoin", "failureReturnsOnlyAfterQuiescence", "atomicStartPermit",
                    "challengeBoundReceipts", "freshCaptureIds", "receiptSequenceChain", "receiptAcquisitionOwnsSources"):
            values[key] = True
        return _wrap(values)

    @property
    def pins(self) -> runner.TrustedPins:
        return runner.TrustedPins(_sha(self.tool_raw), _sha(self.manifest_raw), self.admission().sha256,
            _sha(self.frida_admission_raw), self.stage_policy_sha256, self.receipt_key)


def _detached_configuration(config: Configuration) -> Configuration:
    _require(type(config) is Configuration, "exact configuration required")
    return Configuration(contracts.RunContract(config.contract.raw), config.stage_index,
        runner.StageBinding(**asdict(config.binding)), config.manifest_raw, config.tool_raw,
        config.frida_admission_raw, config.implementation_sha256, config.worker_image_sha256,
        config.stage_policy_sha256, tuple((name, digest) for name, digest in config.source_pins), config.receipt_key)


def s1c_read_plan(config: Configuration) -> dict:
    """Exact additional selectors for separate S1c review; not runnable commands.

    Clean S1 already supplies dumpsys_activity. S1c must not accept arbitrary
    shell text, extensions, writes, generic process signals, or URI mutations.
    A content resolver must attest the exact provider's retained APK bytes too.
    """
    config = _detached_configuration(config)
    manifest = _json(config.manifest_raw)
    pdf = manifest["files"]["originalPdf"]
    return dict(authority=S1C_AUTHORITY, serial=config.binding.serial,
        process={"pid": config.binding.pid, "statPath": f"/proc/{config.binding.pid}/stat",
                 "cmdlinePath": f"/proc/{config.binding.pid}/cmdline", "bootIdPath": "/proc/sys/kernel/random/boot_id"},
        buildProperty="ro.build.fingerprint", deviceClock="CLOCK_BOOTTIME",
        retainedFiles=[manifest["attachment"][role]["path"] for role in ("apk", "framework", "module")] +
                      [pdf["path"], manifest["files"]["mark"]["path"] or pdf["path"] + ".mark"],
        fileReadPolicy={"noFollow": True, "regularOnly": True, "readOnly": True,
                        "retainHandleAcrossBeforeAfter": True, "stableStatBeforeAfterBytes": True,
                        "maximumBytes": MAX_FILE_BYTES, "nullableMarkRequiresExactAbsence": True},
        uri={"documentUri": pdf["documentUri"], "resolveOnly": True,
             "retainedProviderApkRequired": pdf["documentUri"].startswith("content://")})


def _request_wire(request: runner.AuthorityRequest) -> dict:
    _require(type(request) is runner.AuthorityRequest and type(request.binding) is runner.StageBinding,
             "exact detached runner request required")
    return _copy(asdict(request))


def _request(value: dict, config: Configuration) -> runner.AuthorityRequest:
    runner._exact(value, {"phase", "manifest_sha256", "binding", "absolute_deadline_ns",
                        "tool_bundle_sha256", "run_nonce", "sequence", "previous_receipt_sha256"}, "request")
    _same(value["binding"], asdict(config.binding), "request binding differs from retained plan")
    _same(value["manifest_sha256"], _sha(config.manifest_raw), "manifest challenge differs")
    _same(value["tool_bundle_sha256"], _sha(config.tool_raw), "tool challenge differs")
    _same(value["absolute_deadline_ns"], config.binding.absolute_deadline_ns, "request deadline differs")
    contracts._sha(value["run_nonce"])
    _require(type(value["sequence"]) is int and value["sequence"] in (1, 2), "receipt sequence differs")
    _same(value["phase"], "before" if value["sequence"] == 1 else "after", "phase/sequence differs")
    if value["sequence"] == 1:
        _same(value["previous_receipt_sha256"], None, "before predecessor forbidden")
    else:
        contracts._sha(value["previous_receipt_sha256"])
    return runner.AuthorityRequest(value["phase"], value["manifest_sha256"],
        runner.StageBinding(**value["binding"]), value["absolute_deadline_ns"],
        value["tool_bundle_sha256"], value["run_nonce"], value["sequence"], value["previous_receipt_sha256"])


class AuthorityEngine:
    """Worker-side dispatcher. The authenticated S2 registry owns registration.

    Only admitted inside-worker Dispatch objects may reach dispatch(); selectors
    contain no expected bytes or digests. Every source remains pinned across both
    captures. The engine cannot perform I/O except through these read interfaces.
    """
    def __init__(self, config: Configuration, sources: tuple[tuple[str, ReadOnlySource], ...],
                 clock_ns: Callable[[], int], nonce: Callable[[], str] = lambda: secrets.token_hex(32)):
        _require(type(config) is Configuration, "validated worker configuration required")
        _require(type(sources) is tuple and tuple(pair[0] for pair in sources) == SOURCE_NAMES,
                 "exact read-only retained source set required")
        self.config, self._sources, self._clock, self._nonce = _detached_configuration(config), dict(sources), clock_ns, nonce
        self._source_objects = tuple(self._sources[name] for name in SOURCE_NAMES)
        self._owner = threading.get_ident()
        self._state, self._sequence, self._previous, self._run_nonce = "NEW", 0, None, None
        self._source_ids, self._capture_ids = set(), set()
        self._file_ids, self._file_stats = {}, {}
        self._before = None
        self._last_ns = 0
        self._pen_binding = None
        self._pen_sequence = 0
        self._target_boot = None
        self._host_identity = None

    def _now(self, deadline: int) -> int:
        now = self._clock()
        _require(type(now) is int and self._last_ns <= now < deadline, "worker clock/deadline invalid")
        self._last_ns = now
        return now

    def _verify(self, deadline: int) -> None:
        _require(all(self._sources[name] is expected for name, expected in zip(SOURCE_NAMES, self._source_objects)),
                 "retained source object changed")
        for name, expected in self.config.source_pins:
            source = self._sources[name]
            source.verify()
            raw = source.canonical_bytes()
            _require(_sha(raw) == expected, "retained source authority changed: " + name)
            descriptor = _json(raw)
            runner._exact(descriptor, {"authority", "session", "resource", "readOnly", "operations"}, "source descriptor")
            _same(descriptor["session"], self.config.session, "source session differs")
            _same(descriptor["readOnly"], True, "source is not read-only")
            ResourceIdentity.parse(descriptor["resource"])
            if name == "device_read":
                _same(descriptor["authority"], S1C_AUTHORITY, "S1c authority required")
                _same(descriptor["operations"], list(S1C_OPERATIONS), "exact S1c read set required")
        self._now(deadline)

    def _read(self, source: str, operation: Read, selector: dict, deadline: int) -> Any:
        issued = self._now(deadline)
        challenge = self._nonce()
        contracts._sha(challenge)
        _require(challenge not in self._source_ids, "source challenge repeated")
        self._source_ids.add(challenge)
        evidence = self._sources[source].read(operation, _copy(selector), challenge, deadline)
        now = self._now(deadline)
        _require(type(evidence) is ReadEvidence and evidence.challenge == challenge,
                 "source did not bind fresh acquisition challenge")
        contracts._sha(evidence.capture_id)
        _require(evidence.capture_id not in self._capture_ids, "source capture replay")
        _require(type(evidence.captured_ns) is int and issued <= evidence.captured_ns <= now,
                 "stale/future source capture")
        self._capture_ids.add(evidence.capture_id)
        self._acquisition_floor = issued
        return _detach_read(evidence.payload)

    def _file(self, role: str, path: str, deadline: int, *, optional: bool = False) -> tuple[dict, FileRead]:
        _require(type(path) is str and path.startswith("/") and "\x00" not in path and len(path) <= 4096,
                 "exact absolute read-only file selector required")
        value = self._read("device_read", Read.FILE, {"role": role, "path": path, "limit": MAX_FILE_BYTES}, deadline)
        _require(type(value) is FileRead and type(value.identity) is ResourceIdentity,
                 "retained regular file evidence required")
        _same(value.path, path, "file read selected another path")
        _require(value.identity.kind == "file" and type(value.present) is bool, "file identity/presence invalid")
        identity = value.identity.wire()
        if role in self._file_ids:
            _same(identity, self._file_ids[role], "file authority replaced between captures")
        else:
            _require(all(value.identity.slot != ResourceIdentity.parse(old).slot for old in self._file_ids.values()),
                     "file source slots alias")
            self._file_ids[role] = _copy(identity)
        if not value.present:
            _require(optional and value.contents is value.stat_before is value.stat_after is None,
                     "required file absent/non-null absent record")
            _require(type(value.absence_proof) is bytes and len(value.absence_proof) > 0,
                     "nullable mark requires independently captured absence evidence")
            return dict(present=False, path=None, size=None, sha256=None, stat=None), value
        _require(type(value.contents) is bytes and 0 < len(value.contents) <= MAX_FILE_BYTES,
                 "bounded actual file bytes required")
        _require(value.absence_proof is None, "present file cannot carry absence proof")
        before, after = _json(value.stat_before), _json(value.stat_after)
        runner._validate_stat(before, "file before stat")
        runner._validate_stat(after, "file after stat")
        _same(before, after, "file stat changed during byte acquisition")
        _require(stat.S_ISREG(int(before["mode"])), "file is not regular")
        if role in self._file_stats:
            _same(before, self._file_stats[role], "retained file stat changed")
        self._file_stats[role] = _copy(before)
        return dict(present=True, path=value.path, size=str(len(value.contents)),
                    sha256=_sha(value.contents), stat=before), value

    def _target(self, deadline: int) -> dict:
        bound = self.config.binding
        value = self._read("device_read", Read.PROCESS, {"pid": bound.pid}, deadline)
        _require(type(value) is ProcessRead and type(value.stat_bytes) is bytes and
                 type(value.cmdline_bytes) is bytes, "raw process identity evidence required")
        _require(len(value.stat_bytes) <= 8192 and len(value.cmdline_bytes) <= 4096, "process evidence oversized")
        contracts._match(value.boot_id, contracts._BOOT, "exact device boot identity required")
        text = value.stat_bytes.decode("ascii", "strict")
        match = re.fullmatch(r"([1-9][0-9]*) \([^\n]*\) ([RSDI]) (.*)\n", text)
        _require(match is not None, "process stat is malformed/dead/stopped")
        fields = match.group(3).split(" ")
        _require(len(fields) >= 19 and re.fullmatch(r"[1-9][0-9]*", fields[18]) is not None,
                 "process starttime unavailable")
        _require(value.cmdline_bytes == runner.PACKAGE_NAME.encode() + b"\x00", "target cmdline changed/ambiguous")
        command = value.cmdline_bytes[:-1].decode("ascii")
        result = dict(authority=runner.TARGET_AUTHORITY, serial=bound.serial, pid=int(match.group(1)),
                      startTimeTicks=fields[18], cmdline=command, cmdlineSha256=_sha(value.cmdline_bytes[:-1]),
                      packageName=command, processName=command, alive=True)
        runner._validate_target(result, bound)
        if self._target_boot is not None:
            _same(value.boot_id, self._target_boot, "target device boot changed")
        self._target_boot = value.boot_id
        return result

    def _host(self, deadline: int, task: android.DocumentTaskAuthority) -> dict:
        value = self._read("host", Read.HOST, {}, deadline)
        _require(type(value) is HostRead and type(value.snapshot) is host.Snapshot and
                 type(value.placement) is host.AppliedPlacement and type(value.ready_event) is host.HostEvent,
                 "independent S3 snapshot/placement/event required")
        snap, placement, event = value.snapshot, value.placement, value.ready_event
        # Dataclass annotations and Python equality do not reject bool/int or
        # float/int aliases. Validate the complete event before comparing IDs.
        host._process(event.producer)
        _require(type(event.cursor) is int and 0 < event.cursor <= host.MAX_EVENTS and
                 type(event.generation) is int and event.generation > 0 and
                 type(event.produced_ns) is int and event.produced_ns > 0 and
                 type(event.session) is str and type(event.kind) is str and event.kind == "PLACEMENT_READY" and
                 type(event.body) is dict, "placement event schema differs")
        host._bounded_data(event.body)
        _require(len(runner.canonical_bytes(event.body)) <= host.MAX_EVENT_BYTES, "placement event body oversized")
        runner._exact(event.body, {"sequence", "requested", "effective", "rect"}, "placement event body")
        _require(type(event.body["sequence"]) is int and event.body["sequence"] > 0 and
                 type(event.body["requested"]) is str and type(event.body["effective"]) is str and
                 type(event.body["rect"]) is list and len(event.body["rect"]) == 4 and
                 all(type(n) is int for n in event.body["rect"]), "placement event body field types differ")
        _require(type(placement.session) is str and type(placement.generation) is int and placement.generation > 0 and
                 type(placement.display_id) is int and placement.display_id > 0 and
                 type(placement.sequence) is int and placement.sequence > 0 and
                 type(placement.requested) is host.Placement and type(placement.effective) is host.Placement and
                 type(placement.rect) is host.Rect and all(type(n) is int for n in placement.rect.wire()),
                 "placement identity schema differs")
        _same(event.session, self.config.contract.value["hostSessionId"], "retained host event session differs")
        _require(type(snap.complete) is bool and snap.complete, "incomplete host inventory")
        _require(type(snap.captured_ns) is int and self._acquisition_floor <= snap.captured_ns <= self._last_ns,
                 "host snapshot predates acquisition")
        _same(asdict(snap.package), asdict(host.PINNED_PACKAGE), "host APK authority differs")
        for rows, kind in ((snap.processes, host.ProcessIdentity), (snap.activities, host.ActivityRecord),
                           (snap.windows, host.WindowRecord), (snap.displays, host.DisplayRecord)):
            _require(type(rows) is tuple and len(rows) <= host.MAX_CAPTURE_ROWS and all(type(row) is kind for row in rows),
                     "host snapshot topology differs")
        for process in snap.processes:
            host._process(process)
        for row in snap.activities + snap.windows:
            host._process(row.process)
            _require(type(row.task_id) is int and row.task_id > 0 and type(row.display_id) is int and row.display_id >= 0
                     and type(row.visible) is bool, "host activity/window identity type differs")
        for row in snap.activities:
            _require(type(row.resumed) is bool and type(row.token) is str and bool(row.token), "host activity state differs")
        for row in snap.windows:
            _require(type(row.focused) is bool and type(row.activity_token) is str and bool(row.activity_token),
                     "host window state differs")
            for rect in (row.frame, row.surface_frame):
                _require(rect is None or (type(rect) is host.Rect and all(type(n) is int for n in rect.wire())), "host frame types differ")
        for row in snap.displays:
            _require(type(row.display_id) is int and type(row.flags) is frozenset and
                     all(n is None or type(n) is int for n in (row.width, row.height, row.density)), "host display types differ")
        _require(len({row.pid for row in snap.processes}) == len(snap.processes) and
                 len({row.display_id for row in snap.displays}) == len(snap.displays) and
                 len({row.task_id for row in snap.activities}) == len(snap.activities) and
                 len({row.activity_token for row in snap.windows}) == len(snap.windows), "ambiguous host snapshot identities")
        for digest in (snap.am_sha256, snap.window_sha256, snap.display_sha256, snap.process_sha256):
            contracts._sha(digest)
        activities = [item for item in snap.activities if item.process.package == host.HOST_PACKAGE]
        _require(len(activities) == 1, "host activity absent/ambiguous")
        activity = activities[0]
        host._process(activity.process)
        independently_captured_identity = asdict(activity.process)
        if self._host_identity is not None:
            _same(independently_captured_identity, self._host_identity,
                  "retained S3 host process PID/start identity changed")
        windows = [item for item in snap.windows if item.process == activity.process and item.task_id == activity.task_id
                   and item.activity_token == activity.token]
        displays = [item for item in snap.displays if item.display_id == placement.display_id]
        _require(len(windows) == len(displays) == 1, "host window/display absent/ambiguous")
        window, display = windows[0], displays[0]
        _require(activity.process in snap.processes and display.owner == activity.process and
                 activity.display_id == window.display_id == 0, "host exact process/display ownership differs")
        stage = self.config.contract.value["stages"][self.config.stage_index]
        _same(placement.rect.wire(), stage["rect"], "S0 indexed frame differs")
        _same(placement.effective.value, stage["stage"], "host effective stage differs")
        physical = [item for item in snap.displays if item.display_id == 0]
        _require(len(physical) == 1, "physical display missing/ambiguous")
        _same([physical[0].width, physical[0].height], stage["physicalSize"], "indexed physical orientation differs")
        # These three frozen S3 methods are pure validators: no commands or
        # captures are invoked. Their view contains only independently read IDs.
        view = SimpleNamespace(process=activity.process, host_task_id=activity.task_id, host_token=activity.token,
                               _density=300, display_id=placement.display_id, generation=placement.generation,
                               session=placement.session)
        host.HostAuthority._physical(view, snap, (placement.requested,))
        host.HostAuthority._display(view, snap)
        target = host.ProcessIdentity(task.pid, int(self.config.binding.start_time_ticks), task.uid, task.package_name)
        host.HostAuthority._check_foreign(
            view,
            host.ForeignIdentity(
                target, task.task_id, task.activity_token,
                android.stable_authority_sha256(task)),
            snap)
        _require(event.producer == activity.process and event.session == placement.session and
                 event.generation == placement.generation and event.kind == "PLACEMENT_READY",
                 "placement acknowledgement identity differs")
        _require(type(placement.sequence) is int and placement.sequence > 0 and
                 type(event.produced_ns) is int and 0 < event.produced_ns <= snap.captured_ns,
                 "placement sequence/time differs")
        _same(event.body, {"sequence": placement.sequence, "requested": placement.requested.value,
                          "effective": placement.effective.value, "rect": placement.rect.wire()}, "placement ACK differs")
        _require(window.surface_frame == placement.rect and window.buffer == (1404, 1872), "host surface is not live/attached")
        self._host_identity = _copy(independently_captured_identity)
        return dict(authority=runner.HOST_AUTHORITY, hostSessionId=placement.session, stage=placement.effective.value,
            displayId=display.display_id, defaultDisplayId=activity.display_id, displayGeneration=placement.generation,
            placementRequestGeneration=placement.sequence, placementReadyGeneration=event.body["sequence"],
            hostPackageName=snap.package.package, hostApkSha256=snap.package.apk_sha256, hostTaskId=activity.task_id,
            hostActivityToken=activity.token, displaySize=[display.width, display.height], densityDpi=display.density,
            requestedFrame=placement.rect.wire(), measuredGlobalFrame=window.surface_frame.wire(), applied=True,
            activityResumed=activity.resumed, activityVisible=activity.visible, activityFocused=window.focused,
            surfaceAttached=True, surfaceValid=True)

    def _pen(self, deadline: int) -> dict:
        value = self._read("pen", Read.PEN, {"stage_session": self.config.session}, deadline)
        _require(type(value) is pen.CaptureLease and type(value.binding) is pen.LeaseBinding,
                 "live S4 capture lease required")
        bound = value.binding
        _require(type(value.sequence) is int and value.sequence > self._pen_sequence, "pen source receipt replay")
        self._pen_sequence = value.sequence
        _require(type(bound.stage_session) is pen.StageSession and bound.stage_session.value == self.config.session,
                 "pen observer session changed")
        for identity in (bound.peer, bound.worker, bound.guardian):
            _require(type(identity) is pen.ProcessIdentity, "exact pen process identity required")
            pen.ProcessIdentity(identity.pid, identity.starttime)
        _require(len({bound.peer.pid, bound.worker.pid, bound.guardian.pid, self.config.binding.pid}) == 4,
                 "pen owner/target alias")
        contracts._sha(bound.token)
        contracts._sha(bound.guardian_session)
        _same(bound.device_clock_domain, contracts.DEVICE_CLOCK_DOMAIN, "pen device clock differs")
        _require(type(value.device_boottime_ms) is int and type(bound.deadline_boottime_ms) is int and
                 type(value.remaining_ms) is int and 0 < value.device_boottime_ms < bound.deadline_boottime_ms and
                 value.remaining_ms == bound.deadline_boottime_ms - value.device_boottime_ms,
                 "pen BOOTTIME remaining is not independently measured")
        if self._pen_binding is not None:
            _same(asdict(bound), self._pen_binding, "retained pen binding changed")
        self._pen_binding = _copy(asdict(bound))
        return dict(authority=runner.PEN_LEASE_AUTHORITY, leaseId=bound.token, serial=self.config.binding.serial,
            helperPid=bound.worker.pid, helperStartTimeTicks=str(bound.worker.starttime), holderSessionId=self.config.session,
            mode="observation-only", deviceClockDomain=bound.device_clock_domain,
            remainingLeaseMs=value.remaining_ms, active=True)

    def dispatch(self, operation: str, payload: dict, deadline_ns: int) -> dict:
        try:
            _require(threading.get_ident() == self._owner and self._state != "SEALED", "worker owner/terminal use violation")
            _require(type(deadline_ns) is int and deadline_ns <= self.config.binding.absolute_deadline_ns,
                     "worker operation cannot extend stage deadline")
            self._verify(deadline_ns)
            if operation == "authority_admission":
                _require(self._state == "NEW", "admission replay")
                _same(payload, {"configurationSha256": self.configuration_sha256()}, "worker bootstrap binding differs")
                self._state = "ADMITTED"
                return {"admission": self.config.admission().raw.decode("utf-8")}
            _require(operation == "authority_capture" and self._state in ("ADMITTED", "BEFORE"), "closed authority operation")
            request = _request(payload, self.config)
            _require(request.sequence == self._sequence + 1 and request.previous_receipt_sha256 == self._previous,
                     "receipt predecessor/sequence replay")
            if self._run_nonce is not None:
                _same(request.run_nonce, self._run_nonce, "before/after nonce changed")
            self._run_nonce = request.run_nonce
            manifest = runner.load_canonical(self.config.manifest_raw, runner.MAX_MANIFEST_BYTES)
            tool = runner.load_canonical(self.config.tool_raw, runner.MAX_AUTHORITY_BYTES)
            observed_tool = self._read("tool_bundle", Read.TOOL, {}, deadline_ns)
            _same(_json(observed_tool), tool.value, "locked tool bundle changed")
            server = _json(self._read("private_adb", Read.SERVER, {}, deadline_ns))
            target = self._target(deadline_ns)
            fingerprint = self._read("device_read", Read.FINGERPRINT, {}, deadline_ns)
            _require(type(fingerprint) is bytes and len(fingerprint) < 4096 and fingerprint.endswith(b"\n"),
                     "raw firmware fingerprint required")
            firmware = {"fingerprint": fingerprint[:-1].decode("utf-8", "strict")}
            for role in ("apk", "framework", "module"):
                measured, _ = self._file(role, manifest.value["attachment"][role]["path"], deadline_ns)
                firmware[role] = {"path": measured["path"], "size": int(measured["size"]), "sha256": measured["sha256"]}
                if role == "module":
                    firmware[role]["name"] = measured["path"].rsplit("/", 1)[1]
            pdf_path = manifest.value["files"]["originalPdf"]["path"]
            pdf, pdf_read = self._file("pdf", pdf_path, deadline_ns)
            mark_path = manifest.value["files"]["mark"]["path"] or pdf_path + ".mark"
            mark, mark_read = self._file("mark", mark_path, deadline_ns, optional=True)
            for role, read in (("pdf", pdf_read), ("mark", mark_read)):
                fixture = self.config.contract.value["fixtures"][role]
                if fixture is None:
                    _require(not read.present, "S0 nullable mark was created")
                else:
                    _same(read.identity.wire(), fixture["identity"], "S0 file identity differs")
                    _same(_sha(read.contents), fixture["sha256"], "S0 file bytes changed")
                    _same(len(read.contents), fixture["size"], "S0 file length changed")
            uri = _json(self._read("device_read", Read.URI, {"document_uri": manifest.value["expected"]["documentUri"]}, deadline_ns))
            pdf.update(documentUri=uri["documentUri"], uriResolution=uri)
            files = dict(authority=runner.FILE_AUTHORITY, verification="external-before-and-after-exact", originalPdf=pdf, mark=mark)
            task_raw = self._read("private_adb", Read.TASK, {"command_id": "dumpsys_activity"}, deadline_ns)
            task = android.parse_document_task_authority(task_raw, expected_pid=self.config.binding.pid)
            host_record = self._host(deadline_ns, task)
            frida = _json(self._read("frida", Read.FRIDA, {"phase": request.phase}, deadline_ns))
            checkpoint = _json(self._read("ledger", Read.LEDGER, {}, deadline_ns))
            runner._exact(checkpoint, {"runSessionId", "checkpointSha256"}, "S5 retained checkpoint")
            _same(checkpoint["runSessionId"], self.config.session, "ledger run differs")
            contracts._sha(checkpoint["checkpointSha256"])
            lease = self._pen(deadline_ns)  # Last acquisition; verification must follow it.
            self._verify(deadline_ns)
            capture_id = self._nonce()
            contracts._sha(capture_id)
            _require(capture_id not in self._capture_ids, "capture ID reused")
            self._capture_ids.add(capture_id)
            record = _wrap(dict(schemaVersion=2, authority=runner.STAGE_AUTHORITY, phase=request.phase,
                captureId=capture_id, providerSessionId=self.config.session, manifestSha256=request.manifest_sha256,
                toolBundleSha256=request.tool_bundle_sha256, taskAuthoritySha256=_sha(task.canonical_bytes()),
                privateAdbServer=server, target=target, firmware=firmware, files=files, host=host_record,
                penLease=lease, frida=frida))
            receipt_body = dict(schemaVersion=2, authority=runner.STAGE_RECEIPT_AUTHORITY,
                providerImplementationSha256=self.config.implementation_sha256, providerSessionId=self.config.session,
                runNonce=request.run_nonce, manifestSha256=request.manifest_sha256, observerSessionId=self.config.session,
                stage=request.binding.stage, phase=request.phase, sequence=request.sequence,
                previousReceiptSha256=request.previous_receipt_sha256, captureSha256=record.sha256,
                absoluteMonotonicDeadlineNs=str(request.absolute_deadline_ns), receiptKeyId=_sha(self.config.receipt_key))
            self._now(deadline_ns)
            receipt_body["authenticator"] = hmac.new(self.config.receipt_key, runner.canonical_bytes(receipt_body), hashlib.sha256).hexdigest()
            capture = runner.StageAuthorityCapture(record, task, _wrap(receipt_body))
            admitted = runner._authority(self.config.admission())
            loaded = runner.validate_stage_authority(capture, request, manifest, self.config.pins, tool,
                                                    admitted, runner._authority(_wrap(_json(self.config.frida_admission_raw))))
            runner._validate_capture_receipt(capture, request, admitted, self.config.pins)
            if self._before is not None:
                runner.require_stage_stability(self._before, capture, runner._authority(self._before.record), loaded)
            retained_before = runner._snapshot_stage_capture(capture) if request.phase == "before" else None
            result = {"record": record.raw.decode("utf-8"), "task": task.canonical_bytes().decode("utf-8"),
                      "receipt": capture.receipt.raw.decode("utf-8"),
                      "stability": _stability_wire(capture, self._host_identity, self.config.receipt_key)}
            # All acquisitions, MACs, validators and reference detachment are
            # complete. Reattest exact retained handles/descriptors immediately
            # before publication; a pen read may have invalidated another source.
            self._verify(deadline_ns)
            self._now(deadline_ns)
            if request.phase == "before":
                self._before = retained_before
            self._sequence, self._previous = request.sequence, capture.receipt.sha256
            self._state = "BEFORE" if request.phase == "before" else "COMPLETE"
            return result
        except BaseException:
            self._state = "SEALED"
            raise

    def configuration_sha256(self) -> str:
        # Key ID only: no secret is published in a plan, receipt, or diagnostic.
        return _sha(runner.canonical_bytes(dict(contract=self.config.contract.sha256,
            manifest=_sha(self.config.manifest_raw), tool=_sha(self.config.tool_raw),
            binding=asdict(self.config.binding), stageIndex=self.config.stage_index,
            admission=self.config.admission().sha256, sources=dict(self.config.source_pins),
            image=self.config.worker_image_sha256, policy=self.config.stage_policy_sha256,
            frida=_sha(self.config.frida_admission_raw))))


@dataclass
class _Call:
    action: str
    arguments: tuple
    done: threading.Event = field(default_factory=threading.Event)
    value: Any = None
    error: BaseException | None = None


class _CallDeadline:
    """One non-rebasable caller budget, including locks and local validation."""
    def __init__(self, clock: Callable[[], int], stage_deadline_ns: int, timeout_ms: int):
        self._clock, self._timeout_ms = clock, timeout_ms
        now = clock()
        _require(type(now) is int and now > 0, "authority call clock invalid")
        self._last_ns = now
        self.deadline_ns = min(stage_deadline_ns, now + timeout_ms * 1000000)
        _require(now < self.deadline_ns, "authority call deadline already expired")

    def check(self) -> int:
        now = self._clock()
        _require(type(now) is int and self._last_ns <= now < self.deadline_ns,
                 "authority call proof/publication exceeded original per-call deadline")
        self._last_ns = now
        return now

    def remaining_ms(self) -> int:
        return min(self._timeout_ms, max(1, (self.deadline_ns - self.check() + 999999) // 1000000))


class AuthorityProvider:
    """Exact frozen runner facade. No source/manifest data is read on this side.

    factory constructs a fresh S2 worker *on its owner thread*. Its authenticated
    image bootstrap must already own the exact Configuration and read sources.
    A factory must self-bound and return an unstarted worker without side effects.
    Retain this object on any reported cleanup obligation; never substitute a PID
    kill. Only its contained authority worker is termination-owned here.
    """
    def __init__(self, config: Configuration, factory: Callable[[], isolated.IsolatedWorker], *, bootstrap_ms: int = 250):
        _require(type(config) is Configuration and callable(factory), "configuration and exact isolated factory required")
        _require(type(bootstrap_ms) is int and 1 <= bootstrap_ms <= MAX_BOOTSTRAP_MS, "bootstrap bound differs")
        self.config, self._factory = _detached_configuration(config), factory
        self._queue: queue.Queue[_Call] = queue.Queue(maxsize=2)
        self._ready = threading.Event()
        self._operation_lock, self._stop_lock = threading.Lock(), threading.Lock()
        self._state_lock = threading.RLock()
        self._worker = None
        self._startup_error = None
        self._closing = threading.Event()
        self._state = "NEW"
        self._counter = 0
        self._previous = None
        self._nonce = None
        self._before = None
        self._host_identity = None
        self.cleanup_obligations = ()
        self._thread = threading.Thread(target=self._main, args=(bootstrap_ms,), name="native-page-authority-owner", daemon=True)
        self._thread.start()
        if not self._ready.wait(bootstrap_ms / 1000):
            self._closing.set()
            self.cleanup_obligations = ("authority bootstrap did not settle; retain owner",)
            error = AuthorityError(self.cleanup_obligations[0])
            error.retained_owner = self
            raise error
        if self._startup_error is not None:
            error = AuthorityError("authority bootstrap failed; retained owner required")
            error.retained_owner = self
            raise error from self._startup_error

    def _main(self, bootstrap_ms: int) -> None:
        try:
            worker = self._factory()
            _require(type(worker) is isolated.IsolatedWorker and worker.state == "NEW" and
                     worker.session == self.config.session and worker.image.role == "authority_worker",
                     "factory must return one fresh exact S2 authority worker")
            self._worker = worker
            worker.image.verify()
            _require(_sha(worker.image.canonical_bytes()) == self.config.worker_image_sha256, "worker image pin differs")
            _require(not self._closing.is_set(), "bootstrap canceled before launch")
            worker.start(worker.runtime.now_ns() + bootstrap_ms * 1_000_000)
            _require(not self._closing.is_set(), "bootstrap completed after cancellation")
        except BaseException as error:
            self._startup_error = error
            if self._worker is not None:
                try:
                    self._worker.fail_stop_and_quiesce(bootstrap_ms)
                    self._worker.assert_quiescent()
                except BaseException:
                    self.cleanup_obligations = ("bootstrap worker kill/join not established",)
            self._ready.set()
            return
        self._ready.set()
        while True:
            call = self._queue.get()
            try:
                if call.action == "stop":
                    return
                _require(not self._closing.is_set(), "owner is terminally sealed")
                if call.action == "register":
                    call.value = worker.register_operation(*call.arguments)
                elif call.action == "begin":
                    call.value = worker.begin_and_wait(*call.arguments)
                elif call.action == "assert":
                    worker.assert_quiescent()
                else:
                    raise AuthorityError("unknown authority owner operation")
            except BaseException as error:
                call.error = error
            finally:
                call.done.set()

    def _submit(self, action: str, arguments: tuple, milliseconds: int) -> Any:
        _require(not self._closing.is_set(), "authority channel sealed")
        call = _Call(action, arguments)
        self._queue.put_nowait(call)
        _require(call.done.wait(milliseconds / 1000), "authority worker did not self-bound")
        if call.error is not None:
            raise AuthorityError("isolated authority operation failed") from call.error
        return call.value

    def _timeout(self, timeout_ms: int) -> int:
        _require(type(timeout_ms) is int and 1 <= timeout_ms <= 10000, "exact positive bounded timeout required")
        return timeout_ms

    def _call_deadline(self, timeout_ms: int) -> _CallDeadline:
        timeout_ms = self._timeout(timeout_ms)
        _require(not self._closing.is_set() and self._worker is not None, "authority worker unavailable")
        return _CallDeadline(self._worker.runtime.now_ns, self.config.binding.absolute_deadline_ns, timeout_ms)

    def _started(self, operation: str, payload: dict, timeout_ms: int, permit: runner.OperationStartPermit,
                 budget: _CallDeadline) -> dict:
        timeout_ms = self._timeout(timeout_ms)
        try:
            _require(type(permit) is runner.OperationStartPermit, "frozen operation start permit required")
            _require(self._operation_lock.acquire(timeout=budget.remaining_ms() / 1000), "concurrent authority operation")
            try:
                _require(not self._closing.is_set() and self._worker is not None, "authority worker unavailable")
                deadline = budget.deadline_ns
                self._counter += 1
                operation_id = "authority." + str(self._counter)
                ticket = permit.start(lambda: self._submit("register", (operation_id, operation, _copy(payload), deadline), budget.remaining_ms()))
                permit.require_exact_start(runner.AuthorityProviderQuiescenceFailure)
                result = self._submit("begin", (ticket, deadline), budget.remaining_ms())
                _require(type(result) is isolated.OperationResult and result.operation_id == operation_id and
                         type(result.callbacks) is tuple and not result.callbacks, "authority result/callback channel differs")
                # Outer S2 strings carry complete canonical authority documents;
                # the runner's *inner* JSON string limit must not be applied to
                # those containers. Each contained document is validated below.
                result = isolated.decode_json(isolated.canonical_json(result.value))
                budget.check()
                return result
            finally:
                self._operation_lock.release()
        except BaseException as error:
            self.fail_stop_and_quiesce(timeout_ms)
            raise AuthorityError("authority call failed after terminal worker fence") from error

    def preview_admission(self) -> runner.CanonicalAuthority:
        return self.config.admission()

    def admission(self, timeout_ms: int, start_permit: runner.OperationStartPermit) -> runner.CanonicalAuthority:
        try:
            budget = self._call_deadline(timeout_ms)
            _require(self._state == "NEW", "authority admission replay")
            # Same projection as worker bootstrap, with no source invocation.
            projection = object.__new__(AuthorityEngine)
            projection.config = self.config
            result = self._started("authority_admission", {"configurationSha256": projection.configuration_sha256()}, timeout_ms, start_permit, budget)
            _same(result, {"admission": self.preview_admission().raw.decode("utf-8")}, "worker admission does not match bootstrap")
            admitted = self.preview_admission()
            runner._validate_provider_admission(admitted, self.config.pins)
            detached = runner.CanonicalAuthority(admitted.raw, admitted.sha256)
            with self._state_lock:
                _require(not self._closing.is_set(), "admission raced terminal fence")
                budget.check()
                self._state = "ADMITTED"
            return detached
        except BaseException:
            self.fail_stop_and_quiesce(self._timeout(timeout_ms))
            raise

    def capture(self, request: runner.AuthorityRequest, timeout_ms: int,
                start_permit: runner.OperationStartPermit) -> runner.StageAuthorityCapture:
        try:
            budget = self._call_deadline(timeout_ms)
            _require(self._state in ("ADMITTED", "BEFORE"), "post-terminal or unadmitted capture")
            wire = _request_wire(request)
            request = _request(wire, self.config)
            _require(request.sequence == (1 if self._state == "ADMITTED" else 2) and
                     request.previous_receipt_sha256 == self._previous, "facade sequence/receipt replay")
            if self._nonce is not None:
                _same(request.run_nonce, self._nonce, "facade nonce changed")
            result = self._started("authority_capture", wire, timeout_ms, start_permit, budget)
            runner._exact(result, {"record", "task", "receipt", "stability"}, "worker capture")
            authorities = []
            for name in ("record", "receipt"):
                _require(type(result[name]) is str, "authority wire must be detached text")
                raw = result[name].encode("utf-8")
                authorities.append(runner.CanonicalAuthority(raw, _sha(raw)))
            task_value = _json(result["task"].encode("utf-8"))
            task = android.DocumentTaskAuthority(**task_value)
            capture = runner.StageAuthorityCapture(authorities[0], task, authorities[1])
            admitted = runner._authority(self.preview_admission())
            runner._validate_capture_receipt(capture, request, admitted, self.config.pins)
            host_identity = _validate_stability(result["stability"], capture, self.config.receipt_key)
            if self._host_identity is not None:
                _same(host_identity, self._host_identity, "facade retained host process identity changed")
            loaded = runner.validate_stage_authority(capture, request,
                runner.load_canonical(self.config.manifest_raw, runner.MAX_MANIFEST_BYTES), self.config.pins,
                runner.load_canonical(self.config.tool_raw, runner.MAX_AUTHORITY_BYTES), admitted,
                runner.load_canonical(self.config.frida_admission_raw, runner.MAX_AUTHORITY_BYTES))
            if self._before is not None:
                runner.require_stage_stability(self._before, capture, runner._authority(self._before.record), loaded)
            detached = runner._snapshot_stage_capture(capture)
            retained_before = runner._snapshot_stage_capture(capture) if request.phase == "before" else None
            with self._state_lock:
                _require(not self._closing.is_set(), "capture raced terminal fence")
                budget.check()
                if request.phase == "before":
                    self._before = retained_before
                self._host_identity = host_identity
                self._previous, self._nonce = capture.receipt.sha256, request.run_nonce
                self._state = "BEFORE" if request.phase == "before" else "COMPLETE"
            return detached
        except BaseException:
            self.fail_stop_and_quiesce(self._timeout(timeout_ms))
            raise

    def cancel_and_quiesce(self, timeout_ms: int) -> None:
        self.fail_stop_and_quiesce(timeout_ms)

    def assert_quiescent(self, timeout_ms: int) -> None:
        try:
            if self._closing.is_set():
                _require(self._state == "CLOSED" and not self._thread.is_alive() and not self.cleanup_obligations,
                         "authority terminal quiescence unknown")
            else:
                self._submit("assert", (), self._timeout(timeout_ms))
        except BaseException:
            self.fail_stop_and_quiesce(self._timeout(timeout_ms))
            raise

    def fail_stop_and_quiesce(self, timeout_ms: int) -> None:
        timeout_ms = self._timeout(timeout_ms)
        with self._state_lock:
            self._closing.set()
        if self._state == "CLOSED" and not self._thread.is_alive():
            return
        deadline = time.monotonic_ns() + timeout_ms * 1000000
        _require(self._stop_lock.acquire(timeout=timeout_ms / 1000), "concurrent fail-stop did not settle")
        errors = []
        try:
            worker = self._worker
            if worker is not None:
                try:
                    worker.fail_stop_and_quiesce(timeout_ms)
                    worker.assert_quiescent()
                except BaseException:
                    errors.append("exact authority worker kill/join not established")
            if self._thread.is_alive():
                try:
                    self._queue.put_nowait(_Call("stop", ()))
                except queue.Full:
                    errors.append("authority owner stop queue full")
            self._thread.join(max(0, (deadline - time.monotonic_ns()) / 1000000000))
            if self._thread.is_alive():
                errors.append("authority owner thread did not join")
            self.cleanup_obligations = tuple(errors)
            self._state = "QUARANTINED" if errors else "CLOSED"
            _require(not errors, "; ".join(errors))
        finally:
            self._stop_lock.release()
