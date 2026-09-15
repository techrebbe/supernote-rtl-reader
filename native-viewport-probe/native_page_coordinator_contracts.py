"""S0: pure, fail-closed contracts for the visual-only native-page coordinator.

No transport, filesystem, subprocess, clock sampling, provider imports, or device
operations live here. Evidence hashes are *references*, not authentication. A
future reviewed coordinator must obtain them from independently authenticated
S1/S1b/S2/S3/S4/S5 authorities before supplying an event. A valid model trace is
not hardware admission, and cannot mint a runner/provider authority.

The single session spans the S4 lease and all four runner invocations. Each
invocation still has its own nonce and before/after receipt chain. Host absolute
deadlines and device BOOTTIME never share an arithmetic operation.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
import unicodedata


AUTHORITY = "rtl-reader-native-page-coordinator-contracts-v1"
EVENT_AUTHORITY = "rtl-reader-native-page-coordinator-contract-event-v1"
SCHEMA_VERSION = 1
RUNNER_SCHEMA_VERSION = 2
AUTHORIZED_SERIAL = "SN078C10015092"
PACKAGE_NAME = "com.supernote.document"
COMPONENT = PACKAGE_NAME + "/" + PACKAGE_NAME + ".document.DocumentActivity"
HOST_PACKAGE = "com.techrebbe.supernote.nativepagehost"
HOST_COMPONENT = HOST_PACKAGE + "/" + HOST_PACKAGE + ".NativePageHostActivity"
FIRMWARE_FINGERPRINT = (
    "Supernote/Supernote/Supernote:11/RQ2A.210505.003/"
    "eng.supern.20260616.100032:user/release-keys"
)
APK_SHA256 = "f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482"
FRAMEWORK_SHA256 = "c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d"
EXPECTED_OBSERVER_SHA256 = "46b674674ac78c6d4d22b770ee29a0d9371051bac76c9240ce7174d736b3282d"
CLEANUP_TIMEOUT_MS = 250
CLEANUP_STEP_TIMEOUT_MS = 25
MIN_DEADLINE_MS = 250
MAX_DEADLINE_MS = 10_000
DEVICE_CLOCK_DOMAIN = "android-boottime-v1"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_WIRE_BYTES = 131_072

AUTHORITIES = MappingProxyType({
    "runner": "rtl-reader-native-page-graph-runner-v2",
    "manifest": "rtl-reader-native-page-graph-manifest-v2",
    "snapshot": "rtl-reader-native-page-graph-snapshot-v2",
    "coordinator": "rtl-reader-native-page-graph-coordinator-v2",
    "externalSession": "rtl-reader-native-page-external-session-v2",
    "calibration": "rtl-reader-native-page-calibration-raw-v1",
    "file": "rtl-reader-native-page-file-authority-v1",
    "providerAdmission": "rtl-reader-native-page-provider-admission-v2",
    "stage": "rtl-reader-native-page-external-stage-authority-v2",
    "stageReceipt": "rtl-reader-native-page-stage-receipt-v2",
    "stagePolicy": "rtl-reader-native-page-stage-policy-v2",
    "target": "rtl-reader-target-process-authority-v2",
    "host": "rtl-reader-native-host-surface-authority-v2",
    "pen": "rtl-reader-live-pen-lease-v1",
    "adbServer": "rtl-reader-private-adb-server-authority-v1",
    "frida": "rtl-reader-frida-lifecycle-authority-v1",
    "privateAdb": "rtl-reader-private-adb-authority-v1",
    "windowsTools": "rtl-reader-windows-adb-bundle-authority-v1",
})

# Independent gate constants, not calculated by the host implementation.
STAGE_LAYOUTS = (
    (0, "stage_0_full", "FULL", "PORTRAIT", (1404, 1872), (0, 0, 1404, 1872)),
    (1, "stage_1_left", "LEFT", "LANDSCAPE", (1872, 1404), (0, 78, 936, 1248)),
    (2, "stage_2_right", "RIGHT", "LANDSCAPE", (1872, 1404), (936, 78, 936, 1248)),
    (3, "stage_3_full", "FULL", "LANDSCAPE", (1872, 1404), (409, 0, 1053, 1404)),
)

CLEANUP_STEPS = (
    ("detach_seal_frida", "frida_provider"),
    ("restore_full", "host_authority"),
    ("destroy_foreign_task", "root_supervisor"),
    ("destroy_virtual_display", "host_authority"),
    ("prove_foreign_absence", "external_authority"),
    ("finish_pen_lease", "pen_peer"),
    ("ordinary_stock_reopen", "root_supervisor"),
    ("verify_unchanged_files", "external_authority"),
)
RESOURCE_OWNERS = MappingProxyType({
    "authority_worker": ("process", "isolated_ipc"),
    "frida_worker": ("process", "isolated_ipc"),
    "private_adb_server": ("process", "private_adb"),
    "root_frida_server": ("process", "mutating_private_adb"),
    "stock_process": ("process", "stock_reader"),
    "foreign_task": ("android_task", "root_supervisor"),
    "virtual_display": ("virtual_display", "host_authority"),
    "host_session": ("host_session", "host_authority"),
    "pen_worker": ("process", "pen_peer"),
    "pen_guardian": ("process", "pen_peer"),
    "device_peer": ("process", "pen_peer"),
    "pen_lease": ("pen_lease", "pen_peer"),
    "frida_attachment": ("frida_attachment", "frida_provider"),
    "pdf": ("file", "stock_reader"),
    "mark": ("file", "stock_reader"),
    "tool_bundle": ("tool_bundle", "windows_tool_authority"),
    "run_ledger": ("file", "cleanup_store"),
    "checkpoint": ("file", "cleanup_store"),
})
GENERIC_CLEANUP_ROLES = frozenset(("authority_worker", "frida_worker", "private_adb_server"))
ADMISSION_BLOCKERS = (
    "V2_AUTHENTICATED_PROVIDERS_UNAVAILABLE",
    "FROZEN_RUNNER_REMOTE_CLEANUP_BUDGET_UNPROVEN",
    "REVIEWED_MUTATING_PRIVATE_ADB_OWNER_UNAVAILABLE",
)
REQUIRED_MUTATING_CAPABILITIES = (
    "stage_exact_temporary_root_frida_server",
    "chmod_exact_temporary_root_frida_server",
    "start_exact_temporary_root_frida_server",
    "inspect_exact_temporary_root_frida_server",
    "terminate_exact_temporary_root_frida_server",
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
_DECIMAL = re.compile(r"[1-9][0-9]{0,29}\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


class ContractError(ValueError):
    """Rejected structure, identity, clock, or transition; never authorizes I/O."""


def _require(condition, message):
    if not condition:
        raise ContractError(message)


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "exact fields required")
    return value


def _int(value, low=0, high=MAX_SAFE_INTEGER):
    _require(type(value) is int and low <= value <= high, "integer range/type")
    return value


def _match(value, pattern, message):
    _require(type(value) is str and pattern.fullmatch(value) is not None, message)
    return value


def _sha(value):
    return _match(value, _SHA, "lowercase SHA256 required")


def _decimal(value):
    _match(value, _DECIMAL, "canonical positive decimal required")
    return int(value)


def _same(actual, expected, message="exact constant/binding required"):
    # Canonical comparison deliberately distinguishes 1, True and nested aliases.
    _require(canonical_bytes(actual) == canonical_bytes(expected), message)


def canonical_bytes(value):
    """Bounded exact-builtins-only JSON, with NFC strings and no numeric coercion."""
    count = 0

    def check(item, depth):
        nonlocal count
        count += 1
        _require(count <= 4096 and depth <= 16, "JSON topology limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            _int(item, -MAX_SAFE_INTEGER)
        elif type(item) is str:
            _require(len(item) <= 8192 and "\x00" not in item and
                     unicodedata.normalize("NFC", item) == item, "invalid JSON string")
            try:
                item.encode("utf-8", "strict")
            except UnicodeError as error:
                raise ContractError("invalid Unicode") from error
        elif type(item) is list:
            for child in item:
                check(child, depth + 1)
        elif type(item) is dict:
            for key, child in item.items():
                _require(type(key) is str, "string keys required")
                check(key, depth + 1)
                check(child, depth + 1)
        else:
            raise ContractError("non-JSON or inexact builtin type")
    check(value, 0)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    _require(len(raw) <= MAX_WIRE_BYTES, "wire size limit")
    return raw


def load_canonical(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE_BYTES, "bounded bytes required")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def bad_number(_):
        raise ContractError("floating/nonfinite numbers forbidden")

    def exact_integer(value):
        _require(len(value) <= 17, "oversized JSON integer")
        return _int(int(value), -MAX_SAFE_INTEGER)

    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_float=bad_number, parse_constant=bad_number, parse_int=exact_integer)
        _require(canonical_bytes(value) == raw, "noncanonical JSON encoding")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContractError("invalid canonical JSON") from error


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class HostInstant:
    clock_id: str
    nanoseconds: int

    def __post_init__(self):
        _match(self.clock_id, _TOKEN, "host clock incarnation required")
        _int(self.nanoseconds, 1, 10**30 - 1)


@dataclass(frozen=True)
class DeviceBoottime:
    milliseconds: int

    def __post_init__(self):
        _int(self.milliseconds, 1, (1 << 64) - 1)


def remaining_device_ms(expiry, now):
    _require(type(expiry) is DeviceBoottime and type(now) is DeviceBoottime,
             "device BOOTTIME required; host subtraction forbidden")
    _require(now.milliseconds < expiry.milliseconds, "device lease expired")
    return expiry.milliseconds - now.milliseconds


@dataclass(frozen=True)
class HostDeadline:
    clock_id: str
    issued_ns: int
    absolute_ns: int
    hard_deadline_ms: int

    def __post_init__(self):
        HostInstant(self.clock_id, self.issued_ns)
        HostInstant(self.clock_id, self.absolute_ns)
        _int(self.hard_deadline_ms, MIN_DEADLINE_MS, MAX_DEADLINE_MS)
        _require(0 < self.absolute_ns - self.issued_ns <= self.hard_deadline_ms * 1_000_000,
                 "absolute deadline exceeds frozen runner bound")

    @classmethod
    def parse(cls, value):
        _keys(value, "clockId issuedNs absoluteNs hardDeadlineMs noRetry")
        _same(value["noRetry"], True)
        return cls(value["clockId"], _decimal(value["issuedNs"]),
                   _decimal(value["absoluteNs"]), value["hardDeadlineMs"])

    def require_live(self, now):
        _require(type(now) is HostInstant and now.clock_id == self.clock_id,
                 "host clock domain/incarnation changed")
        _require(self.issued_ns <= now.nanoseconds < self.absolute_ns, "host deadline expired/not issued")


@dataclass(frozen=True)
class ResourceIdentity:
    """Exact S5 identity wire, including boot/start incarnation for processes."""
    kind: str
    namespace: str
    key: str
    incarnation: str

    def __post_init__(self):
        _match(self.kind, re.compile(r"[a-z][a-z0-9_]{0,31}\Z"), "resource kind")
        for value in (self.namespace, self.key, self.incarnation):
            _match(value, _RESOURCE, "resource identity")
        if self.kind == "process":
            _match(self.key, re.compile(r"[1-9][0-9]*\Z"), "canonical process pid")
            boot, separator, start = self.incarnation.partition(":")
            _require(separator == ":", "boot/start identity required")
            _match(boot, _BOOT, "boot UUID required")
            _match(start, re.compile(r"[1-9][0-9]*\Z"), "process start identity required")

    def wire(self):
        return dict(kind=self.kind, namespace=self.namespace, key=self.key, incarnation=self.incarnation)

    @classmethod
    def parse(cls, value):
        _keys(value, "kind namespace key incarnation")
        return cls(**value)

    @property
    def resource_id(self):
        return digest(self.wire())


@dataclass(frozen=True)
class ResourceBinding:
    role: str
    owner: str
    identity: ResourceIdentity

    def __post_init__(self):
        _require(type(self.role) is str and self.role in RESOURCE_OWNERS, "unknown resource role")
        _require(type(self.identity) is ResourceIdentity, "exact resource identity required")
        kind, owner = RESOURCE_OWNERS[self.role]
        _require(self.identity.kind == kind and type(self.owner) is str and self.owner == owner,
                 "wrong resource kind/owner")

    def require_generic_cleanup(self, owner):
        _require(self.role in GENERIC_CLEANUP_ROLES and type(owner) is str and owner == self.owner,
                 "generic cleanup never owns stock, root server, host or pen resources")


def validate_resource_bindings(bindings):
    """A retained ownership set may not reuse a slot, even with a new incarnation."""
    _require(type(bindings) is tuple and len(bindings) <= 128, "bounded immutable ownership set required")
    slots = set()
    for binding in bindings:
        _require(type(binding) is ResourceBinding, "validated resource binding required")
        identity = binding.identity
        slot = (identity.kind, identity.namespace, identity.key)
        _require(slot not in slots, "resource alias, duplicate owner or reused incarnation")
        slots.add(slot)
    return bindings


def admission_status():
    """Unconditionally blocked. Input evidence cannot toggle this result."""
    return {
        "admitted": False, "blockers": list(ADMISSION_BLOCKERS),
        "cleanupBudget": {"totalMs": CLEANUP_TIMEOUT_MS, "perCallMs": CLEANUP_STEP_TIMEOUT_MS,
                          "remoteAdbFridaHardwareProven": False},
        "mutatingPrivateAdb": {
            "status": "separately-reviewed-owner-required",
            "cleanS1ReadOnly": True, "injectedAuthenticatedInterfaceOnly": True,
            "ambientAdbOrFridaFallback": False,
            "capabilities": list(REQUIRED_MUTATING_CAPABILITIES),
            "ownership": "exact-retained-process-and-temporary-file-identities-only",
        },
    }


def _stages(session):
    return [dict(stageIndex=index, commandId=command, stage=stage, orientation=orientation,
                 physicalSize=list(size), rect=list(rect), observerSessionId=session)
            for index, command, stage, orientation, size, rect in STAGE_LAYOUTS]


def _target():
    return dict(serial=AUTHORIZED_SERIAL, package=PACKAGE_NAME, component=COMPONENT, uid=1000,
                firmwareFingerprint=FIRMWARE_FINGERPRINT, apkSha256=APK_SHA256,
                frameworkSha256=FRAMEWORK_SHA256, observerSha256=EXPECTED_OBSERVER_SHA256)


def _policy():
    return dict(noRetry=True, visualOnly=True, maxJavaChooseWalks=1, retainedRootSamples=2,
                detachOnDeadline=True, abortOnAnyError=True, verifyTargetLivenessAfter=True,
                stockDisplayZeroPrecondition="no-Document-task-or-activity;process-may-live",
                foreignDisposal="exact-causal-launch-and-attach-proof-only",
                genericCleanupExcludes=["stock_process", "root_frida_server", "pen_worker",
                                        "pen_guardian", "device_peer", "pen_lease"],
                cleanupOrder=[dict(stepId=step, owner=owner) for step, owner in CLEANUP_STEPS],
                admission=admission_status())


def _file(value):
    _keys(value, "identity sha256 size")
    identity = ResourceIdentity.parse(value["identity"])
    _require(identity.kind == "file", "file resource identity required")
    _sha(value["sha256"])
    _int(value["size"])


@dataclass(frozen=True)
class RunContract:
    """Canonical bytes own the plan; returned dictionaries are disposable copies."""
    raw: bytes

    def __post_init__(self):
        value = load_canonical(self.raw)
        _keys(value, "authority schemaVersion runnerSchemaVersion authorities runSessionId hostSessionId "
              "hostClockId createdHostNs absoluteRunDeadlineNs target host canvas stages policy fixtures")
        _same(value["authority"], AUTHORITY)
        _same(value["schemaVersion"], SCHEMA_VERSION)
        _same(value["runnerSchemaVersion"], RUNNER_SCHEMA_VERSION)
        _same(value["authorities"], dict(AUTHORITIES))
        _sha(value["runSessionId"])
        _match(value["hostSessionId"], _TOKEN, "host session required")
        _match(value["hostClockId"], _TOKEN, "host clock required")
        _require(_decimal(value["createdHostNs"]) < _decimal(value["absoluteRunDeadlineNs"]),
                 "absolute run deadline required")
        _same(value["target"], _target())
        _same(value["host"], {"package": HOST_PACKAGE, "component": HOST_COMPONENT})
        _same(value["canvas"], {"width": 1404, "height": 1872, "densityDpi": 300, "rotation": 0,
                                "flags": ["PUBLIC", "OWN_CONTENT_ONLY", "DESTROY_CONTENT_ON_REMOVAL"]})
        _same(value["stages"], _stages(value["runSessionId"]), "four exact indexed stages/shared session required")
        _same(value["policy"], _policy())
        fixtures = _keys(value["fixtures"], "pdf mark savedInkSha256 uriResolutionSha256")
        _file(fixtures["pdf"])
        if fixtures["mark"] is not None:
            _file(fixtures["mark"])
            # A different incarnation cannot give one retained slot two owners.
            validate_resource_bindings(tuple(ResourceBinding(role, "stock_reader",
                ResourceIdentity.parse(fixtures[role]["identity"])) for role in ("pdf", "mark")))
        _sha(fixtures["savedInkSha256"])
        _sha(fixtures["uriResolutionSha256"])

    @classmethod
    def create(cls, *, run_session_id, host_session_id, created, deadline, fixtures):
        _require(type(created) is HostInstant and type(deadline) is HostInstant and
                 created.clock_id == deadline.clock_id, "one host clock required")
        return cls(canonical_bytes(dict(
            authority=AUTHORITY, schemaVersion=SCHEMA_VERSION, runnerSchemaVersion=RUNNER_SCHEMA_VERSION,
            authorities=dict(AUTHORITIES), runSessionId=run_session_id, hostSessionId=host_session_id,
            hostClockId=created.clock_id, createdHostNs=str(created.nanoseconds),
            absoluteRunDeadlineNs=str(deadline.nanoseconds), target=_target(),
            host={"package": HOST_PACKAGE, "component": HOST_COMPONENT},
            canvas={"width": 1404, "height": 1872, "densityDpi": 300, "rotation": 0,
                    "flags": ["PUBLIC", "OWN_CONTENT_ONLY", "DESTROY_CONTENT_ON_REMOVAL"]},
            stages=_stages(run_session_id), policy=_policy(), fixtures=fixtures)))

    @property
    def value(self):
        return load_canonical(self.raw)

    @property
    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()


def _process(value):
    _keys(value, "identity package uid")
    identity = ResourceIdentity.parse(value["identity"])
    _require(identity.kind == "process" and identity.namespace == AUTHORIZED_SERIAL, "device process required")
    _same(value["package"], PACKAGE_NAME)
    _same(value["uid"], 1000)
    _int(int(identity.key), 2, (1 << 31) - 1)
    _int(int(identity.incarnation.split(":")[1]), 1, (1 << 64) - 1)
    return value


def _display(value, plan):
    _keys(value, "identity displayId generation hostSessionId")
    _int(value["displayId"], 1, 1024)
    _int(value["generation"], 1)
    _same(value["hostSessionId"], plan["hostSessionId"])
    identity = ResourceIdentity.parse(value["identity"])
    _same(identity.wire(), ResourceIdentity("virtual_display", AUTHORIZED_SERIAL,
          str(value["displayId"]), plan["hostSessionId"] + ":" + str(value["generation"])).wire())


def _foreign(value, display):
    _keys(value, "identity process taskId activityToken component display")
    _process(value["process"])
    _int(value["taskId"])
    _match(value["activityToken"], re.compile(r"[0-9a-f]{1,16}\Z"), "activity token required")
    _same(value["component"], COMPONENT)
    _same(value["display"], display)
    incarnation = (display["hostSessionId"] + ":" + str(display["generation"]) + ":" +
                   value["activityToken"] + ":" + digest(value["process"]))
    _same(ResourceIdentity.parse(value["identity"]).wire(), ResourceIdentity(
        "android_task", AUTHORIZED_SERIAL, str(value["taskId"]), incarnation).wire())


def _pen(value, plan):
    _keys(value, "observerSessionId leaseToken peer worker guardian guardianSession deviceClockDomain "
          "absoluteDeviceBoottimeExpiryMs")
    _same(value["observerSessionId"], plan["runSessionId"])
    _same(value["deviceClockDomain"], DEVICE_CLOCK_DOMAIN)
    _sha(value["leaseToken"])
    _sha(value["guardianSession"])
    identities = []
    for role in ("peer", "worker", "guardian"):
        identity = ResourceIdentity.parse(value[role])
        _require(identity.kind == "process" and identity.namespace == AUTHORIZED_SERIAL,
                 "pen exact device process required")
        _int(int(identity.key), 2, (1 << 31) - 1)
        _int(int(identity.incarnation.split(":")[1]), 1, (1 << 64) - 1)
        identities.append(identity)
    _require(len({item.key for item in identities}) == 3, "distinct peer/worker/guardian PIDs required")
    _require(len({item.incarnation.split(":")[0] for item in identities}) == 1, "pen boot identity drift")
    DeviceBoottime(_decimal(value["absoluteDeviceBoottimeExpiryMs"]))


class CoordinatorModel:
    """Offline trace checker, not a production coordinator or authority provider.

    Invalid events poison the run before raising. Cleanup can follow a primary
    failure, but cannot erase it. Uncertain launch ownership or cleanup failure
    requires retained quarantine; no generic kill/close operation is exposed.
    """

    def __init__(self, contract):
        _require(type(contract) is RunContract, "validated immutable contract required")
        self._plan = contract.value
        self._contract_sha = contract.sha256
        self._phase = "DORMANT"
        self._failures = ()
        self._sequence = 0
        self._last_sha = None
        self._last_ns = _decimal(self._plan["createdHostNs"])
        self._stock = self._precheck_sha = self._pen = self._display = None
        self._launch = self._foreign = self._window = None
        self._active = None
        self._nonces = set()
        self._completed = 0
        self._cleanup_index = 0
        self._cleanup_deadline = None
        self._device_ms = 0
        self._stable_graph = None

    @property
    def phase(self):
        return self._phase

    @property
    def failures(self):
        return self._failures

    @property
    def stage_index(self):
        return self._completed

    @property
    def disposable_foreign(self):
        return (None if self._foreign is None or self._cleanup_index >= 3 else
                load_canonical(canonical_bytes(self._foreign)))

    @property
    def retained_quarantine(self):
        return self._phase == "QUARANTINED"

    @property
    def event_head(self):
        return self._sequence, self._last_sha

    def runner_binding_kwargs(self):
        """Exact frozen StageBinding shape; S0 retains the separate indexed stage."""
        _require(self._phase == "CAPTURING" and not self._failures, "no live stage binding")
        identity = self._foreign["process"]["identity"]
        return dict(serial=AUTHORIZED_SERIAL, pid=int(identity["key"]),
                    start_time_ticks=identity["incarnation"].split(":")[1],
                    observer_session_id=self._plan["runSessionId"], deadline_ms=self._window.hard_deadline_ms,
                    absolute_deadline_ns=self._window.absolute_ns, stage=self._active["stage"]["stage"])

    def _poison(self, reason, quarantine=False):
        self._failures += (reason,)
        self._phase = "QUARANTINED" if quarantine or self._phase == "CLEANING" else "FAILED"

    def _has_retained_live_obligations(self):
        # The stock process is not ours. Known/possible foreign ownership and
        # unclosed pen/display/Frida bindings remain ours to retain, not to kill.
        return ((self._pen is not None and self._cleanup_index < 6) or
                (self._display is not None and self._cleanup_index < 4) or
                ((self._launch is not None or self._foreign is not None) and self._cleanup_index < 3) or
                (self._active is not None and self._cleanup_index < 1))

    def apply(self, raw, now):
        cleanup_requested = False
        try:
            _require(self._phase not in ("CLEAN", "CLEANED_WITH_ERRORS", "QUARANTINED"), "terminal trace")
            event = load_canonical(raw)
            # This only classifies a rejected cleanup request for retention; it
            # confers no authority and does not bypass any envelope validation.
            cleanup_requested = type(event) is dict and event.get("kind") == "begin_cleanup"
            _keys(event, "authority schemaVersion contractSha256 runSessionId sequence previousEventSha256 "
                  "observedHostNs kind body")
            _same(event["authority"], EVENT_AUTHORITY)
            _same(event["schemaVersion"], SCHEMA_VERSION)
            _same(event["contractSha256"], self._contract_sha)
            _same(event["runSessionId"], self._plan["runSessionId"])
            _same(event["sequence"], self._sequence + 1)
            _same(event["previousEventSha256"], self._last_sha)
            _require(type(now) is HostInstant and now.clock_id == self._plan["hostClockId"], "trusted host clock required")
            observed = _decimal(event["observedHostNs"])
            _require(self._last_ns <= observed <= now.nanoseconds, "backward/future event time")
            deadline = (self._cleanup_deadline if self._phase == "CLEANING" else
                        self._window.absolute_ns if self._phase == "CAPTURING" else
                        _decimal(self._plan["absoluteRunDeadlineNs"]))
            # Cleanup may start after a stage expires, but does not extend its budget.
            if event["kind"] == "begin_cleanup":
                deadline = (self._window.absolute_ns if self._window is not None else
                            _decimal(self._plan["absoluteRunDeadlineNs"])) + CLEANUP_TIMEOUT_MS * 1_000_000
            _require(now.nanoseconds < deadline, "absolute deadline expired")
            _require(type(event["kind"]) is str and type(event["body"]) is dict, "typed event required")
            self._transition(event["kind"], event["body"], now)
            self._sequence += 1
            self._last_sha = hashlib.sha256(raw).hexdigest()
            self._last_ns = now.nanoseconds
            return self._phase
        except ContractError as error:
            if self._phase not in ("QUARANTINED", "CLEAN", "CLEANED_WITH_ERRORS"):
                self._poison(str(error), quarantine=cleanup_requested and self._has_retained_live_obligations())
            raise

    def _device_sample(self, body, required):
        _same(body["penBinding"], self._pen)
        sample = DeviceBoottime(_decimal(body["deviceBoottimeMs"]))
        _require(sample.milliseconds >= self._device_ms, "device BOOTTIME moved backward")
        remaining = remaining_device_ms(DeviceBoottime(_decimal(
            self._pen["absoluteDeviceBoottimeExpiryMs"])), sample)
        _require(remaining >= required, "insufficient pen lease remaining")
        self._device_ms = sample.milliseconds

    def _transition(self, kind, body, now):
        if kind == "failure":
            _keys(body, "reason evidenceSha256")
            _match(body["reason"], _TOKEN, "bounded failure reason required")
            _sha(body["evidenceSha256"])
            self._poison(body["reason"])
            return
        if kind == "begin_cleanup":
            _keys(body, "primaryFailure evidenceSha256")
            _sha(body["evidenceSha256"])
            _require(self._phase != "CLEANING", "cleanup cannot retry")
            _same(body["primaryFailure"], bool(self._failures))
            _require(self._failures or self._completed == 4, "incomplete run must fail before cleanup")
            if self._launch is not None and self._foreign is None:
                self._poison("uncertain causal task ownership; retain pen/display and require reviewed recovery", True)
                return
            self._cleanup_deadline = (self._window.absolute_ns if self._window else
                _decimal(self._plan["absoluteRunDeadlineNs"])) + CLEANUP_TIMEOUT_MS * 1_000_000
            self._phase = "CLEANING"
            return
        if kind == "cleanup_step":
            _require(self._phase == "CLEANING", "cleanup not started")
            self._cleanup(body)
            return
        _require(not self._failures, "failed run cannot resume or retry")
        if kind == "prechecked":
            _require(self._phase == "DORMANT", "precheck once")
            _keys(body, "serial documentTasks documentActivities stockProcess evidenceSha256 fixtures")
            _same(body["serial"], AUTHORIZED_SERIAL)
            # Full inventory must be empty, not merely a count on display 0.
            _same(body["documentTasks"], [])
            _same(body["documentActivities"], [])
            _same(body["fixtures"], self._plan["fixtures"])
            if body["stockProcess"] is not None:
                _process(body["stockProcess"])
            self._stock = body["stockProcess"]
            self._precheck_sha = _sha(body["evidenceSha256"])
            self._phase = "PRECHECKED"
        elif kind == "pen_acquired":
            _require(self._phase == "PRECHECKED", "pen acquire after absence proof only")
            _keys(body, "beforeAbsenceSha256 penBinding deviceBoottimeMs")
            _same(body["beforeAbsenceSha256"], self._precheck_sha)
            _pen(body["penBinding"], self._plan)
            if self._stock is not None:
                _same(body["penBinding"]["worker"]["incarnation"].split(":")[0],
                      self._stock["identity"]["incarnation"].split(":")[0])
                _require(all(body["penBinding"][role]["key"] != self._stock["identity"]["key"]
                             for role in ("peer", "worker", "guardian")), "pen/stock process alias")
            self._pen = body["penBinding"]
            self._device_sample(body, CLEANUP_TIMEOUT_MS)
            self._phase = "PEN_BLOCKED"
        elif kind == "display_ready":
            _require(self._phase == "PEN_BLOCKED", "display creation requires pen exclusion")
            _keys(body, "display evidenceSha256")
            _display(body["display"], self._plan)
            _sha(body["evidenceSha256"])
            self._display = body["display"]
            self._phase = "DISPLAY_READY"
        elif kind == "foreign_launch_recorded":
            _require(self._phase == "DISPLAY_READY", "launch once on ready display")
            _keys(body, "commandId component display beforeAbsenceSha256 commandSha256 fixtureSha256 "
                  "prelaunchAbsenceSha256 documentTasks documentActivities")
            _same(body["commandId"], "launch_foreign_document")
            _same(body["component"], COMPONENT)
            _same(body["display"], self._display)
            _same(body["beforeAbsenceSha256"], self._precheck_sha)
            _sha(body["prelaunchAbsenceSha256"])
            _same(body["documentTasks"], [])
            _same(body["documentActivities"], [])
            _same(body["fixtureSha256"], self._plan["fixtures"]["pdf"]["sha256"])
            _sha(body["commandSha256"])
            self._launch = body
            self._phase = "LAUNCH_UNPROVEN"
        elif kind == "foreign_attached":
            _require(self._phase == "LAUNCH_UNPROVEN", "causal launch required before attach")
            _keys(body, "foreign launchCommandSha256 causalLaunchProofSha256 hostAttachAckSha256 "
                  "documentTasks documentActivities displayZeroDocumentTasks displayZeroDocumentActivities "
                  "prelaunchAbsenceSha256")
            _same(body["launchCommandSha256"], self._launch["commandSha256"])
            _same(body["prelaunchAbsenceSha256"], self._launch["prelaunchAbsenceSha256"])
            _sha(body["causalLaunchProofSha256"])
            _sha(body["hostAttachAckSha256"])
            _foreign(body["foreign"], self._display)
            _same(body["foreign"]["process"]["identity"]["incarnation"].split(":")[0],
                  self._pen["worker"]["incarnation"].split(":")[0])
            _require(all(self._pen[role]["key"] != body["foreign"]["process"]["identity"]["key"]
                         for role in ("peer", "worker", "guardian")), "foreign/pen process alias")
            if self._stock is not None:
                _same(body["foreign"]["process"], self._stock)
            _same(body["documentTasks"], [body["foreign"]["identity"]])
            _same(body["documentActivities"], [body["foreign"]["activityToken"]])
            _same(body["displayZeroDocumentTasks"], [])
            _same(body["displayZeroDocumentActivities"], [])
            self._stock = body["foreign"]["process"]
            self._foreign = body["foreign"]
            self._phase = "ONE_NATIVE_TASK_BOUND"
        elif kind == "capture_started":
            _require(self._phase in ("ONE_NATIVE_TASK_BOUND", "STAGE_OBSERVED") and self._completed < 4,
                     "one capture per stage in order")
            _keys(body, "stage window runNonce manifestSha256 placementAckSha256 penBinding deviceBoottimeMs foreign")
            _same(body["stage"], self._plan["stages"][self._completed])
            _same(body["foreign"], self._foreign)
            window = HostDeadline.parse(body["window"])
            window.require_live(now)
            _require(window.clock_id == self._plan["hostClockId"] and window.issued_ns == now.nanoseconds and
                     window.absolute_ns <= _decimal(self._plan["absoluteRunDeadlineNs"]), "fresh bounded stage deadline")
            nonce = _sha(body["runNonce"])
            _require(nonce not in self._nonces, "per-stage nonce replay")
            _sha(body["manifestSha256"])
            _sha(body["placementAckSha256"])
            self._device_sample(body, window.hard_deadline_ms + CLEANUP_TIMEOUT_MS)
            self._window = window
            self._active = body
            self._nonces.add(nonce)
            self._phase = "CAPTURING"
        elif kind == "capture_completed":
            _require(self._phase == "CAPTURING", "capture completion without exact start")
            _keys(body, "stage runNonce manifestSha256 beforeSequence afterSequence beforeReceiptSha256 "
                  "afterPreviousReceiptSha256 afterReceiptSha256 beforeInvariantSha256 afterInvariantSha256 "
                  "beforeGraphSha256 afterGraphSha256 quiescenceSha256 retainedAuthoritySha256 "
                  "stageLedgerRecordSha256 durableCheckpointSha256 penBinding deviceBoottimeMs foreign")
            for key in ("stage", "runNonce", "manifestSha256", "foreign"):
                _same(body[key], self._active[key])
            _same(body["beforeSequence"], 1)
            _same(body["afterSequence"], 2)
            for key in body:
                if key.endswith("Sha256"):
                    _sha(body[key])
            _same(body["afterPreviousReceiptSha256"], body["beforeReceiptSha256"])
            _require(body["afterReceiptSha256"] != body["beforeReceiptSha256"], "receipt replay")
            _same(body["beforeInvariantSha256"], body["afterInvariantSha256"])
            _same(body["beforeGraphSha256"], body["afterGraphSha256"])
            if self._stable_graph is not None:
                _same(body["beforeGraphSha256"], self._stable_graph)
            self._device_sample(body, CLEANUP_TIMEOUT_MS)
            self._stable_graph = body["beforeGraphSha256"]
            self._completed += 1
            self._phase = "STAGE_OBSERVED"
        else:
            raise ContractError("unknown event")

    def _cleanup(self, body):
        _keys(body, "stepIndex stepId owner evidenceSha256 intentRecordSha256 completionRecordSha256 "
              "durableCheckpointSha256 attempt details")
        _require(self._cleanup_index < len(CLEANUP_STEPS), "cleanup complete")
        step, owner = CLEANUP_STEPS[self._cleanup_index]
        _same(body["stepIndex"], self._cleanup_index)
        _same(body["stepId"], step)
        _same(body["owner"], owner)
        _sha(body["evidenceSha256"])
        _same(body["attempt"], 1)
        for field in ("intentRecordSha256", "completionRecordSha256", "durableCheckpointSha256"):
            _sha(body[field])
        _require(body["intentRecordSha256"] != body["completionRecordSha256"], "cleanup intent/completion replay")
        details = body["details"]
        if step == "detach_seal_frida":
            _same(details, {"callbacksSealed": True, "unloaded": True, "detached": True,
                            "isolatedWorkersClosed": True})
        elif step == "restore_full":
            _same(details, {"foreign": self._foreign, "placement": "FULL",
                            "performed": self._foreign is not None})
        elif step == "destroy_foreign_task":
            _same(details, {"foreign": self._foreign, "display": self._display,
                            "exactTaskAbsent": True, "hostAcknowledgedAbsent": True,
                            "noMigrationToDisplayZero": True})
        elif step == "destroy_virtual_display":
            _same(details, {"display": self._display, "exactDisplayAbsent": True,
                            "hostSessionQuiescent": True, "noMigrationToDisplayZero": True})
        elif step == "prove_foreign_absence":
            _same(details, {"stockProcess": self._stock, "documentTasks": [], "documentActivities": [],
                            "foreignDisplayAbsent": True, "foreignSurfaceAbsent": True,
                            "foreignHelpersClosed": True})
        elif step == "finish_pen_lease":
            _same(details, {"penBinding": self._pen, "authenticatedReleased": self._pen is not None,
                            "sealedControlAndPhaseBeforeRelease": self._pen is not None,
                            "workerGuardianPeerClosed": True,
                            "independentDeviceReacquireProven": self._pen is not None})
        elif step == "ordinary_stock_reopen":
            _keys(details, "component displayId process fixtureSha256 ordinaryRouteAuthoritySha256")
            _same(details["component"], COMPONENT)
            _same(details["displayId"], 0)
            _process(details["process"])
            if self._stock is not None:
                _same(details["process"], self._stock)
            _same(details["fixtureSha256"], self._plan["fixtures"]["pdf"]["sha256"])
            _sha(details["ordinaryRouteAuthoritySha256"])
        elif step == "verify_unchanged_files":
            _same(details, self._plan["fixtures"])
        self._cleanup_index += 1
        if self._cleanup_index == len(CLEANUP_STEPS):
            self._phase = "CLEANED_WITH_ERRORS" if self._failures else "CLEAN"
