"""Complete platform-capture backend over one frozen PrivateADB service.

The device-side collector is outside this host module's authority.  It must
emit one normalized, binary-framed stdout wire for the exact service literal
owned by :mod:`native_page_private_adb`.  This module never accepts command
text, never runs multiple shell services, and never attempts to normalize
firmware-dependent raw ``dumpsys`` text on the host.

Collector stdout wire (all integer lengths are unsigned big-endian)::

    b"NPPCAP01"
    0x01 | u32 length | sha256(payload) | ActivityManager payload
    0x02 | u32 length | sha256(payload) | WindowManager payload
    0x03 | u32 length | sha256(payload) | normalized process-facts payload
    0x04 | u32 length | sha256(payload) | DisplayManager payload
    0x00 | sha256(all preceding bytes)

Members are mandatory, unique, and ordered.  Any missing, reordered,
duplicated, oversized, digest-mismatched, or trailing byte seals the backend.
The process-facts member is converted into the request-specific process receipt
consumed by ``native_page_visual_platform_authority``; that receipt binds the
three other exact members, the host monotonic capture bracket, and the caller's
already-validated request scope.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
import struct
import threading
from typing import Callable
import uuid

import native_page_host_authority as host
import native_page_private_adb as private
import native_page_visual_platform_authority as platform


AUTHORITY = "rtl-reader-native-page-private-adb-platform-backend-v1"
PROCESS_FACTS_AUTHORITY = "rtl-reader-native-page-private-adb-process-facts-v1"
PROCESS_FACTS_HEADER = "NATIVE PAGE PROCESS FACTS (private-adb-platform-v1)"
COLLECTOR_MAGIC = b"NPPCAP01"
COLLECTOR_TERMINAL_TAG = 0
COLLECTOR_MEMBERS = (
    (1, "activity", platform.MAX_ACTIVITY_BYTES),
    (2, "window", platform.MAX_WINDOW_BYTES),
    (3, "process", platform.MAX_PROCESS_BYTES),
    (4, "display", platform.MAX_DISPLAY_BYTES),
)
MEMBER_HEADER = struct.Struct(">BI32s")
COLLECTOR_TERMINAL_BYTES = 1 + hashlib.sha256().digest_size
MAX_COLLECTOR_WIRE_BYTES = private.MAX_PLATFORM_CAPTURE_BYTES
MAX_AUTHORITY_BYTES = 262_144
MAX_CAPTURE_IDS = 1_000_000
MAX_LINE_BYTES = 65_536

HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
SERIAL_RE = private.SERIAL_RE
LABEL_RE = platform.LABEL
PACKAGE_RE = platform.PACKAGE


class PrivateAdbPlatformBackendError(RuntimeError):
    """The complete-capture backend rejected authority or evidence."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PrivateAdbPlatformBackendError(message)


def _sha(raw: bytes) -> str:
    _need(type(raw) is bytes, "digest input is not exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        raw = json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise PrivateAdbPlatformBackendError(
            "backend authority is not canonical JSON") from error
    _need(0 < len(raw) <= MAX_AUTHORITY_BYTES,
          "backend authority is absent or oversized")
    return raw


def _canonical_uuid(value: object, label: str) -> str:
    _need(type(value) is str, label + " is not text")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as error:
        raise PrivateAdbPlatformBackendError(label + " is not a UUID") from error
    _need(value == canonical, label + " is not a canonical lowercase UUID")
    return value


def _decimal(value: str, label: str, minimum: int, maximum: int) -> int:
    _need(re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
          label + " is not canonical decimal")
    result = int(value, 10)
    _need(minimum <= result <= maximum, label + " is outside bounds")
    return result


def _lines(raw: bytes, *, label: str, maximum: int) -> list[str]:
    _need(type(raw) is bytes and 0 < len(raw) <= maximum,
          label + " is absent or oversized")
    _need(b"\x00" not in raw and b"\r" not in raw and raw.endswith(b"\n"),
          label + " is not canonical LF-terminated text")
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeError as error:
        raise PrivateAdbPlatformBackendError(label + " is not ASCII") from error
    _need(all((ord(character) >= 0x20 or character == "\n") and
              ord(character) != 0x7f for character in text),
          label + " contains a control character")
    result = text[:-1].split("\n")
    _need(all(len(line.encode("ascii")) <= MAX_LINE_BYTES for line in result),
          label + " contains an oversized line")
    return result


def decode_collector_wire(raw: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Decode the exact four-member collector wire, with no recovery path."""
    _need(type(raw) is bytes and
          len(COLLECTOR_MAGIC) + COLLECTOR_TERMINAL_BYTES < len(raw) <=
          MAX_COLLECTOR_WIRE_BYTES,
          "collector wire is absent or outside the total bound")
    _need(raw.startswith(COLLECTOR_MAGIC), "collector wire magic differs")
    offset = len(COLLECTOR_MAGIC)
    members: list[bytes] = []
    for expected_tag, label, maximum in COLLECTOR_MEMBERS:
        _need(len(raw) - offset >= MEMBER_HEADER.size,
              label + " member header is truncated")
        tag, size, digest = MEMBER_HEADER.unpack_from(raw, offset)
        _need(tag == expected_tag,
              label + " member is absent, duplicated, or reordered")
        offset += MEMBER_HEADER.size
        _need(0 < size <= maximum,
              label + " member is empty or oversized")
        _need(size <= len(raw) - offset,
              label + " member payload is truncated")
        payload = raw[offset:offset + size]
        _need(hashlib.sha256(payload).digest() == digest,
              label + " member digest differs")
        members.append(payload)
        offset += size
    _need(len(raw) - offset == COLLECTOR_TERMINAL_BYTES,
          "collector wire has a missing or trailing terminal")
    _need(raw[offset] == COLLECTOR_TERMINAL_TAG,
          "collector terminal tag differs")
    _need(hashlib.sha256(raw[:offset]).digest() == raw[offset + 1:],
          "collector aggregate digest differs")
    return tuple(members)  # type: ignore[return-value]


@dataclass(frozen=True)
class _ProcessFacts:
    serial: str
    boot_id: str
    package: host.PackageRecord
    processes: tuple[host.ProcessIdentity, ...]


def _parse_process_facts(raw: bytes) -> _ProcessFacts:
    lines = _lines(raw, label="process facts", maximum=platform.MAX_PROCESS_BYTES)
    _need(len(lines) >= 7 and lines[0] == PROCESS_FACTS_HEADER,
          "process facts header differs or is truncated")
    _need(lines[1] == "authority=" + PROCESS_FACTS_AUTHORITY,
          "process facts authority differs")
    serial = lines[2].removeprefix("serial=")
    _need(lines[2] == "serial=" + serial and SERIAL_RE.fullmatch(serial) is not None,
          "process facts serial differs")
    boot_id = lines[3].removeprefix("bootId=")
    _need(lines[3] == "bootId=" + boot_id,
          "process facts boot field differs")
    _canonical_uuid(boot_id, "process facts boot ID")
    expected_policy = (
        "policy readOnly=true mutationCount=0 userDocumentSelectionCount=0 "
        "scopePackages=" + ",".join(platform.RELEVANT_PACKAGES)
    )
    _need(lines[4] == expected_policy,
          "process facts are mutable, incomplete, or out of scope")
    package_match = re.fullmatch(
        r"package name=([^ ]+) installedApkSha256=([^ ]+) "
        r"reviewedUnsignedApkSha256=([^ ]+) dexSha256=([^ ]+) "
        r"signerCertSha256=([^ ]+) versionCode=([^ ]+) versionName=([^ ]+)",
        lines[5],
    )
    _need(package_match is not None, "process facts package format differs")
    package_values = package_match.groups()
    package = host.PackageRecord(
        package_values[0], package_values[1], package_values[2],
        package_values[3], package_values[4],
        _decimal(package_values[5], "package version code", 1, 2_147_483_647),
        package_values[6],
    )
    _need(package == host.PINNED_PACKAGE,
          "process facts host package authority differs")
    end = re.fullmatch(r"END processCount=([^ ]+) packageCount=([^ ]+)",
                       lines[-1])
    _need(end is not None, "process facts terminal differs")
    process_count = _decimal(end.group(1), "process count", 1,
                             platform.MAX_ROWS)
    _need(_decimal(end.group(2), "package count", 1, 1) == 1,
          "process facts package count differs")
    process_lines = lines[6:-1]
    _need(len(process_lines) == process_count,
          "process facts count differs")
    processes: list[host.ProcessIdentity] = []
    for line in process_lines:
        match = re.fullmatch(
            r"process pid=([^ ]+) startTicks=([^ ]+) uid=([^ ]+) package=([^ ]+)",
            line,
        )
        _need(match is not None, "process facts row format differs")
        pid, start_ticks, uid, package_name = match.groups()
        _need(package_name in platform.RELEVANT_PACKAGES,
              "process facts row escaped package scope")
        processes.append(host.ProcessIdentity(
            _decimal(pid, "process PID", 1, platform.MAX_PID),
            _decimal(start_ticks, "process start ticks", 1,
                     platform.MAX_START_TICKS),
            _decimal(uid, "process UID", 0, 2_147_483_647),
            package_name,
        ))
    _need(processes == sorted(processes, key=lambda item: item.pid),
          "process facts are not in canonical PID order")
    _need(len({item.pid for item in processes}) == len(processes) and
          len({item.package for item in processes}) == len(processes),
          "process facts contain duplicate identities")
    return _ProcessFacts(serial, boot_id, package, tuple(processes))


def _receipt(*, request: platform.CaptureRequest,
             capture_id: str,
             transport: private.PlatformCaptureTransportResult,
             activity: bytes, window: bytes, display: bytes,
             facts: _ProcessFacts) -> bytes:
    display_id = "none" if request.display_id is None else str(request.display_id)
    foreign_sha = ("none" if request.foreign_sha256 is None else
                   request.foreign_sha256)
    package = facts.package
    lines = [
        "NATIVE PAGE PROCESS INVENTORY (visual-platform-v1)",
        f"capture authority={platform.BACKEND_CAPTURE_AUTHORITY} "
        f"captureId={capture_id} label={request.label} "
        f"serial={request.serial} bootId={request.boot_id} "
        f"startedNs={transport.started_ns} capturedNs={transport.captured_ns} "
        f"finishedNs={transport.finished_ns}",
        f"scope displayId={display_id} foreignSha256={foreign_sha}",
        f"bind activityBytes={len(activity)} activitySha256={_sha(activity)} "
        f"windowBytes={len(window)} windowSha256={_sha(window)} "
        f"displayBytes={len(display)} displaySha256={_sha(display)}",
        "policy complete=true readOnly=true mutationCount=0 "
        "userDocumentSelectionCount=0 scopePackages=" +
        ",".join(platform.RELEVANT_PACKAGES),
        f"package name={package.package} "
        f"installedApkSha256={package.apk_sha256} "
        f"reviewedUnsignedApkSha256={package.reviewed_unsigned_apk_sha256} "
        f"dexSha256={package.dex_sha256} "
        f"signerCertSha256={package.signer_cert_sha256} "
        f"versionCode={package.version_code} versionName={package.version_name}",
    ]
    lines.extend(
        f"process pid={item.pid} startTicks={item.start_ticks} uid={item.uid} "
        f"package={item.package}"
        for item in facts.processes
    )
    lines.append(f"END processCount={len(facts.processes)} packageCount=1")
    raw = ("\n".join(lines) + "\n").encode("ascii")
    _need(len(raw) <= platform.MAX_PROCESS_BYTES,
          "request-specific process receipt is oversized")
    return raw


class PrivateAdbPlatformBackend:
    """Retained complete-capture backend accepted by VisualPlatformAuthority."""

    def __init__(self, transport: private.PrivateAdbServer, *, boot_id: str,
                 generation: int,
                 capture_id_factory: Callable[[], str] | None = None):
        _need(type(transport) is private.PrivateAdbServer,
              "backend requires the exact reviewed PrivateAdbServer")
        _canonical_uuid(boot_id, "backend boot ID")
        _need(type(generation) is int and generation > 0,
              "backend generation is invalid")
        self._transport = transport
        self._boot_id = boot_id
        self._generation = generation
        self._capture_id_factory = (
            capture_id_factory if capture_id_factory is not None else
            lambda: str(uuid.uuid4())
        )
        _need(callable(self._capture_id_factory),
              "capture ID factory is not callable")
        self._mutex = threading.Lock()
        self._failed: str | None = None
        self._capture_ids: set[str] = set()
        self._last_clock_ns = -1
        self._transport_identity = transport.platform_transport_identity()
        _need(self._transport_identity.authority ==
              private.PLATFORM_CAPTURE_TRANSPORT_AUTHORITY and
              self._transport_identity.serial == transport.serial and
              self._transport_identity.service_sha256 ==
              private.PLATFORM_CAPTURE_SERVICE_SHA256 and
              self._transport_identity.read_only is True and
              self._transport_identity.static_service is True and
              self._transport_identity.explicit_serial is True and
              self._transport_identity.retained_server is True and
              self._transport_identity.ambient_discovery is False,
              "transport lacks exact static retained authority")
        self._canonical = _canonical_json({
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "transport": asdict(self._transport_identity),
            "collectorService": private.PLATFORM_CAPTURE_SERVICE,
            "collectorServiceSha256": private.PLATFORM_CAPTURE_SERVICE_SHA256,
            "collectorWireMagicHex": COLLECTOR_MAGIC.hex(),
            "collectorMemberOrder": [item[1] for item in COLLECTOR_MEMBERS],
            "collectorMemberMaximumBytes": {
                item[1]: item[2] for item in COLLECTOR_MEMBERS
            },
            "collectorWireMaximumBytes": MAX_COLLECTOR_WIRE_BYTES,
            "processFactsAuthority": PROCESS_FACTS_AUTHORITY,
            "serial": self._transport_identity.serial,
            "bootId": boot_id,
            "generation": generation,
            "readOnly": True,
            "completeCapture": True,
            "ambientDiscovery": False,
            "userDocumentSelection": False,
        })
        self._identity = platform.BackendIdentity(
            AUTHORITY, _sha(self._canonical), self._transport_identity.serial,
            boot_id, generation, True, True, False,
        )
        self.verify()

    def _clock(self) -> int:
        value = self._transport.now_ns()
        _need(type(value) is int and 0 <= value <= 2**63 - 1,
              "transport clock is not canonical nanoseconds")
        _need(value >= self._last_clock_ns,
              "transport clock moved backwards")
        self._last_clock_ns = value
        return value

    def _verify_locked(self) -> None:
        _need(self._failed is None, "platform backend is sealed")
        current = self._transport.platform_transport_identity()
        _need(current == self._transport_identity,
              "retained transport identity drifted")

    def verify(self) -> None:
        _need(self._mutex.acquire(blocking=False),
              "platform backend is concurrent or reentrant")
        try:
            self._verify_locked()
        finally:
            self._mutex.release()

    def canonical_bytes(self) -> bytes:
        self.verify()
        return self._canonical

    def identity(self) -> platform.BackendIdentity:
        self.verify()
        return self._identity

    def now_ns(self) -> int:
        _need(self._mutex.acquire(blocking=False),
              "platform backend is concurrent or reentrant")
        try:
            self._verify_locked()
            return self._clock()
        finally:
            self._mutex.release()

    def _request(self, request: platform.CaptureRequest) -> None:
        _need(type(request) is platform.CaptureRequest,
              "capture request is not exact typed authority")
        _need(type(request.label) is str and
              LABEL_RE.fullmatch(request.label) is not None and
              type(request.serial) is str and
              SERIAL_RE.fullmatch(request.serial) is not None and
              request.serial == self._identity.serial and
              type(request.boot_id) is str and
              request.boot_id == self._boot_id and
              (request.display_id is None or
               (type(request.display_id) is int and
                1 <= request.display_id <= platform.MAX_DISPLAY_ID)) and
              (request.foreign_sha256 is None or
               (type(request.foreign_sha256) is str and
                HEX_RE.fullmatch(request.foreign_sha256) is not None and
                type(request.display_id) is int)),
              "capture request escaped serial/boot/scope authority")

    def capture_complete(self, request: platform.CaptureRequest,
                         deadline_ns: int) -> platform.RawPlatformBundle:
        _need(self._mutex.acquire(blocking=False),
              "platform backend capture is concurrent or reentrant")
        try:
            return self._capture_locked(request, deadline_ns)
        finally:
            self._mutex.release()

    def _capture_locked(self, request: platform.CaptureRequest,
                        deadline_ns: int) -> platform.RawPlatformBundle:
        try:
            self._verify_locked()
            self._request(request)
            before = self._clock()
            _need(type(deadline_ns) is int and
                  before < deadline_ns <= before + platform.MAX_CAPTURE_NS,
                  "capture deadline is expired or outside authority")
            result = self._transport.capture_platform_wire(
                deadline_ns / 1_000_000_000)
            after = self._clock()
            _need(type(result) is private.PlatformCaptureTransportResult and
                  result.transport == self._transport_identity and
                  type(result.stdout) is bytes and result.stdout and
                  result.stderr == b"" and result.exit_code == 0 and
                  result.eof is True and
                  type(result.started_ns) is int and
                  type(result.captured_ns) is int and
                  type(result.finished_ns) is int and
                  before <= result.started_ns <= result.captured_ns <=
                  result.finished_ns <= after < deadline_ns,
                  "transport result lacks a complete trusted capture bracket")
            activity, window, process_raw, display = decode_collector_wire(
                result.stdout)
            facts = _parse_process_facts(process_raw)
            _need(facts.serial == request.serial and
                  facts.boot_id == request.boot_id,
                  "collector facts borrowed another serial or boot")
            capture_id = _canonical_uuid(
                self._capture_id_factory(), "capture ID")
            _need(capture_id not in self._capture_ids and
                  len(self._capture_ids) < MAX_CAPTURE_IDS,
                  "capture ID was replayed or retention bound was exceeded")
            receipt = _receipt(
                request=request, capture_id=capture_id, transport=result,
                activity=activity, window=window, display=display, facts=facts,
            )
            self._verify_locked()
            self._capture_ids.add(capture_id)
            return platform.RawPlatformBundle(
                activity, window, receipt, display)
        except BaseException as error:
            self._failed = str(error)
            if isinstance(error, PrivateAdbPlatformBackendError):
                raise
            raise PrivateAdbPlatformBackendError(
                "complete platform capture failed closed") from error


__all__ = [
    "AUTHORITY", "PROCESS_FACTS_AUTHORITY", "PROCESS_FACTS_HEADER",
    "COLLECTOR_MAGIC", "COLLECTOR_MEMBERS", "MAX_COLLECTOR_WIRE_BYTES",
    "PrivateAdbPlatformBackendError", "PrivateAdbPlatformBackend",
    "decode_collector_wire",
]
