"""Typed S4 pen peer. Transport must own an authenticated, dedicated device broker.

This module never launches, signals, kills, or generically cleans up a pen process.
Its caller supplies absence-proof capabilities from the stage observer, not booleans.
Only broker CLOCK_BOOTTIME samples determine time remaining. A remote transport must
authenticate its broker executable/session and exact process handle before use;
untrusted shell text or host-clock estimates do not implement this protocol.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
import re
from typing import Protocol

CLOCK_DOMAIN = "android-boottime-v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"[1-9][0-9]{0,19}\Z")


class PeerError(RuntimeError):
    """Outcome is unknown; peer ownership must be retained for reboot recovery."""


def _hex(value: str) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ValueError("Expected an exact lowercase SHA-256/session value")
    return value


def _positive(value: str) -> int:
    if not _DECIMAL.fullmatch(value) or int(value) > (1 << 64) - 1:
        raise ValueError("Invalid unsigned protocol integer")
    return int(value)


@dataclass(frozen=True)
class StageSession:
    value: str

    def __post_init__(self) -> None:
        _hex(self.value)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    starttime: int

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 < self.pid <= 2147483647:
            raise ValueError("Invalid exact process PID")
        if type(self.starttime) is not int or not 0 < self.starttime < 1 << 64:
            raise ValueError("Invalid process starttime")


@dataclass(frozen=True)
class BeforeAbsenceProof:
    stage_session: StageSession
    sha256: str

    def __post_init__(self) -> None:
        _hex(self.sha256)


@dataclass(frozen=True)
class FinalAbsenceProof:
    stage_session: StageSession
    lease_token: str
    sha256: str

    def __post_init__(self) -> None:
        _hex(self.lease_token)
        _hex(self.sha256)


@dataclass(frozen=True)
class LeaseBinding:
    stage_session: StageSession
    token: str
    peer: ProcessIdentity
    worker: ProcessIdentity
    guardian: ProcessIdentity
    guardian_session: str
    deadline_boottime_ms: int
    device_clock_domain: str = CLOCK_DOMAIN


@dataclass(frozen=True)
class CaptureLease:
    binding: LeaseBinding
    sequence: int
    device_boottime_ms: int
    remaining_ms: int


@dataclass(frozen=True)
class ClosureProof:
    """Transport's exact peer-handle wait result, never a PID-only kill/probe."""
    peer: ProcessIdentity
    exit_code: int
    output_eof: bool
    trailing_output: bytes


class BrokerTransport(Protocol):
    peer_identity: ProcessIdentity

    def exchange(self, atomic_command: bytes) -> bytes:
        """Exactly one bounded broker record; partial/trailing output is an error."""
        ...

    def wait_exact_peer_closed(self) -> ClosureProof:
        """Wait without killing; broker already proved worker/guardian closure."""
        ...

    def retain_quarantine(self, atomic_command: bytes) -> None:
        """Retain this peer and every ownership handle, even if communication fails."""
        ...


class Lifecycle(Enum):
    NEW = auto()
    ACQUIRED = auto()
    CAPTURED = auto()
    FINISHING = auto()
    RELEASED = auto()
    QUARANTINED = auto()


_FIELDS = (
    "stage_session", "sequence", "token", "peer_pid", "peer_starttime",
    "worker_pid", "worker_starttime", "guardian_pid", "guardian_starttime",
    "guardian_session", "deviceClockDomain", "deadline_boottime_ms",
    "device_boottime_ms", "proof_sha256", "worker_closed", "guardian_closed",
)


class PenPeer:
    """No close/context-manager/destructor: generic cleanup has no ownership here."""

    def __init__(self, transport: BrokerTransport, stage_session: StageSession,
                 token: str, hold_ms: int) -> None:
        self.transport = transport
        self.stage_session = stage_session
        self.token = _hex(token)
        if type(hold_ms) is not int or not 0 < hold_ms <= 300000:
            raise ValueError("Invalid lease duration")
        if not isinstance(transport.peer_identity, ProcessIdentity):
            raise ValueError("Transport lacks authenticated peer identity")
        self._peer_identity = transport.peer_identity
        self.hold_ms = hold_ms
        self.state = Lifecycle.NEW
        self.binding: LeaseBinding | None = None
        self.sequence = 0
        self._last_device_ms = 0
        self.quarantine_reason: str | None = None

    def quarantine(self, reason: str) -> None:
        if self.state is Lifecycle.RELEASED:
            raise PeerError("Released peer cannot be repurposed")
        self.state = Lifecycle.QUARANTINED
        self.quarantine_reason = reason
        # A fixed wire reason avoids admitting caller text as a protocol command.
        try:
            self.transport.retain_quarantine(
                f"QUARANTINE stage_session={self.stage_session.value}\n".encode("ascii"))
        except Exception:
            pass  # Ownership/reference intentionally retained, never cleanup.

    def _fail(self, reason: str) -> None:
        self.quarantine(reason)
        raise PeerError(reason)

    def _receipt(self, command: bytes, kind: str, proof_hash: str,
                 closing: bool = False) -> CaptureLease:
        try:
            if self.transport.peer_identity != self._peer_identity:
                raise ValueError("Authenticated transport peer identity drifted")
            raw = self.transport.exchange(command)
            if not isinstance(raw, bytes) or len(raw) > 2048 or not raw.endswith(b"\n"):
                raise ValueError("Unavailable/partial broker status")
            if raw.count(b"\n") != 1 or b"\r" in raw or b"\x00" in raw:
                raise ValueError("Trailing/replayed broker status")
            words = raw[:-1].decode("ascii").split(" ")
            if words[:2] != ["PEN_PAGE_PEER", kind] or len(words) != len(_FIELDS) + 2:
                raise ValueError("Unexpected broker status")
            fields = {}
            for key, word in zip(_FIELDS, words[2:]):
                if not word.startswith(key + "="):
                    raise ValueError("Noncanonical broker status")
                fields[key] = word[len(key) + 1:]
            seq = _positive(fields["sequence"])
            now = _positive(fields["device_boottime_ms"])
            deadline = _positive(fields["deadline_boottime_ms"])
            if fields["stage_session"] != self.stage_session.value or fields["token"] != self.token:
                raise ValueError("Wrong session/token")
            if fields["deviceClockDomain"] != CLOCK_DOMAIN or seq != self.sequence + 1:
                raise ValueError("Cross-clock/replayed receipt")
            peer = ProcessIdentity(_positive(fields["peer_pid"]), _positive(fields["peer_starttime"]))
            worker = ProcessIdentity(_positive(fields["worker_pid"]), _positive(fields["worker_starttime"]))
            guardian = ProcessIdentity(_positive(fields["guardian_pid"]), _positive(fields["guardian_starttime"]))
            if (len({peer.pid, worker.pid, guardian.pid}) != 3 or peer != self._peer_identity
                    or self.transport.peer_identity != self._peer_identity):
                raise ValueError("Unbound/aliased process identities")
            binding = LeaseBinding(self.stage_session, self.token, peer, worker, guardian,
                                   _hex(fields["guardian_session"]), deadline)
            if self.binding is not None and binding != self.binding:
                raise ValueError("Lease binding changed")
            if fields["proof_sha256"] != proof_hash or now < self._last_device_ms:
                raise ValueError("Wrong proof or backwards device clock")
            if closing:
                if fields["worker_closed"] != "true" or fields["guardian_closed"] != "true":
                    raise ValueError("Release lacks process closure")
                if now > deadline + 1000:
                    raise ValueError("Release beyond device protocol grace")
            elif (fields["worker_closed"] != "false" or fields["guardian_closed"] != "false"
                  or now >= deadline or deadline - now > self.hold_ms):
                raise ValueError("Expired/incoherent device lease")
            self.binding = binding
            self.sequence = seq
            self._last_device_ms = now
            return CaptureLease(binding, seq, now, max(0, deadline - now))
        except Exception as error:
            self._fail(str(error))
        raise AssertionError("unreachable")

    def acquire(self, before_absence_proof: BeforeAbsenceProof) -> CaptureLease:
        if (self.state is not Lifecycle.NEW or
                not isinstance(before_absence_proof, BeforeAbsenceProof) or
                before_absence_proof.stage_session != self.stage_session):
            self._fail("Invalid/replayed before-absence proof")
        proof = before_absence_proof.sha256
        result = self._receipt(
            f"ACQUIRE stage_session={self.stage_session.value} before_absence_proof={proof}\n".encode(),
            "ACQUIRED", proof)
        self.state = Lifecycle.ACQUIRED
        return result

    def capture_lease(self, stage_session: StageSession) -> CaptureLease:
        if self.state not in (Lifecycle.ACQUIRED, Lifecycle.CAPTURED) or stage_session != self.stage_session:
            self._fail("Invalid capture lifecycle/session")
        result = self._receipt(
            f"CAPTURE stage_session={stage_session.value} sequence={self.sequence + 1}\n".encode(),
            "CAPTURED", "0" * 64)
        self.state = Lifecycle.CAPTURED
        return result

    def finish(self, final_absence_proof: FinalAbsenceProof) -> ClosureProof:
        if (self.state is not Lifecycle.CAPTURED or
                not isinstance(final_absence_proof, FinalAbsenceProof) or
                final_absence_proof.stage_session != self.stage_session or
                final_absence_proof.lease_token != self.token):
            self._fail("Invalid/replayed final-absence proof")
        self.state = Lifecycle.FINISHING
        proof = final_absence_proof.sha256
        self._receipt(
            (f"FINISH stage_session={self.stage_session.value} sequence={self.sequence + 1} "
             f"final_absence_proof={proof}\n").encode(), "RELEASED", proof, closing=True)
        try:
            if self.binding is None or self.binding.peer != self._peer_identity:
                raise ValueError("Authenticated peer binding unavailable")
            expected_peer = self.binding.peer
            if self.transport.peer_identity != expected_peer:
                raise ValueError("Transport peer changed before closure wait")
            closure = self.transport.wait_exact_peer_closed()
            if (not isinstance(closure, ClosureProof) or closure.peer != expected_peer
                    or self.transport.peer_identity != expected_peer
                    or type(closure.exit_code) is not int or closure.exit_code != 0
                    or closure.output_eof is not True or closure.trailing_output != b""):
                raise ValueError("Exact peer exit/EOF not proven")
        except Exception as error:
            self._fail(str(error))
        self.state = Lifecycle.RELEASED
        return closure
