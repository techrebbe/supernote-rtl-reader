"""Fail-closed, append-only cleanup authority; this module issues no OS commands.

Storage is deliberately injected. A production adapter MUST provide an exclusive
cross-process lease, exclusive temporary creation, atomic non-overwriting rename
within one directory, durable file fsync, and durable directory fsync. Unsupported
durability/locking must raise, never be reported as successful. No platform's
rename, close, command return code, or process exit is assumed to prove cleanup.

Published records are immutable canonical JSON, individually SHA-256 linked.
Unpublished .pending-* files are retained as non-authoritative crash remnants;
recovery neither executes nor deletes them. Recovery validates the entire chain
and synchronizes the surviving directory before granting any mutation authority.
It requires a caller-held trusted checkpoint outside that mutable directory.
The checkpoint is a minimum anchored prefix, not a truncation target: any valid
surviving suffix is replayed because mutation may precede checkpoint delivery.
The caller must retain its latest received checkpoint; an unkeyed hash chain
cannot invent external authenticity or detect rollback beyond a stale anchor.
An observer is a separate, trusted read-only adapter: its evidence must attest to
the exact target incarnation, never merely a PID, display number, or path.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import hashlib
import json
import re
import secrets
from typing import Callable, ContextManager, Protocol


ZERO_HASH = "0" * 64
MAX_RECORD_BYTES = 128 * 1024
MAX_RECORDS = 10000
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_OWNER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}\Z")
_RECORD = re.compile(r"([0-9]{20})\.json\Z")
_PENDING = re.compile(r"\.pending-[0-9a-f]{32}\Z")


class LedgerError(RuntimeError):
    pass


class AuthorityError(LedgerError):
    pass


class CorruptLedger(LedgerError):
    pass


class PersistenceError(LedgerError):
    def __init__(self, primary: Exception, cleanup: Exception | None = None):
        super().__init__(f"record publication uncertain: {primary}")
        self.primary = primary
        self.cleanup = cleanup


class DurableStore(Protocol):
    def exclusive(self) -> ContextManager[None]: ...
    def names(self) -> list[str]: ...
    def read(self, name: str) -> bytes: ...
    def create(self, name: str) -> object: ...
    def write(self, handle: object, payload: bytes) -> int: ...
    def fsync_file(self, handle: object) -> None: ...
    def close(self, handle: object) -> None: ...
    def rename_no_replace(self, source: str, destination: str) -> None: ...
    def fsync_directory(self) -> None: ...


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive) or value > 2**63 - 1:
        raise AuthorityError("expected a bounded exact integer")
    return value


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AuthorityError("invalid exact identity token")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise AuthorityError("invalid lowercase SHA-256 authority")
    return value


def _owner(value: object) -> str:
    if type(value) is not str or _OWNER.fullmatch(value) is None:
        raise AuthorityError("invalid cleanup owner")
    return value


def _keys(value: object, names: set[str]) -> dict:
    if type(value) is not dict or set(value) != names:
        raise AuthorityError("record topology differs from its exact schema")
    return value


def canonical_json(value: object) -> bytes:
    """One ASCII JSON value, sorted keys, no NaN, and exactly one terminal LF."""
    def exact(item):
        if item is None or type(item) in (str, bool):
            return
        if type(item) is int:
            _integer(item)
            return
        if type(item) is list:
            for child in item:
                exact(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                exact(child)
            return
        raise AuthorityError("value is not a strict JSON authority type")
    exact(value)
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorruptLedger("duplicate JSON key")
        result[key] = value
    return result


def decode_record(payload: bytes) -> dict:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_RECORD_BYTES:
        raise CorruptLedger("record size/type is invalid")
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(
                               CorruptLedger("non-finite JSON number")))
        if canonical_json(value) != payload:
            raise CorruptLedger("record is not canonical JSON/LF")
        _keys(value, {"version", "sequence", "previous_hash", "event", "data",
                      "remaining", "hash"})
        if type(value["version"]) is not int or value["version"] != 1:
            raise CorruptLedger("unsupported record version")
        _integer(value["sequence"])
        _digest(value["previous_hash"])
        expected = _digest(value["hash"])
        unsigned = {key: item for key, item in value.items() if key != "hash"}
        if hashlib.sha256(canonical_json(unsigned)).hexdigest() != expected:
            raise CorruptLedger("record hash differs")
        if type(value["remaining"]) is not list or any(
                type(item) is not str for item in value["remaining"]):
            raise CorruptLedger("remaining obligations are not an exact list")
        return value
    except (UnicodeError, ValueError, TypeError, AuthorityError) as error:
        raise CorruptLedger(str(error)) from error


@dataclass(frozen=True)
class ResourceIdentity:
    kind: str
    namespace: str
    key: str
    incarnation: str

    def __post_init__(self):
        if type(self.kind) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,31}", self.kind) is None:
            raise AuthorityError("invalid resource kind")
        for value in (self.namespace, self.key, self.incarnation):
            _token(value)
        # A PID is never identity by itself: bind boot UUID and kernel start ticks.
        if self.kind == "process" and (
                re.fullmatch(r"[1-9][0-9]*", self.key) is None
                or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}:[1-9][0-9]*",
                                self.incarnation) is None):
            raise AuthorityError("process identity requires PID plus boot/start incarnation")

    def wire(self) -> dict:
        return dict(kind=self.kind, namespace=self.namespace, key=self.key,
                    incarnation=self.incarnation)

    @classmethod
    def parse(cls, value: object) -> ResourceIdentity:
        return cls(**_keys(value, {"kind", "namespace", "key", "incarnation"}))

    @property
    def resource_id(self) -> str:
        return hashlib.sha256(canonical_json(self.wire())).hexdigest()

    @property
    def slot(self) -> tuple[str, str, str]:
        return self.kind, self.namespace, self.key


@dataclass(frozen=True)
class Observation:
    target: ResourceIdentity
    actual: ResourceIdentity | None
    status: str
    conclusive: bool
    evidence_sha256: str
    state_sha256: str | None = None

    def __post_init__(self):
        if type(self.target) is not ResourceIdentity or (
                self.actual is not None and type(self.actual) is not ResourceIdentity):
            raise AuthorityError("observation identity is not exact")
        if self.status not in ("present", "absent", "restored", "unknown") or type(
                self.status) is not str or type(self.conclusive) is not bool:
            raise AuthorityError("observation status/certainty is not exact")
        _digest(self.evidence_sha256)
        if self.state_sha256 is not None:
            _digest(self.state_sha256)
        if self.status == "absent" and self.actual is not None:
            raise AuthorityError("absence observation contradicts an actual identity")
        if self.status in ("present", "restored") and self.actual is None:
            raise AuthorityError("present observation lacks an actual identity")
        if self.status == "unknown" and self.conclusive:
            raise AuthorityError("unknown observation cannot be conclusive")
        if self.status == "restored" and self.state_sha256 is None:
            raise AuthorityError("restoration observation lacks exact state authority")

    def wire(self) -> dict:
        return dict(target=self.target.wire(), actual=None if self.actual is None else self.actual.wire(),
                    status=self.status, conclusive=self.conclusive,
                    evidence_sha256=self.evidence_sha256, state_sha256=self.state_sha256)

    @classmethod
    def parse(cls, value: object) -> Observation:
        data = _keys(value, {"target", "actual", "status", "conclusive", "evidence_sha256", "state_sha256"})
        return cls(ResourceIdentity.parse(data["target"]),
                   None if data["actual"] is None else ResourceIdentity.parse(data["actual"]),
                   data["status"], data["conclusive"], data["evidence_sha256"], data["state_sha256"])


@dataclass(frozen=True)
class CleanupAuthorization:
    identity: ResourceIdentity
    owner: str
    intent_id: str
    intent_record_sha256: str
    attempt: int
    deadline_ns: int


@dataclass(frozen=True)
class RecoveryCheckpoint:
    ledger_id: str
    sequence: int
    record_sha256: str

    def __post_init__(self):
        if type(self.ledger_id) is not str or re.fullmatch(r"[0-9a-f]{32}", self.ledger_id) is None:
            raise AuthorityError("invalid externally held ledger identity")
        _integer(self.sequence)
        _digest(self.record_sha256)


def _remaining(state: dict) -> list[str]:
    return sorted(key for key, value in state["resources"].items() if not value["complete"])


def _satisfies(resource: dict, observation: Observation) -> bool:
    identity = ResourceIdentity.parse(resource["identity"])
    if observation.target != identity or not observation.conclusive:
        return False
    if resource["postcondition"] == "absent":
        return observation.status == "absent" and observation.actual is None
    return (observation.status == "restored" and observation.actual == identity
            and observation.state_sha256 == resource["baseline_sha256"])


def _apply(state: dict | None, event: object, data: object, record_sha256: str = ZERO_HASH) -> dict:
    if type(event) is not str:
        raise AuthorityError("event type is not exact")
    if state is None:
        value = _keys(data, {"ledger_id", "clock_id"})
        if event != "opened" or type(value["ledger_id"]) is not str or re.fullmatch(
                r"[0-9a-f]{32}", value["ledger_id"]) is None:
            raise AuthorityError("chain must begin with one exact ledger identity")
        return dict(ledger_id=value["ledger_id"], clock_id=_token(value["clock_id"]),
                    resources={}, intent_ids=[], primary_errors=[], cleanup_errors=[], finalized=False)
    result = copy.deepcopy(state)
    if result["finalized"]:
        raise AuthorityError("finalized ledger is immutable")
    if event == "registered":
        value = _keys(data, {"identity", "owner", "postcondition", "baseline_sha256"})
        identity = ResourceIdentity.parse(value["identity"])
        _owner(value["owner"])
        if type(value["postcondition"]) is not str or value["postcondition"] not in ("absent", "restored"):
            raise AuthorityError("unknown cleanup postcondition")
        if value["postcondition"] == "restored":
            _digest(value["baseline_sha256"])
        elif value["baseline_sha256"] is not None:
            raise AuthorityError("absence cleanup cannot declare restoration state")
        if any(ResourceIdentity.parse(item["identity"]).slot == identity.slot
               for item in result["resources"].values()):
            raise AuthorityError("resource slot already has a cleanup owner")
        result["resources"][identity.resource_id] = dict(value, attempt=0, complete=False,
                                                       intent_id=None, pending_observation=None)
    elif event == "primary_error":
        value = _keys(data, {"message"})
        _error_message(value["message"])
        result["primary_errors"].append(value["message"])
    elif event == "finalized":
        value = _keys(data, {"result"})
        expected = "cleaned_with_errors" if result["primary_errors"] or result["cleanup_errors"] else "cleaned"
        if _remaining(result) or value["result"] != expected:
            raise AuthorityError("finalization lacks all exact observed postconditions")
        result["finalized"] = True
    else:
        schemas = {
            "cleanup_intent": {"resource", "owner", "intent_id", "attempt", "deadline_ns", "authorized_at_ns"},
            "cleanup_observed": {"resource", "owner", "observation"},
            "cleanup_decision": {"resource", "owner", "observation_sha256", "decided_at_ns", "deadline_ns", "success"},
            "cleanup_error": {"resource", "owner", "stage", "message"},
        }
        if event not in schemas:
            raise AuthorityError("unknown ledger event")
        value = _keys(data, schemas[event])
        resource_id = _digest(value["resource"])
        resource = result["resources"].get(resource_id)
        if resource is None or _owner(value["owner"]) != resource["owner"] or (
                resource["complete"] and event != "cleanup_error"):
            raise AuthorityError("cleanup resource/owner/obligation is not live")
        if event == "cleanup_intent":
            if (_integer(value["attempt"], positive=True) != resource["attempt"] + 1
                    or _integer(value["deadline_ns"], positive=True) <= _integer(value["authorized_at_ns"])
                    or type(value["intent_id"]) is not str
                    or re.fullmatch(r"[0-9a-f]{32}", value["intent_id"]) is None
                    or value["intent_id"] in result["intent_ids"]):
                raise AuthorityError("cleanup intent is stale, duplicated, or past deadline")
            resource["attempt"] = value["attempt"]
            resource["intent_id"] = value["intent_id"]
            result["intent_ids"].append(value["intent_id"])
        elif event == "cleanup_observed":
            observation = Observation.parse(value["observation"])
            if observation.target != ResourceIdentity.parse(resource["identity"]):
                raise AuthorityError("observation targets another exact resource")
            # Evidence alone never discharges an obligation. A later durable
            # terminal decision must reference this exact hash-linked record.
            resource["pending_observation"] = dict(record_sha256=record_sha256,
                observation=observation.wire(), decided=False)
        elif event == "cleanup_decision":
            pending = resource["pending_observation"]
            decided_at = _integer(value["decided_at_ns"])
            deadline = _integer(value["deadline_ns"], positive=True)
            if (pending is None or pending["decided"]
                    or _digest(value["observation_sha256"]) != pending["record_sha256"]
                    or type(value["success"]) is not bool):
                raise AuthorityError("terminal cleanup decision lacks exact pending evidence")
            expected = decided_at < deadline and _satisfies(
                resource, Observation.parse(pending["observation"]))
            if value["success"] != expected:
                raise AuthorityError("terminal cleanup decision contradicts evidence/deadline")
            pending["decided"] = True
            resource["complete"] = expected
            if not expected:
                result["cleanup_errors"].append(dict(resource=resource_id, owner=value["owner"],
                    stage="deadline" if decided_at >= deadline else "postcondition",
                    message="terminal cleanup decision did not establish timely exact cleanup"))
        else:
            if value["stage"] not in ("authority", "deadline", "mutation", "observation", "postcondition"):
                raise AuthorityError("unknown cleanup error stage")
            _error_message(value["message"])
            result["cleanup_errors"].append(dict(value))
    return result


def _error_message(value: object) -> str:
    if type(value) is not str or not value or len(value) > 2048 or "\0" in value:
        raise AuthorityError("invalid error evidence")
    return value


class CleanupLedger:
    def __init__(self, store: DurableStore, clock: Callable[[], int], clock_id: str):
        self._store, self._clock, self._clock_id = store, clock, _token(clock_id)
        self._state = None
        self._sequence = 0
        self._head = ZERO_HASH
        self._usable = True

    @classmethod
    def create(cls, store: DurableStore, clock: Callable[[], int], clock_id: str,
               *, ledger_id: str | None = None) -> CleanupLedger:
        result = cls(store, clock, clock_id)
        with store.exclusive():
            if store.names():
                raise AuthorityError("new ledger requires an empty dedicated store")
            result._append("opened", dict(ledger_id=ledger_id or secrets.token_hex(16), clock_id=clock_id))
        return result

    @classmethod
    def recover(cls, store: DurableStore, clock: Callable[[], int], clock_id: str, *,
                checkpoint: RecoveryCheckpoint | None = None) -> CleanupLedger:
        if type(checkpoint) is not RecoveryCheckpoint:
            raise AuthorityError("recovery requires a trusted externally held checkpoint")
        result = cls(store, clock, clock_id)
        with store.exclusive():
            names = result._published_names()
            if not names or checkpoint.sequence >= len(names):
                raise CorruptLedger("trusted checkpoint prefix is missing")
            for sequence, name in enumerate(names):
                record = decode_record(store.read(name))
                if record["sequence"] != sequence or record["previous_hash"] != result._head:
                    raise CorruptLedger("record sequence/hash link differs")
                if sequence == checkpoint.sequence and record["hash"] != checkpoint.record_sha256:
                    raise CorruptLedger("trusted checkpoint hash differs")
                try:
                    candidate = _apply(result._state, record["event"], record["data"], record["hash"])
                    if record["remaining"] != _remaining(candidate):
                        raise CorruptLedger("remaining obligations differ from replayed state")
                except AuthorityError as error:
                    raise CorruptLedger(str(error)) from error
                result._state, result._head = candidate, record["hash"]
                result._sequence += 1
            if result._state["ledger_id"] != checkpoint.ledger_id:
                raise CorruptLedger("trusted checkpoint belongs to another ledger")
            if result._state["clock_id"] != clock_id:
                raise AuthorityError("cleanup clock/boot domain changed")
            # A visible rename from an interrupted publisher is not yet durable.
            store.fsync_directory()
        return result

    def _published_names(self) -> list[str]:
        names = self._store.names()
        if type(names) is not list or any(type(name) is not str for name in names) or len(names) != len(set(names)):
            raise CorruptLedger("directory name inventory is not exact")
        published = []
        for name in names:
            if _RECORD.fullmatch(name):
                published.append(name)
            elif not _PENDING.fullmatch(name):
                raise CorruptLedger("unexpected ledger directory entry")
        published.sort()
        if len(published) > MAX_RECORDS or published != [f"{i:020d}.json" for i in range(len(published))]:
            raise CorruptLedger("published record sequence is missing or excessive")
        return published

    @contextmanager
    def _operation(self):
        if not self._usable:
            raise AuthorityError("publication was uncertain; recover before continuing")
        with self._store.exclusive():
            names = self._published_names()
            if len(names) != self._sequence or not names:
                raise AuthorityError("ledger instance is stale; recover under the exclusive lease")
            # Revalidate the whole prefix, not only its final record: a damaged
            # earlier file cannot be hidden behind an unchanged tail/hash.
            replay, previous = None, ZERO_HASH
            for sequence, name in enumerate(names):
                record = decode_record(self._store.read(name))
                if record["sequence"] != sequence or record["previous_hash"] != previous:
                    raise CorruptLedger("live record sequence/hash link differs")
                replay = _apply(replay, record["event"], record["data"], record["hash"])
                if record["remaining"] != _remaining(replay):
                    raise CorruptLedger("live remaining obligations differ")
                previous = record["hash"]
            if previous != self._head or replay != self._state:
                raise AuthorityError("ledger instance is stale; recover under the exclusive lease")
            if self._state["finalized"]:
                raise AuthorityError("ledger is already finalized")
            yield

    def _append(self, event: str, data: dict) -> None:
        candidate = _apply(self._state, event, data)
        record = dict(version=1, sequence=self._sequence, previous_hash=self._head,
                      event=event, data=data, remaining=_remaining(candidate))
        record["hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
        candidate = _apply(self._state, event, data, record["hash"])
        payload = canonical_json(record)
        if len(payload) > MAX_RECORD_BYTES or self._sequence >= MAX_RECORDS:
            raise AuthorityError("ledger record budget exhausted")
        temporary = ".pending-" + secrets.token_hex(16)
        handle = None
        try:
            handle = self._store.create(temporary)
            offset = 0
            while offset < len(payload):
                count = self._store.write(handle, payload[offset:])
                if type(count) is not int or not 0 < count <= len(payload) - offset:
                    raise OSError("record write made invalid/no progress")
                offset += count
            self._store.fsync_file(handle)
            self._store.close(handle)
            handle = None
            self._store.rename_no_replace(temporary, f"{self._sequence:020d}.json")
            self._store.fsync_directory()
        except Exception as primary:
            self._usable = False
            cleanup = None
            if handle is not None:
                try:
                    self._store.close(handle)
                except Exception as error:
                    cleanup = error
            raise PersistenceError(primary, cleanup) from primary
        self._state, self._head = candidate, record["hash"]
        self._sequence += 1

    @property
    def remaining(self) -> tuple[str, ...]:
        return tuple(_remaining(self._state))

    @property
    def checkpoint(self) -> RecoveryCheckpoint:
        if not self._usable or self._state is None:
            raise AuthorityError("uncertain publisher cannot issue a checkpoint")
        return RecoveryCheckpoint(self._state["ledger_id"], self._sequence - 1, self._head)

    @property
    def errors(self) -> dict:
        return copy.deepcopy(dict(primary=self._state["primary_errors"], cleanup=self._state["cleanup_errors"]))

    @property
    def finalized(self) -> bool:
        return self._usable and self._state["finalized"]

    @property
    def successful(self) -> bool:
        return self.finalized and not self._state["primary_errors"] and not self._state["cleanup_errors"]

    def register(self, identity: ResourceIdentity, owner: str, *, postcondition: str = "absent",
                 baseline_sha256: str | None = None) -> str:
        with self._operation():
            if type(identity) is not ResourceIdentity:
                raise AuthorityError("registration requires a complete exact identity")
            self._append("registered", dict(identity=identity.wire(), owner=owner,
                         postcondition=postcondition, baseline_sha256=baseline_sha256))
        return identity.resource_id

    def primary_failure(self, message: str) -> None:
        with self._operation():
            self._append("primary_error", dict(message=message))

    def _error(self, resource: str, owner: str, stage: str, message: str) -> None:
        self._append("cleanup_error", dict(resource=resource, owner=owner, stage=stage,
                     message=_error_message(message[:2048] or "unspecified cleanup error")))

    def attempt_cleanup(self, resource_id: str, owner: str, *, deadline_ns: int,
                        observe: Callable[[ResourceIdentity], Observation],
                        mutate: Callable[[CleanupAuthorization], object]) -> bool:
        """Returns true only after an exact terminal-success record is durable.

        The store lease spans authority checks, durable intent, mutation, and
        observation. A mutation return value is intentionally ignored. The
        trusted deadline sample AFTER durable observation and BEFORE terminal
        append is the decision linearization point. No later clock check may
        contradict a committed terminal decision; the outer coordinator still
        enforces its own overall deadline. Callbacks must use bounded I/O.
        Crash before terminal decision leaves an obligation; retry observes
        afresh before acting, even if earlier pending evidence looked successful.
        """
        with self._operation():
            _integer(deadline_ns, positive=True)
            resource = self._state["resources"].get(_digest(resource_id))
            if resource is None or resource["owner"] != _owner(owner) or resource["complete"]:
                raise AuthorityError("no exact live cleanup ownership")
            identity = ResourceIdentity.parse(resource["identity"])

            def expired(now: int | None = None) -> bool:
                if _integer(self._clock() if now is None else now) >= deadline_ns:
                    self._error(resource_id, owner, "deadline", "cleanup deadline exhausted; obligation remains")
                    return True
                return False

            def observation() -> Observation | None:
                try:
                    result = observe(identity)
                    if type(result) is not Observation or result.target != identity:
                        raise AuthorityError("observer did not identify the exact cleanup target")
                    return result
                except Exception as error:
                    self._error(resource_id, owner, "observation", str(error))
                    return None

            def admit(result: Observation | None) -> str:
                if result is None:
                    return "blocked"
                if _satisfies(resource, result):
                    return "complete" if decide(result) else "blocked"
                if not result.conclusive or result.actual != identity or result.status != "present":
                    decide(result)
                    return "blocked"
                return "present"

            def decide(result: Observation) -> bool:
                self._append("cleanup_observed", dict(resource=resource_id, owner=owner,
                                                     observation=result.wire()))
                observation_hash = self._head
                decided_at = _integer(self._clock())
                success = decided_at < deadline_ns and _satisfies(resource, result)
                self._append("cleanup_decision", dict(resource=resource_id, owner=owner,
                    observation_sha256=observation_hash, decided_at_ns=decided_at,
                    deadline_ns=deadline_ns, success=success))
                # Do not sample the clock here: durable replay must agree with
                # this returned decision even if publication itself was slow.
                return success

            if expired():
                return False
            status = admit(observation())
            if status != "present":
                return status == "complete"
            authorized_at = _integer(self._clock())
            if expired(authorized_at):
                return False
            intent_id = secrets.token_hex(16)
            attempt = resource["attempt"] + 1
            self._append("cleanup_intent", dict(resource=resource_id, owner=owner,
                         intent_id=intent_id, attempt=attempt, deadline_ns=deadline_ns,
                         authorized_at_ns=authorized_at))
            if expired():
                return False
            status = admit(observation())
            if status != "present":
                return status == "complete"
            if expired():
                return False
            authorization = CleanupAuthorization(identity, owner, intent_id, self._head, attempt, deadline_ns)
            try:
                mutate(authorization)
            except Exception as error:
                self._error(resource_id, owner, "mutation", str(error))
            result = observation()
            if result is None:
                return False
            return decide(result)

    def finalize(self) -> bool:
        with self._operation():
            result = "cleaned_with_errors" if self._state["primary_errors"] or self._state["cleanup_errors"] else "cleaned"
            self._append("finalized", dict(result=result))
        return self.successful
